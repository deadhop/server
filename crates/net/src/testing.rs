//! Stand-in proxies for tests: a SOCKS5 proxy and an HTTP CONNECT proxy
//! (plain or over TLS with the test certificate). Compiled for this crate's
//! own tests and, behind the `test-support` feature, for the tests of the
//! services that use it. Never part of a release build.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::relay::Io;

/// Copy bytes both ways until either side closes.
async fn pipe<A: Io, B: Io>(mut a: A, mut b: B) {
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
}

/// A minimal SOCKS5 proxy, optionally requiring a user name and password.
pub async fn socks5_proxy(auth: Option<(&'static str, &'static str)>) -> (u16, JoinHandle<()>) {
    socks5_proxy_on("127.0.0.1:0", auth).await
}

/// The same, on a chosen address (to bring a stopped proxy back on its port).
pub async fn socks5_proxy_on(bind: &str, auth: Option<(&'static str, &'static str)>) -> (u16, JoinHandle<()>) {
    let l = TcpListener::bind(bind).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).await.unwrap();
                let mut methods = vec![0u8; head[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                if let Some((user, pass)) = auth {
                    s.write_all(&[5, 2]).await.unwrap();
                    let mut v = [0u8; 2];
                    s.read_exact(&mut v).await.unwrap();
                    let mut u = vec![0u8; v[1] as usize];
                    s.read_exact(&mut u).await.unwrap();
                    let mut pl = [0u8; 1];
                    s.read_exact(&mut pl).await.unwrap();
                    let mut p = vec![0u8; pl[0] as usize];
                    s.read_exact(&mut p).await.unwrap();
                    let ok = u == user.as_bytes() && p == pass.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        return;
                    }
                } else {
                    s.write_all(&[5, 0]).await.unwrap();
                }
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.unwrap();
                let host = match req[3] {
                    3 => {
                        let mut n = [0u8; 1];
                        s.read_exact(&mut n).await.unwrap();
                        let mut name = vec![0u8; n[0] as usize];
                        s.read_exact(&mut name).await.unwrap();
                        String::from_utf8(name).unwrap()
                    }
                    _ => {
                        let mut ip = [0u8; 4];
                        s.read_exact(&mut ip).await.unwrap();
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                };
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await.unwrap();
                let target = TcpStream::connect((host.as_str(), u16::from_be_bytes(port)))
                    .await
                    .unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                pipe(s, target).await;
            });
        }
    });
    (port, task)
}

async fn serve_connect<S: Io>(mut s: S, auth: Option<&'static str>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        if s.read(&mut b).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(b[0]);
    }
    let text = String::from_utf8(head).unwrap();
    let target = text.split_whitespace().nth(1).unwrap().to_string();
    if let Some(token) = auth {
        if !text.contains(&format!("Proxy-Authorization: Basic {token}\r\n")) {
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
            return;
        }
    }
    let target = TcpStream::connect(target.as_str()).await.unwrap();
    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .unwrap();
    pipe(s, target).await;
}

/// A minimal HTTP CONNECT proxy, plain or over TLS with the test certificate.
pub async fn connect_proxy(tls: bool, auth: Option<&'static str>) -> (u16, JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tls.then(|| {
        use rustls::pki_types::pem::PemObject;
        let certs = vec![rustls::pki_types::CertificateDer::from_pem_slice(CERT).unwrap()];
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(KEY).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    });
    let task = tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(a) => {
                        if let Ok(t) = a.accept(s).await {
                            serve_connect(t, auth).await;
                        }
                    }
                    None => serve_connect(s, auth).await,
                }
            });
        }
    });
    (port, task)
}

pub const CERT: &[u8] = include_bytes!("../tests/fixtures/proxy-test-cert.pem");
pub const KEY: &[u8] = include_bytes!("../tests/fixtures/proxy-test-key.pem");
