//! The verifier in real handshakes (TLS 1.3 and TLS 1.2) against a server with
//! a self-signed certificate.

use std::sync::Arc;

use deadhop_tlspin::{fingerprint_hex, parse_fingerprint, pinned, tls_config};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CERT: &[u8] = include_bytes!("fixtures/proxy-test-cert.pem");
const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
const KEY: &[u8] = include_bytes!("fixtures/proxy-test-key.pem");

/// A TLS server that answers one byte per connection; returns its address and
/// the certificate's fingerprint.
async fn server(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> (String, String) {
    let cert = CertificateDer::from_pem_slice(CERT).unwrap();
    let fp = fingerprint_hex(cert.as_ref());
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tls.write_all(b"k").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (addr, fp)
}

async fn connect(addr: &str, config: rustls::ClientConfig) -> Result<u8, String> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let mut b = [0u8; 1];
    tls.read_exact(&mut b).await.map_err(|e| e.to_string())?;
    Ok(b[0])
}

#[tokio::test]
async fn a_pinned_certificate_is_accepted_on_tls_13_and_tls_12() {
    for versions in [rustls::DEFAULT_VERSIONS, TLS12_ONLY] {
        let (addr, fp) = server(versions).await;
        let pin = parse_fingerprint(&fp).unwrap();
        // One of several pins matches.
        let verifier = pinned(Some(vec![[9; 32], pin]));
        assert_eq!(connect(&addr, tls_config(Some(verifier.clone()))).await, Ok(b'k'));
        // The certificate it was shown is recorded.
        assert_eq!(*verifier.seen.lock().unwrap(), Some(pin));
    }
}

#[tokio::test]
async fn another_certificate_is_refused_and_no_pins_only_reads() {
    let (addr, fp) = server(rustls::DEFAULT_VERSIONS).await;
    let e = connect(&addr, tls_config(Some(pinned(Some(vec![[9; 32]])))))
        .await
        .unwrap_err();
    assert!(
        e.contains("does not match the pinned fingerprint") && e.contains(&fp),
        "{e}"
    );
    // Without pins everything is accepted and the fingerprint is recorded.
    let reader = pinned(None);
    assert_eq!(connect(&addr, tls_config(Some(reader.clone()))).await, Ok(b'k'));
    assert_eq!(hex::encode(reader.seen.lock().unwrap().unwrap()), fp);
    // The public web roots do not know a self-signed certificate.
    assert!(connect(&addr, tls_config(None)).await.is_err());
}

#[test]
fn fingerprints_are_parsed_and_printed() {
    let fp = fingerprint_hex(b"x");
    assert_eq!(fp.len(), 64);
    let colons: Vec<String> = fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
        .collect();
    assert_eq!(
        parse_fingerprint(&format!(" {} ", colons.join(":"))).map(hex::encode),
        Some(fp)
    );
    assert_eq!(parse_fingerprint("abcd"), None);
    assert_eq!(parse_fingerprint(&"zz".repeat(32)), None);
}

#[test]
fn the_first_certificate_of_a_pem_file_is_read() {
    let pem = std::str::from_utf8(CERT).unwrap();
    let der = deadhop_tlspin::first_pem_cert(&format!("junk\n{pem}{pem}")).unwrap();
    assert_eq!(der, CertificateDer::from_pem_slice(CERT).unwrap().as_ref());
    for (bad, why) in [
        ("nothing here", "no certificate in the PEM file"),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA",
            "unterminated certificate in the PEM file",
        ),
        (
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----",
            "the certificate in the PEM file is not valid base64",
        ),
    ] {
        assert_eq!(deadhop_tlspin::first_pem_cert(bad).unwrap_err(), why);
    }
}
