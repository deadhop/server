//! Stand-ins for tests: an I2P router with canned registry pages. Compiled
//! for this crate's own tests and, behind the `test-support` feature, for the
//! tests of the services that use it. Never part of a release build.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A destination with no certificate: 384 bytes of `fill`, then a null
/// certificate, in I2P base64.
pub fn fake_destination(fill: u8) -> String {
    let mut d = vec![fill; 385];
    d.extend_from_slice(&[0, 0]);
    base64::engine::general_purpose::STANDARD
        .encode(d)
        .replace('+', "-")
        .replace('/', "~")
}

/// A stand-in I2P router: answers `CONNECT host:80` itself and serves the
/// canned reply for that host; an unknown host gets a 502, as from a
/// router that cannot reach it. Records the requests it served.
pub async fn fake_router(pages: HashMap<String, String>) -> (u16, Arc<std::sync::Mutex<Vec<String>>>, JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let pages = pages.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let target = head.split_whitespace().nth(1).unwrap_or_default().to_string();
                let host = target.trim_end_matches(":80").to_string();
                let Some(page) = pages.get(&host).filter(|_| target.ends_with(":80")) else {
                    let _ = s.write_all(b"HTTP/1.1 502 Domain Not Found\r\n\r\n").await;
                    return;
                };
                let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let req = read_head(&mut s).await;
                log.lock().unwrap().push(req);
                let _ = s.write_all(page.as_bytes()).await;
                if page.contains("chunked") {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });
        }
    });
    (port, seen, task)
}

pub async fn read_head(s: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).await.unwrap_or(0) == 1 {
        head.push(b[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

pub fn page_with(dest: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"http://x.i2p/?i2paddresshelper={dest}\">go</a>"
    )
}
