//! I2P name lookups. A human `.i2p` name is asked of jump services (name
//! registries) through the I2P router's HTTP proxy; their page carries the
//! name's destination in an `i2paddresshelper=` link, and the relay is then
//! pinned to the destination's b32 address. Names are looked up once, when a
//! relay is added, never when connecting.

use std::time::Duration;

use base64::Engine;
use bitcoin::hashes::{sha256, Hash};
use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use deadhop_net::relay::ProxyTransport;

/// Registries used when none are configured.
pub const DEFAULT_REGISTRIES: [&str; 2] = [
    "http://notbob.i2p/cgi-bin/jump.cgi?q={name}",
    "http://stats.i2p/cgi-bin/jump.cgi?a={name}",
];
/// Most registries in the list.
pub const MAX_REGISTRIES: usize = 4;
/// Longest registry template.
pub const REGISTRY_LEN: usize = 200;
/// Longest name looked up.
pub const NAME_LEN: usize = 100;
/// Most of a registry's reply that is read.
pub const MAX_REPLY: usize = 256 * 1024;
/// How long one registry may take (I2P is slow).
pub const LOOKUP_SECS: u64 = 90;

const HELPER: &str = "i2paddresshelper=";
/// The user agent I2P's own HTTP proxy sends for everyone; some registries
/// refuse a request without one.
const USER_AGENT: &str = "MYOB/6.66 (AN/ON)";

pub fn default_registries() -> Vec<String> {
    DEFAULT_REGISTRIES.iter().map(|s| s.to_string()).collect()
}

fn bad(why: String) -> Error {
    Error::InvalidParams(why)
}

/// Split `http://host/path?query` into host and the path with its query.
fn split(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("http://")?;
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, path) = rest.split_at(cut);
    Some((host, path))
}

/// Check a registry template: `http://<host>.i2p/...{name}...`, short, no
/// port, user name or spaces.
pub fn check_registry(t: &str) -> Result<()> {
    if t.len() > REGISTRY_LEN || t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad(format!(
            "I2P registry: at most {REGISTRY_LEN} characters, no spaces"
        )));
    }
    let Some((host, path)) = split(t) else {
        return Err(bad(format!("I2P registry '{t}' must start with http://")));
    };
    let host_ok = host.len() > 4
        && host.ends_with(".i2p")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if !host_ok {
        return Err(bad(format!(
            "I2P registry '{t}' must name a lowercase .i2p host with no port or user name"
        )));
    }
    if !path.contains("{name}") {
        return Err(bad(format!("I2P registry '{t}' must contain {{name}} after the host")));
    }
    Ok(())
}

/// Check a name to look up: a lowercase `.i2p` name, not a `.b32.i2p` address.
pub fn check_name(name: &str) -> Result<()> {
    let ok = name.len() <= NAME_LEN
        && name.ends_with(".i2p")
        && !name.ends_with(".b32.i2p")
        && name.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if !ok {
        return Err(bad(format!(
            "the name must be a lowercase .i2p name (not a .b32.i2p address) of at most {NAME_LEN} characters"
        )));
    }
    Ok(())
}

/// The registry url for one name.
pub fn fill(template: &str, name: &str) -> String {
    template.replace("{name}", name)
}

/// The first `i2paddresshelper=` value in a page, with `%3D`, `%7E` and
/// friends decoded. `None` if there is none.
pub fn helper_value(page: &[u8]) -> Option<String> {
    let at = page.windows(HELPER.len()).position(|w| w == HELPER.as_bytes())? + HELPER.len();
    let raw: Vec<u8> = page[at..]
        .iter()
        .copied()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'~' | b'=' | b'%'))
        .collect();
    let mut out = String::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = std::str::from_utf8(raw.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()? as char);
            i += 3;
        } else {
            out.push(raw[i] as char);
            i += 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Lowercase RFC 4648 base32 without padding.
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The `.b32.i2p` address of a destination in I2P's base64 (`-` and `~`
/// for `+` and `/`).
pub fn b32_address(destination: &str) -> std::result::Result<String, String> {
    let std_b64: String = destination
        .chars()
        .map(|c| match c {
            '-' => '+',
            '~' => '/',
            c => c,
        })
        .collect();
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let bytes = engine
        .decode(std_b64)
        .map_err(|_| "the destination is not valid base64".to_string())?;
    // 256-byte public key, 128-byte signing key, then a certificate: type
    // (1 byte), length (2 bytes) and that many bytes.
    if bytes.len() < 387 {
        return Err("the destination is too short".into());
    }
    let cert_len = usize::from(u16::from_be_bytes([bytes[385], bytes[386]]));
    if bytes.len() != 387 + cert_len {
        return Err("the destination has the wrong length".into());
    }
    Ok(format!(
        "{}.b32.i2p",
        base32(&sha256::Hash::hash(&bytes).to_byte_array())
    ))
}

/// Undo `Transfer-Encoding: chunked`; whatever cannot be parsed is kept as is.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&rest[..eol])
            .ok()
            .and_then(|l| usize::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16).ok());
        let Some(size) = size else { break };
        rest = &rest[eol + 2..];
        if size == 0 {
            return out;
        }
        let take = size.min(rest.len());
        out.extend_from_slice(&rest[..take]);
        rest = rest.get(take + 2..).unwrap_or_default();
        if take < size {
            return out;
        }
    }
    out.extend_from_slice(rest);
    out
}

/// The helper value in a whole HTTP reply: in the head (a redirect's
/// `Location`) or in the body.
pub fn helper_in_reply(reply: &[u8]) -> Option<String> {
    let split = reply.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&reply[..i], &reply[i + 4..]),
        None => (reply, &[][..]),
    };
    if let Some(v) = helper_value(head) {
        return Some(v);
    }
    let chunked = String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .lines()
        .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    if chunked {
        helper_value(&dechunk(body))
    } else {
        helper_value(body)
    }
}

/// Whether a reply so far holds a complete, valid destination.
fn helper_done(reply: &[u8]) -> bool {
    helper_in_reply(reply).is_some_and(|d| b32_address(&d).is_ok())
}

/// What one registry said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// It knows the name: its b32 address.
    Found(String),
    /// It answered without a (usable) address.
    Unknown(String),
    /// It could not be reached or did not answer in time.
    Unreachable(String),
}

impl Answer {
    /// Why a registry gave no address; `None` if it did.
    fn why(&self) -> Option<&str> {
        match self {
            Answer::Found(_) => None,
            Answer::Unknown(w) | Answer::Unreachable(w) => Some(w),
        }
    }
}

/// Ask one registry, through the I2P router, for `name`.
pub async fn ask(proxy: &ProxyTransport, template: &str, name: &str, secs: u64) -> Answer {
    let url = fill(template, name);
    let Some((host, path)) = split(&url) else {
        return Answer::Unreachable("not an http:// url".into());
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    // Some registries keep the connection open after the page, so reading
    // stops once a whole destination has arrived (its length is in it), and
    // what came before a timeout is still used.
    let mut reply = Vec::new();
    let fetch = async {
        let mut s = proxy.tunnel(host, 80).await?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: text/html\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await?;
        s.flush().await?;
        let mut buf = [0u8; 8192];
        while reply.len() < MAX_REPLY && !helper_done(&reply) {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n.min(MAX_REPLY - reply.len())]);
        }
        std::io::Result::Ok(())
    };
    match tokio::time::timeout(Duration::from_secs(secs), fetch).await {
        Err(_) if reply.is_empty() => return Answer::Unreachable(format!("no answer within {secs} s")),
        Ok(Err(e)) if reply.is_empty() => return Answer::Unreachable(e.to_string()),
        _ => {}
    }
    if reply.is_empty() {
        return Answer::Unreachable("empty reply".into());
    }
    let status = String::from_utf8_lossy(reply.split(|b| *b == b'\n').next().unwrap_or_default())
        .trim()
        .to_string();
    match helper_in_reply(&reply) {
        Some(dest) => match b32_address(&dest) {
            Ok(a) => Answer::Found(a),
            Err(why) => Answer::Unknown(format!("bad address helper: {why}")),
        },
        None => Answer::Unknown(format!("no address in the reply ({status})")),
    }
}

/// A registry that gave another address than the chosen one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Disagreement {
    pub registry: String,
    pub address: String,
}

/// Result of `resolve_i2p_name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct I2pNameLookup {
    pub name: String,
    /// The `.b32.i2p` address, from the first registry (in list order) that knew the name.
    pub address: String,
    /// That registry.
    pub registry: String,
    /// Every registry that gave this address, `registry` included.
    pub agreeing: Vec<String>,
    /// Registries that gave another address.
    pub disagreeing: Vec<Disagreement>,
    /// Registries that answered without an address.
    pub unknown: Vec<String>,
    /// Registries that could not be reached or did not answer in time.
    pub unreachable: Vec<String>,
}

/// Ask every registry at once and put the answers together.
pub async fn lookup(proxy: &ProxyTransport, registries: &[String], name: &str, secs: u64) -> Result<I2pNameLookup> {
    let answers = futures_util::future::join_all(registries.iter().map(|r| ask(proxy, r, name, secs))).await;
    summarize(name, registries, &answers)
}

/// Put the registries' answers (in list order) together.
pub fn summarize(name: &str, registries: &[String], answers: &[Answer]) -> Result<I2pNameLookup> {
    let first = registries.iter().zip(answers).find_map(|(r, a)| match a {
        Answer::Found(addr) => Some((r.clone(), addr.clone())),
        _ => None,
    });
    let Some((registry, address)) = first else {
        let why: Vec<String> = registries
            .iter()
            .zip(answers)
            .filter_map(|(r, a)| a.why().map(|w| format!("{r}: {w}")))
            .collect();
        let all_unreachable = answers.iter().all(|a| matches!(a, Answer::Unreachable(_)));
        let lead = if all_unreachable {
            "no I2P registry could be reached through the I2P router".to_string()
        } else {
            format!("no I2P registry knows {name}")
        };
        return Err(Error::InvalidParams(format!("{lead} ({})", why.join("; "))));
    };
    let mut out = I2pNameLookup {
        name: name.to_string(),
        address: address.clone(),
        registry,
        agreeing: Vec::new(),
        disagreeing: Vec::new(),
        unknown: Vec::new(),
        unreachable: Vec::new(),
    };
    for (r, a) in registries.iter().zip(answers) {
        match a {
            Answer::Found(x) if *x == address => out.agreeing.push(r.clone()),
            Answer::Found(x) => out.disagreeing.push(Disagreement {
                registry: r.clone(),
                address: x.clone(),
            }),
            Answer::Unknown(_) => out.unknown.push(r.clone()),
            Answer::Unreachable(_) => out.unreachable.push(r.clone()),
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Destination of `nostr-not.i2p` as notbob.i2p gave it.
    pub const NOSTR_NOT_DEST: &str = concat!(
        "w45~kCTUJn0jE-f~7V7-N2cQ~n7~hclPum~Wkc0mt1mORgQ5sGnNDl6J73-2cdWSwd0ks0ABhlCZrvc2im1pV8YD3kwl7bQPN5WDfygSPYriNyJkKEcsBgi1tSPues3jD9DBMk9aU422U8cK59ZFMbFcCLRFJV-oMLVX45k0~1t1R9r1Dd~B73jjG0P4f2isOmDS4rXM9bjTAvP1LFQMalQqotXQP7TGOOMxLcp2Sltt3LOY5m-cysLbgkdEMGtg17Cr",
        "kPWLas0RZpTqIGgHzLcvkufi9hn6uDAN0cqm2pT-gpPrSrq54E0mVwo6i2Jm6Z3I24pd5Pk87PjfwoBbHkXZVosXlJ~xmsoHINdR4V11bT5jg1Uf8jNqhB6-62PiRdlWixeUn~Gaygcg11HhXXVtPmODVR~yM2qEHr7rY-LuF8SiF5Sf8ZrKByDXUeFddW0-Y4NVH~IzaoQevutj4tBPQ1TPp7SZaO4geS9fWZMVNHeIPqsFc0~xedJZ8allBQAEAAcAAA=="
    );
    pub const NOSTR_NOT_B32: &str = "nostrsrpr4c7lrswidgws2dzx5yrllqujdewru34jfydjjqplapq.b32.i2p";

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

    #[test]
    fn base32_matches_rfc_4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn a_known_destination_gives_its_b32_address() {
        assert_eq!(b32_address(NOSTR_NOT_DEST).unwrap(), NOSTR_NOT_B32);
        let page = format!("<a href='http://nostr-not.i2p/?i2paddresshelper={NOSTR_NOT_DEST}'>");
        assert_eq!(helper_value(page.as_bytes()).as_deref(), Some(NOSTR_NOT_DEST));
        let a = b32_address(&fake_destination(7)).unwrap();
        assert_eq!(a.len(), 52 + ".b32.i2p".len());
        assert_ne!(a, b32_address(&fake_destination(8)).unwrap());
        // Padding is optional.
        assert_eq!(b32_address(fake_destination(7).trim_end_matches('=')).unwrap(), a);
        assert!(b32_address("AAAA").unwrap_err().contains("short"));
        assert!(b32_address("not base64!").is_err());
        // A certificate length that does not match the rest.
        let mut d = vec![1u8; 385];
        d.extend_from_slice(&[0, 9]);
        let wrong = base64::engine::general_purpose::STANDARD.encode(d);
        assert!(b32_address(&wrong).unwrap_err().contains("length"));
    }

    #[test]
    fn the_helper_is_found_where_it_is() {
        let d = fake_destination(3);
        let page = format!("<a href=\"http://x.i2p/?i2paddresshelper={d}\">x</a>");
        assert_eq!(helper_value(page.as_bytes()), Some(d.clone()));
        // Percent-encoded padding.
        let enc = d.replace('=', "%3D").replace('~', "%7E");
        assert_eq!(
            helper_value(format!("?i2paddresshelper={enc}&x").as_bytes()),
            Some(d.clone())
        );
        // Missing, empty, malformed.
        assert_eq!(helper_value(b"<html>Unknown host</html>"), None);
        assert_eq!(helper_value(b"i2paddresshelper=\""), None);
        assert_eq!(helper_value(b"i2paddresshelper=%zz"), None);
        let bad = helper_value(b"i2paddresshelper=AAAA").unwrap();
        assert!(b32_address(&bad).is_err());
        // In a redirect.
        let redirect = format!("HTTP/1.1 301 Moved\r\nLocation: http://x.i2p/?i2paddresshelper={d}\r\n\r\n");
        assert_eq!(helper_in_reply(redirect.as_bytes()), Some(d.clone()));
        // In a chunked body, cut across chunks.
        let body = format!("a href=\"?i2paddresshelper={d}\"");
        let (one, two) = body.split_at(40);
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{one}\r\n{:x}\r\n{two}\r\n0\r\n\r\n",
            one.len(),
            two.len()
        );
        assert_eq!(helper_in_reply(chunked.as_bytes()), Some(d));
    }

    #[test]
    fn registry_templates_and_names_are_checked() {
        for ok in DEFAULT_REGISTRIES {
            check_registry(ok).unwrap();
        }
        for bad in [
            "https://notbob.i2p/?q={name}",
            "http://notbob.i2p/?q=",
            "http://notbob.i2p{name}",
            "http://{name}.i2p/",
            "http://example.com/?q={name}",
            "http://notbob.i2p:8080/?q={name}",
            "http://u@notbob.i2p/?q={name}",
            "http://NotBob.i2p/?q={name}",
            "http://notbob.i2p/?q={name} x",
            "notbob.i2p/?q={name}",
        ] {
            assert!(check_registry(bad).is_err(), "{bad}");
        }
        assert!(check_registry(&format!("http://a.i2p/{}{{name}}", "x".repeat(200))).is_err());
        assert_eq!(
            fill(DEFAULT_REGISTRIES[0], "a.i2p"),
            "http://notbob.i2p/cgi-bin/jump.cgi?q=a.i2p"
        );
        check_name("nostr-not.i2p").unwrap();
        check_name("sub.name.i2p").unwrap();
        for bad in [
            "Nostr.i2p",
            "nostr.onion",
            "abc.b32.i2p",
            ".i2p",
            "a..i2p",
            "-a.i2p",
            "a b.i2p",
            "a/x.i2p",
        ] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        assert!(check_name(&format!("{}.i2p", "a".repeat(100))).is_err());
    }

    #[test]
    fn answers_are_put_together_in_list_order() {
        let regs: Vec<String> = ["r1", "r2", "r3", "r4"].iter().map(|s| s.to_string()).collect();
        let out = summarize(
            "x.i2p",
            &regs,
            &[
                Answer::Unknown("404".into()),
                Answer::Found("b.b32.i2p".into()),
                Answer::Found("c.b32.i2p".into()),
                Answer::Unreachable("down".into()),
            ],
        )
        .unwrap();
        assert_eq!((out.registry.as_str(), out.address.as_str()), ("r2", "b.b32.i2p"));
        assert_eq!(out.agreeing, ["r2"]);
        assert_eq!(
            out.disagreeing,
            [Disagreement {
                registry: "r3".into(),
                address: "c.b32.i2p".into()
            }]
        );
        assert_eq!(
            (out.unknown, out.unreachable),
            (vec!["r1".to_string()], vec!["r4".to_string()])
        );
        let down = summarize("x.i2p", &regs[..1], &[Answer::Unreachable("502".into())]);
        assert!(format!("{:?}", down.unwrap_err()).contains("could be reached"));
        let none = summarize(
            "x.i2p",
            &regs[..2],
            &[Answer::Unknown("404".into()), Answer::Unreachable("502".into())],
        );
        assert!(format!("{:?}", none.unwrap_err()).contains("knows x.i2p"));
    }

    /// A stand-in I2P router: answers `CONNECT host:80` itself and serves the
    /// canned reply for that host; an unknown host gets a 502, as from a
    /// router that cannot reach it. Records the requests it served.
    pub async fn fake_router(
        pages: HashMap<String, String>,
    ) -> (u16, Arc<std::sync::Mutex<Vec<String>>>, JoinHandle<()>) {
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

    async fn read_head(s: &mut tokio::net::TcpStream) -> String {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).await.unwrap_or(0) == 1 {
            head.push(b[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// A chunked page, with a chunk boundary inside the destination, from
    /// a server that leaves the connection open afterwards.
    fn chunked_page(dest: &str) -> String {
        let body = format!("<a href=\"?i2paddresshelper={dest}\">go</a>");
        let (one, two) = body.split_at(200);
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{one}\r\n{:x}\r\n{two}\r\n",
            one.len(),
            two.len()
        )
    }

    pub fn page_with(dest: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"http://x.i2p/?i2paddresshelper={dest}\">go</a>")
    }

    #[tokio::test]
    async fn every_registry_is_asked_through_the_router() {
        let pages: HashMap<String, String> = [
            ("one.i2p".to_string(), page_with(&fake_destination(1))),
            ("two.i2p".to_string(), page_with(&fake_destination(1))),
            ("other.i2p".to_string(), page_with(&fake_destination(2))),
            (
                "nothing.i2p".to_string(),
                "HTTP/1.1 404 Not Found\r\n\r\nunknown".to_string(),
            ),
            ("chunked.i2p".to_string(), chunked_page(&fake_destination(1))),
        ]
        .into();
        let (port, seen, task) = fake_router(pages).await;
        let proxy = ProxyTransport::new(
            deadhop_net::relay::parse_proxy(&format!("http://127.0.0.1:{port}"))
                .unwrap()
                .unwrap(),
        );
        let regs: Vec<String> = ["nothing", "one", "down", "other", "two", "chunked"]
            .iter()
            .map(|h| format!("http://{h}.i2p/jump?q={{name}}"))
            .collect();
        // The chunked page is left open: reading stops at its destination.
        let started = std::time::Instant::now();
        let out = lookup(&proxy, &regs, "x.i2p", 20).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(out.address, b32_address(&fake_destination(1)).unwrap());
        assert_eq!(out.registry, regs[1]);
        assert_eq!(out.agreeing, [regs[1].clone(), regs[4].clone(), regs[5].clone()]);
        assert_eq!(out.disagreeing[0].registry, regs[3]);
        assert_eq!(out.unknown, [regs[0].clone()]);
        assert_eq!(out.unreachable, [regs[2].clone()]);
        let requests = seen.lock().unwrap().clone();
        assert!(requests
            .iter()
            .any(|r| r.starts_with("GET /jump?q=x.i2p HTTP/1.1\r\n") && r.contains("Host: one.i2p\r\n")));
        assert!(requests
            .iter()
            .all(|r| r.contains("Connection: close\r\n") && r.contains("User-Agent: MYOB/6.66 (AN/ON)\r\n")));
        task.abort();
    }

    #[test]
    fn percent_escapes_and_chunks_are_undone() {
        assert_eq!(helper_value(b"i2paddresshelper=a%3Db%7E").as_deref(), Some("a=b~"));
        assert_eq!(helper_value(b"i2paddresshelper=ab%3"), None);
        // A chunk that claims more than arrives is kept as far as it goes.
        assert_eq!(dechunk(b"a\r\nabcd"), b"abcd");
        assert_eq!(dechunk(b"4\r\nabcd\r\n0\r\n\r\n"), b"abcd");
        // What cannot be parsed is kept as is.
        assert_eq!(dechunk(b"zz\r\nabcd"), b"zz\r\nabcd");
    }

    #[test]
    fn a_failed_answer_says_why() {
        assert_eq!(Answer::Found("a".into()).why(), None);
        assert_eq!(Answer::Unknown("u".into()).why(), Some("u"));
        assert_eq!(Answer::Unreachable("x".into()).why(), Some("x"));
    }

    #[tokio::test]
    async fn odd_registry_replies_are_told_apart() {
        let pages: HashMap<String, String> = [
            (
                "bad.i2p".to_string(),
                "HTTP/1.1 200 OK\r\n\r\n?i2paddresshelper=AAAA".to_string(),
            ),
            ("empty.i2p".to_string(), String::new()),
        ]
        .into();
        let (port, _seen, task) = fake_router(pages).await;
        let proxy = ProxyTransport::new(
            deadhop_net::relay::parse_proxy(&format!("http://127.0.0.1:{port}"))
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            ask(&proxy, "ftp://x.i2p/{name}", "x.i2p", 5).await,
            Answer::Unreachable("not an http:// url".into())
        );
        let bad = ask(&proxy, "http://bad.i2p", "x.i2p", 5).await;
        assert!(
            matches!(&bad, Answer::Unknown(why) if why.starts_with("bad address helper")),
            "{bad:?}"
        );
        assert_eq!(
            ask(&proxy, "http://empty.i2p", "x.i2p", 5).await,
            Answer::Unreachable("empty reply".into())
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_silent_registry_times_out() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        // Answers the CONNECT, then says nothing until the client gives up.
        let router = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let _ = read_head(&mut s).await;
            let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest).await;
        });
        let proxy = ProxyTransport::new(
            deadhop_net::relay::parse_proxy(&format!("http://127.0.0.1:{port}"))
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            ask(&proxy, "http://slow.i2p/{name}", "x.i2p", 1).await,
            Answer::Unreachable("no answer within 1 s".into())
        );
        router.await.unwrap();
    }
}
