//! Nostr relay connections, optionally through a proxy.
//!
//! Only relay traffic uses the proxy. The Electrum connection is meant to stay
//! on this machine or a private network and is always direct.
//!
//! Supported proxies, all with optional `user:password@`:
//! - `socks5://host:port`: host names are resolved by the proxy, so `.onion`
//!   relays work through Tor;
//! - `https://host:port`: TLS to the proxy (checked against the public web
//!   roots), then an HTTP `CONNECT` tunnel;
//! - `http://host:port`: a plain HTTP `CONNECT` tunnel, for a proxy on this
//!   machine or a private network.

// Without the `contextvm` feature, what only the ContextVM pool uses is unused.
#![cfg_attr(not(feature = "contextvm"), allow(unused_imports, dead_code))]

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(feature = "contextvm")]
use async_trait::async_trait;
use async_wsocket::message::{CloseFrame, Message};
use base64::Engine;
#[cfg(feature = "contextvm")]
use contextvm_sdk::relay::RelayPoolTrait;
use nostr_sdk::pool::transport::error::TransportError;
use nostr_sdk::pool::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use nostr_sdk::prelude::{BoxedFuture, NostrSigner, RelayPoolNotification};
use nostr_sdk::{Client, Event, EventBuilder, EventId, Filter, Keys, PublicKey, Url};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as Wire;

use crate::error::{Error, Result};

/// Longest proxy URL accepted.
const MAX_PROXY_LEN: usize = 300;
/// Largest proxy reply header read while opening a tunnel.
const MAX_CONNECT_REPLY: usize = 8 * 1024;

/// Kind of proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
    Https,
}

/// A parsed proxy setting.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxySpec {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl fmt::Debug for ProxySpec {
    // Never print the password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySpec")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|(u, _)| u))
            .finish()
    }
}

fn bad(why: &str) -> Error {
    Error::InvalidParams(format!("proxy: {why}"))
}

/// Parse a proxy URL. The empty string means "no proxy".
pub fn parse_proxy(s: &str) -> Result<Option<ProxySpec>> {
    if s.is_empty() {
        return Ok(None);
    }
    if s.len() > MAX_PROXY_LEN || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("must be a short url without spaces"));
    }
    let url = Url::parse(s).map_err(|_| bad("not a valid url, e.g. socks5://127.0.0.1:9050"))?;
    let kind = match url.scheme() {
        "socks5" | "socks5h" => ProxyKind::Socks5,
        "http" => ProxyKind::Http,
        "https" => ProxyKind::Https,
        _ => return Err(bad("scheme must be socks5://, https:// or http://")),
    };
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(bad("a host is required"))?;
    let port = url.port_or_known_default().ok_or_else(|| bad("a port is required"))?;
    if !(url.path().is_empty() || url.path() == "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(bad("only scheme, credentials, host and port are allowed"));
    }
    let decode = |v: &str| percent_decode(v).ok_or_else(|| bad("credentials must be valid percent-encoded UTF-8"));
    let auth = match url.username() {
        "" => None,
        user => Some((decode(user)?, decode(url.password().unwrap_or_default())?)),
    };
    Ok(Some(ProxySpec {
        kind,
        host: host.trim_start_matches('[').trim_end_matches(']').to_string(),
        port,
        auth,
    }))
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The proxy URL with any password replaced by `***`, safe to show and log.
pub fn redact(s: &str) -> String {
    match Url::parse(s) {
        Ok(mut url) if url.password().is_some() => {
            url.set_password(Some("***"))
                .expect("a url with a password accepts a new one");
            url.to_string().trim_end_matches('/').to_string()
        }
        _ => s.to_string(),
    }
}

/// Anything a websocket can run over.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// An HTTP proxy answered `CONNECT` with this status instead of 200.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyStatus(pub String);

impl fmt::Display for ProxyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy refused the tunnel (status {})", self.0)
    }
}

impl std::error::Error for ProxyStatus {}

/// Ask an HTTP proxy to open a tunnel to `host:port` over `stream`.
pub async fn http_connect<S: Io>(
    mut stream: S,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
) -> io::Result<S> {
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((user, pass)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read the reply header byte by byte so nothing of the tunnel is consumed.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_CONNECT_REPLY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "proxy reply too long"));
        }
        let mut b = [0u8; 1];
        if stream.read(&mut b).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed the connection",
            ));
        }
        head.push(b[0]);
    }
    let status = String::from_utf8_lossy(&head);
    let code = status
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .unwrap_or_default();
    if code != "200" {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            ProxyStatus(code.to_string()),
        ));
    }
    Ok(stream)
}

/// Opens relay websockets through a proxy.
#[derive(Debug, Clone)]
pub struct ProxyTransport {
    spec: ProxySpec,
    /// TLS settings for talking to an `https://` proxy itself.
    proxy_tls: Arc<rustls::ClientConfig>,
}

/// TLS client settings trusting the public web roots.
pub fn web_roots() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

impl ProxyTransport {
    pub fn new(spec: ProxySpec) -> Self {
        Self::with_proxy_tls(spec, web_roots())
    }

    /// Like [`new`](Self::new) with explicit TLS settings for an `https://` proxy.
    pub fn with_proxy_tls(spec: ProxySpec, proxy_tls: Arc<rustls::ClientConfig>) -> Self {
        ProxyTransport { spec, proxy_tls }
    }

    /// A byte stream to `host:port` through the proxy.
    pub async fn tunnel(&self, host: &str, port: u16) -> io::Result<Box<dyn Io>> {
        let s = &self.spec;
        match s.kind {
            ProxyKind::Socks5 => {
                let proxy = (s.host.as_str(), s.port);
                let stream = match &s.auth {
                    None => tokio_socks::tcp::Socks5Stream::connect(proxy, (host, port)).await,
                    Some((u, p)) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password(proxy, (host, port), u, p).await
                    }
                }
                .map_err(io::Error::other)?;
                Ok(Box::new(stream.into_inner()))
            }
            ProxyKind::Http => {
                let tcp = TcpStream::connect((s.host.as_str(), s.port)).await?;
                Ok(Box::new(http_connect(tcp, host, port, s.auth.as_ref()).await?))
            }
            ProxyKind::Https => {
                let name = rustls::pki_types::ServerName::try_from(s.host.clone()).map_err(io::Error::other)?;
                let tcp = TcpStream::connect((s.host.as_str(), s.port)).await?;
                let tls = tokio_rustls::TlsConnector::from(self.proxy_tls.clone())
                    .connect(name, tcp)
                    .await?;
                Ok(Box::new(http_connect(tls, host, port, s.auth.as_ref()).await?))
            }
        }
    }

    async fn open(&self, url: &Url) -> std::result::Result<(Sink, Stream), TransportError> {
        open_ws(url, Some(self)).await
    }
}

/// Open a websocket to `url`, through `proxy` or straight.
async fn open_ws(url: &Url, proxy: Option<&ProxyTransport>) -> std::result::Result<(Sink, Stream), TransportError> {
    let host = url
        .host_str()
        .ok_or_else(|| TransportError::backend(io::Error::new(io::ErrorKind::InvalidInput, "relay url has no host")))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let stream: Box<dyn Io> = match proxy {
        Some(p) => p.tunnel(&host, port).await.map_err(TransportError::backend)?,
        None => Box::new(
            TcpStream::connect((host.as_str(), port))
                .await
                .map_err(TransportError::backend)?,
        ),
    };
    let (socket, _) = tokio_tungstenite::client_async_tls_with_config(url.as_str(), stream, None, None)
        .await
        .map_err(TransportError::backend)?;
    use futures_util::{StreamExt, TryStreamExt};
    let (tx, rx) = socket.split();
    let sink: Sink = Box::new(WsSink(tx));
    let stream: Stream = Box::pin(rx.map_ok(from_wire).map_err(TransportError::backend));
    Ok((sink, stream))
}

/// Opens each relay's websocket its own way: through the proxy its route
/// names, or straight. A relay without a route is refused (it is never added
/// to the pool, so this does not happen in practice). The table is shared
/// with the [`Pool`] built on it, which swaps it when routes change (see
/// [`Pool::reroute`]).
#[derive(Debug, Clone)]
pub struct RoutingTransport {
    routes: RouteTable,
}

/// Each relay and its proxy (`None`: straight), shared between a transport
/// and its pool.
type RouteTable = Arc<std::sync::RwLock<Vec<(String, Option<ProxyTransport>)>>>;

fn table(routes: Vec<(String, Option<ProxySpec>)>) -> Vec<(String, Option<ProxyTransport>)> {
    routes
        .into_iter()
        .map(|(relay, spec)| (relay, spec.map(ProxyTransport::new)))
        .collect()
}

/// The route of `url` in `routes`: `None` when it has none, `Some(None)`
/// when it goes straight.
fn route_in(routes: &[(String, Option<ProxyTransport>)], url: &str) -> Option<Option<ProxyTransport>> {
    routes
        .iter()
        .find(|(relay, _)| same_relay(relay, url))
        .map(|(_, p)| p.clone())
}

impl RoutingTransport {
    /// `routes`: relay address and its proxy (`None`: straight).
    pub fn new(routes: Vec<(String, Option<ProxySpec>)>) -> Self {
        RoutingTransport {
            routes: Arc::new(std::sync::RwLock::new(table(routes))),
        }
    }

    // Cloned out of the table, so no lock is held while connecting.
    fn route(&self, url: &Url) -> Option<Option<ProxyTransport>> {
        route_in(
            &self.routes.read().unwrap_or_else(std::sync::PoisonError::into_inner),
            url.as_str(),
        )
    }
}

/// Whether two relay addresses name the same relay, ignoring case and a
/// trailing slash (`wss://a`, `WSS://A/`). Routing and `publish_to` both use
/// it, so a relay that routes also receives what is sent to it by name.
fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/').eq_ignore_ascii_case(b.trim_end_matches('/'))
}

impl WebSocketTransport for RoutingTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        _mode: &'a nostr_sdk::pool::ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, std::result::Result<(Sink, Stream), TransportError>> {
        Box::pin(async move {
            let Some(proxy) = self.route(url) else {
                return Err(TransportError::backend(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "this relay has no route",
                )));
            };
            tokio::time::timeout(timeout, open_ws(url, proxy.as_ref()))
                .await
                .map_err(|_| {
                    TransportError::backend(io::Error::new(io::ErrorKind::TimedOut, "relay connection timed out"))
                })?
        })
    }
}

type Sink = WebSocketSink;
type Stream = WebSocketStream;
type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<Box<dyn Io>>>;

struct WsSink(futures_util::stream::SplitSink<Socket, Wire>);

/// Convert a received websocket message to the relay library's type.
pub fn from_wire(m: Wire) -> Message {
    match m {
        Wire::Text(t) => Message::Text(t.to_string()),
        Wire::Binary(b) => Message::Binary(b.to_vec()),
        Wire::Ping(b) => Message::Ping(b.to_vec()),
        Wire::Pong(b) => Message::Pong(b.to_vec()),
        Wire::Close(f) => Message::Close(f.map(|f| CloseFrame {
            code: f.code.into(),
            reason: f.reason.to_string(),
        })),
        // Raw frames are never produced while reading.
        Wire::Frame(f) => Message::Binary(f.into_payload().to_vec()),
    }
}

impl futures_util::Sink<Message> for WsSink {
    type Error = TransportError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx).map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(Wire::from(item))
            .map_err(TransportError::backend)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(TransportError::backend)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(TransportError::backend)
    }
}

impl WebSocketTransport for ProxyTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        _mode: &'a nostr_sdk::pool::ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, std::result::Result<(Sink, Stream), TransportError>> {
        Box::pin(async move {
            tokio::time::timeout(timeout, self.open(url)).await.map_err(|_| {
                TransportError::backend(io::Error::new(io::ErrorKind::TimedOut, "relay connection timed out"))
            })?
        })
    }
}

/// The relay pool the server transport runs on: a nostr client that connects
/// directly or through [`ProxyTransport`].
pub struct Pool {
    client: Arc<Client>,
    sink: Option<RelaySink>,
    /// The routes of a routed pool, shared with its transport.
    routes: Option<RouteTable>,
}

fn relay_err(e: impl fmt::Display) -> Error {
    Error::InvalidParams(format!("relay: {e}"))
}

#[cfg(feature = "contextvm")]
fn transport_err(e: impl fmt::Display) -> contextvm_sdk::Error {
    contextvm_sdk::Error::Transport(e.to_string())
}

#[cfg(feature = "contextvm")]
fn other_err(e: impl fmt::Display) -> contextvm_sdk::Error {
    contextvm_sdk::Error::Other(e.to_string())
}

/// Told how each relay did with each event sent: its address, whether it
/// accepted the event, and how long that took in milliseconds.
pub type RelaySink = Arc<dyn Fn(&str, bool, u64) + Send + Sync>;

impl Pool {
    pub fn new(keys: Keys, proxy: Option<ProxySpec>) -> Self {
        let builder = Client::builder().signer(keys);
        let client = match proxy {
            Some(spec) => builder.websocket_transport(ProxyTransport::new(spec)).build(),
            None => builder.build(),
        };
        Pool {
            client: Arc::new(client),
            sink: None,
            routes: None,
        }
    }

    /// A pool whose relays each go their own way (see [`RoutingTransport`]).
    pub fn routed(keys: Keys, routes: Vec<(String, Option<ProxySpec>)>) -> Self {
        let transport = RoutingTransport::new(routes);
        let table = transport.routes.clone();
        let client = Client::builder().signer(keys).websocket_transport(transport).build();
        Pool {
            client: Arc::new(client),
            sink: None,
            routes: Some(table),
        }
    }

    /// Give a routed pool new routes, moving only what changed: a relay whose
    /// proxy is different is dropped and connected again through the new one,
    /// a relay no longer listed is dropped, a new one is added and connected,
    /// and every other relay keeps its connection. A relay added again takes
    /// the pool's subscriptions with it.
    pub async fn reroute(&self, routes: Vec<(String, Option<ProxySpec>)>) -> Result<()> {
        let Some(shared) = &self.routes else {
            return Err(Error::InvalidParams("this relay pool does not route each relay".into()));
        };
        let next = table(routes);
        let before = std::mem::replace(
            &mut *shared.write().unwrap_or_else(std::sync::PoisonError::into_inner),
            next.clone(),
        );
        let spec = |r: Option<Option<ProxyTransport>>| r.map(|p| p.map(|t| t.spec));
        let current = self.client.relays().await;
        for url in current.keys() {
            let now = spec(route_in(&next, url.as_str()));
            if now == spec(route_in(&before, url.as_str())) {
                continue;
            }
            self.client.force_remove_relay(url).await.map_err(relay_err)?;
            if now.is_some() {
                self.client.add_relay(url).await.map_err(relay_err)?;
                self.client.connect_relay(url).await.map_err(relay_err)?;
            }
        }
        for (relay, _) in &next {
            if !current.keys().any(|u| same_relay(u.as_str(), relay)) {
                self.client.add_relay(relay).await.map_err(relay_err)?;
                self.client.connect_relay(relay).await.map_err(relay_err)?;
            }
        }
        Ok(())
    }

    pub fn client(&self) -> &Arc<Client> {
        &self.client
    }

    /// Report every relay's result for each event sent, whether it came
    /// before or after the send returned (see [`RelaySink`]).
    pub fn with_sink(mut self, sink: RelaySink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Send `event` to every relay (or only to `only`) and return as soon as
    /// one of them accepts it. The other relays keep trying in the background:
    /// a relay that hangs or is still connecting must never hold up a reply
    /// that a working relay has already delivered. Fails only when every
    /// relay refused it.
    #[cfg(feature = "contextvm")]
    async fn send_first_ok(&self, event: &Event, only: Option<&[String]>) -> contextvm_sdk::Result<EventId> {
        let relays = self.client.relays().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for (url, relay) in relays {
            if only.is_some_and(|only| !only.iter().any(|u| same_relay(u, url.as_str()))) {
                continue;
            }
            let (tx, event, sink) = (tx.clone(), event.clone(), self.sink.clone());
            tokio::spawn(async move {
                let started = Instant::now();
                let result = relay.send_event(&event).await;
                if let Some(sink) = sink {
                    sink(url.as_str(), result.is_ok(), started.elapsed().as_millis() as u64);
                }
                // The receiver is gone once one relay accepted: nothing to report.
                let _ = tx.send((url, result));
            });
        }
        drop(tx);
        let mut refused = Vec::new();
        while let Some((url, result)) = rx.recv().await {
            match result {
                Ok(_) => return Ok(event.id),
                Err(e) => refused.push(format!("{url}: {e}")),
            }
        }
        Err(transport_err(if refused.is_empty() {
            "no relay to send to".to_string()
        } else {
            format!("every relay refused the event ({})", refused.join("; "))
        }))
    }
}

#[cfg(feature = "contextvm")]
#[async_trait]
impl RelayPoolTrait for Pool {
    async fn connect(&self, relay_urls: &[String]) -> contextvm_sdk::Result<()> {
        for url in relay_urls {
            self.client.add_relay(url).await.map_err(transport_err)?;
        }
        self.client.connect().await;
        Ok(())
    }

    async fn disconnect(&self) -> contextvm_sdk::Result<()> {
        self.client.disconnect().await;
        Ok(())
    }

    async fn publish_event(&self, event: &Event) -> contextvm_sdk::Result<EventId> {
        self.send_first_ok(event, None).await
    }

    async fn publish(&self, builder: EventBuilder) -> contextvm_sdk::Result<EventId> {
        let event = self.sign(builder).await?;
        self.send_first_ok(&event, None).await
    }

    async fn sign(&self, builder: EventBuilder) -> contextvm_sdk::Result<Event> {
        self.client.sign_event_builder(builder).await.map_err(transport_err)
    }

    async fn signer(&self) -> contextvm_sdk::Result<Arc<dyn NostrSigner>> {
        self.client.signer().await.map_err(other_err)
    }

    fn notifications(&self) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    async fn public_key(&self) -> contextvm_sdk::Result<PublicKey> {
        self.signer().await?.get_public_key().await.map_err(other_err)
    }

    async fn subscribe(&self, filters: Vec<Filter>) -> contextvm_sdk::Result<()> {
        for filter in filters {
            self.client.subscribe(filter, None).await.map_err(transport_err)?;
        }
        Ok(())
    }

    async fn publish_to(&self, urls: &[String], builder: EventBuilder) -> contextvm_sdk::Result<EventId> {
        let event = self.sign(builder).await?;
        self.send_first_ok(&event, Some(urls)).await
    }

    async fn fetch_events(&self, filters: Vec<Filter>, timeout: Duration) -> contextvm_sdk::Result<Vec<Event>> {
        let mut all = Vec::new();
        for filter in filters {
            all.extend(self.client.fetch_events(filter, timeout).await.map_err(transport_err)?);
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{connect_proxy, socks5_proxy, CERT};
    use futures_util::{SinkExt, StreamExt};
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::Kind;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn test_roots() -> Arc<rustls::ClientConfig> {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from_pem_slice(CERT).unwrap())
            .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    }

    fn spec(s: &str) -> ProxySpec {
        parse_proxy(s).unwrap().unwrap()
    }

    #[test]
    fn proxy_urls_are_parsed_strictly() {
        assert_eq!(parse_proxy("").unwrap(), None);
        let s = spec("socks5://127.0.0.1:9050");
        assert_eq!(
            (s.kind, s.host.as_str(), s.port, s.auth),
            (ProxyKind::Socks5, "127.0.0.1", 9050, None)
        );
        assert_eq!(spec("socks5h://tor:9050").kind, ProxyKind::Socks5);
        assert_eq!(spec("http://proxy.lan:3128/").kind, ProxyKind::Http);
        let s = spec("https://us%40r:p%3Ass@proxy.example:443");
        assert_eq!(s.kind, ProxyKind::Https);
        assert_eq!(s.auth, Some(("us@r".to_string(), "p:ss".to_string())));
        assert_eq!(
            spec("socks5://only@h:1").auth,
            Some(("only".to_string(), String::new()))
        );
        assert_eq!(spec("socks5://[::1]:1080").host, "::1");
        assert!(!format!("{:?}", spec("socks5://u:secret@h:1")).contains("secret"));

        let bad = [
            ("socks5://host", "port"),
            ("ftp://h:1", "scheme"),
            ("http://h:1/path", "only scheme"),
            ("http://h:1?x=1", "only scheme"),
            ("http://h:1#x", "only scheme"),
            ("socks5://a b:1", "spaces"),
            ("not a url", "spaces"),
            ("nourl", "not a valid url"),
            ("socks5://:1", "not a valid url"),
            ("socks5://u%ff:p@h:1", "UTF-8"),
            ("socks5://u%zz:p@h:1", "UTF-8"),
            ("socks5://u%f:p@h:1", "UTF-8"),
        ];
        for (input, expect) in bad {
            let e = parse_proxy(input).unwrap_err().to_string();
            assert!(e.contains(expect), "{input}: {e}");
        }
        assert!(parse_proxy(&format!("socks5://{}:1", "a".repeat(400)))
            .unwrap_err()
            .to_string()
            .contains("short"));
        assert!(parse_proxy("data:text/plain,x")
            .unwrap_err()
            .to_string()
            .contains("scheme"));
    }

    #[test]
    fn passwords_are_redacted() {
        assert_eq!(redact("socks5://u:secret@h:1"), "socks5://u:***@h:1");
        assert_eq!(redact("socks5://h:1"), "socks5://h:1");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn every_websocket_message_converts() {
        use tokio_tungstenite::tungstenite::protocol::frame::{coding::CloseCode, CloseFrame as Frame, Frame as Raw};
        assert_eq!(from_wire(Wire::text("a")), Message::Text("a".into()));
        assert_eq!(from_wire(Wire::binary(vec![1])), Message::Binary(vec![1]));
        assert_eq!(from_wire(Wire::Ping(vec![2].into())), Message::Ping(vec![2]));
        assert_eq!(from_wire(Wire::Pong(vec![3].into())), Message::Pong(vec![3]));
        assert_eq!(from_wire(Wire::Close(None)), Message::Close(None));
        let close = Wire::Close(Some(Frame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        }));
        assert_eq!(
            from_wire(close),
            Message::Close(Some(CloseFrame {
                code: 1000,
                reason: "bye".into()
            }))
        );
        let raw = Raw::message(
            vec![4],
            tokio_tungstenite::tungstenite::protocol::frame::coding::OpCode::Data(
                tokio_tungstenite::tungstenite::protocol::frame::coding::Data::Binary,
            ),
            true,
        );
        assert_eq!(from_wire(Wire::Frame(raw)), Message::Binary(vec![4]));
    }

    #[tokio::test]
    async fn http_connect_reports_every_kind_of_refusal() {
        async fn reply(bytes: &'static [u8]) -> io::Result<TcpStream> {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(
                    req.starts_with("CONNECT [::1]:7 HTTP/1.1\r\nHost: [::1]:7\r\n"),
                    "{req}"
                );
                s.write_all(bytes).await.unwrap();
            });
            http_connect(TcpStream::connect(addr).await.unwrap(), "::1", 7, None).await
        }
        assert!(reply(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok());
        assert!(reply(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap_err()
            .to_string()
            .contains("status 403"));
        assert!(reply(b"HTTP/1.1 200").await.unwrap_err().to_string().contains("closed"));
        let long: &'static [u8] = Box::leak(vec![b'x'; MAX_CONNECT_REPLY + 10].into_boxed_slice());
        assert!(reply(long).await.unwrap_err().to_string().contains("too long"));
    }

    /// Send a subscription through `t` to a mock relay and wait for its EOSE.
    async fn round_trip(t: &impl WebSocketTransport, relay: &str) {
        let url = Url::parse(relay).unwrap();
        let (mut tx, mut rx) = t
            .connect(&url, &nostr_sdk::pool::ConnectionMode::Direct, Duration::from_secs(5))
            .await
            .unwrap();
        tx.send(Message::Text(r#"["REQ","s",{"limit":1}]"#.into()))
            .await
            .unwrap();
        // Nothing is stored, so the first answer is the end of stored events.
        let first = rx.next().await.unwrap().unwrap();
        assert!(matches!(&first, Message::Text(t) if t.contains("EOSE")), "{first:?}");
        tx.close().await.unwrap();
    }

    #[tokio::test]
    async fn each_relay_takes_its_own_route() {
        let (a, b) = (MockRelay::run().await.unwrap(), MockRelay::run().await.unwrap());
        let (a, b) = (a.url().await.to_string(), b.url().await.to_string());
        let (p, _t) = socks5_proxy(None).await;
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // a goes through the proxy (written with another case and no trailing
        // slash), b straight.
        let t = RoutingTransport::new(vec![
            (
                a.to_uppercase().trim_end_matches('/').to_string(),
                Some(spec(&format!("socks5://127.0.0.1:{p}"))),
            ),
            (b.clone(), None),
        ]);
        round_trip(&t, &a).await;
        round_trip(&t, &b).await;
        assert!(t.support_ping());
        // Through a proxy that is not there, a fails although it is reachable
        // straight: it really goes through its proxy. b is untouched.
        let t = RoutingTransport::new(vec![
            (a.clone(), Some(spec(&format!("socks5://127.0.0.1:{dead}")))),
            (b.clone(), None),
        ]);
        let mode = nostr_sdk::pool::ConnectionMode::Direct;
        assert!(t
            .connect(&Url::parse(&a).unwrap(), &mode, Duration::from_secs(5))
            .await
            .is_err());
        round_trip(&t, &b).await;
        // A relay without a route is refused, never connected some other way.
        let t = RoutingTransport::new(vec![(b.clone(), None)]);
        let err = t
            .connect(&Url::parse(&a).unwrap(), &mode, Duration::from_secs(5))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("no route"), "{err}");
        // A relay that never answers times out.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://127.0.0.1:{}", silent.local_addr().unwrap().port());
        let t = RoutingTransport::new(vec![(url.clone(), None)]);
        let err = t
            .connect(&Url::parse(&url).unwrap(), &mode, Duration::from_millis(200))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("timed out"), "{err}");
        drop(silent);
        // Straight to a port nobody listens on fails at once.
        let t = RoutingTransport::new(vec![(format!("ws://127.0.0.1:{dead}"), None)]);
        let url = Url::parse(&format!("ws://127.0.0.1:{dead}")).unwrap();
        assert!(t.connect(&url, &mode, Duration::from_secs(5)).await.is_err());
    }

    #[tokio::test]
    async fn a_routed_pool_connects_its_relays() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let pool = Pool::routed(Keys::generate(), vec![(url.clone(), None)]);
        pool.connect(std::slice::from_ref(&url)).await.unwrap();
        let connected = async {
            loop {
                if pool.client().relays().await.values().any(|r| r.is_connected()) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), connected).await.unwrap();
        pool.disconnect().await.unwrap();
    }

    /// A port in front of `target` that counts the connections made through it.
    async fn counted(target: &str) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let to = Url::parse(target).unwrap();
        let to = (to.host_str().unwrap().to_string(), to.port().unwrap());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://127.0.0.1:{}", l.local_addr().unwrap().port());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = count.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut t = TcpStream::connect((to.0.as_str(), to.1)).await.unwrap();
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut t).await;
                });
            }
        });
        (url, count)
    }

    async fn connected(pool: &Pool, url: &str) {
        let wait = async {
            loop {
                let relays = pool.client().relays().await;
                if relays
                    .iter()
                    .any(|(u, r)| same_relay(u.as_str(), url) && r.is_connected())
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait).await.unwrap();
    }

    #[tokio::test]
    async fn new_routes_move_only_the_relays_whose_route_changed() {
        let (ra, rb, rc) = (
            MockRelay::run().await.unwrap(),
            MockRelay::run().await.unwrap(),
            MockRelay::run().await.unwrap(),
        );
        let ((a, na), (b, nb)) = (
            counted(&ra.url().await.to_string()).await,
            counted(&rb.url().await.to_string()).await,
        );
        let (c, nc) = counted(&rc.url().await.to_string()).await;
        let (p1, t1) = socks5_proxy(None).await;
        let (p2, _t2) = socks5_proxy(None).await;
        let via = |p: u16| Some(spec(&format!("socks5://127.0.0.1:{p}")));
        let pool = Pool::routed(Keys::generate(), vec![(a.clone(), None), (b.clone(), via(p1))]);
        pool.connect(&[a.clone(), b.clone()]).await.unwrap();
        pool.subscribe(vec![Filter::new().kind(Kind::TextNote)]).await.unwrap();
        let mut notes = pool.notifications();
        connected(&pool, &a).await;
        connected(&pool, &b).await;
        let count = |n: &Arc<std::sync::atomic::AtomicUsize>| n.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!((count(&na), count(&nb)), (1, 1));

        // b moves to the second proxy; the first one takes no new connection,
        // so b can only come back through the second. a is not touched.
        t1.abort();
        pool.reroute(vec![(a.clone(), None), (b.clone(), via(p2))])
            .await
            .unwrap();
        connected(&pool, &b).await;
        assert_eq!((count(&na), count(&nb)), (1, 2));
        // b still has the subscription: a note only b has reaches the pool.
        let writer = Client::builder().signer(Keys::generate()).build();
        writer.add_relay(rb.url().await).await.unwrap();
        writer.connect().await;
        let note = writer
            .send_event_builder(EventBuilder::text_note("moved"))
            .await
            .unwrap();
        let from_b = async {
            let mut from = None;
            while from.is_none() {
                if let Ok(RelayPoolNotification::Event { relay_url, event, .. }) = notes.recv().await {
                    from = (event.id == *note.id()).then_some(relay_url);
                }
            }
            from.unwrap()
        };
        let from = tokio::time::timeout(Duration::from_secs(10), from_b).await.unwrap();
        assert!(same_relay(from.as_str(), &b), "{from}");

        // Same routes again: nothing moves.
        pool.reroute(vec![(a.clone(), None), (b.clone(), via(p2))])
            .await
            .unwrap();
        // a leaves, c joins; b keeps its connection.
        pool.reroute(vec![(b.clone(), via(p2)), (c.clone(), None)])
            .await
            .unwrap();
        connected(&pool, &c).await;
        let relays: Vec<String> = pool.client().relays().await.keys().map(|u| u.to_string()).collect();
        assert!(!relays.iter().any(|u| same_relay(u, &a)), "{relays:?}");
        assert_eq!((count(&na), count(&nb), count(&nc)), (1, 2, 1));

        // An address the relay library refuses, and a pool that does not route.
        let err = pool.reroute(vec![("not a url".into(), None)]).await.unwrap_err();
        assert!(err.to_string().contains("relay:"), "{err}");
        let plain = Pool::new(Keys::generate(), None);
        assert!(plain.reroute(Vec::new()).await.is_err());
        pool.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn every_proxy_kind_carries_relay_traffic() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();

        let (p, _t) = socks5_proxy(None).await;
        round_trip(&ProxyTransport::new(spec(&format!("socks5://127.0.0.1:{p}"))), &url).await;
        // Names are resolved by the proxy (as Tor needs for .onion relays).
        let by_name = url.replace("127.0.0.1", "localhost");
        round_trip(&ProxyTransport::new(spec(&format!("socks5://127.0.0.1:{p}"))), &by_name).await;
        // A client that gives up before sending a request.
        let (hp, _h) = connect_proxy(false, None).await;
        drop(TcpStream::connect(("127.0.0.1", hp)).await.unwrap());
        let (p, _t) = socks5_proxy(Some(("alice", "pw"))).await;
        round_trip(
            &ProxyTransport::new(spec(&format!("socks5://alice:pw@127.0.0.1:{p}"))),
            &url,
        )
        .await;
        let wrong = ProxyTransport::new(spec(&format!("socks5://alice:nope@127.0.0.1:{p}")));
        assert!(wrong.tunnel("127.0.0.1", 1).await.is_err());

        let (p, _t) = connect_proxy(false, None).await;
        round_trip(&ProxyTransport::new(spec(&format!("http://127.0.0.1:{p}"))), &url).await;
        let token = base64::engine::general_purpose::STANDARD.encode("bob:pw");
        let (p, _t) = connect_proxy(false, Some(Box::leak(token.into_boxed_str()))).await;
        round_trip(
            &ProxyTransport::new(spec(&format!("http://bob:pw@127.0.0.1:{p}"))),
            &url,
        )
        .await;
        let denied = ProxyTransport::new(spec(&format!("http://bob:no@127.0.0.1:{p}")));
        assert!(denied
            .tunnel("127.0.0.1", 1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("407"));

        let (p, _t) = connect_proxy(true, None).await;
        let https = spec(&format!("https://localhost:{p}"));
        round_trip(&ProxyTransport::with_proxy_tls(https.clone(), test_roots()), &url).await;
        // The real roots do not trust the test certificate.
        assert!(ProxyTransport::new(https).tunnel("127.0.0.1", 1).await.is_err());
        let nameless = ProxySpec {
            host: "bad host".into(),
            ..spec("https://h:1")
        };
        let refused = ProxyTransport::new(ProxySpec {
            port: p,
            host: "127.0.0.1".into(),
            ..spec("https://h:1")
        });
        assert!(
            refused.tunnel("x", 1).await.is_err(),
            "certificate is for localhost only"
        );
        // Proxies that are not there.
        let dead = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        for kind in ["http", "https"] {
            let t = ProxyTransport::new(spec(&format!("{kind}://127.0.0.1:{dead}")));
            assert!(t.tunnel("x", 1).await.is_err());
        }
        assert!(ProxyTransport::new(nameless).tunnel("x", 1).await.is_err());
    }

    #[tokio::test]
    async fn connection_failures_are_transport_errors() {
        // A proxy that accepts and then says nothing.
        // The kernel completes the handshake for a listener that never accepts.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = silent.local_addr().unwrap().port();
        let t = ProxyTransport::new(spec(&format!("http://127.0.0.1:{p}")));
        let mode = nostr_sdk::pool::ConnectionMode::Direct;
        let url = Url::parse("ws://relay.example").unwrap();
        let e = t.connect(&url, &mode, Duration::from_millis(200)).await.err().unwrap();
        assert!(e.to_string().contains("timed out"), "{e}");
        let nohost = Url::parse("x:relay").unwrap();
        assert!(t
            .connect(&nohost, &mode, Duration::from_secs(1))
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("no host"));
        // The tunnel opens but the far side is not a websocket server.
        let (p, _t) = connect_proxy(false, None).await;
        let not_ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = not_ws.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = not_ws.accept().await.unwrap();
            let _ = s.write_all(b"nope\r\n\r\n").await;
        });
        let t = ProxyTransport::new(spec(&format!("http://127.0.0.1:{p}")));
        let url = Url::parse(&format!("ws://{addr}")).unwrap();
        assert!(t.connect(&url, &mode, Duration::from_secs(2)).await.is_err());
        let _ = Kind::TextNote;
    }

    #[tokio::test]
    async fn the_pool_works_directly_and_through_a_proxy() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let (p, _t) = socks5_proxy(None).await;
        for proxy in [None, Some(spec(&format!("socks5://127.0.0.1:{p}")))] {
            let keys = Keys::generate();
            let pool = Pool::new(keys.clone(), proxy);
            let mut notes = pool.notifications();
            pool.connect(std::slice::from_ref(&url)).await.unwrap();
            assert_eq!(pool.public_key().await.unwrap(), keys.public_key());
            assert_eq!(
                pool.signer().await.unwrap().get_public_key().await.unwrap(),
                keys.public_key()
            );
            pool.subscribe(vec![Filter::new().author(keys.public_key())])
                .await
                .unwrap();
            let signed = pool.sign(EventBuilder::text_note("a")).await.unwrap();
            pool.publish_event(&signed).await.unwrap();
            pool.publish(EventBuilder::text_note("b")).await.unwrap();
            pool.publish_to(std::slice::from_ref(&url), EventBuilder::text_note("c"))
                .await
                .unwrap();
            let got = pool
                .fetch_events(vec![Filter::new().author(keys.public_key())], Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(got.len(), 3);
            assert!(tokio::time::timeout(Duration::from_secs(5), notes.recv()).await.is_ok());
            pool.disconnect().await.unwrap();
            assert!(pool.connect(&["not a url".to_string()]).await.is_err());
        }
        // Without a signer the key cannot be read.
        let unsigned = Pool {
            client: Arc::new(Client::builder().build()),
            sink: None,
            routes: None,
        };
        assert!(unsigned.public_key().await.is_err());
        assert!(unsigned.sign(EventBuilder::text_note("x")).await.is_err());
        assert!(unsigned.publish(EventBuilder::text_note("x")).await.is_err());
        assert!(unsigned
            .publish_event(&EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap())
            .await
            .is_err());
        assert!(unsigned
            .publish_to(std::slice::from_ref(&url), EventBuilder::text_note("x"))
            .await
            .is_err());
        assert!(unsigned.subscribe(vec![Filter::new()]).await.is_err());
        assert!(unsigned
            .fetch_events(vec![Filter::new()], Duration::from_millis(100))
            .await
            .is_err());
    }

    /// A relay that answers every event with `OK false`.
    async fn refusing_relay() -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    while let Some(Ok(frame)) = ws.next().await {
                        let Wire::Text(text) = frame else { continue };
                        let msg: serde_json::Value = serde_json::from_str(&text).unwrap();
                        if msg[0] == "EVENT" {
                            let ok = serde_json::json!(["OK", msg[1]["id"], false, "blocked: test relay"]);
                            ws.send(Wire::Text(ok.to_string().into())).await.unwrap();
                        }
                    }
                });
            }
        });
        (url, task)
    }

    #[tokio::test]
    async fn every_relay_reports_how_it_did_with_each_event() {
        let good = MockRelay::run().await.unwrap();
        let good_url = good.url().await.to_string();
        let (bad_url, _bad) = refusing_relay().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink: RelaySink = Arc::new(move |relay, ok, _ms| {
            let _ = tx.send((relay.trim_end_matches('/').to_string(), ok));
        });
        let pool = Pool::new(Keys::generate(), None).with_sink(sink);
        pool.connect(&[good_url.clone(), bad_url.clone()]).await.unwrap();
        pool.client().wait_for_connection(Duration::from_secs(5)).await;
        pool.publish(EventBuilder::text_note("a")).await.unwrap();
        // Each relay reports, the slower one possibly after the send has returned.
        let mut got = vec![rx.recv().await.unwrap(), rx.recv().await.unwrap()];
        got.sort();
        let mut want = vec![
            (good_url.trim_end_matches('/').to_string(), true),
            (bad_url.trim_end_matches('/').to_string(), false),
        ];
        want.sort();
        assert_eq!(got, want);
        pool.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn a_reply_is_sent_once_any_relay_accepts_it() {
        let good = MockRelay::run().await.unwrap();
        let good_url = good.url().await.to_string();
        let (bad_url, _bad) = refusing_relay().await;
        let keys = Keys::generate();

        // One relay refusing does not fail the send; the other accepts it.
        let pool = Pool::new(keys.clone(), None);
        pool.connect(&[good_url.clone(), bad_url.clone()]).await.unwrap();
        pool.client().wait_for_connection(Duration::from_secs(5)).await;
        // The refusing relay ignores everything but events (a REQ here).
        pool.subscribe(vec![Filter::new().author(keys.public_key())])
            .await
            .unwrap();
        let signed = pool.sign(EventBuilder::text_note("a")).await.unwrap();
        assert_eq!(pool.publish_event(&signed).await.unwrap(), signed.id);
        // Sending to named relays leaves the others out.
        let only_bad = pool
            .publish_to(std::slice::from_ref(&bad_url), EventBuilder::text_note("b"))
            .await;
        assert!(only_bad.unwrap_err().to_string().contains("every relay refused"));
        assert!(pool
            .publish_to(&[format!("{good_url}/")], EventBuilder::text_note("c"))
            .await
            .is_ok());
        // The name is matched ignoring case, as routing matches it.
        assert!(pool
            .publish_to(&[good_url.to_ascii_uppercase()], EventBuilder::text_note("c2"))
            .await
            .is_ok());
        assert!(pool
            .publish_to(&["ws://127.0.0.1:9".to_string()], EventBuilder::text_note("d"))
            .await
            .unwrap_err()
            .to_string()
            .contains("no relay to send to"));
        pool.disconnect().await.unwrap();

        // Only when every relay refuses does the send fail.
        let refused = Pool::new(keys, None);
        refused.connect(std::slice::from_ref(&bad_url)).await.unwrap();
        refused.client().wait_for_connection(Duration::from_secs(5)).await;
        let e = refused.publish(EventBuilder::text_note("e")).await.unwrap_err();
        assert!(e.to_string().contains("blocked: test relay"), "{e}");
        refused.disconnect().await.unwrap();
    }
}
