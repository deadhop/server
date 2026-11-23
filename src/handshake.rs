//! Completes the MCP handshake locally, before any network message is read.
//!
//! The MCP library finishes its handshake on the first message it receives and
//! gives up for good if that message is not a well-formed `initialize`. On a
//! transport shared by every Nostr user, that would let one anonymous stray
//! message silence the service. This wrapper feeds the library a synthetic
//! `initialize` exchange itself and swallows the reply, so remote peers can
//! never take part in (or break) the handshake.

use std::collections::VecDeque;
use std::future::Future;

use rmcp::model::{JsonRpcMessage, NumberOrString};
use rmcp::service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use serde_json::json;

/// Request id of the synthetic `initialize`. Real requests can never carry
/// it: the Nostr transport replaces every inbound id with a 64-hex event id.
pub const LOCAL_INIT_ID: &str = "deadhop-local-init";

/// The handshake as this service performs it: its own request id, client
/// name and version.
pub fn local<T>(inner: T) -> LocalHandshake<T> {
    LocalHandshake::new(inner, LOCAL_INIT_ID, "deadhop-local", env!("CARGO_PKG_VERSION"))
}

/// Transport wrapper that performs the handshake on behalf of the peer.
pub struct LocalHandshake<T> {
    inner: T,
    pending: VecDeque<RxJsonRpcMessage<RoleServer>>,
    init_id: String,
}

impl<T> LocalHandshake<T> {
    /// `init_id` is the request id of the synthetic `initialize` (one no real
    /// request can carry); `client_name` and `client_version` are what the
    /// service reports as the client of its own handshake.
    pub fn new(inner: T, init_id: &str, client_name: &str, client_version: &str) -> Self {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": client_name, "version": client_version }
            }
        });
        let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let pending = [initialize, initialized]
            .into_iter()
            .map(|m| serde_json::from_value(m).expect("static handshake messages are valid"))
            .collect();
        LocalHandshake {
            inner,
            pending,
            init_id: init_id.to_string(),
        }
    }
}

fn is_local_reply(item: &TxJsonRpcMessage<RoleServer>, init_id: &str) -> bool {
    let id = match item {
        JsonRpcMessage::Response(r) => Some(&r.id),
        JsonRpcMessage::Error(e) => e.id.as_ref(),
        _ => None,
    };
    matches!(id, Some(NumberOrString::String(s)) if s.as_ref() == init_id)
}

impl<T: Transport<RoleServer>> Transport<RoleServer> for LocalHandshake<T> {
    type Error = T::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // The reply to our own `initialize` has no recipient.
        let forward = if is_local_reply(&item, &self.init_id) {
            None
        } else {
            Some(self.inner.send(item))
        };
        async move {
            match forward {
                Some(sending) => sending.await,
                None => Ok(()),
            }
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        match self.pending.pop_front() {
            Some(local) => Some(local),
            None => self.inner.receive().await,
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rmcp::model::{ClientRequest, ErrorCode, ErrorData, JsonRpcError, JsonRpcVersion2_0};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    /// In-memory transport: tests push inbound messages and read what was sent.
    pub struct Scripted {
        pub inbound: mpsc::UnboundedReceiver<RxJsonRpcMessage<RoleServer>>,
        pub sent: Arc<Mutex<Vec<serde_json::Value>>>,
        pub closed: Arc<Mutex<bool>>,
    }

    pub type Handle = (
        mpsc::UnboundedSender<RxJsonRpcMessage<RoleServer>>,
        Arc<Mutex<Vec<serde_json::Value>>>,
        Arc<Mutex<bool>>,
    );

    pub fn scripted() -> (Scripted, Handle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(Mutex::new(false));
        (
            Scripted {
                inbound: rx,
                sent: sent.clone(),
                closed: closed.clone(),
            },
            (tx, sent, closed),
        )
    }

    impl Transport<RoleServer> for Scripted {
        type Error = std::io::Error;
        fn send(
            &mut self,
            item: TxJsonRpcMessage<RoleServer>,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            self.sent.lock().unwrap().push(serde_json::to_value(&item).unwrap());
            std::future::ready(Ok(()))
        }
        async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
            self.inbound.recv().await
        }
        async fn close(&mut self) -> Result<(), Self::Error> {
            *self.closed.lock().unwrap() = true;
            Ok(())
        }
    }

    pub fn rx(value: serde_json::Value) -> RxJsonRpcMessage<RoleServer> {
        serde_json::from_value(value).unwrap()
    }

    /// The handshake of some service: its id, name and version are its own.
    const INIT: &str = "test-local-init";

    fn wrap<T>(inner: T) -> LocalHandshake<T> {
        LocalHandshake::new(inner, INIT, "test-local", "9.9.9")
    }

    fn reply(id: &str) -> TxJsonRpcMessage<RoleServer> {
        serde_json::from_value(json!({ "jsonrpc": "2.0", "id": id, "result": {} })).unwrap()
    }

    #[tokio::test]
    async fn yields_the_handshake_first_then_the_network() {
        let (inner, (tx, _, _)) = scripted();
        let mut t = wrap(inner);
        tx.send(rx(
            json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 1 } }),
        ))
        .unwrap();
        drop(tx);

        let first = t.receive().await.unwrap();
        assert!(
            matches!(&first, JsonRpcMessage::Request(r) if matches!(r.request, ClientRequest::InitializeRequest(_)))
        );
        assert!(matches!(t.receive().await.unwrap(), JsonRpcMessage::Notification(_)));
        // Only now does a remote message get through.
        assert!(matches!(t.receive().await.unwrap(), JsonRpcMessage::Notification(_)));
        assert!(t.receive().await.is_none());
    }

    #[tokio::test]
    async fn swallows_replies_to_the_local_handshake_only() {
        let (inner, (_tx, sent, closed)) = scripted();
        let mut t = wrap(inner);

        t.send(reply(INIT)).await.unwrap();
        let failed = JsonRpcMessage::Error(JsonRpcError {
            jsonrpc: JsonRpcVersion2_0,
            id: Some(NumberOrString::String(INIT.into())),
            error: ErrorData::new(ErrorCode(-32603), "x", None),
        });
        t.send(failed).await.unwrap();
        assert!(sent.lock().unwrap().is_empty());

        t.send(reply("a".repeat(64).as_str())).await.unwrap();
        t.send(serde_json::from_value(json!({ "jsonrpc": "2.0", "id": 7, "result": {} })).unwrap())
            .await
            .unwrap();
        let no_id = JsonRpcMessage::Error(JsonRpcError {
            jsonrpc: JsonRpcVersion2_0,
            id: None,
            error: ErrorData::new(ErrorCode(-32700), "parse", None),
        });
        t.send(no_id).await.unwrap();
        t.send(
            serde_json::from_value(json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(sent.lock().unwrap().len(), 4);

        t.close().await.unwrap();
        assert!(*closed.lock().unwrap());
    }
}
