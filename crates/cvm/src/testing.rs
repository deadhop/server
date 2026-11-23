//! An in-memory MCP transport for tests. Compiled for this crate's own tests
//! and, behind the `test-support` feature, for the tests of the services that
//! use it. Never part of a release build.

use std::future::Future;
use std::sync::{Arc, Mutex};

use rmcp::service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
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
