//! ContextVM plumbing every deadhop service repeats: the MCP handshake done
//! locally (so no remote peer can take part in it or break it), the identity
//! of a request's sender, and the event kind. Moved from deadhop's server,
//! which re-exports everything at its old paths.

pub mod caller;
pub mod handshake;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

/// The event kind ContextVM requests and replies use (ephemeral).
pub const CTXVM_KIND: u16 = 25910;
