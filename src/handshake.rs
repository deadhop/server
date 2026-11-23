//! Completes the MCP handshake locally, before any network message is read.
//! The wrapper lives in the `deadhop-cvm` crate (see its `handshake` module);
//! this service's own identity in that handshake stays here.

pub use deadhop_cvm::handshake::LocalHandshake;

/// Request id of the synthetic `initialize`. Real requests can never carry
/// it: the Nostr transport replaces every inbound id with a 64-hex event id.
pub const LOCAL_INIT_ID: &str = "deadhop-local-init";

/// The handshake as this service performs it: its own request id, client
/// name and version.
pub fn local<T>(inner: T) -> LocalHandshake<T> {
    LocalHandshake::new(inner, LOCAL_INIT_ID, "deadhop-local", env!("CARGO_PKG_VERSION"))
}

/// The in-memory transport, where the tests of other modules look for it.
#[cfg(test)]
pub(crate) mod tests {
    pub use deadhop_cvm::testing::scripted;
}
