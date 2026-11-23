//! Relay networking shared by the deadhop services: proxy addresses and
//! tunnels, a websocket transport that routes each relay its own way, a relay
//! pool that returns as soon as one relay accepts an event, and classifiers
//! for the hosts relays and proxies live on. Moved verbatim from deadhop's
//! server, which re-exports everything at its old paths.

pub mod error;
pub mod hosts;
pub mod relay;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
