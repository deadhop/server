//! The network engine of a deadhop service: its network settings and lanes,
//! the routing rules, the proxy pool and its strategies, relay health, I2P
//! name lookups, the privacy audit, and the runtime that ties them to a host.
//! Moved verbatim from deadhop's server, which re-exports everything at its
//! old paths.

pub mod error;
#[cfg(test)]
mod hosttests;
#[cfg(test)]
mod goldentests;
pub mod i2p;
pub mod netruntime;
pub mod network;
pub mod privacy;
pub mod proxypool;
pub mod relayhealth;
pub mod routes;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod tools;
