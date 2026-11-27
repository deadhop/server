//! deadhop: on-chain bitcoin payments served only over ContextVM (MCP over Nostr).
pub mod app;
pub mod config;
pub mod db;
pub mod electrum;
pub mod error;
pub mod handshake;
pub mod i2p;
pub mod invoicekeys;
pub mod keyholder;
pub mod keys;
pub mod manage;
pub mod mcp;
pub mod nethost;
pub mod netruntime;
pub mod network;
#[cfg(test)]
mod pooltests;
pub mod pow;
pub mod privacy;
pub mod proxypool;
pub mod ratelimit;
pub mod relay;
pub mod relayhealth;
pub mod routes;
pub mod service;
pub mod settings;
#[cfg(test)]
mod snapshot;
pub mod wallet;
