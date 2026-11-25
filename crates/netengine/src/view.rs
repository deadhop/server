//! The network views' wire types: what `get_network` and `update_network`
//! take and return, the same on every service that serves them (the payment
//! service's dashboard, the standalone console).

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::network::ProxyPatch;

/// One of the service's keys and what it is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct KeyInfo {
    /// Its id, such as `invoices` or `admin`.
    pub id: String,
    /// What the dashboard calls it.
    pub label: String,
    /// Hex public key; empty until the service has loaded it.
    pub pubkey: String,
    /// The tools this key serves (`*`: all of them).
    pub tools: Vec<String>,
    /// Only operators are served on this key.
    pub operators_only: bool,
    /// The relays it connects to now.
    pub relays: Vec<String>,
}

/// The network part of the settings, for the network views (core's dashboard
/// and the standalone console): what `get_network` and `update_network` return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct NetworkView {
    /// Live values (proxy passwords hidden).
    pub settings: crate::network::NetworkSettings,
    /// Values from the environment, used where nothing is overridden.
    pub defaults: crate::network::NetworkSettings,
    /// Names of the network settings changed from a dashboard.
    pub overridden: Vec<String>,
    /// The bitcoin network (`bitcoin`, `testnet`, `signet` or `regtest`): on
    /// `bitcoin` a relay must use TLS unless it is on this machine or an overlay network.
    pub chain: String,
    /// The lanes (this service's keys) that relays and proxies are assigned to.
    pub keys: Vec<KeyInfo>,
    pub proxy_locked: bool,
    pub restart_pending: bool,
    pub warnings: Vec<String>,
}

/// Changes to the network settings; anything left out stays as it is.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkPatch {
    #[serde(default)]
    pub relays: Option<Vec<String>>,
    /// Replaces the whole map of relays used by only some keys.
    #[serde(default)]
    pub relay_keys: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// Replaces the whole map of relay names.
    #[serde(default)]
    pub relay_names: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub proxies: Option<ProxyPatch>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateNetworkParams {
    /// Only the network settings to change.
    pub patch: NetworkPatch,
}
