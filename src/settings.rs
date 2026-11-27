//! Settings an operator may change at runtime from the dashboard.
//!
//! The environment supplies the defaults; changes made remotely are stored as
//! overrides in the database and win over the environment until reset.
//! Anything that decides where money goes or whom the service trusts (the
//! xpub, network, Electrum server, operator list, data directory) is
//! deliberately not here: a stolen operator key must not be able to redirect
//! payments or lock the owner out.

use std::collections::BTreeMap;

use bitcoin::Network;
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::config::{is_loopback, is_loopback_host, is_overlay_host, MAX_MONEY_SAT};
use crate::error::{Error, Result};
use crate::network::{keep, take, within, NetworkSettings, Topology};
use deadhop_netengine::legacy;
// The network part of the settings lives in `network.rs`; these keep their old paths.
pub use crate::network::{
    same_relay, OfflinePolicy, ProxyEntry, ProxyEntryInput, ProxyGroup, ProxyPatch, ProxySettings, Strategy,
};
pub use crate::routes::Destination;

/// Inclusive bounds shared by the environment loader and runtime changes, so
/// the two can never disagree about what is valid.
pub mod bounds {
    pub const POW_BITS: (u64, u64) = (0, 64);
    pub const POW_WINDOW_SECS: (u64, u64) = (30, 3_600);
    pub const MIN_CONFIRMATIONS: (u64, u64) = (1, 144);
    pub const EXPIRY_SECS: (u64, u64) = (60, 30 * 86_400);
    pub const AMOUNT_SAT: (u64, u64) = (1, super::MAX_MONEY_SAT);
    pub const MAX_OPEN_INVOICES: (u64, u64) = (1, 100_000);
    pub const MAX_INVOICES_PER_DAY: (u64, u64) = (1, 1_000_000);
    pub const RATE_CREATE: (u64, u64) = (1, 100_000);
    pub const RATE_REQUESTS: (u64, u64) = (1, 1_000_000);
    pub const POLL_SECS: (u64, u64) = (1, 3_600);
    pub const LATE_GRACE_SECS: (u64, u64) = (0, 30 * 86_400);
    pub const RELAYS: (usize, usize) = (1, 8);
    pub const RELAY_URL_LEN: usize = 200;
    pub const SWEEP_THRESHOLD_SAT: (u64, u64) = (10_000, super::MAX_MONEY_SAT);
    pub const SWEEP_FEE_RATE: (u64, u64) = (1, 1_000);
    pub const SWEEP_ANONYMITY_SET: (u64, u64) = (2, 1_000);
    // The bounds of the network settings live with them.
    pub use crate::network::bounds::{GROUPS, GROUP_MIN, NAME_LEN, PROXIES, PROXY_ID_LEN, PROXY_INTERVAL_SECS};
}

/// How a future sweep would leave this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SweepMode {
    Payjoin,
    Coinjoin,
}

/// Policy for moving funds out once they pile up. Stored and reported only:
/// this service holds no spending keys, so a separate signer must carry it
/// out. There is intentionally no destination field; the signer owns that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Sweep {
    /// Whether the policy is active.
    pub enabled: bool,
    /// PayJoin or CoinJoin.
    pub mode: SweepMode,
    /// Confirmed balance (satoshis) that triggers a sweep.
    pub threshold_sat: u64,
    /// Highest fee rate a sweep may pay, in sat/vB.
    pub max_fee_rate_sat_vb: u32,
    /// Smallest acceptable CoinJoin anonymity set.
    pub min_anonymity_set: u32,
}

impl Default for Sweep {
    fn default() -> Self {
        Sweep {
            enabled: false,
            mode: SweepMode::Payjoin,
            threshold_sat: 1_000_000,
            max_fee_rate_sat_vb: 20,
            min_anonymity_set: 5,
        }
    }
}

/// Every setting that can change while the service runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Settings {
    pub name: String,
    pub relays: Vec<String>,
    /// Relays that only some keys use: relay url to key ids. A relay not
    /// listed here is used by every key.
    #[serde(default)]
    pub relay_keys: BTreeMap<String, Vec<String>>,
    /// Names shown for relays (such as the I2P name behind a b32 address):
    /// relay url to name. Connections always use the url.
    #[serde(default)]
    pub relay_names: BTreeMap<String, String>,
    pub public_invoicing: bool,
    pub pow_bits: u8,
    pub pow_window_secs: u64,
    pub min_confirmations: u32,
    pub default_expiry_secs: u64,
    pub max_expiry_secs: u64,
    pub min_amount_sat: u64,
    pub max_amount_sat: u64,
    pub max_open_invoices: u64,
    pub max_invoices_per_day: u64,
    pub rate_global_per_min: u32,
    pub rate_per_key_per_min: u32,
    pub rate_requests_per_min: u32,
    pub rate_requests_per_key_per_min: u32,
    pub poll_secs: u64,
    pub late_grace_secs: u64,
    /// Proxies for relay connections only.
    pub proxies: ProxySettings,
    pub sweep: Sweep,
    /// The keys relays and proxies can be assigned to (the service's keys in
    /// use). Not a setting: the service fills it in from its keys. Empty
    /// means the built-in keys.
    #[serde(skip)]
    pub lanes: Vec<crate::network::Lane>,
}

/// Partial update of [`Sweep`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SweepPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SweepMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_sat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_rate_sat_vb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_anonymity_set: Option<u32>,
}

/// Partial update of [`Settings`]; also the stored form of the overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
    /// Replaces the whole map of relays used by only some keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_keys: Option<BTreeMap<String, Vec<String>>>,
    /// Replaces the whole map of relay names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_names: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_invoicing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pow_bits: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pow_window_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_expiry_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_expiry_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_amount_sat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_sat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_invoices: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invoices_per_day: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_global_per_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_key_per_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_requests_per_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_requests_per_key_per_min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_grace_secs: Option<u64>,
    /// Old form of a single proxy url (empty: no proxy). It replaces the
    /// whole proxy setup with that one proxy as the default route; it is
    /// never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxies: Option<ProxyPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep: Option<SweepPatch>,
}

impl SweepPatch {
    fn apply(&self, s: &mut Sweep) {
        take(&mut s.enabled, &self.enabled);
        take(&mut s.mode, &self.mode);
        take(&mut s.threshold_sat, &self.threshold_sat);
        take(&mut s.max_fee_rate_sat_vb, &self.max_fee_rate_sat_vb);
        take(&mut s.min_anonymity_set, &self.min_anonymity_set);
    }

    fn merge(&mut self, o: &SweepPatch) {
        keep(&mut self.enabled, &o.enabled);
        keep(&mut self.mode, &o.mode);
        keep(&mut self.threshold_sat, &o.threshold_sat);
        keep(&mut self.max_fee_rate_sat_vb, &o.max_fee_rate_sat_vb);
        keep(&mut self.min_anonymity_set, &o.min_anonymity_set);
    }

    fn names(&self, out: &mut Vec<String>) {
        let fields = [
            ("enabled", self.enabled.is_some()),
            ("mode", self.mode.is_some()),
            ("threshold_sat", self.threshold_sat.is_some()),
            ("max_fee_rate_sat_vb", self.max_fee_rate_sat_vb.is_some()),
            ("min_anonymity_set", self.min_anonymity_set.is_some()),
        ];
        out.extend(fields.iter().filter(|f| f.1).map(|f| format!("sweep.{}", f.0)));
    }
}

impl SettingsPatch {
    /// `base` with this patch applied on top.
    pub fn apply(&self, base: &Settings) -> Settings {
        let mut s = base.clone();
        take(&mut s.name, &self.name);
        take(&mut s.relays, &self.relays);
        take(&mut s.relay_keys, &self.relay_keys);
        // Entries for relays that are gone, or that name no key, mean nothing.
        let relays = s.relays.clone();
        s.relay_keys
            .retain(|url, keys| !keys.is_empty() && relays.iter().any(|r| same_relay(r, url)));
        take(&mut s.relay_names, &self.relay_names);
        s.relay_names
            .retain(|url, name| !name.trim().is_empty() && relays.iter().any(|r| same_relay(r, url)));
        take(&mut s.public_invoicing, &self.public_invoicing);
        take(&mut s.pow_bits, &self.pow_bits);
        take(&mut s.pow_window_secs, &self.pow_window_secs);
        take(&mut s.min_confirmations, &self.min_confirmations);
        take(&mut s.default_expiry_secs, &self.default_expiry_secs);
        take(&mut s.max_expiry_secs, &self.max_expiry_secs);
        take(&mut s.min_amount_sat, &self.min_amount_sat);
        take(&mut s.max_amount_sat, &self.max_amount_sat);
        take(&mut s.max_open_invoices, &self.max_open_invoices);
        take(&mut s.max_invoices_per_day, &self.max_invoices_per_day);
        take(&mut s.rate_global_per_min, &self.rate_global_per_min);
        take(&mut s.rate_per_key_per_min, &self.rate_per_key_per_min);
        take(&mut s.rate_requests_per_min, &self.rate_requests_per_min);
        take(
            &mut s.rate_requests_per_key_per_min,
            &self.rate_requests_per_key_per_min,
        );
        take(&mut s.poll_secs, &self.poll_secs);
        take(&mut s.late_grace_secs, &self.late_grace_secs);
        if let Some(p) = &self.proxies {
            p.apply(&mut s.proxies);
        }
        if let Some(sw) = &self.sweep {
            sw.apply(&mut s.sweep);
        }
        s
    }

    /// Fold a newer patch into this one; fields it sets win.
    pub fn merge(&mut self, o: &SettingsPatch) {
        keep(&mut self.name, &o.name);
        keep(&mut self.relays, &o.relays);
        keep(&mut self.relay_keys, &o.relay_keys);
        keep(&mut self.relay_names, &o.relay_names);
        keep(&mut self.public_invoicing, &o.public_invoicing);
        keep(&mut self.pow_bits, &o.pow_bits);
        keep(&mut self.pow_window_secs, &o.pow_window_secs);
        keep(&mut self.min_confirmations, &o.min_confirmations);
        keep(&mut self.default_expiry_secs, &o.default_expiry_secs);
        keep(&mut self.max_expiry_secs, &o.max_expiry_secs);
        keep(&mut self.min_amount_sat, &o.min_amount_sat);
        keep(&mut self.max_amount_sat, &o.max_amount_sat);
        keep(&mut self.max_open_invoices, &o.max_open_invoices);
        keep(&mut self.max_invoices_per_day, &o.max_invoices_per_day);
        keep(&mut self.rate_global_per_min, &o.rate_global_per_min);
        keep(&mut self.rate_per_key_per_min, &o.rate_per_key_per_min);
        keep(&mut self.rate_requests_per_min, &o.rate_requests_per_min);
        keep(
            &mut self.rate_requests_per_key_per_min,
            &o.rate_requests_per_key_per_min,
        );
        keep(&mut self.poll_secs, &o.poll_secs);
        keep(&mut self.late_grace_secs, &o.late_grace_secs);
        if let Some(p) = &o.proxies {
            self.proxies.get_or_insert_with(ProxyPatch::default).merge(p);
        }
        if let Some(sw) = &o.sweep {
            self.sweep.get_or_insert_with(SweepPatch::default).merge(sw);
        }
    }

    /// Names of the settings this patch sets, for showing what is overridden.
    pub fn names(&self) -> Vec<String> {
        let fields = [
            ("name", self.name.is_some()),
            ("relays", self.relays.is_some()),
            ("relay_keys", self.relay_keys.is_some()),
            ("relay_names", self.relay_names.is_some()),
            ("public_invoicing", self.public_invoicing.is_some()),
            ("pow_bits", self.pow_bits.is_some()),
            ("pow_window_secs", self.pow_window_secs.is_some()),
            ("min_confirmations", self.min_confirmations.is_some()),
            ("default_expiry_secs", self.default_expiry_secs.is_some()),
            ("max_expiry_secs", self.max_expiry_secs.is_some()),
            ("min_amount_sat", self.min_amount_sat.is_some()),
            ("max_amount_sat", self.max_amount_sat.is_some()),
            ("max_open_invoices", self.max_open_invoices.is_some()),
            ("max_invoices_per_day", self.max_invoices_per_day.is_some()),
            ("rate_global_per_min", self.rate_global_per_min.is_some()),
            ("rate_per_key_per_min", self.rate_per_key_per_min.is_some()),
            ("rate_requests_per_min", self.rate_requests_per_min.is_some()),
            (
                "rate_requests_per_key_per_min",
                self.rate_requests_per_key_per_min.is_some(),
            ),
            ("poll_secs", self.poll_secs.is_some()),
            ("late_grace_secs", self.late_grace_secs.is_some()),
        ];
        let mut out: Vec<String> = fields.iter().filter(|f| f.1).map(|f| f.0.to_string()).collect();
        if let Some(p) = &self.proxies {
            p.names(&mut out);
        }
        if let Some(sw) = &self.sweep {
            sw.names(&mut out);
        }
        out
    }
}

/// A settings change stored before proxy groups (#53), in today's shape.
///
/// What was stored then was a change to the environment's settings in the
/// old shape (`env`). Both are put together the old way and converted with
/// [`legacy::convert`], the conversion the environment goes through too.
/// Every proxy setting the old change made is kept, and so is any route
/// that comes out differently from the environment's: a proxy setting
/// left to the environment stays so.
pub fn upgrade_stored(json: &str, env: &legacy::ProxySettings) -> serde_json::Result<SettingsPatch> {
    let mut v: serde_json::Value = serde_json::from_str(json)?;
    let old = v.as_object_mut().and_then(|o| o.remove("proxies"));
    let mut patch: SettingsPatch = serde_json::from_value(v)?;
    let old: legacy::ProxyPatch = old.map(serde_json::from_value).transpose()?.unwrap_or_default();
    let single = patch.proxy.take();
    let mut then = env.clone();
    if let Some(url) = &single {
        // The single address of the first versions: a list of one, or none.
        then.list = (!url.is_empty())
            .then(|| legacy::ProxyEntry {
                id: "saved".into(),
                name: String::new(),
                url: url.clone(),
                keys: Vec::new(),
                pool: true,
                i2p: false,
            })
            .into_iter()
            .collect();
    }
    old.apply(&mut then);
    let lanes = crate::keys::lanes();
    let (now, was) = (legacy::convert(&then, &lanes), legacy::convert(env, &lanes));
    // What shaped the routes: the list (with its pool and keys), the
    // strategy, and rules (a rule to the pool follows the pool).
    let route = single.is_some() || old.sets_default() || old.rules.is_some();
    fn kept<T: Clone + PartialEq>(set: bool, now: &T, was: &T) -> Option<T> {
        (set || now != was).then(|| now.clone())
    }
    let p = ProxyPatch {
        list: kept(single.is_some() || old.list.is_some(), &now.list, &was.list)
            .and_then(|l| ProxyPatch::with_list(&l).list),
        groups: kept(route, &now.groups, &was.groups),
        default: kept(route, &now.default, &was.default),
        default_keys: kept(route, &now.default_keys, &was.default_keys),
        offline: old.offline,
        transparent: old.transparent,
        rules: kept(old.rules.is_some(), &now.rules, &was.rules),
        i2p_registries: old.i2p_registries,
        ..ProxyPatch::default()
    };
    patch.proxies = (p != ProxyPatch::default()).then_some(p);
    Ok(patch)
}

/// Validate a relay list for runtime use. Stricter than the environment
/// loader: on mainnet only TLS relays, unless the relay is on this machine.
pub fn check_relays(relays: &[String], network: Network) -> Result<()> {
    let (min, max) = bounds::RELAYS;
    if relays.len() < min || relays.len() > max {
        return Err(Error::InvalidParams(format!(
            "between {min} and {max} relays are required"
        )));
    }
    for (i, r) in relays.iter().enumerate() {
        if r.len() > bounds::RELAY_URL_LEN || r.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidParams(
                "relay urls must be short and contain no spaces".into(),
            ));
        }
        if !(r.starts_with("wss://") || r.starts_with("ws://")) {
            return Err(Error::InvalidParams(format!(
                "relay '{r}' must be a ws:// or wss:// url"
            )));
        }
        // Decide on the host the connection will actually use. The raw
        // authority may carry userinfo, and "ws://127.0.0.1:80@remote" would
        // look local to a string check while connecting to "remote".
        let host = match nostr_sdk::Url::parse(r) {
            Ok(url) if nostr_sdk::RelayUrl::parse(r).is_ok() => {
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(Error::InvalidParams(format!(
                        "relay '{r}' must not contain a user name or password"
                    )));
                }
                url.host_str().unwrap_or_default().to_string()
            }
            _ => String::new(),
        };
        if host.is_empty() {
            return Err(Error::InvalidParams(format!("relay '{r}' is not a valid url")));
        }
        // Plain ws:// is only for this machine, or for Tor, I2P and FIPS hosts,
        // which encrypt the whole path themselves.
        if network == Network::Bitcoin && r.starts_with("ws://") && !is_loopback_host(&host) && !is_overlay_host(&host)
        {
            return Err(Error::InvalidParams(format!(
                "relay '{r}' must use wss:// on mainnet (ws:// is only for this machine, or .onion, .i2p and .fips addresses)"
            )));
        }
        if relays[..i].contains(r) {
            return Err(Error::InvalidParams(format!("relay '{r}' is listed twice")));
        }
    }
    Ok(())
}

impl Settings {
    /// The network part of these settings.
    pub fn network(&self) -> NetworkSettings {
        NetworkSettings {
            relays: self.relays.clone(),
            relay_keys: self.relay_keys.clone(),
            relay_names: self.relay_names.clone(),
            proxies: self.proxies.clone(),
        }
    }

    /// Replace the network part of these settings.
    pub fn set_network(&mut self, network: NetworkSettings) {
        self.relays = network.relays;
        self.relay_keys = network.relay_keys;
        self.relay_names = network.relay_names;
        self.proxies = network.proxies;
    }

    /// The network settings together with this service's lanes (its keys).
    pub fn topology(&self) -> Topology {
        Topology {
            settings: self.network(),
            lanes: if self.lanes.is_empty() {
                crate::keys::lanes()
            } else {
                self.lanes.clone()
            },
        }
    }

    /// The keys (by id) that use this relay.
    pub fn relay_users(&self, relay: &str) -> Vec<String> {
        self.topology().relay_users(relay)
    }

    /// The relays one key connects to, in list order.
    pub fn relays_for(&self, key: &str) -> Vec<String> {
        self.topology().relays_for(key)
    }

    /// Check every value and every relationship between values, except the
    /// relay list (see [`check_relays`], applied to lists set from the
    /// dashboard; the environment's list is accepted as configured).
    /// `has_admins` is false when nobody but the public could create invoices.
    pub fn validate(&self, has_admins: bool) -> Result<()> {
        use bounds::*;
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > NAME_LEN || !name.chars().all(crate::service::is_plain_text) {
            return Err(Error::InvalidParams(format!(
                "name must be 1 to {NAME_LEN} visible characters"
            )));
        }
        self.topology().validate()?;
        within("pow_bits", u64::from(self.pow_bits), POW_BITS)?;
        within("pow_window_secs", self.pow_window_secs, POW_WINDOW_SECS)?;
        within(
            "min_confirmations",
            u64::from(self.min_confirmations),
            MIN_CONFIRMATIONS,
        )?;
        within("default_expiry_secs", self.default_expiry_secs, EXPIRY_SECS)?;
        within("max_expiry_secs", self.max_expiry_secs, EXPIRY_SECS)?;
        within("min_amount_sat", self.min_amount_sat, AMOUNT_SAT)?;
        within("max_amount_sat", self.max_amount_sat, AMOUNT_SAT)?;
        within("max_open_invoices", self.max_open_invoices, MAX_OPEN_INVOICES)?;
        within("max_invoices_per_day", self.max_invoices_per_day, MAX_INVOICES_PER_DAY)?;
        within("rate_global_per_min", u64::from(self.rate_global_per_min), RATE_CREATE)?;
        within(
            "rate_per_key_per_min",
            u64::from(self.rate_per_key_per_min),
            RATE_CREATE,
        )?;
        within(
            "rate_requests_per_min",
            u64::from(self.rate_requests_per_min),
            RATE_REQUESTS,
        )?;
        within(
            "rate_requests_per_key_per_min",
            u64::from(self.rate_requests_per_key_per_min),
            RATE_REQUESTS,
        )?;
        within("poll_secs", self.poll_secs, POLL_SECS)?;
        within("late_grace_secs", self.late_grace_secs, LATE_GRACE_SECS)?;
        within("sweep.threshold_sat", self.sweep.threshold_sat, SWEEP_THRESHOLD_SAT)?;
        within(
            "sweep.max_fee_rate_sat_vb",
            u64::from(self.sweep.max_fee_rate_sat_vb),
            SWEEP_FEE_RATE,
        )?;
        within(
            "sweep.min_anonymity_set",
            u64::from(self.sweep.min_anonymity_set),
            SWEEP_ANONYMITY_SET,
        )?;
        if self.min_amount_sat > self.max_amount_sat {
            return Err(Error::InvalidParams("min_amount_sat exceeds max_amount_sat".into()));
        }
        if self.default_expiry_secs > self.max_expiry_secs {
            return Err(Error::InvalidParams(
                "default_expiry_secs exceeds max_expiry_secs".into(),
            ));
        }
        if !has_admins && !self.public_invoicing {
            return Err(Error::InvalidParams(
                "public invoicing cannot be turned off when no operators are configured".into(),
            ));
        }
        Ok(())
    }

    /// Settings that are allowed but that an operator should think twice about.
    pub fn warnings(&self, network: Network, electrum: &str, security: &crate::electrum::Security) -> Vec<String> {
        use crate::electrum::Security;
        let mut w = Vec::new();
        if !is_loopback(electrum) {
            w.push(match security {
                Security::Plain => {
                    "DEADHOP_ELECTRUM is not on this machine: the link is unencrypted and whoever runs or can \
                 intercept that server decides which invoices look paid; use tls:// with a pinned certificate"
                        .to_string()
                }
                _ => "DEADHOP_ELECTRUM is not on this machine: the link is encrypted, but whoever runs that server \
                 decides which invoices look paid"
                    .to_string(),
            });
        }
        if *security == Security::Tls {
            w.push(
                "the Electrum certificate is checked only against public authorities; pin it with \
                 DEADHOP_ELECTRUM_CERT_SHA256 (see `deadhop fingerprint`)"
                    .to_string(),
            );
        }
        if self.public_invoicing && self.pow_bits < 16 {
            w.push(format!(
                "public invoicing with only {} bits of proof of work: anyone can create invoices almost for free",
                self.pow_bits
            ));
        }
        let plaintext = |r: &String| {
            r.starts_with("ws://")
                && !nostr_sdk::Url::parse(r)
                    .ok()
                    .and_then(|u| u.host_str().map(is_overlay_host))
                    .unwrap_or(false)
        };
        if network == Network::Bitcoin && self.relays.iter().any(plaintext) {
            w.push("a relay uses ws:// (no TLS) on mainnet".to_string());
        }
        if network == Network::Bitcoin && self.min_confirmations < 2 && self.max_amount_sat > 10_000_000 {
            w.push("invoices above 0.1 BTC are marked paid after a single confirmation".to_string());
        }
        w
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::tests::{base, load};

    pub fn defaults() -> Settings {
        load(&base()).unwrap().settings()
    }

    fn entry(id: &str, url: &str) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: String::new(),
            url: url.into(),
            i2p: false,
        }
    }

    #[test]
    fn a_proxy_list_keeps_hidden_passwords_through_edits_and_reorders() {
        let current = vec![
            entry("one", "socks5://u:secret1@10.0.0.1:1080"),
            entry("two", "http://u:secret2@10.0.0.2:3128"),
        ];
        // What the dashboard holds (passwords hidden), reordered, plus a new one.
        let mut patch = ProxyPatch {
            list: Some(vec![
                ProxyEntryInput {
                    id: Some("two".into()),
                    name: Some("second".into()),
                    url: crate::relay::redact(&current[1].url),
                    keys: None,
                    pool: None,
                    i2p: None,
                },
                ProxyEntryInput {
                    id: Some("one".into()),
                    name: None,
                    url: crate::relay::redact(&current[0].url),
                    keys: None,
                    pool: None,
                    i2p: None,
                },
                ProxyEntryInput {
                    id: None,
                    name: None,
                    url: "socks5://10.0.0.3:9050".into(),
                    keys: None,
                    pool: None,
                    i2p: None,
                },
            ]),
            ..ProxyPatch::default()
        };
        patch.resolve(&current).unwrap();
        let mut s = ProxySettings::default();
        patch.apply(&mut s);
        s.validate(&crate::keys::lanes()).unwrap();
        assert_eq!(
            s.list.iter().map(|e| e.url.as_str()).collect::<Vec<_>>(),
            [
                "http://u:secret2@10.0.0.2:3128",
                "socks5://u:secret1@10.0.0.1:1080",
                "socks5://10.0.0.3:9050"
            ]
        );
        assert_eq!(s.list[0].id, "two");
        assert!(s.list[2].id.starts_with('p') && s.list[2].id.len() > 3);

        // Without an id, the hidden url is matched to the entry showing the same text.
        let mut by_text = ProxyPatch::with_list(&[]);
        by_text.list = Some(vec![ProxyEntryInput {
            id: None,
            name: None,
            url: crate::relay::redact(&current[0].url),
            keys: None,
            pool: None,
            i2p: None,
        }]);
        by_text.resolve(&current).unwrap();
        assert_eq!(by_text.list.as_ref().unwrap()[0].url, current[0].url);
        assert_eq!(by_text.list.as_ref().unwrap()[0].id.as_deref(), Some("one"));

        // A hidden password that matches nothing is refused, not stored as '***'.
        let mut bad = ProxyPatch {
            list: Some(vec![ProxyEntryInput {
                id: Some("one".into()),
                name: None,
                url: "socks5://u:***@evil.example:1".into(),
                keys: None,
                pool: None,
                i2p: None,
            }]),
            ..ProxyPatch::default()
        };
        assert!(bad.resolve(&current).unwrap_err().to_string().contains("hidden"));
    }

    #[test]
    fn proxy_ids_and_names_are_checked_and_an_empty_old_proxy_clears_the_list() {
        let mut p = ProxySettings {
            list: vec![entry("Bad Id", "socks5://h:1")],
            ..ProxySettings::default()
        };
        assert!(p
            .validate(&crate::keys::lanes())
            .unwrap_err()
            .to_string()
            .contains("bad id"));
        p.list = vec![ProxyEntry {
            name: "x".repeat(61),
            ..entry("a", "socks5://h:1")
        }];
        assert!(p
            .validate(&crate::keys::lanes())
            .unwrap_err()
            .to_string()
            .contains("proxy name"));
        p.list = vec![ProxyEntry {
            name: "Tor".into(),
            ..entry("a", "socks5://h:1")
        }];
        p.validate(&crate::keys::lanes()).unwrap();
        // Entries stored without an id (never written by this version) still get one.
        let bare: ProxyPatch =
            serde_json::from_value(serde_json::json!({ "list": [{ "url": "socks5://h:1" }] })).unwrap();
        let mut applied = ProxySettings::default();
        bare.apply(&mut applied);
        assert_eq!(applied.list[0].id, "p0");
        // The single address of old clients is never stored or applied as such.
        let mut s = defaults();
        s.proxies = p;
        let single: SettingsPatch = serde_json::from_value(serde_json::json!({ "proxy": "" })).unwrap();
        assert_eq!(single.apply(&s).proxies, s.proxies);
        assert!(single.names().is_empty());
    }

    #[test]
    fn proxy_patches_merge_and_name_their_fields() {
        let mut stored: SettingsPatch = serde_json::from_value(
            serde_json::json!({ "proxies": { "list": [{ "id": "a", "url": "socks5://h:1" }] } }),
        )
        .unwrap();
        let newer: SettingsPatch = serde_json::from_value(serde_json::json!({
            "proxies": {
                "list": [{ "id": "a", "url": "socks5://h:2" }, { "id": "b", "url": "socks5://h:3" }],
                "groups": [{ "id": "g", "proxies": ["a", "b"], "strategy": "chaos" }],
                "default": { "group": "g" },
                "default_keys": { "admin": { "proxy": "a" } }
            }
        }))
        .unwrap();
        stored.merge(&newer);
        let s = stored.apply(&defaults());
        assert_eq!(
            (
                s.proxies.list[0].url.as_str(),
                s.proxies.groups[0].strategy,
                &s.proxies.default
            ),
            ("socks5://h:2", Strategy::Chaos, &Destination::Group("g".into()))
        );
        s.validate(true).unwrap();
        assert_eq!(
            stored.names(),
            vec![
                "proxies.list",
                "proxies.groups",
                "proxies.default",
                "proxies.default_keys"
            ]
        );
        // Switching a policy keeps the list.
        stored.merge(&SettingsPatch {
            proxies: Some(ProxyPatch {
                offline: Some(OfflinePolicy::Open),
                transparent: Some(true),
                ..ProxyPatch::default()
            }),
            ..SettingsPatch::default()
        });
        let s = stored.apply(&defaults());
        assert!(s.proxies.transparent && s.proxies.offline == OfflinePolicy::Open);
        assert_eq!(s.proxies.list.len(), 2);
        // Redaction for display.
        let p = ProxySettings {
            list: vec![entry("a", "socks5://u:pw@h:1")],
            ..ProxySettings::default()
        };
        assert_eq!(p.redacted().list[0].url, "socks5://u:***@h:1");
        assert!(serde_json::from_value::<SettingsPatch>(serde_json::json!({ "proxies": { "x": 1 } })).is_err());
    }

    fn err(s: &Settings) -> String {
        s.validate(true).unwrap_err().to_string()
    }

    #[test]
    fn defaults_are_valid_and_reflect_the_environment() {
        let s = defaults();
        s.validate(true).unwrap();
        assert_eq!(s.relays, vec!["ws://127.0.0.1:7777", "wss://relay.example"]);
        assert_eq!(s.pow_bits, 20);
        assert_eq!(s.sweep, Sweep::default());
    }

    #[test]
    fn patches_apply_merge_and_name_their_fields() {
        let base = defaults();
        let empty = SettingsPatch::default();
        assert_eq!(empty.apply(&base), base);
        assert!(empty.names().is_empty());

        let mut stored: SettingsPatch = serde_json::from_value(serde_json::json!({
            "pow_bits": 22, "relays": ["wss://a.example"], "sweep": { "enabled": true }
        }))
        .unwrap();
        let newer: SettingsPatch = serde_json::from_value(serde_json::json!({
            "name": "shop", "public_invoicing": true, "pow_window_secs": 60, "min_confirmations": 3,
            "default_expiry_secs": 600, "max_expiry_secs": 7200, "min_amount_sat": 2000,
            "max_amount_sat": 3000, "max_open_invoices": 9, "max_invoices_per_day": 99,
            "rate_global_per_min": 5, "rate_per_key_per_min": 2, "rate_requests_per_min": 50,
            "rate_requests_per_key_per_min": 10, "poll_secs": 30, "late_grace_secs": 0,
            "proxies": { "list": [{ "id": "tor", "url": "socks5://127.0.0.1:9050" }], "default": { "proxy": "tor" } },
            "sweep": { "mode": "coinjoin", "threshold_sat": 50000, "max_fee_rate_sat_vb": 3, "min_anonymity_set": 9 }
        }))
        .unwrap();
        stored.merge(&newer);
        let s = stored.apply(&base);
        assert_eq!((s.name.as_str(), s.pow_bits, s.relays.len()), ("shop", 22, 1));
        assert_eq!(
            (s.min_confirmations, s.poll_secs, s.late_grace_secs, s.max_open_invoices),
            (3, 30, 0, 9)
        );
        assert_eq!(
            s.sweep,
            Sweep {
                enabled: true,
                mode: SweepMode::Coinjoin,
                threshold_sat: 50_000,
                max_fee_rate_sat_vb: 3,
                min_anonymity_set: 9
            }
        );
        s.validate(true).unwrap();
        assert_eq!(stored.names().len(), 25);
        assert_eq!(s.proxies.list.len(), 1);
        assert_eq!(s.proxies.list[0].url, "socks5://127.0.0.1:9050");
        assert!(stored.names().contains(&"sweep.mode".to_string()));

        // A sweep patch merged into overrides that had none.
        let mut fresh = SettingsPatch::default();
        fresh.merge(&SettingsPatch {
            sweep: Some(SweepPatch {
                enabled: Some(true),
                ..SweepPatch::default()
            }),
            ..SettingsPatch::default()
        });
        assert_eq!(fresh.names(), vec!["sweep.enabled"]);

        // Unknown fields are refused, including inside the sweep policy.
        assert!(serde_json::from_value::<SettingsPatch>(serde_json::json!({ "xpub": "x" })).is_err());
        assert!(serde_json::from_value::<SettingsPatch>(serde_json::json!({ "sweep": { "to": "x" } })).is_err());
    }

    #[test]
    fn every_value_is_bounded() {
        let ok = defaults();
        type Change = Box<dyn Fn(&mut Settings)>;
        let cases: Vec<(Change, &str)> = vec![
            (Box::new(|s| s.name = " ".into()), "name must be"),
            (Box::new(|s| s.name = "a\u{202E}b".into()), "name must be"),
            (Box::new(|s| s.name = "x".repeat(61)), "name must be"),
            (Box::new(|s| s.pow_bits = 65), "pow_bits"),
            (Box::new(|s| s.pow_window_secs = 1), "pow_window_secs"),
            (Box::new(|s| s.min_confirmations = 0), "min_confirmations"),
            (Box::new(|s| s.default_expiry_secs = 10), "default_expiry_secs"),
            (Box::new(|s| s.max_expiry_secs = 10), "max_expiry_secs"),
            (Box::new(|s| s.min_amount_sat = 0), "min_amount_sat"),
            (Box::new(|s| s.max_amount_sat = MAX_MONEY_SAT + 1), "max_amount_sat"),
            (Box::new(|s| s.max_open_invoices = 0), "max_open_invoices"),
            (Box::new(|s| s.max_invoices_per_day = 0), "max_invoices_per_day"),
            (Box::new(|s| s.rate_global_per_min = 0), "rate_global_per_min"),
            (Box::new(|s| s.rate_per_key_per_min = 0), "rate_per_key_per_min"),
            (Box::new(|s| s.rate_requests_per_min = 0), "rate_requests_per_min"),
            (
                Box::new(|s| s.rate_requests_per_key_per_min = 0),
                "rate_requests_per_key_per_min",
            ),
            (Box::new(|s| s.poll_secs = 0), "poll_secs"),
            (Box::new(|s| s.late_grace_secs = 31 * 86_400), "late_grace_secs"),
            (
                Box::new(|s| s.proxies.list = vec![entry("a", "ftp://x:1")]),
                "proxy: scheme",
            ),
            (
                Box::new(|s| {
                    s.proxies.list = vec![entry("a", "socks5://h:1"), entry("b", "socks5://h:2")];
                    s.proxies.groups = vec![ProxyGroup {
                        id: "g".into(),
                        name: String::new(),
                        proxies: vec!["a".into(), "b".into()],
                        strategy: Strategy::RoundRobin,
                        rotate_secs: 59,
                        chaos_min_secs: 300,
                        chaos_max_secs: 900,
                    }];
                }),
                "rotate_secs",
            ),
            (
                Box::new(|s| s.proxies.default = Destination::Group("gone".into())),
                "the default route points at a group",
            ),
            (
                Box::new(|s| s.proxies.list = vec![entry("a", "socks5://h:1"), entry("a", "socks5://h:2")]),
                "same id",
            ),
            (
                Box::new(|s| s.proxies.list = vec![entry("a", "socks5://h:1"), entry("b", "socks5://h:1")]),
                "listed twice",
            ),
            (Box::new(|s| s.proxies.list = vec![entry("a", "")]), "address is empty"),
            (
                Box::new(|s| {
                    s.proxies.list = (0..9)
                        .map(|i| entry(&format!("p{i}"), &format!("socks5://h:{}", i + 1)))
                        .collect()
                }),
                "at most 8",
            ),
            (Box::new(|s| s.sweep.threshold_sat = 1), "sweep.threshold_sat"),
            (
                Box::new(|s| s.sweep.max_fee_rate_sat_vb = 0),
                "sweep.max_fee_rate_sat_vb",
            ),
            (Box::new(|s| s.sweep.min_anonymity_set = 1), "sweep.min_anonymity_set"),
            (
                Box::new(|s| s.min_amount_sat = s.max_amount_sat + 1),
                "min_amount_sat exceeds",
            ),
            (
                Box::new(|s| s.default_expiry_secs = s.max_expiry_secs + 1),
                "default_expiry_secs exceeds",
            ),
        ];
        for (change, expect) in cases {
            let mut s = ok.clone();
            change(&mut s);
            assert!(err(&s).contains(expect), "{expect}: {}", err(&s));
        }
        let mut closed = ok.clone();
        closed.public_invoicing = false;
        assert!(closed.validate(false).unwrap_err().to_string().contains("no operators"));
    }

    #[test]
    fn relay_lists_are_checked() {
        let r = |v: &[&str], n: Network| check_relays(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), n);
        assert!(r(&["wss://relay.example", "ws://127.0.0.1:7777"], Network::Bitcoin).is_ok());
        assert!(r(&["ws://relay.example"], Network::Regtest).is_ok());
        let bad: Vec<(Vec<&str>, &str)> = vec![
            (vec![], "between 1 and 8"),
            (vec!["wss://a.example"; 9], "between 1 and 8"),
            (vec!["https://a.example"], "must be a ws://"),
            (vec!["wss://"], "not a valid url"),
            (vec!["wss://a b.example"], "no spaces"),
            (vec!["wss://a.example", "wss://a.example"], "listed twice"),
        ];
        for (list, expect) in bad {
            assert!(
                r(&list, Network::Regtest).unwrap_err().to_string().contains(expect),
                "{expect}"
            );
        }
        let long = format!("wss://{}.example", "a".repeat(200));
        assert!(r(&[&long], Network::Regtest).unwrap_err().to_string().contains("short"));
        assert!(r(&["ws://relay.example"], Network::Bitcoin)
            .unwrap_err()
            .to_string()
            .contains("wss:// on mainnet"));
        // Tor, I2P and FIPS addresses are encrypted end to end: plain ws:// is fine there.
        assert!(r(
            &[
                "ws://4ajy63hxt5hui5o4zg5ep675p2jtjuolyhpzfjjueyfdh3p6gvzpk6id.onion/",
                "ws://relay.b32.i2p:80",
                "ws://npub1abc.fips:7777"
            ],
            Network::Bitcoin
        )
        .is_ok());
        // ...but only as a whole trailing label, and never with userinfo.
        for spoof in [
            "ws://a.onion.example",
            "ws://onion",
            "ws://a.fips.example.com",
            "ws://a.onion@evil.example",
            "ws://x.i2px",
        ] {
            assert!(r(&[spoof], Network::Bitcoin).is_err(), "{spoof}");
        }
        // The reason says what to do instead.
        let why = r(&["ws://relay.example"], Network::Bitcoin).unwrap_err().to_string();
        assert!(why.contains(".onion, .i2p and .fips"), "{why}");
        // Local plaintext relays stay allowed on mainnet, by any loopback spelling.
        assert!(r(&["ws://localhost:7777", "ws://[::1]:7777/path"], Network::Bitcoin).is_ok());
        // Userinfo must not make a remote host pass for a local one (issue #7):
        // the connection would go to evil.example over plaintext.
        for spoof in [
            "ws://127.0.0.1:80@evil.example",
            "ws://localhost:9050@evil.example",
            "ws://[::1]:1@evil.example",
            "wss://user@relay.example",
            "wss://:secret@relay.example",
        ] {
            for net in [Network::Bitcoin, Network::Regtest] {
                assert!(
                    r(&[spoof], net)
                        .unwrap_err()
                        .to_string()
                        .contains("user name or password"),
                    "{spoof}"
                );
            }
        }
    }

    #[test]
    fn encrypted_overlay_relays_are_not_warned_about() {
        let plain = crate::electrum::Security::Plain;
        let mut s = defaults();
        s.relays = vec![
            "ws://abc.onion/".into(),
            "ws://node.b32.i2p".into(),
            "ws://npub1abc.fips:7777".into(),
        ];
        assert!(!s
            .warnings(Network::Bitcoin, "127.0.0.1:50001", &plain)
            .iter()
            .any(|w| w.contains("no TLS")));
        s.relays.push("ws://relay.example".into());
        assert!(s
            .warnings(Network::Bitcoin, "127.0.0.1:50001", &plain)
            .iter()
            .any(|w| w.contains("no TLS")));
    }

    #[test]
    fn warnings_name_risky_choices() {
        let mut s = defaults();
        let plain = crate::electrum::Security::Plain;
        assert!(s.warnings(Network::Regtest, "127.0.0.1:50001", &plain).is_empty());
        s.public_invoicing = true;
        s.pow_bits = 8;
        s.relays = vec!["ws://relay.example".into()];
        s.max_amount_sat = 50_000_000;
        let w = s.warnings(Network::Bitcoin, "10.0.0.2:50001", &plain);
        assert_eq!(w.len(), 4, "{w:?}");
        assert!(w[0].contains("unencrypted"));
        let tls = s.warnings(Network::Regtest, "10.0.0.2:50002", &crate::electrum::Security::Tls);
        assert!(
            tls[0].contains("link is encrypted") && tls[1].contains("pin it"),
            "{tls:?}"
        );
        let pinned = crate::electrum::Security::Pinned(vec![[0; 32]]);
        assert_eq!(
            s.warnings(Network::Regtest, "127.0.0.1:50002", &pinned).len(),
            1,
            "only the weak work warning"
        );
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn relays_and_proxies_are_assigned_to_keys() {
        let mut s = defaults();
        let (a, b) = (s.relays[0].clone(), s.relays[1].clone());
        // Nothing assigned: every key uses every relay.
        assert_eq!(s.relays_for("invoices"), s.relays);
        assert_eq!(s.relays_for("admin"), s.relays);
        assert_eq!(s.relay_users(&a), ids(&["invoices", "admin"]));
        s.validate(true).unwrap();

        // One relay for the public key only (written with a trailing slash).
        s.relay_keys.insert(format!("{b}/"), ids(&["invoices"]));
        assert_eq!(s.relay_users(&b), ids(&["invoices"]));
        assert_eq!(s.relays_for("admin"), std::slice::from_ref(&a));
        assert_eq!(s.relays_for("invoices"), s.relays);
        s.validate(true).unwrap();
        assert!(same_relay("wss://x.example/", "wss://x.example"));
    }

    #[test]
    fn a_key_must_keep_a_relay_and_a_proxy() {
        let mut s = defaults();
        let all = s.relays.clone();
        // Every relay given to the administration key leaves the public key with none.
        s.relay_keys = all.iter().map(|r| (r.clone(), ids(&["admin"]))).collect();
        let e = err(&s);
        assert!(e.contains("no relay is assigned to the public invoices key"), "{e}");
        s.relay_keys = all.iter().map(|r| (r.clone(), ids(&["invoices"]))).collect();
        let e = err(&s);
        assert!(e.contains("no relay is assigned to the administration key"), "{e}");
        s.relay_keys = [(all[0].clone(), ids(&["root"]))].into();
        let e = err(&s);
        assert!(e.contains("no key 'root'"), "{e}");
        s.relay_keys.clear();

        // Proxies for some keys only: each key's own default route.
        s.proxies.list = vec![entry("a", "socks5://h:1"), entry("b", "socks5://h:2")];
        s.proxies.default = Destination::Proxy("a".into());
        s.proxies.default_keys = [("admin".to_string(), Destination::Proxy("b".into()))].into();
        s.validate(true).unwrap();
        s.proxies.default_keys = [("root".to_string(), Destination::Proxy("b".into()))].into();
        let e = err(&s);
        assert!(e.contains("default route: there is no key 'root'"), "{e}");
    }

    #[test]
    fn proxy_fields_from_before_groups_are_refused() {
        for old in [
            serde_json::json!({ "proxies": { "mode": "chaos" } }),
            serde_json::json!({ "proxies": { "list": [{ "url": "socks5://h:1", "keys": ["admin"] }] } }),
        ] {
            let e = serde_json::from_value::<SettingsPatch>(old).unwrap_err().to_string();
            assert!(e.contains("from before proxy groups"), "{e}");
        }
    }

    fn legacy_env(list: &[&str], mode: legacy::ProxyMode) -> legacy::ProxySettings {
        legacy::ProxySettings {
            list: list
                .iter()
                .enumerate()
                .map(|(i, url)| legacy::ProxyEntry {
                    id: format!("env{}", i + 1),
                    name: String::new(),
                    url: url.to_string(),
                    keys: Vec::new(),
                    pool: true,
                    i2p: false,
                })
                .collect(),
            mode,
            ..legacy::ProxySettings::default()
        }
    }

    #[test]
    fn settings_stored_before_groups_are_upgraded_keeping_what_they_set() {
        use legacy::ProxyMode;
        let env = legacy_env(&["socks5://e:1", "socks5://e:2"], ProxyMode::Failover);
        let up = |json: serde_json::Value| upgrade_stored(&json.to_string(), &env).unwrap();
        // Nothing about proxies: nothing about proxies, whatever the environment says.
        let p = up(serde_json::json!({ "pow_bits": 22 }));
        assert_eq!((p.pow_bits, p.proxies), (Some(22), None));
        // Only the policy: only the policy.
        let p = up(serde_json::json!({ "proxies": { "offline": "open", "transparent": false } }))
            .proxies
            .unwrap();
        assert_eq!(
            (p.offline, p.transparent, p.list, p.default),
            (Some(OfflinePolicy::Open), Some(false), None, None)
        );
        // The strategy: the environment's proxies stay the environment's, the
        // group and the default route are kept.
        let p = up(serde_json::json!({ "proxies": { "mode": "round_robin", "rotate_secs": 600 } }))
            .proxies
            .unwrap();
        assert!(p.list.is_none());
        let g = &p.groups.as_ref().unwrap()[0];
        assert_eq!(
            (g.strategy, g.rotate_secs, g.proxies.len()),
            (Strategy::RoundRobin, 600, 2)
        );
        assert_eq!(p.default, Some(Destination::Group("default".into())));
        // A list: kept, with what it means for the default route; rules too.
        let p = up(serde_json::json!({ "proxies": {
            "list": [{ "id": "tor", "url": "socks5://t:1", "pool": false }, { "id": "a", "url": "socks5://a:1" }],
            "rules": [{ "match": ["*.onion"], "to": { "proxy": "tor" } }, { "match": ["b.example"], "to": "pool" }],
            "i2p_registries": []
        } }))
        .proxies
        .unwrap();
        let list = p.list.as_ref().unwrap();
        assert_eq!((list[0].id.as_deref(), list.len()), (Some("tor"), 2));
        assert_eq!(p.default, Some(Destination::Proxy("a".into())));
        assert_eq!(p.groups, Some(Vec::new()));
        let rules = p.rules.as_ref().unwrap();
        assert_eq!(
            (&rules[1].to, &rules[1].fallback),
            (&Destination::Proxy("a".into()), &crate::routes::Fallback::Policy)
        );
        assert_eq!(p.i2p_registries, Some(Vec::new()));
        // The single address of the first versions: that proxy; empty: none.
        let p = up(serde_json::json!({ "proxy": "socks5://s:1" })).proxies.unwrap();
        assert_eq!(p.list.as_ref().unwrap()[0].id.as_deref(), Some("saved"));
        assert_eq!(p.default, Some(Destination::Proxy("saved".into())));
        let p = up(serde_json::json!({ "proxy": "" })).proxies.unwrap();
        assert_eq!((p.list, p.default), (Some(Vec::new()), Some(Destination::Direct)));
        // Applied over the environment, it routes as before: the transparent
        // claim changes what an empty lane means, and that is kept.
        let no_env = legacy_env(&[], ProxyMode::Off);
        let p = upgrade_stored(
            &serde_json::json!({ "proxies": { "list": [{ "id": "a", "url": "socks5://a:1", "pool": false }] } })
                .to_string(),
            &no_env,
        )
        .unwrap();
        assert_eq!(p.proxies.as_ref().unwrap().default, Some(Destination::Block));
        let p = upgrade_stored(
            &serde_json::json!({ "proxies": { "transparent": true } }).to_string(),
            &env,
        )
        .unwrap();
        assert_eq!(p.proxies.as_ref().unwrap().default, None, "the same with or without");
        // What cannot be read either way is an error.
        for bad in ["{not json", r#"{"nope":1}"#, r#"{"proxies":{"list":3}}"#] {
            assert!(upgrade_stored(bad, &env).is_err(), "{bad}");
        }
    }

    #[test]
    fn relay_assignments_travel_in_patches() {
        let base = defaults();
        let (a, b) = (base.relays[0].clone(), base.relays[1].clone());
        let patch: SettingsPatch = serde_json::from_value(serde_json::json!({
            "relay_keys": { (b.clone()): ["invoices"], "wss://gone.example": ["admin"], (a.clone()): [] }
        }))
        .unwrap();
        assert_eq!(patch.names(), ["relay_keys"]);
        // Entries for relays that are not listed, or that name no key, mean nothing.
        let applied = patch.apply(&base);
        assert_eq!(applied.relay_keys, [(b.clone(), ids(&["invoices"]))].into());

        // Removing a relay drops its assignment with it.
        let drop_b: SettingsPatch = serde_json::from_value(serde_json::json!({ "relays": [a.clone()] })).unwrap();
        let mut stored = patch.clone();
        stored.merge(&drop_b);
        assert!(stored.apply(&base).relay_keys.is_empty());

        // A newer assignment replaces the stored one as a whole.
        let newer: SettingsPatch =
            serde_json::from_value(serde_json::json!({ "relay_keys": { (a.clone()): ["admin"] } })).unwrap();
        let mut stored = patch;
        stored.merge(&newer);
        assert_eq!(stored.apply(&base).relay_keys, [(a, ids(&["admin"]))].into());
    }

    #[test]
    fn settings_saved_before_i2p_load_and_names_follow_the_relays() {
        let old: ProxySettings = serde_json::from_value(serde_json::json!({
            "list": [{ "id": "a", "name": "", "url": "http://127.0.0.1:4444" }],
            "default": { "proxy": "a" }, "offline": "kill_switch", "transparent": false
        }))
        .unwrap();
        assert!(!old.list[0].i2p);
        assert_eq!(old.i2p_registries, crate::i2p::default_registries());
        // The I2P marker survives a round trip through a patch.
        let mut marked = old.clone();
        marked.list[0].i2p = true;
        let mut back = ProxySettings::default();
        ProxyPatch::with_list(&marked.list).apply(&mut back);
        assert!(back.list[0].i2p);

        let base = defaults();
        let relay = base.relays[0].clone();
        let named: SettingsPatch = serde_json::from_value(serde_json::json!({
            "relay_names": { (relay.clone()): "nostr-not.i2p", "wss://gone.example": "x", (format!("{relay}/")): " " }
        }))
        .unwrap();
        assert_eq!(named.names(), ["relay_names"]);
        let s = named.apply(&base);
        assert_eq!(s.relay_names, [(relay.clone(), "nostr-not.i2p".to_string())].into());
        s.validate(true).unwrap();
        // A relay taken off the list loses its name.
        let mut stored = named.clone();
        stored.merge(&serde_json::from_value(serde_json::json!({ "relays": ["wss://other.example"] })).unwrap());
        assert!(stored.apply(&base).relay_names.is_empty());
    }

    #[test]
    fn the_network_part_is_taken_out_and_put_back_whole() {
        let base = defaults();
        let mut changed = base.clone();
        changed.relays.push("wss://other.example".into());
        changed.relay_keys.insert("wss://other.example".into(), ids(&["admin"]));
        changed.relay_names.insert("wss://other.example".into(), "Other".into());
        changed.proxies.transparent = true;
        let network = changed.network();
        assert_eq!(
            (
                &network.relays,
                &network.relay_keys,
                &network.relay_names,
                &network.proxies
            ),
            (
                &changed.relays,
                &changed.relay_keys,
                &changed.relay_names,
                &changed.proxies
            )
        );
        // Put into other settings, only the network part changes.
        let mut other = base.clone();
        other.set_network(network);
        assert_eq!(other, changed);
        // The lanes are this service's keys, whatever the settings say.
        let topology = changed.topology();
        assert_eq!(topology.settings, changed.network());
        let lanes: Vec<(&str, &str)> = topology
            .lanes
            .iter()
            .map(|l| (l.id.as_str(), l.label.as_str()))
            .collect();
        assert_eq!(lanes, [("invoices", "Public invoices"), ("admin", "Administration")]);
    }
}
