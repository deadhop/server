//! The network part of a service's settings (relays, who uses which relay,
//! relay names, proxies and routing rules) and the lanes that use it.
//!
//! A lane is one independent set of relay connections with its own identity:
//! this service has one per key. The host declares its lanes; settings refer
//! to them by id (on the wire the field is still called `keys`).

use std::collections::BTreeMap;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Inclusive bounds of the network settings.
pub mod bounds {
    pub const NAME_LEN: usize = 60;
    /// Most proxies in the list.
    pub const PROXIES: usize = 8;
    /// Every switch of proxy reconnects every relay, so intervals have a floor.
    pub const PROXY_INTERVAL_SECS: (u64, u64) = (60, 7 * 86_400);
    pub const PROXY_ID_LEN: usize = 24;
}

/// One lane, as its host declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    /// What settings call it.
    pub id: String,
    /// What people call it, as in "the Administration key".
    pub label: String,
}

/// Whether a list of lane ids assigns something to `id`. An empty list is
/// every lane.
pub fn assigned(keys: &[String], id: &str) -> bool {
    keys.is_empty() || keys.iter().any(|k| k == id)
}

/// Check that every id names a lane, and none is named twice.
pub fn check_ids(lanes: &[Lane], keys: &[String], what: &str) -> Result<()> {
    for (i, k) in keys.iter().enumerate() {
        if !lanes.iter().any(|l| &l.id == k) {
            return Err(Error::InvalidParams(format!("{what}: there is no key '{k}'")));
        }
        if keys[..i].contains(k) {
            return Err(Error::InvalidParams(format!("{what}: key '{k}' is named twice")));
        }
    }
    Ok(())
}

/// A relay address without a trailing slash, so `wss://a` and `wss://a/` are one relay.
pub fn relay_key(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Whether two relay addresses are the same relay.
pub fn same_relay(a: &str, b: &str) -> bool {
    relay_key(a) == relay_key(b)
}

pub fn within(name: &str, v: u64, (min, max): (u64, u64)) -> Result<()> {
    if v < min || v > max {
        return Err(Error::InvalidParams(format!("{name} must be between {min} and {max}")));
    }
    Ok(())
}

pub fn take<T: Clone>(slot: &mut T, v: &Option<T>) {
    if let Some(v) = v {
        *slot = v.clone();
    }
}

pub fn keep<T: Clone>(slot: &mut Option<T>, v: &Option<T>) {
    if v.is_some() {
        slot.clone_from(v);
    }
}

// One proxy in the ordered list. `id` is stable across reorders and edits, so
// a password the dashboard never sees (it shows `***`) is kept when the list
// is saved again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxyEntry {
    pub id: String,
    // Optional label for the dashboard.
    pub name: String,
    // `socks5://`, `https://` or `http://` url.
    pub url: String,
    // The keys (by id) whose default route may use this proxy; empty is every key.
    #[serde(default)]
    pub keys: Vec<String>,
    // Whether this proxy is in the default route (the pool). A proxy left out
    // is used only by routing rules that name it.
    #[serde(default = "in_pool")]
    pub pool: bool,
    // This is an I2P router's HTTP proxy, the one used to look up I2P names.
    #[serde(default)]
    pub i2p: bool,
}

fn in_pool() -> bool {
    true
}

// How the proxies in the list are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    // The first proxy in the list only, never another: while it is down the
    // offline policy applies.
    Off,
    // The first reachable proxy in list order; the next one when it fails.
    Failover,
    // Take the reachable proxies in turn, one change every `rotate_secs`.
    RoundRobin,
    // Change to a random reachable proxy after a random time between
    // `chaos_min_secs` and `chaos_max_secs`.
    Chaos,
}

// What the service does while no proxy is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfflinePolicy {
    // Disconnect from every relay: the service is off until a proxy is back.
    KillSwitch,
    // Connect straight (clearnet) but answer operators only, so the proxies
    // can be repaired (unless they are locked on the host).
    AdminOnly,
    // Connect straight but answer invoicing only; operators are not served.
    InvoicingOnly,
    // Connect straight and carry on as usual.
    Open,
}

// Relay proxies: an ordered list, how to choose among them, and what to do
// when none works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProxySettings {
    pub list: Vec<ProxyEntry>,
    pub mode: ProxyMode,
    // Round robin: seconds between changes.
    pub rotate_secs: u64,
    // Chaos: shortest and longest time (seconds) before the next change.
    pub chaos_min_secs: u64,
    pub chaos_max_secs: u64,
    pub offline: OfflinePolicy,
    // The operator runs a transparent proxy around this service: it is not
    // checked, the list is ignored and privacy warnings about the proxy are
    // not raised.
    pub transparent: bool,
    // Routing rules, in order: the first that matches a relay decides its
    // route; a relay none matches takes the default route (the list above).
    #[serde(default)]
    pub rules: Vec<crate::routes::Rule>,
    // I2P name registries (jump services) asked through the I2P proxy, as url
    // templates with a `{name}` placeholder. Empty turns lookups off.
    #[serde(default = "crate::i2p::default_registries")]
    pub i2p_registries: Vec<String>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        ProxySettings {
            list: Vec::new(),
            mode: ProxyMode::Off,
            rotate_secs: 3_600,
            chaos_min_secs: 300,
            chaos_max_secs: 900,
            offline: OfflinePolicy::KillSwitch,
            transparent: false,
            rules: Vec::new(),
            i2p_registries: crate::i2p::default_registries(),
        }
    }
}

// A proxy as sent from the dashboard. A missing `id` makes a new entry; a
// url shown as `***` (what the dashboard receives) keeps the stored password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyEntryInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub url: String,
    // The keys that may use this proxy; left out or empty is every key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    // In the default route; left out is yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<bool>,
    // An I2P router's HTTP proxy; left out is no.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2p: Option<bool>,
}

// Partial update of [`ProxySettings`]; `list` replaces the whole list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<Vec<ProxyEntryInput>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ProxyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chaos_min_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chaos_max_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<OfflinePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent: Option<bool>,
    // Replaces the whole rule list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<crate::routes::Rule>>,
    // Replaces the whole registry list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2p_registries: Option<Vec<String>>,
}

fn new_proxy_id() -> String {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("the system has a random source");
    format!("p{}", hex::encode(b))
}

pub fn entries_from(list: &[ProxyEntryInput]) -> Vec<ProxyEntry> {
    list.iter()
        .enumerate()
        .map(|(i, e)| ProxyEntry {
            id: e.id.clone().unwrap_or_else(|| format!("p{i}")),
            name: e.name.clone().unwrap_or_default(),
            url: e.url.clone(),
            keys: e.keys.clone().unwrap_or_default(),
            pool: e.pool.unwrap_or(true),
            i2p: e.i2p.unwrap_or(false),
        })
        .collect()
}

impl ProxyPatch {
    // A patch that sets the whole list and nothing else.
    pub fn with_list(list: &[ProxyEntry]) -> ProxyPatch {
        ProxyPatch {
            list: Some(
                list.iter()
                    .map(|e| ProxyEntryInput {
                        id: Some(e.id.clone()),
                        name: Some(e.name.clone()),
                        url: e.url.clone(),
                        keys: Some(e.keys.clone()),
                        pool: Some(e.pool),
                        i2p: Some(e.i2p),
                    })
                    .collect(),
            ),
            ..ProxyPatch::default()
        }
    }

    // Give new entries an id, and put back the real url of entries sent with
    // a hidden password. Afterwards every entry has an id and a usable url.
    pub fn resolve(&mut self, current: &[ProxyEntry]) -> Result<()> {
        let Some(list) = &mut self.list else { return Ok(()) };
        for input in list.iter_mut() {
            let stored = match &input.id {
                Some(id) => current.iter().find(|c| &c.id == id),
                None => current.iter().find(|c| deadhop_net::relay::redact(&c.url) == input.url),
            };
            if input.url.contains("***") {
                match stored.filter(|c| deadhop_net::relay::redact(&c.url) == input.url) {
                    Some(c) => input.url.clone_from(&c.url),
                    None => {
                        return Err(Error::InvalidParams(
                            "proxy: the password is hidden; type the full address again".into(),
                        ))
                    }
                }
            }
            if input.id.is_none() {
                input.id = Some(stored.map_or_else(new_proxy_id, |c| c.id.clone()));
            }
        }
        Ok(())
    }

    pub fn apply(&self, s: &mut ProxySettings) {
        if let Some(list) = &self.list {
            s.list = entries_from(list);
        }
        take(&mut s.mode, &self.mode);
        take(&mut s.rotate_secs, &self.rotate_secs);
        take(&mut s.chaos_min_secs, &self.chaos_min_secs);
        take(&mut s.chaos_max_secs, &self.chaos_max_secs);
        take(&mut s.offline, &self.offline);
        take(&mut s.transparent, &self.transparent);
        if let Some(rules) = &self.rules {
            s.rules.clone_from(rules);
        }
        if let Some(r) = &self.i2p_registries {
            s.i2p_registries.clone_from(r);
        }
    }

    pub fn merge(&mut self, o: &ProxyPatch) {
        keep(&mut self.list, &o.list);
        keep(&mut self.mode, &o.mode);
        keep(&mut self.rotate_secs, &o.rotate_secs);
        keep(&mut self.chaos_min_secs, &o.chaos_min_secs);
        keep(&mut self.chaos_max_secs, &o.chaos_max_secs);
        keep(&mut self.offline, &o.offline);
        keep(&mut self.transparent, &o.transparent);
        keep(&mut self.rules, &o.rules);
        keep(&mut self.i2p_registries, &o.i2p_registries);
    }

    pub fn names(&self, out: &mut Vec<String>) {
        let fields = [
            ("list", self.list.is_some()),
            ("mode", self.mode.is_some()),
            ("rotate_secs", self.rotate_secs.is_some()),
            ("chaos_min_secs", self.chaos_min_secs.is_some()),
            ("chaos_max_secs", self.chaos_max_secs.is_some()),
            ("offline", self.offline.is_some()),
            ("transparent", self.transparent.is_some()),
            ("rules", self.rules.is_some()),
            ("i2p_registries", self.i2p_registries.is_some()),
        ];
        out.extend(fields.iter().filter(|f| f.1).map(|f| format!("proxies.{}", f.0)));
    }
}

impl ProxySettings {
    pub fn validate(&self, lanes: &[Lane]) -> Result<()> {
        use bounds::*;
        if self.list.len() > PROXIES {
            return Err(Error::InvalidParams(format!("at most {PROXIES} proxies")));
        }
        for (i, e) in self.list.iter().enumerate() {
            let ok_id = !e.id.is_empty()
                && e.id.len() <= PROXY_ID_LEN
                && e.id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
            if !ok_id {
                return Err(Error::InvalidParams("proxy: bad id".into()));
            }
            if e.name.chars().count() > NAME_LEN || !e.name.chars().all(deadhop_net::is_plain_text) {
                return Err(Error::InvalidParams(format!(
                    "proxy name must be at most {NAME_LEN} visible characters"
                )));
            }
            check_ids(lanes, &e.keys, "proxy")?;
            if deadhop_net::relay::parse_proxy(&e.url)?.is_none() {
                return Err(Error::InvalidParams("proxy: the address is empty".into()));
            }
            if self.list[..i].iter().any(|o| o.id == e.id) {
                return Err(Error::InvalidParams("proxy: the same id is used twice".into()));
            }
            if self.list[..i].iter().any(|o| o.url == e.url) {
                return Err(Error::InvalidParams("proxy: the same address is listed twice".into()));
            }
            if e.i2p {
                if !e.url.trim().to_ascii_lowercase().starts_with("http://") {
                    return Err(Error::InvalidParams(
                        "proxy: an I2P router proxy must be its http:// proxy".into(),
                    ));
                }
                if self.list[..i].iter().any(|o| o.i2p) {
                    return Err(Error::InvalidParams("proxy: at most one I2P router proxy".into()));
                }
            }
        }
        if self.i2p_registries.len() > crate::i2p::MAX_REGISTRIES {
            return Err(Error::InvalidParams(format!(
                "at most {} I2P name registries",
                crate::i2p::MAX_REGISTRIES
            )));
        }
        for (i, r) in self.i2p_registries.iter().enumerate() {
            crate::i2p::check_registry(r)?;
            if self.i2p_registries[..i].contains(r) {
                return Err(Error::InvalidParams("I2P registry: listed twice".into()));
            }
        }
        within("proxies.rotate_secs", self.rotate_secs, PROXY_INTERVAL_SECS)?;
        within("proxies.chaos_min_secs", self.chaos_min_secs, PROXY_INTERVAL_SECS)?;
        within("proxies.chaos_max_secs", self.chaos_max_secs, PROXY_INTERVAL_SECS)?;
        if self.chaos_min_secs > self.chaos_max_secs {
            return Err(Error::InvalidParams(
                "proxies.chaos_min_secs exceeds proxies.chaos_max_secs".into(),
            ));
        }
        Ok(())
    }

    // Replace each url's password with `***`.
    pub fn redacted(&self) -> ProxySettings {
        let mut s = self.clone();
        s.list
            .iter_mut()
            .for_each(|e| e.url = deadhop_net::relay::redact(&e.url));
        s
    }
}

/// The network settings of a service: what is stored and shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NetworkSettings {
    pub relays: Vec<String>,
    /// Relays that only some lanes use: relay url to lane ids. A relay not
    /// listed here is used by every lane.
    #[serde(default)]
    pub relay_keys: BTreeMap<String, Vec<String>>,
    /// Names shown for relays (such as the I2P name behind a b32 address):
    /// relay url to name. Connections always use the url.
    #[serde(default)]
    pub relay_names: BTreeMap<String, String>,
    /// Proxies for relay connections only.
    pub proxies: ProxySettings,
}

/// The network settings together with the lanes of the service they belong
/// to: everything that decides where a relay connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    pub settings: NetworkSettings,
    pub lanes: Vec<Lane>,
}

impl std::ops::Deref for Topology {
    type Target = NetworkSettings;
    fn deref(&self) -> &NetworkSettings {
        &self.settings
    }
}

impl std::ops::DerefMut for Topology {
    fn deref_mut(&mut self) -> &mut NetworkSettings {
        &mut self.settings
    }
}

impl Topology {
    /// The keys (by id) that use this relay.
    pub fn relay_users(&self, relay: &str) -> Vec<String> {
        match self.relay_keys.iter().find(|(url, _)| same_relay(url, relay)) {
            Some((_, keys)) => keys.clone(),
            None => self.lanes.iter().map(|k| k.id.clone()).collect(),
        }
    }

    /// The relays one key connects to, in list order.
    pub fn relays_for(&self, key: &str) -> Vec<String> {
        self.relays
            .iter()
            .filter(|r| self.relay_users(r).iter().any(|k| k == key))
            .cloned()
            .collect()
    }

    /// The relays used by any of the keys a proxy carries (empty: every key),
    /// in list order.
    pub fn relays_through(&self, proxy_keys: &[String]) -> Vec<String> {
        self.relays
            .iter()
            .filter(|r| self.relay_users(r).iter().any(|k| assigned(proxy_keys, k)))
            .cloned()
            .collect()
    }

    /// Check the network settings and every relationship between them and
    /// the lanes, except the relay list itself.
    pub fn validate(&self) -> Result<()> {
        use bounds::NAME_LEN;
        self.proxies.validate(&self.lanes)?;
        crate::routes::check_rules(self)?;
        // A key whose relays may take the default route needs a proxy in it:
        // otherwise those relays would connect straight while the rest hide
        // behind one. That must be chosen by taking the proxies away, not by
        // forgetting a key.
        let proxies = &self.proxies;
        if !proxies.transparent && !proxies.list.is_empty() {
            if let Some(k) = self.lanes.iter().find(|k| {
                crate::routes::uses_default(self, &k.id)
                    && !proxies.list.iter().any(|e| e.pool && assigned(&e.keys, &k.id))
            }) {
                return Err(Error::InvalidParams(format!(
                    "no proxy in the default route is assigned to the {} key, which would connect without one",
                    k.label.to_lowercase()
                )));
            }
        }
        for keys in self.relay_keys.values() {
            check_ids(&self.lanes, keys, "relay")?;
        }
        for name in self.relay_names.values() {
            if name.trim().is_empty()
                || name.chars().count() > NAME_LEN
                || !name.chars().all(deadhop_net::is_plain_text)
            {
                return Err(Error::InvalidParams(format!(
                    "relay names must be 1 to {NAME_LEN} visible characters"
                )));
            }
        }
        if let Some(k) = self.lanes.iter().find(|k| self.relays_for(&k.id).is_empty()) {
            return Err(Error::InvalidParams(format!(
                "no relay is assigned to the {} key, which could then not be reached",
                k.label.to_lowercase()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{Fallback, RouteTo, Rule};

    fn lanes() -> Vec<Lane> {
        [("invoices", "Public invoices"), ("admin", "Administration")]
            .iter()
            .map(|(id, label)| Lane {
                id: id.to_string(),
                label: label.to_string(),
            })
            .collect()
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn entry(id: &str, url: &str) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: String::new(),
            url: url.into(),
            keys: Vec::new(),
            pool: true,
            i2p: false,
        }
    }

    fn topology(relays: &[&str]) -> Topology {
        Topology {
            settings: NetworkSettings {
                relays: ids(relays),
                relay_keys: BTreeMap::new(),
                relay_names: BTreeMap::new(),
                proxies: ProxySettings::default(),
            },
            lanes: lanes(),
        }
    }

    fn why<T: std::fmt::Debug>(r: Result<T>) -> String {
        r.unwrap_err().to_string()
    }

    #[test]
    fn lane_ids_are_assigned_and_checked() {
        assert!(assigned(&[], "admin") && assigned(&ids(&["admin"]), "admin"));
        assert!(!assigned(&ids(&["invoices"]), "admin"));
        check_ids(&lanes(), &ids(&["admin", "invoices"]), "relay").unwrap();
        assert_eq!(
            why(check_ids(&lanes(), &ids(&["nobody"]), "relay")),
            "invalid parameters: relay: there is no key 'nobody'"
        );
        assert_eq!(
            why(check_ids(&lanes(), &ids(&["admin", "admin"]), "proxy")),
            "invalid parameters: proxy: key 'admin' is named twice"
        );
    }

    #[test]
    fn small_helpers_do_what_they_say() {
        assert_eq!(relay_key("wss://a/"), "wss://a");
        assert!(same_relay("wss://a", "wss://a/") && !same_relay("wss://a", "wss://b"));
        within("x", 5, (1, 5)).unwrap();
        assert_eq!(
            why(within("x", 6, (1, 5))),
            "invalid parameters: x must be between 1 and 5"
        );
        assert!(within("x", 0, (1, 5)).is_err());
        let mut slot = 1;
        take(&mut slot, &None);
        assert_eq!(slot, 1);
        take(&mut slot, &Some(2));
        assert_eq!(slot, 2);
        let mut kept = Some(1);
        keep(&mut kept, &None);
        assert_eq!(kept, Some(1));
        keep(&mut kept, &Some(3));
        assert_eq!(kept, Some(3));
    }

    #[test]
    fn a_proxy_patch_fills_in_ids_keeps_hidden_passwords_and_applies_whole() {
        let stored = vec![
            entry("tor", "socks5://127.0.0.1:9050"),
            entry("vpn", "socks5://user:secret@10.8.0.1:1080"),
        ];
        // What the dashboard sends back: ids, and the password shown as ***.
        let mut patch = ProxyPatch::with_list(&stored);
        patch.list.as_mut().unwrap()[1].url = "socks5://user:***@10.8.0.1:1080".into();
        patch.resolve(&stored).unwrap();
        assert_eq!(patch.list.as_ref().unwrap()[1].url, stored[1].url);
        // Without an id, the stored entry with the same (hidden) address is meant.
        let input = |url: &str| ProxyEntryInput {
            id: None,
            name: None,
            url: url.into(),
            keys: None,
            pool: None,
            i2p: None,
        };
        let mut by_address = ProxyPatch {
            list: Some(vec![input("socks5://user:***@10.8.0.1:1080"), input("socks5://new:1")]),
            ..ProxyPatch::default()
        };
        by_address.resolve(&stored).unwrap();
        let list = by_address.list.clone().unwrap();
        assert_eq!(
            (list[0].id.as_deref(), list[0].url.as_str()),
            (Some("vpn"), stored[1].url.as_str())
        );
        let fresh = list[1].id.clone().unwrap();
        assert!(fresh.starts_with('p') && fresh.len() == 9, "{fresh}");
        // A hidden password with nothing stored behind it cannot be used.
        let mut lost = ProxyPatch {
            list: Some(vec![input("socks5://who:***@h:1")]),
            ..ProxyPatch::default()
        };
        assert!(why(lost.resolve(&stored)).contains("the password is hidden"));
        let mut wrong_id = ProxyPatch {
            list: Some(vec![ProxyEntryInput {
                id: Some("tor".into()),
                ..input("socks5://user:***@10.8.0.1:1080")
            }]),
            ..ProxyPatch::default()
        };
        assert!(wrong_id.resolve(&stored).is_err());
        // No list in the patch: nothing to do.
        ProxyPatch::default().resolve(&stored).unwrap();

        // Entries get their defaults; everything set is applied, the rest is kept.
        let made = entries_from(&[input("socks5://a:1"), input("socks5://b:1")]);
        assert_eq!((made[0].id.as_str(), made[1].id.as_str()), ("p0", "p1"));
        assert!(made[0].pool && !made[0].i2p && made[0].keys.is_empty() && made[0].name.is_empty());
        let rule = Rule {
            name: String::new(),
            patterns: ids(&["*.onion"]),
            keys: Vec::new(),
            to: RouteTo::Block,
            fallback: Fallback::Offline,
        };
        let full = ProxyPatch {
            list: by_address.list.clone(),
            mode: Some(ProxyMode::Chaos),
            rotate_secs: Some(120),
            chaos_min_secs: Some(61),
            chaos_max_secs: Some(62),
            offline: Some(OfflinePolicy::Open),
            transparent: Some(true),
            rules: Some(vec![rule.clone()]),
            i2p_registries: Some(ids(&["http://reg.i2p/?q={name}"])),
        };
        let mut s = ProxySettings::default();
        ProxyPatch::default().apply(&mut s);
        assert_eq!(s, ProxySettings::default());
        full.apply(&mut s);
        assert_eq!(
            (s.list.len(), s.mode, s.rotate_secs, s.chaos_min_secs, s.chaos_max_secs),
            (2, ProxyMode::Chaos, 120, 61, 62)
        );
        assert_eq!(
            (s.offline, s.transparent, s.rules.len()),
            (OfflinePolicy::Open, true, 1)
        );
        assert_eq!(s.i2p_registries, ids(&["http://reg.i2p/?q={name}"]));
        // Merging keeps what the newer patch does not mention.
        let mut merged = ProxyPatch {
            mode: Some(ProxyMode::Failover),
            ..ProxyPatch::default()
        };
        merged.merge(&ProxyPatch::default());
        assert_eq!(merged.mode, Some(ProxyMode::Failover));
        merged.merge(&full);
        assert_eq!(merged, full);
        let mut names = Vec::new();
        ProxyPatch::default().names(&mut names);
        assert!(names.is_empty());
        full.names(&mut names);
        assert_eq!(
            names,
            [
                "proxies.list",
                "proxies.mode",
                "proxies.rotate_secs",
                "proxies.chaos_min_secs",
                "proxies.chaos_max_secs",
                "proxies.offline",
                "proxies.transparent",
                "proxies.rules",
                "proxies.i2p_registries"
            ]
        );
        assert_eq!(s.redacted().list[0].url, "socks5://user:***@10.8.0.1:1080");
    }

    #[test]
    fn proxy_settings_are_checked() {
        let with = |list: Vec<ProxyEntry>| ProxySettings {
            list,
            ..ProxySettings::default()
        };
        let named = |id: &str, f: &dyn Fn(&mut ProxyEntry)| {
            let mut e = entry(id, &format!("socks5://{id}:1"));
            f(&mut e);
            e
        };
        with(vec![entry("tor", "socks5://h:1")]).validate(&lanes()).unwrap();
        let nine = (0..9)
            .map(|i| entry(&format!("p{i}"), &format!("socks5://h{i}:1")))
            .collect();
        let cases: Vec<(ProxySettings, &str)> =
            vec![
            (with(nine), "at most 8 proxies"),
            (with(vec![entry("Bad Id", "socks5://h:1")]), "proxy: bad id"),
            (with(vec![entry("", "socks5://h:1")]), "proxy: bad id"),
            (with(vec![entry(&"a".repeat(25), "socks5://h:1")]), "proxy: bad id"),
            (
                with(vec![named("a", &|e| e.name = "n".repeat(61))]),
                "proxy name must be at most 60 visible characters",
            ),
            (
                with(vec![named("a", &|e| e.name = "a\u{200b}b".into())]),
                "proxy name must be at most 60 visible characters",
            ),
            (with(vec![named("a", &|e| e.keys = ids(&["nobody"]))]), "proxy: there is no key 'nobody'"),
            (with(vec![entry("a", "")]), "proxy: the address is empty"),
            (with(vec![entry("a", "ftp://h:1")]), "proxy: scheme must be socks5://, https:// or http://"),
            (
                with(vec![entry("a", "socks5://h:1"), entry("a", "socks5://h:2")]),
                "proxy: the same id is used twice",
            ),
            (
                with(vec![entry("a", "socks5://h:1"), entry("b", "socks5://h:1")]),
                "proxy: the same address is listed twice",
            ),
            (
                with(vec![named("a", &|e| e.i2p = true)]),
                "proxy: an I2P router proxy must be its http:// proxy",
            ),
            (
                with(vec![
                    named("a", &|e| (e.i2p, e.url) = (true, "http://h:1".into())),
                    named("b", &|e| (e.i2p, e.url) = (true, "HTTP://h:2".into())),
                ]),
                "proxy: at most one I2P router proxy",
            ),
            (
                ProxySettings {
                    i2p_registries: (0..5).map(|i| format!("http://r{i}.i2p/?q={{name}}")).collect(),
                    ..ProxySettings::default()
                },
                "at most 4 I2P name registries",
            ),
            (
                ProxySettings {
                    i2p_registries: ids(&["http://example.com/?q={name}"]),
                    ..ProxySettings::default()
                },
                "I2P registry 'http://example.com/?q={name}' must name a lowercase .i2p host with no port or user name",
            ),
            (
                ProxySettings {
                    i2p_registries: ids(&["http://a.i2p/?q={name}", "http://a.i2p/?q={name}"]),
                    ..ProxySettings::default()
                },
                "I2P registry: listed twice",
            ),
            (
                ProxySettings {
                    rotate_secs: 1,
                    ..ProxySettings::default()
                },
                "proxies.rotate_secs must be between 60 and 604800",
            ),
            (
                ProxySettings {
                    chaos_min_secs: 1,
                    ..ProxySettings::default()
                },
                "proxies.chaos_min_secs must be between 60 and 604800",
            ),
            (
                ProxySettings {
                    chaos_max_secs: 1,
                    ..ProxySettings::default()
                },
                "proxies.chaos_max_secs must be between 60 and 604800",
            ),
            (
                ProxySettings {
                    chaos_min_secs: 900,
                    chaos_max_secs: 300,
                    ..ProxySettings::default()
                },
                "proxies.chaos_min_secs exceeds proxies.chaos_max_secs",
            ),
        ];
        for (settings, text) in cases {
            assert_eq!(why(settings.validate(&lanes())), format!("invalid parameters: {text}"));
        }
        // An I2P router's own http:// proxy is fine.
        with(vec![named("i2p", &|e| {
            (e.i2p, e.url, e.pool) = (true, "http://127.0.0.1:4444".into(), false)
        })])
        .validate(&lanes())
        .unwrap();
    }

    #[test]
    fn a_topology_says_which_lane_uses_which_relay() {
        let (a, b) = ("wss://a.example", "wss://b.example");
        let mut t = topology(&[a, b]);
        assert_eq!(t.relay_users(a), ids(&["invoices", "admin"]));
        assert_eq!(t.relays_for("admin"), ids(&[a, b]));
        // One relay for one lane only (the address may end in a slash).
        t.relay_keys.insert(format!("{b}/"), ids(&["invoices"]));
        assert_eq!(t.relay_users(b), ids(&["invoices"]));
        assert_eq!(t.relays_for("admin"), ids(&[a]));
        assert_eq!(t.relays_for("invoices"), ids(&[a, b]));
        assert_eq!(t.relays_through(&ids(&["admin"])), ids(&[a]));
        assert_eq!(t.relays_through(&[]), ids(&[a, b]));
        // The settings are reached through the topology, and can be changed there.
        assert_eq!(t.relays.len(), 2);
        t.relays.pop();
        assert_eq!(t.settings.relays, ids(&[a]));
    }

    #[test]
    fn a_topology_is_checked_as_a_whole() {
        let (a, b) = ("wss://a.example", "wss://b.example");
        topology(&[a, b]).validate().unwrap();
        let refused = |change: &dyn Fn(&mut Topology)| {
            let mut t = topology(&[a, b]);
            change(&mut t);
            why(t.validate())
        };
        // The proxies and the rules are checked first.
        assert_eq!(
            refused(&|t| t.proxies.rotate_secs = 1),
            "invalid parameters: proxies.rotate_secs must be between 60 and 604800"
        );
        assert_eq!(
            refused(&|t| t.proxies.rules = vec![Rule {
                name: String::new(),
                patterns: Vec::new(),
                keys: Vec::new(),
                to: RouteTo::Block,
                fallback: Fallback::Offline,
            }]),
            "invalid parameters: rule 1: between 1 and 16 relays or patterns are required"
        );
        // A lane whose relays take the default route needs a proxy in it.
        assert_eq!(
            refused(&|t| {
                let mut tor = entry("tor", "socks5://h:1");
                tor.keys = ids(&["invoices"]);
                t.proxies.list = vec![tor];
            }),
            "invalid parameters: no proxy in the default route is assigned to the administration key, which would \
             connect without one"
        );
        // With a transparent proxy, or a proxy for every lane, there is nothing to forget.
        let mut ok = topology(&[a, b]);
        ok.proxies.list = vec![entry("tor", "socks5://h:1")];
        ok.validate().unwrap();
        ok.proxies.list[0].keys = ids(&["invoices"]);
        ok.proxies.transparent = true;
        ok.validate().unwrap();
        assert_eq!(
            refused(&|t| {
                t.relay_keys.insert(a.into(), ids(&["nobody"]));
            }),
            "invalid parameters: relay: there is no key 'nobody'"
        );
        for bad in [" ".to_string(), "n".repeat(61), "a\u{202e}b".to_string()] {
            assert_eq!(
                refused(&|t| {
                    t.relay_names.insert(a.into(), bad.clone());
                }),
                "invalid parameters: relay names must be 1 to 60 visible characters"
            );
        }
        assert_eq!(
            refused(&|t| {
                t.relay_keys.insert(a.into(), ids(&["invoices"]));
                t.relay_keys.insert(b.into(), ids(&["invoices"]));
            }),
            "invalid parameters: no relay is assigned to the administration key, which could then not be reached"
        );
        let mut named = topology(&[a, b]);
        named.relay_names.insert(a.into(), "Relay A".into());
        named.validate().unwrap();
    }

    #[test]
    fn stored_proxy_settings_read_back_with_their_defaults() {
        let old: ProxySettings = serde_json::from_value(serde_json::json!({
            "list": [{ "id": "a", "name": "", "url": "http://127.0.0.1:4444" }],
            "mode": "failover", "rotate_secs": 3600, "chaos_min_secs": 300, "chaos_max_secs": 900,
            "offline": "kill_switch", "transparent": false
        }))
        .unwrap();
        assert!(old.list[0].pool && !old.list[0].i2p && old.list[0].keys.is_empty());
        assert!(old.rules.is_empty());
        assert_eq!(old.i2p_registries, crate::i2p::default_registries());
        let network: NetworkSettings =
            serde_json::from_value(serde_json::json!({ "relays": ["wss://a.example"], "proxies": old })).unwrap();
        assert!(network.relay_keys.is_empty() && network.relay_names.is_empty());
    }
}
