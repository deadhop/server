//! Proxy settings in the shape they were saved in before proxy groups (#53),
//! and [`convert`], the one way they become today's settings. A service
//! converts what its environment says and what it stored with it, once.
//!
//! Before groups, every proxy was in "the pool" unless taken out of it, a
//! proxy could be kept to some keys, and one strategy (`mode`) chose among
//! each key's pool proxies. A rule could send relays to the pool, or fall
//! back to it. The conversion keeps every key's routes exactly:
//!
//! 1. A key's lane is the pool proxies assigned to it, in list order.
//! 2. A lane becomes a destination: none is direct (no proxies at all, or a
//!    transparent proxy) or blocked (proxies, none for this key: its relays
//!    are all ruled, and an empty lane never carried one); one proxy, or the
//!    strategy off, is that first proxy; two or more is a group "Default"
//!    with the old strategy (one group per key, "Default (<key>)", when the
//!    keys' lanes differ).
//! 3. The default route is the first key's destination; another key whose
//!    destination differs gets its own (`default_keys`).
//! 4. A rule to the pool goes to the key's destination, and leaves the rest
//!    to the offline policy, as the pool did; a fallback to the pool falls
//!    back to that destination. Where the keys a rule applies to have
//!    different destinations, the rule becomes one rule per destination, in
//!    the same place. (With no proxy at all, a rule sending Tor or I2P relays
//!    to the pool, which never connected them, blocks them.)

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::network::{self, assigned, Lane, OfflinePolicy, ProxyGroup, Strategy};
use crate::routes::{self, Destination};

fn in_pool() -> bool {
    true
}

/// A proxy in the old list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProxyEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub url: String,
    /// The keys whose default route may use it; empty is every key.
    #[serde(default)]
    pub keys: Vec<String>,
    /// In the default route (the pool).
    #[serde(default = "in_pool")]
    pub pool: bool,
    #[serde(default)]
    pub i2p: bool,
}

/// The old strategy, for every key's pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    Off,
    Failover,
    RoundRobin,
    Chaos,
}

/// Where an old rule sent its relays.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTo {
    Pool,
    Direct,
    Block,
    Proxy(String),
}

/// What an old rule did while its proxy was down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    #[default]
    Offline,
    Pool,
}

/// An old routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    pub to: RouteTo,
    #[serde(default)]
    pub fallback: Fallback,
}

/// The old proxy settings, whole.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProxySettings {
    pub list: Vec<ProxyEntry>,
    pub mode: ProxyMode,
    pub rotate_secs: u64,
    pub chaos_min_secs: u64,
    pub chaos_max_secs: u64,
    pub offline: OfflinePolicy,
    pub transparent: bool,
    #[serde(default)]
    pub rules: Vec<Rule>,
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

/// An old proxy as a client sent it (and as it was stored).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProxyEntryInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub url: String,
    #[serde(default)]
    pub keys: Option<Vec<String>>,
    #[serde(default)]
    pub pool: Option<bool>,
    #[serde(default)]
    pub i2p: Option<bool>,
}

/// An old stored change of the proxy settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ProxyPatch {
    #[serde(default)]
    pub list: Option<Vec<ProxyEntryInput>>,
    #[serde(default)]
    pub mode: Option<ProxyMode>,
    #[serde(default)]
    pub rotate_secs: Option<u64>,
    #[serde(default)]
    pub chaos_min_secs: Option<u64>,
    #[serde(default)]
    pub chaos_max_secs: Option<u64>,
    #[serde(default)]
    pub offline: Option<OfflinePolicy>,
    #[serde(default)]
    pub transparent: Option<bool>,
    #[serde(default)]
    pub rules: Option<Vec<Rule>>,
    #[serde(default)]
    pub i2p_registries: Option<Vec<String>>,
}

impl ProxyPatch {
    /// Apply this patch the way the old code did.
    pub fn apply(&self, s: &mut ProxySettings) {
        if let Some(list) = &self.list {
            s.list = list
                .iter()
                .enumerate()
                .map(|(i, e)| ProxyEntry {
                    id: e.id.clone().unwrap_or_else(|| format!("p{i}")),
                    name: e.name.clone().unwrap_or_default(),
                    url: e.url.clone(),
                    keys: e.keys.clone().unwrap_or_default(),
                    pool: e.pool.unwrap_or(true),
                    i2p: e.i2p.unwrap_or(false),
                })
                .collect();
        }
        network::take(&mut s.mode, &self.mode);
        network::take(&mut s.rotate_secs, &self.rotate_secs);
        network::take(&mut s.chaos_min_secs, &self.chaos_min_secs);
        network::take(&mut s.chaos_max_secs, &self.chaos_max_secs);
        network::take(&mut s.offline, &self.offline);
        network::take(&mut s.transparent, &self.transparent);
        network::take(&mut s.rules, &self.rules);
        network::take(&mut s.i2p_registries, &self.i2p_registries);
    }

    /// Whether this patch sets where relays go by default: the list (its
    /// pool and keys) or the strategy.
    pub fn sets_default(&self) -> bool {
        self.list.is_some()
            || self.mode.is_some()
            || self.rotate_secs.is_some()
            || self.chaos_min_secs.is_some()
            || self.chaos_max_secs.is_some()
    }
}

/// The settings `old` meant, for a service with these lanes (see the module notes).
pub fn convert(old: &ProxySettings, lanes: &[Lane]) -> network::ProxySettings {
    let list = old
        .list
        .iter()
        .map(|e| network::ProxyEntry {
            id: e.id.clone(),
            name: e.name.clone(),
            url: e.url.clone(),
            i2p: e.i2p,
        })
        .collect();
    let lane_of = |key: &str| -> Vec<String> {
        old.list
            .iter()
            .filter(|e| e.pool && assigned(&e.keys, key))
            .map(|e| e.id.clone())
            .collect()
    };
    let strategy = match old.mode {
        ProxyMode::Off => None,
        ProxyMode::Failover => Some(Strategy::Failover),
        ProxyMode::RoundRobin => Some(Strategy::RoundRobin),
        ProxyMode::Chaos => Some(Strategy::Chaos),
    };
    // The lanes that need a group, each once, with the first key that has it.
    let mut grouped: Vec<(Vec<String>, &Lane)> = Vec::new();
    for l in lanes {
        let lane = lane_of(&l.id);
        if strategy.is_some() && lane.len() > 1 && !grouped.iter().any(|(g, _)| *g == lane) {
            grouped.push((lane, l));
        }
    }
    let one = grouped.len() == 1;
    let groups: Vec<ProxyGroup> = grouped
        .iter()
        .map(|(proxies, l)| ProxyGroup {
            id: if one {
                "default".into()
            } else {
                format!("default-{}", l.id)
            },
            name: if one {
                "Default".into()
            } else {
                format!("Default ({})", l.label)
            },
            proxies: proxies.clone(),
            strategy: strategy.expect("only a strategy makes groups"),
            rotate_secs: old.rotate_secs,
            chaos_min_secs: old.chaos_min_secs,
            chaos_max_secs: old.chaos_max_secs,
        })
        .collect();
    let dest = |key: &str| -> Destination {
        let lane = lane_of(key);
        match (lane.first(), groups.iter().find(|g| g.proxies == lane)) {
            (None, _) if old.list.is_empty() || old.transparent => Destination::Direct,
            (None, _) => Destination::Block,
            (_, Some(g)) => Destination::Group(g.id.clone()),
            (Some(first), None) => Destination::Proxy(first.clone()),
        }
    };
    let default = lanes.first().map_or(Destination::Direct, |l| dest(&l.id));
    let default_keys: BTreeMap<String, Destination> = lanes
        .iter()
        .map(|l| (l.id.clone(), dest(&l.id)))
        .filter(|(_, d)| *d != default)
        .collect();
    let rules = old
        .rules
        .iter()
        .flat_map(|r| convert_rule(r, lanes, &dest, old.transparent))
        .collect();
    network::ProxySettings {
        list,
        groups,
        default,
        default_keys,
        offline: old.offline,
        transparent: old.transparent,
        rules,
        i2p_registries: old.i2p_registries.clone(),
    }
}

/// One old rule as one or more new ones (one per destination its keys have).
fn convert_rule(r: &Rule, lanes: &[Lane], dest: &dyn Fn(&str) -> Destination, transparent: bool) -> Vec<routes::Rule> {
    let rule = |keys: Vec<String>, to: Destination, fallback: routes::Fallback| routes::Rule {
        name: r.name.clone(),
        patterns: r.patterns.clone(),
        keys,
        to,
        fallback,
    };
    let fixed = |to: Destination| {
        // A fallback only ever applied to a rule through a proxy.
        let fallback = match (&r.to, r.fallback) {
            (RouteTo::Proxy(_), Fallback::Pool) => None,
            _ => Some(routes::Fallback::Offline),
        };
        fallback.map(|f| vec![rule(r.keys.clone(), to.clone(), f)])
    };
    let simple = match &r.to {
        RouteTo::Direct => fixed(Destination::Direct),
        RouteTo::Block => fixed(Destination::Block),
        RouteTo::Proxy(id) => fixed(Destination::Proxy(id.clone())),
        RouteTo::Pool => None,
    };
    if let Some(v) = simple {
        return v;
    }
    // By the keys' destinations, in lane order.
    let mut by_dest: Vec<(Destination, Vec<String>)> = Vec::new();
    for l in lanes.iter().filter(|l| assigned(&r.keys, &l.id)) {
        let d = dest(&l.id);
        match by_dest.iter_mut().find(|(x, _)| *x == d) {
            Some((_, keys)) => keys.push(l.id.clone()),
            None => by_dest.push((d, vec![l.id.clone()])),
        }
    }
    let split = by_dest.len() > 1;
    by_dest
        .into_iter()
        .map(|(d, keys)| {
            let keys = if split { keys } else { r.keys.clone() };
            // With no proxy at all, a Tor or I2P relay sent to the pool was
            // never connected; a rule may not send it straight.
            let tor = !transparent && r.patterns.iter().any(|p| routes::names_tor_or_i2p(p));
            match (&r.to, d) {
                (RouteTo::Proxy(id), d) => rule(keys, Destination::Proxy(id.clone()), routes::Fallback::To(d)),
                (_, Destination::Direct) if tor => rule(keys, Destination::Block, routes::Fallback::Offline),
                (_, d) => rule(keys, d, routes::Fallback::Policy),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Fallback as NewFallback;

    fn lanes() -> Vec<Lane> {
        [("invoices", "Public invoices"), ("admin", "Administration")]
            .iter()
            .map(|(id, label)| Lane {
                id: id.to_string(),
                label: label.to_string(),
            })
            .collect()
    }

    fn entry(id: &str, keys: &[&str], pool: bool) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: format!("{id} name"),
            url: format!("socks5://{id}:1"),
            keys: keys.iter().map(|k| k.to_string()).collect(),
            pool,
            i2p: false,
        }
    }

    fn rule(patterns: &[&str], keys: &[&str], to: RouteTo, fallback: Fallback) -> Rule {
        Rule {
            name: "r".into(),
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            keys: keys.iter().map(|k| k.to_string()).collect(),
            to,
            fallback,
        }
    }

    fn old(list: Vec<ProxyEntry>, mode: ProxyMode, rules: Vec<Rule>) -> ProxySettings {
        ProxySettings {
            list,
            mode,
            rotate_secs: 1_800,
            chaos_min_secs: 120,
            chaos_max_secs: 600,
            rules,
            ..ProxySettings::default()
        }
    }

    fn proxy(id: &str) -> Destination {
        Destination::Proxy(id.into())
    }

    fn group(id: &str) -> Destination {
        Destination::Group(id.into())
    }

    #[test]
    fn a_shared_pool_becomes_one_default_group_with_the_old_strategy() {
        let s = convert(
            &old(
                vec![entry("a", &[], true), entry("b", &[], true), entry("tor", &[], false)],
                ProxyMode::Chaos,
                Vec::new(),
            ),
            &lanes(),
        );
        assert_eq!(
            s.list
                .iter()
                .map(|e| (e.id.as_str(), e.name.as_str()))
                .collect::<Vec<_>>(),
            [("a", "a name"), ("b", "b name"), ("tor", "tor name")]
        );
        assert_eq!(
            s.groups,
            [ProxyGroup {
                id: "default".into(),
                name: "Default".into(),
                proxies: vec!["a".into(), "b".into()],
                strategy: Strategy::Chaos,
                rotate_secs: 1_800,
                chaos_min_secs: 120,
                chaos_max_secs: 600,
            }]
        );
        assert_eq!((s.default.clone(), s.default_keys.len()), (group("default"), 0));
        // The strategy off, or one proxy: that proxy, and no group.
        let off = convert(
            &old(
                vec![entry("a", &[], true), entry("b", &[], true)],
                ProxyMode::Off,
                Vec::new(),
            ),
            &lanes(),
        );
        assert!(off.groups.is_empty());
        assert_eq!(off.default, proxy("a"));
        let one = convert(
            &old(vec![entry("a", &[], true)], ProxyMode::RoundRobin, Vec::new()),
            &lanes(),
        );
        assert!(one.groups.is_empty());
        assert_eq!(one.default, proxy("a"));
        for (mode, strategy) in [
            (ProxyMode::Failover, Strategy::Failover),
            (ProxyMode::RoundRobin, Strategy::RoundRobin),
        ] {
            let two = convert(
                &old(vec![entry("a", &[], true), entry("b", &[], true)], mode, Vec::new()),
                &lanes(),
            );
            assert_eq!(two.groups[0].strategy, strategy);
        }
        // No proxy: straight, as before.
        let none = convert(&ProxySettings::default(), &lanes());
        assert_eq!(
            (none.default, none.default_keys.len(), none.groups.len()),
            (Destination::Direct, 0, 0)
        );
        assert_eq!(none.i2p_registries, crate::i2p::default_registries());
        assert_eq!(convert(&ProxySettings::default(), &[]).default, Destination::Direct);
    }

    #[test]
    fn keys_with_different_pools_get_their_own_default_routes_and_groups() {
        // Each key its own pair: a group per key, named after it.
        let s = convert(
            &old(
                vec![
                    entry("a", &["invoices"], true),
                    entry("b", &["invoices"], true),
                    entry("c", &["admin"], true),
                    entry("d", &["admin"], true),
                ],
                ProxyMode::RoundRobin,
                Vec::new(),
            ),
            &lanes(),
        );
        assert_eq!(
            s.groups
                .iter()
                .map(|g| (g.id.as_str(), g.name.as_str()))
                .collect::<Vec<_>>(),
            [
                ("default-invoices", "Default (Public invoices)"),
                ("default-admin", "Default (Administration)")
            ]
        );
        assert_eq!(s.default, group("default-invoices"));
        assert_eq!(s.default_keys["admin"], group("default-admin"));
        // A key with no pool proxy of its own: blocked by default (its relays
        // are all ruled, or the old settings were refused), not straight.
        let s = convert(
            &old(
                vec![entry("a", &["invoices"], true), entry("tor", &[], false)],
                ProxyMode::Failover,
                vec![rule(
                    &["*"],
                    &["admin"],
                    RouteTo::Proxy("tor".into()),
                    Fallback::Offline,
                )],
            ),
            &lanes(),
        );
        assert_eq!(
            (s.default.clone(), s.default_keys["admin"].clone()),
            (proxy("a"), Destination::Block)
        );
        // Behind a transparent proxy an empty lane is straight (as it routed).
        let mut t = old(vec![entry("a", &[], false)], ProxyMode::Off, Vec::new());
        t.transparent = true;
        let s = convert(&t, &lanes());
        assert_eq!((s.default.clone(), s.transparent), (Destination::Direct, true));
        let topology = crate::network::Topology {
            settings: crate::network::NetworkSettings {
                relays: vec!["wss://a.example".into()],
                relay_keys: Default::default(),
                relay_names: Default::default(),
                proxies: s,
            },
            lanes: lanes(),
        };
        topology.validate().unwrap();
    }

    #[test]
    fn pool_rules_and_fallbacks_go_where_each_key_s_pool_went() {
        let list = vec![
            entry("a", &["invoices"], true),
            entry("b", &["admin"], true),
            entry("tor", &[], false),
        ];
        let rules = vec![
            rule(&["*.onion"], &[], RouteTo::Proxy("tor".into()), Fallback::Pool),
            rule(&["b.example"], &["admin"], RouteTo::Pool, Fallback::Offline),
            rule(&["c.example"], &[], RouteTo::Pool, Fallback::Offline),
            rule(&["d.example"], &[], RouteTo::Direct, Fallback::Pool),
            rule(&["e.example"], &[], RouteTo::Block, Fallback::Offline),
        ];
        let s = convert(&old(list, ProxyMode::Failover, rules), &lanes());
        let shown: Vec<(String, Vec<String>, Destination, NewFallback)> = s
            .rules
            .iter()
            .map(|r| (r.patterns[0].clone(), r.keys.clone(), r.to.clone(), r.fallback.clone()))
            .collect();
        let keys = |k: &[&str]| k.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        assert_eq!(
            shown,
            [
                (
                    "*.onion".into(),
                    keys(&["invoices"]),
                    proxy("tor"),
                    NewFallback::To(proxy("a"))
                ),
                (
                    "*.onion".into(),
                    keys(&["admin"]),
                    proxy("tor"),
                    NewFallback::To(proxy("b"))
                ),
                ("b.example".into(), keys(&["admin"]), proxy("b"), NewFallback::Policy),
                ("c.example".into(), keys(&["invoices"]), proxy("a"), NewFallback::Policy),
                ("c.example".into(), keys(&["admin"]), proxy("b"), NewFallback::Policy),
                ("d.example".into(), keys(&[]), Destination::Direct, NewFallback::Offline),
                ("e.example".into(), keys(&[]), Destination::Block, NewFallback::Offline),
            ]
        );
        assert!(s.rules.iter().all(|r| r.name == "r"));
        // One destination for every key: one rule, keys as they were.
        let s = convert(
            &old(
                vec![entry("a", &[], true), entry("b", &[], true)],
                ProxyMode::RoundRobin,
                vec![rule(&["c.example"], &[], RouteTo::Pool, Fallback::Offline)],
            ),
            &lanes(),
        );
        assert_eq!(s.rules.len(), 1);
        assert_eq!((s.rules[0].keys.len(), s.rules[0].to.clone()), (0, group("default")));
        // No proxy at all: a Tor relay sent to the pool never connected, so it
        // is blocked; other relays go straight, as the pool did.
        let s = convert(
            &old(
                Vec::new(),
                ProxyMode::Off,
                vec![
                    rule(&["*.onion"], &[], RouteTo::Pool, Fallback::Offline),
                    rule(&["c.example"], &[], RouteTo::Pool, Fallback::Offline),
                ],
            ),
            &lanes(),
        );
        assert_eq!(
            (s.rules[0].to.clone(), s.rules[0].fallback.clone()),
            (Destination::Block, NewFallback::Offline)
        );
        assert_eq!(
            (s.rules[1].to.clone(), s.rules[1].fallback.clone()),
            (Destination::Direct, NewFallback::Policy)
        );
        // Behind a transparent proxy it stays as it was (nothing is straight there).
        let mut t = old(
            Vec::new(),
            ProxyMode::Off,
            vec![rule(&["*.onion"], &[], RouteTo::Pool, Fallback::Offline)],
        );
        t.transparent = true;
        assert_eq!(convert(&t, &lanes()).rules[0].to, Destination::Direct);
    }

    #[test]
    fn an_old_stored_patch_applies_as_it_did() {
        let patch: ProxyPatch = serde_json::from_value(serde_json::json!({
            "list": [
                { "url": "socks5://a:1" },
                { "id": "b", "name": "B", "url": "socks5://b:1", "keys": ["admin"], "pool": false, "i2p": false }
            ],
            "mode": "round_robin", "rotate_secs": 600, "chaos_min_secs": 60, "chaos_max_secs": 120,
            "offline": "open", "transparent": true,
            "rules": [{ "match": ["*"], "to": "pool" }],
            "i2p_registries": []
        }))
        .unwrap();
        let mut s = ProxySettings::default();
        patch.apply(&mut s);
        assert_eq!(
            s.list[0],
            ProxyEntry {
                id: "p0".into(),
                name: String::new(),
                url: "socks5://a:1".into(),
                keys: Vec::new(),
                pool: true,
                i2p: false,
            }
        );
        assert_eq!((s.list[1].pool, s.list[1].keys.len()), (false, 1));
        assert_eq!(
            (s.mode, s.rotate_secs, s.chaos_min_secs, s.chaos_max_secs),
            (ProxyMode::RoundRobin, 600, 60, 120)
        );
        assert_eq!(
            (s.offline, s.transparent, s.rules.len(), s.i2p_registries.len()),
            (OfflinePolicy::Open, true, 1, 0)
        );
        // An entry stored before `pool` existed is in the pool.
        let bare: ProxyEntry = serde_json::from_value(serde_json::json!({ "id": "a", "url": "socks5://a:1" })).unwrap();
        assert!(bare.pool && bare.keys.is_empty() && bare.name.is_empty() && !bare.i2p);
        let mut kept = s.clone();
        ProxyPatch::default().apply(&mut kept);
        assert_eq!(kept, s);
        assert!(patch.sets_default() && !ProxyPatch::default().sets_default());
        for only in [
            serde_json::json!({ "mode": "off" }),
            serde_json::json!({ "rotate_secs": 60 }),
            serde_json::json!({ "chaos_min_secs": 60 }),
            serde_json::json!({ "chaos_max_secs": 60 }),
            serde_json::json!({ "list": [] }),
        ] {
            assert!(serde_json::from_value::<ProxyPatch>(only).unwrap().sets_default());
        }
    }
}
