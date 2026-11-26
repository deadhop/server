//! Routing rules: which way each relay connection goes.
//!
//! An operator keeps an ordered list of [`Rule`]s, and the default route as
//! its last, fixed entry ("everything else"). For each key and each of its
//! relays, the first rule that applies to the key and matches the relay
//! decides the route: through one proxy, through a group of proxies (and its
//! strategy), directly, or nowhere. A relay no rule matches takes the key's
//! default route, which points at one of the same [`Destination`]s.
//!
//! [`resolve`] is pure: given the settings, what each destination gives now
//! and what the offline policy means for the key, it says where each relay
//! goes and why. The service keeps the state it needs (`proxypool.rs`), the
//! app acts on it (`app.rs`).
//!
//! Patterns are matched against the relay's host as a URL parser reads it
//! (never the raw authority, which may carry user info), lower case. A
//! pattern with `://` is one exact relay address. Otherwise it is a host
//! pattern: `*` stands for any run of characters, dots included, and an
//! optional `:port` must equal the relay's port (or the scheme's default).
//! `*.example.com` does not match `example.com` itself.

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::network::{assigned, ProxySettings, Topology};

/// Most rules in the list (an old pool rule may become one per key).
pub const MAX_RULES: usize = 32;
/// Most patterns in one rule.
pub const MAX_PATTERNS: usize = 16;
/// Longest pattern.
pub const MAX_PATTERN_LEN: usize = 256;
/// Longest rule name.
pub const MAX_NAME_LEN: usize = 60;

// Where relays go: a rule's target, a fallback, or the default route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    // No proxy at all.
    Direct,
    // Never connect.
    Block,
    // Through this proxy (by id).
    Proxy(String),
    // Through the proxy a group (by id) has chosen by its strategy.
    Group(String),
}

impl Destination {
    /// Whether this is proxy `id`.
    pub fn is_proxy(&self, id: &str) -> bool {
        matches!(self, Destination::Proxy(p) if p == id)
    }

    /// Whether this goes through a proxy (one, or a group's).
    pub fn via_proxy(&self) -> bool {
        matches!(self, Destination::Proxy(_) | Destination::Group(_))
    }
}

// What a rule does while its proxy (or every proxy of its group) is down.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    // Stay offline: never connect another way.
    #[default]
    Offline,
    // The offline policy decides, as it does for the default route.
    Policy,
    // Use this destination instead; when it has nothing reachable either,
    // the offline policy decides.
    To(Destination),
}

// One routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    // Optional label for the dashboard.
    #[serde(default)]
    pub name: String,
    // Relay addresses (`wss://relay.example`) or host patterns (`*.onion`,
    // `relay*.example.com:7777`). The rule matches a relay if any one does.
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    // The keys (by id) this rule applies to; empty is every key.
    #[serde(default)]
    pub keys: Vec<String>,
    pub to: Destination,
    // Only for a rule that goes through a proxy or a group.
    #[serde(default)]
    pub fallback: Fallback,
}

pub use deadhop_net::hosts::{host_port, never_direct};

/// `*` matches any run of characters (dots included); everything else is literal.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// A host pattern split into its host part and optional port.
fn split_port(pattern: &str) -> (&str, Option<&str>) {
    if let Some(rest) = pattern.strip_prefix('[') {
        // `[::1]` or `[::1]:7777`
        return match rest.split_once(']') {
            Some((host, tail)) => (host, tail.strip_prefix(':')),
            None => (pattern, None),
        };
    }
    match pattern.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (pattern, None),
    }
}

/// Whether two relay addresses are one relay (case and a trailing slash do not matter).
fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/').eq_ignore_ascii_case(b.trim_end_matches('/'))
}

/// Whether `pattern` matches `relay` (see the module notes).
pub fn matches(pattern: &str, relay: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.contains("://") {
        return same_relay(pattern, relay);
    }
    let Some((host, port)) = host_port(relay) else {
        return false;
    };
    let pattern = pattern.to_ascii_lowercase();
    let (host_pattern, want_port) = split_port(&pattern);
    if let Some(p) = want_port {
        if p.parse::<u16>().ok() != Some(port) {
            return false;
        }
    }
    glob(host_pattern, &host)
}

/// Why a pattern is not usable, if it is not.
pub fn pattern_problem(pattern: &str) -> Option<String> {
    let p = pattern.trim();
    if p.is_empty() {
        return Some("a pattern is empty".into());
    }
    if p.len() > MAX_PATTERN_LEN {
        return Some(format!("pattern '{p}' is too long"));
    }
    if p.contains("://") {
        return match host_port(p) {
            Some(_) if p.starts_with("ws://") || p.starts_with("wss://") => None,
            _ => Some(format!("'{p}' is not a relay address (ws:// or wss://)")),
        };
    }
    let ok = p
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | ':' | '[' | ']'));
    if !ok {
        return Some(format!(
            "pattern '{p}' may hold only letters, digits, '.', '-', '_', '*' and a ':port'"
        ));
    }
    let lower = p.to_ascii_lowercase();
    let (_, port) = split_port(&lower);
    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return Some(format!("pattern '{p}' has a port that is not a number"));
    }
    None
}

/// Whether a pattern can only ever match Tor or I2P relays, which must never
/// be reached without a proxy.
pub fn names_tor_or_i2p(pattern: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let host = if p.contains("://") {
        host_port(&p).map(|(h, _)| h).unwrap_or_default()
    } else {
        split_port(&p).0.to_string()
    };
    let host = host.trim_end_matches('.');
    host.ends_with(".onion") || host.ends_with(".i2p")
}

impl Rule {
    /// Whether this rule applies to `key` and matches `relay`.
    pub fn applies(&self, key: &str, relay: &str) -> bool {
        assigned(&self.keys, key) && self.patterns.iter().any(|p| matches(p, relay))
    }
}

/// The first rule (by index) that applies to `key` and matches `relay`.
pub fn first_rule(rules: &[Rule], key: &str, relay: &str) -> Option<usize> {
    rules.iter().position(|r| r.applies(key, relay))
}

/// Check that a destination names a proxy or a group that exists. `what`
/// says who points at it ("rule 2"), `fix` what to change ("the rule").
pub fn check_destination(proxies: &ProxySettings, d: &Destination, what: &str, fix: &str) -> Result<()> {
    match d {
        Destination::Proxy(id) if !proxies.list.iter().any(|e| &e.id == id) => Err(Error::InvalidParams(format!(
            "{what} points at a proxy that is not in the list; change {fix} first"
        ))),
        Destination::Group(id) if !proxies.groups.iter().any(|g| &g.id == id) => Err(Error::InvalidParams(format!(
            "{what} points at a group that does not exist; change {fix} first"
        ))),
        _ => Ok(()),
    }
}

/// Check the rule list against the proxies, the groups and the relays.
pub fn check_rules(settings: &Topology) -> Result<()> {
    let proxies = &settings.proxies;
    let rules = &proxies.rules;
    if rules.len() > MAX_RULES {
        return Err(Error::InvalidParams(format!("at most {MAX_RULES} routing rules")));
    }
    for (i, r) in rules.iter().enumerate() {
        let n = i + 1;
        if r.name.chars().count() > MAX_NAME_LEN {
            return Err(Error::InvalidParams(format!("rule {n}: the name is too long")));
        }
        if r.patterns.is_empty() || r.patterns.len() > MAX_PATTERNS {
            return Err(Error::InvalidParams(format!(
                "rule {n}: between 1 and {MAX_PATTERNS} relays or patterns are required"
            )));
        }
        if let Some(why) = r.patterns.iter().find_map(|p| pattern_problem(p)) {
            return Err(Error::InvalidParams(format!("rule {n}: {why}")));
        }
        if let Some(k) = r.keys.iter().find(|k| !settings.lanes.iter().any(|l| &l.id == *k)) {
            return Err(Error::InvalidParams(format!("rule {n}: there is no key '{k}'")));
        }
        check_destination(proxies, &r.to, &format!("rule {n}"), "the rule")?;
        if let Fallback::To(d) = &r.fallback {
            check_destination(proxies, d, &format!("the fallback of rule {n}"), "the rule")?;
        }
        // (A fallback is only ever taken from a proxy or a group.)
        let direct =
            r.to == Destination::Direct || (r.to.via_proxy() && r.fallback == Fallback::To(Destination::Direct));
        // (Behind a transparent proxy nothing goes straight.)
        if direct && !proxies.transparent && r.patterns.iter().any(|p| names_tor_or_i2p(p)) {
            return Err(Error::InvalidParams(format!(
                "rule {n}: Tor and I2P relays can only be reached through a proxy, never directly"
            )));
        }
    }
    // Every key keeps a relay that neither a rule nor its default route blocks.
    for key in &settings.lanes {
        let relays = settings.relays_for(&key.id);
        let open = relays.iter().any(|relay| {
            let to = match first_rule(rules, &key.id, relay) {
                Some(i) => &rules[i].to,
                None => proxies.default_for(&key.id),
            };
            *to != Destination::Block
        });
        if !relays.is_empty() && !open {
            return Err(Error::InvalidParams(format!(
                "the rules block every relay of the {} key; it could not be reached",
                key.label
            )));
        }
    }
    Ok(())
}

/// Where one relay connection goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// Through this proxy (id and url).
    Proxy { id: String, url: String },
    /// Straight to the relay.
    Direct,
    /// No connection.
    Off,
}

/// Why a relay goes the way it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    // A rule chose this route and it is in use.
    Rule,
    // No rule matched: the default route.
    Default,
    // The rule's proxy or group is down; the rule's fallback is in use.
    Fallback,
    // The rule's proxy or group has nothing reachable and the rule stays offline.
    ProxyDown,
    // A rule, or the default route, blocks this relay.
    Blocked,
    // Nothing reachable where the relay may go, and the offline policy keeps this key off.
    PoolOffline,
    // Tor and I2P relays are never connected without a proxy.
    NeverDirect,
    // A transparent proxy is declared: everything goes straight to it.
    Transparent,
}

/// The decision for one relay of one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub relay: String,
    /// Index of the rule that matched, if one did.
    pub rule: Option<usize>,
    pub via: Via,
    pub reason: Reason,
    /// The offline policy decided this route: nothing it may use was reachable.
    pub by_policy: bool,
}

/// Where each of `key`'s relays goes, in list order. `now` gives the proxy
/// (id and url) a proxy or group destination uses now, or `None` while it
/// has nothing reachable. `offline` is what the offline policy means for the
/// key: connect straight, or stay off; `None` before anything was probed,
/// when the key waits (off) and the policy has not decided anything yet.
pub fn resolve(
    settings: &Topology,
    key: &str,
    now: &dyn Fn(&Destination) -> Option<(String, String)>,
    offline: Option<bool>,
) -> Vec<Resolved> {
    let proxies = &settings.proxies;
    let rules = &proxies.rules;
    settings
        .relays_for(key)
        .into_iter()
        .map(|relay| {
            let rule = first_rule(rules, key, &relay);
            let policy = |reason| match offline {
                Some(true) => (Via::Direct, reason, true),
                Some(false) => (Via::Off, Reason::PoolOffline, true),
                None => (Via::Off, Reason::PoolOffline, false),
            };
            let go = |d: &Destination, reason| match d {
                Destination::Direct => Some((Via::Direct, reason, false)),
                Destination::Block => Some((Via::Off, Reason::Blocked, false)),
                _ => now(d).map(|(id, url)| (Via::Proxy { id, url }, reason, false)),
            };
            let (via, reason, by_policy) = match rule.map(|i| &rules[i]) {
                Some(Rule {
                    to: Destination::Block, ..
                }) => (Via::Off, Reason::Blocked, false),
                // A default route that blocks blocks, like a rule, even
                // behind a transparent proxy.
                None if *proxies.default_for(key) == Destination::Block => (Via::Off, Reason::Blocked, false),
                _ if proxies.transparent => (Via::Direct, Reason::Transparent, false),
                None => go(proxies.default_for(key), Reason::Default).unwrap_or_else(|| policy(Reason::Default)),
                Some(r) => go(&r.to, Reason::Rule).unwrap_or_else(|| match &r.fallback {
                    // "Stay offline" means never another way, not "do not
                    // try": with nothing to choose between, a relay always
                    // goes through its one proxy and the connection keeps
                    // retrying there. The probe only decides a fallback.
                    Fallback::Offline => match (&r.to, proxies.list.iter().find(|e| r.to.is_proxy(&e.id))) {
                        (Destination::Proxy(id), Some(e)) => (
                            Via::Proxy {
                                id: id.clone(),
                                url: e.url.clone(),
                            },
                            Reason::Rule,
                            false,
                        ),
                        _ => (Via::Off, Reason::ProxyDown, false),
                    },
                    Fallback::Policy => policy(Reason::Rule),
                    Fallback::To(d) => go(d, Reason::Fallback).unwrap_or_else(|| policy(Reason::Fallback)),
                }),
            };
            // Whatever the rules say, a Tor or I2P relay is never reached without a proxy.
            let (via, reason) = if via == Via::Direct && never_direct(&relay) && !proxies.transparent {
                (Via::Off, Reason::NeverDirect)
            } else {
                (via, reason)
            };
            Resolved {
                relay,
                rule,
                via,
                reason,
                by_policy,
            }
        })
        .collect()
}

/// Whether some relay of `key` takes the default route (no rule matches
/// it). When none does, where the default route points does not matter for
/// that key.
pub fn uses_default(settings: &Topology, key: &str) -> bool {
    let rules = &settings.proxies.rules;
    settings
        .relays_for(key)
        .iter()
        .any(|relay| first_rule(rules, key, relay).is_none())
}

/// The groups (by id) one key may use: through its default route, or a rule
/// that applies to it, or such a rule's fallback.
pub fn groups_used(settings: &Topology, key: &str) -> Vec<String> {
    let proxies = &settings.proxies;
    let mut out: Vec<String> = Vec::new();
    let rules = proxies.rules.iter().filter(|r| assigned(&r.keys, key));
    let fallbacks = rules.clone().filter_map(|r| match &r.fallback {
        Fallback::To(d) => Some(d),
        _ => None,
    });
    let dests = std::iter::once(proxies.default_for(key))
        .chain(rules.map(|r| &r.to))
        .chain(fallbacks);
    for d in dests {
        if let Destination::Group(g) = d {
            if !out.contains(g) {
                out.push(g.clone());
            }
        }
    }
    out
}

/// The relays that may be sent through proxy `id` (for any key), in list
/// order: what a probe of that proxy should try, so a proxy is never tried
/// against a relay it would not carry.
pub fn relays_through_proxy(settings: &Topology, id: &str) -> Vec<String> {
    let proxies = &settings.proxies;
    if !proxies.list.iter().any(|e| e.id == id) {
        return Vec::new();
    }
    let carries = |d: &Destination| match d {
        Destination::Proxy(p) => p == id,
        Destination::Group(g) => proxies
            .groups
            .iter()
            .any(|x| &x.id == g && x.proxies.iter().any(|p| p == id)),
        _ => false,
    };
    let rules = &proxies.rules;
    settings
        .relays
        .iter()
        .filter(|relay| {
            settings
                .relay_users(relay)
                .iter()
                .any(|key| match first_rule(rules, key, relay).map(|i| &rules[i]) {
                    // A fallback is only ever taken from a proxy or a group.
                    Some(r) => {
                        carries(&r.to) || (r.to.via_proxy() && matches!(&r.fallback, Fallback::To(d) if carries(d)))
                    }
                    None => carries(proxies.default_for(key)),
                })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Lane, NetworkSettings, ProxyEntry, ProxySettings};

    #[test]
    fn patterns_match_hosts_as_documented() {
        // The same cases run in the dashboard (dashboard/src/lib/routes.test.ts).
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/route-patterns.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() > 20);
        for c in cases {
            let (pattern, relay, want) = (c[0].as_str().unwrap(), c[1].as_str().unwrap(), c[2].as_bool().unwrap());
            assert_eq!(matches(pattern, relay), want, "{pattern} vs {relay}");
        }
    }

    #[test]
    fn odd_addresses_give_no_host_and_unclosed_brackets_no_port() {
        // The url crate gives no host at all, never an empty one.
        assert_eq!(host_port("foo:///x"), None);
        assert_eq!(host_port("[::1]:80"), None);
        assert_eq!(host_port("ws://[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(split_port("[::1"), ("[::1", None));
    }

    #[test]
    fn patterns_are_checked() {
        for good in ["*.onion", "relay.example:7777", "[::1]:80", "wss://relay.example", "*"] {
            assert_eq!(pattern_problem(good), None, "{good}");
        }
        let bad: &[(&str, &str)] = &[
            ("", "empty"),
            ("   ", "empty"),
            ("https://relay.example", "not a relay address"),
            ("wss://", "not a relay address"),
            ("relay example", "may hold only"),
            ("relay.example/path", "may hold only"),
            ("relay.example:port", "not a number"),
            ("relay.example:99999", "not a number"),
        ];
        for (p, why) in bad {
            assert!(pattern_problem(p).unwrap().contains(why), "{p}");
        }
        assert!(pattern_problem(&"a".repeat(MAX_PATTERN_LEN + 1))
            .unwrap()
            .contains("too long"));
    }

    #[test]
    fn tor_and_i2p_relays_are_never_direct() {
        assert!(never_direct("ws://abc.onion"));
        assert!(never_direct("ws://abc.b32.i2p."));
        assert!(!never_direct("ws://npub1x.fips:7777"));
        assert!(!never_direct("wss://relay.example"));
        assert!(!never_direct("nonsense"));
        assert!(names_tor_or_i2p("*.onion") && names_tor_or_i2p("ws://abc.i2p/") && names_tor_or_i2p("x.onion:80"));
        assert!(!names_tor_or_i2p("*") && !names_tor_or_i2p("*.fips") && !names_tor_or_i2p("wss://"));
    }

    fn entry(id: &str) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: id.into(),
            url: format!("socks5://{id}:1"),
            i2p: false,
        }
    }

    fn rule(patterns: &[&str], to: Destination) -> Rule {
        Rule {
            name: String::new(),
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            keys: Vec::new(),
            to,
            fallback: Fallback::Offline,
        }
    }

    fn proxy(id: &str) -> Destination {
        Destination::Proxy(id.into())
    }

    fn group(id: &str) -> Destination {
        Destination::Group(id.into())
    }

    const ONION: &str = "ws://abc.onion";
    const LAN: &str = "ws://relay.lan:4869";
    const VPN_RELAY: &str = "wss://relay.contextvm.org";
    const PLAIN: &str = "wss://bucket.coracle.social";

    /// tor, vpn and i2p listed; a group "exits" of tor and vpn; the default
    /// route through tor.
    fn settings(rules: Vec<Rule>) -> Topology {
        let lane = |id: &str, label: &str| Lane {
            id: id.into(),
            label: label.into(),
        };
        let mut s = Topology {
            settings: NetworkSettings {
                relays: Vec::new(),
                relay_keys: Default::default(),
                relay_names: Default::default(),
                proxies: ProxySettings::default(),
            },
            lanes: vec![lane("invoices", "Public invoices"), lane("admin", "Administration")],
        };
        s.relays = vec![VPN_RELAY.into(), PLAIN.into(), ONION.into(), LAN.into()];
        s.proxies.list = vec![entry("tor"), entry("vpn"), entry("i2p")];
        s.proxies.groups = vec![crate::network::ProxyGroup {
            id: "exits".into(),
            name: String::new(),
            proxies: vec!["tor".into(), "vpn".into()],
            strategy: crate::network::Strategy::Failover,
            rotate_secs: 3_600,
            chaos_min_secs: 300,
            chaos_max_secs: 900,
        }];
        s.proxies.default = proxy("tor");
        s.proxies.rules = rules;
        s
    }

    /// What each destination gives: a proxy while it is up; the group its
    /// first proxy that is up.
    fn now_with(up: &'static dyn Fn(&str) -> bool) -> impl Fn(&Destination) -> Option<(String, String)> {
        move |d: &Destination| {
            let id = match d {
                Destination::Proxy(id) => Some(id.clone()).filter(|id| up(id)),
                // (Only proxies and groups are asked about.)
                _ => ["tor", "vpn"].into_iter().find(|id| up(id)).map(String::from),
            };
            id.map(|id| (id.clone(), format!("socks5://{id}:1")))
        }
    }

    fn table(
        s: &Topology,
        key: &str,
        up: &'static dyn Fn(&str) -> bool,
        offline: Option<bool>,
    ) -> Vec<(String, Option<usize>, Via, Reason)> {
        resolve(s, key, &now_with(up), offline)
            .into_iter()
            .map(|r| (r.relay, r.rule, r.via, r.reason))
            .collect()
    }

    fn by_policy(s: &Topology, key: &str, up: &'static dyn Fn(&str) -> bool, offline: Option<bool>) -> Vec<bool> {
        resolve(s, key, &now_with(up), offline)
            .into_iter()
            .map(|r| r.by_policy)
            .collect()
    }

    fn via(id: &str) -> Via {
        Via::Proxy {
            id: id.into(),
            url: format!("socks5://{id}:1"),
        }
    }

    const ALL_UP: &dyn Fn(&str) -> bool = &|_| true;
    const NONE_UP: &dyn Fn(&str) -> bool = &|_| false;
    const VPN_DOWN: &dyn Fn(&str) -> bool = &|id| id != "vpn";
    const TOR_DOWN: &dyn Fn(&str) -> bool = &|id| id != "tor";

    #[test]
    fn the_first_matching_rule_decides_and_the_rest_take_the_default_route() {
        let mut vpn = rule(&[VPN_RELAY], proxy("vpn"));
        vpn.fallback = Fallback::To(group("exits"));
        let s = settings(vec![
            rule(&["*.onion"], proxy("tor")),
            rule(&["*.lan"], Destination::Direct),
            vpn,
            // Never reached for the relay above: rule 3 comes first.
            rule(&["*.contextvm.org"], Destination::Block),
        ]);
        assert_eq!(
            table(&s, "invoices", ALL_UP, Some(false)),
            vec![
                (VPN_RELAY.into(), Some(2), via("vpn"), Reason::Rule),
                (PLAIN.into(), None, via("tor"), Reason::Default),
                (ONION.into(), Some(0), via("tor"), Reason::Rule),
                (LAN.into(), Some(1), Via::Direct, Reason::Rule),
            ]
        );
        // A rule's proxy down with a fallback: its relay goes there.
        assert_eq!(table(&s, "invoices", VPN_DOWN, Some(false))[0].2, via("tor"));
        assert_eq!(table(&s, "invoices", VPN_DOWN, Some(false))[0].3, Reason::Fallback);
        // A rule's proxy down with "stay offline": its relay still goes through
        // that proxy (never another way) rather than being held back.
        assert_eq!(
            table(&s, "invoices", TOR_DOWN, Some(false))[2],
            (ONION.into(), Some(0), via("tor"), Reason::Rule)
        );
        // Nothing up: the default route and the fallback leave it to the
        // policy, which keeps this key off (or sends it straight).
        let t = table(&s, "invoices", NONE_UP, Some(false));
        assert_eq!((t[0].2.clone(), t[0].3), (Via::Off, Reason::PoolOffline));
        assert_eq!((t[1].2.clone(), t[1].3), (Via::Off, Reason::PoolOffline));
        assert_eq!(
            by_policy(&s, "invoices", NONE_UP, Some(false)),
            [true, true, false, false]
        );
        let t = table(&s, "admin", NONE_UP, Some(true));
        assert_eq!((t[0].2.clone(), t[0].3), (Via::Direct, Reason::Fallback));
        assert_eq!((t[1].2.clone(), t[1].3), (Via::Direct, Reason::Default));
        // Before anything was probed the key waits: off, and not the policy's doing.
        let t = table(&s, "admin", NONE_UP, None);
        assert_eq!((t[1].2.clone(), t[1].3), (Via::Off, Reason::PoolOffline));
        assert_eq!(by_policy(&s, "admin", NONE_UP, None), [false; 4]);
    }

    #[test]
    fn rules_to_groups_fall_back_to_the_policy_or_stay_offline() {
        let mut policy = rule(&[VPN_RELAY], group("exits"));
        policy.fallback = Fallback::Policy;
        let mut to_block = rule(&[PLAIN], proxy("vpn"));
        to_block.fallback = Fallback::To(Destination::Block);
        let s = settings(vec![policy, to_block, rule(&["*.onion"], group("exits"))]);
        assert_eq!(
            table(&s, "admin", ALL_UP, Some(true))[..3],
            [
                (VPN_RELAY.into(), Some(0), via("tor"), Reason::Rule),
                (PLAIN.into(), Some(1), via("vpn"), Reason::Rule),
                (ONION.into(), Some(2), via("tor"), Reason::Rule),
            ]
        );
        let t = table(&s, "admin", NONE_UP, Some(true));
        // The policy says straight, put down to the rule; a fallback that
        // blocks blocks; a group with nothing up and "stay offline" is off.
        assert_eq!(
            t[..3],
            [
                (VPN_RELAY.into(), Some(0), Via::Direct, Reason::Rule),
                (PLAIN.into(), Some(1), Via::Off, Reason::Blocked),
                (ONION.into(), Some(2), Via::Off, Reason::ProxyDown),
            ]
        );
        assert_eq!(by_policy(&s, "admin", NONE_UP, Some(true))[..3], [true, false, false]);
        // A fallback straight for a Tor relay is still never straight.
        let mut onion = rule(&["*.onion"], proxy("vpn"));
        onion.fallback = Fallback::To(Destination::Direct);
        let s = settings(vec![onion]);
        assert_eq!(
            table(&s, "admin", NONE_UP, Some(false))[2],
            (ONION.into(), Some(0), Via::Off, Reason::NeverDirect)
        );
    }

    #[test]
    fn rules_for_one_key_leave_the_other_alone_and_block_and_groups_work() {
        let mut only_admin = rule(&["*"], Destination::Block);
        only_admin.keys = vec!["admin".into()];
        let s = settings(vec![rule(&[PLAIN], group("exits")), only_admin]);
        let admin = table(&s, "admin", ALL_UP, Some(false));
        assert_eq!(admin[0], (VPN_RELAY.into(), Some(1), Via::Off, Reason::Blocked));
        assert_eq!(admin[1], (PLAIN.into(), Some(0), via("tor"), Reason::Rule));
        let invoices = table(&s, "invoices", ALL_UP, Some(false));
        assert_eq!(invoices[0], (VPN_RELAY.into(), None, via("tor"), Reason::Default));
        // One key's own default route; a default route that blocks.
        let mut s = s;
        s.proxies.default_keys.insert("invoices".into(), Destination::Block);
        assert_eq!(
            table(&s, "invoices", ALL_UP, Some(false))[0],
            (VPN_RELAY.into(), None, Via::Off, Reason::Blocked)
        );
        assert_eq!(table(&s, "admin", ALL_UP, Some(false))[1].2, via("tor"));
    }

    #[test]
    fn tor_relays_never_go_direct_and_a_transparent_proxy_takes_everything_but_blocks() {
        // The default route is straight: the onion relay is held back.
        let mut s = settings(vec![rule(&[LAN], Destination::Block)]);
        s.proxies.default = Destination::Direct;
        let t = table(&s, "invoices", ALL_UP, Some(false));
        assert_eq!(t[2], (ONION.into(), None, Via::Off, Reason::NeverDirect));
        assert_eq!(t[1].2, Via::Direct);
        s.proxies.transparent = true;
        let t = table(&s, "invoices", NONE_UP, Some(false));
        assert_eq!(t[2], (ONION.into(), None, Via::Direct, Reason::Transparent));
        assert_eq!(t[3], (LAN.into(), Some(0), Via::Off, Reason::Blocked));
        // A default route that blocks blocks there too.
        s.proxies.default = Destination::Block;
        let t = table(&s, "invoices", NONE_UP, Some(false));
        assert_eq!(t[2], (ONION.into(), None, Via::Off, Reason::Blocked));
        // A rule to a proxy that is no longer listed counts as down.
        let s = settings(vec![rule(&["*.onion"], proxy("gone"))]);
        assert_eq!(
            table(&s, "invoices", NONE_UP, Some(false))[2],
            (ONION.into(), Some(0), Via::Off, Reason::ProxyDown)
        );
    }

    #[test]
    fn which_keys_take_the_default_route_which_groups_they_use_and_what_each_proxy_is_probed_against() {
        let mut vpn = rule(&[VPN_RELAY], proxy("vpn"));
        vpn.fallback = Fallback::To(group("exits"));
        let mut lan = rule(&["*.lan", PLAIN], Destination::Direct);
        // A fallback is never taken from a straight rule.
        lan.fallback = Fallback::To(proxy("i2p"));
        let s = settings(vec![rule(&["*.onion"], proxy("tor")), lan, vpn]);
        assert!(!uses_default(&s, "invoices"), "every relay is ruled");
        assert_eq!(groups_used(&s, "invoices"), ["exits"]);
        let s2 = settings(vec![rule(&["*"], proxy("i2p"))]);
        assert!(!uses_default(&s2, "invoices"));
        assert!(groups_used(&s2, "admin").is_empty());
        let mut s3 = settings(vec![rule(&[PLAIN], group("exits")), rule(&[LAN], group("exits"))]);
        s3.proxies.default = group("exits");
        assert!(uses_default(&s3, "admin"));
        assert_eq!(groups_used(&s3, "admin"), ["exits"], "each group once");
        // A proxy is probed against the relays a rule, a fallback, a group or
        // the default route may send through it. One in none of them, or an
        // unknown id: none.
        assert_eq!(
            relays_through_proxy(&s, "tor"),
            vec![VPN_RELAY.to_string(), ONION.to_string()]
        );
        assert_eq!(relays_through_proxy(&s, "vpn"), vec![VPN_RELAY.to_string()]);
        assert!(relays_through_proxy(&s, "i2p").is_empty());
        assert!(relays_through_proxy(&s, "nope").is_empty());
        assert_eq!(relays_through_proxy(&s2, "i2p").len(), 4);
        assert!(relays_through_proxy(&s3, "i2p").is_empty());
        assert_eq!(relays_through_proxy(&s3, "vpn").len(), 4);
        assert!(Destination::Group("x".into()).via_proxy() && !Destination::Block.via_proxy());
    }

    #[test]
    fn rule_lists_are_checked() {
        let check = |rules: Vec<Rule>| {
            let s = settings(rules);
            check_rules(&s).map_err(|e| e.to_string())
        };
        assert!(check(vec![
            rule(&["*.onion"], proxy("tor")),
            rule(&["*.lan"], Destination::Direct),
            rule(&["*.i2p"], group("exits")),
        ])
        .is_ok());
        let named = |name: &str| Rule {
            name: name.into(),
            ..rule(&["*"], group("exits"))
        };
        let keyed = |k: &str| Rule {
            keys: vec![k.into()],
            ..rule(&["*"], group("exits"))
        };
        let falling = |to: Destination, patterns: &[&str]| Rule {
            fallback: Fallback::To(to),
            ..rule(patterns, proxy("tor"))
        };
        let bad: Vec<(Vec<Rule>, &str)> = vec![
            (vec![rule(&["*"], group("exits")); MAX_RULES + 1], "at most"),
            (vec![named(&"n".repeat(MAX_NAME_LEN + 1))], "name is too long"),
            (vec![rule(&[], group("exits"))], "between 1 and"),
            (vec![rule(&["a b"], group("exits"))], "rule 1: pattern"),
            (vec![keyed("nobody")], "no key 'nobody'"),
            (
                vec![rule(&["*"], proxy("gone"))],
                "rule 1 points at a proxy that is not in the list; change the rule first",
            ),
            (
                vec![rule(&["*"], group("gone"))],
                "rule 1 points at a group that does not exist; change the rule first",
            ),
            (
                vec![falling(group("gone"), &["*"])],
                "the fallback of rule 1 points at a group",
            ),
            (vec![rule(&["*.onion"], Destination::Direct)], "never directly"),
            (vec![rule(&[ONION], Destination::Direct)], "never directly"),
            (vec![falling(Destination::Direct, &["*.i2p"])], "never directly"),
            (vec![rule(&["*"], Destination::Block)], "block every relay"),
        ];
        for (rules, why) in bad {
            let err = check(rules).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }
        let mut too_many = rule(&["*"], group("exits"));
        too_many.patterns = vec!["*".into(); MAX_PATTERNS + 1];
        assert!(check(vec![too_many]).unwrap_err().contains("between 1 and"));
        // Blocking everything for one key is refused; for one relay, fine.
        let mut admin_block = rule(&["*"], Destination::Block);
        admin_block.keys = vec!["admin".into()];
        assert!(check(vec![admin_block]).unwrap_err().contains("Administration"));
        assert!(check(vec![rule(&[PLAIN], Destination::Block)]).is_ok());
        // The default route counts: blocking by default leaves the ruled relays.
        let mut s = settings(vec![rule(&[PLAIN], group("exits"))]);
        s.proxies.default = Destination::Block;
        assert!(check_rules(&s).is_ok());
        s.proxies.rules.clear();
        assert!(check_rules(&s).unwrap_err().to_string().contains("block every relay"));
        // A fallback a rule never takes is not checked for being straight.
        let mut blocked = rule(&["*.onion"], Destination::Block);
        blocked.fallback = Fallback::To(Destination::Direct);
        assert!(check(vec![blocked, rule(&[PLAIN], group("exits"))]).is_ok());
        // Behind a transparent proxy nothing is straight, so a Tor rule may say so.
        let mut s = settings(vec![rule(&["*.onion"], Destination::Direct)]);
        s.proxies.transparent = true;
        assert!(check_rules(&s).is_ok());
        let p = &s.proxies;
        assert!(check_destination(p, &Destination::Direct, "x", "y").is_ok());
    }

    #[test]
    fn rules_read_and_write_the_documented_json() {
        let json = serde_json::json!([
            {"match": ["*.onion"], "to": {"proxy": "tor"}},
            {"name": "lan", "match": ["*.lan"], "keys": ["admin"], "to": "direct"},
            {"match": [VPN_RELAY], "to": {"proxy": "vpn"}, "fallback": {"to": {"group": "exits"}}},
            {"match": ["*"], "to": "block"},
            {"match": ["*"], "to": {"group": "exits"}, "fallback": "policy"},
            {"match": ["*"], "to": {"proxy": "tor"}, "fallback": {"to": "direct"}}
        ]);
        let rules: Vec<Rule> = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(rules[0].to, proxy("tor"));
        assert_eq!(rules[0].fallback, Fallback::Offline);
        assert_eq!(rules[1].keys, vec!["admin".to_string()]);
        assert_eq!(rules[2].fallback, Fallback::To(group("exits")));
        assert_eq!(rules[3].to, Destination::Block);
        assert_eq!(
            (rules[4].to.clone(), rules[4].fallback.clone()),
            (group("exits"), Fallback::Policy)
        );
        assert_eq!(rules[5].fallback, Fallback::To(Destination::Direct));
        assert!(
            serde_json::from_value::<Rule>(serde_json::json!({"match": ["*"], "to": "block", "extra": 1})).is_err()
        );
        // The pool is gone: a rule that names it is refused.
        let old = serde_json::from_value::<Rule>(serde_json::json!({"match": ["*"], "to": "pool"}));
        assert!(old.unwrap_err().to_string().contains("unknown variant `pool`"));
        let back = serde_json::to_value(&rules).unwrap();
        assert_eq!(back[1]["to"], "direct");
        assert_eq!(back[0]["to"]["proxy"], "tor");
        assert_eq!(back[2]["fallback"]["to"]["group"], "exits");
        assert_eq!(back[4]["fallback"], "policy");
        assert_eq!(back[0]["fallback"], "offline");
    }
}
