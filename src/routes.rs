//! Routing rules: which way each relay connection goes.
//!
//! An operator keeps an ordered list of [`Rule`]s. For each key and each of
//! its relays, the first rule that applies to the key and matches the relay
//! decides the route: through one proxy, through the default route (the proxy
//! pool and its strategy), directly, or nowhere. A relay no rule matches takes
//! the default route.
//!
//! [`resolve`] is pure: given the settings, the key's default route and which
//! proxies are up, it says where each relay goes and why. The service keeps
//! the state it needs (`proxypool.rs`), the app acts on it (`app.rs`).
//!
//! Patterns are matched against the relay's host as a URL parser reads it
//! (never the raw authority, which may carry user info), lower case. A
//! pattern with `://` is one exact relay address. Otherwise it is a host
//! pattern: `*` stands for any run of characters, dots included, and an
//! optional `:port` must equal the relay's port (or the scheme's default).
//! `*.example.com` does not match `example.com` itself.

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::config::is_overlay_host;
use crate::error::{Error, Result};
use crate::settings::{ProxySettings, Settings};

/// Most rules in the list.
pub const MAX_RULES: usize = 16;
/// Most patterns in one rule.
pub const MAX_PATTERNS: usize = 16;
/// Longest pattern.
pub const MAX_PATTERN_LEN: usize = 256;
/// Longest rule name.
pub const MAX_NAME_LEN: usize = 60;

// Where the relays a rule matches go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteTo {
    // The default route: the proxy pool and its strategy.
    Pool,
    // No proxy at all.
    Direct,
    // Never connect.
    Block,
    // Through this proxy (by id).
    Proxy(String),
}

// What a rule that goes through one proxy does while that proxy is down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    // Stay offline: never connect another way.
    #[default]
    Offline,
    // Use the default route until the proxy is back.
    Pool,
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
    pub to: RouteTo,
    // Only for a rule that goes through one proxy.
    #[serde(default)]
    pub fallback: Fallback,
}

/// The host (lower case, without IPv6 brackets) and port of a relay address,
/// as a URL parser reads them.
pub fn host_port(relay: &str) -> Option<(String, u16)> {
    let url = nostr_sdk::Url::parse(relay).ok()?;
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some((host, url.port_or_known_default()?))
}

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
fn names_tor_or_i2p(pattern: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let host = if p.contains("://") {
        host_port(&p).map(|(h, _)| h).unwrap_or_default()
    } else {
        split_port(&p).0.to_string()
    };
    let host = host.trim_end_matches('.');
    host.ends_with(".onion") || host.ends_with(".i2p")
}

/// Whether a relay must never be connected without a proxy: Tor and I2P names
/// would go to the system resolver and fail, telling it what we looked up.
pub fn never_direct(relay: &str) -> bool {
    host_port(relay).is_some_and(|(h, _)| {
        let h = h.trim_end_matches('.');
        is_overlay_host(h) && !h.ends_with(".fips")
    })
}

impl Rule {
    /// Whether this rule applies to `key` and matches `relay`.
    pub fn applies(&self, key: &str, relay: &str) -> bool {
        crate::keys::assigned(&self.keys, key) && self.patterns.iter().any(|p| matches(p, relay))
    }
}

/// The first rule (by index) that applies to `key` and matches `relay`.
pub fn first_rule(rules: &[Rule], key: &str, relay: &str) -> Option<usize> {
    rules.iter().position(|r| r.applies(key, relay))
}

/// Check the rule list against the proxy list and the relays. `relays_for`
/// gives each key's relays.
pub fn check_rules(proxies: &ProxySettings, settings: &Settings) -> Result<()> {
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
        if let Some(k) = r.keys.iter().find(|k| crate::keys::def(k).is_none()) {
            return Err(Error::InvalidParams(format!("rule {n}: there is no key '{k}'")));
        }
        match &r.to {
            RouteTo::Proxy(id) if !proxies.list.iter().any(|e| &e.id == id) => {
                return Err(Error::InvalidParams(format!(
                    "rule {n} points at a proxy that is not in the list; change the rule first"
                )));
            }
            RouteTo::Direct if r.patterns.iter().any(|p| names_tor_or_i2p(p)) => {
                return Err(Error::InvalidParams(format!(
                    "rule {n}: Tor and I2P relays can only be reached through a proxy, never directly"
                )));
            }
            _ => {}
        }
    }
    // Every key keeps a relay that no rule blocks.
    for key in crate::keys::KEYS {
        let relays = settings.relays_for(key.id);
        let open = relays.iter().any(|relay| {
            !matches!(
                first_rule(rules, key.id, relay).map(|i| &rules[i].to),
                Some(RouteTo::Block)
            )
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
    // The rule's proxy is down; the rule says to use the default route.
    Fallback,
    // The rule's proxy is no longer listed (the rule cannot be followed).
    ProxyDown,
    // A rule blocks this relay.
    Blocked,
    // The default route has no reachable proxy and the offline policy keeps this key off.
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
}

/// What a key's default route is now: the pool's proxy, straight, or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultRoute {
    Proxy {
        id: String,
        url: String,
    },
    Direct,
    /// The pool has no reachable proxy and the offline policy keeps the key off.
    Off,
}

impl DefaultRoute {
    fn via(&self) -> Via {
        match self {
            DefaultRoute::Proxy { id, url } => Via::Proxy {
                id: id.clone(),
                url: url.clone(),
            },
            DefaultRoute::Direct => Via::Direct,
            DefaultRoute::Off => Via::Off,
        }
    }
}

/// Where each of `key`'s relays goes, in list order. `up` says whether a
/// proxy (by id) answered its last probe.
pub fn resolve(settings: &Settings, key: &str, default: &DefaultRoute, up: &dyn Fn(&str) -> bool) -> Vec<Resolved> {
    let proxies = &settings.proxies;
    let rules = &proxies.rules;
    settings
        .relays_for(key)
        .into_iter()
        .map(|relay| {
            let rule = first_rule(rules, key, &relay);
            let on_default = |reason| {
                let via = default.via();
                let reason = if via == Via::Off { Reason::PoolOffline } else { reason };
                (via, reason)
            };
            let (via, reason) = match rule.map(|i| &rules[i]) {
                Some(Rule { to: RouteTo::Block, .. }) => (Via::Off, Reason::Blocked),
                _ if proxies.transparent => (Via::Direct, Reason::Transparent),
                None => on_default(Reason::Default),
                Some(Rule { to: RouteTo::Pool, .. }) => on_default(Reason::Rule),
                Some(Rule {
                    to: RouteTo::Direct, ..
                }) => (Via::Direct, Reason::Rule),
                Some(Rule {
                    to: RouteTo::Proxy(id),
                    fallback,
                    ..
                }) => match proxies.list.iter().find(|e| &e.id == id) {
                    // "Stay offline" means never another way, not "do not
                    // try": with nothing to choose between, the relay always
                    // goes through its proxy and the connection keeps
                    // retrying there. The probe only decides a fallback.
                    Some(e) if up(id) || *fallback == Fallback::Offline => (
                        Via::Proxy {
                            id: id.clone(),
                            url: e.url.clone(),
                        },
                        Reason::Rule,
                    ),
                    _ if *fallback == Fallback::Pool => on_default(Reason::Fallback),
                    _ => (Via::Off, Reason::ProxyDown),
                },
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
            }
        })
        .collect()
}

/// Whether some relay of `key` may take the default route (a rule-free relay,
/// a rule to the pool, or a rule whose proxy falls back to it). When none can,
/// the pool being empty or down does not matter for that key.
pub fn uses_default(settings: &Settings, key: &str) -> bool {
    let rules = &settings.proxies.rules;
    settings
        .relays_for(key)
        .iter()
        .any(|relay| match first_rule(rules, key, relay).map(|i| &rules[i]) {
            None => true,
            Some(r) => {
                matches!(r.to, RouteTo::Pool) || (matches!(r.to, RouteTo::Proxy(_)) && r.fallback == Fallback::Pool)
            }
        })
}

/// The relays that may be sent through proxy `id` (for any key), in list
/// order: what a probe of that proxy should try, so a proxy is never tried
/// against a relay it would not carry.
pub fn relays_through_proxy(settings: &Settings, id: &str) -> Vec<String> {
    let proxies = &settings.proxies;
    let Some(entry) = proxies.list.iter().find(|e| e.id == id) else {
        return Vec::new();
    };
    let rules = &proxies.rules;
    settings
        .relays
        .iter()
        .filter(|relay| {
            settings.relay_users(relay).iter().any(|key| {
                let rule = first_rule(rules, key, relay).map(|i| &rules[i]);
                let in_pool = entry.pool && crate::keys::assigned(&entry.keys, key);
                match rule {
                    Some(Rule {
                        to: RouteTo::Proxy(p),
                        fallback,
                        ..
                    }) => p == id || (in_pool && *fallback == Fallback::Pool),
                    Some(Rule { to: RouteTo::Pool, .. }) | None => in_pool,
                    Some(_) => false,
                }
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ProxyEntry;

    #[test]
    fn patterns_match_hosts_as_documented() {
        // The same cases run in the dashboard (dashboard/src/lib/routes.test.ts).
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/route-patterns.json")).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert!(cases.len() > 20);
        for c in cases {
            let (pattern, relay, want) = (c[0].as_str().unwrap(), c[1].as_str().unwrap(), c[2].as_bool().unwrap());
            assert_eq!(matches(pattern, relay), want, "{pattern} vs {relay}");
        }
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

    fn entry(id: &str, pool: bool) -> ProxyEntry {
        ProxyEntry {
            id: id.into(),
            name: id.into(),
            url: format!("socks5://{id}:1"),
            keys: Vec::new(),
            pool,
        }
    }

    fn rule(patterns: &[&str], to: RouteTo) -> Rule {
        Rule {
            name: String::new(),
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            keys: Vec::new(),
            to,
            fallback: Fallback::Offline,
        }
    }

    const ONION: &str = "ws://abc.onion";
    const LAN: &str = "ws://relay.lan:4869";
    const VPN_RELAY: &str = "wss://relay.contextvm.org";
    const PLAIN: &str = "wss://bucket.coracle.social";

    fn settings(rules: Vec<Rule>) -> Settings {
        let mut s = crate::settings::tests::defaults();
        s.relays = vec![VPN_RELAY.into(), PLAIN.into(), ONION.into(), LAN.into()];
        s.proxies.list = vec![entry("tor", true), entry("vpn", true), entry("i2p", false)];
        s.proxies.rules = rules;
        s
    }

    fn pool() -> DefaultRoute {
        DefaultRoute::Proxy {
            id: "tor".into(),
            url: "socks5://tor:1".into(),
        }
    }

    fn table(
        s: &Settings,
        key: &str,
        default: &DefaultRoute,
        up: &dyn Fn(&str) -> bool,
    ) -> Vec<(String, Option<usize>, Via, Reason)> {
        resolve(s, key, default, up)
            .into_iter()
            .map(|r| (r.relay, r.rule, r.via, r.reason))
            .collect()
    }

    fn via(id: &str) -> Via {
        Via::Proxy {
            id: id.into(),
            url: format!("socks5://{id}:1"),
        }
    }

    #[test]
    fn the_first_matching_rule_decides_and_the_rest_take_the_default_route() {
        let mut vpn = rule(&[VPN_RELAY], RouteTo::Proxy("vpn".into()));
        vpn.fallback = Fallback::Pool;
        let s = settings(vec![
            rule(&["*.onion"], RouteTo::Proxy("tor".into())),
            rule(&["*.lan"], RouteTo::Direct),
            vpn,
            // Never reached for the relay above: rule 3 comes first.
            rule(&["*.contextvm.org"], RouteTo::Block),
        ]);
        let all_up = |_: &str| true;
        assert_eq!(
            table(&s, "invoices", &pool(), &all_up),
            vec![
                (VPN_RELAY.into(), Some(2), via("vpn"), Reason::Rule),
                (PLAIN.into(), None, via("tor"), Reason::Default),
                (ONION.into(), Some(0), via("tor"), Reason::Rule),
                (LAN.into(), Some(1), Via::Direct, Reason::Rule),
            ]
        );
        // A rule's proxy down with "use the default route": its relay falls back.
        let vpn_down = |id: &str| id != "vpn";
        assert_eq!(table(&s, "invoices", &pool(), &vpn_down)[0].2, via("tor"));
        assert_eq!(table(&s, "invoices", &pool(), &vpn_down)[0].3, Reason::Fallback);
        // A rule's proxy down with "stay offline": its relay still goes through
        // that proxy (never another way) rather than being held back.
        let tor_down = |id: &str| id != "tor";
        assert_eq!(
            table(&s, "invoices", &pool(), &tor_down)[2],
            (ONION.into(), Some(0), via("tor"), Reason::Rule)
        );
        // With the pool off, default and fallback relays are off as well.
        let t = table(&s, "invoices", &DefaultRoute::Off, &vpn_down);
        assert_eq!((t[0].2.clone(), t[0].3), (Via::Off, Reason::PoolOffline));
        assert_eq!((t[1].2.clone(), t[1].3), (Via::Off, Reason::PoolOffline));
    }

    #[test]
    fn rules_for_one_key_leave_the_other_alone_and_block_and_pool_work() {
        let mut only_admin = rule(&["*"], RouteTo::Block);
        only_admin.keys = vec!["admin".into()];
        let s = settings(vec![rule(&[PLAIN], RouteTo::Pool), only_admin]);
        let up = |_: &str| true;
        let admin = table(&s, "admin", &pool(), &up);
        assert_eq!(admin[0], (VPN_RELAY.into(), Some(1), Via::Off, Reason::Blocked));
        assert_eq!(admin[1], (PLAIN.into(), Some(0), via("tor"), Reason::Rule));
        let invoices = table(&s, "invoices", &pool(), &up);
        assert_eq!(invoices[0], (VPN_RELAY.into(), None, via("tor"), Reason::Default));
    }

    #[test]
    fn tor_relays_never_go_direct_and_a_transparent_proxy_takes_everything_but_blocks() {
        // The default route is straight (no proxy configured): the onion relay is held back.
        let s = settings(vec![rule(&[LAN], RouteTo::Block)]);
        let t = table(&s, "invoices", &DefaultRoute::Direct, &|_| true);
        assert_eq!(t[2], (ONION.into(), None, Via::Off, Reason::NeverDirect));
        assert_eq!(t[1].2, Via::Direct);
        let mut s = s;
        s.proxies.transparent = true;
        let t = table(&s, "invoices", &DefaultRoute::Off, &|_| false);
        assert_eq!(t[2], (ONION.into(), None, Via::Direct, Reason::Transparent));
        assert_eq!(t[3], (LAN.into(), Some(0), Via::Off, Reason::Blocked));
        // A rule to a proxy that is no longer listed counts as down.
        let s = settings(vec![rule(&["*.onion"], RouteTo::Proxy("gone".into()))]);
        assert_eq!(table(&s, "invoices", &pool(), &|_| true)[2].2, Via::Off);
    }

    #[test]
    fn which_keys_need_the_default_route_and_what_each_proxy_is_probed_against() {
        let mut vpn = rule(&[VPN_RELAY], RouteTo::Proxy("vpn".into()));
        vpn.fallback = Fallback::Pool;
        let s = settings(vec![
            rule(&["*.onion"], RouteTo::Proxy("tor".into())),
            rule(&["*.lan", PLAIN], RouteTo::Direct),
            vpn,
        ]);
        assert!(uses_default(&s, "invoices"), "vpn falls back to the pool");
        let s2 = settings(vec![rule(&["*"], RouteTo::Proxy("i2p".into()))]);
        assert!(!uses_default(&s2, "invoices"));
        let s3 = settings(vec![rule(&["*"], RouteTo::Pool)]);
        assert!(uses_default(&s3, "admin"));
        // A proxy is probed against the relays a rule sends it, plus, while it
        // is in the pool, those that may take the default route (here a pool
        // fallback). One in no rule and out of the pool, or an unknown id: none.
        assert_eq!(
            relays_through_proxy(&s, "tor"),
            vec![VPN_RELAY.to_string(), ONION.to_string()]
        );
        assert_eq!(relays_through_proxy(&s, "vpn"), vec![VPN_RELAY.to_string()]);
        assert!(relays_through_proxy(&s, "i2p").is_empty());
        assert!(relays_through_proxy(&s, "nope").is_empty());
        assert_eq!(relays_through_proxy(&s3, "i2p"), Vec::<String>::new());
        assert_eq!(relays_through_proxy(&s3, "tor").len(), 4);
    }

    #[test]
    fn rule_lists_are_checked() {
        let check = |rules: Vec<Rule>| {
            let s = settings(rules);
            check_rules(&s.proxies, &s).map_err(|e| e.to_string())
        };
        assert!(check(vec![
            rule(&["*.onion"], RouteTo::Proxy("tor".into())),
            rule(&["*.lan"], RouteTo::Direct)
        ])
        .is_ok());
        let named = |name: &str| Rule {
            name: name.into(),
            ..rule(&["*"], RouteTo::Pool)
        };
        let keyed = |k: &str| Rule {
            keys: vec![k.into()],
            ..rule(&["*"], RouteTo::Pool)
        };
        let bad: Vec<(Vec<Rule>, &str)> = vec![
            (vec![rule(&["*"], RouteTo::Pool); MAX_RULES + 1], "at most"),
            (vec![named(&"n".repeat(MAX_NAME_LEN + 1))], "name is too long"),
            (vec![rule(&[], RouteTo::Pool)], "between 1 and"),
            (vec![rule(&["a b"], RouteTo::Pool)], "rule 1: pattern"),
            (vec![keyed("nobody")], "no key 'nobody'"),
            (vec![rule(&["*"], RouteTo::Proxy("gone".into()))], "not in the list"),
            (vec![rule(&["*.onion"], RouteTo::Direct)], "never directly"),
            (vec![rule(&[ONION], RouteTo::Direct)], "never directly"),
            (vec![rule(&["*"], RouteTo::Block)], "block every relay"),
        ];
        for (rules, why) in bad {
            let err = check(rules).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }
        let mut too_many = rule(&["*"], RouteTo::Pool);
        too_many.patterns = vec!["*".into(); MAX_PATTERNS + 1];
        assert!(check(vec![too_many]).unwrap_err().contains("between 1 and"));
        // Blocking everything for one key is refused; for one relay, fine.
        let mut admin_block = rule(&["*"], RouteTo::Block);
        admin_block.keys = vec!["admin".into()];
        assert!(check(vec![admin_block]).unwrap_err().contains("Administration"));
        assert!(check(vec![rule(&[PLAIN], RouteTo::Block)]).is_ok());
    }

    #[test]
    fn rules_read_and_write_the_documented_json() {
        let json = serde_json::json!([
            {"match": ["*.onion"], "to": {"proxy": "tor"}},
            {"name": "lan", "match": ["*.lan"], "keys": ["admin"], "to": "direct"},
            {"match": [VPN_RELAY], "to": {"proxy": "vpn"}, "fallback": "pool"},
            {"match": ["*"], "to": "block"},
            {"match": ["*"], "to": "pool"}
        ]);
        let rules: Vec<Rule> = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(rules[0].to, RouteTo::Proxy("tor".into()));
        assert_eq!(rules[0].fallback, Fallback::Offline);
        assert_eq!(rules[1].keys, vec!["admin".to_string()]);
        assert_eq!(rules[2].fallback, Fallback::Pool);
        assert_eq!(rules[3].to, RouteTo::Block);
        assert!(serde_json::from_value::<Rule>(serde_json::json!({"match": ["*"], "to": "pool", "extra": 1})).is_err());
        let back = serde_json::to_value(&rules).unwrap();
        assert_eq!(back[1]["to"], "direct");
        assert_eq!(back[0]["to"]["proxy"], "tor");
    }
}
