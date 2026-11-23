//! The proxy pool as this service runs it: the tests that need the whole
//! service (settings saved through the operator tools, the database, the
//! keys). They were the second half of `proxypool.rs`'s test module and are
//! unchanged apart from their imports.

use crate::network::{OfflinePolicy, ProxyEntry, ProxyMode, ProxySettings};
use crate::privacy::ProxyCheck;
use crate::proxypool::*;

fn cfg(mode: ProxyMode, n: usize) -> ProxySettings {
    ProxySettings {
        list: (0..n)
            .map(|i| ProxyEntry {
                id: format!("p{i}"),
                name: String::new(),
                url: format!("socks5://h:{}", i + 1),
                keys: Vec::new(),
                pool: true,
                i2p: false,
            })
            .collect(),
        mode,
        rotate_secs: 600,
        chaos_min_secs: 300,
        chaos_max_secs: 900,
        ..ProxySettings::default()
    }
}

#[tokio::test]
async fn a_listed_proxy_without_a_plan_reads_as_offline_and_checks_never_connect_straight() {
    let r = rig(|_| {}).await;
    listed(&r, ProxyMode::Failover, OfflinePolicy::KillSwitch, 1);
    let h = r.svc.pool_health();
    assert_eq!((h.state, h.posture), (PoolState::Offline, Posture::Off));
    // No connection is allowed, so the relay check does not make one either.
    assert_eq!(r.svc.refresh_relay_health().await, Some(Vec::new()));
    // Resetting to the environment's (empty) list is a proxy change too.
    let patch = serde_json::from_value(serde_json::json!({
        "proxies": { "list": [{ "id": "a", "url": "socks5://h:1" }] }
    }))
    .unwrap();
    r.svc
        .update_settings(&r.admin(), crate::manage::UpdateSettingsParams { patch })
        .unwrap();
    probe(&r, "a", true);
    r.svc.replan();
    r.svc.reset_settings(&r.admin()).unwrap();
    assert!(r.svc.settings().proxies.list.is_empty());
    assert!(r.svc.pool.lock().unwrap().probation.is_some());
}

#[tokio::test]
async fn a_proxy_is_tested_by_id_by_address_or_as_the_one_in_use() {
    use crate::manage::CheckProxyParams;
    let r = rig(|_| {}).await;
    let (port, _p) = crate::relay::tests::socks5_proxy(None).await;
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5://127.0.0.1:{port}");
    let mut s = r.svc.settings().clone();
    s.relays = vec![format!("ws://127.0.0.1:{}", relay.local_addr().unwrap().port())];
    s.proxies.list = vec![ProxyEntry {
        id: "good".into(),
        name: String::new(),
        url: url.clone(),
        keys: Vec::new(),
        pool: true,
        i2p: false,
    }];
    r.svc.apply_settings(s);
    r.svc.refresh_pool().await;
    let ask = |id: Option<&str>, proxy: Option<&str>| CheckProxyParams {
        id: id.map(Into::into),
        proxy: proxy.map(Into::into),
    };
    // The proxy in use.
    let c = r.svc.check_proxy(&r.admin(), ask(None, None)).await.unwrap();
    assert_eq!(c.status, "connected");
    assert!(r.svc.last_proxy_check.lock().unwrap().is_some());
    // By id, and by its address.
    assert_eq!(
        r.svc
            .check_proxy(&r.admin(), ask(Some("good"), None))
            .await
            .unwrap()
            .status,
        "connected"
    );
    assert_eq!(
        r.svc
            .check_proxy(&r.admin(), ask(None, Some(&url)))
            .await
            .unwrap()
            .status,
        "connected"
    );
    // Mistakes.
    let msg = |e: Result<(), crate::error::Error>| e.unwrap_err().to_string();
    assert!(
        msg(r.svc.check_proxy(&r.admin(), ask(Some("nope"), None)).await.map(|_| ())).contains("no proxy with that id")
    );
    assert!(msg(r
        .svc
        .check_proxy(&r.admin(), ask(Some("good"), Some(&url)))
        .await
        .map(|_| ()))
    .contains("not both"));
}

#[tokio::test]
async fn routing_rules_move_single_relays_and_report_why() {
    use crate::routes::{Fallback, Reason, RouteTo, Rule};
    let r = rig(|_| {}).await;
    let (onion, vpn, plain) = ("ws://abc.onion", "wss://vpn.example", "wss://plain.example");
    let mut s = r.svc.settings().clone();
    s.relays = vec![onion.into(), vpn.into(), plain.into()];
    let entry = |id: &str, pool: bool| ProxyEntry {
        id: id.into(),
        name: id.into(),
        url: format!("socks5://{id}:1"),
        keys: Vec::new(),
        pool,
        i2p: false,
    };
    s.proxies = ProxySettings {
        list: vec![entry("tor", true), entry("vpn", false)],
        rules: vec![
            Rule {
                name: String::new(),
                patterns: vec!["*.onion".into()],
                keys: Vec::new(),
                to: RouteTo::Proxy("tor".into()),
                fallback: Fallback::Offline,
            },
            Rule {
                name: String::new(),
                patterns: vec![vpn.into()],
                keys: Vec::new(),
                to: RouteTo::Proxy("vpn".into()),
                fallback: Fallback::Pool,
            },
        ],
        ..ProxySettings::default()
    };
    r.svc.apply_settings(s);
    probe(&r, "tor", true);
    probe(&r, "vpn", true);
    r.svc.replan();
    let routes = |r: &Rig| -> Vec<(String, Option<String>, Reason)> {
        r.svc
            .routes_for("invoices")
            .into_iter()
            .map(|x| {
                let via = match x.via {
                    crate::routes::Via::Proxy { id, .. } => Some(id),
                    crate::routes::Via::Direct => Some("direct".into()),
                    crate::routes::Via::Off => None,
                };
                (x.relay, via, x.reason)
            })
            .collect()
    };
    assert_eq!(
        routes(&r),
        vec![
            (onion.into(), Some("tor".into()), Reason::Rule),
            (vpn.into(), Some("vpn".into()), Reason::Rule),
            (plain.into(), Some("tor".into()), Reason::Default),
        ]
    );
    // Drain the wake-up from setting things up.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(50), r.svc.pool_changed()).await;
    // vpn goes down: only its relay moves (to the default route), and the
    // supervisor is told although no key's default route changed.
    probe(&r, "vpn", false);
    r.svc.replan();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), r.svc.pool_changed())
            .await
            .is_ok()
    );
    assert_eq!(routes(&r)[1], (vpn.into(), Some("tor".into()), Reason::Fallback));
    // Health says the same, numbering rules from 1.
    let h = r.svc.pool_health();
    let vpn_route = h.routes.iter().find(|x| x.key == "invoices" && x.relay == vpn).unwrap();
    assert_eq!(
        (
            vpn_route.rule,
            vpn_route.via,
            vpn_route.proxy.as_deref(),
            vpn_route.reason
        ),
        (Some(2), RouteVia::Proxy, Some("tor"), Reason::Fallback)
    );
    assert!(h.proxies.iter().any(|p| p.id == "vpn" && !p.pool));
    assert!(h.lanes.iter().all(|l| l.uses_default));
    // The pool's only proxy down too: a "stay offline" rule's relay keeps
    // going through its own proxy; the rest have no default route, so the
    // kill switch applies.
    probe(&r, "tor", false);
    r.svc.replan();
    assert_eq!(
        routes(&r),
        vec![
            (onion.into(), Some("tor".into()), Reason::Rule),
            (vpn.into(), None, Reason::PoolOffline),
            (plain.into(), None, Reason::PoolOffline),
        ]
    );
    assert_eq!(r.svc.posture(), Posture::Off);
    // On a host that is itself behind a proxy, every relay goes straight.
    let mut s = r.svc.settings().clone();
    s.proxies.transparent = true;
    r.svc.apply_settings(s);
    r.svc.replan();
    assert!(routes(&r)
        .iter()
        .all(|(_, via, why)| via.as_deref() == Some("direct") && *why == Reason::Transparent));
}

#[tokio::test]
async fn an_empty_default_route_is_offline_never_straight_and_only_matters_when_used() {
    use crate::routes::{Fallback, Reason, RouteTo, Rule};
    let r = rig(|_| {}).await;
    let mut s = r.svc.settings().clone();
    s.relays = vec!["wss://a.example".into()];
    s.proxies.list = vec![ProxyEntry {
        id: "only".into(),
        name: String::new(),
        url: "socks5://only:1".into(),
        keys: Vec::new(),
        pool: false,
        i2p: false,
    }];
    r.svc.apply_settings(s.clone());
    probe(&r, "only", true);
    r.svc.replan();
    // The relay takes the default route, which has no proxy: offline, not straight.
    let x = &r.svc.routes_for("invoices")[0];
    assert_eq!(
        (x.via.clone(), x.reason),
        (crate::routes::Via::Off, Reason::PoolOffline)
    );
    assert_eq!(r.svc.posture(), Posture::Off);
    assert_eq!(r.svc.pool_health().posture, Posture::Off);
    // With every relay ruled to the proxy, the empty pool hurts nobody.
    s.proxies.rules = vec![Rule {
        name: String::new(),
        patterns: vec!["*".into()],
        keys: Vec::new(),
        to: RouteTo::Proxy("only".into()),
        fallback: Fallback::Offline,
    }];
    r.svc.apply_settings(s);
    r.svc.replan();
    assert!(matches!(
        r.svc.routes_for("admin")[0].via,
        crate::routes::Via::Proxy { .. }
    ));
    assert_eq!(r.svc.posture(), Posture::Normal);
    let h = r.svc.pool_health();
    assert_eq!(h.posture, Posture::Normal);
    assert!(h.lanes.iter().all(|l| !l.uses_default && l.state == PoolState::Offline));
    // A proxy that carries no relay is not probed, and its old probe is forgotten.
    let mut s = r.svc.settings().clone();
    s.proxies.rules.clear();
    s.proxies.list[0].pool = false;
    r.svc.apply_settings(s);
    r.svc.refresh_pool().await;
    assert!(r.svc.pool.lock().unwrap().probes.is_empty());
}

#[tokio::test]
async fn a_proxy_that_carries_nothing_cannot_be_tested_and_rule_directs_reach_the_audit() {
    use crate::manage::CheckProxyParams;
    use crate::routes::{Fallback, RouteTo, Rule};
    let r = rig(|_| {}).await;
    let mut s = r.svc.settings().clone();
    s.relays = vec![
        "wss://open.example".into(),
        "ws://relay.lan:1".into(),
        "ws://x.fips:1".into(),
        "wss://relay.home.example".into(),
        "wss://mixed.example".into(),
    ];
    s.proxies.list = vec![ProxyEntry {
        id: "spare".into(),
        name: String::new(),
        url: "socks5://127.0.0.1:1".into(),
        keys: Vec::new(),
        pool: false,
        i2p: false,
    }];
    let direct = |p: &str| Rule {
        name: String::new(),
        patterns: vec![p.into()],
        keys: Vec::new(),
        to: RouteTo::Direct,
        fallback: Fallback::Offline,
    };
    // Straight to an internet relay is a finding; to the LAN and FIPS it is not.
    s.proxies.rules = vec![
        direct("open.example"),
        direct("*.lan"),
        direct("*.fips"),
        direct("relay.home.example"),
        direct("mixed.example"),
    ];
    // A LAN name that resolves only to private addresses stays local; one
    // with any public address, or none at all, reaches the internet.
    *r.svc.resolver.lock().unwrap() = std::sync::Arc::new(|host: String, _| {
        Box::pin(async move {
            match host.as_str() {
                "relay.home.example" => vec!["192.168.1.5".parse().unwrap()],
                "mixed.example" => vec!["10.0.0.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
                _ => vec![],
            }
        })
    });
    r.svc.apply_settings(s);
    r.svc.replan();
    let err = r
        .svc
        .check_proxy(
            &r.admin(),
            CheckProxyParams {
                id: Some("spare".into()),
                proxy: None,
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no relay goes through this proxy"), "{err}");
    let audit = r.svc.privacy_audit(&r.admin()).await.unwrap();
    let c = audit.checks.iter().find(|c| c.id == "relays_direct_by_rule").unwrap();
    assert_eq!(
        c.evidence,
        vec![
            "direct   wss://open.example".to_string(),
            "direct   wss://mixed.example".to_string()
        ]
    );
}

use crate::service::tests::{public, rig, Rig, T0};
use nostr_sdk::Keys;
use std::sync::atomic::Ordering;

fn listed(r: &Rig, mode: ProxyMode, offline: OfflinePolicy, n: usize) {
    let mut s = r.svc.settings().clone();
    s.proxies = ProxySettings {
        offline,
        ..cfg(mode, n)
    };
    r.svc.apply_settings(s);
}

fn probe(r: &Rig, id: &str, up: bool) {
    r.svc.record_probe(
        id,
        ProxyCheck {
            proxy: format!("socks5://h/{id}"),
            status: if up { "connected" } else { "failed" }.into(),
            checked_at: r.now.load(Ordering::SeqCst),
            relays: Vec::new(),
        },
    );
}

fn proxy_in_use(r: &Rig) -> Option<String> {
    r.svc.active_proxy()
}

#[tokio::test]
async fn the_connection_follows_the_plan_and_the_policy() {
    let r = rig(|_| {}).await;
    // No list: straight, by choice. A list with no plan yet: wait, do not leak.
    assert_eq!(r.svc.connection(), Connection::Direct);
    listed(&r, ProxyMode::Failover, OfflinePolicy::KillSwitch, 2);
    assert_eq!(r.svc.connection(), Connection::Off);
    assert_eq!(r.svc.posture(), Posture::Normal, "not gated before the first plan");

    probe(&r, "p1", true);
    r.svc.replan();
    assert_eq!(r.svc.connection(), Connection::Via("socks5://h:2".into()));
    assert_eq!(r.svc.pool_health().active.as_deref(), Some("p1"));
    probe(&r, "p0", true);
    probe(&r, "p1", true);
    r.now.fetch_add(FAILBACK_HOLD_SECS + 1, Ordering::SeqCst);
    r.svc.replan();
    assert_eq!(proxy_in_use(&r).as_deref(), Some("socks5://h:1"));

    // Everything down: each policy is a different connection and posture.
    probe(&r, "p0", false);
    probe(&r, "p1", false);
    // (The key for the public and the key for operators each keep only what the policy keeps.)
    for (policy, public, operators, posture) in [
        (
            OfflinePolicy::KillSwitch,
            Connection::Off,
            Connection::Off,
            Posture::Off,
        ),
        (
            OfflinePolicy::AdminOnly,
            Connection::Off,
            Connection::Direct,
            Posture::AdminOnly,
        ),
        (
            OfflinePolicy::InvoicingOnly,
            Connection::Direct,
            Connection::Off,
            Posture::InvoicingOnly,
        ),
        (
            OfflinePolicy::Open,
            Connection::Direct,
            Connection::Direct,
            Posture::Open,
        ),
    ] {
        listed(&r, ProxyMode::Failover, policy, 2);
        r.svc.replan();
        assert_eq!(
            (r.svc.connection(), r.svc.connection_for("admin"), r.svc.posture()),
            (public, operators, posture),
            "{policy:?}"
        );
        assert_eq!(r.svc.pool_health().state, PoolState::Offline);
    }
    // A proxy returns: back through it, not gated.
    probe(&r, "p1", true);
    r.svc.replan();
    assert_eq!(r.svc.posture(), Posture::Normal);
    assert_eq!(proxy_in_use(&r).as_deref(), Some("socks5://h:2"));
}

fn assign(r: &Rig, keys: &[&[&str]]) {
    let mut s = r.svc.settings().clone();
    for (e, k) in s.proxies.list.iter_mut().zip(keys) {
        e.keys = k.iter().map(|k| k.to_string()).collect();
    }
    r.svc.apply_settings(s);
}

#[tokio::test]
async fn each_key_plans_over_its_own_proxies() {
    let r = rig(|_| {}).await;
    listed(&r, ProxyMode::Failover, OfflinePolicy::KillSwitch, 2);
    assign(&r, &[&["invoices"], &["admin"]]);
    probe(&r, "p0", true);
    probe(&r, "p1", true);
    r.svc.replan();
    assert_eq!(r.svc.connection_for("invoices"), Connection::Via("socks5://h:1".into()));
    assert_eq!(r.svc.connection_for("admin"), Connection::Via("socks5://h:2".into()));
    assert_eq!(r.svc.active_proxy_for("admin").as_deref(), Some("socks5://h:2"));
    assert_eq!(
        r.svc.active_proxy().as_deref(),
        Some("socks5://h:1"),
        "the public key's"
    );
    let h = r.svc.pool_health();
    let lanes: Vec<(&str, Option<&str>, PoolState)> = h
        .lanes
        .iter()
        .map(|l| (l.key.as_str(), l.active.as_deref(), l.state))
        .collect();
    assert_eq!(
        lanes,
        [
            ("invoices", Some("p0"), PoolState::Active),
            ("admin", Some("p1"), PoolState::Active)
        ]
    );
    assert_eq!(h.proxies[1].keys, ["admin"]);
    assert_eq!((h.state, h.active.as_deref()), (PoolState::Active, Some("p0")));

    // The administration key's only proxy goes down: only that key is cut off.
    probe(&r, "p1", false);
    r.svc.replan();
    assert_eq!(r.svc.connection_for("invoices"), Connection::Via("socks5://h:1".into()));
    assert_eq!(r.svc.connection_for("admin"), Connection::Off);
    assert_eq!(r.svc.posture(), Posture::Off);
    let h = r.svc.pool_health();
    assert_eq!(
        (h.lanes[0].state, h.lanes[1].state),
        (PoolState::Active, PoolState::Offline)
    );
    assert_eq!(h.posture, Posture::Off);

    // A proxy shared by both keys is used by both; a key is unknown to the plan until it runs.
    assign(&r, &[&[], &[]]);
    probe(&r, "p1", true);
    r.svc.replan();
    assert_eq!(r.svc.connection_for("invoices"), r.svc.connection_for("admin"));
    r.svc.pool.lock().unwrap().applied.clear();
    assert_eq!(
        r.svc.connection_for("invoices"),
        Connection::Off,
        "a list with no plan yet: wait"
    );
    assert_eq!(r.svc.pool_health().lanes[0].state, PoolState::Offline);
}

#[tokio::test]
async fn a_proxy_is_probed_only_against_the_relays_of_its_keys() {
    let r = rig(|_| {}).await;
    let (port, _p) = crate::relay::tests::socks5_proxy(None).await;
    let (a, b) = (
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
    );
    let url = |l: &tokio::net::TcpListener| format!("ws://127.0.0.1:{}", l.local_addr().unwrap().port());
    let mut s = r.svc.settings().clone();
    s.relays = vec![url(&a), url(&b)];
    s.relay_keys = [(url(&b), vec!["invoices".to_string()])].into();
    s.proxies.list = vec![ProxyEntry {
        id: "admin-only".into(),
        name: String::new(),
        url: format!("socks5://127.0.0.1:{port}"),
        keys: vec!["admin".into()],
        pool: true,
        i2p: false,
    }];
    r.svc.apply_settings(s);
    r.svc.refresh_pool().await;
    let probed: Vec<String> = r.svc.pool.lock().unwrap().probes["admin-only"]
        .check
        .relays
        .iter()
        .map(|x| x.relay.clone())
        .collect();
    assert_eq!(probed.len(), 1, "{probed:?}");
    assert!(
        probed[0].contains(&a.local_addr().unwrap().port().to_string()),
        "{probed:?}"
    );
}

#[tokio::test]
async fn rotation_follows_the_clock_and_is_suspended_with_one_proxy() {
    let r = rig(|_| {}).await;
    listed(&r, ProxyMode::RoundRobin, OfflinePolicy::KillSwitch, 3);
    for id in ["p0", "p1", "p2"] {
        probe(&r, id, true);
    }
    r.svc.replan();
    let health = r.svc.pool_health();
    assert_eq!(
        (health.state, health.reachable, health.total),
        (PoolState::Active, 3, 3)
    );
    assert_eq!(health.next_switch_at, Some(T0 + 600));
    let order = |r: &Rig| {
        let mut seen = Vec::new();
        for _ in 0..4 {
            seen.push(r.svc.pool_health().active.unwrap());
            r.now.fetch_add(600, Ordering::SeqCst);
            for id in ["p0", "p1", "p2"] {
                probe(r, id, true);
            }
            r.svc.replan();
        }
        seen
    };
    assert_eq!(order(&r), ["p0", "p1", "p2", "p0"]);

    // Two of three go down: rotation is suspended on the one left.
    probe(&r, "p0", false);
    probe(&r, "p1", false);
    r.svc.replan();
    let h = r.svc.pool_health();
    assert_eq!(
        (h.state, h.active.as_deref(), h.next_switch_at),
        (PoolState::Suspended, Some("p2"), None)
    );
    assert_eq!(h.posture, Posture::Normal);
    // The dashboard sees why each one is down.
    assert_eq!(
        h.proxies.iter().map(|p| p.reachable).collect::<Vec<_>>(),
        [Some(false), Some(false), Some(true)]
    );
}

#[tokio::test]
async fn the_policy_decides_who_may_call() {
    use crate::error::Error;
    let r = rig(|_| {}).await;
    let user = Keys::generate();
    let who = |r: &Rig| public(&user, 4, r.now.load(Ordering::SeqCst));
    let down = |r: &Rig, policy| {
        listed(r, ProxyMode::Failover, policy, 1);
        probe(r, "p0", false);
        r.svc.replan();
    };
    // Operators only.
    down(&r, OfflinePolicy::AdminOnly);
    assert!(matches!(r.svc.info(&who(&r)), Err(Error::Unavailable)));
    assert!(r.svc.info(&r.admin()).unwrap().is_admin);
    assert!(r.svc.health(&r.admin()).await.is_ok());
    // Invoicing only: the public is served, operators are nobody.
    down(&r, OfflinePolicy::InvoicingOnly);
    assert!(!r.svc.info(&who(&r)).unwrap().is_admin);
    assert!(matches!(r.svc.health(&r.admin()).await, Err(Error::Unauthorized)));
    assert!(!r.svc.info(&r.admin()).unwrap().is_admin);
    // Open and the kill switch (which has no connection to call over) do not gate.
    for policy in [OfflinePolicy::Open, OfflinePolicy::KillSwitch] {
        down(&r, policy);
        assert!(r.svc.info(&who(&r)).is_ok() && r.svc.health(&r.admin()).await.is_ok());
    }
    // The public is never told why.
    assert_eq!(Error::Unavailable.public_message(), "service temporarily unavailable");
}

#[tokio::test]
async fn a_transparent_proxy_means_straight_connections_and_no_probing() {
    let r = rig(|_| {}).await;
    listed(&r, ProxyMode::Chaos, OfflinePolicy::KillSwitch, 2);
    let mut s = r.svc.settings().clone();
    s.proxies.transparent = true;
    r.svc.apply_settings(s);
    // Even a list full of dead proxies, and a plan from before, changes nothing.
    probe(&r, "p0", false);
    probe(&r, "p1", false);
    r.svc.replan();
    r.svc.refresh_pool().await;
    let h = r.svc.pool_health();
    assert_eq!(
        (h.state, h.posture, h.transparent),
        (PoolState::Transparent, Posture::Normal, true)
    );
    assert_eq!(r.svc.connection(), Connection::Direct);
    assert_eq!(r.svc.active_proxy(), None);
    assert!(
        h.proxies.iter().all(|p| p.url.starts_with("socks5://")),
        "the list is kept, inactive"
    );
}

#[tokio::test]
async fn probing_marks_a_proxy_that_tunnels_up_and_one_that_does_not_down() {
    let r = rig(|_| {}).await;
    let (port, _p) = crate::relay::tests::socks5_proxy(None).await;
    // A relay on this machine, which the mock proxy can reach.
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://127.0.0.1:{}", relay.local_addr().unwrap().port());
    let mut s = r.svc.settings().clone();
    s.relays = vec![relay_url];
    s.proxies.list = vec![
        ProxyEntry {
            id: "good".into(),
            name: "Tor".into(),
            url: format!("socks5://127.0.0.1:{port}"),
            keys: Vec::new(),
            pool: true,
            i2p: false,
        },
        ProxyEntry {
            id: "bad".into(),
            name: String::new(),
            url: "socks5://127.0.0.1:9".into(),
            keys: Vec::new(),
            pool: true,
            i2p: false,
        },
    ];
    r.svc.apply_settings(s);
    r.svc.refresh_pool().await;
    let h = r.svc.pool_health();
    assert_eq!(h.active.as_deref(), Some("good"));
    assert_eq!(h.proxies[0].reachable, Some(true));
    assert_eq!(h.proxies[0].status.as_deref(), Some("connected"));
    assert_eq!(h.proxies[1].reachable, Some(false));
    assert!(h.proxies[1].reason.as_deref().is_some_and(|r| !r.is_empty()));
    assert_eq!(h.proxies[0].name, "Tor");
    // "Up since" survives a second probe while it stays up.
    let since = r.svc.pool.lock().unwrap().probes["good"].up_since;
    r.now.fetch_add(30, Ordering::SeqCst);
    r.svc.refresh_pool().await;
    assert_eq!(r.svc.pool.lock().unwrap().probes["good"].up_since, since);
}

#[tokio::test]
async fn a_change_that_leaves_nothing_reachable_is_undone_once() {
    let r = rig(|_| {}).await;
    let (port, _p) = crate::relay::tests::socks5_proxy(None).await;
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut s = r.svc.settings().clone();
    s.relays = vec![format!("ws://127.0.0.1:{}", relay.local_addr().unwrap().port())];
    s.proxies.list = vec![ProxyEntry {
        id: "a".into(),
        name: String::new(),
        url: format!("socks5://127.0.0.1:{port}"),
        keys: Vec::new(),
        pool: true,
        i2p: false,
    }];
    r.svc.apply_settings(s);
    r.svc.refresh_pool().await;
    assert_eq!(r.svc.pool_health().state, PoolState::Active);

    // The operator replaces it with a dead one.
    let bad = serde_json::from_value(serde_json::json!({
        "proxies": { "list": [{ "url": "socks5://127.0.0.1:9" }] }
    }))
    .unwrap();
    r.svc
        .update_settings(&r.admin(), crate::manage::UpdateSettingsParams { patch: bad })
        .unwrap();
    assert_eq!(r.svc.settings().proxies.list[0].url, "socks5://127.0.0.1:9");
    r.svc.refresh_pool().await;
    assert_eq!(r.svc.settings().proxies.list[0].id, "a", "the previous list is back");
    assert_eq!(r.svc.pool_health().state, PoolState::Active);
    let last = r.svc.db.audit_recent(5).unwrap();
    assert!(last
        .iter()
        .any(|e| e.action == "revert_proxies" && e.actor == "service"));
    // What is saved is the working list, in the new form.
    let stored = r.svc.stored_patch().unwrap();
    assert!(stored.proxy.is_none());
    assert_eq!(stored.proxies.unwrap().list.unwrap()[0].id.as_deref(), Some("a"));
}

#[tokio::test]
async fn the_strategy_cannot_be_turned_off_while_the_first_proxy_is_down() {
    let r = rig(|_| {}).await;
    let save = |v: serde_json::Value| {
        let patch = serde_json::from_value(v).unwrap();
        r.svc
            .update_settings(&r.admin(), crate::manage::UpdateSettingsParams { patch })
    };
    save(serde_json::json!({ "proxies": { "mode": "failover", "list": [
        { "id": "p0", "url": "socks5://h:1" }, { "id": "p1", "url": "socks5://h:2" }
    ] } }))
    .unwrap();
    r.svc.pool.lock().unwrap().probation = None;
    probe(&r, "p0", false);
    probe(&r, "p1", true);
    r.svc.replan();
    assert_eq!(r.svc.pool_health().active.as_deref(), Some("p1"));
    // Off would leave every key offline now, the operators' included.
    let e = save(serde_json::json!({ "proxies": { "mode": "off" } })).unwrap_err();
    assert!(e.to_string().contains("first proxy"), "{e}");
    assert_eq!(r.svc.settings().proxies.mode, ProxyMode::Failover);
    // With a reachable proxy first, it is taken.
    save(serde_json::json!({ "proxies": { "mode": "off", "list": [
        { "id": "p1", "url": "socks5://h:2" }, { "id": "p0", "url": "socks5://h:1" }
    ] } }))
    .unwrap();
    r.svc.pool.lock().unwrap().probation = None;
    r.svc.replan();
    assert_eq!(
        (r.svc.pool_health().active.as_deref(), r.svc.posture()),
        (Some("p1"), Posture::Normal)
    );
    // Off means it: the first going down cuts the key off, though p0 is up.
    probe(&r, "p1", false);
    probe(&r, "p0", true);
    r.svc.replan();
    let h = r.svc.pool_health();
    assert_eq!(
        (h.state, h.reachable, r.svc.posture()),
        (PoolState::Offline, 1, Posture::Off)
    );
    // A transparent proxy does the work: nothing here can strand a key.
    save(serde_json::json!({ "proxies": { "mode": "failover" } })).unwrap();
    save(serde_json::json!({ "proxies": { "mode": "off", "transparent": true } })).unwrap();
    assert_eq!(r.svc.settings().proxies.mode, ProxyMode::Off);
}

#[tokio::test]
async fn a_changed_policy_is_not_undone_when_the_same_proxies_fail_later() {
    let r = rig(|_| {}).await;
    let first = serde_json::from_value(serde_json::json!({
        "proxies": { "list": [{ "id": "p0", "url": "socks5://h:1" }] }
    }))
    .unwrap();
    r.svc
        .update_settings(&r.admin(), crate::manage::UpdateSettingsParams { patch: first })
        .unwrap();
    r.svc.pool.lock().unwrap().probation = None;
    probe(&r, "p0", true);
    r.svc.replan();
    let patch = serde_json::from_value(serde_json::json!({ "proxies": { "offline": "open" } })).unwrap();
    r.svc
        .update_settings(&r.admin(), crate::manage::UpdateSettingsParams { patch })
        .unwrap();
    assert!(r.svc.pool.lock().unwrap().probation.is_none());
    probe(&r, "p0", false);
    r.svc.replan();
    assert_eq!(r.svc.settings().proxies.offline, OfflinePolicy::Open);
    assert_eq!(r.svc.posture(), Posture::Open);
}

#[tokio::test]
async fn a_proxy_saved_before_there_was_a_list_survives_the_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let cfg = crate::config::tests::load(&crate::config::tests::base()).unwrap();
    crate::db::Db::open(&path)
        .unwrap()
        .meta_set(
            crate::service::META_SETTINGS,
            Some(r#"{"proxy":"socks5://me:pw@10.1.2.3:1080","pow_bits":21}"#),
        )
        .unwrap();
    let (svc, _f) = crate::manage::tests::on_disk(&cfg, &path, T0).await;
    assert!(
        svc.settings_problem.lock().unwrap().is_none(),
        "the old form still reads"
    );
    let live = svc.settings().proxies.list.clone();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].url, "socks5://me:pw@10.1.2.3:1080");
    assert_eq!(svc.settings().pow_bits, 21, "nothing else was dropped");
    assert_eq!(svc.settings().proxies.mode, ProxyMode::Off);
    assert_eq!(svc.settings().proxies.offline, OfflinePolicy::KillSwitch);
}
