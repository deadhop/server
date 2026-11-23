//! The runtime against a host that is nothing but what the runtime asks of
//! one: a topology that tests change, a clock they set, an operator and a
//! stranger, and lists of what the runtime told it to keep.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use deadhop_cvm::caller::Caller;

use crate::error::{Error, Result};
use crate::netruntime::*;
use crate::network::{Lane, NetworkSettings, OfflinePolicy, ProxyEntry, ProxyMode, ProxySettings, Topology};
use crate::privacy::ProxyCheck;
use crate::proxypool::*;
use crate::routes::{DefaultRoute, Fallback, Reason, RouteTo, Rule, Via};

pub const T0: u64 = 1_700_000_000;

/// How the host says no.
#[derive(Debug)]
pub struct Refused(pub &'static str);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

fn refused<T>(why: &'static str) -> Result<T> {
    Err(Error::Host(Box::new(Refused(why))))
}

pub struct FakeHost {
    pub topology: Mutex<Topology>,
    pub now: AtomicU64,
    pub locked: AtomicBool,
    /// Make the host fail at keeping things (audit entries, relay results, a revert).
    pub broken: AtomicBool,
    pub audits: Mutex<Vec<(String, String, String)>>,
    pub events: Mutex<Vec<RelayEventRow>>,
    pub states: Mutex<Vec<RelayState>>,
    pub reverts: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl NetworkHost for FakeHost {
    fn topology(&self) -> Topology {
        self.topology.lock().unwrap().clone()
    }

    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    /// Like the payment service: `admin` is the operators' lane.
    fn connects_while_offline(&self, lane: &str, policy: OfflinePolicy) -> bool {
        match policy {
            OfflinePolicy::KillSwitch => false,
            OfflinePolicy::AdminOnly => lane == "admin",
            OfflinePolicy::InvoicingOnly => lane != "admin",
            OfflinePolicy::Open => true,
        }
    }

    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> Result<()> {
        if self.broken.load(Ordering::SeqCst) {
            return refused("cannot save");
        }
        self.topology.lock().unwrap().settings.proxies = previous;
        self.reverts.lock().unwrap().push(why.to_string());
        Ok(())
    }

    fn admit_change(&self, caller: &Caller) -> Result<String> {
        match caller.pubkey.as_deref() {
            Some("op") => Ok("op".into()),
            _ => refused("not authorized"),
        }
    }

    fn admit_read(&self, caller: &Caller) -> Result<()> {
        self.admit_change(caller).map(|_| ())
    }

    fn audit(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        if self.broken.load(Ordering::SeqCst) {
            return refused("cannot write");
        }
        self.audits
            .lock()
            .unwrap()
            .push((actor.into(), action.into(), detail.into()));
        Ok(())
    }

    fn proxy_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    async fn relay_states(&self) -> Vec<RelayState> {
        self.states.lock().unwrap().clone()
    }

    fn store_relay_event(&self, row: &RelayEventRow) -> Result<()> {
        if self.broken.load(Ordering::SeqCst) {
            return refused("cannot store");
        }
        self.events.lock().unwrap().push(RelayEventRow {
            at: row.at,
            relay: row.relay.clone(),
            kind: row.kind.clone(),
            ok: row.ok,
            ms: row.ms,
        });
        Ok(())
    }

    fn relay_events_since(&self, since: u64) -> Result<Vec<RelayEventRow>> {
        if self.broken.load(Ordering::SeqCst) {
            return refused("cannot read");
        }
        let events = self.events.lock().unwrap();
        Ok(events
            .iter()
            .filter(|e| e.at >= since)
            .map(|e| RelayEventRow {
                at: e.at,
                relay: e.relay.clone(),
                kind: e.kind.clone(),
                ok: e.ok,
                ms: e.ms,
            })
            .collect())
    }

    fn audit_facts(&self) -> AuditFacts {
        AuditFacts {
            electrum: "127.0.0.1:50001".into(),
            electrum_plain: true,
            electrum_transport: "tcp".into(),
            announce: false,
        }
    }
}

/// A runtime and its host.
pub struct Rig {
    pub net: NetworkRuntime,
    pub host: FakeHost,
}

pub const A: &str = "wss://a.example";
pub const B: &str = "wss://b.example";

pub fn rig(relays: &[&str]) -> Rig {
    let lane = |id: &str, label: &str| Lane {
        id: id.into(),
        label: label.into(),
    };
    Rig {
        net: NetworkRuntime::default(),
        host: FakeHost {
            topology: Mutex::new(Topology {
                settings: NetworkSettings {
                    relays: relays.iter().map(|r| r.to_string()).collect(),
                    relay_keys: Default::default(),
                    relay_names: Default::default(),
                    proxies: ProxySettings::default(),
                },
                lanes: vec![lane("invoices", "Public invoices"), lane("admin", "Administration")],
            }),
            now: AtomicU64::new(T0),
            locked: AtomicBool::new(false),
            broken: AtomicBool::new(false),
            audits: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            states: Mutex::new(Vec::new()),
            reverts: Mutex::new(Vec::new()),
        },
    }
}

impl Rig {
    /// Change the host's settings.
    pub fn set(&self, change: impl FnOnce(&mut Topology)) {
        change(&mut self.host.topology.lock().unwrap());
    }

    pub fn proxies(&self) -> ProxySettings {
        self.host.topology().proxies.clone()
    }

    pub fn probe(&self, id: &str, up: bool) {
        self.net.record_probe(
            id,
            ProxyCheck {
                proxy: format!("socks5://h/{id}"),
                status: if up { "connected" } else { "failed" }.into(),
                checked_at: self.host.now(),
                relays: Vec::new(),
            },
        );
    }

    pub fn replan(&self) {
        self.net.replan(&self.host);
    }

    pub fn applied(&self, lane: &str) -> Option<(PoolState, Option<String>)> {
        let pool = self.net.pool.lock().unwrap();
        pool.applied.get(lane).map(|a| (a.state, a.active.clone()))
    }

    /// Whether the supervisor was told the connections may have changed.
    pub async fn woken(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(100), self.net.pool_changed())
            .await
            .is_ok()
    }
}

pub fn entry(id: &str) -> ProxyEntry {
    ProxyEntry {
        id: id.into(),
        name: String::new(),
        url: format!("socks5://{id}:1"),
        keys: Vec::new(),
        pool: true,
        i2p: false,
    }
}

pub fn rule(patterns: &[&str], to: RouteTo, fallback: Fallback) -> Rule {
    Rule {
        name: String::new(),
        patterns: patterns.iter().map(|p| p.to_string()).collect(),
        keys: Vec::new(),
        to,
        fallback,
    }
}

pub fn op() -> Caller {
    Caller {
        pubkey: Some("op".into()),
        event: None,
    }
}

pub fn text<T: std::fmt::Debug>(r: Result<T>) -> String {
    r.unwrap_err().to_string()
}

fn via(id: &str) -> Connection {
    Connection::Via(format!("socks5://{id}:1"))
}

#[tokio::test]
async fn connections_follow_the_plan_and_the_host_says_what_offline_means() {
    let r = rig(&[A, B]);
    let (net, host) = (&r.net, &r.host);
    // No proxy configured: straight, by choice, with or without a plan.
    assert_eq!(net.connection_for(host, "invoices"), Connection::Direct);
    assert_eq!(net.main_proxy(host), None);
    assert_eq!(net.posture(host), Posture::Normal);
    assert_eq!(net.default_route_for(host, "admin"), DefaultRoute::Direct);
    assert_eq!(
        net.lane_routes(host, "admin"),
        Some(vec![(A.to_string(), String::new()), (B.to_string(), String::new())])
    );
    assert!(
        net.pool_health(host).lanes.iter().all(|l| l.state == PoolState::Direct),
        "before any plan"
    );
    r.replan();
    assert_eq!(r.applied("invoices"), Some((PoolState::Direct, None)));
    assert_eq!(net.connection_for(host, "invoices"), Connection::Direct);

    // A list with no plan yet: wait, do not leak.
    r.set(|t| {
        t.proxies.list = vec![entry("tor"), entry("vpn")];
        t.proxies.mode = ProxyMode::Failover;
    });
    *net.pool.lock().unwrap() = PoolRuntime::default();
    assert_eq!(net.connection_for(host, "invoices"), Connection::Off);
    assert_eq!(net.default_route_for(host, "invoices"), DefaultRoute::Off);
    assert_eq!(net.lane_routes(host, "invoices"), None);
    let waiting = net.pool_health(host);
    assert!(waiting
        .lanes
        .iter()
        .all(|l| l.state == PoolState::Offline && l.active.is_none()));

    // Both up: the first one carries every lane.
    r.probe("tor", true);
    r.probe("vpn", true);
    r.replan();
    assert!(r.woken().await);
    assert_eq!(r.applied("admin"), Some((PoolState::Active, Some("tor".into()))));
    assert_eq!(net.connection_for(host, "admin"), via("tor"));
    assert_eq!(net.active_proxy_for(host, "admin").as_deref(), Some("socks5://tor:1"));
    assert_eq!(net.main_proxy(host).as_deref(), Some("socks5://tor:1"));
    assert_eq!(
        net.default_route_for(host, "invoices"),
        DefaultRoute::Proxy {
            id: "tor".into(),
            url: "socks5://tor:1".into()
        }
    );
    assert_eq!(
        net.lane_routes(host, "invoices"),
        Some(vec![
            (A.to_string(), "socks5://tor:1".into()),
            (B.to_string(), "socks5://tor:1".into())
        ])
    );
    assert_eq!(net.posture(host), Posture::Normal);
    // Nothing changed: the supervisor is left alone.
    r.replan();
    assert!(!r.woken().await);

    // Everything down: the policy applies, and the host says what it means for each lane.
    r.probe("tor", false);
    r.probe("vpn", false);
    r.replan();
    assert!(r.woken().await);
    let cases = [
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
    ];
    for (policy, invoices, admin, posture) in cases {
        r.set(|t| t.proxies.offline = policy);
        assert_eq!(net.connection_for(host, "invoices"), invoices, "{policy:?}");
        assert_eq!(net.connection_for(host, "admin"), admin, "{policy:?}");
        assert_eq!(net.posture(host), posture);
        assert_eq!(net.active_proxy_for(host, "invoices"), None);
    }

    // A transparent proxy: straight, whatever was planned or probed.
    r.set(|t| t.proxies.transparent = true);
    assert_eq!(net.connection_for(host, "invoices"), Connection::Direct);
    r.replan();
    assert_eq!(r.applied("invoices"), Some((PoolState::Transparent, None)));
    assert_eq!(net.connection_for(host, "invoices"), Connection::Direct);
    assert_eq!(net.posture(host), Posture::Normal);
    let h = net.pool_health(host);
    assert!(h.transparent && h.lanes.iter().all(|l| l.state == PoolState::Transparent));
}

#[tokio::test]
async fn each_lane_plans_over_its_own_proxies_and_rotation_follows_the_clock() {
    let r = rig(&[A, B]);
    let (net, host) = (&r.net, &r.host);
    // tor is for the public lane only, vpn for the operators' lane.
    r.set(|t| {
        let (mut tor, mut vpn) = (entry("tor"), entry("vpn"));
        tor.keys = vec!["invoices".into()];
        vpn.keys = vec!["admin".into()];
        t.proxies.list = vec![tor, vpn];
        t.proxies.mode = ProxyMode::Failover;
    });
    r.probe("tor", true);
    r.probe("vpn", false);
    r.probe("gone", true);
    r.replan();
    assert_eq!(r.applied("invoices"), Some((PoolState::Active, Some("tor".into()))));
    assert_eq!(r.applied("admin"), Some((PoolState::Offline, None)));
    assert!(
        !net.pool.lock().unwrap().probes.contains_key("gone"),
        "a probe of an unlisted proxy is dropped"
    );
    assert_eq!(net.connection_for(host, "invoices"), via("tor"));
    assert_eq!(net.connection_for(host, "admin"), Connection::Off);
    assert_eq!(net.posture(host), Posture::Off);

    // A lane that no pool proxy is assigned to is offline, not "no proxy, go straight".
    r.set(|t| t.proxies.list[1].pool = false);
    r.replan();
    assert_eq!(r.applied("admin"), Some((PoolState::Offline, None)));
    let h = net.pool_health(host);
    assert_eq!((h.lanes[1].reachable, h.lanes[1].uses_default), (0, true));

    // Round robin over two reachable proxies: one change per interval, each lane on its own.
    r.set(|t| {
        t.proxies.list = vec![entry("tor"), entry("vpn")];
        t.proxies.mode = ProxyMode::RoundRobin;
        t.proxies.rotate_secs = 600;
    });
    r.probe("vpn", true);
    r.replan();
    assert_eq!(r.applied("admin"), Some((PoolState::Active, Some("tor".into()))));
    assert_eq!(net.pool_health(host).next_switch_at, Some(T0 + 600));
    host.now.store(T0 + 600, Ordering::SeqCst);
    r.replan();
    assert_eq!(r.applied("admin"), Some((PoolState::Active, Some("vpn".into()))));
    assert_eq!(net.connection_for(host, "admin"), via("vpn"));
    // One of two down: rotation is suspended on the one that is left.
    r.probe("vpn", false);
    r.replan();
    assert_eq!(r.applied("invoices"), Some((PoolState::Suspended, Some("tor".into()))));
    assert_eq!(net.pool_health(host).next_switch_at, None);
}

#[tokio::test]
async fn a_rule_moves_single_relays_and_health_reports_where_each_goes() {
    let r = rig(&[A, B, "ws://abc.onion"]);
    let (net, host) = (&r.net, &r.host);
    r.set(|t| {
        let mut vpn = entry("vpn");
        vpn.pool = false;
        t.proxies.list = vec![entry("tor"), vpn];
        t.proxies.mode = ProxyMode::Failover;
        t.proxies.rules = vec![
            rule(&[B], RouteTo::Proxy("vpn".into()), Fallback::Pool),
            rule(&["*.onion"], RouteTo::Block, Fallback::Offline),
        ];
    });
    r.probe("tor", true);
    r.probe("vpn", true);
    r.replan();
    assert!(r.woken().await);
    let routes = |lane: &str| -> Vec<(String, Option<usize>, Via, Reason)> {
        net.routes_for(host, lane)
            .into_iter()
            .map(|x| (x.relay, x.rule, x.via, x.reason))
            .collect()
    };
    let through = |id: &str| Via::Proxy {
        id: id.into(),
        url: format!("socks5://{id}:1"),
    };
    assert_eq!(
        routes("admin"),
        vec![
            (A.to_string(), None, through("tor"), Reason::Default),
            (B.to_string(), Some(0), through("vpn"), Reason::Rule),
            ("ws://abc.onion".to_string(), Some(1), Via::Off, Reason::Blocked),
        ]
    );
    assert_eq!(
        net.lane_routes(host, "admin"),
        Some(vec![
            (A.to_string(), "socks5://tor:1".into()),
            (B.to_string(), "socks5://vpn:1".into())
        ])
    );
    // The rule's own proxy goes down: only its relay moves (to the default
    // route), and the supervisor is told although no lane's plan changed.
    r.probe("vpn", false);
    r.replan();
    assert!(r.woken().await);
    assert_eq!(
        routes("admin")[1],
        (B.to_string(), Some(0), through("tor"), Reason::Fallback)
    );

    // Health says the same, numbering rules from 1, with the first lane's plan on top.
    let mut failed = ProxyCheck {
        proxy: "socks5://vpn:1".into(),
        status: "failed".into(),
        checked_at: T0,
        relays: Vec::new(),
    };
    failed.relays.push(crate::privacy::RelayCheck {
        relay: B.into(),
        ok: false,
        code: "refused".into(),
        reason: "The proxy refused the connection.".into(),
        ms: None,
    });
    net.record_probe("vpn", failed);
    let h = net.pool_health(host);
    assert_eq!(
        (h.state, h.posture, h.mode),
        (PoolState::Active, Posture::Normal, ProxyMode::Failover)
    );
    assert_eq!((h.active.as_deref(), h.reachable, h.total), (Some("tor"), 1, 2));
    assert_eq!(
        (h.offline, h.transparent, h.next_switch_at),
        (OfflinePolicy::KillSwitch, false, None)
    );
    let vpn = h.proxies.iter().find(|p| p.id == "vpn").unwrap();
    assert_eq!(
        (
            vpn.reachable,
            vpn.status.as_deref(),
            vpn.reason.as_deref(),
            vpn.pool,
            vpn.checked_at
        ),
        (
            Some(false),
            Some("failed"),
            Some("The proxy refused the connection."),
            false,
            Some(T0)
        )
    );
    assert_eq!(vpn.url, "socks5://vpn:1");
    let b = h.routes.iter().find(|x| x.key == "admin" && x.relay == B).unwrap();
    assert_eq!(
        (b.rule, b.via, b.proxy.as_deref(), b.reason),
        (Some(1), RouteVia::Proxy, Some("tor"), Reason::Fallback)
    );
    let onion = h.routes.iter().find(|x| x.relay == "ws://abc.onion").unwrap();
    assert_eq!(
        (onion.rule, onion.via, onion.proxy.as_deref()),
        (Some(2), RouteVia::Off, None)
    );
    // A rule that sends a relay straight shows as direct.
    r.set(|t| t.proxies.rules[0].to = RouteTo::Direct);
    let h = net.pool_health(host);
    let b = h.routes.iter().find(|x| x.key == "invoices" && x.relay == B).unwrap();
    assert_eq!(
        (b.via, b.proxy.as_deref(), b.reason),
        (RouteVia::Direct, None, Reason::Rule)
    );
    assert_eq!(
        net.lane_routes(host, "invoices").unwrap()[1],
        (B.to_string(), String::new())
    );
    // The default route down: the offline posture shows in health too.
    r.probe("tor", false);
    r.replan();
    assert_eq!(net.pool_health(host).posture, Posture::Off);
}

#[tokio::test]
async fn a_proxy_change_that_leaves_nothing_reachable_is_undone_once() {
    let r = rig(&[A]);
    let (net, host) = (&r.net, &r.host);
    r.set(|t| {
        t.proxies.list = vec![entry("tor")];
        t.proxies.mode = ProxyMode::Failover;
    });
    r.probe("tor", true);
    r.replan();
    let _ = r.woken().await;
    let working = r.proxies();

    // The operator replaces the list with one that does not work.
    r.set(|t| t.proxies.list = vec![entry("typo")]);
    net.begin_probation(host, working.clone());
    assert!(net.pool.lock().unwrap().probation.is_some());
    r.probe("typo", false);
    r.replan();
    assert_eq!(r.proxies(), working, "the previous proxies are back");
    assert_eq!(
        host.reverts.lock().unwrap().as_slice(),
        ["none of the new proxies was reachable; back to the previous ones"]
    );
    assert!(net.pool.lock().unwrap().probation.is_none());

    // A change that works ends the probation; so does time running out.
    r.set(|t| t.proxies.list = vec![entry("vpn")]);
    net.begin_probation(host, working.clone());
    r.probe("vpn", true);
    r.replan();
    assert!(net.pool.lock().unwrap().probation.is_none());
    assert_eq!(r.proxies().list[0].id, "vpn");
    let with_vpn = r.proxies();
    r.set(|t| t.proxies.list = vec![entry("slow")]);
    net.begin_probation(host, with_vpn.clone());
    host.now.store(T0 + PROBATION_SECS, Ordering::SeqCst);
    r.probe("slow", false);
    r.replan();
    assert_eq!(r.proxies().list[0].id, "slow", "too late to undo");
    assert!(net.pool.lock().unwrap().probation.is_none());
    assert_eq!(host.reverts.lock().unwrap().len(), 1);

    // A host that cannot put them back leaves the new ones in place, offline.
    r.probe("slow", true);
    r.replan();
    let with_slow = r.proxies();
    r.set(|t| t.proxies.list = vec![entry("typo")]);
    net.begin_probation(host, with_slow);
    host.broken.store(true, Ordering::SeqCst);
    r.probe("typo", false);
    r.replan();
    assert_eq!(r.proxies().list[0].id, "typo");
    assert_eq!(r.applied("invoices"), Some((PoolState::Offline, None)));
    host.broken.store(false, Ordering::SeqCst);

    // Only a different list can be a mistake worth undoing, and only when the old one worked.
    let now = r.proxies();
    net.pool.lock().unwrap().probation = None;
    net.begin_probation(host, now.clone());
    assert!(net.pool.lock().unwrap().probation.is_none(), "the same list");
    net.begin_probation(host, with_vpn.clone());
    assert!(
        net.pool.lock().unwrap().probation.is_none(),
        "it was not working before"
    );
    r.probe("typo", true);
    r.replan();
    net.begin_probation(host, ProxySettings::default());
    assert!(
        net.pool.lock().unwrap().probation.is_none(),
        "there was no proxy before"
    );
    let mut transparent = with_vpn;
    transparent.transparent = true;
    net.begin_probation(host, transparent);
    assert!(
        net.pool.lock().unwrap().probation.is_none(),
        "a transparent proxy was declared before"
    );
}

#[tokio::test]
async fn turning_the_strategy_off_would_strand_a_lane_whose_first_proxy_is_down() {
    let r = rig(&[A]);
    let (net, host) = (&r.net, &r.host);
    r.set(|t| t.proxies.list = vec![entry("tor"), entry("vpn")]);
    let next = host.topology();
    assert_eq!(net.stranded_by_off(&next), None, "nothing probed yet");
    r.probe("tor", false);
    r.probe("vpn", true);
    assert_eq!(net.stranded_by_off(&next).as_deref(), Some("Public invoices"));
    r.probe("tor", true);
    assert_eq!(net.stranded_by_off(&next), None);
    r.probe("tor", false);
    let mut transparent = next.clone();
    transparent.proxies.transparent = true;
    assert_eq!(net.stranded_by_off(&transparent), None);
    // A lane none of whose relays takes the default route is not hurt.
    let mut ruled = next;
    ruled.proxies.rules = vec![rule(&["*"], RouteTo::Direct, Fallback::Offline)];
    assert_eq!(net.stranded_by_off(&ruled), None);
}

/// A relay address that accepts TCP connections (enough for a tunnel through a proxy).
async fn listening_relay() -> (String, tokio::net::TcpListener) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    (format!("ws://127.0.0.1:{}", l.local_addr().unwrap().port()), l)
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn proxy_on(id: &str, port: u16) -> ProxyEntry {
    ProxyEntry {
        url: format!("socks5://127.0.0.1:{port}"),
        ..entry(id)
    }
}

fn params(id: Option<&str>, proxy: Option<&str>) -> CheckProxyParams {
    CheckProxyParams {
        proxy: proxy.map(str::to_string),
        id: id.map(str::to_string),
    }
}

#[tokio::test]
async fn probing_marks_a_proxy_that_tunnels_up_one_that_does_not_down_and_skips_one_that_carries_nothing() {
    let (relay, _l) = listening_relay().await;
    let r = rig(&[&relay]);
    let (net, host) = (&r.net, &r.host);
    // Nothing to probe: the plan is still made.
    net.refresh_pool(host).await;
    assert_eq!(r.applied("invoices"), Some((PoolState::Direct, None)));

    let (good, _p) = deadhop_net::testing::socks5_proxy(None).await;
    let bad = closed_port().await;
    r.set(|t| {
        let mut idle = proxy_on("idle", bad);
        idle.pool = false;
        t.proxies.list = vec![proxy_on("bad", bad), proxy_on("good", good), idle];
        t.proxies.mode = ProxyMode::Failover;
    });
    // A probe left over for the proxy that carries nothing is forgotten.
    r.probe("idle", true);
    net.refresh_pool(host).await;
    {
        let pool = net.pool.lock().unwrap();
        assert!(!pool.probes["bad"].up && pool.probes["good"].up);
        assert!(!pool.probes.contains_key("idle"));
        assert_eq!(pool.probes["good"].check.status, "connected");
    }
    assert_eq!(r.applied("admin"), Some((PoolState::Active, Some("good".into()))));

    // The loop probes at once, again when woken, and stops when told to.
    let r = std::sync::Arc::new(r);
    let stop = tokio_util::sync::CancellationToken::new();
    r.set(|t| t.proxies.list.swap(0, 1));
    let looping = tokio::spawn({
        let (r, stop) = (r.clone(), stop.clone());
        async move { run_probe_loop(&r.net, &r.host, stop).await }
    });
    assert!(r.woken().await || r.applied("admin") == Some((PoolState::Active, Some("good".into()))));
    r.set(|t| t.proxies.list.truncate(1));
    r.net.wake_pool();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r.net.pool.lock().unwrap().probes.len(), 1);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), looping)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_proxy_is_tested_by_id_by_address_or_as_the_one_in_use() {
    let (relay, _l) = listening_relay().await;
    let r = rig(&[&relay]);
    let (net, host) = (&r.net, &r.host);
    let (good, _p) = deadhop_net::testing::socks5_proxy(None).await;
    let good_url = format!("socks5://127.0.0.1:{good}");

    // Not an operator; then no proxy at all: nothing to connect through.
    assert_eq!(
        text(net.check_proxy(host, &Caller::default(), params(None, None)).await),
        "not authorized"
    );
    let none = net.check_proxy(host, &op(), params(None, None)).await.unwrap();
    assert_eq!((none.status.as_str(), none.proxy.as_str()), ("direct", ""));
    assert_eq!(net.last_proxy_check.lock().unwrap().as_ref().unwrap().status, "direct");
    assert_eq!(
        host.audits.lock().unwrap().last().unwrap(),
        &(
            "op".to_string(),
            "check_proxy".to_string(),
            "no proxy: direct".to_string()
        )
    );

    // An address that is not in the list is tried against every relay, and kept nowhere.
    let tried = net
        .check_proxy(host, &op(), params(None, Some(&format!(" {good_url} "))))
        .await
        .unwrap();
    assert_eq!(tried.status, "connected");
    assert!(net.pool.lock().unwrap().probes.is_empty());

    r.set(|t| {
        let mut idle = proxy_on("idle", good + 1);
        idle.url = "socks5://user:secret@127.0.0.1:9".into();
        idle.pool = false;
        t.proxies.list = vec![proxy_on("good", good), idle];
        t.proxies.mode = ProxyMode::Failover;
    });
    // By id: the result is remembered as that proxy's probe.
    let by_id = net.check_proxy(host, &op(), params(Some("good"), None)).await.unwrap();
    assert_eq!(by_id.status, "connected");
    assert!(net.pool.lock().unwrap().probes["good"].up);
    // By the address of a listed proxy: the same.
    net.pool.lock().unwrap().probes.clear();
    net.check_proxy(host, &op(), params(None, Some(&good_url)))
        .await
        .unwrap();
    assert!(net.pool.lock().unwrap().probes.contains_key("good"));
    // The one in use, once there is a plan: kept as the live proxy's last check.
    r.replan();
    assert_eq!(net.main_proxy(host).as_deref(), Some(good_url.as_str()));
    *net.last_proxy_check.lock().unwrap() = None;
    let live = net.check_proxy(host, &op(), params(None, None)).await.unwrap();
    assert_eq!(live.proxy, good_url);
    assert_eq!(net.last_proxy_check.lock().unwrap().as_ref().unwrap().proxy, good_url);
    assert!(host.audits.lock().unwrap().last().unwrap().2.starts_with(&good_url));

    // Refusals.
    assert_eq!(
        text(net.check_proxy(host, &op(), params(Some("nope"), None)).await),
        "invalid parameters: there is no proxy with that id"
    );
    assert_eq!(
        text(
            net.check_proxy(host, &op(), params(Some("good"), Some("socks5://h:1")))
                .await
        ),
        "invalid parameters: give either id or proxy, not both"
    );
    assert_eq!(
        text(net.check_proxy(host, &op(), params(None, Some("ftp://h:1"))).await),
        "invalid parameters: proxy: scheme must be socks5://, https:// or http://"
    );
    assert_eq!(
        text(net.check_proxy(host, &op(), params(Some("idle"), None)).await),
        "invalid parameters: no relay goes through this proxy yet: add a rule that uses it, or put it in the default \
         route"
    );
    assert!(!net.proxy_check_busy.load(Ordering::SeqCst));
    // Locked on the host: only what is listed may be tested.
    host.locked.store(true, Ordering::SeqCst);
    assert_eq!(
        text(net.check_proxy(host, &op(), params(None, Some("socks5://h:1"))).await),
        "invalid parameters: the proxies are locked on the host (DEADHOP_PROXY_LOCKED); only the listed ones can be \
         tested"
    );
    net.proxy_checks.lock().unwrap().clear();
    net.check_proxy(host, &op(), params(Some("good"), None)).await.unwrap();
    host.locked.store(false, Ordering::SeqCst);
    // One at a time, a few a minute.
    net.proxy_check_busy.store(true, Ordering::SeqCst);
    assert_eq!(
        text(net.check_proxy(host, &op(), params(Some("good"), None)).await),
        "rate limit exceeded"
    );
    net.proxy_check_busy.store(false, Ordering::SeqCst);
    *net.proxy_checks.lock().unwrap() = vec![T0; PROXY_CHECKS_PER_MIN];
    assert_eq!(
        text(net.check_proxy(host, &op(), params(Some("good"), None)).await),
        "rate limit exceeded"
    );
    host.now.store(T0 + 60, Ordering::SeqCst);
    net.check_proxy(host, &op(), params(Some("good"), None)).await.unwrap();
    // A host that cannot record the check fails it.
    host.broken.store(true, Ordering::SeqCst);
    assert_eq!(
        text(net.check_proxy(host, &op(), params(Some("good"), None)).await),
        "cannot write"
    );
}

fn name(n: &str) -> ResolveI2pNameParams {
    ResolveI2pNameParams { name: n.into() }
}

#[tokio::test]
async fn an_i2p_name_is_asked_of_every_registry_through_the_router() {
    use crate::testing::{fake_destination, fake_router, page_with};
    let pages = [("one.i2p".to_string(), page_with(&fake_destination(1)))].into();
    let (port, _seen, router) = fake_router(pages).await;
    let r = rig(&[A]);
    let (net, host) = (&r.net, &r.host);
    let ask = |n: &'static str| async move { net.resolve_i2p_name(host, &op(), name(n)).await };

    assert_eq!(
        text(net.resolve_i2p_name(host, &Caller::default(), name("x.i2p")).await),
        "not authorized"
    );
    assert_eq!(
        text(ask("x.i2p").await),
        "invalid parameters: there is no I2P router proxy: add the router's http:// proxy as an I2P proxy first"
    );
    assert!(text(ask("Bad Name").await).contains("lowercase .i2p name"));
    host.locked.store(true, Ordering::SeqCst);
    assert_eq!(
        text(ask("x.i2p").await),
        "invalid parameters: the proxies are locked on the host (DEADHOP_PROXY_LOCKED), so I2P names cannot be \
         looked up"
    );
    host.locked.store(false, Ordering::SeqCst);
    let router_entry = |url: &str| ProxyEntry {
        url: url.into(),
        pool: false,
        i2p: true,
        ..entry("router")
    };
    r.set(|t| {
        t.proxies.list = vec![router_entry("")];
        t.proxies.i2p_registries = Vec::new();
    });
    assert_eq!(
        text(ask("x.i2p").await),
        "invalid parameters: there are no I2P name registries, so lookups are off"
    );
    r.set(|t| {
        t.proxies.i2p_registries = vec![
            "http://one.i2p/jump?q={name}".into(),
            "http://down.i2p/?q={name}".into(),
        ]
    });
    assert_eq!(
        text(ask("x.i2p").await),
        "invalid parameters: the I2P router proxy has no address"
    );
    r.set(|t| t.proxies.list = vec![router_entry("ftp://h:1")]);
    assert!(text(ask("x.i2p").await).contains("scheme must be"));

    r.set(|t| t.proxies.list = vec![router_entry(&format!("http://127.0.0.1:{port}"))]);
    let found = ask(" x.i2p ").await.unwrap();
    assert_eq!(found.address, crate::i2p::b32_address(&fake_destination(1)).unwrap());
    assert_eq!((found.agreeing.len(), found.unreachable.len()), (1, 1));
    let entry = host.audits.lock().unwrap().last().unwrap().clone();
    assert_eq!((entry.0.as_str(), entry.1.as_str()), ("op", "resolve_i2p_name"));
    assert_eq!(entry.2, format!("x.i2p: {} (1 agree, 0 disagree)", found.address));
    // A name nobody knows is recorded as a failure, and is the caller's answer.
    r.set(|t| t.proxies.i2p_registries = vec!["http://down.i2p/?q={name}".into()]);
    assert!(text(ask("x.i2p").await).contains("no I2P registry could be reached"));
    assert!(host
        .audits
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .2
        .starts_with("x.i2p: failed: "));

    // One at a time, a few a minute; the busy flag is cleared however a lookup ends.
    assert!(!net.i2p_lookup_busy.load(Ordering::SeqCst));
    net.i2p_lookup_busy.store(true, Ordering::SeqCst);
    assert_eq!(text(ask("x.i2p").await), "rate limit exceeded");
    net.i2p_lookup_busy.store(false, Ordering::SeqCst);
    *net.i2p_lookups.lock().unwrap() = vec![T0; I2P_LOOKUPS_PER_MIN];
    assert_eq!(text(ask("x.i2p").await), "rate limit exceeded");
    host.now.store(T0 + 61, Ordering::SeqCst);
    host.broken.store(true, Ordering::SeqCst);
    assert_eq!(text(ask("x.i2p").await), "cannot write");
    assert!(!net.i2p_lookup_busy.load(Ordering::SeqCst));
    router.abort();
}

#[tokio::test]
async fn relays_are_checked_the_way_they_are_routed_and_their_results_kept() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let up = relay.url().await.to_string();
    let down = format!("ws://127.0.0.1:{}", closed_port().await);
    let r = rig(&[&up, &down, "ws://abc.onion"]);
    let (net, host) = (&r.net, &r.host);
    // The onion relay has no route (never straight), so it is not checked.
    let checked = net.refresh_relay_health(host).await.unwrap();
    assert_eq!(checked.len(), 2);
    assert_eq!(
        (checked[0].relay.as_str(), checked[0].status.as_str()),
        (up.as_str(), "ok")
    );
    assert_eq!(checked[1].status, "down");
    assert_eq!(*net.relay_health.lock().unwrap(), checked);
    let kept: Vec<(String, String, bool)> = host
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| (e.relay.clone(), e.kind.clone(), e.ok))
        .collect();
    assert_eq!(
        kept,
        vec![
            (up.trim_end_matches('/').to_string(), "check".to_string(), true),
            (down.clone(), "check".to_string(), false)
        ]
    );
    // A check already running: no second one.
    net.relay_health_busy.store(true, Ordering::SeqCst);
    assert_eq!(net.refresh_relay_health(host).await, None);
    assert_eq!(text(net.check_relays(host, &op()).await), "rate limit exceeded");
    net.relay_health_busy.store(false, Ordering::SeqCst);

    // On demand: operators only, a few times a minute.
    assert_eq!(text(net.check_relays(host, &Caller::default()).await), "not authorized");
    net.relay_checks.lock().unwrap().clear();
    assert_eq!(net.check_relays(host, &op()).await.unwrap().relays.len(), 2);
    *net.relay_checks.lock().unwrap() = vec![T0; RELAY_CHECKS_PER_MIN];
    assert_eq!(text(net.check_relays(host, &op()).await), "rate limit exceeded");

    // A relay that goes through a proxy is checked through it; with the kill
    // switch on and no proxy reachable nothing has a route, so nothing is checked.
    let (proxy, _p) = deadhop_net::testing::socks5_proxy(None).await;
    r.set(|t| {
        t.relays.truncate(1);
        t.proxies.list = vec![proxy_on("good", proxy)];
    });
    r.probe("good", true);
    r.replan();
    let through = net.refresh_relay_health(host).await.unwrap();
    assert_eq!(through[0].status, "ok");
    r.probe("good", false);
    r.replan();
    assert_eq!(net.refresh_relay_health(host).await, Some(Vec::new()));
    assert!(net.relay_health.lock().unwrap().is_empty());
    assert!(!net.relay_health_busy.load(Ordering::SeqCst));

    // A result the host cannot keep is not the caller's problem.
    host.broken.store(true, Ordering::SeqCst);
    let before = host.events.lock().unwrap().len();
    net.record_relay_event(host, &up, "send", true, Some(5));
    assert_eq!(host.events.lock().unwrap().len(), before);
}

#[tokio::test]
async fn relay_history_buckets_checks_and_sends_per_relay() {
    let r = rig(&[A, "wss://b.example/"]);
    let (net, host) = (&r.net, &r.host);
    let window = |w: Option<&str>| RelayHistoryParams {
        window: w.map(str::to_string),
    };
    assert_eq!(
        text(net.relay_history(host, &Caller::default(), window(None))),
        "not authorized"
    );
    assert_eq!(
        text(net.relay_history(host, &op(), window(Some("2h")))),
        "invalid parameters: window must be 15m, 1h, 12h, 1d or 1w"
    );
    // Results at different times, one for a relay that is no longer listed.
    for (ago, relay, kind, ok, ms) in [
        (10, A, "check", true, Some(100)),
        (20, A, "check", false, None),
        (400, A, "send", true, Some(300)),
        (500, A, "send", false, Some(9_999)),
        (30, "wss://gone.example", "send", true, None),
        (30, "wss://b.example/", "check", true, Some(50)),
    ] {
        host.now.store(T0 - ago, Ordering::SeqCst);
        net.record_relay_event(host, relay, kind, ok, ms);
    }
    host.now.store(T0, Ordering::SeqCst);
    let h = net.relay_history(host, &op(), window(None)).unwrap();
    assert_eq!((h.window.as_str(), h.bucket_secs), ("1h", 300));
    assert_eq!(h.until - h.since, 3_600);
    assert!(h.since <= T0 - 3_300 && T0 < h.until);
    let names: Vec<&str> = h.relays.iter().map(|x| x.relay.as_str()).collect();
    assert_eq!(names, [A, "wss://b.example", "wss://gone.example"]);
    let a = &h.relays[0];
    assert_eq!((a.checks, a.check_failures, a.sends, a.send_failures), (2, 1, 2, 1));
    assert_eq!(a.avg_ms, Some(200), "only results that succeeded count");
    assert_eq!(a.points.len(), 12);
    assert_eq!(a.points.iter().map(|p| p.ok + p.fail).sum::<u32>(), 4);
    assert_eq!((h.relays[1].checks, h.relays[1].avg_ms), (1, Some(50)));
    assert_eq!((h.relays[2].sends, h.relays[2].avg_ms), (1, None));
    // A shorter window sees fewer of them.
    let short = net.relay_history(host, &op(), window(Some("15m"))).unwrap();
    assert_eq!((short.bucket_secs, short.relays[0].points.len()), (60, 15));
    assert_eq!((short.relays[0].checks, short.relays[0].sends), (2, 2));
    for w in ["12h", "1d", "1w"] {
        assert_eq!(net.relay_history(host, &op(), window(Some(w))).unwrap().window, w);
    }
    host.broken.store(true, Ordering::SeqCst);
    assert_eq!(text(net.relay_history(host, &op(), window(None))), "cannot read");
}

#[tokio::test]
async fn the_privacy_audit_is_given_what_the_runtime_and_the_host_know() {
    let r = rig(&[A, "wss://relay.lan", "wss://named.example", "ws://node.fips", B]);
    let (net, host) = (&r.net, &r.host);
    assert_eq!(
        text(net.privacy_audit(host, &Caller::default()).await),
        "not authorized"
    );
    *host.states.lock().unwrap() = vec![RelayState {
        url: A.into(),
        status: "connected".into(),
        connected: true,
        keys: vec!["invoices".into()],
    }];
    // Names resolve as this test says: one stays on the local network.
    *net.resolver.lock().unwrap() = std::sync::Arc::new(|host: String, _| {
        Box::pin(async move {
            if host == "named.example" {
                vec!["10.0.0.5".parse().unwrap()]
            } else {
                vec!["93.184.216.34".parse().unwrap()]
            }
        })
    });
    r.set(|t| {
        t.proxies.rules = vec![rule(&["*"], RouteTo::Direct, Fallback::Offline)];
    });
    let direct = net.privacy_audit(host, &op()).await.unwrap();
    let check = |a: &crate::privacy::PrivacyAudit, id: &str| a.checks.iter().find(|c| c.id == id).cloned();
    let listed = serde_json::to_string(&direct).unwrap();
    assert!(listed.contains(A) && listed.contains(B), "{listed}");
    for private in ["relay.lan", "named.example", "node.fips"] {
        assert!(!listed.contains(private), "{private} stays off the internet");
    }
    assert!(check(&direct, "relays_via_proxy").is_some());

    // With a proxy in use, its last check (and only its own) is part of the audit.
    r.set(|t| {
        t.proxies.rules.clear();
        t.proxies.list = vec![entry("tor")];
    });
    r.probe("tor", true);
    r.replan();
    *net.last_proxy_check.lock().unwrap() = Some(ProxyCheck {
        proxy: "socks5://other:1".into(),
        status: "connected".into(),
        checked_at: T0,
        relays: Vec::new(),
    });
    let stale = serde_json::to_string(&net.privacy_audit(host, &op()).await.unwrap()).unwrap();
    net.last_proxy_check.lock().unwrap().as_mut().unwrap().proxy = "socks5://tor:1".into();
    let fresh = serde_json::to_string(&net.privacy_audit(host, &op()).await.unwrap()).unwrap();
    assert_ne!(stale, fresh, "a check of another proxy says nothing about this one");
    assert!(fresh.contains("socks5://tor:1"));
}
