//! Which proxy carries the relay connections.
//!
//! [`plan`] is a pure function: given the settings, which proxies answered
//! their last probe and the clock, it says which proxy to use now. Everything
//! that touches the network or the service lives elsewhere (`manage.rs` holds
//! the probe loop's state, `app.rs` acts on the plan).
//!
//! - **Off** uses the first proxy in the list and never another: while it is
//!   down the offline policy applies.
//! - **Failover** uses the first reachable proxy in list order. When a proxy
//!   earlier in the list comes back, the service returns to it only after it
//!   has stayed up for [`FAILBACK_HOLD_SECS`], so a flapping proxy does not
//!   reconnect every relay over and over.
//! - **Round robin** takes the reachable proxies in turn, one change per
//!   interval (never per connection).
//! - **Chaos** changes to a random other reachable proxy after a random time
//!   between a minimum and a maximum.
//! - Rotation needs at least two reachable proxies. With one, it is
//!   *suspended*: that proxy keeps carrying traffic (never worse than going
//!   direct) until a second one is back. With none, the offline policy applies.

use std::collections::HashMap;

use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use crate::netruntime::{NetworkHost, NetworkRuntime};
use crate::network::Topology;
use crate::network::{OfflinePolicy, ProxyMode, ProxySettings};
use crate::privacy::ProxyCheck;
use deadhop_net::relay::{parse_proxy, redact};

/// A proxy that came back must stay up this long before failover returns to it.
pub const FAILBACK_HOLD_SECS: u64 = 120;

// Where the pool stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    // The operator runs a transparent proxy; nothing here is checked or used.
    Transparent,
    // No proxy is configured: relays connect straight.
    Direct,
    // A proxy is chosen by the mode.
    Active,
    // Rotation needs two reachable proxies and only one is: it stays in use.
    Suspended,
    // Proxies are configured and none it may use is reachable (with the
    // strategy off: the first is down): the offline policy applies.
    Offline,
}

// What the service does with its relay connections and its callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    // Relays connect through the active proxy (or straight, if none is set
    // or a transparent proxy does the work); everything is served.
    Normal,
    // No relay connection at all.
    Off,
    // Straight connection, operators only.
    AdminOnly,
    // Straight connection, invoicing only.
    InvoicingOnly,
    // Straight connection, everything served.
    Open,
}

impl Posture {
    // The posture while no proxy is reachable.
    pub fn offline(policy: OfflinePolicy) -> Posture {
        match policy {
            OfflinePolicy::KillSwitch => Posture::Off,
            OfflinePolicy::AdminOnly => Posture::AdminOnly,
            OfflinePolicy::InvoicingOnly => Posture::InvoicingOnly,
            OfflinePolicy::Open => Posture::Open,
        }
    }
}

/// How one proxy did at its last probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    pub up: bool,
    /// Since when it has been up without a failure (unix seconds).
    pub up_since: u64,
}

/// What the rotation modes remember between plans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rotation {
    /// Id of the proxy in use.
    pub current: Option<String>,
    /// When rotation changes it next (0: not started).
    pub due_at: u64,
}

/// The decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Id of the proxy to use, if any.
    pub active: Option<String>,
    pub state: PoolState,
    /// When rotation will change the proxy, if it is rotating.
    pub next_switch_at: Option<u64>,
    pub reachable: usize,
}

/// A random whole number in `min..=max`.
pub fn random_between(min: u64, max: u64) -> u64 {
    if max <= min {
        return min;
    }
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("the system has a random source");
    min + u64::from_le_bytes(b) % (max - min + 1)
}

/// Decide which proxy to use. `reach` is in list order.
pub fn plan(
    cfg: &ProxySettings,
    reach: &[Reach],
    rot: &mut Rotation,
    now: u64,
    rng: &mut dyn FnMut(u64, u64) -> u64,
) -> Plan {
    let state_only = |state, reachable| Plan {
        active: None,
        state,
        next_switch_at: None,
        reachable,
    };
    if cfg.transparent {
        *rot = Rotation::default();
        return state_only(PoolState::Transparent, 0);
    }
    if cfg.list.is_empty() {
        *rot = Rotation::default();
        return state_only(PoolState::Direct, 0);
    }
    let ups: Vec<usize> = (0..cfg.list.len())
        .filter(|&i| reach.get(i).is_some_and(|r| r.up))
        .collect();
    if ups.is_empty() {
        *rot = Rotation::default();
        return state_only(PoolState::Offline, 0);
    }
    let id = |i: usize| cfg.list[i].id.clone();
    // Off: the first proxy only. While it is down the key is offline, even
    // with others up: it never moves to another exit.
    if cfg.mode == ProxyMode::Off {
        if ups[0] != 0 {
            *rot = Rotation::default();
            return state_only(PoolState::Offline, ups.len());
        }
        *rot = Rotation {
            current: Some(id(0)),
            due_at: 0,
        };
        return Plan {
            active: Some(id(0)),
            state: PoolState::Active,
            next_switch_at: None,
            reachable: ups.len(),
        };
    }
    let current = rot
        .current
        .as_ref()
        .and_then(|c| ups.iter().copied().find(|&i| &cfg.list[i].id == c));

    // One proxy configured: there is nothing to choose between, so the strategy
    // does not apply and that proxy is simply used while it is up.
    if cfg.mode == ProxyMode::Failover || cfg.list.len() == 1 {
        let best = ups[0];
        let pick = match current {
            Some(c) if c <= best => c,
            Some(c) if now.saturating_sub(reach[best].up_since) < FAILBACK_HOLD_SECS => c,
            _ => best,
        };
        *rot = Rotation {
            current: Some(id(pick)),
            due_at: 0,
        };
        return Plan {
            active: Some(id(pick)),
            state: PoolState::Active,
            next_switch_at: None,
            reachable: ups.len(),
        };
    }

    let interval = |rng: &mut dyn FnMut(u64, u64) -> u64| match cfg.mode {
        ProxyMode::Chaos => rng(cfg.chaos_min_secs, cfg.chaos_max_secs),
        _ => cfg.rotate_secs,
    };
    if ups.len() == 1 {
        *rot = Rotation {
            current: Some(id(ups[0])),
            due_at: 0,
        };
        return Plan {
            active: Some(id(ups[0])),
            state: PoolState::Suspended,
            next_switch_at: None,
            reachable: 1,
        };
    }
    let pick = match current {
        // Still good and not due: stay. (A timer that was never started, after a
        // suspension, starts now.)
        Some(c) if rot.due_at == 0 => {
            rot.due_at = now + interval(rng);
            c
        }
        Some(c) if now < rot.due_at => c,
        Some(c) => {
            rot.due_at = now + interval(rng);
            match cfg.mode {
                ProxyMode::Chaos => {
                    let others: Vec<usize> = ups.iter().copied().filter(|&i| i != c).collect();
                    others[rng(0, others.len() as u64 - 1) as usize]
                }
                // The next reachable proxy after this one, wrapping around.
                _ => ups.iter().copied().find(|&i| i > c).unwrap_or(ups[0]),
            }
        }
        None => {
            rot.due_at = now + interval(rng);
            match cfg.mode {
                ProxyMode::Chaos => ups[rng(0, ups.len() as u64 - 1) as usize],
                _ => ups[0],
            }
        }
    };
    rot.current = Some(id(pick));
    Plan {
        active: Some(id(pick)),
        state: PoolState::Active,
        next_switch_at: Some(rot.due_at),
        reachable: ups.len(),
    }
}

/// The state the probe loop keeps for one proxy.
#[derive(Debug, Clone)]
pub struct Probe {
    pub up: bool,
    pub up_since: u64,
    pub check: ProxyCheck,
}

/// What the plan last decided (kept with the url, so a settings change does
/// not move the connections before the new list has been probed).
#[derive(Debug, Clone)]
pub struct Applied {
    pub active: Option<String>,
    pub active_url: Option<String>,
    pub state: PoolState,
    pub next_switch_at: Option<u64>,
    pub reachable: usize,
}

/// Runtime state of the pool (never saved).
#[derive(Debug, Default)]
pub struct PoolRuntime {
    /// Rotation state per key: each key rotates on its own, so two keys do
    /// not change proxy in the same second.
    pub rot: HashMap<String, Rotation>,
    pub probes: HashMap<String, Probe>,
    /// What the plan decided, per key.
    pub applied: HashMap<String, Applied>,
    /// Proxy settings an operator just replaced, to go back to if none of the
    /// new ones works (the proxy list is the way back in, so a typo must not
    /// lock anyone out).
    pub probation: Option<Probation>,
    /// Where each key's relays went at the last plan: (key, relay, proxy url
    /// or "" for straight). The supervisor is woken when this changes.
    pub route_shape: Vec<(String, String, Option<String>)>,
}

#[derive(Debug, Clone)]
pub struct Probation {
    pub previous: ProxySettings,
    pub until: u64,
}

/// How long a changed proxy list may stay unreachable before it is undone.
pub const PROBATION_SECS: u64 = 180;

/// What the relay connections should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    /// No relay connection at all.
    Off,
    /// Straight to the relays (no proxy, a transparent one, or clearnet while offline).
    Direct,
    /// Through this proxy url.
    Via(String),
}

// How one proxy looks on the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ProxyHealth {
    pub id: String,
    pub name: String,
    // Password hidden.
    pub url: String,
    // `None` until it has been probed.
    pub reachable: Option<bool>,
    pub checked_at: Option<u64>,
    // `connected`, `partial` or `failed` at the last probe.
    pub status: Option<String>,
    // The first reason a relay could not be reached, if any.
    pub reason: Option<String>,
    // The keys (by id) whose default route may use this proxy; empty is every key.
    pub keys: Vec<String>,
    // In the default route (the pool).
    pub pool: bool,
}

// How a relay connection goes: through a proxy, straight, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteVia {
    Proxy,
    Direct,
    Off,
}

// Where one relay of one key goes now, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RouteHealth {
    pub key: String,
    pub relay: String,
    // Number (from 1) of the rule that matched; none: the default route.
    pub rule: Option<usize>,
    pub via: RouteVia,
    // Id of the proxy, when it goes through one.
    pub proxy: Option<String>,
    pub reason: crate::routes::Reason,
}

// How one key's relay connections stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LaneHealth {
    // The key's id.
    pub key: String,
    pub state: PoolState,
    // Id of the proxy this key uses.
    pub active: Option<String>,
    pub reachable: usize,
    // When rotation changes this key's proxy next.
    pub next_switch_at: Option<u64>,
    // Whether any relay of this key may take the default route; when none
    // can, this lane's state does not affect the key.
    pub uses_default: bool,
}

// The pool as shown in `get_health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PoolHealth {
    pub state: PoolState,
    // What the service does now: `normal`, `off`, `admin_only`, `invoicing_only` or `open`.
    pub posture: Posture,
    pub mode: ProxyMode,
    pub offline: OfflinePolicy,
    pub transparent: bool,
    // Id of the proxy in use.
    pub active: Option<String>,
    pub reachable: usize,
    pub total: usize,
    // When rotation changes the proxy next.
    pub next_switch_at: Option<u64>,
    pub proxies: Vec<ProxyHealth>,
    // Each key's own plan. The fields above are the public invoices key's.
    pub lanes: Vec<LaneHealth>,
    // Where every relay of every key goes now.
    pub routes: Vec<RouteHealth>,
}

impl NetworkRuntime {
    /// The posture the plan implies right now: the offline policy applies as
    /// soon as any key has no reachable proxy.
    pub fn posture(&self, host: &dyn NetworkHost) -> Posture {
        let settings = host.topology();
        let offline = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .applied
            .iter()
            .any(|(k, a)| a.state == PoolState::Offline && crate::routes::uses_default(&settings, k));
        if offline {
            Posture::offline(settings.proxies.offline)
        } else {
            Posture::Normal
        }
    }

    /// What one key's relay connections should be now. While its proxies are
    /// all down, the offline policy decides: the kill switch cuts the key off,
    /// and the others connect straight for the one kind of key they keep.
    pub fn connection_for(&self, host: &dyn NetworkHost, key: &str) -> Connection {
        let settings = host.topology();
        if settings.proxies.transparent {
            return Connection::Direct;
        }
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match pool.applied.get(key) {
            // Nothing to choose from: straight. With a list, wait for the first plan.
            None if settings.proxies.list.is_empty() => Connection::Direct,
            None => Connection::Off,
            Some(a) => match (a.state, &a.active_url) {
                (PoolState::Direct | PoolState::Transparent, _) => Connection::Direct,
                (PoolState::Offline, _) => {
                    // What the policy means for this lane is the host's to say.
                    if host.connects_while_offline(key, settings.proxies.offline) {
                        Connection::Direct
                    } else {
                        Connection::Off
                    }
                }
                (_, url) => url.clone().map_or(Connection::Off, Connection::Via),
            },
        }
    }

    /// The proxy url one key's relay traffic goes through, if any.
    pub fn active_proxy_for(&self, host: &dyn NetworkHost, key: &str) -> Option<String> {
        match self.connection_for(host, key) {
            Connection::Via(u) => Some(u),
            _ => None,
        }
    }

    /// Wait until the plan may have changed what the connections should be.
    pub async fn pool_changed(&self) {
        self.pool_switch.notified().await;
    }

    /// Ask the probe loop to look again now.
    pub fn wake_pool(&self) {
        self.pool_wake.notify_one();
    }

    /// Probe every proxy (all at once, against the live relays) and plan again.
    pub async fn refresh_pool(&self, host: &dyn NetworkHost) {
        let cfg = host.topology().proxies.clone();
        if !cfg.transparent && !cfg.list.is_empty() {
            let settings = host.topology();
            let now = host.now();
            // A proxy is only ever tried against the relays it would carry
            // (by the rules, or as part of the default route for its keys), so
            // it never sees a relay or key it was not given. One that would
            // carry nothing is not tried at all.
            let targets: Vec<(String, Vec<String>, Option<deadhop_net::relay::ProxySpec>, String)> = cfg
                .list
                .iter()
                .map(|e| {
                    (
                        e.id.clone(),
                        crate::routes::relays_through_proxy(&settings, &e.id),
                        parse_proxy(&e.url).ok().flatten(),
                        redact(&e.url),
                    )
                })
                .collect();
            let probes = targets
                .iter()
                .filter(|t| !t.1.is_empty())
                .map(|(_, relays, spec, shown)| async move {
                    crate::privacy::check(spec.as_ref(), shown, relays, now).await
                });
            let results = futures_util::future::join_all(probes).await;
            let mut results = results.into_iter();
            for (id, relays, _, _) in &targets {
                if relays.is_empty() {
                    self.forget_probe(id);
                } else if let Some(check) = results.next() {
                    self.record_probe(id, check);
                }
            }
        }
        self.replan(host);
    }

    /// Forget a proxy's last probe (it carries nothing, so it is not tried).
    pub(crate) fn forget_probe(&self, id: &str) {
        self.pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .probes
            .remove(id);
    }

    /// Remember a probe of one proxy.
    pub(crate) fn record_probe(&self, id: &str, check: ProxyCheck) {
        let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let up = check.status != "failed";
        let since = match pool.probes.get(id) {
            Some(p) if p.up && up => p.up_since,
            _ => check.checked_at,
        };
        pool.probes.insert(
            id.to_string(),
            Probe {
                up,
                up_since: since,
                check,
            },
        );
    }

    /// Choose a proxy from the probes so far. Wakes the supervisor when the
    /// connections should change, and undoes a proxy change that left nothing
    /// reachable.
    pub fn replan(&self, host: &dyn NetworkHost) {
        let settings = host.topology();
        let cfg = settings.proxies.clone();
        let now = host.now();
        let (decided, revert_to) = {
            let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            pool.probes.retain(|id, _| cfg.list.iter().any(|e| &e.id == id));
            let mut decided: Vec<(String, Applied)> = Vec::new();
            for key in settings.lanes.iter() {
                // This key's own default route: the proxies in the pool that
                // it may use, in list order.
                let mut lane = cfg.clone();
                lane.list
                    .retain(|e| e.pool && crate::network::assigned(&e.keys, &key.id));
                if lane.list.is_empty() && !cfg.list.is_empty() && !cfg.transparent {
                    // Proxies are configured but none is in this key's
                    // default route: that is not "no proxy, go straight".
                    decided.push((
                        key.id.to_string(),
                        Applied {
                            active: None,
                            active_url: None,
                            state: PoolState::Offline,
                            next_switch_at: None,
                            reachable: 0,
                        },
                    ));
                    continue;
                }
                let reach: Vec<Reach> = lane
                    .list
                    .iter()
                    .map(|e| {
                        pool.probes.get(&e.id).map_or(
                            Reach {
                                up: false,
                                up_since: now,
                            },
                            |p| Reach {
                                up: p.up,
                                up_since: p.up_since,
                            },
                        )
                    })
                    .collect();
                let mut rot = pool.rot.remove(&key.id).unwrap_or_default();
                let d = plan(&lane, &reach, &mut rot, now, &mut random_between);
                pool.rot.insert(key.id.to_string(), rot);
                let active_url = d
                    .active
                    .as_ref()
                    .and_then(|id| lane.list.iter().find(|e| &e.id == id))
                    .map(|e| e.url.clone());
                decided.push((
                    key.id.to_string(),
                    Applied {
                        active: d.active,
                        active_url,
                        state: d.state,
                        next_switch_at: d.next_switch_at,
                        reachable: d.reachable,
                    },
                ));
            }
            // Only a key whose relays may use the default route is hurt by it being down.
            let offline = decided
                .iter()
                .any(|(k, a)| a.state == PoolState::Offline && crate::routes::uses_default(&settings, k));
            // A change that left a key with nothing reachable is undone once;
            // one that works (or a probation that ran out) ends the probation.
            let revert_to = match pool.probation.clone() {
                Some(p) if offline && now < p.until && p.previous != cfg => Some(p.previous),
                Some(p) if !offline || now >= p.until => {
                    pool.probation = None;
                    None
                }
                _ => None,
            };
            (decided, revert_to)
        };
        let reverted = revert_to.is_some_and(|previous| {
            host.revert_proxies(
                previous,
                "none of the new proxies was reachable; back to the previous ones",
            )
            .is_ok()
        });
        if reverted {
            self.pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .probation = None;
            self.wake_pool();
            return;
        }
        let changed = {
            let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let shape = |m: &HashMap<String, Applied>| {
                let mut v: Vec<_> = m
                    .iter()
                    .map(|(k, a)| (k.clone(), a.active_url.clone(), a.state))
                    .collect();
                v.sort_by(|a, b| a.0.cmp(&b.0));
                v
            };
            let before = shape(&pool.applied);
            pool.applied = decided.into_iter().collect();
            before != shape(&pool.applied)
        };
        // A rule's own proxy going up or down moves relays even when no
        // key's default route changed.
        let routes = self.route_shape(host);
        let moved = {
            let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let moved = pool.route_shape != routes;
            pool.route_shape = routes;
            moved
        };
        if changed || moved {
            self.pool_switch.notify_one();
        }
    }

    /// Where every key's relays go now: (key, relay, proxy url, or "" for
    /// straight); relays with no connection are left out.
    fn route_shape(&self, host: &dyn NetworkHost) -> Vec<(String, String, Option<String>)> {
        let lanes = host.topology().lanes;
        lanes
            .iter()
            .flat_map(|k| {
                self.routes_for(host, &k.id).into_iter().map(move |r| {
                    let url = match r.via {
                        crate::routes::Via::Proxy { url, .. } => Some(url),
                        crate::routes::Via::Direct => Some(String::new()),
                        crate::routes::Via::Off => None,
                    };
                    (k.id.to_string(), r.relay, url)
                })
            })
            .collect()
    }

    /// The label of a key that turning the strategy off would cut off now:
    /// one whose relays take the default route, whose first proxy there was
    /// down at its last probe while another of its proxies was up.
    pub fn stranded_by_off(&self, next: &Topology) -> Option<String> {
        if next.proxies.transparent {
            return None;
        }
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let up = |e: &&crate::network::ProxyEntry| pool.probes.get(&e.id).map(|p| p.up);
        next.lanes
            .iter()
            .find(|k| {
                let lane: Vec<_> = next
                    .proxies
                    .list
                    .iter()
                    .filter(|e| e.pool && crate::network::assigned(&e.keys, &k.id))
                    .collect();
                crate::routes::uses_default(next, &k.id)
                    && lane.first().map(up) == Some(Some(false))
                    && lane.iter().skip(1).any(|e| up(e) == Some(true))
            })
            .map(|k| k.label.clone())
    }

    /// One key's default route now, as the routing rules see it.
    pub fn default_route_for(&self, host: &dyn NetworkHost, key: &str) -> crate::routes::DefaultRoute {
        use crate::routes::DefaultRoute;
        match self.connection_for(host, key) {
            Connection::Off => DefaultRoute::Off,
            Connection::Direct => DefaultRoute::Direct,
            Connection::Via(url) => {
                let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let id = pool.applied.get(key).and_then(|a| a.active.clone()).unwrap_or_default();
                DefaultRoute::Proxy { id, url }
            }
        }
    }

    /// Where each of one key's relays goes now, and why.
    pub fn routes_for(&self, host: &dyn NetworkHost, key: &str) -> Vec<crate::routes::Resolved> {
        let settings = host.topology();
        let default = self.default_route_for(host, key);
        let up: std::collections::HashSet<String> = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .probes
            .iter()
            .filter(|(_, p)| p.up)
            .map(|(id, _)| id.clone())
            .collect();
        crate::routes::resolve(&settings, key, &default, &|id| up.contains(id))
    }

    /// The pool as the dashboard shows it.
    pub fn pool_health(&self, host: &dyn NetworkHost) -> PoolHealth {
        let settings = host.topology();
        let cfg = settings.proxies.clone();
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let waiting = if cfg.list.is_empty() {
            PoolState::Direct
        } else {
            PoolState::Offline
        };
        let lanes: Vec<LaneHealth> = settings
            .lanes
            .iter()
            .map(|k| match pool.applied.get(&k.id) {
                Some(a) if !cfg.transparent => LaneHealth {
                    key: k.id.to_string(),
                    state: a.state,
                    active: a.active.clone(),
                    reachable: a.reachable,
                    next_switch_at: a.next_switch_at,
                    uses_default: crate::routes::uses_default(&settings, &k.id),
                },
                _ => LaneHealth {
                    key: k.id.to_string(),
                    state: if cfg.transparent {
                        PoolState::Transparent
                    } else {
                        waiting
                    },
                    active: None,
                    reachable: 0,
                    next_switch_at: None,
                    uses_default: crate::routes::uses_default(&settings, &k.id),
                },
            })
            .collect();
        let proxies = cfg
            .list
            .iter()
            .map(|e| {
                let p = pool.probes.get(&e.id);
                ProxyHealth {
                    id: e.id.clone(),
                    name: e.name.clone(),
                    url: redact(&e.url),
                    reachable: p.map(|p| p.up),
                    checked_at: p.map(|p| p.check.checked_at),
                    status: p.map(|p| p.check.status.clone()),
                    reason: p.and_then(|p| p.check.relays.iter().find(|r| !r.ok).map(|r| r.reason.clone())),
                    keys: e.keys.clone(),
                    pool: e.pool,
                }
            })
            .collect();
        drop(pool);
        let routes = settings
            .lanes
            .iter()
            .flat_map(|k| {
                self.routes_for(host, &k.id).into_iter().map(move |r| {
                    let (via, proxy) = match r.via {
                        crate::routes::Via::Proxy { id, .. } => (RouteVia::Proxy, Some(id)),
                        crate::routes::Via::Direct => (RouteVia::Direct, None),
                        crate::routes::Via::Off => (RouteVia::Off, None),
                    };
                    RouteHealth {
                        key: k.id.to_string(),
                        relay: r.relay,
                        rule: r.rule.map(|i| i + 1),
                        via,
                        proxy,
                        reason: r.reason,
                    }
                })
            })
            .collect();
        // The top-level fields are the public invoices key's lane.
        let main = lanes[0].clone();
        PoolHealth {
            state: main.state,
            posture: if lanes.iter().any(|l| l.state == PoolState::Offline && l.uses_default) {
                Posture::offline(cfg.offline)
            } else {
                Posture::Normal
            },
            mode: cfg.mode,
            offline: cfg.offline,
            transparent: cfg.transparent,
            active: main.active,
            reachable: main.reachable,
            total: cfg.list.len(),
            next_switch_at: lanes.iter().filter_map(|l| l.next_switch_at).min(),
            proxies,
            lanes,
            routes,
        }
    }
}

/// How often every proxy is probed.
#[cfg(not(test))]
pub const PROBE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(test)]
pub const PROBE_EVERY: std::time::Duration = std::time::Duration::from_millis(300);

/// How long to wait before looking again: a probe interval, or less when
/// rotation is due sooner.
pub fn probe_wait(next_switch_at: Option<u64>, now: u64) -> std::time::Duration {
    next_switch_at.map_or(PROBE_EVERY, |t| {
        PROBE_EVERY.min(std::time::Duration::from_secs(t.saturating_sub(now).max(1)))
    })
}

/// Probe the proxies now and then (and at once when asked), and keep the plan
/// current: it also moves rotation along when its time comes.
pub async fn run_probe_loop(net: &NetworkRuntime, host: &dyn NetworkHost, stop: tokio_util::sync::CancellationToken) {
    loop {
        net.refresh_pool(host).await;
        // Rotation has its own timer; probes are slower than a short interval.
        let wait = probe_wait(net.pool_health(host).next_switch_at, host.now());
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = net.pool_wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ProxyEntry;

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

    fn up(flags: &[bool]) -> Vec<Reach> {
        flags.iter().map(|&u| Reach { up: u, up_since: 0 }).collect()
    }

    /// A "random" source that returns the low end, or a fixed pick.
    fn low(min: u64, _max: u64) -> u64 {
        min
    }

    #[test]
    fn nothing_is_used_when_transparent_or_when_there_is_no_proxy() {
        let mut rot = Rotation::default();
        let mut c = cfg(ProxyMode::Failover, 2);
        c.transparent = true;
        let p = plan(&c, &up(&[true, true]), &mut rot, 0, &mut low);
        assert_eq!((p.state, p.active), (PoolState::Transparent, None));
        let p = plan(&cfg(ProxyMode::Chaos, 0), &[], &mut rot, 0, &mut low);
        assert_eq!((p.state, p.active), (PoolState::Direct, None));
    }

    #[test]
    fn one_configured_proxy_ignores_the_strategy() {
        for mode in [ProxyMode::RoundRobin, ProxyMode::Chaos] {
            let c = cfg(mode, 1);
            let mut rot = Rotation::default();
            let p = plan(&c, &up(&[true]), &mut rot, 0, &mut low);
            assert_eq!(
                (p.state, p.active, p.next_switch_at),
                (PoolState::Active, Some("p0".to_string()), None)
            );
            let p = plan(&c, &up(&[false]), &mut rot, 10, &mut low);
            assert_eq!((p.state, p.active), (PoolState::Offline, None));
        }
    }

    #[test]
    fn off_uses_the_first_proxy_and_never_another() {
        let c = cfg(ProxyMode::Off, 3);
        // Coming from another strategy: whatever was in use, it is the first now.
        let mut rot = Rotation {
            current: Some("p2".into()),
            due_at: 99,
        };
        let p = plan(&c, &up(&[true, true, true]), &mut rot, 1_000, &mut low);
        assert_eq!(
            (p.active.as_deref(), p.state, p.next_switch_at, p.reachable),
            (Some("p0"), PoolState::Active, None, 3)
        );
        assert_eq!(rot.due_at, 0);
        // The first is down: offline, though the others are up.
        let p = plan(&c, &up(&[false, true, true]), &mut rot, 1_010, &mut low);
        assert_eq!((p.active, p.state, p.reachable), (None, PoolState::Offline, 2));
        assert_eq!(rot, Rotation::default());
        // It is back: used again at once, with no hold.
        let mut r = up(&[true, true, true]);
        r[0].up_since = 1_020;
        let p = plan(&c, &r, &mut rot, 1_021, &mut low);
        assert_eq!((p.active.as_deref(), p.state), (Some("p0"), PoolState::Active));
    }

    #[test]
    fn failover_uses_the_first_reachable_proxy_in_order() {
        let c = cfg(ProxyMode::Failover, 3);
        let mut rot = Rotation::default();
        let mut at = |flags: &[bool], now| plan(&c, &up(flags), &mut rot, now, &mut low);
        assert_eq!(at(&[true, true, true], 10_000).active.as_deref(), Some("p0"));
        assert_eq!(at(&[false, true, true], 10_010).active.as_deref(), Some("p1"));
        assert_eq!(at(&[false, false, true], 10_020).active.as_deref(), Some("p2"));
        let p = at(&[false, true, true], 10_030);
        assert_eq!(
            (p.active.as_deref(), p.state, p.reachable),
            (Some("p1"), PoolState::Active, 2)
        );
        // A single reachable proxy is enough for failover.
        let p = at(&[false, false, true], 10_040);
        assert_eq!((p.active.as_deref(), p.state), (Some("p2"), PoolState::Active));
        let p = at(&[false, false, false], 10_050);
        assert_eq!((p.active, p.state, p.reachable), (None, PoolState::Offline, 0));
    }

    #[test]
    fn failover_returns_to_an_earlier_proxy_only_after_it_has_stayed_up() {
        let c = cfg(ProxyMode::Failover, 2);
        let mut rot = Rotation::default();
        // p1 carries traffic while p0 is down.
        let p = plan(&c, &up(&[false, true]), &mut rot, 1_000, &mut low);
        assert_eq!(p.active.as_deref(), Some("p1"));
        // p0 is back, but only just.
        let mut r = up(&[true, true]);
        r[0].up_since = 1_050;
        let p = plan(&c, &r, &mut rot, 1_060, &mut low);
        assert_eq!(p.active.as_deref(), Some("p1"), "held down");
        let p = plan(&c, &r, &mut rot, 1_050 + FAILBACK_HOLD_SECS, &mut low);
        assert_eq!(p.active.as_deref(), Some("p0"), "back to the first");
        // When the one in use fails, the hold does not apply.
        let mut r = up(&[true, false]);
        r[0].up_since = 5_000;
        let mut rot = Rotation {
            current: Some("p1".into()),
            due_at: 0,
        };
        assert_eq!(plan(&c, &r, &mut rot, 5_001, &mut low).active.as_deref(), Some("p0"));
    }

    #[test]
    fn round_robin_goes_around_at_the_interval_and_not_before() {
        let c = cfg(ProxyMode::RoundRobin, 3);
        let mut rot = Rotation::default();
        let all = up(&[true, true, true]);
        let first = plan(&c, &all, &mut rot, 1_000, &mut low);
        assert_eq!(
            (first.active.as_deref(), first.next_switch_at),
            (Some("p0"), Some(1_600))
        );
        // Not before the interval, however often it is asked.
        for now in [1_001, 1_300, 1_599] {
            assert_eq!(plan(&c, &all, &mut rot, now, &mut low).active.as_deref(), Some("p0"));
        }
        let order: Vec<String> = [1_600, 2_200, 2_800, 3_400]
            .iter()
            .map(|&now| plan(&c, &all, &mut rot, now, &mut low).active.unwrap())
            .collect();
        assert_eq!(order, ["p1", "p2", "p0", "p1"]);
        assert_eq!(rot.due_at, 4_000);
    }

    #[test]
    fn round_robin_skips_proxies_that_are_down_and_leaves_at_once_when_the_current_one_fails() {
        let c = cfg(ProxyMode::RoundRobin, 3);
        let mut rot = Rotation::default();
        plan(&c, &up(&[true, true, true]), &mut rot, 0, &mut low);
        // p1 is down at the next turn: p0 goes to p2.
        let p = plan(&c, &up(&[true, false, true]), &mut rot, 600, &mut low);
        assert_eq!(p.active.as_deref(), Some("p2"));
        // The current one fails mid-interval: leave it now and restart the timer.
        let p = plan(&c, &up(&[true, false, false]), &mut rot, 700, &mut low);
        assert_eq!(p.state, PoolState::Suspended);
        assert_eq!(p.active.as_deref(), Some("p0"));
        let p = plan(&c, &up(&[true, true, false]), &mut rot, 710, &mut low);
        assert_eq!((p.active.as_deref(), p.next_switch_at), (Some("p0"), Some(1_310)));
    }

    #[test]
    fn rotation_is_suspended_with_one_reachable_proxy_and_resumes_with_two() {
        for mode in [ProxyMode::RoundRobin, ProxyMode::Chaos] {
            let c = cfg(mode, 3);
            let mut rot = Rotation::default();
            let p = plan(&c, &up(&[false, true, false]), &mut rot, 100, &mut low);
            assert_eq!(
                (p.state, p.active.as_deref(), p.next_switch_at, p.reachable),
                (PoolState::Suspended, Some("p1"), None, 1)
            );
            // Stays suspended however long it lasts.
            let p = plan(&c, &up(&[false, true, false]), &mut rot, 100_000, &mut low);
            assert_eq!(p.state, PoolState::Suspended);
            // A second proxy returns: the one in use is kept and the timer starts now.
            let p = plan(&c, &up(&[true, true, false]), &mut rot, 200_000, &mut low);
            assert_eq!((p.state, p.active.as_deref()), (PoolState::Active, Some("p1")));
            assert!(p.next_switch_at.unwrap() > 200_000);
            let p = plan(&c, &up(&[false, false, false]), &mut rot, 300_000, &mut low);
            assert_eq!(p.state, PoolState::Offline);
        }
    }

    #[test]
    fn chaos_picks_another_proxy_after_a_random_time_inside_the_range() {
        let c = cfg(ProxyMode::Chaos, 3);
        let all = up(&[true, true, true]);
        let mut rot = Rotation::default();
        // The random source is asked for the interval in range, then for a pick.
        let mut asked: Vec<(u64, u64)> = Vec::new();
        let mut rng = |min: u64, max: u64| {
            asked.push((min, max));
            max
        };
        let p = plan(&c, &all, &mut rot, 1_000, &mut rng);
        // First start: an interval, then a pick among all three (the highest).
        assert_eq!((p.active.as_deref(), p.next_switch_at), (Some("p2"), Some(1_000 + 900)));
        assert_eq!(asked, [(300, 900), (0, 2)]);
        // Not due yet: no further draws.
        let before = rot.clone();
        plan(&c, &all, &mut rot, 1_899, &mut low);
        assert_eq!(rot, before, "nothing was drawn or changed");
        // Due: it never picks the proxy it is already on.
        for _ in 0..3 {
            let before = rot.current.clone();
            let now = rot.due_at;
            let mut rng = |min: u64, _max: u64| min;
            let p = plan(&c, &all, &mut rot, now, &mut rng);
            assert_ne!(p.active, before);
            assert_eq!(p.next_switch_at, Some(now + 300));
        }
    }

    #[test]
    fn the_real_random_source_stays_inside_its_range() {
        assert_eq!(random_between(5, 5), 5);
        assert_eq!(random_between(9, 3), 9);
        let seen: std::collections::HashSet<u64> = (0..400).map(|_| random_between(300, 303)).collect();
        assert!(seen.iter().all(|v| (300..=303).contains(v)));
        assert!(seen.len() > 1);
    }

    #[test]
    fn the_offline_policy_decides_the_posture() {
        assert_eq!(Posture::offline(OfflinePolicy::KillSwitch), Posture::Off);
        assert_eq!(Posture::offline(OfflinePolicy::AdminOnly), Posture::AdminOnly);
        assert_eq!(Posture::offline(OfflinePolicy::InvoicingOnly), Posture::InvoicingOnly);
        assert_eq!(Posture::offline(OfflinePolicy::Open), Posture::Open);
    }

    // ---- the pool inside the service ----

    #[test]
    fn the_probe_waits_for_the_sooner_of_an_interval_and_the_next_rotation() {
        assert_eq!(probe_wait(None, 100), PROBE_EVERY);
        let one = std::time::Duration::from_secs(1);
        assert_eq!(probe_wait(Some(100), 100), PROBE_EVERY.min(one));
        assert_eq!(probe_wait(Some(50), 100), PROBE_EVERY.min(one));
        assert_eq!(
            probe_wait(Some(103), 100),
            PROBE_EVERY.min(std::time::Duration::from_secs(3))
        );
        assert_eq!(probe_wait(Some(1_000_000), 100), PROBE_EVERY);
    }
}
