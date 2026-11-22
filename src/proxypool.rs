//! Which proxy carries the relay connections.
//!
//! [`plan`] is a pure function: given the settings, which proxies answered
//! their last probe and the clock, it says which proxy to use now. Everything
//! that touches the network or the service lives elsewhere (`manage.rs` holds
//! the probe loop's state, `app.rs` acts on the plan).
//!
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

use crate::privacy::ProxyCheck;
use crate::relay::{parse_proxy, redact};
use crate::service::Service;
use crate::settings::{OfflinePolicy, ProxyMode, ProxySettings};

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
    // Proxies are configured and none is reachable: the offline policy applies.
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

impl PoolRuntime {
    /// Set (or clear) what every key's plan decided.
    #[cfg(test)]
    pub fn set_applied(&mut self, a: Option<Applied>) {
        self.applied = match a {
            Some(a) => crate::keys::KEYS
                .iter()
                .map(|k| (k.id.to_string(), a.clone()))
                .collect(),
            None => HashMap::new(),
        };
    }
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

impl Service {
    /// The posture the plan implies right now: the offline policy applies as
    /// soon as any key has no reachable proxy.
    pub fn posture(&self) -> Posture {
        let settings = self.settings().clone();
        let offline = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .applied
            .iter()
            .any(|(k, a)| a.state == PoolState::Offline && crate::routes::uses_default(&settings, k));
        if offline {
            Posture::offline(self.settings().proxies.offline)
        } else {
            Posture::Normal
        }
    }

    /// What the public invoices key's relay connections should be now.
    pub fn connection(&self) -> Connection {
        self.connection_for(crate::keys::INVOICES)
    }

    /// What one key's relay connections should be now. While its proxies are
    /// all down, the offline policy decides: the kill switch cuts the key off,
    /// and the others connect straight for the one kind of key they keep.
    pub fn connection_for(&self, key: &str) -> Connection {
        let settings = self.settings();
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
                    let operators = crate::keys::def(key).is_some_and(|k| k.operators_only);
                    match (settings.proxies.offline, operators) {
                        (OfflinePolicy::KillSwitch, _)
                        | (OfflinePolicy::AdminOnly, false)
                        | (OfflinePolicy::InvoicingOnly, true) => Connection::Off,
                        _ => Connection::Direct,
                    }
                }
                (_, url) => url.clone().map_or(Connection::Off, Connection::Via),
            },
        }
    }

    /// The proxy url relay traffic goes through, if any.
    pub fn active_proxy(&self) -> Option<String> {
        self.active_proxy_for(crate::keys::INVOICES)
    }

    /// The proxy url one key's relay traffic goes through, if any.
    pub fn active_proxy_for(&self, key: &str) -> Option<String> {
        match self.connection_for(key) {
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
    pub async fn refresh_pool(&self) {
        let cfg = self.settings().proxies.clone();
        if !cfg.transparent && !cfg.list.is_empty() {
            let settings = self.settings().clone();
            let now = (self.clock)();
            // A proxy is only ever tried against the relays it would carry
            // (by the rules, or as part of the default route for its keys), so
            // it never sees a relay or key it was not given. One that would
            // carry nothing is not tried at all.
            let targets: Vec<(String, Vec<String>, Option<crate::relay::ProxySpec>, String)> = cfg
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
        self.replan();
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
    pub fn replan(&self) {
        let settings = self.settings().clone();
        let cfg = settings.proxies.clone();
        let now = (self.clock)();
        let (decided, revert_to) = {
            let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            pool.probes.retain(|id, _| cfg.list.iter().any(|e| &e.id == id));
            let mut decided: Vec<(String, Applied)> = Vec::new();
            for key in crate::keys::KEYS.iter() {
                // This key's own default route: the proxies in the pool that
                // it may use, in list order.
                let mut lane = cfg.clone();
                lane.list.retain(|e| e.pool && crate::keys::assigned(&e.keys, key.id));
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
                let mut rot = pool.rot.remove(key.id).unwrap_or_default();
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
            self.revert_proxies(
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
        let routes = self.route_shape();
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
    fn route_shape(&self) -> Vec<(String, String, Option<String>)> {
        crate::keys::KEYS
            .iter()
            .flat_map(|k| {
                self.routes_for(k.id).into_iter().map(move |r| {
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

    /// One key's default route now, as the routing rules see it.
    pub fn default_route_for(&self, key: &str) -> crate::routes::DefaultRoute {
        use crate::routes::DefaultRoute;
        match self.connection_for(key) {
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
    pub fn routes_for(&self, key: &str) -> Vec<crate::routes::Resolved> {
        let settings = self.settings().clone();
        let default = self.default_route_for(key);
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
    pub fn pool_health(&self) -> PoolHealth {
        let settings = self.settings().clone();
        let cfg = settings.proxies.clone();
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let waiting = if cfg.list.is_empty() {
            PoolState::Direct
        } else {
            PoolState::Offline
        };
        let lanes: Vec<LaneHealth> = crate::keys::KEYS
            .iter()
            .map(|k| match pool.applied.get(k.id) {
                Some(a) if !cfg.transparent => LaneHealth {
                    key: k.id.to_string(),
                    state: a.state,
                    active: a.active.clone(),
                    reachable: a.reachable,
                    next_switch_at: a.next_switch_at,
                    uses_default: crate::routes::uses_default(&settings, k.id),
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
                    uses_default: crate::routes::uses_default(&settings, k.id),
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
        let routes = crate::keys::KEYS
            .iter()
            .flat_map(|k| {
                self.routes_for(k.id).into_iter().map(move |r| {
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
pub async fn probe_loop(svc: std::sync::Arc<Service>, stop: tokio_util::sync::CancellationToken) {
    loop {
        svc.refresh_pool().await;
        // Rotation has its own timer; probes are slower than a short interval.
        let wait = probe_wait(svc.pool_health().next_switch_at, (svc.clock)());
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = svc.pool_wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ProxyEntry;

    fn cfg(mode: ProxyMode, n: usize) -> ProxySettings {
        ProxySettings {
            list: (0..n)
                .map(|i| ProxyEntry {
                    id: format!("p{i}"),
                    name: String::new(),
                    url: format!("socks5://h:{}", i + 1),
                    keys: Vec::new(),
                    pool: true,
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
            msg(r.svc.check_proxy(&r.admin(), ask(Some("nope"), None)).await.map(|_| ()))
                .contains("no proxy with that id")
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
        ];
        s.proxies.list = vec![ProxyEntry {
            id: "spare".into(),
            name: String::new(),
            url: "socks5://127.0.0.1:1".into(),
            keys: Vec::new(),
            pool: false,
        }];
        let direct = |p: &str| Rule {
            name: String::new(),
            patterns: vec![p.into()],
            keys: Vec::new(),
            to: RouteTo::Direct,
            fallback: Fallback::Offline,
        };
        // Straight to an internet relay is a finding; to the LAN and FIPS it is not.
        s.proxies.rules = vec![direct("open.example"), direct("*.lan"), direct("*.fips")];
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
        assert_eq!(c.evidence, vec!["direct   wss://open.example".to_string()]);
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
            },
            ProxyEntry {
                id: "bad".into(),
                name: String::new(),
                url: "socks5://127.0.0.1:9".into(),
                keys: Vec::new(),
                pool: true,
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
        assert_eq!(svc.settings().proxies.mode, ProxyMode::Failover);
        assert_eq!(svc.settings().proxies.offline, OfflinePolicy::KillSwitch);
    }
}
