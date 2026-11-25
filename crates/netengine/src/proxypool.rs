//! Which proxy carries the relay connections.
//!
//! [`plan`] is a pure function: given a proxy group, which of its proxies
//! answered their last probe and the clock, it says which one to use now.
//! Everything that touches the network or the service lives elsewhere
//! (`manage.rs` holds the probe loop's state, `app.rs` acts on the plan).
//!
//! A group chooses by its strategy:
//!
//! - **Failover** uses the first reachable proxy in the group's order. When a
//!   proxy earlier in the order comes back, the group returns to it only
//!   after it has stayed up for [`FAILBACK_HOLD_SECS`], so a flapping proxy
//!   does not reconnect every relay over and over.
//! - **Round robin** takes the reachable proxies in turn, one change per
//!   interval (never per connection).
//! - **Chaos** changes to a random other reachable proxy after a random time
//!   between a minimum and a maximum.
//! - Rotation needs at least two reachable proxies. With one, it is
//!   *suspended*: that proxy keeps carrying traffic (never worse than going
//!   direct) until a second one is back. With none, the group is offline.
//!
//! Every key plans each group it uses on its own, so two keys on one group
//! do not change proxy in the same second. A default route that points at a
//! single proxy uses it while it is up; one that has nothing reachable leaves
//! the key to the offline policy.

use std::collections::HashMap;

use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use crate::netruntime::{NetworkHost, NetworkRuntime};
use crate::network::{OfflinePolicy, ProxyGroup, ProxySettings, Strategy, Topology};
use crate::privacy::ProxyCheck;
use crate::routes::Destination;
use deadhop_net::relay::{parse_proxy, redact};

/// A proxy that came back must stay up this long before failover returns to it.
pub const FAILBACK_HOLD_SECS: u64 = 120;

// Where a key's default route (or one of its groups) stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    // The operator runs a transparent proxy; nothing here is checked or used.
    Transparent,
    // The default route is direct: relays connect straight.
    Direct,
    // A proxy is in use (the group's choice, or the one proxy).
    Active,
    // Rotation needs two reachable proxies and only one is: it stays in use.
    Suspended,
    // Nothing it may use is reachable: the offline policy applies.
    Offline,
    // The default route blocks: relays no rule matches never connect.
    Blocked,
}

// What the service does with its relay connections and its callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    // Relays connect where their routes say; everything is served.
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
    // The posture while the offline policy applies.
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

/// What the rotation strategies remember between plans.
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

/// Decide which of a group's proxies to use. `reach` is in the group's order.
pub fn plan(
    g: &ProxyGroup,
    reach: &[Reach],
    rot: &mut Rotation,
    now: u64,
    rng: &mut dyn FnMut(u64, u64) -> u64,
) -> Plan {
    let ups: Vec<usize> = (0..g.proxies.len())
        .filter(|&i| reach.get(i).is_some_and(|r| r.up))
        .collect();
    if ups.is_empty() {
        *rot = Rotation::default();
        return Plan {
            active: None,
            state: PoolState::Offline,
            next_switch_at: None,
            reachable: 0,
        };
    }
    let id = |i: usize| g.proxies[i].clone();
    let current = rot
        .current
        .as_ref()
        .and_then(|c| ups.iter().copied().find(|&i| &g.proxies[i] == c));

    if g.strategy == Strategy::Failover {
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

    let interval = |rng: &mut dyn FnMut(u64, u64) -> u64| match g.strategy {
        Strategy::Chaos => rng(g.chaos_min_secs, g.chaos_max_secs),
        _ => g.rotate_secs,
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
            match g.strategy {
                Strategy::Chaos => {
                    let others: Vec<usize> = ups.iter().copied().filter(|&i| i != c).collect();
                    others[rng(0, others.len() as u64 - 1) as usize]
                }
                // The next reachable proxy after this one, wrapping around.
                _ => ups.iter().copied().find(|&i| i > c).unwrap_or(ups[0]),
            }
        }
        None => {
            rot.due_at = now + interval(rng);
            match g.strategy {
                Strategy::Chaos => ups[rng(0, ups.len() as u64 - 1) as usize],
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

/// What a plan last decided (kept with the url, so a settings change does
/// not move the connections before the new list has been probed).
#[derive(Debug, Clone)]
pub struct Applied {
    pub active: Option<String>,
    pub active_url: Option<String>,
    pub state: PoolState,
    pub next_switch_at: Option<u64>,
    pub reachable: usize,
}

impl Applied {
    /// A state with no proxy in it.
    pub fn bare(state: PoolState) -> Applied {
        Applied {
            active: None,
            active_url: None,
            state,
            next_switch_at: None,
            reachable: 0,
        }
    }

    /// The proxy (id and url) in use, if one is.
    fn proxy(&self) -> Option<(String, String)> {
        match self.state {
            PoolState::Active | PoolState::Suspended => self.active.clone().zip(self.active_url.clone()),
            _ => None,
        }
    }
}

/// A key and a group (by id): what each key plans on its own.
pub type LaneGroup = (String, String);

/// Runtime state of the proxies (never saved).
#[derive(Debug, Default)]
pub struct PoolRuntime {
    /// Rotation state per key and group: each key rotates on its own, so two
    /// keys do not change proxy in the same second.
    pub rot: HashMap<LaneGroup, Rotation>,
    pub probes: HashMap<String, Probe>,
    /// What each key's default route is, at the last plan.
    pub applied: HashMap<String, Applied>,
    /// What each group a key uses chose for it, at the last plan.
    pub groups: HashMap<LaneGroup, Applied>,
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

/// What a key's default route should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    /// No relay connection at all.
    Off,
    /// Straight to the relays (direct, a transparent proxy, or clearnet while offline).
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

// What one group chose for one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GroupHealth {
    // The group's id.
    pub group: String,
    pub state: PoolState,
    // Id of the proxy the group uses for this key.
    pub active: Option<String>,
    pub reachable: usize,
    // When rotation changes it next.
    pub next_switch_at: Option<u64>,
}

// How one key's relay connections stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LaneHealth {
    // The key's id.
    pub key: String,
    // Where its default route points.
    pub default: Destination,
    // Where its default route stands.
    pub state: PoolState,
    // Id of the proxy its default route uses.
    pub active: Option<String>,
    pub reachable: usize,
    // When rotation changes its default route's proxy next.
    pub next_switch_at: Option<u64>,
    // Whether any relay of this key takes the default route; when none
    // does, the default route's state does not affect the key.
    pub uses_default: bool,
    // Every group this key uses (by its default route, a rule or a
    // fallback), and what each chose for it.
    pub groups: Vec<GroupHealth>,
}

// The proxies as shown in `get_health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PoolHealth {
    // The first key's default route (the public invoices key's).
    pub state: PoolState,
    // What the service does now: `normal`, `off`, `admin_only`, `invoicing_only` or `open`.
    pub posture: Posture,
    // The default route (for every key without its own).
    pub default: Destination,
    pub offline: OfflinePolicy,
    pub transparent: bool,
    // Id of the proxy the first key's default route uses.
    pub active: Option<String>,
    pub reachable: usize,
    pub total: usize,
    // When rotation changes a proxy next (any key, any group).
    pub next_switch_at: Option<u64>,
    pub proxies: Vec<ProxyHealth>,
    // Each key's own plan. The fields above are the first key's.
    pub lanes: Vec<LaneHealth>,
    // Where every relay of every key goes now.
    pub routes: Vec<RouteHealth>,
}

impl NetworkRuntime {
    /// The posture the plan implies right now: the offline policy applies as
    /// soon as it decides where any relay of any key goes (nothing that relay
    /// may use is reachable).
    pub fn posture(&self, host: &dyn NetworkHost) -> Posture {
        let settings = host.topology();
        let offline = settings
            .lanes
            .iter()
            .any(|k| self.routes_for(host, &k.id).iter().any(|r| r.by_policy));
        if offline {
            Posture::offline(settings.proxies.offline)
        } else {
            Posture::Normal
        }
    }

    /// What one key's default route should be now. While it has nothing
    /// reachable, the offline policy decides: the kill switch cuts the key's
    /// default relays off, and the others connect straight for the one kind
    /// of key they keep.
    pub fn connection_for(&self, host: &dyn NetworkHost, key: &str) -> Connection {
        let settings = host.topology();
        if settings.proxies.transparent {
            return Connection::Direct;
        }
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match pool.applied.get(key) {
            // Straight by choice needs no plan; anything else waits for one.
            None if *settings.proxies.default_for(key) == Destination::Direct => Connection::Direct,
            None => Connection::Off,
            Some(a) => match (a.state, &a.active_url) {
                (PoolState::Direct | PoolState::Transparent, _) => Connection::Direct,
                (PoolState::Blocked, _) => Connection::Off,
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

    /// The proxy url one key's default route goes through, if any.
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
            // (by a rule, a fallback, a group or the default route), so it
            // never sees a relay or key it was not given. One that would
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
    pub fn forget_probe(&self, id: &str) {
        self.pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .probes
            .remove(id);
    }

    /// Remember a probe of one proxy.
    pub fn record_probe(&self, id: &str, check: ProxyCheck) {
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

    /// Plan every group each key uses, and each key's default route, from
    /// the probes so far. Wakes the supervisor when the connections should
    /// change, and undoes a proxy change that left nothing reachable.
    pub fn replan(&self, host: &dyn NetworkHost) {
        let settings = host.topology();
        let cfg = settings.proxies.clone();
        let now = host.now();
        let (decided, plans, revert_to) = {
            let mut pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            pool.probes.retain(|id, _| cfg.list.iter().any(|e| &e.id == id));
            let reach = |pool: &PoolRuntime, id: &str| {
                pool.probes.get(id).map_or(
                    Reach {
                        up: false,
                        up_since: now,
                    },
                    |p| Reach {
                        up: p.up,
                        up_since: p.up_since,
                    },
                )
            };
            let url = |id: &str| cfg.list.iter().find(|e| e.id == id).map(|e| e.url.clone());
            let mut decided: Vec<(String, Applied)> = Vec::new();
            let mut plans: HashMap<LaneGroup, Applied> = HashMap::new();
            for key in settings.lanes.iter() {
                let used = if cfg.transparent {
                    Vec::new()
                } else {
                    crate::routes::groups_used(&settings, &key.id)
                };
                for g in cfg.groups.iter().filter(|g| used.contains(&g.id)) {
                    let at = (key.id.clone(), g.id.clone());
                    let r: Vec<Reach> = g.proxies.iter().map(|id| reach(&pool, id)).collect();
                    let mut rot = pool.rot.remove(&at).unwrap_or_default();
                    let d = plan(g, &r, &mut rot, now, &mut random_between);
                    pool.rot.insert(at.clone(), rot);
                    let active_url = d.active.as_deref().and_then(url);
                    plans.insert(
                        at,
                        Applied {
                            active: d.active,
                            active_url,
                            state: d.state,
                            next_switch_at: d.next_switch_at,
                            reachable: d.reachable,
                        },
                    );
                }
                let default = match cfg.default_for(&key.id) {
                    _ if cfg.transparent => Applied::bare(PoolState::Transparent),
                    Destination::Direct => Applied::bare(PoolState::Direct),
                    Destination::Block => Applied::bare(PoolState::Blocked),
                    Destination::Proxy(id) if reach(&pool, id).up => Applied {
                        active: Some(id.clone()),
                        active_url: url(id),
                        state: PoolState::Active,
                        next_switch_at: None,
                        reachable: 1,
                    },
                    Destination::Proxy(_) => Applied::bare(PoolState::Offline),
                    Destination::Group(g) => plans
                        .get(&(key.id.clone(), g.clone()))
                        .cloned()
                        .unwrap_or_else(|| Applied::bare(PoolState::Offline)),
                };
                decided.push((key.id.to_string(), default));
            }
            // A key and group no longer planned starts over if it comes back.
            pool.rot.retain(|at, _| plans.contains_key(at));
            // Only a key whose relays take the default route is hurt by it being down.
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
            (decided, plans, revert_to)
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
            let shape = |m: &HashMap<String, Applied>, g: &HashMap<LaneGroup, Applied>| {
                let mut v: Vec<_> = m
                    .iter()
                    .map(|(k, a)| (k.clone(), String::new(), a.active_url.clone(), a.state))
                    .chain(
                        g.iter()
                            .map(|((k, id), a)| (k.clone(), id.clone(), a.active_url.clone(), a.state)),
                    )
                    .collect();
                v.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
                v
            };
            let before = shape(&pool.applied, &pool.groups);
            pool.applied = decided.into_iter().collect();
            pool.groups = plans;
            before != shape(&pool.applied, &pool.groups)
        };
        // A rule's own proxy going up or down moves relays even when no
        // plan changed.
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

    /// The label of a key that `next` would cut off now: one whose relays
    /// take the default route, whose default route in `next` has nothing up
    /// at the last probes (a proxy, or every proxy of a group, failed) while
    /// its default route in `before` did not.
    pub fn stranded(&self, before: &Topology, next: &Topology) -> Option<String> {
        if next.proxies.transparent {
            return None;
        }
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let failed = |id: &String| pool.probes.get(id).is_some_and(|p| !p.up);
        let down = |t: &Topology, key: &str| match t.proxies.default_for(key) {
            Destination::Proxy(id) => failed(id),
            Destination::Group(g) => t
                .proxies
                .groups
                .iter()
                .any(|x| &x.id == g && x.proxies.iter().all(failed)),
            _ => false,
        };
        next.lanes
            .iter()
            .find(|k| crate::routes::uses_default(next, &k.id) && down(next, &k.id) && !down(before, &k.id))
            .map(|k| k.label.clone())
    }

    /// Where each of one key's relays goes now, and why.
    pub fn routes_for(&self, host: &dyn NetworkHost, key: &str) -> Vec<crate::routes::Resolved> {
        let settings = host.topology();
        let proxies = &settings.proxies;
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let planned = pool.applied.get(key);
        let default = proxies.default_for(key);
        let now = |d: &Destination| -> Option<(String, String)> {
            match d {
                // The default route as planned (with the url it was planned with).
                _ if d == default => planned.and_then(Applied::proxy),
                Destination::Group(g) => pool.groups.get(&(key.to_string(), g.clone())).and_then(Applied::proxy),
                // A proxy (only proxies and groups are asked about), while it is up.
                _ => proxies
                    .list
                    .iter()
                    .find(|e| d.is_proxy(&e.id) && pool.probes.get(&e.id).is_some_and(|p| p.up))
                    .map(|e| (e.id.clone(), e.url.clone())),
            }
        };
        let offline = planned.map(|_| host.connects_while_offline(key, proxies.offline));
        crate::routes::resolve(&settings, key, &now, offline)
    }

    /// The proxies as the dashboard shows them.
    pub fn pool_health(&self, host: &dyn NetworkHost) -> PoolHealth {
        let settings = host.topology();
        let cfg = settings.proxies.clone();
        let posture = self.posture(host);
        let pool = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Before the first plan: straight or blocked by choice, else waiting.
        let waiting = |key: &str| {
            Applied::bare(match cfg.default_for(key) {
                _ if cfg.transparent => PoolState::Transparent,
                Destination::Direct => PoolState::Direct,
                Destination::Block => PoolState::Blocked,
                _ => PoolState::Offline,
            })
        };
        let group_health = |key: &str, g: String| {
            let a = pool
                .groups
                .get(&(key.to_string(), g.clone()))
                .cloned()
                .unwrap_or_else(|| Applied::bare(PoolState::Offline));
            GroupHealth {
                group: g,
                state: a.state,
                active: a.active,
                reachable: a.reachable,
                next_switch_at: a.next_switch_at,
            }
        };
        let lanes: Vec<LaneHealth> = settings
            .lanes
            .iter()
            .map(|k| {
                // A transparent proxy overrides whatever was planned.
                let (a, groups) = match pool.applied.get(&k.id) {
                    _ if cfg.transparent => (waiting(&k.id), Vec::new()),
                    a => (
                        a.cloned().unwrap_or_else(|| waiting(&k.id)),
                        crate::routes::groups_used(&settings, &k.id),
                    ),
                };
                LaneHealth {
                    key: k.id.to_string(),
                    default: cfg.default_for(&k.id).clone(),
                    state: a.state,
                    active: a.active,
                    reachable: a.reachable,
                    next_switch_at: a.next_switch_at,
                    uses_default: crate::routes::uses_default(&settings, &k.id),
                    groups: groups.into_iter().map(|g| group_health(&k.id, g)).collect(),
                }
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
                }
            })
            .collect();
        let next_switch_at = pool
            .applied
            .values()
            .chain(pool.groups.values())
            .filter_map(|a| a.next_switch_at)
            .min();
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
        // The top-level fields are the first key's lane.
        let main = lanes[0].clone();
        PoolHealth {
            state: main.state,
            posture,
            default: cfg.default.clone(),
            offline: cfg.offline,
            transparent: cfg.transparent,
            active: main.active,
            reachable: main.reachable,
            total: cfg.list.len(),
            next_switch_at,
            proxies,
            lanes,
            routes,
        }
    }
}

/// How often every proxy is probed.
#[cfg(not(any(test, feature = "test-support")))]
pub const PROBE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(any(test, feature = "test-support"))]
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

    fn cfg(strategy: Strategy, n: usize) -> ProxyGroup {
        ProxyGroup {
            id: "g".into(),
            name: String::new(),
            proxies: (0..n).map(|i| format!("p{i}")).collect(),
            strategy,
            rotate_secs: 600,
            chaos_min_secs: 300,
            chaos_max_secs: 900,
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
    fn a_group_with_nothing_reachable_is_offline_and_forgets_its_rotation() {
        let mut rot = Rotation {
            current: Some("p1".into()),
            due_at: 99,
        };
        let p = plan(
            &cfg(Strategy::RoundRobin, 2),
            &up(&[false, false]),
            &mut rot,
            0,
            &mut low,
        );
        assert_eq!((p.state, p.active, p.reachable), (PoolState::Offline, None, 0));
        assert_eq!(rot, Rotation::default());
        // A probe missing for a proxy counts as down.
        let p = plan(&cfg(Strategy::Failover, 2), &[], &mut rot, 0, &mut low);
        assert_eq!(p.state, PoolState::Offline);
    }

    #[test]
    fn failover_uses_the_first_reachable_proxy_in_order() {
        let c = cfg(Strategy::Failover, 3);
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
        let c = cfg(Strategy::Failover, 2);
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
        let c = cfg(Strategy::RoundRobin, 3);
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
        let c = cfg(Strategy::RoundRobin, 3);
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
        for mode in [Strategy::RoundRobin, Strategy::Chaos] {
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
        let c = cfg(Strategy::Chaos, 3);
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
