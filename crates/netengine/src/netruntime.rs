//! The network side of a service at run time: which proxy each lane uses,
//! where each relay goes, the proxy and relay checks and their budgets.
//!
//! The runtime owns that state and nothing else. What it needs from the
//! service around it (the settings, the clock, who may ask, where results
//! are kept) it asks of a [`NetworkHost`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::network::{relay_key, OfflinePolicy, ProxySettings, Topology};
use crate::privacy::{audit, own_listening, AuditInputs, PrivacyAudit, ProxyCheck};
use crate::relayhealth::{check_relay, RelayHealth};
use deadhop_cvm::caller::Caller;
use deadhop_net::relay::{parse_proxy, redact};

/// What the runtime asks of the service it runs in.
#[async_trait::async_trait]
pub trait NetworkHost: Send + Sync {
    /// The live network settings, with the host's lanes.
    fn topology(&self) -> Topology;
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
    /// While a lane's default route has nothing reachable: whether it
    /// connects straight under this policy (or stays off). The kill switch
    /// and "carry on" mean the same everywhere; what the policies in between
    /// keep running is the host's own business.
    fn connects_while_offline(&self, lane: &str, policy: OfflinePolicy) -> bool;
    /// Put the previous proxy settings back (a change left nothing reachable).
    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> Result<()>;
    /// Admit a caller who is about to make this machine open connections
    /// (a proxy check, a name lookup): admitted and budgeted like a change to
    /// the settings. Gives the name to record the act under.
    fn admit_change(&self, caller: &Caller) -> Result<String>;
    /// Admit a caller who only reads.
    fn admit_read(&self, caller: &Caller) -> Result<()>;
    /// Write an audit entry.
    fn audit(&self, actor: &str, action: &str, detail: &str) -> Result<()>;
    /// Whether the proxies are locked on the host.
    fn proxy_locked(&self) -> bool;
    /// The relay connections as they are now.
    async fn relay_states(&self) -> Vec<RelayState>;
    /// Keep a relay result.
    fn store_relay_event(&self, row: &RelayEventRow) -> Result<()>;
    /// The relay results kept from `since` on, oldest first.
    fn relay_events_since(&self, since: u64) -> Result<Vec<RelayEventRow>>;
    /// What the privacy audit needs to know about the host itself.
    fn audit_facts(&self) -> AuditFacts;
}

/// Connection state of one relay, as reported by the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RelayState {
    pub url: String,
    /// Transport status, for example `connected`, `connecting` or `disconnected`.
    pub status: String,
    pub connected: bool,
    /// The keys (by id) that use this relay.
    pub keys: Vec<String>,
}

/// One relay result: a health check (`check`) or a reply sent (`send`).
#[derive(Debug, PartialEq, Eq)]
pub struct RelayEventRow {
    pub at: u64,
    pub relay: String,
    pub kind: String,
    pub ok: bool,
    pub ms: Option<u64>,
}

pub use crate::privacy::{AnnounceFacts, AuditFacts, ElectrumFacts};

/// On-demand relay checks allowed per minute, all operators together.
pub const RELAY_CHECKS_PER_MIN: usize = 6;
/// Longest wait for each step of a relay check.
#[cfg(not(any(test, feature = "test-support")))]
pub const RELAY_CHECK_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(any(test, feature = "test-support"))]
pub const RELAY_CHECK_LIMIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Windows the relay history can show: name, length and bucket size in seconds.
pub const HISTORY_WINDOWS: [(&str, u64, u64); 5] = [
    ("15m", 900, 60),
    ("1h", 3_600, 300),
    ("12h", 43_200, 1_800),
    ("1d", 86_400, 3_600),
    ("1w", 604_800, 21_600),
];

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayHistoryParams {
    /// `15m`, `1h`, `12h`, `1d` or `1w`; default `1h`.
    #[serde(default)]
    pub window: Option<String>,
}

/// Relay results in one bucket of time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RelayPoint {
    /// Start of the bucket (unix seconds).
    pub start: u64,
    pub ok: u32,
    pub fail: u32,
}

/// One relay over a window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RelayStats {
    pub relay: String,
    /// End-to-end health checks, and how many of them failed.
    pub checks: u32,
    pub check_failures: u32,
    /// Replies sent through this relay, and how many it did not accept.
    pub sends: u32,
    pub send_failures: u32,
    /// Mean round trip of the results that carry one, in milliseconds.
    pub avg_ms: Option<u64>,
    pub points: Vec<RelayPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RelayHistory {
    pub window: String,
    pub bucket_secs: u64,
    /// Start of the first bucket and end of the last (unix seconds).
    pub since: u64,
    pub until: u64,
    pub relays: Vec<RelayStats>,
}

/// Result of `check_relays`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RelayHealthReport {
    pub relays: Vec<RelayHealth>,
}

/// Proxy checks allowed per minute, all operators together.
pub const PROXY_CHECKS_PER_MIN: usize = 6;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckProxyParams {
    /// The proxy to test (`socks5://`, `http://` or `https://`, optional
    /// `user:password@`); empty for none.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Test the listed proxy with this id (its saved password is used).
    /// With neither `id` nor `proxy`, the proxy in use is tested.
    #[serde(default)]
    pub id: Option<String>,
}

/// I2P name lookups allowed per minute, all operators together.
pub const I2P_LOOKUPS_PER_MIN: usize = 4;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveI2pNameParams {
    /// A lowercase `.i2p` name such as `example.i2p` (not a `.b32.i2p` address).
    pub name: String,
}

/// Clears a busy flag when dropped, so a cancelled call does not leave it set.
pub struct Busy<'a>(&'a AtomicBool);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The network state of one service (never saved).
pub struct NetworkRuntime {
    /// Result of the last check of the live proxy.
    pub last_proxy_check: Mutex<Option<crate::privacy::ProxyCheck>>,
    /// A proxy check is running.
    pub proxy_check_busy: AtomicBool,
    /// Which proxy is in use and how the others are doing (never saved).
    pub pool: Mutex<crate::proxypool::PoolRuntime>,
    /// Asks the probe loop to look at the proxies now.
    pub pool_wake: tokio::sync::Notify,
    /// Tells the supervisor the connections may need to change.
    pub pool_switch: tokio::sync::Notify,
    /// When recent proxy checks started (for their per-minute budget).
    pub proxy_checks: Mutex<Vec<u64>>,
    /// An I2P name lookup is running.
    pub i2p_lookup_busy: AtomicBool,
    /// When recent I2P name lookups started (for their per-minute budget).
    pub i2p_lookups: Mutex<Vec<u64>>,
    /// Where the kernel lists this namespace's sockets (`/proc/net`).
    pub proc_net: std::path::PathBuf,
    /// Looks up relay hosts, to tell a direct route to the local network
    /// from one to the internet (see the privacy audit).
    pub resolver: Mutex<crate::privacy::Resolver>,
    /// Result of the last check of every live relay.
    pub relay_health: Mutex<Vec<crate::relayhealth::RelayHealth>>,
    /// A relay check is running.
    pub relay_health_busy: AtomicBool,
    /// When recent on-demand relay checks started (for their per-minute budget).
    pub relay_checks: Mutex<Vec<u64>>,
}

impl Default for NetworkRuntime {
    fn default() -> Self {
        NetworkRuntime {
            last_proxy_check: Mutex::new(None),
            proxy_check_busy: AtomicBool::new(false),
            pool: Mutex::new(crate::proxypool::PoolRuntime::default()),
            pool_wake: tokio::sync::Notify::new(),
            pool_switch: tokio::sync::Notify::new(),
            proxy_checks: Mutex::new(Vec::new()),
            i2p_lookup_busy: AtomicBool::new(false),
            i2p_lookups: Mutex::new(Vec::new()),
            proc_net: std::path::PathBuf::from("/proc/net"),
            resolver: Mutex::new(crate::privacy::system_resolver()),
            relay_health: Mutex::new(Vec::new()),
            relay_health_busy: AtomicBool::new(false),
            relay_checks: Mutex::new(Vec::new()),
        }
    }
}

/// Each relay of a lane and the proxy url it goes through ("" for straight).
pub type Routes = Vec<(String, String)>;

/// Each relay of `routes` and its parsed proxy, as a routed relay pool takes them.
pub fn route_specs(routes: &Routes) -> Result<Vec<(String, Option<deadhop_net::relay::ProxySpec>)>> {
    routes.iter().map(|(r, p)| Ok((r.clone(), parse_proxy(p)?))).collect()
}

/// Whether two sets of routes name the same relays in the same order (so
/// the relays can move to their new routes on the connections they have).
pub fn same_relays(a: &Routes, b: &Routes) -> bool {
    a.iter().map(|r| &r.0).eq(b.iter().map(|r| &r.0))
}

impl NetworkRuntime {
    /// How a lane should be connected now: each relay that has a route and
    /// its proxy, or `None` when no relay of the lane should connect at all
    /// (the kill switch, or every relay blocked or waiting on a proxy that is
    /// down). The host rebuilds a lane's connections from this whenever
    /// [`pool_changed`](Self::pool_changed) says the plan moved.
    pub fn lane_routes(&self, host: &dyn NetworkHost, lane: &str) -> Option<Routes> {
        let routes: Routes = self
            .routes_for(host, lane)
            .into_iter()
            .filter_map(|r| match r.via {
                crate::routes::Via::Proxy { url, .. } => Some((r.relay, url)),
                crate::routes::Via::Direct => Some((r.relay, String::new())),
                crate::routes::Via::Off => None,
            })
            .collect();
        (!routes.is_empty()).then_some(routes)
    }

    /// The proxy url the first lane's relay traffic goes through, if any:
    /// "the proxy in use" where one is named without a lane.
    pub fn main_proxy(&self, host: &dyn NetworkHost) -> Option<String> {
        let first = host.topology().lanes.first().map(|l| l.id.clone())?;
        self.active_proxy_for(host, &first)
    }

    /// Test a proxy against the live relays (operators only). It opens
    /// connections from this machine to the proxy, so it is admitted and
    /// recorded like a change, honours the host's proxy lock, tunnels only to
    /// the live relays, runs one at a time and has a per-minute budget.
    pub async fn check_proxy(
        &self,
        host: &dyn NetworkHost,
        caller: &Caller,
        p: CheckProxyParams,
    ) -> Result<ProxyCheck> {
        let actor = host.admit_change(caller)?;
        let cfg = host.topology().proxies.clone();
        let (raw, id) = match (&p.id, &p.proxy) {
            (Some(id), None) => {
                let e = cfg
                    .list
                    .iter()
                    .find(|e| &e.id == id)
                    .ok_or_else(|| Error::InvalidParams("there is no proxy with that id".into()))?;
                (e.url.clone(), Some(e.id.clone()))
            }
            (Some(_), Some(_)) => return Err(Error::InvalidParams("give either id or proxy, not both".into())),
            (None, Some(url)) => {
                let url = url.trim().to_string();
                let listed = cfg.list.iter().find(|e| e.url == url).map(|e| e.id.clone());
                (url, listed)
            }
            (None, None) => match self.main_proxy(host) {
                Some(url) => {
                    let id = cfg.list.iter().find(|e| e.url == url).map(|e| e.id.clone());
                    (url, id)
                }
                None => (String::new(), None),
            },
        };
        // Testing opens connections to whatever address is given, so a locked
        // proxy list only allows testing what is already in it.
        if host.proxy_locked() && !raw.is_empty() && id.is_none() {
            return Err(Error::InvalidParams(format!(
                "the proxies are locked on the host ({}); only the listed ones can be tested",
                host.audit_facts().lock_setting
            )));
        }
        let spec = parse_proxy(&raw)?;
        let now = host.now();
        {
            let mut recent = self
                .proxy_checks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.retain(|t| now.saturating_sub(*t) < 60);
            if recent.len() >= PROXY_CHECKS_PER_MIN {
                return Err(Error::RateLimited);
            }
            recent.push(now);
        }
        if self.proxy_check_busy.swap(true, Ordering::SeqCst) {
            return Err(Error::RateLimited);
        }
        // Only the relays this proxy would carry, by the rules or as part of
        // the default route (all of them for an address that is not in the list).
        let relays = match &id {
            Some(id) => crate::routes::relays_through_proxy(&host.topology(), id),
            None => host.topology().relays.clone(),
        };
        if relays.is_empty() {
            self.proxy_check_busy.store(false, Ordering::SeqCst);
            return Err(Error::InvalidParams(
                "no relay goes through this proxy yet: point a rule, a group or the default route at it".into(),
            ));
        }
        let shown = redact(&raw);
        let result = crate::privacy::check(spec.as_ref(), &shown, &relays, now).await;
        self.proxy_check_busy.store(false, Ordering::SeqCst);
        if let Some(id) = &id {
            self.record_probe(id, result.clone());
            if self.main_proxy(host).as_deref() == Some(raw.as_str()) {
                *self
                    .last_proxy_check
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result.clone());
            }
        } else if raw.is_empty() && self.main_proxy(host).is_none() {
            *self
                .last_proxy_check
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result.clone());
        }
        let target = if shown.is_empty() { "no proxy" } else { shown.as_str() };
        host.audit(&actor, "check_proxy", &format!("{target}: {}", result.status))?;
        Ok(result)
    }

    /// Look an I2P name up (operators only): ask every configured registry,
    /// through the I2P router proxy and nothing else, for the name's b32
    /// address. Admitted and recorded like a change, refused while the
    /// proxies are locked on the host, one at a time, with a per-minute budget.
    pub async fn resolve_i2p_name(
        &self,
        host: &dyn NetworkHost,
        caller: &Caller,
        p: ResolveI2pNameParams,
    ) -> Result<crate::i2p::I2pNameLookup> {
        let actor = host.admit_change(caller)?;
        if host.proxy_locked() {
            return Err(Error::InvalidParams(format!(
                "the proxies are locked on the host ({}), so I2P names cannot be looked up",
                host.audit_facts().lock_setting
            )));
        }
        let name = p.name.trim().to_string();
        crate::i2p::check_name(&name)?;
        let cfg = host.topology().proxies.clone();
        let Some(router) = cfg.list.iter().find(|e| e.i2p) else {
            return Err(Error::InvalidParams(
                "there is no I2P router proxy: add the router's http:// proxy as an I2P proxy first".into(),
            ));
        };
        if cfg.i2p_registries.is_empty() {
            return Err(Error::InvalidParams(
                "there are no I2P name registries, so lookups are off".into(),
            ));
        }
        let spec = parse_proxy(&router.url)?
            .ok_or_else(|| Error::InvalidParams("the I2P router proxy has no address".into()))?;
        let now = host.now();
        {
            let mut recent = self
                .i2p_lookups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.retain(|t| now.saturating_sub(*t) < 60);
            if recent.len() >= I2P_LOOKUPS_PER_MIN {
                return Err(Error::RateLimited);
            }
            recent.push(now);
        }
        if self.i2p_lookup_busy.swap(true, Ordering::SeqCst) {
            return Err(Error::RateLimited);
        }
        let _busy = Busy(&self.i2p_lookup_busy);
        let proxy = deadhop_net::relay::ProxyTransport::new(spec);
        let out = crate::i2p::lookup(&proxy, &cfg.i2p_registries, &name, crate::i2p::LOOKUP_SECS).await;
        let detail = match &out {
            Ok(l) => format!(
                "{name}: {} ({} agree, {} disagree)",
                l.address,
                l.agreeing.len(),
                l.disagreeing.len()
            ),
            Err(e) => format!("{name}: failed: {e}"),
        };
        host.audit(&actor, "resolve_i2p_name", &detail)?;
        out
    }

    /// Check every live relay (through the live proxy) and keep the result
    /// for `health`. `None` if a check is already running.
    pub async fn refresh_relay_health(&self, host: &dyn NetworkHost) -> Option<Vec<RelayHealth>> {
        if self.relay_health_busy.swap(true, Ordering::SeqCst) {
            return None;
        }
        // Each relay is checked the way one of its own keys reaches it now
        // (its route: a proxy, or straight), never another way. A relay with
        // no route (blocked, kill switch, its proxy down) is not checked: a
        // check must not make a connection the routes do not allow. Saved
        // proxies were validated when saved.
        let settings = host.topology();
        let mut jobs: Vec<(String, Option<deadhop_net::relay::ProxySpec>)> = Vec::new();
        for r in &settings.relays {
            let route = settings.relay_users(r).into_iter().find_map(|k| {
                self.routes_for(host, &k)
                    .into_iter()
                    .find(|x| &x.relay == r)
                    .and_then(|x| match x.via {
                        crate::routes::Via::Proxy { url, .. } => Some(parse_proxy(&url).ok().flatten()),
                        crate::routes::Via::Direct => Some(None),
                        crate::routes::Via::Off => None,
                    })
            });
            if let Some(spec) = route {
                jobs.push((r.clone(), spec));
            }
        }
        if jobs.is_empty() {
            self.relay_health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            self.relay_health_busy.store(false, Ordering::SeqCst);
            return Some(Vec::new());
        }
        let now = host.now();
        let checks = jobs
            .iter()
            .map(|(r, spec)| check_relay(r, spec.as_ref(), RELAY_CHECK_LIMIT, now));
        let all = futures_util::future::join_all(checks).await;
        for h in &all {
            self.record_relay_event(host, &h.relay, "check", h.status == "ok", h.ms);
        }
        *self
            .relay_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = all.clone();
        self.relay_health_busy.store(false, Ordering::SeqCst);
        Some(all)
    }

    /// Remember how a relay did. A failure to store it must not disturb serving.
    pub fn record_relay_event(&self, host: &dyn NetworkHost, relay: &str, kind: &str, ok: bool, ms: Option<u64>) {
        let row = RelayEventRow {
            at: host.now(),
            relay: relay_key(relay),
            kind: kind.into(),
            ok,
            ms,
        };
        if let Err(e) = host.store_relay_event(&row) {
            tracing::warn!(target: "deadhop::manage", error = %e, "could not record a relay result");
        }
    }

    /// How each relay did over a window (operators only).
    pub fn relay_history(
        &self,
        host: &dyn NetworkHost,
        caller: &Caller,
        p: RelayHistoryParams,
    ) -> Result<RelayHistory> {
        host.admit_read(caller)?;
        let name = p.window.unwrap_or_else(|| "1h".into());
        let &(window, length, bucket) = HISTORY_WINDOWS
            .iter()
            .find(|w| w.0 == name)
            .ok_or_else(|| Error::InvalidParams("window must be 15m, 1h, 12h, 1d or 1w".into()))?;
        let now = host.now();
        let count = (length / bucket) as usize;
        let last = now / bucket * bucket;
        let since = last - (count as u64 - 1) * bucket;
        let events = host.relay_events_since(since)?;
        // The live relays first, then any other that has results in the window.
        let mut names: Vec<String> = host.topology().relays.iter().map(|r| relay_key(r)).collect();
        for e in &events {
            if !names.contains(&e.relay) {
                names.push(e.relay.clone());
            }
        }
        let relays = names
            .into_iter()
            .map(|relay| {
                let mut points: Vec<RelayPoint> = (0..count as u64)
                    .map(|i| RelayPoint {
                        start: since + i * bucket,
                        ok: 0,
                        fail: 0,
                    })
                    .collect();
                let (mut checks, mut check_failures, mut sends, mut send_failures) = (0, 0, 0, 0);
                let (mut ms_total, mut ms_count) = (0u64, 0u64);
                for e in events.iter().filter(|e| e.relay == relay && e.at <= now) {
                    let point = &mut points[((e.at - since) / bucket) as usize];
                    if e.ok {
                        point.ok += 1;
                    } else {
                        point.fail += 1;
                    }
                    let (total, failed) = if e.kind == "check" {
                        (&mut checks, &mut check_failures)
                    } else {
                        (&mut sends, &mut send_failures)
                    };
                    *total += 1;
                    *failed += u32::from(!e.ok);
                    if let (true, Some(ms)) = (e.ok, e.ms) {
                        ms_total += ms;
                        ms_count += 1;
                    }
                }
                RelayStats {
                    relay,
                    checks,
                    check_failures,
                    sends,
                    send_failures,
                    avg_ms: (ms_count > 0).then(|| ms_total / ms_count),
                    points,
                }
            })
            .collect();
        Ok(RelayHistory {
            window: window.into(),
            bucket_secs: bucket,
            since,
            until: last + bucket,
            relays,
        })
    }

    /// Check every live relay now (operators only, a few times a minute).
    pub async fn check_relays(&self, host: &dyn NetworkHost, caller: &Caller) -> Result<RelayHealthReport> {
        host.admit_read(caller)?;
        let now = host.now();
        {
            let mut recent = self
                .relay_checks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            recent.retain(|t| now.saturating_sub(*t) < 60);
            if recent.len() >= RELAY_CHECKS_PER_MIN {
                return Err(Error::RateLimited);
            }
            recent.push(now);
        }
        let relays = self.refresh_relay_health(host).await.ok_or(Error::RateLimited)?;
        Ok(RelayHealthReport { relays })
    }

    /// What can be learned about where this service runs (operators only).
    pub async fn privacy_audit(&self, host: &dyn NetworkHost, caller: &Caller) -> Result<PrivacyAudit> {
        host.admit_read(caller)?;
        let facts = host.audit_facts();
        let relays = host.relay_states().await;
        let s = host.topology();
        let (offline, configured, transparent) = (s.proxies.offline, s.proxies.list.len(), s.proxies.transparent);
        let default_direct = configured > 0
            && s.lanes.iter().any(|k| {
                *s.proxies.default_for(&k.id) == crate::routes::Destination::Direct
                    && crate::routes::uses_default(&s, &k.id)
            });
        // The proxy in use: the first key's default route's, or else the
        // first one a rule sends relays through (a rules-only setup).
        let ruled = || {
            s.lanes.iter().find_map(|k| {
                self.routes_for(host, &k.id).into_iter().find_map(|r| match r.via {
                    crate::routes::Via::Proxy { url, .. } => Some(url),
                    _ => None,
                })
            })
        };
        let proxy_raw = self.main_proxy(host).or_else(ruled).unwrap_or_default();
        let spec = parse_proxy(&proxy_raw).ok().flatten();
        let last_check = self
            .last_proxy_check
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|c| c.proxy == redact(&proxy_raw));
        Ok(audit(AuditInputs {
            proxy: spec.as_ref(),
            proxy_shown: redact(&proxy_raw),
            proxy_locked: host.proxy_locked(),
            transparent,
            configured,
            offline,
            relays,
            last_check,
            facts,
            listening: own_listening(&self.proc_net),
            direct_by_rule: self.direct_by_rule(host).await,
            default_direct,
            now: host.now(),
        }))
    }

    /// Relays a routing rule sends straight to a host on the internet (not
    /// this machine, a private network, or Tor, I2P and FIPS), once each. A
    /// name that resolves only to private addresses (a LAN name such as
    /// relay.home.example) stays on the local network and is not listed.
    async fn direct_by_rule(&self, host: &dyn NetworkHost) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for relay in self.direct_by_rule_text(host) {
            let (host, port) = crate::routes::host_port(&relay).expect("listed relays have a host");
            let resolve = self
                .resolver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if !crate::privacy::resolves_private(&resolve(host, port).await) {
                out.push(relay);
            }
        }
        out
    }

    /// The relays routed direct by a rule or by the default route (by
    /// choice, not by the offline policy) whose host name is not, as
    /// written, private (an address, a single label, .lan and similar, or an
    /// overlay).
    fn direct_by_rule_text(&self, host: &dyn NetworkHost) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        // (With no proxy at all, everything is straight; that is its own finding.)
        let listed = !host.topology().proxies.list.is_empty();
        for k in host.topology().lanes {
            for r in self.routes_for(host, &k.id) {
                let internet = crate::routes::host_port(&r.relay).is_some_and(|(h, _)| {
                    !crate::privacy::is_private_host(&h) && !deadhop_net::hosts::is_overlay_host(&h)
                });
                let chosen = r.reason == crate::routes::Reason::Rule
                    || (listed && r.reason == crate::routes::Reason::Default && !r.by_policy);
                if r.via == crate::routes::Via::Direct && chosen && internet && !out.contains(&r.relay) {
                    out.push(r.relay);
                }
            }
        }
        out
    }

    /// Look at the proxies again at once, and undo the change (once) if none
    /// of the new ones is reachable: the proxies are the way back in.
    pub fn begin_probation(&self, host: &dyn NetworkHost, previous: ProxySettings) {
        self.probation(host, previous, false);
    }

    /// The same, and also when the previous settings had no proxy at all:
    /// for a host where going back to straight connections is the safe
    /// undo (its address is public anyway), so a first proxy that does not
    /// work cannot cut it off for good.
    pub fn begin_probation_back_to_direct(&self, host: &dyn NetworkHost, previous: ProxySettings) {
        self.probation(host, previous, true);
    }

    fn probation(&self, host: &dyn NetworkHost, previous: ProxySettings, direct_ok: bool) {
        let now = host.now();
        let now_set = host.topology().settings.proxies;
        // What decides where relays go: the proxies, the groups, the default
        // routes and the rules.
        let routes_changed = previous.list != now_set.list
            || previous.groups != now_set.groups
            || previous.default != now_set.default
            || previous.default_keys != now_set.default_keys
            || previous.rules != now_set.rules;
        let was_working = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .applied
            .values()
            .all(|a| a.state != crate::proxypool::PoolState::Offline);
        // Only a change of where relays go can be a mistake worth undoing; a
        // changed policy is not, and must not be undone when the same
        // proxies fail later.
        if routes_changed && was_working && !previous.transparent && (direct_ok || !previous.list.is_empty()) {
            self.pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .probation = Some(crate::proxypool::Probation {
                previous,
                until: now + crate::proxypool::PROBATION_SECS,
            });
        }
        self.wake_pool();
    }
}
