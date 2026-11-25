//! This service as the host of its network runtime: what the runtime may ask
//! of it, and the service's own methods, which hand over to the runtime.

use std::sync::Arc;

use crate::db::RelayEventRow;
use crate::electrum::Security;
use crate::error::{to_engine, Result};
use crate::netruntime::{
    AuditFacts, CheckProxyParams, NetworkHost, RelayHealthReport, RelayHistory, RelayHistoryParams,
    ResolveI2pNameParams,
};
use crate::network::{OfflinePolicy, ProxySettings, Topology};
use crate::privacy::{PrivacyAudit, ProxyCheck};
use crate::proxypool::{Connection, PoolHealth, Posture};
use crate::relayhealth::RelayHealth;
use crate::service::{Caller, RelayState, Service};
use crate::settings::Settings;
use deadhop_netengine::error::Result as EngineResult;

#[async_trait::async_trait]
impl NetworkHost for Service {
    fn topology(&self) -> Topology {
        self.settings().topology()
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn connects_while_offline(&self, lane: &str, policy: OfflinePolicy) -> bool {
        let operators = crate::keys::def(lane).is_some_and(|k| k.operators_only);
        !matches!(
            (policy, operators),
            (OfflinePolicy::KillSwitch, _) | (OfflinePolicy::AdminOnly, false) | (OfflinePolicy::InvoicingOnly, true)
        )
    }

    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> EngineResult<()> {
        Service::revert_proxies(self, previous, why).map_err(to_engine)
    }

    fn admit_change(&self, caller: &Caller) -> EngineResult<String> {
        Service::admit_change(self, caller).map_err(to_engine)
    }

    fn admit_read(&self, caller: &Caller) -> EngineResult<()> {
        self.read_only(caller).map_err(to_engine)
    }

    fn audit(&self, actor: &str, action: &str, detail: &str) -> EngineResult<()> {
        self.record(actor, action, detail).map_err(to_engine)
    }

    fn proxy_locked(&self) -> bool {
        self.cfg.proxy_locked
    }

    async fn relay_states(&self) -> Vec<RelayState> {
        Service::relay_states(self).await
    }

    fn store_relay_event(&self, row: &RelayEventRow) -> EngineResult<()> {
        self.db.record_relay_event(row).map_err(to_engine)
    }

    fn relay_events_since(&self, since: u64) -> EngineResult<Vec<RelayEventRow>> {
        self.db.relay_events_since(since).map_err(to_engine)
    }

    fn audit_facts(&self) -> AuditFacts {
        AuditFacts {
            electrum: self.cfg.electrum.clone(),
            electrum_plain: matches!(self.cfg.electrum_security, Security::Plain),
            electrum_transport: self.cfg.electrum_security.label().to_string(),
            announce: self.cfg.announce,
        }
    }
}

impl Service {
    /// The posture the plan implies right now: the offline policy applies as
    /// soon as it decides where any relay goes.
    pub fn posture(&self) -> Posture {
        self.net.posture(self)
    }

    /// What the public invoices key's relay connections should be now.
    pub fn connection(&self) -> Connection {
        self.connection_for(crate::keys::INVOICES)
    }

    /// What one key's relay connections should be now.
    pub fn connection_for(&self, key: &str) -> Connection {
        self.net.connection_for(self, key)
    }

    /// The proxy url relay traffic goes through, if any.
    pub fn active_proxy(&self) -> Option<String> {
        self.active_proxy_for(crate::keys::INVOICES)
    }

    /// The proxy url one key's relay traffic goes through, if any.
    pub fn active_proxy_for(&self, key: &str) -> Option<String> {
        self.net.active_proxy_for(self, key)
    }

    /// Probe every proxy (all at once, against the live relays) and plan again.
    pub async fn refresh_pool(&self) {
        self.net.refresh_pool(self).await;
    }

    /// Choose a proxy from the probes so far.
    pub fn replan(&self) {
        self.net.replan(self);
    }

    /// The label of a key whose default route `next` would leave with
    /// nothing reachable now (see [`crate::netruntime::NetworkRuntime::stranded`]).
    pub fn stranded(&self, next: &Settings) -> Option<String> {
        self.net.stranded(&self.settings().topology(), &next.topology())
    }

    /// Where each of one key's relays goes now, and why.
    pub fn routes_for(&self, key: &str) -> Vec<crate::routes::Resolved> {
        self.net.routes_for(self, key)
    }

    /// The pool as the dashboard shows it.
    pub fn pool_health(&self) -> PoolHealth {
        self.net.pool_health(self)
    }

    /// Test a proxy against the live relays (operators only).
    pub async fn check_proxy(&self, caller: &Caller, p: CheckProxyParams) -> Result<ProxyCheck> {
        Ok(self.net.check_proxy(self, caller, p).await?)
    }

    /// Look an I2P name up (operators only).
    pub async fn resolve_i2p_name(
        &self,
        caller: &Caller,
        p: ResolveI2pNameParams,
    ) -> Result<crate::i2p::I2pNameLookup> {
        Ok(self.net.resolve_i2p_name(self, caller, p).await?)
    }

    /// Check every live relay and keep the result for `health`. `None` if a
    /// check is already running.
    pub async fn refresh_relay_health(&self) -> Option<Vec<RelayHealth>> {
        self.net.refresh_relay_health(self).await
    }

    /// Remember how a relay did.
    pub(crate) fn record_relay_event(&self, relay: &str, kind: &str, ok: bool, ms: Option<u64>) {
        self.net.record_relay_event(self, relay, kind, ok, ms);
    }

    /// How each relay did over a window (operators only).
    pub fn relay_history(&self, caller: &Caller, p: RelayHistoryParams) -> Result<RelayHistory> {
        Ok(self.net.relay_history(self, caller, p)?)
    }

    /// Check every live relay now (operators only, a few times a minute).
    pub async fn check_relays(&self, caller: &Caller) -> Result<RelayHealthReport> {
        Ok(self.net.check_relays(self, caller).await?)
    }

    /// What can be learned about where this service runs (operators only).
    pub async fn privacy_audit(&self, caller: &Caller) -> Result<PrivacyAudit> {
        Ok(self.net.privacy_audit(self, caller).await?)
    }

    /// Look at the proxies again at once, and undo the change (once) if none
    /// of the new ones is reachable.
    pub(crate) fn begin_probation(&self, previous: ProxySettings) {
        self.net.begin_probation(self, previous);
    }
}

/// Probe the proxies now and then (and at once when asked), and keep the plan current.
pub async fn probe_loop(svc: Arc<Service>, stop: tokio_util::sync::CancellationToken) {
    crate::proxypool::run_probe_loop(&svc.net, &*svc, stop).await;
}
