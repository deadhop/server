//! This service as the host of its network runtime: what the runtime may ask
//! of it, and the service's own methods, which hand over to the runtime.

use std::sync::Arc;

use crate::error::Result;
use crate::netruntime::NetworkHost;
use crate::network::{OfflinePolicy, ProxySettings, Topology};
use crate::proxypool::{Connection, PoolHealth, Posture};
use crate::service::Service;
use crate::settings::Settings;

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

    fn revert_proxies(&self, previous: ProxySettings, why: &str) -> Result<()> {
        Service::revert_proxies(self, previous, why)
    }
}

impl Service {
    /// The posture the plan implies right now: the offline policy applies as
    /// soon as any key has no reachable proxy.
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

    /// The label of a key that turning the strategy off would cut off now.
    pub fn stranded_by_off(&self, next: &Settings) -> Option<String> {
        self.net.stranded_by_off(&next.topology())
    }

    /// One key's default route now, as the routing rules see it.
    pub fn default_route_for(&self, key: &str) -> crate::routes::DefaultRoute {
        self.net.default_route_for(self, key)
    }

    /// Where each of one key's relays goes now, and why.
    pub fn routes_for(&self, key: &str) -> Vec<crate::routes::Resolved> {
        self.net.routes_for(self, key)
    }

    /// The pool as the dashboard shows it.
    pub fn pool_health(&self) -> PoolHealth {
        self.net.pool_health(self)
    }
}

/// Probe the proxies now and then (and at once when asked), and keep the plan current.
pub async fn probe_loop(svc: Arc<Service>, stop: tokio_util::sync::CancellationToken) {
    crate::proxypool::run_probe_loop(&svc.net, &*svc, stop).await;
}
