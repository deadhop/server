//! The network side of a service at run time: which proxy each lane uses,
//! where each relay goes, the proxy and relay checks and their budgets.
//!
//! The runtime owns that state and nothing else. What it needs from the
//! service around it (the settings, the clock, who may ask, where results
//! are kept) it asks of a [`NetworkHost`].

use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use crate::error::Result;
use crate::network::{OfflinePolicy, ProxySettings, Topology};

/// What the runtime asks of the service it runs in.
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
}

/// The network state of one service (never saved).
pub struct NetworkRuntime {
    /// Result of the last check of the live proxy.
    pub(crate) last_proxy_check: Mutex<Option<crate::privacy::ProxyCheck>>,
    /// A proxy check is running.
    pub(crate) proxy_check_busy: AtomicBool,
    /// Which proxy is in use and how the others are doing (never saved).
    pub(crate) pool: Mutex<crate::proxypool::PoolRuntime>,
    /// Asks the probe loop to look at the proxies now.
    pub(crate) pool_wake: tokio::sync::Notify,
    /// Tells the supervisor the connections may need to change.
    pub(crate) pool_switch: tokio::sync::Notify,
    /// When recent proxy checks started (for their per-minute budget).
    pub(crate) proxy_checks: Mutex<Vec<u64>>,
    /// An I2P name lookup is running.
    pub(crate) i2p_lookup_busy: AtomicBool,
    /// When recent I2P name lookups started (for their per-minute budget).
    pub(crate) i2p_lookups: Mutex<Vec<u64>>,
    /// Where the kernel lists this namespace's sockets (`/proc/net`).
    pub(crate) proc_net: std::path::PathBuf,
    /// Looks up relay hosts, to tell a direct route to the local network
    /// from one to the internet (see the privacy audit).
    pub(crate) resolver: Mutex<crate::privacy::Resolver>,
    /// Result of the last check of every live relay.
    pub(crate) relay_health: Mutex<Vec<crate::relayhealth::RelayHealth>>,
    /// A relay check is running.
    pub(crate) relay_health_busy: AtomicBool,
    /// When recent on-demand relay checks started (for their per-minute budget).
    pub(crate) relay_checks: Mutex<Vec<u64>>,
}

impl NetworkRuntime {
    pub fn new() -> Self {
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

impl Default for NetworkRuntime {
    fn default() -> Self {
        Self::new()
    }
}
