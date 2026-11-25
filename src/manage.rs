//! Operator tools beyond invoicing: health, metrics, settings, operator keys,
//! service control, backups and wiping.
//!
//! Every tool here is operator-only. Every tool that changes state also needs
//! a fresh request event addressed to this service that was never used before
//! (checked against a list that survives restarts), and leaves an entry in
//! the audit log.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::config::{is_loopback, parse_pubkey};
use crate::db::OperatorRow;
use crate::error::{Error, Result};
use crate::privacy::ProxyCheck;
use crate::proxypool::PoolHealth;
use crate::relay::redact;
use crate::relayhealth::RelayHealth;
use crate::service::{
    is_plain_text, Caller, RelayState, Service, DAY_SECS, META_LAST_BACKUP, META_PAUSED, META_SETTINGS,
};
use crate::settings::{check_relays, Destination, ProxyPatch, ProxySettings, Settings, SettingsPatch, SweepMode};

/// Directory (inside the data directory) holding database backups.
pub const BACKUP_DIR: &str = "backups";
/// Backups kept; older ones are deleted when a new one is made.
pub const BACKUPS_KEPT: usize = 10;
/// Operator keys that may be added from the dashboard.
pub const MAX_EXTRA_OPERATORS: usize = 20;
/// Text an operator must type to wipe the database.
pub const WIPE_CONFIRMATION: &str = "WIPE";
const LABEL_LEN: usize = 60;

// ---- Wire types -----------------------------------------------------------

// The network views' types are the network engine's, shared with every
// service that serves them.
pub use deadhop_netengine::view::{KeyInfo, NetworkPatch, NetworkView, UpdateNetworkParams};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ServiceHealth {
    pub version: String,
    /// When this process started (unix seconds).
    pub started_at: u64,
    pub uptime_secs: u64,
    /// When this service first ran with this database.
    pub online_since: u64,
    /// Invoicing stopped by an operator.
    pub paused: bool,
    /// In-process restarts since the process started.
    pub restarts: u32,
    pub restart_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ChainHealth {
    pub ok: bool,
    pub tip_height: Option<u32>,
    pub last_poll_at: Option<u64>,
    pub poll_secs: u64,
    pub watch_errors: u64,
    /// Whether the Electrum server is on this machine.
    pub backend_local: bool,
    /// `tcp`, `tls` (public authorities) or `tls-pinned`.
    pub transport: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DatabaseHealth {
    /// SQLite quick integrity check passed.
    pub ok: bool,
    pub size_bytes: u64,
    pub invoices: u64,
    pub backups: u32,
    pub last_backup_at: Option<u64>,
}

/// Result of `get_health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Health {
    pub service: ServiceHealth,
    /// The keys, each with its own relays.
    pub keys: Vec<KeyInfo>,
    pub relays: Vec<RelayState>,
    /// Proxy used for relay connections now (password hidden), empty if direct.
    pub proxy: String,
    /// The last test of that proxy, if one ran.
    pub proxy_check: Option<ProxyCheck>,
    /// Every proxy, which one is in use and what happens when none works.
    pub proxy_pool: PoolHealth,
    /// The last health check of every live relay (empty until the first ran).
    pub relay_health: Vec<RelayHealth>,
    pub chain: ChainHealth,
    pub database: DatabaseHealth,
    pub warnings: Vec<String>,
}

/// Payments within one trailing window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct PaymentWindow {
    /// `24h`, `7d`, `30d` or `365d`.
    pub label: String,
    pub secs: u64,
    /// False while the service has been online for less than the window; the
    /// figures then cover only the time it has been online.
    pub available: bool,
    pub count: u64,
    pub sat: u64,
}

/// What the sweep policy would do now. Nothing is executed by this service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SweepStatus {
    pub enabled: bool,
    pub mode: SweepMode,
    pub threshold_sat: u64,
    /// Confirmed satoshis received (spends are not visible to a watch-only service).
    pub received_sat: u64,
    /// Enabled and at or above the threshold.
    pub due: bool,
}

/// Result of `get_metrics`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Metrics {
    pub now: u64,
    pub online_since: u64,
    /// Addresses handed out so far (the next derivation index).
    pub addresses_created: u32,
    pub invoices: u64,
    /// Invoices paid in full and confirmed.
    pub payments: u64,
    pub received_sat: u64,
    pub windows: Vec<PaymentWindow>,
    pub sweep: SweepStatus,
}

/// Span of a payment series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Range {
    /// 24 hourly buckets.
    Day,
    /// 7 daily buckets.
    Week,
    /// 30 daily buckets.
    Month,
    /// 52 weekly buckets.
    Year,
}

impl Range {
    fn buckets(self) -> (u64, usize) {
        match self {
            Range::Day => (3_600, 24),
            Range::Week => (DAY_SECS, 7),
            Range::Month => (DAY_SECS, 30),
            Range::Year => (7 * DAY_SECS, 52),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeriesParams {
    pub range: Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SeriesPoint {
    /// Bucket start (unix seconds, UTC-aligned).
    pub start: u64,
    pub count: u64,
    pub sat: u64,
}

/// Result of `get_payment_series`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Series {
    pub range: Range,
    pub bucket_secs: u64,
    pub online_since: u64,
    pub points: Vec<SeriesPoint>,
}

/// An operator key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Operator {
    /// Hex public key.
    pub pubkey: String,
    pub label: String,
    /// `environment` keys come from DEADHOP_ADMINS and cannot be removed remotely.
    pub source: String,
    pub added_at: Option<u64>,
}

/// What can only be changed on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct FixedSettings {
    pub network: String,
    pub electrum: String,
    /// `tcp`, `tls` (public authorities) or `tls-pinned`.
    pub electrum_transport: String,
    /// Receive address at index 0, to compare with the wallet.
    pub first_address: String,
    pub announce: bool,
    /// The keys and what each is for.
    pub keys: Vec<KeyInfo>,
    /// DEADHOP_PROXY_LOCKED: the proxy can only be changed on the host.
    pub proxy_locked: bool,
}

/// Result of the settings tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SettingsView {
    /// Live values.
    pub settings: Settings,
    /// Values from the environment, used where nothing is overridden.
    pub defaults: Settings,
    /// Names of the settings changed from the dashboard.
    pub overridden: Vec<String>,
    pub fixed: FixedSettings,
    pub operators: Vec<Operator>,
    pub restart_pending: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSettingsParams {
    /// Only the settings to change.
    pub patch: SettingsPatch,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddOperatorParams {
    /// Hex, `npub` or `nprofile`.
    pub pubkey: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveOperatorParams {
    /// Hex, `npub` or `nprofile`.
    pub pubkey: String,
}

/// What `control_service` should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ControlAction {
    /// Refuse new invoices. Payments keep being watched; operators can still connect.
    Stop,
    /// Accept new invoices again.
    Start,
    /// Reconnect to the relays and reload settings, in-process.
    Restart,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlParams {
    pub action: ControlAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ControlResult {
    pub paused: bool,
    pub restart_pending: bool,
}

/// A database backup on the service host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Backup {
    /// File name inside `<data dir>/backups`.
    pub file: String,
    pub size_bytes: u64,
    pub created_at: u64,
}

/// The backups on the service host, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BackupList {
    pub backups: Vec<Backup>,
}

/// When a backup was made, read from a name this service gives its backups
/// (`deadhop-<12-digit unix time>-<3-digit sequence>.sqlite`). Any other
/// name is not one of ours: it is never listed, counted or pruned.
fn backup_time(name: &str) -> Option<u64> {
    let (time, seq) = name
        .strip_prefix("deadhop-")?
        .strip_suffix(".sqlite")?
        .split_once('-')?;
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    (digits(time, 12) && digits(seq, 3))
        .then(|| time.parse().ok())
        .flatten()
}

// Lives with the network settings; kept at its old path.
pub(crate) use crate::network::relay_key;

// The network checks and their types live with the network runtime; these keep their old paths.
pub use crate::netruntime::{
    CheckProxyParams, RelayHealthReport, RelayHistory, RelayHistoryParams, RelayPoint, RelayStats, ResolveI2pNameParams,
};
#[cfg(test)]
pub(crate) use crate::netruntime::{PROXY_CHECKS_PER_MIN, RELAY_CHECKS_PER_MIN};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WipeParams {
    /// Must be exactly `WIPE`.
    pub confirm: String,
    /// Also forget settings changed from the dashboard.
    #[serde(default)]
    pub include_settings: bool,
    /// Wipe even though customers may still pay some invoices.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct WipeResult {
    pub deleted: u64,
    /// Backup taken just before wiping.
    pub backup: Backup,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditParams {
    /// 1 to 200, default 50.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct AuditEntry {
    pub at: u64,
    /// Hex key of the operator, or `service`.
    pub actor: String,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

// ---- Implementation ---------------------------------------------------------

impl Service {
    /// Admission for every state-changing operator tool. Returns the caller.
    pub(crate) fn admit_change(&self, caller: &Caller) -> Result<String> {
        self.require_admin(caller)?;
        let pubkey = caller.pubkey.clone().ok_or(Error::Unauthorized)?;
        let event = caller
            .event
            .as_ref()
            .ok_or_else(|| Error::Pow("request event unavailable".into()))?;
        self.check_event(event, &pubkey, (self.clock)(), true)?;
        Ok(pubkey)
    }

    pub(crate) fn read_only(&self, caller: &Caller) -> Result<()> {
        self.admit(caller)?;
        self.require_admin(caller)
    }

    pub(crate) fn record(&self, actor: &str, action: &str, detail: &str) -> Result<()> {
        tracing::info!(actor, action, detail, "operator action");
        self.db.audit((self.clock)(), actor, action, detail)
    }

    fn backup_dir(&self) -> PathBuf {
        self.cfg.data_dir.join(BACKUP_DIR)
    }

    /// Backups on disk, newest first.
    fn backups(&self) -> Result<Vec<Backup>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(self.backup_dir()) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(created_at) = backup_time(&name) {
                out.push(Backup {
                    size_bytes: entry.metadata()?.len(),
                    file: name,
                    created_at,
                });
            }
        }
        // Names embed a zero-padded timestamp and sequence, so they sort by age.
        out.sort_by(|a, b| b.file.cmp(&a.file));
        Ok(out)
    }

    fn warnings(&self) -> Vec<String> {
        let mut w = self
            .settings()
            .warnings(self.cfg.network, &self.cfg.electrum, &self.cfg.electrum_security);
        if let Some(problem) = self
            .settings_problem
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            w.push(problem);
        }
        if self.is_paused() {
            w.push("invoicing is stopped: new invoices are refused until an operator starts it".into());
        }
        if let Some(file) = &self.cfg.xpub_file {
            let beside = |name| file.with_file_name(name);
            if beside(crate::keyholder::GENERATED_FILE).exists() && !beside(crate::keyholder::EXPORTED_FILE).exists() {
                w.push(
                    "the wallet was generated on this host and its recovery phrase has not been backed up: \
                     run `deadhop wallet export` in the wallet service and keep the words offline"
                        .into(),
                );
            }
        }
        w
    }

    /// Live relay connections, or the configured relays as `unknown` before
    /// the relay pool is up.
    pub(crate) async fn relay_states(&self) -> Vec<RelayState> {
        let mut probes: Vec<(String, Arc<dyn crate::service::RelayProbe>)> = self
            .relay_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(k, p)| (k.clone(), p.clone()))
            .collect();
        probes.sort_by(|a, b| a.0.cmp(&b.0));
        let settings = self.settings().clone();
        let mut out: Vec<RelayState> = Vec::new();
        for (key, probe) in &probes {
            for s in probe.states().await {
                // A relay several keys use is one row: connected only if it is for each of them.
                match out.iter_mut().find(|o| relay_key(&o.url) == relay_key(&s.url)) {
                    Some(o) => {
                        o.keys.push(key.clone());
                        if o.connected && !s.connected {
                            o.connected = false;
                            o.status = s.status;
                        }
                    }
                    None => out.push(RelayState {
                        keys: vec![key.clone()],
                        ..s
                    }),
                }
            }
        }
        // Relays no key is connected to yet (or at all): shown as unknown.
        for url in &settings.relays {
            if !out.iter().any(|o| relay_key(&o.url) == relay_key(url)) {
                out.push(RelayState {
                    url: url.clone(),
                    status: "unknown".into(),
                    connected: false,
                    keys: settings.relay_users(url),
                });
            }
        }
        for o in &mut out {
            o.keys.sort();
        }
        out.sort_by(|a, b| a.url.cmp(&b.url));
        out
    }

    /// The keys, with the public key and relays each has now.
    pub(crate) fn key_infos(&self) -> Vec<KeyInfo> {
        let settings = self.settings().clone();
        let pubkeys = self
            .key_pubkeys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        crate::keys::KEYS
            .iter()
            .map(|k| KeyInfo {
                id: k.id.to_string(),
                label: k.label.to_string(),
                pubkey: pubkeys
                    .iter()
                    .find(|(id, _)| id == k.id)
                    .map(|(_, p)| p.clone())
                    .unwrap_or_default(),
                tools: k
                    .tools
                    .map_or_else(|| vec!["*".into()], |t| t.iter().map(|s| s.to_string()).collect()),
                operators_only: k.operators_only,
                relays: settings.relays_for(k.id),
            })
            .collect()
    }

    /// Relay, chain, database and process health (operators only).
    pub async fn health(&self, caller: &Caller) -> Result<Health> {
        self.read_only(caller)?;
        let relays = self.relay_states().await;
        let now = (self.clock)();
        let chain = *self
            .chain_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let check = self.db.check()?;
        let backups = self.backups()?;
        Ok(Health {
            service: ServiceHealth {
                version: env!("CARGO_PKG_VERSION").to_string(),
                started_at: self.started_at,
                uptime_secs: now.saturating_sub(self.started_at),
                online_since: self.online_since,
                paused: self.is_paused(),
                restarts: self.restarts.load(Ordering::Relaxed),
                restart_pending: self.restart_pending.load(Ordering::Relaxed),
            },
            keys: self.key_infos(),
            relays,
            proxy: redact(&self.active_proxy().unwrap_or_default()),
            proxy_pool: self.pool_health(),
            proxy_check: self
                .last_proxy_check
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            relay_health: self
                .relay_health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            chain: ChainHealth {
                ok: chain.chain_ok,
                tip_height: chain.tip,
                last_poll_at: chain.last_poll_at,
                poll_secs: self.poll_secs(),
                watch_errors: chain.watch_errors,
                backend_local: is_loopback(&self.cfg.electrum),
                transport: self.cfg.electrum_security.label().to_string(),
            },
            database: DatabaseHealth {
                ok: check.ok,
                size_bytes: check.size_bytes,
                invoices: check.invoices,
                backups: backups.len() as u32,
                last_backup_at: self.db.meta_get(META_LAST_BACKUP)?.and_then(|v| v.parse().ok()),
            },
            warnings: self.warnings(),
        })
    }

    /// Address, invoice and payment counts (operators only).
    pub fn metrics(&self, caller: &Caller) -> Result<Metrics> {
        self.read_only(caller)?;
        let now = (self.clock)();
        let t = self.db.totals()?;
        let age = now.saturating_sub(self.online_since);
        let windows = [
            ("24h", DAY_SECS),
            ("7d", 7 * DAY_SECS),
            ("30d", 30 * DAY_SECS),
            ("365d", 365 * DAY_SECS),
        ]
        .into_iter()
        .map(|(label, secs)| {
            let (count, sat) = self.db.payments_since(now.saturating_sub(secs))?;
            Ok(PaymentWindow {
                label: label.into(),
                secs,
                available: age >= secs,
                count,
                sat,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        let sweep = self.settings().sweep.clone();
        Ok(Metrics {
            now,
            online_since: self.online_since,
            addresses_created: t.next_index,
            invoices: t.pending + t.detected + t.confirmed + t.expired,
            payments: t.confirmed,
            received_sat: t.confirmed_sat,
            windows,
            sweep: SweepStatus {
                enabled: sweep.enabled,
                mode: sweep.mode,
                threshold_sat: sweep.threshold_sat,
                received_sat: t.confirmed_sat,
                due: sweep.enabled && t.confirmed_sat >= sweep.threshold_sat,
            },
        })
    }

    /// Confirmed payments over time, gap-filled (operators only).
    pub fn payment_series(&self, caller: &Caller, p: SeriesParams) -> Result<Series> {
        self.read_only(caller)?;
        let (width, n) = p.range.buckets();
        let end = ((self.clock)() / width + 1) * width;
        let start = end - width * n as u64;
        let points = self
            .db
            .payment_buckets(start, width, n)?
            .into_iter()
            .enumerate()
            .map(|(i, (count, sat))| SeriesPoint {
                start: start + width * i as u64,
                count,
                sat,
            })
            .collect();
        Ok(Series {
            range: p.range,
            bucket_secs: width,
            online_since: self.online_since,
            points,
        })
    }

    /// The stored changes. Stored ones that cannot be read are an error, so
    /// a change made on top of them never drops them silently (a reset
    /// clears them).
    pub(crate) fn stored_patch(&self) -> Result<SettingsPatch> {
        match self.db.meta_get(META_SETTINGS)? {
            Some(json) => serde_json::from_str(&json).map_err(|e| {
                Error::InvalidParams(format!(
                    "the saved settings could not be read ({e}); reset them before changing them"
                ))
            }),
            None => Ok(SettingsPatch::default()),
        }
    }

    fn operators_view(&self) -> Result<Vec<Operator>> {
        let mut env: Vec<&String> = self.cfg.admins.iter().collect();
        env.sort();
        let mut out: Vec<Operator> = env
            .into_iter()
            .map(|k| Operator {
                pubkey: k.clone(),
                label: String::new(),
                source: "environment".into(),
                added_at: None,
            })
            .collect();
        out.extend(
            self.db
                .operators()?
                .into_iter()
                .filter(|o| !self.cfg.admins.contains(&o.pubkey))
                .map(|o| Operator {
                    pubkey: o.pubkey,
                    label: o.label,
                    source: "dashboard".into(),
                    added_at: Some(o.added_at),
                }),
        );
        Ok(out)
    }

    fn settings_view(&self) -> Result<SettingsView> {
        let hide = |mut s: Settings| {
            s.proxies = s.proxies.redacted();
            s
        };
        Ok(SettingsView {
            settings: hide(self.settings().clone()),
            defaults: hide(self.cfg.settings()),
            // (Saved settings that cannot be read were not applied: nothing is overridden.)
            overridden: self.stored_patch().unwrap_or_default().names(),
            fixed: FixedSettings {
                network: self.cfg.network.to_string(),
                electrum: self.cfg.electrum.clone(),
                electrum_transport: self.cfg.electrum_security.label().to_string(),
                first_address: self.first_address()?,
                announce: self.cfg.announce,
                keys: self.key_infos(),
                proxy_locked: self.cfg.proxy_locked,
            },
            operators: self.operators_view()?,
            restart_pending: self.restart_pending.load(Ordering::Relaxed),
            warnings: self.warnings(),
        })
    }

    fn has_operators(&self) -> bool {
        !self.cfg.admins.is_empty()
            || !self
                .extra_operators
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
    }

    /// The network part of the settings view.
    fn network_view(&self, v: SettingsView) -> NetworkView {
        let network_name =
            |n: &String| ["relays", "relay_keys", "relay_names"].contains(&n.as_str()) || n.starts_with("proxies.");
        NetworkView {
            settings: v.settings.network(),
            defaults: v.defaults.network(),
            overridden: v.overridden.into_iter().filter(network_name).collect(),
            chain: v.fixed.network,
            keys: v.fixed.keys,
            proxy_locked: v.fixed.proxy_locked,
            restart_pending: v.restart_pending,
            warnings: v.warnings,
        }
    }

    /// The network settings (operators only).
    pub fn get_network(&self, caller: &Caller) -> Result<NetworkView> {
        Ok(self.network_view(self.get_settings(caller)?))
    }

    /// Change the network settings (operators only): the same checks, storage
    /// and reconnection as `update_settings`, for the network part alone.
    pub fn update_network(&self, caller: &Caller, p: UpdateNetworkParams) -> Result<NetworkView> {
        let patch = SettingsPatch {
            relays: p.patch.relays,
            relay_keys: p.patch.relay_keys,
            relay_names: p.patch.relay_names,
            proxies: p.patch.proxies,
            ..SettingsPatch::default()
        };
        let view = self.update_settings(caller, UpdateSettingsParams { patch })?;
        Ok(self.network_view(view))
    }

    /// Live and default settings, and who can operate the service.
    pub fn get_settings(&self, caller: &Caller) -> Result<SettingsView> {
        self.read_only(caller)?;
        self.settings_view()
    }

    /// Change settings. Takes effect at once; a changed relay list triggers a
    /// restart (reverted automatically if none of the new relays connect).
    pub fn update_settings(&self, caller: &Caller, p: UpdateSettingsParams) -> Result<SettingsView> {
        let actor = self.admit_change(caller)?;
        let mut patch = p.patch.clone();
        // The old single-address form becomes the whole proxy setup: a list
        // of one, the default route through it (or none, straight).
        let single = patch.proxy.take().map(|old| old.trim().to_string());
        if let Some(url) = &single {
            let px = patch.proxies.get_or_insert_with(ProxyPatch::default);
            px.list = Some(
                (!url.is_empty())
                    .then(|| crate::settings::ProxyEntryInput {
                        url: url.clone(),
                        ..Default::default()
                    })
                    .into_iter()
                    .collect(),
            );
            px.groups = Some(Vec::new());
            px.default_keys = Some(Default::default());
        }
        // Every proxy setting (the list, groups, routes, what happens when none
        // works, and the transparent claim) decides where relay traffic goes
        // and who can see this machine, so one lock covers them all.
        if self.cfg.proxy_locked && patch.proxies.is_some() {
            return Err(Error::InvalidParams(
                "the proxy settings are locked on the host (DEADHOP_PROXY_LOCKED)".into(),
            ));
        }
        let before = self.settings().proxies.clone();
        if let Some(px) = &mut patch.proxies {
            px.resolve(&before.list)?;
            if single.is_some() {
                let first = px.list.iter().flatten().next().and_then(|e| e.id.clone());
                px.default = Some(first.map_or(Destination::Direct, Destination::Proxy));
            }
            // The first proxies of a setup that had none (and went direct)
            // carry the default route unless the patch says otherwise, as
            // new proxies used to join the pool: the first that is not an
            // I2P router's.
            if before.list.is_empty() && before.default == Destination::Direct && px.default.is_none() {
                px.default = px
                    .list
                    .iter()
                    .flatten()
                    .find(|e| e.i2p != Some(true))
                    .and_then(|e| e.id.clone())
                    .map(Destination::Proxy);
            }
        }
        let mut stored = self.stored_patch()?;
        stored.merge(&patch);
        let next = stored.apply(&self.cfg.settings());
        next.validate(self.has_operators())?;
        if p.patch.relays.is_some() {
            check_relays(&next.relays, self.cfg.network)?;
        }
        // A name is only for a listed relay.
        if let Some(names) = &p.patch.relay_names {
            if let Some(url) = names
                .keys()
                .find(|u| !next.relays.iter().any(|r| crate::settings::same_relay(r, u)))
            {
                return Err(Error::InvalidParams(format!(
                    "relay_names: '{url}' is not a listed relay"
                )));
            }
        }
        // The relays from the host's configuration are the way back in when a
        // saved relay setup fails, so the administration key keeps one of them
        // whenever relays are shared out between keys.
        if !next.relay_keys.is_empty()
            && !next
                .relays_for(crate::keys::ADMIN)
                .iter()
                .any(|r| self.cfg.relays.iter().any(|e| crate::settings::same_relay(e, r)))
        {
            return Err(Error::InvalidParams(
                "the administration key must keep at least one relay from DEADHOP_RELAYS, the way back in if the others fail".into(),
            ));
        }
        // Pointing a key's default route at a proxy or group that is down
        // would cut that key off at once, perhaps the operator's own way in.
        if next.proxies != before {
            if let Some(key) = self.stranded(&next) {
                return Err(Error::InvalidParams(format!(
                    "the {key} key's default route would have nothing reachable now, which would cut that key off; point it at a proxy or group that is up, or wait until one is back"
                )));
            }
        }
        let relays_changed = self.connection_changes(&next);
        let proxies_changed = next.proxies != before;
        let json = serde_json::to_string(&stored).expect("settings always serialize");
        self.db.meta_set(META_SETTINGS, Some(&json))?;
        self.apply_settings(next);
        *self
            .settings_problem
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let mut shown = patch.clone();
        if let Some(px) = &mut shown.proxies {
            for e in px.list.iter_mut().flatten() {
                e.url = redact(&e.url);
            }
        }
        let changed = serde_json::to_string(&shown).expect("settings always serialize");
        self.record(&actor, "update_settings", &changed)?;
        if proxies_changed {
            self.begin_probation(before);
        }
        if relays_changed {
            self.schedule_restart();
        }
        self.settings_view()
    }

    /// Drop every override and return to the environment values.
    pub fn reset_settings(&self, caller: &Caller) -> Result<SettingsView> {
        let actor = self.admit_change(caller)?;
        let next = self.cfg.settings();
        let relays_changed = self.connection_changes(&next);
        let before = self.settings().proxies.clone();
        let proxies_changed = next.proxies != before;
        self.db.meta_set(META_SETTINGS, None)?;
        self.apply_settings(next);
        if proxies_changed {
            self.begin_probation(before);
        }
        *self
            .settings_problem
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.record(&actor, "reset_settings", "")?;
        if relays_changed {
            self.schedule_restart();
        }
        self.settings_view()
    }

    /// Whether `next` needs new relay connections. A new proxy list does not:
    /// the probe loop picks the proxy and the supervisor follows it.
    fn connection_changes(&self, next: &Settings) -> bool {
        next.relays != self.settings().relays || next.relay_keys != self.settings().relay_keys
    }

    /// Put the proxy settings back as they were (the supervisor's own act).
    pub(crate) fn revert_proxies(&self, previous: ProxySettings, why: &str) -> Result<()> {
        // (Saved settings that cannot be read were not applied; these replace them.)
        let mut stored = self.stored_patch().unwrap_or_default();
        stored.proxies = (previous != self.cfg.proxies).then(|| ProxyPatch {
            list: ProxyPatch::with_list(&previous.list).list,
            groups: Some(previous.groups.clone()),
            default: Some(previous.default.clone()),
            default_keys: Some(previous.default_keys.clone()),
            offline: Some(previous.offline),
            transparent: Some(previous.transparent),
            rules: Some(previous.rules.clone()),
            i2p_registries: Some(previous.i2p_registries.clone()),
            ..ProxyPatch::default()
        });
        let next = stored.apply(&self.cfg.settings());
        let json = serde_json::to_string(&stored).expect("settings always serialize");
        self.db.meta_set(META_SETTINGS, Some(&json))?;
        self.apply_settings(next);
        self.record("service", "revert_proxies", why)
    }

    /// Called by the supervisor when new relay connections (a relay list)
    /// could not connect: go back to the ones that worked.
    pub fn revert_connection(
        &self,
        relays: Vec<String>,
        relay_keys: std::collections::BTreeMap<String, Vec<String>>,
        why: &str,
    ) -> Result<()> {
        // (Saved settings that cannot be read were not applied; these replace them.)
        let mut stored = self.stored_patch().unwrap_or_default();
        stored.relays = (relays != self.cfg.relays).then_some(relays);
        stored.relay_keys = (!relay_keys.is_empty()).then_some(relay_keys);
        let next = stored.apply(&self.cfg.settings());
        let json = serde_json::to_string(&stored).expect("settings always serialize");
        self.db.meta_set(META_SETTINGS, Some(&json))?;
        self.apply_settings(next);
        self.record("service", "revert_connection", why)
    }

    /// Let another key operate the service.
    pub fn add_operator(&self, caller: &Caller, p: AddOperatorParams) -> Result<SettingsView> {
        let actor = self.admit_change(caller)?;
        let pubkey = parse_pubkey(&p.pubkey)
            .ok_or_else(|| Error::InvalidParams("pubkey must be a hex key, npub or nprofile".into()))?;
        let label = p.label.unwrap_or_default().trim().to_string();
        if label.chars().count() > LABEL_LEN || !label.chars().all(is_plain_text) {
            return Err(Error::InvalidParams(format!(
                "label must be at most {LABEL_LEN} visible characters"
            )));
        }
        if self.cfg.admins.contains(&pubkey) {
            return Err(Error::InvalidParams(
                "that key is already an operator (from the environment)".into(),
            ));
        }
        let mut extra = self
            .extra_operators
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !extra.contains(&pubkey) && extra.len() >= MAX_EXTRA_OPERATORS {
            return Err(Error::InvalidParams(format!(
                "at most {MAX_EXTRA_OPERATORS} operators can be added"
            )));
        }
        self.db.add_operator(&OperatorRow {
            pubkey: pubkey.clone(),
            label: label.clone(),
            added_at: (self.clock)(),
            added_by: actor.clone(),
        })?;
        extra.insert(pubkey.clone());
        drop(extra);
        self.record(&actor, "add_operator", format!("{pubkey} {label}").trim_end())?;
        self.settings_view()
    }

    /// Revoke a key added from the dashboard. Environment keys stay.
    pub fn remove_operator(&self, caller: &Caller, p: RemoveOperatorParams) -> Result<SettingsView> {
        let actor = self.admit_change(caller)?;
        let pubkey = parse_pubkey(&p.pubkey)
            .ok_or_else(|| Error::InvalidParams("pubkey must be a hex key, npub or nprofile".into()))?;
        if self.cfg.admins.contains(&pubkey) {
            return Err(Error::InvalidParams(
                "operators from DEADHOP_ADMINS can only be removed on the host".into(),
            ));
        }
        let mut extra = self
            .extra_operators
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Without an operator nobody could stop invoicing, change settings,
        // or add an operator again: that is final whether or not the public
        // can still create invoices (issue #8).
        if extra.len() == 1 && extra.contains(&pubkey) && self.cfg.admins.is_empty() {
            return Err(Error::InvalidParams(
                "this is the last operator; without one nobody could manage the service. \
                 Add another operator first, or set DEADHOP_ADMINS on the host"
                    .into(),
            ));
        }
        if !self.db.remove_operator(&pubkey)? {
            return Err(Error::NotFound);
        }
        extra.remove(&pubkey);
        drop(extra);
        self.record(&actor, "remove_operator", &pubkey)?;
        self.settings_view()
    }

    /// Stop or start invoicing, or restart the relay connections.
    pub fn control(&self, caller: &Caller, p: ControlParams) -> Result<ControlResult> {
        let actor = self.admit_change(caller)?;
        match p.action {
            ControlAction::Stop => {
                self.db.meta_set(META_PAUSED, Some("1"))?;
                self.paused.store(true, Ordering::Relaxed);
                self.record(&actor, "stop", "invoicing stopped")?;
            }
            ControlAction::Start => {
                self.db.meta_set(META_PAUSED, None)?;
                self.paused.store(false, Ordering::Relaxed);
                self.record(&actor, "start", "invoicing started")?;
            }
            ControlAction::Restart => {
                self.record(&actor, "restart", "relay connections restarting")?;
                self.schedule_restart();
            }
        }
        Ok(ControlResult {
            paused: self.is_paused(),
            restart_pending: self.restart_pending.load(Ordering::Relaxed),
        })
    }

    fn make_backup(&self) -> Result<Backup> {
        let dir = self.backup_dir();
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let now = (self.clock)();
        let existing = self.backups()?;
        // Several backups within one second get increasing sequence numbers.
        let seq = (0u32..)
            .find(|n| {
                !existing
                    .iter()
                    .any(|b| b.file == format!("deadhop-{now:012}-{n:03}.sqlite"))
            })
            .expect("a free sequence number exists");
        let file = format!("deadhop-{now:012}-{seq:03}.sqlite");
        let path = dir.join(&file);
        self.db.backup_to(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let size_bytes = fs::metadata(&path)?.len();
        self.db.meta_set(META_LAST_BACKUP, Some(&now.to_string()))?;
        for old in self.backups()?.into_iter().skip(BACKUPS_KEPT) {
            fs::remove_file(dir.join(old.file))?;
        }
        Ok(Backup {
            file,
            size_bytes,
            created_at: now,
        })
    }

    /// Write a consistent copy of the database next to it, on the host.
    pub fn backup(&self, caller: &Caller) -> Result<Backup> {
        let actor = self.admit_change(caller)?;
        let b = self.make_backup()?;
        self.record(&actor, "backup", &b.file)?;
        Ok(b)
    }

    /// The backups kept on the host, newest first (operators only).
    pub fn list_backups(&self, caller: &Caller) -> Result<BackupList> {
        self.read_only(caller)?;
        Ok(BackupList {
            backups: self.backups()?,
        })
    }

    /// Delete every invoice, after taking a backup. Address indices are never
    /// reused, so a wiped service still hands out fresh addresses.
    pub fn wipe(&self, caller: &Caller, p: WipeParams) -> Result<WipeResult> {
        let actor = self.admit_change(caller)?;
        if p.confirm != WIPE_CONFIRMATION {
            return Err(Error::InvalidParams(format!("type {WIPE_CONFIRMATION} to confirm")));
        }
        let now = (self.clock)();
        let watched = self
            .db
            .count_watched(now.saturating_sub(self.settings().late_grace_secs))?;
        if watched > 0 && !p.force {
            return Err(Error::InvalidParams(format!(
                "{watched} invoice(s) may still be paid; wait until they settle or pass force"
            )));
        }
        let backup = self.make_backup()?;
        let deleted = self.db.wipe(p.include_settings.then_some(META_SETTINGS))?;
        if p.include_settings {
            let next = self.cfg.settings();
            let relays_changed = self.connection_changes(&next);
            self.apply_settings(next);
            if relays_changed {
                self.schedule_restart();
            }
        }
        let detail = format!(
            "{deleted} invoices; backup {}; settings {}",
            backup.file, p.include_settings
        );
        self.record(&actor, "wipe", &detail)?;
        Ok(WipeResult { deleted, backup })
    }

    /// Recent operator actions (operators only).
    pub fn audit_log(&self, caller: &Caller, p: AuditParams) -> Result<AuditLog> {
        self.read_only(caller)?;
        let limit = p.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(Error::InvalidParams("limit must be between 1 and 200".into()));
        }
        let entries = self
            .db
            .audit_recent(limit)?
            .into_iter()
            .map(|r| AuditEntry {
                at: r.at,
                actor: r.actor,
                action: r.action,
                detail: r.detail,
            })
            .collect();
        Ok(AuditLog { entries })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Db;
    use crate::db::RelayEventRow;
    use crate::electrum::testutil::FakeElectrum;
    use crate::pow::tests::SERVICE;
    use crate::service::tests::{public, request, rig, Rig, T0};
    use crate::service::{Clock, CreateInvoiceParams, GetInvoiceParams};
    use crate::settings::SweepPatch;
    use crate::wallet::Wallet;
    use nostr_sdk::{Keys, ToBech32};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    fn code<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
        r.unwrap_err().code()
    }

    fn msg<T: std::fmt::Debug>(r: Result<T>) -> String {
        r.unwrap_err().to_string()
    }

    fn patch(v: serde_json::Value) -> UpdateSettingsParams {
        UpdateSettingsParams {
            patch: serde_json::from_value(v).unwrap(),
        }
    }

    /// A caller that is not an operator.
    fn stranger() -> Caller {
        public(&Keys::generate(), 4, T0)
    }

    /// A service over a database file, so restarts can be simulated.
    pub(crate) async fn on_disk(cfg: &Config, path: &std::path::Path, now: u64) -> (Service, FakeElectrum) {
        let fake = FakeElectrum::start().await;
        let n = Arc::new(AtomicU64::new(now));
        let clock: Clock = Arc::new(move || n.load(Ordering::SeqCst));
        let svc = Service::new(
            cfg.clone(),
            Db::open(path).unwrap(),
            Wallet::new(&cfg.xpub, cfg.network).unwrap(),
            Arc::new(fake.client()),
            clock,
            SERVICE.to_string(),
        )
        .unwrap();
        (svc, fake)
    }

    fn admin_of(keys: &Keys, at: u64, salt: u64) -> Caller {
        Caller {
            pubkey: Some(keys.public_key().to_hex()),
            event: Some(request(keys, at, salt)),
        }
    }

    fn pay_and_confirm(r: &Rig, amount: u64) {
        let inv = r.create(amount);
        let script = r.svc.wallet.script_for(&inv.address).unwrap();
        r.fake.pay(&script, amount as i64 as u64, 100);
        r.fake.set(|s| s.tip = 101);
    }

    struct Probe(Vec<RelayState>);
    #[async_trait::async_trait]
    impl crate::service::RelayProbe for Probe {
        async fn states(&self) -> Vec<RelayState> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn operator_tools_are_closed_to_everyone_else() {
        let r = rig(|_| {}).await;
        let s = stranger();
        assert_eq!(code(r.svc.health(&s).await), "unauthorized");
        assert_eq!(code(r.svc.metrics(&s)), "unauthorized");
        assert_eq!(
            code(r.svc.payment_series(&s, SeriesParams { range: Range::Day })),
            "unauthorized"
        );
        assert_eq!(code(r.svc.get_settings(&s)), "unauthorized");
        assert_eq!(
            code(r.svc.update_settings(&s, patch(serde_json::json!({})))),
            "unauthorized"
        );
        assert_eq!(code(r.svc.reset_settings(&s)), "unauthorized");
        assert_eq!(code(r.svc.list_backups(&s)), "unauthorized");
        assert_eq!(code(r.svc.check_relays(&s).await), "unauthorized");
        assert_eq!(
            code(r.svc.relay_history(&s, RelayHistoryParams::default())),
            "unauthorized"
        );
        let add = AddOperatorParams {
            pubkey: s.pubkey.clone().unwrap(),
            label: None,
        };
        assert_eq!(code(r.svc.add_operator(&s, add)), "unauthorized");
        let rm = RemoveOperatorParams {
            pubkey: s.pubkey.clone().unwrap(),
        };
        assert_eq!(code(r.svc.remove_operator(&s, rm)), "unauthorized");
        let stop = ControlParams {
            action: ControlAction::Stop,
        };
        assert_eq!(code(r.svc.control(&s, stop)), "unauthorized");
        assert_eq!(code(r.svc.backup(&s)), "unauthorized");
        let wipe = WipeParams {
            confirm: "WIPE".into(),
            include_settings: false,
            force: true,
        };
        assert_eq!(code(r.svc.wipe(&s, wipe)), "unauthorized");
        assert_eq!(code(r.svc.audit_log(&s, AuditParams::default())), "unauthorized");
    }

    #[tokio::test]
    async fn changes_need_a_fresh_unused_request_even_across_restarts() {
        let r = rig(|_| {}).await;
        let caller = r.admin();
        r.svc
            .control(
                &caller,
                ControlParams {
                    action: ControlAction::Stop,
                },
            )
            .unwrap();
        let again = r.svc.control(
            &caller,
            ControlParams {
                action: ControlAction::Start,
            },
        );
        assert!(msg(again).contains("already used"));
        let no_event = Caller {
            event: None,
            ..r.admin()
        };
        assert_eq!(code(r.svc.backup(&no_event)), "pow_rejected");
        let no_key = Caller {
            pubkey: None,
            ..r.admin()
        };
        assert_eq!(code(r.svc.backup(&no_key)), "unauthorized");
        let stale = admin_of(&r.admin_keys, T0 - 10_000, 1);
        assert_eq!(code(r.svc.backup(&stale)), "pow_rejected");

        // The used id is in the database, so a fresh process refuses it too.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let cfg = r.svc.cfg.clone();
        let event = admin_of(&r.admin_keys, T0, 77);
        let (first, _f1) = on_disk(&cfg, &path, T0).await;
        first.backup(&event).unwrap();
        drop(first);
        let (second, _f2) = on_disk(&cfg, &path, T0).await;
        assert!(msg(second.backup(&event)).contains("already used"));
    }

    #[tokio::test]
    async fn an_unexported_generated_wallet_is_a_warning() {
        let public = tempfile::tempdir().unwrap();
        let file = public.path().join("account.xpub");
        let f = file.clone();
        let r = rig(move |c| c.xpub_file = Some(f)).await;
        let warned = |r: &Rig| {
            let w = r.svc.warnings();
            w.iter().any(|w| w.contains("recovery phrase has not been backed up"))
        };
        assert!(!warned(&r), "a key from a file is not necessarily generated here");
        fs::write(file.with_file_name(crate::keyholder::GENERATED_FILE), "generated").unwrap();
        assert!(warned(&r));
        fs::write(file.with_file_name(crate::keyholder::EXPORTED_FILE), "1").unwrap();
        assert!(!warned(&r));
    }

    #[tokio::test]
    async fn health_reports_every_part() {
        let r = rig(|_| {}).await;
        let h = r.svc.health(&r.admin()).await.unwrap();
        assert_eq!(h.relays.len(), 2);
        assert!(h.relays.iter().all(|x| x.status == "unknown" && !x.connected));
        assert!(h.database.ok);
        assert_eq!((h.database.backups, h.database.last_backup_at), (0, None));
        assert!(!h.chain.ok && h.chain.backend_local);
        assert_eq!(h.chain.poll_secs, 10);
        assert_eq!(
            (h.service.started_at, h.service.uptime_secs, h.service.online_since),
            (T0, 0, T0)
        );
        assert!(!h.service.paused);
        assert_eq!(h.warnings.len(), 1, "the rig's weak proof of work: {:?}", h.warnings);

        r.svc.poll_once().await.unwrap();
        r.svc.set_relay_probe(
            "invoices",
            Some(Arc::new(Probe(vec![RelayState {
                url: "wss://relay.example".into(),
                status: "connected".into(),
                connected: true,
                keys: Vec::new(),
            }]))),
        );
        r.svc
            .control(
                &r.admin(),
                ControlParams {
                    action: ControlAction::Stop,
                },
            )
            .unwrap();
        r.svc.backup(&r.admin()).unwrap();
        r.set_now(T0 + 90);
        let h = r.svc.health(&r.admin()).await.unwrap();
        // Relays no pool has are listed too, as unknown.
        assert!(h.relays.iter().any(|x| x.url == "wss://relay.example" && x.connected));
        assert!(h.relays.iter().filter(|x| !x.connected).all(|x| x.status == "unknown"));
        assert!(h.chain.ok && h.chain.last_poll_at.is_some());
        assert_eq!((h.database.backups, h.database.last_backup_at), (1, Some(T0)));
        assert_eq!(h.service.uptime_secs, 90);
        assert!(h.service.paused);
        assert!(h.warnings.iter().any(|w| w.contains("invoicing is stopped")));

        // A backup location that cannot be listed is an error, not a crash.
        let dir = r.svc.cfg.data_dir.join(BACKUP_DIR);
        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"not a directory").unwrap();
        assert_eq!(code(r.svc.health(&r.admin()).await), "internal");
    }

    #[tokio::test]
    async fn metrics_windows_are_gated_by_how_long_the_service_has_run() {
        let r = rig(|_| {}).await;
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "sweep": { "enabled": true, "threshold_sat": 10000 } })),
            )
            .unwrap();
        pay_and_confirm(&r, 6_000);
        r.set_now(T0 + 2 * DAY_SECS);
        r.svc.poll_once().await.unwrap();
        pay_and_confirm(&r, 5_000);
        r.svc.poll_once().await.unwrap();
        r.create(7_000);

        let m = r.svc.metrics(&r.admin()).unwrap();
        assert_eq!(
            (m.addresses_created, m.invoices, m.payments, m.received_sat),
            (3, 3, 2, 11_000)
        );
        assert_eq!((m.now, m.online_since), (T0 + 2 * DAY_SECS, T0));
        let w: Vec<(&str, bool, u64, u64)> = m
            .windows
            .iter()
            .map(|w| (w.label.as_str(), w.available, w.count, w.sat))
            .collect();
        assert_eq!(
            w,
            [
                ("24h", true, 2, 11_000),
                ("7d", false, 2, 11_000),
                ("30d", false, 2, 11_000),
                ("365d", false, 2, 11_000)
            ]
        );
        assert!(m.sweep.enabled && m.sweep.due && m.sweep.received_sat == 11_000);

        // Hourly buckets for a day, gap-filled, ending with the current hour.
        let day = r
            .svc
            .payment_series(&r.admin(), SeriesParams { range: Range::Day })
            .unwrap();
        assert_eq!((day.points.len(), day.bucket_secs, day.online_since), (24, 3_600, T0));
        assert_eq!(day.points.iter().map(|p| p.count).sum::<u64>(), 2);
        let last = day.points.last().unwrap();
        assert!(last.start <= T0 + 2 * DAY_SECS && T0 + 2 * DAY_SECS < last.start + 3_600);
        assert_eq!(last.count, 2);
        for (range, n, width) in [
            (Range::Week, 7, DAY_SECS),
            (Range::Month, 30, DAY_SECS),
            (Range::Year, 52, 7 * DAY_SECS),
        ] {
            let s = r.svc.payment_series(&r.admin(), SeriesParams { range }).unwrap();
            assert_eq!((s.points.len(), s.bucket_secs, s.range), (n, width, range));
            assert_eq!(s.points.iter().map(|p| p.sat).sum::<u64>(), 11_000);
        }
    }

    #[tokio::test]
    async fn the_replay_cache_follows_the_window_and_the_creation_rate() {
        let r = rig(|_| {}).await;
        assert_eq!(r.svc.pow.capacity(), crate::pow::MIN_CAPACITY);
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "pow_window_secs": 3_600, "rate_global_per_min": 10_000 })),
            )
            .unwrap();
        assert_eq!(r.svc.pow.capacity(), crate::pow::capacity_for(10_000, 3_600));
        assert!(r.svc.pow.capacity() > crate::pow::MIN_CAPACITY);
        r.svc.reset_settings(&r.admin()).unwrap();
        assert_eq!(r.svc.pow.capacity(), crate::pow::MIN_CAPACITY);
    }

    #[tokio::test]
    async fn settings_change_live_persist_and_reset() {
        let r = rig(|_| {}).await;
        let v = r.svc.get_settings(&r.admin()).unwrap();
        assert!(v.overridden.is_empty() && !v.restart_pending);
        assert_eq!(v.settings, v.defaults);
        assert_eq!((v.fixed.network.as_str(), v.fixed.announce), ("regtest", false));
        assert_eq!(v.fixed.first_address, r.svc.first_address().unwrap());
        assert_eq!(v.operators.len(), 1);
        assert_eq!(v.operators[0].source, "environment");

        let v = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "pow_bits": 12, "name": "Shop", "min_confirmations": 3 })),
            )
            .unwrap();
        assert_eq!(v.overridden, ["name", "pow_bits", "min_confirmations"]);
        assert!(!v.restart_pending, "no relay change, no restart");
        let info = r.svc.info(&stranger()).unwrap();
        assert_eq!(
            (info.pow_bits, info.name.as_str(), info.min_confirmations),
            (12, "Shop", 3)
        );
        assert_eq!(r.svc.pow.bits(), 12);

        // Invalid changes are refused and leave everything as it was.
        let bad = r.svc.update_settings(
            &r.admin(),
            patch(serde_json::json!({ "min_amount_sat": 10_000_000_000u64 })),
        );
        assert!(msg(bad).contains("min_amount_sat exceeds"));
        assert_eq!(r.svc.settings().pow_bits, 12);

        // A new relay list is applied by a restart.
        let v = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "relays": ["wss://new.example"] })),
            )
            .unwrap();
        assert!(v.restart_pending);
        tokio::time::timeout(std::time::Duration::from_secs(1), r.svc.restart_requested())
            .await
            .unwrap();
        r.svc.restarted();
        assert!(!r.svc.get_settings(&r.admin()).unwrap().restart_pending);

        // Going back to the environment, which also restarts for the relays.
        let v = r.svc.reset_settings(&r.admin()).unwrap();
        assert!(v.overridden.is_empty() && v.restart_pending);
        assert_eq!(r.svc.settings().pow_bits, 4);
        r.svc.restarted();
        let v = r.svc.reset_settings(&r.admin()).unwrap();
        assert!(!v.restart_pending, "nothing to reconnect");

        let log = r.svc.audit_log(&r.admin(), AuditParams { limit: Some(10) }).unwrap();
        let actions: Vec<&str> = log.entries.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(
            actions,
            ["reset_settings", "reset_settings", "update_settings", "update_settings"]
        );
        assert_eq!(log.entries[3].actor, r.admin_keys.public_key().to_hex());
        assert!(log.entries[3].detail.contains("\"pow_bits\":12"));
        assert_eq!(
            code(r.svc.audit_log(&r.admin(), AuditParams { limit: Some(0) })),
            "invalid_params"
        );
        assert_eq!(
            r.svc
                .audit_log(&r.admin(), AuditParams::default())
                .unwrap()
                .entries
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn stored_settings_survive_restarts_unless_they_no_longer_fit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keys = Keys::generate();
        let mut cfg = crate::config::tests::load(&crate::config::tests::base()).unwrap();
        cfg.admins = [keys.public_key().to_hex()].into();
        cfg.data_dir = dir.path().to_path_buf();
        {
            let (svc, _f) = on_disk(&cfg, &path, T0).await;
            svc.update_settings(
                &admin_of(&keys, T0, 1),
                patch(serde_json::json!({ "default_expiry_secs": 7200, "sweep": { "mode": "coinjoin" } })),
            )
            .unwrap();
            svc.control(
                &admin_of(&keys, T0, 2),
                ControlParams {
                    action: ControlAction::Stop,
                },
            )
            .unwrap();
        }
        let (svc, _f) = on_disk(&cfg, &path, T0 + 5).await;
        assert_eq!(svc.settings().default_expiry_secs, 7200);
        assert_eq!(svc.settings().sweep.mode, SweepMode::Coinjoin);
        assert!(svc.is_paused(), "stop survives a restart");
        assert_eq!(svc.online_since, T0);
        drop(svc);

        // The environment changed so that the stored value is out of range.
        let mut tight = cfg.clone();
        tight.max_expiry_secs = 3_600;
        let (svc, _f) = on_disk(&tight, &path, T0).await;
        assert_eq!(svc.settings().default_expiry_secs, 3_600);
        let w = svc.health(&admin_of(&keys, T0, 3)).await.unwrap().warnings;
        assert!(w.iter().any(|w| w.contains("saved settings were not applied")), "{w:?}");
        // Saving anything valid clears the warning.
        svc.update_settings(
            &admin_of(&keys, T0, 4),
            patch(serde_json::json!({ "default_expiry_secs": 600 })),
        )
        .unwrap();
        assert!(svc
            .get_settings(&admin_of(&keys, T0, 5))
            .unwrap()
            .warnings
            .iter()
            .all(|w| !w.contains("saved")));
        drop(svc);

        // Unreadable stored settings are ignored the same way.
        Db::open(&path)
            .unwrap()
            .meta_set(META_SETTINGS, Some("{not json"))
            .unwrap();
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert_eq!(svc.settings().default_expiry_secs, 3_600);
        assert!(svc
            .settings_problem
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains("could not be read"));
        // A reset also clears the problem.
        svc.reset_settings(&admin_of(&keys, T0, 6)).unwrap();
        assert!(svc.settings_problem.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn operator_keys_can_be_added_in_any_format_and_removed() {
        let r = rig(|_| {}).await;
        let new = Keys::generate();
        let hex = new.public_key().to_hex();
        let profile = nostr_sdk::nips::nip19::Nip19Profile::new(
            new.public_key(),
            [nostr_sdk::RelayUrl::parse("wss://relay.example").unwrap()],
        );
        let forms = [
            hex.clone(),
            new.public_key().to_bech32().unwrap(),
            format!("nostr:{}", profile.to_bech32().unwrap()),
        ];
        for form in &forms {
            let v = r
                .svc
                .add_operator(
                    &r.admin(),
                    AddOperatorParams {
                        pubkey: form.clone(),
                        label: Some(" till 2 ".into()),
                    },
                )
                .unwrap();
            assert_eq!(v.operators.len(), 2);
            assert_eq!(
                (v.operators[1].pubkey.as_str(), v.operators[1].label.as_str()),
                (hex.as_str(), "till 2")
            );
            assert_eq!(v.operators[1].source, "dashboard");
        }
        // The new key is an operator now.
        let as_new = admin_of(&new, T0, 1);
        assert!(r.svc.stats(&as_new).is_ok());

        let bad = |pubkey: &str, label: Option<&str>| {
            msg(r.svc.add_operator(
                &r.admin(),
                AddOperatorParams {
                    pubkey: pubkey.into(),
                    label: label.map(Into::into),
                },
            ))
        };
        assert!(bad("npub1nope", None).contains("hex key, npub or nprofile"));
        assert!(bad(&hex, Some("a\u{202E}b")).contains("label"));
        assert!(bad(&r.admin_keys.public_key().to_hex(), None).contains("already an operator"));
        for _ in 1..MAX_EXTRA_OPERATORS {
            r.svc
                .add_operator(
                    &r.admin(),
                    AddOperatorParams {
                        pubkey: Keys::generate().public_key().to_hex(),
                        label: None,
                    },
                )
                .unwrap();
        }
        assert!(bad(&Keys::generate().public_key().to_hex(), None).contains("at most 20"));
        // Relabelling an existing one still works at the limit.
        r.svc
            .add_operator(
                &r.admin(),
                AddOperatorParams {
                    pubkey: hex.clone(),
                    label: None,
                },
            )
            .unwrap();

        let rm = |pubkey: &str| {
            r.svc
                .remove_operator(&r.admin(), RemoveOperatorParams { pubkey: pubkey.into() })
        };
        assert!(msg(rm(&r.admin_keys.public_key().to_hex())).contains("only be removed on the host"));
        assert!(msg(rm("x")).contains("hex key"));
        assert_eq!(code(rm(&Keys::generate().public_key().to_hex())), "not_found");
        rm(&new.public_key().to_bech32().unwrap()).unwrap();
        assert_eq!(code(r.svc.stats(&admin_of(&new, T0, 2))), "unauthorized");
        let actions: Vec<String> = r
            .svc
            .audit_log(&r.admin(), AuditParams::default())
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions[0], "remove_operator");
        assert!(actions.iter().filter(|a| *a == "add_operator").count() >= 3);
    }

    #[tokio::test]
    async fn the_last_operator_cannot_lock_everyone_out() {
        // No operators in the environment: the public opened the service.
        let r = rig(|c| c.admins.clear()).await;
        let first = Keys::generate();
        // Seed one operator directly, as the host would.
        r.svc
            .db
            .add_operator(&OperatorRow {
                pubkey: first.public_key().to_hex(),
                label: String::new(),
                added_at: T0,
                added_by: "host".into(),
            })
            .unwrap();
        r.svc
            .extra_operators
            .write()
            .unwrap()
            .insert(first.public_key().to_hex());
        r.svc
            .update_settings(
                &admin_of(&first, T0, 1),
                patch(serde_json::json!({ "public_invoicing": false })),
            )
            .unwrap();
        let out = r.svc.remove_operator(
            &admin_of(&first, T0, 2),
            RemoveOperatorParams {
                pubkey: first.public_key().to_hex(),
            },
        );
        assert!(msg(out).contains("last operator"));
        // With public invoicing on, leaving would still end all management
        // for good (issue #8), so it is refused too.
        r.svc
            .update_settings(
                &admin_of(&first, T0, 3),
                patch(serde_json::json!({ "public_invoicing": true })),
            )
            .unwrap();
        let out = r.svc.remove_operator(
            &admin_of(&first, T0, 6),
            RemoveOperatorParams {
                pubkey: first.public_key().to_hex(),
            },
        );
        assert!(msg(out).contains("nobody could manage the service"));
        // Once someone else can operate, the first operator may leave.
        let second = Keys::generate();
        r.svc
            .db
            .add_operator(&OperatorRow {
                pubkey: second.public_key().to_hex(),
                label: String::new(),
                added_at: T0,
                added_by: "host".into(),
            })
            .unwrap();
        r.svc
            .extra_operators
            .write()
            .unwrap()
            .insert(second.public_key().to_hex());
        r.svc
            .remove_operator(
                &admin_of(&first, T0, 4),
                RemoveOperatorParams {
                    pubkey: first.public_key().to_hex(),
                },
            )
            .unwrap();
        assert!(msg(r
            .svc
            .update_settings(&admin_of(&first, T0, 5), patch(serde_json::json!({}))))
        .contains("not authorized"));
    }

    #[tokio::test]
    async fn stop_start_and_restart() {
        let r = rig(|_| {}).await;
        let c = r
            .svc
            .control(
                &r.admin(),
                ControlParams {
                    action: ControlAction::Stop,
                },
            )
            .unwrap();
        assert!(c.paused && !c.restart_pending);
        let p = CreateInvoiceParams {
            amount_sat: 5_000,
            memo: None,
            expiry_secs: None,
        };
        assert_eq!(code(r.svc.create_invoice(&r.admin(), p.clone())), "paused");
        assert_eq!(
            code(r.svc.create_invoice(&public(&Keys::generate(), 4, T0), p.clone())),
            "paused"
        );
        // Existing invoices can still be looked up and are still watched.
        let c = r
            .svc
            .control(
                &r.admin(),
                ControlParams {
                    action: ControlAction::Start,
                },
            )
            .unwrap();
        assert!(!c.paused);
        let inv = r.svc.create_invoice(&r.admin(), p).unwrap();
        r.svc
            .control(
                &r.admin(),
                ControlParams {
                    action: ControlAction::Stop,
                },
            )
            .unwrap();
        assert!(r
            .svc
            .get_invoice(&stranger(), GetInvoiceParams { id: inv.id.clone() })
            .is_ok());
        assert_eq!(r.svc.poll_once().await.unwrap(), 0);

        let c = r
            .svc
            .control(
                &r.admin(),
                ControlParams {
                    action: ControlAction::Restart,
                },
            )
            .unwrap();
        assert!(c.restart_pending);
        r.svc.restart_requested().await;
        r.svc.restarted();
        let h = r.svc.health(&r.admin()).await.unwrap();
        assert_eq!((h.service.restarts, h.service.restart_pending), (1, false));
    }

    #[tokio::test]
    async fn relays_are_reverted_on_request_of_the_supervisor() {
        let r = rig(|_| {}).await;
        let env = r.svc.cfg.relays.clone();
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "relays": ["wss://a.example"] })))
            .unwrap();
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "relays": ["wss://b.example"] })))
            .unwrap();
        r.svc
            .revert_connection(vec!["wss://a.example".into()], Default::default(), "test")
            .unwrap();
        assert_eq!(r.svc.settings().relays, ["wss://a.example"]);
        assert!(r
            .svc
            .get_settings(&r.admin())
            .unwrap()
            .overridden
            .contains(&"relays".to_string()));
        // Reverting to the environment list removes the override.
        r.svc
            .revert_connection(env.clone(), Default::default(), "test")
            .unwrap();
        assert_eq!(r.svc.settings().relays, env);
        assert!(r.svc.get_settings(&r.admin()).unwrap().overridden.is_empty());
        let log = r.svc.audit_log(&r.admin(), AuditParams::default()).unwrap();
        assert_eq!(
            (log.entries[0].actor.as_str(), log.entries[0].action.as_str()),
            ("service", "revert_connection")
        );
    }

    #[tokio::test]
    async fn relays_are_checked_end_to_end_and_kept_for_health() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let good = relay.url().await.to_string();
        let r = rig(|c| c.relays = vec![good.clone(), "ws://127.0.0.1:9".into()]).await;
        assert!(
            r.svc.health(&r.admin()).await.unwrap().relay_health.is_empty(),
            "none before the first check"
        );
        let report = r.svc.check_relays(&r.admin()).await.unwrap();
        let status: Vec<(&str, &str)> = report
            .relays
            .iter()
            .map(|h| (h.relay.as_str(), h.status.as_str()))
            .collect();
        assert_eq!(status, [(good.as_str(), "ok"), ("ws://127.0.0.1:9", "down")]);
        assert_eq!(r.svc.health(&r.admin()).await.unwrap().relay_health, report.relays);
        // Each check is kept for the history, one result per relay.
        let h = r
            .svc
            .relay_history(
                &r.admin(),
                RelayHistoryParams {
                    window: Some("15m".into()),
                },
            )
            .unwrap();
        let tally: Vec<(u32, u32)> = h.relays.iter().map(|s| (s.checks, s.check_failures)).collect();
        assert_eq!(tally, [(1, 0), (1, 1)]);

        // A check already running is not started twice.
        r.svc.relay_health_busy.store(true, Ordering::SeqCst);
        assert_eq!(code(r.svc.check_relays(&r.admin()).await), "rate_limited");
        assert!(r.svc.refresh_relay_health().await.is_none());
        r.svc.relay_health_busy.store(false, Ordering::SeqCst);

        // A few checks a minute, then a pause.
        for _ in 0..4 {
            r.svc.check_relays(&r.admin()).await.unwrap();
        }
        assert_eq!(code(r.svc.check_relays(&r.admin()).await), "rate_limited");
        r.set_now(T0 + 61);
        assert!(r.svc.check_relays(&r.admin()).await.is_ok());
    }

    #[tokio::test]
    async fn relay_history_buckets_checks_and_sends_per_relay() {
        let r = rig(|c| c.relays = vec!["wss://a.example".into(), "wss://b.example/".into()]).await;
        let admin = r.admin();
        let history = |w: &str| {
            r.svc
                .relay_history(&admin, RelayHistoryParams { window: Some(w.into()) })
                .unwrap()
        };
        // Nothing recorded yet: every bucket of every live relay is empty.
        let empty = history("15m");
        assert_eq!(
            (empty.window.as_str(), empty.bucket_secs, empty.relays.len()),
            ("15m", 60, 2)
        );
        assert!(empty
            .relays
            .iter()
            .all(|s| s.points.len() == 15 && s.points.iter().all(|p| p.ok + p.fail == 0)));
        assert_eq!(empty.relays[0].avg_ms, None);

        // A check, replies, a failure, a trailing slash, and a relay no longer in the list.
        r.svc.record_relay_event("wss://a.example", "check", true, Some(100));
        r.svc.record_relay_event("wss://a.example/", "send", true, Some(50));
        r.svc.record_relay_event("wss://a.example", "send", false, Some(9_000));
        r.set_now(T0 + 130);
        r.svc.record_relay_event("wss://b.example", "check", false, None);
        r.svc.record_relay_event("wss://old.example", "send", true, None);
        // Not yet happened (the clock moved back): not counted.
        r.svc
            .db
            .record_relay_event(&RelayEventRow {
                at: T0 + 10_000,
                relay: "wss://a.example".into(),
                kind: "send".into(),
                ok: false,
                ms: None,
            })
            .unwrap();

        let h = history("15m");
        let names: Vec<&str> = h.relays.iter().map(|s| s.relay.as_str()).collect();
        assert_eq!(names, ["wss://a.example", "wss://b.example", "wss://old.example"]);
        let a = &h.relays[0];
        assert_eq!((a.checks, a.check_failures, a.sends, a.send_failures), (1, 0, 2, 1));
        assert_eq!(a.avg_ms, Some(75), "failures do not count towards the round trip");
        let b = &h.relays[1];
        assert_eq!((b.checks, b.check_failures, b.sends, b.avg_ms), (1, 1, 0, None));
        assert_eq!(h.until - h.since, 900);
        assert_eq!(a.points.iter().map(|p| p.ok + p.fail).sum::<u32>(), 3);
        assert_eq!(a.points.last().unwrap().start + 60, h.until);

        // Longer windows use coarser buckets over the same results.
        for (w, secs, n) in [
            ("1h", 300, 12),
            ("12h", 1_800, 24),
            ("1d", 3_600, 24),
            ("1w", 21_600, 28),
        ] {
            let h = history(w);
            assert_eq!((h.bucket_secs, h.relays[0].points.len()), (secs, n), "{w}");
            assert_eq!(h.relays[0].sends, 2, "{w}");
        }
        // The default is an hour; anything else is refused.
        let default = r.svc.relay_history(&admin, RelayHistoryParams::default()).unwrap();
        assert_eq!(default.window, "1h");
        let bad = RelayHistoryParams {
            window: Some("2h".into()),
        };
        assert_eq!(code(r.svc.relay_history(&admin, bad)), "invalid_params");

        // A result older than the window is left out of it.
        r.set_now(T0 + 2_000);
        assert_eq!(history("15m").relays[0].sends, 0);
        assert_eq!(history("1h").relays[0].sends, 2);

        // A database that cannot take the result does not disturb serving.
        r.svc.db.execute_raw("DROP TABLE relay_events");
        r.svc.record_relay_event("wss://a.example", "send", true, None);
    }

    #[test]
    fn only_names_this_service_gives_are_backups() {
        assert_eq!(backup_time("deadhop-001700000000-000.sqlite"), Some(1_700_000_000));
        assert_eq!(backup_time("deadhop-001700000000-042.sqlite"), Some(1_700_000_000));
        for other in [
            "notes.txt",
            "deadhop-x.sqlite",
            "deadhop-001700000000.sqlite",
            "deadhop-01700000000-000.sqlite",
            "deadhop-001700000000-00.sqlite",
            "deadhop-00170000000a-000.sqlite",
            "deadhop-001700000000-000.sqlite-wal",
            "cvmpay-001700000000-000.sqlite",
        ] {
            assert_eq!(backup_time(other), None, "{other}");
        }
    }

    #[tokio::test]
    async fn backups_are_listed_newest_first() {
        let r = rig(|_| {}).await;
        assert!(
            r.svc.list_backups(&r.admin()).unwrap().backups.is_empty(),
            "no directory yet"
        );
        r.create(5_000);
        let first = r.svc.backup(&r.admin()).unwrap();
        r.set_now(T0 + 60);
        let second = r.svc.backup(&r.admin()).unwrap();
        let dir = r.svc.cfg.data_dir.join(BACKUP_DIR);
        fs::write(dir.join("notes.txt"), b"keep").unwrap();
        fs::write(dir.join("deadhop-x.sqlite"), b"not ours").unwrap();
        let list = r.svc.list_backups(&r.admin()).unwrap().backups;
        assert_eq!(list, [second.clone(), first]);
        assert_eq!(list[0].created_at, T0 + 60);
        assert!(list[0].size_bytes > 0);
        // The count in health agrees with the list.
        assert_eq!(r.svc.health(&r.admin()).await.unwrap().database.backups, 2);
        // Listing changes nothing, so it leaves no audit entry.
        let log = r.svc.audit_log(&r.admin(), AuditParams::default()).unwrap();
        assert_eq!(log.entries[0].detail, second.file);

        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"not a directory").unwrap();
        assert_eq!(code(r.svc.list_backups(&r.admin())), "internal");
    }

    #[tokio::test]
    async fn backups_are_private_numbered_and_pruned() {
        use std::os::unix::fs::PermissionsExt;
        let r = rig(|_| {}).await;
        r.create(5_000);
        let b = r.svc.backup(&r.admin()).unwrap();
        assert_eq!(b.file, format!("deadhop-{T0:012}-000.sqlite"));
        assert!(b.size_bytes > 0 && b.created_at == T0);
        let dir = r.svc.cfg.data_dir.join(BACKUP_DIR);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let path = dir.join(&b.file);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Db::open(&path).unwrap().totals().unwrap().pending, 1);

        // Same second: next sequence number. Unrelated files are left alone.
        fs::write(dir.join("notes.txt"), b"keep").unwrap();
        assert_eq!(
            r.svc.backup(&r.admin()).unwrap().file,
            format!("deadhop-{T0:012}-001.sqlite")
        );
        for i in 0..12 {
            r.set_now(T0 + 1 + i);
            r.svc.backup(&r.admin()).unwrap();
        }
        let left: Vec<String> = r.svc.backups().unwrap().into_iter().map(|b| b.file).collect();
        assert_eq!(left.len(), BACKUPS_KEPT);
        assert_eq!(left[0], format!("deadhop-{:012}-000.sqlite", T0 + 12));
        assert!(dir.join("notes.txt").exists());

        // A data directory that cannot hold backups.
        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"x").unwrap();
        assert_eq!(code(r.svc.backup(&r.admin())), "internal");
    }

    #[tokio::test]
    async fn wiping_is_confirmed_backed_up_and_never_reuses_addresses() {
        let r = rig(|_| {}).await;
        let first = r.create(5_000);
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "pow_bits": 9 })))
            .unwrap();
        let wipe = |confirm: &str, include_settings, force| {
            r.svc.wipe(
                &r.admin(),
                WipeParams {
                    confirm: confirm.into(),
                    include_settings,
                    force,
                },
            )
        };
        assert!(msg(wipe("wipe", false, true)).contains("type WIPE"));
        assert!(msg(wipe("WIPE", false, false)).contains("1 invoice(s) may still be paid"));
        let w = wipe("WIPE", false, true).unwrap();
        assert_eq!(w.deleted, 1);
        assert!(r.svc.cfg.data_dir.join(BACKUP_DIR).join(&w.backup.file).exists());
        assert_eq!(r.svc.settings().pow_bits, 9, "settings kept");
        let next = r.create(5_000);
        assert_ne!(next.address, first.address);
        assert_eq!(r.svc.metrics(&r.admin()).unwrap().addresses_created, 2);

        // Nothing watched any more: no force needed. Settings can go too.
        r.svc
            .db
            .update(&next.id, crate::db::Status::Expired, 0, 0, None)
            .unwrap();
        r.set_now(T0 + 30 * DAY_SECS);
        let w = wipe("WIPE", true, false).unwrap();
        assert_eq!(w.deleted, 1);
        assert_eq!(r.svc.settings().pow_bits, 4, "settings back to the environment");
        let log = r.svc.audit_log(&r.admin(), AuditParams::default()).unwrap();
        assert!(log.entries[0].detail.contains("settings true"));

        // Wiping settings that changed the relays reconnects.
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "relays": ["wss://x.example"] })))
            .unwrap();
        r.svc.restarted();
        wipe("WIPE", true, false).unwrap();
        assert!(r.svc.restart_pending.load(Ordering::Relaxed));

        // A failing backup stops the wipe.
        let dir = r.svc.cfg.data_dir.join(BACKUP_DIR);
        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"x").unwrap();
        let _ = r.create(5_000);
        assert_eq!(code(wipe("WIPE", false, true)), "internal");
        assert_eq!(r.svc.metrics(&r.admin()).unwrap().invoices, 1);
    }

    #[tokio::test]
    async fn an_environment_relay_list_is_not_rechecked_on_unrelated_changes() {
        // Accepted as configured on the host (for example ws:// on mainnet, which
        // only warns), but the same list would be refused from the dashboard.
        let r = rig(|c| c.relays = vec!["ws://".into()]).await;
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "pow_bits": 21 })))
            .unwrap();
        let out = r
            .svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "relays": ["ws://"] })));
        assert!(msg(out).contains("not a valid url"));
    }

    #[tokio::test]
    async fn stored_relays_are_checked_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let cfg = crate::config::tests::load(&crate::config::tests::base()).unwrap();
        Db::open(&path)
            .unwrap()
            .meta_set(META_SETTINGS, Some(r#"{"relays":["https://x"]}"#))
            .unwrap();
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert_eq!(svc.settings().relays, cfg.relays);
        assert!(svc
            .settings_problem
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains("ws:// or wss://"));
    }

    #[tokio::test]
    async fn proxy_passwords_stay_hidden_and_the_host_can_lock_the_proxy() {
        let r = rig(|_| {}).await;
        let v = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": { "list": [
                    { "url": "socks5://me:hunter2@127.0.0.1:9050", "name": "tor" }
                ] } })),
            )
            .unwrap();
        assert!(!v.restart_pending, "the pool picks the proxy; relays need no restart");
        let shown = &v.settings.proxies.list[0];
        assert_eq!(
            (shown.url.as_str(), shown.name.as_str()),
            ("socks5://me:***@127.0.0.1:9050", "tor")
        );
        assert!(!v.fixed.proxy_locked);
        assert_eq!(
            r.svc.settings().proxies.list[0].url,
            "socks5://me:hunter2@127.0.0.1:9050",
            "the live value is intact"
        );
        let log = r.svc.audit_log(&r.admin(), AuditParams::default()).unwrap();
        assert!(!log.entries[0].detail.contains("hunter2"), "{}", log.entries[0].detail);
        assert!(msg(r.svc.update_settings(
            &r.admin(),
            patch(serde_json::json!({ "proxies": { "list": [{ "url": "ftp://x:1" }] } }))
        ))
        .contains("scheme"));
        assert!(r
            .svc
            .get_settings(&r.admin())
            .unwrap()
            .overridden
            .contains(&"proxies.list".to_string()));

        // The old single-address form still works, and becomes a one-entry list.
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxy": "socks5://127.0.0.1:1" })),
            )
            .unwrap();
        assert_eq!(r.svc.settings().proxies.list.len(), 1);
        assert_eq!(r.svc.settings().proxies.list[0].url, "socks5://127.0.0.1:1");
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "proxy": "" })))
            .unwrap();
        assert!(r.svc.settings().proxies.list.is_empty());

        // Every proxy setting is behind the host's lock; others are not.
        let locked = rig(|c| c.proxy_locked = true).await;
        for p in [
            serde_json::json!({ "proxy": "" }),
            serde_json::json!({ "proxies": { "list": [] } }),
            serde_json::json!({ "proxies": { "transparent": true } }),
            serde_json::json!({ "proxies": { "offline": "open" } }),
            serde_json::json!({ "proxies": { "groups": [] } }),
            serde_json::json!({ "proxies": { "default": "direct" } }),
            serde_json::json!({ "proxies": { "default_keys": {} } }),
        ] {
            let out = locked.svc.update_settings(&locked.admin(), patch(p.clone()));
            assert!(msg(out).contains("locked on the host"), "{p}");
        }
        assert!(locked.svc.get_settings(&locked.admin()).unwrap().fixed.proxy_locked);
        locked
            .svc
            .update_settings(&locked.admin(), patch(serde_json::json!({ "pow_bits": 10 })))
            .unwrap();
    }

    #[tokio::test]
    async fn reordering_a_list_with_hidden_passwords_keeps_every_password() {
        let r = rig(|_| {}).await;
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": { "list": [
                    { "id": "a", "url": "socks5://u:one@10.0.0.1:1080" },
                    { "id": "b", "url": "http://u:two@10.0.0.2:3128" }
                ] } })),
            )
            .unwrap();
        // The dashboard holds what it was shown, and sends it back reordered.
        let shown = r.svc.get_settings(&r.admin()).unwrap().settings.proxies.list;
        assert_eq!(shown[0].url, "socks5://u:***@10.0.0.1:1080");
        let reordered = serde_json::json!({ "proxies": { "list": [
            { "id": "b", "url": shown[1].url },
            { "id": "a", "url": shown[0].url },
        ] } });
        r.svc.update_settings(&r.admin(), patch(reordered)).unwrap();
        let live = r.svc.settings().proxies.list.clone();
        assert_eq!(
            live.iter().map(|e| (e.id.as_str(), e.url.as_str())).collect::<Vec<_>>(),
            [
                ("b", "http://u:two@10.0.0.2:3128"),
                ("a", "socks5://u:one@10.0.0.1:1080")
            ]
        );
        // What is stored (and so what a restart loads) has the same secrets.
        let stored = r.svc.stored_patch().unwrap();
        let list = stored.proxies.unwrap().list.unwrap();
        assert!(list.iter().all(|e| !e.url.contains("***")));
        // A hidden password with nothing to restore it from is refused.
        let bad = patch(serde_json::json!({ "proxies": { "list": [{ "url": "socks5://u:***@10.9.9.9:1" }] } }));
        assert!(msg(r.svc.update_settings(&r.admin(), bad)).contains("hidden"));
        assert_eq!(r.svc.settings().proxies.list.len(), 2);
    }

    /// A local port nobody listens on.
    async fn closed_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    fn try_proxy(proxy: Option<String>) -> CheckProxyParams {
        CheckProxyParams { proxy, id: None }
    }

    #[tokio::test]
    async fn checking_a_proxy_is_admitted_recorded_and_budgeted_like_a_change() {
        let r = rig(|_| {}).await;
        let dead = format!("socks5://user:secret@127.0.0.1:{}", closed_port().await);

        // Another proxy: tested, recorded with its password hidden, not
        // remembered as the live proxy's health.
        let c = r.svc.check_proxy(&r.admin(), try_proxy(Some(dead))).await.unwrap();
        assert_eq!(c.status, "failed");
        assert!(c.proxy.contains("***") && !c.proxy.contains("secret"));
        assert!(r.svc.health(&r.admin()).await.unwrap().proxy_check.is_none());
        let last = r.svc.db.audit_recent(1).unwrap().remove(0);
        assert_eq!(last.action, "check_proxy");
        assert!(last.detail.ends_with(": failed") && !last.detail.contains("secret"));

        // The live proxy (none here) is remembered for health.
        let c = r.svc.check_proxy(&r.admin(), try_proxy(None)).await.unwrap();
        assert_eq!(c.status, "direct");
        assert_eq!(
            r.svc.health(&r.admin()).await.unwrap().proxy_check.unwrap().status,
            "direct"
        );
        assert_eq!(r.svc.db.audit_recent(1).unwrap()[0].detail, "no proxy: direct");

        // Not a proxy address.
        assert!(msg(r.svc.check_proxy(&r.admin(), try_proxy(Some("ftp://x:1".into()))).await).contains("proxy"));

        // Six per minute, all operators together.
        for _ in 0..4 {
            r.svc.check_proxy(&r.admin(), try_proxy(None)).await.unwrap();
        }
        assert!(matches!(
            r.svc.check_proxy(&r.admin(), try_proxy(None)).await,
            Err(Error::RateLimited)
        ));
    }

    #[tokio::test]
    async fn only_one_proxy_check_runs_at_a_time() {
        let r = rig(|_| {}).await;
        // A proxy that accepts and never answers holds the first check.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(silent.accept().await.unwrap().0);
            }
        });
        let proxy = format!("socks5://127.0.0.1:{port}");
        let (a, b) = (r.admin(), r.admin());
        let first = r.svc.check_proxy(&a, try_proxy(Some(proxy.clone())));
        let second = async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            r.svc.check_proxy(&b, try_proxy(Some(proxy.clone()))).await
        };
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap().relays[0].code, "ETIMEDOUT");
        assert!(matches!(second, Err(Error::RateLimited)));
        hold.abort();
    }

    #[tokio::test]
    async fn a_locked_proxy_can_only_be_tested_as_it_is() {
        let r = rig(|c| c.proxy_locked = true).await;
        let out = r
            .svc
            .check_proxy(&r.admin(), try_proxy(Some("socks5://127.0.0.1:9050".into())))
            .await;
        assert!(msg(out).contains("locked on the host"));
        assert!(r.svc.check_proxy(&r.admin(), try_proxy(None)).await.is_ok());
    }

    fn lookup(name: &str) -> ResolveI2pNameParams {
        ResolveI2pNameParams { name: name.into() }
    }

    /// Point the service at a fake I2P router (as its I2P proxy) and at
    /// registries on the given hosts.
    fn use_router(r: &Rig, port: u16, hosts: &[&str]) {
        let regs: Vec<String> = hosts.iter().map(|h| format!("http://{h}/jump?q={{name}}")).collect();
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": {
                    "list": [{ "id": "router", "url": format!("http://127.0.0.1:{port}"), "i2p": true }],
                    "i2p_registries": regs,
                } })),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn an_i2p_name_is_asked_of_every_registry_through_the_i2p_proxy() {
        use crate::i2p::tests::{fake_destination, fake_router, page_with};
        let pages = [
            ("one.i2p".to_string(), page_with(&fake_destination(1))),
            ("two.i2p".to_string(), page_with(&fake_destination(1))),
            ("other.i2p".to_string(), page_with(&fake_destination(2))),
            ("blank.i2p".to_string(), "HTTP/1.1 404 Not Found\r\n\r\nno".to_string()),
        ]
        .into();
        let (port, _, task) = fake_router(pages).await;
        let r = rig(|_| {}).await;
        use_router(&r, port, &["blank.i2p", "one.i2p", "other.i2p", "two.i2p"]);
        let regs = r.svc.settings().proxies.i2p_registries.clone();
        let out = r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await.unwrap();
        assert_eq!(out.address, crate::i2p::b32_address(&fake_destination(1)).unwrap());
        assert_eq!(out.registry, regs[1]);
        assert_eq!(out.agreeing, [regs[1].clone(), regs[3].clone()]);
        assert_eq!(out.disagreeing.len(), 1);
        assert_eq!(out.disagreeing[0].registry, regs[2]);
        assert_eq!(out.unknown, [regs[0].clone()]);
        let last = r.svc.db.audit_recent(1).unwrap().remove(0);
        assert_eq!(last.action, "resolve_i2p_name");
        assert!(last.detail.starts_with(&format!("x.i2p: {}", out.address)));

        // Known nowhere, or no registry reachable: said plainly, and recorded.
        use_router(&r, port, &["blank.i2p"]);
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("knows x.i2p"));
        use_router(&r, port, &["gone.i2p"]);
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("could be reached"));
        assert!(r.svc.db.audit_recent(1).unwrap()[0].detail.contains("failed"));

        // Bad names never leave the machine.
        for bad in ["x.b32.i2p", "X.i2p", "x.onion", ""] {
            assert!(
                msg(r.svc.resolve_i2p_name(&r.admin(), lookup(bad)).await).contains(".i2p name"),
                "{bad}"
            );
        }
        // Four per minute, all operators together (three used above).
        use_router(&r, port, &["one.i2p"]);
        r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await.unwrap();
        assert!(matches!(
            r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await,
            Err(Error::RateLimited)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn an_i2p_lookup_needs_an_i2p_proxy_and_registries() {
        let r = rig(|_| {}).await;
        assert_eq!(
            code(r.svc.resolve_i2p_name(&stranger(), lookup("x.i2p")).await),
            "unauthorized"
        );
        // A plain HTTP proxy is never used for lookups.
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": { "list": [{ "url": "http://127.0.0.1:4444" }] } })),
            )
            .unwrap();
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("no I2P router proxy"));
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": {
                    "list": [{ "url": "http://127.0.0.1:4444", "i2p": true }],
                    "i2p_registries": []
                } })),
            )
            .unwrap();
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("no I2P name registries"));
        // Nothing was looked up, so nothing was recorded.
        assert!(r.svc.db.audit_recent(1).unwrap()[0].action != "resolve_i2p_name");
    }

    #[tokio::test]
    async fn only_one_i2p_lookup_runs_at_a_time() {
        let r = rig(|_| {}).await;
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": { "list": [{ "url": "http://127.0.0.1:4444", "i2p": true }] } })),
            )
            .unwrap();
        r.svc.i2p_lookup_busy.store(true, Ordering::SeqCst);
        assert_eq!(
            code(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await),
            "rate_limited"
        );
    }

    #[tokio::test]
    async fn an_i2p_router_without_an_address_is_refused() {
        // Saving never lets this through; settings applied some other way still must not panic.
        let r = rig(|_| {}).await;
        let mut s = r.svc.settings().clone();
        s.proxies.list = vec![serde_json::from_value(serde_json::json!({
            "id": "i2p", "name": "", "url": "", "i2p": true
        }))
        .unwrap()];
        r.svc.apply_settings(s);
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("has no address"));
    }

    #[tokio::test]
    async fn i2p_proxies_and_registries_are_checked_when_saved() {
        let r = rig(|_| {}).await;
        let save = |p: serde_json::Value| {
            r.svc
                .update_settings(&r.admin(), patch(serde_json::json!({ "proxies": p })))
        };
        assert!(msg(save(
            serde_json::json!({ "list": [{ "url": "socks5://127.0.0.1:1", "i2p": true }] })
        ))
        .contains("http://"));
        assert!(msg(save(serde_json::json!({ "list": [
            { "url": "http://127.0.0.1:1", "i2p": true },
            { "url": "http://127.0.0.1:2", "i2p": true }
        ] })))
        .contains("at most one"));
        assert!(msg(save(
            serde_json::json!({ "i2p_registries": ["http://example.com/?q={name}"] })
        ))
        .contains(".i2p"));
        assert!(msg(save(serde_json::json!({ "i2p_registries": ["http://a.i2p/?q="] }))).contains("{name}"));
        let five: Vec<String> = (0..5).map(|i| format!("http://r{i}.i2p/?q={{name}}")).collect();
        assert!(msg(save(serde_json::json!({ "i2p_registries": five }))).contains("at most 4"));
        assert!(msg(save(serde_json::json!({ "i2p_registries": [
            "http://a.i2p/?q={name}",
            "http://a.i2p/?q={name}"
        ] })))
        .contains("listed twice"));
        assert!(serde_json::from_value::<ProxyPatch>(serde_json::json!({ "registries": [] })).is_err());
        let v = save(serde_json::json!({ "list": [{ "id": "i2p", "url": "http://127.0.0.1:4444", "i2p": true }] }))
            .unwrap();
        assert!(v.settings.proxies.list[0].i2p);
        assert_eq!(v.settings.proxies.i2p_registries, crate::i2p::default_registries());
        assert!(v.overridden.contains(&"proxies.list".to_string()));
    }

    #[tokio::test]
    async fn an_i2p_router_is_only_used_by_the_rules_that_name_it() {
        let r = rig(|_| {}).await;
        let only = serde_json::json!({
            "list": [{ "id": "i2p", "url": "http://127.0.0.1:4444", "i2p": true }],
            "rules": [{ "match": ["*.i2p"], "to": { "proxy": "i2p" } }]
        });
        let v = r
            .svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "proxies": only })))
            .unwrap();
        assert!(v.settings.proxies.list[0].i2p);
        assert_eq!(v.settings.proxies.default, Destination::Direct);
    }

    #[tokio::test]
    async fn the_first_proxies_carry_the_default_route_unless_told_otherwise() {
        let added = |default: Option<serde_json::Value>| async move {
            let r = rig(|_| {}).await;
            let mut px = serde_json::json!({ "list": [
                { "id": "i2p", "url": "http://127.0.0.1:4444", "i2p": true },
                { "url": "socks5://127.0.0.1:9050" }
            ] });
            if let Some(d) = default {
                px["default"] = d;
            }
            let v = r
                .svc
                .update_settings(&r.admin(), patch(serde_json::json!({ "proxies": px })))
                .unwrap();
            (
                v.settings.proxies.default.clone(),
                v.settings.proxies.list[1].id.clone(),
            )
        };
        // From none to some, no default given: the first that is not an I2P router.
        let (default, id) = added(None).await;
        assert_eq!(default, Destination::Proxy(id));
        // Said otherwise: as said.
        let (default, _) = added(Some(serde_json::json!("direct"))).await;
        assert_eq!(default, Destination::Direct);
    }

    #[tokio::test]
    async fn locked_proxies_forbid_i2p_lookups() {
        let r = rig(|c| c.proxy_locked = true).await;
        assert!(msg(r.svc.resolve_i2p_name(&r.admin(), lookup("x.i2p")).await).contains("locked on the host"));
        let out = r.svc.update_settings(
            &r.admin(),
            patch(serde_json::json!({ "proxies": { "i2p_registries": [] } })),
        );
        assert!(msg(out).contains("locked on the host"));
    }

    #[tokio::test]
    async fn relays_can_be_given_names_to_show() {
        let r = rig(|_| {}).await;
        let relay = r.svc.settings().relays[0].clone();
        let v = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "relay_names": { (relay.clone()): "nostr-not.i2p" } })),
            )
            .unwrap();
        assert_eq!(v.settings.relay_names[&relay], "nostr-not.i2p");
        assert!(v.overridden.contains(&"relay_names".to_string()));
        // Only for listed relays, and only plain short text.
        let other = patch(serde_json::json!({ "relay_names": { "wss://gone.example": "x" } }));
        assert!(msg(r.svc.update_settings(&r.admin(), other)).contains("not a listed relay"));
        let long = patch(serde_json::json!({ "relay_names": { (relay.clone()): "x".repeat(61) } }));
        assert!(msg(r.svc.update_settings(&r.admin(), long)).contains("relay names"));
        let ctl = patch(serde_json::json!({ "relay_names": { (relay.clone()): "a\u{7}b" } }));
        assert!(msg(r.svc.update_settings(&r.admin(), ctl)).contains("relay names"));
        assert_eq!(r.svc.settings().relay_names[&relay], "nostr-not.i2p");
        // A name does not restart the connections.
        assert!(!r.svc.restart_pending.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_privacy_audit_reports_what_it_can_measure() {
        let r = rig(|_| {}).await;
        let a = r.svc.privacy_audit(&r.admin()).await.unwrap();
        // No proxy in the test configuration: relays see the IP.
        assert!(a
            .checks
            .iter()
            .any(|c| c.id == "relays_via_proxy" && c.result == "fail"));
        assert_eq!(a.total, 7);
        assert!(a.checked <= a.total && a.score <= 70);
        // A remembered check of a proxy that is no longer the live one is ignored.
        r.svc.check_proxy(&r.admin(), try_proxy(None)).await.unwrap();
        r.svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "proxies": {
                    "list": [{ "id": "p", "url": "socks5://127.0.0.1:9050" }],
                    "default": { "proxy": "p" }
                } })),
            )
            .unwrap();
        let id = r.svc.settings().proxies.list[0].id.clone();
        let up = ProxyCheck {
            proxy: "socks5://127.0.0.1:9050".into(),
            status: "connected".into(),
            checked_at: (r.svc.clock)(),
            relays: Vec::new(),
        };
        r.svc.record_probe(&id, up);
        r.svc.replan();
        let a = r.svc.privacy_audit(&r.admin()).await.unwrap();
        assert!(a
            .checks
            .iter()
            .any(|c| c.id == "proxy_check" && c.result == "not_checked"));
    }

    #[tokio::test]
    async fn an_existing_database_counts_as_online_since_its_first_invoice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keys = Keys::generate();
        let mut cfg = crate::config::tests::load(&crate::config::tests::base()).unwrap();
        cfg.admins = [keys.public_key().to_hex()].into();
        {
            let (svc, _f) = on_disk(&cfg, &path, T0 - 500).await;
            let p = CreateInvoiceParams {
                amount_sat: 5_000,
                memo: None,
                expiry_secs: None,
            };
            svc.create_invoice(&admin_of(&keys, T0 - 500, 1), p).unwrap();
        }
        // As if written by a version that did not record the first start.
        Db::open(&path)
            .unwrap()
            .meta_set(crate::service::META_ONLINE_SINCE, None)
            .unwrap();
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert_eq!(svc.online_since, T0 - 500);
    }

    #[test]
    fn sweep_patch_unknown_fields_are_rejected() {
        assert!(serde_json::from_value::<SweepPatch>(serde_json::json!({ "destination": "bc1q" })).is_err());
    }

    fn applied(state: crate::proxypool::PoolState, url: Option<&str>) -> crate::proxypool::Applied {
        crate::proxypool::Applied {
            active: url.map(|_| "p".to_string()),
            active_url: url.map(Into::into),
            state,
            next_switch_at: None,
            reachable: usize::from(url.is_some()),
        }
    }

    #[tokio::test]
    async fn relays_are_shared_out_between_keys_and_shown_with_their_keys() {
        let r = rig(|c| c.relays = vec!["wss://a.example".into(), "wss://b.example".into()]).await;
        // Before any pool is up: the configured relays, each with the keys that use it.
        let h = r.svc.health(&r.admin()).await.unwrap();
        assert!(h
            .relays
            .iter()
            .all(|x| x.keys == ["admin", "invoices"] && x.status == "unknown"));
        let summary: Vec<(&str, usize, bool)> = h
            .keys
            .iter()
            .map(|k| (k.id.as_str(), k.relays.len(), k.operators_only))
            .collect();
        assert_eq!(summary, [("invoices", 2, false), ("admin", 2, true)]);
        assert_eq!(h.keys[0].tools, ["get_info", "create_invoice", "get_invoice"]);
        assert_eq!(h.keys[1].tools, ["*"]);
        assert!(h.keys[0].pubkey.is_empty());
        r.svc.set_key_pubkey("invoices", "aa");
        r.svc.set_key_pubkey("invoices", "bb");
        r.svc.set_key_pubkey("admin", "cc");
        let keys = r.svc.get_settings(&r.admin()).unwrap().fixed.keys;
        assert_eq!((keys[0].pubkey.as_str(), keys[1].pubkey.as_str()), ("bb", "cc"));

        // A relay for the public key only: the restart brings the keys apart.
        let v = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({ "relay_keys": { "wss://b.example": ["invoices"] } })),
            )
            .unwrap();
        assert!(v.restart_pending);
        assert_eq!(v.settings.relay_keys["wss://b.example"], ["invoices"]);
        assert!(v.overridden.contains(&"relay_keys".to_string()));
        let h = r.svc.health(&r.admin()).await.unwrap();
        assert_eq!(h.keys[1].relays, ["wss://a.example"]);
        assert_eq!(h.relays[1].keys, ["invoices"]);

        // The administration key keeps a relay from the host's own list.
        let e = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({
                    "relays": ["wss://a.example", "wss://c.example"],
                    "relay_keys": { "wss://a.example": ["invoices"] }
                })),
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("must keep at least one relay from DEADHOP_RELAYS"), "{e}");
        // A key cannot be left without any relay either.
        let e = r
            .svc
            .update_settings(
                &r.admin(),
                patch(serde_json::json!({
                    "relay_keys": { "wss://a.example": ["invoices"], "wss://b.example": ["invoices"] }
                })),
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("no relay is assigned to the administration key"), "{e}");

        // Going back to a relay setup drops the shared-out relays with it.
        r.svc
            .revert_connection(r.svc.cfg.relays.clone(), Default::default(), "test")
            .unwrap();
        assert!(r.svc.settings().relay_keys.is_empty());
        r.svc
            .revert_connection(
                r.svc.cfg.relays.clone(),
                [("wss://b.example".to_string(), vec!["admin".to_string()])].into(),
                "test",
            )
            .unwrap();
        assert_eq!(r.svc.settings().relay_keys.len(), 1);
    }

    #[tokio::test]
    async fn a_relay_several_keys_use_is_one_row_and_connected_only_if_it_is_for_each() {
        let r = rig(|c| c.relays = vec!["wss://a.example".into(), "wss://b.example".into()]).await;
        let state = |url: &str, ok: bool| RelayState {
            url: url.into(),
            status: if ok { "connected" } else { "disconnected" }.into(),
            connected: ok,
            keys: Vec::new(),
        };
        r.svc.set_relay_probe(
            "invoices",
            Some(Arc::new(Probe(vec![
                state("wss://a.example", false),
                state("wss://b.example/", true),
            ]))),
        );
        // (Keys are merged in id order, so a connected row meets a disconnected one here.)
        r.svc
            .set_relay_probe("admin", Some(Arc::new(Probe(vec![state("wss://a.example", true)]))));
        let rows = r.svc.relay_states().await;
        let shown: Vec<(&str, &str, bool, &[String])> = rows
            .iter()
            .map(|x| (x.url.as_str(), x.status.as_str(), x.connected, x.keys.as_slice()))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "wss://a.example",
                    "disconnected",
                    false,
                    &["admin".to_string(), "invoices".to_string()][..]
                ),
                ("wss://b.example/", "connected", true, &["invoices".to_string()][..]),
            ]
        );
        // A key's pool going away leaves the other's rows.
        r.svc.set_relay_probe("invoices", None);
        let rows = r.svc.relay_states().await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].status, "unknown", "no pool has b now");
    }

    #[tokio::test]
    async fn each_relay_is_checked_the_way_one_of_its_keys_reaches_it() {
        use crate::proxypool::PoolState;
        let good = nostr_relay_builder::MockRelay::run()
            .await
            .unwrap()
            .url()
            .await
            .to_string();
        let r = rig(|c| c.relays = vec![good.clone(), "ws://127.0.0.1:9".into()]).await;
        // The second relay is for the public key only, and that key is cut off (kill switch).
        let mut s = r.svc.settings().clone();
        s.relay_keys = [("ws://127.0.0.1:9".to_string(), vec!["invoices".to_string()])].into();
        s.proxies.list = vec![crate::settings::ProxyEntry {
            id: "x".into(),
            name: String::new(),
            url: "socks5://127.0.0.1:9".into(),
            i2p: false,
        }];
        s.proxies.default = crate::settings::Destination::Proxy("x".into());
        r.svc.apply_settings(s);
        {
            let mut pool = r.svc.pool.lock().unwrap();
            pool.applied
                .insert("invoices".into(), applied(PoolState::Offline, None));
            pool.applied
                .insert("admin".into(), applied(PoolState::Active, Some("socks5://127.0.0.1:9")));
        }
        let report = r.svc.refresh_relay_health().await.unwrap();
        // Only the relay the administration key reaches is checked, and through that key's proxy.
        let names: Vec<&str> = report.iter().map(|h| h.relay.as_str()).collect();
        assert_eq!(names, [good.as_str()]);
        assert_eq!(report[0].status, "down", "its proxy is not there");
    }

    // ---- Recorded wire behaviour (see snapshot.rs): later refactors must leave these unchanged. ----

    /// The settings view as clients get it, with the random operator key made fixed.
    fn view_json(v: &SettingsView) -> serde_json::Value {
        let mut j = serde_json::to_value(v).unwrap();
        for o in j["operators"].as_array_mut().unwrap() {
            o["pubkey"] = "<operator>".into();
        }
        j
    }

    #[tokio::test]
    async fn get_settings_default_snapshot() {
        let r = rig(|_| {}).await;
        crate::snapshot::check(
            "get_settings_default",
            &view_json(&r.svc.get_settings(&r.admin()).unwrap()),
        );
    }

    /// Proxies of every kind, rules of every kind, relays with names.
    fn full_patch() -> serde_json::Value {
        serde_json::json!({
            "name": "snapshot service",
            "relays": ["wss://relay-a.example", "wss://relay-b.example", "ws://abcdefghij.onion", "ws://nostr-not.i2p"],
            "relay_names": { "ws://nostr-not.i2p": "nostr-not.i2p", "wss://relay-a.example": "Relay A" },
            "proxies": {
                "list": [
                    { "id": "tor", "name": "Tor", "url": "socks5://127.0.0.1:9050" },
                    { "id": "vpn", "name": "VPN", "url": "socks5://user:secret@10.8.0.1:1080" },
                    { "id": "i2p", "name": "I2P router", "url": "http://127.0.0.1:4444", "i2p": true }
                ],
                "groups": [{
                    "id": "exits", "name": "Exits", "proxies": ["tor", "vpn"], "strategy": "round_robin",
                    "rotate_secs": 1800, "chaos_min_secs": 120, "chaos_max_secs": 600
                }],
                "default": { "proxy": "tor" },
                "offline": "kill_switch",
                "rules": [
                    { "name": "onions", "match": ["*.onion"], "to": { "proxy": "tor" }, "fallback": "offline" },
                    { "name": "i2p", "match": ["*.i2p"], "to": { "proxy": "i2p" } },
                    { "match": ["wss://relay-b.example"], "to": "direct" },
                    { "name": "never", "match": ["relay-c.example:7777"], "to": "block" },
                    { "match": ["relay-a.example"], "to": { "group": "exits" }, "fallback": "policy" }
                ],
                "i2p_registries": ["http://notbob.i2p/cgi-bin/jump.cgi?q={name}", "http://reg.i2p/?a={name}"]
            }
        })
    }

    #[tokio::test]
    async fn get_settings_full_snapshot_and_a_stored_patch_reads_back() {
        let r = rig(|_| {}).await;
        r.svc.update_settings(&r.admin(), patch(full_patch())).unwrap();
        crate::snapshot::check(
            "get_settings_full",
            &view_json(&r.svc.get_settings(&r.admin()).unwrap()),
        );
        // What was stored is the patch, in a form that reads back as itself.
        let stored = r.svc.stored_patch().unwrap();
        let raw = r.svc.db.meta_get(META_SETTINGS).unwrap().unwrap();
        assert_eq!(
            raw,
            include_str!("../tests/fixtures/stored_settings_groups.json").trim_end()
        );
        crate::snapshot::check("stored_settings_patch", &serde_json::from_str(&raw).unwrap());
        assert_eq!(serde_json::from_str::<SettingsPatch>(&raw).unwrap(), stored);
    }

    #[test]
    fn a_stored_patch_written_by_earlier_code_reads_back_the_same() {
        // The exact text the service stored when it was last changed through
        // `full_patch`; a later version must read it and write it back unchanged.
        let blob = include_str!("../tests/fixtures/stored_settings_groups.json").trim_end();
        let read: SettingsPatch = serde_json::from_str(blob).unwrap();
        assert_eq!(serde_json::to_string(&read).unwrap(), blob);
        assert_eq!(read.relays.as_ref().unwrap().len(), 4);
        assert_eq!(read.proxies.as_ref().unwrap().rules.as_ref().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn settings_stored_before_groups_are_converted_once_keeping_every_override() {
        use crate::service::{META_SETTINGS_PRE_GROUPS, META_SETTINGS_SHAPE};
        use crate::settings::Destination;
        // What the service stored before proxy groups, through the old `full_patch`.
        let old = include_str!("../tests/fixtures/stored_settings_patch.json").trim_end();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keys = Keys::generate();
        let mut cfg = crate::config::tests::load(&crate::config::tests::base()).unwrap();
        cfg.admins = [keys.public_key().to_hex()].into();
        cfg.data_dir = dir.path().to_path_buf();
        Db::open(&path).unwrap().meta_set(META_SETTINGS, Some(old)).unwrap();
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert!(svc.settings_problem.lock().unwrap().is_none());
        let s = svc.settings().clone();
        // Everything else as it was.
        assert_eq!(s.name, "snapshot service");
        assert_eq!(s.relays.len(), 4);
        assert_eq!(s.relay_names.len(), 2);
        // The proxies: the same list, the pool of one became the default route,
        // and the rule to the pool goes there and leaves the rest to the policy.
        let p = &s.proxies;
        assert_eq!(
            p.list
                .iter()
                .map(|e| (e.id.as_str(), e.name.as_str(), e.url.as_str(), e.i2p))
                .collect::<Vec<_>>(),
            [
                ("tor", "Tor", "socks5://127.0.0.1:9050", false),
                ("vpn", "VPN", "socks5://user:secret@10.8.0.1:1080", false),
                ("i2p", "I2P router", "http://127.0.0.1:4444", true)
            ]
        );
        assert_eq!(
            (&p.default, p.groups.len(), p.default_keys.len()),
            (&Destination::Proxy("tor".into()), 0, 0)
        );
        assert_eq!(
            (p.offline, p.transparent),
            (crate::settings::OfflinePolicy::KillSwitch, false)
        );
        assert_eq!(p.rules.len(), 5);
        assert_eq!(
            (&p.rules[4].to, &p.rules[4].fallback),
            (&Destination::Proxy("tor".into()), &crate::routes::Fallback::Policy)
        );
        assert_eq!(
            p.rules[..4].iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["onions", "i2p", "", "never"]
        );
        assert_eq!(p.i2p_registries.len(), 2);
        // Each of them still shows as overridden.
        let names = svc.stored_patch().unwrap().names();
        for n in [
            "name",
            "relays",
            "relay_names",
            "proxies.list",
            "proxies.default",
            "proxies.offline",
            "proxies.rules",
            "proxies.i2p_registries",
        ] {
            assert!(names.contains(&n.to_string()), "{n}: {names:?}");
        }
        // The old blob is kept beside the new one, and it is not converted again.
        assert_eq!(svc.db.meta_get(META_SETTINGS_PRE_GROUPS).unwrap().as_deref(), Some(old));
        assert_eq!(svc.db.meta_get(META_SETTINGS_SHAPE).unwrap().as_deref(), Some("groups"));
        let new = svc.db.meta_get(META_SETTINGS).unwrap().unwrap();
        drop(svc);
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert_eq!(svc.db.meta_get(META_SETTINGS).unwrap().unwrap(), new);
        assert_eq!(svc.settings().proxies, s.proxies);
        drop(svc);

        // Stored settings that cannot be read are left as they are, and say so.
        let path = dir.path().join("unreadable.sqlite");
        Db::open(&path)
            .unwrap()
            .meta_set(META_SETTINGS, Some("{not json"))
            .unwrap();
        let (svc, _f) = on_disk(&cfg, &path, T0).await;
        assert_eq!(svc.db.meta_get(META_SETTINGS).unwrap().as_deref(), Some("{not json"));
        // A copy is kept, and the next start tries again.
        assert_eq!(
            svc.db.meta_get(META_SETTINGS_PRE_GROUPS).unwrap().as_deref(),
            Some("{not json")
        );
        assert!(svc.db.meta_get(META_SETTINGS_SHAPE).unwrap().is_none());
        // A change on top of them is refused rather than dropping them.
        let e = svc
            .update_settings(&admin_of(&keys, T0, 1), patch(serde_json::json!({ "pow_bits": 10 })))
            .unwrap_err();
        assert!(e.to_string().contains("could not be read"), "{e}");
    }

    #[tokio::test]
    async fn saved_proxy_settings_that_no_longer_fit_the_environment_are_put_aside_alone() {
        use crate::service::META_SETTINGS_DROPPED_PROXIES;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let keys = Keys::generate();
        let mut env = crate::config::tests::base();
        env.insert("DEADHOP_PROXY", "socks5://127.0.0.1:9050".into());
        env.insert("DEADHOP_PROXIES", "socks5://127.0.0.1:9051".into());
        let mut cfg = crate::config::tests::load(&env).unwrap();
        cfg.admins = [keys.public_key().to_hex()].into();
        cfg.data_dir = dir.path().to_path_buf();
        {
            let (svc, _f) = on_disk(&cfg, &path, T0).await;
            svc.update_settings(
                &admin_of(&keys, T0, 1),
                patch(serde_json::json!({ "pow_bits": 22, "proxies": { "default": { "proxy": "env2" } } })),
            )
            .unwrap();
        }
        // The environment loses its second proxy: what was saved for it no longer fits.
        env.remove("DEADHOP_PROXIES");
        let mut fewer = crate::config::tests::load(&env).unwrap();
        (fewer.admins, fewer.data_dir) = (cfg.admins.clone(), cfg.data_dir.clone());
        let (svc, _f) = on_disk(&fewer, &path, T0).await;
        assert_eq!(svc.settings().pow_bits, 22, "the rest still applies");
        assert_eq!(svc.settings().proxies, fewer.proxies);
        let problem = svc.settings_problem.lock().unwrap().clone().unwrap();
        assert!(problem.contains("saved proxy settings were not applied"), "{problem}");
        assert!(svc.stored_patch().unwrap().proxies.is_none());
        assert_eq!(
            svc.db.meta_get(META_SETTINGS_DROPPED_PROXIES).unwrap().as_deref(),
            Some(r#"{"default":{"proxy":"env2"}}"#)
        );
        let w = svc.health(&admin_of(&keys, T0, 2)).await.unwrap().warnings;
        assert!(w.iter().any(|w| w.contains("saved proxy settings")), "{w:?}");
    }

    fn refusal<T: std::fmt::Debug>(
        out: &mut std::collections::BTreeMap<String, serde_json::Value>,
        label: &str,
        r: Result<T>,
    ) {
        let e = r.unwrap_err();
        let shown = serde_json::json!({ "code": e.code(), "public_message": e.public_message() });
        assert!(out.insert(label.into(), shown).is_none(), "{label} twice");
    }

    #[tokio::test]
    async fn network_tool_refusals_snapshot() {
        use serde_json::json;
        let mut out = std::collections::BTreeMap::new();
        let o = &mut out;
        let params = |v: serde_json::Value| serde_json::from_value::<CheckProxyParams>(v).unwrap();

        // check_proxy
        let r = rig(|_| {}).await;
        refusal(
            o,
            "check_proxy: not an operator",
            r.svc.check_proxy(&stranger(), params(json!({}))).await,
        );
        refusal(
            o,
            "check_proxy: unknown id",
            r.svc.check_proxy(&r.admin(), params(json!({ "id": "nope" }))).await,
        );
        refusal(
            o,
            "check_proxy: id and proxy",
            r.svc
                .check_proxy(&r.admin(), params(json!({ "id": "a", "proxy": "socks5://h:1" })))
                .await,
        );
        refusal(
            o,
            "check_proxy: bad address",
            r.svc
                .check_proxy(&r.admin(), params(json!({ "proxy": "ftp://h:1" })))
                .await,
        );
        r.svc
            .update_settings(
                &r.admin(),
                patch(json!({ "proxies": {
                    "list": [{ "id": "tor", "url": "socks5://127.0.0.1:9050" }, { "id": "vpn", "url": "socks5://127.0.0.1:1080" }],
                    "default": { "proxy": "tor" }
                } })),
            )
            .unwrap();
        refusal(
            o,
            "check_proxy: no relay goes through it",
            r.svc.check_proxy(&r.admin(), params(json!({ "id": "vpn" }))).await,
        );
        r.svc.proxy_check_busy.store(true, Ordering::SeqCst);
        refusal(
            o,
            "check_proxy: one at a time",
            r.svc.check_proxy(&r.admin(), params(json!({ "id": "tor" }))).await,
        );
        r.svc.proxy_check_busy.store(false, Ordering::SeqCst);
        r.svc
            .proxy_checks
            .lock()
            .unwrap()
            .extend(std::iter::repeat_n(T0, PROXY_CHECKS_PER_MIN));
        refusal(
            o,
            "check_proxy: per-minute budget",
            r.svc.check_proxy(&r.admin(), params(json!({ "id": "tor" }))).await,
        );
        let locked = rig(|c| c.proxy_locked = true).await;
        refusal(
            o,
            "check_proxy: locked, address not listed",
            locked
                .svc
                .check_proxy(&locked.admin(), params(json!({ "proxy": "socks5://h:1" })))
                .await,
        );

        // check_relays, get_relay_history, get_privacy_audit
        refusal(
            o,
            "check_relays: not an operator",
            r.svc.check_relays(&stranger()).await,
        );
        r.svc
            .relay_checks
            .lock()
            .unwrap()
            .extend(std::iter::repeat_n(T0, RELAY_CHECKS_PER_MIN));
        refusal(
            o,
            "check_relays: per-minute budget",
            r.svc.check_relays(&r.admin()).await,
        );
        let window = |w: Option<&str>| RelayHistoryParams {
            window: w.map(str::to_string),
        };
        refusal(
            o,
            "get_relay_history: not an operator",
            r.svc.relay_history(&stranger(), window(None)),
        );
        refusal(
            o,
            "get_relay_history: bad window",
            r.svc.relay_history(&r.admin(), window(Some("2h"))),
        );
        refusal(
            o,
            "get_privacy_audit: not an operator",
            r.svc.privacy_audit(&stranger()).await,
        );

        // resolve_i2p_name
        let l = |n: &str| lookup(n);
        refusal(
            o,
            "resolve_i2p_name: not an operator",
            r.svc.resolve_i2p_name(&stranger(), l("x.i2p")).await,
        );
        refusal(
            o,
            "resolve_i2p_name: locked",
            locked.svc.resolve_i2p_name(&locked.admin(), l("x.i2p")).await,
        );
        refusal(
            o,
            "resolve_i2p_name: bad name",
            r.svc.resolve_i2p_name(&r.admin(), l("Bad Name")).await,
        );
        refusal(
            o,
            "resolve_i2p_name: no I2P router",
            r.svc.resolve_i2p_name(&r.admin(), l("x.i2p")).await,
        );
        let ready = rig(|_| {}).await;
        ready
            .svc
            .update_settings(
                &ready.admin(),
                patch(json!({ "proxies": { "list": [{ "id": "i2p", "url": "http://127.0.0.1:4444", "i2p": true }], "i2p_registries": [] } })),
            )
            .unwrap();
        refusal(
            o,
            "resolve_i2p_name: no registries",
            ready.svc.resolve_i2p_name(&ready.admin(), l("x.i2p")).await,
        );
        ready
            .svc
            .update_settings(
                &ready.admin(),
                patch(json!({ "proxies": { "i2p_registries": ["http://reg.i2p/?q={name}"] } })),
            )
            .unwrap();
        ready.svc.i2p_lookup_busy.store(true, Ordering::SeqCst);
        refusal(
            o,
            "resolve_i2p_name: one at a time",
            ready.svc.resolve_i2p_name(&ready.admin(), l("x.i2p")).await,
        );

        // update_settings: proxies and relays
        let save = |p: serde_json::Value| r.svc.update_settings(&r.admin(), patch(p));
        let proxies = |p: serde_json::Value| save(json!({ "proxies": p }));
        let nine: Vec<_> = (0..9)
            .map(|i| json!({ "id": format!("p{i}"), "url": format!("socks5://h{i}:1") }))
            .collect();
        refusal(o, "update_settings: too many proxies", proxies(json!({ "list": nine })));
        refusal(
            o,
            "update_settings: proxy bad id",
            proxies(json!({ "list": [{ "id": "Bad Id", "url": "socks5://h:1" }] })),
        );
        refusal(
            o,
            "update_settings: proxy name too long",
            proxies(json!({ "list": [{ "id": "a", "name": "n".repeat(61), "url": "socks5://h:1" }] })),
        );
        refusal(
            o,
            "update_settings: proxy empty address",
            proxies(json!({ "list": [{ "id": "a", "url": " " }] })),
        );
        refusal(
            o,
            "update_settings: proxy bad scheme",
            proxies(json!({ "list": [{ "id": "a", "url": "ftp://h:1" }] })),
        );
        refusal(
            o,
            "update_settings: proxy id twice",
            proxies(json!({ "list": [{ "id": "a", "url": "socks5://h:1" }, { "id": "a", "url": "socks5://h:2" }] })),
        );
        refusal(
            o,
            "update_settings: proxy address twice",
            proxies(json!({ "list": [{ "id": "a", "url": "socks5://h:1" }, { "id": "b", "url": "socks5://h:1" }] })),
        );
        refusal(
            o,
            "update_settings: i2p proxy not http",
            proxies(json!({ "list": [{ "id": "a", "url": "socks5://h:1", "i2p": true }] })),
        );
        refusal(
            o,
            "update_settings: two i2p proxies",
            proxies(json!({ "list": [
                { "id": "a", "url": "http://h:1", "i2p": true },
                { "id": "b", "url": "http://h:2", "i2p": true }
            ] })),
        );
        refusal(
            o,
            "update_settings: bad registry",
            proxies(json!({ "i2p_registries": ["http://example.com/?q={name}"] })),
        );
        refusal(
            o,
            "update_settings: too many registries",
            proxies(
                json!({ "i2p_registries": (0..5).map(|i| format!("http://r{i}.i2p/?q={{name}}")).collect::<Vec<_>>() }),
            ),
        );
        refusal(
            o,
            "update_settings: registry twice",
            proxies(json!({ "i2p_registries": ["http://a.i2p/?q={name}", "http://a.i2p/?q={name}"] })),
        );
        refusal(
            o,
            "update_settings: rotate interval out of range",
            proxies(json!({
                "list": [{ "id": "a", "url": "socks5://h:1" }, { "id": "b", "url": "socks5://h:2" }],
                "groups": [{ "id": "g", "proxies": ["a", "b"], "strategy": "round_robin", "rotate_secs": 1 }]
            })),
        );
        refusal(
            o,
            "update_settings: rule names no proxy",
            proxies(json!({ "rules": [{ "match": ["*.onion"], "to": { "proxy": "ghost" } }] })),
        );
        refusal(
            o,
            "update_settings: rule pattern empty",
            proxies(json!({ "rules": [{ "match": [""], "to": "direct" }] })),
        );
        refusal(o, "update_settings: no relays", save(json!({ "relays": [] })));
        let nine_relays: Vec<_> = (0..9).map(|i| format!("wss://r{i}.example")).collect();
        refusal(
            o,
            "update_settings: too many relays",
            save(json!({ "relays": nine_relays })),
        );
        refusal(
            o,
            "update_settings: relay not ws",
            save(json!({ "relays": ["https://relay.example"] })),
        );
        refusal(
            o,
            "update_settings: relay with spaces",
            save(json!({ "relays": ["wss://relay example"] })),
        );
        refusal(
            o,
            "update_settings: relay with a password",
            save(json!({ "relays": ["wss://user:pw@relay.example"] })),
        );
        refusal(
            o,
            "update_settings: relay name for an unlisted relay",
            save(json!({ "relay_names": { "wss://" : "x".repeat(61) } })),
        );
        refusal(
            o,
            "update_settings: not an operator",
            r.svc.update_settings(&stranger(), patch(json!({ "name": "x" }))),
        );

        crate::snapshot::check("network_tool_refusals", &serde_json::to_value(&out).unwrap());
    }

    // ---- Network behaviour the wire snapshots above do not cover: where each relay
    // goes, what health reports, and the refusals that depend on the keys. ----

    /// `full_patch`, with a relay and a rule each given to one key only.
    fn keyed_patch() -> serde_json::Value {
        let mut p = full_patch();
        // One relay from the environment's list stays, for the administration key.
        p["relays"].as_array_mut().unwrap().push("wss://relay.example".into());
        p["relay_keys"] = serde_json::json!({ "wss://relay-b.example": ["invoices"], "ws://nostr-not.i2p": ["admin"] });
        p["proxies"]["default_keys"] = serde_json::json!({ "admin": { "group": "exits" } });
        p["proxies"]["rules"][0]["keys"] = serde_json::json!(["admin"]);
        p["proxies"]["rules"][4]["fallback"] = serde_json::json!("offline");
        p["proxies"]["rules"].as_array_mut().unwrap().push(serde_json::json!({
            "name": "vpn", "match": ["relay.example"], "to": { "proxy": "vpn" }, "fallback": { "to": { "group": "exits" } }
        }));
        p
    }

    fn probe(r: &Rig, id: &str, up: bool) {
        r.svc.record_probe(
            id,
            crate::privacy::ProxyCheck {
                proxy: format!("socks5://h/{id}"),
                status: if up { "connected" } else { "failed" }.into(),
                checked_at: T0,
                relays: Vec::new(),
            },
        );
    }

    #[tokio::test]
    async fn route_table_snapshot() {
        use crate::routes::{groups_used, relays_through_proxy, resolve, uses_default, Destination};
        let mut out = std::collections::BTreeMap::new();
        for (name, patch_json) in [("full", full_patch()), ("keyed", keyed_patch())] {
            let r = rig(|_| {}).await;
            r.svc.update_settings(&r.admin(), patch(patch_json)).unwrap();
            let s = r.svc.settings().topology();
            let url = |id: &str| s.proxies.list.iter().find(|e| e.id == id).unwrap().url.clone();
            // Every proxy up (a group uses its first), or none.
            let up = |d: &Destination| {
                let id = match d {
                    Destination::Group(g) => s.proxies.groups.iter().find(|x| &x.id == g).unwrap().proxies[0].clone(),
                    // (Only proxies and groups are asked about.)
                    d => serde_json::to_value(d).unwrap()["proxy"].as_str().unwrap().to_string(),
                };
                Some((id.clone(), url(&id)))
            };
            let down = |_: &Destination| None;
            type Now<'a> = &'a dyn Fn(&Destination) -> Option<(String, String)>;
            let cases: [(&str, Now, Option<bool>); 4] = [
                ("proxies up", &up, Some(false)),
                ("proxies down, the policy keeps the key off", &down, Some(false)),
                ("proxies down, the policy connects straight", &down, Some(true)),
                ("nothing probed yet", &down, None),
            ];
            for key in ["invoices", "admin"] {
                for (case, now, offline) in &cases {
                    let table: Vec<String> = resolve(&s, key, now, *offline)
                        .iter()
                        .map(|x| format!("{x:?}"))
                        .collect();
                    out.insert(format!("{name} / {key} / {case}"), serde_json::json!(table));
                }
                out.insert(
                    format!("{name} / {key} / uses the default route"),
                    serde_json::json!(uses_default(&s, key)),
                );
                out.insert(
                    format!("{name} / {key} / groups used"),
                    serde_json::json!(groups_used(&s, key)),
                );
            }
            for id in ["tor", "vpn", "i2p", "ghost"] {
                out.insert(
                    format!("{name} / relays through {id}"),
                    serde_json::json!(relays_through_proxy(&s, id)),
                );
            }
        }
        crate::snapshot::check("route_table", &serde_json::to_value(&out).unwrap());
    }

    #[tokio::test]
    async fn pool_health_snapshot() {
        let mut out = std::collections::BTreeMap::new();
        for (name, patch_json) in [("full", full_patch()), ("keyed", keyed_patch())] {
            let r = rig(|_| {}).await;
            r.svc.update_settings(&r.admin(), patch(patch_json)).unwrap();
            r.svc.replan();
            out.insert(
                format!("{name} / nothing probed"),
                serde_json::to_value(r.svc.pool_health()).unwrap(),
            );
            for id in ["tor", "vpn", "i2p"] {
                probe(&r, id, true);
            }
            r.svc.replan();
            out.insert(
                format!("{name} / all up"),
                serde_json::to_value(r.svc.pool_health()).unwrap(),
            );
            probe(&r, "tor", false);
            r.svc.replan();
            out.insert(
                format!("{name} / tor down"),
                serde_json::to_value(r.svc.pool_health()).unwrap(),
            );
            out.insert(
                format!("{name} / tor down / posture, connection, proxy in use"),
                serde_json::json!([
                    format!("{:?}", r.svc.posture()),
                    format!("{:?}", r.svc.connection()),
                    format!("{:?}", r.svc.active_proxy()),
                    format!("{:?}", r.svc.connection_for("admin")),
                    format!("{:?}", r.svc.active_proxy_for("admin")),
                ]),
            );
        }
        crate::snapshot::check("pool_health", &serde_json::to_value(&out).unwrap());
    }

    #[tokio::test]
    async fn key_refusals_snapshot() {
        use serde_json::json;
        let mut out = std::collections::BTreeMap::new();
        let o = &mut out;
        let r = rig(|_| {}).await;
        let save = |p: serde_json::Value| r.svc.update_settings(&r.admin(), patch(p));
        let tor = json!({ "id": "tor", "url": "socks5://127.0.0.1:9050" });
        refusal(
            o,
            "a rule for a key that does not exist",
            save(json!({ "proxies": { "rules": [{ "match": ["*.onion"], "to": "block", "keys": ["nobody"] }] } })),
        );
        refusal(
            o,
            "a default route for a key that does not exist",
            save(json!({ "proxies": { "default_keys": { "nobody": "direct" } } })),
        );
        refusal(
            o,
            "a relay for a key that does not exist",
            save(json!({ "relay_keys": { "wss://relay.example": ["nobody"] } })),
        );
        refusal(
            o,
            "a key left without a relay",
            save(json!({ "relay_keys": { "wss://relay.example": ["invoices"], "ws://127.0.0.1:7777": ["invoices"] } })),
        );
        refusal(
            o,
            "every relay of a key is blocked",
            save(json!({ "proxies": { "rules": [{ "match": ["*"], "to": "block", "keys": ["admin"] }] } })),
        );
        refusal(
            o,
            "a key's default route blocks its every relay",
            save(json!({ "proxies": { "default_keys": { "admin": "block" } } })),
        );
        refusal(
            o,
            "a rule sends an onion relay straight",
            save(json!({ "proxies": { "rules": [{ "match": ["*.onion"], "to": "direct" }] } })),
        );
        refusal(
            o,
            "a rule falls back to sending an onion relay straight",
            save(json!({ "proxies": {
                "list": [tor],
                "rules": [{ "match": ["*.onion"], "to": { "proxy": "tor" }, "fallback": { "to": "direct" } }]
            } })),
        );
        refusal(
            o,
            "a group of one proxy",
            save(json!({ "proxies": {
                "list": [tor],
                "groups": [{ "id": "g", "proxies": ["tor"], "strategy": "failover" }]
            } })),
        );
        refusal(
            o,
            "the default route points at a group that does not exist",
            save(json!({ "proxies": { "default": { "group": "gone" } } })),
        );
        // Pointing a key's default route at a proxy that is down.
        save(json!({ "proxies": {
            "list": [tor, { "id": "vpn", "url": "socks5://127.0.0.1:1080" }],
            "groups": [{ "id": "g", "proxies": ["tor", "vpn"], "strategy": "failover" }],
            "default": { "group": "g" }
        } }))
        .unwrap();
        probe(&r, "tor", false);
        probe(&r, "vpn", true);
        r.svc.replan();
        refusal(
            o,
            "a key's default route is pointed at a proxy that is down",
            save(json!({ "proxies": { "default": { "proxy": "tor" } } })),
        );
        crate::snapshot::check("key_refusals", &serde_json::to_value(&out).unwrap());
    }

    #[tokio::test]
    async fn the_network_part_is_read_and_changed_on_its_own() {
        let r = rig(|_| {}).await;
        assert_eq!(code(r.svc.get_network(&stranger())), "unauthorized");
        let none = UpdateNetworkParams {
            patch: NetworkPatch::default(),
        };
        assert_eq!(code(r.svc.update_network(&stranger(), none)), "unauthorized");
        // A change outside the network shows nowhere in the network view.
        r.svc
            .update_settings(&r.admin(), patch(serde_json::json!({ "name": "renamed" })))
            .unwrap();
        let v = r.svc.get_network(&r.admin()).unwrap();
        assert!(v.overridden.is_empty(), "{:?}", v.overridden);
        assert_eq!((v.chain.as_str(), v.keys.len(), v.proxy_locked), ("regtest", 2, false));
        assert_eq!(v.settings, v.defaults);
        // A network change goes through the same checks and storage as update_settings.
        let p: NetworkPatch = serde_json::from_value(serde_json::json!({
            "relay_names": { "wss://relay.example": "Relay" },
            "proxies": { "list": [{ "id": "tor", "url": "socks5://user:pw@127.0.0.1:9050" }] }
        }))
        .unwrap();
        let v = r
            .svc
            .update_network(&r.admin(), UpdateNetworkParams { patch: p })
            .unwrap();
        assert_eq!(
            v.overridden,
            ["name", "relay_names", "proxies.list", "proxies.default"]
                .iter()
                .skip(1)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(v.settings.relay_names["wss://relay.example"], "Relay");
        assert_eq!(v.settings.proxies.list[0].url, "socks5://user:***@127.0.0.1:9050");
        assert_eq!(r.svc.get_settings(&r.admin()).unwrap().settings.name, "renamed");
        let bad: NetworkPatch = serde_json::from_value(serde_json::json!({ "relays": [] })).unwrap();
        assert_eq!(
            code(r.svc.update_network(&r.admin(), UpdateNetworkParams { patch: bad })),
            "invalid_params"
        );
        assert!(serde_json::from_value::<NetworkPatch>(serde_json::json!({ "name": "x" })).is_err());
    }
}
