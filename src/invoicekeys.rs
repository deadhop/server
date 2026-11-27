//! Invoice keys an operator adds, one per service run on this server: listing
//! them with each one's takings, adding, changing, archiving and restoring.
//!
//! A new key starts with the relays and routes of another invoice key (the
//! original one, unless told otherwise): it is added wherever that key is
//! named in the network settings. Archiving takes it out of them again; it is
//! refused while some relay or rule would be left for that key alone, since an
//! empty list there means "every key".

use std::collections::BTreeMap;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::db::KeyTotals;
use crate::error::{Error, Result};
use crate::keys::{self, KeyRow, INVOICES};
use crate::network::take;
use crate::service::META_SETTINGS;
use crate::service::{Caller, Service};
use crate::settings::{ProxyPatch, Settings, SettingsPatch};

/// Arguments of `list_invoice_keys`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListInvoiceKeysParams {
    /// Count only invoices created at or after this time (unix seconds); default: all.
    #[serde(default)]
    pub since: Option<u64>,
}

/// One invoice key, what it is set to, and its takings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct InvoiceKeyInfo {
    #[serde(flatten)]
    pub key: KeyRow,
    /// Hex public key; empty until the service has loaded it.
    pub pubkey: String,
    /// The original invoice key (`invoices`), the one apps used before keys could be added.
    pub original: bool,
    /// The relays it connects to now (none while archived).
    pub relays: Vec<String>,
    pub totals: KeyTotals,
}

/// Result of `list_invoice_keys` and of every change to the keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct InvoiceKeyList {
    /// The original key first, then the added ones, archived ones included.
    pub keys: Vec<InvoiceKeyInfo>,
    /// Invoice keys that can be in use at once, the original one included.
    pub max_keys: u32,
    /// The start of the period the totals cover.
    pub since: u64,
}

/// Arguments of `add_invoice_key`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddInvoiceKeyParams {
    /// Permanent id: 2 to 24 lower-case letters, digits or dashes, starting with a letter.
    pub id: String,
    /// What the dashboard calls it.
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Palette index, 0 to 7.
    #[serde(default)]
    pub color: Option<u8>,
    /// Service name given on this key; empty is the service's own name.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether anyone may create invoices on it (default true).
    #[serde(default)]
    pub public_invoicing: Option<bool>,
    /// Whether it is announced on the relays (default false).
    #[serde(default)]
    pub announce: Option<bool>,
    /// The invoice key whose relays and routes it starts with (default `invoices`);
    /// empty: only what is set for every key.
    #[serde(default)]
    pub copy_from: Option<String>,
}

/// Arguments of `update_invoice_key`; anything left out stays as it is. On the
/// original key only the label, description and colour can change (the rest
/// are service settings).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateInvoiceKeyParams {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub color: Option<u8>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub public_invoicing: Option<bool>,
    #[serde(default)]
    pub announce: Option<bool>,
}

/// Arguments of `archive_invoice_key` and `restore_invoice_key`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvoiceKeyIdParams {
    pub id: String,
    /// Restoring: the invoice key whose relays and routes it takes (default `invoices`).
    #[serde(default)]
    pub copy_from: Option<String>,
}

/// The network settings that name keys, with `to` added wherever `from` is named.
fn copied(s: &Settings, from: &str, to: &str) -> (BTreeMap<String, Vec<String>>, ProxyPatch) {
    let add = |keys: &[String]| {
        let mut keys = keys.to_vec();
        if keys.iter().any(|k| k == from) {
            keys.push(to.to_string());
        }
        keys
    };
    let relay_keys = s.relay_keys.iter().map(|(r, k)| (r.clone(), add(k))).collect();
    let mut default_keys = s.proxies.default_keys.clone();
    if let Some(d) = s.proxies.default_keys.get(from) {
        default_keys.insert(to.to_string(), d.clone());
    }
    let mut rules = s.proxies.rules.clone();
    rules.iter_mut().for_each(|r| r.keys = add(&r.keys));
    (relay_keys, routes(s, default_keys, rules))
}

/// The network settings that name keys, without `id`; or why it cannot be
/// taken out (a relay or rule that would be left with no key, which would
/// read as every key).
fn stripped(s: &Settings, id: &str, label: &str) -> Result<(BTreeMap<String, Vec<String>>, ProxyPatch)> {
    let without = |keys: &[String]| keys.iter().filter(|k| *k != id).cloned().collect::<Vec<_>>();
    let alone = |keys: &[String]| keys.len() == 1 && keys[0] == id;
    if let Some((relay, _)) = s.relay_keys.iter().find(|(_, k)| alone(k)) {
        return Err(Error::InvalidParams(format!(
            "relay '{relay}' is used by {label} alone: remove it, or give it to another key first"
        )));
    }
    if let Some(n) = s.proxies.rules.iter().position(|r| alone(&r.keys)) {
        return Err(Error::InvalidParams(format!(
            "rule {} is for {label} alone: remove it, or give it to another key first",
            n + 1
        )));
    }
    let relay_keys = s.relay_keys.iter().map(|(r, k)| (r.clone(), without(k))).collect();
    let mut default_keys = s.proxies.default_keys.clone();
    default_keys.remove(id);
    let mut rules = s.proxies.rules.clone();
    rules.iter_mut().for_each(|r| r.keys = without(&r.keys));
    Ok((relay_keys, routes(s, default_keys, rules)))
}

/// A proxy change that replaces the per-key default routes and the rules,
/// only where they change.
fn routes(
    s: &Settings,
    default_keys: BTreeMap<String, crate::settings::Destination>,
    rules: Vec<crate::routes::Rule>,
) -> ProxyPatch {
    ProxyPatch {
        default_keys: (default_keys != s.proxies.default_keys).then_some(default_keys),
        rules: (rules != s.proxies.rules).then_some(rules),
        ..ProxyPatch::default()
    }
}

impl Service {
    /// What is shown for the original key: the label, description and
    /// colour an operator gave it, the rest from the service settings.
    fn original_row(&self) -> KeyRow {
        let s = self.settings();
        let stored = self.registry().row(INVOICES).cloned();
        KeyRow {
            id: INVOICES.into(),
            label: self.registry().label(INVOICES),
            description: stored.as_ref().map(|r| r.description.clone()).unwrap_or_default(),
            color: stored.as_ref().map_or(0, |r| r.color),
            name: String::new(),
            public_invoicing: s.public_invoicing,
            announce: self.cfg.announce,
            created_at: self.online_since,
            created_by: String::new(),
            archived_at: None,
        }
    }

    /// The invoice keys and their takings since `since` (operators only).
    pub fn list_invoice_keys(&self, caller: &Caller, p: ListInvoiceKeysParams) -> Result<InvoiceKeyList> {
        self.read_only(caller)?;
        self.invoice_keys(p.since.unwrap_or(0))
    }

    fn invoice_keys(&self, since: u64) -> Result<InvoiceKeyList> {
        let totals = self.db.key_totals(since)?;
        let pubkeys = self
            .key_pubkeys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let settings = self.settings().clone();
        let registry = self.registry();
        let mut rows = vec![self.original_row()];
        rows.extend(registry.added().cloned());
        let keys = rows
            .into_iter()
            .map(|key| {
                let pubkey = pubkeys
                    .iter()
                    .find(|(id, _)| *id == key.id)
                    .map(|(_, p)| p.clone())
                    // An archived key is not loaded; its public key is on disk.
                    .or_else(|| {
                        let file = self.cfg.data_dir.join(keys::added_def(&key.id, "", false).pubkey_file);
                        std::fs::read_to_string(file).ok()
                    })
                    .unwrap_or_default();
                let totals = totals.iter().find(|t| t.key == key.id).cloned().unwrap_or(KeyTotals {
                    key: key.id.clone(),
                    ..KeyTotals::default()
                });
                InvoiceKeyInfo {
                    original: key.id == INVOICES,
                    relays: if key.archived_at.is_some() {
                        Vec::new()
                    } else {
                        settings.relays_for(&key.id)
                    },
                    pubkey,
                    totals,
                    key,
                }
            })
            .collect();
        Ok(InvoiceKeyList {
            keys,
            max_keys: keys::MAX_INVOICE_KEYS as u32,
            since,
        })
    }

    /// Store a change to the keys and to the network settings that name them,
    /// together, and tell the supervisor.
    fn change_keys(
        &self,
        actor: &str,
        action: &str,
        rows: Vec<KeyRow>,
        network: Option<(BTreeMap<String, Vec<String>>, ProxyPatch)>,
    ) -> Result<InvoiceKeyList> {
        let id = rows.first().map(|r| r.id.clone()).unwrap_or_default();
        let mut registry_rows: Vec<KeyRow> = self.registry().added().cloned().collect();
        if let Some(r) = self.registry().row(INVOICES) {
            registry_rows.push(r.clone());
        }
        for r in &rows {
            registry_rows.retain(|x| x.id != r.id);
            registry_rows.push(r.clone());
        }
        let registry = keys::Registry::new(registry_rows);
        let mut base = self.cfg.settings();
        base.lanes = registry.lanes();
        let mut stored = self.stored_patch()?;
        if let Some((relay_keys, proxies)) = network {
            stored.merge(&SettingsPatch {
                relay_keys: Some(relay_keys),
                proxies: (proxies != ProxyPatch::default()).then_some(proxies),
                ..SettingsPatch::default()
            });
        }
        let next = stored.apply(&base);
        next.validate(self.has_operators())?;
        for r in &rows {
            self.db.put_key_row(r)?;
        }
        let json = serde_json::to_string(&stored).expect("settings always serialize");
        self.db.meta_set(META_SETTINGS, Some(&json))?;
        *self.keys.write().unwrap_or_else(std::sync::PoisonError::into_inner) = registry;
        self.apply_settings(next);
        self.record(actor, action, &id)?;
        self.keys_changed.notify_one();
        self.invoice_keys(0)
    }

    /// The invoice key in use that another starts from, or none.
    fn source(&self, copy_from: Option<&str>) -> Result<Option<String>> {
        match copy_from.unwrap_or(INVOICES) {
            "" => Ok(None),
            k if self.registry().def(k).is_some_and(|d| !d.operators_only) => Ok(Some(k.to_string())),
            k => Err(Error::InvalidParams(format!(
                "copy_from: no invoice key '{k}' is in use"
            ))),
        }
    }

    fn check_room(&self) -> Result<()> {
        if self.registry().active().count() + 1 >= keys::MAX_INVOICE_KEYS {
            return Err(Error::InvalidParams(format!(
                "at most {} invoice keys can be in use at once; archive one first",
                keys::MAX_INVOICE_KEYS
            )));
        }
        Ok(())
    }

    /// Add an invoice key (operators only): make its secret, store it, and
    /// connect it with the relays and routes of `copy_from`.
    pub fn add_invoice_key(&self, caller: &Caller, p: AddInvoiceKeyParams) -> Result<InvoiceKeyList> {
        let actor = self.admit_change(caller)?;
        keys::check_new_id(&p.id)?;
        let row = KeyRow {
            id: p.id.clone(),
            label: p.label.trim().to_string(),
            description: p.description.unwrap_or_default().trim().to_string(),
            color: p.color.unwrap_or(1),
            name: p.name.unwrap_or_default().trim().to_string(),
            public_invoicing: p.public_invoicing.unwrap_or(true),
            announce: p.announce.unwrap_or(false),
            created_at: (self.clock)(),
            created_by: actor.clone(),
            archived_at: None,
        };
        keys::check_text(&row.label, &row.description, &row.name, row.color)?;
        if let Some(old) = self.registry().row(&p.id) {
            return Err(Error::InvalidParams(format!(
                "there is already a key '{}'{}",
                p.id,
                if old.archived_at.is_some() {
                    " (archived: restore it)"
                } else {
                    ""
                }
            )));
        }
        self.check_room()?;
        let from = self.source(p.copy_from.as_deref())?;
        // Made now, so that a failure to write it changes nothing else.
        keys::open_identity(
            &self.cfg.data_dir,
            std::sync::Arc::new(keys::added_def(&row.id, &row.label, row.announce)),
        )?;
        let network = from.map(|f| copied(&self.settings(), &f, &row.id));
        self.change_keys(&actor, "add_invoice_key", vec![row], network)
    }

    /// Change what an invoice key is called and how it presents itself.
    pub fn update_invoice_key(&self, caller: &Caller, p: UpdateInvoiceKeyParams) -> Result<InvoiceKeyList> {
        let actor = self.admit_change(caller)?;
        let original = p.id == INVOICES;
        let mut row = if original {
            self.original_row()
        } else {
            self.registry()
                .row(&p.id)
                .filter(|r| !keys::is_builtin(&r.id))
                .cloned()
                .ok_or_else(|| Error::InvalidParams(format!("there is no invoice key '{}'", p.id)))?
        };
        if original && (p.name.is_some() || p.public_invoicing.is_some() || p.announce.is_some()) {
            return Err(Error::InvalidParams(
                "the original key's name, public invoicing and announcing are service settings".into(),
            ));
        }
        take(&mut row.label, &p.label.map(|l| l.trim().to_string()));
        take(&mut row.description, &p.description.map(|d| d.trim().to_string()));
        take(&mut row.color, &p.color);
        take(&mut row.name, &p.name.map(|n| n.trim().to_string()));
        take(&mut row.public_invoicing, &p.public_invoicing);
        take(&mut row.announce, &p.announce);
        keys::check_text(&row.label, &row.description, &row.name, row.color)?;
        self.change_keys(&actor, "update_invoice_key", vec![row], None)
    }

    /// The added invoice key with this id.
    fn added_row(&self, id: &str) -> Result<KeyRow> {
        self.registry()
            .row(id)
            .filter(|r| !keys::is_builtin(&r.id))
            .cloned()
            .ok_or_else(|| Error::InvalidParams(format!("there is no added invoice key '{id}'")))
    }

    /// Archive an added invoice key: it disconnects and serves nothing; its
    /// invoices stay, and payments to them are still watched.
    pub fn archive_invoice_key(&self, caller: &Caller, p: InvoiceKeyIdParams) -> Result<InvoiceKeyList> {
        let actor = self.admit_change(caller)?;
        let mut row = self.added_row(&p.id)?;
        if row.archived_at.is_some() {
            return Err(Error::InvalidParams(format!("'{}' is already archived", p.id)));
        }
        let network = stripped(&self.settings(), &row.id, &row.label)?;
        row.archived_at = Some((self.clock)());
        self.change_keys(&actor, "archive_invoice_key", vec![row], Some(network))
    }

    /// Bring an archived invoice key back, with the same address.
    pub fn restore_invoice_key(&self, caller: &Caller, p: InvoiceKeyIdParams) -> Result<InvoiceKeyList> {
        let actor = self.admit_change(caller)?;
        let mut row = self.added_row(&p.id)?;
        if row.archived_at.is_none() {
            return Err(Error::InvalidParams(format!("'{}' is not archived", p.id)));
        }
        self.check_room()?;
        let from = self.source(p.copy_from.as_deref())?;
        row.archived_at = None;
        let network = from.map(|f| copied(&self.settings(), &f, &row.id));
        self.change_keys(&actor, "restore_invoice_key", vec![row], network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manage::UpdateSettingsParams;
    use crate::service::tests::{public, rig, Rig, T0};
    use crate::service::{CreateInvoiceParams, ListInvoicesParams};
    use crate::settings::Destination;
    use nostr_sdk::Keys;

    fn add(id: &str) -> AddInvoiceKeyParams {
        AddInvoiceKeyParams {
            id: id.into(),
            label: format!("{id} label"),
            ..AddInvoiceKeyParams::default()
        }
    }

    fn err(r: Result<InvoiceKeyList>) -> String {
        r.unwrap_err().to_string()
    }

    fn ids(l: &InvoiceKeyList) -> Vec<&str> {
        l.keys.iter().map(|k| k.key.id.as_str()).collect()
    }

    fn rule(keys: &[&str]) -> crate::routes::Rule {
        crate::routes::Rule {
            name: String::new(),
            patterns: vec!["*.example".into()],
            keys: keys.iter().map(|k| k.to_string()).collect(),
            to: Destination::Direct,
            fallback: Default::default(),
        }
    }

    /// The env relays, with `wss://relay.example` for the original key only,
    /// a rule for it, and a default route of its own.
    fn shared_out(r: &Rig) {
        let patch = SettingsPatch {
            relay_keys: Some([("wss://relay.example".to_string(), vec![INVOICES.to_string()])].into()),
            proxies: Some(ProxyPatch {
                rules: Some(vec![rule(&[INVOICES])]),
                default_keys: Some([(INVOICES.to_string(), Destination::Direct)].into()),
                ..ProxyPatch::default()
            }),
            ..SettingsPatch::default()
        };
        r.svc
            .update_settings(&r.admin(), UpdateSettingsParams { patch })
            .unwrap();
    }

    fn invoice(key: Option<&str>) -> CreateInvoiceParams {
        CreateInvoiceParams {
            amount_sat: 5_000,
            memo: None,
            expiry_secs: None,
            key: key.map(String::from),
        }
    }

    #[tokio::test]
    async fn a_key_is_added_with_the_relays_and_routes_of_another() {
        let r = rig(|_| {}).await;
        shared_out(&r);
        let l = r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        assert_eq!(ids(&l), [INVOICES, "shop"]);
        let shop = &l.keys[1];
        assert!(!shop.original && l.keys[0].original);
        assert_eq!(shop.relays, ["ws://127.0.0.1:7777", "wss://relay.example"]);
        assert_eq!(
            (shop.key.color, shop.key.public_invoicing, shop.key.announce),
            (1, true, false)
        );
        assert_eq!(l.max_keys, 7);
        let s = r.svc.settings().clone();
        assert_eq!(s.relay_keys["wss://relay.example"], [INVOICES, "shop"]);
        assert_eq!(s.proxies.rules[0].keys, [INVOICES, "shop"]);
        assert_eq!(s.proxies.default_keys["shop"], Destination::Direct);
        // Its secret is on disk, and it is a lane of the network settings now.
        assert!(r.svc.cfg.data_dir.join("keys/shop.nsec").exists());
        assert!(r.svc.settings().lanes.iter().any(|l| l.id == "shop"));
        assert!(r.svc.key_infos().iter().any(|k| k.id == "shop"));
        // Saved settings that name it still load after a restart.
        let stored = r.svc.stored_patch().unwrap();
        assert!(stored.relay_keys.unwrap()["wss://relay.example"].contains(&"shop".to_string()));
        // Starting from nothing: only what every key uses.
        let plain = AddInvoiceKeyParams {
            copy_from: Some(String::new()),
            ..add("cafe")
        };
        let l = r.svc.add_invoice_key(&r.admin(), plain).unwrap();
        assert_eq!(l.keys[2].relays, ["ws://127.0.0.1:7777"]);
        assert!(!r.svc.settings().proxies.default_keys.contains_key("cafe"));
        // Copying from a key with no default route of its own copies none.
        let from_cafe = AddInvoiceKeyParams {
            copy_from: Some("cafe".into()),
            ..add("bar")
        };
        r.svc.add_invoice_key(&r.admin(), from_cafe).unwrap();
        assert!(!r.svc.settings().proxies.default_keys.contains_key("bar"));
    }

    #[tokio::test]
    async fn adding_a_key_is_checked() {
        let r = rig(|_| {}).await;
        assert!(err(r.svc.add_invoice_key(&r.admin(), add("Bad"))).contains("lower-case"));
        let blank = AddInvoiceKeyParams {
            label: " ".into(),
            ..add("shop")
        };
        assert!(err(r.svc.add_invoice_key(&r.admin(), blank)).contains("label"));
        let from = AddInvoiceKeyParams {
            copy_from: Some(crate::keys::ADMIN.into()),
            ..add("shop")
        };
        assert!(err(r.svc.add_invoice_key(&r.admin(), from)).contains("copy_from"));
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        assert!(err(r.svc.add_invoice_key(&r.admin(), add("shop"))).ends_with("'shop'"));
        for id in ["k2", "k3", "k4", "k5", "k6"] {
            r.svc.add_invoice_key(&r.admin(), add(id)).unwrap();
        }
        assert!(err(r.svc.add_invoice_key(&r.admin(), add("k7"))).contains("at most 7"));
        let gone = InvoiceKeyIdParams {
            id: "k6".into(),
            copy_from: None,
        };
        r.svc.archive_invoice_key(&r.admin(), gone.clone()).unwrap();
        assert!(err(r.svc.add_invoice_key(&r.admin(), add("k6"))).contains("restore it"));
        // Only operators.
        let stranger = public(&Keys::generate(), 4, T0);
        assert_eq!(
            r.svc.add_invoice_key(&stranger, add("x2")).unwrap_err().code(),
            "unauthorized"
        );
        assert_eq!(
            r.svc
                .list_invoice_keys(&stranger, ListInvoiceKeysParams::default())
                .unwrap_err()
                .code(),
            "unauthorized"
        );
        // A key file that cannot be written changes nothing.
        std::fs::write(r.svc.cfg.data_dir.join("keys/x2.nsec"), "junk").unwrap();
        r.svc
            .archive_invoice_key(
                &r.admin(),
                InvoiceKeyIdParams {
                    id: "k5".into(),
                    copy_from: None,
                },
            )
            .unwrap();
        assert!(r.svc.add_invoice_key(&r.admin(), add("x2")).is_err());
        assert!(r.svc.registry().row("x2").is_none());
    }

    #[tokio::test]
    async fn keys_are_relabelled_and_presented() {
        let r = rig(|_| {}).await;
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        let change = UpdateInvoiceKeyParams {
            id: "shop".into(),
            label: Some(" Shop ".into()),
            name: Some("Corner Shop".into()),
            public_invoicing: Some(false),
            announce: Some(true),
            color: Some(3),
            description: Some("the shop".into()),
        };
        let l = r.svc.update_invoice_key(&r.admin(), change).unwrap();
        let shop = &l.keys[1].key;
        assert_eq!(
            (
                shop.label.as_str(),
                shop.name.as_str(),
                shop.public_invoicing,
                shop.announce,
                shop.color
            ),
            ("Shop", "Corner Shop", false, true, 3)
        );
        assert_eq!(r.svc.info_on(&r.admin(), "shop").unwrap().name, "Corner Shop");
        assert!(!r.svc.info_on(&r.admin(), "shop").unwrap().public_invoicing);
        assert_eq!(r.svc.registry().def("shop").unwrap().label, "Shop");
        // The original key: its label, description and colour only.
        let original = UpdateInvoiceKeyParams {
            id: INVOICES.into(),
            label: Some("Storefront".into()),
            ..UpdateInvoiceKeyParams::default()
        };
        let l = r.svc.update_invoice_key(&r.admin(), original).unwrap();
        assert_eq!(l.keys[0].key.label, "Storefront");
        assert!(l.keys[0].key.public_invoicing);
        assert_eq!(r.svc.key_infos()[0].label, "Storefront");
        // A later change to another key keeps the original's label.
        let again = UpdateInvoiceKeyParams {
            id: "shop".into(),
            color: Some(2),
            ..UpdateInvoiceKeyParams::default()
        };
        let l = r.svc.update_invoice_key(&r.admin(), again).unwrap();
        assert_eq!((l.keys[0].key.label.as_str(), l.keys[1].key.color), ("Storefront", 2));
        let name = UpdateInvoiceKeyParams {
            id: INVOICES.into(),
            name: Some("x".into()),
            ..UpdateInvoiceKeyParams::default()
        };
        assert!(err(r.svc.update_invoice_key(&r.admin(), name)).contains("service settings"));
        let nobody = UpdateInvoiceKeyParams {
            id: "nobody".into(),
            ..UpdateInvoiceKeyParams::default()
        };
        assert!(err(r.svc.update_invoice_key(&r.admin(), nobody)).contains("no invoice key"));
        let bad = UpdateInvoiceKeyParams {
            id: "shop".into(),
            color: Some(9),
            ..UpdateInvoiceKeyParams::default()
        };
        assert!(err(r.svc.update_invoice_key(&r.admin(), bad)).contains("color"));
    }

    #[tokio::test]
    async fn archiving_takes_a_key_out_and_restoring_brings_it_back() {
        let r = rig(|_| {}).await;
        shared_out(&r);
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        let shop = |copy_from: Option<&str>| InvoiceKeyIdParams {
            id: "shop".into(),
            copy_from: copy_from.map(String::from),
        };
        assert!(err(r.svc.restore_invoice_key(&r.admin(), shop(None))).contains("not archived"));
        let l = r.svc.archive_invoice_key(&r.admin(), shop(None)).unwrap();
        assert_eq!(l.keys[1].key.archived_at, Some(T0));
        assert!(l.keys[1].relays.is_empty());
        let s = r.svc.settings().clone();
        assert_eq!(s.relay_keys["wss://relay.example"], [INVOICES]);
        assert_eq!(s.proxies.rules[0].keys, [INVOICES]);
        assert!(!s.proxies.default_keys.contains_key("shop"));
        assert!(r.svc.registry().def("shop").is_none());
        assert!(err(r.svc.archive_invoice_key(&r.admin(), shop(None))).contains("already archived"));
        let l = r.svc.restore_invoice_key(&r.admin(), shop(Some(INVOICES))).unwrap();
        assert_eq!(l.keys[1].key.archived_at, None);
        assert_eq!(r.svc.settings().relay_keys["wss://relay.example"], [INVOICES, "shop"]);
        let original = InvoiceKeyIdParams {
            id: INVOICES.into(),
            copy_from: None,
        };
        assert!(err(r.svc.archive_invoice_key(&r.admin(), original)).contains("no added invoice key"));
    }

    #[tokio::test]
    async fn a_key_that_alone_uses_a_relay_or_rule_is_not_archived() {
        let r = rig(|_| {}).await;
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        let only = |relay_keys: Option<Vec<&str>>, rule_keys: Option<Vec<&str>>| SettingsPatch {
            relay_keys: relay_keys.map(|k| {
                [(
                    "wss://relay.example".to_string(),
                    k.iter().map(|s| s.to_string()).collect(),
                )]
                .into()
            }),
            proxies: rule_keys.map(|k| ProxyPatch {
                rules: Some(vec![rule(&k)]),
                ..ProxyPatch::default()
            }),
            ..SettingsPatch::default()
        };
        let set = |patch| {
            r.svc
                .update_settings(&r.admin(), UpdateSettingsParams { patch })
                .unwrap()
        };
        set(only(Some(vec!["shop"]), None));
        let shop = InvoiceKeyIdParams {
            id: "shop".into(),
            copy_from: None,
        };
        assert!(err(r.svc.archive_invoice_key(&r.admin(), shop.clone())).contains("relay 'wss://relay.example'"));
        set(only(Some(vec![INVOICES, "shop"]), Some(vec!["shop"])));
        assert!(err(r.svc.archive_invoice_key(&r.admin(), shop.clone())).contains("rule 1"));
    }

    #[tokio::test]
    async fn invoices_are_booked_to_the_key_they_came_in_on() {
        let r = rig(|_| {}).await;
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        let keys = Keys::generate();
        let on_shop = r
            .svc
            .create_invoice_on(&public(&keys, 4, T0), invoice(None), "shop")
            .unwrap();
        // An operator books one to the shop from the administration key.
        let booked = r
            .svc
            .create_invoice_on(&r.admin(), invoice(Some("shop")), crate::keys::ADMIN)
            .unwrap();
        let mine = r
            .svc
            .create_invoice_on(&r.admin(), invoice(None), crate::keys::ADMIN)
            .unwrap();
        // On an invoice key, only that key may be named.
        let same = r
            .svc
            .create_invoice_on(&public(&keys, 4, T0 + 1), invoice(Some("shop")), "shop")
            .unwrap();
        let other = r
            .svc
            .create_invoice_on(&public(&keys, 4, T0 + 2), invoice(Some(INVOICES)), "shop")
            .unwrap_err();
        assert!(other.to_string().contains("only 'shop'"));
        let unknown = r
            .svc
            .create_invoice_on(&r.admin(), invoice(Some("nobody")), crate::keys::ADMIN)
            .unwrap_err();
        assert!(unknown.to_string().contains("no invoice key 'nobody'"));
        let admin = r
            .svc
            .create_invoice_on(&r.admin(), invoice(Some(crate::keys::ADMIN)), crate::keys::ADMIN)
            .unwrap_err();
        assert!(admin.to_string().contains("no invoice key 'admin'"));
        let list = |key: Option<&str>| {
            r.svc
                .list_invoices(
                    &r.admin(),
                    ListInvoicesParams {
                        key: key.map(String::from),
                        with_key: true,
                        ..ListInvoicesParams::default()
                    },
                )
                .unwrap()
        };
        let shop = list(Some("shop"));
        let got: Vec<&str> = shop.invoices.iter().map(|i| i.invoice.id.as_str()).collect();
        assert_eq!(got, [same.id.as_str(), booked.id.as_str(), on_shop.id.as_str()]);
        assert!(shop.invoices.iter().all(|i| i.key.as_deref() == Some("shop")));
        assert_eq!(list(Some(INVOICES)).invoices[0].invoice.id, mine.id);
        // Without with_key the rows are what they always were.
        let plain = r.svc.list_invoices(&r.admin(), ListInvoicesParams::default()).unwrap();
        assert!(plain.invoices.iter().all(|i| i.key.is_none()));
        let v = serde_json::to_value(&plain.invoices[0]).unwrap();
        assert!(v.get("key").is_none());
        // The ledger.
        let l = r
            .svc
            .list_invoice_keys(&r.admin(), ListInvoiceKeysParams { since: None })
            .unwrap();
        assert_eq!((l.keys[0].totals.pending, l.keys[1].totals.pending), (1, 3));
        let later = r
            .svc
            .list_invoice_keys(&r.admin(), ListInvoiceKeysParams { since: Some(T0 + 1) })
            .unwrap();
        assert_eq!((later.since, later.keys[1].totals.pending), (T0 + 1, 0));
    }

    #[tokio::test]
    async fn a_key_closed_to_the_public_takes_operators_only() {
        let r = rig(|_| {}).await;
        r.svc
            .add_invoice_key(
                &r.admin(),
                AddInvoiceKeyParams {
                    public_invoicing: Some(false),
                    name: Some("Back office".into()),
                    ..add("office")
                },
            )
            .unwrap();
        let e = r
            .svc
            .create_invoice_on(&public(&Keys::generate(), 4, T0), invoice(None), "office")
            .unwrap_err();
        assert_eq!(e.code(), "unauthorized");
        assert_eq!(r.svc.info_on(&r.admin(), "office").unwrap().name, "Back office");
        r.svc.create_invoice_on(&r.admin(), invoice(None), "office").unwrap();
        // The original key still presents the service.
        assert!(r.svc.info(&r.admin()).unwrap().public_invoicing);
    }

    #[tokio::test]
    async fn an_archived_key_shows_the_public_key_on_disk() {
        let r = rig(|_| {}).await;
        r.svc.add_invoice_key(&r.admin(), add("shop")).unwrap();
        r.svc
            .archive_invoice_key(
                &r.admin(),
                InvoiceKeyIdParams {
                    id: "shop".into(),
                    copy_from: None,
                },
            )
            .unwrap();
        // Nothing loaded it in this rig, so its public key is read from its file, once there.
        let l = r
            .svc
            .list_invoice_keys(&r.admin(), ListInvoiceKeysParams::default())
            .unwrap();
        assert_eq!(l.keys[1].pubkey, "");
        std::fs::write(r.svc.cfg.data_dir.join("keys/shop.pubkey"), "ab12").unwrap();
        let l = r
            .svc
            .list_invoice_keys(&r.admin(), ListInvoiceKeysParams::default())
            .unwrap();
        assert_eq!(l.keys[1].pubkey, "ab12");
        // A loaded key's public key comes from the service.
        r.svc.set_key_pubkey(INVOICES, "cd34");
        let l = r
            .svc
            .list_invoice_keys(&r.admin(), ListInvoiceKeysParams::default())
            .unwrap();
        assert_eq!(l.keys[0].pubkey, "cd34");
    }

    #[tokio::test]
    async fn settings_that_no_longer_validate_change_no_key() {
        let r = rig(|_| {}).await;
        // Saved settings that cannot be read are refused before any key changes.
        r.svc.db.meta_set(META_SETTINGS, Some("{not json")).unwrap();
        assert!(r.svc.add_invoice_key(&r.admin(), add("shop")).is_err());
        assert!(r.svc.registry().row("shop").is_none());
    }
}
