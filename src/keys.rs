//! The service's nostr keys, one per purpose.
//!
//! Two keys are built in: the original invoice key (`invoices`, the address
//! customers have always used) and the administration key (`admin`). An
//! operator may add more invoice keys, one per service they run on this
//! server, so that each service's invoices are booked to its own key. What a
//! key may do is fixed by its kind: every invoice key serves the public tools
//! and nothing else, the administration key serves operators only.
//!
//! Settings refer to keys by their `id` (a string). Ids are permanent: a key
//! is archived, never deleted, so nothing saved ever names a key that is gone.

use std::path::Path;
use std::sync::Arc;

use nostr_sdk::Keys;
use rmcp::schemars::{self, JsonSchema};
use serde::Serialize;

use crate::error::{Error, Result};

/// The original invoice key: the public one, the address customers already use.
pub const INVOICES: &str = "invoices";
/// The key operators manage the service through.
pub const ADMIN: &str = "admin";
/// Invoice keys in use at once, the original one included. With the
/// administration key that makes 8, the most keys the dashboards and consoles
/// already in use accept.
pub const MAX_INVOICE_KEYS: usize = 7;
/// Directory (in the data directory) holding the added keys' secrets.
pub const KEYS_DIR: &str = "keys";
/// Colours a key can be shown in (indices into the dashboard's palette).
pub const COLORS: u8 = 8;
/// Longest label, description and announced name.
pub const LABEL_LEN: usize = 40;
pub const DESCRIPTION_LEN: usize = 120;
pub const NAME_LEN: usize = 64;

/// One key and its fixed scope.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyDef {
    pub id: String,
    /// What the dashboard calls it.
    pub label: String,
    /// File (in the data directory) holding the secret key.
    pub file: String,
    /// File the public key is written to once the service is serving.
    pub pubkey_file: String,
    /// The tools this key serves; `None` is all of them.
    pub tools: Option<&'static [&'static str]>,
    /// Only operators may use this key at all.
    pub operators_only: bool,
    /// Whether this key may be announced on the relays (when announcing is on).
    pub announce: bool,
}

/// The tools anyone may call.
pub const PUBLIC_TOOLS: [&str; 3] = ["get_info", "create_invoice", "get_invoice"];

/// The built-in keys, before any label an operator gave them.
pub fn builtin() -> [KeyDef; 2] {
    [
        KeyDef {
            id: INVOICES.into(),
            label: "Public invoices".into(),
            // The first key the service ever had: it stays the public one, so the
            // address customers already use does not change.
            file: crate::app::KEY_FILE.into(),
            pubkey_file: crate::app::PUBKEY_FILE.into(),
            tools: Some(&PUBLIC_TOOLS),
            operators_only: false,
            announce: true,
        },
        KeyDef {
            id: ADMIN.into(),
            label: "Administration".into(),
            file: "admin.nsec".into(),
            pubkey_file: "admin.pubkey".into(),
            tools: None,
            operators_only: true,
            announce: false,
        },
    ]
}

/// Whether `id` names a built-in key.
pub fn is_builtin(id: &str) -> bool {
    id == INVOICES || id == ADMIN
}

/// What is stored about a key: everything about an added invoice key, and the
/// label, description and colour an operator gave a built-in one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct KeyRow {
    pub id: String,
    pub label: String,
    pub description: String,
    /// Index into the dashboard's palette, 0 to 7.
    pub color: u8,
    /// The service name this key gives in `get_info` and its announcement;
    /// empty is the service's own name.
    pub name: String,
    /// Whether anyone (not only operators) may create invoices on this key.
    /// The service-wide setting must allow it too.
    pub public_invoicing: bool,
    /// Whether this key is announced on the relays (when announcing is on).
    pub announce: bool,
    pub created_at: u64,
    /// The operator who added it (hex public key); empty for a built-in key.
    pub created_by: String,
    /// When it was archived; an archived key is not connected and serves nothing.
    pub archived_at: Option<u64>,
}

/// An added invoice key's fixed scope.
pub fn added_def(id: &str, label: &str, announce: bool) -> KeyDef {
    KeyDef {
        id: id.into(),
        label: label.into(),
        file: format!("{KEYS_DIR}/{id}.nsec"),
        pubkey_file: format!("{KEYS_DIR}/{id}.pubkey"),
        tools: Some(&PUBLIC_TOOLS),
        operators_only: false,
        announce,
    }
}

/// Check an id an operator chose for a new key: lower-case letters, digits
/// and dashes, starting with a letter, 2 to 24 characters, and not a built-in id.
pub fn check_new_id(id: &str) -> Result<()> {
    let shaped = (2..=24).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !shaped {
        return Err(Error::InvalidParams(
            "id must be 2 to 24 lower-case letters, digits or dashes, starting with a letter".into(),
        ));
    }
    if is_builtin(id) {
        return Err(Error::InvalidParams(format!("'{id}' is a built-in key")));
    }
    Ok(())
}

/// Check the text an operator gave a key.
pub fn check_text(label: &str, description: &str, name: &str, color: u8) -> Result<()> {
    let plain = |s: &str, max: usize| s.chars().count() <= max && s.chars().all(crate::service::is_plain_text);
    if label.trim().is_empty() || !plain(label, LABEL_LEN) {
        return Err(Error::InvalidParams(format!(
            "label must be 1 to {LABEL_LEN} visible characters"
        )));
    }
    if !plain(description, DESCRIPTION_LEN) {
        return Err(Error::InvalidParams(format!(
            "description must be at most {DESCRIPTION_LEN} visible characters"
        )));
    }
    if !plain(name, NAME_LEN) {
        return Err(Error::InvalidParams(format!(
            "name must be at most {NAME_LEN} visible characters"
        )));
    }
    if color >= COLORS {
        return Err(Error::InvalidParams(format!("color must be below {COLORS}")));
    }
    Ok(())
}

/// Every key the service knows: the built-in ones and the added ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    rows: Vec<KeyRow>,
}

impl Registry {
    pub fn new(rows: Vec<KeyRow>) -> Self {
        Registry { rows }
    }

    /// The stored row of a key, if any.
    pub fn row(&self, id: &str) -> Option<&KeyRow> {
        self.rows.iter().find(|r| r.id == id)
    }

    /// The added invoice keys, archived ones included, oldest first.
    pub fn added(&self) -> impl Iterator<Item = &KeyRow> {
        self.rows.iter().filter(|r| !is_builtin(&r.id))
    }

    /// The added invoice keys in use (not archived).
    pub fn active(&self) -> impl Iterator<Item = &KeyRow> {
        self.added().filter(|r| r.archived_at.is_none())
    }

    /// The keys in use, in the order they are shown and started: the original
    /// invoice key, the added ones, then the administration key. Built-in
    /// keys carry the label an operator gave them.
    pub fn defs(&self) -> Vec<Arc<KeyDef>> {
        let [invoices, admin] = builtin();
        let relabel = |mut d: KeyDef| {
            if let Some(r) = self.row(&d.id) {
                d.label = r.label.clone();
            }
            Arc::new(d)
        };
        let mut out = vec![relabel(invoices)];
        out.extend(self.active().map(|r| Arc::new(added_def(&r.id, &r.label, r.announce))));
        out.push(relabel(admin));
        out
    }

    /// The key in use with this id.
    pub fn def(&self, id: &str) -> Option<Arc<KeyDef>> {
        self.defs().into_iter().find(|d| d.id == id)
    }

    /// The keys in use as the network settings see them: one lane each.
    pub fn lanes(&self) -> Vec<crate::network::Lane> {
        self.defs()
            .iter()
            .map(|k| crate::network::Lane {
                id: k.id.clone(),
                label: k.label.clone(),
            })
            .collect()
    }

    /// The label of any key, archived ones included; its id when unknown.
    pub fn label(&self, id: &str) -> String {
        match (self.row(id), builtin().iter().find(|d| d.id == id)) {
            (Some(r), _) => r.label.clone(),
            (None, Some(d)) => d.label.clone(),
            (None, None) => id.to_string(),
        }
    }
}

/// The built-in keys as the network settings see them, before any key is
/// added (for checking the environment's settings).
pub fn lanes() -> Vec<crate::network::Lane> {
    Registry::default().lanes()
}

// Assigning things to keys lives with the network settings; kept at its old path.
pub use crate::network::assigned;

/// Check that every id names one of `lanes`, and none is named twice.
pub fn check_ids(lanes: &[crate::network::Lane], keys: &[String], what: &str) -> Result<()> {
    Ok(crate::network::check_ids(lanes, keys, what)?)
}

/// A key and what it is for.
pub struct Identity {
    pub def: Arc<KeyDef>,
    pub keys: Keys,
}

impl Identity {
    pub fn pubkey(&self) -> String {
        self.keys.public_key().to_hex()
    }
}

/// Load one key from the data directory, creating it if it does not exist yet.
pub fn open_identity(data_dir: &Path, def: Arc<KeyDef>) -> Result<Identity> {
    crate::app::open_dir(data_dir)?;
    if def.file.starts_with(KEYS_DIR) {
        crate::app::open_dir(&data_dir.join(KEYS_DIR))?;
    }
    let keys = crate::app::load_or_create_keys(&data_dir.join(&def.file))?;
    Ok(Identity { def, keys })
}

/// Load every key in use from the data directory, creating the ones that do
/// not exist yet (the data directory too).
pub fn open_identities(data_dir: &Path, registry: &Registry) -> Result<Vec<Identity>> {
    registry
        .defs()
        .into_iter()
        .map(|def| open_identity(data_dir, def))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An added key as a test wants it.
    pub fn row(id: &str, archived: bool) -> KeyRow {
        KeyRow {
            id: id.into(),
            label: format!("{id} label"),
            description: String::new(),
            color: 1,
            name: String::new(),
            public_invoicing: true,
            announce: false,
            created_at: 1,
            created_by: "ab".into(),
            archived_at: archived.then_some(2),
        }
    }

    #[test]
    fn the_builtin_keys_are_consistent() {
        let [invoices, admin] = builtin();
        assert_eq!(invoices.file, "server.nsec");
        // Nothing but the public tools reaches the public key, and the admin
        // key is never announced.
        assert_eq!(invoices.tools, Some(&PUBLIC_TOOLS[..]));
        assert!(!admin.announce && admin.operators_only);
        assert!(!invoices.operators_only);
        assert!(is_builtin(INVOICES) && is_builtin(ADMIN) && !is_builtin("shop"));
    }

    #[test]
    fn the_registry_orders_relabels_and_leaves_out_archived_keys() {
        let empty = Registry::default();
        let ids: Vec<String> = empty.defs().iter().map(|d| d.id.clone()).collect();
        assert_eq!(ids, [INVOICES, ADMIN]);
        assert_eq!(lanes().len(), 2);
        let mut original = row(INVOICES, false);
        original.label = "Storefront".into();
        let r = Registry::new(vec![original, row("shop", false), row("gone", true)]);
        let ids: Vec<String> = r.defs().iter().map(|d| d.id.clone()).collect();
        assert_eq!(ids, [INVOICES, "shop", ADMIN]);
        assert_eq!(r.def(INVOICES).unwrap().label, "Storefront");
        assert_eq!(r.def(ADMIN).unwrap().label, "Administration");
        let shop = r.def("shop").unwrap();
        assert_eq!(
            (shop.file.as_str(), shop.pubkey_file.as_str()),
            ("keys/shop.nsec", "keys/shop.pubkey")
        );
        assert_eq!(shop.tools, Some(&PUBLIC_TOOLS[..]));
        assert!(!shop.operators_only && !shop.announce);
        assert!(r.def("gone").is_none());
        assert_eq!(r.added().count(), 2);
        assert_eq!(r.active().count(), 1);
        assert_eq!(r.lanes().len(), 3);
        assert_eq!(r.label("gone"), "gone label");
        assert_eq!(r.label(ADMIN), "Administration");
        assert_eq!(r.label("nobody"), "nobody");
    }

    #[test]
    fn new_ids_and_texts_are_checked() {
        assert!(check_new_id("bread-club").is_ok());
        assert!(check_new_id("b2").is_ok());
        for bad in ["", "a", "Shop", "1shop", "shop_x", "a234567890123456789012345", "-x"] {
            assert!(check_new_id(bad).is_err(), "{bad}");
        }
        assert!(check_new_id(ADMIN).unwrap_err().to_string().contains("built-in"));
        assert!(check_text("Shop", "", "", 0).is_ok());
        assert!(check_text(" ", "", "", 0).is_err());
        assert!(check_text(&"x".repeat(41), "", "", 0).is_err());
        assert!(check_text("Shop", &"x".repeat(121), "", 0).is_err());
        assert!(check_text("Shop", "", "bad\nname", 0).is_err());
        assert!(check_text("Shop", "", "", COLORS).is_err());
    }

    #[test]
    fn an_empty_assignment_is_every_key() {
        let only = vec![ADMIN.to_string()];
        assert!(assigned(&[], INVOICES) && assigned(&[], ADMIN));
        assert!(assigned(&only, ADMIN) && !assigned(&only, INVOICES));
    }

    #[test]
    fn ids_are_checked() {
        let l = lanes();
        assert!(check_ids(&l, &[], "x").is_ok());
        assert!(check_ids(&l, &[ADMIN.into(), INVOICES.into()], "x").is_ok());
        let unknown = check_ids(&l, &["root".into()], "relay").unwrap_err().to_string();
        assert!(unknown.contains("no key 'root'"), "{unknown}");
        let twice = check_ids(&l, &[ADMIN.into(), ADMIN.into()], "proxy")
            .unwrap_err()
            .to_string();
        assert!(twice.contains("twice"), "{twice}");
    }

    #[test]
    fn each_key_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::new(vec![row("shop", false)]);
        let first = open_identities(&dir.path().join("data"), &reg).unwrap();
        let again = open_identities(&dir.path().join("data"), &reg).unwrap();
        assert_eq!(first.len(), 3);
        assert_ne!(first[0].pubkey(), first[1].pubkey());
        for (a, b) in first.iter().zip(&again) {
            assert_eq!(a.pubkey(), b.pubkey());
        }
        assert!(dir.path().join("data/keys/shop.nsec").exists());
        // A file in the way of a key is an error, not a new key.
        let file = dir.path().join("plain");
        std::fs::write(&file, "x").unwrap();
        assert!(open_identities(&file, &reg).is_err());
        // So is a file where the keys directory should be.
        let d2 = dir.path().join("d2");
        std::fs::create_dir(&d2).unwrap();
        std::fs::write(d2.join(KEYS_DIR), "x").unwrap();
        assert!(open_identities(&d2, &reg).is_err());
    }
}
