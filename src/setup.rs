//! Setup mode: what the service does before it has ever been set up.
//!
//! A service that is given none of the settings that say what it watches and
//! who may use it (`DEADHOP_ELECTRUM`, `DEADHOP_ADMINS`,
//! `DEADHOP_PUBLIC_INVOICING`) and whose data directory holds no database has
//! never run. Rather than exit, and be restarted in a loop by its supervisor,
//! it stays up idle: it connects to nothing, names what is missing in its log,
//! and writes the same list (names only, never a value) to
//! `DEADHOP_PUBLIC_DIR/setup.json`, where the dashboard finds it and offers to
//! walk the operator through the settings.
//!
//! Anything else still stops the service as before: a value that is present
//! but wrong, only some of those settings, or a service that has a database
//! (it was set up once) and lost its settings.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::config::parse_network;

/// File in `DEADHOP_PUBLIC_DIR` telling the dashboard that the service waits
/// for its settings. Removed when the service starts with them.
pub const SETUP_FILE: &str = "setup.json";

/// How often the log repeats what is missing while the service waits.
pub const REMIND_EVERY: Duration = Duration::from_secs(600);

/// The settings whose absence (all of them) means "never set up".
const UNSET_WHEN_NEW: [&str; 3] = ["DEADHOP_ELECTRUM", "DEADHOP_ADMINS", "DEADHOP_PUBLIC_INVOICING"];

/// Whether a setting was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Required, and not given.
    Missing,
    /// Given.
    Found,
    /// Not given; the service has a default for it.
    Default,
}

/// One setting the dashboard asks about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Setting {
    /// Its variable.
    pub name: &'static str,
    /// Whether it was given.
    pub state: State,
    /// What it is for, in a few words.
    pub about: &'static str,
}

/// What `setup.json` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// Format of this file.
    pub version: u32,
    /// The network the service would run on (`DEADHOP_NETWORK`, or the default).
    pub network: String,
    /// Each setting the dashboard asks about, and whether it was given.
    pub settings: Vec<Setting>,
}

/// The setup status, when the service has never been set up; `None` when it
/// should load its configuration as usual (and fail on what is wrong).
/// `has_database` says whether the data directory holds a database.
pub fn status(get: &dyn Fn(&str) -> Option<String>, has_database: bool) -> Option<Status> {
    let get = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if has_database || UNSET_WHEN_NEW.iter().any(|k| get(k).is_some()) {
        return None;
    }
    let network = match get("DEADHOP_NETWORK") {
        None => "bitcoin".to_string(),
        Some(n) => {
            parse_network(&n).ok()?;
            if n == "mainnet" {
                "bitcoin".to_string()
            } else {
                n
            }
        }
    };
    let given = |found: bool, otherwise: State| if found { State::Found } else { otherwise };
    let has_xpub = get("DEADHOP_XPUB").is_some()
        || get("DEADHOP_XPUB_FILE")
            .and_then(|f| fs::read_to_string(f).ok())
            .is_some_and(|k| !k.trim().is_empty());
    let settings = vec![
        Setting {
            name: "DEADHOP_ELECTRUM",
            state: State::Missing,
            about: "where to watch the chain",
        },
        Setting {
            name: "DEADHOP_ADMINS",
            state: State::Missing,
            about: "who may operate it (or DEADHOP_PUBLIC_INVOICING=true)",
        },
        Setting {
            name: "DEADHOP_XPUB",
            state: given(has_xpub, State::Missing),
            about: "the account key payments go to",
        },
        Setting {
            name: "DEADHOP_RELAYS",
            state: given(get("DEADHOP_RELAYS").is_some(), State::Missing),
            about: "the relays it is reached through",
        },
        Setting {
            name: "DEADHOP_NETWORK",
            state: given(get("DEADHOP_NETWORK").is_some(), State::Default),
            about: "the bitcoin network",
        },
    ];
    Some(Status {
        version: 1,
        network,
        settings,
    })
}

/// Write `setup.json` into the public directory, if there is one.
fn publish(status: &Status, dir: Option<&Path>) {
    let Some(dir) = dir else { return };
    let body = serde_json::to_string(status).expect("plain data serializes");
    let tmp = dir.join(format!("{SETUP_FILE}.new"));
    let written = fs::write(&tmp, body).and_then(|()| fs::rename(&tmp, dir.join(SETUP_FILE)));
    if let Err(e) = written {
        tracing::warn!(error = %e, dir = %dir.display(), "could not tell the dashboard that the service waits for its settings");
    }
}

/// Name what is missing in the log.
fn remind(status: &Status) {
    tracing::warn!(network = %status.network, "deadhop is not set up yet: waiting for its settings (setup mode)");
    for s in &status.settings {
        match s.state {
            State::Missing => tracing::warn!("  missing  {}  {}", s.name, s.about),
            State::Found => tracing::info!("  found    {}  {}", s.name, s.about),
            State::Default => tracing::info!("  default  {}  {}", s.name, s.about),
        }
    }
    tracing::info!(
        "open the dashboard to answer a few questions and get the settings to paste, then restart the service"
    );
    tracing::info!("nothing is connected: no relay, no Electrum, no invoices");
}

/// Wait idle, connected to nothing, until `shutdown`: publish the status for
/// the dashboard and repeat what is missing in the log every `every`.
pub async fn wait(status: Status, public_dir: Option<&Path>, shutdown: impl Future<Output = ()>, every: Duration) {
    publish(&status, public_dir);
    tokio::pin!(shutdown);
    loop {
        remind(&status);
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(every) => {}
        }
    }
}

/// Remove a `setup.json` left by an earlier run in setup mode: the service
/// now has its settings.
pub fn clear(public_dir: Option<&Path>) {
    if let Some(dir) = public_dir {
        let _ = fs::remove_file(dir.join(SETUP_FILE));
    }
}

/// `DEADHOP_PUBLIC_DIR`, when it is set and not blank.
pub fn public_dir(get: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    get("DEADHOP_PUBLIC_DIR")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    fn state(s: &Status, name: &str) -> State {
        s.settings.iter().find(|x| x.name == name).unwrap().state
    }

    #[test]
    fn nothing_set_and_no_database_is_setup_mode() {
        let s = status(&lookup(&[]), false).unwrap();
        assert_eq!(s.version, 1);
        assert_eq!(s.network, "bitcoin");
        assert_eq!(state(&s, "DEADHOP_ELECTRUM"), State::Missing);
        assert_eq!(state(&s, "DEADHOP_ADMINS"), State::Missing);
        assert_eq!(state(&s, "DEADHOP_XPUB"), State::Missing);
        assert_eq!(state(&s, "DEADHOP_RELAYS"), State::Missing);
        assert_eq!(state(&s, "DEADHOP_NETWORK"), State::Default);
        // Blank values, as container platforms pass unset ones, count as unset.
        let blank = lookup(&[
            ("DEADHOP_ELECTRUM", " "),
            ("DEADHOP_ADMINS", ""),
            ("DEADHOP_PUBLIC_INVOICING", ""),
        ]);
        assert!(status(&blank, false).is_some());
    }

    #[test]
    fn any_of_the_settings_or_a_database_means_set_up() {
        for k in UNSET_WHEN_NEW {
            assert_eq!(status(&lookup(&[(k, "false")]), false), None, "{k}");
        }
        assert_eq!(status(&lookup(&[]), true), None);
    }

    #[test]
    fn what_was_given_is_found() {
        let s = status(
            &lookup(&[
                ("DEADHOP_RELAYS", "wss://relay.example"),
                ("DEADHOP_NETWORK", "regtest"),
                ("DEADHOP_XPUB", "xpub…"),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(s.network, "regtest");
        assert_eq!(state(&s, "DEADHOP_RELAYS"), State::Found);
        assert_eq!(state(&s, "DEADHOP_NETWORK"), State::Found);
        assert_eq!(state(&s, "DEADHOP_XPUB"), State::Found);
        let s = status(&lookup(&[("DEADHOP_NETWORK", "mainnet")]), false).unwrap();
        assert_eq!(s.network, "bitcoin");
    }

    #[test]
    fn a_wrong_network_is_left_to_the_configuration() {
        assert_eq!(status(&lookup(&[("DEADHOP_NETWORK", "dogecoin")]), false), None);
    }

    #[test]
    fn the_account_key_can_be_in_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("account.xpub");
        let path = file.to_string_lossy().into_owned();
        let get = lookup(&[("DEADHOP_XPUB_FILE", &path)]);
        assert_eq!(
            state(&status(&get, false).unwrap(), "DEADHOP_XPUB"),
            State::Missing,
            "no file yet"
        );
        fs::write(&file, "\n").unwrap();
        assert_eq!(
            state(&status(&get, false).unwrap(), "DEADHOP_XPUB"),
            State::Missing,
            "empty"
        );
        fs::write(&file, "zpub…\n").unwrap();
        assert_eq!(state(&status(&get, false).unwrap(), "DEADHOP_XPUB"), State::Found);
    }

    #[test]
    fn the_status_file_names_settings_and_never_values() {
        let dir = tempfile::tempdir().unwrap();
        let s = status(&lookup(&[("DEADHOP_XPUB", "zpub-secretish")]), false).unwrap();
        publish(&s, Some(dir.path()));
        let text = fs::read_to_string(dir.path().join(SETUP_FILE)).unwrap();
        assert!(!text.contains("zpub-secretish"));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["network"], "bitcoin");
        assert_eq!(v["settings"][0]["name"], "DEADHOP_ELECTRUM");
        assert_eq!(v["settings"][0]["state"], "missing");
        assert_eq!(v["settings"][2]["state"], "found");
        assert_eq!(v["settings"][4]["state"], "default");
        clear(Some(dir.path()));
        assert!(!dir.path().join(SETUP_FILE).exists());
        // Nothing to clear, or nowhere to publish: no error.
        clear(Some(dir.path()));
        clear(None);
        publish(&s, None);
        // A directory that cannot be written is logged, not fatal.
        publish(&s, Some(&dir.path().join("missing")));
    }

    #[tokio::test]
    async fn it_waits_until_shut_down_and_repeats_the_reminder() {
        let dir = tempfile::tempdir().unwrap();
        let s = status(
            &lookup(&[("DEADHOP_RELAYS", "wss://r"), ("DEADHOP_NETWORK", "signet")]),
            false,
        )
        .unwrap();
        let started = std::time::Instant::now();
        wait(
            s,
            Some(dir.path()),
            tokio::time::sleep(Duration::from_millis(60)),
            Duration::from_millis(10),
        )
        .await;
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(dir.path().join(SETUP_FILE).exists());
    }

    #[test]
    fn the_public_directory_is_read_from_the_environment() {
        assert_eq!(public_dir(&lookup(&[])), None);
        assert_eq!(public_dir(&lookup(&[("DEADHOP_PUBLIC_DIR", " ")])), None);
        assert_eq!(
            public_dir(&lookup(&[("DEADHOP_PUBLIC_DIR", "/public")])),
            Some(PathBuf::from("/public"))
        );
    }
}
