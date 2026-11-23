//! Recorded wire behaviour. A snapshot is a JSON file under `tests/snapshots/`
//! that the code must keep producing: the tool list and its schemas,
//! `get_settings`, the stored settings form and the refusals clients see.
//!
//! A change is shown as a failed comparison. The value found is always
//! written to `target/snapshots-actual/<name>.json`; when a change is
//! intended, copy that file over the committed one.

use std::path::Path;

/// Compare `value` with the committed snapshot `name`.
pub fn check(name: &str, value: &serde_json::Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = format!("{}\n", serde_json::to_string_pretty(value).unwrap());
    let actual = root.join("target/snapshots-actual");
    std::fs::create_dir_all(&actual).unwrap();
    std::fs::write(actual.join(format!("{name}.json")), &found).unwrap();
    let committed = std::fs::read_to_string(root.join(format!("tests/snapshots/{name}.json")))
        .expect("a snapshot is committed (a new one: copy it from target/snapshots-actual/)");
    assert!(
        committed == found,
        "snapshot {name} changed: diff tests/snapshots/{name}.json target/snapshots-actual/{name}.json; \
         if intended, copy the second over the first"
    );
}
