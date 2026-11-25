//! Where every relay of every key goes, for a table of saved proxy settings,
//! proxy health and offline policies, compared with a recorded file. The file
//! was written before proxy groups replaced the pool (#53): settings saved in
//! the old shape must still route exactly as they did.
//!
//! `GOLDEN_WRITE=1 cargo test golden` rewrites the file.

use std::collections::BTreeMap;

use crate::hosttests::{rig, A, B};
use crate::network::{OfflinePolicy, ProxySettings};
use crate::routes::Via;

const SETTINGS: &str = include_str!("../tests/fixtures/routing_old_settings.json");
const GOLDEN: &str = include_str!("../tests/fixtures/routing_golden.json");
const ONION: &str = "wss://x.onion";

fn policies() -> [(OfflinePolicy, &'static str); 4] {
    [
        (OfflinePolicy::KillSwitch, "kill_switch"),
        (OfflinePolicy::AdminOnly, "admin_only"),
        (OfflinePolicy::InvoicingOnly, "invoicing_only"),
        (OfflinePolicy::Open, "open"),
    ]
}

/// Which proxies answer: all, all but the first, none.
fn health(ids: &[String]) -> Vec<(&'static str, Vec<(String, bool)>)> {
    let all = |up: bool| ids.iter().map(|id| (id.clone(), up)).collect();
    let first_down = ids.iter().enumerate().map(|(i, id)| (id.clone(), i != 0)).collect();
    vec![("all_up", all(true)), ("first_down", first_down), ("all_down", all(false))]
}

fn record(name: &str, proxies: &ProxySettings) -> BTreeMap<String, serde_json::Value> {
    let ids: Vec<String> = proxies.list.iter().map(|e| e.id.clone()).collect();
    let mut out = BTreeMap::new();
    for (policy, policy_name) in policies() {
        for (health_name, up) in health(&ids) {
            let r = rig(&[A, B, ONION]);
            r.set(|t| {
                t.settings.proxies = proxies.clone();
                t.settings.proxies.offline = policy;
            });
            for (id, is_up) in &up {
                r.probe(id, *is_up);
            }
            r.replan();
            let mut lanes = BTreeMap::new();
            for lane in ["invoices", "admin"] {
                let routes: Vec<String> = r
                    .net
                    .routes_for(&r.host, lane)
                    .into_iter()
                    .map(|x| {
                        let via = match x.via {
                            Via::Proxy { id, .. } => format!("proxy:{id}"),
                            Via::Direct => "direct".into(),
                            Via::Off => "off".into(),
                        };
                        format!("{} {via} {:?}", x.relay, x.reason)
                    })
                    .collect();
                lanes.insert(lane.to_string(), routes);
            }
            let posture = format!("{:?}", r.net.posture(&r.host));
            out.insert(
                format!("{name} {policy_name} {health_name}"),
                serde_json::json!({ "posture": posture, "lanes": lanes }),
            );
        }
    }
    out
}

/// Every fixture, routed.
pub fn routed(fixtures: &BTreeMap<String, ProxySettings>) -> BTreeMap<String, serde_json::Value> {
    let mut all = BTreeMap::new();
    for (name, proxies) in fixtures {
        all.extend(record(name, proxies));
    }
    all
}

#[test]
fn saved_settings_route_as_recorded() {
    let fixtures: BTreeMap<String, ProxySettings> = serde_json::from_str(SETTINGS).unwrap();
    let got = routed(&fixtures);
    if std::env::var("GOLDEN_WRITE").is_ok() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/routing_golden.json");
        std::fs::write(path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        return;
    }
    let want: BTreeMap<String, serde_json::Value> = serde_json::from_str(GOLDEN).unwrap();
    assert_eq!(got.len(), want.len());
    for (case, value) in &want {
        assert_eq!(got.get(case), Some(value), "{case}");
    }
}
