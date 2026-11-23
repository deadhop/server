//! Look a real name up through a real I2P router, with the default registries.
//!
//! Ignored by default:
//!
//!   DEADHOP_TEST_I2P_PROXY=http://host:4444 cargo test --test live_i2p -- --ignored --nocapture

use deadhop::i2p::{ask, default_registries, summarize, LOOKUP_SECS};
use deadhop::relay::{parse_proxy, ProxyTransport};

/// The b32 address of `nostr-not.i2p`.
const NOSTR_NOT_B32: &str = "nostrsrpr4c7lrswidgws2dzx5yrllqujdewru34jfydjjqplapq.b32.i2p";

#[tokio::test]
#[ignore = "needs a real I2P router; set DEADHOP_TEST_I2P_PROXY"]
async fn live_i2p_lookup() {
    let url = std::env::var("DEADHOP_TEST_I2P_PROXY").expect("DEADHOP_TEST_I2P_PROXY is set");
    let proxy = ProxyTransport::new(parse_proxy(&url).unwrap().unwrap());
    let regs = default_registries();
    let answers =
        futures_util::future::join_all(regs.iter().map(|r| ask(&proxy, r, "nostr-not.i2p", LOOKUP_SECS))).await;
    for (r, a) in regs.iter().zip(&answers) {
        println!("{r}: {a:?}");
    }
    let out = summarize("nostr-not.i2p", &regs, &answers).unwrap();
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    assert_eq!(out.address, NOSTR_NOT_B32);
}
