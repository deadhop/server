//! The watch-only wallet account. The code lives in the `deadhop-common`
//! crate (see its `wallet` module); everything keeps its old path here.

pub use deadhop_common::wallet::*;
// The Electrum script hash lives in the Electrum crate and keeps its old path.
pub use deadhop_electrum::scripthash;
