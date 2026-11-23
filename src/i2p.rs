//! I2P name lookups. The code lives in the `deadhop-netengine` crate (see its
//! `i2p` module); everything keeps its old path here.

pub use deadhop_netengine::i2p::*;

/// The stand-in I2P router, where the tests of other modules look for it.
#[cfg(test)]
pub(crate) mod tests {
    pub use deadhop_netengine::testing::{fake_destination, fake_router, page_with};
}
