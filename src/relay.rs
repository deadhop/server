//! Nostr relay connections, optionally through a proxy. The code lives in the
//! `deadhop-net` crate (see its `relay` module); everything keeps its old path here.

pub use deadhop_net::relay::*;

use crate::error::Result;

/// Parse a proxy URL. The empty string means "no proxy".
pub fn parse_proxy(s: &str) -> Result<Option<ProxySpec>> {
    Ok(deadhop_net::relay::parse_proxy(s)?)
}

/// The stand-in proxies, where the tests of other modules look for them.
#[cfg(test)]
pub(crate) mod tests {
    pub use deadhop_net::testing::{socks5_proxy, socks5_proxy_on};
}
