//! A hardened Electrum client: every reply is treated as hostile. Lines and
//! whole polls have size caps, the server's chain is checked by its genesis
//! hash, and each transaction is re-hashed before it is believed. TLS can be
//! pinned to certificate fingerprints. Moved verbatim from deadhop's server,
//! which re-exports everything at its old paths.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::ScriptBuf;

mod client;
pub mod error;

pub use client::*;
use error::{Error, Result};

/// Electrum protocol script hash: `sha256(scriptPubKey)`, byte-reversed, hex.
pub fn scripthash(script: &ScriptBuf) -> String {
    let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

/// Characters allowed in a memo. Besides control characters this refuses the
/// invisible and direction-changing ones, which could be used to make a note
/// shown on the merchant's page read as something else.
pub fn is_plain_text(c: char) -> bool {
    !(c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{FEFF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202F}'
            | '\u{2060}'..='\u{206F}'
            | '\u{E000}'..='\u{F8FF}'
            | '\u{FFF0}'..='\u{FFFF}'
            | '\u{E0000}'..='\u{E0FFF}'
            | '\u{F0000}'..='\u{10FFFF}'))
}

/// `host:port` (plain TCP) or `tls://host:port` / `ssl://host:port`, plus
/// optional comma-separated certificate fingerprints to pin.
pub fn parse_electrum(spec: &str, pins: Option<&str>) -> Result<(String, crate::Security)> {
    use crate::{parse_fingerprint, Security};
    let (tls, addr) = match spec.split_once("://") {
        None => (false, spec),
        Some(("tcp", rest)) => (false, rest),
        Some(("tls" | "ssl", rest)) => (true, rest),
        Some(_) => {
            return Err(Error::Config(
                "DEADHOP_ELECTRUM scheme must be tcp://, tls:// or ssl://".into(),
            ))
        }
    };
    let port_ok = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if !port_ok {
        return Err(Error::Config(
            "DEADHOP_ELECTRUM must be host:port or tls://host:port".into(),
        ));
    }
    let security = match (tls, pins) {
        (false, None) => Security::Plain,
        (false, Some(_)) => {
            return Err(Error::Config(
                "DEADHOP_ELECTRUM_CERT_SHA256 needs a tls:// Electrum server".into(),
            ))
        }
        (true, None) => Security::Tls,
        (true, Some(list)) => {
            let pins = list
                .split(',')
                .map(|p| {
                    parse_fingerprint(p)
                        .ok_or_else(|| Error::Config(format!("'{}' is not a SHA-256 fingerprint", p.trim())))
                })
                .collect::<Result<Vec<_>>>()?;
            Security::Pinned(pins)
        }
    };
    Ok((addr.to_string(), security))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_hash_is_the_reversed_sha256_of_the_script() {
        // The Electrum protocol documentation's example script.
        let script = ScriptBuf::from_hex("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac").unwrap();
        assert_eq!(
            scripthash(&script),
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        );
    }

    #[test]
    fn plain_text_has_no_control_invisible_or_direction_characters() {
        for ok in ['a', 'é', '日', ' ', '€', '😀'] {
            assert!(is_plain_text(ok), "{ok:?}");
        }
        let hidden = [
            '\n',
            '\u{0}',
            '\u{7f}',
            '\u{ad}',
            '\u{61c}',
            '\u{180e}',
            '\u{feff}',
            '\u{200b}',
            '\u{200f}',
            '\u{2028}',
            '\u{202e}',
            '\u{2060}',
            '\u{206f}',
            '\u{e000}',
            '\u{f8ff}',
            '\u{fff0}',
            '\u{ffff}',
            '\u{e0001}',
            '\u{e0fff}',
            '\u{f0000}',
            '\u{10ffff}',
        ];
        for bad in hidden {
            assert!(!is_plain_text(bad), "{bad:?}");
        }
    }

    #[test]
    fn an_electrum_address_is_parsed_with_its_protection() {
        let pin = "ab".repeat(32);
        assert_eq!(
            parse_electrum("h:50001", None).unwrap(),
            ("h:50001".to_string(), Security::Plain)
        );
        assert_eq!(
            parse_electrum("tcp://h:50001", None).unwrap(),
            ("h:50001".to_string(), Security::Plain)
        );
        assert_eq!(
            parse_electrum("tls://h:50002", None).unwrap(),
            ("h:50002".to_string(), Security::Tls)
        );
        assert_eq!(parse_electrum("ssl://[::1]:50002", None).unwrap().1, Security::Tls);
        let two = format!("{pin}, {}", "cd".repeat(32));
        assert_eq!(
            parse_electrum("tls://h:50002", Some(&two)).unwrap().1,
            Security::Pinned(vec![[0xab; 32], [0xcd; 32]])
        );
        let refused = [
            (
                "http://h:1",
                None,
                "DEADHOP_ELECTRUM scheme must be tcp://, tls:// or ssl://",
            ),
            ("h", None, "DEADHOP_ELECTRUM must be host:port or tls://host:port"),
            (":50001", None, "DEADHOP_ELECTRUM must be host:port or tls://host:port"),
            ("h:port", None, "DEADHOP_ELECTRUM must be host:port or tls://host:port"),
            (
                "h:50001",
                Some(pin.as_str()),
                "DEADHOP_ELECTRUM_CERT_SHA256 needs a tls:// Electrum server",
            ),
            ("tls://h:50002", Some(" nope "), "'nope' is not a SHA-256 fingerprint"),
        ];
        for (spec, pins, why) in refused {
            let e = parse_electrum(spec, pins).unwrap_err();
            assert_eq!(e.to_string(), format!("invalid configuration: {why}"), "{spec}");
        }
    }
}
