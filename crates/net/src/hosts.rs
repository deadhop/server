//! Host classifiers: what kind of place a relay or proxy address points at.
//! Use them on a host that a URL parser extracted, never on a raw authority.

/// Whether a bare host (no port; IPv6 with or without brackets) is this
/// machine. Use this on a host that a URL parser extracted, never on a raw
/// authority, which may carry userinfo (`ws://127.0.0.1:80@remote.example`).
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether a bare host lives on a network that encrypts the whole path itself:
/// Tor (`.onion`), I2P (`.i2p`, including `.b32.i2p`) or the FIPS mesh
/// (`.fips`). A plain `ws://` relay there is not readable in transit, so the
/// mainnet rule against unencrypted relays does not apply. Like
/// [`is_loopback_host`], use it on a host a URL parser extracted.
pub fn is_overlay_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    ["onion", "i2p", "fips"]
        .iter()
        .any(|tld| host.strip_suffix(tld).is_some_and(|rest| rest.ends_with('.')))
}

pub fn is_private_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if is_loopback_host(&host) {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_link_local() || ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64
        }
        Ok(std::net::IpAddr::V6(ip)) => (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => {
            !host.contains('.')
                || [".local", ".lan", ".home.arpa", ".internal"]
                    .iter()
                    .any(|s| host.ends_with(s))
        }
    }
}

/// The host (lower case, without IPv6 brackets) and port of a relay address,
/// as a URL parser reads them.
pub fn host_port(relay: &str) -> Option<(String, u16)> {
    let url = nostr_sdk::Url::parse(relay).ok()?;
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    Some((host, url.port_or_known_default()?))
}

/// Whether a relay must never be connected without a proxy: Tor and I2P names
/// would go to the system resolver and fail, telling it what we looked up.
pub fn never_direct(relay: &str) -> bool {
    host_port(relay).is_some_and(|(h, _)| {
        let h = h.trim_end_matches('.');
        is_overlay_host(h) && !h.ends_with(".fips")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_is_recognised_by_name_and_address() {
        for yes in ["localhost", "LocalHost", "127.0.0.1", "127.9.9.9", "::1", "[::1]"] {
            assert!(is_loopback_host(yes), "{yes}");
        }
        for no in ["localhost.example", "10.0.0.1", "relay.example", "", "::2"] {
            assert!(!is_loopback_host(no), "{no}");
        }
    }

    #[test]
    fn overlay_networks_are_recognised_whatever_the_case_or_trailing_dot() {
        for yes in [
            "abc.onion",
            "ABC.Onion",
            "x.i2p",
            "x.b32.i2p",
            "node.fips",
            "abc.onion.",
        ] {
            assert!(is_overlay_host(yes), "{yes}");
        }
        for no in ["onion", "i2p", "notonion", "abc.onion.example", "relay.example", ""] {
            assert!(!is_overlay_host(no), "{no}");
        }
    }

    #[test]
    fn private_hosts_are_this_machine_private_ranges_and_local_names() {
        let private = [
            "localhost",
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "[fd00::1]",
            "fe80::1",
            "printer",
            "nas.local",
            "Box.LAN",
            "x.home.arpa",
            "db.internal",
        ];
        for yes in private {
            assert!(is_private_host(yes), "{yes}");
        }
        for no in [
            "8.8.8.8",
            "100.128.0.1",
            "100.63.0.1",
            "2001:db8::1",
            "relay.example",
            "abc.onion",
        ] {
            assert!(!is_private_host(no), "{no}");
        }
    }

    #[test]
    fn a_relay_address_gives_its_host_and_port() {
        assert_eq!(host_port("wss://Relay.Example"), Some(("relay.example".into(), 443)));
        assert_eq!(
            host_port("ws://relay.example:7777/path"),
            Some(("relay.example".into(), 7777))
        );
        assert_eq!(host_port("ws://[::1]:80"), Some(("::1".into(), 80)));
        // Not a url, no host, or a scheme with no known port.
        assert_eq!(host_port("relay.example:7777"), None);
        assert_eq!(host_port("not a url"), None);
        assert_eq!(host_port("foo:///x"), None);
        assert_eq!(host_port("foo://relay.example"), None);
    }

    #[test]
    fn tor_and_i2p_relays_are_never_direct_but_fips_and_the_rest_may_be() {
        for yes in ["ws://abc.onion", "ws://abc.onion.:80", "ws://x.i2p", "wss://X.B32.I2P"] {
            assert!(never_direct(yes), "{yes}");
        }
        for no in [
            "ws://node.fips",
            "wss://relay.example",
            "ws://127.0.0.1:7777",
            "abc.onion",
        ] {
            assert!(!never_direct(no), "{no}");
        }
    }
}
