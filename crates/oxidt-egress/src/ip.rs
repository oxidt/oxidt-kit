use std::net::IpAddr;

/// Whether `ip` is on a network a server must not connect to on a user's
/// behalf.
///
/// IPv4: private, loopback, link-local (cloud metadata lives at
/// 169.254.169.254), broadcast, unspecified, documentation, `0.0.0.0/8`,
/// multicast and reserved (`224.0.0.0/3`), carrier-grade NAT `100.64.0.0/10`,
/// IETF protocol assignments `192.0.0.0/24` and benchmarking `198.18.0.0/15`.
///
/// IPv6: anything outside global unicast `2000::/3` (which excludes loopback,
/// unspecified, unique-local, link-local and multicast), plus `2001::/23`
/// protocol assignments, `2001:db8::/32` and `3fff::/20` documentation, and
/// `2002::/16` 6to4, which can encode a private IPv4 destination. An
/// IPv4-mapped address is judged as the IPv4 address it carries.
pub fn is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || a == 0
                // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved.
                || a >= 224
                // 100.64.0.0/10, carrier-grade NAT — `is_shared` is unstable.
                || (a == 100 && (64..128).contains(&b))
                // 192.0.0.0/24, IETF protocol assignments.
                || (a == 192 && b == 0 && c == 0)
                // 198.18.0.0/15, benchmarking — `is_benchmarking` is unstable.
                || (a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden(IpAddr::V4(v4));
            }
            let s = v6.segments();
            (s[0] & 0xe000) != 0x2000
                || (s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                || s[0] == 0x2002
                || (s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn private_and_loopback_addresses_are_forbidden() {
        let forbidden = [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            // AWS/GCP instance metadata — the classic SSRF target.
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            // The same metadata address, tunnelled through IPv4-mapped IPv6.
            "::ffff:169.254.169.254",
            // Benchmarking, protocol assignments, documentation.
            "198.18.0.1",
            "198.19.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "203.0.113.7",
            // Multicast, reserved, broadcast.
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            // IPv6 multicast, documentation, 6to4 wrapping 10.0.0.1,
            // protocol assignments, and anything outside global unicast.
            "ff02::1",
            "2001:db8::1",
            "3fff::1",
            "2002:0a00:0001::1",
            "2001::1",
            "64:ff9b::a00:1",
        ];
        for address in forbidden {
            assert!(
                is_forbidden(address.parse().unwrap()),
                "{address} should be forbidden"
            );
        }
    }

    #[test]
    fn rejects_local_metadata_and_special_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            // Alibaba Cloud metadata, inside carrier-grade NAT.
            "100.100.100.200",
            "0.0.0.0",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002:7f00:1::",
        ] {
            assert!(is_forbidden(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(!is_forbidden(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for address in ["142.250.185.110", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                !is_forbidden(address.parse().unwrap()),
                "{address} should be allowed"
            );
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_smuggle_a_private_address() {
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(is_forbidden(mapped));
    }

    #[test]
    fn unspecified_ipv6_is_forbidden() {
        assert!(is_forbidden(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }
}
