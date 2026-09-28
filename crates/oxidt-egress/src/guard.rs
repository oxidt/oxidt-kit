use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use url::{Host, Url};

use crate::{Error, is_forbidden};

/// A host and the addresses it was checked at. Connect only to these —
/// [`pinned_client`](crate::pinned_client) does — or the check proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// The URL's host as written (`host_str`, so an IPv6 literal keeps its
    /// brackets).
    pub host: String,
    /// Every address the host resolved to, each already checked, with the URL's
    /// port (or 443).
    pub addrs: Vec<SocketAddr>,
}

/// Resolve `url`'s host with the blocking system resolver and refuse it if any
/// address is on a non-public network. A literal address is checked as is,
/// without DNS.
///
/// Every address must pass, not just the first: the connector may try any of
/// them.
pub fn guard_host(url: &Url) -> Result<Pinned, Error> {
    let (host, port) = parts(url)?;
    let addrs = match literal(url, port) {
        Some(addr) => vec![addr],
        None => (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| Error::Resolve(host.clone()))?
            .collect(),
    };
    checked(host, addrs)
}

/// [`guard_host`] on tokio's resolver, for use inside an async runtime. Wrap it
/// in your own timeout if a slow resolver must not stall the caller.
#[cfg(feature = "tokio")]
pub async fn guard_host_async(url: &Url) -> Result<Pinned, Error> {
    let (host, port) = parts(url)?;
    let addrs = match literal(url, port) {
        Some(addr) => vec![addr],
        None => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| Error::Resolve(host.clone()))?
            .collect(),
    };
    checked(host, addrs)
}

/// Cheap check for a URL whose host is written as a literal forbidden address,
/// with no DNS involved.
pub fn literal_ip_is_forbidden(url: &Url) -> bool {
    literal(url, 0).is_some_and(|addr| is_forbidden(addr.ip()))
}

fn parts(url: &Url) -> Result<(String, u16), Error> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| Error::Host(url.to_string()))?;
    Ok((host.to_string(), url.port_or_known_default().unwrap_or(443)))
}

/// The address a literal-IP host names. `url::Host` has already unbracketed an
/// IPv6 literal, which DNS would otherwise fail to look up.
fn literal(url: &Url, port: u16) -> Option<SocketAddr> {
    let ip: IpAddr = match url.host()? {
        Host::Ipv4(ip) => ip.into(),
        Host::Ipv6(ip) => ip.into(),
        Host::Domain(_) => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn checked(host: String, addrs: Vec<SocketAddr>) -> Result<Pinned, Error> {
    if addrs.is_empty() {
        return Err(Error::Resolve(host));
    }
    if let Some(bad) = addrs.iter().find(|addr| is_forbidden(addr.ip())) {
        return Err(Error::Forbidden(bad.ip()));
    }
    Ok(Pinned { host, addrs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::next_hop;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn a_redirect_to_a_literal_private_address_is_caught() {
        assert!(literal_ip_is_forbidden(&url(
            "https://169.254.169.254/latest/meta-data/"
        )));
        assert!(literal_ip_is_forbidden(&url("https://[::1]/cal.ics")));
        assert!(!literal_ip_is_forbidden(&url(
            "https://calendar.google.com/cal.ics"
        )));
    }

    #[test]
    fn guard_returns_the_addresses_it_checked_for_pinning() {
        assert_eq!(
            guard_host(&url("https://8.8.8.8/cal.ics")).unwrap().addrs,
            vec!["8.8.8.8:443".parse::<SocketAddr>().unwrap()]
        );

        // An explicit port is kept, and a bracketed IPv6 host is understood.
        assert_eq!(
            guard_host(&url("https://[2606:4700:4700::1111]:8443/cal.ics"))
                .unwrap()
                .addrs,
            vec!["[2606:4700:4700::1111]:8443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn a_literal_address_with_a_port_is_pinned_under_its_written_host() {
        let pinned = guard_host(&url("https://1.1.1.1:8443/dav/")).unwrap();
        assert_eq!(
            pinned,
            Pinned {
                host: "1.1.1.1".to_string(),
                addrs: vec!["1.1.1.1:8443".parse().unwrap()],
            }
        );
    }

    #[test]
    fn guard_refuses_literal_addresses_in_the_new_ranges() {
        for u in [
            "https://198.18.0.1/cal.ics",
            "https://224.0.0.1/cal.ics",
            "https://[2002:a00:1::1]/cal.ics",
            "https://[2001:db8::1]/cal.ics",
        ] {
            assert!(
                matches!(guard_host(&url(u)), Err(Error::Forbidden(_))),
                "{u} should be refused"
            );
        }
    }

    #[test]
    fn guard_rejects_a_hostname_that_resolves_to_loopback() {
        assert!(guard_host(&url("https://localhost/cal.ics")).is_err());
    }

    #[test]
    fn a_redirect_into_the_private_network_is_refused_at_the_guard() {
        let feed = url("https://calendar.example.com/feeds/a/basic.ics");
        let next = next_hop(&feed, "https://169.254.169.254/latest/meta-data/").unwrap();
        assert!(matches!(guard_host(&next), Err(Error::Forbidden(_))));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn the_async_guard_applies_the_same_checks() {
        assert!(matches!(
            guard_host_async(&url("https://169.254.169.254/")).await,
            Err(Error::Forbidden(_))
        ));
        assert!(guard_host_async(&url("https://localhost/")).await.is_err());
        assert_eq!(
            guard_host_async(&url("https://[2606:4700:4700::1111]:8443/"))
                .await
                .unwrap()
                .addrs,
            vec!["[2606:4700:4700::1111]:8443".parse::<SocketAddr>().unwrap()]
        );
    }
}
