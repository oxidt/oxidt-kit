use std::time::Duration;

use crate::{Error, Pinned};

/// How long a pinned client may take. `total` bounds each whole request,
/// `connect` just the TCP + TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: Duration,
    pub total: Duration,
}

/// A client that can only reach `pinned.host`, and only at the addresses that
/// were checked. https only, no proxy, no redirects, no retries.
///
/// Build a new one per host: a pin covers exactly one. Walk redirects yourself
/// with [`next_hop`](crate::next_hop), guarding and pinning each hop.
pub fn pinned_client(pinned: &Pinned, timeouts: Timeouts) -> Result<reqwest::Client, Error> {
    pin(reqwest::Client::builder(), pinned)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.total)
        .build()
        .map_err(|e| Error::Client(e.to_string()))
}

/// Apply the whole egress policy to a builder you configure further: https
/// only, no proxy (environment proxies included), no redirects, no retries,
/// and `pinned.host` resolved to `pinned.addrs` only.
pub fn pin(builder: reqwest::ClientBuilder, pinned: &Pinned) -> reqwest::ClientBuilder {
    builder
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // A replayed request is a second write the user never asked for.
        .retry(reqwest::retry::never())
        .resolve_to_addrs(&pinned.host, &pinned.addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_pin_builds_a_client() {
        let pinned = crate::guard_host(&url::Url::parse("https://1.1.1.1/").unwrap()).unwrap();
        let second = Duration::from_secs(1);
        assert!(
            pinned_client(
                &pinned,
                Timeouts {
                    connect: second,
                    total: second
                }
            )
            .is_ok()
        );
    }
}
