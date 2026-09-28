use url::Url;

use crate::Error;

/// What a URL may carry beyond scheme, host, port and path.
///
/// The [`Default`] is strict: no query, no fragment, at most 2048 bytes — right
/// for an endpoint the user names, such as an MCP server or a CalDAV account.
/// A calendar feed is different: Google's and Outlook's secret ICS links carry
/// their token in the query, so allow it there:
///
/// ```
/// use oxidt_egress::{UrlPolicy, check_url};
///
/// let feed = UrlPolicy { allow_query: true, ..UrlPolicy::default() };
/// assert!(check_url("https://example.com/cal.ics?token=abc", &feed).is_ok());
/// assert!(check_url("https://example.com/cal.ics?token=abc", &UrlPolicy::default()).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlPolicy {
    pub allow_query: bool,
    pub allow_fragment: bool,
    /// In bytes, measured on the trimmed input.
    pub max_len: usize,
}

impl Default for UrlPolicy {
    fn default() -> Self {
        Self {
            allow_query: false,
            allow_fragment: false,
            max_len: 2048,
        }
    }
}

/// Parse a URL the user supplied and hold it to `policy`: https only, a host,
/// never a username or password, and query/fragment/length as the policy says.
///
/// Surrounding whitespace is trimmed — people paste with a trailing newline
/// more often than not. This checks the URL only; the host's addresses are
/// checked by [`guard_host`](crate::guard_host) when connecting.
pub fn check_url(input: &str, policy: &UrlPolicy) -> Result<Url, Error> {
    let input = input.trim();
    if input.len() > policy.max_len {
        return Err(Error::TooLong(policy.max_len));
    }
    let url = Url::parse(input).map_err(|_| Error::Invalid)?;
    if url.scheme() != "https" {
        return Err(Error::Scheme);
    }
    if url.host().is_none() {
        return Err(Error::Host(input.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Userinfo);
    }
    if url.query().is_some() && !policy.allow_query {
        return Err(Error::Query);
    }
    if url.fragment().is_some() && !policy.allow_fragment {
        return Err(Error::Fragment);
    }
    Ok(url)
}

/// Where a redirect leads, resolved against the URL that sent it. Only https
/// without userinfo is followed; the address checks run when the caller guards
/// and pins a client for the new URL.
pub fn next_hop(from: &Url, location: &str) -> Result<Url, Error> {
    let next = from.join(location).map_err(|_| Error::Invalid)?;
    if next.scheme() != "https" {
        return Err(Error::Scheme);
    }
    if !next.username().is_empty() || next.password().is_some() {
        return Err(Error::Userinfo);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed() -> Url {
        Url::parse("https://calendar.example.com/feeds/a/basic.ics").unwrap()
    }

    #[test]
    fn endpoint_requires_https_without_embedded_credentials() {
        let strict = UrlPolicy::default();
        assert!(check_url("https://seggwat.com/mcp", &strict).is_ok());
        for url in [
            "http://example.com/mcp",
            "file:///etc/passwd",
            "https://token@example.com/mcp",
            "https://example.com/mcp?token=secret",
            "https://example.com/mcp#fragment",
        ] {
            assert!(check_url(url, &strict).is_err(), "{url}");
        }
    }

    #[test]
    fn plain_http_and_other_schemes_are_refused() {
        for url in [
            "http://example.com/cal.ics",
            "file:///etc/passwd",
            "gopher://example.com",
            "not a url",
        ] {
            assert!(
                check_url(url, &UrlPolicy::default()).is_err(),
                "{url} should be refused"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert!(check_url("  https://example.com/cal.ics\n", &UrlPolicy::default()).is_ok());
    }

    #[test]
    fn the_feed_policy_allows_a_token_in_the_query_but_never_userinfo() {
        let feed = UrlPolicy {
            allow_query: true,
            ..UrlPolicy::default()
        };
        assert!(check_url("https://example.com/basic.ics?key=secret", &feed).is_ok());
        assert!(matches!(
            check_url("https://me:pw@example.com/basic.ics", &feed),
            Err(Error::Userinfo)
        ));
    }

    #[test]
    fn overlong_urls_are_refused_before_parsing() {
        let long = format!("https://example.com/{}", "a".repeat(2048));
        assert!(matches!(
            check_url(&long, &UrlPolicy::default()),
            Err(Error::TooLong(2048))
        ));
    }

    #[test]
    fn a_relative_redirect_stays_on_the_same_host() {
        let next = next_hop(&feed(), "/feeds/b/basic.ics").unwrap();
        assert_eq!(
            next.as_str(),
            "https://calendar.example.com/feeds/b/basic.ics"
        );
    }

    #[test]
    fn a_redirect_to_another_host_is_followed_for_the_guard_to_check() {
        let next = next_hop(&feed(), "https://p01-caldav.icloud.com/x.ics").unwrap();
        assert_eq!(next.host_str(), Some("p01-caldav.icloud.com"));
    }

    #[test]
    fn a_redirect_off_https_is_refused() {
        for location in ["http://calendar.example.com/a.ics", "file:///etc/passwd"] {
            assert!(
                next_hop(&feed(), location).is_err(),
                "{location} should be refused"
            );
        }
    }
}
