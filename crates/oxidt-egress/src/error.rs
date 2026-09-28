use std::net::IpAddr;

/// Why a URL or its host was refused. Carries no user-facing copy; map it to
/// your own.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not a URL at all, or a redirect target that doesn't resolve to one.
    #[error("not a valid URL")]
    Invalid,
    #[error("only https URLs are allowed")]
    Scheme,
    #[error("URLs may not embed credentials")]
    Userinfo,
    #[error("URLs may not carry a query")]
    Query,
    #[error("URLs may not carry a fragment")]
    Fragment,
    #[error("URL is longer than {0} bytes")]
    TooLong(usize),
    /// The URL names no host that could be connected to.
    #[error("URL has no usable host: {0}")]
    Host(String),
    /// The host resolved to, or is, an address on a non-public network.
    #[error("{0} is not a public address")]
    Forbidden(IpAddr),
    /// DNS failed or returned nothing for this host.
    #[error("could not resolve {0}")]
    Resolve(String),
    /// reqwest refused to build the client.
    #[error("could not build the HTTP client: {0}")]
    Client(String),
}
