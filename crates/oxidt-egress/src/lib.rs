//! Outbound HTTP to user-supplied URLs without becoming a proxy into the
//! private network.
//!
//! ## Why any of this
//!
//! A server that connects to whatever URL a user types is, left unguarded, a
//! proxy into everything the deployment can reach — cloud metadata endpoints,
//! internal admin panels, databases on the private network. The guards here:
//!
//! - **https only, never userinfo** ([`check_url`]), and enforced again on the
//!   client. Query and fragment are refused by default; [`UrlPolicy`] relaxes
//!   that for URLs that carry their credential in the query, like ICS feeds.
//! - **Every resolved address is checked** before connecting ([`guard_host`],
//!   [`guard_host_async`]): loopback, private, link-local, carrier-grade NAT,
//!   benchmarking, documentation, multicast and reserved IPv4 are refused, and
//!   IPv6 must be global unicast (no unique-local, no 6to4, no documentation),
//!   including IPv4 smuggled in as IPv4-mapped IPv6 ([`is_forbidden`]).
//! - **The checked addresses are the ones connected to.** [`pinned_client`]
//!   hands them to reqwest via `resolve_to_addrs`, so the connector never asks
//!   DNS again — a hostile resolver can't answer the check with a public address
//!   and the connection with a private one. The client also ignores proxy
//!   environment variables, follows no redirects and retries nothing.
//! - **Redirects are walked by the caller**, one hop at a time ([`next_hop`]),
//!   each hop guarded and pinned again: a pin only covers the host it was made
//!   for, so letting reqwest follow a redirect to another host would resolve
//!   that host unchecked.

mod error;
mod guard;
mod ip;
mod policy;

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use client::{Timeouts, pin, pinned_client};
pub use error::Error;
#[cfg(feature = "tokio")]
pub use guard::guard_host_async;
pub use guard::{Pinned, guard_host, literal_ip_is_forbidden};
pub use ip::is_forbidden;
pub use policy::{UrlPolicy, check_url, next_hop};
