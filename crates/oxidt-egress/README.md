# oxidt-egress

Outbound HTTP to user-supplied URLs without becoming a proxy into the private
network. https-only URL policy, address checks on every resolved address, a
reqwest client pinned to exactly those addresses, and the pieces to walk
redirects by hand.

```toml
[dependencies]
oxidt-egress = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-egress-v0.1.0" }
```

Features: `client` (default) adds the pinned reqwest 0.13 client; `tokio` adds
`guard_host_async`. Without either, the crate is `url` + `thiserror`.

## Why

A server that fetches a URL a user typed — a calendar feed, a CalDAV
collection, an MCP endpoint — will connect to whatever it's given. Left
unguarded that's server-side request forgery: a proxy into everything the
deployment can reach, from `169.254.169.254` cloud metadata to the admin panel
and the database on the private network.

- **https only, never userinfo.** `check_url` refuses other schemes and any
  `user:pass@`, and the client enforces https again.
- **Every resolved address is checked**, not just the first: loopback, private,
  link-local, carrier-grade NAT, benchmarking, documentation, multicast and
  reserved IPv4; IPv6 must be global unicast (no unique-local, no 6to4, no
  documentation, no `2001::/23`), and IPv4-mapped IPv6 is judged as the IPv4 it
  carries.
- **The checked addresses are the ones connected to.** Checking a hostname and
  then letting the HTTP client resolve it again leaves a DNS-rebinding gap: a
  hostile resolver answers the check with a public address and the connection,
  a millisecond later, with `127.0.0.1`. `pinned_client` hands the checked
  addresses to reqwest via `resolve_to_addrs`, so the connector never asks DNS
  again. It also ignores proxy environment variables, follows no redirects and
  retries nothing.
- **Redirects are walked by hand.** A pin covers one host. If reqwest followed a
  redirect to another host it would resolve that host unchecked, so the client
  follows none: read `Location`, resolve it with `next_hop` (https only), then
  guard and pin the new URL afresh. Cap the hops and share one deadline across
  the walk.

## API

```rust
// Reqwest-free core
pub fn is_forbidden(ip: IpAddr) -> bool;
pub struct UrlPolicy { pub allow_query: bool, pub allow_fragment: bool, pub max_len: usize }
pub fn check_url(input: &str, policy: &UrlPolicy) -> Result<Url, Error>;
pub struct Pinned { pub host: String, pub addrs: Vec<SocketAddr> }
pub fn guard_host(url: &Url) -> Result<Pinned, Error>;                // blocking DNS
pub async fn guard_host_async(url: &Url) -> Result<Pinned, Error>;    // feature `tokio`
pub fn next_hop(from: &Url, location: &str) -> Result<Url, Error>;
pub fn literal_ip_is_forbidden(url: &Url) -> bool;

// feature `client`
pub struct Timeouts { pub connect: Duration, pub total: Duration }
pub fn pinned_client(pinned: &Pinned, timeouts: Timeouts) -> Result<reqwest::Client, Error>;
pub fn pin(builder: reqwest::ClientBuilder, pinned: &Pinned) -> reqwest::ClientBuilder;
```

`Error` says which rule refused (`Invalid`, `Scheme`, `Userinfo`, `Query`,
`Fragment`, `TooLong`, `Host`, `Forbidden(IpAddr)`, `Resolve`, `Client`) and
carries no user-facing copy — map it to your own.

A literal-IP host (`https://[2606:4700:4700::1111]:8443/`) is checked without
DNS and keeps its port. `guard_host_async` has no timeout of its own; wrap it
in `tokio::time::timeout` if a slow resolver must not stall the caller.

## Two policies

`UrlPolicy::default()` is strict — no query, no fragment, at most 2048 bytes.
Right for an endpoint the user names (an MCP server, a CalDAV account), where a
query string is either a mistake or a credential in the wrong place.

A calendar feed carries its secret in the query (Google's and Outlook's secret
ICS links do), so allow it there:

```rust
use oxidt_egress::{UrlPolicy, check_url};

let feed = UrlPolicy { allow_query: true, ..UrlPolicy::default() };
let url = check_url(pasted, &feed)?;
```

App-specific rewriting — `webcal://` to `https://` for Apple and Outlook links —
belongs in the app, before `check_url`.

## A feed fetch, end to end

```rust
use std::time::{Duration, Instant};
use oxidt_egress::{Timeouts, UrlPolicy, check_url, guard_host_async, next_hop, pinned_client};

let mut url = check_url(input, &UrlPolicy { allow_query: true, ..UrlPolicy::default() })?;
let deadline = Instant::now() + Duration::from_secs(15);
for _ in 0..=4 {
    let left = deadline.saturating_duration_since(Instant::now());
    let client = pinned_client(&guard_host_async(&url).await?, Timeouts { connect: left, total: left })?;
    let response = client.get(url.clone()).send().await?;
    match response.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()) {
        Some(location) if response.status().is_redirection() => url = next_hop(&url, location)?,
        _ => return read_bounded(response).await,
    }
}
Err("too many redirects")
```

Bound the body while it downloads, not after — a server that lies about
`Content-Length` shouldn't get to exhaust memory.

## On a different reqwest version

`pinned_client` and `pin` are reqwest 0.13. On another version, use the core
and apply the pin yourself — it's three builder calls plus the policy:

```rust
let pinned = oxidt_egress::guard_host(&url)?;
let client = reqwest::Client::builder()
    .https_only(true).no_proxy().redirect(reqwest::redirect::Policy::none())
    .resolve_to_addrs(&pinned.host, &pinned.addrs)
    .build()?;
```

## License

MIT — see [LICENSE](../../LICENSE).
