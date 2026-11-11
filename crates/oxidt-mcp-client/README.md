# oxidt-mcp-client

Outbound MCP for a hosted app: reach a remote MCP endpoint a user typed in,
list its tools, and call one exactly once. Every connection goes through
[`oxidt-egress`](../oxidt-egress).

```toml
[dependencies]
oxidt-mcp-client = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-mcp-client-v0.1.0" }
```

```rust,no_run
use oxidt_mcp_client::{Endpoint, Outcome, call, tools};

# async fn example(token: secrecy::SecretString) -> Result<(), oxidt_mcp_client::Error> {
let endpoint = Endpoint::new("https://mcp.example.org/mcp", Some(token))?;
for tool in tools(&endpoint).await? {
    println!("{} (read-only: {:?})", tool.name, tool.read_only);
}
let arguments = serde_json::json!({"text": "Hello"}).as_object().cloned().unwrap_or_default();
match call(&endpoint, "send_note", arguments).await? {
    Outcome::Succeeded(text) => println!("{text}"),
    Outcome::Failed(text) => println!("the tool refused: {text}"),
    // Sent, no final answer: it may have run. Do not call again by yourself.
    Outcome::Unknown => println!("check the service"),
}
# Ok(()) }
```

## Why

**The URL is user input.** A hosted app that fetches whatever a user types is
a proxy into its own network. The URL must be public https; every resolved
address is checked; the connection is pinned to those addresses; there is no
proxy and no redirect.

**A write must not happen twice.** The HTTP client does not retry, an expired
session is not re-initialised, and `call` makes one attempt. `Err` means
the tool call was not sent. `Outcome::Unknown` means the request went out and no final
answer came back, so the tool may have run: record it and let the user check
the service before anything is sent again.

**A remote tool can change after the user allowed it.** `gate` holds the
rule: allow, ask or block per tool, a default when the user chose none, and a
hold on any tool whose definition is not the one they accepted. The app
stores the settings and the accepted schema; `tool_gate` decides.

**Results are someone else's text.** A result is pretty JSON for display, cut
at `MAX_RESULT` bytes, with the token redacted. Show it as text. Never render
it as markup, and never let a model treat it as instructions.

## Sign-in (feature `oauth`)

For a server that wants a real sign-in instead of a pasted token:

```toml
oxidt-mcp-client = { git = "…", tag = "oxidt-mcp-client-v0.1.0", features = ["oauth"] }
```

- `oauth::begin(url, &client)` discovers the server's sign-in, registers the
  app (or presents its client metadata document) and returns the address to
  send the browser to, plus a `Pending` flow.
- `oauth::finish(pending, code, state, iss)` exchanges the callback's code for
  a token and a `Grant`.
- `oauth::access_token(&mut grant)` returns a usable token before each
  connection, refreshing when needed.

The app owns three things, because they need its database and sessions:

1. **Store the `Pending` flow encrypted**, keyed by `Pending::state()`, bound
   to the signed-in user *and* the browser that started it, for about ten
   minutes, and delete it as it is claimed. A callback from another browser,
   twice, or late must find nothing.
2. **Store the `Grant` encrypted.** It holds the refresh token.
3. **Lock the connection's row around `access_token`** and save the grant
   before releasing it. A rotating refresh token used by two workers at once
   signs the user out.

`access_token` updates the grant in place; save it whatever the call returns.
`Error::Expired` means the user signs in again; `Error::Unavailable` and
`Error::Timeout` mean try again later with the same grant.

**Keep rmcp's own logging quiet in production.** rmcp logs parts of the OAuth
exchange itself, before this crate sees them: the authorization code at
DEBUG, and a rejected refresh's provider-written description at WARN. Filter
the `rmcp` target to `error` (for example `RUST_LOG=info,rmcp=error`).

Refused: a server that publishes no OAuth metadata (nothing is probed at
guessed paths), one without PKCE `S256`, an answer from another issuer, and
any endpoint that is not public https. `oauth::Error` is a fixed set of
categories; provider response bodies never reach a message.

## More

- **A key in its own header:** `Endpoint::with_header(url, "X-API-Key", key)`
  for a server that does not use `Authorization: Bearer`.
- **Client credentials handed out in advance:** set `Client::registered` for a
  provider without dynamic registration; nothing is registered then.
- **A token rejected before it expired:** `oauth::refresh_now(&mut grant)`
  refreshes at once. Try the call once more; a second rejection means the
  user signs in again.
- **Disconnecting:** `oauth::revoke(&grant)` tells the provider the grant is
  finished (RFC 7009). Delete your own copy first and always; a provider
  that is down or refuses must not keep a user from disconnecting.

## Not included

Storage and sessions.

Extracted from smiet.
