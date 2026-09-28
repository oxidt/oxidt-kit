# oxidt-mcp-oauth

The OAuth 2.1 authorization-server core an app needs to let claude.ai / ChatGPT
connect to its MCP endpoint: discovery metadata, dynamic client registration,
PKCE authorization code, and the validation rules — without owning your
storage, sessions or consent page.

```toml
[dependencies]
oxidt-mcp-oauth = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-mcp-oauth-v0.1.0" }
```

No axum, no database, no clock. Every function is pure: requests in, a
validated value or an `OAuthError` out.

## Why a core and not a full server

The two apps this came from (dowat, smiet) run the same flow on completely
different plumbing: a file-backed store versus Postgres, a signed cookie versus
a `tower-sessions` session, a Dioxus consent page versus server-rendered HTML,
rotating refresh tokens versus minted API keys. A crate that owned any of that
would fit one of them.

What must not drift between them is the security-relevant part: which
callbacks are allowed, that PKCE is S256-only, that a code only redeems for the
client, redirect URI and resource it was issued for, and what the discovery
documents say. That is what lives here.

## Endpoints an app wires

| endpoint | calls |
|---|---|
| `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728) | `metadata::protected_resource` |
| `GET /.well-known/oauth-authorization-server` (RFC 8414) | `metadata::authorization_server` |
| `POST /oauth/register` (RFC 7591) | `register::validate`, then `register::response` |
| `GET /oauth/authorize` | `authorize::validate`; after consent `authorize::redirect_url` |
| `POST /oauth/token` | `token::parse`; for a code `token::verify_code_exchange` |
| 401 from the MCP endpoint | `challenge::www_authenticate` |

The app keeps: client/code/token storage, taking a code (delete-on-read, so it
is single-use), the consent session and page, CSRF on the decision, rate
limits, and what it issues.

```rust
use oxidt_mcp_oauth::{Allowlist, LoopbackHttp, Scopes, authorize};

let allowlist = Allowlist::claude()
    .with_chatgpt()
    .with_loopback_http(LoopbackHttp::Path("/callback".into()));
let scopes = Scopes { required: vec!["tasks:write".into()], optional: vec!["offline_access".into()] };

match authorize::validate(&req, &client.redirect_uris, &allowlist, &scopes, Some(&resource)) {
    Ok(validated) => { /* stash, show consent */ }
    Err(authorize::AuthorizeError::InvalidRedirectUri) => { /* error page, never redirect */ }
    Err(authorize::AuthorizeError::Redirect(e)) => { /* redirect_url(&req.redirect_uri, &[("error", e.error), …]) */ }
}
```

## Two consumer shapes

- **Opaque refresh-token store (dowat).** Required `tasks:write`, optional
  `offline_access`, `refresh_tokens: true`, `revocation: true`,
  `iss_parameter: true`, resource bound to `{base}/mcp`. The app hashes and
  stores an access/refresh pair, rotates refresh tokens and revokes the family
  on reuse; it gets `token::Grant::RefreshToken` from `parse` and re-checks the
  grant scope with `Scopes::validate_scope` on every use.
- **Minting API keys (smiet).** Required `mcp`, no refresh, no revocation, no
  resource binding (`resource: None`). After `verify_code_exchange` it mints an
  `oat_` API key that its existing API-key auth accepts, and answers
  `Grant::RefreshToken` with `unsupported_grant_type`.

## The rules

- **Allowlist.** Exact matches first (claude.ai, claude.com, custom schemes such
  as `com.oxidt.smiet://oauth/callback`). Anything else must parse and carry no
  userinfo, query or fragment, then be ChatGPT's connector callback (opt-in) or
  plain-`http` loopback under the configured `LoopbackHttp` policy.
- **Registration.** 1–8 redirect URIs, all allowed; public clients only;
  `grant_types` must include `authorization_code` and nothing beyond
  `refresh_token`; `response_types` exactly `code`; `client_name` trimmed,
  non-blank, ≤ 100 bytes, no control characters.
- **Authorize.** Redirect URI registered *and* allowed (else no redirect),
  `response_type=code`, `S256` only with a 43-character challenge, `state`
  ≤ 2048 bytes, `resource` must match when bound, scope via `Scopes`.
- **Token.** `client_id` and `redirect_uri` required and equal to the stored
  code's, `expires_at > now`, verifier 43–128 unreserved characters and PKCE
  via `oxidt_crypto::verify_pkce_s256` (constant time), resource must match
  when bound (`invalid_target`).

## RFCs

6749 (OAuth 2.0), 7591 (dynamic client registration), 7636 (PKCE), 8414
(authorization server metadata), 8707 (resource indicators), 9728 (protected
resource metadata). OAuth 2.1 defaults throughout: S256 only, no implicit grant,
exact redirect-URI matching.

## License

MIT — see [LICENSE](../../LICENSE).
