# oxidt-auth

Authentication for a Dioxus fullstack app: a custom login UI driven against
FerrisKey's REST API, with sessions, CSRF, and rate limiting on the Axum side.

Login is OTP-first with auto-detection — the user types an email, and the crate
decides whether to challenge a passkey, ask for a password, or mail a one-time
code. FerrisKey is the identity provider; the login screen is yours.

```toml
[dependencies]
oxidt-auth = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-auth-v0.14.1", features = ["server"] }
```

No default features. Enable `server` (Axum handlers, FerrisKey client, session
and rate-limit machinery), `web` (WASM passkey helpers), or both — a fullstack
app normally propagates both, and that union is what CI gates on.

Not on Dioxus? `axum` is `server` without Dioxus and the login pages, and
`topcoat` adds the [Topcoat](#topcoat) adapter on top of it.

## Storage stays in your app

The crate has no database dependency. It reaches storage through three traits:

| trait | what you implement |
|---|---|
| `AuthUserStore` | look up / create a user, update their `sub`, record TOS acceptance and logins, decide the post-login redirect |
| `AuthEmailSender` | deliver the OTP code (pair it with [`oxidt-smtp`](../oxidt-smtp)) |
| `AuthRateLimitStore` | a shared counter for rate limiting — see below |

`AuthUser.id` is a `String` on purpose: Mongo's `ObjectId::to_hex()` and
Postgres' `Uuid::to_string()` both round-trip through it, so the crate never
needs to know which one you run. ID validation belongs in your store impl.

## Wiring it up

```rust
use oxidt_auth::{auth_router, AuthConfig, AuthState, JwksCache};
use std::sync::Arc;

let config = AuthConfig {
    login_page_url: "/login".into(),
    default_post_login_url: "/dashboard".into(),
    ferriskey_url: std::env::var("FERRISKEY_URL")?,
    ferriskey_realm: "myapp".into(),
    ferriskey_client_id: "myapp-dashboard".into(),
    ferriskey_client_secret: std::env::var("FERRISKEY_CLIENT_SECRET").ok(),
    base_url: "https://app.example.com".into(),
    trust_proxy_headers: true, // only behind a proxy you control
    ..Default::default()
};

let state = AuthState {
    user_store: Arc::new(MyUserStore::new(db.clone())),
    email_sender: Arc::new(MyEmailSender::new(smtp.clone())),
    jwks_cache: Arc::new(JwksCache::new(
        &config.ferriskey_url,
        config.ferriskey_issuer_url.as_deref().unwrap_or(&config.ferriskey_url),
        &config.ferriskey_realm,
        &config.ferriskey_client_id,
    )),
    rate_limit_store: Some(Arc::new(MyRateLimitStore::new(db.clone()))),
};

let app = my_router
    .merge(auth_router(config, state))
    .layer(session_manager_layer); // tower-sessions, provided by your app
```

The router needs a `tower_sessions::Session` in the request extensions — mount
your `SessionManagerLayer` outside it, or every request fails with
`AuthError::AuthSessionLayerNotFound`.

On the UI side, render `LoginPage { redirect_url }` (pass `embed: true` to drop
the built-in page wrapper and card), and read the session back in server
functions with the `UserSession` extractor:

```rust
let user = user_session.data()?; // Err(AuthError::UserNotLoggedIn) if anonymous
```

`UserDataRefreshTrigger` is a context signal the login flow bumps on success, so
the shell can re-fetch user data instead of reloading the page — provide it via
`use_context_provider` above the page.

The login markup is Tailwind + DaisyUI (`card`, `base-200`, `loading-spinner`),
so it inherits the host app's DaisyUI theme rather than shipping its own CSS.

## Routes

`auth_router` mounts:

```
POST /auth/logout
POST /auth/session/start                 email → passkey | password | OTP
POST /auth/session/passkey/verify
POST /auth/session/password/verify
POST /auth/session/otp/verify
POST /auth/session/otp/resend
POST /auth/session/captcha/verify        new-user registration (bollwark)
POST /auth/session/accept-tos            when AuthConfig::tos_version is set
POST /auth/dev-login                     debug builds only
GET  /auth/sso/start?next=               SSO mode only, see below
GET  /auth/callback
POST /auth/sso/complete
```

## SSO mode (browser redirect)

Apps sharing one FerrisKey realm can share one login. Set `sso_enabled: true`
and link the login page to `GET /auth/sso/start?next=/dashboard`. The browser
is sent to FerrisKey's hosted login page instead of the custom `LoginPage` and
comes back to `GET /auth/callback`, which serves a small page that redeems the
code **from the browser** and posts the id_token to `POST /auth/sso/complete`.
The app validates it (JWKS, audience, nonce) and opens the session like any
other login.

The exchange runs in the browser on purpose: FerrisKey sets its SSO cookie
(`FERRISKEY_IDENTITY`) on the token endpoint's response and nowhere else, so a
server-side exchange never gets it into the browser. With the cookie in place,
the next app's `/auth/sso/start` comes back with a code and no prompt — for as
long as the client's `access_token_lifetime`, which is what the cookie carries.
The PKCE verifier and the token response pass through the browser, as for any
public (SPA) client; the app only ever accepts an id_token with its own
audience and the nonce it minted for that session.

FerrisKey client checklist, one per app, all in the shared realm:

- **public** client with PKCE required — no secret is used in this mode
- redirect URI `{base_url}/auth/callback` (exact match)
- CORS for the browser's token request: on FerrisKey 0.7.x this is the
  server-wide `ALLOWED_ORIGINS` env of the API container (comma-separated; add
  `{base_url}`'s origin). Newer FerrisKey has per-client web origins instead,
  where `+` derives the origin from the redirect URI
- post-logout redirect URI `{base_url}{login_page_url}` (exact match; the
  root URL or a trailing slash won't do)
- `access_token_lifetime` = the silent-SSO window you want (realm default 300 s)
- users' emails marked verified, or an existing account cannot be re-bound to
  its new `sub` (see the security notes)
- no roles, scopes or mappers: the app reads `sub`, `email` and
  `email_verified` from the default `openid email profile` scope

`ferriskey_url` must be reachable from the browser. Logout redirects through
FerrisKey's end-session endpoint so the identity cookie is cleared; that only
works for a **top-level** `POST /auth/logout` (a form submit) — a `fetch`
follows the redirect without credentials and the cookie survives. Other apps'
local sessions are not ended; they expire on their own.

Set the tower-sessions cookie to `SameSite=Lax`. The login returns from
FerrisKey by a top-level redirect, and `Strict` withholds the cookie on any
cross-site navigation — which includes `localhost` against a hosted IdP — so
the callback finds no flow. oxidt-auth's origin check still covers the POSTs.

Two things to know when testing:

- **Silent SSO cannot be observed from `localhost`.** FerrisKey's identity
  cookie is `SameSite=Lax`, and browsers discard a Lax cookie delivered by a
  cross-site request; `localhost` → `auth.example` is cross-site, while
  `app.example` → `auth.example` is not. Logging in works locally, the
  no-prompt second login only shows on the deployed host.
- **A FerrisKey console session in the same browser breaks the flow** (0.7.x):
  the hosted login page restarts the OAuth request with its own random `state`
  and drops the nonce and PKCE challenge, so the callback answers
  `Login flow state mismatch`. Log out of the console and retry. The same
  happens after the page's 10-minute session refresh.

## Local mode (no identity provider)

The `local-login` feature runs the crate without FerrisKey at all: email OTP
(which also registers), passkeys verified by the app's own WebAuthn Relying
Party, and — opt-in — a password step. It implies `passkey-rp`, so the app supplies an
`AuthPasskeyStore`, and `AuthUserStore` gains one required method,
`get_user_by_id` (the passkey-autofill path has a credential row and no email).

```toml
auth = { package = "oxidt-auth", git = "…/oxidt-kit.git", tag = "oxidt-auth-v0.14.1", optional = true }

[features]
server = ["auth/server", "auth/local-login", ...]
web    = ["auth/web", ...]
```

```rust
use oxidt_auth::{local_auth_router, AuthConfig, AuthState};

let config = AuthConfig {
    login_page_url: "/login".into(),
    default_post_login_url: "/dashboard".into(),
    base_url: "https://app.example.com".into(), // also the passkey RP ID
    allowed_registration_emails: admin_emails,   // see below
    ..Default::default()
};
let state = AuthState::local(
    Arc::new(MyUserStore::new(db.clone())),
    Arc::new(MyEmailSender::new(smtp.clone())),
    Arc::new(MyPasskeyStore::new(db.clone())),
);
let app = my_router.merge(local_auth_router(config, state));
```

Mount `local_auth_router` *instead of* `auth_router` — both own
`/auth/session/*`. On the UI side render `LocalLoginPage { redirect_url,
app_name, logo_src, captcha_config }`; it adds passkey autofill (conditional
UI), an explicit "Sign in with a passkey" button, and a one-time enrollment
offer after an OTP login.

```
POST /auth/session/start                        email → passkey options | OTP
POST /auth/session/otp/verify                   creates the account if new
POST /auth/session/otp/resend
POST /auth/session/password/verify              only when password_login is set
POST /auth/session/passkey/verify
POST /auth/session/passkey/conditional/options  discoverable (autofill) request
POST /auth/session/passkey-fallback-otp         cancelled ceremony → OTP
POST /auth/session/captcha/verify               only when CAPTCHA_* is set
POST /auth/passkey/enroll/options|verify
POST /auth/session/accept-tos                   when AuthConfig::tos_version is set
POST /auth/logout
```

**Registration is closed by default**, exactly as in FerrisKey mode: set
`allowed_registration_emails` / `allowed_registration_domains`, or leave both
empty and only the very first account may register (first-run bootstrap).
`open_registration: true` lifts both for a public sign-up, and an app that
invites people answers `AuthUserStore::is_invited` so an invitation is enough on
its own. A verified OTP for
a permitted, unknown address creates the account; `sub` is minted by the crate
(an opaque random token) and never rewritten afterwards.

### Password login, and running without SMTP

`AuthConfig::password_login` (default `false`) adds a password step to the page
and mounts `POST /auth/session/password/verify` (`{"email", "password"}`). The
app owns the hash: `AuthUserStore::verify_password(email, password)` answers,
defaulting to `false` so every existing impl keeps compiling. Verify with a
constant-time comparison, and against a dummy hash for an unknown address so
timing does not reveal which addresses exist.

```rust
// at boot: hash the configured admin password once
let admin_hash = oxidt_crypto::hash_secret(&std::env::var("ADMIN_PASSWORD")?)?;
// in the store: `email` arrives trimmed and lowercased
async fn verify_password(&self, email: &str, password: &str) -> AuthResult<bool> {
    Ok(email == self.admin_email && oxidt_crypto::verify_secret(&self.admin_hash, password))
}
```

A `true` is authorization by itself — the operator configured that credential —
so the address is admitted **whatever the registration policy says**, and the
account is created on first login through the same path a verified OTP uses.
The start-session response reports `password` (the flag) and `otp` (whether the
emailed-code branch exists at all). Both are global, never per-address, so
neither can be used to enumerate which addresses have a password. While
`password_login` is on, `/auth/session/start` mails nothing — the person is
about to type a password — and the page's "Email me a code instead" asks for
one through `/auth/session/passkey-fallback-otp`, which carries the resend
throttle.

Without SMTP, build the state with `AuthState::local_without_email(user_store,
passkey_store)`: `email_sender` is an `Option`, and every path that would send
mail — start, resend, the passkey fallback — answers `503`. That leaves the
password step (and passkeys) as the way in, so `POST /auth/session/start` says
`otp: false, password: true`; with `password_login` off as well it answers
`503` naming the misconfiguration, since the deployment can log nobody in.

**Passkey RP ID.** Derived from `base_url`'s host. A credential only works
against the RP ID it was registered under, so moving the app to another host
invalidates every enrolled passkey.

The page leaves a few optional styling hooks for the host stylesheet:
`.auth-bg`, `.auth-card`, and the `animate-scale-in` / `animate-step-in` /
`animate-alert-in` / `animate-pulse-glow` utilities. It renders fine without
them. Because the page lives in a git dependency, Tailwind cannot scan its
classes — keep a safelist file in the app (dx-admin's `safelist-oxidt-auth.html`
is one) and add it as an `@source`.

## Deleting the IdP account

`ferriskey::delete_user(base, realm, service_token, user_id)` deletes a FerrisKey
user, credentials included, for an app's own account-deletion flow. Get the
token with `ferriskey::service_account_token` using the app's client
credentials; the `user_id` is the `sub` of a FerrisKey login. It returns
`Ok(true)` when deleted and `Ok(false)` on a 404 (already gone), so a retry is
safe. The client's service account needs a role with the `manage_users`
permission in the realm, or FerrisKey answers 403.

## Confirming a sensitive action by email

`action_proof` (feature `axum`) asks a logged-in session for a fresh emailed
code before one sensitive action, such as removing a passkey or deleting an
account. The code is bound to the action, user, session and target, and it is
mailed to the account's current address. It expires after 5 minutes and allows
5 guesses (malformed ones count). It is spent **in the same transaction as the
action**. No elevation token is ever issued.

The crate runs the protocol. The app implements `ActionProofBackend`: storage,
quotas, the action's own email, and the action itself.

```rust
use oxidt_auth::action_proof::{self, ActionBinding, ActionProofError};

const REMOVE_PASSKEY: &str = "passkey-removal";

// POST /api/passkeys/removal-code  {id}
let binding = ActionBinding::from_session(&session, REMOVE_PASSKEY, id.to_string()).await?;
action_proof::request(&PasskeyRemoval(state.clone()), &binding).await?;

// POST /api/passkeys/delete  {id, code}
let binding = ActionBinding::from_session(&session, REMOVE_PASSKEY, id.to_string()).await?;
match action_proof::confirm(&PasskeyRemoval(state.clone()), &binding, &code).await {
    Ok(()) => {}                                    // removed, exactly once
    Err(ActionProofError::Rejected) => {}           // 403: ask for a new code
    Err(ActionProofError::LimitExceeded) => {}      // 429
    Err(ActionProofError::Backend(e)) => {}         // the app's own error, e.g. NotFound
    Err(_) => {}                                    // 500
}
```

`ActionBinding::from_session` takes the user from `LoggedInData`, never from
the request. The session part is a hash of the session id. The built-in login
handlers rotate that id, so a pending code does not survive a relogin. The
`session::login` helper alone does not rotate it: a custom login must call
`session.cycle_id()` itself. Build the binding from the live session on every
request, as above, and never cache it across requests. These routes live in
the app, not in `auth_router`, so give them a same-origin check yourself
(`csrf::csrf_origin_check`, or an equivalent).

A code only proves the user could read the account's mail just now. It grants
no permission. `consume_and_perform` must re-run the action's own
authorization in the same transaction (the target still exists, the user still
owns it, a membership or role is still held) and roll back if any check fails.

Each backend method must be atomic in storage that all replicas share. A
process-local lock is not enough. On PostgreSQL that takes a proofs table, the
app's quota counters, one statement per method, and one transaction for
`consume_and_perform`:

```sql
CREATE TABLE action_proofs (
    action TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_key TEXT NOT NULL,
    target TEXT NOT NULL,
    recipient TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (action, user_id, session_key)
);
```

| method | what it must do |
|---|---|
| `charge_issue` / `charge_guess` | a shared counter upsert (`INSERT … ON CONFLICT DO UPDATE … RETURNING count`) keyed by action and user, **never by session or target**, shared by all replicas. An `Err` refuses, so the counter fails closed (unlike an `AuthRateLimitStore` that fails open). A daily issuance cap is what bounds guessing across resends. Keep each counter until its window ends: a sweep that deletes it sooner (hourly, say) resets a daily cap |
| `recipient` | `SELECT u.email … JOIN <target table> … WHERE u.id = $user AND <target> = $target`: the current address, and `None` unless the user owns the target |
| `store_pending` | `INSERT … ON CONFLICT (action, user_id, session_key) DO UPDATE SET target, recipient, code_hash, attempts = 0, expires_at = NOW() + ttl` |
| `send_code` | **the action's own email**: what is being confirmed, that the code does not sign anyone in, and what to do if the request was not theirs. Not the login-code mail |
| `discard_pending` | `DELETE … WHERE action, user_id, session_key AND code_hash = $hash`, so a racing resend's code survives. Best effort after a failed send: an error is only logged, and the row then stays usable until it expires |
| `charge_attempt` | `UPDATE … SET attempts = attempts + 1 WHERE action, user_id, session_key, target AND expires_at > NOW() AND attempts < $max RETURNING code_hash` |
| `consume_and_perform` | in one transaction: `DELETE FROM action_proofs p USING users u WHERE` action, user_id, session_key, target, `p.code_hash = $hash AND p.expires_at > NOW() AND u.id = p.user_id AND u.email = p.recipient`. If one row was deleted, re-check the action's authorization, run the action scoped by user and target, and commit (`Ok(true)`). If none, `Ok(false)`. If a check or the action fails, roll back and return `Err` |

`ActionProofError::Delivery` means `send_code` returned an error, not that the
mail went nowhere: an SMTP failure can still deliver. The crate then tries
`discard_pending`, which can fail too.

The quotas, the email copy, the schema and sweeping expired rows are all the
app's. Sweep expired proofs freely, but never a quota counter whose window is
still open. The crate's tests run a backend built to these contracts through resend,
failed-delivery and double-confirm races.

## Security notes

**Middleware order is load-bearing.** Axum applies the last `.layer()`
outermost, so CSRF origin checking runs *before* rate limiting. That is
deliberate: a cross-origin POST is rejected before it can consume a real user's
per-IP quota or reach the shared counter. If you re-layer the router, keep that
order.

**Rate limiting is 20 req/min per IP** (`AUTH_REQUESTS_PER_MINUTE`) across all
auth endpoints. `rate_limit_store: None` falls back to an in-process limiter,
which is fine for a single instance and wrong for several — N replicas allow N×
the quota. Wire a shared store before you scale out. The field is `Option` so
adopting the crate and wiring the backend can be separate commits.

**OTP and password attempt caps are enforced under a per-session lock,** with
the counter written back before the lock is released. Without that, parallel
requests carrying one cookie each read the same count and the cap is met once
per burst, not per request. The lock is in-process, so N replicas serving the
same cookie at once can overshoot by at most N passes — a bound set by your
deployment, not by the attacker.

**An id_token's email may only claim an existing account when the IdP marks it
`email_verified`.** An unverified match is refused with 401 rather than migrated
or duplicated, so a FerrisKey user whose address was never verified cannot log
into a local account that happens to share it. Email-OTP logins count as
verified by construction.

**`trust_proxy_headers` defaults to `false`.** Only turn it on behind a reverse
proxy you control; otherwise a client can spoof `X-Forwarded-For` and get a
fresh quota per request.

**Logout is `POST`,** so a cross-site `<img>` or link can't force it.

**Request bodies are capped at 64 KiB** on both routers. Every auth body is
small — an email, a code, a captcha token, one WebAuthn credential, an
id_token — and the passkey paths decode CBOR from unauthenticated callers.

**`/auth/dev-login` is compiled out of release builds** (`#[cfg(debug_assertions)]`)
*and* additionally requires `DEV_LOGIN=true` at runtime.

**A captcha guards new-user registration**, using bollwark: set `CAPTCHA_URL`,
`CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY` and the login page mounts the widget
in the email form, pre-solving while the user types; the token is verified
server-to-server and fails closed on a missing token, a rejection, or an
unreachable captcha server. With those vars unset there is no captcha and the
registration allowlist is the only gate — fine for an internal deployment,
not for a public one. A public product sets `open_registration: true` on
`AuthConfig`, which admits every address and leaves the captcha as the whole
gate.

**reqwest is built on rustls**, not native-tls, to keep OpenSSL out of slim
runtime images.

## Hydration

With SSR the browser paints the login form fully styled long before the WASM
bundle lands. Until it does, no handler is attached — and a `<form>` whose
`onsubmit` hasn't attached still performs the browser's *native* submit on
Enter: a GET that reloads the page and discards the typed email.

`use_hydrated()` reports which side of that line the page is on; `LoginPage`
uses it to keep the controls in a `disabled` `<fieldset>` until interactive.
Gating only the submit button is not enough — it doesn't stop implicit
submission.

If the bundle takes too long, the page reveals a stall notice styled by a
`.hydration-stall` class your stylesheet is expected to define (a delayed
reveal, since if the bundle never arrives there is no Rust running to notice).
Without the class the notice just appears immediately; nothing breaks.

## The seam between the two modes

`passkey-rp` (0.2.0) made the app its own WebAuthn Relying Party while still
logging in through FerrisKey; `local-login` (0.7.0) builds on it to drop the IdP
entirely. The two login back-ends are separate handler modules with separate
pages, sharing the OTP core (attempt cap under a per-session lock, recipient
binding, captcha), the registration allowlist, sessions, CSRF, rate limiting
and the RP. The FerrisKey `LoginPage` does not yet have the local page's
passkey autofill or enrollment offer.

## License

MIT — see [LICENSE](../../LICENSE).

## Topcoat

With the `topcoat` feature, mount the router as a tower service and wrap the
whole Topcoat router in your `SessionManagerLayer`, so pages and the auth
handlers share one session:

```rust
use topcoat::router::{Router, tower::{TowerLayer, TowerRoute}};

let router = Router::builder()
    .route(TowerRoute::any("/auth/{*rest}", auth_router(config, state)))
    .layer(TowerLayer::new(session_manager_layer))
    .build();
```

Read the session in a page or route:

```rust
let user = oxidt_auth::topcoat::user_session(cx).await?.data()?;
```

Render the FerrisKey login page as a component, inside your own document:

```rust
#[page("/login")]
async fn login(cx: &Cx) -> Result<impl View> {
    Ok(view! {
        document(
            title: "Sign in",
            ferriskey_login_page(redirect_url: "/dashboard", captcha: captcha_config())
        )
    })
}
```

It is server-rendered with the same steps as the Dioxus `LoginPage` (email,
passkey, password, email code, captcha-gated registration, terms) and talks to
the same `auth_router` endpoints. `redirect_url` must be a relative path or it
is dropped and the server's default applies; after login the page loads the
URL the server answers with. `embed: true` leaves out the full-page wrapper,
card and "Welcome" heading. `captcha` is the bollwark `(server_url, site_key)`.
In a debug build with `DEV_LOGIN=true` it also shows the dev-login button.
There is no `on_success` / `on_signup` callback: login ends in a full page load.

With `local-login` too, render the self-owned login page instead (mount
`local_auth_router` instead of `auth_router`):

```rust
view! {
    local_login_page(redirect_url: "/dashboard", app_name: Some("Acme".to_owned()))
}
```

It is server-rendered with the same steps as the Dioxus `LocalLoginPage`
(OTP, passkey autofill and modal, password, terms, passkey offer).

On both pages an inlined script drives the steps, so a strict CSP needs to
allow inline scripts. Styling is the same Tailwind + DaisyUI classes as the
Dioxus pages, so point Tailwind's scan (or your safelist) at this crate's
`src/topcoat/`. The local page also uses the optional host hooks listed under
[Local mode](#local-mode-no-identity-provider); the FerrisKey page needs none.
