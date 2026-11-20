//! The redirect login against a generic OIDC issuer, end to end: an
//! in-process issuer (discovery, JWKS, RS256-signed id_tokens) and the app's
//! `auth_router` served over real sockets, driven the way the browser does.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::routing::get;
use serde_json::{Value, json};
use tower_sessions::{MemoryStore, SessionManagerLayer};

use super::super::shared::tests::{OneUserStore, state, victim};
use crate::config::AuthConfig;
use crate::jwt::{JwksCache, JwtError};
use crate::state::AuthState;

/// Test-only RSA key; its public half is `MODULUS` below.
const PRIVATE_KEY: &[u8] = include_bytes!("testdata/oidc-test-key.pem");
const MODULUS: &str = "oqO0CM8DQqVZL7HwLkj1M0_4SbNystSfpMJwE_5dhIwCnq1tRH2MRrh5Jin5qlY_DkkDDjrWA7Adu47dZjl4iitdCrOwsPDyCITWbbvx0aLx68P4WnwV9jlxGlftF-ZutV2emBu7Shch687QiwHGmCUh8n7cLttgRy5fXn-nb9RXb7sw80uvoUhzXeZ-4wfisJvk-fLnIJUFr2tJ_QvHLMMfcLCzJZRUnbUxdfY1fznkHeGowxdmOa2FqlCzzEcLahpSxtvNM8fWTHlGMJKE8R2M9hN5ttHae9OJGyHbH_NiVJ2j3vIznODn4neulQ0RULcghqLozrNVG14Ik1LNvw";
const KID: &str = "test-key-1";
const CLIENT_ID: &str = "oxidt-ci";

/// An issuer at `http://127.0.0.1:<port>` whose discovery document names
/// `claimed_issuer` (normally its own URL).
async fn mock_issuer(claimed_issuer: Option<&str>) -> String {
    let claimed_issuer = claimed_issuer.map(str::to_string);
    mock_issuer_with(move |doc| {
        if let Some(iss) = claimed_issuer {
            doc["issuer"] = json!(iss);
        }
    })
    .await
}

/// An issuer whose discovery document `edit` may change.
async fn mock_issuer_with(edit: impl FnOnce(&mut Value)) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut doc = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "end_session_endpoint": format!("{base}/logout"),
    });
    edit(&mut doc);
    let jwks = json!({ "keys": [{
        "kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID, "n": MODULUS, "e": "AQAB",
    }]});
    let router = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { axum::Json(doc) }),
        )
        .route(
            "/jwks",
            get({
                let jwks = jwks.clone();
                move || async move { axum::Json(jwks) }
            }),
        )
        // The same key at FerrisKey's realm-shaped URL, for the regression
        // tests of the FerrisKey SSO mode.
        .route(
            "/realms/r/protocol/openid-connect/certs",
            get(move || async move { axum::Json(jwks) }),
        );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(issuer: &str, nonce: &str) -> Value {
    json!({
        "iss": issuer,
        "sub": "sso|ann",
        "aud": CLIENT_ID,
        "exp": now() + 300,
        "iat": now(),
        "nonce": nonce,
        "email": "ann@example.com",
        "email_verified": true,
    })
}

fn sign_with(claims: &Value, kid: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

fn sign(claims: &Value) -> String {
    sign_with(claims, KID)
}

// ── Token validation ────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_id_token_is_accepted() {
    let issuer = mock_issuer(None).await;
    let cache = JwksCache::oidc(&issuer, CLIENT_ID);
    let claims = cache
        .validate_token(&sign(&claims(&issuer, "n")))
        .await
        .unwrap();
    assert_eq!(claims.sub, "sso|ann");
    assert_eq!(claims.email_verified, Some(true));
}

#[tokio::test]
async fn foreign_issuer_audience_expiry_and_key_are_rejected() {
    let issuer = mock_issuer(None).await;
    let cache = JwksCache::oidc(&issuer, CLIENT_ID);
    let tamper = |field: &str, value: Value| {
        let mut c = claims(&issuer, "n");
        c[field] = value;
        sign(&c)
    };

    for (what, token) in [
        ("issuer", tamper("iss", json!("https://evil.example"))),
        ("audience", tamper("aud", json!("another-app"))),
        // Beyond the 60 s clock leeway.
        ("expiry", tamper("exp", json!(now() - 600))),
    ] {
        assert!(
            matches!(
                cache.validate_token(&token).await,
                Err(JwtError::ValidationFailed)
            ),
            "{what} not rejected"
        );
    }
    assert!(matches!(
        cache
            .validate_token(&sign_with(&claims(&issuer, "n"), "rotated-away"))
            .await,
        Err(JwtError::UnknownKid)
    ));
}

#[tokio::test]
async fn a_token_shared_with_or_issued_to_another_client_is_rejected() {
    let issuer = mock_issuer(None).await;
    let cache = JwksCache::oidc(&issuer, CLIENT_ID);
    let with = |field: &str, value: Value| {
        let mut c = claims(&issuer, "n");
        c[field] = value;
        sign(&c)
    };

    for (what, token) in [
        ("azp", with("azp", json!("another-app"))),
        (
            "second audience",
            with("aud", json!([CLIENT_ID, "another-app"])),
        ),
    ] {
        assert!(
            matches!(
                cache.validate_token(&token).await,
                Err(JwtError::ValidationFailed)
            ),
            "{what} not rejected"
        );
    }
    for (what, token) in [
        ("own azp", with("azp", json!(CLIENT_ID))),
        ("one-element aud", with("aud", json!([CLIENT_ID]))),
    ] {
        assert!(
            cache.validate_token(&token).await.is_ok(),
            "{what} rejected"
        );
    }
}

#[tokio::test]
async fn ferriskey_tokens_keep_their_extra_audiences() {
    let idp = mock_issuer(None).await;
    let cache = JwksCache::new(&idp, &idp, "r", CLIENT_ID);
    let mut c = claims(&format!("{idp}/realms/r"), "n");
    c["aud"] = json!([CLIENT_ID, "account"]);
    c["azp"] = json!("account");
    assert!(cache.validate_token(&sign(&c)).await.is_ok());
}

#[tokio::test]
async fn an_issuer_or_endpoint_off_https_is_refused() {
    // Not loopback, and never contacted: refused before any fetch.
    let cache = JwksCache::oidc("http://idp.example.test", CLIENT_ID);
    assert!(cache.oidc_endpoints().await.is_err());

    for field in [
        "jwks_uri",
        "authorization_endpoint",
        "token_endpoint",
        "end_session_endpoint",
    ] {
        let issuer = mock_issuer_with(|doc| doc[field] = json!("http://idp.example.test/x")).await;
        let cache = JwksCache::oidc(&issuer, CLIENT_ID);
        assert!(cache.oidc_endpoints().await.is_err(), "{field} over http");
    }
}

#[tokio::test]
async fn a_localhost_issuer_is_reached_on_loopback_whatever_dns_says() {
    // `issuer.localhost` need not resolve anywhere on this machine: the
    // issuer client pins it to loopback, where the mock listens.
    let mut named = String::new();
    let issuer = mock_issuer_with(|doc| {
        let base = doc["issuer"].as_str().unwrap().to_string();
        named = base.replace("127.0.0.1", "issuer.localhost");
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "end_session_endpoint",
        ] {
            let v = doc[field]
                .as_str()
                .unwrap()
                .replace("127.0.0.1", "issuer.localhost");
            doc[field] = json!(v);
        }
    })
    .await;
    assert!(issuer.contains("127.0.0.1"));
    let cache = JwksCache::oidc(&named, CLIENT_ID);
    let endpoints = cache.oidc_endpoints().await.unwrap().unwrap();
    assert!(endpoints.jwks_uri.starts_with("http://issuer.localhost:"));
    let token = sign(&claims(&named, "n"));
    assert!(
        cache.validate_token(&token).await.is_ok(),
        "keys fetched via loopback"
    );
}

#[test]
fn https_is_required_except_on_loopback() {
    use crate::jwt::is_secure_issuer_url as ok;
    for url in [
        "https://idp.example",
        "http://localhost:8080",
        "http://LOCALHOST",
        "http://sso.localhost",
        "http://127.0.0.1",
        "http://127.1.2.3:9",
        "http://[::1]:9000/x",
    ] {
        assert!(ok(url), "{url}");
    }
    for url in [
        "http://idp.example",
        "http://localhost.example",
        "http://10.0.0.1",
        "http://[::2]",
        "ftp://idp.example",
        "idp.example",
    ] {
        assert!(!ok(url), "{url}");
    }
}

#[tokio::test]
async fn a_discovery_document_for_another_issuer_is_refused() {
    let issuer = mock_issuer(Some("https://evil.example")).await;
    let cache = JwksCache::oidc(&issuer, CLIENT_ID);
    assert!(cache.oidc_endpoints().await.is_err());
    let token = sign(&claims("https://evil.example", "n"));
    assert!(cache.validate_token(&token).await.is_err());
}

// ── The redirect flow through auth_router ────────────────────────────

/// A browser of one: carries the session cookie by hand and never follows
/// redirects, so every hop can be inspected.
struct Browser {
    http: reqwest::Client,
    app: String,
    cookie: Option<String>,
}

impl Browser {
    async fn send(&mut self, req: reqwest::RequestBuilder) -> reqwest::Response {
        let req = match &self.cookie {
            Some(c) => req.header("cookie", c),
            None => req,
        };
        let resp = req.send().await.unwrap();
        if let Some(set) = resp.headers().get("set-cookie") {
            let pair = set.to_str().unwrap().split(';').next().unwrap();
            self.cookie = Some(pair.to_string());
        }
        resp
    }

    async fn get(&mut self, path: &str) -> reqwest::Response {
        let req = self.http.get(format!("{}{path}", self.app));
        self.send(req).await
    }

    async fn post_json(&mut self, path: &str, body: Value) -> reqwest::Response {
        let req = self
            .http
            .post(format!("{}{path}", self.app))
            .header("origin", &self.app)
            .json(&body);
        self.send(req).await
    }
}

/// The app with `auth_router` over a generic issuer, where ann may register.
/// `sso_enabled` is left off: the issuer alone selects the redirect login.
async fn app(issuer: &str, store: Arc<OneUserStore>) -> Browser {
    let config = AuthConfig {
        allowed_registration_emails: vec!["ann@example.com".to_string()],
        ..Default::default()
    };
    app_with(config, JwksCache::oidc(issuer, CLIENT_ID), store).await
}

/// The app in FerrisKey mode against `idp`, realm `r`.
async fn ferriskey_app(idp: &str, sso_enabled: bool) -> Browser {
    let config = AuthConfig {
        ferriskey_url: idp.to_string(),
        ferriskey_realm: "r".to_string(),
        ferriskey_client_id: CLIENT_ID.to_string(),
        sso_enabled,
        ..Default::default()
    };
    let jwks = JwksCache::new(idp, idp, "r", CLIENT_ID);
    app_with(config, jwks, Arc::default()).await
}

async fn app_with(config: AuthConfig, jwks: JwksCache, store: Arc<OneUserStore>) -> Browser {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = format!("http://{}", listener.local_addr().unwrap());
    let config = AuthConfig {
        base_url: app.clone(),
        ..config
    };
    let auth_state = AuthState {
        jwks_cache: Arc::new(jwks),
        ..state(store)
    };
    let router = crate::auth_router(config, auth_state)
        .layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false));
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Browser {
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        app,
        cookie: None,
    }
}

fn location(resp: &reqwest::Response) -> url::Url {
    url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap()
}

/// `GET /auth/sso/start`, returning the authorization request's parameters.
async fn start(browser: &mut Browser, issuer: &str) -> HashMap<String, String> {
    start_at(browser, &format!("{issuer}/authorize")).await
}

async fn start_at(browser: &mut Browser, authorize: &str) -> HashMap<String, String> {
    let resp = browser.get("/auth/sso/start?next=/builds").await;
    assert_eq!(resp.status(), 303);
    let url = location(&resp);
    assert_eq!(url.as_str().split('?').next().unwrap(), authorize);
    url.query_pairs().into_owned().collect()
}

#[tokio::test]
async fn sso_start_sends_the_browser_to_the_discovered_authorization_endpoint() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    let q = start(&mut browser, &issuer).await;
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["redirect_uri"], format!("{}/auth/callback", browser.app));
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(!q["state"].is_empty() && !q["nonce"].is_empty());
}

#[tokio::test]
async fn the_ferriskey_custom_login_is_not_mounted() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    let resp = browser
        .post_json("/auth/session/start", json!({ "email": "ann@example.com" }))
        .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn callback_with_a_foreign_state_is_refused() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    start(&mut browser, &issuer).await;
    let resp = browser.get("/auth/callback?code=c0de&state=forged").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn callback_page_redeems_the_code_at_the_discovered_token_endpoint() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    let q = start(&mut browser, &issuer).await;
    let resp = browser
        .get(&format!("/auth/callback?code=c0de&state={}", q["state"]))
        .await;
    assert_eq!(resp.status(), 200);
    let csp = resp.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains(&format!("connect-src 'self' {issuer};")));
    let page = resp.text().await.unwrap();
    assert!(page.contains(&format!(r#""token_url":"{issuer}/token""#)));
    assert!(page.contains(&format!(r#""client_id":"{CLIENT_ID}""#)));
}

#[tokio::test]
async fn sso_complete_binds_the_id_token_to_the_flow_nonce() {
    let issuer = mock_issuer(None).await;
    let store = Arc::new(OneUserStore::default());
    let mut browser = app(&issuer, store.clone()).await;
    let q = start(&mut browser, &issuer).await;

    let replayed = sign(&claims(&issuer, "some-other-flow"));
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": replayed }))
        .await;
    assert_eq!(resp.status(), 401);
    assert!(store.created.lock().unwrap().is_empty());

    let token = sign(&claims(&issuer, &q["nonce"]));
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": token }))
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["redirect_url"], "/builds");
    let created = store.created.lock().unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].sub, "sso|ann");
}

#[tokio::test]
async fn an_unverified_email_cannot_claim_an_existing_account() {
    let issuer = mock_issuer(None).await;
    let store = Arc::new(OneUserStore {
        by_email: Some(victim()),
        ..Default::default()
    });
    let mut browser = app(&issuer, store.clone()).await;
    let q = start(&mut browser, &issuer).await;
    let mut c = claims(&issuer, &q["nonce"]);
    c["email"] = json!("victim@example.com");
    c["email_verified"] = json!(false);
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": sign(&c) }))
        .await;
    assert_eq!(resp.status(), 401);
    assert!(store.sub_updates.lock().unwrap().is_empty());
}

/// One login against `issuer` with `edit` applied to ann's claims; the
/// status and body of `/auth/sso/complete`.
async fn complete_with(
    browser: &mut Browser,
    issuer: &str,
    edit: impl FnOnce(&mut Value),
) -> (u16, String) {
    let q = start(browser, issuer).await;
    let mut c = claims(issuer, &q["nonce"]);
    edit(&mut c);
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": sign(&c) }))
        .await;
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// Registration closed to ann: an allowlist naming someone else.
fn closed() -> AuthConfig {
    AuthConfig {
        allowed_registration_emails: vec!["bob@example.com".to_string()],
        ..Default::default()
    }
}

#[tokio::test]
async fn a_new_identity_follows_the_apps_registration_policy() {
    let issuer = mock_issuer(None).await;

    // Closed: refused with a reason, nothing created, no session.
    let store = Arc::new(OneUserStore::default());
    let mut browser = app_with(closed(), JwksCache::oidc(&issuer, CLIENT_ID), store.clone()).await;
    let (status, body) = complete_with(&mut browser, &issuer, |_| {}).await;
    assert_eq!(status, 401);
    assert!(body.contains("not permitted to use this app"), "{body}");
    assert!(store.created.lock().unwrap().is_empty());
    let logout = browser.post_json("/auth/logout", json!({})).await;
    assert_eq!(logout.headers()["location"], "/", "no session was opened");

    // Invited: admitted although the allowlist names someone else.
    let store = Arc::new(OneUserStore {
        invited: true,
        ..Default::default()
    });
    let mut browser = app_with(closed(), JwksCache::oidc(&issuer, CLIENT_ID), store.clone()).await;
    assert_eq!(complete_with(&mut browser, &issuer, |_| {}).await.0, 200);
    assert_eq!(store.created.lock().unwrap().len(), 1);

    // Allowlisted, but the issuer does not vouch for the address.
    let store = Arc::new(OneUserStore::default());
    let mut browser = app(&issuer, store.clone()).await;
    let (status, body) = complete_with(&mut browser, &issuer, |c| {
        c["email_verified"] = json!(false)
    })
    .await;
    assert_eq!(status, 401);
    assert!(body.contains("not verified"), "{body}");
    assert!(store.created.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_existing_account_signs_in_while_registration_is_closed() {
    let issuer = mock_issuer(None).await;
    let store = Arc::new(OneUserStore {
        by_sub: Some(victim()),
        ..Default::default()
    });
    let mut browser = app_with(closed(), JwksCache::oidc(&issuer, CLIENT_ID), store.clone()).await;
    let (status, _) = complete_with(&mut browser, &issuer, |_| {}).await;
    assert_eq!(status, 200);
    assert!(store.created.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_account_gone_since_it_was_found_is_not_recreated_unchecked() {
    // Found by sub at the first read, deleted before the next.
    let issuer = mock_issuer(None).await;
    let store = Arc::new(OneUserStore {
        by_sub_once: std::sync::Mutex::new(Some(victim())),
        ..Default::default()
    });
    let mut browser = app_with(closed(), JwksCache::oidc(&issuer, CLIENT_ID), store.clone()).await;
    let (status, _) = complete_with(&mut browser, &issuer, |_| {}).await;
    // One read decides: it found the account, so that account signs in, and
    // no replacement is created behind the registration policy's back.
    assert_eq!(status, 200);
    assert!(store.created.lock().unwrap().is_empty());
}

#[cfg(feature = "passkey-rp")]
#[tokio::test]
async fn passkey_enrollment_is_mounted_only_in_ferriskey_mode() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    let resp = browser
        .post_json("/auth/passkey/enroll/options", json!({}))
        .await;
    assert_eq!(resp.status(), 404);

    let mut browser = ferriskey_app(&issuer, true).await;
    let resp = browser
        .post_json("/auth/passkey/enroll/options", json!({}))
        .await;
    assert_eq!(resp.status(), 401, "mounted, and wants a session");
}

#[tokio::test]
async fn logout_goes_through_the_discovered_end_session_endpoint() {
    let issuer = mock_issuer(None).await;
    let mut browser = app(&issuer, Arc::default()).await;
    let q = start(&mut browser, &issuer).await;
    let token = sign(&claims(&issuer, &q["nonce"]));
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": token }))
        .await;
    assert_eq!(resp.status(), 200);

    let resp = browser.post_json("/auth/logout", json!({})).await;
    assert_eq!(resp.status(), 303);
    let url = location(&resp);
    assert_eq!(
        url.as_str().split('?').next().unwrap(),
        format!("{issuer}/logout")
    );
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(
        q["post_logout_redirect_uri"],
        format!("{}/login", browser.app)
    );
}

// ── FerrisKey mode is unchanged ──────────────────────────────────────

#[tokio::test]
async fn ferriskey_sso_still_uses_the_realm_urls() {
    let idp = mock_issuer(None).await;
    let mut browser = ferriskey_app(&idp, true).await;
    let q = start_at(
        &mut browser,
        &format!("{idp}/realms/r/protocol/openid-connect/auth"),
    )
    .await;
    let resp = browser
        .get(&format!("/auth/callback?code=c0de&state={}", q["state"]))
        .await;
    let page = resp.text().await.unwrap();
    assert!(page.contains(&format!(
        r#""token_url":"{idp}/realms/r/protocol/openid-connect/token""#
    )));

    let token = sign(&claims(&format!("{idp}/realms/r"), &q["nonce"]));
    let resp = browser
        .post_json("/auth/sso/complete", json!({ "id_token": token }))
        .await;
    assert_eq!(resp.status(), 200);

    let resp = browser.post_json("/auth/logout", json!({})).await;
    assert_eq!(resp.status(), 303);
    let url = location(&resp);
    assert_eq!(
        url.as_str().split('?').next().unwrap(),
        format!("{idp}/realms/r/protocol/openid-connect/logout")
    );
}

#[tokio::test]
async fn ferriskey_mode_keeps_the_custom_login_and_gates_sso_on_the_flag() {
    let idp = mock_issuer(None).await;
    let mut browser = ferriskey_app(&idp, false).await;
    assert_eq!(browser.get("/auth/sso/start").await.status(), 404);
    // Mounted: it fails on the missing client secret, not as an unknown route.
    let resp = browser
        .post_json("/auth/session/start", json!({ "email": "ann@example.com" }))
        .await;
    assert_ne!(resp.status(), 404);
}
