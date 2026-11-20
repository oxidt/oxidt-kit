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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let doc = json!({
        "issuer": claimed_issuer.unwrap_or(&base),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "end_session_endpoint": format!("{base}/logout"),
    });
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

/// The app with `auth_router` over a generic issuer. `sso_enabled` is left
/// off: the issuer alone selects the redirect login.
async fn app(issuer: &str, store: Arc<OneUserStore>) -> Browser {
    app_with(
        AuthConfig::default(),
        JwksCache::oidc(issuer, CLIENT_ID),
        store,
    )
    .await
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
