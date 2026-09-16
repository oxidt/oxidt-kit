//! The monitoring surface every dx app presents to the central project board.
//!
//! Two endpoints, extracted from stepshots and infrapage — which each carried
//! their own copy of this file and had drifted 102 lines apart:
//!
//! - `GET /health` — public liveness probe. 200 when every check passes, 503
//!   otherwise.
//! - `GET /api/admin/metrics` — bearer-guarded business KPIs.
//!
//! The paths are fixed on purpose. The board polls every project uniformly, so
//! the path *is* the contract; an app that picks its own drops off the board.
//! The rare app that must mount elsewhere calls [`health_response`] and
//! [`metrics_response`] directly and keeps the payload shape.
//!
//! # The database stays on the app side
//!
//! This crate has no `sqlx`, no `mongodb`, and never will — the two apps it
//! came from are on different databases and that must keep costing nothing.
//! [`MonitorSource`] is the seam: the app gathers its counts however it likes
//! (one Postgres aggregate, a handful of Mongo counts, a cached snapshot) and
//! the crate owns only the wire format and the token check.
//!
//! ```no_run
//! use dx_monitor::{HealthCheck, Kpi, MonitorSource, MonitorToken};
//!
//! struct Metrics(AppState);
//!
//! #[async_trait::async_trait]
//! impl MonitorSource for Metrics {
//!     async fn health(&self) -> Vec<HealthCheck> {
//!         vec![HealthCheck::new("db", self.0.ping_db().await.is_ok())]
//!     }
//!
//!     async fn kpis(&self) -> Vec<Kpi> {
//!         vec![Kpi::new("users", "Users", self.0.count_users().await.unwrap_or(0))]
//!     }
//! }
//!
//! # struct AppState;
//! # impl AppState {
//! #     async fn ping_db(&self) -> Result<(), ()> { Ok(()) }
//! #     async fn count_users(&self) -> Result<i64, ()> { Ok(0) }
//! # }
//! # fn wire(state: AppState) -> axum::Router {
//! axum::Router::new()
//!     // ...the app's own routes...
//!     .merge(dx_monitor::router(Metrics(state), MonitorToken::from_env()))
//! # }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Where the board polls liveness.
pub const HEALTH_PATH: &str = "/health";

/// Where the board polls business KPIs.
pub const METRICS_PATH: &str = "/api/admin/metrics";

/// The environment variable [`MonitorToken::from_env`] reads.
pub const TOKEN_ENV: &str = "MONITOR_TOKEN";

/// One business number, as the board renders it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kpi {
    /// Stable machine key. The board keys its columns on this, so renaming one
    /// silently drops a column — add a new key and retire the old one instead.
    pub key: &'static str,
    /// Human label.
    pub label: &'static str,
    /// The count itself.
    pub value: i64,
    /// Change over the last 24 hours, for the KPIs that track one. Omitted
    /// from the payload entirely when absent, rather than sent as null — the
    /// board distinguishes "no delta for this KPI" from "delta of zero".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_24h: Option<i64>,
}

impl Kpi {
    /// A KPI with no 24-hour delta.
    pub fn new(key: &'static str, label: &'static str, value: i64) -> Self {
        Self {
            key,
            label,
            value,
            delta_24h: None,
        }
    }

    /// Attach the 24-hour delta.
    #[must_use]
    pub fn with_delta_24h(mut self, delta: i64) -> Self {
        self.delta_24h = Some(delta);
        self
    }
}

/// One named dependency the liveness probe reports on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    /// Key in the `checks` object. `db` is the conventional name for the
    /// application database whichever engine is behind it, so a Mongo→Postgres
    /// move does not break the board's polling contract.
    pub name: &'static str,
    /// Whether the dependency answered.
    pub ok: bool,
}

impl HealthCheck {
    pub fn new(name: &'static str, ok: bool) -> Self {
        Self { name, ok }
    }
}

/// The app's answers for both endpoints.
///
/// Implemented by the host app over its `AppState`, the same way `dx-auth`'s
/// stores are.
#[async_trait::async_trait]
pub trait MonitorSource: Send + Sync + 'static {
    /// Dependencies to probe. The app is healthy when every one is `ok`; an
    /// empty list is therefore healthy.
    async fn health(&self) -> Vec<HealthCheck>;

    /// Business counts.
    ///
    /// Infallible on purpose: both original copies degraded a failing count to
    /// `0` rather than failing the whole response, which keeps the board's
    /// column set stable when one query breaks. Absorb errors here.
    async fn kpis(&self) -> Vec<Kpi>;
}

/// The bearer token the board presents, or nothing when metrics are off.
///
/// stepshots reads it off its `Secrets` struct and infrapage off the
/// environment, so this takes an `Option<String>` and treats an empty string
/// as absent — which covers both without either app changing how it loads
/// config.
#[derive(Clone, Default)]
pub struct MonitorToken(Option<[u8; 32]>);

impl MonitorToken {
    /// Empty or missing means the metrics endpoint stays off.
    pub fn new(token: Option<impl AsRef<str>>) -> Self {
        Self(
            token
                .map(|t| t.as_ref().to_owned())
                .filter(|t| !t.is_empty())
                .map(|t| digest(&t)),
        )
    }

    /// Read [`TOKEN_ENV`] from the environment.
    pub fn from_env() -> Self {
        Self::new(std::env::var(TOKEN_ENV).ok())
    }

    /// Whether a token is configured at all.
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Constant-time check of a presented token.
    ///
    /// Both sides are hashed to 32 bytes before comparison, so the comparison
    /// runs over a fixed width and leaks neither the expected token's length
    /// nor how far a guess matched. (The originals compared the raw bytes and
    /// returned early on a length mismatch, which told an attacker the length.)
    pub fn accepts(&self, presented: &str) -> bool {
        let Some(expected) = self.0.as_ref() else {
            return false;
        };
        digest(presented).ct_eq(expected).into()
    }
}

impl std::fmt::Debug for MonitorToken {
    /// Never prints the token, not even the hash.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MonitorToken")
            .field(&if self.is_enabled() {
                "configured"
            } else {
                "disabled"
            })
            .finish()
    }
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// `GET /health`, for apps mounting it themselves.
pub async fn health_response<M: MonitorSource + ?Sized>(source: &M) -> Response {
    let checks = source.health().await;
    let healthy = checks.iter().all(|c| c.ok);
    let checks: serde_json::Map<String, serde_json::Value> = checks
        .into_iter()
        .map(|c| (c.name.to_owned(), json!(c.ok)))
        .collect();

    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(json!({
            "status": if healthy { "healthy" } else { "unhealthy" },
            "checks": checks,
        })),
    )
        .into_response()
}

/// `GET /api/admin/metrics`, for apps mounting it themselves.
///
/// Answers 404 rather than 401 when no token is configured: an endpoint that
/// is switched off should not advertise that it exists.
pub async fn metrics_response<M: MonitorSource + ?Sized>(
    source: &M,
    token: &MonitorToken,
    headers: &HeaderMap,
) -> Response {
    if !token.is_enabled() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "metrics not enabled" })),
        )
            .into_response();
    }

    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .is_some_and(|t| token.accepts(t));
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    Json(json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "kpis": source.kpis().await,
    }))
    .into_response()
}

/// Both endpoints on their conventional paths, ready to `.merge()` into the
/// app's router.
pub fn router<M: MonitorSource>(source: M, token: MonitorToken) -> Router {
    let source = Arc::new(source);
    let token = Arc::new(token);

    Router::new()
        .route(
            HEALTH_PATH,
            get({
                let source = Arc::clone(&source);
                move || {
                    let source = Arc::clone(&source);
                    async move { health_response(source.as_ref()).await }
                }
            }),
        )
        .route(
            METRICS_PATH,
            get({
                let source = Arc::clone(&source);
                let token = Arc::clone(&token);
                move |headers: HeaderMap| {
                    let source = Arc::clone(&source);
                    let token = Arc::clone(&token);
                    async move { metrics_response(source.as_ref(), token.as_ref(), &headers).await }
                }
            }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        checks: Vec<HealthCheck>,
        kpis: Vec<Kpi>,
    }

    #[async_trait::async_trait]
    impl MonitorSource for Fake {
        async fn health(&self) -> Vec<HealthCheck> {
            self.checks.clone()
        }
        async fn kpis(&self) -> Vec<Kpi> {
            self.kpis.clone()
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn an_empty_token_leaves_metrics_switched_off() {
        assert!(!MonitorToken::new(Some("")).is_enabled());
        assert!(!MonitorToken::new(None::<&str>).is_enabled());
        assert!(MonitorToken::new(Some("s3cret")).is_enabled());
    }

    #[test]
    fn a_disabled_token_accepts_nothing() {
        let token = MonitorToken::new(None::<&str>);
        assert!(!token.accepts(""));
        assert!(!token.accepts("s3cret"));
    }

    #[test]
    fn only_the_exact_token_is_accepted() {
        let token = MonitorToken::new(Some("s3cret"));
        assert!(token.accepts("s3cret"));
        assert!(!token.accepts("s3cre"));
        assert!(!token.accepts("s3cretx"));
        assert!(!token.accepts("S3CRET"));
    }

    #[test]
    fn the_debug_impl_never_prints_the_token() {
        let shown = format!("{:?}", MonitorToken::new(Some("s3cret")));
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("configured"), "{shown}");
    }

    #[tokio::test]
    async fn health_reports_every_check_and_is_healthy_when_all_pass() {
        let source = Fake {
            checks: vec![
                HealthCheck::new("db", true),
                HealthCheck::new("cache", true),
            ],
            kpis: vec![],
        };

        let response = health_response(&source).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!({ "status": "healthy", "checks": { "db": true, "cache": true } })
        );
    }

    #[tokio::test]
    async fn one_failing_check_makes_the_whole_probe_unavailable() {
        let source = Fake {
            checks: vec![
                HealthCheck::new("db", true),
                HealthCheck::new("cache", false),
            ],
            kpis: vec![],
        };

        let response = health_response(&source).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_json(response).await,
            json!({ "status": "unhealthy", "checks": { "db": true, "cache": false } })
        );
    }

    #[tokio::test]
    async fn an_app_with_nothing_to_probe_is_healthy() {
        let source = Fake {
            checks: vec![],
            kpis: vec![],
        };

        let response = health_response(&source).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!({ "status": "healthy", "checks": {} })
        );
    }

    #[tokio::test]
    async fn metrics_hide_behind_a_404_when_no_token_is_configured() {
        let source = Fake {
            checks: vec![],
            kpis: vec![],
        };

        let response = metrics_response(
            &source,
            &MonitorToken::new(None::<&str>),
            &bearer("anything"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_refuse_a_wrong_or_missing_bearer() {
        let source = Fake {
            checks: vec![],
            kpis: vec![],
        };
        let token = MonitorToken::new(Some("s3cret"));

        for headers in [HeaderMap::new(), bearer("wrong")] {
            let response = metrics_response(&source, &token, &headers).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // A bare token without the scheme is not a bearer credential.
        let mut bare = HeaderMap::new();
        bare.insert(header::AUTHORIZATION, "s3cret".parse().unwrap());
        let response = metrics_response(&source, &token, &bare).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_router_mounts_both_endpoints_on_their_conventional_paths() {
        use tower::ServiceExt;

        let app = router(
            Fake {
                checks: vec![HealthCheck::new("db", true)],
                kpis: vec![Kpi::new("users", "Users", 1)],
            },
            MonitorToken::new(Some("s3cret")),
        );

        let health = app
            .clone()
            .oneshot(
                axum::http::Request::get(HEALTH_PATH)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let mut request = axum::http::Request::get(METRICS_PATH);
        request
            .headers_mut()
            .unwrap()
            .insert(header::AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        let metrics = app
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        assert_eq!(body_json(metrics).await["kpis"][0]["key"], "users");
    }

    #[tokio::test]
    async fn metrics_serve_the_kpis_and_omit_an_absent_delta() {
        let source = Fake {
            checks: vec![],
            kpis: vec![
                Kpi::new("users", "Users", 42).with_delta_24h(3),
                Kpi::new("active_subs", "Active subs", 7),
            ],
        };

        let response = metrics_response(
            &source,
            &MonitorToken::new(Some("s3cret")),
            &bearer("s3cret"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_json(response).await;
        assert!(body["generated_at"].is_string());
        assert_eq!(
            body["kpis"],
            json!([
                { "key": "users", "label": "Users", "value": 42, "delta_24h": 3 },
                { "key": "active_subs", "label": "Active subs", "value": 7 },
            ])
        );
    }
}
