use std::{future::Future, sync::Arc};

use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager,
    tower::{StreamableHttpServerConfig, StreamableHttpService},
};

use crate::{Agent, McpServer, Principal};

/// The host owns OAuth discovery and credential validation. Use `oxidt-mcp-oauth`
/// when implementing discovery. This crate does not issue tokens or trust cookies.
pub struct HttpConfig {
    pub allowed_hosts: Vec<String>,
    /// Browser origins allowed to call MCP, e.g. `https://app.example.com:443`.
    /// Requests without an `Origin` header (non-browser clients) always pass;
    /// empty rejects every request that carries one.
    pub allowed_origins: Vec<String>,
    pub www_authenticate: HeaderValue,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthError {
    Unauthorized,
    Unavailable,
}

/// Mount `/mcp`. Authentication runs on EVERY request, including discovery and calls.
/// The callback must validate credentials and resolve current tenant membership/scopes.
pub fn router<F, Fut>(agent: Arc<Agent>, config: HttpConfig, authenticate: F) -> Router
where
    F: Fn(HeaderMap) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<Principal, AuthError>> + Send + 'static,
{
    assert!(
        !config.allowed_hosts.is_empty(),
        "MCP needs an explicit host allowlist"
    );
    let service = StreamableHttpService::new(
        move || Ok(McpServer(agent.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(config.allowed_hosts)
            .with_allowed_origins(config.allowed_origins)
            .enforce_origin_validation()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_max_request_body_bytes(64 * 1024),
    );
    Router::new()
        .route_service("/mcp", service)
        .layer(middleware::from_fn(
            move |mut request: Request, next: Next| {
                let authenticate = authenticate.clone();
                let challenge = config.www_authenticate.clone();
                async move {
                    match authenticate(request.headers().clone()).await {
                        Ok(principal)
                            if !principal.user_id.is_empty()
                                && !principal.tenant_id.is_empty()
                                && !principal.client_id.is_empty()
                                && !principal.grant_id.is_empty() =>
                        {
                            request.extensions_mut().insert(principal);
                            next.run(request).await
                        }
                        Ok(_) | Err(AuthError::Unauthorized) => (
                            StatusCode::UNAUTHORIZED,
                            [(header::WWW_AUTHENTICATE, challenge)],
                        )
                            .into_response(),
                        Err(AuthError::Unavailable) => {
                            StatusCode::SERVICE_UNAVAILABLE.into_response()
                        }
                    }
                }
            },
        ))
}

/// Mount the already authenticated MCP router directly into a Topcoat router.
#[cfg(feature = "topcoat")]
pub fn topcoat_route(router: Router) -> topcoat::router::tower::TowerRoute<Router> {
    topcoat::router::tower::TowerRoute::any("/mcp", router)
}
