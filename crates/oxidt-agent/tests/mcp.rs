use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode},
};
use oxidt_agent::{Agent, AuthError, Capability, Effect, HttpConfig, Principal, RegistrationError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Lookup {
    query: String,
}

#[derive(Serialize, JsonSchema)]
struct ResultData {
    tenant: String,
    query: String,
}

fn app() -> (Router, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut agent = Agent::new();
    let count = calls.clone();
    agent
        .register(
            Capability::new(
                "search",
                "Search your tenant's notes",
                "notes:read",
                Effect::Read,
            ),
            move |principal, input: Lookup| {
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    Ok(ResultData {
                        tenant: principal.tenant_id,
                        query: input.query,
                    })
                }
            },
        )
        .unwrap();
    let count = calls.clone();
    agent
        .register(
            Capability::new(
                "send",
                "Send a note externally",
                "notes:send",
                Effect::External,
            ),
            move |principal, input: Lookup| {
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    Ok(ResultData {
                        tenant: principal.tenant_id,
                        query: input.query,
                    })
                }
            },
        )
        .unwrap();
    let router = oxidt_agent::router(
        Arc::new(agent),
        HttpConfig {
            allowed_hosts: vec!["localhost".into()],
            allowed_origins: vec!["http://localhost:*".into()],
            www_authenticate: HeaderValue::from_static(
                "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource\"",
            ),
        },
        |headers| async move {
            let token = headers.get("authorization").and_then(|h| h.to_str().ok());
            let (tenant, permissions) = match token {
                Some("Bearer alice") => ("tenant-a", vec!["notes:read", "notes:send"]),
                Some("Bearer bob") => ("tenant-b", vec!["notes:read"]),
                Some("Bearer restricted") => ("tenant-a", vec![]),
                Some("Bearer offline") => return Err(AuthError::Unavailable),
                _ => return Err(AuthError::Unauthorized),
            };
            Ok(Principal {
                user_id: token.unwrap().into(),
                tenant_id: tenant.into(),
                client_id: "test-client".into(),
                grant_id: "test-grant".into(),
                permissions: permissions.into_iter().map(String::from).collect(),
            })
        },
    );
    (router, calls)
}

async fn request(
    app: &Router,
    token: Option<&str>,
    host: &str,
    method: &str,
    params: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    request_from(app, token, host, None, method, params).await
}

async fn request_from(
    app: &Router,
    token: Option<&str>,
    host: &str,
    origin: Option<&str>,
    method: &str,
    params: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let version = params["_meta"]["io.modelcontextprotocol/protocolVersion"]
        .as_str()
        .unwrap_or("2025-11-25");
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-method", method)
        .header("mcp-protocol-version", version);
    if let Some(name) = params["name"].as_str() {
        builder = builder.header("mcp-name", name);
    }
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"body": String::from_utf8_lossy(&bytes)}));
    (parts.status, parts.headers, value)
}

#[tokio::test]
async fn authenticates_discovery_and_invocation_on_every_request() {
    let (app, calls) = app();
    for token in [None, Some("invalid")] {
        let (status, headers, _) = request(&app, token, "localhost", "tools/list", json!({})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            headers["www-authenticate"]
                .to_str()
                .unwrap()
                .contains("resource_metadata")
        );
    }
    let (status, _, _) = request(
        &app,
        Some("alice"),
        "attacker.test",
        "tools/list",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = request(&app, Some("offline"), "localhost", "tools/list", json!({})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_foreign_browser_origins_but_not_clients_without_origin() {
    let (app, _) = app();
    for (origin, expected) in [
        (Some("https://attacker.test"), StatusCode::FORBIDDEN),
        (Some("null"), StatusCode::FORBIDDEN),
        (Some("http://localhost:3000"), StatusCode::OK),
        (None, StatusCode::OK),
    ] {
        let (status, _, body) = request_from(
            &app,
            Some("alice"),
            "localhost",
            origin,
            "tools/list",
            json!({}),
        )
        .await;
        assert_eq!(status, expected, "{origin:?}: {body}");
    }
}

#[tokio::test]
async fn discovers_only_permitted_tools_and_returns_structured_tenant_results() {
    let (app, calls) = app();
    let (status, _, body) = request(&app, Some("bob"), "localhost", "tools/list", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tools = body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "search");
    assert_eq!(
        tools[0]["inputSchema"]["properties"]["query"]["type"],
        "string"
    );
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
    assert!(tools[0]["outputSchema"].is_object());

    for (token, tenant) in [("alice", "tenant-a"), ("bob", "tenant-b")] {
        let (status, _, body) = request(
            &app,
            Some(token),
            "localhost",
            "tools/call",
            json!({
                "name": "search", "arguments": {"query": "hello"},
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["structuredContent"],
            json!({"tenant": tenant, "query": "hello"})
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn refuses_ungranted_calls_forged_tenants_bad_input_and_approval_bypass() {
    let (app, calls) = app();
    for (token, name, arguments, code) in [
        ("restricted", "search", json!({"query": "x"}), "unavailable"),
        ("alice", "missing", json!({}), "unavailable"),
        ("alice", "search", json!({"query": 42}), "invalid_input"),
        (
            "alice",
            "search",
            json!({"query": "x", "tenant_id": "tenant-b"}),
            "invalid_input",
        ),
        (
            "alice",
            "send",
            json!({"query": "x", "approved": true}),
            "approval_required",
        ),
        ("bob", "send", json!({"query": "x"}), "unavailable"),
    ] {
        let (status, _, body) = request(
            &app,
            Some(token),
            "localhost",
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["isError"], true, "{body}");
        assert_eq!(body["result"]["structuredContent"]["code"], code, "{body}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "Rejected requests must never enter application handlers"
    );
}

#[tokio::test]
async fn legacy_initialize_negotiates_the_requested_version() {
    let (app, _) = app();
    let (status, _, body) = request(&app, Some("alice"), "localhost", "initialize", json!({
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"},
    })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["protocolVersion"], "2025-11-25");
}

#[test]
fn duplicate_registration_never_replaces_the_original_handler() {
    let mut agent = Agent::new();
    let capability = Capability::new("search", "Search", "read", Effect::Read);
    agent
        .register(capability.clone(), |p, i: Lookup| async move {
            Ok(ResultData {
                tenant: p.tenant_id,
                query: i.query,
            })
        })
        .unwrap();
    let error = agent
        .register(capability, |p, i: Lookup| async move {
            Ok(ResultData {
                tenant: p.tenant_id,
                query: i.query,
            })
        })
        .unwrap_err();
    assert!(matches!(error, RegistrationError::Duplicate(_)));
}

#[tokio::test]
async fn modern_stateless_calls_use_authenticated_identity_not_client_metadata() {
    let (app, calls) = app();
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "claimed-admin", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let (status, _, body) = request(
        &app,
        Some("bob"),
        "localhost",
        "server/discover",
        json!({"_meta": meta}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let (status, _, body) = request(
        &app,
        Some("bob"),
        "localhost",
        "tools/call",
        json!({
            "name": "search", "arguments": {"query": "modern"}, "_meta": meta,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["result"]["structuredContent"]["tenant"], "tenant-b",
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversized_calls_do_not_reach_the_handler() {
    let (app, calls) = app();
    let (status, _, _) = request(
        &app,
        Some("alice"),
        "localhost",
        "tools/call",
        json!({
            "name": "search", "arguments": {"query": "x".repeat(65 * 1024)},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "topcoat")]
#[tokio::test]
async fn same_endpoint_works_when_mounted_inside_topcoat() {
    let (mcp, _) = app();
    let router = topcoat::router::Router::builder()
        .route(oxidt_agent::topcoat_route(mcp))
        .build();
    let app = Router::new().fallback_service(topcoat::router::tower::TowerService::new(router));
    let (status, _, body) = request(
        &app,
        Some("bob"),
        "localhost",
        "tools/call",
        json!({
            "name": "search", "arguments": {"query": "via Topcoat"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["structuredContent"]["tenant"], "tenant-b");
}
