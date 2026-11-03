//! Local-only example. Set AGENT_DEMO_TOKEN; no database or external services needed.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::http::{HeaderValue, header};
use oxidt_agent::{
    Agent, Approval, AuthError, Capability, Effect, HttpConfig, Principal, ToolError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use topcoat::{
    router::page,
    view::{View, view},
};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddNote {
    /// A short note to save in the authenticated tenant's notebook.
    text: String,
}

#[derive(Serialize, JsonSchema)]
struct Notes {
    notes: Vec<String>,
}

type Store = Arc<Mutex<BTreeMap<String, Vec<String>>>>;

// A normal application service: the same function can be called from a UI action.
fn add_note(store: &Store, principal: &Principal, input: AddNote) -> Result<Notes, ToolError> {
    if input.text.trim().is_empty() || input.text.len() > 1000 {
        return Err(ToolError::new(
            "invalid_note",
            "Note must contain 1–1000 bytes of non-blank text",
        ));
    }
    let mut store = store.lock().unwrap();
    let notes = store.entry(principal.tenant_id.clone()).or_default();
    if notes.len() >= 100 {
        return Err(ToolError::new(
            "notebook_full",
            "This demo accepts up to 100 notes",
        ));
    }
    notes.push(input.text);
    Ok(Notes {
        notes: notes.clone(),
    })
}

#[page("/")]
async fn home() -> topcoat::Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head><title>"Oxidt Agent prototype"</title></head>
            <body>
                <h1>"A Topcoat app with embedded agent access"</h1>
                <p>
                    "Connect your MCP client to http://127.0.0.1:8097/mcp with the bearer token you set in AGENT_DEMO_TOKEN."
                </p>
                <p>
                    "Tools: list_notes, add_note. Notes belong to the authenticated demo tenant and reset on restart."
                </p>
            </body>
        </html>
    })
}

/// Compares SHA-256 digests, so response timing reveals nothing about the expected credential.
fn same_credential(given: Option<&HeaderValue>, expected: &HeaderValue) -> bool {
    given.is_some_and(|given| {
        Sha256::digest(given.as_bytes()) == Sha256::digest(expected.as_bytes())
    })
}

fn app(credential: HeaderValue) -> Result<axum::Router, oxidt_agent::RegistrationError> {
    let store: Store = Arc::default();
    let mut agent = Agent::new();
    let read_store = store.clone();
    agent.register(
        Capability::new(
            "list_notes",
            "List notes in your notebook",
            "notes:read",
            Effect::Read,
        ),
        move |principal, _: Empty| {
            let store = read_store.clone();
            async move {
                Ok(Notes {
                    notes: store
                        .lock()
                        .unwrap()
                        .get(&principal.tenant_id)
                        .cloned()
                        .unwrap_or_default(),
                })
            }
        },
    )?;
    agent.register(
        Capability::new(
            "add_note",
            "Add a note to your notebook",
            "notes:write",
            Effect::Write,
        )
        .with_approval(Approval::NotRequired),
        move |principal, input: AddNote| {
            let store = store.clone();
            async move { add_note(&store, &principal, input) }
        },
    )?;
    let mcp = oxidt_agent::router(
        Arc::new(agent),
        HttpConfig {
            allowed_hosts: vec!["127.0.0.1".into(), "localhost".into()],
            // MCP clients are not browsers: reject any request carrying an Origin.
            allowed_origins: Vec::new(),
            www_authenticate: HeaderValue::from_static("Bearer realm=\"oxidt-agent-demo\""),
        },
        move |headers| {
            let valid = same_credential(headers.get(header::AUTHORIZATION), &credential);
            async move {
                if !valid {
                    return Err(AuthError::Unauthorized);
                }
                // Demo identity only. Production apps resolve their own validated credential.
                Ok(Principal {
                    user_id: "demo-user".into(),
                    tenant_id: "demo-tenant".into(),
                    client_id: "demo-client".into(),
                    grant_id: "demo-grant".into(),
                    permissions: ["notes:read".into(), "notes:write".into()].into(),
                })
            }
        },
    );
    let topcoat = topcoat::router::Router::builder()
        .page(home)
        .route(oxidt_agent::topcoat_route(mcp))
        .build();
    Ok(axum::Router::new().fallback_service(topcoat::router::tower::TowerService::new(topcoat)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("AGENT_DEMO_TOKEN")?;
    if token.len() < 32 {
        return Err("AGENT_DEMO_TOKEN must have at least 32 characters".into());
    }
    let app = app(HeaderValue::from_str(&format!("Bearer {token}"))?)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8097").await?;
    eprintln!("Topcoat: http://127.0.0.1:8097 — MCP: /mcp");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    #[tokio::test]
    async fn demo_page_and_notebook_work_through_the_real_router() {
        let app = app(HeaderValue::from_static("Bearer example-test-credential")).unwrap();
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = to_bytes(response.into_body(), 65536).await.unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains("embedded agent access"));
        assert!(!html.contains("example-test-credential"));
        for (name, arguments, expected) in [
            ("list_notes", json!({}), json!([])),
            (
                "add_note",
                json!({"text": "Prototype verified"}),
                json!(["Prototype verified"]),
            ),
            ("list_notes", json!({}), json!(["Prototype verified"])),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("host", "localhost")
                .header("authorization", "Bearer example-test-credential")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", "2025-11-25")
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                        "name": name, "arguments": arguments,
                    }})
                    .to_string(),
                ))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 65536).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body["result"]["structuredContent"]["notes"], expected,
                "{body}"
            );
        }
    }
}
