//! A localhost Streamable HTTP mock. The tests open their session directly:
//! the public functions go through the address guard and cannot reach
//! loopback, which the first test pins down.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use serde_json::json;

use super::*;

/// Serves `initialize`, `tools/list` and `tools/call`; counts the calls.
async fn mock(answer: Value) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let router = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, Json(request): Json<Value>| {
            let (calls, answer) = (seen.clone(), answer.clone());
            async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer test-token");
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => json!({
                        "protocolVersion": request["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "1"}
                    }),
                    "tools/list" => json!({"tools": [
                        {"name": "send_note", "description": "Send a note",
                         "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
                        {"name": "list_notes", "inputSchema": {"type": "object"},
                         "annotations": {"readOnlyHint": true}}
                    ]}),
                    "tools/call" => {
                        calls.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(request["params"]["name"], "send_note");
                        assert_eq!(request["params"]["arguments"]["text"], "Hello");
                        answer
                    }
                    _ => return StatusCode::ACCEPTED.into_response(),
                };
                Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                    .into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, calls)
}

fn token() -> SecretString {
    SecretString::from("test-token")
}

async fn session(url: &str) -> Session {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    open(http, url, &Auth::Bearer(token())).await.unwrap()
}

fn hello() -> Map<String, Value> {
    json!({"text": "Hello"}).as_object().unwrap().clone()
}

#[tokio::test]
async fn only_public_https_endpoints_are_reached() {
    assert!(matches!(
        Endpoint::new("http://example.org/mcp", None),
        Err(Error::Url(_))
    ));
    assert!(matches!(
        Endpoint::new("https://user:pw@example.org/mcp", None),
        Err(Error::Url(_))
    ));
    // A well-formed URL that points inside: refused before any request.
    for inside in [
        "https://127.0.0.1/mcp",
        "https://10.0.0.5/mcp",
        "https://[::1]/mcp",
    ] {
        let endpoint = Endpoint::new(inside, None).unwrap();
        assert!(matches!(tools(&endpoint).await, Err(Error::Address(_))));
        assert!(matches!(
            call(&endpoint, "send_note", Map::new()).await,
            Err(Error::Address(_))
        ));
    }
}

#[tokio::test]
async fn tools_are_listed_sorted_with_the_servers_read_only_mark() {
    let (url, _) = mock(json!({})).await;
    let session = session(&url).await;
    let tools = list(&session).await.unwrap();
    close(session).await;

    assert_eq!(
        tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["list_notes", "send_note"]
    );
    assert_eq!(tools[0].read_only, Some(true));
    assert_eq!(tools[1].read_only, None);
    assert_eq!(tools[1].description, "Send a note");
    assert_eq!(tools[1].schema["properties"]["text"]["type"], "string");
}

#[tokio::test]
async fn a_tool_is_called_once_with_its_arguments_and_the_token_is_redacted() {
    let answer = json!({"content": [{"type": "text", "text": "Sent with test-token"}]});
    let (url, calls) = mock(answer).await;
    let session = session(&url).await;
    let outcome = dispatch(&session, Some(&token()), "send_note", hello()).await;
    close(session).await;

    let Outcome::Succeeded(text) = outcome else {
        panic!("expected success, got {outcome:?}")
    };
    assert!(text.contains("Sent with [redacted]"));
    assert!(!text.contains("test-token"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_tools_own_error_is_a_failure_not_a_success() {
    let answer = json!({"content": [{"type": "text", "text": "No such list"}], "isError": true});
    let (url, calls) = mock(answer).await;
    let session = session(&url).await;
    let outcome = dispatch(&session, Some(&token()), "send_note", hello()).await;
    close(session).await;

    assert!(matches!(outcome, Outcome::Failed(text) if text.contains("No such list")));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_answer_that_is_not_a_result_is_unknown_and_not_retried() {
    // Not a tool result at all: the request went out, the outcome is unknown.
    let (url, calls) = mock(json!("nonsense")).await;
    let session = session(&url).await;
    let outcome = dispatch(&session, Some(&token()), "send_note", hello()).await;
    close(session).await;

    assert_eq!(outcome, Outcome::Unknown);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_long_result_is_cut_on_a_character_boundary() {
    let long = "ä".repeat(MAX_RESULT);
    let cut = shown(long);
    assert!(cut.len() <= MAX_RESULT + "\n…result truncated".len());
    assert!(cut.ends_with("…result truncated"));
}

#[tokio::test]
async fn a_key_can_go_in_a_header_of_its_own_but_not_in_a_reserved_one() {
    let url = "https://mcp.example.org/mcp";
    assert!(Endpoint::with_header(url, "X-API-Key", token()).is_ok());
    for (name, value) in [
        ("Authorization", "test-token"),
        ("Host", "internal"),
        ("X Bad Name", "test-token"),
        ("X-API-Key", "line\nbreak"),
    ] {
        let refused = Endpoint::with_header(url, name, SecretString::from(value));
        assert!(matches!(refused, Err(Error::Header)), "{name}");
    }

    // The header reaches the server, and no bearer token does.
    let router = Router::new().route(
        "/mcp",
        post(
            |headers: HeaderMap, Json(request): Json<Value>| async move {
                assert_eq!(headers.get("x-api-key").unwrap(), "test-token");
                assert!(headers.get("authorization").is_none());
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => json!({
                        "protocolVersion": request["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock", "version": "1"}
                    }),
                    "tools/list" => json!({"tools": []}),
                    _ => return StatusCode::ACCEPTED.into_response(),
                };
                Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                    .into_response()
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let auth = Auth::Header(HeaderName::from_static("x-api-key"), token());
    let session = open(http, &local, &auth).await.unwrap();
    assert!(list(&session).await.unwrap().is_empty());
    close(session).await;
}

#[test]
fn a_secret_with_quotes_is_redacted_wherever_a_server_echoes_it() {
    // Written as JSON, this key is escaped and a text search would miss it.
    let key = SecretString::from(r#"k"e\y"#);
    let mut result = json!({
        "content": [{"type": "text", "text": r#"Your key is k"e\y."#}],
        r#"k"e\y"#: {"nested": [r#"again k"e\y"#]}
    });
    redact(&mut result, Some(&key));
    let text = serde_json::to_string(&result).unwrap();
    assert!(!text.contains(r#"k\"e"#), "{text}");
    assert_eq!(text.matches("[redacted]").count(), 3);

    let mut tool = Tool {
        name: "echo".into(),
        description: r#"Uses k"e\y"#.into(),
        schema: json!({"default": r#"k"e\y"#}),
        read_only: None,
    };
    scrub(&mut tool, Some(&key));
    assert_eq!(tool.description, "Uses [redacted]");
    assert_eq!(tool.schema["default"], "[redacted]");
}
