//! Outbound MCP for a hosted app: reach a remote MCP endpoint a user typed
//! in, list its tools, and call one.
//!
//! Extracted from **smiet**, where each user connects their own services and
//! a reviewed note becomes one tool call.
//!
//! - [`Endpoint::new`] accepts a public `https://` URL and nothing else.
//! - [`tools`] connects, lists every tool, and disconnects.
//! - [`call`] connects, calls one tool **once**, and disconnects. It reports
//!   an [`Outcome`], including [`Outcome::Unknown`] when the request went out
//!   and no final answer came back.
//! - [`gate`] is the allow / ask / block rule for a connection's tools, with
//!   the hold on a tool whose definition changed.
//!
//! - `oauth` (feature `oauth`) signs in to a server that wants OAuth and
//!   keeps the resulting token fresh.
//!
//! No storage and no sessions: the app keeps the URL, the token and any
//! OAuth grant encrypted, and passes them in.
//!
//! # Safety properties
//!
//! - The URL is user input. It is checked ([`oxidt_egress::check_url`]),
//!   every resolved address is checked, and the connection is pinned to
//!   those addresses: no private network, no proxy, no redirects.
//! - A write is never replayed. The HTTP client does not retry, an expired
//!   session is not re-initialised, and [`call`] makes one attempt. After
//!   [`Outcome::Unknown`] the caller must not call again by itself: the tool
//!   may have run.
//! - The client offers the server nothing to call back into: no sampling,
//!   roots or elicitation.
//! - A result is text for display. It is written by the remote service, so
//!   treat it as data, never as instructions or markup. The token is
//!   redacted from it and it is cut at [`MAX_RESULT`] bytes.

pub mod gate;
#[cfg(feature = "oauth")]
pub mod oauth;

use std::time::Duration;

use oxidt_egress::{Timeouts, UrlPolicy};
use rmcp::{
    model::{CallToolRequestParams, CallToolResponse, PaginatedRequestParams},
    service::{RoleClient, RunningService, ServiceExt},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

pub use gate::{ToolGate, ToolPolicy, tool_gate};
/// The egress crate this one is built on, so an app names one crate and tag.
pub use oxidt_egress;

/// Longest wait for the address lookup, and again for the handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for a tool's answer.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(45);
/// Longest wait for the whole tool list.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(20);
/// A result longer than this many bytes is cut.
pub const MAX_RESULT: usize = 32_000;
/// A server offering more tools than this is refused.
pub const MAX_TOOLS: usize = 500;

/// Why no tool call was sent, or why the tool list could not be read. Every
/// variant means the remote tool did **not** run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an allowed server URL: {0}")]
    Url(oxidt_egress::Error),
    #[error("the server address could not be used: {0}")]
    Address(oxidt_egress::Error),
    #[error("the server address lookup timed out")]
    LookupTimeout,
    #[error("could not connect; check the server URL and access token")]
    Connect,
    #[error("the connection timed out")]
    ConnectTimeout,
    #[error("could not load the server's tools")]
    Tools,
    #[error("the server offers too many tools")]
    TooManyTools,
}

/// A remote MCP endpoint and how to authenticate to it.
#[derive(Clone)]
pub struct Endpoint {
    url: Url,
    token: Option<SecretString>,
}

impl Endpoint {
    /// `url` must be public https without credentials, query or fragment.
    /// `token` is sent as `Authorization: Bearer …`.
    pub fn new(url: &str, token: Option<SecretString>) -> Result<Self, Error> {
        let url = oxidt_egress::check_url(url, &UrlPolicy::default()).map_err(Error::Url)?;
        Ok(Self { url, token })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

/// One tool as the server offers it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    /// Its input schema. Compare it with the one the user accepted to hold a
    /// tool that changed (see [`gate`]).
    pub schema: Value,
    /// The server's own claim that the tool changes nothing.
    #[serde(default)]
    pub read_only: Option<bool>,
}

/// How a call ended. The text is the tool's result as pretty JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Succeeded(String),
    /// The tool answered with an error of its own.
    Failed(String),
    /// The request went out and no final answer came back: the tool may have
    /// run. Never call again automatically; the user checks the service.
    Unknown,
}

type Session = RunningService<RoleClient, ()>;

/// Every tool the endpoint offers, sorted by name.
pub async fn tools(endpoint: &Endpoint) -> Result<Vec<Tool>, Error> {
    let session = connect(endpoint).await?;
    let listed = tokio::time::timeout(LIST_TIMEOUT, list(&session)).await;
    close(session).await;
    listed.map_err(|_| Error::Tools)?
}

/// Call `name` once. `Err` means the tool call was not sent (the handshake
/// may have been).
pub async fn call(
    endpoint: &Endpoint,
    name: &str,
    arguments: Map<String, Value>,
) -> Result<Outcome, Error> {
    let session = connect(endpoint).await?;
    let outcome = dispatch(&session, endpoint.token.as_ref(), name, arguments).await;
    close(session).await;
    Ok(outcome)
}

async fn connect(endpoint: &Endpoint) -> Result<Session, Error> {
    let pinned = tokio::time::timeout(
        CONNECT_TIMEOUT,
        oxidt_egress::guard_host_async(&endpoint.url),
    )
    .await
    .map_err(|_| Error::LookupTimeout)?
    .map_err(Error::Address)?;
    let timeouts = Timeouts {
        connect: CONNECT_TIMEOUT,
        total: CALL_TIMEOUT + Duration::from_secs(10),
    };
    let http = oxidt_egress::pinned_client(&pinned, timeouts).map_err(Error::Address)?;
    open(http, endpoint.url.as_str(), endpoint.token.as_ref()).await
}

/// The handshake over an HTTP client the caller vouches for.
async fn open(
    http: reqwest::Client,
    uri: &str,
    token: Option<&SecretString>,
) -> Result<Session, Error> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(uri.to_owned())
        .max_sse_event_size(256 * 1024)
        .reinit_on_expired_session(false);
    if let Some(token) = token {
        config = config.auth_header(token.expose_secret().to_owned());
    }
    let transport = StreamableHttpClientTransport::with_client(http, config);
    tokio::time::timeout(CONNECT_TIMEOUT, ().serve(transport))
        .await
        .map_err(|_| Error::ConnectTimeout)?
        .map_err(|_| Error::Connect)
}

async fn close(session: Session) {
    let _ = tokio::time::timeout(Duration::from_secs(2), session.cancel()).await;
}

async fn list(session: &Session) -> Result<Vec<Tool>, Error> {
    let mut tools = Vec::new();
    let mut cursor = None;
    // Ten pages at most: a server that never ends its list is refused.
    for _ in 0..10 {
        let mut params = PaginatedRequestParams::default();
        params.cursor = cursor;
        let page = session
            .list_tools(Some(params))
            .await
            .map_err(|_| Error::Tools)?;
        tools.extend(page.tools.into_iter().map(|tool| Tool {
            name: tool.name.to_string(),
            description: tool.description.map(|d| d.to_string()).unwrap_or_default(),
            schema: Value::Object((*tool.input_schema).clone()),
            read_only: tool.annotations.and_then(|a| a.read_only_hint),
        }));
        if tools.len() > MAX_TOOLS {
            return Err(Error::TooManyTools);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            tools.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(tools);
        }
    }
    Err(Error::TooManyTools)
}

async fn dispatch(
    session: &Session,
    token: Option<&SecretString>,
    name: &str,
    arguments: Map<String, Value>,
) -> Outcome {
    let params = CallToolRequestParams::new(name.to_owned()).with_arguments(arguments);
    let reply = tokio::time::timeout(CALL_TIMEOUT, session.call_tool_once(params)).await;
    let Ok(Ok(CallToolResponse::Complete(result))) = reply else {
        // A timeout, a dropped connection, or a server that wants further
        // interaction: in each the tool may have run.
        return Outcome::Unknown;
    };
    let failed = result.is_error == Some(true);
    let text = serde_json::to_string_pretty(&result).unwrap_or_default();
    let text = shown(text, token);
    if failed {
        Outcome::Failed(text)
    } else {
        Outcome::Succeeded(text)
    }
}

/// A result as it may be shown: without the token, and not too long.
fn shown(mut text: String, token: Option<&SecretString>) -> String {
    if let Some(token) = token.map(|t| t.expose_secret()).filter(|t| !t.is_empty()) {
        text = text.replace(token, "[redacted]");
    }
    if text.len() > MAX_RESULT {
        text.truncate(text.floor_char_boundary(MAX_RESULT));
        text.push_str("\n…result truncated");
    }
    text
}

#[cfg(test)]
mod tests;
