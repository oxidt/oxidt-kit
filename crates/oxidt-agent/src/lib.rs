//! Embedded MCP access. The host authenticates; capabilities enforce agent permissions;
//! application services still enforce resource ownership and business rules.

#[cfg(feature = "durable")]
pub mod durable;
mod http;

#[cfg(feature = "topcoat")]
pub use http::topcoat_route;
pub use http::{AuthError, HttpConfig, router};
pub use oxidt_agent_core::{AccessError, Approval, Capability, Effect, Principal};

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
    },
    service::RequestContext,
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tracing::Instrument;

type Invocation = Pin<Box<dyn Future<Output = Result<Value, ToolError>> + Send>>;
type Handler = dyn Fn(Principal, Value) -> Invocation + Send + Sync;

struct Entry {
    capability: Capability,
    tool: Tool,
    handler: Box<Handler>,
}

/// A startup-built registry. Freeze it in an `Arc` when mounting the router.
#[derive(Default)]
pub struct Agent {
    entries: BTreeMap<String, Entry>,
}

impl Agent {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a typed application function. Input must have an object JSON schema.
    /// Input shape is checked by Serde; business constraints belong in the handler.
    pub fn register<I, O, F, Fut>(
        &mut self,
        capability: Capability,
        handler: F,
    ) -> Result<(), RegistrationError>
    where
        I: DeserializeOwned + JsonSchema + Send + 'static,
        O: Serialize + JsonSchema + Send + 'static,
        F: Fn(Principal, I) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ToolError>> + Send + 'static,
    {
        if self.entries.contains_key(&capability.name) {
            return Err(RegistrationError::Duplicate(capability.name));
        }
        if capability.name.is_empty()
            || capability.version.trim().is_empty()
            || capability.name.len() > 64
            || !capability
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || capability.description.trim().is_empty()
            || capability.permission.trim().is_empty()
        {
            return Err(RegistrationError::InvalidCapability);
        }
        let schema = rmcp::handler::server::tool::schema_for_input::<I>()
            .map_err(|_| RegistrationError::InvalidInputSchema)?;
        let tool = Tool::new(
            capability.name.clone(),
            capability.description.clone(),
            schema,
        )
        .with_output_schema::<O>()
        .with_annotations(
            ToolAnnotations::new()
                .read_only(capability.effect == Effect::Read)
                .open_world(capability.effect == Effect::External),
        );
        let handler = Arc::new(handler);
        self.entries.insert(
            capability.name.clone(),
            Entry {
                capability,
                tool,
                handler: Box::new(move |principal, arguments| {
                    let handler = handler.clone();
                    Box::pin(async move {
                        let input = serde_json::from_value(arguments).map_err(|_| {
                            ToolError::new(
                                "invalid_input",
                                "Arguments do not match the tool input type",
                            )
                        })?;
                        let output = handler(principal, input).await?;
                        serde_json::to_value(output).map_err(|_| {
                            ToolError::new("invalid_output", "The tool could not encode its result")
                        })
                    })
                }),
            },
        );
        Ok(())
    }

    pub fn tools(&self, principal: &Principal) -> Vec<Tool> {
        self.entries
            .values()
            .filter(|entry| entry.capability.visible_to(principal))
            .map(|entry| entry.tool.clone())
            .collect()
    }

    /// Also usable by an in-app agent. The caller must supply authenticated identity.
    pub async fn invoke(
        &self,
        principal: Principal,
        name: &str,
        arguments: Value,
    ) -> Result<Value, ToolError> {
        // OpenTelemetry GenAI conventions, exported by the host's tracing-opentelemetry layer.
        // Never record arguments, credentials or returned application data.
        let span = tracing::info_span!(
            "agent.tool",
            otel.name = %format_args!("execute_tool {name}"),
            gen_ai.operation.name = "execute_tool",
            gen_ai.tool.name = name,
            agent.effect = tracing::field::Empty,
            tenant_id = %principal.tenant_id,
            client_id = %principal.client_id,
            agent.request_id = tracing::field::Empty,
            error.type = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
        );
        let result = self
            .invoke_entry(principal.clone(), name, arguments)
            .instrument(span.clone())
            .await;
        if let Err(error) = &result {
            span.record("error.type", error.code);
            span.record("otel.status_code", "ERROR");
        }
        span.in_scope(|| {
            tracing::info!(tool = name, tenant_id = %principal.tenant_id, client_id = %principal.client_id,
                success = result.is_ok(), "Agent invocation completed");
        });
        result
    }

    async fn invoke_entry(
        &self,
        principal: Principal,
        name: &str,
        arguments: Value,
    ) -> Result<Value, ToolError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| ToolError::new("unavailable", "Tool is unavailable"))?;
        tracing::Span::current().record(
            "agent.effect",
            tracing::field::debug(entry.capability.effect),
        );
        entry
            .capability
            .authorize(&principal)
            .map_err(|error| match error {
                AccessError::Forbidden => ToolError::new("unavailable", "Tool is unavailable"),
                AccessError::ApprovalRequired => {
                    ToolError::new("approval_required", error.to_string())
                }
            })?;
        (entry.handler)(principal, arguments).await
    }
}

/// Messages are returned to the agent. Supply safe categories, never raw database/provider errors.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
    /// Durable actions retry only retryable errors; a permanent one fails the action at once.
    pub retryable: bool,
}

impl ToolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: true,
        }
    }

    /// An error that retrying cannot fix, such as failed business validation.
    pub fn permanent(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            retryable: false,
            ..Self::new(code, message)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("Capability is already registered: {0}")]
    Duplicate(String),
    #[error(
        "Capability needs a name (1–64 ASCII letters, digits, underscores or hyphens), description and permission"
    )]
    InvalidCapability,
    #[error("Tool input must have an object JSON schema")]
    InvalidInputSchema,
}

#[derive(Clone)]
struct McpServer(Arc<Agent>);

fn principal(context: &RequestContext<RoleServer>) -> Result<Principal, McpError> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Principal>())
        .cloned()
        .ok_or_else(|| McpError::invalid_request("Authentication required", None))
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new("oxidt-agent", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.0.tools(&principal(&context)?),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let principal = principal(&context)?;
        let result = self
            .0
            .invoke(
                principal,
                &request.name,
                Value::Object(request.arguments.unwrap_or_default()),
            )
            .await;
        Ok(match result {
            Ok(value) => CallToolResult::structured(value),
            Err(error) => CallToolResult::structured_error(
                json!({"code": error.code, "message": error.message}),
            ),
        }
        .into())
    }
}
