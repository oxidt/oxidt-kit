//! Durable, transactional actions. The host owns migrations, authentication,
//! review routes and worker lifecycle. Approval is never an MCP tool.
//!
//! Handlers MUST use the supplied connection for all mutations. Do not perform
//! external effects here: enqueue an outbox entry in this transaction instead.
//! An action row lock serializes attempts; the mutation and result commit together.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::{Agent, Approval, Capability, Principal, RegistrationError, ToolError};

/// Only the application's authenticated browser/reviewer path may construct this.
/// The requesting user can review their own actions in the selected tenant.
#[derive(Clone, Debug)]
pub struct Reviewer {
    pub user_id: String,
    pub tenant_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub user_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub grant_id: String,
}

impl Identity {
    fn matches(&self, principal: &Principal) -> bool {
        self.user_id == principal.user_id
            && self.tenant_id == principal.tenant_id
            && self.client_id == principal.client_id
            && self.grant_id == principal.grant_id
    }
}

/// Resolve current membership, client grants and permissions. Return `None` for
/// revoked access. Never reconstruct permissions from the queued request.
pub trait ResolveIdentity: Send + Sync {
    fn resolve(
        &self,
        connection: &mut PgConnection,
        identity: &Identity,
    ) -> impl Future<Output = Result<Option<Principal>, sqlx::Error>> + Send;
}

pub struct ActionContext<'a> {
    pub connection: &'a mut PgConnection,
    pub principal: &'a Principal,
    pub request_id: Uuid,
}

pub trait Action: Send + Sync + 'static {
    type Input: DeserializeOwned + Serialize + JsonSchema + Send + 'static;
    type Output: Serialize + JsonSchema + Send + 'static;

    /// Errors roll back the handler's mutations. Retryable errors use oxidt-jobs'
    /// bounded retries; a `ToolError::permanent` fails the action without retrying.
    fn execute(
        &self,
        context: ActionContext<'_>,
        input: Self::Input,
    ) -> impl Future<Output = Result<Self::Output, ToolError>> + Send;
}

type Attempt<'a> = Pin<Box<dyn Future<Output = Result<Value, ToolError>> + Send + 'a>>;
trait ErasedAction: Send + Sync {
    fn execute<'a>(&'a self, context: ActionContext<'a>, arguments: Value) -> Attempt<'a>;
}
struct Typed<A>(A);
impl<A: Action> ErasedAction for Typed<A> {
    fn execute<'a>(&'a self, context: ActionContext<'a>, arguments: Value) -> Attempt<'a> {
        Box::pin(async move {
            let input = serde_json::from_value(arguments).map_err(|_| {
                ToolError::permanent("invalid_input", "Stored action input is invalid")
            })?;
            let output = self.0.execute(context, input).await?;
            serde_json::to_value(output).map_err(|_| {
                ToolError::permanent("invalid_output", "Action result could not be encoded")
            })
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Request<I> {
    /// A UUID generated once per intended action. Reuse it when retrying submission.
    request_id: String,
    /// Exact operation to submit for approval/execution.
    arguments: I,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Receipt {
    pub request_id: String,
    pub status: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    request_id: String,
}

#[derive(Serialize, JsonSchema)]
struct StatusOutput {
    request_id: String,
    status: String,
    result: Option<Value>,
    /// The safe `{"code","message"}` of a failed action, when the handler reported one.
    error: Option<Value>,
}

/// Contains potentially sensitive arguments/results. Only return through authenticated routes.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RequestRecord {
    pub id: Uuid,
    pub user_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub grant_id: String,
    pub name: String,
    pub definition: Value,
    pub arguments: Value,
    pub status: String,
    pub result: Option<Value>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

impl RequestRecord {
    fn identity(&self) -> Identity {
        Identity {
            user_id: self.user_id.clone(),
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            grant_id: self.grant_id.clone(),
        }
    }
    fn receipt(&self) -> Receipt {
        Receipt {
            request_id: self.id.to_string(),
            status: self.status.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Request is unavailable")]
    Unavailable,
    #[error("Request no longer matches this operation or decision")]
    Conflict,
    #[error("Action storage is unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("Action attempt failed: {0}")]
    Attempt(&'static str),
}

impl From<Error> for ToolError {
    fn from(error: Error) -> Self {
        let code = match error {
            Error::Unavailable => "unavailable",
            Error::Conflict => "conflict",
            Error::Storage(_) => "storage_unavailable",
            Error::Attempt(code) => code,
        };
        ToolError::new(code, error.to_string())
    }
}

struct Registered {
    capability: Capability,
    definition: Value,
    handler: Box<dyn ErasedAction>,
}

/// Build alongside `Agent`, then share with the host's review routes and job dispatcher.
pub struct Actions {
    pool: PgPool,
    entries: BTreeMap<String, Registered>,
}

impl Actions {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            entries: BTreeMap::new(),
        }
    }

    /// Add authenticated polling for receipts. Still checks the action's own
    /// permission and exact requesting identity on every lookup.
    pub fn register_status_tool(
        self: &Arc<Self>,
        agent: &mut Agent,
        permission: &str,
    ) -> Result<(), RegistrationError> {
        let actions = self.clone();
        agent.register(
            Capability::new(
                "get_action",
                "Read the status and result of your submitted action",
                permission,
                crate::Effect::Read,
            ),
            move |principal, input: StatusInput| {
                let actions = actions.clone();
                async move {
                    let id = Uuid::parse_str(&input.request_id).map_err(|_| {
                        ToolError::new("invalid_input", "request_id must be a UUID")
                    })?;
                    let row = actions.get(&principal, id).await.map_err(ToolError::from)?;
                    // A failed action stores its error in `result`.
                    let (result, error) = if row.status == "failed" {
                        (None, row.result)
                    } else {
                        (row.result, None)
                    };
                    Ok(StatusOutput {
                        request_id: row.id.to_string(),
                        status: row.status,
                        result,
                        error,
                    })
                }
            },
        )
    }

    /// Register an MCP submission tool. Its output is a receipt; the action result
    /// is retrieved separately. There is no immediate path to the action handler.
    pub fn register<A: Action>(
        &mut self,
        agent: &mut Agent,
        capability: Capability,
        action: A,
    ) -> Result<(), RegistrationError> {
        if self.entries.contains_key(&capability.name) {
            return Err(RegistrationError::Duplicate(capability.name));
        }
        let definition = json!({
            "name": capability.name, "version": capability.version,
            "description": capability.description, "permission": capability.permission,
            "effect": format!("{:?}", capability.effect), "approval": format!("{:?}", capability.approval),
            "input": schemars::schema_for!(A::Input), "output": schemars::schema_for!(A::Output),
        });
        let pool = self.pool.clone();
        let spec = definition.clone();
        let cap = capability.clone();
        let mut submission = capability.clone().with_approval(Approval::NotRequired);
        submission.description = format!(
            "Request: {}. Returns a durable receipt; {}. Reuse request_id on retries.",
            capability.description,
            if capability.approval == Approval::Required {
                "requires human approval before execution"
            } else {
                "executes in the background"
            }
        );
        agent.register(submission, move |principal, request: Request<A::Input>| {
            let (pool, definition, capability) = (pool.clone(), spec.clone(), cap.clone());
            async move {
                let id = Uuid::parse_str(&request.request_id)
                    .map_err(|_| ToolError::new("invalid_input", "request_id must be a UUID"))?;
                let arguments = serde_json::to_value(request.arguments).map_err(|_| {
                    ToolError::new("invalid_input", "Arguments could not be encoded")
                })?;
                submit(&pool, &capability, &definition, principal, id, arguments)
                    .await
                    .map_err(ToolError::from)
            }
        })?;
        self.entries.insert(
            capability.name.clone(),
            Registered {
                capability,
                definition,
                handler: Box::new(Typed(action)),
            },
        );
        Ok(())
    }

    /// Agent read path: scope by user AND tenant AND client, even for a guessed UUID.
    pub async fn get(&self, principal: &Principal, id: Uuid) -> Result<RequestRecord, Error> {
        let row = self.record(id).await?;
        if !row.identity().matches(principal)
            || !self
                .entries
                .get(&row.name)
                .is_some_and(|e| e.capability.visible_to(principal))
        {
            return Err(Error::Unavailable);
        }
        Ok(row)
    }

    /// Host-authenticated reviewer read path. Identity must come from browser auth.
    pub async fn review(&self, reviewer: &Reviewer, id: Uuid) -> Result<RequestRecord, Error> {
        let row = self.record(id).await?;
        if row.user_id != reviewer.user_id || row.tenant_id != reviewer.tenant_id {
            return Err(Error::Unavailable);
        }
        Ok(row)
    }

    /// One snapshot, so status and result always agree. Uses the database clock,
    /// like `decide`/`execute`. A final attempt that timed out or crashed never
    /// reaches `execute`'s failure path, so the queue's status fills in.
    async fn record(&self, id: Uuid) -> Result<RequestRecord, Error> {
        let row = sqlx::query(
            "SELECT a.*, CASE WHEN a.status='pending' AND a.expires_at <= clock_timestamp() THEN 'expired' \
             WHEN a.status='queued' AND j.status IN ('running','failed') THEN j.status \
             ELSE a.status END AS effective_status \
             FROM agent_actions a LEFT JOIN background_jobs j ON j.dedupe_key=$2 WHERE a.id=$1",
        )
        .bind(id)
        .bind(job_key(id))
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Unavailable)?;
        Ok(RequestRecord {
            status: row.try_get("effective_status")?,
            ..RequestRecord::from_row(&row)?
        })
    }

    /// Human decision, outside MCP. Approval + queue insert commit together.
    /// Repeated identical decisions are harmless; conflicting decisions are rejected.
    #[tracing::instrument(name = "agent.decide", skip_all, err(Display),
        fields(agent.request_id = %id, agent.approve = approve, agent.status = tracing::field::Empty))]
    pub async fn decide<R: ResolveIdentity>(
        &self,
        reviewer: &Reviewer,
        id: Uuid,
        approve: bool,
        resolver: &R,
    ) -> Result<Receipt, Error> {
        let mut tx = self.pool.begin().await?;
        let mut row: RequestRecord =
            sqlx::query_as("SELECT * FROM agent_actions WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(Error::Unavailable)?;
        if row.user_id != reviewer.user_id || row.tenant_id != reviewer.tenant_id {
            return Err(Error::Unavailable);
        }
        if (!approve && row.status == "rejected")
            || (approve
                && row.reviewed_by.is_some()
                && matches!(row.status.as_str(), "queued" | "completed"))
        {
            return Ok(row.receipt());
        }
        if row.status != "pending" {
            return Err(Error::Conflict);
        }
        let expired: bool = sqlx::query_scalar(
            "SELECT expires_at <= clock_timestamp() FROM agent_actions WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let status = if expired {
            "expired"
        } else if !approve {
            "rejected"
        } else {
            match self.current(&mut tx, &row, resolver).await? {
                Some(_) => "queued",
                None => "invalidated",
            }
        };
        sqlx::query(
            "UPDATE agent_actions SET status=$2,reviewed_by=$3,reviewed_at=NOW() WHERE id=$1",
        )
        .bind(id)
        .bind(status)
        .bind(&reviewer.user_id)
        .execute(&mut *tx)
        .await?;
        if status == "queued" {
            enqueue(&mut tx, id).await?;
        }
        tx.commit().await?;
        tracing::Span::current().record("agent.status", status);
        row.status = status.into();
        Ok(row.receipt())
    }

    async fn current<R: ResolveIdentity>(
        &self,
        connection: &mut PgConnection,
        row: &RequestRecord,
        resolver: &R,
    ) -> Result<Option<Principal>, sqlx::Error> {
        let Some(entry) = self
            .entries
            .get(&row.name)
            .filter(|entry| entry.definition == row.definition)
        else {
            return Ok(None);
        };
        let identity = row.identity();
        Ok(resolver
            .resolve(connection, &identity)
            .await?
            .filter(|p| identity.matches(p) && entry.capability.visible_to(p)))
    }

    /// Call from the application's existing oxidt-jobs Handler dispatcher.
    /// All retries use the same request ID. A completed action returns without
    /// re-running its handler, including after a crash before job acknowledgement.
    pub async fn execute_job<R: ResolveIdentity>(
        &self,
        job: &oxidt_jobs::Job,
        resolver: &R,
    ) -> Result<(), oxidt_jobs::JobFailure> {
        if job.payload["type"] != "oxidt_agent_action" {
            return Err("Unknown agent job".into());
        }
        let id = job.payload["request_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("Invalid agent job")?;
        // Attempts are counted at claim, so this is the final one once they meet.
        let last = job.attempts >= job.max_attempts;
        self.execute(id, resolver, last).await.map_err(|error| {
            oxidt_jobs::JobFailure::Safe(match error {
                Error::Attempt(code) => code,
                _ => "Agent action attempt failed",
            })
        })
    }

    #[tracing::instrument(name = "agent.execute", skip_all, err(Display),
        fields(agent.request_id = %id, gen_ai.tool.name = tracing::field::Empty, agent.status = tracing::field::Empty))]
    async fn execute<R: ResolveIdentity>(
        &self,
        id: Uuid,
        resolver: &R,
        last: bool,
    ) -> Result<(), Error> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query_as::<_, RequestRecord>(
            "SELECT * FROM agent_actions WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(());
        };
        let span = tracing::Span::current();
        span.record("gen_ai.tool.name", row.name.as_str());
        if row.status != "queued" {
            span.record("agent.status", row.status.as_str());
            return Ok(());
        }
        let expired: bool = sqlx::query_scalar(
            "SELECT expires_at <= clock_timestamp() FROM agent_actions WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let entry = self.entries.get(&row.name);
        let principal = if expired || entry.is_none() {
            None
        } else {
            self.current(&mut tx, &row, resolver).await?
        };
        let (Some(principal), Some(entry)) = (principal, entry) else {
            let status = if expired { "expired" } else { "invalidated" };
            sqlx::query("UPDATE agent_actions SET status=$2,finished_at=NOW() WHERE id=$1")
                .bind(id)
                .bind(status)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            span.record("agent.status", status);
            return Ok(());
        };
        // Queued is only reachable through submit (no approval needed) or decide.
        if entry.capability.approval == Approval::Required
            && row.reviewed_by.as_deref() != Some(row.user_id.as_str())
        {
            return Err(Error::Conflict);
        }
        // A savepoint: a failed handler's mutations roll back while the row stays locked.
        let mut attempt = sqlx::Connection::begin(&mut *tx).await?;
        let outcome = entry
            .handler
            .execute(
                ActionContext {
                    connection: &mut attempt,
                    principal: &principal,
                    request_id: id,
                },
                row.arguments,
            )
            .await;
        let (status, result, retryable) = match outcome {
            Ok(result) => {
                attempt.commit().await?;
                ("completed", result, None)
            }
            Err(error) => {
                attempt.rollback().await?;
                if error.retryable && !last {
                    span.record("agent.status", "queued");
                    return Err(Error::Attempt(error.code));
                }
                let result = json!({"code": error.code, "message": error.message});
                ("failed", result, error.retryable.then_some(error.code))
            }
        };
        sqlx::query("UPDATE agent_actions SET status=$2, result=$3, finished_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .bind(&result)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        span.record("agent.status", status);
        // Exhausted retries also fail the job; a permanent error is acknowledged.
        retryable.map_or(Ok(()), |code| Err(Error::Attempt(code)))
    }
}

fn job_key(id: Uuid) -> String {
    format!("oxidt-agent:{id}")
}
async fn enqueue(connection: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    oxidt_jobs::enqueue(
        connection,
        None,
        "oxidt_agent_action",
        json!({"type":"oxidt_agent_action", "request_id":id}),
        0,
        Utc::now(),
        Some(&job_key(id)),
    )
    .await
}

async fn submit(
    pool: &PgPool,
    capability: &Capability,
    definition: &Value,
    principal: Principal,
    id: Uuid,
    arguments: Value,
) -> Result<Receipt, Error> {
    if !capability.visible_to(&principal) {
        return Err(Error::Unavailable);
    }
    // Correlates this MCP call with the later decide/execute spans.
    tracing::Span::current().record("agent.request_id", tracing::field::display(id));
    let status = if capability.approval == Approval::Required {
        "pending"
    } else {
        "queued"
    };
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query("INSERT INTO agent_actions (id,user_id,tenant_id,client_id,grant_id,name,definition,arguments,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING")
        .bind(id).bind(&principal.user_id).bind(&principal.tenant_id).bind(&principal.client_id).bind(&principal.grant_id).bind(&capability.name).bind(definition).bind(&arguments).bind(status)
        .execute(&mut *tx).await?.rows_affected();
    let row: RequestRecord = sqlx::query_as("SELECT * FROM agent_actions WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if !row.identity().matches(&principal) {
        return Err(Error::Unavailable);
    }
    if row.name != capability.name || row.definition != *definition || row.arguments != arguments {
        return Err(Error::Conflict);
    }
    if inserted == 1 && status == "queued" {
        enqueue(&mut tx, id).await?;
    }
    tx.commit().await?;
    Ok(row.receipt())
}
