#![cfg(feature = "durable")]

use oxidt_agent::{
    Agent, Approval, Capability, Effect, Principal, ToolError,
    durable::{
        Action, ActionContext, Actions, Error, Identity, MAX_ALLOWANCE, ResolveIdentity, Reviewer,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Input {
    text: String,
}
#[derive(Serialize, JsonSchema)]
struct Output {
    text: String,
}
struct Save {
    fail_once: Arc<AtomicBool>,
}
impl Action for Save {
    type Input = Input;
    type Output = Output;
    async fn execute(&self, context: ActionContext<'_>, input: Input) -> Result<Output, ToolError> {
        sqlx::query("INSERT INTO effects(id,tenant_id,text) VALUES($1,$2,$3)")
            .bind(context.request_id)
            .bind(&context.principal.tenant_id)
            .bind(&input.text)
            .execute(context.connection)
            .await
            .map_err(|_| ToolError::new("db", "Storage failed"))?;
        if input.text.is_empty() {
            return Err(ToolError::permanent(
                "invalid_note",
                "Note must not be empty",
            ));
        }
        if self.fail_once.swap(false, Ordering::SeqCst) {
            return Err(ToolError::new("retry", "Retry this attempt"));
        }
        Ok(Output { text: input.text })
    }
}

struct Resolver(AtomicBool);
impl ResolveIdentity for Resolver {
    async fn resolve(
        &self,
        _: &mut PgConnection,
        identity: &Identity,
    ) -> Result<Option<Principal>, sqlx::Error> {
        Ok(self.0.load(Ordering::SeqCst).then(|| Principal {
            user_id: identity.user_id.clone(),
            tenant_id: identity.tenant_id.clone(),
            client_id: identity.client_id.clone(),
            grant_id: identity.grant_id.clone(),
            permissions: ["notes:write".into(), "actions:read".into()].into(),
        }))
    }
}

fn principal() -> Principal {
    Principal {
        user_id: "owner".into(),
        tenant_id: "tenant-a".into(),
        client_id: "client-a".into(),
        grant_id: "grant-a".into(),
        permissions: ["notes:write".into(), "actions:read".into()].into(),
    }
}
fn reviewer() -> Reviewer {
    Reviewer {
        user_id: "owner".into(),
        tenant_id: "tenant-a".into(),
    }
}

fn registry(
    pool: &PgPool,
    version: &str,
    approval: Approval,
    fail_once: bool,
) -> (Agent, Arc<Actions>) {
    let mut agent = Agent::new();
    let mut actions = Actions::new(pool.clone());
    actions
        .register(
            &mut agent,
            Capability::new("save", "Save note", "notes:write", Effect::Write)
                .with_version(version)
                .with_approval(approval),
            Save {
                fail_once: Arc::new(AtomicBool::new(fail_once)),
            },
        )
        .unwrap();
    let actions = Arc::new(actions);
    actions
        .register_status_tool(&mut agent, "actions:read")
        .unwrap();
    (agent, actions)
}
async fn setup(pool: &PgPool) {
    sqlx::raw_sql(include_str!("../../oxidt-jobs/schema.sql"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE effects(id UUID PRIMARY KEY,tenant_id TEXT NOT NULL,text TEXT NOT NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
}
async fn submit(agent: &Agent, id: Uuid) -> Value {
    agent
        .invoke(
            principal(),
            "save",
            json!({"request_id":id,"arguments":{"text":"reviewed text"}}),
        )
        .await
        .unwrap()
}
async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM effects")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn invalid_or_unprivileged_submissions_never_access_storage() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@localhost/unused")
        .unwrap();
    let (agent, _) = registry(&pool, "1", Approval::Required, false);
    let tools = agent.tools(&principal());
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        ["get_action", "save"]
    );
    let input_schema = serde_json::to_value(&tools[1].input_schema).unwrap();
    assert_eq!(input_schema["properties"]["request_id"]["type"], "string");
    for args in [
        json!({"request_id":"not-a-uuid","arguments":{"text":"hello"}}),
        json!({"request_id":Uuid::new_v4(),"arguments":{"text":"hello"},"approved":true}),
        json!({"request_id":Uuid::new_v4(),"arguments":{"text":"hello","tenant_id":"other"}}),
    ] {
        let error = agent.invoke(principal(), "save", args).await.unwrap_err();
        assert_eq!(error.code, "invalid_input");
    }
    let mut unprivileged = principal();
    unprivileged.permissions.clear();
    assert_eq!(
        agent
            .invoke(
                unprivileged,
                "save",
                json!({"request_id":Uuid::new_v4(),"arguments":{"text":"hello"}})
            )
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
}

#[sqlx::test(migrations = false)]
async fn approval_is_required_and_duplicate_submissions_are_bound_to_exact_identity_and_arguments(
    pool: PgPool,
) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    let (a, b) = tokio::join!(submit(&agent, id), submit(&agent, id));
    assert_eq!(a, b);
    assert_eq!(a["status"], "pending");
    assert!(oxidt_jobs::claim(&pool).await.unwrap().is_none());
    assert_eq!(count(&pool).await, 0);
    let changed = agent
        .invoke(
            principal(),
            "save",
            json!({"request_id":id,"arguments":{"text":"changed"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(changed.code, "conflict");
    let mut different_grant = principal();
    different_grant.grant_id = "other-grant".into();
    assert!(matches!(
        actions.get(&different_grant, id).await,
        Err(Error::Unavailable)
    ));
    let mut other = principal();
    other.client_id = "other-client".into();
    assert!(matches!(
        actions.get(&other, id).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        agent
            .invoke(
                other,
                "save",
                json!({"request_id":id,"arguments":{"text":"reviewed text"}})
            )
            .await
            .unwrap_err()
            .code,
        "unavailable"
    );
    let forged = agent
        .invoke(
            principal(),
            "save",
            json!({"request_id":id,"arguments":{"text":"reviewed text"},"approved":true}),
        )
        .await
        .unwrap_err();
    assert_eq!(forged.code, "invalid_input");
    let other_reviewer = Reviewer {
        user_id: "owner".into(),
        tenant_id: "tenant-b".into(),
    };
    assert!(matches!(
        actions
            .decide(&other_reviewer, id, true, &Resolver(AtomicBool::new(true)))
            .await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        actions.review(&other_reviewer, id).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(
        actions.review(&reviewer(), id).await.unwrap().arguments,
        json!({"text":"reviewed text"})
    );
}

#[sqlx::test(migrations = false)]
async fn concurrent_approval_enqueues_once_and_recovery_after_missing_ack_does_not_repeat_effect(
    pool: PgPool,
) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    let human = reviewer();
    let (a, b) = tokio::join!(
        actions.decide(&human, id, true, &resolver),
        actions.decide(&human, id, true, &resolver)
    );
    assert_eq!(a.unwrap().status, "queued");
    assert_eq!(b.unwrap().status, "queued");
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM background_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(queued, 1);
    let first = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    actions.execute_job(&first, &resolver).await.unwrap();
    assert_eq!(count(&pool).await, 1);
    // Mutation committed but the worker died before acknowledging the job.
    sqlx::query("UPDATE background_jobs SET lease_until=NOW()-INTERVAL '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let retry = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    // Reconstruct the registry to model an application restart.
    let (restarted_agent, restarted) = registry(&pool, "1", Approval::Required, false);
    restarted.execute_job(&retry, &resolver).await.unwrap();
    oxidt_jobs::finish(&pool, &retry, Ok(())).await.unwrap();
    assert_eq!(count(&pool).await, 1);
    let state = restarted_agent
        .invoke(principal(), "get_action", json!({"request_id":id}))
        .await
        .unwrap();
    assert_eq!(state["status"], "completed");
    assert_eq!(state["result"], json!({"text":"reviewed text"}));
}

#[sqlx::test(migrations = false)]
async fn failed_attempt_rolls_back_application_mutation_before_retry(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::NotRequired, true);
    let id = Uuid::new_v4();
    assert_eq!(submit(&agent, id).await["status"], "queued");
    let resolver = Resolver(AtomicBool::new(true));
    let first = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    let failure = actions.execute_job(&first, &resolver).await;
    assert!(failure.is_err());
    oxidt_jobs::finish(&pool, &first, failure).await.unwrap();
    assert_eq!(count(&pool).await, 0);
    let last_error: String = sqlx::query_scalar("SELECT last_error FROM background_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(last_error, "retry");
    assert_eq!(
        actions.get(&principal(), id).await.unwrap().status,
        "queued"
    );
    sqlx::query("UPDATE background_jobs SET run_at=NOW()")
        .execute(&pool)
        .await
        .unwrap();
    let retry = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    actions.execute_job(&retry, &resolver).await.unwrap();
    oxidt_jobs::finish(&pool, &retry, Ok(())).await.unwrap();
    assert_eq!(count(&pool).await, 1);
    assert_eq!(
        actions.get(&principal(), id).await.unwrap().status,
        "completed"
    );
}

#[sqlx::test(migrations = false)]
async fn revoke_after_approval_prevents_execution(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    actions
        .decide(&reviewer(), id, true, &resolver)
        .await
        .unwrap();
    resolver.0.store(false, Ordering::SeqCst);
    let job = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    actions.execute_job(&job, &resolver).await.unwrap();
    assert_eq!(
        actions.get(&principal(), id).await.unwrap().status,
        "invalidated"
    );
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test(migrations = false)]
async fn version_changes_invalidate_pending_and_already_approved_actions(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let pending = Uuid::new_v4();
    submit(&agent, pending).await;
    let approved = Uuid::new_v4();
    submit(&agent, approved).await;
    let resolver = Resolver(AtomicBool::new(true));
    actions
        .decide(&reviewer(), approved, true, &resolver)
        .await
        .unwrap();
    let (_, newer) = registry(&pool, "2", Approval::Required, false);
    assert_eq!(
        newer
            .decide(&reviewer(), pending, true, &resolver)
            .await
            .unwrap()
            .status,
        "invalidated"
    );
    let job = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    newer.execute_job(&job, &resolver).await.unwrap();
    assert_eq!(
        newer.get(&principal(), approved).await.unwrap().status,
        "invalidated"
    );
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test(migrations = false)]
async fn rejection_and_expiry_cannot_later_be_approved(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    assert_eq!(
        actions
            .decide(&reviewer(), id, false, &resolver)
            .await
            .unwrap()
            .status,
        "rejected"
    );
    assert_eq!(
        actions
            .decide(&reviewer(), id, false, &resolver)
            .await
            .unwrap()
            .status,
        "rejected"
    );
    assert!(matches!(
        actions.decide(&reviewer(), id, true, &resolver).await,
        Err(Error::Conflict)
    ));
    let expired = Uuid::new_v4();
    submit(&agent, expired).await;
    sqlx::query("UPDATE agent_actions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(expired)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        actions
            .decide(&reviewer(), expired, true, &resolver)
            .await
            .unwrap()
            .status,
        "expired"
    );
    assert!(oxidt_jobs::claim(&pool).await.unwrap().is_none());
}

#[sqlx::test(migrations = false)]
async fn enqueue_failure_rolls_back_approval(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    sqlx::query("ALTER TABLE background_jobs ADD CONSTRAINT reject_demo CHECK (kind <> 'oxidt_agent_action')").execute(&pool).await.unwrap();
    assert!(
        actions
            .decide(&reviewer(), id, true, &Resolver(AtomicBool::new(true)))
            .await
            .is_err()
    );
    let row = actions.review(&reviewer(), id).await.unwrap();
    assert_eq!(row.status, "pending");
    assert!(row.reviewed_by.is_none());
}

#[sqlx::test(migrations = false)]
async fn exhausted_job_retries_are_visible_to_the_agent(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::NotRequired, true);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    sqlx::query("UPDATE background_jobs SET max_attempts=1")
        .execute(&pool)
        .await
        .unwrap();
    let job = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    let result = actions
        .execute_job(&job, &Resolver(AtomicBool::new(true)))
        .await;
    oxidt_jobs::finish(&pool, &job, result).await.unwrap();
    let job_state: (String, String) =
        sqlx::query_as("SELECT status, last_error FROM background_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(job_state, ("failed".into(), "retry".into()));
    // Persisted on the action itself, so pruning the queue does not lose it.
    sqlx::query("DELETE FROM background_jobs")
        .execute(&pool)
        .await
        .unwrap();
    let row = actions.get(&principal(), id).await.unwrap();
    assert_eq!(row.status, "failed");
    assert_eq!(
        row.result,
        Some(json!({"code":"retry","message":"Retry this attempt"}))
    );
    assert_eq!(count(&pool).await, 0);
}

#[sqlx::test(migrations = false)]
async fn permanent_errors_fail_the_action_without_retrying(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::NotRequired, false);
    let id = Uuid::new_v4();
    agent
        .invoke(
            principal(),
            "save",
            json!({"request_id":id,"arguments":{"text":""}}),
        )
        .await
        .unwrap();
    let job = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    let result = actions
        .execute_job(&job, &Resolver(AtomicBool::new(true)))
        .await;
    assert!(
        result.is_ok(),
        "a permanent error is acknowledged, not retried"
    );
    oxidt_jobs::finish(&pool, &job, result).await.unwrap();
    assert!(oxidt_jobs::claim(&pool).await.unwrap().is_none());
    assert_eq!(count(&pool).await, 0);
    let state = agent
        .invoke(principal(), "get_action", json!({"request_id":id}))
        .await
        .unwrap();
    assert_eq!(state["status"], "failed");
    assert_eq!(state["result"], Value::Null);
    assert_eq!(
        state["error"],
        json!({"code":"invalid_note","message":"Note must not be empty"})
    );
}

#[sqlx::test(migrations = false)]
async fn overlapping_attempts_after_lease_expiry_commit_only_one_effect(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::NotRequired, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let first = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    sqlx::query("UPDATE background_jobs SET lease_until=NOW()-INTERVAL '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let second = oxidt_jobs::claim(&pool).await.unwrap().unwrap();
    let resolver = Resolver(AtomicBool::new(true));
    let (a, b) = tokio::join!(
        actions.execute_job(&first, &resolver),
        actions.execute_job(&second, &resolver)
    );
    a.unwrap();
    b.unwrap();
    oxidt_jobs::finish(&pool, &first, Ok(())).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT status FROM background_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        state, "running",
        "stale attempt cannot acknowledge the new lease"
    );
    oxidt_jobs::finish(&pool, &second, Ok(())).await.unwrap();
    assert_eq!(count(&pool).await, 1);
}

const HOUR: Duration = Duration::from_secs(3600);

fn allowing(pool: &PgPool, version: &str) -> (Agent, Arc<Actions>) {
    let mut agent = Agent::new();
    let mut actions = Actions::new(pool.clone());
    actions
        .register(
            &mut agent,
            Capability::new("save", "Save note", "notes:write", Effect::Write)
                .with_version(version)
                .with_allowances(),
            Save {
                fail_once: Arc::new(AtomicBool::new(false)),
            },
        )
        .unwrap();
    (agent, Arc::new(actions))
}
async fn submit_as(agent: &Agent, principal: Principal) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let receipt = agent
        .invoke(
            principal,
            "save",
            json!({"request_id":id,"arguments":{"text":"anything"}}),
        )
        .await
        .unwrap();
    (id, receipt["status"].as_str().unwrap().to_string())
}
/// Approve a first request with a one hour allowance and run it.
async fn allow(pool: &PgPool, agent: &Agent, actions: &Actions) -> Uuid {
    let id = Uuid::new_v4();
    submit(agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    actions
        .approve_and_allow(&reviewer(), id, HOUR, &resolver)
        .await
        .unwrap();
    run_next(pool, actions).await;
    id
}
async fn run_next(pool: &PgPool, actions: &Actions) {
    let job = oxidt_jobs::claim(pool).await.unwrap().unwrap();
    let result = actions
        .execute_job(&job, &Resolver(AtomicBool::new(true)))
        .await;
    oxidt_jobs::finish(pool, &job, result).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn allowance_queues_later_submissions_with_any_arguments(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    allow(&pool, &agent, &actions).await;
    assert_eq!(count(&pool).await, 1);

    let (id, status) = submit_as(&agent, principal()).await;
    assert_eq!(status, "queued");
    run_next(&pool, &actions).await;
    let row = actions.get(&principal(), id).await.unwrap();
    assert_eq!(row.status, "completed");
    assert_eq!(row.reviewed_by.as_deref(), Some("owner"));
    assert!(row.allowance_id.is_some());
    assert_eq!(count(&pool).await, 2);
}

#[sqlx::test(migrations = false)]
async fn allowance_is_bound_to_exact_identity_and_definition(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    allow(&pool, &agent, &actions).await;

    for change in [
        |p: &mut Principal| p.client_id = "client-b".into(),
        |p: &mut Principal| p.grant_id = "grant-b".into(),
        |p: &mut Principal| p.user_id = "someone-else".into(),
        |p: &mut Principal| p.tenant_id = "tenant-b".into(),
    ] {
        let mut other = principal();
        change(&mut other);
        assert_eq!(submit_as(&agent, other).await.1, "pending");
    }
    let (next_version, _) = allowing(&pool, "2");
    assert_eq!(submit_as(&next_version, principal()).await.1, "pending");
    assert_eq!(submit_as(&agent, principal()).await.1, "queued");
}

#[sqlx::test(migrations = false)]
async fn capabilities_must_opt_in_to_allowances(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = registry(&pool, "1", Approval::Required, false);
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    assert!(matches!(
        actions
            .approve_and_allow(&reviewer(), id, HOUR, &resolver)
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        actions.get(&principal(), id).await.unwrap().status,
        "pending"
    );
    assert!(actions.allowances(&reviewer()).await.unwrap().is_empty());
}

#[sqlx::test(migrations = false)]
async fn allowance_duration_is_bounded(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    let id = Uuid::new_v4();
    submit(&agent, id).await;
    let resolver = Resolver(AtomicBool::new(true));
    for duration in [Duration::ZERO, MAX_ALLOWANCE + Duration::from_secs(1)] {
        assert!(matches!(
            actions
                .approve_and_allow(&reviewer(), id, duration, &resolver)
                .await,
            Err(Error::InvalidAllowance)
        ));
    }
    actions
        .approve_and_allow(&reviewer(), id, MAX_ALLOWANCE, &resolver)
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn expired_allowance_returns_to_review(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    allow(&pool, &agent, &actions).await;
    sqlx::query("UPDATE agent_allowances SET expires_at=NOW()-INTERVAL '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(submit_as(&agent, principal()).await.1, "pending");
    assert!(actions.allowances(&reviewer()).await.unwrap().is_empty());
}

#[sqlx::test(migrations = false)]
async fn revoking_stops_new_and_queued_requests(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    allow(&pool, &agent, &actions).await;
    let (queued, status) = submit_as(&agent, principal()).await;
    assert_eq!(status, "queued");

    let allowance = actions.allowances(&reviewer()).await.unwrap().remove(0);
    let stranger = Reviewer {
        user_id: "stranger".into(),
        tenant_id: "tenant-a".into(),
    };
    assert!(matches!(
        actions.revoke_allowance(&stranger, allowance.id).await,
        Err(Error::Unavailable)
    ));
    assert_eq!(submit_as(&agent, principal()).await.1, "queued");
    run_next(&pool, &actions).await;
    assert_eq!(count(&pool).await, 2);

    actions
        .revoke_allowance(&reviewer(), allowance.id)
        .await
        .unwrap();
    actions
        .revoke_allowance(&reviewer(), allowance.id)
        .await
        .unwrap();
    assert_eq!(submit_as(&agent, principal()).await.1, "pending");
    run_next(&pool, &actions).await;
    assert_eq!(count(&pool).await, 2);
    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM agent_actions WHERE allowance_id IS NOT NULL ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(statuses, ["completed", "completed", "invalidated"]);
    assert_ne!(
        actions.get(&principal(), queued).await.unwrap().status,
        "queued"
    );
}

#[sqlx::test(migrations = false)]
async fn repeated_allow_does_not_extend_and_one_time_approval_cannot_upgrade(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    let id = allow(&pool, &agent, &actions).await;
    let before = actions.allowances(&reviewer()).await.unwrap().remove(0);
    let resolver = Resolver(AtomicBool::new(true));
    actions
        .approve_and_allow(&reviewer(), id, MAX_ALLOWANCE, &resolver)
        .await
        .unwrap();
    let after = actions.allowances(&reviewer()).await.unwrap().remove(0);
    assert_eq!(before.expires_at, after.expires_at);

    let (once, _) = submit_as(
        &agent,
        Principal {
            grant_id: "grant-b".into(),
            ..principal()
        },
    )
    .await;
    actions
        .decide(&reviewer(), once, true, &resolver)
        .await
        .unwrap();
    assert!(matches!(
        actions
            .approve_and_allow(&reviewer(), once, HOUR, &resolver)
            .await,
        Err(Error::Conflict)
    ));
}

#[sqlx::test(migrations = false)]
async fn a_new_allowance_replaces_the_active_one(pool: PgPool) {
    setup(&pool).await;
    let (agent, actions) = allowing(&pool, "1");
    allow(&pool, &agent, &actions).await;
    let (next_version, next_actions) = allowing(&pool, "2");
    let (id, _) = submit_as(&next_version, principal()).await;
    next_actions
        .approve_and_allow(&reviewer(), id, HOUR, &Resolver(AtomicBool::new(true)))
        .await
        .unwrap();
    assert_eq!(actions.allowances(&reviewer()).await.unwrap().len(), 1);
    assert_eq!(submit_as(&agent, principal()).await.1, "pending");
    assert_eq!(submit_as(&next_version, principal()).await.1, "queued");
}
