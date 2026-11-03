# oxidt-agent — embedded prototype

Register typed application functions once and expose them as authenticated MCP
tools inside an Axum or Topcoat application. One process, direct Rust calls.
The policy model lives in `oxidt-agent-core`, with no HTTP or framework dependency.

## What works

- Input/output schemas derived from Rust types; input deserialization before execution.
- Application-supplied authentication on every HTTP request, including tool discovery.
- Permission-filtered discovery and permission checks on every invocation.
- User, tenant, client and authorization-grant identity passed separately from tool arguments.
- Read/write/external-effect annotations and structured tool results/errors.
- Immediate writes require approval by default and fail closed. Durable actions persist approval requests.
- MCP Streamable HTTP, an explicit host allowlist and a 64 KiB request limit.
- A Topcoat route adapter, a minimal notebook example and a durable approval example.

## Run the Topcoat example

From the kit root, with Rust 1.99 or newer:

```sh
export AGENT_DEMO_TOKEN="$(openssl rand -hex 32)"
cargo run -p oxidt-agent --features topcoat --example topcoat
```

Open `http://127.0.0.1:8097`. Connect an MCP client to
`http://127.0.0.1:8097/mcp`, using `Authorization: Bearer <AGENT_DEMO_TOKEN>`.
The token is a local demo credential, with one fixed demo identity. It is never
rendered in the page. The demo does not provide OAuth login/discovery.

Try `list_notes` with `{}`, then `add_note` with `{"text":"Try embedded MCP"}`.
The example explicitly permits adding notes without approval. Its bounded,
in-memory notebook resets on restart and does not deduplicate repeated writes.

## Host application integration

```rust,ignore
let mut agent = Agent::new();
agent.register(
    Capability::new("search_notes", "Search your notes", "notes:read", Effect::Read),
    move |principal, input: SearchNotes| {
        let services = services.clone();
        async move { services.search_notes(principal, input).await }
    },
)?;

let mcp = oxidt_agent::router(Arc::new(agent), config, authenticate);
let app = topcoat::router::Router::builder()
    .route(oxidt_agent::topcoat_route(mcp))
    .build();
```

`authenticate` is an async callback from `HeaderMap` to
`Result<Principal, AuthError>`. Resolve current identity, tenant membership,
client, grant ID and permissions using the app's existing API-key/OAuth implementation.
`AuthError::Unauthorized` returns 401 with the configured `WWW-Authenticate`
header; a failed identity backend returns 503 through `AuthError::Unavailable`.
The app supplies discovery routes and the challenge URL with `oxidt-mcp-oauth`.

Mount this route outside browser login redirects and browser CSRF middleware.
`HttpConfig::allowed_hosts` and `allowed_origins` drive the MCP SDK's Host/Origin
validation. Requests without an `Origin` header (non-browser MCP clients) pass;
any present `Origin` must be listed, so an empty `allowed_origins` rejects all
browser-originated requests (fail closed). Add the app's normal rate limits.
Authentication is never inferred from MCP session IDs or tool arguments.
The transport is stateless, including for legacy clients: no reconnect/event
replay or server-initiated interactive requests are provided by this prototype.

The handler is a normal application function. The application remains
responsible for resource ownership and business validation. For example, a
`conversation_id` must belong to `principal.tenant_id`; the library cannot
infer that from an ID. Prefer `#[serde(deny_unknown_fields)]` on input structs.
Do not expose a tenant override or an `approved: bool` argument.

Custom JSON Schema constraints are documentation; enforce them in your input
type or handler. Keep output types object-shaped when supporting older clients.
Return safe `ToolError` messages, not raw SQL/provider errors or secrets.
The host installs the tracing subscriber; invocation logs omit inputs/results.

Each call runs in an `agent.tool` span using OpenTelemetry GenAI field names
(`otel.name = "execute_tool <name>"`, `gen_ai.tool.name`, `error.type`,
`otel.status_code`), exported by the host's `tracing-opentelemetry` layer.
Durable actions add `agent.request_id` to the submission span and to the later
`agent.decide`/`agent.execute` spans, so one ID joins submit, review and execution.

## Durable actions and approvals

Enable `durable` to use PostgreSQL and `oxidt-jobs`. The host applies
`oxidt-jobs/schema.sql`, then this crate's `schema.sql`, through its migrations.
There are no automatic migrations or background workers during router assembly.

```rust,ignore
let mut agent = Agent::new();
let mut actions = Actions::new(pool.clone());
actions.register(
    &mut agent,
    Capability::new("save_note", "Save a note", "notes:write", Effect::Write)
        .with_version("1"),
    SaveNote,
)?;
let actions = Arc::new(actions);
actions.register_status_tool(&mut agent, "actions:read")?;
```

Implement `Action` with typed `Input`/`Output`. Its handler receives
`ActionContext { connection, principal, request_id }`. **All mutations must use
this transaction's connection.** Enqueue external deliveries in an outbox;
do not send email, call a payment provider, or write files inside an action.

The MCP tool takes an envelope:

```json
{
  "request_id": "b8d0ea76-bc2f-40a9-a9b4-3eeb493cc4c0",
  "arguments": { "text": "Save this after approval" }
}
```

It returns a receipt. Reuse that UUID for retries of the same intended action.
The ID is bound to the user, tenant, client, authorization grant, capability
version/schema/policy, and normalized typed arguments. A conflicting reuse fails.
`get_action` takes `{"request_id":"..."}` and returns status and eventual result.
Only the requesting identity with the action's current permission can read it.

1. Submission persists the exact operation, initially `pending` when approval is
   required. The agent cannot pass an `approved` flag or invoke an approval tool.
2. The host authenticates a human reviewer separately and calls `Actions::review`
   and `Actions::decide`. The requesting user reviews their own actions in that
   tenant. The library does not infer reviewer identity from an agent token.
3. Approval revalidates the action definition and current access, then commits
   the decision and job enqueue atomically. Rejection never queues execution.
4. The app's existing `oxidt_jobs::Handler` dispatches `oxidt_agent_action` payloads
   to `actions.execute_job(job, resolver)`. Keep dispatch for other task kinds;
   the shared queue is not scoped to agent work.
5. Execution resolves the **specific grant** again with `ResolveIdentity`.
   Return `None` for revoked keys/grants/memberships. Resolve current permissions,
   never restore them from a stored snapshot. The supplied connection allows
   locking authorization rows if revocation must serialize with the mutation.
6. The worker locks the action row, executes the handler, and commits its mutations
   and result together. A repeated attempt sees `completed` and skips execution.
   Handler errors roll back. A `ToolError::new` error retries with the queue's
   bounded backoff, recording its code as the job's `last_error`; a
   `ToolError::permanent` error (such as failed validation) fails at once.
   Either way the final failure is stored on the action as `failed`, and
   `get_action` returns its `{"code","message"}` as `error`. Retries in
   progress poll as `queued`/`running`.

Requests expire after 24 hours, checked again before execution starts. Changes
to a capability's stored definition invalidate pending/queued work; bump its
version whenever handler semantics change. Business-specific revision checks
(such as a changed draft) remain the handler's responsibility.

Retain action records for the required idempotency window: deleting a completed
record removes that protection. The host owns retention of arguments/results,
and sweeping expired `pending` rows (indexed by `expires_at`).
This is transactional database execution, not a guarantee of exactly-once
external delivery. There is no cancellation API or multi-step workflow engine.

## Run the durable Topcoat example

Use an app-owned database/login on the shared local Postgres service. Its role
needs `CREATEDB` for `sqlx::test` databases; do not use the shared superuser as the
application login. Set `DATABASE_URL` to that connection string.

```sh
# First run, on an empty app database: atomically create the demo tables and exit.
cargo run -p oxidt-agent --features topcoat,durable --example durable-topcoat -- --init

export AGENT_DEMO_TOKEN="$(openssl rand -hex 32)"
export AGENT_REVIEW_TOKEN="$(openssl rand -hex 32)"
cargo run -p oxidt-agent --features topcoat,durable --example durable-topcoat
```

Open `http://127.0.0.1:8098`. Connect MCP at `/mcp` with the agent bearer token,
submit `add_note` using the envelope above, then paste the returned ID into the
page. The browser reviewer login is `owner`, with `AGENT_REVIEW_TOKEN` as its
password. Approve/reject the displayed arguments, then refresh or use `get_action`.
The saved note and execution result survive restarts.

This local demo uses distinct static agent/reviewer credentials and a fixed
identity resolver. Production apps supply their existing login, CSRF protection,
rate limiting and live grant/membership queries. The demo rejects cross-origin
review POSTs, does not expose the review token through MCP, and stops its worker
on SIGINT/SIGTERM. The review URL intentionally uses `127.0.0.1`, matching its
Origin check.

## Dapr-style building blocks in Topcoat

These should be independently usable backend crates. Topcoat adapters provide
routes and optional UI; they should not own the infrastructure abstractions.

| Building block | Direction |
|---|---|
| Durable jobs | Reuse `oxidt-jobs`; application owns migrations and worker lifecycle |
| Pub/sub | Add when an app needs it; transactional outbox and broker delivery semantics |
| Service calls | Typed async clients with deadlines; retry only when safe |
| State | Use the application's database and transactions initially |
| Secrets/configuration | Reuse deployment configuration and existing secret providers |
| Tracing/metrics | Share the application's tracing and telemetry pipeline |
| Discovery, mTLS, network isolation | Deployment infrastructure; embedding cannot supply a process boundary |

A sidecar can later bind capabilities to HTTP handlers using the same core.
It is not needed to test the Topcoat integration, and would add an identity
handoff plus an application API to every call.

## Verify

```sh
# Database tests require DATABASE_URL with CREATEDB.
cargo test -p oxidt-agent-core -p oxidt-agent --all-features
cargo test -p oxidt-agent --no-default-features
cargo test -p oxidt-agent --features topcoat --example topcoat
cargo test -p oxidt-agent --features topcoat,durable --example durable-topcoat
cargo clippy -p oxidt-agent-core -p oxidt-agent --all-features --all-targets -- -D warnings
```
