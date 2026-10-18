# oxidt-agent-setup

The response contract for agent-driven setup over MCP. An agent working in the
user's repo calls the app's `setup_*` tool and writes the env vars and snippet
it gets back into the codebase. It then calls `verify_setup` until the first
event arrives, so the user never has to open the dashboard.

```toml
[dependencies]
oxidt-agent-setup = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-agent-setup-v0.2.0" }
```

Types only (Serde + schemars): no axum, no rmcp, no database.

## The two tools every app exposes

| tool | returns | rule |
|---|---|---|
| `setup_<kind>` (`setup_project`, `setup_website`, …) | `Setup` | idempotent: the same input returns the existing resource with `created: false` |
| `verify_setup(id)` | `Verification` | `waiting` + a hint until the first event, then `receiving` |

Some steps can't be done by an agent: billing, third-party OAuth consent such as
GSC, and accepting an invitation. Those go in `Setup.human_steps` as a URL, and
the tool still succeeds instead of failing.

Env vars marked `secret: true` get written to the env file. They are never shown
to the user or committed. `secret: false` values (a DSN, a public site key) are
safe to commit, so they can go straight into deploy config.

If the app speaks an existing SDK's protocol (Thermite takes Sentry events), list
it in `Setup.compatible_with`. An agent that finds that SDK in the repo
configures it instead of adding the snippet.

```rust
#[tool(description = "Create or reuse a project and return its DSN and install snippet")]
async fn setup_project(&self, Parameters(p): Parameters<SetupProject>) -> Result<Json<Setup>, McpError> { … }

#[tool(description = "Has this project received its first event yet?")]
async fn verify_setup(&self, Parameters(p): Parameters<ById>) -> Result<Json<Verification>, McpError> {
    let (first, last) = store.event_bounds(&p.id).await?;
    Ok(Json(Verification::from_events(first, last, "trigger any error in the app")))
}
```
