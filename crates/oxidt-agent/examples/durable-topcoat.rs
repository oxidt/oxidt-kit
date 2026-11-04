//! PostgreSQL example: MCP submission → separate human approval → background action.
use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Form, Router,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use oxidt_agent::{
    Agent, AuthError, Capability, Effect, HttpConfig, Principal, ToolError,
    durable::{Action, ActionContext, Actions, Identity, ResolveIdentity, Reviewer},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use topcoat::{
    context::Cx,
    router::{page, query_params, request},
    view::{View, view},
};
use uuid::Uuid;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddNote {
    text: String,
}
#[derive(Serialize, JsonSchema)]
struct Note {
    id: String,
    text: String,
}
struct SaveNote;
impl Action for SaveNote {
    type Input = AddNote;
    type Output = Note;
    async fn execute(&self, context: ActionContext<'_>, input: AddNote) -> Result<Note, ToolError> {
        if input.text.trim().is_empty() || input.text.len() > 1000 {
            return Err(ToolError::permanent(
                "invalid_note",
                "Note must contain 1–1000 bytes of non-blank text",
            ));
        }
        sqlx::query("INSERT INTO agent_demo_notes(id,tenant_id,text) VALUES($1,$2,$3)")
            .bind(context.request_id)
            .bind(&context.principal.tenant_id)
            .bind(&input.text)
            .execute(context.connection)
            .await
            .map_err(|_| ToolError::new("storage_unavailable", "Could not save note"))?;
        Ok(Note {
            id: context.request_id.to_string(),
            text: input.text,
        })
    }
}

fn principal() -> Principal {
    Principal {
        user_id: "demo-owner".into(),
        tenant_id: "demo-tenant".into(),
        client_id: "demo-agent".into(),
        grant_id: "demo-grant".into(),
        permissions: ["notes:write".into(), "actions:read".into()].into(),
    }
}
struct DemoIdentity;
impl ResolveIdentity for DemoIdentity {
    async fn resolve(
        &self,
        _: &mut PgConnection,
        identity: &Identity,
    ) -> Result<Option<Principal>, sqlx::Error> {
        let current = principal();
        Ok((identity.user_id == current.user_id
            && identity.tenant_id == current.tenant_id
            && identity.client_id == current.client_id
            && identity.grant_id == current.grant_id)
            .then_some(current))
    }
}

#[derive(Clone)]
struct Worker {
    pool: PgPool,
    actions: Arc<Actions>,
}
impl oxidt_jobs::Handler for Worker {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    async fn execute(&self, job: &oxidt_jobs::Job) -> Result<(), oxidt_jobs::JobFailure> {
        self.actions.execute_job(job, &DemoIdentity).await
    }
    async fn schedule(&self) -> Result<(), sqlx::Error> {
        Ok(())
    }
}

#[page("/")]
async fn home() -> topcoat::Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head><title>"Durable agent actions"</title></head>
            <body>
                <h1>"Durable agent actions"</h1>
                <p>
                    "Connect your MCP client to /mcp using AGENT_DEMO_TOKEN. Request add_note, then review its request ID here."
                </p>
                <p>"Review login: owner, with AGENT_REVIEW_TOKEN as the password."</p>
                <form action="/review" method="get">
                    <label>
                        "Request ID "
                        <input name="id" required=(true) />
                    </label>
                    <button type="submit">"Review action"</button>
                </form>
            </body>
        </html>
    })
}

#[query_params]
struct ReviewQuery {
    id: Uuid,
}

#[page("/review")]
async fn review_page(cx: &Cx) -> topcoat::Result<impl View> {
    let id = query_params::<ReviewQuery>(cx)
        .map_err(|_| topcoat::Error::msg("Invalid request ID"))?
        .id;
    let actions = request::extensions(cx)
        .get::<Arc<Actions>>()
        .expect("actions extension");
    let reviewer = request::extensions(cx)
        .get::<Reviewer>()
        .expect("authenticated reviewer");
    let row = actions
        .review(reviewer, id)
        .await
        .map_err(|_| topcoat::Error::msg("Request is unavailable"))?;
    let allowances = actions
        .allowances(reviewer)
        .await
        .map_err(|_| topcoat::Error::msg("Allowances are unavailable"))?;
    let allowable = row.definition["allowances"] == true;
    let arguments = serde_json::to_string_pretty(&row.arguments)?;
    let result = row
        .result
        .as_ref()
        .map(serde_json::to_string_pretty)
        .transpose()?;
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head><title>"Review agent action"</title></head>
            <body>
                <h1>"Review agent action"</h1>
                <p>
                    "Action: "
                    (&row.name)
                    " · Version: "
                    (row.definition["version"].as_str().unwrap_or(""))
                </p>
                <p>
                    "Agent: "
                    (&row.client_id)
                    " · Tenant: "
                    (&row.tenant_id)
                </p>
                <p>
                    "Status: "
                    (&row.status)
                </p>
                <pre>(arguments)</pre>
                if row.status == "pending" {
                    <form method="post" action="/review/decision">
                        <input type="hidden" name="id" value=(id.to_string()) />
                        <button name="decision" value="approve" type="submit">
                            "Approve action"
                        </button>
                        if allowable {
                            <button name="decision" value="allow" type="submit">
                                "Approve and allow for 1 hour"
                            </button>
                        }
                        <button name="decision" value="reject" type="submit">
                            "Reject action"
                        </button>
                    </form>
                    if allowable {
                        <p>
                            "Allowing skips review of this action from this agent for 1 hour, whatever its arguments."
                        </p>
                    }
                }
                if let Some(result) = result {
                    <pre>(result)</pre>
                }
                if !allowances.is_empty() {
                    <h2>"Active allowances"</h2>
                }
                for allowance in &allowances {
                    <form method="post" action="/review/allowance/revoke">
                        <input type="hidden" name="id" value=(id.to_string()) />
                        <input
                            type="hidden"
                            name="allowance"
                            value=(allowance.id.to_string())
                        />
                        (&allowance.name)
                        " · Agent: "
                        (&allowance.client_id)
                        " · Until: "
                        (allowance.expires_at.to_rfc3339())
                        " "
                        <button type="submit">"Revoke"</button>
                    </form>
                }
                <p><a href=(format!("/review?id={id}"))>"Refresh status"</a></p>
            </body>
        </html>
    })
}

#[derive(Deserialize)]
struct Decision {
    id: Uuid,
    decision: String,
}
async fn decide(
    Extension(actions): Extension<Arc<Actions>>,
    Extension(reviewer): Extension<Reviewer>,
    Form(input): Form<Decision>,
) -> Response {
    let outcome = match input.decision.as_str() {
        "approve" => {
            actions
                .decide(&reviewer, input.id, true, &DemoIdentity)
                .await
        }
        "reject" => {
            actions
                .decide(&reviewer, input.id, false, &DemoIdentity)
                .await
        }
        "allow" => {
            actions
                .approve_and_allow(
                    &reviewer,
                    input.id,
                    Duration::from_secs(3600),
                    &DemoIdentity,
                )
                .await
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match outcome {
        Ok(_) => Redirect::to(&format!("/review?id={}", input.id)).into_response(),
        Err(_) => (
            StatusCode::CONFLICT,
            "Request is unavailable or no longer awaiting this decision",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct Revocation {
    id: Uuid,
    allowance: Uuid,
}
async fn revoke(
    Extension(actions): Extension<Arc<Actions>>,
    Extension(reviewer): Extension<Reviewer>,
    Form(input): Form<Revocation>,
) -> Response {
    match actions.revoke_allowance(&reviewer, input.allowance).await {
        Ok(()) => Redirect::to(&format!("/review?id={}", input.id)).into_response(),
        Err(_) => (StatusCode::CONFLICT, "Allowance is unavailable").into_response(),
    }
}

/// Compares SHA-256 digests, so response timing reveals nothing about the expected credential.
fn same_credential(given: Option<&HeaderValue>, expected: &HeaderValue) -> bool {
    given.is_some_and(|given| {
        Sha256::digest(given.as_bytes()) == Sha256::digest(expected.as_bytes())
    })
}

fn review_routes(actions: Arc<Actions>, review_credential: HeaderValue) -> Router {
    let pages = topcoat::router::Router::builder().page(review_page).build();
    Router::new()
        .route_service("/review", topcoat::router::tower::TowerService::new(pages))
        .route("/review/decision", post(decide))
        .route("/review/allowance/revoke", post(revoke))
        .layer(Extension(actions))
        .layer(middleware::from_fn(move |mut req: Request, next: Next| {
            let valid =
                same_credential(req.headers().get(header::AUTHORIZATION), &review_credential);
            async move {
                if !valid {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [(header::WWW_AUTHENTICATE, "Basic realm=\"Action review\"")],
                    )
                        .into_response();
                }
                // Separate browser-only decision path. Origin checks prevent cross-site form posts.
                if req.method() == axum::http::Method::POST
                    && req
                        .headers()
                        .get(header::ORIGIN)
                        .and_then(|h| h.to_str().ok())
                        != Some("http://127.0.0.1:8098")
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                req.extensions_mut().insert(Reviewer {
                    user_id: "demo-owner".into(),
                    tenant_id: "demo-tenant".into(),
                });
                let mut response = next.run(req).await;
                let headers = response.headers_mut();
                headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                headers.insert(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("frame-ancestors 'none'"),
                );
                response
            }
        }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    if std::env::args().any(|arg| arg == "--init") {
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(include_str!("../../oxidt-jobs/schema.sql"))
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(include_str!("../schema.sql"))
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql("CREATE TABLE agent_demo_notes(id UUID PRIMARY KEY,tenant_id TEXT NOT NULL,text TEXT NOT NULL)").execute(&mut *tx).await?;
        tx.commit().await?;
        eprintln!("Created durable demo tables. Run again without --init to serve.");
        return Ok(());
    }
    let agent_token = std::env::var("AGENT_DEMO_TOKEN")?;
    let review_token = std::env::var("AGENT_REVIEW_TOKEN")?;
    if agent_token.len() < 32 || review_token.len() < 32 || agent_token == review_token {
        return Err("Use distinct AGENT_DEMO_TOKEN and AGENT_REVIEW_TOKEN values, at least 32 characters each".into());
    }
    let agent_credential = HeaderValue::from_str(&format!("Bearer {agent_token}"))?;
    let review_credential = HeaderValue::from_str(&format!(
        "Basic {}",
        STANDARD.encode(format!("owner:{review_token}"))
    ))?;
    let mut agent = Agent::new();
    let mut actions = Actions::new(pool.clone());
    actions.register(
        &mut agent,
        Capability::new(
            "add_note",
            "Save a note in your tenant's notebook",
            "notes:write",
            Effect::Write,
        )
        .with_allowances(),
        SaveNote,
    )?;
    let actions = Arc::new(actions);
    actions.register_status_tool(&mut agent, "actions:read")?;
    let mcp = oxidt_agent::router(
        Arc::new(agent),
        HttpConfig {
            allowed_hosts: vec!["127.0.0.1".into()],
            // MCP clients are not browsers: reject any request carrying an Origin.
            allowed_origins: Vec::new(),
            www_authenticate: HeaderValue::from_static("Bearer realm=\"Agent demo\""),
        },
        move |headers| {
            let valid = same_credential(headers.get(header::AUTHORIZATION), &agent_credential);
            async move {
                if valid {
                    Ok(principal())
                } else {
                    Err(AuthError::Unauthorized)
                }
            }
        },
    );
    let pages = topcoat::router::Router::builder()
        .page(home)
        .route(oxidt_agent::topcoat_route(mcp))
        .build();
    let app = Router::new()
        .merge(review_routes(actions.clone(), review_credential))
        .fallback_service(topcoat::router::tower::TowerService::new(pages));
    // Bind before starting workers so a failed bind cannot leave a worker running.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8098").await?;
    let (stop, worker) = oxidt_jobs::spawn(Worker { pool, actions }, 1);
    eprintln!("Durable Topcoat demo: http://127.0.0.1:8098");
    let stopping = stop.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown().await;
            let _ = stopping.send(true);
        })
        .await;
    let _ = stop.send(true);
    worker.await?;
    result?;
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
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn agent_token_and_cross_origin_posts_cannot_approve() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .unwrap();
        let app = review_routes(
            Arc::new(Actions::new(pool)),
            HeaderValue::from_static("Basic reviewer-credential"),
        );
        for (credential, origin, expected) in [
            (
                "Bearer agent-credential",
                "http://127.0.0.1:8098",
                StatusCode::UNAUTHORIZED,
            ),
            (
                "Basic reviewer-credential",
                "http://evil.test",
                StatusCode::FORBIDDEN,
            ),
            ("Basic reviewer-credential", "null", StatusCode::FORBIDDEN),
        ] {
            let req = Request::builder()
                .method("POST")
                .uri("/review/decision")
                .header("authorization", credential)
                .header("origin", origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
        }
    }
}
