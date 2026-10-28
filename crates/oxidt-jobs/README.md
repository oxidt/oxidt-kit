# oxidt-jobs

Durable, at-least-once jobs in one Postgres table. SKIP LOCKED claims, a lease
token that fences acknowledgements from old workers, priority, exponential
backoff (capped at an hour) with an optional retry-after, and a worker pool.

```toml
[dependencies]
oxidt-jobs = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-jobs-v0.1.0" }
```

## Why

Every oxidt app carried its own copy of the same 250-line `jobs.rs`, and the
copies drifted: priority in two, a worker pool in one, retry-after in another.
The SQL is the part that has to be right, so it lives here once.

## Using it

Copy `schema.sql` into a migration (add `REFERENCES users(id)` to `owner_id` if
you like). The crate never runs migrations.

The app keeps its typed task enum and implements `Handler`:

```rust
#[derive(Clone)]
struct Jobs(AppState);

impl oxidt_jobs::Handler for Jobs {
    fn pool(&self) -> &PgPool { &self.0.db.pool }
    async fn execute(&self, job: &oxidt_jobs::Job) -> Result<(), oxidt_jobs::JobFailure> {
        let task: Task = serde_json::from_value(job.payload.clone()).map_err(|_| "Invalid job payload")?;
        match task { /* … */ }
        Ok(())
    }
    async fn schedule(&self) -> Result<(), sqlx::Error> {
        // Recurring work: time-bucketed dedupe_key, so racing replicas insert once.
        Ok(())
    }
}

// In main only, never in router assembly:
let (stop, handle) = oxidt_jobs::spawn(Jobs(state), 1);
```

Enqueue inside the domain transaction with
`oxidt_jobs::enqueue(&mut tx, owner, task.kind(), payload, task.priority(), run_at, dedupe_key)`.

Failure messages land in `last_error`, so they are fixed categories
(`&'static str`), never provider responses or payloads. Attempts time out after
60 seconds; leases last 90.
