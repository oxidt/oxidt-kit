# oxidt-jobs

Durable, at-least-once jobs in one Postgres table. SKIP LOCKED claims, a lease
token that fences acknowledgements from old workers, priority, exponential
backoff (capped at an hour) with an optional retry-after, and a worker pool.

```toml
[dependencies]
oxidt-jobs = { git = "https://github.com/oxidt/oxidt-kit.git", tag = "oxidt-jobs-v0.1.4" }
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
(`&'static str`), never provider responses or payloads.

Attempts time out after 60 seconds; override `Handler::attempt_timeout` for
longer jobs. Leases last 90 seconds and renew every 30 while an attempt runs. A
worker drops the attempt if it loses the lease or goes 60 seconds without a
confirmed renewal, so two workers don't overlap during a database outage. Panics
count as failed attempts and the worker keeps running. Shutdown waits for a
running attempt.

## Cleaning up

Nothing deletes finished jobs for you. Call `oxidt_jobs::prune(&pool, age)` from a
daily job, with an age longer than your longest `dedupe_key` bucket: deleting a
job frees its key. Only completed jobs go; failed ones stay for debugging.

## Watching it

`oxidt_jobs::stats(&pool)` reads the queue from the table: jobs due, scheduled
and running, failures in the last 24 hours, and how long the oldest due job has
waited. Alert on `oldest_due_seconds`, which climbs when the worker stops as well
as when it falls behind. With the `monitor` feature, `Stats::kpis()` gives the
same numbers as `oxidt-monitor` KPIs. The crate is re-exported, so import it from
here instead of adding it as a dependency, which at another tag would make `Kpi`
a different type:

```rust
use oxidt_jobs::oxidt_monitor::{Kpi, MonitorSource};

async fn kpis(&self) -> Vec<Kpi> {
    match oxidt_jobs::stats(&self.0.db.pool).await {
        Ok(stats) => stats.kpis(),
        // Empty, not zeros: a zero backlog would read as healthy.
        Err(error) => {
            tracing::error!(%error, "Job stats failed");
            Vec::new()
        }
    }
}
```

Keep these out of `/health`: a backlog is a reason to look, not to restart.

Each attempt runs in a `job.attempt` span with `job.id`, `job.kind`,
`job.attempt` and `job.outcome` (`completed`, `retrying`, `failed`, `lease_lost`
or `unacknowledged`). Outcomes are logged once recorded. Attempts log at `info` on success, `warn` when they will retry and
`error` with "Job failed permanently" when out of attempts, including a worker
that died on its last one.
