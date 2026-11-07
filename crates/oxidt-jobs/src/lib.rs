//! Durable, at-least-once jobs in one Postgres table, `background_jobs`
//! (see `schema.sql`).
//!
//! Claims use SKIP LOCKED; a lease token fences acknowledgements from old
//! workers. The app owns the typed task enum, its handlers and the recurring
//! schedule, through [`Handler`]; this crate owns the SQL and the worker loop.
use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use sqlx::{PgConnection, PgPool};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

/// The `oxidt-monitor` that [`Stats::kpis`] builds on. Import it from here: a
/// separate dependency at another tag makes `Kpi` a different type.
#[cfg(feature = "monitor")]
pub use oxidt_monitor;

/// A running attempt gets this long unless [`Handler::attempt_timeout`] says otherwise.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
const LEASE_SECS: i32 = 90;
/// A running attempt renews its lease this often. Two periods without a
/// confirmed renewal drop the attempt, a period before the lease can lapse and
/// another worker can claim the job.
const LEASE_RENEWAL: Duration = Duration::from_secs(30);
const IDLE_POLL: Duration = Duration::from_secs(2);

/// Queue `payload` (by convention tagged `"type": kind`) to run at `run_at`;
/// higher `priority` runs first among due jobs. A taken `dedupe_key` makes
/// this a no-op. Takes a connection so callers can enqueue in their domain
/// transaction.
pub async fn enqueue(
    conn: &mut PgConnection,
    owner: Option<Uuid>,
    kind: &str,
    payload: serde_json::Value,
    priority: i32,
    run_at: DateTime<Utc>,
    dedupe_key: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO background_jobs (id, owner_id, kind, payload, priority, run_at, dedupe_key) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (dedupe_key) DO NOTHING")
        .bind(Uuid::new_v4()).bind(owner).bind(kind).bind(payload).bind(priority)
        .bind(run_at).bind(dedupe_key).execute(conn).await?;
    Ok(())
}

/// One claimed attempt. Only the holder of its lease can acknowledge it.
#[derive(sqlx::FromRow)]
pub struct Job {
    pub id: Uuid,
    pub owner_id: Option<Uuid>,
    pub kind: String,
    pub payload: serde_json::Value,
    /// Counted at claim, so this attempt is the last when `attempts >= max_attempts`.
    pub attempts: i32,
    pub max_attempts: i32,
    lease_token: Uuid,
}

/// Why an attempt failed. The message is a safe handler category, never
/// provider responses, payloads or credentials: it is stored in `last_error`.
#[derive(Debug)]
pub enum JobFailure {
    /// Retry with exponential backoff.
    Safe(&'static str),
    /// Retry no sooner than this many seconds (e.g. a throttled provider).
    RetryAfter(&'static str, u32),
}
impl From<&'static str> for JobFailure {
    fn from(value: &'static str) -> Self {
        Self::Safe(value)
    }
}

pub async fn claim(pool: &PgPool) -> Result<Option<Job>, sqlx::Error> {
    // A crash on the final attempt must become visible as a failure too.
    let lapsed: Vec<(Uuid, String)> = sqlx::query_as("UPDATE background_jobs SET status='failed', last_error='Worker lease expired', finished_at=lease_until, lease_token=NULL, lease_until=NULL WHERE status='running' AND lease_until < NOW() AND attempts >= max_attempts RETURNING id, kind")
        .fetch_all(pool).await?;
    for (job_id, kind) in lapsed {
        tracing::error!(%job_id, kind, reason = "Worker lease expired", "Job failed permanently");
    }
    sqlx::query_as::<_, Job>(
        r#"
        WITH candidate AS (
            SELECT id FROM background_jobs
            WHERE attempts < max_attempts AND
              ((status='pending' AND run_at <= NOW()) OR (status='running' AND lease_until < NOW()))
            ORDER BY priority DESC, run_at, created_at FOR UPDATE SKIP LOCKED LIMIT 1
        )
        UPDATE background_jobs j SET status='running', attempts=attempts+1,
            lease_until=NOW()+make_interval(secs => $2), lease_token=$1
        FROM candidate WHERE j.id=candidate.id
        RETURNING j.id, j.owner_id, j.kind, j.payload, j.attempts, j.max_attempts, j.lease_token
    "#,
    )
    .bind(Uuid::new_v4())
    .bind(LEASE_SECS)
    .fetch_optional(pool)
    .await
}

/// Extend a running attempt's lease. False means it is no longer this
/// attempt's to extend.
async fn renew(pool: &PgPool, job: &Job) -> Result<bool, sqlx::Error> {
    let renewed = sqlx::query("UPDATE background_jobs SET lease_until=NOW()+make_interval(secs => $3) WHERE id=$1 AND lease_token=$2 AND status='running'")
        .bind(job.id).bind(job.lease_token).bind(LEASE_SECS).execute(pool).await?;
    Ok(renewed.rows_affected() == 1)
}

/// Acknowledge an attempt. A no-op if the lease has since passed to another
/// worker.
pub async fn finish(
    pool: &PgPool,
    job: &Job,
    outcome: Result<(), JobFailure>,
) -> Result<(), sqlx::Error> {
    acknowledge(pool, job, outcome).await.map(|_| ())
}

/// False means the lease had passed on, so nothing was recorded.
async fn acknowledge(
    pool: &PgPool,
    job: &Job,
    outcome: Result<(), JobFailure>,
) -> Result<bool, sqlx::Error> {
    let (error, retry_after) = match outcome {
        Ok(()) => (None, 0),
        Err(JobFailure::Safe(e)) => (Some(e), 0),
        Err(JobFailure::RetryAfter(e, secs)) => (Some(e), i32::try_from(secs).unwrap_or(i32::MAX)),
    };
    let updated = sqlx::query(r#"UPDATE background_jobs SET
        status=CASE WHEN $3::TEXT IS NULL THEN 'completed' WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
        last_error=$3,
        run_at=CASE WHEN $3::TEXT IS NOT NULL AND attempts < max_attempts THEN NOW()+make_interval(secs => GREATEST($4::INT, LEAST(3600, 5 * power(2, attempts))::INT)) ELSE run_at END,
        finished_at=CASE WHEN $3::TEXT IS NULL OR attempts >= max_attempts THEN NOW() ELSE NULL END,
        payload=CASE WHEN $3::TEXT IS NULL THEN '{}'::JSONB ELSE payload END,
        lease_until=NULL, lease_token=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running'"#)
        .bind(job.id).bind(job.lease_token).bind(error).bind(retry_after).execute(pool).await?;
    Ok(updated.rows_affected() == 1)
}

/// Delete completed jobs finished more than `older_than` ago, returning how many
/// went. Deleting a job frees its `dedupe_key`, so `older_than` must outlast the
/// longest key bucket or that work runs twice. Failed jobs stay, for debugging.
pub async fn prune(pool: &PgPool, older_than: Duration) -> Result<u64, sqlx::Error> {
    let pruned = sqlx::query("DELETE FROM background_jobs WHERE status='completed' AND finished_at < NOW()-make_interval(secs => $1)")
        .bind(older_than.as_secs_f64())
        .execute(pool)
        .await?;
    Ok(pruned.rows_affected())
}

/// The queue right now, from the table alone, so it also tells on a dead worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Stats {
    /// Ready to claim now, including attempts whose worker stopped renewing.
    pub due: i64,
    /// Waiting for a later `run_at`, including backoff.
    pub scheduled: i64,
    /// Held by a worker with a live lease.
    pub running: i64,
    /// Out of attempts in the last 24 hours, including a final attempt whose
    /// worker died, before any worker has marked it failed.
    pub failed_24h: i64,
    /// How long the oldest due job has waited, 0 when none is. Alert on this: it
    /// climbs whether the worker stopped or just can't keep up.
    pub oldest_due_seconds: i64,
}

/// Read [`Stats`]. Scans the table, so call it on demand, not per job.
pub async fn stats(pool: &PgPool) -> Result<Stats, sqlx::Error> {
    sqlx::query_as(
        r#"
        WITH jobs AS (
            SELECT status, run_at, finished_at, lease_until, attempts >= max_attempts AS exhausted,
                status='running' AND lease_until < NOW() AS lapsed,
                (status='pending' AND run_at <= NOW())
                    OR (status='running' AND lease_until < NOW() AND attempts < max_attempts) AS due
            FROM background_jobs
        )
        SELECT
            count(*) FILTER (WHERE due) AS due,
            count(*) FILTER (WHERE status='pending' AND NOT due) AS scheduled,
            count(*) FILTER (WHERE status='running' AND NOT lapsed) AS running,
            count(*) FILTER (WHERE (status='failed' AND finished_at > NOW()-INTERVAL '24 hours')
                OR (lapsed AND exhausted AND lease_until > NOW()-INTERVAL '24 hours')) AS failed_24h,
            COALESCE(EXTRACT(EPOCH FROM NOW()-min(run_at) FILTER (WHERE due))::BIGINT, 0) AS oldest_due_seconds
        FROM jobs
    "#,
    )
    .fetch_one(pool)
    .await
}

#[cfg(feature = "monitor")]
impl Stats {
    /// The queue as `oxidt-monitor` KPIs, for the app's `MonitorSource`.
    pub fn kpis(&self) -> Vec<oxidt_monitor::Kpi> {
        use oxidt_monitor::Kpi;
        vec![
            Kpi::new("jobs_due", "Jobs due", self.due),
            Kpi::new("jobs_scheduled", "Jobs scheduled", self.scheduled),
            Kpi::new("jobs_running", "Jobs running", self.running),
            Kpi::new("jobs_failed_24h", "Jobs failed (24h)", self.failed_24h),
            Kpi::new(
                "jobs_oldest_due_seconds",
                "Oldest due job (s)",
                self.oldest_due_seconds,
            ),
        ]
    }
}

/// What the app plugs into the worker loop.
pub trait Handler: Clone + Send + Sync + 'static {
    fn pool(&self) -> &PgPool;
    /// Run one attempt: deserialize `job.payload` into the app's task enum and
    /// dispatch.
    fn execute(&self, job: &Job) -> impl Future<Output = Result<(), JobFailure>> + Send;
    /// How long this attempt may run. The lease is renewed meanwhile, so this
    /// can exceed it. Shutdown waits for a running attempt.
    fn attempt_timeout(&self, _job: &Job) -> Duration {
        ATTEMPT_TIMEOUT
    }
    /// Insert recurring jobs, deduplicated by a time-bucketed `dedupe_key` so
    /// replicas racing here enqueue once. Called by the first worker each poll.
    fn schedule(&self) -> impl Future<Output = Result<(), sqlx::Error>> + Send;
}

/// Start `workers` loops (0 makes a web-only node that only enqueues). Start
/// only in main, not router assembly: HTTP tests must not start workers. Send
/// `true` on the returned sender to stop, then await the handle.
pub fn spawn<H: Handler>(
    handler: H,
    workers: usize,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let loops: Vec<_> = (0..workers)
        .map(|i| tokio::spawn(work(handler.clone(), stopping.clone(), i == 0)))
        .collect();
    let handle = tokio::spawn(async move {
        for worker in loops {
            let _ = worker.await;
        }
    });
    (stop, handle)
}

/// One worker loop; only the first also schedules recurring work.
async fn work<H: Handler>(
    handler: H,
    mut stopping: tokio::sync::watch::Receiver<bool>,
    schedules: bool,
) {
    loop {
        if *stopping.borrow() {
            break;
        }
        if schedules {
            match AssertUnwindSafe(handler.schedule()).catch_unwind().await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!(%error, "Job scheduler failed"),
                Err(_) => tracing::error!("Job scheduler panicked"),
            }
        }
        match claim(handler.pool()).await {
            Ok(Some(job)) => {
                let span = tracing::info_span!(
                    "job.attempt",
                    job.id = %job.id,
                    job.kind = %job.kind,
                    job.attempt = job.attempts,
                    job.outcome = tracing::field::Empty,
                );
                run(&handler, &job).instrument(span).await;
                continue;
            }
            Ok(None) => {}
            Err(error) => tracing::error!(%error, "Job claim failed"),
        }
        tokio::select! { _ = stopping.changed() => break, _ = tokio::time::sleep(IDLE_POLL) => {} }
    }
}

/// Run a claimed job and acknowledge it, reporting what happened. Fields repeat
/// on the events because not every subscriber shows the span's.
async fn run<H: Handler>(handler: &H, job: &Job) {
    let started = Instant::now();
    let span = tracing::Span::current();
    let Some(outcome) = attempt(handler, job, LEASE_RENEWAL).await else {
        span.record("job.outcome", "lease_lost");
        return;
    };
    let (job_id, kind) = (job.id, job.kind.as_str());
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let failure = match &outcome {
        Ok(()) => None,
        Err(JobFailure::Safe(reason) | JobFailure::RetryAfter(reason, _)) => Some(*reason),
    };
    // Only what was recorded is reported as final.
    match (acknowledge(handler.pool(), job, outcome).await, failure) {
        (Err(error), _) => {
            span.record("job.outcome", "unacknowledged");
            tracing::error!(%error, %job_id, kind, "Job acknowledgement failed");
        }
        (Ok(false), _) => {
            span.record("job.outcome", "lease_lost");
            tracing::warn!(%job_id, kind, "Job lease lost, result not recorded");
        }
        (Ok(true), None) => {
            span.record("job.outcome", "completed");
            tracing::info!(%job_id, kind, duration_ms, "Job completed");
        }
        (Ok(true), Some(reason)) if job.attempts >= job.max_attempts => {
            span.record("job.outcome", "failed");
            tracing::error!(%job_id, kind, duration_ms, reason, "Job failed permanently");
        }
        (Ok(true), Some(reason)) => {
            span.record("job.outcome", "retrying");
            tracing::warn!(%job_id, kind, duration_ms, reason, "Job attempt failed");
        }
    }
}

/// Run one attempt, renewing its lease. A panic or timeout is a failed
/// attempt; `None` means the lease was lost or could not be confirmed, so the
/// attempt is dropped unacknowledged.
async fn attempt<H: Handler>(
    handler: &H,
    job: &Job,
    renew_every: Duration,
) -> Option<Result<(), JobFailure>> {
    let run = tokio::time::timeout(
        handler.attempt_timeout(job),
        AssertUnwindSafe(handler.execute(job)).catch_unwind(),
    );
    let keep_lease = async {
        let mut give_up_at = Instant::now() + renew_every * 2;
        loop {
            tokio::time::sleep_until(give_up_at.min(Instant::now() + renew_every)).await;
            let started = Instant::now();
            if started >= give_up_at {
                break;
            }
            match tokio::time::timeout_at(give_up_at, renew(handler.pool(), job)).await {
                Ok(Ok(true)) => give_up_at = started + renew_every * 2,
                Ok(Ok(false)) | Err(_) => break,
                Ok(Err(error)) => {
                    tracing::error!(%error, job_id=%job.id, "Job lease renewal failed");
                }
            }
        }
    };
    tokio::select! {
        outcome = run => Some(match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(JobFailure::Safe("Job panicked")),
            Err(_) => Err(JobFailure::Safe("Job timed out")),
        }),
        () = keep_lease => {
            tracing::warn!(job_id=%job.id, "Job lease lost, dropping attempt");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Due at once even when the database clock trails this one.
    fn due() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::seconds(5)
    }
    async fn setup(pool: &PgPool) {
        sqlx::raw_sql(include_str!("../schema.sql"))
            .execute(pool)
            .await
            .unwrap();
    }
    async fn add(pool: &PgPool, priority: i32, when: DateTime<Utc>, dedupe: Option<&str>) {
        let payload = serde_json::json!({ "type": "test", "priority": priority });
        enqueue(
            &mut pool.acquire().await.unwrap(),
            None,
            "test",
            payload,
            priority,
            when,
            dedupe,
        )
        .await
        .unwrap();
    }
    async fn status(pool: &PgPool) -> String {
        sqlx::query_scalar("SELECT status FROM background_jobs")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    async fn prune_deletes_only_old_completed_jobs(pool: PgPool) {
        setup(&pool).await;
        for (key, status, age_hours) in [
            ("old", "completed", 48),
            ("recent", "completed", 1),
            ("failed", "failed", 48),
        ] {
            add(&pool, 0, due(), Some(key)).await;
            sqlx::query("UPDATE background_jobs SET status=$2, finished_at=NOW()-make_interval(hours => $3) WHERE dedupe_key=$1")
                .bind(key)
                .bind(status)
                .bind(age_hours)
                .execute(&pool)
                .await
                .unwrap();
        }
        add(&pool, 0, due(), Some("pending")).await;

        let pruned = prune(&pool, Duration::from_secs(24 * 3600)).await.unwrap();

        assert_eq!(pruned, 1);
        let kept: Vec<String> =
            sqlx::query_scalar("SELECT dedupe_key FROM background_jobs ORDER BY dedupe_key")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(kept, ["failed", "pending", "recent"]);
    }

    #[sqlx::test(migrations = false)]
    async fn concurrent_workers_claim_once_and_respect_schedule(pool: PgPool) {
        setup(&pool).await;
        add(&pool, 0, due(), None).await;
        let (a, b) = tokio::join!(claim(&pool), claim(&pool));
        assert_eq!(
            usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
            1
        );
        add(&pool, 0, Utc::now() + chrono::Duration::hours(1), None).await;
        assert!(claim(&pool).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn expired_leases_retry_and_fence_old_workers(pool: PgPool) {
        setup(&pool).await;
        add(&pool, 0, due(), None).await;
        let first = claim(&pool).await.unwrap().unwrap();
        sqlx::query("UPDATE background_jobs SET lease_until=NOW()-INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        let second = claim(&pool).await.unwrap().unwrap();
        finish(&pool, &first, Ok(())).await.unwrap();
        assert_eq!(status(&pool).await, "running");
        finish(&pool, &second, Err("Delivery failed".into()))
            .await
            .unwrap();
        assert!(claim(&pool).await.unwrap().is_none());
        sqlx::query("UPDATE background_jobs SET attempts=max_attempts-1, run_at=NOW()")
            .execute(&pool)
            .await
            .unwrap();
        let last = claim(&pool).await.unwrap().unwrap();
        finish(&pool, &last, Err("Delivery failed".into()))
            .await
            .unwrap();
        assert_eq!(status(&pool).await, "failed");
    }

    #[sqlx::test(migrations = false)]
    async fn enqueue_rolls_back_and_dedupes(pool: PgPool) {
        setup(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        enqueue(&mut tx, None, "test", serde_json::json!({}), 0, due(), None)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(claim(&pool).await.unwrap().is_none());
        tokio::join!(
            add(&pool, 0, due(), Some("daily:1")),
            add(&pool, 0, due(), Some("daily:1"))
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM background_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test(migrations = false)]
    async fn higher_priority_runs_first_among_due_jobs(pool: PgPool) {
        setup(&pool).await;
        add(&pool, 0, Utc::now() - chrono::Duration::minutes(5), None).await;
        add(&pool, 10, due(), None).await;
        add(&pool, 10, Utc::now() + chrono::Duration::hours(1), None).await;
        let first = claim(&pool).await.unwrap().unwrap();
        assert_eq!(first.payload["priority"], 10);
        let second = claim(&pool).await.unwrap().unwrap();
        assert_eq!(second.payload["priority"], 0);
        assert!(claim(&pool).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn retry_after_delays_past_the_backoff(pool: PgPool) {
        setup(&pool).await;
        add(&pool, 0, due(), None).await;
        let job = claim(&pool).await.unwrap().unwrap();
        finish(&pool, &job, Err(JobFailure::RetryAfter("Throttled", 600)))
            .await
            .unwrap();
        let (state, delay, error): (String, f64, String) = sqlx::query_as(
            "SELECT status, EXTRACT(EPOCH FROM run_at - NOW())::FLOAT8, last_error FROM background_jobs",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "pending");
        assert!(delay > 590.0, "backoff alone would be 10s, got {delay}");
        assert_eq!(error, "Throttled");
    }

    #[derive(Clone)]
    struct Recorder(PgPool);
    impl Handler for Recorder {
        fn pool(&self) -> &PgPool {
            &self.0
        }
        async fn execute(&self, job: &Job) -> Result<(), JobFailure> {
            match job.payload["fail"].as_bool() {
                Some(true) => Err("Told to fail".into()),
                _ => Ok(()),
            }
        }
        async fn schedule(&self) -> Result<(), sqlx::Error> {
            let mut conn = self.0.acquire().await?;
            enqueue(
                &mut conn,
                None,
                "tick",
                serde_json::json!({}),
                0,
                due(),
                Some("tick:once"),
            )
            .await
        }
    }

    #[sqlx::test(migrations = false)]
    async fn workers_run_scheduled_and_queued_jobs_then_stop(pool: PgPool) {
        setup(&pool).await;
        let mut conn = pool.acquire().await.unwrap();
        let fail = serde_json::json!({ "fail": true });
        enqueue(&mut conn, None, "bad", fail, 0, due(), None)
            .await
            .unwrap();
        drop(conn);
        let (stop, handle) = spawn(Recorder(pool.clone()), 3);
        let summary = || async {
            sqlx::query_as::<_, (String, String)>(
                "SELECT kind, status FROM background_jobs ORDER BY kind",
            )
            .fetch_all(&pool)
            .await
            .unwrap()
        };
        let mut rows = summary().await;
        for _ in 0..50 {
            if rows.len() == 2
                && rows.iter().all(|(_, s)| s != "running")
                && rows[1].1 == "completed"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            rows = summary().await;
        }
        assert_eq!(
            rows,
            [
                ("bad".into(), "pending".into()),
                ("tick".into(), "completed".into())
            ]
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }

    /// Does what the payload says, and optionally panics while scheduling.
    #[derive(Clone)]
    struct Scripted {
        pool: PgPool,
        panic_in_schedule: bool,
    }
    impl Handler for Scripted {
        fn pool(&self) -> &PgPool {
            &self.pool
        }
        async fn execute(&self, job: &Job) -> Result<(), JobFailure> {
            match job.payload["do"].as_str() {
                Some("panic") => panic!("told to panic"),
                Some("hang") => std::future::pending().await,
                _ => Ok(()),
            }
        }
        fn attempt_timeout(&self, job: &Job) -> Duration {
            job.payload["timeout_ms"]
                .as_u64()
                .map_or(ATTEMPT_TIMEOUT, Duration::from_millis)
        }
        async fn schedule(&self) -> Result<(), sqlx::Error> {
            assert!(!self.panic_in_schedule, "told to panic");
            Ok(())
        }
    }
    fn scripted(pool: &PgPool) -> Scripted {
        Scripted {
            pool: pool.clone(),
            panic_in_schedule: false,
        }
    }
    async fn add_scripted(pool: &PgPool, kind: &str, priority: i32, payload: serde_json::Value) {
        let mut conn = pool.acquire().await.unwrap();
        enqueue(&mut conn, None, kind, payload, priority, due(), None)
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn workers_survive_panics_in_jobs_and_schedule(pool: PgPool) {
        setup(&pool).await;
        add_scripted(&pool, "boom", 10, serde_json::json!({ "do": "panic" })).await;
        add_scripted(&pool, "next", 0, serde_json::json!({})).await;
        let handler = Scripted {
            panic_in_schedule: true,
            ..scripted(&pool)
        };
        let (stop, handle) = spawn(handler, 1);
        let summary = || async {
            sqlx::query_as::<_, (String, String, Option<String>)>(
                "SELECT kind, status, last_error FROM background_jobs ORDER BY kind",
            )
            .fetch_all(&pool)
            .await
            .unwrap()
        };
        let mut rows = summary().await;
        for _ in 0..50 {
            if rows[1].1 == "completed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            rows = summary().await;
        }
        assert_eq!(
            rows,
            [
                ("boom".into(), "pending".into(), Some("Job panicked".into())),
                ("next".into(), "completed".into(), None)
            ]
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn running_attempts_renew_their_lease_until_they_time_out(pool: PgPool) {
        setup(&pool).await;
        let payload = serde_json::json!({ "do": "hang", "timeout_ms": 1500 });
        add_scripted(&pool, "slow", 0, payload).await;
        let job = claim(&pool).await.unwrap().unwrap();
        sqlx::query("UPDATE background_jobs SET lease_until=NOW()+INTERVAL '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        let outcome = attempt(&scripted(&pool), &job, Duration::from_millis(500)).await;
        assert!(matches!(
            outcome,
            Some(Err(JobFailure::Safe("Job timed out")))
        ));
        let remaining: f64 = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM lease_until - NOW())::FLOAT8 FROM background_jobs",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(remaining > 60.0, "lease was not renewed: {remaining}s left");
    }

    #[sqlx::test(migrations = false)]
    async fn losing_the_lease_drops_the_attempt(pool: PgPool) {
        setup(&pool).await;
        add_scripted(&pool, "slow", 0, serde_json::json!({ "do": "hang" })).await;
        let job = claim(&pool).await.unwrap().unwrap();
        sqlx::query("UPDATE background_jobs SET lease_token=gen_random_uuid()")
            .execute(&pool)
            .await
            .unwrap();
        let handler = scripted(&pool);
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            attempt(&handler, &job, Duration::from_millis(50)),
        )
        .await
        .unwrap();
        assert!(outcome.is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn unconfirmed_renewals_drop_the_attempt(pool: PgPool) {
        setup(&pool).await;
        // Renewing errors at once on the closed pool and stalls on the unreachable one.
        for closed in [true, false] {
            add_scripted(&pool, "slow", 0, serde_json::json!({ "do": "hang" })).await;
            let job = claim(&pool).await.unwrap().unwrap();
            let unreachable = PgPool::connect_lazy("postgres://127.0.0.1:1/none").unwrap();
            if closed {
                unreachable.close().await;
            }
            let handler = Scripted {
                pool: unreachable,
                panic_in_schedule: false,
            };
            let outcome = tokio::time::timeout(
                Duration::from_secs(5),
                attempt(&handler, &job, Duration::from_millis(50)),
            )
            .await
            .unwrap();
            assert!(outcome.is_none());
        }
    }

    #[sqlx::test(migrations = false)]
    async fn stats_count_the_queue_and_age_of_the_oldest_due_job(pool: PgPool) {
        setup(&pool).await;
        let empty = stats(&pool).await.unwrap();
        assert_eq!(empty.due + empty.oldest_due_seconds, 0);

        add(&pool, 0, due(), None).await; // Claimed below, stays running.
        let running = claim(&pool).await.unwrap().unwrap();
        add(&pool, 0, due(), None).await; // Lease lapses below.
        let lapsed = claim(&pool).await.unwrap().unwrap();
        sqlx::query("UPDATE background_jobs SET lease_until=NOW()-INTERVAL '1 second', run_at=NOW()-INTERVAL '10 minutes' WHERE id=$1")
            .bind(lapsed.id).execute(&pool).await.unwrap();
        add(&pool, 0, Utc::now() - chrono::Duration::minutes(5), None).await;
        add(&pool, 0, Utc::now() + chrono::Duration::hours(1), None).await;
        add(&pool, 0, Utc::now() + chrono::Duration::hours(2), None).await;
        for age in ["1 hour", "2 days"] {
            sqlx::query("INSERT INTO background_jobs (id,kind,status,finished_at) VALUES ($1,'old','failed',NOW()-$2::INTERVAL)")
                .bind(Uuid::new_v4()).bind(age).execute(&pool).await.unwrap();
        }

        // Died on its final attempt, with no worker left to mark it failed.
        sqlx::query("INSERT INTO background_jobs (id,kind,status,attempts,run_at,lease_until) VALUES ($1,'dead','running',5,NOW()-INTERVAL '1 hour',NOW()-INTERVAL '1 second')")
            .bind(Uuid::new_v4()).execute(&pool).await.unwrap();

        sqlx::query("INSERT INTO background_jobs (id,kind,status,attempts,run_at,lease_until) VALUES ($1,'long-dead','running',5,NOW()-INTERVAL '3 days',NOW()-INTERVAL '2 days')")
            .bind(Uuid::new_v4()).execute(&pool).await.unwrap();

        let found = stats(&pool).await.unwrap();
        assert_eq!(
            (found.due, found.scheduled, found.running, found.failed_24h),
            (2, 2, 1, 2)
        );
        assert!((598..=610).contains(&found.oldest_due_seconds), "{found:?}");
        assert_eq!(running.kind, "test");
    }

    #[sqlx::test(migrations = false)]
    async fn a_lease_lost_long_ago_is_not_a_recent_failure(pool: PgPool) {
        setup(&pool).await;
        sqlx::query("INSERT INTO background_jobs (id,kind,status,attempts,lease_until) VALUES ($1,'long-dead','running',5,NOW()-INTERVAL '2 days')")
            .bind(Uuid::new_v4()).execute(&pool).await.unwrap();
        assert!(claim(&pool).await.unwrap().is_none());
        assert_eq!(status(&pool).await, "failed");
        assert_eq!(stats(&pool).await.unwrap().failed_24h, 0);
    }

    #[cfg(feature = "monitor")]
    #[test]
    fn kpis_keep_their_board_keys() {
        let stats = Stats {
            due: 1,
            scheduled: 2,
            running: 3,
            failed_24h: 4,
            oldest_due_seconds: 5,
        };
        let found: Vec<_> = stats.kpis().iter().map(|k| (k.key, k.value)).collect();
        assert_eq!(
            found,
            [
                ("jobs_due", 1),
                ("jobs_scheduled", 2),
                ("jobs_running", 3),
                ("jobs_failed_24h", 4),
                ("jobs_oldest_due_seconds", 5)
            ]
        );
    }
}
