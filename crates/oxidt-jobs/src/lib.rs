//! Durable, at-least-once jobs in one Postgres table, `background_jobs`
//! (see `schema.sql`).
//!
//! Claims use SKIP LOCKED; a lease token fences acknowledgements from old
//! workers. The app owns the typed task enum, its handlers and the recurring
//! schedule, through [`Handler`]; this crate owns the SQL and the worker loop.
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use std::future::Future;
use std::time::Duration;
use uuid::Uuid;

/// A running attempt gets this long, shorter than the lease below.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
const LEASE_SECS: i32 = 90;
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
    pub payload: serde_json::Value,
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
    sqlx::query("UPDATE background_jobs SET status='failed', last_error='Worker lease expired', finished_at=NOW(), lease_token=NULL, lease_until=NULL WHERE status='running' AND lease_until < NOW() AND attempts >= max_attempts")
        .execute(pool).await?;
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
        RETURNING j.id, j.owner_id, j.payload, j.lease_token
    "#,
    )
    .bind(Uuid::new_v4())
    .bind(LEASE_SECS)
    .fetch_optional(pool)
    .await
}

/// Acknowledge an attempt. A no-op if the lease has since passed to another
/// worker.
pub async fn finish(
    pool: &PgPool,
    job: &Job,
    outcome: Result<(), JobFailure>,
) -> Result<(), sqlx::Error> {
    let (error, retry_after) = match outcome {
        Ok(()) => (None, 0),
        Err(JobFailure::Safe(e)) => (Some(e), 0),
        Err(JobFailure::RetryAfter(e, secs)) => (Some(e), i32::try_from(secs).unwrap_or(i32::MAX)),
    };
    sqlx::query(r#"UPDATE background_jobs SET
        status=CASE WHEN $3::TEXT IS NULL THEN 'completed' WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
        last_error=$3,
        run_at=CASE WHEN $3::TEXT IS NOT NULL AND attempts < max_attempts THEN NOW()+make_interval(secs => GREATEST($4::INT, LEAST(3600, 5 * power(2, attempts))::INT)) ELSE run_at END,
        finished_at=CASE WHEN $3::TEXT IS NULL OR attempts >= max_attempts THEN NOW() ELSE NULL END,
        payload=CASE WHEN $3::TEXT IS NULL THEN '{}'::JSONB ELSE payload END,
        lease_until=NULL, lease_token=NULL
        WHERE id=$1 AND lease_token=$2 AND status='running'"#)
        .bind(job.id).bind(job.lease_token).bind(error).bind(retry_after).execute(pool).await?;
    Ok(())
}

/// What the app plugs into the worker loop.
pub trait Handler: Clone + Send + Sync + 'static {
    fn pool(&self) -> &PgPool;
    /// Run one attempt: deserialize `job.payload` into the app's task enum and
    /// dispatch.
    fn execute(&self, job: &Job) -> impl Future<Output = Result<(), JobFailure>> + Send;
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
        if schedules && let Err(error) = handler.schedule().await {
            tracing::error!(%error, "Job scheduler failed");
        }
        match claim(handler.pool()).await {
            Ok(Some(job)) => {
                let outcome = tokio::time::timeout(ATTEMPT_TIMEOUT, handler.execute(&job))
                    .await
                    .unwrap_or(Err(JobFailure::Safe("Job timed out")));
                if let Err(JobFailure::Safe(reason) | JobFailure::RetryAfter(reason, _)) = &outcome
                {
                    tracing::warn!(job_id=%job.id, reason, "Job attempt failed");
                }
                if let Err(error) = finish(handler.pool(), &job, outcome).await {
                    tracing::error!(%error, job_id=%job.id, "Job acknowledgement failed");
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => tracing::error!(%error, "Job claim failed"),
        }
        tokio::select! { _ = stopping.changed() => break, _ = tokio::time::sleep(IDLE_POLL) => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn concurrent_workers_claim_once_and_respect_schedule(pool: PgPool) {
        setup(&pool).await;
        add(&pool, 0, Utc::now(), None).await;
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
        add(&pool, 0, Utc::now(), None).await;
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
        enqueue(
            &mut tx,
            None,
            "test",
            serde_json::json!({}),
            0,
            Utc::now(),
            None,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert!(claim(&pool).await.unwrap().is_none());
        tokio::join!(
            add(&pool, 0, Utc::now(), Some("daily:1")),
            add(&pool, 0, Utc::now(), Some("daily:1"))
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
        add(&pool, 10, Utc::now(), None).await;
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
        add(&pool, 0, Utc::now(), None).await;
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
                Utc::now(),
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
        enqueue(&mut conn, None, "bad", fail, 0, Utc::now(), None)
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
}
