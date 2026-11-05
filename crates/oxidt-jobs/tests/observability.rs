//! Its own test binary with a single test: tracing caches which callsites are
//! enabled process-wide, so a scoped subscriber misses events when parallel
//! tests touch the same callsites.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oxidt_jobs::{Handler, Job, JobFailure};
use sqlx::PgPool;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, prelude::*};
use uuid::Uuid;

/// Collects span fields and events as text.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl Visit for Captured {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let line = format!("{}={value:?}", field.name()).replace('"', "");
        self.0.lock().unwrap().push(line);
    }
}
impl<S: Subscriber> Layer<S> for Captured {
    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
        attrs.record(&mut self.clone());
    }
    fn on_record(&self, _: &Id, values: &Record<'_>, _: Context<'_, S>) {
        values.record(&mut self.clone());
    }
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let level = event.metadata().level();
        self.0.lock().unwrap().push(format!("level={level}"));
        event.record(&mut self.clone());
    }
}
impl Captured {
    fn has(&self, line: &str) -> bool {
        self.0.lock().unwrap().iter().any(|l| l == line)
    }
}

#[derive(Clone)]
struct Scripted(PgPool);
impl Handler for Scripted {
    fn pool(&self) -> &PgPool {
        &self.0
    }
    async fn execute(&self, job: &Job) -> Result<(), JobFailure> {
        match job.kind.as_str() {
            "flaky" => Err("Told to fail".into()),
            "doomed" => panic!("told to panic"),
            "fenced" => {
                sqlx::query("UPDATE background_jobs SET lease_token=gen_random_uuid() WHERE id=$1")
                    .bind(job.id)
                    .execute(&self.0)
                    .await
                    .map_err(|_| "Fencing failed")?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
    async fn schedule(&self) -> Result<(), sqlx::Error> {
        Ok(())
    }
}

async fn insert(pool: &PgPool, kind: &str, status: &str, attempts: i32) {
    sqlx::query(
        "INSERT INTO background_jobs (id,kind,status,attempts,run_at,lease_until) \
         VALUES ($1,$2,$3,$4,NOW()-INTERVAL '1 minute',NOW()-INTERVAL '1 second')",
    )
    .bind(Uuid::new_v4())
    .bind(kind)
    .bind(status)
    .bind(attempts)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn workers_report_every_outcome(pool: PgPool) {
    let captured = Captured::default();
    tracing_subscriber::registry().with(captured.clone()).init();
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(&pool)
        .await
        .unwrap();
    insert(&pool, "fine", "pending", 0).await;
    insert(&pool, "flaky", "pending", 0).await;
    insert(&pool, "doomed", "pending", 4).await;
    insert(&pool, "crashed", "running", 5).await;
    insert(&pool, "fenced", "pending", 0).await;

    let (stop, handle) = oxidt_jobs::spawn(Scripted(pool.clone()), 1);
    let summary = || async {
        sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT kind, status, last_error FROM background_jobs ORDER BY kind",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let expected: [(String, String, Option<String>); 5] = [
        (
            "crashed".into(),
            "failed".into(),
            Some("Worker lease expired".into()),
        ),
        (
            "doomed".into(),
            "failed".into(),
            Some("Job panicked".into()),
        ),
        ("fenced".into(), "running".into(), None),
        ("fine".into(), "completed".into(), None),
        (
            "flaky".into(),
            "pending".into(),
            Some("Told to fail".into()),
        ),
    ];
    let mut rows = summary().await;
    for _ in 0..50 {
        if rows == expected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        rows = summary().await;
    }
    assert_eq!(rows, expected);
    stop.send(true).unwrap();
    handle.await.unwrap();

    for line in [
        "job.outcome=completed",
        "job.outcome=retrying",
        "job.outcome=failed",
        "job.outcome=lease_lost",
        "job.kind=fine",
        "job.attempt=1",
        "level=INFO",
        "level=WARN",
        "level=ERROR",
        "message=Job completed",
        "message=Job attempt failed",
        "message=Job failed permanently",
        "message=Job lease lost, result not recorded",
        "kind=doomed",
        "reason=Job panicked",
        "kind=crashed",
        "reason=Worker lease expired",
    ] {
        assert!(captured.has(line), "missing {line}");
    }
}
