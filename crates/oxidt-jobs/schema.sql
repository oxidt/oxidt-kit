-- The table oxidt-jobs reads and writes. Apps copy this into their own
-- migrations (and may add `REFERENCES users(id) ON DELETE CASCADE` to
-- owner_id); the crate never runs migrations itself.
CREATE TABLE background_jobs (
    id UUID PRIMARY KEY,
    owner_id UUID,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
    priority INTEGER NOT NULL DEFAULT 0,
    run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ,
    lease_token UUID,
    dedupe_key TEXT UNIQUE,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX background_jobs_ready ON background_jobs (priority DESC, run_at) WHERE status = 'pending';
CREATE INDEX background_jobs_expired ON background_jobs (lease_until) WHERE status = 'running';
CREATE INDEX background_jobs_owner ON background_jobs (owner_id, created_at DESC);
