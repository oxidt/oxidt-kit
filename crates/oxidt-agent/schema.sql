-- Apply after oxidt-jobs/schema.sql, through the host application's migrations.
-- No stored credentials or permission snapshots: execution resolves identity again.
CREATE TABLE agent_actions (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    definition JSONB NOT NULL,
    arguments JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','queued','completed','rejected','expired','invalidated','failed')),
    -- The action's output, or the safe {"code","message"} error when failed.
    result JSONB,
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    finished_at TIMESTAMPTZ
);
CREATE INDEX agent_actions_review ON agent_actions (tenant_id, user_id, created_at DESC);
-- The host owns retention: sweep stale pending rows and prune finished ones.
CREATE INDEX agent_actions_pending_expiry ON agent_actions (expires_at) WHERE status = 'pending';
