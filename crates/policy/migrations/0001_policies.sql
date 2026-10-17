-- Policy store. Conditions, actions and floor overrides are JSON in the same
-- shape as the TOML pack. tenant_id '' is the platform namespace; each tenant
-- has its own ids and groups.
CREATE TABLE IF NOT EXISTS policies (
    tenant_id TEXT NOT NULL DEFAULT '',
    id TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_value TEXT,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    dry_run INTEGER NOT NULL DEFAULT 0,
    mandatory INTEGER NOT NULL DEFAULT 0,
    override_floor TEXT NOT NULL DEFAULT '[]',
    conditions TEXT NOT NULL,
    actions TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS policy_groups (
    tenant_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (tenant_id, name, address)
);

-- `seeded` is set once the pack has been imported, so deleting every policy
-- sticks. `revision` goes up on every write so the gateway knows to reload.
CREATE TABLE IF NOT EXISTS policy_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
