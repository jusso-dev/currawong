-- Policy store. Conditions and actions are JSON in the same shape as the TOML pack.
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    scope_kind TEXT NOT NULL,
    scope_value TEXT,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    dry_run INTEGER NOT NULL DEFAULT 0,
    conditions TEXT NOT NULL,
    actions TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS policies_tenant ON policies (tenant_id);

CREATE TABLE IF NOT EXISTS policy_groups (
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (name, address)
);
