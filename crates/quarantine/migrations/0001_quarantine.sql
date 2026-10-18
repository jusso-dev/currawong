-- One row per held recipient. The message bytes are one blob per spool
-- message, keyed by message_id, shared by its rows. Times are Unix seconds.
CREATE TABLE quarantine (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    message_id TEXT NOT NULL,
    queue TEXT NOT NULL,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    score REAL,
    reason TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    direction TEXT NOT NULL,
    -- Our headers at hold time (Authentication-Results), re-used on release.
    headers_json TEXT NOT NULL,
    bimi_json TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    digested_at INTEGER,
    released_at INTEGER,
    released_by TEXT,
    deleted_at INTEGER,
    deleted_by TEXT
);
CREATE INDEX quarantine_recipient ON quarantine (tenant_id, recipient);
CREATE INDEX quarantine_message ON quarantine (message_id);
CREATE INDEX quarantine_expires ON quarantine (expires_at);

-- Spent digest links, kept until they would have expired anyway.
CREATE TABLE quarantine_links (
    mac TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used_at INTEGER NOT NULL
);

CREATE TABLE quarantine_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE quarantine_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    tenant_id TEXT,
    item_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    detail TEXT
);
CREATE TRIGGER quarantine_audit_no_update BEFORE UPDATE ON quarantine_audit
BEGIN
    SELECT RAISE(ABORT, 'quarantine_audit is append-only');
END;
CREATE TRIGGER quarantine_audit_no_delete BEFORE DELETE ON quarantine_audit
BEGIN
    SELECT RAISE(ABORT, 'quarantine_audit is append-only');
END;
