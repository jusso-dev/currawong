-- One row per indicator per feed. The primary key is the lookup index.
CREATE TABLE indicators (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    threat TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    -- The feed's own end of validity (STIX valid_until), if any.
    expires INTEGER,
    sync_id INTEGER NOT NULL,
    PRIMARY KEY (kind, value, source)
) WITHOUT ROWID;
CREATE INDEX indicators_source ON indicators (source, sync_id);

-- Sync state per feed, for conditional GET and staleness.
CREATE TABLE feeds (
    source TEXT PRIMARY KEY,
    etag TEXT,
    last_modified TEXT,
    last_attempt INTEGER,
    last_success INTEGER,
    last_error TEXT,
    indicators INTEGER NOT NULL DEFAULT 0,
    sync_id INTEGER NOT NULL DEFAULT 0
);
