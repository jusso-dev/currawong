# ADR 0003: Storage choice

Status: Proposed

## Decision
- Spool: local filesystem (ADR 0001).
- Config and policy: TOML file for bootstrap, then database.
- Metadata (message log, quarantine index, audit log, users, tenants): SQLite via `sqlx` for single node, PostgreSQL via `sqlx` for clustered and MSP deployments. Same migrations, kept portable.
- Quarantine blobs: filesystem by default, S3-compatible (`aws-sdk-s3` or `object_store`) as an option, restricted to `ap-southeast-2` and `ap-southeast-4` unless residency is overridden.
- Search: SQL indexes on sender, recipient, subject hash and time first. A full text index (tantivy) is an M3 option.

## Consequences
One code path with two SQL backends needs CI against both.
