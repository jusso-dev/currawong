# ADR 0001: Queue and spool design

Status: Proposed

## Context
A mail gateway must not lose mail it has acknowledged. It must also survive restarts mid-scan and retry deliveries over days.

## Decision
- One directory per state under `spool_dir`: `incoming/`, `active/`, `deferred/`, `done/`.
- Each message is two files: `<ulid>.eml` (raw bytes, immutable) and `<ulid>.json` (envelope, tenant, attempts, next retry, stage results).
- Write to `incoming/<ulid>.tmp`, fsync the file, rename to final name, fsync the directory, then reply 250.
- State changes are atomic renames between directories.
- Delivery retries use exponential backoff (5m, 15m, 30m, 1h, then hourly) up to 5 days, then a DSN bounce.
- An in-memory index is rebuilt by scanning directories on start.

## Consequences
Simple, debuggable with `ls`, no database on the hot path. Single-node only; clustering (M3) needs a shared queue, likely PostgreSQL `SKIP LOCKED`.

## Alternatives considered
Embedded KV (sled, redb): faster but harder to inspect. Kafka or NATS: too heavy for a single appliance.
