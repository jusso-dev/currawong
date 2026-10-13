# Currawong architecture

## Goals

1. Never lose an accepted message. A 250 reply to `DATA` means the message is durably on disk.
2. Never let a parser bug compromise the gateway. Untrusted content is parsed in isolated, resource-limited worker processes.
3. Keep every byte of customer data in Australia unless an operator explicitly opts out.
4. One binary, one config file, runnable on a VM, in a container or as an appliance image.

## Message flow

1. **Accept.** `currawong-smtp` listens on port 25 (inbound) and 587/465 (outbound submission from trusted hosts). Connection-level checks run first: rate limits, DNSBLs, reputation, greylisting, recipient validation. These are cheap and reject most junk before `DATA`.
2. **Spool.** On `DATA` end the message is written to the spool (`currawong-spool`, see ADR 0001) with an fsync, then the client gets 250. Each message gets a ULID `MessageId`.
3. **Pipeline.** Workers pull from the spool and run stages in order. Each stage appends results to a `ScanReport`:
   - `auth`: SPF, DKIM, DMARC, ARC (in-process, `mail-auth`).
   - `parse`: MIME parse and extraction in an isolated worker (ADR 0002).
   - `scan`: ClamAV, YARA, file type, archives, macros, HTML smuggling, QR codes, URLs.
   - `classify`: spam score, BEC signals, optional LLM.
   - `dlp`: Australian identifiers and protective markings (outbound and inbound).
4. **Decide.** `currawong-policy` turns the report into a `Verdict` using per tenant, domain, group and user policy.
5. **Act.** Deliver via `mail-send` (with DANE and MTA-STS for outbound), quarantine, reject (only possible pre-250 for connection-level checks; post-acceptance mail gets bounced or quarantined), or discard.
6. **Emit.** Every verdict produces an event to the event bus, exported to SIEMs (syslog/CEF, webhook, Wedgetail).

## Processes

- `currawongd` supervisor: SMTP listeners, spool, policy, delivery, admin API.
- `currawong-parser` workers: spawned by the supervisor, run with seccomp, no network, rlimits on memory and CPU, talk over a Unix socket with length-prefixed messages.
- External: `clamd`, optional YARA rules dir, optional sandbox API, optional LLM endpoint.

## Storage

See ADR 0003. Spool on local disk, metadata and policy in SQLite for single-node and PostgreSQL for clusters, quarantine blobs on disk or S3-compatible storage in an Australian region.

## Multi-tenancy

Every row and every spool record carries a `tenant_id`. Tenants own domains. MSP operators get a parent tenant with child tenants. RBAC roles: `platform_admin`, `msp_admin`, `tenant_admin`, `auditor`, `end_user`.

## Security boundaries

| Boundary | Control |
| --- | --- |
| Internet to SMTP | Size limits, timeouts, command length limits, connection caps |
| Raw message to parser | Separate process, seccomp, rlimits, wall clock timeout |
| Admin UI | OIDC or local accounts with TOTP, RBAC, CSRF, audit log |
| Secrets | Read from files or env, never logged |
