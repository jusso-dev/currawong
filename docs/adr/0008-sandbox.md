# ADR 0008: On-premises asynchronous attachment detonation

Status: Accepted

## Context

Detonation takes longer than an SMTP transaction. Accepted mail must remain durably spooled while a separate service analyses an attachment. No cloud multi-scanner or GPL implementation is linked into Currawong.

## Decision

- Optional `scanner.sandbox` selects an implementation of `Sandbox` (submit/status). CAPEv2's `/apiv2` API is implemented. DRAKVUF upload/status/report routes were verified upstream, but no malicious/clean verdict or score contract was verified; `kind = "drakvuf"` is refused rather than treating observations as a clean result.
- Attachment selection covers executables, scripts, macro/OLE Office parts, PDFs, archives and their risky extracted members, disk images and HTML attachments (including unnamed explicit attachment dispositions). `submit` narrows categories. Existing static file controls remain active even after a clean sandbox result.
- HTTP is residency-checked, DNS-pinned, proxy-free and redirect-free. In addition, sandbox peers must be loopback, RFC 1918, link-local or IPv6 local addresses, even with residency overrides. CAPE HTTP operations have a 15-second deadline, create replies a 64 KiB cap and status/reports an 8 MiB cap. Uploads are capped by `max_file_size` and verified against the supervisor's SHA-256.
- SQLite at `spool.dir/sandbox.sqlite3` stores tasks keyed by service and SHA-256. A reservation precedes upload; a crash or ambiguous failed upload cannot cause an immediate second detonation. Concurrent attempts share the reservation. Pending tasks survive restarts, polling is throttled, and terminal verdicts/failures expire at `cache_ttl_secs`.
- First submission and pending statuses defer the message with `awaiting sandbox`. Spool retry uses `poll_secs`, subject to the scheduler's normal polling cadence. `max_wait_secs` is measured from the original reservation. Timeout either fails closed to `scan-failed` or continues, according to `on_timeout`; other findings still apply.
- CAPE `reported` fetches JSON report `malscore` and signatures. Currawong uses an explicit threshold of 5/10 for malicious and reports normalised score 0..1. Missing/invalid scores or signatures cannot mean clean. Malicious findings use `EngineResult::Malware`, so the existing malware floor wins over any pending service. Infrastructure failures defer when required and add a note when optional; failed analysis, malformed protocol and oversize parts fail closed.

## Consequences

CAPE is a separate GPL-3.0 service, with guest operating system licences and isolated virtual machines managed separately. Ambiguous uploads are held as unknown reservations until timeout, rather than redetonated; no upstream idempotency token exists. TTL bounds age, not cache cardinality, and expiry is lazy on cache access. A permanently unavailable required engine is eventually held by the existing `max_scan_deferrals` cap. No live CAPE, DRAKVUF, guest VM or real malware was run. See [integration guide](../integrations/sandbox.md).
