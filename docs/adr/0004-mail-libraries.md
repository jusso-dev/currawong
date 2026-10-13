# ADR 0004: Mail libraries

Status: Proposed

## Decision
Use Stalwart's crates: `mail-parser` (MIME), `mail-auth` (SPF, DKIM, DMARC, ARC), `mail-send` (outbound SMTP), plus `hickory-resolver` for DNS. Write our own SMTP server state machine on tokio (with `tokio-rustls`) rather than embedding a full MTA, so we control limits and hooks at every SMTP stage.

## Consequences
Stalwart crates are dual licensed (Apache-2.0 OR MIT for these crates at the time of writing; verify each release). Pin versions and track upstream security advisories.
