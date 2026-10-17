# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced at build time from XOR bytes and is not stored as a contiguous string in the repository.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check. `deploy/docker-compose.yml` starts `clamav/clamav:stable`.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here.
- Spool power loss. The spool crash tests (`cargo test -p currawong-spool`) stop `accept`, `transition` and `recover` after every filesystem step, which models a process crash. They cannot model power loss, where writes or renames that were never fsynced may be lost or reordered. The fsync ordering that keeps the 250 promise across power loss was reasoned through, not tested. A real check needs a fault-injecting block device or filesystem, such as `dm-flakey` or a `LazyFS` mount.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## Policy engine (#37)

`cargo test -p currawong-policy` and `cargo test -p currawongd --test policy` cover the engine. The corpus test runs every sample in `testdata/corpus/expected.toml` through the real pipeline and default pack, with an in-process fake clamd for EICAR.

- A built-in floor runs before any pack: malware and failed scans are quarantined, scans a required engine could not complete are deferred. Tenant policies cannot lift it. A platform global policy can lift named rules (`override_floor = ["malware"]`) for the mail its conditions match; each rule is lifted separately, and every such policy is logged as a warning when loaded.
- Storage is SQLite through `rusqlite`, not `sqlx`. The workspace already links `rusqlite` with bundled SQLite, and `sqlx-sqlite` would link a second `libsqlite3-sys`, which Cargo refuses. Migrations are plain SQL in `crates/policy/migrations/`, tracked with `PRAGMA user_version`. PostgreSQL is not supported yet. Store calls are synchronous; the admin API should call them through `spawn_blocking`.
- "Editable via API" is the `PolicyStore` Rust API (upsert, delete, groups, TOML import and export), namespaced per tenant. There is no HTTP endpoint or RBAC yet; that belongs to the admin issue.
- Tenant and direction are resolved per recipient from `relay.tenants` and `domains.accept`. Outbound user and group scopes match only an authenticated identity, and the SMTP session does not put the login on the envelope yet, so those scopes do not match outbound mail today. Binding MAIL FROM to the credential is left to the SMTP session owner.
- Header, redirect and bcc actions are applied before delivery. Redirect and bcc only reach the recipient tenant's domains or `policy.forward_domains`. Tenant redirect and bcc stop once the message carries three `Received` fields this gateway wrote; platform and mandatory ones always apply. A sender can forge our `Received` line to stop tenant forwarding, but not platform or mandatory forwarding. Banner, encrypt and require TLS are refused at load time until delivery can carry them out.
- Reject sends a DSN with the policy's code and a generic reason, only to authenticated senders or senders that passed SPF or DMARC, never to automatic mail, and at most once per message. Otherwise the message is ended without a bounce. Discard ends the message without quarantining it. Quarantine records the queue name in the reason only, because the quarantine store has no queues yet.
- The default pack tags spam with an `X-Currawong-Spam: [SPAM]` header, not a subject rewrite, because the spool does not rewrite bodies.
- Nothing produces a `spam` score yet, so the spam policies do not fire on real mail. The tests inject scores.
- When recipients (or tenants) get different outcomes the message is split. The plan is saved under `spool/split/` before any copy is made, and a retry finishes that plan rather than deciding again. Copies carry the same decision and get ids derived from the original and their recipients.
- Policies are checked on every pipeline pass, on a blocking thread, and reloaded only when the pack file's time or size or the database revision changes. A database is seeded from the pack once; after that the pack file is not read. A database with the layout of an earlier development build is refused with a clear error.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
