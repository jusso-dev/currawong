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
- Wedgetail's ingest API. The `yumaitau/wedgetail` repository could not be fetched from this environment, so its real ingest format was not checked. The connector uses the issue #42 fallback, a JSON array of OCSF 1.3 events over HTTPS with a bearer token, documented in `docs/events.md`. It was tested against an in-process HTTPS fake only. Once the Wedgetail API is known, match it in `crates/integrations/src/export/wedgetail.rs`.
- OCSF schema validation. The OCSF class, activity and disposition ids in `docs/events.md` were written from the public OCSF 1.3 schema and were not run through an OCSF validator.
- A real SIEM. Syslog (TCP and TLS), webhook and Wedgetail exports were tested against in-process receivers on loopback with generated certificates. No Splunk, Sentinel, QRadar or ArcSight instance parsed the CEF output.
- Event export in the running daemon. The scheduler emits a `message_verdict` event for every verdict it applies, but `currawongd` does not yet read an `[events]` section or install an `EventBus`, so emitted events go nowhere until that is wired in `main.rs` and `crates/core/src/config.rs`. Those files were left alone because other changes to them were in flight. URL click, quarantine release, admin action and verdict change events have schema, CEF and OCSF mappings but no emitters yet.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
