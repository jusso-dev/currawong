# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced from XOR bytes (at build time in `crates/scan`, at run time in `crates/testkit`) and is not stored as a contiguous string in the repository. `cargo test -p currawong-testkit` sends every entry in `testdata/corpus/expected.toml` through SMTP and the scan pipeline and checks the recorded verdict.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check. `deploy/docker-compose.yml` starts `clamav/clamav:stable`.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- `cargo +nightly fuzz build` and `cargo +nightly fuzz run smtp_command -- -max_total_time=60`. Neither nightly nor `cargo-fuzz` is installed here, and the agent sandbox refused to install them (`rustup toolchain install nightly` and `cargo install cargo-fuzz` failed with "Operation not permitted" writing to `~/.rustup` and `~/.cargo`). The `fuzz/` package was therefore not compiled: `libfuzzer-sys` source could not be unpacked either. `fuzz/Cargo.lock` was resolved from the workspace lock. The stand-in ran instead: `cargo test -p currawong-fuzzstand` (seeds plus 3000 mutations per target) and `FUZZSTAND_ROUNDS=200000 cargo test -p currawong-fuzzstand --release` (2.6 million inputs across 13 targets, no panic). That is not coverage-guided. See `docs/fuzzing.md`.
- `cargo deny check advisories` on the residency, telemetry, testkit and fuzz changes. The sandbox could not take the advisory database lock in `~/.cargo/advisory-dbs`. `cargo deny check bans licenses sources` passed.
- Testkit delivery. `currawong-testkit` runs the SMTP server and the daemon's scan pipeline (`classify_pending`) against a fake clamd. It does not start outbound delivery, which needs DNS and an MX.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
