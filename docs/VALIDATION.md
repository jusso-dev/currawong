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
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here. That includes YARA matching under the filter and under a real `RLIMIT_AS`, which macOS does not enforce.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## YARA

`cargo test -p currawong-scan yara` covers the starter rules on their fixtures, a broken rule file (logged, previous rules stay active), hot reload (`notify` `PollWatcher`, two-second interval, so it also works on bind mounts and network volumes), and matching of MIME parts and archive members both in-process and through a live parser worker. `cargo test -p currawongd yara` covers the pipeline report and `--check-config` rejecting a broken rule.

Matching runs in the parser worker (ADR 0002) because yara-x modules such as `pe`, `dotnet`, `elf`, `macho` and `lnk` parse hostile files. The supervisor compiles the rules and writes a serialised copy to a private temporary file, which the worker deserialises; the worker never compiles rule source. yara-x reserves 16 MiB of address space per scanner, inside the worker's 512 MiB `RLIMIT_AS`.

Build cost: yara-x brings wasmtime and cranelift, about 145 extra crates. A cold debug build of yara-x and its dependencies took 10 min 11 s wall clock here, with yara-x itself about 6 min 45 s, on a machine with a load average near 50 from parallel builds, so expect less on an idle machine. Incremental builds are unaffected. Licences: yara-x is BSD-3-Clause; wasmtime and cranelift are `Apache-2.0 WITH LLVM-exception` and notify is `CC0-1.0`, both added to `deny.toml`.

Advisories: yara-x 1.21 (the latest) pins wasmtime 45, which has seven RustSec advisories fixed only in wasmtime 48 and 49. They concern the component model, async, WASI, multiple engines and hostile wasm modules. yara-x builds wasmtime with only `cranelift` and `runtime`, runs only wasm it generated from operator rules, and never runs wasm from mail, so they are ignored in `deny.toml` with that reason. Remove the ignores when yara-x moves to a fixed wasmtime. Separately, `cargo deny check advisories` currently fails on advisories that were already in the tree before YARA: rustls 0.23.45 (RUSTSEC-2026-0346 to 0349, fixed in 0.23.46) and zip 2.4.2 and 8.6.0 (RUSTSEC-2026-0367 to 0369, fixed in 9.0.0; 8.6.0 comes in through mail-auth). Those need their own change.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
