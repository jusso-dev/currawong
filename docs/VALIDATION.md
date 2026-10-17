# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). On 2026-10-17 advisories failed on entries published after the last run, outside the scanner: RUSTSEC-2026-0346 to 0349 (`rustls` 0.23.45, fixed in 0.23.46) and RUSTSEC-2026-0367 to 0369 (`zip` 8.6.0 pulled in by `mail-auth`; the advisories concern `extract()` to disk). The parser worker's own `zip` is now 9.x and is not affected. Bans, licences and sources pass. Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced at build time from XOR bytes and is not stored as a contiguous string in the repository.

The scan and pipeline tests spawn the real `currawong-parser-worker` binary. `cargo test --workspace` builds it; running `cargo test -p currawong-scan` or `-p currawongd` alone needs `cargo build -p currawong-parser-worker` first, and the tests say so rather than skip.

The fake clamd tests cover a reply of `INSTREAM size limit exceeded` sent before the client has finished and followed by a close (fail closed, not defer), a clamd that accepts and never reads (times out, defers), a reply split across reads, and archive members written by the worker being sent as separate streams.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check (EICAR, and a 120 MiB stream that must hit `StreamMaxLength` and fail closed). `deploy/docker-compose.yml` starts `clamav/clamav:stable` on loopback.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. On Linux the parser worker installs a seccompiler filter on all threads that returns EPERM for network sockets (`socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`), `execve`, `ptrace`, `process_vm_readv`/`writev`, `kill`/`tkill`, io_uring, `bpf`, `perf_event_open`, `userfaultfd`, keyrings, mounts, namespaces, `chroot`/`pivot_root`, module loading and similar. If the limits or the filter cannot be installed (unknown architecture, build or apply error) the worker reports the error and exits, so mail fails closed. This machine is macOS, so the filter was not executed here, and neither was `crates/parser-worker/tests/sandbox.rs` (inside the sandbox `socket(AF_INET, SOCK_STREAM)` returns EPERM). Both are `cfg(target_os = "linux")` and run in Linux CI. The module and the test were compiled and linted for Linux in a scratch crate (`cargo clippy --target x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, `-D warnings`). macOS and Windows workers run unsandboxed (dev builds only, issue #23).
- RLIMIT_AS. macOS does not enforce it, so `decompression_bomb_hits_the_memory_limit` in `crates/scan/tests/engines.rs` (a 1 GiB gzip bomb against a 256 MiB worker with extraction limits set far higher) is Linux only and was not run here.
- Not done from the review of #23: the seccomp filter is a denylist, not an allowlist, because an allowlist cannot be checked on this machine and a missing syscall would stop every worker. There is no filesystem restriction (Landlock or similar): a compromised worker can still read files the daemon's user can read. The worker gets a cleared environment, per-job CPU limits and a recycled process after `max_jobs_per_worker`.
- 7z. Extracted with `sevenz-rust2` (LZMA, LZMA2, AES). Archives using methods not built in (BZip2, PPMd, Deflate, Zstandard, Brotli, LZ4) are flagged `Unscannable` and quarantined. RAR is detected and not extracted (licence), and is flagged `Unscannable`.
- `deploy/docker-compose.yml` healthcheck (`clamdcheck.sh`) was not run; Docker was not used.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
