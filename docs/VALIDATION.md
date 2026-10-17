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
- Worker sandbox (Linux). Before its runtime starts any thread the worker closes inherited descriptors, sets RLIMIT_AS, CORE=0, FSIZE, CPU (per job) and, under a dedicated uid, NPROC; marks itself non-dumpable; applies Landlock so it can read only its private `in/` and write only its `out/` (the supervisor copies each message into a 0700 per-worker directory); and installs a hand-written seccomp BPF filter on all threads. The filter kills on a foreign architecture, refuses x32 system calls, returns EPERM for sockets, send/recv*, exec, ptrace, process_vm_*, kill/tkill/tgkill, pidfd_*, io_uring, bpf, perf, userfaultfd, keyrings, mounts and the new mount API, unshare/setns, chroot/pivot_root, module loading, identity changes and similar, ENOSYS for clone3 (glibc falls back to clone), and EPERM for clone with namespace flags. Any failure stops the worker with a `startup` frame; the message is deferred. Landlock missing is a failure unless `scanner.require_landlock = false`. The daemon itself is non-dumpable, refuses to run a worker as root without `scanner.worker_uid`, runs a self-test job at startup, and `/readyz` runs one too. None of this was executed here (macOS). `crates/parser-worker/tests/sandbox.rs` runs the real worker binary with `--probe` on Linux CI and checks each attempt's errno (socket, pidfd_open, pidfd_getfd, ptrace, kill, tgkill, execve, clone with CLONE_NEWUSER, unshare, x32 getpid, clone3, opening /proc/<parent>/mem and /etc/passwd, writing to `in/` and the worker directory, and that `in/` is readable and `out/` writable). The pool tests on Linux CI run every job inside that sandbox. The module and the test were compiled and linted for x86_64 (gnu and musl) and aarch64 Linux with `-D warnings` in a scratch crate. If the CI kernel lacks Landlock, those tests fail by design. macOS and Windows workers run unsandboxed (dev builds only, issue #23).
- RLIMIT_AS. macOS does not enforce it, so `decompression_bomb_hits_the_memory_limit` in `crates/scan/tests/engines.rs` (a 1 GiB gzip bomb against a 256 MiB worker with extraction limits set far higher) is Linux only and was not run here.
- Not done: the seccomp filter is a denylist with argument checks, not an allowlist. An allowlist cannot be exercised on this machine, and a missing call would stop every worker. Classifying several messages at once (`worker_pool_size` at a time) has no dedicated test.
- 7z. Extracted with `sevenz-rust2` (LZMA, LZMA2, AES). Archives using methods not built in (BZip2, PPMd, Deflate, Zstandard, Brotli, LZ4) are flagged `Unscannable` and quarantined. RAR is detected and not extracted (licence), and is flagged `Unscannable`.
- `deploy/docker-compose.yml` healthcheck (`clamdcheck.sh`) was not run; Docker was not used.
- Spool power loss. The spool crash tests (`cargo test -p currawong-spool`) stop `accept`, `transition` and `recover` after every filesystem step, which models a process crash. They cannot model power loss, where writes or renames that were never fsynced may be lost or reordered. The fsync ordering that keeps the 250 promise across power loss was reasoned through, not tested. A real check needs a fault-injecting block device or filesystem, such as `dm-flakey` or a `LazyFS` mount.

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
