# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`
- Packaging (#46), on macOS arm64. `cargo build --release -p currawongd -p currawong-parser-worker`: currawongd is 19,313,216 bytes (15,564,824 stripped), the worker 2,549,872 (2,164,792 stripped), the healthcheck probe 492,312. These are Mach-O sizes; linux-x86_64 sizes were not measured.
- `cargo deb -p currawongd --no-build` (cargo-deb 3.8.0) produced a .deb. `dpkg-deb` is not installed, so it was unpacked with `ar` and `tar`: control, conffiles (`/etc/currawong/currawong.toml`), the maintainer scripts with cargo-deb's systemd snippets merged at `#DEBHELPER#`, and the file list. The binaries inside were macOS builds, so this checks layout and metadata only.
- `currawong-healthcheck` against a running `currawongd` (TLS listener on a high port, certificate made with the exact `openssl req` line from postinst): exit 0. Against a closed port and against the SMTP port: exit 1.
- `cargo test -p currawong-setup-tui`: input validation, the rendered config loads and passes `Config::validate`, input cannot inject TOML, the config and certificate are written 0640 through a temporary file, a rejected config leaves the old file in place, and the generated certificate loads in `TlsManager`. Form tests cover typing, focus, toggles and the first-boot password checks.
- The `currawong-setup` binary, driven through a pseudo-terminal with keystrokes: with a normal window, and with `--firstboot` on a 0x0 window like a serial console (it falls back to 80x24). `packaging/appliance/serial-expect.py --complete` ran against it through a local unix-socket bridge standing in for QEMU's serial socket, with stub `systemctl`, `hostnamectl` and `chpasswd` and a fake getty and shell. The wizard appeared, saving passed the real `currawongd --check-config`, `currawong.toml`, `cert.pem` and `key.pem` were 0640, the password reached `chpasswd` only on stdin, the marker was written, the tty1 instance was stopped, and the login and health-check steps matched. This found and fixed three bugs: ratatui's partial redraws dropping letters from the serial text, `Terminal::clear` waiting on a cursor-position reply a serial line never sends, and a `CURRAWONG_` environment variable in the unit that `currawongd` read as a config override.
- `currawongd --check-config` on the example config with `CURRAWONG_METRICS__LISTEN=0.0.0.0:9090` (the container image) and on the config rendered by `helm template`.
- `shellcheck` on postinst, postrm, the generated prerm, `mkosi.postinst.chroot` and every `run:` step in `docs/ci/release.yml`.
- `helm lint deploy/helm/currawong` and `helm template`.
- `rustfmt --check` and `clippy-driver -D warnings` on `packaging/docker/healthcheck.rs` (it is not a workspace crate).

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced at build time from XOR bytes and is not stored as a contiguous string in the repository.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check. `deploy/docker-compose.yml` starts `clamav/clamav:stable`.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here. That includes YARA matching under the filter and under a real `RLIMIT_AS`, which macOS does not enforce.
- Spool power loss. The spool crash tests (`cargo test -p currawong-spool`) stop `accept`, `transition` and `recover` after every filesystem step, which models a process crash. They cannot model power loss, where writes or renames that were never fsynced may be lost or reordered. The fsync ordering that keeps the 250 promise across power loss was reasoned through, not tested. A real check needs a fault-injecting block device or filesystem, such as `dm-flakey` or a `LazyFS` mount.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.
- #46 packaging acceptance criteria. None of the three was run here: Docker must not be used on this machine (the default context is a remote host), QEMU and mkosi were not run, and there is no Debian 12 host. `docs/ci/release.yml` checks each on GitHub-hosted runners, and each job fails with an `::error::` line:
  - `container`: builds the image, fails if `docker image inspect` reports 80,000,000 bytes or more, starts it with a throwaway certificate, and fails unless `/healthz` returns 200 and Docker's `HEALTHCHECK` reports healthy.
  - `deb` and `deb-install`: build the .deb in `rust:1-bookworm`, boot `debian:12` with systemd as PID 1 (`--privileged`, `/sbin/init`), `apt-get install` the package, and fail unless `systemctl is-active currawongd` succeeds and `/healthz` returns 200. They also check the `currawong` user, `key.pem` at `root:currawong 640` and listeners on 25, 465 and 587. A privileged container is not a VM; a Debian 12 VM is still the authoritative check.
  - `appliance`: builds the image with mkosi v25.3 and boots it in QEMU (KVM when `/dev/kvm` is usable, otherwise TCG with a 45-minute timeout). `serial-expect.py --complete` waits for the wizard on ttyS0, fills it in, waits for "Currawong is running", logs in as root and fails unless `currawongd` is active and `/healthz` returns 200 inside the VM. The serial log is uploaded as an artefact.
  To check by hand on a Linux host, run the same commands as the workflow steps. The appliance check is:
    ```bash
    sudo mkosi -C packaging/appliance build
    qemu-img convert -O qcow2 packaging/appliance/mkosi.output/currawong-appliance.raw currawong-appliance.qcow2
    qemu-system-x86_64 -machine q35 -accel kvm -m 2048 -smp 2 -bios /usr/share/ovmf/OVMF.fd \
      -drive if=virtio,format=qcow2,file=currawong-appliance.qcow2,snapshot=on -nic user,model=virtio-net-pci \
      -display none -monitor none -chardev socket,id=ser0,path=serial.sock,server=on,wait=off -serial chardev:ser0 &
    python3 packaging/appliance/serial-expect.py --socket serial.sock --timeout 600 --complete
    ```
- The systemd unit was checked by reading it. `systemd-analyze verify` and `security` run in the `deb-install` job but only report. The parser worker's seccomp and rlimit calls under `SystemCallFilter=@system-service seccomp` and `MemoryDenyWriteExecute=yes` have not been exercised on Linux.
- The wizard on a real Linux VT (tty1) and a real UART was not run; only on macOS pseudo-terminals. `hostnamectl`, `chpasswd` and `systemctl` were stubs locally.
- mkosi config syntax was written for mkosi v25 and not built here. The AMI import commands in `docs/packaging.md` were not run. The appliance root is a fixed 8 GiB and does not grow to fill a larger disk.
- The Helm chart was linted and rendered, not installed on a cluster.
- hadolint is not installed, so the Dockerfile was not linted.
- `cargo deny check advisories`, with a freshly fetched advisory database, fails on RUSTSEC-2026-0346 to 0349 (rustls 0.23.45) and RUSTSEC-2026-0367 to 0369 (zip 2.4.2 and 8.6.0), which are already on main. The ratatui and crossterm crates #46 adds bring no advisories. `bans`, `licenses` and `sources` pass.

## YARA

`cargo test -p currawong-scan yara` covers the starter rules on their fixtures, a broken rule file (logged, previous rules stay active), broken rules at startup (an error, not an empty set), an emptied directory (rejected), rule files in any case and in subdirectories, a dangling entry (an error, not skipped), misspelt action tags (rejected), compiler warnings (logged and printed by `--check-config`), the per-message budget, de-duplication and part-name cleaning, concurrent reloads, hot reload (`notify` `PollWatcher`, two-second interval, so it also works on bind mounts and network volumes), and matching of MIME parts and archive members both in-process and through a live parser worker, including a second rules generation sent to the same worker. `cargo test -p currawong-parser-worker yara` drives the real worker binary over stdin: rules load, generation check, and a bad blob dropping the old rules. `cargo test -p currawongd yara` covers the pipeline report in-process and through the worker with a spooled body, fail-closed when the rules cannot load, and `--check-config` rejecting a broken rule. The worker-backed tests in `currawong-scan` and `currawongd` need `target/debug/currawong-parser-worker`: `cargo test --workspace` builds it; on their own run `cargo build -p currawong-parser-worker` first. They fail rather than skip when it is missing or stale.

Matching runs in the parser worker (ADR 0002) because yara-x modules such as `pe`, `dotnet`, `elf`, `macho` and `lnk` parse hostile files. The supervisor compiles the rules and sends the serialised set to each worker as a `LoadRules` frame on its stdin, once per worker and rules generation, before the next job. No rules file exists on disk and the worker never reads rules from a path or compiles rule source. Parse requests name the generation; a worker without it fails the job closed. yara-x reserves 16 MiB of address space per scanner, inside the worker's 512 MiB `RLIMIT_AS`.

Loading is the slow step: yara-x 1.21 is built without `native-code-serialization`, so deserialising recompiles the rules' wasm with cranelift. The load has its own timeout (`scanner.yara.load_timeout_secs`, default 120 s), separate from `job_timeout_secs`. Measured on this machine (Apple silicon, load average 25 to 50 from parallel builds) with a release build of 5,000 generated rules, each with a text and a hex pattern (`cargo test --release -p currawong-scan --test yara -- --ignored --nocapture`): compile 1.1 s, serialised blob 1.3 MB as base64, worker load (deserialise and recompile) 1.1 s, a 10 MiB scan 0.1 s. Debug builds are several times slower. Real community sets with heavy regular expressions or modules will differ; the default 120 s leaves about a hundredfold margin over this measurement. Until the #23 change lands per-job CPU limits, the load's CPU time counts against the worker's lifetime `RLIMIT_CPU` (`worker_cpu_secs`); raise that for large rule sets.

Per message, matching has a budget of 20 s, 512 MiB scanned and 2,048 distinct parts; identical content is matched once. Exceeding the budget fails the job closed with the reason. yara-x module parsing (`pe`, `dotnet` and so on) cannot be interrupted by the yara-x timeout; the worker's job timeout and kill cover that case. Attachment names in matches have control characters removed and are capped at 128 characters.

Build cost: yara-x brings wasmtime and cranelift, about 145 extra crates. A cold debug build of yara-x and its dependencies took 10 min 11 s wall clock here, with yara-x itself about 6 min 45 s, on a machine with a load average near 50 from parallel builds, so expect less on an idle machine. Incremental builds are unaffected. Licences: yara-x is BSD-3-Clause; wasmtime and cranelift are `Apache-2.0 WITH LLVM-exception` and notify is `CC0-1.0`, both added to `deny.toml`.

Advisories: yara-x 1.21 (the latest) pins wasmtime ^45, which has seven RustSec advisories. Fixes exist only in other wasmtime lines (46.0.x and 47.x for two of them, all seven by 48.0.6 or 49.0.3), none semver-compatible with 45. They concern the component model, async, WASI, multiple engines and hostile wasm modules. yara-x builds wasmtime with only `cranelift`, `runtime` and `std` and uses one engine. The only wasm it runs is the rules blob, which currawongd compiles from operator rule files and hands to the worker over its stdin pipe, never from a path or from mail; RUSTSEC-2026-0359 (hostile wasm) therefore rests on the integrity of the rules directory and the supervisor. They are ignored in `deny.toml` with these reasons. Remove the ignores when yara-x moves to a fixed wasmtime. Separately, `cargo deny check advisories` currently fails on advisories that were already in the tree before YARA: rustls 0.23.45 (RUSTSEC-2026-0346 to 0349, fixed in 0.23.46) and zip 2.4.2 and 8.6.0 (RUSTSEC-2026-0367 to 0369, fixed in 9.0.0; 8.6.0 comes in through mail-auth). Those need their own change.

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
