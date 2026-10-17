# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`
- Packaging (#46), on macOS arm64. `cargo build --release -p currawongd -p currawong-parser-worker`: currawongd is 19,313,216 bytes (15,564,824 stripped), the worker 2,549,872 (2,164,792 stripped), the healthcheck probe 492,312. These are Mach-O sizes; linux-x86_64 sizes were not measured.
- `cargo deb -p currawongd --no-build` (cargo-deb 3.8.0) produced a .deb. `dpkg-deb` is not installed, so it was unpacked with `ar` and `tar`: control, conffiles (`/etc/currawong/currawong.toml`), the maintainer scripts with cargo-deb's systemd snippets merged at `#DEBHELPER#`, and the file list (both binaries in `/usr/bin`, `currawong-setup` in `/usr/sbin`, the unit in `/usr/lib/systemd/system`). The binaries inside were macOS builds, so this checks layout and metadata only.
- `currawong-healthcheck` against a running `currawongd` (TLS listener on a high port, certificate made with the exact `openssl req` line from postinst): exit 0. Against a closed port and against the SMTP port: exit 1.
- `currawongd --check-config` on: the example config with `CURRAWONG_METRICS__LISTEN=0.0.0.0:9090` (the container image), the config block `currawong-setup` writes (run with sample answers), and the config rendered by `helm template`.
- `shellcheck` on `currawong-setup`, postinst, postrm, the generated prerm, `mkosi.postinst.chroot` and every `run:` step in `docs/ci/release.yml`. The wizard's input patterns were checked to accept valid values and reject quotes and brackets.
- `helm lint deploy/helm/currawong` and `helm template`.
- `rustfmt --check` and `clippy-driver -D warnings` on `packaging/docker/healthcheck.rs` (it is not a workspace crate).

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced at build time from XOR bytes and is not stored as a contiguous string in the repository.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check. `deploy/docker-compose.yml` starts `clamav/clamav:stable`.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here.
- Spool power loss. The spool crash tests (`cargo test -p currawong-spool`) stop `accept`, `transition` and `recover` after every filesystem step, which models a process crash. They cannot model power loss, where writes or renames that were never fsynced may be lost or reordered. The fsync ordering that keeps the 250 promise across power loss was reasoned through, not tested. A real check needs a fault-injecting block device or filesystem, such as `dm-flakey` or a `LazyFS` mount.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.
- #46 packaging acceptance criteria. None of the three was run here: Docker must not be used on this machine (the default context is a remote host), QEMU was not run, and there is no Debian 12 host. `docs/ci/release.yml` runs all three. To check them by hand:
  - Image under 80 MB passes `/healthz`:
    ```bash
    docker build -t currawong:dev .
    docker image inspect currawong:dev --format '{{.Size}}'   # must be < 83886080
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
      -subj /CN=dev.example.test -keyout key.pem -out cert.pem && chmod 0644 key.pem cert.pem
    docker run -d --name cw -p 127.0.0.1:9090:9090 \
      -v "$PWD/cert.pem:/etc/currawong/cert.pem:ro" -v "$PWD/key.pem:/etc/currawong/key.pem:ro" currawong:dev
    sleep 45; docker inspect -f '{{.State.Health.Status}}' cw   # healthy
    curl -fsS http://127.0.0.1:9090/healthz                    # ok
    ```
  - The .deb installs and starts on Debian 12 (on a Debian 12 VM, as root):
    ```bash
    apt-get install -y build-essential curl && curl -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"
    cargo install cargo-deb --locked
    cargo build --release --locked -p currawongd -p currawong-parser-worker
    cargo deb -p currawongd --no-build
    dpkg-deb --info target/debian/currawong_*.deb && dpkg-deb --contents target/debian/currawong_*.deb
    apt-get install -y ./target/debian/currawong_*_amd64.deb
    systemctl is-active currawongd && curl -fsS http://127.0.0.1:9090/healthz
    ss -ltnp | grep -E ':(25|465|587) '
    systemd-analyze security currawongd.service
    systemd-analyze verify /usr/lib/systemd/system/currawongd.service
    ```
  - The appliance boots to the wizard in QEMU (Linux host with mkosi v25+, `qemu-system-x86`, `qemu-utils`, `ovmf`, and the .deb above in `target/debian/`):
    ```bash
    sudo mkosi -C packaging/appliance build
    qemu-img convert -O qcow2 packaging/appliance/mkosi.output/currawong-appliance.raw currawong-appliance.qcow2
    qemu-system-x86_64 -machine q35 -accel kvm -m 2048 -smp 2 -bios /usr/share/ovmf/OVMF.fd \
      -drive if=virtio,format=qcow2,file=currawong-appliance.qcow2,snapshot=on
    ```
    The QEMU window (tty1) should show the "Currawong setup" welcome box. Complete it, log in as root and run `systemctl is-active currawongd` and `curl -fsS http://127.0.0.1:9090/healthz`. CI checks only that `currawong-firstboot.service` started, from the serial log.
- The systemd unit was checked by reading it, not by `systemd-analyze verify` or `systemd-analyze security`. In particular, the parser worker's seccomp and rlimit calls under `SystemCallFilter=@system-service seccomp` and `MemoryDenyWriteExecute=yes` have not been exercised on Linux.
- The wizard was not run interactively (no whiptail session); only its config output and input patterns were tested.
- mkosi config syntax was written for mkosi v25 and not built. The AMI import commands in `docs/packaging.md` were not run. The appliance root is a fixed 8 GiB and does not grow to fill a larger disk.
- The Helm chart was linted and rendered, not installed on a cluster.
- hadolint is not installed, so the Dockerfile was not linted.
- `cargo deny check advisories` on the #46 tree, with a freshly fetched advisory database, fails on advisories published after the last run: RUSTSEC-2026-0346 to 0349 (rustls 0.23.45) and RUSTSEC-2026-0367 to 0369 (zip 2.4.2 and 8.6.0). `bans`, `licenses` and `sources` pass. #46 does not change dependencies, so these are left for a dependency update.
- Issue #46 names a `crates/setup-tui` crate on ratatui. The first-boot wizard is a `whiptail` script (`packaging/setup/currawong-setup`) instead, to keep the change to packaging files. A ratatui wizard is still open.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
