# Packaging

Currawong ships as a container image, a Debian 12 package, an appliance disk image and a Helm chart. `.github/workflows/release.yml` builds and checks all four. What has and has not been run is in `docs/VALIDATION.md`.

Every form runs the same two binaries: `currawongd` and `currawong-parser-worker`, installed side by side in `/usr/bin` because the daemon looks for the worker next to its own executable. Config lives in `/etc/currawong/currawong.toml`, the spool in `/var/spool/currawong`, and SQLite state (greylist, relay credentials, residency reports) in `/var/lib/currawong`.

## Container

```bash
docker build -t currawong:dev .
```

- Built on `rust:1-bookworm`, run on `gcr.io/distroless/cc-debian12:nonroot` as user 65532. No shell, no package manager.
- Exposes 25, 587, 465, 8443 (admin UI, later milestone) and 9090 (metrics, `/healthz`, `/readyz`). `CURRAWONG_METRICS__LISTEN=0.0.0.0:9090` is set in the image.
- `HEALTHCHECK` runs `/usr/bin/currawong-healthcheck`, a std-only probe (`packaging/docker/healthcheck.rs`) that exits 0 only on `HTTP 200` from `/healthz`.
- The bundled config is `config/currawong.example.toml`. Mount your own config, plus `cert.pem` and `key.pem`, at `/etc/currawong`. The STARTTLS listeners do not start without them.
- Ports below 1024 bind as non-root because Docker sets `net.ipv4.ip_unprivileged_port_start=0` in the container network namespace. Under Kubernetes the Helm chart sets the same sysctl.
- Volumes: `/var/spool/currawong` and `/var/lib/currawong`. The spool holds accepted mail; keep it on durable storage.

```bash
docker run -d --name currawong -p 25:25 -p 587:587 -p 465:465 -p 127.0.0.1:9090:9090 \
  -v /srv/currawong/etc:/etc/currawong:ro \
  -v currawong-spool:/var/spool/currawong -v currawong-state:/var/lib/currawong \
  currawong:dev
```

## Debian package

```bash
cargo build --release --locked -p currawongd -p currawong-parser-worker -p currawong-setup-tui
cargo deb -p currawongd --no-build
sudo apt install ./target/debian/currawong_*_amd64.deb
```

Build on Debian 12 (or in `rust:1-bookworm`) so the binaries link against bookworm's glibc. `--no-build` is needed because `cargo deb` alone only builds `currawongd`, not the worker and wizard binaries from the other crates.

The package (`[package.metadata.deb]` in `crates/currawongd/Cargo.toml`):

- installs `/usr/bin/currawongd`, `/usr/bin/currawong-parser-worker`, `/usr/sbin/currawong-setup`, and `/etc/currawong/currawong.toml` as a conffile;
- creates the `currawong` system user, `/var/spool/currawong` and `/var/lib/currawong` (0750, `currawong:currawong`) and `/etc/currawong` (0750, `root:currawong`);
- generates a self-signed P-256 certificate for `hostname -f` if `/etc/currawong/cert.pem` and `key.pem` are both missing, so the daemon starts;
- enables and starts `currawongd.service` (`packaging/systemd/currawongd.service`).

The unit runs as `currawong` with only `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict` (only the spool and `/var/lib/currawong` are writable), `NoNewPrivileges=yes`, private `/tmp` and `/dev`, kernel and cgroup protection, `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK` and `SystemCallFilter=@system-service seccomp` minus `@privileged` and friends. `seccomp` is allowed so the parser worker can install its own, tighter filter. Check the result with `systemd-analyze security currawongd.service`.

`systemctl reload currawongd` sends SIGHUP, which reloads the certificate and key without closing a listener; if the new files do not load, the old certificate stays in use and the error is logged. To use an ACME CA instead of the self-signed certificate, replace `tls.cert` and `tls.key` with a `[tls.acme]` section (see the example config) and keep `cache_dir` under `/var/lib/currawong` so the unit can write it. The HTTP-01 listener on port 80 works with the existing `CAP_NET_BIND_SERVICE`. Open port 80 to the CA as well as 25, 465 and 587.

Then run `sudo currawong-setup` to write a real config.

## Setup wizard

`currawong-setup` (`crates/setup-tui`, ratatui) is a one-screen terminal form. It asks for the gateway hostname, accepted domains, the next hop (Microsoft 365, Google Workspace or Exchange), the networks allowed to relay, whether to use the local clamd, and whether to write a new self-signed certificate. Tab or the arrows move, Space toggles, Enter on Save writes.

On Save it validates every field, renders a short `/etc/currawong/currawong.toml` through the TOML serialiser (so input cannot add keys; everything else keeps its default), writes it to a temporary file created 0640 and owned by group `currawong`, runs `currawongd --check-config` on that file, and only then renames it over the old config. The certificate and key are generated in-process (rcgen, P-256, 825 days) and written the same way, so neither is ever world-readable. It then enables and restarts `currawongd`.

With `--firstboot --tty NAME` (the appliance) it also sets the system hostname and the root password (passed to `chpasswd` on stdin), writes `/var/lib/currawong/.setup-complete`, and stops the wizard on the other console. Esc does not leave the wizard on first boot. A serial console reports a 0x0 window, so the wizard falls back to 80x24 there.

## Appliance image

`packaging/appliance/` is an [mkosi](https://github.com/systemd/mkosi) (v25 or later) definition: Debian 12, UEFI with systemd-boot, an 8 GiB ext4 root, `clamav-daemon` and `clamav-freshclam`, nftables (SMTP in, everything else dropped), unattended security upgrades, DHCP on wired interfaces, no SSH server and a locked root account.

```bash
# Needs target/debian/currawong_*_amd64.deb from the step above.
sudo mkosi -C packaging/appliance build
raw=packaging/appliance/mkosi.output/currawong-appliance.raw
qemu-img convert -O qcow2 "$raw" currawong-appliance.qcow2                        # Proxmox, KVM
qemu-img convert -O vmdk -o subformat=streamOptimized "$raw" currawong-appliance.vmdk  # VMware
qemu-img convert -O vhdx "$raw" currawong-appliance.vhdx                          # Hyper-V (Gen 2)
```

On first boot `currawong-firstboot@tty1.service` and `currawong-firstboot@ttyS0.service` run `currawong-setup --firstboot` on the VGA console and the serial console, before the login prompts. Whichever console saves first wins; a lock stops two saves at once, and the other console is then released to its login prompt. The serial instance also serves the EC2 serial console and the CI boot test (`packaging/appliance/serial-expect.py`). `currawongd` stays disabled until the wizard has written a config. ClamAV signatures are downloaded by freshclam on first boot. If clamd was enabled in the wizard, mail is deferred until the signatures arrive and clamd is running, not delivered unscanned.

### AMI (ap-southeast-2)

The raw image boots on Nitro instances in UEFI mode. Import it with the VM Import service role (`vmimport`) and a bucket in Sydney:

```bash
aws s3 cp "$raw" s3://BUCKET/currawong-appliance.raw --region ap-southeast-2
aws ec2 import-snapshot --region ap-southeast-2 \
  --disk-container "Format=RAW,UserBucket={S3Bucket=BUCKET,S3Key=currawong-appliance.raw}"
aws ec2 register-image --region ap-southeast-2 --name currawong-appliance \
  --architecture x86_64 --boot-mode uefi --ena-support --root-device-name /dev/xvda \
  --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=SNAPSHOT_ID}"
```

EC2 has no VGA console. Run the wizard on the EC2 serial console (ttyS0), or pre-seed `/etc/currawong/currawong.toml`, `cert.pem`, `key.pem` and `/var/lib/currawong/.setup-complete` in the image and enable `currawongd.service`.

## Helm chart

`deploy/helm/currawong/` deploys a StatefulSet with a spool PVC and a state PVC, a `LoadBalancer` service with `externalTrafficPolicy: Local` (client IPs matter for DNSBL, greylisting and rate limits), and liveness and readiness probes on `/healthz` and `/readyz`. Pods run as 65532 with a read-only root filesystem, no capabilities and the `RuntimeDefault` seccomp profile.

```bash
kubectl create secret tls currawong-tls --cert=cert.pem --key=key.pem
helm install currawong deploy/helm/currawong --set-file config=my-currawong.toml
```
