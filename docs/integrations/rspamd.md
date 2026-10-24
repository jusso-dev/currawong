# Rspamd alongside Currawong

Rspamd is optional and off by default. Run it on the gateway or an on-premises host allowed by residency. Rspamd is Apache-2.0 and communicates only over HTTP; no Rspamd code is linked.

Upstream references verified 24 October 2026: [HTTP protocol](https://docs.rspamd.com/developers/protocol/), [controller](https://docs.rspamd.com/workers/controller/), [installation](https://docs.rspamd.com/getting-started/installation/). Scan and learning endpoints are separate by default.

A local Compose starting point (pin approved image versions/digests for deployment):

```yaml
services:
  rspamd:
    image: rspamd/rspamd:latest
    ports:
      - "127.0.0.1:11333:11333"
      - "127.0.0.1:11334:11334"
    volumes:
      - ./local.d:/etc/rspamd/local.d:ro
      - rspamd-data:/var/lib/rspamd
    depends_on: [redis]
  redis:
    image: redis:latest
    command: [redis-server, --save, "60", "1"]
    volumes: [redis-data:/data]
volumes:
  rspamd-data: {}
  redis-data: {}
```

Set `local.d/redis.conf` to `servers = "redis:6379";`. Configure a controller password/enable-password using upstream instructions and the secret file mechanism on the gateway; never use the image's placeholder password. Published-port connections are not container loopback. Restrict access to the controller, persist Redis for learning, and configure a local recursive DNS resolver as described upstream. Audit/disable remote lookups, external scanners and telemetry in Rspamd as residency requires. The example does not perform that audit or deploy any service.

```toml
[scanner.rspamd]
url = "http://127.0.0.1:11333"
# Optional: opts into learning on spam release, not merely scan access.
controller_url = "http://127.0.0.1:11334"
password_file = "/etc/currawong/rspamd-password"
required = true
timeout_secs = 15
max_size = 52428800
```

When Currawong itself runs in a container, use a private service address instead of its loopback and authorise that exact name/CIDR in residency. Use verified HTTPS for traffic crossing hosts. `/checkv2` receives raw message bytes, IP, Helo, From, one Rcpt per recipient, Queue-Id, Hostname and User when authenticated. The envelope has no reverse-hostname field, so Hostname currently carries HELO rather than performing another DNS lookup. Responses record action/score and bounded symbols; policy decides the disposition. `/learnham` and `/learnspam` receive raw bytes and optional Password. Only spam releases trigger automatic ham learning; no administrator mark-spam endpoint currently exists.

Required service failure defers mail and fails readiness. Optional unreachable service adds a report note. Invalid replies or size-limit failures quarantine through the existing scan-failure floor. No live Rspamd or Compose setup was run; tests use an in-process HTTP fake.
