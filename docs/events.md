# Events: `currawong.event.v1`

The gateway emits one event for every verdict it applies, and the schema also covers URL clicks, quarantine releases, admin actions and verdict changes. Events are exported to syslog, signed webhooks and Wedgetail by `crates/integrations` (`currawong_integrations::export`).

## Schema

Every event is a JSON object with these common fields and a `type` tag.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `currawong.event.v1` |
| `id` | string | ULID, unique per event. Sorts by time |
| `time` | string | RFC 3339, UTC |
| `tenant_id` | string, optional | Tenant that owns the message or action |
| `type` | string | One of the types below |

| `type` | Fields |
| --- | --- |
| `message_verdict` | `message_id`, `direction` (`inbound` or `outbound`), `mail_from`, `rcpt_to` (array), `verdict` (`deliver`, `quarantine`, `reject`, `discard` or `defer`), `reason` (optional) |
| `url_click` | `message_id`, `recipient` (the copy's recipients, comma separated; empty when there were too many), `url`, `action` (`allowed`, `warned` or `blocked`) |
| `quarantine_release` | `message_id`, `released_by`, `rcpt_to` (array) |
| `admin_action` | `actor`, `action`, `target` |
| `verdict_changed` | `message_id`, `from`, `to`, `changed_by` |

Example:

```json
{"schema":"currawong.event.v1","id":"01JA0000000000000000000001","time":"2026-10-17T00:00:00Z","tenant_id":"tenant-a","type":"message_verdict","message_id":"01JA00000000000000000000M1","direction":"inbound","mail_from":"billing@example.net","rcpt_to":["ap@example.com.au"],"verdict":"quarantine","reason":"malware"}
```

New fields may be added to v1. Consumers must ignore fields they do not know. Removing or renaming a field needs `currawong.event.v2`.

## Severity

CEF severity (0 to 10) is the base. Syslog and OCSF severities are derived from it.

| Event | CEF | Syslog | OCSF `severity_id` |
| --- | --- | --- | --- |
| verdict `deliver` | 1 | 6 informational | 1 |
| verdict `defer` | 3 | 6 informational | 2 |
| verdict `discard` | 5 | 5 notice | 3 |
| verdict `quarantine` | 7 | 4 warning | 4 |
| verdict `reject` | 8 | 4 warning | 4 |
| `url_click` blocked / allowed | 7 / 3 | 4 / 6 | 4 / 2 |
| `quarantine_release`, `verdict_changed` | 5 | 5 notice | 3 |
| `admin_action` | 3 | 6 informational | 2 |

## CEF

`CEF:0|Currawong|Currawong Gateway|<version>|<type>|<name>|<severity>|<extension>`

Header fields escape `\` and `|`, and line breaks become spaces. Extension values escape `\` and `=`, and encode line breaks as `\n` and `\r`. Golden files for every event type are in `testdata/cef/`.

| Event field | CEF key |
| --- | --- |
| `time` | `rt` (milliseconds since the epoch) |
| `id` | `externalId` |
| `tenant_id` | `cs1` (`cs1Label=tenant`) |
| `message_id` | `cs2` (`cs2Label=messageId`) |
| `verdict`, `action`, `to` | `act` (`release` for a quarantine release) |
| `mail_from`, `released_by`, `actor`, `changed_by` | `suser` |
| `rcpt_to` (comma separated), `recipient` | `duser` |
| `direction` | `deviceDirection` (0 inbound, 1 outbound) |
| `reason` | `reason` |
| `url` | `request` |
| `target` | `cs3` (`cs3Label=target`) |
| `from` (previous verdict) | `cs4` (`cs4Label=previousVerdict`) |

## Syslog

RFC 5424 over TCP or TLS (TLS is the default), with octet-counted framing (RFC 6587, RFC 5425). Facility `local0`, APP-NAME `currawong`, MSGID is the event `type`, no structured data. The MSG is the CEF line by default, or the JSON event with `payload = "json"`.

```
<132>1 2026-10-17T00:00:00.000Z gw1.example.com.au currawong - message_verdict - CEF:0|Currawong|...
```

## Webhook

`POST` with `Content-Type: application/json` and body `{"schema":"currawong.event.v1","events":[...]}`.

- `X-Currawong-Timestamp`: Unix seconds.
- `X-Currawong-Signature`: `v1=` followed by the hex HMAC-SHA256 of `{timestamp}.{body}` with the shared secret.

Receivers recompute the HMAC over the raw body, compare in constant time, and refuse timestamps more than 300 seconds from their clock. `currawong_integrations::export::webhook::verify` does exactly that. Any 2xx response is success. Anything else is retried.

## Wedgetail

Wedgetail's ingest API could not be checked for this release (see `docs/VALIDATION.md`), so the connector uses the fallback from issue #42: OCSF over HTTPS.

- `POST` to the configured URL, `Authorization: Bearer <token>`, `Content-Type: application/json`.
- Body: a JSON array of OCSF 1.3 events. Any 2xx response is success.

| Event | OCSF class | `activity_id` | `disposition_id` |
| --- | --- | --- | --- |
| `message_verdict` | Email Activity (4009) | 3 Scan | deliver 1 Allowed, reject 2 Blocked, quarantine 3 Quarantined, discard 6 Dropped, defer 14 Delayed |
| `verdict_changed` | Email Activity (4009) | 99 Other | from the new verdict |
| `quarantine_release` | Email Activity (4009) | 99 Other | 9 Restored |
| `url_click` | Email URL Activity (4012) | 3 Scan | blocked 2, allowed 1 |
| `admin_action` | API Activity (6003) | 99 Other | 0 |

Common OCSF fields: `category_uid`, `type_uid` (`class_uid * 100 + activity_id`), `time` (milliseconds), `severity_id`, `message` (the event type), `metadata.uid` (event id), `metadata.tenant_uid`, `metadata.product`, `metadata.version`. Email Activity adds `email.uid`, `email.from`, `email.to` and `direction_id` (1 inbound, 2 outbound). The full Currawong event is kept in `unmapped.currawong`, so nothing is lost when a field has no OCSF home.

## Delivery and buffering

Each exporter has its own bounded in-memory queue and worker. Emitting an event never waits: a slow or offline SIEM delays only its own exporter.

1. The event goes on the exporter's queue (`queue_capacity`, default 1024).
2. If the queue is full, it is written to `overflow_dir/<exporter>/<id>.json` (write to `.tmp`, then rename).
3. If the overflow already holds `overflow_max_files` events (default 100,000), the event is dropped and `currawong_events_dropped_total{sink=...}` is incremented.

Workers send batches of up to `batch_size` events, oldest overflow files first. A failed batch is moved to the overflow and retried with exponential backoff from 1 second to 60 seconds. Delivery is at least once. Ordering is best effort, so use `time` and `id`.

Overflow files are not fsynced. Mail durability comes first, and a power loss can lose buffered events.

## Residency and TLS

Every exporter destination is checked against the residency guard (`docs/residency.md`) when the exporter is built and again before each send. HTTP exporters also check every redirect target, and a refused redirect fails the send. Syslog destinations are checked as `syslog://host:port` or `syslog-tls://host:port`, which is also the form a residency override must use.

HTTP exporters require `https`, ignore proxy environment variables and always verify certificates against the public web roots plus an optional private CA (`ca_file`). There is no setting that disables verification.

## Configuration

The `[events]` section of the main configuration (`crates/core/src/config.rs`, commented example in `config/currawong.example.toml`):

```toml
[events]
queue_capacity = 1024
batch_size = 100
overflow_max_files = 100000
# overflow_dir defaults to <spool.dir>/events

[events.syslog]
address = "siem.corp.example:6514"
tls = true
# ca_file = "/etc/currawong/siem-ca.pem"
payload = "cef"            # or "json"

[events.webhook]
url = "https://10.20.0.5/currawong"
secret_file = "/etc/currawong/webhook.key"

[events.wedgetail]
url = "https://wedgetail.corp.example/api/ingest/ocsf"
token_file = "/etc/currawong/wedgetail.token"
```

`currawongd --check-config` checks the shape of each sink (host and port for syslog, `https` for the webhook and Wedgetail) and runs every destination through the residency guard. A foreign SIEM fails the check. At start-up the daemon builds the sinks and installs the event bus. On shutdown it keeps sending for up to 10 seconds, then writes what is still queued, including a batch whose send it abandons, to the overflow for the next start.

## Emitters

| Event | Emitted by |
| --- | --- |
| `message_verdict` | The scheduler, after each verdict is applied (deliver, quarantine hold, reject, discard, defer). Split messages emit one per recipient group |
| `admin_action` | `policy.reload` when the policy files or database change. Actor is `policy-store` until the admin API exists |
| `quarantine_release`, `url_click`, `verdict_changed`, other admin actions | Not yet: release, click-time protection and the admin API are not built. TODO hooks are in `crates/quarantine`, `crates/scan/src/url_rewrite.rs` and `crates/admin` |


## Outbreak retrospective verdicts (ADR 0010)

Outbreak protection reuses `verdict_changed`. `from = "deliver"` means handed to the local delivery queue; `to = "retro_detection"` means newly detected after that hand-off. It does not mean a mailbox item was moved or deleted. `changed_by` is `outbreak:<source>:<indicator>`; sources include `intel:<feed>:<threat>`, `yara:<namespace>:<rule>` and `clamav:<signature>`. `tenant_id` and `message_id` identify the delivered copy. Normal severity for verdict changes applies. Notification is at least once around crashes; adapters must deduplicate.

```json
{"schema":"currawong.event.v1","id":"01JA0000000000000000000006","time":"2026-10-25T00:00:00Z","tenant_id":"tenant-a","type":"verdict_changed","message_id":"01JA00000000000000000000M1","from":"deliver","to":"retro_detection","changed_by":"outbreak:intel:openphish:phishing:https://phish.example.test/login"}
```

The durable detection passed to a `Remediation` adapter also carries direction, sender, recipients and delivery time. The default adapter logs only; real mailbox remediation is #41/#51. Existing signed event webhook destinations can receive these events.
