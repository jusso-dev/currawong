# Australian data residency

`residency.mode = "au"` is the default. The gateway refuses to send message content to a host outside the configured rules.

## Rules

Rules are host suffixes, exact names and CIDRs. `s3.ap-southeast-2.amazonaws.com` and `s3.ap-southeast-4.amazonaws.com` are the default object-storage suffixes (Sydney and Melbourne). A name is allowed when it equals a suffix or ends with `.{suffix}`. Lookalikes fail. IPv4 and IPv6 literals (`https://[::1]/`) match CIDRs only. Only `http` and `https` URLs are accepted.

The guard does not use GeoIP and it does not resolve names. A name rule trusts whoever controls that DNS name.

The default CIDRs are loopback plus every RFC 1918 range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). That treats any private address as on-premises, which is true for a single-site appliance and not for a VPC peered overseas. Narrow `residency.allowed_cidrs` to your own networks.

## What is checked

At startup (`currawongd` and `--check-config`) every configured content destination is checked, and startup fails on the first one that is denied:

- `scanner.clamd.address`. clamd receives whole messages. `unix:` sockets are local. A TCP address must be loopback or inside an allowed CIDR, so `tcp:8.8.8.8:3310` fails even when set through `CURRAWONG_SCANNER__CLAMD__ADDRESS`.
- `residency.content_endpoints`: sandbox, LLM, object store and webhook URLs. A `us-east-1` bucket fails.

At run time, every client that carries content off the gateway must call the guard per request, not only when it is built:

- `ResidencyGuard::check_request(&url)` before each request.
- `ResidencyGuard::check_redirect(&current, location)` for each redirect, before following it. It resolves a relative `Location` and returns the URL to request. HTTP clients must turn off automatic redirects so that no hop skips the guard.
- `ResidencyGuard::check_socket(&addr)` for raw TCP peers.

The `SandboxClient`, `LlmClient`, `ObjectStoreClient` and `WebhookClient` constructors in `currawong_core::content` check their base URL. Later HTTP clients (webhooks, Graph, sandbox, LLM) use the per-request calls above.

## Overrides and `mode = "off"`

An override is an exact URL plus a `reason` and an `approved_by`. Both must be non-empty or startup fails. The first use of each override is logged at warn level and recorded once in the audit log, so repeated use does not grow memory. Every configured override is listed in the report, used or not.

`mode = "off"` is refused unless `residency.off_approval = { reason = "...", approved_by = "..." }` is set. When it is, the first check logs a warning and the report carries the approval. Leave residency on for any deployment that handles Australian government, health or finance mail.

## Signed report

With `residency.signing_key_path` set, `currawongd` writes a signed report at startup and again at the start of each UTC calendar month:

- `report_dir/residency-report-<YYYY-MM-DDTHHMMSSZ>.json`, written atomically, mode `0600`. Old reports are never overwritten.
- `report_dir/residency-signing.pub`, the hex Ed25519 public key.

The report lists mode, an RFC 3339 `generated_at`, each content destination (clamd and `content_endpoints`) with its decision and matched rule, the overrides used since startup, every configured override, the `off` approval and the allow rules. Reports are canonical JSON signed with Ed25519. The signing key file is mode `0600` on Unix.

Without `residency.signing_key_path` no report is written, and `currawongd` logs a warning at startup.

An auditor verifies a report with `verify_report(&signed, &trusted_key)`, where `trusted_key` is the public key they pinned out of band (for example from `residency-signing.pub` at install time). The key embedded in a report is informational only. A report re-signed with any other key fails.
