# Australian data residency

`residency.mode = "au"` is the default. The gateway refuses to send message content to a host outside the configured rules.

## Rules

Rules are host suffixes, exact names and CIDRs. `s3.ap-southeast-2.amazonaws.com` and `s3.ap-southeast-4.amazonaws.com` are the default object-storage suffixes (Sydney and Melbourne). A name is allowed when it equals a suffix or ends with `.{suffix}`. Lookalikes fail. IPv4 and IPv6 literals (`https://[::1]/`) match CIDRs only. Only `http` and `https` URLs are accepted.

The guard does not use GeoIP. Name rules are decided on the name, so on their own they trust DNS. Resolution is therefore a required second step (see "Resolving and pinning").

The default CIDRs are loopback plus every RFC 1918 range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). That treats any private address as on-premises, which is true for a single-site appliance and not for a VPC peered overseas. Narrow `residency.allowed_cidrs` to your own networks.

## What is checked at startup

`currawongd` and `--check-config` check every configured content destination, and fail on the first one that is denied:

- `scanner.clamd.address`. clamd receives whole messages. It must be `unix:/path` or `tcp:<ip>:<port>`; a TCP address must be loopback or inside an allowed CIDR, so `tcp:8.8.8.8:3310` fails even when set through `CURRAWONG_SCANNER__CLAMD__ADDRESS`.
- `residency.content_endpoints`: sandbox, LLM, object store and webhook URLs. A `us-east-1` bucket fails.

## Resolving and pinning

`ResidencyGuard::resolve(&url)` checks the URL, resolves it and returns the one `SocketAddr` to connect to. `ResidencyGuard::pin(&url, &resolved)` does the same for addresses a caller resolved itself.

- An exact name (`allowed_names`, meant for on-premises hosts) must resolve only to addresses inside an allowed CIDR. An internal name that DNS points overseas is refused.
- A host suffix (a cloud region) trusts the provider's DNS for that suffix.
- In every case the caller connects to the returned address and does not resolve the name again, so a DNS change between the check and the connection cannot move it.

## Run-time clients

`currawong_core::content::GuardedClient` is the client for anything that carries content off the gateway. `SandboxClient`, `LlmClient`, `ObjectStoreClient` and `WebhookClient` wrap it. Each holds an `Arc<ResidencyGuard>` and an `HttpTransport`:

- The base URL is checked when the client is built.
- `send` resolves and pins every request through the guard, then hands the transport the pinned address.
- The transport must not follow redirects. `send` follows them itself, at most `MAX_REDIRECTS` hops. Each `Location` is checked with `check_redirect` before it is resolved, so a redirect to a foreign host fails and is never requested. 303 (and 301 or 302 after a POST) continue as GET without the body; 307 and 308 keep both.

Webhooks (#42), Graph (#41), the sandbox (#28) and the LLM classifier (#32) implement `HttpTransport` and use these clients. Raw TCP peers call `check_socket`.

## Recipient-designated hosts

Traffic to hosts that the recipient's DNS chooses is outside the residency guard by design: SMTP delivery to the MX, MTA-STS policy fetches, TLS-RPT uploads and DMARC aggregate reports. It carries no stored customer content beyond what delivery itself sends, and the destination is not ours to choose. SSRF protection still applies: those names must resolve to public addresses (unless `delivery.allow_private_mx` is set), and policy fetches and report uploads use only `https` on port 443 with a plain host name, no address literal and no user information.

## Overrides and `mode = "off"`

An override is an exact URL plus a `reason` and an `approved_by`. Both must be non-empty or startup fails. The first use of each override is logged at warn level and recorded once in the audit log, so repeated use does not grow memory. Every configured override is listed in the report, used or not.

`mode = "off"` is refused unless `residency.off_approval = { reason = "...", approved_by = "..." }` is set. The approval is an audit gate, not a control: it records who turned residency off and why, and then nothing is checked. The warning and the audit entry are written as soon as the guard is built (at `--check-config` and at startup), whether or not any content destination is configured, and every report carries the approval. Leave residency on for any deployment that handles Australian government, health or finance mail.

## Signed report

With `residency.signing_key_path` set, `currawongd` writes a signed report once per UTC calendar month, and again at startup when the residency section or clamd address changed since the last report:

- `report_dir/residency-report-<YYYY-MM-DDTHHMMSSZ>.json`, written atomically, mode `0600`. Reports are never overwritten.
- `report_dir/residency-signing.pub`, the hex Ed25519 public key.
- `report_dir/last-report.json`, the month and configuration digest of the last report, so a restart keeps the cadence.

Reports older than `residency.report_retention_days` (default 400) are deleted. A failed write is logged, counted in `currawong_residency_report_failures_total` and reported by `/readyz` as `residency-report` until a later write succeeds.

The report lists mode, an RFC 3339 `generated_at`, each content destination (clamd and `content_endpoints`) with its decision and matched rule, the overrides used since startup, every configured override, the `off` approval and the allow rules. Reports are canonical JSON signed with Ed25519.

The signing key is created atomically: a temporary `0600` file, synced, then linked into place, so a crash never leaves a partial key and two starts never replace each other's key. Its directory is created `0700`. An existing key readable by group or others is refused at startup.

Without `residency.signing_key_path` no report is written, and `currawongd` logs a warning at startup.

An auditor verifies a report with `verify_report(&signed, &trusted_key)`, where `trusted_key` is the public key they pinned out of band (for example from `residency-signing.pub` at install time). The key embedded in a report is informational only. A report re-signed with any other key fails.

## Optional domain-age and click analysis (ADR 0012)

`rdap.enabled` permits IANA bootstrap downloads and public HTTPS registry lookups. Only registrable domain names leave the gateway; own domains are excluded. DNS and RDAP providers may be overseas. No mail addresses, content, attachments or full message URLs are submitted. SQLite caches reduce lookups; `rdap.scan_urls` separately enables URL-domain enrichment at scan time.

`click.fetch.enabled` permits recipient-designated page fetches outside Australia. Requests disclose their full URL, appliance address and fixed User-Agent, without cookies, email content, credentials or referrers. Every fetched HTTP or meta-refresh hop is resolved, checked and pinned; private/metadata/special-use addresses are refused. Wrappers are decoded locally, with reputation checked at every hop. These fetches can activate tracking and one-time links.

The analyser receives full URLs and, only with `click.analyser.include_html`, a bounded HTML excerpt. `click.analyser.url` joins startup content endpoint checks; runtime POSTs call `check_request`, resolve and pin. All DNS answers must be loopback, even with a residency override. Redirects are checked with `check_redirect` and refused. Any analyser-controlled browser/ML egress needs its own equivalent protections. See [ADR 0012](adr/0012-click-analysis.md) for contracts and limits.
