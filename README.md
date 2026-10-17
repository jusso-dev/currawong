# Currawong

Currawong is an open source email security gateway written in Rust, built for Australian organisations. It sits in front of your mailboxes (Microsoft 365, Google Workspace or on-premises Exchange), checks every message going in and out, and keeps your data in Australia.

It runs as a VM, a container or an appliance image. Think FortiMail, Proofpoint or Mimecast, but memory safe, self-hostable and aware of Australian rules such as PSPF protective markings and Australian identifiers like TFNs and Medicare numbers.

> Status: M1 relay. The gateway accepts mail for configured domains, spools it, checks SPF, DKIM, DMARC and ARC, DKIM signs outbound tenant mail and ARC seals delivered mail once keys exist (`currawongd dkim generate`), parses and unpacks attachments (zip, 7z, tar, gzip, ISO and attached messages) in sandboxed worker processes, scans the message and every extracted part with ClamAV (clamd is required by default), and quarantines malware, active content (renamed executables, macros, OLE objects, encrypted archives), anything that could not be inspected, and DMARC `p=reject`. Official ClamAV signatures are the baseline, not a complete detector: add on-premises supplemental signatures and keep the file-type checks on. See [docs/adr/0005-malware-engines.md](docs/adr/0005-malware-engines.md). YARA rules in `scanner.yara.rules_dir` (yara-x) are matched against the message, every part and every archive member inside the parser worker, reload without a restart, and appear on the scan report for policy; starter rules are in [rules/yara/](rules/yara/). Outbound mail is scanned for TFN, Medicare, ABN, ACN, driver's licence and card numbers with checksum validation, and the default policy pack holds it for review at five distinct TFNs, Medicare, card or licence numbers (logs carry redacted samples only). Outbound delivery enforces DANE and MTA-STS, uses verified opportunistic STARTTLS otherwise, and sends daily TLS-RPT reports; see [docs/outbound-tls.md](docs/outbound-tls.md). Policies can require TLS or DANE for a message, and encrypt it with S/MIME when the recipient's certificate is known or hold it in a secure portal reached by link and one-time code. Spam, phishing and BEC blocking are not in this milestone. Checks that need a live clamd, a live MX or a second signature set are listed in [docs/VALIDATION.md](docs/VALIDATION.md).

## Why

- Mail gateways parse hostile input at high volume while exposed to the internet. That is exactly where memory safety pays off.
- Australian buyers need data residency, ACSC threat feeds and PSPF marking enforcement. Global vendors treat these as afterthoughts.
- MSPs need real multi-tenancy without per-tenant appliances.

## Features (planned)

| Area | What it does |
| --- | --- |
| SMTP gateway | Inbound and outbound relay on tokio, STARTTLS, MTA-STS, DANE, TLS-RPT, greylisting, rate limits, DNSBLs, connection reputation |
| Sender authentication | SPF, DKIM, DMARC and ARC via Stalwart's `mail-auth`, daily DMARC aggregate (RUA) reports, BIMI logo lookup |
| Malware | ClamAV (clamd), YARA, true file type checks, nested archive extraction with limits, macro and OLE detection, sandbox detonation hook |
| Phishing | URL rewriting with time-of-click checks, lookalike and homoglyph domains, HTML smuggling, QR code phishing |
| BEC | Display name spoofing, payment and invoice change detection, optional pluggable LLM classifier |
| Spam | Bayesian and rule scoring |
| Outbound data protection | TFN, Medicare, ABN, ACN, driver's licence and Luhn-checked card detection, policy-based TLS and encryption |
| Protective markings | Read and enforce `X-Protective-Marking` (OFFICIAL, OFFICIAL: Sensitive, PROTECTED) |
| Quarantine | Quarantine store, user digests, release workflow |
| Policy | Per domain, group and user policy engine |
| Admin | axum web UI and API, RBAC, MSP multi-tenancy, audit log |
| Mailbox platforms | M365, Google Workspace and on-premises Exchange 2016, 2019 and SE (connectors, hybrid, Edge, journaling monitor mode), with post-delivery remediation via Graph, Gmail API or legacy EWS |
| Feeds and SIEM | ACSC CTIS feeds, syslog/CEF and webhook export, first-class [Wedgetail](https://github.com/yumaitau/wedgetail) integration |
| Residency | On-premises or AWS Sydney and Melbourne only, enforced in config |
| Hardening | Sandboxed parser processes, cargo-fuzz targets, memory and size limits |

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the ADRs in [docs/adr](docs/adr).

```
internet -> [smtp listener] -> [spool (durable queue)] -> [pipeline workers]
                                                     auth -> scan (isolated) -> dlp -> policy
                                                                       |
                                     deliver (mail-send) / quarantine / reject -> events -> SIEM
```

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `crates/core` | Shared types: `MessageId`, `Direction`, `Verdict`, errors |
| `crates/smtp` | SMTP server and outbound delivery |
| `crates/spool` | Durable on-disk queue |
| `crates/auth` | SPF, DKIM, DMARC, ARC, BIMI |
| `crates/scan` | Scanner orchestration and isolated parser workers |
| `crates/classify` | Spam scoring (per-tenant Bayes and TOML rules) and lookalike domains |
| `crates/dlp` | Australian identifier detection and protective markings |
| `crates/policy` | Policy engine and scoring |
| `crates/quarantine` | Quarantine store and digests |
| `crates/admin` | axum admin API and UI |
| `crates/integrations` | Event export: syslog (RFC 5424, CEF), signed webhooks and Wedgetail. See [docs/events.md](docs/events.md) |
| `crates/currawongd` | The daemon binary |
| `crates/setup-tui` | `currawong-setup`, the first-run wizard |

## Roadmap

- **M0 skeleton:** workspace, config, logging, CI, spool format.
- **M1 MVP:** working relay with sender authentication and ClamAV.
- **M2 FortiMail parity:** spam, URL protection, BEC, DLP, quarantine, admin UI, multi-tenancy, mailbox APIs.
- **M3 beyond:** LLM BEC classifier, sandbox detonation, residency attestation, appliance images.

## Building

```
cargo check --workspace
cargo test --workspace
```

Packaging for the container image, Debian package, appliance image and Helm chart is described in [docs/packaging.md](docs/packaging.md). It is not yet verified end to end; see [docs/VALIDATION.md](docs/VALIDATION.md).

CI runs from `.github/workflows/`: `ci.yml` (checks), `release.yml` (packaging) and `fuzz.yml` (nightly fuzzing).

## Licence

MIT. See [LICENSE](LICENSE).
