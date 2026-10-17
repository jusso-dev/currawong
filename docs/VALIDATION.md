# Validation

Commands run on this tree, and the checks that were not run.

## Ran

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (advisories, bans, licences and sources). Hickory is 0.26 so the 0.25 proto advisories are not in the tree. `RUSTSEC-2023-0071` (the `rsa` crate timing issue) is ignored in `deny.toml`: that crate only generates DKIM keys on the appliance. Signing uses `mail-auth`'s aws-lc backend.
- `cargo run -p currawongd -- --config config/currawong.example.toml --check-config`

Unit tests use fakes for DNS, clamd and the downstream SMTP sink. They bind port 0, not port 25. The EICAR test string is produced at build time from XOR bytes and is not stored as a contiguous string in the repository.

## Not run, and why

- Live clamd. No clamd was listening. `CLAMD_ADDR=... cargo test -p currawong-scan clamav -- --ignored` is the check. `deploy/docker-compose.yml` starts `clamav/clamav:stable`.
- A second, email-focused signature set. Config accepts `scanner.extra_signature_dirs` and `scanner.extra_database_paths`. Currawong checks that those paths exist and expects the operator to point clamd at them (`OfficialDatabaseOnly no`). It does not ship or download a supplemental set, and it does not upload mail.
- Live MX delivery. Delivery tests use an in-process SMTP sink. A real MX lookup and a remote 250 were not exercised.
- DMARC aggregate reports to a real report consumer. `cargo test -p currawong-auth --test dmarc_report` validates the generated XML, the gunzipped attachment and a report built from hostile control characters against `testdata/dmarc/rua.xsd` (RFC 9990 Appendix A, which replaces RFC 7489 Appendix C) with `xmllint`. The test fails if `xmllint` (libxml2-utils) is missing. `rua` consent answers come from the in-process TXT cache and MX answers from `MapDns`; the live resolver path, its timeouts and a real MX were not exercised. Report destinations are refused when they are malformed, an IP literal, one of our own domains, or when an MX resolves to a loopback, private, link-local, CGNAT or unique-local address. Delivery re-resolves the MX, so the delivery-side address filter is still what stops DNS rebinding. Reports are queued as ordinary outbound mail and are not DKIM signed yet: they pick up outbound signing once delivery applies it, and until then reach a DMARC pass only through SPF for the report address domain. Known limits: a `!0` size suffix parses the same as no limit; a `_report._dmarc` record's own `rua` override (RFC 9990 section 4 step 9) is not applied; rows that arrive after their day was reported (a message deferred past the one-hour grace period) are dropped; reports are per policy domain for the whole gateway, not per tenant.
- BIMI VMC verification. `default._bimi.<domain>` is read for the DMARC `header.from` domain, only when the published DMARC record has `p` and `sp` at quarantine or reject and `pct` absent or 100, and the logo and authority URLs pass HTTPS, host name and length checks. The result is stored beside quarantined mail in `bimi.json` with `displayable: false`. When an `a=` tag is published the VMC status is `unverified`: the certificate is not fetched, its chain is not checked against the BIMI trust roots, and the logo must not be shown as verified. The quarantine UI that displays the logo does not exist yet (admin is a stub). The BIMI lookup in the daemon uses live DNS and was only tested with an in-process TXT map.
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
