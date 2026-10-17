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
- `cargo +nightly fuzz build`. `cargo-fuzz` is not installed here. `cargo test -p currawong-fuzzstand` is the stand-in and does not need libFuzzer. See `docs/fuzzing.md`.
- seccomp. The parser worker installs a seccompiler filter only on Linux. This machine is macOS, so workers run unsandboxed. The Linux filter is untested here.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## DLP (Australian identifiers)

Tests use the ATO's published TFN (`123 456 782`) and ABN (`51 824 753 556`) samples, ASIC's published ACN examples, the common Medicare sample (`2123 45670 1`), card scheme test numbers, and synthetic values built to pass a checksum. No real person's identifier is in the repository.

- Single-digit changes. TFN, ABN and card (Luhn) checks reject every single-digit change. The Medicare check digit covers only the first eight digits, so changes to the issue number or IRN are not detectable. ASIC's ACN check uses even weights, so a change of 5 at weights 8, 6, 4 or 2 gives another valid ACN. `crates/dlp/tests/detectors.rs` asserts exactly that.
- Driver's licences have no check digit. They are matched only next to a context word, and the state formats overlap, so the kind is "driver's licence", not a specific state.
- Text extraction covers text and HTML bodies, forwarded messages, and top-level docx, xlsx and PDF attachments, using documents built in `crates/parser-worker/tests/text.rs`. Documents inside zip or other archives are not text-extracted. Real-world Office and PDF files from other producers were not tested; scanned (image-only) PDFs yield no text.
- `cargo deny check` with `pdf-extract` and `calamine` added: bans, licences and sources pass. Advisories fail on new 2026 entries against `rustls` 0.23.45 and `zip` 2.4.2 and 8.6.0, which were already in the lockfile (`zip` 8.6.0 through `mail-auth`; `calamine` shares it). The `zip` advisories concern `extract()` to a directory, which neither the parser nor `calamine` calls. Upgrading those crates is left to a separate change.
- The quarantine-for-review rule is in the M1 `currawong-policy::decide` so the default holds outbound mail at 5 distinct TFNs (`dlp.review_thresholds`). The policy engine rewrite (#37) should carry it into its default pack.

## ADR 0002 and the worker transport

ADR 0002 says the supervisor talks to parser workers over a Unix socket. Issue #23 specifies length-prefixed JSON on stdin and stdout. M1 follows the issue: `LengthDelimitedCodec` on the worker's standard streams. The ADR decision is unchanged. The transport should be reconciled in a later ADR update rather than silently rewritten.

## Malware accuracy

Official ClamAV signatures are the baseline only. See `docs/adr/0005-malware-engines.md`. Do not treat a clean clamd result, on the official set alone, as proof that a message is safe. File-type and macro findings are part of the M1 decision.
