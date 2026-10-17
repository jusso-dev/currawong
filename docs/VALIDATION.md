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
- Spool power loss. The spool crash tests (`cargo test -p currawong-spool`) stop `accept`, `transition` and `recover` after every filesystem step, which models a process crash. They cannot model power loss, where writes or renames that were never fsynced may be lost or reordered. The fsync ordering that keeps the 250 promise across power loss was reasoned through, not tested. A real check needs a fault-injecting block device or filesystem, such as `dm-flakey` or a `LazyFS` mount.
- 7z extraction. 7z is recognised by magic and flagged, and it is not unpacked (no `sevenz` crate in the workspace). zip, tar, gz and a minimal ISO walk are implemented. RAR is detected and not extracted.

## DLP (Australian identifiers)

The only identifier literals in the repository are published samples: the ATO's TFN (`123 456 782`) and ABN (`51 824 753 556`), ASIC's ACN examples, the common Medicare sample (`2123 45670 1`) and card scheme test numbers. Where tests need more distinct valid values they derive them at run time (`synthetic_tfns` in `crates/dlp/tests/detectors.rs`, `sample_tfns` in `crates/currawongd/tests/pipeline.rs`) and do not commit them.

- Single-digit changes. TFN (nine and eight digit), ABN and card (Luhn) checks reject every single-digit change. The Medicare check digit covers only the first eight digits, so changes to the issue number or IRN are not detectable. ASIC's ACN check uses even weights, so a change of 5 at weights 8, 6, 4 or 2 gives another valid ACN. `crates/dlp/tests/detectors.rs` asserts exactly that.
- False positives. One random nine-digit number in eleven is a valid TFN, so a bare number scores below the default `min_confidence`. It counts when "TFN" is within 60 bytes before or 30 after (+30), or anywhere in the same text, such as a column header (+15). Medicare works the same way. Eight-digit TFNs need the word nearby. Numbers glued to letters (`INV123456782`) lose 20.
- Evasion. Unicode decimal digits (fullwidth, Arabic-Indic and other common scripts) are read as digits, zero-width and bidi format characters are ignored, and up to three separators (spaces, tabs, line breaks, `. , - / _` and Unicode spaces and dashes) may sit between digit groups. Letters, other punctuation and wider gaps split numbers. The licence detector reads ASCII only.
- Work is linear in the text. One MiB of hostile input scans in a few hundred milliseconds in release; `hostile_input_scans_in_linear_time` bounds it at 1 s (2 s in dev builds, where the crate is built at opt-level 2). Text over 2 MiB is not scanned and marks the report incomplete.
- Driver's licences have no check digit. They are matched only next to a context word, and the state formats overlap, so the kind is "driver's licence", not a specific state. Samples are fully masked.
- Text extraction covers the subject, attachment names, text and HTML bodies (tags removed; comment, script, style and attribute text kept; numeric entities decoded), forwarded messages, and top-level docx (body, headers, footers, footnotes, endnotes, comments), xlsx (cells streamed, at most one million) and PDF attachments, using documents built in `crates/parser-worker/tests/text.rs`. Bodies are collected first. PDF and Office parsing only runs in the parser worker; in-process parsing, and the scanner-disabled path, mark documents as unread.
- Incomplete scans are held for review: text over the 1 MiB extraction budget, a document over 32 MiB or one that fails to parse (encrypted PDFs included), or documents skipped outside the worker. Documents inside zip or other archives are not text-extracted and do not mark the scan incomplete. Real-world Office and PDF files from other producers were not tested; scanned (image-only) PDFs yield no text.
- PDF extraction has no time or output bound of its own. The worker's CPU, memory and wall-clock limits apply. A hostile `sharedStrings.xml` count can make calamine over-allocate; that also only happens inside the worker.
- `cargo deny check` with `pdf-extract` and `calamine` added: bans, licences and sources pass. Advisories fail on new 2026 entries against `rustls` 0.23.45 and `zip` 2.4.2 and 8.6.0, which were already in the lockfile (`zip` 8.6.0 through `mail-auth`; `calamine` shares it). The `zip` advisories concern `extract()` to a directory, which neither the parser nor `calamine` calls. Upgrading those crates is left to a separate change.
- The decision is policy. DLP exposes `dlp.<kind>` counts and a `dlp.incomplete` flag as signals; the default pack (`config/policies/default.toml`) quarantines outbound mail in the `dlp` queue at 5 distinct TFNs, Medicare, card or licence numbers, or when the scan is incomplete. `crates/policy/tests/engine.rs` and `crates/currawongd/tests/pipeline.rs` cover it end to end.

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
