# Fuzzing

Fuzz entry points live in library code so the normal test suite does not need libFuzzer:

- `currawong_smtp::fuzz::{command, data, sasl}`. `data` uses the session's own framing (`LinesCodec` with the line limit, then `push_data_line`, including the drain after an oversized message).
- `currawong_parser::fuzz::mime`.
- `currawong_fuzzstand::*` for the rest: `archive_extract` (the first byte picks the attachment name, two passwords are tried), `office_detect` (file type and Office/RTF checks), `pspf_parse`, `dlp_scan`, `url_rewrite` (`currawong_scan::urls::fuzz`: link rewriting of a whole message, MIME, HTML and text), `auth_strip` (forged Authentication-Results), `clamd_address`, `parser_ipc` (length-prefixed frames and the JSON request) and `spool_envelope` (envelope JSON).

`currawong_fuzzstand::TARGETS` lists every target. A test checks that it matches `fuzz/fuzz_targets/`, `fuzz/Cargo.toml` and `docs/ci/fuzz.yml`.

## Stable stand-in

`cargo test -p currawong-fuzzstand` runs every target over the built-in seeds and every file in `testdata/`, then over 3000 deterministic mutations per target (bit flips, inserts, deletes, truncation, splices and CRLF, dot and NUL tokens). The mutation seed is fixed, so a failure repeats. For a longer run:

```bash
FUZZSTAND_ROUNDS=200000 cargo test -p currawong-fuzzstand --release
```

This is not coverage-guided. It catches panics in shallow paths, not the deep ones libFuzzer finds.

## libFuzzer

The libFuzzer targets are a separate package in `fuzz/` so they are not part of the workspace. `fuzz/Cargo.lock` is committed and was derived from the workspace lock, so the targets build against the same versions. With nightly and cargo-fuzz:

```bash
cargo install cargo-fuzz --locked
./scripts/seed-fuzz.sh
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run smtp_command -- -max_total_time=60 -rss_limit_mb=512
```

`scripts/seed-fuzz.sh` copies `testdata/` fixtures and small protocol seeds into `fuzz/corpus/<target>/`. Nightly CI is described in `docs/ci/fuzz.yml` (10 minutes per target, 512 MiB RSS). Crashes go to `fuzz/artifacts/` (ignored by git). Do not add exploit inputs; a crash is a panic or a resource blow-up, and the fix is a tighter limit or a rejected parse. Add the minimised input as a unit test next to the fix.

## Gaps

- clamd reply parsing (`classify` in `crates/scan/src/clamav.rs`) is private, so only address parsing is fuzzed.
