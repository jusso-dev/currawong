# Fuzzing

Parser entry points live in library code so the normal test suite does not need libFuzzer:

- `currawong_smtp::fuzz::{command, data}`
- `currawong_parser::fuzz::{mime, archive, urls_in}`
- `currawong_scan::url_rewrite::fuzz`
- `currawong_dlp::fuzz_scan` (TFN checksum samples and PSPF markings)

`cargo test -p currawong-fuzzstand` runs those functions on fixed seeds. That is the stand-in when `cargo-fuzz` is not installed.

The libFuzzer targets are a separate package in `fuzz/` so they are not part of the workspace. When nightly cargo-fuzz is available:

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run smtp_command -- -max_total_time=60 -rss_limit_mb=512
```

`scripts/seed-fuzz.sh` copies `testdata/` fixtures into `fuzz/corpus/<target>/`. Nightly CI is described in `docs/ci/fuzz.yml` (10 minutes, 512 MiB RSS). Crashes belong in `fuzz/artifacts/`. Do not add exploit inputs; a crash is a panic or a resource blow-up, and the fix is a tighter limit or a rejected parse.
