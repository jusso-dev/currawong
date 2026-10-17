# Contributing

Currawong is a defensive mail gateway. Do not add exploit code, weaponised samples, or instructions for bypassing filters. Malware tests use the EICAR string, generated at build time, and nothing else. Identifier fixtures use published checksum samples.

## Checks

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo run -p currawongd -- --config config/currawong.example.toml --check-config
```

Tests must pass without a network, a display, clamd or a DNS server. Bind SMTP on port 0. Fakes stand in for DNS, clamd and the next hop.

`cargo test -p currawong-fuzzstand` covers the parser entry points when cargo-fuzz is not installed. See `docs/fuzzing.md`.

CI config is in `.github/workflows/`.

## Layout

Crates live under `crates/`. Decisions live in `docs/adr/`. The example configuration is `config/currawong.example.toml`. Australian English in user-facing docs and errors.
