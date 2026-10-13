# ADR 0002: Scanner isolation

Status: Proposed

## Context
MIME, archive, OLE, PDF and image (QR) parsing of hostile input is the riskiest code in the product, even in Rust (panics, decompression bombs, dependency bugs, unsafe in C bindings).

## Decision
- Parsing and extraction run in `currawong-parser` child processes, not threads.
- Each worker: no network (seccomp filter via `seccompiler` on Linux, deny `socket`, `connect`), `setrlimit` for address space (default 512 MiB) and CPU (default 30 s), read-only access to its input.
- Supervisor talks to workers over a Unix socket using length-prefixed `serde_json` frames (move to `bincode` if profiling shows need).
- A worker that crashes, times out or exceeds limits yields a `ScanOutcome::Failed`, which policy treats as quarantine by default (fail closed).
- Workers are recycled after N messages (default 500).
- ClamAV runs as its own `clamd` process and is reached over its socket.

## Consequences
Extra latency per message (process reuse keeps it low). Clear blast radius. macOS and Windows dev builds run workers without seccomp.
