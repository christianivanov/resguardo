# CLAUDE.md

Instructions for AI coding assistants working on Resguardo.

## Source of truth

- The design lives in `docs/SOLUTION.md` (kept locally, not versioned). What it does not say is not decided: ask before implementing it.
- If an annex contradicts an earlier section, the annex wins; point out the contradiction.
- `docs/adr/` records the decisions taken. A new design decision is proposed as an ADR **before** it is implemented.
- Ideas outside the v0.1 scope go to `LATER.md`, never into code.

## Working rules

1. One milestone at a time, in the order of the plan (M0 → M6).
2. Before writing code, show a five-line plan and wait for confirmation.
3. Small commits, each with tests, all checks green, Conventional Commits and `Signed-off-by` (`git commit -s`).
4. Commits must not include `Co-Authored-By` or "Generated with" trailers for AI tools.
5. For every detector and policy rule: write the golden test first, then the implementation.
6. After a task, run the local checks below and show their real output.
7. If a test fails and you do not know why, say so. Never change a test to make it pass.

## Local checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Builds are slow on the maintainer's machine (2017 Intel MacBook Pro): prefer `cargo check` and `cargo test -p <crate>` while iterating, and run the full set before committing.

## Never

- **Call the real OpenAI or Anthropic APIs** in tests, examples or the lab. Use `tools/mock-upstream`.
- **Log request content, virtual keys, provider credentials or the signing key**, not even in debug logs.
- **Fail open.** Any error in scanning, policy, audit, signing or configuration blocks the request.
- **Use `unsafe`.** Every crate has `#![forbid(unsafe_code)]`.
- **Implement cryptography.** Use established crates (`sha2`, `ed25519-dalek` or `ring`) and check their current documentation.
- **Pin dependency versions from memory.** Check crates.io and the current docs of `hyper`, `axum`, `reqwest` and `rustls`.
- **Add a dependency without asking**, or one whose license is not allowed by `deny.toml`.
- **Copy code from other projects.** Write it from scratch; if copying is ever unavoidable, ask first.
- **Build offensive capabilities.** The lab uses fake secrets and local servers, only to demonstrate the defence.

## Language

- Conversation with the maintainer: Spanish.
- Code, comments, commits, ADRs, docs and README: English.
- The maintainer comes from 8+ years of backend Java. Explain in one line any Rust choice that is not obvious from Java (ownership, lifetimes, `Pin`, `Send`, `async`).

## Repository layout

```text
crates/
  resguardo-core/     domain types, errors, configuration
  resguardo-scan/     scanning pipeline and detectors (pure)
  resguardo-policy/   decision from principal, request and findings (pure)
  resguardo-proto/    OpenAI and Anthropic normalization, SSE parser
  resguardo-egress/   destination allowlist, credentials, HTTP client and TLS
  resguardo-audit/    hash-chained, signed audit log and verification
  resguardo/          binary: HTTP server and CLI
config/               example configuration
docs/                 ADRs, threat model, accuracy and benchmark reports
fixtures/             synthetic requests, SSE streams, accuracy corpus
tools/mock-upstream/  fake OpenAI and Anthropic server
lab/                  docker compose exfiltration lab with an internal network
fuzz/                 cargo-fuzz targets
```

## Crate boundaries

| Crate | May depend on |
| --- | --- |
| `resguardo-core` | no workspace crate |
| `resguardo-scan`, `resguardo-policy`, `resguardo-proto`, `resguardo-audit` | `resguardo-core` |
| `resguardo-egress` | `resguardo-core`, `resguardo-audit`; **never** `scan` or `policy` |
| `resguardo` (binary) | all |

`cargo deny check` enforces this through `[bans]` in `deny.toml`. Add internal dependencies only when code uses them.

## Conventions

- **Errors:** `thiserror` in libraries, `anyhow` only in the binary. No `unwrap` or `expect` outside tests (clippy denies them).
- **Purity:** `resguardo-scan` and `resguardo-policy` do no I/O and do not read the clock.
- **Explicit limits:** every buffer, decode and recursion has a configurable maximum with a default.
- **Regular expressions:** the `regex` crate (linear time). Never `fancy-regex`. It has no look-around: check boundaries in code.
- **Determinism:** collections that get serialized are ordered (`BTreeMap`).
- **Findings never contain the matched value**, only class, span, rule, confidence and decoding layers.
- **Audit log fields:** strings, integers, booleans, objects and lists only. No floats; latencies are integer microseconds.
- **Glossary:** one name per concept in code (`Provider`, `Principal`, `VirtualKey`, `ProviderCredential`, `CanonicalRequest`, `ScanText`, `Scanner`, `Finding`, `DataClass`, `Action`, `Decision`, `AuditEntry`…), as defined in the design document.
