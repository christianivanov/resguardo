# 0001. Single process with the egress boundary drawn by crates

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The target architecture splits Resguardo into two processes: `front`, which authenticates, scans and decides, and `connect`, the only process allowed to reach the internet and the only one that holds provider credentials. A compromised `front` could then not exfiltrate anything on its own.

Two processes mean two binaries, an internal protocol between them, its authentication, and twice the deployment work. That does not fit the v0.1 timeline (launch before 9 February 2027) next to streaming, Spanish validators, the signed log and the lab.

## Decision

v0.1 ships **one binary and one process**. The future split is prepared in the code:

- Outbound traffic lives only in `resguardo-egress`, which also owns provider credentials.
- `resguardo-egress` depends only on `resguardo-core` and `resguardo-audit`. It **never** depends on `resguardo-scan` or `resguardo-policy`, and only receives requests that have already been decided.
- `cargo deny check` enforces these edges with `[bans]` wrappers in `deny.toml`, so a violation fails the build instead of a review.

## Consequences

- Simple to run: one binary, one config file, one container.
- A memory-level compromise of the process reaches everything, credentials included. The threat model must say so, and the README must not claim process isolation.
- Moving to two processes in v0.2 means adding a transport between crates that already have a narrow interface; it is a reorganisation, not a rewrite.
- Each new dependency between crates has to be checked against the allowed graph.
