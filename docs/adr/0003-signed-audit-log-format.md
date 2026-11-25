# 0003. Audit log format and signature

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

Resguardo promises that every decision leaves a receipt that a third party can verify. An ordinary log file can be edited without trace. The receipt must also not become a leak: if it stored prompts, the log would hold exactly the data Resguardo is meant to protect.

## Decision

- **File:** append-only JSON Lines, two entries per request: `decision`, written and flushed (`fsync`) **before** anything is sent upstream, and `outcome`, written when the request ends. If the decision entry cannot be written, the request is blocked (ADR 0002).
- **Content:** metadata only: sequence number, kind, timestamp, request id, principal, provider, model, body size and SHA-256, finding classes and counts, decision, status, and latencies in integer microseconds. **No prompt content, no matched values, no keys.** No floating-point fields.
- **Chain:** every entry carries `prev`, the hash of the previous entry; the first uses 64 zeros.
- **Hash:** `hash` = SHA-256 (hex) of the entry without `hash` and `sig`, serialized with the JSON Canonicalization Scheme (RFC 8785).
- **Signature:** `sig` = Ed25519 signature over the 32 hash bytes with the instance's private key, Base64url without padding.
- **Keys:** `resguardo init` creates the key pair; the private key file must have 0600 permissions. The public key is all an auditor needs. `--rotate-key` creates a new pair and records the rotation in the log.
- **Verification:** `resguardo verify-log <path> --pubkey <file>` recomputes hash and signature for each line and checks `prev` and `seq`. At the first failure it reports the line and reason (`hash`, `sig`, `prev` or `seq`) and exits with code 1.
- **Implementation:** established crates only (`sha2`, `ed25519-dalek` or `ring`). For RFC 8785, use an existing crate if it passes the RFC's test vectors, or implement the subset needed (strings, integers, booleans, objects, lists); this is still open.

## Consequences

- Anyone with the public key can detect edited, deleted or reordered entries.
- **Limit:** whoever controls the machine and the private key can rewrite the whole log consistently. Timestamping (RFC 3161) and external anchoring are v0.2; the README states this.
- Integer-only fields keep canonicalization trivial and stable across languages.
- One `fsync` per request adds latency; the benchmark must measure it.
- The format follows the same building blocks (Ed25519, RFC 8785) as current IETF drafts for signed evidence, which makes it easier to align with them later.
