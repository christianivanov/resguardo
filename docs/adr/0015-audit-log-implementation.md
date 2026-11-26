# 0015. Audit log: keys, entries, recovery and rotation

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

ADR 0003 fixes the format of the signed audit log: JSON Lines, a hash chain, RFC 8785 canonicalization, SHA-256 and Ed25519, and the two entries per request, `decision` and `outcome`. Implementing it leaves several points open:

- which library signs;
- how keys are stored;
- what the entries contain;
- which requests get them;
- what happens after a crash in the middle of a write;
- how a key rotation is recorded so that one public key still verifies the whole log;
- whether to keep the `purpose` per principal that was set aside for M5 (GDPR art. 30).

## Decision

1. **Signing:** Ed25519 from `aws-lc-rs`, the crypto provider rustls already uses (ADR 0006). No new cryptographic library enters the build, and `ring` stays banned. Hashes use `sha2`.
2. **RFC 8785:** a subset written for the log's values: strings, integers within ±(2^53 − 1), booleans, null, lists and objects. A float or a larger integer is refused, so ECMAScript number formatting is never needed. Tests use the RFC's sorting example and the bytes of its Section 3.2.4 for the string and literal members.
3. **Key files.**
   - Private: `ed25519-pkcs8:` and the PKCS#8 v2 document in Base64url, created new with mode 0600. A file others can read is refused at startup.
   - Public: `ed25519:` and the 32 raw bytes in Base64url.
   - Neither file is ever overwritten. Key material is wiped from memory where the library allows it, and never printed.
4. **Which requests get receipts:** every request with an authenticated principal. Requests refused before that (unknown route, missing or unknown key) get none: they make no decision about data leaving, and writing to disk for them would let anyone fill the disk without a key.
5. **Decision entry:**
   - always: `principal`, `provider`, `model`, `stream`, `body_bytes`, `body_sha256`, `findings` (count per class), `flags` (count per limit), `decision` (`allow`, `redact` or `block`) and `purpose` when the principal has one;
   - `forwarded_sha256` when the body was redacted;
   - `code` and `class` for a block.

   It is written, and flushed with `fsync`, before anything is sent upstream. If it cannot be written, the request is `503 AUDIT_UNAVAILABLE` and nothing leaves.
6. **Outcome entry:** `status`, `outcome` (`completed`, `blocked`, `aborted` or `upstream_error`), `upstream_us`, `overhead_us`, `response_findings` and, since [ADR 0017](0017-receipts-for-response-controls.md), `response_controls`, all in integer microseconds and counts. A stream's outcome is written when it ends. Outcomes are written after the response leaves and without their own `fsync`: they reach the disk with the next flush, and if a crash loses one, the chain goes on from the last entry on disk. Waiting for a second `fsync` per request doubled the latency the benchmark measured (M6.2). If the outcome cannot be written, the error is printed, and the next decision write fails if the log is still broken.
7. **Failed writes** cut the file back to its last complete entry, so the chain stays valid once the disk recovers. `/healthz` answers 503 while the last write failed.
8. **Startup.**
   - The last complete entry must verify with the signing key, or startup stops: the file was changed, or the key is not this log's.
   - A torn last line (a crash mid-write) is moved to `<log>.torn-<seq>`, and a signed `recovery` entry records how many bytes were discarded.
   - `run` refuses to start without a signing key and suggests `resguardo init`.
9. **Key rotation:** `resguardo init --rotate-key` writes a `key_rotation` entry signed with the old key that carries the new public key. Later entries are signed with the new key. `verify-log --pubkey <first key>` follows the rotations, so an auditor needs only the first public key. The old public key is kept as `<public_key>.<seq>`, and the old private key is deleted: a rotation is often done because a key may have leaked, and keeping it would let anyone who has it rewrite the history before the rotation. The new pair is written aside first, then the rotation is recorded, then the files are swapped. A last entry that is a rotation to a key not in use stops startup, so a crash in between never leaves the log signed with the wrong key.
10. **`purpose`:** an optional string per principal (1 to 200 characters, no control characters), copied into its decision entries.
11. **Not in v0.1:** rotation of log files by size or date (`LATER.md`). The log grows until the operator archives it.

## Consequences

- G.5 and the G.3 "disk full" row can be tested. A full disk is reproduced with a file size limit (`ulimit -f`) on a real `resguardo run`.
- Anyone with the first public key detects edited, deleted or reordered entries, a key switched without a rotation entry, and a log whose start was cut off.
- The end of the log is not protected: deleting the last entries leaves a valid shorter log. Timestamping and external anchoring (v0.2) address it.
- Unauthenticated rejections leave no receipt; the operator's own access logs cover them.
