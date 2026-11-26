# Architecture and security

How Resguardo is built, which controls exist in code today, and the rules the code follows. For the threats these controls answer, see the [threat model](THREAT_MODEL.md); for why each choice was made, see the [architecture decisions](adr/).

## Crates

One process, split into crates whose dependencies are enforced by `cargo deny` ([ADR 0001](adr/0001-single-process-with-crate-boundary.md)). The egress side can never see scanning or policy, so it could become its own process later.

```text
resguardo (binary) ─┬─ resguardo-core      domain types, configuration, virtual keys     ✅
                    ├─ resguardo-proto     strict parsing, redaction, SSE, response controls ✅
                    ├─ resguardo-egress    allowlist, credentials, TLS                   ✅
                    ├─ resguardo-scan      detectors (pure: no I/O, no clock)            M2
                    ├─ resguardo-policy    decisions (pure)                              M3
                    └─ resguardo-audit     hash-chained, signed log                      M5

tools/mock-upstream   fake OpenAI and Anthropic server used by every test
tools/sdk-smoke       the official Python SDKs run against Resguardo
```

## Request path

Each step fails closed: any error ends the request with an error response, and nothing is sent.

1. **Route.** Only `POST /v1/chat/completions` and `POST /v1/messages`, matched on the exact path. Anything else is `404` without contacting a provider.
2. **Identity.** The virtual key, from `Authorization: Bearer` or `x-api-key`, is hashed and looked up. Missing, unknown, expired or ambiguous keys get `401`.
3. **Query and headers.** Only `beta=true` on `/v1/messages`; `content-type: application/json`; no compressed bodies.
4. **Rate limit.** Per key, checked before the body is read.
5. **Body.** Read up to the key's size limit, within the request timeout.
6. **Strict parsing.** Duplicate keys, invalid UTF-8, unpaired surrogates and trailing data are rejected; every string in the body is extracted with its JSON Pointer ([ADR 0007](adr/0007-strict-request-parsing.md)).
7. **Model.** Must be on the key's list; for Chat Completions the list also decides between `openai` and `openai_compatible` ([ADR 0005](adr/0005-openai-compatible-upstream.md)).
8. **Scan, policy and redaction.** Every text is scanned on a blocking thread, policy takes one decision ([ADR 0012](adr/0012-policy-decision.md)), and a block answers `403 SENSITIVE_DATA` with the class, never the value. Redaction rewrites only the strings that hold a redacted value, and the result is checked against the strict parser before it leaves ([ADR 0013](adr/0013-redaction.md)). Any scanning or redaction error is `500 SCAN_ERROR`, and nothing is sent.
9. **Receipt.** *M5.* The signed decision entry is written before anything leaves.
10. **Egress.** To the configured upstream only, with the real credential.
11. **Response.** Scanned before the application sees it: a whole response string by string, a stream event by event with a 256-byte window per content block. A blocking finding stops it (`403`, or `event: error` in a stream); remote images and links outside the allowed hosts are removed ([ADR 0014](adr/0014-streaming-and-response-controls.md)).

## Security controls in code today

- **Virtual keys.** 256 bits from the operating system's random generator, encoded without modulo bias. Only their SHA-256 is stored; the key is printed once and never logged. Two different keys in `Authorization` and `x-api-key` are rejected, not resolved.
- **Configuration.** Unknown fields are errors, not ignored settings. Upstreams must be `https://`; plain HTTP is accepted only for `localhost` with an explicit flag. URLs with credentials, queries or fragments are rejected. Every problem is reported at once, and any of them stops startup.
- **Strict parsing.** The scanner and the provider can never read different values: the parser rejects what two parsers could read two ways, and the original bytes are forwarded unchanged.
- **Full-body extraction.** Every string in the request reaches the scanner, including content block types that do not exist yet. Only images, audio and PDFs are skipped, and counted.
- **Egress.** A fixed path on the configured origin, re-checked before sending. The application's credentials, cookies and every header outside a short allowlist are dropped, and the real key is added. No redirects, no automatic retries (one receipt, one request), no proxy taken from the environment, timeouts, and a size limit on responses; compressed responses are refused.
- **Provider credentials.** Read from an environment variable or a file that only its owner can read; anything wider stops startup. Held in memory that is wiped on drop, never printed.
- **TLS.** `rustls` with `aws-lc-rs`, offering the hybrid post-quantum key exchange X25519MLKEM768 first, with certificates checked by the operating system's verifier. A test guards the key exchange order, and `cargo deny` bans a second crypto provider ([ADR 0006](adr/0006-tls-crypto-provider.md)).
- **Data minimization.** Findings carry class, position and rule, never the matched value. Error messages never echo request content.
- **Temporary guard.** Until the audit log exists, `resguardo run` refuses any upstream that is not local, so nothing can reach a real provider without a receipt.

## Engineering rules

- `#![forbid(unsafe_code)]` in every crate; `unwrap` and `expect` denied outside tests.
- No home-made cryptography: only established crates, with versions checked against crates.io.
- Every buffer, decoding step and recursion has a configurable limit.
- Detectors and policy rules are written test-first, against golden vectors computed outside the code.
- No real provider is ever called in tests.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test` and `cargo deny` pass on every commit; commits are signed off (DCO).
