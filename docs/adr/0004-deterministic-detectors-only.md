# 0004. Deterministic detectors only

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Detectors for sensitive data fall into two families:

- **Deterministic:** regular expressions, checksums (DNI/NIE letter, CIF control, IBAN mod 97, Luhn), entropy and fixed decoding rules. Predictable, fast and explainable.
- **Model-based or heuristic:** NER models, prompt-injection classifiers, keyword lists. Broader coverage, but slower, non-deterministic, hard to explain in an audit, and with high false-positive rates on ordinary text.

v0.1 must publish a measured false-positive rate and a latency benchmark. Both need detectors whose behaviour can be reproduced exactly.

## Decision

v0.1 ships only deterministic detectors:

- known-format secrets (one `RegexSet`) and an entropy-based `secret_candidate` that only flags;
- invisible and bidirectional control characters;
- DNI, NIE and CIF with control character, IBAN with mod 97, cards with Luhn, Spanish phones and email;
- in responses, remote images and links to hosts outside the allowlist.

**Without a valid checksum there is no finding.** De-obfuscation (NFKC, invisible characters, Base64, hex, URL-encoding) is also deterministic and bounded in depth and size.

Keyword and prompt-injection scanners, model-based detectors (NER, classifiers) and Wasm plugins are left for v0.2.

## Consequences

- Same input, same findings: the golden tests, property tests and the accuracy corpus are reproducible in CI.
- Scanning cost is predictable and can be published.
- Some prompt injections will succeed. The mitigation is architectural: closed egress (ADR 0002), the allowlist and the response controls limit what a hijacked model can send out.
- Names, addresses and other free-text personal data are not detected in v0.1. The README must say so.
