# 0011. Decoding minimums sized to the shortest value a detector finds

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Annex F.1 decodes Base64 fragments of 24 characters or more and hexadecimal fragments of 32 digits or more. The shortest values the detectors find (ADR 0010) are 9 bytes: a DNI, NIE or CIF, or a phone without prefix. Encoded, they are shorter than those minimums, so they are never decoded:

| Value | Base64 | Hexadecimal |
| --- | --- | --- |
| `12345678Z` | `MTIzNDU2Nzha` (12) | `31323334353637385a` (18) |
| `612345678` | `NjEyMzQ1Njc4` (12) | `363132333435363738` (18) |

A bare id or phone sent in Base64 therefore leaves undetected.

Lowering the minimums makes more ordinary words into candidates. On the 41,062 words of 12 to 23 letters in a standard English word list (`/usr/share/dict/words`), measured on 2026-11-26:

- 25 (0.06 %) decode as Base64 to text that passes the printable check of ADR 0008, item 9;
- all 25 are noise, such as `j[ޢZ'jƥ`, and none contains anything a detector reports.

## Decision

1. **Base64:** 12 or more characters of `[A-Za-z0-9+/_-]`, with optional `=` padding. This replaces the 24 of F.1.
2. **Hexadecimal:** 18 or more digits, in even number. This replaces the 32 of F.1.
3. URL-encoding (three `%XX` sequences), the printable check and the depth and size limits do not change.

## Consequences

- A bare id or phone in Base64 or hexadecimal is found, with the encoded fragment as its span and the layer in `via`.
- About 6 in 10,000 long words decode to printable noise and are scanned once more. That costs little, and the detectors need structure and check digits, so noise does not become findings.
- Inside text that was already decoded twice, such a word yields a `decode_depth` flag. It needs a word that decodes as printable at depth 2, which is rare. The accuracy corpus (M6) measures flags as well as findings.
- Word lists in Spanish and source code are not measured yet. The accuracy corpus covers them.
