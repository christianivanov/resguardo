# 0008. Scanning pipeline: limits, flags, aggregation and secret patterns

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Annex F of the design document describes the de-obfuscation pipeline (F.1), the secret patterns (F.2) and invisible text (F.3), and Annex G gives the golden cases. Implementing them left several points open:

- **Two findings on one value.** The Base64 of a GitHub token (G.2) is found as `secret` by the patterns, once decoded, and as `secret_candidate` by the entropy check, on the encoded string: 56 characters at 4.93 bits per character. G.2 expects only `secret`, and aggregation only removes overlaps within one class.
- **What a "flag" is.** When the decode depth or `max_derived_bytes` is exceeded, F.1 emits a `flag`, never an error. A `Finding` needs a `DataClass`, and no class means "a limit was reached".
- **How the limits apply.** It is not specified whether `max_derived_bytes` applies to each decoded text or to all of them, or what happens to content beyond a limit.
- **Confidence values,** which the design leaves open.
- **The secret patterns** were written from memory, and F.2 asks for them to be checked against each provider's documentation.

## Decision

### Limits and flags

1. **Limit flags are a separate type,** `ScanFlag`, next to the findings in a `ScanReport`. A flag names the limit (`decode_depth` or `derived_bytes`), the span of the outermost encoded fragment and the layers crossed, ending with the layer that was not fully decoded. It is not a finding: policy decides what to do with it (M3).
2. **Depth.** The original text is depth 0, and each decoding adds one. With `max_decode_depth = 2`, a fragment found at depth 2 is not scanned. If it would decode to printable text, the pipeline emits a `decode_depth` flag instead. A fragment that decodes to binary or invalid text is ignored, so binary payloads do not raise flags.
3. **Derived bytes.** `max_derived_bytes` applies to **each** decoded text, as section "Motor de detección" of the design states ("64 KB por texto derivado"). When a fragment decodes to more than that, the pipeline scans the part that fits and emits a `derived_bytes` flag. Scanning that first part costs nothing extra and finds more than skipping the whole fragment. Decoding only ever shrinks text (Base64 to 3/4, hex to 1/2, URL-encoding to at most 1/1), so the total work stays linear in the input.

### Aggregation

4. **A `secret_candidate` that overlaps a `secret`** in the same text is dropped. The specific finding already says what the value is. The rule applies to `secret` only. If it applied to every class, an invisible character inside a high-entropy word would remove the candidate, and with `invisible_text = "redact"` the word would leave without a flag.
5. **Findings of the same class that overlap** become one finding. Its span is the **union** of their spans, so redaction (M3) covers everything any detector saw. The rule, confidence and layers are those of the most confident finding. Ties go to the finding with fewer layers, then to the first rule name in alphabetical order.
6. **Confidence:** 100 for invisible characters (certain), 90 for known secret formats, 50 for entropy.

### De-obfuscation details

7. **Base64 candidates** use one alphabet per fragment: URL-safe if the fragment contains `-` or `_`, standard otherwise, and none if it contains both kinds. Padding is optional and non-canonical trailing bits are accepted. An attacker controls the encoding, so the decoder is lenient.
8. **URL-encoding candidates** are runs of RFC 3986 characters (unreserved, reserved and `%`) that contain three or more `%XX` sequences, not necessarily consecutive. `+` is not decoded as a space.
9. **Printable** means valid UTF-8 where at least 90 % of the characters are not control characters (tab, newline and carriage return count as printable). If a decoded text was cut by `max_derived_bytes`, a character cut in half at the end is dropped before the check.
10. **Invisible characters** (F.3) are reported as one finding per run of consecutive characters of the same kind: `invisible_text.zero_width` (U+200B–U+200D, U+2060–U+2064, U+FEFF), `invisible_text.bidi` (U+200E–U+200F, U+202A–U+202E, U+2066–U+2069) and `invisible_text.tag` (U+E0000–U+E007F). They are removed before any detector runs, and a character that NFKC produces is checked as well.
11. **The position map** stores ranges, not one entry per byte: a run of unchanged text is one entry, and only characters that NFKC changes get their own. A span that starts or ends inside the expansion of a character (`ﬁ` → `fi`) widens to the whole original character.

### Secret patterns, checked against provider documentation

All patterns go into one `RegexSet` (F.2), and word boundaries are ASCII (`(?-u:\b)`), so a non-ASCII letter next to a key does not hide it.

| Rule | Pattern | Change from F.2 and source |
| --- | --- | --- |
| `secret.aws_access_key` | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | None. AWS STS `GetAccessKeyInfo`: `AKIA` long-term, `ASIA` temporary |
| `secret.github_token` | `\bgh[pousr]_[A-Za-z0-9]{36}\b`, `\bghs_[A-Za-z0-9._-]{36,}`, `\bgithub_pat_[A-Za-z0-9_]{60,}` | Adds `gho_`, `ghu_`, `ghs_`, `ghr_` (GitHub blog, "Behind GitHub's new authentication token formats") and the stateless `ghs_` installation tokens, about 520 characters with dots, using the pattern GitHub recommends (changelog, 2026-10-02) |
| `secret.anthropic_key` | `\bsk-ant-[A-Za-z0-9_-]{20,}` | None. Covers `sk-ant-api03-` and `sk-ant-admin01-` |
| `secret.openai_key` | `\bsk-[A-Za-z0-9_-]{20,}`, skipped when it starts with `sk-ant-` | Drops the redundant `(proj-)?`. Also matches `sk-svcacct-`, `sk-admin-` and the legacy format. The `sk-ant-` exclusion is checked in code (no look-around) |
| `secret.slack_token` | `\b(xox[abeposr]\|xapp\|xwfp)-[A-Za-z0-9-]{10,}` | Adds app-level `xapp-`, workflow `xwfp-` and rotating `xoxe-` (Slack, "Token types"). `xoxe.xoxp-…` is caught by its `xoxp-` part |
| `secret.google_api_key` | `\bAIza[0-9A-Za-z_-]{35}`, then a check in code that no key character follows | The trailing `\b` of F.2 never matches a key that ends in `-` |
| `secret.stripe_live` | `\b(sk\|rk)_live_[0-9A-Za-z]{20,}\b` | None. Stripe, "API keys" and "Restricted API keys" |
| `secret.private_key` | `-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----` up to the matching `-----END …-----`, or to the end of the text | Adds PGP (`PRIVATE KEY BLOCK`). The span covers the **whole block**, so redacting it removes the key material and not only its header |
| `secret.jwt` | `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | None |
| `secret.resguardo_key` | `\brsg_[A-Za-z0-9]{40,}` | None. Virtual keys are `rsg_` and 43 Base62 characters |

## Consequences

- G.2 can be met as written. The Base64 of a token yields one `secret`. The triple Base64 of a token yields no `secret`, a `decode_depth` flag with `via = ["base64", "base64", "base64"]` and a `secret_candidate` on the outer string. Encoding a secret three times therefore never leaves silently.
- Policy (M3) receives flags and must decide their action. Blocking on `decode_depth` is the strict option for sensitive principals.
- Known gaps, listed in the threat model:
  - partial URL-encoding with fewer than three `%XX` sequences (`ghp%5F…`) is not decoded;
  - Base64 split across lines is decoded line by line, so a secret that crosses a line break is missed;
  - soft hyphens (U+00AD) and variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) are not in F.3, so they are neither removed nor reported (`LATER.md`);
  - opaque high-entropy values (thinking signatures, some ids) can raise `secret_candidate` flags (ADR 0007), whose default action only records them.
- NFKC can expand a character up to about 11 times in bytes (U+FDFA), so the normalized copy of a text can be larger than the original. The amount stays bounded by the body size limit.
- The design document's G.1 row for `SuperSecretPassword2026!!` gives 3.94 bits, measured with the `!!`. Words are made of `[A-Za-z0-9+/=_-]`, so the word scanned is `SuperSecretPassword2026` at 3.85 bits. The outcome (no finding) is the same.
