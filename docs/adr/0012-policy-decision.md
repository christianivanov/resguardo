# 0012. Policy decision: scope, limit flags and the blocking class

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Section "Política" of the design document describes policy as a pure function that takes the principal, the request and the findings, and returns one decision, evaluated in six steps:

1. principal;
2. destination and model;
3. limits;
4. action per finding;
5. combination, where the most restrictive action wins;
6. result: `Allow`, `Redact` with the spans to replace, or `Block` with a code and a class.

Implementing it leaves four points open:

- **Steps 1 to 3 already run in the server** (M1). Key expiry and rate limits need the clock and the limiter's state, which a pure crate cannot read.
- **Limit flags.** ADR 0008 left to policy what to do with `decode_depth` and `derived_bytes` flags, which mean some content was not fully inspected.
- **One class per block.** `Decision::Block` carries one `DataClass`, but several classes can block at once.
- **A class without an action.** The configuration requires a global action for every request class, but nothing says what policy does if one is missing anyway.

## Decision

1. **Scope.** `resguardo-policy` implements steps 4 to 6. Steps 1 to 3 stay in the server, where they already run before the body is scanned, so a refused request is never scanned. Policy does no I/O and does not read the clock.
2. **Action per finding.** Policy takes the principal's action for the class if it has one, and the global action otherwise. If neither exists, the action is `block` (closed by default, ADR 0002).
3. **Limit flags have their own table,** `[policy.scan_limits]`, overridable per principal with `scan_limits.<limit>`:

   | Limit | Default | Why |
   | --- | --- | --- |
   | `decode_depth` | `block` | Legitimate traffic almost never encodes three times |
   | `derived_bytes` | `flag` | A large encoded block (a file sent as text) is common, and its first `max_derived_bytes` were scanned |

   Only `flag` and `block` are accepted. `allow` is not, because a limit is always recorded. `redact` is not, because it would mean replacing the whole fragment, which can be added later. A limit without an action blocks.
4. **Combination.** The decision takes the most restrictive action of all findings and flags: `block` over `redact`, `redact` over `flag`, `flag` over `allow`.
5. **Block.** The code is `SENSITIVE_DATA` (403). The class reported is the first blocking class in this order: `secret`, `secret_candidate`, `es_id`, `iban`, `card`, `phone`, `email`, `invisible_text`. The order follows `DataClass` and puts the most serious class first. When only a limit flag blocks, there is no class. The error message for that case is written with the HTTP wiring in M3.3, and says that some content could not be fully inspected.
6. **Redact and Allow.** `Redact` carries the findings whose action is `redact` as spans, and those whose action is `flag` as flags. `Allow` carries only the flagged findings. Findings whose action is `allow`, and limit flags whose action is `flag`, are not part of the decision. The audit log (M5) counts them from the scan report.
7. **Wiring** scanning and policy into the server happens in M3.3, together with redaction, because a `Redact` decision cannot be served before redaction exists. Until then the server keeps refusing real providers.

## Consequences

- The same report and configuration always give the same decision, which makes policy easy to test with golden cases.
- A secret encoded three times is blocked by default, even though the scanner never sees it.
- An agent that sends a large encoded file passes, and the flag is recorded. A principal that handles sensitive data can set `scan_limits.derived_bytes = "block"`.
- The configuration gains one optional table. A file without it gets the defaults above, so existing configurations stay valid.
