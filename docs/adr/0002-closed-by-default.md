# 0002. Closed by default

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

Resguardo is a boundary: its value is that data does not leave unless policy says so. A boundary that lets traffic through when a component fails, when a rule is missing or when the configuration is ambiguous gives a false sense of safety, which is worse than no boundary.

Two situations need an answer: what happens when nothing explicitly allows a request, and what happens when Resguardo itself fails.

## Decision

1. **Default deny.** A request leaves only if every check passes: a known, unexpired virtual key; a provider and model on the principal's list; limits respected; and no finding whose action is `block`. Anything not explicitly allowed is blocked.
2. **Fail closed.** Any internal error blocks the request with a specific code:
   - scanning error → `SCAN_ERROR` (500);
   - cannot write, flush or sign the audit entry → `AUDIT_UNAVAILABLE` (503);
   - invalid or incomplete configuration, missing signing key, credential files with permissions wider than 0600, or a non-`https` upstream → Resguardo refuses to start.
3. **Egress enforces its own rules** even if policy were wrong: only listed hosts, HTTPS with certificate verification, no redirects (`UPSTREAM_REDIRECT`), and a response size limit.
4. **Combining actions** takes the most restrictive: `block` > `redact` > `flag` > `allow`.
5. Limits that would otherwise exhaust resources (decode depth, derived bytes) stop the work and emit a `flag`; they never let content skip scanning silently.

## Consequences

- Availability depends on Resguardo: a full disk or a lost signing key stops all LLM traffic. This is the intended trade-off and is documented in the README.
- Errors must be typed (`BlockCode`) so the cause is visible without logging content.
- Tests must cover the failure paths (full disk, redirects, invalid config), not only the happy path.
- The only insecure switch, `allow_insecure_upstream`, is accepted only for local hosts and prints a warning at startup.
