# Later

Ideas that are out of scope for v0.1. Add them here instead of implementing them.

- Several upstreams of the same provider, each with its own name (ADR 0005).
- Lab: `allow_insecure_upstream` only accepts local hosts, but the Docker lab reaches the mock upstream by service name. Decide in M6 (for example, allow names listed explicitly as lab hosts).
- Coding agents: a secret read by the agent (for example from `.env`) sits in every later request of the session. With `block`, the session becomes unusable; with `redact`, the conversation is rewritten. Options: redact only inside `tool_result` blocks with deterministic placeholders, or a per-session "acknowledged" state. See `docs/research/claude-code-gateway.md`.
- Use `x-claude-code-session-id` and agent ids as audit metadata.
- Optional routes for Claude Code: `/v1/messages/count_tokens` and `/v1/models`.
- Per-principal option to block requests with binary parts (images, audio, PDFs), which v0.1 forwards without scanning (ADR 0007).
- Scan the values of forwarded headers (`anthropic-beta`), which are short ASCII but not scanned in v0.1.
- A header read timeout for slow clients (slowloris), and TLS on the listening side.
- Scan numbers in the JSON body (for example card numbers sent as numbers), with the original digits rather than the parsed value.
- Regulatory mapping (`docs/COMPLIANCE.md`, M6 at the earliest): which control gives evidence for which article (GDPR art. 5.2, 32 and chapter V, DORA third-party ICT risk, ENS). To be reviewed by someone with legal or compliance background; AI Act deadlines to be checked at the time of writing.
- Spanish Social Security number (NUSS) with its mod 97 check digits, as a new `DataClass` (needs an ADR).
- Audit entries linked to a record of processing activities (GDPR art. 30), for example a `purpose` per principal. **Decide at the start of M5**, before the audit format is fixed.
