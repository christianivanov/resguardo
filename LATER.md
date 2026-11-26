# Later

Ideas that are out of scope for v0.1. Add them here instead of implementing them.

- Several upstreams of the same provider, each with its own name (ADR 0005).
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
- **First after v0.1.0: audit log segments** (needs an ADR). v0.1 keeps one growing file, about 1.1 KB per request, and the operator archives it with Resguardo stopped (ADR 0015, `docs/DEPLOYMENT.md`). Proposal:
  - rotate by size (for example 256 MB) or by day, without stopping;
  - each segment starts with a signed entry that carries the last hash of the previous one, so the chain continues across files and a removed or changed segment is detected;
  - closed segments are never written again, so they can be compressed and shipped off the host (object storage with a retention lock), which also covers "deleting the last entries leaves a valid log";
  - `verify-log` accepts a directory or a series of segments and checks that they fit together;
  - a configurable retention period (GDPR storage limitation: receipts hold no content, but they do say which principal did what and when);
  - free-space monitoring stays with the operator's tools unless a dependency is approved for it.
- Detector tuning from the accuracy corpus (`docs/ACCURACY.md`): ISBNs read as phones (`84` + seven digits) and, by chance, as cards; a UUID run read as a Spanish id. Each change must update the baseline in the same commit.
- Scanning speed: about 17 MB/s on a GitHub Actions runner, 4 MB/s on the 2017 laptop (`docs/BENCHMARKS.md`). Large coding-agent contexts (hundreds of KB per request) feel it most: add a 400 KB text and a concurrent run to `tools/bench`, then profile the window scanners and the Base64 candidates.
- Group commit for the audit log: one `fsync` for the decisions of several concurrent requests, to raise throughput with `fsync` on.
