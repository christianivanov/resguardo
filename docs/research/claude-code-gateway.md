# Claude Code through Resguardo: what the gateway must do

Research for the "coding agents" use case (2026-11-25). Source: the Claude Code gateway documentation, <https://code.claude.com/docs/en/llm-gateway-protocol> and <https://code.claude.com/docs/en/llm-gateway>. Re-check before relying on it: the protocol changes with Claude Code releases.

## Summary

Claude Code can run through Resguardo by setting `ANTHROPIC_BASE_URL`. v0.1 already covers the one required route (`POST /v1/messages`, with streaming). Compatibility needs a few changes to M1 and M4, listed at the end.

The real tension is **redaction**: the docs warn that a gateway that rewrites request bodies breaks Claude Code. For this use case, the right action on findings is `block`, not `redact`, and that creates its own problem (see "Open problem").

## Routes

| Route | Required? | If Resguardo returns 404 |
| --- | --- | --- |
| `POST /v1/messages` (sent as `/v1/messages?beta=true`) | **Yes** | Claude Code does not work |
| `POST /v1/messages/count_tokens` | No | `/context` falls back to a character-based estimate |
| `GET /v1/models?limit=1000` | No; only with `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1` | The model picker uses its cached or built-in list |
| `HEAD /api/hello` | No; connection-warming probe | Nothing breaks |

Annex H already answers 404 to any other route without contacting the provider, which is fine for the optional ones. Route matching must use the **path**, ignoring the query string, and the query must be forwarded.

## Headers

- **Credential:** `ANTHROPIC_AUTH_TOKEN` is sent as `Authorization: Bearer …`, and `ANTHROPIC_API_KEY` as `x-api-key`. Resguardo must accept the virtual key **in either header** on `/v1/messages`, not only `x-api-key` as Annex H says.
- **Forward verbatim:** `anthropic-version` and `anthropic-beta`. "Don't allowlist individual values, because the set changes with Claude Code releases." A beta header stripped while its body field passes through causes `400`s.
- **Optional, informational:** `x-claude-code-session-id`, `x-claude-code-agent-id` and the hint headers (`x-claude-code-request-class`…). Useful as audit metadata later; never required.
- **Response headers to forward unchanged:** `content-type: text/event-stream`, `retry-after` (integer seconds), `x-should-retry`, `anthropic-ratelimit-unified-*`.
- **Resguardo's own 429** (rate limit) should send `retry-after` in integer seconds.

## Body

The docs ask gateways to forward the body **unchanged**: the `system` array exactly as received, every `cache_control` marker, thinking blocks and their signatures, beta fields (`context_management`, `output_config`, tool `strict` and `defer_loading`, `tool_reference` blocks), and mid-conversation `role: "system"` entries. "Treat the headers and body fields as open lists, not closed ones."

This matches the design: `CanonicalRequest.raw` keeps unknown fields, and a request without findings goes out **byte for byte** (G.3). It also means:

- Normalization must extract text from **every** content block type (`text`, `tool_use` input, `tool_result` content, `system` blocks), but rebuild nothing it does not change.
- Redaction rewrites earlier messages. The docs warn that rewriting `system`, `tools` or earlier `messages` can trigger "bound to a different conversation" errors and breaks prompt caching.

## Streaming

- **Do not buffer the whole response:** Claude Code stalls. `passthrough_abort` (the default) is right; `buffer` mode holds up to 2 KB, which still needs testing with Claude Code.
- Relay **every** event in order, through `message_delta` and `message_stop`. Ending the body after a content block starts but before `message_delta` counts as a dropped connection.
- **Forward `ping` events:** during long thinking pauses they are the only bytes, and Claude Code aborts on its idle timeout without them.

## Errors

- Forward upstream error bodies **unmodified**; Claude Code's recovery matches the upstream's wording on `400` and `422`. Annex H already says provider errors pass through untouched.
- Resguardo's own errors use the OpenAI error shape (Annex H). For `/v1/messages`, the Anthropic shape (`{"type":"error","error":{"type":…,"message":…}}`) is more likely to be understood by Anthropic clients. To decide in M1.6.

## Open problem: one secret can end a session

Claude Code resends the whole conversation on every request. If the agent reads a file containing a secret (a `.env`), the secret sits in a `tool_result` block of every later request:

- With `block`, every later request in that session is blocked, so the session is unusable until the user clears it.
- With `redact`, the conversation is rewritten, which the docs warn against. Because redaction is deterministic, the rewrite is identical on every request, so it might not break caching or thinking signatures. **This needs a test with a real Claude Code session.**

Neither is decided for v0.1. Options for v0.2 are in `LATER.md`.

## Changes this implies for v0.1

| Milestone | Change |
| --- | --- |
| M1.2 | The mock upstream emits the full Anthropic event sequence, including `ping`, and records the query string and every header |
| M1.3 | Accept the virtual key in `Authorization: Bearer` as well as `x-api-key` on `/v1/messages` |
| M1.4 | Match routes on the path and forward the query string; extract text from every content block type |
| M1.5 | Forward `anthropic-*` request headers verbatim; forward `retry-after`, `x-should-retry` and `anthropic-ratelimit-*` response headers; strip only the application's credential |
| M1.6 | Decide the error shape on `/v1/messages`; `retry-after` on Resguardo's 429 |
| M4 | Forward `ping` and every event in order; test `buffer` mode with Claude Code |
| M6 | A manual end-to-end test with a real Claude Code session against the mock (no real API keys) |
