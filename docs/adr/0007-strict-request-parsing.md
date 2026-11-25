# 0007. Strict request parsing and full-body text extraction

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

When a request has no findings, Resguardo forwards the **original bytes** (G.3), because coding agents break when a gateway rewrites bodies (see `docs/research/claude-code-gateway.md`). The scanner, however, reads the body **parsed**. Anything the parser and the provider read differently is a way to send data out unscanned:

- **Duplicate keys.** In `{"content":"hello","content":"<secret>"}` one parser keeps the first value and another the last.
- **Fields the scanner does not look at.** Extracting text only from known fields (`messages[].content`…) misses content block types added by the providers later, and fields outside the conversation that still reach the provider (`metadata`, `user`, OpenAI `prediction.content`).
- **The query string.** Forwarded verbatim, it is a channel the scanner never sees.

The design document does not cover these points (it lists "messages, system and tools" as the text to scan) and has no error code for a malformed request.

## Decision

1. **Strict JSON.** Requests are rejected with `400 INVALID_REQUEST` when:
   - the body is not valid UTF-8 JSON;
   - an object has a duplicate key (after unescaping, so `"content"` equals `"content"`);
   - the root is not an object;
   - `model` is missing, empty or not a string, or `messages` is not an array;
   - `stream` is present and is not a boolean.

   Nesting is limited to 128 levels (the `serde_json` limit).
2. **Every string in the body is scanned**, at any depth, with its JSON Pointer. Role:
   - under `/messages/<n>`, the message role (`developer` counts as `system`);
   - a `tool_result` block or a `tool` message counts as `tool`;
   - anything else (`system`, `tools`, `metadata`…) counts as `system`: it is set by the application, not by the conversation.
3. **The only strings not scanned are binary payloads**, which detectors cannot read:
   - `data:` URLs whose media type is `image/*`, `audio/*` or `application/pdf`;
   - Anthropic `source` objects of type `base64` with one of those media types;
   - OpenAI `input_audio.data`.

   Their number is reported (`binary_parts`) so a later version can block them per principal.
4. **Query strings:** none on `/v1/chat/completions`; on `/v1/messages`, only `beta=true` (sent by Claude Code). Anything else is `400 INVALID_REQUEST`.
5. **Error messages never include body content:** only a fixed description, a field name chosen by Resguardo, or a line and column.

## Consequences

- A content block type introduced by a provider tomorrow is scanned without a code change.
- More text is scanned, so more findings are possible. Opaque high-entropy values such as thinking signatures may raise `secret_candidate` flags, which M2 must keep low.
- Images, audio and PDFs are **not scanned in v0.1**. The threat model lists this, and blocking them per principal is in `LATER.md`.
- Numbers are not scanned (a card number sent as a JSON number in `metadata` is not detected). Listed in the threat model.
- Clients that send duplicate keys or unknown query parameters get a `400`. No official SDK does.
