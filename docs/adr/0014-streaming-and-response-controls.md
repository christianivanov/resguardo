# 0014. Streaming, response scanning and response controls

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Section "Streaming y registro firmado" and Annex F.7 of the design document describe streamed responses:

- an incremental SSE parser for OpenAI and Anthropic;
- each fragment scanned together with the last 256 bytes of the previous one;
- two modes, `passthrough_abort` and `buffer`;
- an error event that cuts the stream;
- the removal of remote Markdown images and of links to hosts outside a list.

Annex G.4 gives the golden cases. Several points are open:

- **What is scanned in a response,** and what happens to findings whose action is not `block`.
- **What replaces a removed image or link,** and what happens to a fragment held across events that never closes. F.7 says "until the parenthesis closes or 512 bytes", but releasing an unclosed image after 512 bytes would let a long URL through.
- **Timeouts.** The total request timeout (120 s) would cut long streams. Claude Code responses with extended thinking last minutes.
- **Limits** for the SSE parser, which must not buffer an unbounded event.
- **Non-streamed responses,** which the design does not mention, although images and links reach the application the same way.

## Decision

### What is scanned

1. **Streams.** The texts of each event are scanned:
   - OpenAI: `choices[].delta.content`, `delta.refusal` and `delta.tool_calls[].function.arguments`;
   - Anthropic: `content_block_delta` with `text_delta`, `input_json_delta` (`partial_json`) and `thinking_delta`.

   Each text is scanned with the last `overlap_bytes` (256) of the earlier texts of the same block: a choice and a tool call for OpenAI, a content block index for Anthropic. A secret split across two events is found.
2. **Non-streamed responses** are parsed strictly, and every string in them is scanned, as for requests (ADR 0007).
3. **Response findings.** If policy blocks (ADR 0012, with the same actions and limit flags as requests), the response stops:
   - a stream gets an `event: error` with the JSON of Annex H (code `SENSITIVE_DATA`) and is closed;
   - a non-streamed response is replaced by a `403 SENSITIVE_DATA` error.

   Findings with any other action are only recorded (M5). They travel towards the application, not out of the network, and rewriting text already on its way would complicate streaming for little gain.
4. **Thinking is scanned but never rewritten.** Changing it would break its signature when the client sends it back.

### Response controls

5. **Remote images:** `![alt](url)` whose URL is `http://` or `https://` is replaced by `[image removed]`, when `strip_remote_images` is on. Every remote host counts, including those in `allowed_link_hosts`, because an image loads without a click.
6. **Links:** `[text](url)` to an `http://` or `https://` host outside `allowed_link_hosts` keeps only `text`, when `strip_links_outside` is on. Host comparison is exact and lowercase.
7. **Only inline Markdown, and only text.** The controls apply to response text (`content`, `text_delta`), never to tool arguments or thinking. Reference-style images and links (`![x][ref]` with `[ref]: url`), HTML `<img>` and bare URLs are not handled in v0.1, and the threat model lists them.
8. **Held fragments.** From `[` or `![`, text is held until the Markdown construct closes or turns out not to be one. A held fragment of more than 512 bytes is resolved this way:
   - inside an image, it is removed as an image, because releasing it would let a long URL through;
   - anywhere else, it is released unchanged.

   At the end of the stream, whatever is still held is resolved the same way and sent before the closing event.
9. **Rewritten events.** An event whose text changes is serialized again (`event:`, `id:` and `data:` lines, with the JSON in compact form). Every other event is forwarded as its original bytes.

### Modes

10. **`passthrough_abort`** (default) forwards each event as soon as it has been scanned. Text sent before a blocking finding is not recovered: the application has it, although it never left the network.
11. **`buffer`** holds the scanned events until one of these happens:
    - the held text ends a sentence (`.`, `!`, `?` or a newline);
    - it reaches `buffer_flush_bytes`;
    - an event without text arrives (block stop, message stop, `ping`), which keeps clients alive during long pauses.

    A blocking finding then cuts the stream before the held sentence is released.

### Limits and timeouts

12. **SSE limits.** One event, and one line, may hold at most `[stream] max_event_bytes` (default 1 MiB). A larger one cuts the stream with an error event (closed by default). The total stream size keeps the `max_response_bytes` limit.
13. **Timeouts.**
    - Non-streamed requests keep the total timeout of `request_timeout_secs`, now set per request.
    - Streams have no total timeout. The HTTP client's read timeout cuts them after `request_timeout_secs` without any byte from the provider. Anthropic sends `ping` events during long pauses, so a healthy stream never reaches it.
14. **Provider errors** (status other than 2xx) and non-SSE answers to a stream request are read whole and passed through unchanged, as before.

## Consequences

- G.4 can be met: a key split across two events is caught by the window, and remote images are removed even when split across events.
- With `passthrough_abort`, the first half of a split secret reaches the application before the stream is cut. With `buffer`, it does not. The README states this.
- A stray `![` followed by more than 512 bytes without a closing parenthesis loses that text. That is a deliberate trade for not letting long image URLs through.
- Responses are scanned twice as much as before (requests and responses), which the benchmark (M6) includes.
