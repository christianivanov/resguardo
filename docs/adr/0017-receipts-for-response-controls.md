# 0017. Receipts for response controls

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

The response controls of ADR 0014 change what the application receives: a remote Markdown image becomes `[image removed]`, and a link to a host outside `allowed_link_hosts` keeps only its text. The outcome entry of ADR 0015 records `status`, `outcome`, latencies and `response_findings`, but not these changes.

A real run of `lab/local-demo.sh` shows the gap. The response whose image pointed at the attacker was rewritten, and its outcome entry reads `"outcome":"completed"` with `"response_findings":{}`, the same as an untouched response. The protection worked, but the log cannot show it. An auditor reading the log cannot tell that a prompt injection tried to exfiltrate data through an answer, and the README's promise, a receipt for every decision, does not hold for decisions about responses.

Open points:
- what is recorded, and with which names;
- whether to record the removed URL or its host, which would help an investigation;
- how a removal is counted once, when text arrives in chunks and the filter re-reads held text and checks destinations internally.

## Decision

1. **A new outcome field, `response_controls`:** an object with integer counts, ordered by key. It is present wherever `response_findings` is, that is in the outcome of every response that reached the application, whole or streamed, completed or cut (`{}` when nothing changed). Requests refused before a response have neither.
   - `images_removed`: remote images replaced by `[image removed]`, including an image removed because it never closed or passed the hold limit, and one whose destination was tampered with.
   - `links_removed`: links that kept only their text.

   A key appears only when its count is above zero.
2. **No URLs and no hosts.** The log records how many, never which. A URL or a host is response content, and in this attack it is the payload: `https://dni-12345678z.attacker.test/` carries the exfiltrated value in the host name. Recording it would copy the leaked data into the log that is meant to prove it did not leave. An investigation reproduces the response from the provider's side, or runs the request again against the mock.
3. **Counted once, when the controls release it.** A construct is counted when the filter releases the text that replaces it, not when it parses it. In `buffer` mode, events released by the filter but still held for a sentence end are dropped if the stream is cut; their removals still count, because the attempt happened. Held text that is parsed again, destinations checked internally (the "tampered" check) and the contents of brackets processed to stay balanced do not count on their own. An image inside a removed link counts as one image and one link. Escaping a placeholder is not a removal.
4. **Both paths.** Streamed responses add up the counts of every text block, and the outcome is written when the stream ends, as today. Non-streamed responses count over their text fields. Text that the controls do not touch (tool arguments, thinking; ADR 0014 point 7) is not counted.
5. **`resguardo-proto` stays pure.** `MarkdownState` carries the counts as `Removals`, `MarkdownFilter::removed` and `ResponseControls::apply_counted` expose them, and the binary copies them into the outcome entry. No I/O, no clock.
6. **Tests first.** Golden tests for:
   - one image and one link in a non-streamed response;
   - every text split at each point and pushed one character at a time, counted the same as whole;
   - an unclosed image and an image past the hold limit;
   - a tampered destination;
   - an image inside a link;
   - an allowed link and a local image, which count nothing;
   - the outcome entries of a whole and a streamed response, in both APIs, with no URL in the log;
   - the outcome entry of the local demo, checked by hand.

   The Markdown fuzz target gets two more invariants: the counts for a text are the same whether it arrives whole or split at any point, and a text with nothing removed comes out unchanged, so no change escapes the receipt.
7. **Verification does not change.** `verify-log` checks every field the same way. Logs written before this change have no `response_controls`; v0.1.0 is not released, so no compatibility is promised for them.

## Consequences

- The log shows that an answer was rewritten and how, so an auditor can count attempted exfiltrations through responses per principal and per day.
- The log still holds no content: an attacker's host name never reaches it.
- An investigation that needs the URL cannot get it from Resguardo. That is deliberate.
- The filter keeps a little more state, and the fuzzer has one more invariant to hold.
- A response cut for a secret is already recorded as `blocked` or `aborted` with `response_findings`; this change does not touch it.
