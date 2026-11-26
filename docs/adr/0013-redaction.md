# 0013. Redaction: splice into the original bytes, stable numbering, invisible text removed

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Annex F.6 of the design document describes redaction in four steps:

1. per `ScanText`, sort the spans and merge the overlapping ones;
2. number them per class, in order of appearance in the whole request;
3. replace from back to front;
4. write each text back into the body by its JSON Pointer, leaving the rest untouched.

Several points are open:

- **How the body is rewritten.** A request without findings is forwarded byte for byte (ADR 0007), because coding agents break when a gateway rewrites bodies. `serde_json` is used without `preserve_order`, so serializing the parsed body again would sort every object's keys and change whitespace and escapes across the whole request. The Claude Code gateway notes (`docs/research/claude-code-gateway.md`) warn that rewriting `system`, `tools` or earlier messages breaks prompt caching.
- **Numbering.** "In order of appearance" is not defined for a JSON object. It is also not said whether a value that appears twice gets one number or two.
- **Overlapping spans of different classes,** such as an email that contains a DNI: once merged, it is not said which class the placeholder names.
- **Invisible text,** whose default action is `redact`. A placeholder in the middle of a word (`gh[REDACTED:invisible_text:1]p_…`) adds noise and tells the model nothing.

## Decision

1. **Splice, do not serialize.** Only the JSON string tokens that contain something redacted change. A locator walks the original bytes, which have already passed strict parsing (ADR 0007). It finds the byte range of each string value by its JSON Pointer, and the redacted text, encoded by `serde_json`, replaces that range. Object keys, whitespace, escapes elsewhere and numbers stay as they were.
2. **Checked before sending.** The rewritten body is parsed strictly again. Every text must equal its redacted form, and every other text must equal the original. Any difference blocks the request with `SCAN_ERROR` (closed by default, ADR 0002).
3. **Merging (F.6.1).** Overlapping spans of one text become one. The placeholder names the class of the longest finding in the group, with ties going to `DataClass` order. An email that contains a DNI becomes one `[REDACTED:email:n]`.
4. **Numbering (F.6.2).** Numbers are per class and start at 1. The same text gets the same number everywhere in the request; values are compared in memory only and are never logged. Numbers are assigned in this order:
   - texts outside `messages`, in the order the parser lists them;
   - then the messages, in order;
   - within a text, by position.

   A conversation grows at the end of `messages`, so the placeholders of earlier turns keep their numbers from one request to the next. A rewrite that is identical on every request has the best chance of keeping prompt caching.
5. **Invisible text is removed.** A merged span whose class is `invisible_text` and that was found in the text itself is deleted, with no placeholder. The audit log records it (M5). If the invisible text was found inside a decoded fragment, the span is the whole encoded fragment, so it gets a placeholder like any other class.
6. **Decoded findings** replace the whole encoded fragment, which is their span (ADR 0008).
7. **Headers.** `content-length` follows the new body; the HTTP client sets it, and the incoming one is never forwarded. `x-resguardo-decision` is `allow`, `redact` or `block` (Annex H).

## Consequences

- A request with one DNI differs from the original only inside that one string. Prompt caching and thinking signatures of other blocks are unaffected. Whether Claude Code accepts a rewritten earlier message still needs a test with a real session (research notes, "Open problem").
- Repeated values give the model a consistent conversation: the same DNI is `[REDACTED:es_id:1]` in every turn.
- The locator is a second reader of the JSON, which is the kind of parser difference ADR 0007 guards against. Three things contain it: it only runs on bytes that `serde_json` has already accepted, the check in item 2 runs on every request, and the property tests (M3.4) compare the locator with `serde_json` on random documents.
- Removing invisible characters can join two words. That is what the scanner already saw after normalization.
