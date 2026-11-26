//! Incremental SSE parsing (design document, "Streaming"; ADR 0014), following the
//! WHATWG event stream format: `\n`, `\r\n` and `\r` line endings, `data` lines joined with
//! `\n`, comments, one leading space stripped from values, and a size limit per event.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use resguardo_proto::{SseError, SseEvent, SseParser};

const MAX: usize = 1024;

fn parse_all(input: &[u8]) -> Vec<SseEvent> {
    let mut parser = SseParser::new(MAX);
    let mut events = parser.push(input).unwrap();
    events.extend(parser.finish());
    events
}

/// (event, data) of each event.
fn fields(events: &[SseEvent]) -> Vec<(Option<&str>, Option<&str>)> {
    events
        .iter()
        .map(|e| (e.event.as_deref(), e.data.as_deref()))
        .collect()
}

#[test]
fn openai_chunks_and_done() {
    let input = b"data: {\"a\":1}\n\ndata: [DONE]\n\n";
    let events = parse_all(input);
    assert_eq!(
        fields(&events),
        vec![(None, Some("{\"a\":1}")), (None, Some("[DONE]"))]
    );
}

#[test]
fn anthropic_events_with_names() {
    let input = b"event: message_start\ndata: {}\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\n";
    assert_eq!(
        fields(&parse_all(input)),
        vec![
            (Some("message_start"), Some("{}")),
            (Some("ping"), Some("{\"type\":\"ping\"}"))
        ]
    );
}

#[test]
fn every_line_ending_is_accepted() {
    for input in [
        &b"event: e\r\ndata: x\r\n\r\n"[..],
        &b"event: e\rdata: x\r\r"[..],
        &b"event: e\ndata: x\r\n\r"[..],
    ] {
        assert_eq!(
            fields(&parse_all(input)),
            vec![(Some("e"), Some("x"))],
            "{input:?}"
        );
    }
}

#[test]
fn data_lines_are_joined_with_newlines() {
    let input = b"data: one\ndata:two\ndata\ndata:  three\n\n";
    // One leading space is stripped; `data` without a colon adds an empty line.
    assert_eq!(
        fields(&parse_all(input)),
        vec![(None, Some("one\ntwo\n\n three"))]
    );
}

#[test]
fn comments_and_unknown_fields_are_ignored_but_kept_in_raw() {
    let input = b": keep-alive\nretry: 10\nfoo: bar\ndata: x\nid: 7\n\n";
    let events = parse_all(input);
    assert_eq!(fields(&events), vec![(None, Some("x"))]);
    assert_eq!(events[0].id.as_deref(), Some("7"));
    assert_eq!(events[0].raw, input);
}

#[test]
fn a_block_without_data_is_an_event_without_data() {
    // A comment-only block still has to reach the client: it keeps the connection alive.
    let events = parse_all(b": ping\n\n");
    assert_eq!(fields(&events), vec![(None, None)]);
    assert_eq!(events[0].raw, b": ping\n\n");
}

#[test]
fn raw_bytes_of_all_events_rebuild_the_input() {
    let input: &[u8] =
        b"\xEF\xBB\xBFevent: a\r\ndata: 1\r\n\r\n: c\n\ndata: x\rdata: y\r\r\n\nevent: b\ndata: 2\n\n";
    let events = parse_all(input);
    let rebuilt: Vec<u8> = events.iter().flat_map(|e| e.raw.clone()).collect();
    assert_eq!(rebuilt, input);
    // The byte order mark at the very start is not part of the first field name.
    assert_eq!(events[0].event.as_deref(), Some("a"));
}

#[test]
fn splitting_the_input_anywhere_gives_the_same_events() {
    let input: &[u8] =
        b"event: a\r\ndata: \xC3\xB1\r\n\r\ndata: x\rdata: y\r\r: c\n\nevent: b\ndata: 2\n\n";
    let whole = parse_all(input);
    for split in 0..=input.len() {
        let mut parser = SseParser::new(MAX);
        let mut events = parser.push(&input[..split]).unwrap();
        events.extend(parser.push(&input[split..]).unwrap());
        events.extend(parser.finish());
        assert_eq!(events, whole, "split at {split}");
    }
    // Byte by byte.
    let mut parser = SseParser::new(MAX);
    let mut events = Vec::new();
    for byte in input {
        events.extend(parser.push(std::slice::from_ref(byte)).unwrap());
    }
    events.extend(parser.finish());
    assert_eq!(events, whole);
}

#[test]
fn an_incomplete_event_at_the_end_is_dropped() {
    // A client discards it too, so it is never forwarded unscanned.
    let mut parser = SseParser::new(MAX);
    let events = parser.push(b"data: done\n\ndata: cut").unwrap();
    assert_eq!(fields(&events), vec![(None, Some("done"))]);
    assert_eq!(parser.finish(), None);
}

#[test]
fn invalid_utf8_reads_as_replacement_characters_like_a_client() {
    let events = parse_all(b"data: a\xFFb\n\n");
    assert_eq!(events[0].data.as_deref(), Some("a\u{FFFD}b"));
}

#[test]
fn an_event_over_the_limit_is_an_error() {
    let mut parser = SseParser::new(16);
    assert_eq!(
        parser.push(b"data: 0123456789\ndata: 0123456789\n\n"),
        Err(SseError::EventTooLarge(16))
    );
}

#[test]
fn a_line_that_never_ends_is_an_error_once_over_the_limit() {
    let mut parser = SseParser::new(16);
    assert!(parser.push(b"data: 0123456").unwrap().is_empty());
    assert_eq!(parser.push(b"789abcdef"), Err(SseError::EventTooLarge(16)));
}

#[test]
fn ten_thousand_events_keep_memory_bounded() {
    let mut parser = SseParser::new(MAX);
    let event = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n";
    let mut count = 0;
    for _ in 0..10_000 {
        count += parser.push(event).unwrap().len();
        assert!(parser.buffered() < event.len(), "{}", parser.buffered());
    }
    assert_eq!(count, 10_000);
}
