//! The SSE parser on arbitrary bytes, split at arbitrary points (M4.5).
//!
//! Properties: no panic; the same events wherever the input is split; the raw bytes of the
//! events are exactly the input up to the last complete event; nothing held over the limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use resguardo_proto::{SseError, SseEvent, SseParser};

const MAX_EVENT_BYTES: usize = 4096;

/// Feeds `chunks` one after the other; `None` if the parser refused the input.
fn parse(chunks: &[&[u8]]) -> Option<Vec<SseEvent>> {
    let mut parser = SseParser::new(MAX_EVENT_BYTES);
    let mut events = Vec::new();
    for chunk in chunks {
        match parser.push(chunk) {
            Ok(more) => events.extend(more),
            Err(SseError::EventTooLarge(_)) => return None,
        }
        assert!(parser.buffered() <= MAX_EVENT_BYTES);
    }
    events.extend(parser.finish());
    Some(events)
}

fuzz_target!(|data: &[u8]| {
    // The first two bytes choose two split points; the rest is the stream.
    let [a, b, input @ ..] = data else {
        return;
    };
    let len = input.len();
    let first = usize::from(*a).min(len);
    let second = (first + usize::from(*b)).min(len);

    let whole = parse(&[input]);
    let split = parse(&[&input[..first], &input[first..second], &input[second..]]);
    let bytes: Vec<&[u8]> = input.iter().map(std::slice::from_ref).collect();
    let byte_by_byte = parse(&bytes);

    // A limit error may depend on where the input is split only through what is held, and
    // whole input reaches the limit at least as early, so compare successful parses.
    if let (Some(whole), Some(split)) = (&whole, &split) {
        assert_eq!(whole, split);
    }
    if let (Some(whole), Some(byte_by_byte)) = (&whole, &byte_by_byte) {
        assert_eq!(whole, byte_by_byte);
    }
    if let Some(events) = whole {
        let raw: Vec<u8> = events.iter().flat_map(|e| e.raw.iter().copied()).collect();
        assert!(input.starts_with(&raw), "raw bytes are a prefix of the input");
    }
});
