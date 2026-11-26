//! Normalization of OpenAI and Anthropic requests, and the incremental SSE parser.
//!
//! Pure: no I/O and no clock. Requests are parsed strictly and every string in the body is
//! extracted for scanning, except binary payloads (ADR 0007).
#![forbid(unsafe_code)]

pub mod json;
pub mod markdown;

pub use json::{ProtoError, parse_strict};
pub mod redact;
pub mod request;
pub mod sse;
pub mod stream;

pub use markdown::{MarkdownFilter, MarkdownState, ResponseControls};
pub use redact::{RedactError, redact, replace_strings};
pub use sse::{SseError, SseEvent, SseParser};
pub use stream::{
    Block, ChoicePart, ResponseText, StreamError, StreamEvent, TextKind, analyze_event,
    flush_event, response_texts, rewrite_event,
};

pub use request::{ApiFormat, ParsedRequest, check_query, parse_request, route};
