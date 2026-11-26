//! Normalization of OpenAI and Anthropic requests, and the incremental SSE parser.
//!
//! Pure: no I/O and no clock. Requests are parsed strictly and every string in the body is
//! extracted for scanning, except binary payloads (ADR 0007).
#![forbid(unsafe_code)]

pub mod json;

pub use json::{ProtoError, parse_strict};
pub mod redact;
pub mod request;

pub use redact::{RedactError, redact};

pub use request::{ApiFormat, ParsedRequest, check_query, parse_request, route};
