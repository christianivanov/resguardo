//! Domain types shared by every crate (design document, Annex D).
//!
//! The shape is indicative; the meaning is binding:
//! - a [`Finding`] never contains the matched value;
//! - [`Finding::span`] always refers to the ORIGINAL text;
//! - [`BlockCode::ScanError`] and [`BlockCode::AuditUnavailable`] exist so that internal
//!   failures turn into blocks (closed by default, ADR 0002).

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Upstream API a request is sent to.
///
/// `OpenAiCompatible` speaks the OpenAI Chat Completions format at a configured URL (ADR 0005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
}

impl Provider {
    pub const ALL: [Provider; 3] = [
        Provider::OpenAi,
        Provider::Anthropic,
        Provider::OpenAiCompatible,
    ];

    /// Name used in configuration, audit entries and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::OpenAi => "openai",
            Provider::Anthropic => "anthropic",
            Provider::OpenAiCompatible => "openai_compatible",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who makes the request: an application or agent identified by its virtual key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Accepts 1 to 64 characters of `a-z`, `0-9`, `-` or `_`, starting with a letter or digit.
    /// The id appears in audit entries and file names, so its alphabet stays small.
    pub fn parse(id: &str) -> Option<Self> {
        let valid_byte =
            |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_';
        let mut bytes = id.bytes();
        let valid = (1..=64).contains(&id.len())
            && matches!(bytes.next(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes.all(valid_byte);
        valid.then(|| Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex SHA-256 of a virtual key. The key itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualKeyHash(String);

impl VirtualKeyHash {
    /// Accepts exactly 64 lowercase hexadecimal characters.
    pub fn parse(hex: &str) -> Option<Self> {
        let valid = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        valid.then(|| Self(hex.to_owned()))
    }

    /// For hashes computed by this crate, which are lowercase hex by construction.
    pub(crate) fn from_computed(hex: String) -> Self {
        Self(hex)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Per-principal limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_messages: usize,
    pub requests_per_minute: u32,
}

impl Limits {
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
    pub const DEFAULT_MAX_MESSAGES: usize = 256;
    pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 60;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            max_messages: Self::DEFAULT_MAX_MESSAGES,
            requests_per_minute: Self::DEFAULT_REQUESTS_PER_MINUTE,
        }
    }
}

/// How streamed responses are released to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMode {
    /// Hold text until a sentence ends or `buffer_flush_bytes` is reached.
    Buffer,
    /// Release immediately; on a blocking finding, cut the stream with an error event.
    #[default]
    PassthroughAbort,
}

/// An application or agent allowed to use Resguardo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    /// Allowed models per provider, compared as exact strings.
    pub allowed: BTreeMap<Provider, Vec<String>>,
    pub limits: Limits,
    /// Overrides the global action for these classes.
    pub actions: BTreeMap<DataClass, Action>,
    pub stream_mode: StreamMode,
    /// The virtual key stops working at this instant (UTC). Written as RFC 3339 in the config.
    pub expires_at: Option<OffsetDateTime>,
}

/// Normalized request. Unknown fields stay in `raw` and are forwarded untouched.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalRequest {
    /// UUID v7.
    pub request_id: String,
    pub provider: Provider,
    pub model: String,
    pub texts: Vec<ScanText>,
    pub stream: bool,
    /// Original body, used to rebuild the forwarded request.
    pub raw: serde_json::Value,
}

/// Scannable text with its JSON Pointer inside the original body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanText {
    /// For example `/messages/2/content`.
    pub pointer: String,
    pub role: Role,
    pub text: String,
}

/// Who wrote a [`ScanText`]. Informational: policy does not depend on it.
/// `System` also covers everything the application sets outside the conversation
/// (`tools`, `metadata`…), see ADR 0007.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// Kind of sensitive data a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Secret,
    SecretCandidate,
    EsId,
    Iban,
    Card,
    Phone,
    Email,
    InvisibleText,
    /// Used by response controls (`[response]`), not by `[policy.actions]`.
    Url,
}

impl DataClass {
    /// Classes that request policy assigns an action to.
    pub const REQUEST_CLASSES: [DataClass; 8] = [
        DataClass::Secret,
        DataClass::SecretCandidate,
        DataClass::EsId,
        DataClass::Iban,
        DataClass::Card,
        DataClass::Phone,
        DataClass::Email,
        DataClass::InvisibleText,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DataClass::Secret => "secret",
            DataClass::SecretCandidate => "secret_candidate",
            DataClass::EsId => "es_id",
            DataClass::Iban => "iban",
            DataClass::Card => "card",
            DataClass::Phone => "phone",
            DataClass::Email => "email",
            DataClass::InvisibleText => "invisible_text",
            DataClass::Url => "url",
        }
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ordered from least to most restrictive: combining findings takes the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Flag,
    Redact,
    Block,
}

/// A detector match. Never carries the matched value: use `rule` and `span` to debug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub class: DataClass,
    /// Which [`ScanText`] it belongs to.
    pub pointer: String,
    /// Byte range in the ORIGINAL text. For decoded findings, the whole encoded fragment.
    pub span: Range<usize>,
    /// For example `secret.aws_access_key`.
    pub rule: String,
    /// 0 to 100.
    pub confidence: u8,
    /// Decoding layers crossed, for example `["base64"]`.
    pub via: Vec<String>,
}

/// A scanning limit that stopped decoding (ADR 0008). Not a finding: no data class is known,
/// only that some content was not fully inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimit {
    /// A fragment at `max_decode_depth` would decode to text that was not scanned.
    DecodeDepth,
    /// A decoded text was longer than `max_derived_bytes`; only its first part was scanned.
    DerivedBytes,
}

impl ScanLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanLimit::DecodeDepth => "decode_depth",
            ScanLimit::DerivedBytes => "derived_bytes",
        }
    }
}

impl fmt::Display for ScanLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Records that a [`ScanLimit`] was reached. Like a [`Finding`], it never carries content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFlag {
    pub limit: ScanLimit,
    /// Which [`ScanText`] it belongs to.
    pub pointer: String,
    /// Byte range in the ORIGINAL text: the whole outermost encoded fragment.
    pub span: Range<usize>,
    /// Layers crossed, ending with the one that was not fully decoded.
    pub via: Vec<String>,
}

/// Everything the scanner found in a request, for policy to decide on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub flags: Vec<ScanFlag>,
}

/// Outcome of policy for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        flags: Vec<Finding>,
    },
    Redact {
        spans: Vec<Finding>,
        flags: Vec<Finding>,
    },
    Block {
        code: BlockCode,
        class: Option<DataClass>,
    },
}

/// Why a request was blocked. Each maps to one error code and HTTP status (Annex H).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockCode {
    /// Malformed body, unknown query parameter or missing field (ADR 0007).
    InvalidRequest,
    UnknownKey,
    KeyExpired,
    ModelNotAllowed,
    BodyTooLarge,
    RateLimited,
    SensitiveData,
    ScanError,
    /// The provider answered with a redirect, which is never followed.
    UpstreamRedirect,
    /// Connection, TLS, timeout or an unacceptable response from the provider.
    UpstreamError,
    AuditUnavailable,
}

impl BlockCode {
    /// Error code returned to the application and written to the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockCode::InvalidRequest => "INVALID_REQUEST",
            BlockCode::UnknownKey => "UNKNOWN_KEY",
            BlockCode::KeyExpired => "KEY_EXPIRED",
            BlockCode::ModelNotAllowed => "MODEL_NOT_ALLOWED",
            BlockCode::BodyTooLarge => "BODY_TOO_LARGE",
            BlockCode::RateLimited => "RATE_LIMITED",
            BlockCode::SensitiveData => "SENSITIVE_DATA",
            BlockCode::ScanError => "SCAN_ERROR",
            BlockCode::UpstreamRedirect => "UPSTREAM_REDIRECT",
            BlockCode::UpstreamError => "UPSTREAM_ERROR",
            BlockCode::AuditUnavailable => "AUDIT_UNAVAILABLE",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            BlockCode::InvalidRequest => 400,
            BlockCode::UnknownKey | BlockCode::KeyExpired => 401,
            BlockCode::ModelNotAllowed | BlockCode::SensitiveData => 403,
            BlockCode::BodyTooLarge => 413,
            BlockCode::RateLimited => 429,
            BlockCode::ScanError => 500,
            BlockCode::UpstreamRedirect | BlockCode::UpstreamError => 502,
            BlockCode::AuditUnavailable => 503,
        }
    }
}

impl fmt::Display for BlockCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Decision,
    Outcome,
}

/// One line of the audit log. `hash` and `sig` are computed over the rest (Annex F.8, M5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub kind: AuditKind,
    /// ISO 8601 UTC with milliseconds.
    pub ts: String,
    pub request_id: String,
    /// Strings, integers, booleans, objects and lists only: never floats.
    #[serde(flatten)]
    pub fields: BTreeMap<String, serde_json::Value>,
    /// Hex hash of the previous entry.
    pub prev: String,
    pub hash: String,
    /// Ed25519, Base64url without padding.
    pub sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_are_ordered_from_least_to_most_restrictive() {
        assert!(Action::Allow < Action::Flag);
        assert!(Action::Flag < Action::Redact);
        assert!(Action::Redact < Action::Block);
        assert_eq!(
            [Action::Flag, Action::Block, Action::Redact].iter().max(),
            Some(&Action::Block)
        );
    }

    #[test]
    fn virtual_key_hash_accepts_only_64_lowercase_hex() {
        assert!(VirtualKeyHash::parse(&"a".repeat(64)).is_some());
        assert!(VirtualKeyHash::parse(&"A".repeat(64)).is_none());
        assert!(VirtualKeyHash::parse(&"a".repeat(63)).is_none());
        assert!(VirtualKeyHash::parse(&"g".repeat(64)).is_none());
    }

    #[test]
    fn block_codes_map_to_annex_h() {
        let expected = [
            (BlockCode::InvalidRequest, "INVALID_REQUEST", 400),
            (BlockCode::UnknownKey, "UNKNOWN_KEY", 401),
            (BlockCode::KeyExpired, "KEY_EXPIRED", 401),
            (BlockCode::ModelNotAllowed, "MODEL_NOT_ALLOWED", 403),
            (BlockCode::SensitiveData, "SENSITIVE_DATA", 403),
            (BlockCode::BodyTooLarge, "BODY_TOO_LARGE", 413),
            (BlockCode::RateLimited, "RATE_LIMITED", 429),
            (BlockCode::ScanError, "SCAN_ERROR", 500),
            (BlockCode::UpstreamRedirect, "UPSTREAM_REDIRECT", 502),
            (BlockCode::UpstreamError, "UPSTREAM_ERROR", 502),
            (BlockCode::AuditUnavailable, "AUDIT_UNAVAILABLE", 503),
        ];
        for (code, name, status) in expected {
            assert_eq!(code.as_str(), name);
            assert_eq!(code.http_status(), status);
        }
    }

    #[test]
    fn serialized_names_match_the_configuration() {
        let json = serde_json::to_string(&Provider::OpenAiCompatible).unwrap();
        assert_eq!(json, "\"openai_compatible\"");
        for provider in Provider::ALL {
            assert_eq!(
                serde_json::to_string(&provider).unwrap(),
                format!("\"{}\"", provider.as_str())
            );
        }
        for class in DataClass::REQUEST_CLASSES {
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{}\"", class.as_str())
            );
        }
        let mode: StreamMode = serde_json::from_str("\"passthrough_abort\"").unwrap();
        assert_eq!(mode, StreamMode::PassthroughAbort);
        for limit in [ScanLimit::DecodeDepth, ScanLimit::DerivedBytes] {
            assert_eq!(
                serde_json::to_string(&limit).unwrap(),
                format!("\"{}\"", limit.as_str())
            );
        }
    }
}
