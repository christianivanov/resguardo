//! Routes, query strings and text extraction for both APIs (ADR 0007).

use resguardo_core::{CanonicalRequest, Provider, Role, ScanText};
use serde_json::{Map, Value};

use crate::json::{ProtoError, parse_strict};

/// Wire format of a request. The provider is decided later: `OpenAiChat` goes to `openai` or
/// `openai_compatible` depending on the principal's model lists (ADR 0005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiFormat {
    /// `POST /v1/chat/completions`
    OpenAiChat,
    /// `POST /v1/messages`
    AnthropicMessages,
}

impl ApiFormat {
    /// Path on the upstream, appended to its `base_url`. Fixed: never taken from the client.
    pub fn path(self) -> &'static str {
        match self {
            ApiFormat::OpenAiChat => "/v1/chat/completions",
            ApiFormat::AnthropicMessages => "/v1/messages",
        }
    }
}

/// Matches the exact path, without the query string. Anything else gets a 404 without
/// contacting a provider (Annex H).
pub fn route(method: &str, path: &str) -> Option<ApiFormat> {
    match (method, path) {
        ("POST", "/v1/chat/completions") => Some(ApiFormat::OpenAiChat),
        ("POST", "/v1/messages") => Some(ApiFormat::AnthropicMessages),
        _ => None,
    }
}

/// The query string is a channel the scanner does not see, so only known values pass:
/// none on Chat Completions, `beta=true` on Messages (sent by Claude Code).
pub fn check_query(format: ApiFormat, query: Option<&str>) -> Result<(), ProtoError> {
    let allowed = matches!(
        (format, query),
        (_, None | Some("")) | (ApiFormat::AnthropicMessages, Some("beta=true"))
    );
    if allowed {
        Ok(())
    } else {
        Err(ProtoError::QueryNotAllowed)
    }
}

/// A request body, parsed and with its text extracted.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRequest {
    pub format: ApiFormat,
    pub model: String,
    pub stream: bool,
    /// Length of `messages`, checked against the principal's `max_messages`.
    pub message_count: usize,
    /// Images, audio and PDFs skipped by the scanner (ADR 0007).
    pub binary_parts: usize,
    /// Every string in the body except binary payloads, each with its JSON Pointer.
    pub texts: Vec<ScanText>,
    /// The parsed body. The original bytes are kept by the server for byte-exact forwarding.
    pub raw: Value,
}

impl ParsedRequest {
    /// Adds what is known only after routing: the request id and the resolved provider.
    pub fn into_canonical(self, request_id: String, provider: Provider) -> CanonicalRequest {
        CanonicalRequest {
            request_id,
            provider,
            model: self.model,
            texts: self.texts,
            stream: self.stream,
            raw: self.raw,
        }
    }
}

/// Parses a request body strictly and extracts its text.
pub fn parse_request(format: ApiFormat, body: &[u8]) -> Result<ParsedRequest, ProtoError> {
    let raw = parse_strict(body)?;
    let Value::Object(root) = &raw else {
        return Err(ProtoError::NotAnObject);
    };
    let model = match root.get("model") {
        Some(Value::String(model)) if !model.is_empty() => model.clone(),
        _ => return Err(ProtoError::InvalidField("model")),
    };
    let stream = match root.get("stream") {
        None => false,
        Some(Value::Bool(stream)) => *stream,
        Some(_) => return Err(ProtoError::InvalidField("stream")),
    };
    let message_count = match root.get("messages") {
        Some(Value::Array(messages)) => messages.len(),
        _ => return Err(ProtoError::InvalidField("messages")),
    };

    let mut extractor = Extractor::default();
    let mut pointer = String::new();
    for (key, value) in root {
        with_segment(&mut pointer, key, |pointer| {
            if key == "messages" {
                extractor.messages(value, pointer);
            } else {
                extractor.walk(value, pointer, Role::System, Some(key));
            }
        });
    }

    Ok(ParsedRequest {
        format,
        model,
        stream,
        message_count,
        binary_parts: extractor.binary_parts,
        texts: extractor.texts,
        raw,
    })
}

#[derive(Default)]
struct Extractor {
    texts: Vec<ScanText>,
    binary_parts: usize,
}

impl Extractor {
    /// Each message is walked with its own role.
    fn messages(&mut self, messages: &Value, pointer: &mut String) {
        let Value::Array(messages) = messages else {
            return;
        };
        for (index, message) in messages.iter().enumerate() {
            let role = message_role(message);
            with_segment(pointer, &index.to_string(), |pointer| {
                self.walk(message, pointer, role, None);
            });
        }
    }

    /// Visits every string under `value`. Recursion depth is bounded by the parser's
    /// 128-level nesting limit.
    fn walk(&mut self, value: &Value, pointer: &mut String, role: Role, key: Option<&str>) {
        match value {
            Value::String(text) => {
                if is_binary_data_url(text) {
                    self.binary_parts += 1;
                } else {
                    self.texts.push(ScanText {
                        pointer: pointer.clone(),
                        role,
                        text: text.clone(),
                    });
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    with_segment(pointer, &index.to_string(), |pointer| {
                        self.walk(item, pointer, role, None);
                    });
                }
            }
            Value::Object(object) => {
                // Everything inside a tool result was produced by a tool, not by the user.
                let role = if object.get("type").and_then(Value::as_str) == Some("tool_result") {
                    Role::Tool
                } else {
                    role
                };
                let binary_data = has_binary_data(object, key);
                for (child_key, child) in object {
                    if binary_data && child_key == "data" && child.is_string() {
                        self.binary_parts += 1;
                        continue;
                    }
                    with_segment(pointer, child_key, |pointer| {
                        self.walk(child, pointer, role, Some(child_key));
                    });
                }
            }
            // Numbers, booleans and null are not scanned (ADR 0007, threat model).
            Value::Number(_) | Value::Bool(_) | Value::Null => {}
        }
    }
}

/// Role of a message. Unknown or missing roles count as `User`: the role is informational
/// and never relaxes scanning.
fn message_role(message: &Value) -> Role {
    match message.get("role").and_then(Value::as_str) {
        Some("system" | "developer") => Role::System,
        Some("assistant") => Role::Assistant,
        Some("tool") => Role::Tool,
        _ => Role::User,
    }
}

/// Media types the scanner cannot read as text.
fn is_binary_media_type(media_type: &str) -> bool {
    let media_type = media_type.trim().to_ascii_lowercase();
    media_type.starts_with("image/")
        || media_type.starts_with("audio/")
        || media_type == "application/pdf"
}

/// `data:image/png;base64,…` and similar. A `data:text/plain,…` URL is still scanned.
fn is_binary_data_url(text: &str) -> bool {
    let Some(prefix) = text.get(..5) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case("data:") {
        return false;
    }
    let rest = &text[5..];
    let end = rest.find([';', ',']).unwrap_or(rest.len());
    is_binary_media_type(&rest[..end])
}

/// Objects whose `data` field holds binary content:
/// an Anthropic `{"type":"base64","media_type":"image/png","data":…}` source, or an OpenAI
/// `"input_audio": {"data":…,"format":"wav"}`.
fn has_binary_data(object: &Map<String, Value>, key: Option<&str>) -> bool {
    let base64_source = object.get("type").and_then(Value::as_str) == Some("base64")
        && object
            .get("media_type")
            .and_then(Value::as_str)
            .is_some_and(is_binary_media_type);
    base64_source || key == Some("input_audio")
}

/// Appends `/segment` to the pointer (RFC 6901 escaping), runs `f`, then removes it.
pub(crate) fn with_segment<T>(
    pointer: &mut String,
    segment: &str,
    f: impl FnOnce(&mut String) -> T,
) -> T {
    let len = pointer.len();
    pointer.push('/');
    for c in segment.chars() {
        match c {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            c => pointer.push(c),
        }
    }
    let result = f(pointer);
    pointer.truncate(len);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/../../fixtures/requests/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&path).unwrap()
    }

    fn sorted(texts: &[ScanText]) -> Vec<(String, Role, String)> {
        let mut all: Vec<_> = texts
            .iter()
            .map(|t| (t.pointer.clone(), t.role, t.text.clone()))
            .collect();
        // Pointers are unique, so sorting by them gives a total order.
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    fn expected(rows: &[(&str, Role, &str)]) -> Vec<(String, Role, String)> {
        let mut all: Vec<_> = rows
            .iter()
            .map(|(p, r, t)| ((*p).to_owned(), *r, (*t).to_owned()))
            .collect();
        // Pointers are unique, so sorting by them gives a total order.
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    #[test]
    fn routes_match_the_exact_path_and_method() {
        assert_eq!(
            route("POST", "/v1/chat/completions"),
            Some(ApiFormat::OpenAiChat)
        );
        assert_eq!(
            route("POST", "/v1/messages"),
            Some(ApiFormat::AnthropicMessages)
        );
        for (method, path) in [
            ("GET", "/v1/messages"),
            ("POST", "/v1/messages/"),
            ("POST", "/v1/messages/count_tokens"),
            ("POST", "/V1/messages"),
            ("POST", "/v1/embeddings"),
            ("POST", "/v1//messages"),
            ("POST", "/v1/%6Dessages"),
        ] {
            assert_eq!(route(method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn only_known_query_strings_pass() {
        use ApiFormat::*;
        assert_eq!(check_query(OpenAiChat, None), Ok(()));
        assert_eq!(check_query(OpenAiChat, Some("")), Ok(()));
        assert_eq!(check_query(AnthropicMessages, Some("beta=true")), Ok(()));
        for (format, query) in [
            (OpenAiChat, "beta=true"),
            (AnthropicMessages, "beta=false"),
            (AnthropicMessages, "beta=true&x=1"),
            (AnthropicMessages, "x=AKIAIOSFODNN7EXAMPLE"),
        ] {
            let error = check_query(format, Some(query)).unwrap_err();
            assert_eq!(error, ProtoError::QueryNotAllowed);
            assert!(!error.to_string().contains(query));
        }
    }

    #[test]
    fn anthropic_agent_request_extracts_every_string() {
        let parsed = parse_request(
            ApiFormat::AnthropicMessages,
            &fixture("anthropic_agent.json"),
        )
        .unwrap();
        assert_eq!(parsed.model, "claude-sonnet-5-5");
        assert!(parsed.stream);
        assert_eq!(parsed.message_count, 3);
        assert_eq!(parsed.binary_parts, 1, "the base64 PNG");
        use Role::*;
        let want = expected(&[
            ("/messages/0/content", User, "Read .env"),
            ("/messages/0/role", User, "user"),
            ("/messages/1/content/0/signature", Assistant, "c2lnbmF0dXJl"),
            (
                "/messages/1/content/0/thinking",
                Assistant,
                "I should read it.",
            ),
            ("/messages/1/content/0/type", Assistant, "thinking"),
            ("/messages/1/content/1/id", Assistant, "toolu_01"),
            ("/messages/1/content/1/input/path", Assistant, ".env"),
            ("/messages/1/content/1/name", Assistant, "read_file"),
            ("/messages/1/content/1/type", Assistant, "tool_use"),
            ("/messages/1/role", Assistant, "assistant"),
            (
                "/messages/2/content/0/content/0/text",
                Tool,
                "API_KEY=not-a-real-key",
            ),
            ("/messages/2/content/0/content/0/type", Tool, "text"),
            ("/messages/2/content/0/tool_use_id", Tool, "toolu_01"),
            ("/messages/2/content/0/type", Tool, "tool_result"),
            ("/messages/2/content/1/source/media_type", User, "image/png"),
            ("/messages/2/content/1/source/type", User, "base64"),
            ("/messages/2/content/1/type", User, "image"),
            (
                "/messages/2/content/2/payload/note",
                User,
                "new block types are scanned too",
            ),
            ("/messages/2/content/2/type", User, "future_block"),
            ("/messages/2/role", User, "user"),
            ("/metadata/user_id", System, "user-42"),
            ("/model", System, "claude-sonnet-5-5"),
            ("/system/0/cache_control/type", System, "ephemeral"),
            ("/system/0/text", System, "You are a coding agent."),
            ("/system/0/type", System, "text"),
            ("/tools/0/description", System, "Read a file"),
            (
                "/tools/0/input_schema/properties/path/type",
                System,
                "string",
            ),
            ("/tools/0/input_schema/type", System, "object"),
            ("/tools/0/name", System, "read_file"),
        ]);
        // `context_management.edits` is an empty array, so it adds no text.
        assert_eq!(sorted(&parsed.texts), want);
        // The binary payload never reaches the scanner.
        assert!(parsed.texts.iter().all(|t| t.text != "iVBORw0KGgo="));
    }

    #[test]
    fn openai_request_extracts_every_string() {
        let parsed = parse_request(ApiFormat::OpenAiChat, &fixture("openai_tools.json")).unwrap();
        assert_eq!(parsed.model, "gpt-4.1-mini");
        assert!(!parsed.stream);
        assert_eq!(parsed.message_count, 4);
        assert_eq!(parsed.binary_parts, 1, "the data: image URL");
        use Role::*;
        let want = expected(&[
            ("/messages/0/content", System, "Be brief."),
            ("/messages/0/role", System, "developer"),
            ("/messages/1/content/0/text", User, "What is in this image?"),
            ("/messages/1/content/0/type", User, "text"),
            ("/messages/1/content/1/type", User, "image_url"),
            (
                "/messages/1/content/2/image_url/url",
                User,
                "https://example.com/cat.png",
            ),
            ("/messages/1/content/2/type", User, "image_url"),
            ("/messages/1/role", User, "user"),
            ("/messages/2/role", Assistant, "assistant"),
            (
                "/messages/2/tool_calls/0/function/arguments",
                Assistant,
                "{\"q\":\"cat\"}",
            ),
            (
                "/messages/2/tool_calls/0/function/name",
                Assistant,
                "lookup",
            ),
            ("/messages/2/tool_calls/0/id", Assistant, "call_1"),
            ("/messages/2/tool_calls/0/type", Assistant, "function"),
            ("/messages/3/content", Tool, "A cat."),
            ("/messages/3/role", Tool, "tool"),
            ("/messages/3/tool_call_id", Tool, "call_1"),
            ("/model", System, "gpt-4.1-mini"),
            ("/prediction/content", System, "predicted text"),
            ("/prediction/type", System, "content"),
            ("/user", System, "user-42"),
        ]);
        assert_eq!(sorted(&parsed.texts), want);
    }

    #[test]
    fn raw_keeps_unknown_fields() {
        let body = fixture("anthropic_agent.json");
        let parsed = parse_request(ApiFormat::AnthropicMessages, &body).unwrap();
        let original: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.raw, original);
        assert!(parsed.raw.get("context_management").is_some());
    }

    #[test]
    fn binary_payloads_are_skipped_but_text_disguised_as_data_is_not() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":[
            {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0="}},
            {"type":"document","source":{"type":"base64","media_type":"text/plain","data":"c2VjcmV0"}},
            {"type":"input_audio","input_audio":{"data":"UklGRg==","format":"wav"}},
            {"type":"image_url","image_url":{"url":"DATA:Image/PNG;base64,AAAA"}},
            {"type":"text","text":"data:text/plain;base64,c2VjcmV0"}
        ]}]}"#;
        let parsed = parse_request(ApiFormat::OpenAiChat, body).unwrap();
        // Binary: the PDF, the WAV audio and the PNG data URL. The text/plain source is not.
        assert_eq!(parsed.binary_parts, 3);
        let texts: Vec<&str> = parsed.texts.iter().map(|t| t.text.as_str()).collect();
        assert!(
            texts.contains(&"c2VjcmV0"),
            "text/plain base64 source is scanned"
        );
        assert!(texts.contains(&"data:text/plain;base64,c2VjcmV0"));
        assert!(!texts.contains(&"JVBERi0="));
        assert!(!texts.contains(&"UklGRg=="));
    }

    #[test]
    fn pointers_escape_slash_and_tilde() {
        let body = br#"{"model":"m","messages":[],"metadata":{"a/b":"x","m~n":"y"}}"#;
        let parsed = parse_request(ApiFormat::OpenAiChat, body).unwrap();
        let pointers: Vec<&str> = parsed.texts.iter().map(|t| t.pointer.as_str()).collect();
        assert!(pointers.contains(&"/metadata/a~1b"), "{pointers:?}");
        assert!(pointers.contains(&"/metadata/m~0n"), "{pointers:?}");
    }

    #[test]
    fn required_fields_are_checked() {
        let cases: [(&[u8], ProtoError); 7] = [
            (b"[]", ProtoError::NotAnObject),
            (br#"{"messages":[]}"#, ProtoError::InvalidField("model")),
            (
                br#"{"model":"","messages":[]}"#,
                ProtoError::InvalidField("model"),
            ),
            (
                br#"{"model":7,"messages":[]}"#,
                ProtoError::InvalidField("model"),
            ),
            (br#"{"model":"m"}"#, ProtoError::InvalidField("messages")),
            (
                br#"{"model":"m","messages":{}}"#,
                ProtoError::InvalidField("messages"),
            ),
            (
                br#"{"model":"m","messages":[],"stream":"true"}"#,
                ProtoError::InvalidField("stream"),
            ),
        ];
        for (body, error) in cases {
            assert_eq!(
                parse_request(ApiFormat::AnthropicMessages, body),
                Err(error),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn canonical_request_gets_id_and_provider() {
        let body = br#"{"model":"llama-3","messages":[{"role":"user","content":"hola"}]}"#;
        let canonical = parse_request(ApiFormat::OpenAiChat, body)
            .unwrap()
            .into_canonical("req-1".into(), Provider::OpenAiCompatible);
        assert_eq!(canonical.provider, Provider::OpenAiCompatible);
        assert_eq!(canonical.request_id, "req-1");
        assert_eq!(canonical.model, "llama-3");
    }
}
