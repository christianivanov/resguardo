//! What responses carry, per provider (ADR 0014): the texts to scan, the stream block each
//! one belongs to, and whether response controls apply to it; plus how a stream event whose
//! text changed is written again.

use resguardo_core::ScanText;
use serde_json::{Value, json};

use crate::json::parse_strict;
use crate::request::{ApiFormat, with_segment};
use crate::sse::SseEvent;

/// Whether response controls (images and links) apply to a text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    /// Text shown to the user: OpenAI `content`, Anthropic `text`.
    Text,
    /// Scanned only: tool arguments, refusals, thinking, and every other string.
    Other,
}

/// A stream position whose texts are scanned with a shared window (ADR 0014).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Block {
    /// An OpenAI choice, by its `index`.
    Choice { index: u64, part: ChoicePart },
    /// An Anthropic content block, by its `index`.
    Content(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChoicePart {
    Content,
    Refusal,
    /// A tool call, by its `index`.
    Tool(u64),
}

/// One string of a response, with its JSON Pointer in the event data or response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseText {
    pub pointer: String,
    /// `None`: scanned on its own, without a window.
    pub block: Option<Block>,
    pub kind: TextKind,
    pub text: String,
}

impl ResponseText {
    pub fn to_scan_text(&self) -> ScanText {
        ScanText {
            pointer: self.pointer.clone(),
            role: resguardo_core::Role::Assistant,
            text: self.text.clone(),
        }
    }
}

/// A parsed stream event.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamEvent {
    pub sse: SseEvent,
    pub json: Option<Value>,
    /// Every string of the data, as for requests (ADR 0007); delta texts carry their block.
    pub texts: Vec<ResponseText>,
    /// Choices (OpenAI) or content blocks (Anthropic) that end with this event.
    pub ends: Vec<u64>,
    /// `data: [DONE]` (OpenAI) or `message_stop` (Anthropic).
    pub done: bool,
}

/// Why a stream event could not be read. The stream is cut (closed by default).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("a response stream event does not hold valid JSON")]
    NotJson,
    #[error("a response stream event cannot be written again")]
    Rewrite,
}

pub fn analyze_event(format: ApiFormat, sse: SseEvent) -> Result<StreamEvent, StreamError> {
    let mut event = StreamEvent {
        sse,
        json: None,
        texts: Vec::new(),
        ends: Vec::new(),
        done: false,
    };
    let Some(data) = event.sse.data.as_deref() else {
        return Ok(event);
    };
    if format == ApiFormat::OpenAiChat && data.trim() == "[DONE]" {
        event.done = true;
        return Ok(event);
    }
    let json = parse_strict(data.as_bytes()).map_err(|_| StreamError::NotJson)?;
    let blocks = match format {
        ApiFormat::OpenAiChat => openai_blocks(&json, &mut event.ends),
        ApiFormat::AnthropicMessages => anthropic_blocks(&json, &mut event.ends, &mut event.done),
    };
    event.texts = strings(&json)
        .into_iter()
        .map(|(pointer, text)| {
            let (block, kind) = blocks
                .iter()
                .find(|(p, _, _)| *p == pointer)
                .map_or((None, TextKind::Other), |(_, b, k)| (Some(b.clone()), *k));
            ResponseText {
                pointer,
                block,
                kind,
                text,
            }
        })
        .collect();
    event.json = Some(json);
    Ok(event)
}

/// Delta pointers of an OpenAI chunk, and the choices it finishes.
fn openai_blocks(json: &Value, ends: &mut Vec<u64>) -> Vec<(String, Block, TextKind)> {
    let mut blocks = Vec::new();
    let Some(choices) = json.get("choices").and_then(Value::as_array) else {
        return blocks;
    };
    for (n, choice) in choices.iter().enumerate() {
        let index = choice
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(n as u64);
        let block = |part| Block::Choice { index, part };
        blocks.push((
            format!("/choices/{n}/delta/content"),
            block(ChoicePart::Content),
            TextKind::Text,
        ));
        blocks.push((
            format!("/choices/{n}/delta/refusal"),
            block(ChoicePart::Refusal),
            TextKind::Other,
        ));
        let tools = choice
            .pointer("/delta/tool_calls")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for (t, tool) in tools.iter().enumerate() {
            let tool_index = tool
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or(t as u64);
            blocks.push((
                format!("/choices/{n}/delta/tool_calls/{t}/function/arguments"),
                block(ChoicePart::Tool(tool_index)),
                TextKind::Other,
            ));
        }
        if choice
            .get("finish_reason")
            .is_some_and(|reason| !reason.is_null())
        {
            ends.push(index);
        }
    }
    blocks
}

/// Delta pointer of an Anthropic event, and the block or message it ends.
fn anthropic_blocks(
    json: &Value,
    ends: &mut Vec<u64>,
    done: &mut bool,
) -> Vec<(String, Block, TextKind)> {
    let index = json.get("index").and_then(Value::as_u64);
    match (json.get("type").and_then(Value::as_str), index) {
        (Some("content_block_delta"), Some(index)) => {
            let field = match json.pointer("/delta/type").and_then(Value::as_str) {
                Some("text_delta") => Some(("text", TextKind::Text)),
                Some("input_json_delta") => Some(("partial_json", TextKind::Other)),
                Some("thinking_delta") => Some(("thinking", TextKind::Other)),
                _ => None,
            };
            field
                .map(|(field, kind)| (format!("/delta/{field}"), Block::Content(index), kind))
                .into_iter()
                .collect()
        }
        (Some("content_block_stop"), Some(index)) => {
            ends.push(index);
            Vec::new()
        }
        (Some("message_stop"), _) => {
            *done = true;
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Every string in a response body, with response controls marked on the text shown to the
/// user.
pub fn response_texts(format: ApiFormat, body: &Value) -> Vec<ResponseText> {
    strings(body)
        .into_iter()
        .map(|(pointer, text)| {
            let shown = match format {
                ApiFormat::OpenAiChat => is_choice_content(&pointer),
                ApiFormat::AnthropicMessages => {
                    pointer.ends_with("/text")
                        && pointer.starts_with("/content/")
                        && pointer.matches('/').count() == 3
                        && body
                            .pointer(pointer.trim_end_matches("/text"))
                            .and_then(|block| block.get("type"))
                            .and_then(Value::as_str)
                            == Some("text")
                }
            };
            ResponseText {
                pointer,
                block: None,
                kind: if shown {
                    TextKind::Text
                } else {
                    TextKind::Other
                },
                text,
            }
        })
        .collect()
}

/// `/choices/<n>/message/content`.
fn is_choice_content(pointer: &str) -> bool {
    let parts: Vec<&str> = pointer.split('/').collect();
    matches!(parts.as_slice(), ["", "choices", n, "message", "content"] if n.parse::<u64>().is_ok())
}

/// The event with each pointer set to its new text, written in compact JSON.
pub fn rewrite_event(
    event: &StreamEvent,
    changes: &[(String, String)],
) -> Result<Vec<u8>, StreamError> {
    let mut json = event.json.clone().ok_or(StreamError::Rewrite)?;
    for (pointer, text) in changes {
        *json.pointer_mut(pointer).ok_or(StreamError::Rewrite)? = Value::String(text.clone());
    }
    write_event(event.sse.event.as_deref(), event.sse.id.as_deref(), &json)
}

/// A new text delta for `block`, built from an earlier event of that block, to release text
/// that was held when the block ends.
pub fn flush_event(
    format: ApiFormat,
    template: &StreamEvent,
    block: &Block,
    text: &str,
) -> Result<Vec<u8>, StreamError> {
    match (format, block) {
        (
            ApiFormat::OpenAiChat,
            Block::Choice {
                index,
                part: ChoicePart::Content,
            },
        ) => {
            let mut json = template.json.clone().ok_or(StreamError::Rewrite)?;
            let object = json.as_object_mut().ok_or(StreamError::Rewrite)?;
            object.remove("usage");
            object.insert(
                "choices".to_owned(),
                json!([{"index": index, "delta": {"content": text}, "finish_reason": null}]),
            );
            write_event(None, None, &json)
        }
        (ApiFormat::AnthropicMessages, Block::Content(index)) => write_event(
            Some("content_block_delta"),
            None,
            &json!({"type": "content_block_delta", "index": index,
                    "delta": {"type": "text_delta", "text": text}}),
        ),
        _ => Err(StreamError::Rewrite),
    }
}

fn write_event(
    event: Option<&str>,
    id: Option<&str>,
    json: &Value,
) -> Result<Vec<u8>, StreamError> {
    let data = serde_json::to_string(json).map_err(|_| StreamError::Rewrite)?;
    let mut out = String::with_capacity(data.len() + 64);
    if let Some(event) = event {
        out.push_str("event: ");
        out.push_str(event);
        out.push('\n');
    }
    if let Some(id) = id {
        out.push_str("id: ");
        out.push_str(id);
        out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(&data);
    out.push_str("\n\n");
    Ok(out.into_bytes())
}

/// Every string under `value` with its JSON Pointer. Depth is bounded by the strict parser.
fn strings(value: &Value) -> Vec<(String, String)> {
    fn walk(value: &Value, pointer: &mut String, out: &mut Vec<(String, String)>) {
        match value {
            Value::String(text) => out.push((pointer.clone(), text.clone())),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    with_segment(pointer, &index.to_string(), |p| walk(item, p, out));
                }
            }
            Value::Object(object) => {
                for (key, item) in object {
                    with_segment(pointer, key, |p| walk(item, p, out));
                }
            }
            Value::Number(_) | Value::Bool(_) | Value::Null => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut String::new(), &mut out);
    out
}
