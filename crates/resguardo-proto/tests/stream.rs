//! What each provider's stream events and responses carry (ADR 0014): the texts to scan with
//! their pointer, block and kind, where blocks end, and how a changed event is written.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use resguardo_proto::{
    ApiFormat, Block, ChoicePart, SseParser, StreamEvent, TextKind, analyze_event, flush_event,
    response_texts, rewrite_event,
};
use serde_json::{Value, json};

fn event(format: ApiFormat, raw: &str) -> StreamEvent {
    let mut parser = SseParser::new(1 << 20);
    let mut events = parser.push(raw.as_bytes()).unwrap();
    assert_eq!(events.len(), 1, "{raw}");
    analyze_event(format, events.remove(0)).unwrap()
}

/// (pointer, block, kind, text) of the texts that belong to a block.
fn block_texts(event: &StreamEvent) -> Vec<(&str, Block, TextKind, &str)> {
    event
        .texts
        .iter()
        .filter_map(|t| {
            t.block
                .clone()
                .map(|b| (t.pointer.as_str(), b, t.kind, t.text.as_str()))
        })
        .collect()
}

fn openai_chunk(choice: Value) -> String {
    let data =
        json!({"id": "c1", "object": "chat.completion.chunk", "model": "m", "choices": [choice]});
    format!("data: {data}\n\n")
}

#[test]
fn openai_content_refusal_and_tool_arguments_are_block_texts() {
    let raw = openai_chunk(json!({"index": 2, "delta": {
        "content": "hola",
        "refusal": "no",
        "tool_calls": [{"index": 1, "function": {"arguments": "{\"a\":"}}]
    }, "finish_reason": null}));
    let e = event(ApiFormat::OpenAiChat, &raw);
    let choice = |part| Block::Choice { index: 2, part };
    let mut texts = block_texts(&e);
    texts.sort_by_key(|t| t.0.to_owned());
    assert_eq!(
        texts,
        vec![
            (
                "/choices/0/delta/content",
                choice(ChoicePart::Content),
                TextKind::Text,
                "hola"
            ),
            (
                "/choices/0/delta/refusal",
                choice(ChoicePart::Refusal),
                TextKind::Other,
                "no"
            ),
            (
                "/choices/0/delta/tool_calls/0/function/arguments",
                choice(ChoicePart::Tool(1)),
                TextKind::Other,
                "{\"a\":"
            ),
        ]
    );
    // Other strings (id, model...) are scanned on their own, without a block.
    assert!(e.texts.iter().any(|t| t.block.is_none() && t.text == "c1"));
    assert!(e.ends.is_empty() && !e.done);
}

#[test]
fn openai_finish_reason_ends_the_blocks_of_that_choice() {
    let raw = openai_chunk(json!({"index": 0, "delta": {}, "finish_reason": "stop"}));
    let e = event(ApiFormat::OpenAiChat, &raw);
    assert_eq!(e.ends, vec![0]);
    let done = event(ApiFormat::OpenAiChat, "data: [DONE]\n\n");
    assert!(done.done && done.texts.is_empty());
}

#[test]
fn anthropic_text_json_and_thinking_deltas_are_block_texts() {
    let delta = |kind: &str, field: &str| {
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            json!({"type": "content_block_delta", "index": 3, "delta": {"type": kind, field: "x"}})
        )
    };
    for (kind, field, text_kind) in [
        ("text_delta", "text", TextKind::Text),
        ("input_json_delta", "partial_json", TextKind::Other),
        ("thinking_delta", "thinking", TextKind::Other),
    ] {
        let e = event(ApiFormat::AnthropicMessages, &delta(kind, field));
        assert_eq!(
            block_texts(&e),
            vec![(
                &*format!("/delta/{field}"),
                Block::Content(3),
                text_kind,
                "x"
            )],
            "{kind}"
        );
    }
}

#[test]
fn anthropic_block_stop_and_message_stop() {
    let stop = event(
        ApiFormat::AnthropicMessages,
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":4}\n\n",
    );
    assert_eq!(stop.ends, vec![4]);
    let done = event(
        ApiFormat::AnthropicMessages,
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    assert!(done.done);
}

#[test]
fn events_without_data_have_no_texts() {
    let e = event(ApiFormat::AnthropicMessages, ": keep-alive\n\n");
    assert!(e.texts.is_empty() && e.json.is_none() && !e.done);
}

#[test]
fn data_that_is_not_json_is_an_error() {
    let mut parser = SseParser::new(1 << 20);
    let sse = parser.push(b"data: {not json\n\n").unwrap().remove(0);
    assert!(analyze_event(ApiFormat::OpenAiChat, sse).is_err());
}

#[test]
fn a_rewritten_event_keeps_its_name_and_id_and_changes_only_the_pointer() {
    let raw = "event: content_block_delta\nid: 9\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"![x](https://a.test/)\"}}\n\n";
    let e = event(ApiFormat::AnthropicMessages, raw);
    let bytes = rewrite_event(
        &e,
        &[("/delta/text".to_owned(), "[image removed]".to_owned())],
    )
    .unwrap();
    let again = event(
        ApiFormat::AnthropicMessages,
        std::str::from_utf8(&bytes).unwrap(),
    );
    assert_eq!(again.sse.event.as_deref(), Some("content_block_delta"));
    assert_eq!(again.sse.id.as_deref(), Some("9"));
    assert_eq!(again.json.unwrap()["delta"]["text"], "[image removed]");
}

#[test]
fn flush_events_carry_held_text_in_each_format() {
    let template = event(
        ApiFormat::OpenAiChat,
        &openai_chunk(json!({"index": 1, "delta": {"content": "a"}, "finish_reason": null})),
    );
    let bytes = flush_event(
        ApiFormat::OpenAiChat,
        &template,
        &Block::Choice {
            index: 1,
            part: ChoicePart::Content,
        },
        "held",
    )
    .unwrap();
    let e = event(ApiFormat::OpenAiChat, std::str::from_utf8(&bytes).unwrap());
    let json = e.json.unwrap();
    assert_eq!(json["id"], "c1");
    assert_eq!(json["choices"][0]["index"], 1);
    assert_eq!(json["choices"][0]["delta"]["content"], "held");

    let template = event(
        ApiFormat::AnthropicMessages,
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"text_delta\",\"text\":\"a\"}}\n\n",
    );
    let bytes = flush_event(
        ApiFormat::AnthropicMessages,
        &template,
        &Block::Content(2),
        "held",
    )
    .unwrap();
    let e = event(
        ApiFormat::AnthropicMessages,
        std::str::from_utf8(&bytes).unwrap(),
    );
    assert_eq!(e.sse.event.as_deref(), Some("content_block_delta"));
    assert_eq!(
        e.json.unwrap(),
        json!({"type": "content_block_delta", "index": 2, "delta": {"type": "text_delta", "text": "held"}})
    );
}

#[test]
fn response_texts_mark_what_response_controls_apply_to() {
    let openai = json!({"choices": [{"index": 0, "message": {
        "role": "assistant", "content": "hola",
        "tool_calls": [{"function": {"name": "f", "arguments": "{}"}}]}}]});
    let texts = response_texts(ApiFormat::OpenAiChat, &openai);
    let text_kind: Vec<_> = texts
        .iter()
        .filter(|t| t.kind == TextKind::Text)
        .map(|t| t.pointer.as_str())
        .collect();
    assert_eq!(text_kind, vec!["/choices/0/message/content"]);
    assert!(
        texts.iter().any(|t| t.text == "{}"),
        "every string is scanned"
    );

    let anthropic = json!({"content": [
        {"type": "thinking", "thinking": "hmm", "signature": "sig"},
        {"type": "text", "text": "hola"},
        {"type": "tool_use", "name": "f", "input": {"q": "x"}}]});
    let texts = response_texts(ApiFormat::AnthropicMessages, &anthropic);
    let text_kind: Vec<_> = texts
        .iter()
        .filter(|t| t.kind == TextKind::Text)
        .map(|t| t.pointer.as_str())
        .collect();
    assert_eq!(text_kind, vec!["/content/1/text"]);
    assert!(
        texts
            .iter()
            .any(|t| t.text == "x" && t.pointer == "/content/2/input/q")
    );
}
