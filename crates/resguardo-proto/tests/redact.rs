//! Redaction (Annex F.6, ADR 0013): only the strings that hold a redacted value change, and
//! the rest of the body keeps its exact bytes.
// Test helpers may panic: an invalid fixture is a test failure.
#![allow(clippy::unwrap_used)]

use resguardo_core::{DataClass, Finding};
use resguardo_proto::{ApiFormat, ParsedRequest, RedactError, parse_request, redact};

fn parse(body: &str) -> ParsedRequest {
    parse_request(ApiFormat::AnthropicMessages, body.as_bytes()).unwrap()
}

/// A finding over the first occurrence of `value` in the text at `pointer`.
fn finding(parsed: &ParsedRequest, pointer: &str, class: DataClass, value: &str) -> Finding {
    let text = &parsed
        .texts
        .iter()
        .find(|t| t.pointer == pointer)
        .unwrap_or_else(|| panic!("no text at {pointer}"))
        .text;
    let start = text.find(value).unwrap();
    Finding {
        class,
        pointer: pointer.to_owned(),
        span: start..start + value.len(),
        rule: format!("{class}.test"),
        confidence: 90,
        via: Vec::new(),
    }
}

fn redacted(body: &str, spans: &[Finding]) -> String {
    let parsed = parse(body);
    String::from_utf8(redact(body.as_bytes(), &parsed, spans).unwrap()).unwrap()
}

const CONTENT: &str = "/messages/0/content";

#[test]
fn g3_a_dni_becomes_a_numbered_placeholder() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"Mi DNI es 12345678Z"}]}"#;
    let parsed = parse(body);
    let dni = finding(&parsed, CONTENT, DataClass::EsId, "12345678Z");
    assert_eq!(
        redacted(body, &[dni]),
        r#"{"model":"m","messages":[{"role":"user","content":"Mi DNI es [REDACTED:es_id:1]"}]}"#
    );
}

#[test]
fn g3_two_different_dnis_get_two_numbers() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"12345678Z y 87654321X"}]}"#;
    let parsed = parse(body);
    let spans = [
        finding(&parsed, CONTENT, DataClass::EsId, "12345678Z"),
        finding(&parsed, CONTENT, DataClass::EsId, "87654321X"),
    ];
    assert!(redacted(body, &spans).contains("[REDACTED:es_id:1] y [REDACTED:es_id:2]"));
}

#[test]
fn everything_outside_the_redacted_string_keeps_its_bytes() {
    // Key order, whitespace, escapes and number formats that serializing again would change.
    let body = "{ \"messages\" : [ {\"role\":\"user\", \"content\":\"Mi DNI es 12345678Z\"} ],\n  \
                \"model\": \"m\", \"max_tokens\": 1.0e3, \"metadata\": {\"note\": \"caf\\u00e9 \\/\"} }";
    let parsed = parse(body);
    let dni = finding(&parsed, CONTENT, DataClass::EsId, "12345678Z");
    let expected = body.replace("12345678Z", "[REDACTED:es_id:1]");
    assert_eq!(redacted(body, &[dni]), expected);
}

#[test]
fn a_redacted_string_with_escapes_is_encoded_again() {
    // The span is in the decoded text: "é\n" comes before the id.
    let body =
        r#"{"model":"m","messages":[{"role":"user","content":"caf\u00e9\nDNI 12345678Z \"ok\""}]}"#;
    let parsed = parse(body);
    let dni = finding(&parsed, CONTENT, DataClass::EsId, "12345678Z");
    let out = redacted(body, &[dni]);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        value["messages"][0]["content"],
        "café\nDNI [REDACTED:es_id:1] \"ok\""
    );
}

#[test]
fn the_same_value_gets_the_same_number_in_every_turn() {
    let body = r#"{"model":"m","messages":[
        {"role":"user","content":"soy 12345678Z"},
        {"role":"assistant","content":"vale"},
        {"role":"user","content":"otra vez 87654321X y 12345678Z"}]}"#;
    let parsed = parse(body);
    let spans = [
        finding(&parsed, "/messages/0/content", DataClass::EsId, "12345678Z"),
        finding(&parsed, "/messages/2/content", DataClass::EsId, "87654321X"),
        finding(&parsed, "/messages/2/content", DataClass::EsId, "12345678Z"),
    ];
    let out = redacted(body, &spans);
    assert!(out.contains("soy [REDACTED:es_id:1]"), "{out}");
    assert!(
        out.contains("otra vez [REDACTED:es_id:2] y [REDACTED:es_id:1]"),
        "{out}"
    );
}

#[test]
fn texts_outside_messages_are_numbered_first_wherever_they_are() {
    // `system` comes after `messages` in the bytes, but is numbered first (ADR 0013).
    let body = r#"{"model":"m","messages":[{"role":"user","content":"b@example.es"}],"system":"a@example.es"}"#;
    let parsed = parse(body);
    let spans = [
        finding(&parsed, CONTENT, DataClass::Email, "b@example.es"),
        finding(&parsed, "/system", DataClass::Email, "a@example.es"),
    ];
    let out = redacted(body, &spans);
    assert!(out.contains(r#""system":"[REDACTED:email:1]""#), "{out}");
    assert!(out.contains(r#""content":"[REDACTED:email:2]""#), "{out}");
}

#[test]
fn numbers_are_counted_per_class() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"12345678Z a@example.es 87654321X"}]}"#;
    let parsed = parse(body);
    let spans = [
        finding(&parsed, CONTENT, DataClass::EsId, "12345678Z"),
        finding(&parsed, CONTENT, DataClass::Email, "a@example.es"),
        finding(&parsed, CONTENT, DataClass::EsId, "87654321X"),
    ];
    assert!(
        redacted(body, &spans).contains("[REDACTED:es_id:1] [REDACTED:email:1] [REDACTED:es_id:2]")
    );
}

#[test]
fn overlapping_spans_merge_under_the_class_of_the_longest() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"escribe a 12345678Z@example.es ya"}]}"#;
    let parsed = parse(body);
    let spans = [
        finding(&parsed, CONTENT, DataClass::EsId, "12345678Z"),
        finding(&parsed, CONTENT, DataClass::Email, "12345678Z@example.es"),
    ];
    assert!(redacted(body, &spans).contains("escribe a [REDACTED:email:1] ya"));
}

#[test]
fn invisible_text_is_removed_without_a_placeholder() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"hola\u200Bmundo"}]}"#;
    let parsed = parse(body);
    let invisible = finding(&parsed, CONTENT, DataClass::InvisibleText, "\u{200B}");
    let out = redacted(body, &[invisible]);
    assert!(out.contains(r#""content":"holamundo""#), "{out}");
}

#[test]
fn invisible_text_inside_a_decoded_fragment_gets_a_placeholder() {
    // Base64 of "hola" U+200B "mundo". The span of a decoded finding is the whole encoded
    // fragment (ADR 0008).
    let body = r#"{"model":"m","messages":[{"role":"user","content":"x aG9sYeKAi211bmRv y"}]}"#;
    let parsed = parse(body);
    let mut invisible = finding(
        &parsed,
        CONTENT,
        DataClass::InvisibleText,
        "aG9sYeKAi211bmRv",
    );
    invisible.via = vec!["base64".to_owned()];
    let out = redacted(body, &[invisible]);
    assert!(out.contains("x [REDACTED:invisible_text:1] y"), "{out}");
}

#[test]
fn texts_in_nested_fields_and_escaped_keys_are_found() {
    let body = r#"{"model":"m","messages":[],"tools":[{"name":"t","description":"llama al 612345678"}],"metadata":{"a/b":"12345678Z"}}"#;
    let parsed = parse(body);
    let spans = [
        finding(
            &parsed,
            "/tools/0/description",
            DataClass::Phone,
            "612345678",
        ),
        finding(&parsed, "/metadata/a~1b", DataClass::EsId, "12345678Z"),
    ];
    let out = redacted(body, &spans);
    assert!(
        out.contains(r#""description":"llama al [REDACTED:phone:1]""#),
        "{out}"
    );
    assert!(out.contains(r#""a/b":"[REDACTED:es_id:1]""#), "{out}");
}

#[test]
fn without_spans_the_body_is_returned_unchanged() {
    let body = r#"{ "model": "m", "messages": [] }"#;
    assert_eq!(redacted(body, &[]), body);
}

#[test]
fn spans_that_do_not_fit_their_text_are_errors() {
    let body = r#"{"model":"m","messages":[{"role":"user","content":"señal"}]}"#;
    let parsed = parse(body);
    let base = finding(&parsed, CONTENT, DataClass::EsId, "señal");

    let mut outside = base.clone();
    outside.span = 0..99;
    assert_eq!(
        redact(body.as_bytes(), &parsed, &[outside]),
        Err(RedactError::Span)
    );

    // Byte 3 is inside the two bytes of 'ñ'.
    let mut split = base.clone();
    split.span = 0..3;
    assert_eq!(
        redact(body.as_bytes(), &parsed, &[split]),
        Err(RedactError::Span)
    );

    let mut unknown = base;
    unknown.pointer = "/messages/9/content".to_owned();
    assert_eq!(
        redact(body.as_bytes(), &parsed, &[unknown]),
        Err(RedactError::Span)
    );
}
