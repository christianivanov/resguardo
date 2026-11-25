//! The mock behaves like the providers' formats and records exactly what it receives.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;

use resguardo_mock_upstream::MockUpstream;
use serde_json::Value;

async fn start() -> MockUpstream {
    MockUpstream::start(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("mock starts")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn post(mock: &MockUpstream, path: &str, body: &str) -> reqwest::Response {
    client()
        .post(format!("{}{path}", mock.base_url()))
        .header("content-type", "application/json")
        .header("authorization", "Bearer sk-test-not-real")
        .header("anthropic-beta", "some-beta-2026-01-01")
        .body(body.to_owned())
        .send()
        .await
        .unwrap()
}

/// Data lines of an SSE body, without the `data: ` prefix.
fn sse_data(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn openai_non_streaming_echoes_and_records_the_exact_body() {
    let mock = start().await;
    let body = r#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hola"}],"extra":{"kept":true}}"#;
    let response = post(&mock, "/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-request-id"], "req_mock_1");
    let json: Value = response.json_value().await;
    assert_eq!(json["choices"][0]["message"]["content"], "echo: hola");

    let recorded = mock.requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].body, body.as_bytes());
    assert_eq!(
        recorded[0].header("authorization"),
        Some("Bearer sk-test-not-real")
    );
}

#[tokio::test]
async fn openai_streaming_sends_chunks_and_done() {
    let mock = start().await;
    let body = r#"{"model":"m","stream":true,"messages":[{"role":"user","content":"MOCK_REPLY: one two three four"}]}"#;
    let response = post(&mock, "/v1/chat/completions", body).await;
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let text = response.text().await.unwrap();
    let data = sse_data(&text);
    assert_eq!(data.last().map(String::as_str), Some("[DONE]"));
    let content: String = data
        .iter()
        .filter(|d| *d != "[DONE]")
        .map(|d| serde_json::from_str::<Value>(d).unwrap())
        .filter_map(|v| {
            v["choices"][0]["delta"]["content"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(content, "one two three four");
}

#[tokio::test]
async fn anthropic_streaming_sends_the_full_event_sequence() {
    let mock = start().await;
    let body = r#"{"model":"claude-sonnet-4-5","max_tokens":10,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"#;
    let response = post(&mock, "/v1/messages?beta=true", body).await;
    assert_eq!(
        response.headers()["anthropic-ratelimit-unified-status"],
        "allowed"
    );
    let text = response.text().await.unwrap();
    let events: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("event: "))
        .collect();
    assert_eq!(events.first(), Some(&"message_start"));
    assert!(events.contains(&"ping"));
    assert_eq!(
        &events[events.len() - 2..],
        ["message_delta", "message_stop"]
    );

    let recorded = &mock.requests()[0];
    assert_eq!(recorded.path, "/v1/messages");
    assert_eq!(recorded.query.as_deref(), Some("beta=true"));
    assert_eq!(
        recorded.header("anthropic-beta"),
        Some("some-beta-2026-01-01")
    );
}

#[tokio::test]
async fn anthropic_non_streaming_returns_a_message() {
    let mock = start().await;
    let body = r#"{"model":"claude-sonnet-4-5","max_tokens":10,"messages":[{"role":"user","content":"hola"}]}"#;
    let json: Value = post(&mock, "/v1/messages", body).await.json_value().await;
    assert_eq!(json["type"], "message");
    assert_eq!(json["content"][0]["text"], "echo: hola");
}

#[tokio::test]
async fn special_models_redirect_fail_and_truncate() {
    let mock = start().await;
    let redirect = post(
        &mock,
        "/v1/chat/completions",
        r#"{"model":"mock-redirect"}"#,
    )
    .await;
    assert_eq!(redirect.status(), 302);
    assert!(redirect.headers().contains_key("location"));

    let error = post(&mock, "/v1/messages", r#"{"model":"mock-error"}"#).await;
    assert_eq!(error.status(), 500);
    let json: Value = error.json_value().await;
    assert_eq!(json["type"], "error");

    let body = r#"{"model":"mock-truncate","stream":true,"messages":[{"role":"user","content":"a long enough message"}]}"#;
    let text = post(&mock, "/v1/messages", body)
        .await
        .text()
        .await
        .unwrap();
    assert!(text.contains("content_block_delta"));
    assert!(!text.contains("message_stop"));
}

#[tokio::test]
async fn invalid_json_and_unknown_routes_are_rejected_but_recorded() {
    let mock = start().await;
    assert_eq!(
        post(&mock, "/v1/chat/completions", "not json")
            .await
            .status(),
        400
    );
    assert_eq!(post(&mock, "/v1/embeddings", "{}").await.status(), 404);
    let paths: Vec<String> = mock.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(paths, ["/v1/chat/completions", "/v1/embeddings"]);
    mock.clear();
    assert!(mock.requests().is_empty());
}

/// `reqwest` is built without its `json` feature here, so parse by hand.
trait JsonValue {
    async fn json_value(self) -> Value;
}

impl JsonValue for reqwest::Response {
    async fn json_value(self) -> Value {
        serde_json::from_slice(&self.bytes().await.unwrap()).unwrap()
    }
}
