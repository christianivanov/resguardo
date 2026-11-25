//! Fake OpenAI and Anthropic upstream for Resguardo's tests and lab.
//!
//! It never calls a real API. It records every request it receives (method, path, query,
//! headers and raw body bytes) so tests can assert what Resguardo actually sent.
//!
//! Behaviour is chosen by the request:
//! - By default the reply is `echo: <last user text>`.
//! - If the last user text contains `MOCK_REPLY:`, the reply is everything after it. Tests use
//!   this to make the "model" say something specific (for example a Markdown image).
//! - Model `mock-redirect` answers `302`; `mock-error` answers `500` with a provider error body;
//!   `mock-truncate` cuts a stream after the first text chunk, without the closing events.
//! - With `"stream": true` the reply is sent as SSE in chunks of [`CHUNK_CHARS`] characters,
//!   using each provider's event format (Anthropic includes a `ping`).
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Characters per streamed text chunk.
pub const CHUNK_CHARS: usize = 8;

/// Marker in the last user message that sets the reply text.
pub const REPLY_MARKER: &str = "MOCK_REPLY:";

/// A request as the mock received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Lowercase names, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// First value of a header, by lowercase name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<RecordedRequest>>>);

impl Recorder {
    /// A poisoned lock only means another test thread panicked; the data is still usable.
    fn lock(&self) -> MutexGuard<'_, Vec<RecordedRequest>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the request and returns its 1-based sequence number.
    fn record(&self, method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> usize {
        let mut requests = self.lock();
        requests.push(RecordedRequest {
            method: method.to_string(),
            path: uri.path().to_owned(),
            query: uri.query().map(str::to_owned),
            headers: headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body: body.to_vec(),
        });
        requests.len()
    }
}

/// A running mock server, stopped when dropped.
pub struct MockUpstream {
    addr: SocketAddr,
    recorder: Recorder,
    task: JoinHandle<()>,
}

impl MockUpstream {
    /// Starts the server. Use port 0 to get a free port.
    pub async fn start(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let recorder = Recorder::default();
        let app = router(recorder.clone());
        let task = tokio::spawn(async move {
            // The task ends when aborted on drop; a serve error just stops the mock.
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            addr,
            recorder,
            task,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// For example `http://127.0.0.1:53412`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request received so far, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.recorder.lock().clone()
    }

    pub fn clear(&self) {
        self.recorder.lock().clear();
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves until the listener fails. Used by the `mock-upstream` binary.
pub async fn serve(listener: TcpListener) -> std::io::Result<()> {
    axum::serve(listener, router(Recorder::default())).await
}

fn router(recorder: Recorder) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(openai))
        .route("/v1/messages", post(anthropic))
        .route(
            "/__mock/requests",
            get(list_requests).delete(clear_requests),
        )
        .fallback(not_found)
        .with_state(recorder)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Api {
    OpenAi,
    Anthropic,
}

async fn openai(
    State(recorder): State<Recorder>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = recorder.record(&method, &uri, &headers, &body);
    respond(Api::OpenAi, seq, &body)
}

async fn anthropic(
    State(recorder): State<Recorder>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = recorder.record(&method, &uri, &headers, &body);
    respond(Api::Anthropic, seq, &body)
}

async fn not_found(
    State(recorder): State<Recorder>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    recorder.record(&method, &uri, &headers, &body);
    StatusCode::NOT_FOUND.into_response()
}

async fn list_requests(State(recorder): State<Recorder>) -> Response {
    let requests: Vec<Value> = recorder
        .lock()
        .iter()
        .map(|r| {
            json!({
                "method": r.method,
                "path": r.path,
                "query": r.query,
                "headers": r.headers,
                "body": String::from_utf8_lossy(&r.body),
            })
        })
        .collect();
    json_response(StatusCode::OK, &Value::Array(requests))
}

async fn clear_requests(State(recorder): State<Recorder>) -> StatusCode {
    recorder.lock().clear();
    StatusCode::NO_CONTENT
}

fn respond(api: Api, seq: usize, body: &[u8]) -> Response {
    let request: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return provider_error(
                api,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "body is not valid JSON",
            );
        }
    };
    let model = request["model"].as_str().unwrap_or_default().to_owned();
    let stream = request["stream"].as_bool().unwrap_or(false);

    match model.as_str() {
        "mock-redirect" => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_static("http://127.0.0.1:9/redirected"),
            );
            return response;
        }
        "mock-error" => {
            return provider_error(
                api,
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "mock upstream error",
            );
        }
        _ => {}
    }

    let reply = reply_text(&last_user_text(&request));
    let truncate = model == "mock-truncate";
    let mut response = match (api, stream) {
        (Api::OpenAi, false) => json_response(StatusCode::OK, &openai_message(seq, &model, &reply)),
        (Api::Anthropic, false) => {
            json_response(StatusCode::OK, &anthropic_message(seq, &model, &reply))
        }
        (Api::OpenAi, true) => sse_response(openai_events(seq, &model, &reply, truncate)),
        (Api::Anthropic, true) => sse_response(anthropic_events(seq, &model, &reply, truncate)),
    };
    add_provider_headers(api, seq, response.headers_mut());
    response
}

/// Headers real providers send, so tests can check Resguardo forwards them.
fn add_provider_headers(api: Api, seq: usize, headers: &mut HeaderMap) {
    let pairs: &[(&'static str, String)] = match api {
        Api::OpenAi => &[("x-request-id", format!("req_mock_{seq}"))],
        Api::Anthropic => &[
            ("request-id", format!("req_mock_{seq}")),
            ("anthropic-ratelimit-unified-status", "allowed".to_owned()),
        ],
    };
    for (name, value) in pairs {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(*name, value);
        }
    }
}

/// Text of the last `user` message: a plain string, or the concatenated `text` parts.
fn last_user_text(request: &Value) -> String {
    let Some(messages) = request["messages"].as_array() else {
        return String::new();
    };
    let Some(last) = messages.iter().rev().find(|m| m["role"] == "user") else {
        return String::new();
    };
    match &last["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter(|p| p["type"] == "text")
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn reply_text(user_text: &str) -> String {
    match user_text.find(REPLY_MARKER) {
        Some(at) => user_text[at + REPLY_MARKER.len()..].trim_start().to_owned(),
        None => format!("echo: {user_text}"),
    }
}

/// Splits text into chunks of `CHUNK_CHARS` characters, never inside a UTF-8 character.
fn chunks(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(CHUNK_CHARS)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn openai_message(seq: usize, model: &str, reply: &str) -> Value {
    json!({
        "id": format!("chatcmpl-mock-{seq}"),
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": reply},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    })
}

fn openai_events(seq: usize, model: &str, reply: &str, truncate: bool) -> Vec<Bytes> {
    let chunk = |delta: Value, finish: Value| {
        let data = json!({
            "id": format!("chatcmpl-mock-{seq}"),
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        });
        Bytes::from(format!("data: {data}\n\n"))
    };
    let mut events = vec![chunk(
        json!({"role": "assistant", "content": ""}),
        Value::Null,
    )];
    for piece in chunks(reply) {
        events.push(chunk(json!({"content": piece}), Value::Null));
        if truncate {
            return events;
        }
    }
    events.push(chunk(json!({}), json!("stop")));
    events.push(Bytes::from_static(b"data: [DONE]\n\n"));
    events
}

fn anthropic_message(seq: usize, model: &str, reply: &str) -> Value {
    json!({
        "id": format!("msg_mock_{seq}"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": reply}],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 0, "output_tokens": 0}
    })
}

fn anthropic_events(seq: usize, model: &str, reply: &str, truncate: bool) -> Vec<Bytes> {
    let event = |name: &str, data: Value| Bytes::from(format!("event: {name}\ndata: {data}\n\n"));
    let mut start = anthropic_message(seq, model, "");
    start["content"] = json!([]);
    start["stop_reason"] = Value::Null;

    let mut events = vec![
        event(
            "message_start",
            json!({"type": "message_start", "message": start}),
        ),
        event(
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
                   "content_block": {"type": "text", "text": ""}}),
        ),
        event("ping", json!({"type": "ping"})),
    ];
    for piece in chunks(reply) {
        events.push(event(
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
                   "delta": {"type": "text_delta", "text": piece}}),
        ));
        if truncate {
            return events;
        }
    }
    events.push(event(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ));
    events.push(event(
        "message_delta",
        json!({"type": "message_delta",
               "delta": {"stop_reason": "end_turn", "stop_sequence": null},
               "usage": {"output_tokens": 0}}),
    ));
    events.push(event("message_stop", json!({"type": "message_stop"})));
    events
}

fn provider_error(api: Api, status: StatusCode, kind: &str, message: &str) -> Response {
    let body = match api {
        Api::OpenAi => json!({"error": {"message": message, "type": kind, "code": null}}),
        Api::Anthropic => json!({"type": "error", "error": {"type": kind, "message": message}}),
    };
    json_response(status, &body)
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Each event is a separate body frame, so the client sees realistic chunk boundaries.
fn sse_response(events: Vec<Bytes>) -> Response {
    let stream = futures_util::stream::iter(events.into_iter().map(Ok::<_, Infallible>));
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_marker_sets_the_reply() {
        assert_eq!(reply_text("hola"), "echo: hola");
        assert_eq!(
            reply_text("ignore this MOCK_REPLY: ![x](https://attacker.test/p)"),
            "![x](https://attacker.test/p)"
        );
    }

    #[test]
    fn chunks_never_split_a_character() {
        let text = "ñandú€ y más texto";
        let parts = chunks(text);
        assert_eq!(parts.concat(), text);
        assert!(parts.iter().all(|p| p.chars().count() <= CHUNK_CHARS));
    }

    #[test]
    fn last_user_text_reads_strings_and_text_blocks() {
        let openai = json!({"messages": [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "x"},
            {"role": "user", "content": "second"}
        ]});
        assert_eq!(last_user_text(&openai), "second");
        let anthropic = json!({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "a"},
            {"type": "image", "source": {}},
            {"type": "text", "text": "b"}
        ]}]});
        assert_eq!(last_user_text(&anthropic), "a\nb");
    }
}
