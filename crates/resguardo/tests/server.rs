//! Resguardo in front of the mock upstream: the G.3 cases that do not need scanning, and the
//! request checks around them. Rows of Annex G.3 are marked `G.3`.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use resguardo::server::{App, serve};
use resguardo_core::{Config, VirtualKey};
use resguardo_mock_upstream::MockUpstream;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const OPENAI_KEY: &str = "sk-test-openai-not-real";
const ANTHROPIC_KEY: &str = "sk-ant-test-not-real";

struct Keys {
    bot: String,
    old: String,
    slow: String,
    small: String,
    careful: String,
}

struct Harness {
    mock: MockUpstream,
    url: String,
    keys: Keys,
    client: reqwest::Client,
    /// The audit log and the public key that verifies it.
    audit: PathBuf,
    public_key: PathBuf,
}

fn key(seed: u8) -> (String, String) {
    let key = VirtualKey::from_random_bytes(&[seed; 32]);
    (
        key.expose_secret().to_owned(),
        key.hash().as_str().to_owned(),
    )
}

fn credential_file(key: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "server-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("credential");
    std::fs::write(&path, key).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path.display().to_string()
}

async fn harness() -> Harness {
    let mock = MockUpstream::start(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let base = mock.base_url();
    let (bot, bot_hash) = key(1);
    let (old, old_hash) = key(2);
    let (slow, slow_hash) = key(3);
    let (small, small_hash) = key(4);
    let (careful, careful_hash) = key(5);
    let audit_dir = PathBuf::from(credential_file("unused"))
        .parent()
        .unwrap()
        .join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    let audit = audit_dir.join("audit.jsonl");
    let signing = audit_dir.join("signing.key");
    let public_key = audit_dir.join("signing.pub");
    resguardo_audit::SigningKey::create_files(&signing, &public_key).unwrap();
    let source = format!(
        r#"
[audit]
path = "{audit}"
signing_key = "{signing}"
public_key = "{public}"

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"

[response]
allowed_link_hosts = ["docs.example.com"]

[[upstream]]
provider = "openai"
base_url = "{base}"
credential_file = "{openai}"
allow_insecure_upstream = true

[[upstream]]
provider = "anthropic"
base_url = "{base}"
credential_file = "{anthropic}"
allow_insecure_upstream = true

[[upstream]]
provider = "openai_compatible"
base_url = "{base}"
allow_insecure_upstream = true

[[principal]]
id = "bot"
key_sha256 = "{bot_hash}"
models.openai = ["gpt-4.1-mini", "mock-redirect", "mock-truncate"]
models.anthropic = ["claude-sonnet-5-5", "mock-error"]
models.openai_compatible = ["llama-3"]

[[principal]]
id = "old"
key_sha256 = "{old_hash}"
models.openai = ["gpt-4.1-mini"]
expires_at = "2020-01-01T00:00:00Z"

[[principal]]
id = "slow"
key_sha256 = "{slow_hash}"
models.openai = ["gpt-4.1-mini"]
requests_per_minute = 2

[[principal]]
id = "small"
key_sha256 = "{small_hash}"
models.openai = ["gpt-4.1-mini"]
max_body_bytes = 200
max_messages = 1

[[principal]]
id = "careful"
key_sha256 = "{careful_hash}"
models.openai = ["gpt-4.1-mini"]
models.anthropic = ["claude-sonnet-5-5"]
stream_mode = "buffer"
"#,
        openai = credential_file(OPENAI_KEY),
        anthropic = credential_file(ANTHROPIC_KEY),
        audit = audit.display(),
        signing = signing.display(),
        public = public_key.display(),
    );
    let config = Config::from_toml_str(&source).unwrap();
    let app = Arc::new(App::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, app, std::future::pending()));
    Harness {
        mock,
        url,
        keys: Keys {
            bot,
            old,
            slow,
            small,
            careful,
        },
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        audit,
        public_key,
    }
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// Resguardo's own error code, in either error shape.
    fn code(&self) -> String {
        let json = self.json();
        json["error"]["code"].as_str().unwrap().to_owned()
    }

    fn header(&self, name: &str) -> &str {
        self.headers[name].to_str().unwrap()
    }
}

impl Harness {
    async fn send(&self, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
        let mut request = self
            .client
            .post(format!("{}{path}", self.url))
            .body(body.to_owned());
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.unwrap();
        Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().await.unwrap().to_vec(),
        }
    }

    async fn openai(&self, key: &str, body: &str) -> Reply {
        let bearer = format!("Bearer {key}");
        self.send(
            "/v1/chat/completions",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            body,
        )
        .await
    }

    async fn anthropic(&self, key: &str, body: &str) -> Reply {
        self.send(
            "/v1/messages",
            &[
                ("x-api-key", key),
                ("content-type", "application/json"),
                ("anthropic-version", "2023-06-01"),
            ],
            body,
        )
        .await
    }
}

const CHAT: &str = r#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hola"}]}"#;
const MESSAGES: &str = r#"{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":"hola"}]}"#;

#[tokio::test]
async fn g3_request_without_findings_arrives_byte_for_byte() {
    let h = harness().await;
    // Odd spacing, key order, a non-ASCII character and a number written as 2.50: all kept.
    let body = r#"{ "messages" : [ {"content":"hola ñ","role":"user"} ],  "model":"gpt-4.1-mini" , "zz": [1, 2.50, true] }"#;
    let reply = h.openai(&h.keys.bot, body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["choices"][0]["message"]["content"],
        "echo: hola ñ"
    );
    assert_eq!(reply.header("x-resguardo-decision"), "allow");
    let request_id = reply.header("x-resguardo-request-id");
    assert_eq!(request_id.len(), 36);
    assert_eq!(&request_id[14..15], "7", "UUID v7");
    assert_eq!(
        reply.header("x-request-id"),
        "req_mock_1",
        "provider header kept"
    );

    let sent = &h.mock.requests()[0];
    assert_eq!(sent.body, body.as_bytes());
    assert_eq!(
        sent.header("authorization"),
        Some(&*format!("Bearer {OPENAI_KEY}"))
    );
}

#[tokio::test]
async fn anthropic_request_reaches_the_mock_with_its_own_credential() {
    let h = harness().await;
    let reply = h
        .send(
            "/v1/messages?beta=true",
            &[
                ("x-api-key", &h.keys.bot),
                ("content-type", "application/json"),
                ("anthropic-version", "2023-06-01"),
                ("anthropic-beta", "some-beta-2026-01-01"),
            ],
            MESSAGES,
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["content"][0]["text"], "echo: hola");
    let sent = &h.mock.requests()[0];
    assert_eq!(sent.query.as_deref(), Some("beta=true"));
    assert_eq!(sent.header("x-api-key"), Some(ANTHROPIC_KEY));
    assert_eq!(sent.header("anthropic-beta"), Some("some-beta-2026-01-01"));
    assert!(!format!("{:?}", sent.headers).contains(&h.keys.bot));
}

#[tokio::test]
async fn g3_unknown_key_is_401_in_each_api_error_shape() {
    let h = harness().await;
    let (stranger, _) = key(99);

    let openai = h.openai(&stranger, CHAT).await;
    assert_eq!(openai.status, 401);
    assert_eq!(openai.code(), "UNKNOWN_KEY");
    assert_eq!(openai.json()["error"]["type"], "resguardo_error");
    assert_eq!(openai.header("x-resguardo-decision"), "block");

    let anthropic = h.anthropic(&stranger, MESSAGES).await;
    assert_eq!(anthropic.status, 401);
    let json = anthropic.json();
    assert_eq!(json["type"], "error");
    assert_eq!(json["error"]["type"], "authentication_error");
    assert_eq!(json["error"]["code"], "UNKNOWN_KEY");
    assert!(json["request_id"].is_string());

    let missing = h
        .send(
            "/v1/chat/completions",
            &[("content-type", "application/json")],
            CHAT,
        )
        .await;
    assert_eq!(missing.status, 401);
    assert!(h.mock.requests().is_empty(), "nothing left");
}

#[tokio::test]
async fn expired_key_is_401_key_expired() {
    let h = harness().await;
    let reply = h.openai(&h.keys.old, CHAT).await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.code(), "KEY_EXPIRED");
}

#[tokio::test]
async fn g3_model_outside_the_list_is_403() {
    let h = harness().await;
    let other = CHAT.replace("gpt-4.1-mini", "gpt-5");
    let reply = h.openai(&h.keys.bot, &other).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.code(), "MODEL_NOT_ALLOWED");
    assert_eq!(reply.json()["error"]["type"], "resguardo_policy_violation");
    // An OpenAI model is not allowed through the Anthropic route either.
    let crossed = MESSAGES.replace("claude-sonnet-5-5", "gpt-4.1-mini");
    let reply = h.anthropic(&h.keys.bot, &crossed).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.json()["error"]["type"], "permission_error");
    assert!(h.mock.requests().is_empty());
}

#[tokio::test]
async fn g3_application_credentials_never_reach_the_provider() {
    let h = harness().await;
    // The virtual key goes in one header and a real-looking key in the other. Two different
    // credentials are ambiguous, so the request is refused and nothing leaves (stricter than
    // stripping the extra header: the application is sending a real key it should not have).
    let bearer = format!("Bearer {}", h.keys.bot);
    let reply = h
        .send(
            "/v1/messages",
            &[
                ("authorization", &bearer),
                ("x-api-key", "sk-ant-real-key-of-the-app"),
                ("content-type", "application/json"),
            ],
            MESSAGES,
        )
        .await;
    assert_eq!(reply.status, 401);
    assert!(h.mock.requests().is_empty());

    // The same virtual key in both headers is fine, and neither header is forwarded.
    let reply = h
        .send(
            "/v1/chat/completions",
            &[
                ("authorization", &bearer),
                ("x-api-key", &h.keys.bot),
                ("content-type", "application/json"),
                ("cookie", "session=1"),
            ],
            CHAT,
        )
        .await;
    assert_eq!(reply.status, 200);
    let sent = &h.mock.requests()[0];
    assert_eq!(
        sent.header("authorization"),
        Some(&*format!("Bearer {OPENAI_KEY}"))
    );
    assert_eq!(sent.header("x-api-key"), None);
    assert_eq!(sent.header("cookie"), None);
}

#[tokio::test]
async fn g3_provider_redirect_is_502_and_not_followed() {
    let h = harness().await;
    let body = CHAT.replace("gpt-4.1-mini", "mock-redirect");
    let reply = h.openai(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 502);
    assert_eq!(reply.code(), "UPSTREAM_REDIRECT");
    assert_eq!(h.mock.requests().len(), 1);
}

#[tokio::test]
async fn provider_errors_pass_through_unchanged() {
    let h = harness().await;
    let body = MESSAGES.replace("claude-sonnet-5-5", "mock-error");
    let reply = h.anthropic(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 500);
    assert_eq!(reply.json()["type"], "error");
    assert_eq!(reply.header("x-resguardo-decision"), "allow");
}

#[tokio::test]
async fn openai_compatible_is_chosen_by_model_and_gets_no_credential() {
    let h = harness().await;
    let body = CHAT.replace("gpt-4.1-mini", "llama-3");
    let reply = h.openai(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 200);
    let sent = &h.mock.requests()[0];
    assert_eq!(sent.header("authorization"), None);
}

#[tokio::test]
async fn unknown_routes_and_methods_are_404_without_contacting_the_provider() {
    let h = harness().await;
    let bearer = format!("Bearer {}", h.keys.bot);
    let headers = [
        ("authorization", bearer.as_str()),
        ("content-type", "application/json"),
    ];
    for path in [
        "/v1/embeddings",
        "/v1/messages/count_tokens",
        "/v1/messages/",
        "/V1/chat/completions",
        "/v1/%63hat/completions",
    ] {
        let reply = h.send(path, &headers, CHAT).await;
        assert_eq!(reply.status, 404, "{path}");
        assert_eq!(reply.code(), "NOT_FOUND", "{path}");
    }
    let get = h
        .client
        .get(format!("{}/v1/chat/completions", h.url))
        .header("authorization", &bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 404);
    assert!(h.mock.requests().is_empty());
}

#[tokio::test]
async fn malformed_requests_are_400_and_never_echo_content() {
    let h = harness().await;
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let duplicate = format!(
        r#"{{"model":"gpt-4.1-mini","messages":[{{"role":"user","content":"{secret}","content":"x"}}]}}"#
    );
    // `"stream": true` was refused here until M4; it is now served (ADR 0014).
    for body in [duplicate.as_str(), "not json"] {
        let reply = h.openai(&h.keys.bot, body).await;
        assert_eq!(reply.status, 400, "{body}");
        assert_eq!(reply.code(), "INVALID_REQUEST");
        assert!(!String::from_utf8_lossy(&reply.body).contains(secret));
    }
    let bearer = format!("Bearer {}", h.keys.bot);
    let query = h
        .send(
            &format!("/v1/chat/completions?leak={secret}"),
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
            ],
            CHAT,
        )
        .await;
    assert_eq!(query.status, 400);
    assert!(!String::from_utf8_lossy(&query.body).contains(secret));

    let gzip = h
        .send(
            "/v1/chat/completions",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
            CHAT,
        )
        .await;
    assert_eq!(gzip.status, 400);
    let text = h
        .send(
            "/v1/chat/completions",
            &[("authorization", &bearer), ("content-type", "text/plain")],
            CHAT,
        )
        .await;
    assert_eq!(text.status, 400);
    assert!(h.mock.requests().is_empty());
}

#[tokio::test]
async fn body_and_message_limits_are_413() {
    let h = harness().await;
    let long = CHAT.replace("hola", &"a".repeat(300));
    let reply = h.openai(&h.keys.small, &long).await;
    assert_eq!(reply.status, 413);
    assert_eq!(reply.code(), "BODY_TOO_LARGE");
    let two = r#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}"#;
    let reply = h.openai(&h.keys.small, two).await;
    assert_eq!(reply.status, 413);
    assert!(h.mock.requests().is_empty());
}

#[tokio::test]
async fn rate_limit_is_429_with_retry_after() {
    let h = harness().await;
    assert_eq!(h.openai(&h.keys.slow, CHAT).await.status, 200);
    assert_eq!(h.openai(&h.keys.slow, CHAT).await.status, 200);
    let reply = h.openai(&h.keys.slow, CHAT).await;
    assert_eq!(reply.status, 429);
    assert_eq!(reply.code(), "RATE_LIMITED");
    let retry: u64 = reply.header("retry-after").parse().unwrap();
    assert!((1..=30).contains(&retry), "{retry}");
    assert_eq!(h.mock.requests().len(), 2);
    // Other keys are not affected.
    assert_eq!(h.openai(&h.keys.bot, CHAT).await.status, 200);
}

#[tokio::test]
async fn healthz_answers_without_a_key() {
    let h = harness().await;
    let reply = h
        .client
        .get(format!("{}/healthz", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
}

#[test]
fn run_refuses_to_start_without_a_signing_key() {
    // The temporary guard against real providers is gone with M5; what replaces it is that
    // nothing runs without the key that signs its receipts (ADR 0015).
    let source = include_str!("../../../config/resguardo.example.toml")
        .replace("./data/", "/nonexistent/resguardo-data/");
    let config = Config::from_toml_str(&source).unwrap();
    let error = App::from_config(&config).unwrap_err().to_string();
    assert!(error.contains("resguardo init"), "{error}");
}

// --- Scanning, policy and redaction (M3.3) -----------------------------------------------

/// Fake key from the AWS documentation, split so that secret scanners reading this file do
/// not mistake it for a real one.
const AWS_EXAMPLE_KEY: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

fn chat_with(content: &str) -> String {
    serde_json::json!({
        "model": "gpt-4.1-mini",
        "messages": [{"role": "user", "content": content}],
    })
    .to_string()
}

#[tokio::test]
async fn g3_a_dni_is_redacted_before_it_leaves() {
    let h = harness().await;
    let body = chat_with("Mi DNI es 12345678Z");
    let reply = h.openai(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-resguardo-decision"), "redact");
    let sent = &h.mock.requests()[0];
    assert_eq!(
        sent.body,
        body.replace("12345678Z", "[REDACTED:es_id:1]").as_bytes()
    );
    assert_eq!(
        reply.json()["choices"][0]["message"]["content"],
        "echo: Mi DNI es [REDACTED:es_id:1]"
    );
}

#[tokio::test]
async fn g3_two_different_dnis_are_numbered() {
    let h = harness().await;
    let reply = h
        .openai(&h.keys.bot, &chat_with("12345678Z y 87654321X"))
        .await;
    assert_eq!(reply.status, 200);
    let sent = String::from_utf8(h.mock.requests()[0].body.clone()).unwrap();
    assert!(
        sent.contains("[REDACTED:es_id:1] y [REDACTED:es_id:2]"),
        "{sent}"
    );
}

#[tokio::test]
async fn g3_an_aws_key_is_403_sensitive_data_and_nothing_leaves() {
    let h = harness().await;
    let content = format!("mi clave es {AWS_EXAMPLE_KEY}");

    let openai = h.openai(&h.keys.bot, &chat_with(&content)).await;
    assert_eq!(openai.status, 403);
    assert_eq!(openai.code(), "SENSITIVE_DATA");
    assert_eq!(openai.json()["error"]["type"], "resguardo_policy_violation");
    assert_eq!(openai.header("x-resguardo-decision"), "block");
    let message = openai.json()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(message.contains("'secret'"), "{message}");

    let anthropic_body = MESSAGES.replace("hola", &content);
    let anthropic = h.anthropic(&h.keys.bot, &anthropic_body).await;
    assert_eq!(anthropic.status, 403);
    assert_eq!(anthropic.json()["error"]["type"], "permission_error");
    assert_eq!(anthropic.json()["error"]["code"], "SENSITIVE_DATA");

    for reply in [&openai, &anthropic] {
        assert!(!String::from_utf8_lossy(&reply.body).contains("AKIA"));
    }
    assert!(h.mock.requests().is_empty(), "nothing left");
}

#[tokio::test]
async fn a_secret_encoded_three_times_is_blocked_without_a_class() {
    let h = harness().await;
    // Three Base64 layers of a GitHub token (G.2): the token is never seen, and
    // decode_depth blocks by default (ADR 0012).
    let encoded = concat!(
        "V2pKb2QxZ3dSa05STUZKR1VtdGtTVk5WY0V4VVJURlBWREZDVWxWc1RsVldWbHBZ",
        "VjBac1lWbFhTbXBhUjFadFdqSm9jR0ZuUFQwPQ=="
    );
    let reply = h.openai(&h.keys.bot, &chat_with(encoded)).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.code(), "SENSITIVE_DATA");
    let message = reply.json()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        message.contains("could not be fully inspected"),
        "{message}"
    );
    assert!(h.mock.requests().is_empty());
}

#[tokio::test]
async fn a_flagged_finding_is_forwarded_byte_for_byte() {
    let h = harness().await;
    // A high-entropy word is a secret_candidate, whose action only records it.
    let body = chat_with(concat!(
        "token wJalrXUtnFEMI/K7MDENG/",
        "bPxRfiCYEXAMPLEKEY"
    ));
    let reply = h.openai(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-resguardo-decision"), "allow");
    assert_eq!(h.mock.requests()[0].body, body.as_bytes());
}

#[tokio::test]
async fn texts_outside_the_messages_are_redacted_too() {
    let h = harness().await;
    let body = r#"{"model":"claude-sonnet-5-5","max_tokens":10,"system":"Cliente: ana@example.es","messages":[{"role":"user","content":"hola"}]}"#;
    let reply = h.anthropic(&h.keys.bot, body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-resguardo-decision"), "redact");
    assert_eq!(
        h.mock.requests()[0].body,
        body.replace("ana@example.es", "[REDACTED:email:1]")
            .as_bytes()
    );
}

// --- Streaming and response controls (M4) ------------------------------------------------

/// The AWS documentation example key reversed: the request carries this, which is not a
/// key, and the mock answers with the key itself (`MOCK_REPLY_REVERSED:`).
const AWS_KEY_REVERSED: &str = concat!("ELPMAXE7NND", "OFSOIAIKA");

fn stream_chat(content: &str) -> String {
    serde_json::json!({
        "model": "gpt-4.1-mini",
        "stream": true,
        "messages": [{"role": "user", "content": content}],
    })
    .to_string()
}

fn stream_messages(content: &str) -> String {
    serde_json::json!({
        "model": "claude-sonnet-5-5",
        "max_tokens": 10,
        "stream": true,
        "messages": [{"role": "user", "content": content}],
    })
    .to_string()
}

/// Every SSE event of a body, as (event name, data).
fn sse_events(body: &[u8]) -> Vec<(Option<String>, String)> {
    let mut parser = resguardo_proto::SseParser::new(1 << 24);
    let mut events = parser.push(body).unwrap();
    events.extend(parser.finish());
    events
        .into_iter()
        .filter_map(|e| e.data.map(|d| (e.event, d)))
        .collect()
}

/// The text the application would show: the content deltas, in order.
fn streamed_text(body: &[u8]) -> String {
    sse_events(body)
        .into_iter()
        .filter_map(|(_, data)| serde_json::from_str::<Value>(&data).ok())
        .filter_map(|json| {
            json["choices"][0]["delta"]["content"]
                .as_str()
                .or(json["delta"]["text"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

fn error_event(body: &[u8]) -> Option<Value> {
    sse_events(body)
        .into_iter()
        .find(|(name, _)| name.as_deref() == Some("error"))
        .map(|(_, data)| serde_json::from_str(&data).unwrap())
}

#[tokio::test]
async fn a_stream_is_forwarded_as_events() {
    let h = harness().await;
    let reply = h.openai(&h.keys.bot, &stream_chat("hola mundo")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), "text/event-stream");
    assert_eq!(reply.header("x-resguardo-decision"), "allow");
    assert_eq!(streamed_text(&reply.body), "echo: hola mundo");
    assert!(reply.body.ends_with(b"data: [DONE]\n\n"));

    let reply = h
        .anthropic(&h.keys.bot, &stream_messages("hola mundo"))
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(streamed_text(&reply.body), "echo: hola mundo");
    let names: Vec<_> = sse_events(&reply.body)
        .into_iter()
        .filter_map(|e| e.0)
        .collect();
    assert!(names.contains(&"ping".to_owned()), "{names:?}");
    assert_eq!(names.last().map(String::as_str), Some("message_stop"));
}

#[tokio::test]
async fn g4_a_key_split_across_events_cuts_the_stream_with_an_error_event() {
    let h = harness().await;
    // The mock sends the key in 8-character pieces: AKIAIOSF, ODNN7EXA, MPLE.
    let content = format!("MOCK_REPLY_REVERSED: {AWS_KEY_REVERSED}");

    let reply = h.openai(&h.keys.bot, &stream_chat(&content)).await;
    assert_eq!(reply.status, 200, "the stream had started");
    let error = error_event(&reply.body).expect("an error event");
    assert_eq!(error["error"]["code"], "SENSITIVE_DATA");
    assert!(!String::from_utf8_lossy(&reply.body).contains("[DONE]"));
    assert!(!streamed_text(&reply.body).contains(AWS_EXAMPLE_KEY));

    let reply = h.anthropic(&h.keys.bot, &stream_messages(&content)).await;
    let error = error_event(&reply.body).expect("an error event");
    assert_eq!(error["type"], "error");
    assert_eq!(error["error"]["type"], "permission_error");
    assert_eq!(error["error"]["code"], "SENSITIVE_DATA");
    assert!(!String::from_utf8_lossy(&reply.body).contains("message_stop"));
}

#[tokio::test]
async fn in_buffer_mode_nothing_of_the_split_key_is_released() {
    let h = harness().await;
    let content = format!("MOCK_REPLY_REVERSED: {AWS_KEY_REVERSED}");
    let reply = h.openai(&h.keys.careful, &stream_chat(&content)).await;
    assert!(error_event(&reply.body).is_some());
    assert_eq!(streamed_text(&reply.body), "", "the first piece was held");
    assert!(!String::from_utf8_lossy(&reply.body).contains("AKIA"));
}

#[tokio::test]
async fn in_buffer_mode_text_arrives_complete() {
    let h = harness().await;
    let reply = h
        .openai(&h.keys.careful, &stream_chat("una frase. y otra sin punto"))
        .await;
    assert_eq!(
        streamed_text(&reply.body),
        "echo: una frase. y otra sin punto"
    );
    assert!(reply.body.ends_with(b"data: [DONE]\n\n"));
}

#[tokio::test]
async fn g4_a_remote_image_split_across_events_is_removed() {
    let h = harness().await;
    let content = "MOCK_REPLY: Mira ![x](https://attacker.test/p?d=abc) fin";
    let reply = h.openai(&h.keys.bot, &stream_chat(content)).await;
    assert_eq!(streamed_text(&reply.body), "Mira [image removed] fin");
    let reply = h.anthropic(&h.keys.bot, &stream_messages(content)).await;
    assert_eq!(streamed_text(&reply.body), "Mira [image removed] fin");
    assert!(!String::from_utf8_lossy(&reply.body).contains("attacker.test"));
}

#[tokio::test]
async fn g4_a_link_to_an_allowed_host_is_kept_and_others_lose_their_url() {
    let h = harness().await;
    let content =
        "MOCK_REPLY: [guía](https://docs.example.com/x) y [otra](https://attacker.test/y)";
    let reply = h.openai(&h.keys.bot, &stream_chat(content)).await;
    assert_eq!(
        streamed_text(&reply.body),
        "[guía](https://docs.example.com/x) y otra"
    );
}

#[tokio::test]
async fn g4_ten_thousand_events_without_findings_are_all_forwarded() {
    let h = harness().await;
    // 80,000 characters in 8-character pieces.
    let text = "abcdefgh".repeat(10_000);
    let reply = h
        .openai(&h.keys.bot, &stream_chat(&format!("MOCK_REPLY: {text}")))
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(streamed_text(&reply.body), text);
    assert!(reply.body.ends_with(b"data: [DONE]\n\n"));
}

#[tokio::test]
async fn a_stream_cut_by_the_provider_releases_what_was_held() {
    let h = harness().await;
    // `mock-truncate` stops after the first piece, "ver [abc", without the closing events;
    // "[abc" was held as a possible link and is released at the end.
    let body = stream_chat("MOCK_REPLY: ver [abcdef] fin").replace("gpt-4.1-mini", "mock-truncate");
    let reply = h.openai(&h.keys.bot, &body).await;
    assert_eq!(reply.status, 200);
    assert_eq!(streamed_text(&reply.body), "ver [abc");
}

#[tokio::test]
async fn a_whole_response_gets_the_same_controls() {
    let h = harness().await;
    let reply = h
        .openai(
            &h.keys.bot,
            &chat_with("MOCK_REPLY: ![x](https://attacker.test/p) [a](https://attacker.test/)"),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["choices"][0]["message"]["content"],
        "[image removed] a"
    );
    // ADR 0017: the receipt counts what was removed, and never holds the URL.
    wait_for_entries(&h, 2).await;
    let all = entries(&h);
    assert_eq!(
        all[1]["response_controls"],
        json!({"images_removed": 1, "links_removed": 1})
    );
    assert!(
        !std::fs::read_to_string(&h.audit)
            .unwrap()
            .contains("attacker.test")
    );
}

#[tokio::test]
async fn a_whole_response_with_a_key_is_403() {
    let h = harness().await;
    let content = format!("MOCK_REPLY_REVERSED: {AWS_KEY_REVERSED}");
    let reply = h.openai(&h.keys.bot, &chat_with(&content)).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.code(), "SENSITIVE_DATA");
    assert!(!String::from_utf8_lossy(&reply.body).contains("AKIA"));
}

// --- Signed receipts (M5) ----------------------------------------------------------------

/// Every entry of the audit log, parsed.
fn entries(h: &Harness) -> Vec<Value> {
    std::fs::read_to_string(&h.audit)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn verify(h: &Harness) -> usize {
    let file = std::fs::File::open(&h.audit).unwrap();
    let key = resguardo_audit::PublicKey::load(&h.public_key).unwrap();
    resguardo_audit::verify_log(std::io::BufReader::new(file), &key)
        .unwrap()
        .entries
}

/// Outcome entries are written after the response is sent: wait until they are there.
async fn wait_for_entries(h: &Harness, n: usize) {
    for _ in 0..100 {
        if entries(h).len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("expected {n} entries, found {}", entries(h).len());
}

#[tokio::test]
async fn g5_three_requests_leave_six_entries_that_verify() {
    let h = harness().await;
    for content in ["hola", "Mi DNI es 12345678Z", "adiós"] {
        let reply = h.openai(&h.keys.bot, &chat_with(content)).await;
        assert_eq!(reply.status, 200);
    }
    wait_for_entries(&h, 6).await;
    assert_eq!(verify(&h), 6);
    let all = entries(&h);
    let kinds: Vec<&str> = all.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "decision", "outcome", "decision", "outcome", "decision", "outcome"
        ]
    );
    let dni = &all[2];
    assert_eq!(dni["principal"], "bot");
    assert_eq!(dni["provider"], "openai");
    assert_eq!(dni["model"], "gpt-4.1-mini");
    assert_eq!(dni["decision"], "redact");
    assert_eq!(dni["findings"], serde_json::json!({"es_id": 1}));
    assert!(dni["forwarded_sha256"].is_string());
    assert_eq!(all[3]["status"], 200);
    assert_eq!(all[3]["outcome"], "completed");
    assert!(all[3]["upstream_us"].is_u64());
}

#[tokio::test]
async fn g5_the_dni_and_the_key_of_g3_never_appear_in_the_log() {
    let h = harness().await;
    h.openai(&h.keys.bot, &chat_with("Mi DNI es 12345678Z"))
        .await;
    let blocked = h
        .openai(&h.keys.bot, &chat_with(&format!("clave {AWS_EXAMPLE_KEY}")))
        .await;
    assert_eq!(blocked.status, 403);
    wait_for_entries(&h, 4).await;
    let log = std::fs::read_to_string(&h.audit).unwrap();
    assert!(!log.contains("12345678Z"));
    assert!(!log.contains("AKIA"));
    let all = entries(&h);
    assert_eq!(all[2]["decision"], "block");
    assert_eq!(all[2]["code"], "SENSITIVE_DATA");
    assert_eq!(all[2]["class"], "secret");
    assert_eq!(all[3]["outcome"], "blocked");
    assert_eq!(all[3]["status"], 403);
}

#[tokio::test]
async fn requests_refused_before_the_key_leave_no_receipt_and_later_ones_do() {
    let h = harness().await;
    let (stranger, _) = key(99);
    assert_eq!(h.openai(&stranger, CHAT).await.status, 401);
    let other = CHAT.replace("gpt-4.1-mini", "gpt-5");
    assert_eq!(h.openai(&h.keys.bot, &other).await.status, 403);
    wait_for_entries(&h, 2).await;
    let all = entries(&h);
    assert_eq!(all.len(), 2, "no receipt for the unknown key");
    assert_eq!(all[0]["code"], "MODEL_NOT_ALLOWED");
}

#[tokio::test]
async fn a_stream_leaves_its_outcome_when_it_ends_or_is_cut() {
    let h = harness().await;
    let reply = h.openai(&h.keys.bot, &stream_chat("hola mundo")).await;
    assert_eq!(reply.status, 200);
    let cut = h
        .openai(
            &h.keys.bot,
            &stream_chat(&format!("MOCK_REPLY_REVERSED: {AWS_KEY_REVERSED}")),
        )
        .await;
    assert!(error_event(&cut.body).is_some());
    wait_for_entries(&h, 4).await;
    assert_eq!(verify(&h), 4);
    let all = entries(&h);
    assert_eq!(all[1]["outcome"], "completed");
    assert_eq!(all[1]["stream"], true);
    assert_eq!(all[1]["response_controls"], json!({}));
    assert_eq!(all[3]["outcome"], "aborted");
    assert_eq!(all[3]["response_findings"]["secret"], 1);
    assert_eq!(all[3]["response_controls"], json!({}));
}

#[tokio::test]
async fn a_stream_receipt_counts_what_the_controls_removed() {
    let h = harness().await;
    // The image is split across events; the second text block (Anthropic) is separate.
    let content =
        "MOCK_REPLY: Mira ![x](https://attacker.test/p?d=abc) y [a](https://attacker.test/) fin";
    let reply = h.openai(&h.keys.bot, &stream_chat(content)).await;
    assert_eq!(streamed_text(&reply.body), "Mira [image removed] y a fin");
    let reply = h.anthropic(&h.keys.bot, &stream_messages(content)).await;
    assert_eq!(streamed_text(&reply.body), "Mira [image removed] y a fin");
    wait_for_entries(&h, 4).await;
    assert_eq!(verify(&h), 4);
    let all = entries(&h);
    for outcome in [&all[1], &all[3]] {
        assert_eq!(
            outcome["response_controls"],
            json!({"images_removed": 1, "links_removed": 1})
        );
    }
    assert!(
        !std::fs::read_to_string(&h.audit)
            .unwrap()
            .contains("attacker.test")
    );
}
