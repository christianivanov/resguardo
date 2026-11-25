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
use serde_json::Value;
use tokio::net::TcpListener;

const OPENAI_KEY: &str = "sk-test-openai-not-real";
const ANTHROPIC_KEY: &str = "sk-ant-test-not-real";

struct Keys {
    bot: String,
    old: String,
    slow: String,
    small: String,
}

struct Harness {
    mock: MockUpstream,
    url: String,
    keys: Keys,
    client: reqwest::Client,
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
    let source = format!(
        r#"
[audit]
path = "unused"
signing_key = "unused"
public_key = "unused"

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"

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
models.openai = ["gpt-4.1-mini", "mock-redirect"]
models.anthropic = ["claude-sonnet-4-5", "mock-error"]
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
"#,
        openai = credential_file(OPENAI_KEY),
        anthropic = credential_file(ANTHROPIC_KEY),
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
        },
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
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
const MESSAGES: &str = r#"{"model":"claude-sonnet-4-5","max_tokens":10,"messages":[{"role":"user","content":"hola"}]}"#;

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
    let crossed = MESSAGES.replace("claude-sonnet-4-5", "gpt-4.1-mini");
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
    let body = MESSAGES.replace("claude-sonnet-4-5", "mock-error");
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
    let streaming = CHAT.replace(r#""messages""#, r#""stream":true,"messages""#);
    for body in [duplicate.as_str(), "not json", streaming.as_str()] {
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
fn run_refuses_real_providers_until_scanning_and_audit_exist() {
    let source = include_str!("../../../config/resguardo.example.toml");
    let config = Config::from_toml_str(source).unwrap();
    let error = App::from_config(&config).unwrap_err().to_string();
    assert!(error.contains("only accepts local upstreams"), "{error}");
}
