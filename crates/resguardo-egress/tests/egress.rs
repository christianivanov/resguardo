//! Egress against the mock upstream: what actually leaves, and what is refused.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use resguardo_core::config::{CredentialSource, Upstream};
use resguardo_core::{BlockCode, Provider};
use resguardo_egress::{
    CHAT_COMPLETIONS_PATH, Egress, EgressError, EgressSettings, MESSAGES_PATH, OutboundRequest,
};
use resguardo_mock_upstream::MockUpstream;
use url::Url;

const OPENAI_KEY: &str = "sk-test-openai-not-real";
const ANTHROPIC_KEY: &str = "sk-ant-test-not-real";
const VIRTUAL_KEY: &str = "rsg_0000000000000000000000000000000000000000000";

/// Each call gets its own directory: tests run in parallel and must not rewrite a file
/// another test is reading.
fn credential_file(name: &str, key: &str) -> CredentialSource {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("egress-credentials")
        .join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, format!("{key}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    CredentialSource::File(path)
}

fn settings(max_response_bytes: usize) -> EgressSettings {
    EgressSettings {
        request_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        max_response_bytes,
    }
}

fn upstream(provider: Provider, base_url: &str, credential: Option<CredentialSource>) -> Upstream {
    Upstream {
        provider,
        base_url: Url::parse(base_url).unwrap(),
        credential,
        insecure: true,
    }
}

struct Fixture {
    mock: MockUpstream,
    egress: Egress,
}

async fn fixture(max_response_bytes: usize) -> Fixture {
    let mock = MockUpstream::start(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("mock starts");
    let base = mock.base_url();
    let upstreams = BTreeMap::from([
        (
            Provider::OpenAi,
            upstream(
                Provider::OpenAi,
                &base,
                Some(credential_file("openai.key", OPENAI_KEY)),
            ),
        ),
        (
            Provider::Anthropic,
            upstream(
                Provider::Anthropic,
                &base,
                Some(credential_file("anthropic.key", ANTHROPIC_KEY)),
            ),
        ),
        (
            Provider::OpenAiCompatible,
            upstream(Provider::OpenAiCompatible, &base, None),
        ),
    ]);
    let egress = Egress::new(&upstreams, settings(max_response_bytes)).expect("egress builds");
    Fixture { mock, egress }
}

/// Headers as an application would send them: the virtual key in both places, plus noise.
fn app_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {VIRTUAL_KEY}")).unwrap(),
    );
    headers.insert("x-api-key", HeaderValue::from_static(VIRTUAL_KEY));
    headers.insert("cookie", HeaderValue::from_static("session=abc"));
    headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    headers.insert(
        "anthropic-beta",
        HeaderValue::from_static("beta-2026-01-01"),
    );
    headers
}

fn request<'a>(
    provider: Provider,
    path: &'a str,
    query: Option<&'a str>,
    headers: &'a HeaderMap,
    body: &str,
) -> OutboundRequest<'a> {
    OutboundRequest {
        provider,
        path,
        query,
        incoming_headers: headers,
        body: body.as_bytes().to_vec(),
    }
}

const OPENAI_BODY: &str =
    r#"{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hola"}],"extra":1}"#;
const ANTHROPIC_BODY: &str =
    r#"{"model":"claude-sonnet-5-5","max_tokens":5,"messages":[{"role":"user","content":"hola"}]}"#;

#[tokio::test]
async fn openai_receives_the_real_key_and_the_exact_body() {
    let f = fixture(1 << 20).await;
    let headers = app_headers();
    let response = f
        .egress
        .send(request(
            Provider::OpenAi,
            CHAT_COMPLETIONS_PATH,
            None,
            &headers,
            OPENAI_BODY,
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.headers["x-request-id"], "req_mock_1");

    let sent = &f.mock.requests()[0];
    assert_eq!(sent.path, CHAT_COMPLETIONS_PATH);
    assert_eq!(sent.body, OPENAI_BODY.as_bytes(), "byte for byte");
    assert_eq!(
        sent.header("authorization"),
        Some(&*format!("Bearer {OPENAI_KEY}"))
    );
    assert_eq!(sent.header("x-api-key"), None);
    assert_eq!(sent.header("cookie"), None);
    assert_eq!(sent.header("anthropic-beta"), None, "only for Anthropic");
    assert!(sent.header("user-agent").unwrap().starts_with("resguardo/"));
    let everything = format!("{:?}", sent.headers);
    assert!(
        !everything.contains(VIRTUAL_KEY),
        "the virtual key never leaves"
    );
}

#[tokio::test]
async fn anthropic_receives_x_api_key_beta_headers_and_query() {
    let f = fixture(1 << 20).await;
    let headers = app_headers();
    let response = f
        .egress
        .send(request(
            Provider::Anthropic,
            MESSAGES_PATH,
            Some("beta=true"),
            &headers,
            ANTHROPIC_BODY,
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers["anthropic-ratelimit-unified-status"],
        "allowed"
    );

    let sent = &f.mock.requests()[0];
    assert_eq!(sent.query.as_deref(), Some("beta=true"));
    assert_eq!(sent.header("x-api-key"), Some(ANTHROPIC_KEY));
    assert_eq!(sent.header("authorization"), None);
    assert_eq!(sent.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(sent.header("anthropic-beta"), Some("beta-2026-01-01"));
    assert!(!format!("{:?}", sent.headers).contains(VIRTUAL_KEY));
}

#[tokio::test]
async fn compatible_upstream_without_credential_gets_no_auth_header() {
    let f = fixture(1 << 20).await;
    let headers = app_headers();
    f.egress
        .send(request(
            Provider::OpenAiCompatible,
            CHAT_COMPLETIONS_PATH,
            None,
            &headers,
            OPENAI_BODY,
        ))
        .await
        .unwrap();
    let sent = &f.mock.requests()[0];
    assert_eq!(sent.header("authorization"), None);
    assert_eq!(sent.header("x-api-key"), None);
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let f = fixture(1 << 20).await;
    let headers = HeaderMap::new();
    let error = f
        .egress
        .send(request(
            Provider::OpenAi,
            CHAT_COMPLETIONS_PATH,
            None,
            &headers,
            r#"{"model":"mock-redirect","messages":[]}"#,
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, EgressError::Redirect(302)), "{error}");
    assert_eq!(error.block_code(), BlockCode::UpstreamRedirect);
    assert_eq!(
        f.mock.requests().len(),
        1,
        "the redirect target is never contacted"
    );
}

#[tokio::test]
async fn provider_errors_are_returned_unchanged() {
    let f = fixture(1 << 20).await;
    let headers = HeaderMap::new();
    let response = f
        .egress
        .send(request(
            Provider::Anthropic,
            MESSAGES_PATH,
            None,
            &headers,
            r#"{"model":"mock-error","messages":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 500);
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(json["type"], "error");
}

#[tokio::test]
async fn responses_over_the_limit_are_refused() {
    let f = fixture(16).await;
    let headers = HeaderMap::new();
    let error = f
        .egress
        .send(request(
            Provider::OpenAi,
            CHAT_COMPLETIONS_PATH,
            None,
            &headers,
            OPENAI_BODY,
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(error, EgressError::ResponseTooLarge(16)),
        "{error}"
    );
    assert_eq!(error.block_code(), BlockCode::UpstreamError);
}

#[tokio::test]
async fn bad_routes_and_queries_never_reach_the_network() {
    let f = fixture(1 << 20).await;
    let headers = HeaderMap::new();
    for (provider, path, query) in [
        (Provider::OpenAi, MESSAGES_PATH, None),
        (Provider::Anthropic, CHAT_COMPLETIONS_PATH, None),
        (Provider::OpenAi, "/v1/embeddings", None),
        (Provider::OpenAi, CHAT_COMPLETIONS_PATH, Some("beta=true")),
        (Provider::Anthropic, MESSAGES_PATH, Some("x=secret")),
    ] {
        let error = f
            .egress
            .send(request(provider, path, query, &headers, "{}"))
            .await
            .unwrap_err();
        assert_eq!(error.block_code(), BlockCode::InvalidRequest, "{error}");
        assert!(!error.to_string().contains("secret"), "{error}");
    }
    assert!(f.mock.requests().is_empty());
}

#[tokio::test]
async fn unreachable_upstream_is_an_upstream_error() {
    let upstreams = BTreeMap::from([(
        Provider::OpenAiCompatible,
        // Port 9 (discard): nothing listens there on a test machine.
        upstream(Provider::OpenAiCompatible, "http://127.0.0.1:9", None),
    )]);
    let egress = Egress::new(&upstreams, settings(1024)).unwrap();
    let headers = HeaderMap::new();
    let error = egress
        .send(request(
            Provider::OpenAiCompatible,
            CHAT_COMPLETIONS_PATH,
            None,
            &headers,
            "{}",
        ))
        .await
        .unwrap_err();
    assert_eq!(error.block_code(), BlockCode::UpstreamError, "{error}");
}

#[test]
fn plain_http_without_the_insecure_flag_is_refused() {
    let mut openai = upstream(Provider::OpenAiCompatible, "http://127.0.0.1:9000", None);
    openai.insecure = false;
    let upstreams = BTreeMap::from([(Provider::OpenAiCompatible, openai)]);
    let error = Egress::new(&upstreams, settings(1024)).unwrap_err();
    assert!(matches!(error, EgressError::InsecureScheme(_)), "{error}");
}

#[test]
fn urls_keep_the_base_path_and_origin() {
    let upstreams = BTreeMap::from([(
        Provider::OpenAiCompatible,
        upstream(
            Provider::OpenAiCompatible,
            "https://gateway.example/llm",
            None,
        ),
    )]);
    let egress = Egress::new(&upstreams, settings(1024)).unwrap();
    let url = egress
        .url(Provider::OpenAiCompatible, CHAT_COMPLETIONS_PATH, None)
        .unwrap();
    assert_eq!(
        url.as_str(),
        "https://gateway.example/llm/v1/chat/completions"
    );
    assert!(matches!(
        egress.url(Provider::OpenAi, CHAT_COMPLETIONS_PATH, None),
        Err(EgressError::NoUpstream(Provider::OpenAi))
    ));
}

#[test]
fn credential_problems_stop_startup() {
    let upstreams = BTreeMap::from([(
        Provider::OpenAi,
        upstream(
            Provider::OpenAi,
            "https://api.openai.com",
            Some(CredentialSource::Env(
                "RESGUARDO_TEST_SURELY_UNSET_9c1e".into(),
            )),
        ),
    )]);
    let error = Egress::new(&upstreams, settings(1024)).unwrap_err();
    assert_eq!(error.block_code(), BlockCode::UpstreamError);
    assert!(
        error
            .to_string()
            .contains("RESGUARDO_TEST_SURELY_UNSET_9c1e")
    );
}
