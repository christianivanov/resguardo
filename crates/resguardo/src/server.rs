//! The HTTP proxy (design document, section 4 and Annex H).
//!
//! Order of checks, each one failing closed:
//! route → virtual key → query → content type and encoding → rate limit → body size →
//! strict parsing → message count → model allowed → (scanning, policy and receipt: M2–M5)
//! → egress.
//!
//! Until scanning (M2) and the signed audit log (M5) exist, [`App::from_config`] refuses any
//! upstream that is not a local, explicitly insecure one: nothing can reach a real provider
//! unscanned.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::{
    AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName,
    HeaderValue, RETRY_AFTER,
};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use resguardo_core::{BlockCode, Config, KeyRing, OffsetDateTime, Principal, Provider};
use resguardo_egress::{Egress, OutboundRequest};
use resguardo_proto::{ApiFormat, ParsedRequest, check_query, parse_request, route};
use serde_json::json;
use tokio::net::TcpListener;

use crate::rate_limit::{RateLimiter, retry_after_secs};

const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-resguardo-request-id");
const X_DECISION: HeaderName = HeaderName::from_static("x-resguardo-decision");

/// Everything a request needs, shared by all of them (`Arc`: shared ownership across tasks,
/// like a singleton bean).
#[derive(Debug)]
pub struct App {
    keys: KeyRing,
    limiter: RateLimiter,
    egress: Egress,
    request_timeout: Duration,
}

impl App {
    /// Loads provider credentials and builds the HTTP client. Any problem stops startup.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        // Temporary guard, removed when scanning and the audit log exist (M2, M5).
        if let Some(upstream) = config.upstreams.values().find(|u| !u.insecure) {
            bail!(
                "upstream {} ({}) is not local: until scanning (M2) and the signed audit log (M5) \
                 exist, `resguardo run` only accepts local upstreams with allow_insecure_upstream \
                 = true, such as tools/mock-upstream",
                upstream.provider,
                upstream.base_url
            );
        }
        let egress = Egress::from_config(config).context("setting up egress")?;
        Ok(Self {
            keys: KeyRing::from_config(config),
            limiter: RateLimiter::new(config.principals.iter().map(|p| &p.principal)),
            egress,
            request_timeout: Duration::from_secs(config.server.request_timeout_secs),
        })
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy)
        .with_state(app)
}

/// Serves until `shutdown` completes, then finishes the requests in flight.
pub async fn serve(
    listener: TcpListener,
    app: Arc<App>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown)
        .await
}

/// In M1 there is no audit log or signing key to check yet (Annex H: M5).
async fn healthz() -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
        .into_response()
}

/// Why Resguardo answered itself instead of forwarding.
#[derive(Debug)]
enum Failure {
    NotFound,
    Block {
        code: BlockCode,
        /// Fixed text chosen by Resguardo: never request content.
        message: String,
        retry_after: Option<u64>,
    },
}

impl Failure {
    fn block(code: BlockCode, message: impl Into<String>) -> Self {
        Failure::Block {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::block(BlockCode::InvalidRequest, message)
    }
}

async fn proxy(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = new_request_id();
    let format = route(request.method().as_str(), request.uri().path());
    match handle(&app, format, request).await {
        Ok(response) => forwarded(response, &request_id),
        Err(failure) => error_response(failure, format, &request_id),
    }
}

async fn handle(
    app: &App,
    format: Option<ApiFormat>,
    request: Request,
) -> Result<resguardo_egress::UpstreamResponse, Failure> {
    let Some(format) = format else {
        return Err(Failure::NotFound);
    };
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    let principal = authenticate(app, headers)?;

    let query = parts.uri.query();
    check_query(format, query).map_err(|e| Failure::invalid(e.to_string()))?;
    check_content_headers(headers)?;

    if let Err(wait) = app.limiter.check(&principal.id, Instant::now()) {
        let secs = retry_after_secs(wait);
        return Err(Failure::Block {
            code: BlockCode::RateLimited,
            message: format!("too many requests for this key; retry after {secs} s"),
            retry_after: Some(secs),
        });
    }

    let limit = principal.limits.max_body_bytes;
    let bytes = tokio::time::timeout(app.request_timeout, read_body(body, headers, limit))
        .await
        .map_err(|_| Failure::invalid("request body was not received in time"))??;

    let parsed = parse_request(format, &bytes).map_err(|e| Failure::invalid(e.to_string()))?;
    if parsed.stream {
        return Err(Failure::invalid(
            "streaming is not supported yet (planned for v0.1, milestone M4)",
        ));
    }
    if parsed.message_count > principal.limits.max_messages {
        return Err(Failure::block(
            BlockCode::BodyTooLarge,
            format!(
                "more than {} messages in one request",
                principal.limits.max_messages
            ),
        ));
    }
    let provider = resolve_provider(format, &parsed, principal).ok_or_else(|| {
        Failure::block(
            BlockCode::ModelNotAllowed,
            "this model is not allowed for this key",
        )
    })?;

    // M2–M5 go here: scan `parsed.texts`, decide, and write the signed decision entry
    // before anything leaves. Until then `App::from_config` only allows local upstreams.

    app.egress
        .send(OutboundRequest {
            provider,
            path: format.path(),
            query,
            incoming_headers: headers,
            body: bytes,
        })
        .await
        .map_err(|error| {
            // Operator-facing detail: provider and cause, never content or credentials.
            eprintln!("upstream {provider}: {error}");
            Failure::block(error.block_code(), upstream_message(error.block_code()))
        })
}

/// Accepts the key from `Authorization: Bearer` or `x-api-key`; a header that appears twice
/// or is not valid text counts as a wrong key.
fn authenticate<'a>(app: &'a App, headers: &HeaderMap) -> Result<&'a Principal, Failure> {
    let unknown = || Failure::block(BlockCode::UnknownKey, "unknown or missing virtual key");
    let single = |name: &HeaderName| -> Result<Option<&str>, Failure> {
        let mut values = headers.get_all(name).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(unknown());
        }
        Ok(first.map(|v| v.to_str().unwrap_or("")))
    };
    let key =
        resguardo_core::virtual_key::presented_key(single(&AUTHORIZATION)?, single(&X_API_KEY)?)
            .map_err(|_| unknown())?;
    app.keys
        .authenticate(key, OffsetDateTime::now_utc())
        .map_err(|code| match code {
            BlockCode::KeyExpired => Failure::block(code, "the virtual key has expired"),
            _ => unknown(),
        })
}

/// The scanner reads the body as JSON text, so it must be exactly that: no compression and
/// no other media type.
fn check_content_headers(headers: &HeaderMap) -> Result<(), Failure> {
    if let Some(encoding) = headers.get(CONTENT_ENCODING)
        && encoding.as_bytes() != b"identity"
    {
        return Err(Failure::invalid(
            "compressed request bodies are not accepted",
        ));
    }
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(Failure::invalid("content-type must be application/json"));
    }
    Ok(())
}

/// Reads the body up to `limit` bytes; a declared or actual larger body is refused.
async fn read_body(body: Body, headers: &HeaderMap, limit: usize) -> Result<Vec<u8>, Failure> {
    let too_large = || {
        Failure::block(
            BlockCode::BodyTooLarge,
            format!("request body is larger than {limit} bytes"),
        )
    };
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|length| usize::try_from(length).map_or(true, |l| l > limit)) {
        return Err(too_large());
    }
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Failure::invalid("request body could not be read"))?;
        if bytes.len() + chunk.len() > limit {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Anthropic Messages go to `anthropic`. Chat Completions go to `openai` or
/// `openai_compatible`, whichever of the principal's lists has the model (ADR 0005).
fn resolve_provider(
    format: ApiFormat,
    parsed: &ParsedRequest,
    principal: &Principal,
) -> Option<Provider> {
    let allows = |provider: Provider| {
        principal
            .allowed
            .get(&provider)
            .is_some_and(|models| models.contains(&parsed.model))
    };
    match format {
        ApiFormat::AnthropicMessages => allows(Provider::Anthropic).then_some(Provider::Anthropic),
        ApiFormat::OpenAiChat => [Provider::OpenAi, Provider::OpenAiCompatible]
            .into_iter()
            .find(|p| allows(*p)),
    }
}

fn upstream_message(code: BlockCode) -> &'static str {
    match code {
        BlockCode::UpstreamRedirect => {
            "the provider answered with a redirect, which is not followed"
        }
        BlockCode::InvalidRequest => "the request cannot be forwarded as sent",
        _ => "the provider could not be reached or its response was not accepted",
    }
}

fn forwarded(upstream: resguardo_egress::UpstreamResponse, request_id: &str) -> Response {
    let mut response = Body::from(upstream.body).into_response();
    *response.status_mut() = upstream.status;
    let headers = response.headers_mut();
    headers.extend(upstream.headers);
    add_resguardo_headers(headers, request_id, "allow");
    response
}

/// OpenAI's error shape on Chat Completions and unknown routes (Annex H); Anthropic's on
/// Messages, so each SDK understands its errors. Both carry Resguardo's code and request id.
fn error_response(failure: Failure, format: Option<ApiFormat>, request_id: &str) -> Response {
    let (status, code, message, retry_after) = match failure {
        Failure::NotFound => (
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "unknown route: Resguardo serves POST /v1/chat/completions and POST /v1/messages"
                .to_owned(),
            None,
        ),
        Failure::Block {
            code,
            message,
            retry_after,
        } => (
            StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            code.as_str(),
            message,
            retry_after,
        ),
    };
    let body = match format {
        Some(ApiFormat::AnthropicMessages) => json!({
            "type": "error",
            "error": {
                "type": anthropic_error_type(status),
                "message": message,
                "code": code,
            },
            "request_id": request_id,
        }),
        _ => json!({
            "error": {
                "type": if status == StatusCode::FORBIDDEN {
                    "resguardo_policy_violation"
                } else {
                    "resguardo_error"
                },
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        }),
    };
    let mut response = (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        body.to_string(),
    )
        .into_response();
    let headers = response.headers_mut();
    add_resguardo_headers(headers, request_id, "block");
    if let Some(secs) = retry_after {
        headers.insert(RETRY_AFTER, HeaderValue::from(secs));
    }
    response
}

/// Anthropic's documented error types by status.
fn anthropic_error_type(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        _ => "api_error",
    }
}

fn add_resguardo_headers(headers: &mut HeaderMap, request_id: &str, decision: &'static str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert(X_REQUEST_ID, value);
    }
    headers.insert(X_DECISION, HeaderValue::from_static(decision));
}

/// UUID v7: milliseconds since the epoch, then random bits, so ids sort by time.
/// If the OS random generator fails, a process-wide counter keeps ids unique.
fn new_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let mut random = [0u8; 10];
    if getrandom::fill(&mut random).is_err() {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        random[2..].copy_from_slice(&count);
    }
    uuid::Builder::from_unix_timestamp_millis(millis, &random)
        .into_uuid()
        .hyphenated()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_uuid_v7_and_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'7', "{a}");
    }

    #[test]
    fn anthropic_error_types_follow_the_status() {
        assert_eq!(
            anthropic_error_type(StatusCode::UNAUTHORIZED),
            "authentication_error"
        );
        assert_eq!(anthropic_error_type(StatusCode::BAD_GATEWAY), "api_error");
    }
}
