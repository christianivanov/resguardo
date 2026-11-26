//! The HTTP proxy (design document, section 4 and Annex H).
//!
//! Order of checks, each one failing closed:
//! route → virtual key → query → content type and encoding → rate limit → body size →
//! strict parsing → message count → model allowed → scanning → policy → redaction →
//! signed decision entry → egress → response scanning → signed outcome entry.
//!
//! From the virtual key on, every request leaves two signed entries in the audit log
//! (ADR 0015). If the decision entry cannot be written, nothing leaves.

use std::collections::BTreeMap;
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
use resguardo_audit::{AuditLog, SigningKey};
use resguardo_core::config::StreamConfig;
use resguardo_core::{
    BlockCode, Config, DataClass, Decision, KeyRing, OffsetDateTime, Principal, Provider,
};
use resguardo_egress::{Egress, OutboundRequest, UpstreamAnswer, UpstreamResponse, UpstreamStream};
use resguardo_policy::Policy;
use resguardo_proto::{
    ApiFormat, ParsedRequest, ResponseControls, check_query, parse_request, redact, route,
};
use resguardo_scan::Pipeline;
use serde_json::Value;
use serde_json::json;
use tokio::net::TcpListener;

use crate::rate_limit::{RateLimiter, retry_after_secs};
use crate::receipt::{Receipt, micros, outcome_in_background};

const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-resguardo-request-id");
const X_DECISION: HeaderName = HeaderName::from_static("x-resguardo-decision");

/// Everything a request needs, shared by all of them (`Arc`: shared ownership across tasks,
/// like a singleton bean).
#[derive(Debug)]
pub struct App {
    keys: KeyRing,
    limiter: RateLimiter,
    pub(crate) pipeline: Pipeline,
    pub(crate) policy: Policy,
    pub(crate) controls: ResponseControls,
    pub(crate) stream: StreamConfig,
    pub(crate) audit: AuditLog,
    egress: Egress,
    request_timeout: Duration,
}

impl App {
    /// Loads provider credentials and builds the HTTP client. Any problem stops startup.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let signing_key = &config.audit.signing_key;
        if !signing_key.exists() {
            bail!(
                "no signing key at {}: create one with `resguardo init`",
                signing_key.display()
            );
        }
        let key = SigningKey::load(signing_key).context("loading the signing key")?;
        let audit = AuditLog::open(&config.audit.path, key, config.audit.fsync)
            .context("opening the audit log")?;
        let egress = Egress::from_config(config).context("setting up egress")?;
        let pipeline = Pipeline::new(&config.scan).context("setting up scanning")?;
        Ok(Self {
            keys: KeyRing::from_config(config),
            limiter: RateLimiter::new(config.principals.iter().map(|p| &p.principal)),
            pipeline,
            policy: Policy::from_config(config),
            controls: ResponseControls::from_config(&config.response),
            stream: config.stream.clone(),
            audit,
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

/// Annex H: 200 while the audit log accepts entries; 503 after a failed write, until a
/// write succeeds again.
async fn healthz(State(app): State<Arc<App>>) -> Response {
    let (status, body) = if app.audit.healthy() {
        (StatusCode::OK, r#"{"status":"ok"}"#)
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"audit_unavailable"}"#,
        )
    };
    (status, [(CONTENT_TYPE, "application/json")], body).into_response()
}

/// Why Resguardo answered itself instead of forwarding.
#[derive(Debug)]
pub(crate) enum Failure {
    NotFound,
    Block {
        code: BlockCode,
        /// Fixed text chosen by Resguardo: never request content.
        message: String,
        retry_after: Option<u64>,
    },
}

impl Failure {
    pub(crate) fn block(code: BlockCode, message: impl Into<String>) -> Self {
        Failure::Block {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::block(BlockCode::InvalidRequest, message)
    }

    pub(crate) fn code(&self) -> Option<BlockCode> {
        match self {
            Failure::NotFound => None,
            Failure::Block { code, .. } => Some(*code),
        }
    }
}

async fn proxy(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = new_request_id();
    let format = route(request.method().as_str(), request.uri().path());
    match handle(&app, format, request, &request_id).await {
        Ok(response) => response,
        Err(failure) => error_response(failure, format, &request_id),
    }
}

async fn handle(
    app: &Arc<App>,
    format: Option<ApiFormat>,
    request: Request,
    request_id: &str,
) -> Result<Response, Failure> {
    let Some(format) = format else {
        return Err(Failure::NotFound);
    };
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    let principal = authenticate(app, headers)?;
    // From here on the request gets its receipts (ADR 0015).
    let mut receipt = Receipt::new(request_id, principal);
    match proceed(app, format, &parts, body, principal, &mut receipt).await {
        Ok(response) => Ok(response),
        Err(failure) => Err(receipt.failed(app, failure).await),
    }
}

async fn proceed(
    app: &Arc<App>,
    format: ApiFormat,
    parts: &axum::http::request::Parts,
    body: Body,
    principal: &Principal,
    receipt: &mut Receipt,
) -> Result<Response, Failure> {
    let headers = &parts.headers;
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
    receipt.set("body_bytes", json!(bytes.len()));
    receipt.body("body", &bytes);

    let parsed = parse_request(format, &bytes).map_err(|e| Failure::invalid(e.to_string()))?;
    let stream = parsed.stream;
    receipt.set("model", json!(parsed.model));
    receipt.set("stream", json!(stream));
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
    receipt.set("provider", json!(provider.as_str()));

    let inspection = inspect(Arc::clone(app), principal.clone(), parsed, bytes).await?;
    receipt.findings(&inspection.report);
    let (decision, body) = match inspection.outcome {
        Inspected::Allow(body) => ("allow", body),
        Inspected::Redact(body) => {
            receipt.body("forwarded", &body);
            ("redact", body)
        }
        Inspected::Block(code, class) => {
            receipt.set("decision", json!("block"));
            receipt.set("code", json!(code.as_str()));
            if let Some(class) = class {
                receipt.set("class", json!(class.as_str()));
            }
            return Err(Failure::block(code, blocked_message(class)));
        }
    };
    receipt.set("decision", json!(decision));
    // The signed decision entry, flushed, before anything is sent (ADR 0003).
    receipt.decide(app).await?;

    let outbound = OutboundRequest {
        provider,
        path: format.path(),
        query,
        incoming_headers: headers,
        body,
    };
    let upstream_failed = |error: resguardo_egress::EgressError| {
        // Operator-facing detail: provider and cause, never content or credentials.
        eprintln!("upstream {provider}: {error}");
        Failure::block(error.block_code(), upstream_message(error.block_code()))
    };
    let upstream_started = Instant::now();
    let answer = if stream {
        app.egress
            .send_streaming(outbound)
            .await
            .map_err(upstream_failed)?
    } else {
        UpstreamAnswer::Whole(app.egress.send(outbound).await.map_err(upstream_failed)?)
    };
    match answer {
        UpstreamAnswer::Whole(response) => {
            let upstream_us = micros(upstream_started);
            let (response, response_findings) =
                guard_whole(Arc::clone(app), principal.clone(), format, response).await?;
            let total = micros(receipt.started);
            let fields = BTreeMap::from([
                ("status".to_owned(), json!(response.status.as_u16())),
                ("outcome".to_owned(), json!("completed")),
                ("upstream_us".to_owned(), json!(upstream_us)),
                (
                    "overhead_us".to_owned(),
                    json!(total.saturating_sub(upstream_us)),
                ),
                ("response_findings".to_owned(), response_findings),
            ]);
            // The response does not wait for its outcome: only the decision entry must be
            // on disk before anything leaves (ADR 0003).
            outcome_in_background(app, &receipt.request_id, fields);
            Ok(forwarded(response, &receipt.request_id, decision))
        }
        UpstreamAnswer::Stream(upstream) => Ok(streamed(
            Arc::clone(app),
            principal.clone(),
            format,
            upstream,
            receipt,
            upstream_started,
            decision,
        )),
    }
}

/// Scans a whole response on the blocking pool (ADR 0014).
async fn guard_whole(
    app: Arc<App>,
    principal: Principal,
    format: ApiFormat,
    response: UpstreamResponse,
) -> Result<(UpstreamResponse, Value), Failure> {
    tokio::task::spawn_blocking(move || {
        crate::response::guard_whole(&app, &principal, format, response)
    })
    .await
    .map_err(|_| Failure::block(BlockCode::ScanError, "the response could not be scanned"))?
}

/// Relays an SSE response through a [`crate::response::StreamGuard`]: each chunk is
/// scanned and controlled before it is sent, and a blocking finding ends the stream with
/// an error event. The status and headers go out first, so the decision header is the
/// request's.
fn streamed(
    app: Arc<App>,
    principal: Principal,
    format: ApiFormat,
    upstream: UpstreamStream,
    receipt: &Receipt,
    upstream_started: Instant,
    decision: &'static str,
) -> Response {
    use crate::response::{Step, StreamGuard};

    let request_id = receipt.request_id.as_str();
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let guard = StreamGuard::new(
        app,
        principal,
        format,
        request_id.to_owned(),
        receipt.started,
        upstream_started,
    );
    // `unfold` turns a state and an async step function into a stream, like an iterator
    // whose `next` may wait. `None` as state means the stream is over.
    let body = futures_util::stream::unfold(Some((upstream, guard)), |state| async move {
        let (mut upstream, mut guard) = state?;
        loop {
            let bytes = match upstream.next_chunk().await {
                Ok(Some(chunk)) => match guard.chunk(&chunk) {
                    Step::Continue(bytes) if bytes.is_empty() => continue,
                    Step::Continue(bytes) => {
                        return Some((
                            Ok::<_, std::convert::Infallible>(bytes),
                            Some((upstream, guard)),
                        ));
                    }
                    Step::Stop(bytes) => bytes,
                },
                Ok(None) => guard.end(),
                Err(error) => {
                    eprintln!("upstream stream: {error}");
                    guard.fail()
                }
            };
            return if bytes.is_empty() {
                None
            } else {
                Some((Ok(bytes), None))
            };
        }
    });
    let mut response = Body::from_stream(body).into_response();
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.extend(upstream_headers);
    add_resguardo_headers(headers, request_id, decision);
    response
}

/// What inspection decided, with the scan report for the receipt.
struct Inspection {
    report: resguardo_core::ScanReport,
    outcome: Inspected,
}

enum Inspected {
    /// The original bytes.
    Allow(Vec<u8>),
    /// The redacted bytes.
    Redact(Vec<u8>),
    Block(BlockCode, Option<DataClass>),
}

/// Scans the texts, asks policy and redacts if needed.
///
/// Scanning is CPU work, so it runs on Tokio's blocking pool instead of an async worker,
/// like handing a heavy task to a separate executor in Java. That needs owned values
/// (`'static`), hence the `Arc` and the cloned principal.
async fn inspect(
    app: Arc<App>,
    principal: Principal,
    parsed: ParsedRequest,
    bytes: Vec<u8>,
) -> Result<Inspection, Failure> {
    let scan_failed = || {
        Failure::block(
            BlockCode::ScanError,
            "the request could not be scanned, so it was not sent",
        )
    };
    tokio::task::spawn_blocking(move || {
        let report = app.pipeline.scan(&parsed.texts).map_err(|error| {
            // Scan errors name settings or patterns, never content.
            eprintln!("scanning: {error}");
            scan_failed()
        })?;
        let outcome = match app.policy.decide(&principal, &report) {
            Decision::Allow { .. } => Inspected::Allow(bytes),
            Decision::Redact { spans, .. } => {
                Inspected::Redact(redact(&bytes, &parsed, &spans).map_err(|error| {
                    eprintln!("redaction: {error}");
                    scan_failed()
                })?)
            }
            Decision::Block { code, class } => Inspected::Block(code, class),
        };
        Ok(Inspection { report, outcome })
    })
    .await
    .map_err(|_| scan_failed())?
}

/// Annex H: the class, never the value.
fn blocked_message(class: Option<DataClass>) -> String {
    match class {
        Some(class) => format!("Request blocked: data class '{class}' is not allowed to leave."),
        None => "Request blocked: some encoded content could not be fully inspected.".to_owned(),
    }
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

fn forwarded(upstream: UpstreamResponse, request_id: &str, decision: &'static str) -> Response {
    let mut response = Body::from(upstream.body).into_response();
    *response.status_mut() = upstream.status;
    let headers = response.headers_mut();
    headers.extend(upstream.headers);
    add_resguardo_headers(headers, request_id, decision);
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
    let body = error_body(format, status, code, &message, request_id);
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

/// Annex H error JSON in the shape of the API that was called. Also the data of the
/// `event: error` that ends a stream.
pub(crate) fn error_body(
    format: Option<ApiFormat>,
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
) -> Value {
    match format {
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
    }
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
