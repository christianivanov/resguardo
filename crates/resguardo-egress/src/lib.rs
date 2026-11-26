//! Egress: the only way out of Resguardo (design document, section 6; threat model T3, T5, T19).
//!
//! It applies its own rules even if scanning or policy were wrong:
//!
//! - only the configured upstream of each provider, at a fixed path, with at most `beta=true`
//!   as query string; the final URL must keep the configured scheme, host and port;
//! - plain HTTP only for upstreams explicitly marked insecure (local hosts, checked by config);
//! - the application's own credentials and every header not on a short allowlist are dropped,
//!   and the real credential is added here;
//! - no redirects, no automatic retries (one receipt, one request), no proxy from the
//!   environment, timeouts, and a size limit on responses read into memory;
//! - TLS through `rustls` with `aws-lc-rs`, preferring the hybrid post-quantum key exchange
//!   (ADR 0006), and certificates verified by the operating system's verifier.
#![forbid(unsafe_code)]

pub mod credential;

use std::collections::BTreeMap;
use std::error::Error as _;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use resguardo_core::config::{Config, Upstream};
use resguardo_core::{BlockCode, Provider};
use url::Url;
use zeroize::Zeroizing;

pub use credential::{CredentialError, ProviderCredential};

/// Upstream path for OpenAI Chat Completions (also `openai_compatible`).
pub const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
/// Upstream path for Anthropic Messages.
pub const MESSAGES_PATH: &str = "/v1/messages";

/// Request headers forwarded to Anthropic. Values are forwarded verbatim because their set
/// changes with every Claude Code release; names are not.
const ANTHROPIC_REQUEST_HEADERS: [&str; 2] = ["anthropic-version", "anthropic-beta"];
const MAX_FORWARDED_HEADER_BYTES: usize = 1024;
const MAX_FORWARDED_HEADER_VALUES: usize = 8;

/// Response headers returned to the application. Everything else (cookies, server details,
/// tracing ids of other systems) is dropped.
const RESPONSE_HEADERS: [&str; 5] = [
    "content-type",
    "retry-after",
    "x-should-retry",
    "request-id",
    "x-request-id",
];
const RESPONSE_HEADER_PREFIXES: [&str; 2] = ["anthropic-ratelimit-", "x-ratelimit-"];

/// Timeouts and limits of the HTTP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressSettings {
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_response_bytes: usize,
}

impl EgressSettings {
    pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn from_config(config: &Config) -> Self {
        let request_timeout = Duration::from_secs(config.server.request_timeout_secs);
        Self {
            request_timeout,
            connect_timeout: Self::MAX_CONNECT_TIMEOUT.min(request_timeout),
            max_response_bytes: config.server.max_response_bytes,
        }
    }
}

/// Why a request could not be sent or its response could not be accepted.
/// Messages name providers, paths and limits; never credentials or request content.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("credential for {provider}: {source}")]
    Credential {
        provider: Provider,
        source: CredentialError,
    },
    #[error("plain HTTP to the {0} upstream requires allow_insecure_upstream")]
    InsecureScheme(Provider),
    #[error("cannot build the HTTP client: {0}")]
    Client(String),
    #[error("no upstream configured for {0}")]
    NoUpstream(Provider),
    #[error("path {path} is not a route of {provider}")]
    InvalidRoute { provider: Provider, path: String },
    #[error("query string not allowed for {0}")]
    QueryNotAllowed(Provider),
    #[error("header {0} has too many values, a value that is too long, or non-ASCII characters")]
    InvalidHeader(&'static str),
    #[error("upstream answered with a redirect (HTTP {0}); redirects are never followed")]
    Redirect(u16),
    #[error("upstream request timed out")]
    Timeout,
    #[error("upstream request failed: {0}")]
    Connection(String),
    #[error("upstream response is larger than {0} bytes")]
    ResponseTooLarge(usize),
    #[error("upstream response is compressed; only identity encoding is accepted")]
    ContentEncoding,
}

impl EgressError {
    /// Error code returned to the application (Annex H).
    pub fn block_code(&self) -> BlockCode {
        match self {
            EgressError::QueryNotAllowed(_)
            | EgressError::InvalidHeader(_)
            | EgressError::InvalidRoute { .. } => BlockCode::InvalidRequest,
            EgressError::Redirect(_) => BlockCode::UpstreamRedirect,
            EgressError::Credential { .. }
            | EgressError::InsecureScheme(_)
            | EgressError::Client(_)
            | EgressError::NoUpstream(_)
            | EgressError::Timeout
            | EgressError::Connection(_)
            | EgressError::ResponseTooLarge(_)
            | EgressError::ContentEncoding => BlockCode::UpstreamError,
        }
    }

    fn from_reqwest(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            return EgressError::Timeout;
        }
        // The top-level message is generic ("error sending request"); the cause is in the
        // chain (connection refused, certificate rejected…). The URL is dropped: it holds no
        // secret, but the message does not need it.
        let error = error.without_url();
        let mut message = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        EgressError::Connection(message)
    }
}

/// A request ready to leave, after scanning and policy.
#[derive(Debug)]
pub struct OutboundRequest<'a> {
    pub provider: Provider,
    /// [`CHAT_COMPLETIONS_PATH`] or [`MESSAGES_PATH`].
    pub path: &'a str,
    pub query: Option<&'a str>,
    /// The application's headers, all of them: egress keeps only the allowlisted ones.
    pub incoming_headers: &'a HeaderMap,
    /// Sent exactly as given.
    pub body: Vec<u8>,
}

/// What a stream request got back.
#[derive(Debug)]
pub enum UpstreamAnswer {
    /// Not an SSE stream (a provider error, for example), read whole.
    Whole(UpstreamResponse),
    Stream(UpstreamStream),
}

/// An SSE response being read. Bytes are counted against `max_response_bytes`.
#[derive(Debug)]
pub struct UpstreamStream {
    status: StatusCode,
    headers: HeaderMap,
    response: reqwest::Response,
    read: usize,
    max_bytes: usize,
}

impl UpstreamStream {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Only the allowlisted response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The next chunk, or `None` at the end. A stream silent for the request timeout fails
    /// with [`EgressError::Timeout`].
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, EgressError> {
        let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(EgressError::from_reqwest)?
        else {
            return Ok(None);
        };
        self.read += chunk.len();
        if self.read > self.max_bytes {
            return Err(EgressError::ResponseTooLarge(self.max_bytes));
        }
        Ok(Some(chunk.to_vec()))
    }
}

/// A complete, non-streamed upstream response.
#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: StatusCode,
    /// Only the allowlisted response headers.
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct Destination {
    base_url: Url,
    insecure: bool,
    credential: Option<ProviderCredential>,
}

/// The HTTP client and the destinations it may reach.
#[derive(Debug)]
pub struct Egress {
    client: reqwest::Client,
    destinations: BTreeMap<Provider, Destination>,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl Egress {
    /// Loads every credential. Any failure stops Resguardo from starting (ADR 0002).
    pub fn from_config(config: &Config) -> Result<Self, EgressError> {
        Self::new(&config.upstreams, EgressSettings::from_config(config))
    }

    pub fn new(
        upstreams: &BTreeMap<Provider, Upstream>,
        settings: EgressSettings,
    ) -> Result<Self, EgressError> {
        let mut destinations = BTreeMap::new();
        for (provider, upstream) in upstreams {
            if upstream.base_url.scheme() != "https" && !upstream.insecure {
                return Err(EgressError::InsecureScheme(*provider));
            }
            let credential = upstream
                .credential
                .as_ref()
                .map(credential::load)
                .transpose()
                .map_err(|source| EgressError::Credential {
                    provider: *provider,
                    source,
                })?;
            destinations.insert(
                *provider,
                Destination {
                    base_url: upstream.base_url.clone(),
                    insecure: upstream.insecure,
                    credential,
                },
            );
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .referer(false)
            // Idle timeout: each read must arrive within it. Non-streamed requests also get a
            // total timeout of the same length, per request (ADR 0014).
            .read_timeout(settings.request_timeout)
            .connect_timeout(settings.connect_timeout)
            .user_agent(concat!("resguardo/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| EgressError::Client(e.to_string()))?;
        Ok(Self {
            client,
            destinations,
            request_timeout: settings.request_timeout,
            max_response_bytes: settings.max_response_bytes,
        })
    }

    /// The exact URL a request would go to. Fails for any route, query or origin that is not
    /// the configured one.
    pub fn url(
        &self,
        provider: Provider,
        path: &str,
        query: Option<&str>,
    ) -> Result<Url, EgressError> {
        let destination = self.destination(provider)?;
        let expected_path = match provider {
            Provider::Anthropic => MESSAGES_PATH,
            Provider::OpenAi | Provider::OpenAiCompatible => CHAT_COMPLETIONS_PATH,
        };
        if path != expected_path {
            return Err(EgressError::InvalidRoute {
                provider,
                path: path.to_owned(),
            });
        }
        let query = match (provider, query) {
            (_, None | Some("")) => None,
            (Provider::Anthropic, Some("beta=true")) => Some("beta=true"),
            _ => return Err(EgressError::QueryNotAllowed(provider)),
        };

        let mut url = destination.base_url.clone();
        let full_path = format!("{}{path}", url.path().trim_end_matches('/'));
        url.set_path(&full_path);
        url.set_query(query);

        // Defence in depth: whatever happened above, the URL must keep the configured origin.
        if url.origin() != destination.base_url.origin() {
            return Err(EgressError::InvalidRoute {
                provider,
                path: path.to_owned(),
            });
        }
        if url.scheme() != "https" && !destination.insecure {
            return Err(EgressError::InsecureScheme(provider));
        }
        Ok(url)
    }

    /// Sends one request and reads the whole response, up to `max_response_bytes`, within
    /// the total request timeout.
    pub async fn send(
        &self,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamResponse, EgressError> {
        let response = self.start(request, Some(self.request_timeout)).await?;
        read_response(response, self.max_response_bytes).await
    }

    /// Sends a stream request. An SSE answer is returned as a stream with no total timeout,
    /// only the idle one (ADR 0014); anything else, such as a provider error, is read whole.
    pub async fn send_streaming(
        &self,
        request: OutboundRequest<'_>,
    ) -> Result<UpstreamAnswer, EgressError> {
        let response = self.start(request, None).await?;
        check_head(&response, self.max_response_bytes)?;
        let is_sse = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
            });
        if response.status().is_success() && is_sse {
            Ok(UpstreamAnswer::Stream(UpstreamStream {
                status: response.status(),
                headers: returned_response_headers(response.headers()),
                response,
                read: 0,
                max_bytes: self.max_response_bytes,
            }))
        } else {
            read_response(response, self.max_response_bytes)
                .await
                .map(UpstreamAnswer::Whole)
        }
    }

    async fn start(
        &self,
        request: OutboundRequest<'_>,
        total_timeout: Option<Duration>,
    ) -> Result<reqwest::Response, EgressError> {
        let url = self.url(request.provider, request.path, request.query)?;
        let destination = self.destination(request.provider)?;

        let mut headers = forwarded_request_headers(request.provider, request.incoming_headers)?;
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(credential) = &destination.credential {
            let (name, value) = auth_header(request.provider, credential)?;
            headers.insert(name, value);
        }

        let mut builder = self.client.post(url).headers(headers).body(request.body);
        if let Some(timeout) = total_timeout {
            builder = builder.timeout(timeout);
        }
        builder.send().await.map_err(EgressError::from_reqwest)
    }

    fn destination(&self, provider: Provider) -> Result<&Destination, EgressError> {
        self.destinations
            .get(&provider)
            .ok_or(EgressError::NoUpstream(provider))
    }
}

/// Keeps only the allowlisted request headers. In particular `Authorization`, `x-api-key`
/// (the virtual key), cookies and forwarding headers never leave.
pub fn forwarded_request_headers(
    provider: Provider,
    incoming: &HeaderMap,
) -> Result<HeaderMap, EgressError> {
    let mut forwarded = HeaderMap::new();
    if provider != Provider::Anthropic {
        return Ok(forwarded);
    }
    for name in ANTHROPIC_REQUEST_HEADERS {
        let values = incoming.get_all(name);
        if values.iter().count() > MAX_FORWARDED_HEADER_VALUES {
            return Err(EgressError::InvalidHeader(name));
        }
        for value in values {
            let bytes = value.as_bytes();
            let valid = bytes.len() <= MAX_FORWARDED_HEADER_BYTES
                && bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
            if !valid {
                return Err(EgressError::InvalidHeader(name));
            }
            forwarded.append(HeaderName::from_static(name), value.clone());
        }
    }
    Ok(forwarded)
}

/// Keeps only the allowlisted response headers.
pub fn returned_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut returned = HeaderMap::new();
    for (name, value) in upstream {
        let name_str = name.as_str();
        let allowed = RESPONSE_HEADERS.contains(&name_str)
            || RESPONSE_HEADER_PREFIXES
                .iter()
                .any(|prefix| name_str.starts_with(prefix));
        if allowed {
            returned.append(name.clone(), value.clone());
        }
    }
    returned
}

/// OpenAI and OpenAI-compatible servers take `Authorization: Bearer`, Anthropic `x-api-key`.
/// The header value is marked sensitive, so the HTTP stack never prints it.
fn auth_header(
    provider: Provider,
    credential: &ProviderCredential,
) -> Result<(HeaderName, HeaderValue), EgressError> {
    let (name, value) = match provider {
        Provider::Anthropic => (
            HeaderName::from_static("x-api-key"),
            Zeroizing::new(credential.expose().to_owned()),
        ),
        Provider::OpenAi | Provider::OpenAiCompatible => (
            header::AUTHORIZATION,
            Zeroizing::new(format!("Bearer {}", credential.expose())),
        ),
    };
    // Cannot fail: credentials are checked to be visible ASCII when loaded.
    let mut value = HeaderValue::from_str(&value)
        .map_err(|_| EgressError::Client("credential is not a valid header value".into()))?;
    value.set_sensitive(true);
    Ok((name, value))
}

/// No redirects, no compressed bodies, no declared size over the limit.
fn check_head(response: &reqwest::Response, max_bytes: usize) -> Result<(), EgressError> {
    let status = response.status();
    if status.is_redirection() {
        return Err(EgressError::Redirect(status.as_u16()));
    }
    // The scanner must read the same bytes the application gets, so no compressed bodies.
    // Requests carry no `accept-encoding`, so a compressed answer is unexpected anyway.
    if let Some(encoding) = response.headers().get(header::CONTENT_ENCODING)
        && encoding.as_bytes() != b"identity"
    {
        return Err(EgressError::ContentEncoding);
    }
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |l| l > max_bytes))
    {
        return Err(EgressError::ResponseTooLarge(max_bytes));
    }
    Ok(())
}

async fn read_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<UpstreamResponse, EgressError> {
    check_head(&response, max_bytes)?;
    let status = response.status();
    let too_large = EgressError::ResponseTooLarge(max_bytes);
    let headers = returned_response_headers(response.headers());
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(EgressError::from_reqwest)? {
        if body.len() + chunk.len() > max_bytes {
            return Err(too_large);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use rustls::crypto::SupportedKxGroup;

    use super::*;

    #[test]
    fn post_quantum_key_exchange_is_offered_first() {
        // reqwest uses this provider when no other is installed, and nothing installs one.
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let first: &dyn SupportedKxGroup = provider.kx_groups[0];
        assert_eq!(first.name(), rustls::NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn only_allowlisted_request_headers_are_forwarded() {
        let mut incoming = HeaderMap::new();
        for (name, value) in [
            ("authorization", "Bearer rsg_virtual"),
            ("x-api-key", "rsg_virtual"),
            ("cookie", "session=1"),
            ("x-forwarded-for", "10.0.0.1"),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "a-2026-01-01,b-2026-02-01"),
            ("anthropic-unknown", "x"),
        ] {
            incoming.append(name, HeaderValue::from_static(value));
        }
        let forwarded = forwarded_request_headers(Provider::Anthropic, &incoming).unwrap();
        let names: Vec<&str> = forwarded.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["anthropic-version", "anthropic-beta"]);
        assert_eq!(forwarded["anthropic-beta"], "a-2026-01-01,b-2026-02-01");
        assert!(
            forwarded_request_headers(Provider::OpenAi, &incoming)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn oversized_or_repeated_forwarded_headers_are_rejected() {
        let mut long = HeaderMap::new();
        let value = "a".repeat(MAX_FORWARDED_HEADER_BYTES + 1);
        long.insert("anthropic-beta", HeaderValue::from_str(&value).unwrap());
        assert!(matches!(
            forwarded_request_headers(Provider::Anthropic, &long),
            Err(EgressError::InvalidHeader("anthropic-beta"))
        ));

        let mut repeated = HeaderMap::new();
        for _ in 0..=MAX_FORWARDED_HEADER_VALUES {
            repeated.append("anthropic-beta", HeaderValue::from_static("x"));
        }
        assert!(forwarded_request_headers(Provider::Anthropic, &repeated).is_err());

        let mut non_ascii = HeaderMap::new();
        non_ascii.insert(
            "anthropic-beta",
            HeaderValue::from_bytes(b"caf\xc3\xa9").unwrap(),
        );
        assert!(forwarded_request_headers(Provider::Anthropic, &non_ascii).is_err());
    }

    #[test]
    fn only_allowlisted_response_headers_are_returned() {
        let mut upstream = HeaderMap::new();
        for (name, value) in [
            ("content-type", "application/json"),
            ("retry-after", "3"),
            ("x-should-retry", "true"),
            ("request-id", "req_1"),
            ("anthropic-ratelimit-unified-status", "allowed"),
            ("x-ratelimit-remaining-requests", "10"),
            ("set-cookie", "track=1"),
            ("server", "cloudflare"),
            ("content-length", "10"),
        ] {
            upstream.append(name, HeaderValue::from_static(value));
        }
        let returned = returned_response_headers(&upstream);
        let mut names: Vec<&str> = returned.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "anthropic-ratelimit-unified-status",
                "content-type",
                "request-id",
                "retry-after",
                "x-ratelimit-remaining-requests",
                "x-should-retry",
            ]
        );
    }

    #[test]
    fn upstream_errors_map_to_annex_h() {
        assert_eq!(
            EgressError::Redirect(302).block_code(),
            BlockCode::UpstreamRedirect
        );
        assert_eq!(EgressError::Timeout.block_code(), BlockCode::UpstreamError);
        assert_eq!(
            EgressError::InvalidHeader("anthropic-beta").block_code(),
            BlockCode::InvalidRequest
        );
    }
}
