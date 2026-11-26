//! Configuration loading and validation (design document, Annex E).
//!
//! Parsing is pure: [`Config::from_toml_str`] takes the file contents and never touches the
//! filesystem or the environment. Reading files and checking their permissions belongs to the
//! binary and to `resguardo-egress`.
//!
//! Every problem is collected, not just the first one, so `resguardo config check` can report
//! them all at once. Any problem means Resguardo does not start (ADR 0002).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use url::{Host, Url};

use crate::domain::{
    Action, DataClass, Limits, Principal, PrincipalId, Provider, ScanLimit, StreamMode,
    VirtualKeyHash,
};

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML syntax error, unknown field, wrong type or missing required field.
    /// The message includes line and column.
    #[error("{0}")]
    Syntax(String),
    /// The file parsed, but its values are not acceptable.
    #[error("{}", format_problems(.0))]
    Invalid(Vec<String>),
}

fn format_problems(problems: &[String]) -> String {
    let mut out = String::from("invalid configuration:");
    for problem in problems {
        out.push_str("\n  - ");
        out.push_str(problem);
    }
    out
}

/// A validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub audit: AuditConfig,
    pub scan: ScanConfig,
    pub stream: StreamConfig,
    /// Global action for every request data class (`DataClass::REQUEST_CLASSES`).
    pub actions: BTreeMap<DataClass, Action>,
    /// Global action for every limit flag (`ScanLimit::ALL`), with the defaults of ADR 0012
    /// for those the file does not set.
    pub scan_limits: BTreeMap<ScanLimit, Action>,
    pub response: ResponseConfig,
    pub upstreams: BTreeMap<Provider, Upstream>,
    pub principals: Vec<ConfiguredPrincipal>,
    /// Accepted but worth printing at startup (insecure upstream, public listen address…).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub max_body_bytes: usize,
    pub request_timeout_secs: u64,
    /// Largest non-streamed upstream response that is read into memory.
    pub max_response_bytes: usize,
}

impl ServerConfig {
    pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8787)),
            max_body_bytes: Limits::DEFAULT_MAX_BODY_BYTES,
            request_timeout_secs: 120,
            max_response_bytes: Self::DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default = "default_true")]
    pub fsync: bool,
    pub signing_key: PathBuf,
    pub public_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub max_decode_depth: u8,
    pub max_derived_bytes: usize,
    /// Bits per character. A float is fine here: it never reaches the audit log.
    pub entropy_threshold: f64,
    pub entropy_min_len: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_decode_depth: 2,
            max_derived_bytes: 65_536,
            entropy_threshold: 4.5,
            entropy_min_len: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamConfig {
    pub overlap_bytes: usize,
    pub buffer_flush_bytes: usize,
    /// Largest SSE event, and line, a stream may carry (ADR 0014).
    pub max_event_bytes: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            overlap_bytes: 256,
            buffer_flush_bytes: 2048,
            max_event_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    pub strip_remote_images: bool,
    pub strip_links_outside: bool,
    /// Exact hostnames, lowercase ASCII (punycode for internationalized names).
    pub allowed_link_hosts: Vec<String>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            strip_remote_images: true,
            strip_links_outside: true,
            allowed_link_hosts: Vec::new(),
        }
    }
}

/// An egress destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub provider: Provider,
    /// Scheme, host, optional port and optional path prefix, without a trailing slash.
    pub base_url: Url,
    /// `None` only for `openai_compatible` (ADR 0005).
    pub credential: Option<CredentialSource>,
    /// Plain HTTP to a local host, explicitly allowed.
    pub insecure: bool,
}

/// Where the provider credential is read from. Only the location lives in the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    Env(String),
    File(PathBuf),
}

/// A principal together with the hash of its virtual key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPrincipal {
    pub key_hash: VirtualKeyHash,
    pub principal: Principal,
}

impl Config {
    /// Parses and validates the contents of a configuration file.
    pub fn from_toml_str(source: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            toml::from_str(source).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        raw.validate()
    }
}

// ---------------------------------------------------------------------------------------------
// Raw shapes, exactly as written in the file. `deny_unknown_fields` makes a typo an error
// instead of a silently ignored setting.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: ServerConfig,
    audit: AuditConfig,
    #[serde(default)]
    scan: ScanConfig,
    #[serde(default)]
    stream: StreamConfig,
    policy: RawPolicy,
    #[serde(default)]
    response: ResponseConfig,
    #[serde(default)]
    upstream: Vec<RawUpstream>,
    #[serde(default)]
    principal: Vec<RawPrincipal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    actions: BTreeMap<DataClass, Action>,
    #[serde(default)]
    scan_limits: BTreeMap<ScanLimit, Action>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstream {
    provider: Provider,
    base_url: String,
    credential_env: Option<String>,
    credential_file: Option<PathBuf>,
    #[serde(default)]
    allow_insecure_upstream: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrincipal {
    id: String,
    key_sha256: String,
    #[serde(default)]
    stream_mode: StreamMode,
    requests_per_minute: Option<u32>,
    max_body_bytes: Option<usize>,
    max_messages: Option<usize>,
    #[serde(default)]
    models: BTreeMap<Provider, Vec<String>>,
    #[serde(default)]
    actions: BTreeMap<DataClass, Action>,
    #[serde(default)]
    scan_limits: BTreeMap<ScanLimit, Action>,
    expires_at: Option<String>,
}

fn default_true() -> bool {
    true
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        let mut problems = Vec::new();
        let mut warnings = Vec::new();

        validate_server(&self.server, &mut problems, &mut warnings);
        validate_scan(&self.scan, &mut problems);
        validate_stream(&self.stream, &mut problems);
        validate_actions(
            "[policy.actions]",
            &self.policy.actions,
            true,
            &mut problems,
        );
        validate_scan_limits(
            "[policy.scan_limits] ",
            &self.policy.scan_limits,
            &mut problems,
        );
        let mut scan_limits = self.policy.scan_limits;
        for limit in ScanLimit::ALL {
            scan_limits
                .entry(limit)
                .or_insert_with(|| limit.default_action());
        }
        let response = validate_response(self.response, &mut problems);
        // Declared even if invalid, so one bad upstream does not cascade into model errors.
        let declared: BTreeSet<Provider> = self.upstream.iter().map(|u| u.provider).collect();
        let upstreams = validate_upstreams(self.upstream, &mut problems, &mut warnings);
        let principals = validate_principals(
            self.principal,
            &declared,
            self.server.max_body_bytes,
            &mut problems,
        );
        if principals.is_empty() && problems.is_empty() {
            warnings.push("no [[principal]] configured: every request will be rejected".into());
        }

        if !problems.is_empty() {
            return Err(ConfigError::Invalid(problems));
        }
        Ok(Config {
            server: self.server,
            audit: self.audit,
            scan: self.scan,
            stream: self.stream,
            actions: self.policy.actions,
            scan_limits,
            response,
            upstreams,
            principals,
            warnings,
        })
    }
}

fn validate_server(server: &ServerConfig, problems: &mut Vec<String>, warnings: &mut Vec<String>) {
    if server.max_body_bytes == 0 {
        problems.push("[server] max_body_bytes must be greater than 0".into());
    }
    if server.request_timeout_secs == 0 {
        problems.push("[server] request_timeout_secs must be greater than 0".into());
    }
    if server.max_response_bytes == 0 {
        problems.push("[server] max_response_bytes must be greater than 0".into());
    }
    if !server.listen.ip().is_loopback() {
        warnings.push(format!(
            "[server] listen = {} is reachable from other machines; protect it at the network level",
            server.listen
        ));
    }
}

fn validate_scan(scan: &ScanConfig, problems: &mut Vec<String>) {
    problems.extend(scan.problems());
}

impl ScanConfig {
    /// Every reason these values are not acceptable; empty if they are. Public so the scanner
    /// can refuse values that did not come through [`Config::from_toml_str`].
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.max_decode_depth > 8 {
            problems.push("[scan] max_decode_depth must be at most 8".into());
        }
        if self.max_derived_bytes == 0 {
            problems.push("[scan] max_derived_bytes must be greater than 0".into());
        }
        if !(self.entropy_threshold.is_finite()
            && self.entropy_threshold > 0.0
            && self.entropy_threshold <= 8.0)
        {
            problems
                .push("[scan] entropy_threshold must be between 0 and 8 bits per character".into());
        }
        if self.entropy_min_len < 8 {
            problems.push("[scan] entropy_min_len must be at least 8".into());
        }
        problems
    }
}

fn validate_stream(stream: &StreamConfig, problems: &mut Vec<String>) {
    if stream.overlap_bytes == 0 {
        problems.push("[stream] overlap_bytes must be greater than 0".into());
    }
    if stream.buffer_flush_bytes == 0 {
        problems.push("[stream] buffer_flush_bytes must be greater than 0".into());
    }
    if stream.max_event_bytes == 0 {
        problems.push("[stream] max_event_bytes must be greater than 0".into());
    }
}

/// Limit flags accept `flag` or `block` only (ADR 0012): a limit is always recorded, and
/// redacting a whole encoded fragment is not supported.
fn validate_scan_limits(
    prefix: &str,
    scan_limits: &BTreeMap<ScanLimit, Action>,
    problems: &mut Vec<String>,
) {
    for (limit, action) in scan_limits {
        if !matches!(action, Action::Flag | Action::Block) {
            problems.push(format!("{prefix}{limit} must be \"flag\" or \"block\""));
        }
    }
}

/// `require_all`: the global table must give an action to every request class.
fn validate_actions(
    location: &str,
    actions: &BTreeMap<DataClass, Action>,
    require_all: bool,
    problems: &mut Vec<String>,
) {
    for class in actions.keys() {
        if !DataClass::REQUEST_CLASSES.contains(class) {
            problems.push(format!(
                "{location} cannot set '{class}': it is controlled by [response]"
            ));
        }
    }
    if require_all {
        let missing: Vec<&str> = DataClass::REQUEST_CLASSES
            .iter()
            .filter(|class| !actions.contains_key(class))
            .map(|class| class.as_str())
            .collect();
        if !missing.is_empty() {
            problems.push(format!(
                "{location} has no action for: {}",
                missing.join(", ")
            ));
        }
    }
}

fn validate_response(mut response: ResponseConfig, problems: &mut Vec<String>) -> ResponseConfig {
    for host in &mut response.allowed_link_hosts {
        let valid = !host.is_empty()
            && host.is_ascii()
            && !host.starts_with('.')
            && !host.ends_with('.')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if valid {
            host.make_ascii_lowercase();
        } else {
            problems.push(format!(
                "[response] allowed_link_hosts entry '{host}' must be a bare hostname \
                 (no scheme, path, port or wildcard; punycode for non-ASCII names)"
            ));
        }
    }
    response
}

fn validate_upstreams(
    raw: Vec<RawUpstream>,
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> BTreeMap<Provider, Upstream> {
    let mut upstreams = BTreeMap::new();
    if raw.is_empty() {
        problems.push("no [[upstream]] configured: there is nowhere to send requests".into());
    }
    for (index, upstream) in raw.into_iter().enumerate() {
        let location = format!("[[upstream]] #{} ({})", index + 1, upstream.provider);
        if upstreams.contains_key(&upstream.provider) {
            problems.push(format!(
                "{location}: only one upstream per provider is allowed in v0.1"
            ));
            continue;
        }
        let credential = validate_credential(&location, &upstream, problems);
        let Some(base_url) = validate_base_url(&location, &upstream, problems, warnings) else {
            continue;
        };
        upstreams.insert(
            upstream.provider,
            Upstream {
                provider: upstream.provider,
                base_url,
                credential,
                insecure: upstream.allow_insecure_upstream,
            },
        );
    }
    upstreams
}

fn validate_credential(
    location: &str,
    upstream: &RawUpstream,
    problems: &mut Vec<String>,
) -> Option<CredentialSource> {
    match (&upstream.credential_env, &upstream.credential_file) {
        (Some(_), Some(_)) => {
            problems.push(format!(
                "{location}: credential_env and credential_file are mutually exclusive"
            ));
            None
        }
        (Some(name), None) => {
            if is_env_var_name(name) {
                Some(CredentialSource::Env(name.clone()))
            } else {
                problems.push(format!(
                    "{location}: credential_env '{name}' is not a valid environment variable name"
                ));
                None
            }
        }
        (None, Some(path)) => Some(CredentialSource::File(path.clone())),
        (None, None) => {
            if upstream.provider != Provider::OpenAiCompatible {
                problems.push(format!(
                    "{location}: credential_env or credential_file is required"
                ));
            }
            None
        }
    }
}

fn is_env_var_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn validate_base_url(
    location: &str,
    upstream: &RawUpstream,
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<Url> {
    let mut url = match Url::parse(&upstream.base_url) {
        Ok(url) => url,
        Err(e) => {
            problems.push(format!(
                "{location}: base_url '{}' is not a valid URL: {e}",
                upstream.base_url
            ));
            return None;
        }
    };
    let before = problems.len();
    let local = is_local_host(&url);

    match url.scheme() {
        "https" => {}
        "http" if upstream.allow_insecure_upstream && local => warnings.push(format!(
            "{location}: plain HTTP to {} (allow_insecure_upstream)",
            upstream.base_url
        )),
        "http" => problems.push(format!(
            "{location}: base_url must use https:// (plain http only with \
             allow_insecure_upstream = true and a local host)"
        )),
        other => problems.push(format!(
            "{location}: base_url scheme '{other}' is not allowed; use https://"
        )),
    }
    if upstream.allow_insecure_upstream && !local {
        problems.push(format!(
            "{location}: allow_insecure_upstream is only accepted for localhost, 127.0.0.0/8 or ::1"
        ));
    }
    if url.host().is_none() {
        problems.push(format!("{location}: base_url has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        problems.push(format!(
            "{location}: base_url must not contain user information"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        problems.push(format!(
            "{location}: base_url must not contain a query or fragment"
        ));
    }
    if problems.len() > before {
        return None;
    }
    let trimmed = url.path().trim_end_matches('/').to_owned();
    url.set_path(&trimmed);
    Some(url)
}

fn is_local_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn validate_principals(
    raw: Vec<RawPrincipal>,
    declared_upstreams: &BTreeSet<Provider>,
    server_max_body_bytes: usize,
    problems: &mut Vec<String>,
) -> Vec<ConfiguredPrincipal> {
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut principals = Vec::new();

    for (index, principal) in raw.into_iter().enumerate() {
        let location = format!("[[principal]] #{} ('{}')", index + 1, principal.id);
        let before = problems.len();

        let id = PrincipalId::parse(&principal.id);
        match &id {
            None => problems.push(format!(
                "{location}: id must be 1 to 64 characters of a-z, 0-9, '-' or '_', \
                 starting with a letter or digit"
            )),
            Some(id) if !seen_ids.insert(id.clone()) => {
                problems.push(format!("{location}: duplicate id"));
            }
            Some(_) => {}
        }

        let key_hash = VirtualKeyHash::parse(&principal.key_sha256);
        match &key_hash {
            None => problems.push(format!(
                "{location}: key_sha256 must be 64 lowercase hexadecimal characters"
            )),
            Some(hash) if !seen_keys.insert(hash.clone()) => problems.push(format!(
                "{location}: key_sha256 is already used by another principal"
            )),
            Some(_) => {}
        }

        let expires_at = principal
            .expires_at
            .as_deref()
            .and_then(|value| parse_expiry(&location, value, problems));

        validate_models(&location, &principal.models, declared_upstreams, problems);
        validate_actions(&location, &principal.actions, false, problems);
        validate_scan_limits(
            &format!("{location}: scan_limits."),
            &principal.scan_limits,
            problems,
        );

        let limits = Limits {
            max_body_bytes: principal.max_body_bytes.unwrap_or(server_max_body_bytes),
            max_messages: principal
                .max_messages
                .unwrap_or(Limits::DEFAULT_MAX_MESSAGES),
            requests_per_minute: principal
                .requests_per_minute
                .unwrap_or(Limits::DEFAULT_REQUESTS_PER_MINUTE),
        };
        if limits.max_body_bytes == 0 || limits.max_body_bytes > server_max_body_bytes {
            problems.push(format!(
                "{location}: max_body_bytes must be between 1 and [server] max_body_bytes \
                 ({server_max_body_bytes})"
            ));
        }
        if limits.max_messages == 0 {
            problems.push(format!("{location}: max_messages must be greater than 0"));
        }
        if limits.requests_per_minute == 0 {
            problems.push(format!(
                "{location}: requests_per_minute must be greater than 0"
            ));
        }

        if let (true, Some(key_hash), Some(id)) = (problems.len() == before, key_hash, id) {
            principals.push(ConfiguredPrincipal {
                key_hash,
                principal: Principal {
                    id,
                    allowed: principal.models,
                    limits,
                    actions: principal.actions,
                    scan_limits: principal.scan_limits,
                    stream_mode: principal.stream_mode,
                    expires_at,
                },
            });
        }
    }
    principals
}

/// RFC 3339 with an explicit offset, normalized to UTC. A date without a time or offset is
/// rejected: "2027-02-09" would leave it unclear in which time zone the key stops working.
fn parse_expiry(location: &str, value: &str, problems: &mut Vec<String>) -> Option<OffsetDateTime> {
    match OffsetDateTime::parse(value, &Rfc3339) {
        Ok(instant) => Some(instant.to_offset(UtcOffset::UTC)),
        Err(_) => {
            problems.push(format!(
                "{location}: expires_at '{value}' must be an RFC 3339 timestamp with an offset, \
                 for example 2027-02-09T00:00:00Z"
            ));
            None
        }
    }
}

fn validate_models(
    location: &str,
    models: &BTreeMap<Provider, Vec<String>>,
    declared_upstreams: &BTreeSet<Provider>,
    problems: &mut Vec<String>,
) {
    if models.values().all(Vec::is_empty) {
        problems.push(format!(
            "{location}: no models allowed (set models.<provider>)"
        ));
    }
    for (provider, list) in models {
        if !declared_upstreams.contains(provider) {
            problems.push(format!(
                "{location}: models.{provider} is set but there is no [[upstream]] for {provider}"
            ));
        }
        let mut seen = BTreeSet::new();
        for model in list {
            if model.trim().is_empty() || model.trim() != model {
                problems.push(format!(
                    "{location}: models.{provider} has an empty or padded model name"
                ));
            } else if !seen.insert(model) {
                problems.push(format!(
                    "{location}: models.{provider} lists '{model}' twice"
                ));
            }
        }
    }
    // Both use POST /v1/chat/completions; the model decides the route (ADR 0005).
    if let (Some(openai), Some(compatible)) = (
        models.get(&Provider::OpenAi),
        models.get(&Provider::OpenAiCompatible),
    ) {
        for model in openai.iter().filter(|m| compatible.contains(m)) {
            problems.push(format!(
                "{location}: '{model}' is listed under both openai and openai_compatible, \
                 so the route would be ambiguous"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    const BASE: &str = r#"
[audit]
path = "./data/audit.jsonl"
signing_key = "./data/signing.key"
public_key = "./data/signing.pub"

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"
"#;

    const OPENAI_UPSTREAM: &str = r#"
[[upstream]]
provider = "openai"
base_url = "https://api.openai.com"
credential_env = "OPENAI_API_KEY"
"#;

    fn principal(id: &str, key: &str, extra: &str) -> String {
        format!(
            "\n[[principal]]\nid = \"{id}\"\nkey_sha256 = \"{key}\"\nmodels.openai = [\"gpt-4.1-mini\"]\n{extra}\n"
        )
    }

    fn parse(parts: &[&str]) -> Result<Config, ConfigError> {
        Config::from_toml_str(&parts.concat())
    }

    /// Asserts the config is rejected and some problem mentions `needle`.
    fn assert_rejected(parts: &[&str], needle: &str) {
        match parse(parts) {
            Ok(_) => panic!("expected rejection mentioning {needle:?}"),
            Err(e) => {
                let message = e.to_string();
                assert!(
                    message.contains(needle),
                    "expected {needle:?} in:\n{message}"
                );
            }
        }
    }

    #[test]
    fn example_config_is_valid() {
        let source = include_str!("../../../config/resguardo.example.toml");
        let config = Config::from_toml_str(source).unwrap();
        assert_eq!(config.server.listen.to_string(), "127.0.0.1:8787");
        assert!(config.audit.fsync);
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.principals.len(), 1);
        let support = &config.principals[0].principal;
        assert_eq!(support.id.as_str(), "support-bot");
        assert_eq!(support.actions.get(&DataClass::Email), Some(&Action::Allow));
        assert_eq!(support.limits, Limits::default());
        assert_eq!(support.stream_mode, StreamMode::PassthroughAbort);
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    }

    #[test]
    fn scan_limits_default_to_block_depth_and_flag_size() {
        let p = principal("bot", KEY_A, "");
        let config = parse(&[BASE, OPENAI_UPSTREAM, &p]).unwrap();
        assert_eq!(
            config.scan_limits,
            BTreeMap::from([
                (ScanLimit::DecodeDepth, Action::Block),
                (ScanLimit::DerivedBytes, Action::Flag),
            ])
        );
        assert!(config.principals[0].principal.scan_limits.is_empty());
    }

    #[test]
    fn scan_limits_can_be_set_globally_and_per_principal() {
        let global = "\n[policy.scan_limits]\ndecode_depth = \"flag\"\n";
        let p = principal("bot", KEY_A, "scan_limits.derived_bytes = \"block\"");
        let config = parse(&[BASE, global, OPENAI_UPSTREAM, &p]).unwrap();
        assert_eq!(
            config.scan_limits,
            BTreeMap::from([
                (ScanLimit::DecodeDepth, Action::Flag),
                (ScanLimit::DerivedBytes, Action::Flag),
            ])
        );
        assert_eq!(
            config.principals[0].principal.scan_limits,
            BTreeMap::from([(ScanLimit::DerivedBytes, Action::Block)])
        );
    }

    #[test]
    fn scan_limits_accept_only_flag_and_block() {
        for value in ["allow", "redact"] {
            let global = format!("\n[policy.scan_limits]\ndecode_depth = \"{value}\"\n");
            assert_rejected(
                &[BASE, &global, OPENAI_UPSTREAM],
                "[policy.scan_limits] decode_depth must be \"flag\" or \"block\"",
            );
            let p = principal(
                "bot",
                KEY_A,
                &format!("scan_limits.derived_bytes = \"{value}\""),
            );
            assert_rejected(
                &[BASE, OPENAI_UPSTREAM, &p],
                "scan_limits.derived_bytes must be \"flag\" or \"block\"",
            );
        }
    }

    #[test]
    fn unknown_scan_limits_are_rejected() {
        let global = "\n[policy.scan_limits]\ndepth = \"block\"\n";
        assert_rejected(&[BASE, global, OPENAI_UPSTREAM], "depth");
    }

    #[test]
    fn max_event_bytes_defaults_to_1_mib_and_must_be_positive() {
        assert_eq!(StreamConfig::default().max_event_bytes, 1024 * 1024);
        let stream = "\n[stream]\nmax_event_bytes = 0\n";
        assert_rejected(
            &[BASE, stream, OPENAI_UPSTREAM],
            "[stream] max_event_bytes must be greater than 0",
        );
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let p = principal("bot", KEY_A, "");
        let config = parse(&[BASE, OPENAI_UPSTREAM, &p]).unwrap();
        assert_eq!(config.server, ServerConfig::default());
        assert_eq!(config.scan, ScanConfig::default());
        assert_eq!(config.stream, StreamConfig::default());
        assert!(config.response.strip_remote_images);
        let upstream = &config.upstreams[&Provider::OpenAi];
        assert_eq!(upstream.base_url.as_str(), "https://api.openai.com/");
        assert_eq!(
            upstream.credential,
            Some(CredentialSource::Env("OPENAI_API_KEY".into()))
        );
    }

    #[test]
    fn syntax_errors_report_the_line() {
        let source = format!("{BASE}{OPENAI_UPSTREAM}\n[server]\nlisten = 8787\n");
        let message = Config::from_toml_str(&source).unwrap_err().to_string();
        assert!(message.contains("line"), "{message}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let p = principal("bot", KEY_A, "requests_per_hour = 5");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &p], "requests_per_hour");
    }

    #[test]
    fn unknown_data_class_is_rejected() {
        let p = principal("bot", KEY_A, "actions.passport = \"block\"");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &p], "passport");
    }

    #[test]
    fn missing_global_action_is_rejected() {
        let base = BASE.replace("card = \"block\"\n", "");
        let p = principal("bot", KEY_A, "");
        assert_rejected(&[&base, OPENAI_UPSTREAM, &p], "no action for: card");
    }

    #[test]
    fn url_class_cannot_get_a_request_action() {
        let p = principal("bot", KEY_A, "actions.url = \"allow\"");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &p], "controlled by [response]");
    }

    #[test]
    fn missing_audit_section_is_rejected() {
        let base = BASE.replace("[audit]", "[unused]");
        assert_rejected(&[&base, OPENAI_UPSTREAM], "unused");
        let without = BASE
            .replace("[audit]\n", "")
            .replace("path = \"./data/audit.jsonl\"\n", "")
            .replace("signing_key = \"./data/signing.key\"\n", "")
            .replace("public_key = \"./data/signing.pub\"\n", "");
        assert_rejected(&[&without, OPENAI_UPSTREAM], "audit");
    }

    #[test]
    fn no_upstream_is_rejected() {
        assert_rejected(&[BASE], "no [[upstream]]");
    }

    #[test]
    fn credential_is_required_for_openai_and_anthropic() {
        let upstream =
            "\n[[upstream]]\nprovider = \"anthropic\"\nbase_url = \"https://api.anthropic.com\"\n";
        assert_rejected(
            &[BASE, upstream],
            "credential_env or credential_file is required",
        );
    }

    #[test]
    fn credential_sources_are_mutually_exclusive() {
        let upstream = "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"https://api.openai.com\"\ncredential_env = \"K\"\ncredential_file = \"/k\"\n";
        assert_rejected(&[BASE, upstream], "mutually exclusive");
    }

    #[test]
    fn credential_env_must_be_a_variable_name() {
        let upstream = "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"https://api.openai.com\"\ncredential_env = \"sk-live-123\"\n";
        assert_rejected(&[BASE, upstream], "not a valid environment variable name");
    }

    #[test]
    fn openai_compatible_may_have_no_credential() {
        let upstream = "\n[[upstream]]\nprovider = \"openai_compatible\"\nbase_url = \"https://llm.internal.example/gateway/\"\n";
        let p = "\n[[principal]]\nid = \"bot\"\nkey_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nmodels.openai_compatible = [\"llama-3\"]\n";
        let config = parse(&[BASE, upstream, p]).unwrap();
        let upstream = &config.upstreams[&Provider::OpenAiCompatible];
        assert_eq!(upstream.credential, None);
        assert_eq!(
            upstream.base_url.as_str(),
            "https://llm.internal.example/gateway"
        );
    }

    #[test]
    fn plain_http_is_rejected_without_the_flag() {
        let upstream = "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"http://127.0.0.1:9000\"\ncredential_env = \"K\"\n";
        assert_rejected(&[BASE, upstream], "must use https://");
    }

    #[test]
    fn insecure_flag_only_accepts_local_hosts() {
        let remote = "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"http://api.openai.com\"\ncredential_env = \"K\"\nallow_insecure_upstream = true\n";
        assert_rejected(&[BASE, remote], "only accepted for localhost");

        for host in ["127.0.0.1:9000", "localhost:9000", "[::1]:9000"] {
            let local = format!(
                "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"http://{host}\"\ncredential_env = \"K\"\nallow_insecure_upstream = true\n"
            );
            let p = principal("bot", KEY_A, "");
            let config = parse(&[BASE, &local, &p]).unwrap();
            assert!(config.upstreams[&Provider::OpenAi].insecure);
            assert_eq!(config.warnings.len(), 1, "{host}: {:?}", config.warnings);
        }
    }

    #[test]
    fn base_url_rejects_userinfo_query_and_other_schemes() {
        for (url, needle) in [
            ("https://api.openai.com@attacker.test", "user information"),
            ("https://api.openai.com/?key=1", "query or fragment"),
            ("ftp://api.openai.com", "scheme 'ftp'"),
            ("not a url", "not a valid URL"),
        ] {
            let upstream = format!(
                "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"{url}\"\ncredential_env = \"K\"\n"
            );
            assert_rejected(&[BASE, &upstream], needle);
        }
    }

    #[test]
    fn one_upstream_per_provider() {
        assert_rejected(
            &[BASE, OPENAI_UPSTREAM, OPENAI_UPSTREAM],
            "only one upstream per provider",
        );
    }

    #[test]
    fn principal_ids_and_keys_must_be_unique() {
        let a = principal("bot", KEY_A, "");
        let b = principal("bot", KEY_B, "");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &a, &b], "duplicate id");
        let c = principal("other", KEY_A, "");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &a, &c], "already used");
    }

    #[test]
    fn principal_fields_are_validated() {
        let bad_id = principal("Support Bot", KEY_A, "");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &bad_id], "id must be");
        let bad_key = principal("bot", &KEY_A.to_uppercase(), "");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &bad_key], "key_sha256");
        let zero_rpm = principal("bot", KEY_A, "requests_per_minute = 0");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &zero_rpm], "requests_per_minute");
        let too_big = principal("bot", KEY_A, "max_body_bytes = 2097152");
        assert_rejected(&[BASE, OPENAI_UPSTREAM, &too_big], "max_body_bytes");
    }

    #[test]
    fn models_need_an_upstream_and_no_duplicates() {
        let p = principal("bot", KEY_A, "models.anthropic = [\"claude-sonnet-5-5\"]");
        assert_rejected(
            &[BASE, OPENAI_UPSTREAM, &p],
            "no [[upstream]] for anthropic",
        );
        let none = "\n[[principal]]\nid = \"bot\"\nkey_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
        assert_rejected(&[BASE, OPENAI_UPSTREAM, none], "no models allowed");
        let twice = "\n[[principal]]\nid = \"bot\"\nkey_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nmodels.openai = [\"m\", \"m\"]\n";
        assert_rejected(&[BASE, OPENAI_UPSTREAM, twice], "twice");
    }

    #[test]
    fn same_model_under_openai_and_compatible_is_ambiguous() {
        let compatible =
            "\n[[upstream]]\nprovider = \"openai_compatible\"\nbase_url = \"https://gw.example\"\n";
        let p = principal(
            "bot",
            KEY_A,
            "models.openai_compatible = [\"gpt-4.1-mini\"]",
        );
        assert_rejected(&[BASE, OPENAI_UPSTREAM, compatible, &p], "ambiguous");
    }

    #[test]
    fn link_hosts_must_be_bare_hostnames() {
        let response = "\n[response]\nallowed_link_hosts = [\"https://docs.example.com/\"]\n";
        assert_rejected(&[BASE, OPENAI_UPSTREAM, response], "bare hostname");
        let wildcard = "\n[response]\nallowed_link_hosts = [\"*.example.com\"]\n";
        assert_rejected(&[BASE, OPENAI_UPSTREAM, wildcard], "bare hostname");
        let upper = "\n[response]\nallowed_link_hosts = [\"Docs.Example.com\"]\n";
        let p = principal("bot", KEY_A, "");
        let config = parse(&[BASE, OPENAI_UPSTREAM, upper, &p]).unwrap();
        assert_eq!(config.response.allowed_link_hosts, ["docs.example.com"]);
    }

    #[test]
    fn all_problems_are_reported_together() {
        let upstream =
            "\n[[upstream]]\nprovider = \"openai\"\nbase_url = \"http://api.openai.com\"\n";
        let p = principal("Bad Id", "nothex", "");
        let Err(ConfigError::Invalid(problems)) = parse(&[BASE, upstream, &p]) else {
            panic!("expected validation problems");
        };
        assert!(problems.len() >= 4, "{problems:#?}");
    }

    #[test]
    fn expires_at_is_parsed_and_normalized_to_utc() {
        let p = principal("bot", KEY_A, "expires_at = \"2027-02-09T01:00:00+01:00\"");
        let config = parse(&[BASE, OPENAI_UPSTREAM, &p]).unwrap();
        let expires_at = config.principals[0].principal.expires_at.unwrap();
        assert_eq!(expires_at.offset(), UtcOffset::UTC);
        assert_eq!(expires_at.unix_timestamp(), 1_802_131_200); // 2027-02-09T00:00:00Z
    }

    #[test]
    fn expires_at_without_time_or_offset_is_rejected() {
        for value in [
            "2027-02-09",
            "2027-02-09T00:00:00",
            "tomorrow",
            "2027-13-01T00:00:00Z",
        ] {
            let p = principal("bot", KEY_A, &format!("expires_at = \"{value}\""));
            assert_rejected(&[BASE, OPENAI_UPSTREAM, &p], "RFC 3339");
        }
    }

    #[test]
    fn public_listen_address_is_a_warning_not_an_error() {
        let server = "\n[server]\nlisten = \"0.0.0.0:8787\"\n";
        let p = principal("bot", KEY_A, "");
        let config = parse(&[BASE, server, OPENAI_UPSTREAM, &p]).unwrap();
        assert!(config.warnings.iter().any(|w| w.contains("0.0.0.0")));
    }
}
