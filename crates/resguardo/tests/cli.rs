//! End-to-end tests of the `resguardo` command line.
// Test helpers may panic: a failure to spawn the binary is a test failure.
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn resguardo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_resguardo"))
        .args(args)
        .output()
        .expect("failed to run resguardo")
}

fn repo_file(relative: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.join(relative).display().to_string()
}

#[test]
fn config_check_accepts_the_example() {
    let path = repo_file("config/resguardo.example.toml");
    let output = resguardo(&["config", "check", "--config", &path]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("OK (2 upstream(s), 1 principal(s))"),
        "{stdout}"
    );
}

#[test]
fn config_check_lists_every_problem_and_fails() {
    let path = repo_file("crates/resguardo/tests/fixtures/invalid.toml");
    let output = resguardo(&["config", "check", "--config", &path]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    for needle in [
        "must use https://",
        "credential_env or credential_file",
        "id must be",
        "key_sha256",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?} in:\n{stderr}");
    }
}

#[test]
fn config_check_reports_a_missing_file() {
    let output = resguardo(&["config", "check", "--config", "/nonexistent/resguardo.toml"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("reading /nonexistent/resguardo.toml"),
        "{stderr}"
    );
}

/// Parses `key_sha256 = "<hash>"` out of the instructions printed on stderr.
fn printed_hash(stderr: &str) -> String {
    let line = stderr
        .lines()
        .find(|l| l.trim_start().starts_with("key_sha256 = "))
        .expect("key_sha256 line on stderr");
    line.trim()
        .trim_start_matches("key_sha256 = ")
        .trim_matches('"')
        .to_owned()
}

#[test]
fn key_create_prints_only_the_key_on_stdout_and_its_hash_on_stderr() {
    let output = resguardo(&["key", "create", "--principal", "support-bot"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");

    // stdout holds the key and nothing else, so it can be piped into a secret store.
    let key = stdout.trim_end_matches('\n');
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(key.starts_with("rsg_"), "{key}");
    assert_eq!(key.len(), resguardo_core::virtual_key::KEY_LEN);
    assert!(!stderr.contains(key), "the key must appear only once");

    // The printed hash is the one the proxy will compute for that key.
    let hash = printed_hash(&stderr);
    let config = format!(
        r#"
[audit]
path = "a"
signing_key = "k"
public_key = "p"

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
provider = "anthropic"
base_url = "https://api.anthropic.com"
credential_env = "ANTHROPIC_API_KEY"

[[principal]]
id = "support-bot"
key_sha256 = "{hash}"
models.anthropic = ["claude-sonnet-4-5"]
"#
    );
    let config = resguardo_core::Config::from_toml_str(&config).expect("valid config");
    let ring = resguardo_core::KeyRing::from_config(&config);
    let principal = ring
        .authenticate(key, resguardo_core::OffsetDateTime::now_utc())
        .expect("the new key authenticates");
    assert_eq!(principal.id.as_str(), "support-bot");
}

#[test]
fn key_create_never_repeats_a_key() {
    let mut keys = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let output = resguardo(&["key", "create", "--principal", "bot"]);
        assert!(output.status.success());
        assert!(keys.insert(String::from_utf8_lossy(&output.stdout).into_owned()));
    }
}

#[test]
fn key_create_rejects_an_invalid_principal_id() {
    let output = resguardo(&["key", "create", "--principal", "Support Bot"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "no key may be printed on error");
    assert!(stderr.contains("principal id"), "{stderr}");
}
