//! End-to-end tests of the `resguardo` command line.
// Test helpers may panic: a failure to spawn the binary is a test failure.
#![allow(clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use resguardo_core::Limits;

fn resguardo(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_resguardo"))
        .args(args)
        .output()
        .expect("failed to run resguardo")
}

/// Runs the binary with `input` on standard input. The input is written from another thread,
/// so a large input cannot block while the child fills its output pipes.
fn resguardo_with_stdin(args: &[&str], input: Vec<u8>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_resguardo"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run resguardo");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child
        .wait_with_output()
        .expect("failed to wait for resguardo");
    writer
        .join()
        .expect("stdin writer panicked")
        .expect("failed to write stdin");
    output
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
    // 2, not 1: the configuration could not be checked at all (ADR 0009).
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("reading /nonexistent/resguardo.toml"),
        "{stderr}"
    );
}

/// Parses `key_sha256 = "<hash>"` out of the instructions printed on stderr.
#[test]
fn config_check_reports_a_syntax_error_as_a_problem() {
    let path = repo_file("crates/resguardo/tests/fixtures/syntax-error.toml");
    let output = resguardo(&["config", "check", "--config", &path]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The file was read and checked: a syntax error is an answer, not a failure (ADR 0009).
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("line 3"), "{stderr}");
}

#[test]
fn invalid_arguments_exit_with_2() {
    let output = resguardo(&["config", "check", "--no-such-flag"]);
    assert_eq!(output.status.code(), Some(2));
}

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
models.anthropic = ["claude-sonnet-5-5"]
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
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "no key may be printed on error");
    assert!(stderr.contains("principal id"), "{stderr}");
}

/// Fake key from the AWS documentation, split so that secret scanners reading this file do
/// not mistake it for a real one.
const AWS_EXAMPLE_KEY: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

#[test]
fn scan_of_a_clean_text_exits_with_0() {
    let output = resguardo_with_stdin(&["scan"], b"pedido 12345 enviado el lunes\n".to_vec());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "0 findings, 0 flags\n"
    );
}

#[test]
fn scan_reports_a_secret_without_its_value_and_exits_with_1() {
    let input = format!("my key is {AWS_EXAMPLE_KEY} ok\n");
    let output = resguardo_with_stdin(&["scan"], input.into_bytes());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stdout.contains("finding  secret  secret.aws_access_key  bytes 10..30"),
        "{stdout}"
    );
    assert!(stdout.ends_with("1 finding, 0 flags\n"), "{stdout}");
    for printed in [&stdout, &stderr] {
        assert!(!printed.contains("AKIA"), "the value leaked: {printed}");
    }
}

#[test]
fn scan_of_a_file_shows_the_decoding_layers() {
    let path = repo_file("crates/resguardo/tests/fixtures/scan-base64-secret.txt");
    let output = resguardo(&["scan", "--file", &path]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout.contains(
            "finding  secret  secret.aws_access_key  bytes 14..42  confidence 90  via base64"
        ),
        "{stdout}"
    );
    assert!(
        !stdout.contains("QUtJQ") && !stdout.contains("AKIA"),
        "{stdout}"
    );
}

#[test]
fn scan_reports_a_limit_flag_and_exits_with_1() {
    // "secret text here for depth" in three Base64 layers, one more than the default
    // max_decode_depth of 2.
    let input = "x: WXpKV2FtTnRWakJKU0ZKc1pVaFJaMkZIVm5sYVUwSnRZak5KWjFwSFZuZGtSMmM5\n";
    let output = resguardo_with_stdin(&["scan"], input.as_bytes().to_vec());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout.contains("flag     decode_depth  bytes 3..67  via base64,base64,base64"),
        "{stdout}"
    );
}

#[test]
fn scan_accepts_input_at_the_limit() {
    let input = b"word ".repeat(Limits::DEFAULT_MAX_BODY_BYTES / 5);
    let output = resguardo_with_stdin(&["scan"], input);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn scan_refuses_input_over_the_limit_with_2() {
    let input = vec![b'a'; Limits::DEFAULT_MAX_BODY_BYTES + 1];
    let output = resguardo_with_stdin(&["scan"], input);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "no partial report may be printed");
    assert!(stderr.contains("larger than 1048576 bytes"), "{stderr}");
}

#[test]
fn scan_refuses_invalid_utf8_with_2_without_quoting_it() {
    let mut input = format!("{AWS_EXAMPLE_KEY} ").into_bytes();
    input.extend_from_slice(&[0xff, 0xfe]);
    let output = resguardo_with_stdin(&["scan"], input);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("not valid UTF-8"), "{stderr}");
    assert!(!stderr.contains("AKIA"), "the input leaked: {stderr}");
}

#[test]
fn scan_reports_a_missing_file_with_2() {
    let output = resguardo(&["scan", "--file", "/nonexistent/input.txt"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("reading /nonexistent/input.txt"),
        "{stderr}"
    );
}
