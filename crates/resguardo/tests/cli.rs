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
