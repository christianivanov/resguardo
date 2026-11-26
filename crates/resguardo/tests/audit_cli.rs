//! `resguardo init`, `init --rotate-key` and `verify-log` (Annex H, F.8; ADR 0009, ADR 0015).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use resguardo_audit::{AuditLog, SigningKey};
use resguardo_core::AuditKind;
use serde_json::json;

fn dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "audit-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn resguardo(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_resguardo"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to run resguardo")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Three decisions and outcomes signed with the key `init` created.
fn write_entries(cwd: &Path) {
    let key = SigningKey::load(&cwd.join("data/signing.key")).unwrap();
    let log = AuditLog::open(&cwd.join("data/audit.jsonl"), key, false).unwrap();
    for n in 0..3 {
        let id = format!("req-{n}");
        let fields = BTreeMap::from([("decision".to_owned(), json!("allow"))]);
        log.append(AuditKind::Decision, Some(&id), fields).unwrap();
        let fields = BTreeMap::from([("status".to_owned(), json!(200))]);
        log.append(AuditKind::Outcome, Some(&id), fields).unwrap();
    }
}

#[test]
fn init_writes_the_example_config_and_an_owner_only_key_pair() {
    let cwd = dir();
    let output = resguardo(&cwd, &["init"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(cwd.join("resguardo.toml").exists());
    let private = cwd.join("data/signing.key");
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let public = fs::read_to_string(cwd.join("data/signing.pub")).unwrap();
    assert!(public.starts_with("ed25519:"));
    assert!(String::from_utf8_lossy(&output.stdout).contains(public.trim()));
    assert!(
        !text(&output).contains("ed25519-pkcs8"),
        "no private key printed"
    );

    // Running it again never replaces the keys.
    let again = resguardo(&cwd, &["init"]);
    assert_eq!(again.status.code(), Some(2));
    assert!(text(&again).contains("--rotate-key"), "{}", text(&again));
    assert_eq!(
        fs::read_to_string(cwd.join("data/signing.pub")).unwrap(),
        public
    );
}

#[test]
fn verify_log_exits_0_for_an_intact_log() {
    let cwd = dir();
    assert!(resguardo(&cwd, &["init"]).status.success());
    write_entries(&cwd);
    let output = resguardo(
        &cwd,
        &[
            "verify-log",
            "data/audit.jsonl",
            "--pubkey",
            "data/signing.pub",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        text(&output).contains("OK (6 entries)"),
        "{}",
        text(&output)
    );
}

#[test]
fn verify_log_exits_1_with_the_line_and_reason() {
    let cwd = dir();
    assert!(resguardo(&cwd, &["init"]).status.success());
    write_entries(&cwd);
    let path = cwd.join("data/audit.jsonl");
    let tampered = fs::read_to_string(&path)
        .unwrap()
        .replacen("\"allow\"", "\"block\"", 2);
    fs::write(&path, tampered).unwrap();
    let output = resguardo(
        &cwd,
        &[
            "verify-log",
            "data/audit.jsonl",
            "--pubkey",
            "data/signing.pub",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).contains("line 1: hash"), "{}", text(&output));
}

#[test]
fn verify_log_exits_2_when_it_cannot_read() {
    let cwd = dir();
    assert!(resguardo(&cwd, &["init"]).status.success());
    let missing = resguardo(
        &cwd,
        &[
            "verify-log",
            "data/none.jsonl",
            "--pubkey",
            "data/signing.pub",
        ],
    );
    assert_eq!(missing.status.code(), Some(2));
    let no_key = resguardo(
        &cwd,
        &["verify-log", "data/audit.jsonl", "--pubkey", "x.pub"],
    );
    assert_eq!(no_key.status.code(), Some(2));
}

#[test]
fn rotate_key_records_the_rotation_and_drops_the_old_private_key() {
    let cwd = dir();
    assert!(resguardo(&cwd, &["init"]).status.success());
    write_entries(&cwd);
    let first_public = fs::read_to_string(cwd.join("data/signing.pub")).unwrap();
    fs::write(cwd.join("first.pub"), &first_public).unwrap();

    let output = resguardo(&cwd, &["init", "--rotate-key"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let new_public = fs::read_to_string(cwd.join("data/signing.pub")).unwrap();
    assert_ne!(new_public, first_public);
    // The old public key is kept for auditors, under the rotation's sequence number; the old
    // private key is gone.
    assert_eq!(
        fs::read_to_string(cwd.join("data/signing.pub.7")).unwrap(),
        first_public
    );
    let leftovers: Vec<_> = fs::read_dir(cwd.join("data"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("signing.key"))
        .collect();
    assert_eq!(leftovers, vec!["signing.key"]);

    // New entries are signed with the new key, and the first public key still verifies all.
    write_entries(&cwd);
    let output = resguardo(
        &cwd,
        &["verify-log", "data/audit.jsonl", "--pubkey", "first.pub"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(
        text(&output).contains("OK (13 entries)"),
        "{}",
        text(&output)
    );
}
