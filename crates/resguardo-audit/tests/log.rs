//! The hash-chained, signed audit log and its verification (Annex F.8, G.5; ADR 0003,
//! ADR 0015).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use resguardo_audit::{
    AuditError, AuditLog, KeyError, Reason, SigningKey, VerifyError, canonicalize, verify_log,
};
use resguardo_core::AuditKind;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "audit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fields(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

/// Three requests: a decision and an outcome each (G.5).
fn three_requests(log: &AuditLog) {
    for n in 0..3 {
        let id = format!("req-{n}");
        log.append(
            AuditKind::Decision,
            Some(&id),
            fields(&[
                ("principal", json!("bot")),
                ("decision", json!("allow")),
                ("findings", json!({"es_id": 1})),
            ]),
        )
        .unwrap();
        log.append(
            AuditKind::Outcome,
            Some(&id),
            fields(&[("status", json!(200)), ("upstream_us", json!(1234))]),
        )
        .unwrap();
    }
}

fn verify_file(path: &PathBuf, key: &SigningKey) -> Result<usize, VerifyError> {
    let file = fs::File::open(path).unwrap();
    verify_log(std::io::BufReader::new(file), &key.public_key()).map(|v| v.entries)
}

fn failure(result: Result<usize, VerifyError>) -> (usize, Reason) {
    match result {
        Err(VerifyError::Failed { line, reason }) => (line, reason),
        other => panic!("expected a failure, got {other:?}"),
    }
}

fn lines(path: &PathBuf) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &PathBuf, lines: &[String]) {
    fs::write(path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn g5_three_requests_give_six_entries_that_verify() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    let log = AuditLog::open(&path, key.clone(), true).unwrap();
    three_requests(&log);
    assert_eq!(verify_file(&path, &key).unwrap(), 6);

    let first: Value = serde_json::from_str(&lines(&path)[0]).unwrap();
    assert_eq!(first["seq"], 1);
    assert_eq!(first["kind"], "decision");
    assert_eq!(first["prev"], "0".repeat(64));
    assert_eq!(first["request_id"], "req-0");
    assert!(first["ts"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn hash_and_signature_follow_annex_f8() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    let log = AuditLog::open(&path, key.clone(), false).unwrap();
    three_requests(&log);
    let mut entry: Value = serde_json::from_str(&lines(&path)[1]).unwrap();
    let object = entry.as_object_mut().unwrap();
    let hash = object.remove("hash").unwrap();
    let sig = object.remove("sig").unwrap();
    let canonical = canonicalize(&entry).unwrap();
    assert_eq!(hash, json!(hex(&Sha256::digest(canonical.as_bytes()))));
    assert_eq!(
        sig.as_str().unwrap().len(),
        86,
        "64 bytes in base64url without padding"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn g5_a_changed_character_fails_with_hash() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    let mut all = lines(&path);
    all[2] = all[2].replace("\"bot\"", "\"bat\"");
    write_lines(&path, &all);
    assert_eq!(failure(verify_file(&path, &key)), (3, Reason::Hash));
}

#[test]
fn g5_a_changed_entry_with_a_recomputed_hash_fails_with_sig() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    let mut all = lines(&path);
    let mut entry: Value = serde_json::from_str(&all[2]).unwrap();
    entry["principal"] = json!("bat");
    let object = entry.as_object_mut().unwrap();
    object.remove("hash");
    let sig = object.remove("sig").unwrap();
    let hash = hex(&Sha256::digest(canonicalize(&entry).unwrap().as_bytes()));
    entry["hash"] = json!(hash);
    entry["sig"] = sig;
    all[2] = serde_json::to_string(&entry).unwrap();
    write_lines(&path, &all);
    assert_eq!(failure(verify_file(&path, &key)), (3, Reason::Sig));
}

#[test]
fn g5_a_deleted_entry_fails_with_prev() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    let mut all = lines(&path);
    all.remove(3);
    write_lines(&path, &all);
    let (line, reason) = failure(verify_file(&path, &key));
    assert_eq!(line, 4);
    assert!(matches!(reason, Reason::Prev | Reason::Seq), "{reason:?}");
}

#[test]
fn g5_another_public_key_fails_on_line_1_with_sig() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key, false).unwrap());
    let other = SigningKey::generate().unwrap();
    assert_eq!(failure(verify_file(&path, &other)), (1, Reason::Sig));
}

#[test]
fn reordered_entries_fail() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    let mut all = lines(&path);
    all.swap(2, 3);
    write_lines(&path, &all);
    let (line, reason) = failure(verify_file(&path, &key));
    assert_eq!(line, 3);
    assert!(matches!(reason, Reason::Prev | Reason::Seq), "{reason:?}");
}

#[test]
fn a_reopened_log_continues_the_chain() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    assert_eq!(verify_file(&path, &key).unwrap(), 12);
}

#[test]
fn a_rotated_key_is_followed_from_the_first_public_key() {
    let path = dir().join("audit.jsonl");
    let first = SigningKey::generate().unwrap();
    let second = SigningKey::generate().unwrap();
    let log = AuditLog::open(&path, first.clone(), false).unwrap();
    three_requests(&log);
    log.rotate_key(second.clone()).unwrap();
    three_requests(&log);
    assert_eq!(verify_file(&path, &first).unwrap(), 13);
    let rotation: Value = serde_json::from_str(&lines(&path)[6]).unwrap();
    assert_eq!(rotation["kind"], "key_rotation");
    assert_eq!(rotation["public_key"], json!(second.public_key().to_text()));
    // After the rotation, entries are signed with the new key, so the new key alone does
    // not verify the log from its start.
    assert_eq!(failure(verify_file(&path, &second)), (1, Reason::Sig));
}

#[test]
fn a_torn_last_line_is_set_aside_and_recorded() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    // A crash in the middle of a write leaves half a line.
    const TORN: &[u8] = b"{\"seq\":7,\"kind\":\"deci";
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(TORN);
    fs::write(&path, &bytes).unwrap();

    let log = AuditLog::open(&path, key.clone(), false).unwrap();
    three_requests(&log);
    assert_eq!(verify_file(&path, &key).unwrap(), 13);
    let recovery: Value = serde_json::from_str(&lines(&path)[6]).unwrap();
    assert_eq!(recovery["kind"], "recovery");
    assert_eq!(recovery["discarded_bytes"], TORN.len());
    assert!(recovery.get("request_id").is_none());
    let torn = path.with_file_name("audit.jsonl.torn-7");
    assert_eq!(fs::read(&torn).unwrap(), TORN);
}

#[test]
fn a_log_that_does_not_verify_is_not_opened() {
    let path = dir().join("audit.jsonl");
    let key = SigningKey::generate().unwrap();
    three_requests(&AuditLog::open(&path, key.clone(), false).unwrap());
    let mut all = lines(&path);
    all[5] = all[5].replace("1234", "1235");
    write_lines(&path, &all);
    assert!(matches!(
        AuditLog::open(&path, key, false),
        Err(AuditError::LastEntry(_))
    ));
}

#[test]
fn reserved_names_and_floats_are_refused() {
    let path = dir().join("audit.jsonl");
    let log = AuditLog::open(&path, SigningKey::generate().unwrap(), false).unwrap();
    for name in ["seq", "kind", "ts", "request_id", "prev", "hash", "sig"] {
        assert!(matches!(
            log.append(AuditKind::Outcome, None, fields(&[(name, json!(1))])),
            Err(AuditError::ReservedField(_))
        ));
    }
    assert!(matches!(
        log.append(AuditKind::Outcome, None, fields(&[("latency", json!(1.5))])),
        Err(AuditError::Canonical(_))
    ));
    // Nothing was written by the refused entries.
    assert!(fs::read_to_string(&path).unwrap().is_empty());
}

#[test]
fn key_files_round_trip_and_the_private_key_must_be_owner_only() {
    let dir = dir();
    let private = dir.join("signing.key");
    let public = dir.join("signing.pub");
    let key = SigningKey::create_files(&private, &public).unwrap();
    assert_eq!(
        fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = SigningKey::load(&private).unwrap();
    assert_eq!(loaded.public_key(), key.public_key());
    assert_eq!(
        resguardo_audit::PublicKey::load(&public).unwrap(),
        key.public_key()
    );
    // Existing files are never overwritten.
    assert!(matches!(
        SigningKey::create_files(&private, &public),
        Err(KeyError::Exists(_))
    ));
    fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        SigningKey::load(&private),
        Err(KeyError::Permissions(_))
    ));
}

#[test]
fn key_material_never_shows_in_debug_output() {
    let key = SigningKey::generate().unwrap();
    let debug = format!("{key:?}");
    assert!(!debug.contains("pkcs8") && debug.len() < 80, "{debug}");
}

#[test]
fn a_rotation_whose_new_key_is_not_in_use_stops_startup() {
    // A crash between writing the rotation and installing the new key files would leave
    // the old key in use: entries signed with it would no longer verify.
    let path = dir().join("audit.jsonl");
    let old = SigningKey::generate().unwrap();
    let log = AuditLog::open(&path, old.clone(), false).unwrap();
    three_requests(&log);
    log.rotate_key(SigningKey::generate().unwrap()).unwrap();
    drop(log);
    assert!(matches!(
        AuditLog::open(&path, old, false),
        Err(AuditError::LastEntry(_))
    ));
}
