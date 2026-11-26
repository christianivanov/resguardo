//! The append-only log (Annex F.8 steps 1 to 5; ADR 0003, ADR 0015).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use resguardo_core::{AuditKind, OffsetDateTime};
use serde_json::{Map, Value, json};

use crate::entry::{GENESIS, RESERVED, entry_hash, hex};
use crate::jcs::CanonicalError;
use crate::keys::SigningKey;

/// How far back from the end `open` looks for the last entry. Entries are a few hundred
/// bytes; one this large means the file is not a Resguardo log.
const MAX_TAIL_BYTES: u64 = 1024 * 1024;

/// Why an entry could not be written. Callers block the request (`AUDIT_UNAVAILABLE`,
/// ADR 0002). Messages name files and fields, never their values.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("audit field '{0}' is set by the log itself")]
    ReservedField(String),
    #[error("audit entry: {0}")]
    Canonical(#[from] CanonicalError),
    /// The last entry does not verify with the signing key: the file was changed, or the
    /// key is not this log's.
    #[error("audit log {0}: its last entry does not verify with the signing key")]
    LastEntry(PathBuf),
    #[error("audit log lock poisoned")]
    Poisoned,
}

struct Inner {
    file: File,
    /// Length of the file after the last complete entry.
    len: u64,
    seq: u64,
    prev: String,
    key: SigningKey,
}

/// Shared by every request; entries are written one at a time.
pub struct AuditLog {
    path: PathBuf,
    fsync: bool,
    healthy: AtomicBool,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .field("fsync", &self.fsync)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens or creates the log and continues its chain. A torn last line, left by a crash
    /// in the middle of a write, is moved to `<path>.torn-<seq>` and a `recovery` entry
    /// records it. A last entry that does not verify with `key` stops startup.
    pub fn open(path: &Path, key: SigningKey, fsync: bool) -> Result<Self, AuditError> {
        let io = |source| AuditError::Io {
            path: path.to_owned(),
            source,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(io)?;
        let len = file.metadata().map_err(io)?.len();
        let tail_start = len.saturating_sub(MAX_TAIL_BYTES);
        file.seek(SeekFrom::Start(tail_start)).map_err(io)?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).map_err(io)?;

        // The torn part is whatever follows the last newline.
        let complete = tail.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        if complete == 0 && tail_start > 0 {
            return Err(AuditError::LastEntry(path.to_owned()));
        }
        let torn = tail.get(complete..).unwrap_or_default().to_vec();
        let lines = tail.get(..complete).unwrap_or_default();
        let last = lines
            .strip_suffix(b"\n")
            .and_then(|body| body.rsplit(|&b| b == b'\n').next())
            .filter(|line| !line.is_empty());

        let (seq, prev) = match last {
            None if tail_start == 0 => (0, GENESIS.to_owned()),
            None => return Err(AuditError::LastEntry(path.to_owned())),
            Some(line) => {
                last_entry(line, &key).ok_or_else(|| AuditError::LastEntry(path.to_owned()))?
            }
        };

        let log = Self {
            path: path.to_owned(),
            fsync,
            healthy: AtomicBool::new(true),
            inner: Mutex::new(Inner {
                file,
                len: tail_start + complete as u64,
                seq,
                prev,
                key,
            }),
        };
        if !torn.is_empty() {
            let aside = with_suffix(path, &format!("torn-{}", seq + 1));
            std::fs::write(&aside, &torn).map_err(|source| AuditError::Io {
                path: aside.clone(),
                source,
            })?;
            {
                let inner = log.inner.lock().map_err(|_| AuditError::Poisoned)?;
                inner.file.set_len(inner.len).map_err(io)?;
            }
            log.append(
                AuditKind::Recovery,
                None,
                BTreeMap::from([("discarded_bytes".to_owned(), json!(torn.len()))]),
            )?;
        }
        Ok(log)
    }

    /// Whether the last write succeeded (`/healthz`).
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Signs and appends one entry, flushed to disk first when `fsync` is on. On failure the
    /// file is cut back to the last complete entry, so the chain stays intact.
    pub fn append(
        &self,
        kind: AuditKind,
        request_id: Option<&str>,
        fields: BTreeMap<String, Value>,
    ) -> Result<u64, AuditError> {
        if let Some(name) = fields.keys().find(|k| RESERVED.contains(&k.as_str())) {
            return Err(AuditError::ReservedField(name.clone()));
        }
        let mut inner = self.inner.lock().map_err(|_| AuditError::Poisoned)?;
        let key = inner.key.clone();
        self.write(&mut inner, &key, kind, request_id, fields)
    }

    /// Records a new signing key, signed with the current one, then signs with the new one.
    pub fn rotate_key(&self, new: SigningKey) -> Result<u64, AuditError> {
        let mut inner = self.inner.lock().map_err(|_| AuditError::Poisoned)?;
        let old = inner.key.clone();
        let fields = BTreeMap::from([("public_key".to_owned(), json!(new.public_key().to_text()))]);
        let seq = self.write(&mut inner, &old, AuditKind::KeyRotation, None, fields)?;
        inner.key = new;
        Ok(seq)
    }

    fn write(
        &self,
        inner: &mut Inner,
        key: &SigningKey,
        kind: AuditKind,
        request_id: Option<&str>,
        fields: BTreeMap<String, Value>,
    ) -> Result<u64, AuditError> {
        let seq = inner.seq + 1;
        let mut entry: Map<String, Value> = fields.into_iter().collect();
        entry.insert("seq".to_owned(), json!(seq));
        entry.insert("kind".to_owned(), json!(kind.as_str()));
        entry.insert("ts".to_owned(), json!(timestamp(OffsetDateTime::now_utc())));
        if let Some(id) = request_id {
            entry.insert("request_id".to_owned(), json!(id));
        }
        entry.insert("prev".to_owned(), json!(inner.prev));
        let hash = entry_hash(&entry)?;
        let hash_hex = hex(&hash);
        entry.insert("hash".to_owned(), json!(hash_hex));
        entry.insert(
            "sig".to_owned(),
            json!(URL_SAFE_NO_PAD.encode(key.sign(&hash))),
        );
        let mut line = Value::Object(entry).to_string();
        line.push('\n');

        let result = self.write_line(inner, line.as_bytes());
        self.healthy.store(result.is_ok(), Ordering::Relaxed);
        result.map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        inner.len += line.len() as u64;
        inner.seq = seq;
        inner.prev = hash_hex;
        Ok(seq)
    }

    fn write_line(&self, inner: &mut Inner, line: &[u8]) -> std::io::Result<()> {
        // A failed write may have left part of a line: cut back to the last entry first.
        inner.file.set_len(inner.len)?;
        let written = inner.file.write_all(line).and_then(|()| {
            if self.fsync {
                inner.file.sync_data()
            } else {
                Ok(())
            }
        });
        if written.is_err() {
            let _ = inner.file.set_len(inner.len);
        }
        written
    }
}

/// `seq` and `hash` of the last line, if it verifies with `key` (or is the rotation that
/// introduced `key`).
fn last_entry(line: &[u8], key: &SigningKey) -> Option<(u64, String)> {
    let Value::Object(entry) = serde_json::from_slice::<Value>(line).ok()? else {
        return None;
    };
    let hash = entry.get("hash")?.as_str()?.to_owned();
    let seq = entry.get("seq")?.as_u64()?;
    let computed = entry_hash(&entry).ok()?;
    if hex(&computed) != hash {
        return None;
    }
    let public = key.public_key();
    let signature = URL_SAFE_NO_PAD.decode(entry.get("sig")?.as_str()?).ok()?;
    let rotated_to_key = entry.get("kind").and_then(Value::as_str)
        == Some(AuditKind::KeyRotation.as_str())
        && entry.get("public_key").and_then(Value::as_str) == Some(public.to_text().as_str());
    (public.verify(&computed, &signature) || rotated_to_key).then_some((seq, hash))
}

/// ISO 8601 UTC with milliseconds: `2026-12-10T09:14:03.112Z`.
fn timestamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}
