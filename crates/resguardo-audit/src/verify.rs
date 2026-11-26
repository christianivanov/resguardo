//! `verify-log` (Annex F.8 step 6): each line's hash and signature, and the chain of `prev`
//! and `seq`. Key rotations are followed from the first public key (ADR 0015).

use std::fmt;
use std::io::BufRead;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use resguardo_core::AuditKind;
use serde_json::Value;

use crate::entry::{GENESIS, entry_hash, hex};
use crate::keys::PublicKey;

/// Why a line failed, as `verify-log` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Not an entry Resguardo wrote: not JSON, a missing field, a float…
    Format,
    /// The content does not match its `hash`.
    Hash,
    /// The signature does not match the public key in force.
    Sig,
    /// `prev` is not the `hash` of the line before.
    Prev,
    /// `seq` is not the next number.
    Seq,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::Format => "format",
            Reason::Hash => "hash",
            Reason::Sig => "sig",
            Reason::Prev => "prev",
            Reason::Seq => "seq",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the log could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("line {line}: {reason}")]
    Failed { line: usize, reason: Reason },
}

/// A log that verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub entries: usize,
}

/// Verifies every line; stops at the first failure.
pub fn verify_log(reader: impl BufRead, first_key: &PublicKey) -> Result<Verified, VerifyError> {
    let mut key = *first_key;
    let mut prev = GENESIS.to_owned();
    let mut entries = 0;
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let number = index + 1;
        let fail = |reason| VerifyError::Failed {
            line: number,
            reason,
        };
        let Ok(Value::Object(entry)) = serde_json::from_str::<Value>(&line) else {
            return Err(fail(Reason::Format));
        };
        let text = |name: &str| entry.get(name).and_then(Value::as_str).map(str::to_owned);
        let (Some(hash), Some(sig), Some(entry_prev), Some(entry_seq)) = (
            text("hash"),
            text("sig"),
            text("prev"),
            entry.get("seq").and_then(Value::as_u64),
        ) else {
            return Err(fail(Reason::Format));
        };
        let computed = entry_hash(&entry).map_err(|_| fail(Reason::Format))?;
        if hex(&computed) != hash {
            return Err(fail(Reason::Hash));
        }
        let signature = URL_SAFE_NO_PAD
            .decode(&sig)
            .map_err(|_| fail(Reason::Sig))?;
        if !key.verify(&computed, &signature) {
            return Err(fail(Reason::Sig));
        }
        if entry_prev != prev {
            return Err(fail(Reason::Prev));
        }
        if u64::try_from(number).ok() != Some(entry_seq) {
            return Err(fail(Reason::Seq));
        }
        if text("kind").as_deref() == Some(AuditKind::KeyRotation.as_str()) {
            key = text("public_key")
                .as_deref()
                .and_then(PublicKey::parse)
                .ok_or_else(|| fail(Reason::Format))?;
        }
        prev = hash;
        entries += 1;
    }
    Ok(Verified { entries })
}
