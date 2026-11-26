//! What writer and verifier compute the same way (Annex F.8).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jcs::{CanonicalError, canonicalize};

/// `prev` of the first entry.
pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Names the log sets itself; fields may not use them.
pub(crate) const RESERVED: [&str; 7] = ["seq", "kind", "ts", "request_id", "prev", "hash", "sig"];

/// SHA-256 of the canonical form of an entry without `hash` and `sig`.
pub(crate) fn entry_hash(entry: &Map<String, Value>) -> Result<[u8; 32], CanonicalError> {
    let mut unsigned = entry.clone();
    unsigned.remove("hash");
    unsigned.remove("sig");
    let canonical = canonicalize(&Value::Object(unsigned))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
