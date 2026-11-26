//! Hash-chained, Ed25519-signed audit log and its verification (Annex F.8; ADR 0003,
//! ADR 0015).
//!
//! Every entry carries `prev`, the hash of the one before; `hash`, the SHA-256 of its
//! RFC 8785 canonical form without `hash` and `sig`; and `sig`, the Ed25519 signature of
//! those 32 bytes. Entries hold metadata only, never request content.
#![forbid(unsafe_code)]

mod entry;
mod jcs;
mod keys;
mod log;
mod verify;

pub use jcs::{CanonicalError, canonicalize};
pub use keys::{KeyError, PublicKey, SigningKey};
pub use log::{AuditError, AuditLog};
pub use verify::{Reason, Verified, VerifyError, verify_log};
