//! Virtual keys: format, hashing and authentication (design document, section 6 and Annex H).
//!
//! Security notes, also summarized in `docs/THREAT_MODEL.md` (T6):
//!
//! - A key is `rsg_` followed by 43 Base62 characters that encode 32 bytes from the operating
//!   system's random generator: 256 bits, so guessing one is not feasible.
//! - The encoding converts the 32 bytes as one big number. Picking characters with
//!   `byte % 62` would make some characters more likely than others (modulo bias).
//! - Only the SHA-256 of a key is stored. A slow password hash (Argon2, bcrypt) protects
//!   low-entropy human passwords; a 256-bit random key needs none.
//! - Keys are looked up by their hash, so a lookup's timing depends on the hash of the
//!   attacker's input, never on the stored key. Learning about stored hashes does not help
//!   find a key (SHA-256 preimage resistance), so no constant-time comparison is needed.
//! - [`VirtualKey`] never prints its value: `Debug` shows a placeholder and there is no
//!   `Display`. Errors carry a [`BlockCode`], never the presented value.
//! - Anything unexpected is rejected: a missing key, an unknown scheme in `Authorization`,
//!   two different keys in two headers, a malformed key, an expired key (ADR 0002).

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::config::Config;
use crate::domain::{BlockCode, Principal, VirtualKeyHash};

/// Every virtual key starts with this prefix, so secret scanners can recognize it.
pub const PREFIX: &str = "rsg_";

/// Random bytes behind each key.
pub const RANDOM_BYTES: usize = 32;

/// Base62 characters needed for 32 bytes: 62^43 > 2^256 > 62^42.
const ENCODED_LEN: usize = 43;

/// Total length of a key, prefix included.
pub const KEY_LEN: usize = PREFIX.len() + ENCODED_LEN;

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A virtual key in clear text. Exists only while `resguardo key create` prints it.
pub struct VirtualKey(String);

impl VirtualKey {
    /// Encodes random bytes as a key. The caller provides the randomness, so this stays pure
    /// and testable; the binary reads it from the operating system.
    pub fn from_random_bytes(bytes: &[u8; RANDOM_BYTES]) -> Self {
        // Long division of the 256-bit big-endian number by 62, repeated 43 times. Each
        // remainder is one digit, least significant first, so the digits fill from the right.
        // Leading zero digits are kept: every key has the same length.
        let mut number = *bytes;
        let mut digits = [0u8; ENCODED_LEN];
        for digit in digits.iter_mut().rev() {
            let mut remainder: u16 = 0;
            for byte in &mut number {
                let value = (remainder << 8) | u16::from(*byte);
                // `value < 62 * 256`, so the quotient always fits in a byte.
                *byte = (value / 62) as u8;
                remainder = value % 62;
            }
            *digit = ALPHABET[usize::from(remainder)];
        }
        let mut key = String::with_capacity(KEY_LEN);
        key.push_str(PREFIX);
        key.extend(digits.iter().map(|&d| char::from(d)));
        Self(key)
    }

    /// The key itself. Call it only to show the key once to the operator.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn hash(&self) -> VirtualKeyHash {
        hash_key(&self.0)
    }
}

impl fmt::Debug for VirtualKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VirtualKey(<redacted>)")
    }
}

fn hash_key(key: &str) -> VirtualKeyHash {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(key.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    VirtualKeyHash::from_computed(hex)
}

/// Whether `candidate` has the shape of a virtual key. Checked before hashing, so a provider
/// key sent by mistake (`sk-…`) is rejected the same way as an unknown key.
fn is_well_formed(candidate: &str) -> bool {
    candidate.len() == KEY_LEN
        && candidate
            .strip_prefix(PREFIX)
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Picks the virtual key from the request headers.
///
/// Clients send it as `Authorization: Bearer <key>` (OpenAI SDKs, `ANTHROPIC_AUTH_TOKEN`) or
/// as `x-api-key: <key>` (Anthropic SDKs, `ANTHROPIC_API_KEY`). A header value that is not
/// valid text must be passed as `Some("")` by the caller, so it is rejected, never skipped.
///
/// Rejected with [`BlockCode::UnknownKey`]: no key; an `Authorization` scheme other than
/// `Bearer`; both headers with different values. Never returns the other header's value.
pub fn presented_key<'a>(
    authorization: Option<&'a str>,
    x_api_key: Option<&'a str>,
) -> Result<&'a str, BlockCode> {
    let from_authorization = match authorization {
        None => None,
        Some(value) => Some(bearer_token(value).ok_or(BlockCode::UnknownKey)?),
    };
    match (from_authorization, x_api_key) {
        (Some(key), None) | (None, Some(key)) if !key.is_empty() => Ok(key),
        (Some(a), Some(b)) if a == b && !a.is_empty() => Ok(a),
        _ => Err(BlockCode::UnknownKey),
    }
}

/// `Bearer <token>`: scheme case-insensitive, one or more spaces, a token without spaces.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim_start_matches(' ');
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(' '))
        .then_some(token)
}

/// Principals indexed by the hash of their virtual key.
#[derive(Debug, Clone)]
pub struct KeyRing {
    principals: BTreeMap<VirtualKeyHash, Principal>,
}

impl KeyRing {
    /// Built from a validated configuration, which guarantees unique hashes.
    pub fn from_config(config: &Config) -> Self {
        let principals = config
            .principals
            .iter()
            .map(|p| (p.key_hash.clone(), p.principal.clone()))
            .collect();
        Self { principals }
    }

    /// Finds the principal for a presented key. `now` is passed in, so this never reads the
    /// clock and tests can check the exact expiry instant.
    ///
    /// A key is expired from its `expires_at` instant onwards.
    pub fn authenticate(
        &self,
        presented: &str,
        now: OffsetDateTime,
    ) -> Result<&Principal, BlockCode> {
        if !is_well_formed(presented) {
            return Err(BlockCode::UnknownKey);
        }
        let principal = self
            .principals
            .get(&hash_key(presented))
            .ok_or(BlockCode::UnknownKey)?;
        match principal.expires_at {
            Some(expires_at) if now >= expires_at => Err(BlockCode::KeyExpired),
            _ => Ok(principal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors computed outside this code: Base62 with Python's arbitrary-precision
    /// integers, SHA-256 with `shasum -a 256`.
    const GOLDEN: [(&str, [u8; 32], &str, &str); 3] = [
        (
            "all zeros",
            [0; 32],
            "rsg_0000000000000000000000000000000000000000000",
            "18fbb75213d5caf8f241d7fd0ee48c691d9f50e65e1f09c3d030c7bd0c69f162",
        ),
        (
            "all 0xff",
            [0xff; 32],
            "rsg_yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1",
            "0d53463a59a84db32841c97bc956dc8246e13955ea252bbd3d5421f67929bdbd",
        ),
        (
            "0, 1, 2 … 31",
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            "rsg_003aUlTJC7tjlCTQj2uNU3MFagCXG9LRKRcwGkBIDlf",
            "b138b6b1fa8e691bd3eef6540b642ec4bde4c36713e041751490ea090e374e24",
        ),
    ];

    const KEY: &str = "rsg_003aUlTJC7tjlCTQj2uNU3MFagCXG9LRKRcwGkBIDlf";
    const OTHER_KEY: &str = "rsg_yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1";

    #[test]
    fn keys_and_hashes_match_the_golden_vectors() {
        for (name, bytes, key, hash) in GOLDEN {
            let generated = VirtualKey::from_random_bytes(&bytes);
            assert_eq!(generated.expose_secret(), key, "{name}");
            assert_eq!(generated.hash().as_str(), hash, "{name}");
            assert!(is_well_formed(key), "{name}");
        }
    }

    #[test]
    fn every_generated_key_has_the_same_shape() {
        // Several byte patterns, including ones that produce leading zero digits.
        for seed in 0u8..=255 {
            let mut bytes = [0u8; 32];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = seed
                    .wrapping_mul(31)
                    .wrapping_add(i as u8)
                    .rotate_left(u32::from(seed % 8));
            }
            bytes[0] = seed; // vary the most significant byte too
            let key = VirtualKey::from_random_bytes(&bytes);
            assert_eq!(key.expose_secret().len(), KEY_LEN);
            assert!(is_well_formed(key.expose_secret()), "seed {seed}");
        }
    }

    #[test]
    fn debug_never_shows_the_key() {
        let key = VirtualKey::from_random_bytes(&[7; 32]);
        let debug = format!("{key:?}");
        assert!(!debug.contains(key.expose_secret()));
        assert!(!debug.contains("rsg_"));
    }

    #[test]
    fn malformed_keys_are_recognized() {
        let too_short = &KEY[..KEY_LEN - 1];
        let too_long = format!("{KEY}0");
        let wrong_prefix = KEY.replacen("rsg_", "rsk_", 1);
        let with_symbol = KEY.replacen('a', "-", 1);
        let non_ascii = KEY.replacen('a', "á", 1);
        for bad in [
            "",
            "rsg_",
            too_short,
            &too_long,
            &wrong_prefix,
            &with_symbol,
            &non_ascii,
            "sk-proj-0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            &format!(" {}", &KEY[1..]),
        ] {
            assert!(!is_well_formed(bad), "{bad:?}");
        }
    }

    #[test]
    fn key_is_taken_from_either_header() {
        let bearer = format!("Bearer {KEY}");
        assert_eq!(presented_key(Some(&bearer), None), Ok(KEY));
        assert_eq!(presented_key(None, Some(KEY)), Ok(KEY));
        // The scheme is case-insensitive (RFC 9110, section 11.1).
        let lower = format!("bearer {KEY}");
        assert_eq!(presented_key(Some(&lower), None), Ok(KEY));
        // Both headers with the same key: accepted.
        assert_eq!(presented_key(Some(&bearer), Some(KEY)), Ok(KEY));
    }

    #[test]
    fn ambiguous_or_missing_credentials_are_rejected() {
        let bearer = format!("Bearer {KEY}");
        let basic = format!("Basic {KEY}");
        let rejected = [
            (None, None),
            (Some(bearer.as_str()), Some(OTHER_KEY)),
            (Some(basic.as_str()), None),
            (Some(basic.as_str()), Some(KEY)),
            (Some("Bearer"), None),
            (Some("Bearer "), None),
            (Some(KEY), None),
            (None, Some("")),
            (Some(""), Some(KEY)),
        ];
        for (authorization, x_api_key) in rejected {
            assert_eq!(
                presented_key(authorization, x_api_key),
                Err(BlockCode::UnknownKey),
                "{authorization:?} {x_api_key:?}"
            );
        }
    }

    fn ring(expires_at: Option<&str>) -> KeyRing {
        let expiry = expires_at
            .map(|e| format!("expires_at = \"{e}\"\n"))
            .unwrap_or_default();
        let source = format!(
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
provider = "openai"
base_url = "https://api.openai.com"
credential_env = "OPENAI_API_KEY"

[[principal]]
id = "bot"
key_sha256 = "b138b6b1fa8e691bd3eef6540b642ec4bde4c36713e041751490ea090e374e24"
models.openai = ["gpt-4.1-mini"]
{expiry}"#
        );
        KeyRing::from_config(&Config::from_toml_str(&source).unwrap())
    }

    fn at(rfc3339: &str) -> OffsetDateTime {
        OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn known_key_authenticates() {
        let ring = ring(None);
        let principal = ring.authenticate(KEY, at("2030-01-01T00:00:00Z")).unwrap();
        assert_eq!(principal.id.as_str(), "bot");
    }

    #[test]
    fn unknown_and_malformed_keys_are_rejected() {
        let ring = ring(None);
        let now = at("2030-01-01T00:00:00Z");
        for presented in [OTHER_KEY, "", "sk-not-a-virtual-key", &KEY.to_uppercase()] {
            assert_eq!(
                ring.authenticate(presented, now).map(|p| p.id.as_str()),
                Err(BlockCode::UnknownKey),
                "{presented:?}"
            );
        }
    }

    #[test]
    fn key_expires_exactly_at_expires_at() {
        let ring = ring(Some("2027-02-09T00:00:00Z"));
        let id = |now| ring.authenticate(KEY, at(now)).map(|p| p.id.as_str());
        assert_eq!(id("2027-02-08T23:59:59Z"), Ok("bot"));
        assert_eq!(id("2027-02-09T00:00:00Z"), Err(BlockCode::KeyExpired));
        assert_eq!(id("2027-02-09T00:00:01Z"), Err(BlockCode::KeyExpired));
        // The same instant written with another offset.
        assert_eq!(id("2027-02-09T01:00:00+01:00"), Err(BlockCode::KeyExpired));
    }
}
