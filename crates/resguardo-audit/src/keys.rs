//! The instance's Ed25519 key pair (ADR 0003, ADR 0015), from `aws-lc-rs`, the provider
//! rustls already uses (ADR 0006): no cryptography is implemented here.
//!
//! - Private key file: `ed25519-pkcs8:` and the PKCS#8 v2 document in Base64url, one line,
//!   owner-only (0600). A wider file is refused, like provider credentials.
//! - Public key file: `ed25519:` and the 32 raw bytes in Base64url, one line. It is all an
//!   auditor needs.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroize;

const PRIVATE_PREFIX: &str = "ed25519-pkcs8:";
const PUBLIC_PREFIX: &str = "ed25519:";

/// Messages name files and causes, never key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{0}: already exists; refusing to overwrite a key")]
    Exists(PathBuf),
    #[error("{0}: the signing key must be readable by its owner only (chmod 600)")]
    Permissions(PathBuf),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0}: not a key file Resguardo wrote")]
    Format(PathBuf),
    #[error("the key pair could not be generated")]
    Generate,
}

/// The private key. `Clone` shares it (`Arc`), it is never copied out.
#[derive(Clone)]
pub struct SigningKey {
    pair: Arc<Ed25519KeyPair>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.public_key().to_text())
    }
}

impl SigningKey {
    /// A new key from the operating system's random generator.
    pub fn generate() -> Result<Self, KeyError> {
        let mut pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| KeyError::Generate)?
            .as_ref()
            .to_vec();
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| KeyError::Generate);
        pkcs8.zeroize();
        Ok(Self {
            pair: Arc::new(pair?),
        })
    }

    /// Generates a key and writes both files. Existing files are never overwritten.
    pub fn create_files(private: &Path, public: &Path) -> Result<Self, KeyError> {
        for path in [private, public] {
            if path.exists() {
                return Err(KeyError::Exists(path.to_owned()));
            }
        }
        let key = Self::generate()?;
        key.write_files(private, public)?;
        Ok(key)
    }

    /// Writes the private key (0600, created new) and the public key.
    pub fn write_files(&self, private: &Path, public: &Path) -> Result<(), KeyError> {
        let mut pkcs8 = self
            .pair
            .to_pkcs8()
            .map_err(|_| KeyError::Generate)?
            .as_ref()
            .to_vec();
        let mut line = format!("{PRIVATE_PREFIX}{}\n", URL_SAFE_NO_PAD.encode(&pkcs8));
        pkcs8.zeroize();
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(private)
            .and_then(|mut file| {
                file.write_all(line.as_bytes())
                    .and_then(|()| file.sync_all())
            });
        line.zeroize();
        written.map_err(|source| io_error(private, source))?;
        fs::write(public, format!("{}\n", self.public_key().to_text()))
            .map_err(|source| io_error(public, source))
    }

    /// Loads the private key, refusing a file others can read or write.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let io = |source| KeyError::Io {
            path: path.to_owned(),
            source,
        };
        let mode = fs::metadata(path).map_err(io)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::Permissions(path.to_owned()));
        }
        let mut text = fs::read_to_string(path).map_err(io)?;
        let decoded = text
            .trim()
            .strip_prefix(PRIVATE_PREFIX)
            .and_then(|b64| URL_SAFE_NO_PAD.decode(b64).ok());
        text.zeroize();
        let Some(mut pkcs8) = decoded else {
            return Err(KeyError::Format(path.to_owned()));
        };
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8);
        pkcs8.zeroize();
        let pair = pair.map_err(|_| KeyError::Format(path.to_owned()))?;
        Ok(Self {
            pair: Arc::new(pair),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        let mut bytes = [0u8; 32];
        let raw = self.pair.public_key().as_ref();
        if raw.len() == bytes.len() {
            bytes.copy_from_slice(raw);
        }
        PublicKey(bytes)
    }

    /// Signs `message`: 64 bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }
}

fn io_error(path: &Path, source: std::io::Error) -> KeyError {
    KeyError::Io {
        path: path.to_owned(),
        source,
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl PublicKey {
    /// `ed25519:` and the key in Base64url without padding.
    pub fn to_text(&self) -> String {
        format!("{PUBLIC_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.0))
    }

    pub fn parse(text: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text.trim().strip_prefix(PUBLIC_PREFIX)?)
            .ok()?;
        Some(Self(bytes.try_into().ok()?))
    }

    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let text = fs::read_to_string(path).map_err(|source| KeyError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text).ok_or_else(|| KeyError::Format(path.to_owned()))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&signature::ED25519, self.0)
            .verify(message, signature)
            .is_ok()
    }
}
