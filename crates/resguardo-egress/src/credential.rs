//! Provider credentials: loading and holding (design document, section 6; threat model T5).
//!
//! - Read once at startup from an environment variable or a file. A file readable or writable
//!   by group or others is refused, as is a symbolic link's target with those permissions.
//! - Held in [`secrecy::SecretString`], which wipes the memory when dropped and never prints.
//!   Intermediate copies made while loading are wrapped in [`zeroize::Zeroizing`].
//! - Limits of this approach, stated plainly: the environment variable stays in the process
//!   environment (removing it needs `unsafe`), and the copy placed in the outgoing HTTP header
//!   lives in the HTTP client's buffers until it reuses them.
//! - Errors name the variable or the path, never the value.

use std::fmt;
use std::io::Read;
use std::path::Path;

use resguardo_core::config::CredentialSource;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Larger credential files are refused: no provider key is anywhere near this size.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

/// A provider API key. Only `resguardo-egress` ever holds one.
pub struct ProviderCredential(SecretString);

impl ProviderCredential {
    /// The key itself, for building the outgoing authentication header.
    pub(crate) fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ProviderCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCredential(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("environment variable {0} is not set or is not valid Unicode")]
    EnvMissing(String),
    #[error("cannot read credential file {path}: {kind}")]
    FileRead {
        path: String,
        kind: std::io::ErrorKind,
    },
    #[error("credential file {path} is not a regular file")]
    NotAFile { path: String },
    #[error(
        "credential file {path} is accessible by group or others (mode {mode:o}); run: chmod 600 {path}"
    )]
    FilePermissions { path: String, mode: u32 },
    #[error("credential file {path} is larger than {MAX_CREDENTIAL_BYTES} bytes")]
    TooLarge { path: String },
    #[error("credential from {origin} is empty")]
    Empty { origin: String },
    #[error("credential from {origin} contains characters other than visible ASCII")]
    InvalidCharacters { origin: String },
    #[error("credential_file is only supported on Unix (file permissions cannot be checked)")]
    Unsupported,
}

/// Reads a credential from where the configuration says.
pub fn load(source: &CredentialSource) -> Result<ProviderCredential, CredentialError> {
    match source {
        CredentialSource::Env(name) => {
            let value = std::env::var(name)
                .map(Zeroizing::new)
                .map_err(|_| CredentialError::EnvMissing(name.clone()))?;
            from_raw(&format!("environment variable {name}"), &value)
        }
        CredentialSource::File(path) => load_file(path),
    }
}

#[cfg(unix)]
fn load_file(path: &Path) -> Result<ProviderCredential, CredentialError> {
    use std::os::unix::fs::PermissionsExt;

    let shown = path.display().to_string();
    let read_error = |e: std::io::Error| CredentialError::FileRead {
        path: shown.clone(),
        kind: e.kind(),
    };
    // Open first and inspect the open file, so the checks apply to what is actually read.
    let file = std::fs::File::open(path).map_err(read_error)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() {
        return Err(CredentialError::NotAFile { path: shown });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CredentialError::FilePermissions { path: shown, mode });
    }
    // Capacity reserved up front, so reading never reallocates and leaves stray copies.
    let mut contents = Zeroizing::new(String::with_capacity(MAX_CREDENTIAL_BYTES + 1));
    let limit = u64::try_from(MAX_CREDENTIAL_BYTES + 1).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_string(&mut contents)
        .map_err(read_error)?;
    if contents.len() > MAX_CREDENTIAL_BYTES {
        return Err(CredentialError::TooLarge { path: shown });
    }
    from_raw(&format!("file {shown}"), &contents)
}

#[cfg(not(unix))]
fn load_file(_path: &Path) -> Result<ProviderCredential, CredentialError> {
    Err(CredentialError::Unsupported)
}

/// Trims surrounding whitespace (a trailing newline is usual in files) and accepts only
/// visible ASCII, which is what an HTTP header value may safely carry.
fn from_raw(origin: &str, raw: &str) -> Result<ProviderCredential, CredentialError> {
    let trimmed = raw.trim_ascii();
    if trimmed.is_empty() {
        return Err(CredentialError::Empty {
            origin: origin.to_owned(),
        });
    }
    if !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CredentialError::InvalidCharacters {
            origin: origin.to_owned(),
        });
    }
    Ok(ProviderCredential(SecretString::from(trimmed)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    const FAKE_KEY: &str = "sk-test-not-a-real-key-0123456789";

    /// A directory private to this test process.
    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("resguardo-egress-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fresh file in the test directory, with the given contents and mode.
    fn credential_file(name: &str, contents: &str, mode: u32) -> PathBuf {
        let path = test_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn file_with_owner_only_permissions_is_loaded_and_trimmed() {
        let path = credential_file("ok.key", &format!("{FAKE_KEY}\n"), 0o600);
        let credential = load(&CredentialSource::File(path)).unwrap();
        assert_eq!(credential.expose(), FAKE_KEY);
        let read_only = credential_file("ro.key", FAKE_KEY, 0o400);
        assert!(load(&CredentialSource::File(read_only)).is_ok());
    }

    #[test]
    fn file_readable_by_others_is_refused() {
        for (name, mode) in [("g.key", 0o640), ("o.key", 0o604), ("w.key", 0o620)] {
            let path = credential_file(name, FAKE_KEY, mode);
            let error = load(&CredentialSource::File(path)).unwrap_err();
            assert!(
                matches!(error, CredentialError::FilePermissions { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("chmod 600"));
            assert!(!error.to_string().contains(FAKE_KEY));
        }
    }

    #[test]
    fn missing_file_directory_and_oversized_file_are_refused() {
        let missing = CredentialSource::File("/nonexistent/key".into());
        assert!(matches!(
            load(&missing).unwrap_err(),
            CredentialError::FileRead { .. }
        ));
        assert!(matches!(
            load(&CredentialSource::File(test_dir())).unwrap_err(),
            CredentialError::NotAFile { .. }
        ));
        let big = credential_file("big.key", &"a".repeat(MAX_CREDENTIAL_BYTES + 1), 0o600);
        assert!(matches!(
            load(&CredentialSource::File(big)).unwrap_err(),
            CredentialError::TooLarge { .. }
        ));
    }

    #[test]
    fn empty_or_non_header_safe_values_are_refused() {
        assert!(matches!(
            from_raw("test", " \n").unwrap_err(),
            CredentialError::Empty { .. }
        ));
        for bad in ["sk test", "sk-\u{e9}", "sk-\r\nx-evil: 1", "sk-\t1"] {
            let error = from_raw("test", bad).unwrap_err();
            assert!(
                matches!(error, CredentialError::InvalidCharacters { .. }),
                "{bad:?}"
            );
            assert!(!error.to_string().contains("sk"), "{error}");
        }
    }

    #[test]
    fn missing_environment_variable_is_reported_by_name() {
        let source = CredentialSource::Env("RESGUARDO_TEST_SURELY_UNSET_7f3a".into());
        let error = load(&source).unwrap_err();
        assert_eq!(
            error.to_string(),
            "environment variable RESGUARDO_TEST_SURELY_UNSET_7f3a is not set or is not valid Unicode"
        );
    }

    #[test]
    fn debug_never_shows_the_key() {
        let credential = from_raw("test", FAKE_KEY).unwrap();
        assert!(!format!("{credential:?}").contains(FAKE_KEY));
    }
}
