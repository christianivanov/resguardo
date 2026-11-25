//! The only crate that talks to providers: destination allowlist, credentials, HTTP and TLS.
//!
//! Must never depend on `resguardo-scan` or `resguardo-policy`: it only receives requests
//! that have already been decided.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo-egress");
    }
}
