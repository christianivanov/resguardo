//! Hash-chained, Ed25519-signed audit log and its verification.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo-audit");
    }
}
