//! Domain types, errors and configuration shared by every Resguardo crate.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo-core");
    }
}
