//! Policy decision from principal, request and findings. Pure: no I/O, no clock.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo-policy");
    }
}
