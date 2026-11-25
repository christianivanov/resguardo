//! Normalization of OpenAI and Anthropic requests, and the incremental SSE parser.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo-proto");
    }
}
