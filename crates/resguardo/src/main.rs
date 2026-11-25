//! `resguardo` binary: HTTP proxy server and CLI.
#![forbid(unsafe_code)]

fn main() {
    println!("resguardo {}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "resguardo");
    }
}
