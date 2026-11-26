//! Resguardo's HTTP server and the pieces only the binary needs.
#![forbid(unsafe_code)]

pub mod accuracy;
pub mod rate_limit;
mod receipt;
mod response;
pub mod server;
