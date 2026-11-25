//! Domain types, errors and configuration shared by every Resguardo crate.
#![forbid(unsafe_code)]

pub mod config;
pub mod domain;
pub mod virtual_key;

pub use config::{Config, ConfigError};
pub use domain::*;
pub use virtual_key::{KeyRing, VirtualKey};

/// Re-exported so callers pass the current time without depending on `time` themselves.
pub use time::OffsetDateTime;
