//! Domain types, errors and configuration shared by every Resguardo crate.
#![forbid(unsafe_code)]

pub mod config;
pub mod domain;

pub use config::{Config, ConfigError};
pub use domain::*;
