//! `resguardo` binary: HTTP proxy server and CLI.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use resguardo_core::Config;

/// An egress boundary for LLM traffic: nothing leaves without policy,
/// and every decision leaves a signed receipt.
#[derive(Parser)]
#[command(name = "resguardo", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Validate a configuration file without starting the proxy.
    Check {
        /// Path to the configuration file.
        #[arg(long, default_value = "resguardo.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Config {
            command: ConfigCommand::Check { config },
        } => config_check(&config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // `{:#}` prints the whole context chain on one line: "reading x: No such file".
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Reads and validates the configuration. Warnings go to stderr; the summary to stdout.
fn load_config(path: &Path) -> anyhow::Result<Config> {
    let source =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config = Config::from_toml_str(&source).with_context(|| path.display().to_string())?;
    for warning in &config.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(config)
}

fn config_check(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    println!(
        "{}: OK ({} upstream(s), {} principal(s))",
        path.display(),
        config.upstreams.len(),
        config.principals.len()
    );
    Ok(())
}
