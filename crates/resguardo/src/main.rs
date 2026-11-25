//! `resguardo` binary: HTTP proxy server and CLI.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use resguardo::server::{App, serve};
use resguardo_core::virtual_key::RANDOM_BYTES;
use resguardo_core::{Config, OffsetDateTime, PrincipalId, VirtualKey};

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
    /// Start the proxy.
    Run {
        /// Path to the configuration file.
        #[arg(long, default_value = "resguardo.toml")]
        config: PathBuf,
    },
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Virtual key tools.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
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

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a virtual key. The key is printed once on stdout; its hash and the line to add
    /// to the configuration go to stderr.
    Create {
        /// Id of the principal the key is for.
        #[arg(long)]
        principal: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run { config } => run(&config),
        Command::Config {
            command: ConfigCommand::Check { config },
        } => config_check(&config),
        Command::Key {
            command: KeyCommand::Create { principal },
        } => key_create(&principal),
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
    let now = OffsetDateTime::now_utc();
    for configured in &config.principals {
        let principal = &configured.principal;
        if principal
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            eprintln!(
                "warning: the virtual key of principal '{}' has expired; its requests will be rejected",
                principal.id
            );
        }
    }
    Ok(config)
}

/// Loads everything first (config, credentials, listener), so a problem stops startup
/// before any request is accepted.
fn run(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async {
        let app = Arc::new(App::from_config(&config)?);
        let listener = tokio::net::TcpListener::bind(config.server.listen)
            .await
            .with_context(|| format!("listening on {}", config.server.listen))?;
        eprintln!("resguardo listening on http://{}", listener.local_addr()?);
        serve(listener, app, shutdown_signal())
            .await
            .context("serving")?;
        eprintln!("resguardo stopped");
        Ok(())
    })
}

/// Ctrl-C or, on Unix, SIGTERM (what Docker, systemd and Kubernetes send).
async fn shutdown_signal() {
    let ctrl_c = async {
        // If the handler cannot be installed, never resolve: keep serving.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
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

/// Generates a key from the operating system's random generator. If randomness is not
/// available, no key is printed: a weak key is worse than none.
fn key_create(principal: &str) -> anyhow::Result<()> {
    let Some(principal) = PrincipalId::parse(principal) else {
        bail!(
            "invalid principal id '{principal}': use 1 to 64 characters of a-z, 0-9, '-' or '_', \
             starting with a letter or digit"
        );
    };
    let mut bytes = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("the operating system's random generator failed: {e}"))?;
    // Not wiped afterwards: a plain overwrite can be optimized away, and the process exits
    // right after printing. Memory wiping (`zeroize`) arrives with provider credentials (M1.5).
    let key = VirtualKey::from_random_bytes(&bytes);

    // The key alone on stdout, so `resguardo key create … > file` captures only the key.
    println!("{}", key.expose_secret());
    eprintln!(
        "Virtual key for principal '{principal}' printed on stdout. It is shown only once: store it now.\n\
         Add this line to the [[principal]] entry with id = \"{principal}\":\n\n    key_sha256 = \"{}\"\n",
        key.hash().as_str()
    );
    Ok(())
}
