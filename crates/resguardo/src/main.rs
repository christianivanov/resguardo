//! `resguardo` binary: HTTP proxy server and CLI.
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use resguardo::server::{App, serve};
use resguardo_core::config::ScanConfig;
use resguardo_core::virtual_key::RANDOM_BYTES;
use resguardo_core::{Config, Limits, OffsetDateTime, PrincipalId, ScanReport, VirtualKey};
use resguardo_scan::Pipeline;

/// Largest input `resguardo scan` accepts: the default request body limit.
const MAX_SCAN_INPUT_BYTES: usize = Limits::DEFAULT_MAX_BODY_BYTES;

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
    /// Scan a text with the default detectors and print what was found, never the values.
    ///
    /// Each line gives the data class, the rule, the byte range and the decoding layers.
    /// Input over 1 MiB (the default request body limit) or not valid UTF-8 is refused.
    ///
    /// Exits with 0 when nothing was found, 1 with any finding or limit flag, and 2 when the
    /// input could not be scanned.
    Scan {
        /// File to scan. Without it, standard input is read.
        #[arg(long)]
        file: Option<PathBuf>,
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

/// What a command that completed reports through its exit code (ADR 0009).
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The command did its job and the answer is yes: exit code 0.
    Success,
    /// The command did its job and the answer is no: exit code 1.
    ProblemsFound,
}

/// The command could not do its job (ADR 0009). `clap` uses the same code for invalid
/// arguments.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run { config } => run(&config).map(|()| Outcome::Success),
        Command::Config {
            command: ConfigCommand::Check { config },
        } => config_check(&config),
        Command::Key {
            command: KeyCommand::Create { principal },
        } => key_create(&principal).map(|()| Outcome::Success),
        Command::Scan { file } => scan(file.as_deref()),
    };
    match result {
        Ok(Outcome::Success) => ExitCode::SUCCESS,
        Ok(Outcome::ProblemsFound) => ExitCode::FAILURE,
        Err(error) => {
            print_error(&error);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn print_error(error: &anyhow::Error) {
    // `{:#}` prints the whole context chain on one line: "reading x: No such file".
    eprintln!("error: {error:#}");
}

/// Reads and validates the configuration. Warnings go to stderr.
fn load_config(path: &Path) -> anyhow::Result<Config> {
    parse_config(path, &read_config(path)?)
}

fn read_config(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Validates the configuration read from `path` and prints its warnings on stderr.
fn parse_config(path: &Path, source: &str) -> anyhow::Result<Config> {
    let config = Config::from_toml_str(source).with_context(|| path.display().to_string())?;
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

/// A file that cannot be read is an error; a file that is read but invalid is a problem
/// found, because checking it is this command's job (ADR 0009).
fn config_check(path: &Path) -> anyhow::Result<Outcome> {
    let source = read_config(path)?;
    let config = match parse_config(path, &source) {
        Ok(config) => config,
        Err(problems) => {
            print_error(&problems);
            return Ok(Outcome::ProblemsFound);
        }
    };
    println!(
        "{}: OK ({} upstream(s), {} principal(s))",
        path.display(),
        config.upstreams.len(),
        config.principals.len()
    );
    Ok(Outcome::Success)
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

/// Scans a file or standard input. Output names classes, rules and byte ranges only, so it
/// is safe to paste into a ticket.
fn scan(file: Option<&Path>) -> anyhow::Result<Outcome> {
    let bytes = match file {
        Some(path) => {
            let file =
                std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
            read_limited(file).with_context(|| format!("reading {}", path.display()))?
        }
        None => read_limited(std::io::stdin().lock()).context("reading standard input")?,
    };
    // The error is not shown: it would quote bytes of the input.
    let Ok(text) = String::from_utf8(bytes) else {
        bail!("the input is not valid UTF-8");
    };
    let pipeline = Pipeline::new(&ScanConfig::default())?;
    let report = pipeline.scan_text("", &text)?;
    print!("{}", format_report(&report));
    Ok(scan_outcome(&report))
}

/// A flag means part of the input was not fully checked, so it is never reported as clean.
fn scan_outcome(report: &ScanReport) -> Outcome {
    if report.findings.is_empty() && report.flags.is_empty() {
        Outcome::Success
    } else {
        Outcome::ProblemsFound
    }
}

/// Reads at most [`MAX_SCAN_INPUT_BYTES`]; anything longer is refused, not cut, so a partial
/// scan is never presented as a complete one.
fn read_limited(reader: impl Read) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    // `take` stops after one byte more than the limit: enough to know it was exceeded.
    reader
        .take(MAX_SCAN_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SCAN_INPUT_BYTES {
        bail!("the input is larger than {MAX_SCAN_INPUT_BYTES} bytes");
    }
    Ok(bytes)
}

fn format_report(report: &ScanReport) -> String {
    let mut out = String::new();
    for finding in &report.findings {
        out.push_str(&format!(
            "finding  {}  {}  bytes {}..{}  confidence {}",
            finding.class, finding.rule, finding.span.start, finding.span.end, finding.confidence
        ));
        if !finding.via.is_empty() {
            out.push_str(&format!("  via {}", finding.via.join(",")));
        }
        out.push('\n');
    }
    for flag in &report.flags {
        out.push_str(&format!(
            "flag     {}  bytes {}..{}  via {}\n",
            flag.limit,
            flag.span.start,
            flag.span.end,
            flag.via.join(",")
        ));
    }
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    out.push_str(&format!(
        "{}, {}\n",
        plural(report.findings.len(), "finding"),
        plural(report.flags.len(), "flag")
    ));
    out
}

#[cfg(test)]
mod tests {
    use resguardo_core::{ScanFlag, ScanLimit};

    use super::*;

    #[test]
    fn a_flag_without_findings_is_not_clean() {
        let report = ScanReport {
            findings: Vec::new(),
            flags: vec![ScanFlag {
                limit: ScanLimit::DerivedBytes,
                pointer: String::new(),
                span: 0..10,
                via: vec!["base64".into()],
            }],
        };
        assert_eq!(scan_outcome(&report), Outcome::ProblemsFound);
    }

    #[test]
    fn an_empty_report_is_clean() {
        assert_eq!(scan_outcome(&ScanReport::default()), Outcome::Success);
    }
}
