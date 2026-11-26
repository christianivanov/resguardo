//! `resguardo` binary: HTTP proxy server and CLI.
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use resguardo::server::{App, serve};
use resguardo_audit::{AuditLog, KeyError, PublicKey, SigningKey, VerifyError};
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
    /// Create the signing key pair and the log folder, and the configuration if it is
    /// missing (from the example).
    ///
    /// Existing keys are never replaced. With --rotate-key, a new pair replaces the current
    /// one: the log records the rotation, signed with the old key, the old public key is kept
    /// as <public_key>.<seq> and the old private key is deleted.
    Init {
        /// Path to the configuration file.
        #[arg(long, default_value = "resguardo.toml")]
        config: PathBuf,
        /// Replace the current key pair and record the rotation in the log.
        #[arg(long)]
        rotate_key: bool,
    },
    /// Check the hash chain, signatures and sequence of an audit log.
    ///
    /// Give the public key that signed the first entry: rotations are followed from there.
    /// Exits with 0 when every entry verifies, 1 at the first one that does not (with its
    /// line and the reason: format, hash, sig, prev or seq) and 2 when it cannot read.
    VerifyLog {
        /// The audit log (JSON Lines).
        path: PathBuf,
        /// Public key file (`ed25519:...`).
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Run the detectors over the labelled accuracy corpus and print, per class, what was
    /// found, missed and wrongly found.
    ///
    /// With --baseline, exits with 1 if any class misses more or finds more false positives
    /// than the published counts; with --write-baseline, records the current counts.
    Accuracy {
        /// The corpus (JSON Lines with text, expect, allow and group).
        #[arg(long, default_value = "fixtures/accuracy/corpus.jsonl")]
        corpus: PathBuf,
        /// Published counts that this run may not exceed.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Write the counts of this run as the new baseline.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
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
        Command::Init { config, rotate_key } => if rotate_key {
            rotate(&config)
        } else {
            init(&config)
        }
        .map(|()| Outcome::Success),
        Command::VerifyLog { path, pubkey } => verify_log(&path, &pubkey),
        Command::Accuracy {
            corpus,
            baseline,
            write_baseline,
        } => accuracy(&corpus, baseline.as_deref(), write_baseline.as_deref()),
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

/// Example configuration written by `init` when there is none.
const EXAMPLE_CONFIG: &str = include_str!("../../../config/resguardo.example.toml");

fn init(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        std::fs::write(path, EXAMPLE_CONFIG)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!(
            "Wrote {} from the example configuration: edit it before `resguardo run`.",
            path.display()
        );
    }
    let config = load_config(path)?;
    let audit = &config.audit;
    for file in [&audit.path, &audit.signing_key, &audit.public_key] {
        create_parent(file)?;
    }
    let key = match SigningKey::create_files(&audit.signing_key, &audit.public_key) {
        Ok(key) => key,
        Err(KeyError::Exists(existing)) => bail!(
            "{} already exists; keys are never replaced here, use `resguardo init --rotate-key`",
            existing.display()
        ),
        Err(error) => return Err(error.into()),
    };
    eprintln!(
        "Signing key: {} (owner-only). Public key: {}. Give the public key to auditors:",
        audit.signing_key.display(),
        audit.public_key.display()
    );
    println!("{}", key.public_key().to_text());
    Ok(())
}

/// Owner-only folders for the log and the keys.
fn create_parent(file: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .with_context(|| format!("creating {}", parent.display()))
}

/// ADR 0015: the new pair is written aside first, then the rotation is recorded with the
/// old key, then the files are swapped. A crash in between leaves a log that refuses to
/// start until the new files are in place, never one signed with the wrong key.
fn rotate(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let audit = &config.audit;
    let old = SigningKey::load(&audit.signing_key)?;
    let log = AuditLog::open(&audit.path, old, audit.fsync)?;
    let new_private = with_suffix(&audit.signing_key, "new");
    let new_public = with_suffix(&audit.public_key, "new");
    let new = SigningKey::create_files(&new_private, &new_public)?;
    let seq = log.rotate_key(new.clone())?;
    std::fs::remove_file(&audit.signing_key)
        .with_context(|| format!("removing the old key {}", audit.signing_key.display()))?;
    let kept = with_suffix(&audit.public_key, &seq.to_string());
    std::fs::rename(&audit.public_key, &kept)
        .with_context(|| format!("keeping the old public key as {}", kept.display()))?;
    std::fs::rename(&new_private, &audit.signing_key)
        .with_context(|| format!("installing {}", audit.signing_key.display()))?;
    std::fs::rename(&new_public, &audit.public_key)
        .with_context(|| format!("installing {}", audit.public_key.display()))?;
    eprintln!(
        "Key rotated at entry {seq}. Old public key kept as {}; old private key deleted. \
         Restart `resguardo run`. New public key:",
        kept.display()
    );
    println!("{}", new.public_key().to_text());
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// ADR 0009: 0 intact, 1 a line fails, 2 the log or key cannot be read.
fn verify_log(path: &Path, pubkey: &Path) -> anyhow::Result<Outcome> {
    let key = PublicKey::load(pubkey)?;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    match resguardo_audit::verify_log(std::io::BufReader::new(file), &key) {
        Ok(verified) => {
            println!("{}: OK ({} entries)", path.display(), verified.entries);
            Ok(Outcome::Success)
        }
        Err(VerifyError::Failed { line, reason }) => {
            println!("{}: line {line}: {reason}", path.display());
            Ok(Outcome::ProblemsFound)
        }
        Err(error @ VerifyError::Io(_)) => {
            Err(anyhow::Error::new(error).context(path.display().to_string()))
        }
    }
}

/// ADR 0009: 0 within the baseline (or none given), 1 a regression, 2 cannot read.
fn accuracy(
    corpus: &Path,
    baseline: Option<&Path>,
    write_baseline: Option<&Path>,
) -> anyhow::Result<Outcome> {
    let text =
        std::fs::read_to_string(corpus).with_context(|| format!("reading {}", corpus.display()))?;
    let samples = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("{}: line {}", corpus.display(), i + 1))
        })
        .collect::<anyhow::Result<Vec<resguardo::accuracy::Sample>>>()?;
    let pipeline = Pipeline::new(&ScanConfig::default())?;
    let report = resguardo::accuracy::run(&pipeline, &samples)?;
    print!("{}", report.table());
    if let Some(path) = write_baseline {
        let json = serde_json::to_string_pretty(&report.baseline())?;
        std::fs::write(path, json + "\n").with_context(|| format!("writing {}", path.display()))?;
        eprintln!("baseline written to {}", path.display());
    }
    let Some(path) = baseline else {
        return Ok(Outcome::Success);
    };
    let published: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| path.display().to_string())?;
    let regressions = report.regressions(&published);
    if regressions.is_empty() {
        println!("\nwithin the baseline in {}", path.display());
        Ok(Outcome::Success)
    } else {
        println!("\nworse than the baseline in {}:", path.display());
        for regression in regressions {
            println!("  {regression}");
        }
        Ok(Outcome::ProblemsFound)
    }
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
