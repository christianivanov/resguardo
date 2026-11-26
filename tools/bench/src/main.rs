//! Benchmark (milestone M6.2, ADR 0016): scanning throughput, and the latency Resguardo adds
//! end to end. Everything runs locally against the mock provider: no real API is called.
//!
//! Run in release mode: `cargo run --release -p resguardo-bench`.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use resguardo::server::{App, serve};
use resguardo_audit::SigningKey;
use resguardo_core::config::ScanConfig;
use resguardo_core::{Config, VirtualKey};
use resguardo_mock_upstream::MockUpstream;
use resguardo_scan::Pipeline;

const REQUESTS: usize = 400;
const WARMUP: usize = 20;

fn main() -> anyhow::Result<()> {
    println!("{}", machine());
    scanning()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(end_to_end())
}

fn machine() -> String {
    format!(
        "{} {}, {} logical CPUs, build {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        if cfg!(debug_assertions) {
            "debug (use --release)"
        } else {
            "release"
        }
    )
}

/// A Spanish support conversation with a DNI, an email and a Base64 fragment every few
/// kilobytes: ordinary text with the occasional finding.
fn text(bytes: usize) -> String {
    let block = "El cliente pregunta por el estado de su pedido 12345678 y por la factura \
                 FAC-2026/0042. Indica que su DNI es 12345678Z y su correo ana@example.es. \
                 Adjunta el registro aGVsbG8gd29ybGQgZnJvbSB0aGUgbG9ncw== para soporte. ";
    block.repeat(bytes / block.len() + 1)[..bytes].to_owned()
}

fn scanning() -> anyhow::Result<()> {
    let pipeline = Pipeline::new(&ScanConfig::default())?;
    println!("\n## Scanning\n\n| Text | Per scan | Throughput |\n| --- | --- | --- |");
    for (label, bytes) in [("1 KB", 1024), ("16 KB", 16 * 1024), ("256 KB", 256 * 1024)] {
        let text = text(bytes);
        let runs = (4 * 1024 * 1024 / bytes).clamp(5, 2000);
        let started = Instant::now();
        for _ in 0..runs {
            pipeline.scan_text("/messages/0/content", &text)?;
        }
        let each = started.elapsed() / u32::try_from(runs)?;
        let mb_per_s = bytes as f64 / each.as_secs_f64() / 1_000_000.0;
        println!("| {label} | {} | {mb_per_s:.1} MB/s |", show(each));
    }
    Ok(())
}

async fn end_to_end() -> anyhow::Result<()> {
    let mock = MockUpstream::start(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let client = reqwest::Client::new();
    let plain = r#"{"model":"llama-3","messages":[{"role":"user","content":"hola, ¿cómo va mi pedido 12345678?"}]}"#;
    let with_dni = r#"{"model":"llama-3","messages":[{"role":"user","content":"Mi DNI es 12345678Z y mi pedido el 12345678"}]}"#;

    println!(
        "\n## Latency added end to end\n\n{REQUESTS} sequential requests after {WARMUP} warm-up ones, \
         each through a fresh connection pool shared by the run. \"Added\" is the difference \
         with the same request sent straight to the mock.\n"
    );
    println!(
        "| Path | p50 | p95 | p99 | Added p50 | Added p99 |\n| --- | --- | --- | --- | --- | --- |"
    );
    let direct = run(
        &client,
        &format!("{}/v1/chat/completions", mock.base_url()),
        None,
        plain,
    )
    .await?;
    row("Direct to the mock", &direct, None);

    for (label, fsync, body) in [
        ("Through Resguardo, fsync on", true, plain),
        ("Through Resguardo, fsync off", false, plain),
        (
            "Through Resguardo, redacting a DNI, fsync on",
            true,
            with_dni,
        ),
    ] {
        let (url, key, _dir) = start_resguardo(&mock, fsync).await?;
        let through = run(&client, &url, Some(&key), body).await?;
        row(label, &through, Some(&direct));
    }
    Ok(())
}

async fn start_resguardo(
    mock: &MockUpstream,
    fsync: bool,
) -> anyhow::Result<(String, String, PathBuf)> {
    let dir = std::env::temp_dir().join(format!(
        "resguardo-bench-{}-{}",
        std::process::id(),
        if fsync { "fsync" } else { "nofsync" }
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    SigningKey::create_files(&dir.join("signing.key"), &dir.join("signing.pub"))?;
    let key = VirtualKey::from_random_bytes(&[42; 32]);
    let source = format!(
        r#"
[audit]
path = "{dir}/audit.jsonl"
signing_key = "{dir}/signing.key"
public_key = "{dir}/signing.pub"
fsync = {fsync}

[policy.actions]
secret = "block"
secret_candidate = "flag"
es_id = "redact"
iban = "redact"
card = "block"
phone = "redact"
email = "redact"
invisible_text = "redact"

[[upstream]]
provider = "openai_compatible"
base_url = "{base}"
allow_insecure_upstream = true

[[principal]]
id = "bench"
key_sha256 = "{hash}"
requests_per_minute = 100000
models.openai_compatible = ["llama-3"]
"#,
        dir = dir.display(),
        base = mock.base_url(),
        hash = key.hash().as_str(),
    );
    let config = Config::from_toml_str(&source).context("bench configuration")?;
    let app = Arc::new(App::from_config(&config)?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/v1/chat/completions", listener.local_addr()?);
    tokio::spawn(serve(listener, app, std::future::pending()));
    Ok((url, key.expose_secret().to_owned(), dir))
}

async fn run(
    client: &reqwest::Client,
    url: &str,
    key: Option<&str>,
    body: &str,
) -> anyhow::Result<Vec<Duration>> {
    let mut times = Vec::with_capacity(REQUESTS);
    for i in 0..WARMUP + REQUESTS {
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_owned());
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let started = Instant::now();
        let response = request.send().await?;
        let status = response.status();
        response.bytes().await?;
        let elapsed = started.elapsed();
        anyhow::ensure!(status.is_success(), "request {i} failed with {status}");
        if i >= WARMUP {
            times.push(elapsed);
        }
    }
    times.sort();
    Ok(times)
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted
        .get((sorted.len() * p / 100).min(sorted.len().saturating_sub(1)))
        .copied()
        .unwrap_or_default()
}

fn row(label: &str, times: &[Duration], direct: Option<&[Duration]>) {
    let (p50, p95, p99) = (
        percentile(times, 50),
        percentile(times, 95),
        percentile(times, 99),
    );
    let added = |p: usize, value: Duration| {
        direct.map_or("—".to_owned(), |d| {
            show(value.saturating_sub(percentile(d, p)))
        })
    };
    println!(
        "| {label} | {} | {} | {} | {} | {} |",
        show(p50),
        show(p95),
        show(p99),
        added(50, p50),
        added(99, p99)
    );
}

fn show(d: Duration) -> String {
    let micros = d.as_micros();
    if micros >= 10_000 {
        format!("{:.1} ms", micros as f64 / 1000.0)
    } else {
        format!("{micros} µs")
    }
}
