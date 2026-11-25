//! `mock-upstream`: fake OpenAI and Anthropic server for local tests and the lab.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;

/// Fake OpenAI and Anthropic API. Never calls a real provider.
#[derive(Parser)]
#[command(name = "mock-upstream", version)]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("binding {}", cli.listen))?;
    println!(
        "mock-upstream listening on http://{}",
        listener.local_addr()?
    );
    resguardo_mock_upstream::serve(listener).await?;
    Ok(())
}
