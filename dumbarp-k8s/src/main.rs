mod client;
mod config;
mod crd;
mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "dumbarp-k8s", about = "Replicates dumbarp daemon leases into Cilium LB-IPAM pools")]
struct Cli {
    #[arg(long, default_value = "/etc/dumbarp-k8s/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let cfg = Arc::new(Config::load(&cli.config)?);

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let kube = kube::Client::try_default().await?;

    tracing::info!(
        hosts = cfg.hosts.len(),
        refresh_interval_secs = cfg.refresh_interval_secs,
        stale_after_secs = cfg.stale_after_secs,
        "dumbarp-k8s starting"
    );

    if let Err(err) = reconcile::reconcile_once(&cfg, &http, &kube).await {
        tracing::error!(%err, "initial reconcile failed");
    }
    reconcile::spawn(cfg, http, kube);

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
