mod config;
mod datapath;
mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dumbarp_routing::RouteManager;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::datapath::Datapath;
use crate::reconcile::RouterState;

#[derive(Parser)]
#[command(
    name = "dumbarp-routerd",
    about = "Router-node reconciler: source-based routes plus the DSCP-mode eBPF datapath"
)]
struct Cli {
    #[arg(long, default_value = "/etc/dumbarp-routerd.toml")]
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
    let router = Arc::new(RouteManager::new()?);
    let datapath = Datapath::load(&cfg.dscp.ifaces, cfg.dscp.max_flows)?;
    let state = Arc::new(RouterState {
        cache: Default::default(),
        gateway_cache: Default::default(),
        datapath: Mutex::new(datapath),
        known_ids: Default::default(),
    });

    tracing::info!(
        daemons = cfg.daemons.len(),
        ifaces = cfg.dscp.ifaces.len(),
        max_flows = cfg.dscp.max_flows,
        refresh_interval_secs = cfg.refresh_interval_secs,
        stale_after_secs = cfg.stale_after_secs,
        "dumbarp-routerd starting"
    );

    if let Err(err) = router.reconcile(&[]).await {
        tracing::error!(%err, "purging leftover routing state failed");
    }

    if let Err(err) = reconcile::reconcile_once(&cfg, &http, &router, &state).await {
        tracing::error!(%err, "initial reconcile failed");
    }
    reconcile::spawn(cfg, http, Arc::clone(&router), state);

    shutdown_signal().await?;
    tracing::info!("shutting down");
    if let Err(err) = router.reconcile(&[]).await {
        tracing::error!(%err, "tearing down routing state failed");
    }
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => res?,
        _ = sigterm.recv() => {}
    }
    Ok(())
}
