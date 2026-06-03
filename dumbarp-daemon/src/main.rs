mod config;
mod dhcp;
mod http;
mod lease;
mod neigh;
mod refresh;
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dumbarp::Dumbarp;
use tracing_subscriber::EnvFilter;

use dumbarp_routing::RouteManager;

use crate::config::Config;
use crate::state::AppState;

#[derive(Parser)]
#[command(name = "dumbarpd", about = "HTTP-fronted dumbarp daemon")]
struct Cli {
    #[arg(long, default_value = "/etc/dumbarpd.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

    let engine = Dumbarp::new()?;
    let state = AppState::new(cfg.auth_token, engine);

    let router = if cfg.manage_routing {
        Some(Arc::new(RouteManager::new()?))
    } else {
        None
    };

    dhcp::spawn_all(
        state.clone(),
        cfg.ifaces.clone(),
        Duration::from_secs(cfg.neigh_refresh_interval_secs),
    );
    refresh::spawn(
        state.clone(),
        Duration::from_secs(cfg.refresh_interval_secs),
        router,
    );

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(addr = %cfg.listen, "dumbarpd listening");
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
