mod client;
mod config;
mod http;
mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dumbarp_routing::RouteManager;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::reconcile::GatewayState;

#[derive(Parser)]
#[command(name = "dumbarp-gateway", about = "Installs source-based routes for IPs leased by dumbarp daemons")]
struct Cli {
    #[arg(long, default_value = "/etc/dumbarp-gateway.toml")]
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
    // Left unbuilt when route management is off, so no rtnetlink socket is
    // opened at all: a dumbarp-routerd on the same host then owns the policy
    // rules and routes outright, instead of the two overwriting each other on
    // every pass.
    let router = match cfg.manage_routes {
        true => Some(Arc::new(RouteManager::new()?)),
        false => None,
    };
    let state = Arc::new(GatewayState::default());

    tracing::info!(
        daemons = cfg.daemons.len(),
        manage_routes = cfg.manage_routes,
        refresh_interval_secs = cfg.refresh_interval_secs,
        stale_after_secs = cfg.stale_after_secs,
        "dumbarp-gateway starting"
    );

    if let Err(err) = reconcile::reconcile_once(&cfg, &http, router.as_deref(), &state).await {
        tracing::error!(%err, "initial reconcile failed");
    }
    reconcile::spawn(cfg.clone(), http, router, state.clone());

    match cfg.serve.clone() {
        Some(serve) => {
            let listener = tokio::net::TcpListener::bind(serve.listen).await?;
            tracing::info!(addr = %serve.listen, "serving /daemons");
            let serve_state = crate::http::ServeState {
                cfg,
                state,
                auth_token: Arc::from(serve.auth_token),
            };
            axum::serve(listener, crate::http::router(serve_state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        None => {
            tokio::signal::ctrl_c().await?;
        }
    }

    tracing::info!("shutting down");
    Ok(())
}
