use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use dumbarp_api::LeaseCache;
use dumbarp_routing::{RouteManager, RouteSpec};
use futures::future::join_all;
use tokio::time::{MissedTickBehavior, interval};

use crate::client::fetch;
use crate::config::{Config, DaemonEntry};

pub type GatewayState = LeaseCache;

pub fn spawn(
    cfg: Arc<Config>,
    http: reqwest::Client,
    router: Option<Arc<RouteManager>>,
    state: Arc<GatewayState>,
) {
    tokio::spawn(async move {
        let period = Duration::from_secs(cfg.refresh_interval_secs);
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // consume immediate first tick — reconcile_once already ran
        loop {
            ticker.tick().await;
            if let Err(err) = reconcile_once(&cfg, &http, router.as_deref(), &state).await {
                tracing::error!(%err, "reconcile pass failed");
            }
        }
    });
}

pub async fn reconcile_once(
    cfg: &Config,
    http: &reqwest::Client,
    router: Option<&RouteManager>,
    state: &GatewayState,
) -> anyhow::Result<()> {
    let stale = Duration::from_secs(cfg.stale_after_secs);

    let futures = cfg.daemons.iter().map(|d| fetch(http, d));
    let results = join_all(futures).await;
    let round = cfg
        .daemons
        .iter()
        .map(|d| d.name.clone())
        .zip(results);

    let (stats, view) = state.apply_round(round, stale).await;

    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();
    for daemon in &cfg.daemons {
        let Some(leases) = view.get(&daemon.name) else {
            continue;
        };
        push_specs(daemon, &leases.ips, &mut desired, &mut seen_src);
    }

    let desired_count = desired.len();
    if let Some(router) = router
        && let Err(err) = router.reconcile(&desired).await
    {
        tracing::error!(%err, "routing reconcile failed");
    }

    tracing::info!(
        daemons = cfg.daemons.len(),
        manage_routes = cfg.manage_routes,
        fetched_ok = stats.fetched_ok,
        used_cache = stats.used_cache,
        dropped = stats.dropped,
        desired = desired_count,
        "reconcile complete"
    );
    Ok(())
}

fn push_specs(
    daemon: &DaemonEntry,
    ips: &[Ipv4Addr],
    out: &mut Vec<RouteSpec>,
    seen: &mut HashSet<Ipv4Addr>,
) {
    for ip in ips {
        if !seen.insert(*ip) {
            tracing::warn!(
                daemon = %daemon.name,
                src = %ip,
                "duplicate source IP across daemons; later entries win"
            );
        }
        out.push(RouteSpec {
            src: *ip,
            gateway: daemon.nexthop,
            iface: daemon.device.clone(),
            fwmark: None,
        });
    }
}
