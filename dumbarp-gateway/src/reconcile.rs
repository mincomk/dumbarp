use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dumbarp_routing::{RouteManager, RouteSpec};
use futures::future::join_all;
use tokio::sync::Mutex;
use tokio::time::{MissedTickBehavior, interval};

use crate::client::fetch_ips;
use crate::config::{Config, DaemonEntry};

#[derive(Default)]
pub struct GatewayState {
    cached: Mutex<HashMap<String, CachedEntry>>,
}

struct CachedEntry {
    ips: Vec<Ipv4Addr>,
    last_success: Instant,
}

pub fn spawn(
    cfg: Arc<Config>,
    http: reqwest::Client,
    router: Arc<RouteManager>,
    state: Arc<GatewayState>,
) {
    tokio::spawn(async move {
        let period = Duration::from_secs(cfg.refresh_interval_secs);
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // consume immediate first tick — reconcile_once already ran
        loop {
            ticker.tick().await;
            if let Err(err) = reconcile_once(&cfg, &http, &router, &state).await {
                tracing::error!(%err, "reconcile pass failed");
            }
        }
    });
}

pub async fn reconcile_once(
    cfg: &Config,
    http: &reqwest::Client,
    router: &RouteManager,
    state: &GatewayState,
) -> anyhow::Result<()> {
    let now = Instant::now();
    let stale = Duration::from_secs(cfg.stale_after_secs);

    let futures = cfg.daemons.iter().map(|d| fetch_ips(http, d));
    let results = join_all(futures).await;

    let mut fetched_ok = 0usize;
    let mut used_cache = 0usize;
    let mut dropped = 0usize;

    let mut cached = state.cached.lock().await;
    for (daemon, result) in cfg.daemons.iter().zip(results.into_iter()) {
        match result {
            Ok(ips) => {
                tracing::debug!(daemon = %daemon.name, count = ips.len(), "fetched");
                cached.insert(
                    daemon.name.clone(),
                    CachedEntry {
                        ips,
                        last_success: now,
                    },
                );
                fetched_ok += 1;
            }
            Err(err) => match cached.get(&daemon.name) {
                Some(entry) if now.duration_since(entry.last_success) < stale => {
                    tracing::warn!(daemon = %daemon.name, %err, "fetch failed; using cached IPs");
                    used_cache += 1;
                }
                _ => {
                    tracing::warn!(daemon = %daemon.name, %err, "fetch failed; no fresh cache, dropping");
                    cached.remove(&daemon.name);
                    dropped += 1;
                }
            },
        }
    }

    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();
    for daemon in &cfg.daemons {
        let Some(entry) = cached.get(&daemon.name) else {
            continue;
        };
        push_specs(daemon, &entry.ips, &mut desired, &mut seen_src);
    }
    drop(cached);

    let desired_count = desired.len();
    if let Err(err) = router.reconcile(&desired).await {
        tracing::error!(%err, "routing reconcile failed");
    }

    tracing::info!(
        daemons = cfg.daemons.len(),
        fetched_ok,
        used_cache,
        dropped,
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
        });
    }
}
