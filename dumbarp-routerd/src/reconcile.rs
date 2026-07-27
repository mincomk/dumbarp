use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use dumbarp_api::{LeaseCache, Leases, fetch_leases};
use dumbarp_common::DSCP_ID_MAX;
use dumbarp_routing::{RouteManager, RouteSpec};
use futures::future::join_all;
use tokio::sync::Mutex;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::{Config, DaemonEntry};
use crate::datapath::Datapath;

pub struct RouterState {
    pub cache: LeaseCache,
    pub datapath: Mutex<Datapath>,
}

pub fn spawn(
    cfg: Arc<Config>,
    http: reqwest::Client,
    router: Arc<RouteManager>,
    state: Arc<RouterState>,
) {
    tokio::spawn(async move {
        let period = Duration::from_secs(cfg.refresh_interval_secs);
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
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
    state: &RouterState,
) -> anyhow::Result<()> {
    let stale = Duration::from_secs(cfg.stale_after_secs);

    let futures = cfg
        .daemons
        .iter()
        .map(|d| fetch_leases(http, &d.endpoint, &d.auth_token, &d.name));
    let results = join_all(futures).await;
    let round = cfg
        .daemons
        .iter()
        .map(|d| d.name.clone())
        .zip(results);

    let (stats, view) = state.cache.apply_round(round, stale).await;

    let ids = resolve_ids(cfg, &view);
    let id_set: HashSet<u8> = ids.values().copied().collect();
    if let Err(err) = state.datapath.lock().await.sync_ids(&id_set) {
        tracing::error!(%err, "syncing DSCP_IDS map failed");
    }

    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();
    for daemon in &cfg.daemons {
        let Some(leases) = view.get(&daemon.name) else {
            continue;
        };
        let fwmark = ids.get(&daemon.name).map(|id| u32::from(*id));
        push_specs(daemon, &leases.ips, fwmark, &mut desired, &mut seen_src);
    }

    let desired_count = desired.len();
    if let Err(err) = router.reconcile(&desired).await {
        tracing::error!(%err, "routing reconcile failed");
    }

    tracing::info!(
        daemons = cfg.daemons.len(),
        fetched_ok = stats.fetched_ok,
        used_cache = stats.used_cache,
        dropped = stats.dropped,
        dscp_ids = id_set.len(),
        desired = desired_count,
        "reconcile complete"
    );
    Ok(())
}

fn resolve_ids(cfg: &Config, view: &HashMap<String, Leases>) -> HashMap<String, u8> {
    let mut out: HashMap<String, u8> = HashMap::new();
    let mut claimed: HashMap<u8, String> = HashMap::new();

    for daemon in &cfg.daemons {
        let Some(id) = view.get(&daemon.name).and_then(|l| l.dumbarpd_id) else {
            continue;
        };
        if id == 0 || id > DSCP_ID_MAX {
            tracing::warn!(
                daemon = %daemon.name,
                id,
                max = DSCP_ID_MAX,
                "daemon advertised out-of-range dumbarpd_id; ignoring"
            );
            continue;
        }
        if let Some(owner) = claimed.get(&id) {
            tracing::warn!(
                daemon = %daemon.name,
                conflicting_with = %owner,
                id,
                "duplicate dumbarpd_id across daemons; ignoring"
            );
            continue;
        }
        claimed.insert(id, daemon.name.clone());
        out.insert(daemon.name.clone(), id);
    }
    out
}

fn push_specs(
    daemon: &DaemonEntry,
    ips: &[Ipv4Addr],
    fwmark: Option<u32>,
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
            fwmark,
        });
    }
}
