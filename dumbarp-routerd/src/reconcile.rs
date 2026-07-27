use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use dumbarp_api::{Cache, DaemonRoutes, LeaseCache, Leases, fetch_daemons, fetch_leases};
use dumbarp_common::DSCP_ID_MAX;
use dumbarp_routing::{RouteManager, RouteSpec};
use futures::future::join_all;
use tokio::sync::Mutex;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::{Config, DaemonEntry};
use crate::datapath::Datapath;

const GATEWAY_CACHE_KEY: &str = "gateway";

pub struct RouterState {
    pub cache: LeaseCache,
    pub gateway_cache: Cache<Vec<DaemonRoutes>>,
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
    if cfg.gateway.is_some() {
        return reconcile_via_gateway(cfg, http, router, state).await;
    }
    reconcile_via_daemons(cfg, http, router, state).await
}

async fn reconcile_via_gateway(
    cfg: &Config,
    http: &reqwest::Client,
    router: &RouteManager,
    state: &RouterState,
) -> anyhow::Result<()> {
    let gw = cfg.gateway.as_ref().expect("gateway mode");
    let stale = Duration::from_secs(cfg.stale_after_secs);

    let fetched = fetch_daemons(http, &gw.endpoint, &gw.auth_token, GATEWAY_CACHE_KEY).await;
    let (stats, view) = state
        .gateway_cache
        .apply_round([(GATEWAY_CACHE_KEY.to_string(), fetched)], stale)
        .await;

    let daemons = view.get(GATEWAY_CACHE_KEY).cloned().unwrap_or_default();
    let (desired, id_set) = build_gateway_specs(&daemons, &gw.device_overrides);

    if let Err(err) = state.datapath.lock().await.sync_ids(&id_set) {
        tracing::error!(%err, "syncing DSCP_IDS map failed");
    }

    let desired_count = desired.len();
    if let Err(err) = router.reconcile(&desired).await {
        tracing::error!(%err, "routing reconcile failed");
    }

    tracing::info!(
        mode = "gateway",
        daemons = daemons.len(),
        fetched_ok = stats.fetched_ok,
        used_cache = stats.used_cache,
        dropped = stats.dropped,
        dscp_ids = id_set.len(),
        desired = desired_count,
        "reconcile complete"
    );
    Ok(())
}

async fn reconcile_via_daemons(
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

fn build_gateway_specs(
    daemons: &[DaemonRoutes],
    device_overrides: &HashMap<String, String>,
) -> (Vec<RouteSpec>, HashSet<u8>) {
    let mut id_set: HashSet<u8> = HashSet::new();
    let mut claimed: HashMap<u8, String> = HashMap::new();
    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();

    for d in daemons {
        let device = device_overrides
            .get(&d.name)
            .cloned()
            .unwrap_or_else(|| d.device.clone());

        let fwmark = validate_id(&d.name, d.dumbarpd_id, &mut claimed).map(|id| {
            id_set.insert(id);
            u32::from(id)
        });

        for ip in &d.ips {
            if !seen_src.insert(*ip) {
                tracing::warn!(daemon = %d.name, src = %ip, "duplicate source IP across daemons; later entries win");
            }
            desired.push(RouteSpec {
                src: *ip,
                gateway: d.nexthop,
                iface: device.clone(),
                fwmark,
            });
        }
    }

    (desired, id_set)
}

fn resolve_ids(cfg: &Config, view: &HashMap<String, Leases>) -> HashMap<String, u8> {
    let mut out: HashMap<String, u8> = HashMap::new();
    let mut claimed: HashMap<u8, String> = HashMap::new();

    for daemon in &cfg.daemons {
        let advertised = view.get(&daemon.name).and_then(|l| l.dumbarpd_id);
        if let Some(id) = validate_id(&daemon.name, advertised, &mut claimed) {
            out.insert(daemon.name.clone(), id);
        }
    }
    out
}

fn validate_id(name: &str, id: Option<u8>, claimed: &mut HashMap<u8, String>) -> Option<u8> {
    let id = id?;
    if id == 0 || id > DSCP_ID_MAX {
        tracing::warn!(
            daemon = %name,
            id,
            max = DSCP_ID_MAX,
            "daemon advertised out-of-range dumbarpd_id; ignoring"
        );
        return None;
    }
    if let Some(owner) = claimed.get(&id) {
        tracing::warn!(
            daemon = %name,
            conflicting_with = %owner,
            id,
            "duplicate dumbarpd_id across daemons; ignoring"
        );
        return None;
    }
    claimed.insert(id, name.to_string());
    Some(id)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn daemon(name: &str, nexthop: [u8; 4], device: &str, id: Option<u8>, ips: &[[u8; 4]]) -> DaemonRoutes {
        DaemonRoutes {
            name: name.to_string(),
            nexthop: Ipv4Addr::from(nexthop),
            device: device.to_string(),
            dumbarpd_id: id,
            ips: ips.iter().copied().map(Ipv4Addr::from).collect(),
        }
    }

    #[test]
    fn uses_gateway_device_when_not_overridden() {
        let d = vec![daemon("homelab", [10, 0, 0, 5], "br0", Some(7), &[[110, 110, 110, 110]])];
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new());
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].iface, "br0");
        assert_eq!(specs[0].fwmark, Some(7));
        assert_eq!(specs[0].gateway, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(ids, HashSet::from([7]));
    }

    #[test]
    fn device_override_wins_for_that_daemon_only() {
        let d = vec![
            daemon("homelab", [10, 0, 0, 5], "br0", Some(7), &[[110, 110, 110, 110]]),
            daemon("edge", [10, 0, 0, 6], "br1", Some(9), &[[120, 120, 120, 120]]),
        ];
        let overrides = HashMap::from([("homelab".to_string(), "eno1".to_string())]);
        let (specs, _) = build_gateway_specs(&d, &overrides);
        assert_eq!(specs[0].iface, "eno1");
        assert_eq!(specs[1].iface, "br1");
    }

    #[test]
    fn daemon_without_id_gets_no_fwmark() {
        let d = vec![daemon("legacy", [10, 0, 0, 7], "br0", None, &[[1, 2, 3, 4]])];
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new());
        assert_eq!(specs[0].fwmark, None);
        assert!(ids.is_empty());
    }

    #[test]
    fn out_of_range_and_duplicate_ids_are_dropped() {
        let d = vec![
            daemon("a", [10, 0, 0, 1], "br0", Some(64), &[[1, 1, 1, 1]]),
            daemon("b", [10, 0, 0, 2], "br0", Some(0), &[[2, 2, 2, 2]]),
            daemon("c", [10, 0, 0, 3], "br0", Some(7), &[[3, 3, 3, 3]]),
            daemon("d", [10, 0, 0, 4], "br0", Some(7), &[[4, 4, 4, 4]]),
        ];
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new());
        assert_eq!(ids, HashSet::from([7]));
        assert_eq!(specs[0].fwmark, None);
        assert_eq!(specs[1].fwmark, None);
        assert_eq!(specs[2].fwmark, Some(7));
        assert_eq!(specs[3].fwmark, None);
    }
}
