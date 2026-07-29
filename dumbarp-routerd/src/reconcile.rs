use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dumbarp_api::{Cache, DaemonRoutes, LeaseCache, fetch_daemons, fetch_leases};
use dumbarp_common::DSCP_ID_MAX;
use dumbarp_routing::{RouteManager, RouteSpec};
use futures::future::join_all;
use tokio::sync::Mutex;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::{Config, DaemonEntry};
use crate::datapath::{Counters, Datapath};

const GATEWAY_CACHE_KEY: &str = "gateway";

pub struct RouterState {
    pub cache: LeaseCache,
    pub gateway_cache: Cache<Vec<DaemonRoutes>>,
    pub datapath: Mutex<Datapath>,
    pub known_ids: Mutex<HashMap<String, RememberedId>>,
}

#[derive(Debug, Clone, Copy)]
pub struct RememberedId {
    pub id: u8,
    pub seen: Instant,
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

    let ids = {
        let mut remembered = state.known_ids.lock().await;
        resolve_ids(
            daemons.iter().map(|d| (d.name.clone(), d.dumbarpd_id)),
            &mut remembered,
            stale,
            Instant::now(),
        )
    };
    let (desired, id_set) = build_gateway_specs(&daemons, &gw.device_overrides, &ids);

    let counters = sync_datapath(state, &id_set, &desired).await;

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
        dscp_tagged = counters.dscp_tagged,
        flow_hit = counters.flow_hit,
        src_fallback = counters.src_fallback,
        unmarked = counters.unmarked,
        "reconcile complete"
    );
    Ok(())
}

async fn sync_datapath(
    state: &RouterState,
    id_set: &HashSet<u8>,
    desired: &[RouteSpec],
) -> Counters {
    let src_marks: HashMap<Ipv4Addr, u32> = desired
        .iter()
        .filter_map(|s| s.fwmark.map(|mark| (s.src, mark)))
        .collect();

    let mut datapath = state.datapath.lock().await;
    if let Err(err) = datapath.sync_ids(id_set) {
        tracing::error!(%err, "syncing DSCP_IDS map failed");
    }
    if let Err(err) = datapath.sync_src_marks(&src_marks) {
        tracing::error!(%err, "syncing SRC_MARKS map failed");
    }
    match datapath.counters() {
        Ok(counters) => counters,
        Err(err) => {
            tracing::warn!(%err, "reading datapath counters failed");
            Counters::default()
        }
    }
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

    let ids = {
        let mut remembered = state.known_ids.lock().await;
        resolve_ids(
            cfg.daemons
                .iter()
                .map(|d| (d.name.clone(), view.get(&d.name).and_then(|l| l.dumbarpd_id))),
            &mut remembered,
            stale,
            Instant::now(),
        )
    };
    let id_set: HashSet<u8> = ids.values().copied().collect();

    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();
    for daemon in &cfg.daemons {
        let Some(leases) = view.get(&daemon.name) else {
            continue;
        };
        let Some(id) = ids.get(&daemon.name).copied() else {
            tracing::warn!(
                daemon = %daemon.name,
                ips = leases.ips.len(),
                "no usable dumbarpd_id; skipping source rules"
            );
            continue;
        };
        push_specs(daemon, &leases.ips, u32::from(id), &mut desired, &mut seen_src);
    }

    let counters = sync_datapath(state, &id_set, &desired).await;

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
        dscp_tagged = counters.dscp_tagged,
        flow_hit = counters.flow_hit,
        src_fallback = counters.src_fallback,
        unmarked = counters.unmarked,
        "reconcile complete"
    );
    Ok(())
}

fn build_gateway_specs(
    daemons: &[DaemonRoutes],
    device_overrides: &HashMap<String, String>,
    ids: &HashMap<String, u8>,
) -> (Vec<RouteSpec>, HashSet<u8>) {
    let mut id_set: HashSet<u8> = HashSet::new();
    let mut desired: Vec<RouteSpec> = Vec::new();
    let mut seen_src: HashSet<Ipv4Addr> = HashSet::new();

    for d in daemons {
        let device = device_overrides
            .get(&d.name)
            .cloned()
            .unwrap_or_else(|| d.device.clone());

        let Some(id) = ids.get(&d.name).copied() else {
            tracing::warn!(
                daemon = %d.name,
                ips = d.ips.len(),
                "no usable dumbarpd_id; skipping source rules"
            );
            continue;
        };
        id_set.insert(id);
        let fwmark = Some(u32::from(id));

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

fn resolve_ids(
    advertised: impl IntoIterator<Item = (String, Option<u8>)>,
    remembered: &mut HashMap<String, RememberedId>,
    stale: Duration,
    now: Instant,
) -> HashMap<String, u8> {
    let mut out: HashMap<String, u8> = HashMap::new();
    let mut claimed: HashMap<u8, String> = HashMap::new();

    for (name, advertised) in advertised {
        let candidate = match advertised {
            Some(id) => Some(id),
            None => match remembered.get(&name) {
                Some(prev) if now.duration_since(prev.seen) < stale => {
                    tracing::warn!(
                        daemon = %name,
                        id = prev.id,
                        "no dumbarpd_id advertised; reusing last-known id"
                    );
                    Some(prev.id)
                }
                _ => None,
            },
        };

        let Some(id) = validate_id(&name, candidate, &mut claimed) else {
            continue;
        };
        if advertised == Some(id) {
            remembered.insert(name.clone(), RememberedId { id, seen: now });
        }
        out.insert(name, id);
    }

    remembered.retain(|_, prev| now.duration_since(prev.seen) < stale);
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
    fwmark: u32,
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
            fwmark: Some(fwmark),
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

    fn advertised(daemons: &[DaemonRoutes]) -> Vec<(String, Option<u8>)> {
        daemons
            .iter()
            .map(|d| (d.name.clone(), d.dumbarpd_id))
            .collect()
    }

    fn fresh_ids(daemons: &[DaemonRoutes]) -> HashMap<String, u8> {
        resolve_ids(
            advertised(daemons),
            &mut HashMap::new(),
            Duration::from_secs(300),
            Instant::now(),
        )
    }

    fn src_marks(specs: &[RouteSpec]) -> HashMap<Ipv4Addr, u32> {
        specs
            .iter()
            .filter_map(|s| s.fwmark.map(|mark| (s.src, mark)))
            .collect()
    }

    #[test]
    fn uses_gateway_device_when_not_overridden() {
        let d = vec![daemon("homelab", [10, 0, 0, 5], "br0", Some(7), &[[110, 110, 110, 110]])];
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new(), &fresh_ids(&d));
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
        let (specs, _) = build_gateway_specs(&d, &overrides, &fresh_ids(&d));
        assert_eq!(specs[0].iface, "eno1");
        assert_eq!(specs[1].iface, "br1");
    }

    #[test]
    fn daemon_without_id_is_skipped() {
        let d = vec![daemon("legacy", [10, 0, 0, 7], "br0", None, &[[1, 2, 3, 4]])];
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new(), &fresh_ids(&d));
        assert!(specs.is_empty());
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
        let (specs, ids) = build_gateway_specs(&d, &HashMap::new(), &fresh_ids(&d));
        assert_eq!(ids, HashSet::from([7]));
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].src, Ipv4Addr::new(3, 3, 3, 3));
        assert_eq!(specs[0].fwmark, Some(7));
    }

    #[test]
    fn every_emitted_spec_carries_a_fwmark() {
        let d = vec![
            daemon("a", [10, 0, 0, 1], "br0", None, &[[1, 1, 1, 1]]),
            daemon("b", [10, 0, 0, 2], "br0", Some(3), &[[2, 2, 2, 2], [5, 5, 5, 5]]),
            daemon("c", [10, 0, 0, 3], "br0", Some(70), &[[3, 3, 3, 3]]),
        ];
        let (specs, _) = build_gateway_specs(&d, &HashMap::new(), &fresh_ids(&d));
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().all(|s| s.fwmark == Some(3)));
    }

    #[test]
    fn src_marks_cover_every_spec_with_the_same_mark() {
        let d = vec![
            daemon("a", [10, 0, 0, 1], "br0", Some(3), &[[2, 2, 2, 2], [5, 5, 5, 5]]),
            daemon("b", [10, 0, 0, 2], "br1", Some(9), &[[6, 6, 6, 6]]),
            daemon("c", [10, 0, 0, 3], "br2", None, &[[7, 7, 7, 7]]),
        ];
        let (specs, _) = build_gateway_specs(&d, &HashMap::new(), &fresh_ids(&d));
        let marks = src_marks(&specs);

        assert_eq!(marks.len(), specs.len());
        for spec in &specs {
            assert_eq!(marks.get(&spec.src).copied(), spec.fwmark);
        }
        assert_eq!(marks.get(&Ipv4Addr::new(2, 2, 2, 2)), Some(&3));
        assert_eq!(marks.get(&Ipv4Addr::new(5, 5, 5, 5)), Some(&3));
        assert_eq!(marks.get(&Ipv4Addr::new(6, 6, 6, 6)), Some(&9));
        assert_eq!(marks.get(&Ipv4Addr::new(7, 7, 7, 7)), None);
    }

    #[test]
    fn idless_response_reuses_remembered_id_inside_the_window() {
        let stale = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut remembered = HashMap::new();

        let first = resolve_ids([("a".to_string(), Some(4u8))], &mut remembered, stale, t0);
        assert_eq!(first.get("a"), Some(&4));

        let later = t0 + Duration::from_secs(60);
        let second = resolve_ids([("a".to_string(), None)], &mut remembered, stale, later);
        assert_eq!(second.get("a"), Some(&4));
    }

    #[test]
    fn remembered_id_expires_past_the_window() {
        let stale = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut remembered = HashMap::new();

        resolve_ids([("a".to_string(), Some(4u8))], &mut remembered, stale, t0);

        let later = t0 + Duration::from_secs(301);
        let out = resolve_ids([("a".to_string(), None)], &mut remembered, stale, later);
        assert!(out.is_empty());
        assert!(remembered.is_empty());
    }

    #[test]
    fn reuse_does_not_slide_the_expiry_window() {
        let stale = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut remembered = HashMap::new();

        resolve_ids([("a".to_string(), Some(4u8))], &mut remembered, stale, t0);
        for secs in [100, 200, 290] {
            let out = resolve_ids(
                [("a".to_string(), None)],
                &mut remembered,
                stale,
                t0 + Duration::from_secs(secs),
            );
            assert_eq!(out.get("a"), Some(&4));
        }

        let out = resolve_ids(
            [("a".to_string(), None)],
            &mut remembered,
            stale,
            t0 + Duration::from_secs(300),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_changed_id_wins_immediately() {
        let stale = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut remembered = HashMap::new();

        resolve_ids([("a".to_string(), Some(4u8))], &mut remembered, stale, t0);

        let later = t0 + Duration::from_secs(10);
        let out = resolve_ids([("a".to_string(), Some(9u8))], &mut remembered, stale, later);
        assert_eq!(out.get("a"), Some(&9));

        let after = t0 + Duration::from_secs(20);
        let out = resolve_ids([("a".to_string(), None)], &mut remembered, stale, after);
        assert_eq!(out.get("a"), Some(&9));
    }

    #[test]
    fn a_remembered_id_cannot_collide_with_a_live_one() {
        let stale = Duration::from_secs(300);
        let t0 = Instant::now();
        let mut remembered = HashMap::new();

        resolve_ids([("a".to_string(), Some(4u8))], &mut remembered, stale, t0);

        let later = t0 + Duration::from_secs(10);
        let out = resolve_ids(
            [("b".to_string(), Some(4u8)), ("a".to_string(), None)],
            &mut remembered,
            stale,
            later,
        );
        assert_eq!(out.get("b"), Some(&4));
        assert_eq!(out.get("a"), None);
    }
}
