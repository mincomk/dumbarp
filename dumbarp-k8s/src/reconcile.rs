use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::ObjectList;
use serde_json::json;
use tokio::time::{MissedTickBehavior, interval};

use crate::client::fetch_ips;
use crate::config::{Config, HostConfig};
use crate::crd::{
    CiliumLoadBalancerIPPool, CiliumLoadBalancerIPPoolIPBlock, CiliumLoadBalancerIPPoolSpec,
};

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "dumbarp-k8s";
pub const IP_ANNOTATION: &str = "dumbarp.k8s/ip";
pub const LAST_SEEN_ANNOTATION: &str = "dumbarp.k8s/last-seen-at";

pub fn spawn(cfg: Arc<Config>, http: reqwest::Client, kube: kube::Client) {
    tokio::spawn(async move {
        let period = Duration::from_secs(cfg.refresh_interval_secs);
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = reconcile_once(&cfg, &http, &kube).await {
                tracing::error!(%err, "reconcile pass failed");
            }
        }
    });
}

pub async fn reconcile_once(
    cfg: &Config,
    http: &reqwest::Client,
    kube: &kube::Client,
) -> anyhow::Result<()> {
    let (desired, all_hosts_ok, fetch_errors) = collect_desired(cfg, http).await;

    let api: Api<CiliumLoadBalancerIPPool> = Api::all(kube.clone());
    let current = list_current(&api).await?;

    let now = Utc::now();
    let stale_threshold = now - chrono::Duration::seconds(cfg.stale_after_secs as i64);

    let mut added = 0usize;
    let mut touched = 0usize;
    let mut removed = 0usize;
    let mut kept = 0usize;

    for ip in &desired {
        match current.get(ip) {
            None => {
                create_pool(&api, *ip, now).await?;
                added += 1;
            }
            Some(_) => {
                touch_pool(&api, *ip, now).await?;
                touched += 1;
            }
        }
    }

    for (ip, existing) in &current {
        if desired.contains(ip) {
            continue;
        }
        let prune = if all_hosts_ok {
            true
        } else {
            match existing.last_seen {
                Some(seen) => seen < stale_threshold,
                None => true,
            }
        };
        if prune {
            delete_pool(&api, &existing.name).await?;
            removed += 1;
        } else {
            kept += 1;
        }
    }

    tracing::info!(
        desired = desired.len(),
        added,
        touched,
        removed,
        kept_stale = kept,
        fetch_errors,
        all_hosts_ok,
        "reconcile complete"
    );
    Ok(())
}

struct ExistingPool {
    name: String,
    last_seen: Option<DateTime<Utc>>,
}

async fn collect_desired(
    cfg: &Config,
    http: &reqwest::Client,
) -> (BTreeSet<Ipv4Addr>, bool, usize) {
    let futures = cfg.hosts.iter().map(|h| fetch_for(http, h));
    let results = join_all(futures).await;

    let mut desired = BTreeSet::new();
    let mut errors = 0usize;
    for (host, result) in cfg.hosts.iter().zip(results) {
        match result {
            Ok(ips) => {
                tracing::debug!(host = %host.name, count = ips.len(), "fetched");
                desired.extend(ips);
            }
            Err(err) => {
                errors += 1;
                tracing::warn!(host = %host.name, url = %host.url, %err, "fetch failed");
            }
        }
    }
    (desired, errors == 0, errors)
}

async fn fetch_for(http: &reqwest::Client, host: &HostConfig) -> anyhow::Result<Vec<Ipv4Addr>> {
    fetch_ips(http, host).await
}

async fn list_current(
    api: &Api<CiliumLoadBalancerIPPool>,
) -> anyhow::Result<BTreeMap<Ipv4Addr, ExistingPool>> {
    let selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");
    let list: ObjectList<CiliumLoadBalancerIPPool> =
        api.list(&ListParams::default().labels(&selector)).await?;

    let mut out = BTreeMap::new();
    for pool in list.items {
        let name = pool.metadata.name.clone().unwrap_or_default();
        let Some(annotations) = pool.metadata.annotations.as_ref() else {
            tracing::warn!(pool = %name, "managed pool has no annotations; skipping");
            continue;
        };
        let Some(raw_ip) = annotations.get(IP_ANNOTATION) else {
            tracing::warn!(pool = %name, "managed pool missing {IP_ANNOTATION}; skipping");
            continue;
        };
        let ip: Ipv4Addr = match raw_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(pool = %name, raw_ip, "unparseable IP annotation; skipping");
                continue;
            }
        };
        let last_seen = annotations
            .get(LAST_SEEN_ANNOTATION)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));

        out.insert(ip, ExistingPool { name, last_seen });
    }
    Ok(out)
}

fn pool_name(ip: Ipv4Addr) -> String {
    format!("dumbarp-{}", ip.to_string().replace('.', "-"))
}

fn build_pool(ip: Ipv4Addr, now: DateTime<Utc>) -> CiliumLoadBalancerIPPool {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());

    let mut annotations = BTreeMap::new();
    annotations.insert(IP_ANNOTATION.to_string(), ip.to_string());
    annotations.insert(LAST_SEEN_ANNOTATION.to_string(), now.to_rfc3339());

    CiliumLoadBalancerIPPool {
        metadata: ObjectMeta {
            name: Some(pool_name(ip)),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: CiliumLoadBalancerIPPoolSpec {
            blocks: vec![CiliumLoadBalancerIPPoolIPBlock {
                cidr: Some(format!("{ip}/32")),
            }],
        },
    }
}

async fn create_pool(
    api: &Api<CiliumLoadBalancerIPPool>,
    ip: Ipv4Addr,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let pool = build_pool(ip, now);
    match api.create(&PostParams::default(), &pool).await {
        Ok(_) => {
            tracing::info!(%ip, name = %pool_name(ip), "created pool");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            tracing::debug!(%ip, "pool already exists; touching instead");
            touch_pool(api, ip, now).await
        }
        Err(e) => Err(e.into()),
    }
}

async fn touch_pool(
    api: &Api<CiliumLoadBalancerIPPool>,
    ip: Ipv4Addr,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let patch = json!({
        "metadata": {
            "annotations": {
                LAST_SEEN_ANNOTATION: now.to_rfc3339(),
            }
        }
    });
    api.patch(
        &pool_name(ip),
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

async fn delete_pool(api: &Api<CiliumLoadBalancerIPPool>, name: &str) -> anyhow::Result<()> {
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => {
            tracing::info!(pool = name, "deleted pool");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}
