use std::sync::Arc;
use std::time::Duration;

use tokio::time::{MissedTickBehavior, interval};

use dumbarp_routing::RouteManager;

use crate::lease::{self, LeaseInfo};
use crate::state::AppState;

pub async fn populate_once(
    state: &AppState,
    ifaces: &[String],
    router: Option<&Arc<RouteManager>>,
) {
    for iface in ifaces {
        reconcile_iface(state, iface).await;
    }
    reconcile_routing(state, router).await;
}

pub fn spawn(
    state: AppState,
    ifaces: Vec<String>,
    period: Duration,
    router: Option<Arc<RouteManager>>,
) {
    tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // consume the immediate first tick — populate_once already ran
        loop {
            ticker.tick().await;
            for iface in &ifaces {
                reconcile_iface(&state, iface).await;
            }
            reconcile_routing(&state, router.as_ref()).await;
        }
    });
}

async fn reconcile_iface(state: &AppState, iface: &str) {
    let desired = lease::current_lease(iface);
    let current = state.leases.lock().await.get(iface).copied();

    match (current, desired) {
        (Some(a), Some(b)) if a == b => {}
        (None, None) => {
            tracing::warn!(iface, "no active DHCP lease");
        }
        (_, Some(new)) => {
            apply_attach(state, iface, new).await;
        }
        (Some(_), None) => {
            apply_detach(state, iface).await;
        }
    }
}

async fn apply_attach(state: &AppState, iface: &str, lease: LeaseInfo) {
    let mut engine = state.engine.lock().await;
    let _ = engine.remove_interface(iface); // detach prior, if any
    match engine.add_interface(iface, lease.ip) {
        Ok(()) => {
            drop(engine);
            state.leases.lock().await.insert(iface.to_string(), lease);
            tracing::info!(iface, ip = %lease.ip, gw = %lease.gateway, "attached XDP for leased IP");
        }
        Err(err) => {
            drop(engine);
            state.leases.lock().await.remove(iface);
            tracing::error!(iface, ip = %lease.ip, %err, "failed to attach XDP");
        }
    }
}

async fn apply_detach(state: &AppState, iface: &str) {
    let mut engine = state.engine.lock().await;
    if let Err(err) = engine.remove_interface(iface) {
        tracing::warn!(iface, %err, "detach failed");
    }
    drop(engine);
    state.leases.lock().await.remove(iface);
    tracing::info!(iface, "lease gone; detached");
}

async fn reconcile_routing(state: &AppState, router: Option<&Arc<RouteManager>>) {
    let Some(router) = router else {
        return;
    };
    let desired = state.current_routes().await;
    if let Err(err) = router.reconcile(&desired).await {
        tracing::error!(%err, "routing reconcile failed");
    }
}
