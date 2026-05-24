use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::time::{MissedTickBehavior, interval};

use crate::lease;
use crate::state::AppState;

pub async fn populate_once(state: &AppState, ifaces: &[String]) {
    for iface in ifaces {
        reconcile_iface(state, iface).await;
    }
}

pub fn spawn(state: AppState, ifaces: Vec<String>, period: Duration) {
    tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // consume the immediate first tick — populate_once already ran
        loop {
            ticker.tick().await;
            for iface in &ifaces {
                reconcile_iface(&state, iface).await;
            }
        }
    });
}

async fn reconcile_iface(state: &AppState, iface: &str) {
    let desired = lease::current_ip(iface);
    let current = state.leases.lock().await.get(iface).copied();

    match (current, desired) {
        (Some(a), Some(b)) if a == b => {}
        (None, None) => {
            tracing::warn!(iface, "no active DHCP lease");
        }
        (_, Some(new_ip)) => {
            apply_attach(state, iface, new_ip).await;
        }
        (Some(_), None) => {
            apply_detach(state, iface).await;
        }
    }
}

async fn apply_attach(state: &AppState, iface: &str, ip: Ipv4Addr) {
    let mut engine = state.engine.lock().await;
    let _ = engine.remove_interface(iface); // detach prior, if any
    match engine.add_interface(iface, ip) {
        Ok(()) => {
            drop(engine);
            state.leases.lock().await.insert(iface.to_string(), ip);
            tracing::info!(iface, %ip, "attached XDP for leased IP");
        }
        Err(err) => {
            drop(engine);
            state.leases.lock().await.remove(iface);
            tracing::error!(iface, %ip, %err, "failed to attach XDP");
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
