use std::time::Duration;

use futures::StreamExt;
use mozim::{DhcpV4ClientAsync, DhcpV4Config};
use tokio::task::AbortHandle;

use crate::lease::LeaseInfo;
use crate::neigh;
use crate::state::AppState;

pub fn spawn_all(state: AppState, ifaces: Vec<String>, neigh_period: Duration) {
    for iface in ifaces {
        tokio::spawn(run_dhcp_for_iface(state.clone(), iface, neigh_period));
    }
}

async fn run_dhcp_for_iface(state: AppState, iface: String, neigh_period: Duration) {
    let mut neigh_handle: Option<AbortHandle> = None;

    loop {
        let config = DhcpV4Config::new(&iface);
        let mut client = match DhcpV4ClientAsync::init(config, None) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(iface, %err, "DHCP client init failed; retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        while let Some(event) = client.next().await {
            match event {
                Ok(lease) => {
                    let ip = lease.yiaddr;
                    let Some(gateway) = lease.gateways.as_deref().and_then(|g| g.first()).copied() else {
                        tracing::warn!(iface, %ip, "DHCP lease has no gateway; ignoring");
                        continue;
                    };

                    tracing::info!(iface, %ip, %gateway, "DHCP lease acquired/renewed");

                    let info = LeaseInfo { ip, gateway };

                    // Reattach XDP with potentially new IP
                    {
                        let mut engine = state.engine.lock().await;
                        let _ = engine.remove_interface(&iface);
                        match engine.add_interface(&iface, ip) {
                            Ok(()) => {
                                drop(engine);
                                state.leases.lock().await.insert(iface.clone(), info);
                                tracing::info!(iface, %ip, "XDP attached");
                            }
                            Err(err) => {
                                drop(engine);
                                state.leases.lock().await.remove(&iface);
                                tracing::error!(iface, %ip, %err, "XDP attach failed");
                                continue;
                            }
                        }
                    }

                    // Cancel previous neigh refresher and start fresh one
                    if let Some(h) = neigh_handle.take() {
                        h.abort();
                    }
                    neigh_handle = Some(neigh::spawn_probe_and_refresh(
                        iface.clone(),
                        ip,
                        gateway,
                        neigh_period,
                    ));
                }
                Err(err) => {
                    tracing::error!(iface, %err, "DHCP error; restarting client in 5s");
                    detach(&state, &iface).await;
                    break;
                }
            }
        }

        if let Some(h) = neigh_handle.take() {
            h.abort();
        }
        detach(&state, &iface).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn detach(state: &AppState, iface: &str) {
    let mut engine = state.engine.lock().await;
    if let Err(err) = engine.remove_interface(iface) {
        tracing::warn!(iface, %err, "XDP detach failed");
    }
    drop(engine);
    state.leases.lock().await.remove(iface);
}
