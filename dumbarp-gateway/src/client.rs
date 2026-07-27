use dumbarp_api::{Leases, fetch_leases};

use crate::config::DaemonEntry;

pub async fn fetch(http: &reqwest::Client, daemon: &DaemonEntry) -> anyhow::Result<Leases> {
    fetch_leases(http, &daemon.endpoint, &daemon.auth_token, &daemon.name).await
}
