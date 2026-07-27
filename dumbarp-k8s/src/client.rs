use std::net::Ipv4Addr;

use dumbarp_api::fetch_leases;

use crate::config::HostConfig;

pub async fn fetch_ips(http: &reqwest::Client, host: &HostConfig) -> anyhow::Result<Vec<Ipv4Addr>> {
    let token = host.read_token()?;
    let leases = fetch_leases(http, &host.url, &token, &host.name).await?;
    Ok(leases.ips)
}
