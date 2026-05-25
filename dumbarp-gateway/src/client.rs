use std::net::Ipv4Addr;

use anyhow::Context;
use serde::Deserialize;

use crate::config::DaemonEntry;

#[derive(Deserialize)]
struct LeasesResponse {
    ips: Vec<String>,
}

pub async fn fetch_ips(
    http: &reqwest::Client,
    daemon: &DaemonEntry,
) -> anyhow::Result<Vec<Ipv4Addr>> {
    let url = daemon
        .endpoint
        .join("leases")
        .with_context(|| format!("building /leases URL from {}", daemon.endpoint))?;
    let resp = http
        .get(url.clone())
        .bearer_auth(&daemon.auth_token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url} returned non-success"))?;
    let body: LeasesResponse = resp
        .json()
        .await
        .with_context(|| format!("decoding JSON from {url}"))?;
    let mut ips = Vec::with_capacity(body.ips.len());
    for raw in body.ips {
        let ip: Ipv4Addr = raw
            .parse()
            .with_context(|| format!("parsing IP `{raw}` from {}", daemon.name))?;
        ips.push(ip);
    }
    Ok(ips)
}
