use std::net::Ipv4Addr;

use anyhow::Context;
use serde::Deserialize;

use crate::config::HostConfig;

#[derive(Deserialize)]
struct LeasesResponse {
    ips: Vec<String>,
}

pub async fn fetch_ips(http: &reqwest::Client, host: &HostConfig) -> anyhow::Result<Vec<Ipv4Addr>> {
    let token = host.read_token()?;
    let url = host
        .url
        .join("leases")
        .with_context(|| format!("building /leases URL from {}", host.url))?;
    let resp = http
        .get(url.clone())
        .bearer_auth(token)
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
            .with_context(|| format!("parsing IP `{raw}` from {}", host.name))?;
        ips.push(ip);
    }
    Ok(ips)
}
