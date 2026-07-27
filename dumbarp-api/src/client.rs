use anyhow::Context;
use url::Url;

use crate::{Leases, LeasesResponse};

pub async fn fetch_leases(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    label: &str,
) -> anyhow::Result<Leases> {
    let url = endpoint
        .join("leases")
        .with_context(|| format!("building /leases URL from {endpoint}"))?;
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
    body.parse(label)
}
