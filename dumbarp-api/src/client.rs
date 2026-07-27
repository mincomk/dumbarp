use anyhow::Context;
use serde::de::DeserializeOwned;
use url::Url;

use crate::{DaemonRoutes, DaemonsResponse, Leases, LeasesResponse};

pub async fn fetch_leases(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    label: &str,
) -> anyhow::Result<Leases> {
    let body: LeasesResponse = get_json(http, endpoint, "leases", token).await?;
    body.parse(label)
}

pub async fn fetch_daemons(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    label: &str,
) -> anyhow::Result<Vec<DaemonRoutes>> {
    let body: DaemonsResponse = get_json(http, endpoint, "daemons", token).await?;
    body.parse(label)
}

async fn get_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    endpoint: &Url,
    path: &str,
    token: &str,
) -> anyhow::Result<T> {
    let url = endpoint
        .join(path)
        .with_context(|| format!("building /{path} URL from {endpoint}"))?;
    let resp = http
        .get(url.clone())
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url} returned non-success"))?;
    resp.json()
        .await
        .with_context(|| format!("decoding JSON from {url}"))
}
