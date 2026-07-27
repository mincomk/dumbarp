use std::net::Ipv4Addr;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
mod cache;
#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use cache::{LeaseCache, RoundStats};
#[cfg(feature = "client")]
pub use client::fetch_leases;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LeasesResponse {
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dumbarpd_id: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Leases {
    pub ips: Vec<Ipv4Addr>,
    pub dumbarpd_id: Option<u8>,
}

impl LeasesResponse {
    pub fn parse(self, label: &str) -> anyhow::Result<Leases> {
        let mut ips = Vec::with_capacity(self.ips.len());
        for raw in &self.ips {
            let ip: Ipv4Addr = raw
                .parse()
                .with_context(|| format!("parsing IP `{raw}` from {label}"))?;
            ips.push(ip);
        }
        Ok(Leases {
            ips,
            dumbarpd_id: self.dumbarpd_id,
        })
    }
}

impl Leases {
    pub fn from_ips(ips: Vec<Ipv4Addr>, dumbarpd_id: Option<u8>) -> Self {
        Self { ips, dumbarpd_id }
    }
}
