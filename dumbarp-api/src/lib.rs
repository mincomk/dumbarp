use std::net::Ipv4Addr;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
mod cache;
#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use cache::{Cache, LeaseCache, RoundStats};
#[cfg(feature = "client")]
pub use client::{fetch_daemons, fetch_leases};

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonsResponse {
    pub daemons: Vec<DaemonEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEntryView {
    pub name: String,
    pub nexthop: String,
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dumbarpd_id: Option<u8>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DaemonRoutes {
    pub name: String,
    pub nexthop: Ipv4Addr,
    pub device: String,
    pub dumbarpd_id: Option<u8>,
    pub ips: Vec<Ipv4Addr>,
}

impl LeasesResponse {
    pub fn parse(self, label: &str) -> anyhow::Result<Leases> {
        Ok(Leases {
            ips: parse_ips(&self.ips, label)?,
            dumbarpd_id: self.dumbarpd_id,
        })
    }
}

impl DaemonsResponse {
    pub fn parse(self, label: &str) -> anyhow::Result<Vec<DaemonRoutes>> {
        let mut out = Vec::with_capacity(self.daemons.len());
        for d in self.daemons {
            let nexthop: Ipv4Addr = d.nexthop.parse().with_context(|| {
                format!("parsing nexthop `{}` for daemon `{}` from {label}", d.nexthop, d.name)
            })?;
            if d.device.is_empty() {
                anyhow::bail!("daemon `{}` from {label} has an empty device", d.name);
            }
            let ips = parse_ips(&d.ips, &d.name)?;
            out.push(DaemonRoutes {
                name: d.name,
                nexthop,
                device: d.device,
                dumbarpd_id: d.dumbarpd_id,
                ips,
            });
        }
        Ok(out)
    }
}

fn parse_ips(raw: &[String], label: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut ips = Vec::with_capacity(raw.len());
    for s in raw {
        ips.push(
            s.parse::<Ipv4Addr>()
                .with_context(|| format!("parsing IP `{s}` from {label}"))?,
        );
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemons_response_round_trips() {
        let json = r#"{"daemons":[{"name":"homelab","nexthop":"10.0.0.5","device":"br0","dumbarpd_id":7,"ips":["110.110.110.110"]}]}"#;
        let parsed: DaemonsResponse = serde_json::from_str(json).unwrap();
        let routes = parsed.parse("gw").unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].name, "homelab");
        assert_eq!(routes[0].nexthop, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(routes[0].device, "br0");
        assert_eq!(routes[0].dumbarpd_id, Some(7));
        assert_eq!(routes[0].ips, vec![Ipv4Addr::new(110, 110, 110, 110)]);
    }

    #[test]
    fn daemons_response_tolerates_missing_id() {
        let json = r#"{"daemons":[{"name":"edge","nexthop":"10.0.0.6","device":"br1","ips":[]}]}"#;
        let routes = serde_json::from_str::<DaemonsResponse>(json)
            .unwrap()
            .parse("gw")
            .unwrap();
        assert_eq!(routes[0].dumbarpd_id, None);
        assert!(routes[0].ips.is_empty());
    }

    #[test]
    fn daemons_response_rejects_bad_nexthop_and_device() {
        let bad_ip = r#"{"daemons":[{"name":"x","nexthop":"not-an-ip","device":"br0","ips":[]}]}"#;
        assert!(
            serde_json::from_str::<DaemonsResponse>(bad_ip)
                .unwrap()
                .parse("gw")
                .is_err()
        );

        let no_dev = r#"{"daemons":[{"name":"x","nexthop":"10.0.0.5","device":"","ips":[]}]}"#;
        assert!(
            serde_json::from_str::<DaemonsResponse>(no_dev)
                .unwrap()
                .parse("gw")
                .is_err()
        );
    }

    #[test]
    fn leases_response_tolerates_daemon_without_id() {
        let old = r#"{"ips":["1.2.3.4"]}"#;
        let leases = serde_json::from_str::<LeasesResponse>(old)
            .unwrap()
            .parse("d")
            .unwrap();
        assert_eq!(leases.dumbarpd_id, None);
        assert_eq!(leases.ips, vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }
}
