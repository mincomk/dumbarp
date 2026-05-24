use std::fs;
use std::path::PathBuf;

use chrono::Utc;

use super::lease_parser::{Lease, parse_leases};
use crate::{DhcpLease, ReadDhcpLease};

pub struct IscDhclientRead {
    pub lease_files: Vec<PathBuf>,
}

impl ReadDhcpLease for IscDhclientRead {
    fn read_dhcp_lease(&self) -> Option<DhcpLease> {
        let now = Utc::now();
        let mut all: Vec<Lease> = Vec::new();
        for path in &self.lease_files {
            let Ok(contents) = fs::read_to_string(path) else {
                continue;
            };
            let Ok((_, leases)) = parse_leases(&contents) else {
                continue;
            };
            all.extend(leases);
        }

        let latest = all
            .into_iter()
            .filter(|l| l.expire.is_some_and(|e| e > now))
            .max_by_key(|l| l.expire)?;

        Some(DhcpLease {
            interface: latest.interface?,
            ip_address: latest.fixed_address?,
            subnet_mask: option_value(&latest.options, "subnet-mask")?,
            router: option_value(&latest.options, "routers")?,
            expired: false,
        })
    }
}

fn option_value(opts: &[(String, String)], key: &str) -> Option<String> {
    opts.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}
