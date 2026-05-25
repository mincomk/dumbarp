use std::net::Ipv4Addr;
use std::path::PathBuf;

use dhcp_lease_read::ReadDhcpLease;
use dhcp_lease_read::isc_dhclient::IscDhclientRead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseInfo {
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

pub fn current_lease(iface: &str) -> Option<LeaseInfo> {
    let path = PathBuf::from(format!("/var/lib/dhcp/dhclient.{iface}.leases"));
    let reader = IscDhclientRead {
        lease_files: vec![path],
    };
    let lease = reader.read_dhcp_lease()?;
    let ip = match lease.ip_address.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(err) => {
            tracing::warn!(iface, raw = %lease.ip_address, %err, "lease ip parse failed");
            return None;
        }
    };
    let gateway = match lease.router.parse::<Ipv4Addr>() {
        Ok(gw) => gw,
        Err(err) => {
            tracing::warn!(iface, raw = %lease.router, %err, "lease router parse failed");
            return None;
        }
    };
    Some(LeaseInfo { ip, gateway })
}
