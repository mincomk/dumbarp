use std::net::Ipv4Addr;
use std::path::PathBuf;

use dhcp_lease_read::ReadDhcpLease;
use dhcp_lease_read::isc_dhclient::IscDhclientRead;

pub fn current_ip(iface: &str) -> Option<Ipv4Addr> {
    let path = PathBuf::from(format!("/var/lib/dhcp/dhclient.{iface}.leases"));
    let reader = IscDhclientRead {
        lease_files: vec![path],
    };
    let lease = reader.read_dhcp_lease()?;
    match lease.ip_address.parse::<Ipv4Addr>() {
        Ok(ip) => Some(ip),
        Err(err) => {
            tracing::warn!(iface, raw = %lease.ip_address, %err, "lease ip parse failed");
            None
        }
    }
}
