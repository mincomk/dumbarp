pub mod isc_dhclient;

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub interface: String,
    pub ip_address: String,
    pub subnet_mask: String,
    pub router: String,
    pub expired: bool,
}

pub trait ReadDhcpLease {
    fn read_dhcp_lease(&self) -> Option<DhcpLease>;
}
