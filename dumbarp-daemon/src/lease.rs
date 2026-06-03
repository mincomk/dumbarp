use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseInfo {
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
}
