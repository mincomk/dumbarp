use std::collections::HashMap as StdHashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::HashMap as BpfHashMap,
    programs::{Xdp, XdpMode, xdp::XdpLinkId},
};
use dumbarp_common::ArpKey;

const PROGRAM_NAME: &str = "dumbarp";
const MAP_NAME: &str = "ARP_TABLE";

pub struct Dumbarp {
    bpf: Ebpf,
    attached: StdHashMap<String, Attached>,
}

struct Attached {
    link_id: XdpLinkId,
    key: ArpKey,
}

impl Dumbarp {
    pub fn new() -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/dumbarp"
        )))?;

        let program: &mut Xdp = bpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{PROGRAM_NAME}` not found"))?
            .try_into()?;
        program.load()?;

        Ok(Self {
            bpf,
            attached: StdHashMap::new(),
        })
    }

    pub fn add_interface(&mut self, iface: &str, ip: Ipv4Addr) -> anyhow::Result<()> {
        if self.attached.contains_key(iface) {
            return Err(anyhow!("interface `{iface}` already attached"));
        }

        let mac = iface_mac(iface)?;
        let ifindex = iface_ifindex(iface)?;
        let key = ArpKey {
            ifindex,
            ip: u32::from_ne_bytes(ip.octets()),
        };

        let program: &mut Xdp = self
            .bpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{PROGRAM_NAME}` not found"))?
            .try_into()?;
        let link_id = program
            .attach(iface, XdpMode::Default)
            .with_context(|| format!("attaching XDP to `{iface}`"))?;

        let mut table: BpfHashMap<_, ArpKey, [u8; 6]> = BpfHashMap::try_from(
            self.bpf
                .map_mut(MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{MAP_NAME}` not found"))?,
        )?;
        if let Err(e) = table.insert(key, mac, 0) {
            let program: &mut Xdp = self
                .bpf
                .program_mut(PROGRAM_NAME)
                .unwrap()
                .try_into()
                .unwrap();
            let _ = program.detach(link_id);
            return Err(e).context("inserting ARP_TABLE entry");
        }

        self.attached
            .insert(iface.to_string(), Attached { link_id, key });
        Ok(())
    }

    pub fn remove_interface(&mut self, iface: &str) -> anyhow::Result<()> {
        let Attached { link_id, key } = self
            .attached
            .remove(iface)
            .ok_or_else(|| anyhow!("interface `{iface}` not attached"))?;

        let mut table: BpfHashMap<_, ArpKey, [u8; 6]> = BpfHashMap::try_from(
            self.bpf
                .map_mut(MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{MAP_NAME}` not found"))?,
        )?;
        let _ = table.remove(&key);

        let program: &mut Xdp = self
            .bpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{PROGRAM_NAME}` not found"))?
            .try_into()?;
        program
            .detach(link_id)
            .with_context(|| format!("detaching XDP from `{iface}`"))?;
        Ok(())
    }

    pub fn attached_interfaces(&self) -> impl Iterator<Item = &str> {
        self.attached.keys().map(String::as_str)
    }
}

fn iface_mac(iface: &str) -> anyhow::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    parse_mac(s.trim())
}

fn iface_ifindex(iface: &str) -> anyhow::Result<u32> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let s = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    s.trim()
        .parse::<u32>()
        .with_context(|| format!("parsing ifindex from {path}"))
}

fn parse_mac(mac_str: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("invalid MAC address format: {mac_str}"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("parsing MAC octet `{part}`"))?;
    }
    Ok(mac)
}
