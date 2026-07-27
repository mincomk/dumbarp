use std::collections::HashMap as StdHashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::HashMap as BpfHashMap,
    programs::{
        SchedClassifier, TcAttachType, Xdp, XdpMode, tc, tc::SchedClassifierLinkId,
        xdp::XdpLinkId,
    },
};
use dumbarp_common::ArpKey;

const PROGRAM_NAME: &str = "dumbarp";
const EGRESS_PROGRAM_NAME: &str = "dumbarp_egress";
const MAP_NAME: &str = "ARP_TABLE";
const DSCP_MAP_NAME: &str = "DSCP_ID";

pub struct Dumbarp {
    bpf: Ebpf,
    attached: StdHashMap<String, Attached>,
}

struct Attached {
    link_id: XdpLinkId,
    tc_link_id: Option<SchedClassifierLinkId>,
    key: ArpKey,
    ifindex: u32,
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

        let egress: &mut SchedClassifier = bpf
            .program_mut(EGRESS_PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{EGRESS_PROGRAM_NAME}` not found"))?
            .try_into()?;
        egress.load()?;

        Ok(Self {
            bpf,
            attached: StdHashMap::new(),
        })
    }

    pub fn add_interface(
        &mut self,
        iface: &str,
        ip: Ipv4Addr,
        dscp_id: Option<u8>,
    ) -> anyhow::Result<()> {
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
            self.detach_xdp(link_id);
            return Err(e).context("inserting ARP_TABLE entry");
        }

        let tc_link_id = match dscp_id {
            Some(id) => match self.attach_egress(iface, ifindex, id) {
                Ok(link) => Some(link),
                Err(e) => {
                    self.clear_arp_entry(&key);
                    self.clear_dscp_entry(ifindex);
                    self.detach_xdp(link_id);
                    return Err(e);
                }
            },
            None => None,
        };

        self.attached.insert(
            iface.to_string(),
            Attached {
                link_id,
                tc_link_id,
                key,
                ifindex,
            },
        );
        Ok(())
    }

    pub fn remove_interface(&mut self, iface: &str) -> anyhow::Result<()> {
        let Attached {
            link_id,
            tc_link_id,
            key,
            ifindex,
        } = self
            .attached
            .remove(iface)
            .ok_or_else(|| anyhow!("interface `{iface}` not attached"))?;

        if let Some(tc_link_id) = tc_link_id {
            if let Ok(program) = TryInto::<&mut SchedClassifier>::try_into(
                self.bpf
                    .program_mut(EGRESS_PROGRAM_NAME)
                    .ok_or_else(|| anyhow!("eBPF program `{EGRESS_PROGRAM_NAME}` not found"))?,
            ) {
                let _ = program.detach(tc_link_id);
            }
            self.clear_dscp_entry(ifindex);
        }

        self.clear_arp_entry(&key);

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

    fn attach_egress(
        &mut self,
        iface: &str,
        ifindex: u32,
        dscp_id: u8,
    ) -> anyhow::Result<SchedClassifierLinkId> {
        let mut ids: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
            self.bpf
                .map_mut(DSCP_MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{DSCP_MAP_NAME}` not found"))?,
        )?;
        ids.insert(ifindex, dscp_id, 0)
            .context("inserting DSCP_ID entry")?;

        let _ = tc::qdisc_add_clsact(iface);

        let program: &mut SchedClassifier = self
            .bpf
            .program_mut(EGRESS_PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{EGRESS_PROGRAM_NAME}` not found"))?
            .try_into()?;
        program
            .attach(iface, TcAttachType::Egress)
            .with_context(|| format!("attaching TC egress to `{iface}`"))
    }

    fn detach_xdp(&mut self, link_id: XdpLinkId) {
        if let Some(program) = self.bpf.program_mut(PROGRAM_NAME)
            && let Ok(program) = TryInto::<&mut Xdp>::try_into(program)
        {
            let _ = program.detach(link_id);
        }
    }

    fn clear_arp_entry(&mut self, key: &ArpKey) {
        if let Some(map) = self.bpf.map_mut(MAP_NAME)
            && let Ok(mut table) = BpfHashMap::<_, ArpKey, [u8; 6]>::try_from(map)
        {
            let _ = table.remove(key);
        }
    }

    fn clear_dscp_entry(&mut self, ifindex: u32) {
        if let Some(map) = self.bpf.map_mut(DSCP_MAP_NAME)
            && let Ok(mut ids) = BpfHashMap::<_, u32, u8>::try_from(map)
        {
            let _ = ids.remove(&ifindex);
        }
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
