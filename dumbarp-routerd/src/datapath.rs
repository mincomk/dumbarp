use std::collections::HashSet;

use anyhow::{Context, anyhow};
use aya::{
    Ebpf, EbpfLoader,
    maps::HashMap as BpfHashMap,
    programs::{SchedClassifier, TcAttachType, tc},
};

const PROGRAM_NAME: &str = "dumbarp_routerd";
const IDS_MAP_NAME: &str = "DSCP_IDS";
const FLOWS_MAP_NAME: &str = "FLOWS";

pub struct Datapath {
    bpf: Ebpf,
}

impl Datapath {
    pub fn load(ifaces: &[String], max_flows: u32) -> anyhow::Result<Self> {
        let mut bpf = EbpfLoader::new()
            .map_max_entries(FLOWS_MAP_NAME, max_flows)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/dumbarp-routerd"
            )))?;

        let program: &mut SchedClassifier = bpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{PROGRAM_NAME}` not found"))?
            .try_into()?;
        program.load()?;

        for iface in ifaces {
            let _ = tc::qdisc_add_clsact(iface);
            let program: &mut SchedClassifier = bpf
                .program_mut(PROGRAM_NAME)
                .ok_or_else(|| anyhow!("eBPF program `{PROGRAM_NAME}` not found"))?
                .try_into()?;
            program
                .attach(iface, TcAttachType::Ingress)
                .with_context(|| format!("attaching TC ingress to `{iface}`"))?;
            tracing::info!(iface, "TC ingress attached");
        }

        Ok(Self { bpf })
    }

    pub fn sync_ids(&mut self, ids: &HashSet<u8>) -> anyhow::Result<()> {
        let mut map: BpfHashMap<_, u8, u32> = BpfHashMap::try_from(
            self.bpf
                .map_mut(IDS_MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{IDS_MAP_NAME}` not found"))?,
        )?;

        let existing: Vec<u8> = map.keys().filter_map(Result::ok).collect();
        for id in existing {
            if !ids.contains(&id) {
                let _ = map.remove(&id);
            }
        }
        for id in ids {
            map.insert(*id, u32::from(*id), 0)
                .with_context(|| format!("inserting DSCP_IDS entry {id}"))?;
        }
        Ok(())
    }
}
