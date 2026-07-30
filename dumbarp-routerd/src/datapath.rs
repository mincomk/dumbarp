use std::collections::HashSet;

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::{HashMap as BpfHashMap, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc},
};
use dumbarp_common::{COUNTER_SLOTS, CTR_TAGGED, CTR_UNTAGGED};

const PROGRAM_NAME: &str = "dumbarp_routerd";
const IDS_MAP_NAME: &str = "DSCP_IDS";
const COUNTERS_MAP_NAME: &str = "COUNTERS";

#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub tagged: u64,
    pub untagged: u64,
}

pub struct Datapath {
    bpf: Ebpf,
}

impl Datapath {
    pub fn load(ifaces: &[String]) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
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

    pub fn counters(&self) -> anyhow::Result<Counters> {
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.bpf
                .map(COUNTERS_MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{COUNTERS_MAP_NAME}` not found"))?,
        )?;

        let mut totals = [0u64; COUNTER_SLOTS as usize];
        for (slot, total) in totals.iter_mut().enumerate() {
            let per_cpu = map
                .get(&(slot as u32), 0)
                .with_context(|| format!("reading COUNTERS slot {slot}"))?;
            *total = per_cpu.iter().sum();
        }

        Ok(Counters {
            tagged: totals[CTR_TAGGED as usize],
            untagged: totals[CTR_UNTAGGED as usize],
        })
    }
}
