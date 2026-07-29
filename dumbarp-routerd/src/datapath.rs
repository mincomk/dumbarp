use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::{Context, anyhow};
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap as BpfHashMap, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc},
};
use dumbarp_common::{
    COUNTER_SLOTS, CTR_DSCP_TAGGED, CTR_FLOW_HIT, CTR_SRC_FALLBACK, CTR_UNMARKED,
};

const PROGRAM_NAME: &str = "dumbarp_routerd";
const IDS_MAP_NAME: &str = "DSCP_IDS";
const FLOWS_MAP_NAME: &str = "FLOWS";
const SRC_MARKS_MAP_NAME: &str = "SRC_MARKS";
const COUNTERS_MAP_NAME: &str = "COUNTERS";

#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    pub dscp_tagged: u64,
    pub flow_hit: u64,
    pub src_fallback: u64,
    pub unmarked: u64,
}

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

    pub fn sync_src_marks(&mut self, marks: &HashMap<Ipv4Addr, u32>) -> anyhow::Result<()> {
        let mut map: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
            self.bpf
                .map_mut(SRC_MARKS_MAP_NAME)
                .ok_or_else(|| anyhow!("eBPF map `{SRC_MARKS_MAP_NAME}` not found"))?,
        )?;

        let wanted: HashMap<u32, u32> = marks
            .iter()
            .map(|(ip, mark)| (u32::from_ne_bytes(ip.octets()), *mark))
            .collect();

        let existing: Vec<u32> = map.keys().filter_map(Result::ok).collect();
        for key in existing {
            if !wanted.contains_key(&key) {
                let _ = map.remove(&key);
            }
        }
        for (key, mark) in &wanted {
            map.insert(key, mark, 0)
                .with_context(|| format!("inserting SRC_MARKS entry {key:#x}"))?;
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
            dscp_tagged: totals[CTR_DSCP_TAGGED as usize],
            flow_hit: totals[CTR_FLOW_HIT as usize],
            src_fallback: totals[CTR_SRC_FALLBACK as usize],
            unmarked: totals[CTR_UNMARKED as usize],
        })
    }
}
