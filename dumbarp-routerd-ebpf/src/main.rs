#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, bpf_hdr_start_off::BPF_HDR_START_NET},
    helpers::bpf_skb_load_bytes_relative,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};
use dumbarp_common::{COUNTER_SLOTS, CTR_SKIPPED, CTR_TAGGED, CTR_UNTAGGED, IPV4_TOS_OFFSET};
use network_types::eth::EtherType;

#[map]
static DSCP_IDS: HashMap<u8, u32> = HashMap::with_max_entries(64, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTER_SLOTS, 0);

fn bump(slot: u32) {
    if let Some(v) = COUNTERS.get_ptr_mut(slot) {
        unsafe { *v += 1 };
    }
}

#[classifier]
pub fn dumbarp_routerd(ctx: TcContext) -> i32 {
    steer(&ctx)
}

// The daemon stamps a DSCP tag on traffic heading for one of its lease IPs, and
// that tag rides the packet across every hop of the internal network. Each
// router turns the tag into an skb mark; netfilter then saves the mark onto the
// conntrack entry, so the reply gets it back on whichever hops carry it. The tag
// is left on the wire here — the daemon at the far edge restores the original
// DSCP on its own egress.
//
// Nothing here may assume an Ethernet header. The kernel pushes `skb->mac_len`
// before running an ingress classifier, which is zero on an L3 device such as a
// WireGuard tunnel, so offset 0 is the IP header there and the Ethernet header
// elsewhere. Reading relative to the network header is correct on both.
fn steer(ctx: &TcContext) -> i32 {
    let pass = TC_ACT_OK as i32;

    if unsafe { (*ctx.skb.skb).protocol } != u32::from(EtherType::Ipv4 as u16) {
        bump(CTR_SKIPPED);
        return pass;
    }

    let Ok(tos) = load_net_u8(ctx, IPV4_TOS_OFFSET) else {
        bump(CTR_SKIPPED);
        return pass;
    };
    let dscp = tos >> 2;

    if dscp != 0
        && let Some(mark) = unsafe { DSCP_IDS.get(&dscp) }.copied()
    {
        ctx.skb.set_mark(mark);
        bump(CTR_TAGGED);
        return pass;
    }

    bump(CTR_UNTAGGED);
    pass
}

fn load_net_u8(ctx: &TcContext, offset: usize) -> Result<u8, ()> {
    let mut byte = 0u8;
    let ret = unsafe {
        bpf_skb_load_bytes_relative(
            ctx.skb.skb.cast(),
            offset as u32,
            (&raw mut byte).cast(),
            1,
            BPF_HDR_START_NET,
        )
    };
    if ret == 0 { Ok(byte) } else { Err(()) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
