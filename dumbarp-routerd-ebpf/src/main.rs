#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray},
    programs::TcContext,
};
use dumbarp_common::{COUNTER_SLOTS, CTR_TAGGED, CTR_UNTAGGED};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

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
    match try_steer(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32,
    }
}

// The daemon stamps a DSCP tag on traffic heading for one of its lease IPs, and
// that tag rides the packet across every hop of the internal network. Each
// router turns the tag into an skb mark; netfilter then saves the mark onto the
// conntrack entry, so the reply gets it back on whichever hops carry it. The tag
// is left on the wire here — the daemon at the far edge restores the original
// DSCP on its own egress.
fn try_steer(ctx: &TcContext) -> Result<i32, ()> {
    let pass = TC_ACT_OK as i32;

    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(pass);
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let dscp = ip.tos >> 2;

    if dscp != 0
        && let Some(mark) = unsafe { DSCP_IDS.get(&dscp) }.copied()
    {
        ctx.skb.set_mark(mark);
        bump(CTR_TAGGED);
        return Ok(pass);
    }

    bump(CTR_UNTAGGED);
    Ok(pass)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
