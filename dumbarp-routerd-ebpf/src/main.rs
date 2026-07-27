#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{HashMap, LruHashMap},
    programs::TcContext,
};
use dumbarp_common::{
    FlowKey, IPPROTO_TCP, IPPROTO_UDP, IPV4_CHECK_OFFSET, IPV4_TOS_OFFSET, tos_with_dscp,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static DSCP_IDS: HashMap<u8, u32> = HashMap::with_max_entries(64, 0);

#[map]
static FLOWS: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(65536, 0);

#[classifier]
pub fn dumbarp_routerd(ctx: TcContext) -> i32 {
    match try_steer(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32,
    }
}

fn try_steer(ctx: &TcContext) -> Result<i32, ()> {
    let pass = TC_ACT_OK as i32;

    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(pass);
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let key = flow_key(ctx, &ip);
    let dscp = ip.tos >> 2;

    if dscp != 0
        && let Some(mark) = unsafe { DSCP_IDS.get(&dscp) }.copied()
    {
        let _ = FLOWS.insert(&key.reversed(), &mark, 0);
        return strip_dscp(ctx, &ip);
    }

    if let Some(mark) = unsafe { FLOWS.get(&key) }.copied() {
        ctx.skb.set_mark(mark);
    }

    Ok(pass)
}

fn strip_dscp(ctx: &TcContext, ip: &Ipv4Hdr) -> Result<i32, ()> {
    let pass = TC_ACT_OK as i32;

    let old_tos = ip.tos;
    let new_tos = tos_with_dscp(old_tos, 0);
    if new_tos == old_tos {
        return Ok(pass);
    }

    let old_word = ((ip.vihl as u16) << 8) | old_tos as u16;
    let new_word = ((ip.vihl as u16) << 8) | new_tos as u16;

    ctx.store(EthHdr::LEN + IPV4_TOS_OFFSET, &new_tos, 0)
        .map_err(|_| ())?;
    ctx.l3_csum_replace(
        EthHdr::LEN + IPV4_CHECK_OFFSET,
        old_word.to_be() as u64,
        new_word.to_be() as u64,
        2,
    )
    .map_err(|_| ())?;

    Ok(pass)
}

fn flow_key(ctx: &TcContext, ip: &Ipv4Hdr) -> FlowKey {
    let src = u32::from_ne_bytes(ip.src_addr);
    let dst = u32::from_ne_bytes(ip.dst_addr);
    let proto = ip.proto;

    let mut sport = 0u16;
    let mut dport = 0u16;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && ip.ihl() as usize == Ipv4Hdr::LEN
        && let Ok(ports) = ctx.load::<[u8; 4]>(EthHdr::LEN + Ipv4Hdr::LEN)
    {
        sport = u16::from_be_bytes([ports[0], ports[1]]);
        dport = u16::from_be_bytes([ports[2], ports[3]]);
    }

    FlowKey::new(src, dst, sport, dport, proto)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
