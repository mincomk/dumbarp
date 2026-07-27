#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, xdp_action},
    macros::{classifier, map, xdp},
    maps::{HashMap, LruHashMap},
    programs::{TcContext, XdpContext},
};
use core::mem;
use dumbarp_common::{
    ArpKey, DSCP_ID_MAX, FlowKey, IPPROTO_TCP, IPPROTO_UDP, IPV4_CHECK_OFFSET, IPV4_TOS_OFFSET,
    csum_replace2, tos_with_dscp,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// Map: (ingress ifindex, target IP in network order) -> MAC we answer with.
// Per-iface keying so XDP_TX replies always carry the egress iface's MAC.
#[map]
static ARP_TABLE: HashMap<ArpKey, [u8; 6]> = HashMap::with_max_entries(256, 0);

#[map]
static DSCP_ID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static ORIG_DSCP: LruHashMap<FlowKey, u8> = LruHashMap::with_max_entries(65536, 0);

// ARP header for IPv4-over-Ethernet. network-types doesn't ship an ArpHdr,
// so we define our own packed struct.
#[repr(C, packed)]
struct ArpHdr {
    htype: u16,   // hardware type
    ptype: u16,   // protocol type
    hlen: u8,     // hardware addr len
    plen: u8,     // protocol addr len
    oper: u16,    // operation (1=request, 2=reply)
    sha: [u8; 6], // sender hardware addr
    spa: [u8; 4], // sender protocol addr (IPv4)
    tha: [u8; 6], // target hardware addr
    tpa: [u8; 4], // target protocol addr (IPv4)
}

const ARPOP_REQUEST: u16 = 1;
const ARPOP_REPLY: u16 = 2;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[xdp]
pub fn dumbarp(ctx: XdpContext) -> u32 {
    match try_dumbarp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_dumbarp(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    let ether_type = unsafe { (*eth).ether_type };

    if ether_type == EtherType::Arp.into() {
        return try_arp(ctx, eth);
    }
    if ether_type == EtherType::Ipv4.into() {
        return try_stamp(ctx);
    }
    Ok(xdp_action::XDP_PASS)
}

fn try_arp(ctx: &XdpContext, eth: *mut EthHdr) -> Result<u32, ()> {
    let arp: *mut ArpHdr = ptr_at(ctx, EthHdr::LEN)?;

    // Only IPv4 ARP requests (htype=1 Ethernet, ptype=0x0800 IPv4)
    unsafe {
        if u16::from_be((*arp).oper) != ARPOP_REQUEST {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Target IP the requester is asking about (network byte order)
    let tpa = unsafe { (*arp).tpa };
    let target_ip = u32::from_ne_bytes(tpa);

    let key = ArpKey {
        ifindex: unsafe { (*ctx.ctx).ingress_ifindex },
        ip: target_ip,
    };

    // Do we answer for this (iface, IP)?
    let our_mac = match unsafe { ARP_TABLE.get(&key) } {
        Some(mac) => *mac,
        None => return Ok(xdp_action::XDP_PASS),
    };

    unsafe {
        // --- Rewrite ARP payload: request -> reply ---
        (*arp).oper = ARPOP_REPLY.to_be();

        // New target = old sender
        let old_sha = (*arp).sha;
        let old_spa = (*arp).spa;
        (*arp).tha = old_sha;
        (*arp).tpa = old_spa;

        // New sender = us
        (*arp).sha = our_mac;
        (*arp).spa = tpa; // the IP that was being requested

        // --- Rewrite Ethernet header: swap, set src to our MAC ---
        let eth_src = (*eth).src_addr;
        (*eth).dst_addr = eth_src;
        (*eth).src_addr = our_mac;
    }

    Ok(xdp_action::XDP_TX)
}

fn try_stamp(ctx: &XdpContext) -> Result<u32, ()> {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let id = match unsafe { DSCP_ID.get(&ifindex) } {
        Some(id) if *id != 0 && *id <= DSCP_ID_MAX => *id,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let ip: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let dst = u32::from_ne_bytes(unsafe { (*ip).dst_addr });

    if unsafe { ARP_TABLE.get(&ArpKey { ifindex, ip: dst }) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    let old_tos = unsafe { (*ip).tos };
    let new_tos = tos_with_dscp(old_tos, id);
    if new_tos == old_tos {
        return Ok(xdp_action::XDP_PASS);
    }

    let key = xdp_flow_key(ctx, ip);
    let _ = ORIG_DSCP.insert(&key.reversed(), &(old_tos >> 2), 0);

    unsafe {
        let vihl = (*ip).vihl;
        let old_word = ((vihl as u16) << 8) | old_tos as u16;
        let new_word = ((vihl as u16) << 8) | new_tos as u16;
        let check = u16::from_be_bytes((*ip).check);
        (*ip).tos = new_tos;
        (*ip).check = csum_replace2(check, old_word, new_word).to_be_bytes();
    }

    Ok(xdp_action::XDP_PASS)
}

fn xdp_flow_key(ctx: &XdpContext, ip: *mut Ipv4Hdr) -> FlowKey {
    let (src, dst, proto, ihl) = unsafe {
        (
            u32::from_ne_bytes((*ip).src_addr),
            u32::from_ne_bytes((*ip).dst_addr),
            (*ip).proto,
            (*ip).ihl(),
        )
    };

    let mut sport = 0u16;
    let mut dport = 0u16;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && ihl as usize == Ipv4Hdr::LEN
        && let Ok(ports) = ptr_at::<[u8; 4]>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
    {
        let p = unsafe { *ports };
        sport = u16::from_be_bytes([p[0], p[1]]);
        dport = u16::from_be_bytes([p[2], p[3]]);
    }

    FlowKey::new(src, dst, sport, dport, proto)
}

#[classifier]
pub fn dumbarp_egress(ctx: TcContext) -> i32 {
    match try_terminate(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32,
    }
}

fn try_terminate(ctx: &TcContext) -> Result<i32, ()> {
    let pass = TC_ACT_OK as i32;

    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(pass);
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let old_tos = ip.tos;

    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let our_id = match unsafe { DSCP_ID.get(&ifindex) } {
        Some(id) if *id != 0 => *id,
        _ => return Ok(pass),
    };
    if old_tos >> 2 != our_id {
        return Ok(pass);
    }

    let key = tc_flow_key(ctx, &ip);
    let restored = unsafe { ORIG_DSCP.get(&key) }.copied().unwrap_or(0);

    let new_tos = tos_with_dscp(old_tos, restored);
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

fn tc_flow_key(ctx: &TcContext, ip: &Ipv4Hdr) -> FlowKey {
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
