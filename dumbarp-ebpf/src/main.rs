#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::eth::{EthHdr, EtherType};

// Map: target IP (u32, network order) -> MAC we answer with ([u8; 6])
#[map]
static ARP_TABLE: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(256, 0);

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
    match try_arp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_arp(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_at(ctx, 0)?;

    // Only ARP
    if unsafe { (*eth).ether_type } != EtherType::Arp.into() {
        return Ok(xdp_action::XDP_PASS);
    }

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

    // Do we answer for this IP?
    let our_mac = match unsafe { ARP_TABLE.get(&target_ip) } {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
