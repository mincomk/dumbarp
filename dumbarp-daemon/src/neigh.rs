use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::task::AbortHandle;
use tokio::time::{MissedTickBehavior, interval};

pub fn spawn_probe_and_refresh(
    iface: String,
    src_ip: Ipv4Addr,
    gw_ip: Ipv4Addr,
    period: Duration,
) -> AbortHandle {
    tokio::spawn(async move {
        let mac = match probe_with_retry(&iface, src_ip, gw_ip).await {
            Ok(m) => m,
            Err(err) => {
                tracing::error!(iface, %gw_ip, %err, "ARP probe failed; skipping neigh entry");
                return;
            }
        };

        if let Err(err) = set_permanent_neigh(&iface, gw_ip, mac).await {
            tracing::error!(iface, %gw_ip, %err, "ip neigh replace failed");
        }

        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // skip the immediate first tick — already set above
        loop {
            ticker.tick().await;
            if let Err(err) = set_permanent_neigh(&iface, gw_ip, mac).await {
                tracing::warn!(iface, %gw_ip, %err, "ip neigh replace refresh failed");
            }
        }
    })
    .abort_handle()
}

async fn probe_with_retry(
    iface: &str,
    src_ip: Ipv4Addr,
    gw_ip: Ipv4Addr,
) -> anyhow::Result<[u8; 6]> {
    let iface = iface.to_owned();
    for attempt in 1..=3u32 {
        match tokio::task::spawn_blocking({
            let iface = iface.clone();
            move || probe_gateway_mac(&iface, src_ip, gw_ip)
        })
        .await
        .context("spawn_blocking panicked")?
        {
            Ok(mac) => return Ok(mac),
            Err(err) => {
                tracing::warn!(iface, %gw_ip, attempt, %err, "ARP probe attempt failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    bail!("all ARP probe attempts failed for {gw_ip} on {iface}")
}

async fn set_permanent_neigh(
    iface: &str,
    gw_ip: Ipv4Addr,
    mac: [u8; 6],
) -> anyhow::Result<()> {
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let iface = iface.to_owned();
    let gw_str = gw_ip.to_string();
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new("ip")
            .args(["neigh", "replace", &gw_str, "lladdr", &mac_str, "dev", &iface, "nud", "permanent"])
            .output()
            .context("ip neigh replace")?;
        if !out.status.success() {
            bail!(
                "ip neigh replace exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    })
    .await
    .context("spawn_blocking panicked")?
}

fn read_iface_mac(iface: &str) -> anyhow::Result<[u8; 6]> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read /sys/class/net/{iface}/address"))?;
    parse_mac(raw.trim())
}

fn read_iface_index(iface: &str) -> anyhow::Result<i32> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("read /sys/class/net/{iface}/ifindex"))?;
    raw.trim().parse::<i32>().context("parse ifindex")
}

fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC: {s}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC byte: {p}"))?;
    }
    Ok(out)
}

fn probe_gateway_mac(
    iface: &str,
    src_ip: Ipv4Addr,
    gw_ip: Ipv4Addr,
) -> anyhow::Result<[u8; 6]> {
    let src_mac = read_iface_mac(iface)?;
    let ifindex = read_iface_index(iface)?;

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        bail!("socket(AF_PACKET): {}", std::io::Error::last_os_error());
    }
    let _fd_guard = FdGuard(fd);

    // Set receive timeout of 2 seconds
    let timeout = libc::timeval { tv_sec: 2, tv_usec: 0 };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        bail!("setsockopt SO_RCVTIMEO: {}", std::io::Error::last_os_error());
    }

    // Bind to the specific interface
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    addr.sll_ifindex = ifindex;
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        bail!("bind: {}", std::io::Error::last_os_error());
    }

    // Build ARP request frame (14 ETH + 28 ARP = 42 bytes)
    let frame = build_arp_request(&src_mac, src_ip, gw_ip);

    let mut dest_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    dest_addr.sll_family = libc::AF_PACKET as u16;
    dest_addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    dest_addr.sll_ifindex = ifindex;
    dest_addr.sll_halen = 6;
    dest_addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    let ret = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &dest_addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        bail!("sendto ARP request: {}", std::io::Error::last_os_error());
    }

    // Receive and parse ARP replies until we find one matching the gateway
    let mut buf = [0u8; 1024];
    loop {
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            bail!("recvfrom ARP reply: {}", std::io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 42 {
            continue;
        }
        if let Some(mac) = parse_arp_reply(&buf[..n], gw_ip, src_ip) {
            return Ok(mac);
        }
    }
}

fn build_arp_request(src_mac: &[u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0u8; 42];

    // Ethernet header (14 bytes): dst=broadcast, src=our MAC, ethertype=ARP
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]); // ETH_P_ARP

    // ARP header (28 bytes) starting at offset 14
    let arp = &mut frame[14..];
    arp[0..2].copy_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    arp[2..4].copy_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
    arp[4] = 6;                                // HLEN
    arp[5] = 4;                                // PLEN
    arp[6..8].copy_from_slice(&[0x00, 0x01]); // OPER: Request
    arp[8..14].copy_from_slice(src_mac);       // SHA
    arp[14..18].copy_from_slice(&src_ip.octets()); // SPA
    arp[18..24].copy_from_slice(&[0x00; 6]);   // THA (unknown)
    arp[24..28].copy_from_slice(&dst_ip.octets()); // TPA

    frame
}

fn parse_arp_reply(
    frame: &[u8],
    expected_sender_ip: Ipv4Addr,
    expected_target_ip: Ipv4Addr,
) -> Option<[u8; 6]> {
    // Skip Ethernet header (14 bytes)
    if frame.len() < 42 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0806 {
        return None;
    }
    let arp = &frame[14..];
    let oper = u16::from_be_bytes([arp[6], arp[7]]);
    if oper != 2 {
        // not ARP Reply
        return None;
    }
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
    if sender_ip != expected_sender_ip || target_ip != expected_target_ip {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&arp[8..14]);
    Some(mac)
}

struct FdGuard(i32);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
