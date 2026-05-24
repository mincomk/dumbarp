use aya::{
    Ebpf,
    maps::HashMap,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser)]
struct Opt {
    #[clap(short, long, default_value = "wan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dumbarp"
    )))?;

    let program: &mut Xdp = bpf.program_mut("dumbarp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpMode::Default)?;

    // Populate: answer for 192.168.1.50 with this MAC
    let mut table: HashMap<_, u32, [u8; 6]> = HashMap::try_from(bpf.map_mut("ARP_TABLE").unwrap())?;

    let ip = Ipv4Addr::new(192, 168, 1, 104);
    let ip_key = u32::from_ne_bytes(ip.octets()); // match the program's keying
    let mac: [u8; 6] = parse_mac("02:1a:c5:01:00:00")?;

    table.insert(ip_key, mac, 0)?;

    println!("ARP responder attached to {}. Ctrl-C to exit.", opt.iface);
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn parse_mac(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}
