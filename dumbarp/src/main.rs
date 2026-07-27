use clap::Parser;
use dumbarp::Dumbarp;
use std::net::Ipv4Addr;

#[derive(Parser)]
struct Opt {
    #[clap(short, long, default_value = "wan0")]
    iface: String,

    #[clap(long, default_value = "192.168.1.104")]
    ip: Ipv4Addr,

    #[clap(long)]
    dscp_id: Option<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let mut daemon = Dumbarp::new()?;
    daemon.add_interface(&opt.iface, opt.ip, opt.dscp_id.filter(|id| *id != 0))?;

    println!(
        "ARP responder attached to {} answering for {}. Ctrl-C to exit.",
        opt.iface, opt.ip
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}
