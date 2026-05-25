use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use anyhow::{Context, anyhow};
use futures::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder, new_connection};

const DUMBARP_PROTO_RAW: u8 = 0x9A;
const DUMBARP_PROTO: RouteProtocol = RouteProtocol::Other(DUMBARP_PROTO_RAW);
const DUMBARP_PRIORITY: u32 = 9876;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    pub src: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub iface: String,
}

pub struct RouteManager {
    handle: Handle,
}

impl RouteManager {
    pub fn new() -> anyhow::Result<Self> {
        let (connection, handle, _) =
            new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn reconcile(&self, desired: &[RouteSpec]) -> anyhow::Result<()> {
        // Resolve ifname -> ifindex once per reconcile, dropping specs we can't resolve.
        let mut resolved: HashMap<u32, ResolvedSpec> = HashMap::new();
        for spec in desired {
            match self.ifindex(&spec.iface).await {
                Ok(ifindex) => {
                    let table = table_id_for(spec.src);
                    resolved.insert(
                        table,
                        ResolvedSpec {
                            src: spec.src,
                            gateway: spec.gateway,
                            ifindex,
                        },
                    );
                }
                Err(err) => {
                    tracing::warn!(iface = %spec.iface, %err, "ifindex lookup failed; skipping");
                }
            }
        }

        let current_rules = self.list_rules().await?;
        let current_routes = self.list_routes().await?;

        let mut all_tables: HashSet<u32> = HashSet::new();
        all_tables.extend(current_rules.keys().copied());
        all_tables.extend(current_routes.keys().copied());
        all_tables.extend(resolved.keys().copied());

        for table in all_tables {
            let want = resolved.get(&table);
            let have_rule = current_rules.get(&table);
            let have_route = current_routes.get(&table);

            let matches = match (want, have_rule, have_route) {
                (Some(w), Some(r), Some(rt)) => {
                    r.src == w.src
                        && rt.gateway == w.gateway
                        && rt.oif == w.ifindex
                        && rt.onlink
                }
                _ => false,
            };

            if matches {
                continue;
            }

            if let Some(rule) = have_rule
                && let Err(err) = self.del_rule(rule.src, table).await
            {
                tracing::warn!(table, %err, "delete stale rule failed");
            }
            if have_route.is_some()
                && let Err(err) = self.del_route(table).await
            {
                tracing::warn!(table, %err, "delete stale route failed");
            }

            if let Some(w) = want {
                if let Err(err) = self.add_rule(w.src, table).await {
                    tracing::warn!(table, src = %w.src, %err, "add rule failed");
                    continue;
                }
                if let Err(err) =
                    self.add_route(table, w.gateway, w.ifindex).await
                {
                    tracing::warn!(table, gw = %w.gateway, %err, "add route failed");
                }
            }
        }

        Ok(())
    }

    async fn ifindex(&self, iface: &str) -> anyhow::Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute();
        let link = links
            .try_next()
            .await
            .with_context(|| format!("rtnetlink get link {iface}"))?
            .ok_or_else(|| anyhow!("interface `{iface}` not found"))?;
        Ok(link.header.index)
    }

    async fn list_rules(&self) -> anyhow::Result<HashMap<u32, CurrentRule>> {
        let mut out = HashMap::new();
        let mut stream = self.handle.rule().get(IpVersion::V4).execute();
        while let Some(msg) = stream.try_next().await? {
            let Some((src, table)) = parse_dumbarp_rule(&msg) else {
                continue;
            };
            out.insert(table, CurrentRule { src });
        }
        Ok(out)
    }

    async fn list_routes(&self) -> anyhow::Result<HashMap<u32, CurrentRoute>> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new().build();
        let mut stream = self.handle.route().get(msg).execute();
        let mut out = HashMap::new();
        while let Some(msg) = stream.try_next().await? {
            let Some(current) = parse_dumbarp_route(&msg) else {
                continue;
            };
            out.insert(current.table, current.into_value());
        }
        Ok(out)
    }

    async fn add_rule(&self, src: Ipv4Addr, table: u32) -> anyhow::Result<()> {
        self.handle
            .rule()
            .add()
            .v4()
            .source_prefix(src, 32)
            .table_id(table)
            .action(RuleAction::ToTable)
            .priority(DUMBARP_PRIORITY)
            .execute()
            .await
            .with_context(|| format!("add rule src={src} table={table}"))?;
        Ok(())
    }

    async fn del_rule(&self, src: Ipv4Addr, table: u32) -> anyhow::Result<()> {
        let mut msg = RuleMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.src_len = 32;
        msg.header.action = RuleAction::ToTable;
        msg.attributes.push(RuleAttribute::Source(src.into()));
        msg.attributes.push(RuleAttribute::Table(table));
        msg.attributes.push(RuleAttribute::Priority(DUMBARP_PRIORITY));
        self.handle
            .rule()
            .del(msg)
            .execute()
            .await
            .with_context(|| format!("del rule src={src} table={table}"))?;
        Ok(())
    }

    async fn add_route(
        &self,
        table: u32,
        gateway: Ipv4Addr,
        ifindex: u32,
    ) -> anyhow::Result<()> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table)
            .protocol(DUMBARP_PROTO)
            .output_interface(ifindex)
            .gateway(gateway)
            .onlink()
            .build();
        self.handle
            .route()
            .add(msg)
            .execute()
            .await
            .with_context(|| {
                format!("add route table={table} via {gateway} dev #{ifindex}")
            })?;
        Ok(())
    }

    async fn del_route(&self, table: u32) -> anyhow::Result<()> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(table)
            .protocol(DUMBARP_PROTO)
            .build();
        self.handle
            .route()
            .del(msg)
            .execute()
            .await
            .with_context(|| format!("del route table={table}"))?;
        Ok(())
    }
}

struct ResolvedSpec {
    src: Ipv4Addr,
    gateway: Ipv4Addr,
    ifindex: u32,
}

struct CurrentRule {
    src: Ipv4Addr,
}

struct CurrentRoute {
    gateway: Ipv4Addr,
    oif: u32,
    onlink: bool,
}

struct ParsedRoute {
    table: u32,
    gateway: Ipv4Addr,
    oif: u32,
    onlink: bool,
}

impl ParsedRoute {
    fn into_value(self) -> CurrentRoute {
        CurrentRoute {
            gateway: self.gateway,
            oif: self.oif,
            onlink: self.onlink,
        }
    }
}

// Table IDs 0, 253 (default), 254 (main), 255 (local) are reserved by the
// kernel; nudge collisions away from those four values.
fn table_id_for(ip: Ipv4Addr) -> u32 {
    let raw = u32::from(ip);
    match raw {
        0 | 253 | 254 | 255 => raw.wrapping_add(0x1_0000),
        _ => raw,
    }
}

fn parse_dumbarp_rule(msg: &RuleMessage) -> Option<(Ipv4Addr, u32)> {
    if msg.header.family != AddressFamily::Inet {
        return None;
    }
    let mut priority = None;
    let mut src = None;
    let mut table_attr = None;
    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = Some(*p),
            RuleAttribute::Source(std::net::IpAddr::V4(v4)) => src = Some(*v4),
            RuleAttribute::Table(t) => table_attr = Some(*t),
            _ => {}
        }
    }
    if priority != Some(DUMBARP_PRIORITY) {
        return None;
    }
    let src = src?;
    if msg.header.src_len != 32 {
        return None;
    }
    let table = table_attr.unwrap_or(msg.header.table as u32);
    Some((src, table))
}

fn parse_dumbarp_route(msg: &RouteMessage) -> Option<ParsedRoute> {
    if msg.header.address_family != AddressFamily::Inet {
        return None;
    }
    if msg.header.protocol != DUMBARP_PROTO {
        return None;
    }
    let onlink = msg.header.flags.contains(RouteFlags::Onlink);
    let mut gateway = None;
    let mut oif = None;
    let mut table_attr = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Gateway(RouteAddress::Inet(v4)) => {
                gateway = Some(*v4)
            }
            RouteAttribute::Oif(idx) => oif = Some(*idx),
            RouteAttribute::Table(t) => table_attr = Some(*t),
            _ => {}
        }
    }
    let table = table_attr.unwrap_or(msg.header.table as u32);
    Some(ParsedRoute {
        table,
        gateway: gateway?,
        oif: oif?,
        onlink,
    })
}
