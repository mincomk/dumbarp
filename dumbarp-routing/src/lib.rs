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
const FWMASK_EXACT: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    pub src: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub iface: String,
    pub fwmark: Option<u32>,
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
        let mut ifindex_cache: HashMap<String, u32> = HashMap::new();
        let mut resolved: HashMap<u32, ResolvedSpec> = HashMap::new();
        for spec in desired {
            let ifindex = match ifindex_cache.get(&spec.iface).copied() {
                Some(idx) => idx,
                None => match self.ifindex(&spec.iface).await {
                    Ok(idx) => {
                        ifindex_cache.insert(spec.iface.clone(), idx);
                        idx
                    }
                    Err(err) => {
                        tracing::warn!(iface = %spec.iface, %err, "ifindex lookup failed; skipping");
                        continue;
                    }
                },
            };
            let table = table_id_for(spec.src);
            resolved.insert(
                table,
                ResolvedSpec {
                    src: spec.src,
                    gateway: spec.gateway,
                    ifindex,
                    fwmark: spec.fwmark,
                },
            );
        }

        let current_rules = self.list_rules().await?;
        let current_routes = self.list_routes().await?;

        let mut all_tables: HashSet<u32> = HashSet::new();
        all_tables.extend(current_rules.keys().copied());
        all_tables.extend(current_routes.keys().copied());
        all_tables.extend(resolved.keys().copied());

        for table in all_tables {
            let want = resolved.get(&table);
            let have_rules = current_rules
                .get(&table)
                .map(|rules| rules.as_slice())
                .unwrap_or(&[]);
            let have_route = current_routes.get(&table);

            let matches = match (want, have_rules, have_route) {
                (Some(w), [r], Some(rt)) => {
                    r.matches(w)
                        && rt.gateway == w.gateway
                        && rt.oif == w.ifindex
                        && rt.onlink
                }
                _ => false,
            };

            if matches {
                continue;
            }

            if have_rules.len() > 1 {
                tracing::warn!(
                    table,
                    count = have_rules.len(),
                    "multiple dumbarp rules for one table; removing all"
                );
            }

            let mut delete_failed = false;
            for rule in have_rules {
                if let Err(err) = self.del_rule(rule.src, table, rule.fwmark).await {
                    tracing::warn!(table, src = %rule.src, %err, "delete stale rule failed");
                    delete_failed = true;
                }
            }
            if have_route.is_some()
                && let Err(err) = self.del_route(table).await
            {
                tracing::warn!(table, %err, "delete stale route failed");
                delete_failed = true;
            }

            if let Some(w) = want {
                if delete_failed {
                    tracing::warn!(
                        table,
                        src = %w.src,
                        "skipping add while stale state remains; retrying next pass"
                    );
                    continue;
                }
                if let Err(err) = self.add_rule(w.src, table, w.fwmark).await {
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

    async fn list_rules(&self) -> anyhow::Result<HashMap<u32, Vec<CurrentRule>>> {
        let mut out: HashMap<u32, Vec<CurrentRule>> = HashMap::new();
        let mut stream = self.handle.rule().get(IpVersion::V4).execute();
        while let Some(msg) = stream.try_next().await? {
            let Some((table, rule)) = parse_dumbarp_rule(&msg) else {
                continue;
            };
            out.entry(table).or_default().push(rule);
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

    async fn add_rule(
        &self,
        src: Ipv4Addr,
        table: u32,
        fwmark: Option<u32>,
    ) -> anyhow::Result<()> {
        let mut req = self
            .handle
            .rule()
            .add()
            .v4()
            .source_prefix(src, 32)
            .table_id(table)
            .action(RuleAction::ToTable)
            .priority(DUMBARP_PRIORITY);
        if let Some(mark) = fwmark {
            req = req.fw_mark(mark);
            req.message_mut()
                .attributes
                .push(RuleAttribute::FwMask(FWMASK_EXACT));
        }
        req.execute()
            .await
            .with_context(|| format!("add rule src={src} table={table} fwmark={fwmark:?}"))?;
        Ok(())
    }

    async fn del_rule(
        &self,
        src: Ipv4Addr,
        table: u32,
        fwmark: Option<u32>,
    ) -> anyhow::Result<()> {
        let mut msg = RuleMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.src_len = 32;
        msg.header.action = RuleAction::ToTable;
        msg.attributes.push(RuleAttribute::Source(src.into()));
        msg.attributes.push(RuleAttribute::Table(table));
        msg.attributes.push(RuleAttribute::Priority(DUMBARP_PRIORITY));
        if let Some(mark) = fwmark {
            msg.attributes.push(RuleAttribute::FwMark(mark));
        }
        self.handle
            .rule()
            .del(msg)
            .execute()
            .await
            .with_context(|| format!("del rule src={src} table={table} fwmark={fwmark:?}"))?;
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
    fwmark: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct CurrentRule {
    src: Ipv4Addr,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
}

impl CurrentRule {
    fn matches(&self, want: &ResolvedSpec) -> bool {
        self.src == want.src
            && self.fwmark == want.fwmark
            && self.fwmask == expected_fwmask(want.fwmark)
    }
}

fn expected_fwmask(fwmark: Option<u32>) -> Option<u32> {
    fwmark.map(|_| FWMASK_EXACT)
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
pub fn table_id_for(ip: Ipv4Addr) -> u32 {
    let raw = u32::from(ip);
    match raw {
        0 | 253 | 254 | 255 => raw.wrapping_add(0x1_0000),
        _ => raw,
    }
}

fn parse_dumbarp_rule(msg: &RuleMessage) -> Option<(u32, CurrentRule)> {
    if msg.header.family != AddressFamily::Inet {
        return None;
    }
    let mut priority = None;
    let mut src = None;
    let mut table_attr = None;
    let mut fwmark = None;
    let mut fwmask = None;
    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = Some(*p),
            RuleAttribute::Source(std::net::IpAddr::V4(v4)) => src = Some(*v4),
            RuleAttribute::Table(t) => table_attr = Some(*t),
            RuleAttribute::FwMark(m) => fwmark = Some(*m),
            RuleAttribute::FwMask(m) => fwmask = Some(*m),
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
    let fwmark = fwmark.filter(|m| *m != 0);
    Some((
        table,
        CurrentRule {
            src,
            fwmark,
            fwmask: fwmark.and(fwmask),
        },
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_msg(src: Ipv4Addr, table: u32, fwmark: Option<u32>, fwmask: Option<u32>) -> RuleMessage {
        let mut msg = RuleMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.src_len = 32;
        msg.header.action = RuleAction::ToTable;
        msg.attributes.push(RuleAttribute::Source(src.into()));
        msg.attributes.push(RuleAttribute::Table(table));
        msg.attributes.push(RuleAttribute::Priority(DUMBARP_PRIORITY));
        if let Some(mark) = fwmark {
            msg.attributes.push(RuleAttribute::FwMark(mark));
        }
        if let Some(mask) = fwmask {
            msg.attributes.push(RuleAttribute::FwMask(mask));
        }
        msg
    }

    fn spec(src: Ipv4Addr, fwmark: Option<u32>) -> ResolvedSpec {
        ResolvedSpec {
            src,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            ifindex: 2,
            fwmark,
        }
    }

    #[test]
    fn marked_rule_with_exact_mask_matches() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let msg = rule_msg(src, 1846396077, Some(2), Some(FWMASK_EXACT));
        let (table, rule) = parse_dumbarp_rule(&msg).unwrap();
        assert_eq!(table, 1846396077);
        assert!(rule.matches(&spec(src, Some(2))));
    }

    #[test]
    fn marked_rule_with_narrow_mask_is_drift() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let msg = rule_msg(src, 1846396077, Some(2), Some(0x0F));
        let (_, rule) = parse_dumbarp_rule(&msg).unwrap();
        assert!(!rule.matches(&spec(src, Some(2))));
    }

    #[test]
    fn marked_rule_without_mask_is_drift() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let msg = rule_msg(src, 1846396077, Some(2), None);
        let (_, rule) = parse_dumbarp_rule(&msg).unwrap();
        assert!(!rule.matches(&spec(src, Some(2))));
    }

    #[test]
    fn unmarked_rule_never_matches_marked_spec() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let msg = rule_msg(src, 1846396077, None, None);
        let (_, rule) = parse_dumbarp_rule(&msg).unwrap();
        assert!(!rule.matches(&spec(src, Some(2))));
        assert!(rule.matches(&spec(src, None)));
    }

    #[test]
    fn zero_fwmark_is_treated_as_unmarked() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let msg = rule_msg(src, 1846396077, Some(0), Some(0));
        let (_, rule) = parse_dumbarp_rule(&msg).unwrap();
        assert_eq!(rule.fwmark, None);
        assert_eq!(rule.fwmask, None);
    }

    #[test]
    fn foreign_priority_is_ignored() {
        let src = Ipv4Addr::new(110, 13, 196, 173);
        let mut msg = rule_msg(src, 1846396077, Some(2), Some(FWMASK_EXACT));
        msg.attributes
            .retain(|a| !matches!(a, RuleAttribute::Priority(_)));
        msg.attributes.push(RuleAttribute::Priority(100));
        assert!(parse_dumbarp_rule(&msg).is_none());
    }
}
