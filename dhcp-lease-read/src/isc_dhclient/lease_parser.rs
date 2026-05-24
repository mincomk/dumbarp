use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1, multispace0, space1},
    multi::many0,
};

#[derive(Debug, Clone)]
enum LeaseStmt {
    Interface(String),
    FixedAddress(String),
    Option(String, String),
    Renew(DateTime<Utc>),
    Rebind(DateTime<Utc>),
    Expire(DateTime<Utc>),
}

#[derive(Debug, Clone, Default)]
pub struct Lease {
    pub interface: Option<String>,
    pub fixed_address: Option<String>,
    pub options: Vec<(String, String)>,
    pub renew: Option<DateTime<Utc>>,
    pub rebind: Option<DateTime<Utc>>,
    pub expire: Option<DateTime<Utc>>,
}

fn parse_string_lit(input: &str) -> IResult<&str, String> {
    let (input, _) = tag("\"")(input)?;
    let (input, content) = take_while1(|c| c != '"')(input)?;
    let (input, _) = tag("\"")(input)?;
    Ok((input, content.to_string()))
}

fn parse_interface(input: &str) -> IResult<&str, String> {
    let (input, _) = tag("interface")(input)?;
    let (input, _) = space1(input)?;
    parse_string_lit(input)
}

fn parse_fixed_address(input: &str) -> IResult<&str, String> {
    let (input, _) = tag("fixed-address")(input)?;
    let (input, _) = space1(input)?;
    let (input, ip) = take_while1(|c: char| c.is_alphanumeric() || c == '.')(input)?;
    Ok((input, ip.to_string()))
}

fn parse_option(input: &str) -> IResult<&str, (String, String)> {
    let (input, _) = tag("option")(input)?;
    let (input, _) = space1(input)?;
    let (input, key) = take_while1(|c: char| c.is_alphanumeric() || c == '-')(input)?;
    let (input, _) = space1(input)?;
    let (input, value) = if let Ok((input, val)) = parse_string_lit(input) {
        (input, val)
    } else {
        let (input, val) = take_while1(|c: char| c != ';')(input)?;
        (input, val.trim_end().to_string())
    };
    Ok((input, (key.to_string(), value)))
}

fn parse_u32(input: &str) -> IResult<&str, u32> {
    let (input, digits) = digit1(input)?;
    let n = digits.parse::<u32>().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Digit))
    })?;
    Ok((input, n))
}

fn parse_datetime(input: &str) -> IResult<&str, DateTime<Utc>> {
    // `<weekday> YYYY/MM/DD HH:MM:SS` — weekday is ignored, time is UTC per dhclient.leases(5)
    let (input, _weekday) = parse_u32(input)?;
    let (input, _) = space1(input)?;
    let (input, year) = parse_u32(input)?;
    let (input, _) = char('/')(input)?;
    let (input, month) = parse_u32(input)?;
    let (input, _) = char('/')(input)?;
    let (input, day) = parse_u32(input)?;
    let (input, _) = space1(input)?;
    let (input, hour) = parse_u32(input)?;
    let (input, _) = char(':')(input)?;
    let (input, minute) = parse_u32(input)?;
    let (input, _) = char(':')(input)?;
    let (input, second) = parse_u32(input)?;

    let date = NaiveDate::from_ymd_opt(year as i32, month, day)
        .and_then(|d| d.and_hms_opt(hour, minute, second))
        .ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
    Ok((input, Utc.from_utc_datetime(&date)))
}

fn parse_renew(input: &str) -> IResult<&str, DateTime<Utc>> {
    let (input, _) = tag("renew")(input)?;
    let (input, _) = space1(input)?;
    parse_datetime(input)
}

fn parse_rebind(input: &str) -> IResult<&str, DateTime<Utc>> {
    let (input, _) = tag("rebind")(input)?;
    let (input, _) = space1(input)?;
    parse_datetime(input)
}

fn parse_expire(input: &str) -> IResult<&str, DateTime<Utc>> {
    let (input, _) = tag("expire")(input)?;
    let (input, _) = space1(input)?;
    parse_datetime(input)
}

fn parse_stmt(input: &str) -> IResult<&str, LeaseStmt> {
    let (input, _) = multispace0(input)?;
    let (input, stmt) = alt((
        |i| parse_interface(i).map(|(i, v)| (i, LeaseStmt::Interface(v))),
        |i| parse_fixed_address(i).map(|(i, v)| (i, LeaseStmt::FixedAddress(v))),
        |i| parse_option(i).map(|(i, (k, v))| (i, LeaseStmt::Option(k, v))),
        |i| parse_renew(i).map(|(i, v)| (i, LeaseStmt::Renew(v))),
        |i| parse_rebind(i).map(|(i, v)| (i, LeaseStmt::Rebind(v))),
        |i| parse_expire(i).map(|(i, v)| (i, LeaseStmt::Expire(v))),
    ))
    .parse(input)?;
    let (input, _) = char(';')(input)?;
    Ok((input, stmt))
}

fn parse_lease(input: &str) -> IResult<&str, Lease> {
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("lease")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('{')(input)?;
    let (input, stmts) = many0(parse_stmt).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('}')(input)?;

    let mut lease = Lease::default();
    for stmt in stmts {
        match stmt {
            LeaseStmt::Interface(v) => lease.interface = Some(v),
            LeaseStmt::FixedAddress(v) => lease.fixed_address = Some(v),
            LeaseStmt::Option(k, v) => lease.options.push((k, v)),
            LeaseStmt::Renew(v) => lease.renew = Some(v),
            LeaseStmt::Rebind(v) => lease.rebind = Some(v),
            LeaseStmt::Expire(v) => lease.expire = Some(v),
        }
    }
    Ok((input, lease))
}

pub fn parse_leases(input: &str) -> IResult<&str, Vec<Lease>> {
    let (input, leases) = many0(parse_lease).parse(input)?;
    let (input, _) = multispace0(input)?;
    Ok((input, leases))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"lease {
  interface "wan0";
  fixed-address 192.168.1.104;
  option subnet-mask 255.255.255.0;
  option dhcp-lease-time 43200;
  option routers 192.168.1.1;
  option dhcp-message-type 5;
  option dhcp-server-identifier 192.168.1.1;
  option domain-name-servers 192.168.1.1;
  option dhcp-renewal-time 21600;
  option dhcp-rebinding-time 37800;
  option broadcast-address 192.168.1.255;
  option host-name "zako";
  option domain-name "lan";
  renew 0 2026/05/24 14:49:33;
  rebind 0 2026/05/24 20:21:15;
  expire 0 2026/05/24 21:51:15;
}
lease {
  interface "wan0";
  fixed-address 192.168.1.104;
  option subnet-mask 255.255.255.0;
  option routers 192.168.1.1;
  option dhcp-lease-time 43200;
  option dhcp-message-type 5;
  option domain-name-servers 192.168.1.1;
  option dhcp-server-identifier 192.168.1.1;
  option dhcp-renewal-time 21600;
  option broadcast-address 192.168.1.255;
  option dhcp-rebinding-time 37800;
  option host-name "zako";
  option domain-name "lan";
  renew 0 2026/05/24 16:04:01;
  rebind 0 2026/05/24 21:36:18;
  expire 0 2026/05/24 23:06:18;
}
"#;

    #[test]
    fn parses_sample_leases() {
        let (rest, leases) = parse_leases(SAMPLE).unwrap();
        assert!(rest.trim().is_empty(), "unparsed remainder: {rest:?}");
        assert_eq!(leases.len(), 2);

        let first = &leases[0];
        assert_eq!(first.interface.as_deref(), Some("wan0"));
        assert_eq!(first.fixed_address.as_deref(), Some("192.168.1.104"));
        assert_eq!(first.options.len(), 11);
        assert_eq!(
            first.options[0],
            ("subnet-mask".to_string(), "255.255.255.0".to_string())
        );
        assert_eq!(
            first.options[9],
            ("host-name".to_string(), "zako".to_string())
        );
        assert_eq!(
            first.options[10],
            ("domain-name".to_string(), "lan".to_string())
        );
        assert_eq!(
            first.expire,
            Some(Utc.with_ymd_and_hms(2026, 5, 24, 21, 51, 15).unwrap())
        );

        assert_eq!(
            leases[1].renew,
            Some(Utc.with_ymd_and_hms(2026, 5, 24, 16, 4, 1).unwrap())
        );
    }
}
