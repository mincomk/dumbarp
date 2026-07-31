use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, anyhow};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_stale")]
    pub stale_after_secs: u64,
    #[serde(default = "default_manage_routes")]
    pub manage_routes: bool,
    pub daemons: Vec<DaemonEntry>,
    #[serde(default)]
    pub serve: Option<ServeConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServeConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub auth_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonEntry {
    pub name: String,
    pub endpoint: Url,
    pub auth_token: String,
    pub nexthop: Ipv4Addr,
    pub device: String,
}

fn default_refresh() -> u64 {
    30
}

fn default_stale() -> u64 {
    300
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:1029".parse().unwrap()
}

fn default_manage_routes() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in {}", path.display()))?;

        if cfg.daemons.is_empty() {
            return Err(anyhow!("config: `daemons` must list at least one entry"));
        }
        if cfg.refresh_interval_secs == 0 {
            return Err(anyhow!("config: `refresh_interval_secs` must be > 0"));
        }
        if cfg.stale_after_secs < cfg.refresh_interval_secs {
            return Err(anyhow!(
                "config: `stale_after_secs` ({}) must be >= `refresh_interval_secs` ({})",
                cfg.stale_after_secs,
                cfg.refresh_interval_secs
            ));
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for d in &cfg.daemons {
            if d.name.is_empty() {
                return Err(anyhow!("config: every daemon needs a non-empty `name`"));
            }
            if d.device.is_empty() {
                return Err(anyhow!(
                    "config: daemon `{}` has empty `device`",
                    d.name
                ));
            }
            if d.auth_token.is_empty() {
                return Err(anyhow!(
                    "config: daemon `{}` has empty `auth_token`",
                    d.name
                ));
            }
            if !seen.insert(d.name.as_str()) {
                return Err(anyhow!("config: duplicate daemon name `{}`", d.name));
            }
        }
        if let Some(serve) = &cfg.serve
            && serve.auth_token.is_empty()
        {
            return Err(anyhow!("config: `[serve].auth_token` must be non-empty"));
        }
        if !cfg.manage_routes && cfg.serve.is_none() {
            return Err(anyhow!(
                "config: `manage_routes = false` with no `[serve]` leaves nothing for this gateway to do"
            ));
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[[daemons]]
name = "homelab"
endpoint = "http://10.0.0.5:1028"
auth_token = "t"
nexthop = "10.0.0.5"
device = "br0"
"#;

    const SERVE: &str = r#"
[serve]
listen = "0.0.0.0:1029"
auth_token = "t"
"#;

    fn load_str(raw: &str) -> anyhow::Result<Config> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);

        let dir = std::env::temp_dir().join(format!("dumbarp-gateway-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("c{}.toml", SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, raw).unwrap();
        let out = Config::load(&path);
        let _ = std::fs::remove_file(&path);
        out
    }

    #[test]
    fn manages_routes_by_default() {
        assert!(load_str(BASE).unwrap().manage_routes);
    }

    #[test]
    fn route_management_can_be_ticked_off_alongside_serve() {
        let raw = format!("manage_routes = false\n{BASE}{SERVE}");
        let cfg = load_str(&raw).unwrap();
        assert!(!cfg.manage_routes);
        assert!(cfg.serve.is_some());
    }

    #[test]
    fn rejects_route_management_off_without_serve() {
        let raw = format!("manage_routes = false\n{BASE}");
        assert!(load_str(&raw).is_err());
    }
}
