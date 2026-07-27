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
        Ok(cfg)
    }
}
