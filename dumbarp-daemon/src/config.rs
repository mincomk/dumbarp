use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, anyhow};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub auth_token: String,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    pub ifaces: Vec<String>,
    #[serde(default = "default_manage_routing")]
    pub manage_routing: bool,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:1028".parse().unwrap()
}

fn default_refresh() -> u64 {
    60
}

fn default_manage_routing() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in {}", path.display()))?;

        if cfg.auth_token.is_empty() {
            return Err(anyhow!("config: `auth_token` must be non-empty"));
        }
        if cfg.ifaces.is_empty() {
            return Err(anyhow!("config: `ifaces` must list at least one interface"));
        }
        if cfg.refresh_interval_secs == 0 {
            return Err(anyhow!("config: `refresh_interval_secs` must be > 0"));
        }
        Ok(cfg)
    }
}
