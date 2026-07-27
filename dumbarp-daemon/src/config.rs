use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, anyhow};
use dumbarp_common::DSCP_ID_MAX;
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
    #[serde(default = "default_neigh_refresh")]
    pub neigh_refresh_interval_secs: u64,
    #[serde(default)]
    pub dumbarpd_id: u8,
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

fn default_neigh_refresh() -> u64 {
    30
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
        if cfg.dumbarpd_id > DSCP_ID_MAX {
            return Err(anyhow!(
                "config: `dumbarpd_id` ({}) must be between 1 and {} (0 disables DSCP mode)",
                cfg.dumbarpd_id,
                DSCP_ID_MAX
            ));
        }
        Ok(cfg)
    }

    pub fn dscp_id(&self) -> Option<u8> {
        (self.dumbarpd_id != 0).then_some(self.dumbarpd_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(extra: &str) -> String {
        format!("auth_token = \"t\"\nifaces = [\"eth0\"]\n{extra}")
    }

    fn load_str(raw: &str) -> anyhow::Result<Config> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);

        let dir = std::env::temp_dir().join(format!("dumbarpd-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("c{}.toml", SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, raw).unwrap();
        let out = Config::load(&path);
        let _ = std::fs::remove_file(&path);
        out
    }

    #[test]
    fn dumbarpd_id_defaults_to_disabled() {
        let cfg = load_str(&base("")).unwrap();
        assert_eq!(cfg.dumbarpd_id, 0);
        assert_eq!(cfg.dscp_id(), None);
    }

    #[test]
    fn dumbarpd_id_in_range_is_accepted() {
        for id in [1u8, 7, 63] {
            let cfg = load_str(&base(&format!("dumbarpd_id = {id}"))).unwrap();
            assert_eq!(cfg.dscp_id(), Some(id));
        }
    }

    #[test]
    fn dumbarpd_id_out_of_range_is_rejected() {
        for id in [64u8, 100, 255] {
            assert!(load_str(&base(&format!("dumbarpd_id = {id}"))).is_err());
        }
    }
}
