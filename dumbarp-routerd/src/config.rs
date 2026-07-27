use std::collections::HashSet;
use std::net::Ipv4Addr;
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
    pub dscp: DscpConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonEntry {
    pub name: String,
    pub endpoint: Url,
    pub auth_token: String,
    pub nexthop: Ipv4Addr,
    pub device: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DscpConfig {
    pub ifaces: Vec<String>,
    #[serde(default = "default_max_flows")]
    pub max_flows: u32,
}

fn default_refresh() -> u64 {
    30
}

fn default_stale() -> u64 {
    300
}

fn default_max_flows() -> u32 {
    65536
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.daemons.is_empty() {
            return Err(anyhow!("config: `daemons` must list at least one entry"));
        }
        if self.refresh_interval_secs == 0 {
            return Err(anyhow!("config: `refresh_interval_secs` must be > 0"));
        }
        if self.stale_after_secs < self.refresh_interval_secs {
            return Err(anyhow!(
                "config: `stale_after_secs` ({}) must be >= `refresh_interval_secs` ({})",
                self.stale_after_secs,
                self.refresh_interval_secs
            ));
        }
        if self.dscp.ifaces.is_empty() {
            return Err(anyhow!(
                "config: `[dscp].ifaces` must list at least one interface"
            ));
        }
        if self.dscp.max_flows == 0 {
            return Err(anyhow!("config: `[dscp].max_flows` must be > 0"));
        }

        let mut seen: HashSet<&str> = HashSet::new();
        for d in &self.daemons {
            if d.name.is_empty() {
                return Err(anyhow!("config: every daemon needs a non-empty `name`"));
            }
            if d.device.is_empty() {
                return Err(anyhow!("config: daemon `{}` has empty `device`", d.name));
            }
            if d.auth_token.is_empty() {
                return Err(anyhow!("config: daemon `{}` has empty `auth_token`", d.name));
            }
            if !seen.insert(d.name.as_str()) {
                return Err(anyhow!("config: duplicate daemon name `{}`", d.name));
            }
        }
        Ok(())
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

    fn load_str(raw: &str) -> anyhow::Result<Config> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);

        let dir = std::env::temp_dir().join(format!("dumbarp-routerd-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("c{}.toml", SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, raw).unwrap();
        let out = Config::load(&path);
        let _ = std::fs::remove_file(&path);
        out
    }

    #[test]
    fn accepts_minimal_config() {
        let cfg = load_str(&format!("{BASE}\n[dscp]\nifaces = [\"eth1\"]\n")).unwrap();
        assert_eq!(cfg.dscp.ifaces, vec!["eth1".to_string()]);
        assert_eq!(cfg.dscp.max_flows, 65536);
        assert_eq!(cfg.refresh_interval_secs, 30);
    }

    #[test]
    fn rejects_empty_dscp_ifaces() {
        assert!(load_str(&format!("{BASE}\n[dscp]\nifaces = []\n")).is_err());
    }

    #[test]
    fn rejects_missing_dscp_section() {
        assert!(load_str(BASE).is_err());
    }

    #[test]
    fn rejects_stale_shorter_than_refresh() {
        let raw = format!(
            "refresh_interval_secs = 60\nstale_after_secs = 30\n{BASE}\n[dscp]\nifaces = [\"eth1\"]\n"
        );
        assert!(load_str(&raw).is_err());
    }

    #[test]
    fn rejects_duplicate_daemon_names() {
        let raw = format!("{BASE}{BASE}\n[dscp]\nifaces = [\"eth1\"]\n");
        assert!(load_str(&raw).is_err());
    }
}
