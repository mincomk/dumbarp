use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_stale")]
    pub stale_after_secs: u64,
    pub hosts: Vec<HostConfig>,
}

#[derive(Debug, Deserialize)]
pub struct HostConfig {
    pub name: String,
    pub url: Url,
    pub auth_token_file: PathBuf,
}

fn default_refresh() -> u64 {
    30
}

fn default_stale() -> u64 {
    300
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in {}", path.display()))?;

        if cfg.hosts.is_empty() {
            return Err(anyhow!("config: `hosts` must list at least one daemon"));
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
        let mut seen = std::collections::HashSet::new();
        for h in &cfg.hosts {
            if h.name.is_empty() {
                return Err(anyhow!("config: every host needs a non-empty `name`"));
            }
            if !seen.insert(h.name.clone()) {
                return Err(anyhow!("config: duplicate host name `{}`", h.name));
            }
        }
        Ok(cfg)
    }
}

impl HostConfig {
    pub fn read_token(&self) -> anyhow::Result<String> {
        let raw = std::fs::read_to_string(&self.auth_token_file).with_context(|| {
            format!(
                "reading auth_token_file {} for host `{}`",
                self.auth_token_file.display(),
                self.name
            )
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(anyhow!(
                "auth_token_file {} for host `{}` is empty",
                self.auth_token_file.display(),
                self.name
            ));
        }
        Ok(trimmed.to_string())
    }
}
