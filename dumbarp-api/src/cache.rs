use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::Leases;

#[derive(Default)]
pub struct LeaseCache {
    cached: Mutex<HashMap<String, CachedEntry>>,
}

struct CachedEntry {
    leases: Leases,
    last_success: Instant,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RoundStats {
    pub fetched_ok: usize,
    pub used_cache: usize,
    pub dropped: usize,
}

impl LeaseCache {
    pub async fn apply_round<I>(
        &self,
        results: I,
        stale_after: Duration,
    ) -> (RoundStats, HashMap<String, Leases>)
    where
        I: IntoIterator<Item = (String, anyhow::Result<Leases>)>,
    {
        let now = Instant::now();
        let mut stats = RoundStats::default();
        let mut cached = self.cached.lock().await;

        for (name, result) in results {
            match result {
                Ok(leases) => {
                    tracing::debug!(daemon = %name, count = leases.ips.len(), "fetched");
                    cached.insert(
                        name,
                        CachedEntry {
                            leases,
                            last_success: now,
                        },
                    );
                    stats.fetched_ok += 1;
                }
                Err(err) => match cached.get(&name) {
                    Some(entry) if now.duration_since(entry.last_success) < stale_after => {
                        tracing::warn!(daemon = %name, %err, "fetch failed; using cached IPs");
                        stats.used_cache += 1;
                    }
                    _ => {
                        tracing::warn!(daemon = %name, %err, "fetch failed; no fresh cache, dropping");
                        cached.remove(&name);
                        stats.dropped += 1;
                    }
                },
            }
        }

        let view = cached
            .iter()
            .map(|(name, entry)| (name.clone(), entry.leases.clone()))
            .collect();
        (stats, view)
    }
}
