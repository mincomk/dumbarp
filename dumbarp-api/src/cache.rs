use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::Leases;

pub type LeaseCache = Cache<Leases>;

pub struct Cache<T> {
    cached: Mutex<HashMap<String, CachedEntry<T>>>,
}

struct CachedEntry<T> {
    value: T,
    last_success: Instant,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RoundStats {
    pub fetched_ok: usize,
    pub used_cache: usize,
    pub dropped: usize,
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            cached: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone> Cache<T> {
    pub async fn apply_round<I>(
        &self,
        results: I,
        stale_after: Duration,
    ) -> (RoundStats, HashMap<String, T>)
    where
        I: IntoIterator<Item = (String, anyhow::Result<T>)>,
    {
        let now = Instant::now();
        let mut stats = RoundStats::default();
        let mut cached = self.cached.lock().await;

        for (name, result) in results {
            match result {
                Ok(value) => {
                    tracing::debug!(source = %name, "fetched");
                    cached.insert(
                        name,
                        CachedEntry {
                            value,
                            last_success: now,
                        },
                    );
                    stats.fetched_ok += 1;
                }
                Err(err) => match cached.get(&name) {
                    Some(entry) if now.duration_since(entry.last_success) < stale_after => {
                        tracing::warn!(source = %name, %err, "fetch failed; using cached value");
                        stats.used_cache += 1;
                    }
                    _ => {
                        tracing::warn!(source = %name, %err, "fetch failed; no fresh cache, dropping");
                        cached.remove(&name);
                        stats.dropped += 1;
                    }
                },
            }
        }

        let view = cached
            .iter()
            .map(|(name, entry)| (name.clone(), entry.value.clone()))
            .collect();
        (stats, view)
    }

    pub async fn snapshot(&self) -> HashMap<String, T> {
        self.cached
            .lock()
            .await
            .iter()
            .map(|(name, entry)| (name.clone(), entry.value.clone()))
            .collect()
    }
}
