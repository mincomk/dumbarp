use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use dumbarp::Dumbarp;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub auth_token: Arc<str>,
    pub engine: Arc<Mutex<Dumbarp>>,
    pub leases: Arc<Mutex<BTreeMap<String, Ipv4Addr>>>,
}

impl AppState {
    pub fn new(auth_token: String, engine: Dumbarp) -> Self {
        Self {
            auth_token: Arc::from(auth_token),
            engine: Arc::new(Mutex::new(engine)),
            leases: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn current_ips(&self) -> Vec<Ipv4Addr> {
        self.leases.lock().await.values().copied().collect()
    }
}
