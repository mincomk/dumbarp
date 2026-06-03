use std::sync::Arc;
use std::time::Duration;

use tokio::time::{MissedTickBehavior, interval};

use dumbarp_routing::RouteManager;

use crate::state::AppState;

pub fn spawn(state: AppState, period: Duration, router: Option<Arc<RouteManager>>) {
    tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            reconcile_routing(&state, router.as_ref()).await;
        }
    });
}

async fn reconcile_routing(state: &AppState, router: Option<&Arc<RouteManager>>) {
    let Some(router) = router else {
        return;
    };
    let desired = state.current_routes().await;
    if let Err(err) = router.reconcile(&desired).await {
        tracing::error!(%err, "routing reconcile failed");
    }
}
