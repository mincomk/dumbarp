use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use dumbarp_api::{DaemonEntryView, DaemonsResponse};

use crate::config::Config;
use crate::reconcile::GatewayState;

#[derive(Clone)]
pub struct ServeState {
    pub cfg: Arc<Config>,
    pub state: Arc<GatewayState>,
    pub auth_token: Arc<str>,
}

pub fn router(state: ServeState) -> Router {
    let protected = Router::new()
        .route("/daemons", get(daemons_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer));

    Router::new()
        .route("/healthz", get(healthz_handler))
        .merge(protected)
        .with_state(state)
}

async fn daemons_handler(State(state): State<ServeState>) -> Json<DaemonsResponse> {
    let view = state.state.snapshot().await;

    let daemons = state
        .cfg
        .daemons
        .iter()
        .filter_map(|d| {
            let leases = view.get(&d.name)?;
            Some(DaemonEntryView {
                name: d.name.clone(),
                nexthop: d.nexthop.to_string(),
                device: d.device.clone(),
                dumbarpd_id: leases.dumbarpd_id,
                ips: leases.ips.iter().map(|ip| ip.to_string()).collect(),
            })
        })
        .collect();

    Json(DaemonsResponse { daemons })
}

async fn healthz_handler() -> &'static str {
    "ok"
}

async fn auth_layer(
    State(state): State<ServeState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return unauthorized();
    };
    let Ok(value) = value.to_str() else {
        return unauthorized();
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return unauthorized();
    };
    if !constant_time_eq(token.as_bytes(), state.auth_token.as_bytes()) {
        return unauthorized();
    }
    next.run(request).await
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
