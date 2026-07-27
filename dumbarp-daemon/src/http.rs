use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use dumbarp_api::LeasesResponse;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/leases", get(leases_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer));

    Router::new()
        .route("/healthz", get(healthz_handler))
        .merge(protected)
        .with_state(state)
}

async fn leases_handler(State(state): State<AppState>) -> Json<LeasesResponse> {
    let ips = state
        .current_ips()
        .await
        .into_iter()
        .map(|ip| ip.to_string())
        .collect();
    Json(LeasesResponse {
        ips,
        dumbarpd_id: state.dumbarpd_id,
    })
}

async fn healthz_handler() -> &'static str {
    "ok"
}

async fn auth_layer(
    State(state): State<AppState>,
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
