//! Rustberg's own administration API, served under `/management/v1`.
//!
//! Kept apart from `/v1` because that namespace is the Iceberg REST API and
//! `GET /v1/config` claims to describe it completely. Administration is not part
//! of that contract, and mixing the two would either advertise paths no Iceberg
//! client can interpret or leave undocumented routes inside a namespace that
//! says it has none.

pub mod policies;

use axum::Router;
use axum::routing::{get, post};

use crate::app::AppState;

/// Builds the management routes.
pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/policies",
            get(policies::get_policies).put(policies::update_policies),
        )
        .route("/v1/policies/history", get(policies::policy_history))
        .route("/v1/policies/rollback", post(policies::rollback_policies))
        .with_state(app_state)
}
