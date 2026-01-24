use axum::{routing::get, Router};

use super::handlers::get_config;
use crate::app::AppState;

pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/config", get(get_config))
        .with_state(app_state)
}
