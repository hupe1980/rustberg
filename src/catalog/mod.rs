mod catalog_ext;
mod encrypted_catalog;
mod extract;
pub mod idempotency;
pub mod pagination;
#[cfg(feature = "slatedb-storage")]
mod slate_catalog;
mod v1;
pub mod validation;

use axum::Router;

pub use catalog_ext::{CatalogExt, ExtendedCatalog};
pub use encrypted_catalog::EncryptedCatalog;
pub use idempotency::{IdempotencyCache, DEFAULT_TTL};
#[cfg(feature = "slatedb-storage")]
pub use slate_catalog::SlateCatalog;
pub use v1::ViewStorage;

use crate::app::AppState;

pub fn create_routes(app_state: AppState) -> Router {
    let v1_routes = v1::create_routes(app_state.clone());

    Router::new().nest("/v1", v1_routes)
}
