mod catalog_ext;
mod encrypted_catalog;
mod extract;
pub mod idempotency;
pub mod idempotency_store;
pub mod pagination;
#[cfg(feature = "slatedb-storage")]
mod slate_catalog;
mod v1;
pub mod validation;
mod view_store;

use axum::Router;

pub use catalog_ext::{CatalogExt, ExtendedCatalog, StorageHealthStatus};
pub use encrypted_catalog::EncryptedCatalog;
pub use idempotency::{IdempotencyCache, DEFAULT_TTL};
// Idempotency store exports
#[cfg(feature = "slatedb-storage")]
pub use idempotency_store::SlateDbIdempotencyStore;
pub use idempotency_store::{IdempotencyEntry, IdempotencyStore, MemoryIdempotencyStore};
#[cfg(feature = "slatedb-storage")]
pub use slate_catalog::{IoTimeoutConfig, SlateCatalog};
// View storage exports
#[cfg(feature = "slatedb-storage")]
pub use view_store::SlateDbViewStore;
pub use view_store::{MemoryViewStore, ViewStorage, ViewStore};

use crate::app::AppState;

pub fn create_routes(app_state: AppState) -> Router {
    let v1_routes = v1::create_routes(app_state.clone());

    Router::new().nest("/v1", v1_routes)
}
