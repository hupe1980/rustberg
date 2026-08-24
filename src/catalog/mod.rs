//! The Iceberg catalog: the store, and the REST surface over it.
//!
//! - [`RedbCatalog`] — the embedded catalog, a single-file ACID store
//! - `PostgresCatalog` — the clustered catalog, for multi-replica deployments
//!   (only compiled with the `catalog-postgres` feature)
//! - [`store`] — the [`CatalogStore`] trait both implement
//! - [`file_io`] — how table metadata files are read and written
//! - `v1` — the Iceberg REST v1 API and everything HTTP-shaped
//!
//! Views live in the catalog implementations rather than a side store, so a view
//! shares a transaction domain with tables: a namespace cannot be dropped while
//! it still holds views.

pub mod capabilities;
pub mod federated;
pub mod file_io;
pub mod purge;
mod redb;
mod rest;
pub mod session;
pub mod store;

#[cfg(feature = "catalog-postgres")]
mod postgres;
pub mod v1;

use axum::Router;

pub use capabilities::{Capabilities, Capability};
pub use federated::{FederatedCatalog, Mount};
pub use redb::RedbCatalog;
pub use rest::RestCatalog;
pub use session::Session;
pub use store::{
    CatalogStore, DEFAULT_PAGE_SIZE, Entry, MAX_PAGE_SIZE, Page, PageRequest, StorageHealthStatus,
    UnreachableStore,
};

#[cfg(feature = "catalog-postgres")]
pub use postgres::PostgresCatalog;
pub use v1::idempotency::{DEFAULT_TTL, IdempotencyCache};

use crate::app::AppState;

/// Builds the catalog routes.
///
/// The spec writes every path as `/v1/{prefix}/...`, where the prefix comes from
/// `overrides.prefix` in the config response and is empty when absent. Both
/// shapes are served: `/v1/...` for clients that received no prefix, and
/// `/v1/{prefix}/...` for those that did.
///
/// Rustberg serves one catalog and sends no `prefix` override, so the prefixed
/// form exists to accept clients that send one anyway — several do, hardcoded
/// from another catalog's configuration. The segment is matched and ignored
/// rather than validated: it selects nothing, so a wrong value selects nothing
/// wrongly. Axum matches a literal segment ahead of a dynamic one, so
/// `/v1/namespaces` is the namespaces collection and never a prefix named
/// `namespaces`.
pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .nest("/v1", v1::create_routes(app_state.clone()))
        .nest("/v1/{prefix}", v1::create_routes(app_state))
}
