//! The Iceberg REST Catalog v1 API.
//!
//! Handlers, plus everything that is HTTP-shaped rather than catalog-shaped:
//! path extraction, pagination, request validation, credential delegation,
//! idempotency and namespace ownership.
//!
//! Every handler follows the same shape, and [`guard`] is the reason it can:
//!
//! ```text
//!   extract & validate  →  guard::authorize  →  catalog operation  →  respond
//!   (extract, validation)  (ownership, policy,   (CatalogStore)       (+ credentials,
//!                           obligations)                               if delegated)
//! ```
//!
//! No handler resolves ownership or calls the authorizer itself. That
//! centralisation is what makes the status-code guarantee in [`guard`] hold
//! uniformly instead of per-endpoint.

pub mod delegation;
pub mod extract;
pub mod freshness;
pub mod guard;
pub mod idempotency;
mod namespace;
pub mod ownership;
pub mod pagination;
pub mod plan;
mod routes;
pub mod sign;
pub mod snapshots;
mod table;
pub mod validation;
mod view;

pub use routes::create_routes;
