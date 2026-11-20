//! The Iceberg REST Catalog v1 API.
//!
//! Handlers, plus everything that is HTTP-shaped rather than catalog-shaped:
//! path extraction, pagination, credential delegation, idempotency and namespace
//! ownership.
//!
//! What a *name* may be is not here: it is [`crate::names`], because the rule
//! has callers on both sides of the request — the resources a client asks for,
//! and the tenant a token asserts, which is the first segment of the same Cedar
//! entity id.
//!
//! Every handler follows the same shape, and [`guard`] is the reason it can:
//!
//! ```text
//!   extract & validate  →  guard::authorize  →  catalog operation  →  respond
//!   (extract, names)       (ownership, policy,   (CatalogStore)       (+ credentials,
//!                           obligations)                               if delegated)
//! ```
//!
//! No handler resolves ownership or calls the authorizer itself. That
//! centralisation is what makes the status-code guarantee in [`guard`] hold
//! uniformly instead of per-endpoint.

pub mod delegation;
pub mod enforcement;
pub mod extract;
pub mod freshness;
pub mod guard;
pub mod idempotency;
mod namespace;
pub mod ownership;
pub mod pagination;
pub mod plan;
pub mod restrictions;
mod routes;
pub mod sign;
pub mod snapshots;
mod table;
mod view;

pub use routes::create_routes;

/// Serializes table or view metadata with its lists in a stable order.
///
/// iceberg-rust keeps snapshots and view versions in hash maps, so two loads of
/// the same table could list them in different orders — and clients compare
/// these lists. Snapshots are ordered by sequence number, then timestamp; view
/// versions by version id; their logs by timestamp.
pub(crate) fn ordered_metadata<T: serde::Serialize, S: serde::Serializer>(
    metadata: &T,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::Serialize as _;
    let mut value = serde_json::to_value(metadata).map_err(serde::ser::Error::custom)?;
    let sort_by = |value: &mut serde_json::Value, field: &str, keys: &[&str]| {
        if let Some(list) = value
            .get_mut(field)
            .and_then(serde_json::Value::as_array_mut)
        {
            list.sort_by_key(|item| {
                keys.iter()
                    .map(|k| {
                        item.get(*k)
                            .and_then(serde_json::Value::as_i64)
                            .unwrap_or(i64::MAX)
                    })
                    .collect::<Vec<_>>()
            });
        }
    };
    sort_by(
        &mut value,
        "snapshots",
        &["sequence-number", "timestamp-ms", "snapshot-id"],
    );
    sort_by(&mut value, "snapshot-log", &["timestamp-ms"]);
    sort_by(&mut value, "metadata-log", &["timestamp-ms"]);
    sort_by(&mut value, "versions", &["version-id"]);
    sort_by(&mut value, "version-log", &["timestamp-ms"]);
    value.serialize(serializer)
}
