//! The `snapshots` query parameter on `loadTable`.
//!
//! # Why a table load is allowed to omit snapshots
//!
//! Table metadata carries every snapshot the table has ever kept. On a table
//! written continuously that is the overwhelming majority of the document —
//! tens of thousands of entries, most of them expired and reachable from
//! nothing.
//!
//! A client that only needs to *plan a query* needs the snapshots its branches
//! and tags point at, and nothing else. So the spec lets it say so:
//!
//! ```text
//! GET …/tables/events?snapshots=refs   → only snapshots a ref points at
//! GET …/tables/events?snapshots=all    → every snapshot (the default)
//! ```
//!
//! The saving is not marginal. A table with 50 000 snapshots and a `main`
//! branch plus two tags returns three, and the response drops from megabytes to
//! kilobytes — on the hottest call in the API.
//!
//! # Why `all` is still the default
//!
//! Omitting the parameter must keep meaning what it has always meant. A client
//! that never learned about this parameter is asking for the whole document,
//! and time-travel and snapshot expiry both need history that no ref points at.
//! Pruning by default would silently break them.

use iceberg::spec::TableMetadata;
use serde::Deserialize;

use crate::error::{AppError, Result};

/// How much snapshot history a `loadTable` response should carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapshotScope {
    /// Every snapshot the table retains. The default, and what a client that
    /// omits the parameter has always received.
    #[default]
    All,
    /// Only snapshots reachable from a branch or tag.
    Refs,
}

impl SnapshotScope {
    /// The spelling used on the wire, also folded into the entity tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotScope::All => "all",
            SnapshotScope::Refs => "refs",
        }
    }
}

/// The `snapshots` query parameter, as the spec spells it.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SnapshotsQuery {
    /// `all` or `refs`; absent means [`SnapshotScope::All`].
    pub snapshots: Option<String>,
}

impl SnapshotsQuery {
    /// Resolves the requested scope.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::BadRequest`] for a value that is neither `all` nor
    /// `refs`. An unrecognised value is not quietly treated as `all`: a client
    /// asking for a scope this server does not implement would receive the full
    /// document while believing it had asked for less, and would size its own
    /// buffers accordingly.
    pub fn scope(&self) -> Result<SnapshotScope> {
        match self.snapshots.as_deref() {
            None => Ok(SnapshotScope::All),
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "all" => Ok(SnapshotScope::All),
                "refs" => Ok(SnapshotScope::Refs),
                other => Err(AppError::BadRequest(format!(
                    "Unsupported value '{other}' for the 'snapshots' parameter. \
                     Use 'all' (every snapshot) or 'refs' (only snapshots a branch or tag \
                     points at)."
                ))),
            },
        }
    }
}

/// Returns `metadata` carrying only the snapshots `scope` asks for.
///
/// [`SnapshotScope::All`] hands the metadata back untouched — the common path,
/// and it must not pay for a rebuild it does not need.
///
/// # Errors
///
/// Propagates a metadata build failure, which would mean the pruned document
/// failed its own invariants.
pub fn apply_scope(metadata: TableMetadata, scope: SnapshotScope) -> Result<TableMetadata> {
    if scope == SnapshotScope::All {
        return Ok(metadata);
    }

    // Snapshots a ref points at are the ones to keep; everything else goes.
    // Computed as the complement because the builder removes by id.
    let referenced = referenced_snapshot_ids(&metadata)?;

    let unreferenced: Vec<i64> = metadata
        .snapshots()
        .map(|s| s.snapshot_id())
        .filter(|id| !referenced.contains(id))
        .collect();

    if unreferenced.is_empty() {
        return Ok(metadata);
    }

    // `into_builder` wants the location the metadata was read from; `None` is
    // correct here because nothing is being committed — this is a projection for
    // one response, and it is never written back.
    let pruned = metadata
        .into_builder(None)
        .remove_snapshots(&unreferenced)
        .build()
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to prune unreferenced snapshots from table metadata: {e}"
            ))
        })?
        .metadata;

    Ok(pruned)
}

/// Snapshot ids that a branch or tag points at.
///
/// Read out of the serialized form because `TableMetadata` keeps its `refs` map
/// private and exposes only `snapshot_for_ref(name)`, which needs the names this
/// is trying to discover. `current_snapshot()` is not a substitute: it is the
/// head of `main` alone, so relying on it would silently drop every tag and
/// every other branch — the snapshots a client asking for `refs` most needs.
///
/// The extra serialization is paid only when `snapshots=refs` was requested,
/// which is exactly the request that goes on to save far more than it costs.
fn referenced_snapshot_ids(metadata: &TableMetadata) -> Result<std::collections::HashSet<i64>> {
    let value = serde_json::to_value(metadata)
        .map_err(|e| AppError::Internal(format!("Failed to inspect table metadata refs: {e}")))?;

    Ok(value
        .get("refs")
        .and_then(|refs| refs.as_object())
        .map(|refs| {
            refs.values()
                .filter_map(|r| r.get("snapshot-id").and_then(serde_json::Value::as_i64))
                .collect()
        })
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(value: Option<&str>) -> SnapshotsQuery {
        SnapshotsQuery {
            snapshots: value.map(str::to_string),
        }
    }

    /// A client that never learned about this parameter must keep getting the
    /// whole document.
    #[test]
    fn omitting_the_parameter_means_all() {
        assert_eq!(query(None).scope().unwrap(), SnapshotScope::All);
    }

    #[test]
    fn both_documented_values_parse() {
        assert_eq!(query(Some("all")).scope().unwrap(), SnapshotScope::All);
        assert_eq!(query(Some("refs")).scope().unwrap(), SnapshotScope::Refs);
    }

    #[test]
    fn parsing_is_case_and_whitespace_insensitive() {
        assert_eq!(query(Some("  REFS ")).scope().unwrap(), SnapshotScope::Refs);
    }

    /// Falling back to `all` would hand a client the full document while it
    /// believed it had asked for less.
    #[test]
    fn an_unknown_value_is_rejected_rather_than_defaulted() {
        let err = query(Some("some")).scope().unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert!(
            err.to_string().contains("refs"),
            "the message names the valid values"
        );
    }

    #[test]
    fn the_scope_has_a_stable_wire_spelling() {
        assert_eq!(SnapshotScope::All.as_str(), "all");
        assert_eq!(SnapshotScope::Refs.as_str(), "refs");
    }
}
