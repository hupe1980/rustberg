//! Grading a served table: the I/O half of
//! [`enforcement`](crate::auth::filter_alignment::enforcement).
//!
//! The rule is pure and lives with the alignment code. What it needs from
//! storage is one fact — which partition specs the served snapshot's live files
//! were written under — and that fact is read from the snapshot's manifest list,
//! which is immutable. So it is read once per snapshot and kept, in a bounded
//! cache keyed by the table's UUID *and* the snapshot id: a key without the
//! UUID would let one table be graded by another's manifests.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use iceberg::spec::SnapshotRef;
use iceberg::table::Table;

use crate::auth::Obligations;
use crate::auth::filter_alignment::{Enforcement, enforcement};

/// The response header every `loadTable` and `planTableScan` carries.
pub const HEADER: &str = "rustberg-enforcement";

/// How many snapshots' spec ids are kept. One entry is a handful of integers,
/// so the bound is about a caller cycling snapshots, not about memory per entry.
const CACHE_ENTRIES: u64 = 1024;

type Key = (uuid::Uuid, i64);

fn cache() -> &'static moka::sync::Cache<Key, Arc<BTreeSet<i32>>> {
    static CACHE: OnceLock<moka::sync::Cache<Key, Arc<BTreeSet<i32>>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        moka::sync::Cache::builder()
            .max_capacity(CACHE_ENTRIES)
            .build()
    })
}

/// Grades `obligations` on `table` as served at `snapshot`.
///
/// Reads storage only when it can change the answer: a caller with no row
/// filter is `none` or masked-cooperative whatever the files look like.
///
/// A manifest list that cannot be read is graded against **every** spec the
/// table has ever had — the conservative reading, which may say `cooperative`
/// where the exact one would not, and never the reverse.
pub async fn grade(
    table: &Table,
    snapshot: Option<&SnapshotRef>,
    obligations: &Obligations,
) -> Enforcement {
    let metadata = table.metadata();
    if obligations.row_filters.is_empty() {
        return enforcement(metadata, obligations, None);
    }

    let Some(snapshot) = snapshot else {
        return enforcement(metadata, obligations, None);
    };

    let live = match live_spec_ids(table, snapshot).await {
        Ok(live) => live,
        Err(error) => {
            tracing::warn!(
                table = %table.identifier(),
                snapshot = snapshot.snapshot_id(),
                %error,
                "Could not read the manifest list to grade enforcement; grading against \
                 every partition spec the table has had."
            );
            Arc::new(
                metadata
                    .partition_specs_iter()
                    .map(|s| s.spec_id())
                    .collect(),
            )
        }
    };

    enforcement(metadata, obligations, Some(&live))
}

/// The partition spec ids the snapshot's live manifests were written under.
///
/// A manifest holding only deleted entries is history, not data: it is what a
/// rewrite leaves behind, and counting it would keep the grade cooperative
/// after the operator did exactly what the remedy said. A manifest whose counts
/// are unknown (allowed in format v1) counts as live.
async fn live_spec_ids(
    table: &Table,
    snapshot: &SnapshotRef,
) -> iceberg::Result<Arc<BTreeSet<i32>>> {
    let key = (table.metadata().uuid(), snapshot.snapshot_id());
    if let Some(hit) = cache().get(&key) {
        return Ok(hit);
    }

    let list = table.manifest_list_reader(snapshot).load().await?;
    let ids: Arc<BTreeSet<i32>> = Arc::new(
        list.entries()
            .iter()
            .filter(|manifest| manifest.has_added_files() || manifest.has_existing_files())
            .map(|manifest| manifest.partition_spec_id)
            .collect(),
    );
    cache().insert(key, ids.clone());
    Ok(ids)
}

/// Sets the grade on a response.
pub fn insert_header(response: &mut axum::response::Response, grade: &Enforcement) {
    if let Ok(value) = axum::http::HeaderValue::from_str(&grade.header_value()) {
        response.headers_mut().insert(HEADER, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller cycling snapshots cannot grow the cache past its bound.
    #[test]
    fn the_spec_id_cache_is_bounded() {
        let table = uuid::Uuid::new_v4();
        for snapshot in 0..(CACHE_ENTRIES as i64 * 3) {
            cache().insert((table, snapshot), Arc::new(BTreeSet::from([0])));
        }
        cache().run_pending_tasks();
        assert!(
            cache().entry_count() <= CACHE_ENTRIES,
            "{} entries",
            cache().entry_count()
        );
    }

    /// Two tables with the same snapshot id are two entries.
    #[test]
    fn the_cache_is_keyed_by_table_and_snapshot() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        cache().insert((a, 7), Arc::new(BTreeSet::from([0])));
        cache().insert((b, 7), Arc::new(BTreeSet::from([1])));
        assert_eq!(*cache().get(&(a, 7)).unwrap(), BTreeSet::from([0]));
        assert_eq!(*cache().get(&(b, 7)).unwrap(), BTreeSet::from([1]));
    }
}
