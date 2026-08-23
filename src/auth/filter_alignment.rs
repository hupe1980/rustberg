//! Detecting the moment a row filter stops being enforceable.
//!
//! # The distinction this exists to surface
//!
//! A catalog enforces a row filter by *not handing over files*. That works
//! exactly when the filter's columns are partition columns: if `tenant_id` is a
//! partition field, the files holding another tenant's rows are a different set
//! of files, and withholding them is real enforcement that holds against any
//! engine, hostile or not.
//!
//! When the filter references a non-partition column, permitted and forbidden
//! rows share Parquet row groups. No file-level decision can separate them, and
//! the best any catalog can do is deliver the file and a residual predicate —
//! at which point enforcement is **cooperative**: it holds only because the
//! engine chose to apply the predicate. AWS Lake Formation is explicit about the
//! same limit; it computes the permitted row set and the engine does the
//! filtering.
//!
//! Both look identical in the policy file. One is a security boundary and the
//! other is a request. An operator who cannot tell them apart believes they have
//! the first while running the second, so Rustberg says which it is.
//!
//! # Why this is useful before filters are enforced at all
//!
//! Rustberg does not apply row filters today — an annotated table is refused a
//! storage credential instead. That makes this warning *more* valuable, not
//! less: it tells an operator which of their filters were never going to become
//! architectural enforcement, while the policy set is still small enough to
//! change.
//!
//! # On the column extractor
//!
//! Filters are opaque predicate strings; Rustberg does not parse SQL and should
//! not pretend to. [`referenced_columns`] is a deliberately conservative
//! identifier scan: it strips string literals, then keeps bare identifiers that
//! are not keywords, numbers, or function calls. It over-reports rather than
//! under-reports, and over-reporting only ever produces a warning that names one
//! column too many — the failure that costs an operator a moment's reading,
//! rather than the one that leaves them believing a filter holds when it does
//! not.

use std::collections::BTreeSet;

use iceberg::spec::TableMetadata;

/// Column names a filter references.
///
/// Delegates to [`crate::predicate::referenced_columns`]: one grammar, read one
/// way, so the columns this warns about are exactly the columns the planner
/// prunes on.
pub fn referenced_columns(filter: &serde_json::Value) -> BTreeSet<String> {
    crate::predicate::referenced_columns(filter)
}

/// Names of the columns `metadata`'s current partition spec partitions on.
///
/// Source column names, not partition field names: a spec may partition on
/// `days(ts)` under the name `ts_day`, and a filter referencing `ts` is aligned
/// with it. Comparing partition *field* names would call that misaligned and
/// warn about a filter that is in fact enforceable.
pub fn partition_source_columns(metadata: &TableMetadata) -> BTreeSet<String> {
    let schema = metadata.current_schema();

    metadata
        .default_partition_spec()
        .fields()
        .iter()
        .filter_map(|field| schema.field_by_id(field.source_id))
        .map(|field| field.name.to_ascii_lowercase())
        .collect()
}

/// Columns a filter references that the table does not partition on.
///
/// Empty means the filter is partition-aligned, and withholding files would be
/// real enforcement. Non-empty names the columns that make it cooperative.
pub fn unaligned_columns(filter: &serde_json::Value, metadata: &TableMetadata) -> BTreeSet<String> {
    let partitions = partition_source_columns(metadata);
    referenced_columns(filter)
        .into_iter()
        .filter(|column| !partitions.contains(column))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cols(filter: serde_json::Value) -> Vec<String> {
        referenced_columns(&filter).into_iter().collect()
    }

    #[test]
    fn a_comparison_names_its_column() {
        assert_eq!(
            cols(json!({ "type": "eq", "term": "region", "value": "EU" })),
            vec!["region".to_string()]
        );
    }

    /// The literal is not a column, however much it looks like one.
    #[test]
    fn a_literal_is_not_a_column() {
        assert_eq!(
            cols(json!({ "type": "eq", "term": "region", "value": "team" })),
            vec!["region".to_string()]
        );
    }

    #[test]
    fn a_nested_expression_names_every_column_in_it() {
        assert_eq!(
            cols(json!({
                "type": "and",
                "left":  { "type": "not-null", "child": { "type": "reference", "name": "a" } },
                "right": { "type": "or",
                           "left":  { "type": "in", "term": "b", "values": [1, 2] },
                           "right": { "type": "not",
                                      "child": { "type": "gt", "term": "c", "value": 3 } } }
            })),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    /// A term this catalog cannot bind contributes no column — and no pruning,
    /// so reporting it as unaligned is the safe direction.
    #[test]
    fn an_unbindable_term_names_nothing() {
        assert!(
            cols(json!({
                "type": "eq",
                "term": { "type": "transform", "transform": "day", "term": "ts" },
                "value": 1
            }))
            .is_empty()
        );
    }

    #[test]
    fn a_constant_names_nothing() {
        assert!(cols(json!(true)).is_empty());
        assert!(cols(json!({ "type": "true" })).is_empty());
    }
}

// ============================================================================
// Reporting
// ============================================================================

use std::sync::OnceLock;
use std::time::Duration;

/// Tables already reported, so a hot table cannot flood the log.
///
/// Keyed by policy-set version *and* table, so editing the policies reports
/// again — the operator has changed the thing the warning is about, and
/// suppressing it then would hide the result of their edit.
///
/// Bounded and expiring: this is a diagnostic, and a diagnostic must not become
/// a memory leak on a catalog with a large number of restricted tables.
fn reported() -> &'static moka::sync::Cache<String, ()> {
    static REPORTED: OnceLock<moka::sync::Cache<String, ()>> = OnceLock::new();
    REPORTED.get_or_init(|| {
        moka::sync::Cache::builder()
            .max_capacity(4096)
            .time_to_live(Duration::from_secs(3600))
            .build()
    })
}

/// Warns, once per table per policy set, when a row filter cannot be enforced
/// by withholding files.
///
/// Called from the table load path, where the filter and the partition spec are
/// both in hand. Does nothing when there are no row filters, or when every
/// filtered column is a partition column.
pub fn warn_if_cooperative(
    row_filters: &[serde_json::Value],
    metadata: &TableMetadata,
    table: &str,
    policy_set_version: Option<&str>,
) {
    if row_filters.is_empty() {
        return;
    }

    let unaligned: BTreeSet<String> = row_filters
        .iter()
        .flat_map(|filter| unaligned_columns(filter, metadata))
        .collect();

    if unaligned.is_empty() {
        return;
    }

    let key = format!("{}\u{1F}{table}", policy_set_version.unwrap_or("-"));
    if reported().get(&key).is_some() {
        return;
    }
    reported().insert(key, ());

    let columns: Vec<&str> = unaligned.iter().map(String::as_str).collect();
    tracing::warn!(
        table = %table,
        columns = ?columns,
        policy_set_version = policy_set_version.unwrap_or("-"),
        "Row filter references non-partition columns, so it cannot be enforced by \
         withholding files. A scan plan applies it and returns it as the residual, so a \
         cooperating engine honours it — but an engine using its own storage credentials \
         reads the table unfiltered. Partition on the security boundary to make this \
         enforcement architectural."
    );
}

#[cfg(test)]
mod alignment_tests {
    use super::*;
    use iceberg::spec::{
        NestedField, PrimitiveType, Schema, SortOrder, TableMetadataBuilder, Transform, Type,
        UnboundPartitionSpec,
    };

    /// Table metadata partitioned on `region`, with `email` left unpartitioned.
    fn metadata(partition_on: Option<&str>) -> TableMetadata {
        let schema = Schema::builder()
            .with_fields(vec![
                NestedField::required(1, "region", Type::Primitive(PrimitiveType::String)).into(),
                NestedField::optional(2, "email", Type::Primitive(PrimitiveType::String)).into(),
            ])
            .build()
            .expect("schema builds");

        let spec = match partition_on {
            Some(name) => {
                let source_id = schema
                    .as_struct()
                    .fields()
                    .iter()
                    .find(|f| f.name == name)
                    .expect("partition column is in the schema")
                    .id;
                UnboundPartitionSpec::builder()
                    .add_partition_field(source_id, format!("{name}_p"), Transform::Identity)
                    .expect("partition field is valid")
                    .build()
            }
            None => UnboundPartitionSpec::builder().build(),
        };

        TableMetadataBuilder::new(
            schema,
            spec,
            SortOrder::unsorted_order(),
            "memory://wh/db/t".to_string(),
            iceberg::spec::FormatVersion::V2,
            std::collections::HashMap::new(),
        )
        .expect("metadata builds")
        .build()
        .expect("metadata builds")
        .metadata
    }

    /// The source column is what matters, not the partition field's name: a
    /// spec may name the field `region_p` while the filter says `region`.
    #[test]
    fn partition_columns_are_source_names() {
        let columns = partition_source_columns(&metadata(Some("region")));
        assert!(
            columns.contains("region"),
            "expected the source column name, got {columns:?}"
        );
    }

    /// A filter over a partition column *is* enforceable by withholding files,
    /// so nothing is reported.
    #[test]
    fn a_partition_aligned_filter_reports_nothing() {
        let filter = serde_json::json!({ "type": "eq", "term": "region", "value": "EU" });
        assert!(unaligned_columns(&filter, &metadata(Some("region"))).is_empty());
    }

    /// The case worth warning about: permitted and forbidden rows share files,
    /// so no file-level decision separates them.
    #[test]
    fn a_filter_on_a_non_partition_column_is_reported() {
        let filter = serde_json::json!({ "type": "eq", "term": "email", "value": "a@b.c" });
        let unaligned = unaligned_columns(&filter, &metadata(Some("region")));
        assert_eq!(
            unaligned.into_iter().collect::<Vec<_>>(),
            vec!["email".to_string()]
        );
    }

    /// A mixed filter is only as strong as its weakest column.
    #[test]
    fn a_mixed_filter_reports_only_the_unaligned_column() {
        let filter = serde_json::json!({
            "type": "and",
            "left":  { "type": "eq", "term": "region", "value": "EU" },
            "right": { "type": "eq", "term": "email", "value": "a@b.c" }
        });
        let unaligned = unaligned_columns(&filter, &metadata(Some("region")));
        assert_eq!(
            unaligned.into_iter().collect::<Vec<_>>(),
            vec!["email".to_string()],
            "the partition column is fine; only the other one degrades enforcement"
        );
    }

    /// An unpartitioned table can enforce no filter architecturally at all.
    #[test]
    fn an_unpartitioned_table_aligns_with_nothing() {
        let filter = serde_json::json!({ "type": "eq", "term": "region", "value": "EU" });
        let unaligned = unaligned_columns(&filter, &metadata(None));
        assert_eq!(
            unaligned.into_iter().collect::<Vec<_>>(),
            vec!["region".to_string()]
        );
    }

    /// No filters means nothing to report, and no work done.
    #[test]
    fn no_filters_reports_nothing() {
        warn_if_cooperative(&[], &metadata(None), "db.t", Some("v1"));
    }
}
