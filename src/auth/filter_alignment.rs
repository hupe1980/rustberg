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
//! # Why this fires at table load
//!
//! Rustberg *does* apply row filters — a scan plan is built from the client's
//! filter conjoined with what policy permits, and the residual on every task
//! carries both halves. But a plan is advice to a cooperating engine. What makes
//! a filter architectural is that the files it excludes are never named, and
//! that only happens when the boundary is partition-aligned.
//!
//! So the warning fires where the filter and the partition spec are both in
//! hand, names the table and the columns, and says which of the two kinds of
//! enforcement this deployment actually has.
//!
//! # On reading columns out of a filter
//!
//! A row filter is an Iceberg JSON predicate, so
//! [`crate::predicate::referenced_columns`] reads the columns **exactly**: the
//! grammar says where a column reference can appear, and nothing has to be
//! guessed. That is what a filter written as JSON buys over one written as an
//! opaque SQL string, where an identifier scan would have to over-report.
//!
//! # Case is compared exactly, on both sides
//!
//! Iceberg binds column names case-sensitively by default, and so does the
//! planner here. Folding either side to lowercase would make a filter on
//! `region` look aligned with a partition source called `Region` — the dangerous
//! direction, reporting architectural enforcement for a filter the binder will
//! not bind at all.

use std::collections::BTreeSet;

use iceberg::spec::{TableMetadata, Transform};

/// Column names a filter references.
///
/// Delegates to [`crate::predicate::referenced_columns`]: one grammar, read one
/// way, so the columns this warns about are exactly the columns the planner
/// prunes on.
pub fn referenced_columns(filter: &serde_json::Value) -> BTreeSet<String> {
    crate::predicate::referenced_columns(filter)
}

/// Columns a filter can be enforced on by withholding files.
///
/// **Identity transforms only.** Every other transform is lossy — `days(ts)`
/// puts a whole day in one file, `bucket(16, id)` a sixteenth of all ids — so a
/// filter on the source column selects files whose other rows are forbidden, and
/// the file still has to be delivered with the predicate attached. Counting
/// those as aligned reports cooperative enforcement as architectural, which is
/// the confusion this module exists to prevent.
///
/// Conservative rather than exact: `ts >= '2024-01-01' AND ts < '2024-01-02'`
/// against `days(ts)` *is* enforceable and is reported as unaligned anyway,
/// because deciding that needs a predicate model over transforms `iceberg-rust`
/// does not carry. The error runs in the safe direction.
///
/// **Source names, and full ones.** A spec may name an identity field `reg`
/// while the filter says `region`, so the source column is what is compared —
/// via `Schema::name_by_field_id`, which gives the dotted path. `NestedField::
/// name` is the leaf only, and would match a partition on `user.region` against
/// an unrelated top-level `region` while missing the filter that named it.
pub fn partition_source_columns(metadata: &TableMetadata) -> BTreeSet<String> {
    let schema = metadata.current_schema();

    metadata
        .default_partition_spec()
        .fields()
        .iter()
        .filter(|field| field.transform == Transform::Identity)
        .filter_map(|field| schema.name_by_field_id(field.source_id))
        .map(str::to_string)
        .collect()
}

/// Every column any partition spec the table has ever had puts in a file's
/// partition tuple, whatever the transform.
///
/// Three deliberate differences from [`partition_source_columns`], because the
/// two answer opposite questions. That one asks *what can a filter be enforced
/// on*, so it is narrow: only an identity transform separates rows by value, and
/// only the spec new files are written under matters for a filter about the
/// future.
///
/// This one asks *what does a plan disclose*, so it is wide:
///
/// - **Every transform counts.** `bucket(16, id)` is a lossy function of `id`,
///   but a tuple carrying bucket 7 still narrows `id` to a sixteenth of its
///   range, and `days(ts)` names the day. A mask over the source column is not
///   honoured by publishing a function of it.
/// - **Every spec counts, not just the default.** A snapshot holds files written
///   under specs the table has since evolved away from, and each of those files
///   carries the tuple of the spec it was written under.
/// - **A source id with no name in the current schema still counts**, under the
///   id, since a plan for those files discloses the value either way.
pub fn all_partition_source_columns(metadata: &TableMetadata) -> BTreeSet<String> {
    let schema = metadata.current_schema();

    metadata
        .partition_specs_iter()
        .flat_map(|spec| spec.fields())
        .map(|field| {
            schema
                .name_by_field_id(field.source_id)
                .map_or_else(|| format!("#{}", field.source_id), str::to_string)
        })
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

    // A local cache key, not a namespace path — the same byte for the same
    // reason (neither field can contain one), and deliberately not
    // `names::PART_SEPARATOR`, which answers a different question.
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
        "Row filter references columns this table does not partition on by identity, so \
         it cannot be enforced by withholding files — a transformed partition puts \
         permitted and forbidden rows in the same file. A scan plan applies the filter \
         and returns it as the residual, so a cooperating engine honours it, but an \
         engine using its own storage credentials reads the table unfiltered. Partition \
         on the security boundary to make this enforcement architectural."
    );
}

#[cfg(test)]
mod alignment_tests {
    use super::*;
    use iceberg::spec::{
        NestedField, PrimitiveType, Schema, SortOrder, TableMetadataBuilder, Transform, Type,
        UnboundPartitionSpec,
    };
    use serde_json::json;

    /// Table metadata partitioned on `region` with an identity transform, and
    /// `email` left unpartitioned.
    fn metadata(partition_on: Option<&str>) -> TableMetadata {
        metadata_with(partition_on, Transform::Identity)
    }

    /// The same, with the partition transform named explicitly.
    fn metadata_with(partition_on: Option<&str>, transform: Transform) -> TableMetadata {
        let schema = Schema::builder()
            .with_fields(vec![
                NestedField::required(1, "region", Type::Primitive(PrimitiveType::String)).into(),
                NestedField::optional(2, "email", Type::Primitive(PrimitiveType::String)).into(),
                NestedField::optional(3, "ts", Type::Primitive(PrimitiveType::Timestamp)).into(),
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
                    .add_partition_field(source_id, format!("{name}_p"), transform)
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

    /// A lossy transform puts permitted and forbidden rows in the same file, so
    /// withholding files does not withhold rows and the enforcement is
    /// cooperative — which is exactly what the warning has to say.
    #[test]
    fn a_transformed_partition_is_not_an_enforcement_boundary() {
        for (column, transform) in [
            ("region", Transform::Bucket(16)),
            ("region", Transform::Truncate(4)),
            ("region", Transform::Void),
            ("ts", Transform::Day),
            ("ts", Transform::Hour),
            ("ts", Transform::Month),
            ("ts", Transform::Year),
        ] {
            let metadata = metadata_with(Some(column), transform);
            assert!(
                partition_source_columns(&metadata).is_empty(),
                "{transform:?} does not separate rows by column value"
            );

            let filter = json!({ "type": "eq", "term": column, "value": "EU" });
            assert_eq!(
                unaligned_columns(&filter, &metadata)
                    .into_iter()
                    .collect::<Vec<_>>(),
                vec![column.to_string()],
                "{transform:?} must be reported as cooperative"
            );
        }
    }

    /// Table metadata partitioned on a *nested* column by identity.
    fn metadata_nested() -> TableMetadata {
        let schema = Schema::builder()
            .with_fields(vec![
                NestedField::required(
                    1,
                    "user",
                    Type::Struct(iceberg::spec::StructType::new(vec![
                        NestedField::required(2, "region", Type::Primitive(PrimitiveType::String))
                            .into(),
                    ])),
                )
                .into(),
                NestedField::optional(3, "region", Type::Primitive(PrimitiveType::String)).into(),
            ])
            .build()
            .expect("schema builds");

        let spec = UnboundPartitionSpec::builder()
            .add_partition_field(2, "user_region".to_string(), Transform::Identity)
            .expect("partition field is valid")
            .build();

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

    /// A nested partition column must be compared by its **full** name. The leaf
    /// name is what `NestedField::name` carries, and using it matches a filter on
    /// an unrelated top-level column of the same name while missing the filter
    /// that actually named the nested one.
    #[test]
    fn a_nested_partition_column_is_compared_by_its_full_name() {
        let metadata = metadata_nested();

        assert_eq!(
            partition_source_columns(&metadata)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["user.region".to_string()],
        );

        let on_nested = json!({ "type": "eq", "term": "user.region", "value": "EU" });
        assert!(
            unaligned_columns(&on_nested, &metadata).is_empty(),
            "the partitioned column is aligned"
        );

        let on_top_level = json!({ "type": "eq", "term": "region", "value": "EU" });
        assert_eq!(
            unaligned_columns(&on_top_level, &metadata)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["region".to_string()],
            "a different column that shares the leaf name is not aligned"
        );
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

    /// Case is compared exactly, on both sides.
    ///
    /// Folding either side would make a filter on `region` look aligned with a
    /// partition source spelled `Region` — the dangerous direction: the planner
    /// binds case-sensitively and would not bind that filter at all, while this
    /// reported architectural enforcement.
    #[test]
    fn a_differently_cased_column_is_not_aligned() {
        let filter = serde_json::json!({ "type": "eq", "term": "Region", "value": "EU" });
        assert_eq!(
            unaligned_columns(&filter, &metadata(Some("region")))
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["Region".to_string()],
            "a name the binder will not bind cannot be an enforcement boundary"
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
