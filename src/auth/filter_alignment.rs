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
//! carries both halves. A restricted table is pinned to server-side planning and
//! its planned files come back pre-signed, so an excluded **file** is unnamed and
//! unfetchable.
//!
//! That still leaves the rows *inside* a delivered file, and the residual
//! predicate over them is advice. What makes a filter architectural is that no
//! delivered file contains a forbidden row, and that only happens when the
//! boundary is partition-aligned.
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
pub fn referenced_columns(
    filter: &serde_json::Value,
    metadata: &TableMetadata,
) -> BTreeSet<String> {
    crate::predicate::referenced_columns(filter, metadata.current_schema())
}

/// How strongly a caller's restrictions hold on one table.
///
/// The one answer the header, the signing record, the load-time warning and the
/// administrator's what-if all read, so none of them can disagree with another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// No restriction applies to this caller on this table.
    None,
    /// Every restriction holds against any engine: each filter column is an
    /// identity partition of every spec a live file was written under, and no
    /// column is masked. A forbidden row is in no file the caller is handed.
    Architectural,
    /// The delivered files also hold what is restricted, and only a cooperating
    /// engine applying the residual and the projections withholds it.
    Cooperative {
        /// Filter columns that are not identity partitions of every live spec.
        columns: BTreeSet<String>,
        /// Whether a column mask applies — the file always holds the raw column.
        masked: bool,
    },
}

impl Enforcement {
    /// The grade's name, as the header, the audit record and the docs spell it.
    #[must_use]
    pub const fn grade(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Architectural => "architectural",
            Self::Cooperative { .. } => "cooperative",
        }
    }

    /// The `Rustberg-Enforcement` header value: an RFC 9651 structured-field
    /// Item, with the reasons as parameters —
    /// `cooperative;columns="region,ts";masked`.
    ///
    /// Column names are serialized as an sf-string when they are printable
    /// ASCII and as a Display String (`%"…"`) otherwise, so any column name a
    /// table may have produces a valid header value.
    #[must_use]
    pub fn header_value(&self) -> String {
        match self {
            Self::Cooperative { columns, masked } => {
                let mut value = String::from("cooperative");
                if !columns.is_empty() {
                    let joined = columns.iter().cloned().collect::<Vec<_>>().join(",");
                    value.push_str(";columns=");
                    value.push_str(&structured_string(&joined));
                }
                if *masked {
                    value.push_str(";masked");
                }
                value
            }
            other => other.grade().to_string(),
        }
    }

    /// What would make this grade architectural, in words an operator can act
    /// on — or `None` when there is nothing to change.
    ///
    /// Concrete on purpose: the partition evolution to run, and the fact that
    /// files already written keep the grade cooperative until they are
    /// rewritten. A remedy that only said "partition on the boundary" would let
    /// an operator repartition, see nothing change, and stop trusting the grade.
    #[must_use]
    pub fn remedy(&self, table: &str) -> Option<String> {
        let Self::Cooperative { columns, masked } = self else {
            return None;
        };

        let mut steps = Vec::new();
        if !columns.is_empty() {
            let fields = columns
                .iter()
                .map(|column| format!("ADD PARTITION FIELD {column}"))
                .collect::<Vec<_>>()
                .join(", ");
            steps.push(format!(
                "ALTER TABLE {table} {fields} — then rewrite the files written before it. The \
                 grade turns architectural when no live file was written under a spec that \
                 does not partition on {}.",
                columns.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        if *masked {
            steps.push(
                "A column mask is always cooperative: every delivered file holds the raw \
                 column, and only the engine masks it. To withhold a column from every \
                 engine, deny the table and grant a view that omits it."
                    .to_string(),
            );
        }
        Some(steps.join(" "))
    }
}

/// An RFC 9651 sf-string, or a Display String when the text is not printable
/// ASCII.
fn structured_string(text: &str) -> String {
    if text.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        let mut out = String::from("%\"");
        for byte in text.bytes() {
            if byte == b'%' || byte == b'"' || !(0x20..=0x7e).contains(&byte) {
                out.push_str(&format!("%{byte:02x}"));
            } else {
                out.push(byte as char);
            }
        }
        out.push('"');
        out
    }
}

/// Grades a caller's obligations on one table.
///
/// `live_specs` is the set of partition spec ids the served snapshot's live
/// manifests were written under — `None` for a table with no snapshot, which
/// has no files and is graded by its default spec.
///
/// # Why the served snapshot, and not every spec the table has had
///
/// A filter is enforced by withholding files only if every file the caller may
/// be handed separates rows by the filter column. That is a property of the
/// files, so it is read from the specs files were *written* under. The table's
/// default spec alone overclaims — files written before an evolution are still
/// live and are not partitioned on the column. Every spec in `partition-specs`
/// underclaims forever — that list never forgets a spec, so an operator who
/// repartitioned and rewrote every file would still be told `cooperative`, and
/// the remedy would be a lie.
#[must_use]
pub fn enforcement(
    metadata: &TableMetadata,
    obligations: &crate::auth::Obligations,
    live_specs: Option<&BTreeSet<i32>>,
) -> Enforcement {
    if obligations.is_empty() {
        return Enforcement::None;
    }

    let aligned = aligned_columns(metadata, live_specs);
    let mut opaque = false;
    let mut columns = BTreeSet::new();
    for filter in &obligations.row_filters {
        let referenced = referenced_columns(filter, metadata);
        // A filter that names no column is either a constant — which selects
        // all files or none, and is enforced by selection — or a term this
        // catalog cannot read. The second is never graded architectural: what
        // cannot be read cannot be shown to separate files.
        if referenced.is_empty() && !is_constant(filter) {
            opaque = true;
        }
        columns.extend(referenced.into_iter().filter(|c| !aligned.contains(c)));
    }
    let masked = !obligations.column_masks.is_empty();

    if columns.is_empty() && !masked && !opaque {
        Enforcement::Architectural
    } else {
        Enforcement::Cooperative { columns, masked }
    }
}

/// `true`, `false`, or their object forms.
fn is_constant(filter: &serde_json::Value) -> bool {
    match filter {
        serde_json::Value::Bool(_) => true,
        serde_json::Value::Object(map) => {
            map.len() == 1
                && matches!(
                    map.get("type").and_then(serde_json::Value::as_str),
                    Some("true" | "false")
                )
        }
        _ => false,
    }
}

/// Columns every live spec partitions by identity.
///
/// **Identity transforms only.** Every other transform is lossy — `days(ts)`
/// puts a whole day in one file, `bucket(16, id)` a sixteenth of all ids — so a
/// filter on the source column selects files whose other rows are forbidden.
///
/// Conservative rather than exact: `ts >= '2024-01-01' AND ts < '2024-01-02'`
/// against `days(ts)` *is* enforceable and is reported as unaligned anyway,
/// because deciding that needs a predicate model over transforms `iceberg-rust`
/// does not carry. The error runs in the safe direction, and so does a spec id
/// the metadata does not know: it aligns nothing.
fn aligned_columns(
    metadata: &TableMetadata,
    live_specs: Option<&BTreeSet<i32>>,
) -> BTreeSet<String> {
    let default = [metadata.default_partition_spec_id()];
    let ids: Vec<i32> = match live_specs {
        Some(ids) => ids.iter().copied().collect(),
        None => default.to_vec(),
    };

    let mut per_spec = ids.iter().map(|id| identity_columns(metadata, *id));
    let Some(first) = per_spec.next() else {
        return identity_columns(metadata, metadata.default_partition_spec_id());
    };
    per_spec.fold(first, |acc, next| {
        acc.intersection(&next).cloned().collect()
    })
}

/// Source columns one spec partitions by identity, by full name.
///
/// **Source names, and full ones.** A spec may name an identity field `reg`
/// while the filter says `region`, so the source column is what is compared —
/// via `Schema::name_by_field_id`, which gives the dotted path. `NestedField::
/// name` is the leaf only, and would match a partition on `user.region` against
/// an unrelated top-level `region` while missing the filter that named it.
fn identity_columns(metadata: &TableMetadata, spec_id: i32) -> BTreeSet<String> {
    let schema = metadata.current_schema();
    let Some(spec) = metadata.partition_spec_by_id(spec_id) else {
        return BTreeSet::new();
    };
    spec.fields()
        .iter()
        .filter(|field| field.transform == Transform::Identity)
        .filter_map(|field| schema.name_by_field_id(field.source_id))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
    use serde_json::json;
    use std::sync::Arc;

    /// The columns these tests reference, so an `IdReference` has something to
    /// resolve against.
    fn schema() -> Arc<Schema> {
        Arc::new(
            Schema::builder()
                .with_fields(vec![
                    NestedField::optional(1, "region", Type::Primitive(PrimitiveType::String))
                        .into(),
                    NestedField::optional(2, "a", Type::Primitive(PrimitiveType::String)).into(),
                    NestedField::optional(3, "b", Type::Primitive(PrimitiveType::Long)).into(),
                    NestedField::optional(4, "c", Type::Primitive(PrimitiveType::Long)).into(),
                    NestedField::optional(5, "ts", Type::Primitive(PrimitiveType::Long)).into(),
                ])
                .build()
                .expect("schema builds"),
        )
    }

    fn cols(filter: serde_json::Value) -> Vec<String> {
        crate::predicate::referenced_columns(&filter, &schema())
            .into_iter()
            .collect()
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

    /// A reference by **field id** names its column. `IdReference` is the form
    /// the spec prefers and the one `read-restrictions` mandates, so reading it
    /// as nothing would silently suppress the alignment warning for every filter
    /// written the modern way.
    #[test]
    fn a_reference_by_field_id_names_its_column() {
        assert_eq!(
            cols(json!({
                "type": "eq",
                "left": { "type": "reference", "id": 1 },
                "right": { "type": "literal", "value": "EU" }
            })),
            vec!["region".to_string()]
        );
    }

    /// A term this catalog cannot bind contributes no column. That suppresses
    /// the alignment warning rather than provoking it — safe only because such a
    /// *policy* filter is refused outright at plan time, so there is no
    /// enforcement claim left to be wrong about.
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
/// Derived from the grade rather than from a second reading of the rule, so the
/// log line and the header a caller sees cannot disagree. Says nothing for a
/// grade that is cooperative only because of a mask: that is stated on every
/// response and is not a partitioning mistake an operator can fix.
pub fn warn_if_cooperative(grade: &Enforcement, table: &str, policy_set_version: Option<&str>) {
    let Enforcement::Cooperative { columns, .. } = grade else {
        return;
    };
    if columns.is_empty() {
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

    let columns: Vec<&str> = columns.iter().map(String::as_str).collect();
    tracing::warn!(
        table = %table,
        columns = ?columns,
        policy_set_version = policy_set_version.unwrap_or("-"),
        "Row filter references columns that are not identity partitions of every spec this \
         table's live files were written under, so it cannot be enforced by withholding \
         files. A scan plan applies the filter and returns it as the residual, so a \
         cooperating engine honours it, but an engine using its own storage credentials \
         reads the table unfiltered. Partition on the security boundary and rewrite the \
         older files to make this enforcement architectural."
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
                default_identity_columns(&metadata).is_empty(),
                "{transform:?} does not separate rows by column value"
            );

            let filter = json!({ "type": "eq", "term": column, "value": "EU" });
            assert_eq!(
                unaligned_columns_for_test(&filter, &metadata)
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
            default_identity_columns(&metadata)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["user.region".to_string()],
        );

        let on_nested = json!({ "type": "eq", "term": "user.region", "value": "EU" });
        assert!(
            unaligned_columns_for_test(&on_nested, &metadata).is_empty(),
            "the partitioned column is aligned"
        );

        let on_top_level = json!({ "type": "eq", "term": "region", "value": "EU" });
        assert_eq!(
            unaligned_columns_for_test(&on_top_level, &metadata)
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
        let columns = default_identity_columns(&metadata(Some("region")));
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
        assert!(unaligned_columns_for_test(&filter, &metadata(Some("region"))).is_empty());
    }

    /// The case worth warning about: permitted and forbidden rows share files,
    /// so no file-level decision separates them.
    #[test]
    fn a_filter_on_a_non_partition_column_is_reported() {
        let filter = serde_json::json!({ "type": "eq", "term": "email", "value": "a@b.c" });
        let unaligned = unaligned_columns_for_test(&filter, &metadata(Some("region")));
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
            unaligned_columns_for_test(&filter, &metadata(Some("region")))
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
        let unaligned = unaligned_columns_for_test(&filter, &metadata(Some("region")));
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
        let unaligned = unaligned_columns_for_test(&filter, &metadata(None));
        assert_eq!(
            unaligned.into_iter().collect::<Vec<_>>(),
            vec!["region".to_string()]
        );
    }

    /// No filters means nothing to report, and no work done.
    #[test]
    fn no_filters_reports_nothing() {
        warn_if_cooperative(&Enforcement::None, "db.t", Some("v1"));
    }

    fn default_identity_columns(metadata: &TableMetadata) -> BTreeSet<String> {
        identity_columns(metadata, metadata.default_partition_spec_id())
    }

    fn only_filter(filter: &serde_json::Value) -> crate::auth::Obligations {
        crate::auth::Obligations {
            row_filters: vec![filter.clone()],
            column_masks: Default::default(),
        }
    }

    /// The unaligned columns of one filter against the default spec — the
    /// grade, read for its columns.
    fn unaligned_columns_for_test(
        filter: &serde_json::Value,
        metadata: &TableMetadata,
    ) -> BTreeSet<String> {
        match enforcement(metadata, &only_filter(filter), None) {
            Enforcement::Cooperative { columns, .. } => columns,
            _ => BTreeSet::new(),
        }
    }

    /// `metadata(None)` evolved once: spec 0 unpartitioned, spec 1 (the new
    /// default) partitioned by identity on `region`.
    fn evolved_to_region() -> TableMetadata {
        let base = metadata(None);
        let spec = UnboundPartitionSpec::builder()
            .add_partition_field(1, "region_p".to_string(), Transform::Identity)
            .expect("partition field is valid")
            .build();
        TableMetadataBuilder::new_from_metadata(base, None)
            .add_default_partition_spec(spec)
            .expect("spec is valid")
            .build()
            .expect("metadata builds")
            .metadata
    }

    /// Files written before the evolution are still live and hold every
    /// region. Reading the default spec alone called this architectural — the
    /// dangerous direction.
    #[test]
    fn a_column_partitioned_only_by_the_newest_spec_is_cooperative() {
        let metadata = evolved_to_region();
        let live: BTreeSet<i32> = [0, 1].into();
        let filter = json!({ "type": "eq", "term": "region", "value": "EU" });

        assert_eq!(
            enforcement(&metadata, &only_filter(&filter), Some(&live)),
            Enforcement::Cooperative {
                columns: ["region".to_string()].into(),
                masked: false
            },
        );
    }

    /// Once every live file was written under the new spec, the old one is
    /// history: it stays in `partition-specs` forever, and counting it would
    /// make the remedy impossible to follow.
    #[test]
    fn rewritten_under_the_new_spec_turns_architectural() {
        let metadata = evolved_to_region();
        let live: BTreeSet<i32> = [1].into();
        let filter = json!({ "type": "eq", "term": "region", "value": "EU" });

        assert_eq!(
            enforcement(&metadata, &only_filter(&filter), Some(&live)),
            Enforcement::Architectural,
        );
    }

    /// A spec id the metadata does not carry aligns nothing.
    #[test]
    fn an_unknown_live_spec_aligns_nothing() {
        let metadata = metadata(Some("region"));
        let live: BTreeSet<i32> = [0, 42].into();
        let filter = json!({ "type": "eq", "term": "region", "value": "EU" });

        assert!(matches!(
            enforcement(&metadata, &only_filter(&filter), Some(&live)),
            Enforcement::Cooperative { .. }
        ));
    }

    /// The file holds the raw column whatever the filter does.
    #[test]
    fn a_mask_is_never_architectural() {
        let metadata = metadata(Some("region"));
        let obligations = crate::auth::Obligations {
            row_filters: vec![json!({ "type": "eq", "term": "region", "value": "EU" })],
            column_masks: ["email".to_string()].into(),
        };

        assert_eq!(
            enforcement(&metadata, &obligations, None),
            Enforcement::Cooperative {
                columns: BTreeSet::new(),
                masked: true
            },
        );
    }

    /// A term this catalog cannot read names no column, and is not thereby
    /// aligned.
    #[test]
    fn an_unreadable_filter_is_never_architectural() {
        let metadata = metadata(Some("region"));
        let filter = json!({
            "type": "eq",
            "term": { "type": "transform", "transform": "day", "term": "ts" },
            "value": 1
        });
        assert!(matches!(
            enforcement(&metadata, &only_filter(&filter), None),
            Enforcement::Cooperative { .. }
        ));
        assert_eq!(
            enforcement(&metadata, &only_filter(&json!(false)), None),
            Enforcement::Architectural,
            "a constant selects all files or none"
        );
    }

    #[test]
    fn no_obligations_is_none() {
        assert_eq!(
            enforcement(&metadata(None), &crate::auth::Obligations::default(), None),
            Enforcement::None
        );
    }

    /// The header is an RFC 9651 Item: a token, then parameters.
    #[test]
    fn the_header_is_a_structured_field() {
        assert_eq!(Enforcement::None.header_value(), "none");
        assert_eq!(Enforcement::Architectural.header_value(), "architectural");
        assert_eq!(
            Enforcement::Cooperative {
                columns: ["region".to_string(), "ts".to_string()].into(),
                masked: true
            }
            .header_value(),
            r#"cooperative;columns="region,ts";masked"#
        );
        assert_eq!(
            Enforcement::Cooperative {
                columns: BTreeSet::new(),
                masked: true
            }
            .header_value(),
            "cooperative;masked"
        );
    }

    /// A column name that is not printable ASCII becomes a Display String, so
    /// the value is still a valid header.
    #[test]
    fn a_non_ascii_column_is_a_display_string() {
        let value = Enforcement::Cooperative {
            columns: ["région".to_string(), r#"a"b"#.to_string()].into(),
            masked: false,
        }
        .header_value();
        assert_eq!(value, r#"cooperative;columns=%"a%22b,r%c3%a9gion""#);
        assert!(axum::http::HeaderValue::from_str(&value).is_ok());
    }

    /// The remedy names the statement to run and what else it takes.
    #[test]
    fn the_remedy_is_concrete() {
        let remedy = Enforcement::Cooperative {
            columns: ["region".to_string()].into(),
            masked: true,
        }
        .remedy("sales.orders")
        .expect("a remedy");
        assert!(remedy.contains("ALTER TABLE sales.orders ADD PARTITION FIELD region"));
        assert!(remedy.contains("rewrite the files written before it"));
        assert!(remedy.contains("A column mask is always cooperative"));
        assert_eq!(Enforcement::Architectural.remedy("t"), None);
    }
}
