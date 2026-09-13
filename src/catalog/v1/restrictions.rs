//! `read-restrictions`: the row filter and column projections a conforming
//! reader must apply.
//!
//! Withholding storage access enforces a restriction against anything reading
//! *through* this catalog. It does nothing about an engine holding its own
//! storage credentials, which reads the Parquet directly — and that engine is the
//! one this reaches. The two are stacked rather than alternatives, under one
//! rule: **reporting a restriction never relaxes withholding it.** A table
//! carrying obligations still gets no credential and no signer block.
//!
//! It is cooperative. A conforming reader must apply the restriction and must
//! fail the query rather than return raw rows; a hostile one ignores it.
//!
//! # A restriction this table cannot carry
//!
//! The spec's vocabulary is bounded — nine projection actions, comparisons and
//! set membership over field ids — and a broad permit's filter may name a column
//! this table does not have. Such a filter is published as **`false`**: the
//! caller reads the metadata and none of the rows.
//!
//! Omitting it would tell a conforming reader the table is unrestricted, which is
//! worse than saying nothing because the reader has done everything right.
//! Refusing the load would break every table the policy does not fit.

use std::collections::{BTreeSet, HashSet};

use iceberg::spec::{NestedFieldRef, Schema, TableMetadata, Type};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::auth::Obligations;
use crate::error::{AppError, Result};

/// The restrictions a reader must apply, as `LoadTableResult.read-restrictions`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ReadRestrictions {
    /// One action per column, addressed by field id.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_column_projections: Vec<ColumnProjection>,
    /// Rows the reader may return. Absent means no mandatory filtering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_row_filter: Option<Value>,
}

/// One column-projection action.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ColumnProjection {
    /// The spec's action name.
    pub action: &'static str,
    /// Field id of the column being projected.
    pub field_id: i32,
}

/// `replace-with-null` is illegal on a required field — the spec says a server
/// must not return it and a reader that receives one must fail the query. The
/// fallback covers every type, including structs, which it fills recursively.
const NULLABLE_ACTION: &str = "replace-with-null";
const REQUIRED_ACTION: &str = "mask-to-fixed-value";

/// The restrictions to publish for this caller on this table.
///
/// `None` when policy attaches none. Otherwise every obligation is expressed, or
/// the call fails — see the module docs.
///
/// `masked` is already resolved against this schema, so this function is about
/// *expressing* what policy withholds, not about resolving it again.
///
/// # Errors
///
/// [`AppError::Forbidden`] when an obligation cannot be expressed in the spec's
/// vocabulary.
pub fn read_restrictions(
    schema: &Schema,
    obligations: &Obligations,
    masked: &HashSet<i32>,
) -> Result<Option<ReadRestrictions>> {
    // `Result` is kept although only the projections can fail today: a map-key
    // mask is a policy mistake worth a status code, while an unusable row filter
    // has a safe value to fall back to and takes it.
    if obligations.is_empty() {
        return Ok(None);
    }

    let projections = column_projections(schema, masked)?;
    let filter = row_filter(schema, obligations)?;

    if projections.is_empty() && filter.is_none() {
        return Ok(None);
    }

    Ok(Some(ReadRestrictions {
        required_column_projections: projections,
        required_row_filter: filter,
    }))
}

/// The restrictions for a table, resolving the masks against its current schema.
///
/// The handler's entry point: one call, so `loadTable`, `createTable` and
/// `registerTable` cannot drift in what they publish.
///
/// # Errors
///
/// [`AppError::Forbidden`] when a mask names no column in this schema, or when
/// an obligation cannot be expressed in the spec's vocabulary.
pub fn for_table(
    metadata: &TableMetadata,
    obligations: &Obligations,
) -> Result<Option<ReadRestrictions>> {
    if obligations.is_empty() {
        return Ok(None);
    }
    let schema = metadata.current_schema();
    let masked = super::plan::masked_field_ids(metadata, obligations)?;
    read_restrictions(schema, obligations, &masked)
}

/// One action per masked column, with the spec's three structural rules applied.
///
/// 1. **At most one projection per field id** — the set makes this free.
/// 2. **Never both a nested field and something inside it.** `masked` holds a
///    masked struct *and* everything under it, because that is what the internal
///    checks need. On the wire only the outermost survives: a projection on the
///    struct already covers its fields, and sending both is a response the spec
///    says a reader must fail.
/// 3. **Never a map's key field.** Masking a key can collapse distinct keys into
///    one or null them, which readers silently coalesce — data loss rather than
///    redaction. A policy that asks for it is refused rather than trimmed,
///    because trimming would leave the key readable while the policy says
///    otherwise.
fn column_projections(schema: &Schema, masked: &HashSet<i32>) -> Result<Vec<ColumnProjection>> {
    if masked.is_empty() {
        return Ok(Vec::new());
    }

    let keys = map_key_field_ids(schema);
    if let Some(id) = masked.iter().find(|id| keys.contains(id)) {
        let name = schema
            .name_by_field_id(*id)
            .map_or_else(|| format!("#{id}"), str::to_string);
        return Err(AppError::Forbidden(format!(
            "Policy withholds '{name}', which is the key of a map. A projection on a map \
             key can collapse or null distinct keys, so the specification forbids one and \
             a reader must reject it. Mask the map or its value instead."
        )));
    }

    // Rule 2: keep only the outermost masked field of each chain. A field whose
    // ancestor is masked is already covered by that ancestor's projection.
    let outermost: BTreeSet<i32> = masked
        .iter()
        .copied()
        .filter(|id| !ancestors(schema, *id).iter().any(|up| masked.contains(up)))
        .collect();

    outermost
        .into_iter()
        .map(|field_id| {
            let field = schema.field_by_id(field_id).ok_or_else(|| {
                AppError::Forbidden(format!(
                    "Policy withholds field id {field_id}, which this table's schema does \
                     not have."
                ))
            })?;
            Ok(ColumnProjection {
                action: if field.required {
                    REQUIRED_ACTION
                } else {
                    NULLABLE_ACTION
                },
                field_id,
            })
        })
        .collect()
}

/// The ancestors of a field, outermost first, by walking the schema's dotted
/// names. `user.address.zip` has ancestors `user` and `user.address`.
///
/// Names rather than a structural walk because `Schema` indexes fields by their
/// full dotted path and not by parent, and because the two agree: Iceberg builds
/// that path from the nesting.
fn ancestors(schema: &Schema, id: i32) -> Vec<i32> {
    let Some(name) = schema.name_by_field_id(id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut prefix = String::new();
    for segment in name.split('.').take(name.matches('.').count()) {
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(segment);
        if let Some(parent) = schema.field_id_by_name(&prefix) {
            out.push(parent);
        }
    }
    out
}

/// Every field id that is the key half of a map.
fn map_key_field_ids(schema: &Schema) -> HashSet<i32> {
    fn walk(field: &NestedFieldRef, out: &mut HashSet<i32>) {
        match &*field.field_type {
            Type::Struct(structure) => {
                for nested in structure.fields() {
                    walk(nested, out);
                }
            }
            Type::List(list) => walk(&list.element_field, out),
            Type::Map(map) => {
                out.insert(map.key_field.id);
                walk(&map.key_field, out);
                walk(&map.value_field, out);
            }
            Type::Primitive(_) => {}
        }
    }

    let mut out = HashSet::new();
    for field in schema.as_struct().fields() {
        walk(field, &mut out);
    }
    out
}

/// The policy's row filters as one spec predicate, or `None` when there are none.
///
/// The matching permits' filters are OR-ed, for the reason
/// [`Obligations::row_filters`] gives: permits grant, so a caller sees the union.
///
/// Every column reference is rewritten to an `IdReference`, which the spec
/// requires here — *"Column references within the expression must use field IDs
/// (IdReference), not column names. This ensures the filter remains valid across
/// column renames"*. That is the same argument [`super::plan::masked_field_ids`]
/// makes about masks, arrived at independently by the spec authors.
///
/// # A filter this table cannot carry becomes `false`, not an error
///
/// The spec's vocabulary is bounded, and a broad permit's filter may name a
/// column this table does not have — `resource in Tenant::"acme"` with
/// `@row_filter("region = 'EU'")` reaches every table in the tenant, and most
/// have no `region`.
///
/// Three answers were possible and two are wrong. **Omitting** the filter tells a
/// conforming reader this table is unrestricted, which is the most damaging
/// answer available because the reader has done everything right. **Refusing the
/// load** makes an ordinary policy shape break every table it does not fit.
///
/// So the filter becomes the constant `false`: the caller may read the table's
/// metadata and no rows of it. That is deny-by-default, it is expressible, and it
/// agrees with what [`super::plan`] already does with the same filter — refuse to
/// plan — rather than inventing a third behaviour for the same policy.
fn row_filter(schema: &Schema, obligations: &Obligations) -> Result<Option<Value>> {
    let mut combined: Option<Value> = None;
    for filter in &obligations.row_filters {
        // `false` is absorbing under OR only if every branch is false, so an
        // inexpressible branch cannot be dropped — it contributes `false` and the
        // disjunction carries it, which is exactly the union semantics permits
        // have.
        let bound = to_id_predicate(filter, schema).unwrap_or_else(|reason| {
            tracing::warn!(
                reason = %reason,
                "A policy row filter cannot be expressed as a read-restriction for this \
                 table; publishing `false`, so a conforming reader returns no rows"
            );
            Value::Bool(false)
        });
        combined = Some(match combined {
            None => bound,
            Some(left) => json!({ "type": "or", "left": left, "right": bound }),
        });
    }
    Ok(combined)
}

/// Rewrites one predicate into the spec's preferred form with id references.
///
/// # Errors
///
/// [`AppError::Forbidden`] for anything the spec's bounded vocabulary cannot
/// carry — a transform, a function application, or a column this schema does not
/// have. Refusing rather than dropping the term: a dropped conjunct widens the
/// filter, which is a weaker restriction handed over as though it were the
/// policy.
fn to_id_predicate(filter: &Value, schema: &Schema) -> Result<Value> {
    if let Some(flag) = filter.as_bool() {
        return Ok(Value::Bool(flag));
    }

    let object = filter.as_object().ok_or_else(|| {
        AppError::Forbidden("A policy row filter is not a predicate.".to_string())
    })?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Forbidden("A policy row filter needs a 'type'.".to_string()))?;

    match kind {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "and" | "or" => {
            let left = to_id_predicate(branch(object, "left")?, schema)?;
            let right = to_id_predicate(branch(object, "right")?, schema)?;
            Ok(json!({ "type": kind, "left": left, "right": right }))
        }
        "not" => Ok(json!({
            "type": "not",
            "child": to_id_predicate(branch(object, "child")?, schema)?
        })),
        "is-null" | "not-null" | "is-nan" | "not-nan" => Ok(json!({
            "type": kind,
            "child": id_reference(operand(object, &["child", "term"])?, schema)?
        })),
        "lt" | "lt-eq" | "gt" | "gt-eq" | "eq" | "not-eq" | "starts-with" | "not-starts-with" => {
            let left = id_reference(operand(object, &["left", "term"])?, schema)?;
            let right = object
                .get("right")
                .or_else(|| object.get("value"))
                .ok_or_else(|| {
                    AppError::Forbidden(format!("A policy row filter's '{kind}' has no value."))
                })?;
            Ok(json!({ "type": kind, "left": left, "right": as_literal(right) }))
        }
        "in" | "not-in" => {
            let child = id_reference(operand(object, &["child", "term"])?, schema)?;
            let values = object.get("values").ok_or_else(|| {
                AppError::Forbidden(format!("A policy row filter's '{kind}' has no 'values'."))
            })?;
            Ok(json!({ "type": kind, "child": child, "values": values.clone() }))
        }
        other => Err(AppError::Forbidden(format!(
            "A policy row filter uses '{other}', which the read-restrictions vocabulary \
             cannot express. The table is withheld rather than served with the restriction \
             missing."
        ))),
    }
}

/// A sub-expression, by key.
fn branch<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| AppError::Forbidden(format!("A policy row filter is missing '{key}'.")))
}

/// The first present operand key — the current spelling, then the deprecated one.
fn operand<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Result<&'a Value> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .ok_or_else(|| AppError::Forbidden("A policy row filter has no operand.".to_string()))
}

/// A column reference as an `IdReference`.
///
/// Accepts every spelling the parser does — a bare name, a `NamedReference`, or
/// an `IdReference` that is already in the target form — and refuses a transform
/// or a function application, which the spec's expression vocabulary has no room
/// for here.
fn id_reference(value: &Value, schema: &Schema) -> Result<Value> {
    let name = match value {
        Value::String(name) => name.clone(),
        Value::Object(object) => match object.get("type").and_then(Value::as_str) {
            Some("reference") => {
                if let Some(id) = object.get("id").and_then(Value::as_i64) {
                    // Already an id reference; confirm it resolves here.
                    let id = i32::try_from(id).map_err(|_| {
                        AppError::Forbidden(format!("Field id {id} is out of range."))
                    })?;
                    if schema.field_by_id(id).is_none() {
                        return Err(AppError::Forbidden(format!(
                            "A policy row filter references field id {id}, which this table \
                             does not have."
                        )));
                    }
                    return Ok(json!({ "type": "reference", "id": id }));
                }
                object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AppError::Forbidden(
                            "A policy row filter reference has neither a name nor an id."
                                .to_string(),
                        )
                    })?
                    .to_string()
            }
            _ => {
                return Err(AppError::Forbidden(
                    "A policy row filter applies a transform or a function, which \
                     read-restrictions cannot express. The table is withheld rather than \
                     served with the restriction missing."
                        .to_string(),
                ));
            }
        },
        _ => {
            return Err(AppError::Forbidden(
                "A policy row filter operand is not a column reference.".to_string(),
            ));
        }
    };

    let id = schema
        .field_id_by_name(&name)
        .or_else(|| {
            schema
                .field_by_name_case_insensitive(&name)
                .map(|field| field.id)
        })
        .ok_or_else(|| {
            AppError::Forbidden(format!(
                "A policy row filter names '{name}', which this table does not have."
            ))
        })?;
    Ok(json!({ "type": "reference", "id": id }))
}

/// A comparison's right-hand side as a `Literal`.
///
/// A bare scalar is already one; the typed object form is passed through.
fn as_literal(value: &Value) -> Value {
    if value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        == Some("literal")
    {
        return value.clone();
    }
    json!({ "type": "literal", "value": value.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iceberg::spec::{ListType, MapType, NestedField, PrimitiveType, StructType};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn schema() -> Schema {
        Schema::builder()
            .with_fields(vec![
                NestedField::optional(1, "region", Type::Primitive(PrimitiveType::String)).into(),
                NestedField::required(2, "id", Type::Primitive(PrimitiveType::Long)).into(),
                NestedField::optional(
                    3,
                    "user",
                    Type::Struct(StructType::new(vec![
                        NestedField::optional(4, "ssn", Type::Primitive(PrimitiveType::String))
                            .into(),
                    ])),
                )
                .into(),
                NestedField::optional(
                    5,
                    "tags",
                    Type::Map(MapType::new(
                        Arc::new(NestedField::required(
                            6,
                            "key",
                            Type::Primitive(PrimitiveType::String),
                        )),
                        Arc::new(NestedField::optional(
                            7,
                            "value",
                            Type::Primitive(PrimitiveType::String),
                        )),
                    )),
                )
                .into(),
                NestedField::optional(
                    8,
                    "scores",
                    Type::List(ListType {
                        element_field: Arc::new(NestedField::optional(
                            9,
                            "element",
                            Type::Primitive(PrimitiveType::Long),
                        )),
                    }),
                )
                .into(),
            ])
            .build()
            .expect("schema builds")
    }

    fn obs(filters: Vec<Value>, masks: &[&str]) -> Obligations {
        Obligations {
            row_filters: filters,
            column_masks: masks.iter().map(|m| (*m).to_string()).collect(),
        }
    }

    /// An optional column gets `replace-with-null`; a required one cannot, because
    /// the spec forbids it and says a reader must fail the query.
    #[test]
    fn a_required_column_is_masked_to_a_fixed_value() {
        let schema = schema();
        let masked = HashSet::from([1, 2]);
        let projections = column_projections(&schema, &masked).expect("both express");

        let by_id: HashMap<i32, &str> =
            projections.iter().map(|p| (p.field_id, p.action)).collect();
        assert_eq!(by_id[&1], "replace-with-null", "region is optional");
        assert_eq!(by_id[&2], "mask-to-fixed-value", "id is required");
    }

    /// The spec forbids a projection on both a nested field and anything inside
    /// it. Internally a masked struct carries its descendants, so only the
    /// outermost may go on the wire.
    #[test]
    fn only_the_outermost_masked_field_is_published() {
        let schema = schema();
        // What `masked_field_ids` produces for `@column_mask("user")`.
        let masked = HashSet::from([3, 4]);
        let projections = column_projections(&schema, &masked).expect("expressible");
        assert_eq!(projections.len(), 1, "got {projections:?}");
        assert_eq!(projections[0].field_id, 3, "the struct, not its field");
    }

    /// Masking a map key can collapse or null distinct keys, so the spec forbids
    /// it outright.
    #[test]
    fn a_mask_on_a_map_key_is_refused() {
        let schema = schema();
        let refused = column_projections(&schema, &HashSet::from([6]));
        assert!(
            matches!(refused, Err(AppError::Forbidden(_))),
            "got {refused:?}"
        );
    }

    #[test]
    fn map_keys_are_found_through_nesting() {
        assert_eq!(map_key_field_ids(&schema()), HashSet::from([6]));
    }

    /// Names become field ids, which is what keeps the filter valid across a
    /// rename.
    #[test]
    fn a_row_filter_is_rewritten_to_field_ids() {
        let schema = schema();
        let obligations = obs(
            vec![json!({ "type": "eq", "term": "region", "value": "EU" })],
            &[],
        );
        let filter = row_filter(&schema, &obligations)
            .expect("expressible")
            .expect("a filter is present");
        assert_eq!(
            filter,
            json!({
                "type": "eq",
                "left": { "type": "reference", "id": 1 },
                "right": { "type": "literal", "value": "EU" }
            })
        );
    }

    /// Permits grant, so several filters become a disjunction.
    #[test]
    fn several_row_filters_are_or_ed() {
        let schema = schema();
        let obligations = obs(
            vec![
                json!({ "type": "eq", "term": "region", "value": "EU" }),
                json!({ "type": "eq", "term": "region", "value": "US" }),
            ],
            &[],
        );
        let filter = row_filter(&schema, &obligations)
            .expect("expressible")
            .expect("a filter is present");
        assert_eq!(filter["type"], "or");
        assert_eq!(filter["left"]["left"]["id"], 1);
        assert_eq!(filter["right"]["right"]["value"], "US");
    }

    /// A transform cannot be expressed. Dropping it would widen the filter — a
    /// weaker restriction handed over as though it were the policy — so it
    /// becomes `false` and the caller sees no rows.
    #[test]
    fn a_transform_term_becomes_false_rather_than_widening() {
        let schema = schema();
        let obligations = obs(
            vec![json!({
                "type": "eq",
                "term": { "type": "transform", "transform": "day", "term": "ts" },
                "value": 1
            })],
            &[],
        );
        assert_eq!(
            row_filter(&schema, &obligations).expect("never errors"),
            Some(Value::Bool(false)),
            "an inexpressible filter denies every row"
        );
    }

    /// A filter naming a column this table does not have is the broad-permit
    /// case: `resource in Tenant::"acme"` reaches tables with no `region`. It
    /// denies rather than refusing the load, and above all rather than being
    /// dropped — a dropped filter tells a conforming reader the table is
    /// unrestricted.
    #[test]
    fn an_unknown_column_denies_every_row() {
        let schema = schema();
        let obligations = obs(
            vec![json!({ "type": "eq", "term": "nope", "value": 1 })],
            &[],
        );
        assert_eq!(
            row_filter(&schema, &obligations).expect("never errors"),
            Some(Value::Bool(false))
        );
    }

    /// One expressible filter and one that is not: the disjunction keeps both,
    /// because permits grant and dropping the unusable branch would widen the
    /// result to whatever the others allow.
    #[test]
    fn an_inexpressible_branch_does_not_widen_the_others() {
        let schema = schema();
        let obligations = obs(
            vec![
                json!({ "type": "eq", "term": "region", "value": "EU" }),
                json!({ "type": "eq", "term": "nope", "value": 1 }),
            ],
            &[],
        );
        let filter = row_filter(&schema, &obligations)
            .expect("never errors")
            .expect("present");
        assert_eq!(filter["type"], "or");
        assert_eq!(filter["right"], Value::Bool(false));
        assert_eq!(filter["left"]["left"]["id"], 1);
    }

    /// A filter already written with id references passes through, having been
    /// checked against this table.
    #[test]
    fn an_id_reference_passes_through_after_checking() {
        let schema = schema();
        let obligations = obs(
            vec![json!({
                "type": "eq",
                "left": { "type": "reference", "id": 1 },
                "right": { "type": "literal", "value": "EU" }
            })],
            &[],
        );
        let filter = row_filter(&schema, &obligations)
            .expect("expressible")
            .expect("present");
        assert_eq!(filter["left"]["id"], 1);

        let bad = obs(
            vec![json!({
                "type": "eq",
                "left": { "type": "reference", "id": 999 },
                "right": { "type": "literal", "value": "EU" }
            })],
            &[],
        );
        assert_eq!(
            row_filter(&schema, &bad).expect("never errors"),
            Some(Value::Bool(false)),
            "an id this table does not have denies rather than widening"
        );
    }

    /// No obligations, nothing published — the common case, and the one that must
    /// not add a field to every response.
    #[test]
    fn an_unrestricted_table_publishes_nothing() {
        let schema = schema();
        let none = read_restrictions(&schema, &obs(Vec::new(), &[]), &HashSet::new())
            .expect("no obligations");
        assert!(none.is_none());
    }

    /// Both halves together, as they appear on the wire.
    #[test]
    fn both_halves_serialise_in_the_spec_shape() {
        let schema = schema();
        let obligations = obs(
            vec![json!({ "type": "eq", "term": "region", "value": "EU" })],
            &["user"],
        );
        let restrictions = read_restrictions(&schema, &obligations, &HashSet::from([3, 4]))
            .expect("expressible")
            .expect("present");
        let wire = serde_json::to_value(&restrictions).expect("serialises");
        assert_eq!(
            wire,
            json!({
                "required-column-projections": [
                    { "action": "replace-with-null", "field-id": 3 }
                ],
                "required-row-filter": {
                    "type": "eq",
                    "left": { "type": "reference", "id": 1 },
                    "right": { "type": "literal", "value": "EU" }
                }
            })
        );
    }
}
