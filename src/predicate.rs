//! The Iceberg REST spec's JSON predicate, as a type this catalog can use.
//!
//! One grammar, two callers: the filter a client sends to
//! [`planTableScan`](crate::catalog::v1::plan), and the row filter a Cedar
//! policy attaches to a permit. Both are the spec's `Predicate` JSON, so a
//! policy author writes the same expressions an engine does, and the planner
//! composes the two by conjunction without translating between dialects.
//!
//! # Why a policy filter is JSON and not SQL
//!
//! A SQL-shaped predicate string cannot be applied. Rustberg does not implement
//! a SQL dialect and should not pretend to: a parser that accepted a predicate
//! it then mis-modelled would be worse than one that never looked, because the
//! mistake would be silent and would look like enforcement. The spec's JSON
//! expression is already defined, already parsed here for scan planning, and
//! already the thing an engine's own filter arrives as — so a policy written in
//! it can be *applied* rather than merely *reported*.
//!
//! # Unsupported is widened, malformed is refused
//!
//! The two are different failures and get different answers.
//!
//! A sub-expression this catalog cannot *bind* — a transform term, a function
//! application, a reference by field id, an operator from a newer spec — is
//! **widened away** rather than refused: it contributes nothing to pruning, so
//! the result is a superset of what the predicate selects. Dropping it outright
//! would be the dangerous version, because pruning against a predicate nobody
//! wrote selects *too few* files.
//!
//! Widening is polarity-aware, and that is the whole correctness argument. Under
//! an even number of negations an unbindable term becomes `AlwaysTrue`; under an
//! odd number it becomes `AlwaysFalse`, so `NOT(unbindable)` widens to "match
//! everything" rather than collapsing to "match nothing".
//!
//! A sub-expression that is *malformed* — a column the table does not have, a
//! literal that does not fit its column's type, a missing operand — is an error.
//! Widening those would turn a typo into a silent full scan.

use std::collections::BTreeSet;

use iceberg::expr::{Predicate, Reference};
use iceberg::spec::{Datum, NestedFieldRef, PrimitiveType, SchemaRef, Type};
use iceberg::{Error, ErrorKind, Result};
use serde_json::{Map, Value};

/// A `DataInvalid` error, which the REST layer maps to `400`.
fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::DataInvalid, message.into())
}

/// Decodes lowercase or uppercase hex, which is how the spec spells a binary
/// single value.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] for anything that is not an even number of hex
/// digits.
fn from_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid(
            "a binary literal must have an even number of hex digits",
        ));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| invalid("a binary literal is not hex"))
        })
        .collect()
}

/// Parses one JSON predicate against `schema`.
///
/// See the module docs for how unsupported and malformed expressions differ.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] naming what was wrong.
pub fn parse_predicate(json: &Value, schema: &SchemaRef) -> Result<Predicate> {
    parse_with_polarity(json, schema, true)
}

/// The value an unbindable sub-expression widens to, given its polarity.
const fn widen(positive: bool) -> Predicate {
    if positive {
        Predicate::AlwaysTrue
    } else {
        Predicate::AlwaysFalse
    }
}

/// Parses one node, knowing whether it sits under an even number of negations.
fn parse_with_polarity(json: &Value, schema: &SchemaRef, positive: bool) -> Result<Predicate> {
    // A bare boolean is the current spelling; the `true`/`false` objects are the
    // deprecated one.
    if let Some(value) = json.as_bool() {
        return Ok(if value {
            Predicate::AlwaysTrue
        } else {
            Predicate::AlwaysFalse
        });
    }

    let object = json
        .as_object()
        .ok_or_else(|| invalid("a filter must be a boolean or an expression object".to_string()))?;

    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a filter expression needs a 'type'".to_string()))?;

    match kind {
        "true" => Ok(Predicate::AlwaysTrue),
        "false" => Ok(Predicate::AlwaysFalse),

        "and" | "or" => {
            let left = parse_with_polarity(child(object, "left")?, schema, positive)?;
            let right = parse_with_polarity(child(object, "right")?, schema, positive)?;
            Ok(if kind == "and" {
                left.and(right)
            } else {
                left.or(right)
            })
        }

        "not" => Ok(parse_with_polarity(child(object, "child")?, schema, !positive)?.negate()),

        "is-null" | "not-null" | "is-nan" | "not-nan" => {
            let Some(name) = operand_name(object)? else {
                return Ok(widen(positive));
            };
            let reference = Reference::new(name);
            Ok(match kind {
                "is-null" => reference.is_null(),
                "not-null" => reference.is_not_null(),
                "is-nan" => reference.is_nan(),
                _ => reference.is_not_nan(),
            })
        }

        "lt" | "lt-eq" | "gt" | "gt-eq" | "eq" | "not-eq" | "starts-with" | "not-starts-with" => {
            let Some(name) = comparison_operand(object)? else {
                return Ok(widen(positive));
            };
            let field = field_named(schema, &name)?;
            let value = object
                .get("right")
                .or_else(|| object.get("value"))
                .ok_or_else(|| invalid(format!("comparison '{kind}' needs a value")))?;
            let datum = parse_literal(value, &field)?;
            let reference = Reference::new(name);

            Ok(match kind {
                "lt" => reference.less_than(datum),
                "lt-eq" => reference.less_than_or_equal_to(datum),
                "gt" => reference.greater_than(datum),
                "gt-eq" => reference.greater_than_or_equal_to(datum),
                "eq" => reference.equal_to(datum),
                "not-eq" => reference.not_equal_to(datum),
                "starts-with" => reference.starts_with(datum),
                _ => reference.not_starts_with(datum),
            })
        }

        "in" | "not-in" => {
            let Some(name) = operand_name(object)? else {
                return Ok(widen(positive));
            };
            let field = field_named(schema, &name)?;
            let values = object
                .get("values")
                .ok_or_else(|| invalid(format!("'{kind}' needs 'values'")))?;
            let datums = parse_literals(values, &field)?;
            let reference = Reference::new(name);
            Ok(if kind == "in" {
                reference.is_in(datums)
            } else {
                reference.is_not_in(datums)
            })
        }

        // An operator from a newer spec, or one this catalog does not read.
        // Widened rather than refused, so a client using a newer grammar still
        // gets correct — if less pruned — results.
        other => {
            tracing::debug!(
                operator = other,
                "widening a filter expression this catalog cannot bind"
            );
            Ok(widen(positive))
        }
    }
}

/// One named child of an expression object.
fn child<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    object
        .get(name)
        .ok_or_else(|| invalid(format!("a filter expression needs '{name}'")))
}

/// The column an operand names, for the `child`/`term` forms.
fn operand_name(object: &Map<String, Value>) -> Result<Option<String>> {
    let operand = object
        .get("child")
        .or_else(|| object.get("term"))
        .ok_or_else(|| invalid("a filter expression needs an operand".to_string()))?;
    reference_name(operand)
}

/// The column a comparison's left-hand side names.
fn comparison_operand(object: &Map<String, Value>) -> Result<Option<String>> {
    let operand = object
        .get("left")
        .or_else(|| object.get("term"))
        .ok_or_else(|| invalid("a comparison needs a left-hand side".to_string()))?;
    reference_name(operand)
}

/// Reads a column name out of a term or reference.
///
/// `None` means the operand is well-formed but names something this catalog
/// cannot bind — a transform, a function application, a field id. The caller
/// widens; see [`parse_predicate`].
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] when the operand is not an operand at all.
fn reference_name(value: &Value) -> Result<Option<String>> {
    if let Some(name) = value.as_str() {
        return Ok(Some(name.to_string()));
    }

    let object = value.as_object().ok_or_else(|| {
        invalid("a filter operand must be a field name or a reference".to_string())
    })?;

    match object.get("type").and_then(Value::as_str) {
        // A named reference binds; a reference by field id does not, because
        // this catalog binds against the schema by name.
        Some("reference") => Ok(object
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)),
        Some("transform") | Some("apply") => Ok(None),
        _ => Err(invalid(
            "a filter operand must be a field name or a reference".to_string(),
        )),
    }
}

/// The schema field a filter names.
fn field_named(schema: &SchemaRef, name: &str) -> Result<NestedFieldRef> {
    schema.field_by_name(name).cloned().ok_or_else(|| {
        invalid(format!(
            "the filter names '{name}', which this table has no"
        ))
    })
}

/// Reads one literal, typed by the column it is compared against.
fn parse_literal(value: &Value, field: &NestedFieldRef) -> Result<Datum> {
    let primitive = primitive_type(field)?;

    // A typed literal object carries its own value; the rest is a bare value.
    if let Some(object) = value.as_object()
        && object.get("type").and_then(Value::as_str) == Some("literal")
    {
        let inner = object
            .get("value")
            .ok_or_else(|| invalid("a literal object needs a 'value'".to_string()))?;
        return datum_from_json(inner, &primitive);
    }

    datum_from_json(value, &primitive)
}

/// Reads a set of literals, in either the bare-array or typed-object form.
fn parse_literals(value: &Value, field: &NestedFieldRef) -> Result<Vec<Datum>> {
    let primitive = primitive_type(field)?;

    let values = if let Some(array) = value.as_array() {
        array
    } else if let Some(object) = value.as_object() {
        object
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("a literals object needs 'values'".to_string()))?
    } else {
        return Err(invalid(
            "a set predicate's values must be an array".to_string(),
        ));
    };

    values
        .iter()
        .map(|value| datum_from_json(value, &primitive))
        .collect()
}

/// The primitive type of a field a filter may compare against.
fn primitive_type(field: &NestedFieldRef) -> Result<PrimitiveType> {
    match field.field_type.as_ref() {
        Type::Primitive(primitive) => Ok(primitive.clone()),
        _ => Err(invalid(format!(
            "the filter compares '{}', which is not a primitive column",
            field.name
        ))),
    }
}

/// Builds a typed [`Datum`] from the spec's single-value JSON form.
///
/// Explicit per type rather than routed through a cast, because the two differ:
/// the spec spells a date as `"2023-01-01"` and a decimal as a string, and a
/// cast that guessed would accept one column's spelling for another's.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] when the value does not match the column's type.
fn datum_from_json(value: &Value, primitive: &PrimitiveType) -> Result<Datum> {
    let wrong = |expected: &str| {
        invalid(format!(
            "a filter literal for a {primitive} column must be {expected}, got {value}"
        ))
    };

    match primitive {
        PrimitiveType::Boolean => value
            .as_bool()
            .map(Datum::bool)
            .ok_or_else(|| wrong("a boolean")),
        PrimitiveType::Int => value
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .map(Datum::int)
            .ok_or_else(|| wrong("a 32-bit integer")),
        PrimitiveType::Long => value
            .as_i64()
            .map(Datum::long)
            .ok_or_else(|| wrong("an integer")),
        PrimitiveType::Float => value
            .as_f64()
            .map(|v| Datum::float(v as f32))
            .ok_or_else(|| wrong("a number")),
        PrimitiveType::Double => value
            .as_f64()
            .map(Datum::double)
            .ok_or_else(|| wrong("a number")),
        PrimitiveType::String => value
            .as_str()
            .map(Datum::string)
            .ok_or_else(|| wrong("a string")),
        PrimitiveType::Uuid => value
            .as_str()
            .ok_or_else(|| wrong("a UUID string"))
            .and_then(Datum::uuid_from_str),
        PrimitiveType::Date => match value {
            Value::String(text) => Datum::date_from_str(text),
            Value::Number(_) => value
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .map(Datum::date)
                .ok_or_else(|| wrong("a date string or a day count")),
            _ => Err(wrong("a date string or a day count")),
        },
        PrimitiveType::Time => value
            .as_str()
            .ok_or_else(|| wrong("a time string"))
            .and_then(Datum::time_from_str),
        PrimitiveType::Timestamp => match value {
            Value::String(text) => Datum::timestamp_from_str(text),
            Value::Number(_) => value
                .as_i64()
                .map(Datum::timestamp_micros)
                .ok_or_else(|| wrong("a timestamp string or microseconds")),
            _ => Err(wrong("a timestamp string or microseconds")),
        },
        PrimitiveType::Timestamptz => match value {
            Value::String(text) => Datum::timestamptz_from_str(text),
            Value::Number(_) => value
                .as_i64()
                .map(Datum::timestamptz_micros)
                .ok_or_else(|| wrong("a timestamp string or microseconds")),
            _ => Err(wrong("a timestamp string or microseconds")),
        },
        PrimitiveType::TimestampNs => value
            .as_i64()
            .map(Datum::timestamp_nanos)
            .ok_or_else(|| wrong("nanoseconds")),
        PrimitiveType::TimestamptzNs => value
            .as_i64()
            .map(Datum::timestamptz_nanos)
            .ok_or_else(|| wrong("nanoseconds")),
        PrimitiveType::Decimal { .. } => value
            .as_str()
            .ok_or_else(|| wrong("a decimal string"))
            .and_then(Datum::decimal_from_str)
            .and_then(|datum| datum.to(&Type::Primitive(primitive.clone()))),
        PrimitiveType::Fixed(_) => value
            .as_str()
            .ok_or_else(|| wrong("a hex string"))
            .and_then(from_hex)
            .map(Datum::fixed),
        PrimitiveType::Binary => value
            .as_str()
            .ok_or_else(|| wrong("a hex string"))
            .and_then(from_hex)
            .map(Datum::binary),
    }
}

// ============================================================================
// Reading a predicate without a schema
// ============================================================================

/// Checks that `json` is a well-formed predicate, without binding it.
///
/// Used where there is no table in scope — validating a `@row_filter` when the
/// policy set is loaded. A filter that cannot be read is a startup failure, for
/// the same reason a policy that does not typecheck is: a restriction that
/// silently does not apply is worse than one that refuses to install.
///
/// Shape only. Whether a column exists and whether a literal fits it are
/// questions about a table, and one policy covers tables that do not exist yet.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] naming what could not be read.
pub fn validate_shape(json: &Value) -> Result<()> {
    if json.as_bool().is_some() {
        return Ok(());
    }

    let object = json
        .as_object()
        .ok_or_else(|| invalid("a predicate must be a boolean or an expression object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a predicate expression needs a 'type'"))?;

    match kind {
        "true" | "false" => Ok(()),
        "and" | "or" => {
            validate_shape(child(object, "left")?)?;
            validate_shape(child(object, "right")?)
        }
        "not" => validate_shape(child(object, "child")?),
        "is-null" | "not-null" | "is-nan" | "not-nan" => operand_name(object).map(|_| ()),
        "lt" | "lt-eq" | "gt" | "gt-eq" | "eq" | "not-eq" | "starts-with" | "not-starts-with" => {
            comparison_operand(object)?;
            object
                .get("right")
                .or_else(|| object.get("value"))
                .map(|_| ())
                .ok_or_else(|| invalid(format!("comparison '{kind}' needs a value")))
        }
        "in" | "not-in" => {
            operand_name(object)?;
            object
                .get("values")
                .map(|_| ())
                .ok_or_else(|| invalid(format!("'{kind}' needs 'values'")))
        }
        // Unknown operators are widened at bind time rather than refused, so
        // refusing them here would contradict that.
        _ => Ok(()),
    }
}

/// Every column a predicate names, without binding it.
///
/// Exact, because the grammar says where a column reference can appear. That is
/// what a filter written as JSON buys over one written as an opaque string: an
/// identifier scan over SQL text has to over-report, and this does not.
///
/// A term this catalog cannot bind — a transform, a function application, a
/// field id — contributes no name. It also contributes no pruning, so a caller
/// asking "is this filter partition-aligned" gets `false` from the absence,
/// which is the safe direction.
pub fn referenced_columns(json: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_columns(json, &mut names);
    names
}

fn collect_columns(json: &Value, names: &mut BTreeSet<String>) {
    let Some(object) = json.as_object() else {
        return;
    };
    let Some(kind) = object.get("type").and_then(Value::as_str) else {
        return;
    };

    match kind {
        "and" | "or" => {
            for side in ["left", "right"] {
                if let Some(value) = object.get(side) {
                    collect_columns(value, names);
                }
            }
        }
        "not" => {
            if let Some(value) = object.get("child") {
                collect_columns(value, names);
            }
        }
        _ => {
            for key in ["child", "term", "left"] {
                if let Some(value) = object.get(key)
                    && let Ok(Some(name)) = reference_name(value)
                {
                    names.insert(name);
                }
            }
        }
    }
}
