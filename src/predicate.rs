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
//!
//! # A policy filter never widens
//!
//! That argument holds for a filter the *client* sent, where a superset is safe:
//! the engine applies the predicate itself, so extra files cost time and not
//! correctness.
//!
//! It inverts for a Cedar `@row_filter`, which is a restriction. A superset is a
//! *weaker* restriction, and an unbindable term widening to `AlwaysTrue` turns
//! `@row_filter("region = 'EU'")` into no filter at all, silently, at the moment
//! it was supposed to bite.
//!
//! So the two callers parse with different [`Strictness`]. A policy filter that
//! cannot be bound to *this* table is refused, exactly like one naming a column
//! the table does not have. Load-time validation cannot catch it — there is no
//! table in hand then, only a predicate shape.

use std::collections::BTreeSet;

use iceberg::expr::{Predicate, Reference};
use iceberg::spec::{Datum, NestedFieldRef, PrimitiveType, SchemaRef, Type};
use iceberg::{Error, ErrorKind, Result};
use serde_json::{Map, Value};

/// How a filter's column names are matched against the schema.
///
/// `planTableScan` carries a `case-sensitive` flag, and the scan builder is told
/// about it — but binding a literal to its column happens *here*, because the
/// literal's type comes from the schema field. Read in one place and not the
/// other, `case-sensitive: false` still answers `400` for a name differing only
/// in case — the one thing the flag exists to allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaseSensitivity {
    /// Names must match exactly. The Iceberg default.
    #[default]
    Sensitive,
    /// Names match ignoring case.
    Insensitive,
}

impl CaseSensitivity {
    /// From the boolean the wire carries.
    pub const fn from_flag(case_sensitive: bool) -> Self {
        if case_sensitive {
            Self::Sensitive
        } else {
            Self::Insensitive
        }
    }
}

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

/// What happens to a term this catalog cannot bind.
///
/// See the module docs: the answer depends entirely on whether the predicate is
/// a *request* or a *restriction*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// Widen it. For a filter the client sent, where a superset is safe.
    Widen,
    /// Refuse it. For a policy `@row_filter`, where a superset is a weakened
    /// restriction and therefore a security failure.
    Bindable,
}

/// Parses a **client** filter against `schema`, widening what it cannot bind.
///
/// See the module docs for how unsupported and malformed expressions differ.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] naming what was wrong.
pub fn parse_predicate(
    json: &Value,
    schema: &SchemaRef,
    case: CaseSensitivity,
) -> Result<Predicate> {
    parse_with_polarity(json, schema, case, true, Strictness::Widen)
}

/// Parses a **policy** filter against `schema`, refusing what it cannot bind.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] naming what was wrong, including a term that would
/// have been widened. A restriction that cannot be applied to this table must be
/// reported rather than silently dropped — see the module docs.
pub fn parse_policy_predicate(
    json: &Value,
    schema: &SchemaRef,
    case: CaseSensitivity,
) -> Result<Predicate> {
    parse_with_polarity(json, schema, case, true, Strictness::Bindable)
}

/// The value an unbindable sub-expression widens to, given its polarity — or an
/// error, when the predicate is a restriction that must not be weakened.
fn widen(positive: bool, strictness: Strictness, what: &str) -> Result<Predicate> {
    match strictness {
        Strictness::Widen => Ok(if positive {
            Predicate::AlwaysTrue
        } else {
            Predicate::AlwaysFalse
        }),
        Strictness::Bindable => Err(invalid(format!(
            "{what} cannot be bound by this catalog. In a filter that catalog is free to \
             widen; in a policy row filter widening would remove the restriction, so it is \
             refused instead."
        ))),
    }
}

/// Parses one node, knowing whether it sits under an even number of negations.
fn parse_with_polarity(
    json: &Value,
    schema: &SchemaRef,
    case: CaseSensitivity,
    positive: bool,
    strictness: Strictness,
) -> Result<Predicate> {
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
            let left =
                parse_with_polarity(child(object, "left")?, schema, case, positive, strictness)?;
            let right =
                parse_with_polarity(child(object, "right")?, schema, case, positive, strictness)?;
            Ok(if kind == "and" {
                left.and(right)
            } else {
                left.or(right)
            })
        }

        "not" => {
            Ok(
                parse_with_polarity(child(object, "child")?, schema, case, !positive, strictness)?
                    .negate(),
            )
        }

        "is-null" | "not-null" | "is-nan" | "not-nan" => {
            let Some(name) = operand_name(object)? else {
                return widen(positive, strictness, &format!("the term of '{kind}'"));
            };
            // Bound against the schema like every other column reference. A
            // unary predicate carries no literal to type, which is how this came
            // to be the one operator family that skipped the lookup — and the
            // omission was not cosmetic. `@row_filter` promises that a filter
            // naming a column *this* table has not is refused, so the
            // restriction can never silently fail to apply; without the lookup
            // `is-null` on a misspelled column sailed past that check and failed
            // later, deeper, as somebody else's error.
            let field = field_named(schema, &name, case)?;

            // `is-nan` asks whether a floating-point value is NaN. No other type
            // has one, so on any other column the question is malformed rather
            // than merely false — and answering it `false` would let
            // `not-nan` quietly select every row of a column that cannot have
            // one.
            if matches!(kind, "is-nan" | "not-nan")
                && !matches!(
                    primitive_type(&field)?,
                    PrimitiveType::Float | PrimitiveType::Double
                )
            {
                return Err(invalid(format!(
                    "'{kind}' applies to a float or double column, and '{}' is not one",
                    field.name
                )));
            }

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
                return widen(positive, strictness, &format!("the term of '{kind}'"));
            };
            let field = field_named(schema, &name, case)?;
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
                return widen(positive, strictness, &format!("the term of '{kind}'"));
            };
            let field = field_named(schema, &name, case)?;
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
            widen(positive, strictness, &format!("the operator '{other}'"))
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
fn field_named(schema: &SchemaRef, name: &str, case: CaseSensitivity) -> Result<NestedFieldRef> {
    let field = match case {
        CaseSensitivity::Sensitive => schema.field_by_name(name),
        CaseSensitivity::Insensitive => schema.field_by_name_case_insensitive(name),
    };

    field.cloned().ok_or_else(|| {
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

/// Nanoseconds since the epoch, from the spec's local-time timestamp string.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] for text that is not a timestamp, or one outside
/// the range nanoseconds can express (roughly 1677–2262).
fn nanos_from_naive(text: &str) -> Result<i64> {
    text.parse::<chrono::NaiveDateTime>()
        .map_err(|e| invalid(format!("a timestamp_ns literal is not a timestamp: {e}")))?
        .and_utc()
        .timestamp_nanos_opt()
        .ok_or_else(|| invalid("a timestamp_ns literal is outside the range nanoseconds hold"))
}

/// The same, for the offset-carrying form a `timestamptz_ns` literal takes.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] for text that is not an RFC 3339 timestamp, or one
/// outside the range nanoseconds can express.
fn nanos_from_offset(text: &str) -> Result<i64> {
    chrono::DateTime::parse_from_rfc3339(text)
        .map_err(|e| invalid(format!("a timestamptz_ns literal is not a timestamp: {e}")))?
        .timestamp_nanos_opt()
        .ok_or_else(|| invalid("a timestamptz_ns literal is outside the range nanoseconds hold"))
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
        // The spec spells every timestamp as a string; the integer form is
        // accepted beside it for the same reason it is on the microsecond types
        // above — engines send it. `iceberg-rust` has no `_from_str` for the
        // nanosecond types, so the string is parsed here rather than refused,
        // which is what made `timestamp_ns` the one temporal column a filter
        // could not name the way the spec writes it.
        PrimitiveType::TimestampNs => match value {
            Value::String(text) => nanos_from_naive(text).map(Datum::timestamp_nanos),
            Value::Number(_) => value
                .as_i64()
                .map(Datum::timestamp_nanos)
                .ok_or_else(|| wrong("a timestamp string or nanoseconds")),
            _ => Err(wrong("a timestamp string or nanoseconds")),
        }
        .map_err(|_| wrong("a timestamp string or nanoseconds")),
        PrimitiveType::TimestamptzNs => match value {
            Value::String(text) => nanos_from_offset(text).map(Datum::timestamptz_nanos),
            Value::Number(_) => value
                .as_i64()
                .map(Datum::timestamptz_nanos)
                .ok_or_else(|| wrong("a timestamp string or nanoseconds")),
            _ => Err(wrong("a timestamp string or nanoseconds")),
        }
        .map_err(|_| wrong("a timestamp string or nanoseconds")),
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

/// Checks that `json` is a policy `@row_filter` this catalog will be able to
/// bind, without a table in hand.
///
/// Run when a policy set is loaded. A filter that cannot be read is a startup
/// failure, for the same reason a policy that does not typecheck is: a
/// restriction that silently does not apply is worse than one that refuses to
/// install.
///
/// # It asks the *policy* question, not the client one
///
/// The obvious version of this checks shape and lets an unrecognised operator
/// through, on the grounds that [`parse_predicate`] widens one. That is right
/// for a filter a client sends and wrong here, and the two answers used to
/// disagree: a `@row_filter` is parsed with [`Strictness::Bindable`], which
/// *refuses* an operator or a term it cannot bind (see the module docs). So a
/// misspelled `"type": "equals"`, or a term wrapped in a `transform`, installed
/// cleanly at startup and then turned every `planTableScan` against every table
/// into a `403` — with the load-time check that exists to catch exactly that
/// having said nothing.
///
/// So this refuses what the binder will refuse. The two remaining questions —
/// whether a column exists, and whether a literal fits it — are questions about
/// a *table*, and one policy covers tables that do not exist yet; those stay at
/// plan time, where there is a schema.
///
/// # Errors
///
/// [`ErrorKind::DataInvalid`] naming what could not be read, or what this
/// catalog cannot bind.
pub fn validate_policy_filter(json: &Value) -> Result<()> {
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

    /// Refuses a term the binder would refuse: one naming no column it can
    /// resolve, which is a transform, a function application or a field id.
    fn bindable_operand(name: Option<String>, kind: &str) -> Result<()> {
        name.map(|_| ()).ok_or_else(|| {
            invalid(format!(
                "the term of '{kind}' is a transform, a function application or a field id, \
                 none of which this catalog can bind. In a client's filter that is widened \
                 away; in a policy row filter widening would remove the restriction, so it \
                 is refused."
            ))
        })
    }

    match kind {
        "true" | "false" => Ok(()),
        "and" | "or" => {
            validate_policy_filter(child(object, "left")?)?;
            validate_policy_filter(child(object, "right")?)
        }
        "not" => validate_policy_filter(child(object, "child")?),
        "is-null" | "not-null" | "is-nan" | "not-nan" => {
            bindable_operand(operand_name(object)?, kind)
        }
        "lt" | "lt-eq" | "gt" | "gt-eq" | "eq" | "not-eq" | "starts-with" | "not-starts-with" => {
            bindable_operand(comparison_operand(object)?, kind)?;
            object
                .get("right")
                .or_else(|| object.get("value"))
                .map(|_| ())
                .ok_or_else(|| invalid(format!("comparison '{kind}' needs a value")))
        }
        "in" | "not-in" => {
            bindable_operand(operand_name(object)?, kind)?;
            object
                .get("values")
                .map(|_| ())
                .ok_or_else(|| invalid(format!("'{kind}' needs 'values'")))
        }
        other => Err(invalid(format!(
            "'{other}' is not an operator this catalog binds. A client's filter widens one \
             away, which costs a superset of files; a policy row filter cannot, because a \
             weaker restriction is no restriction. Spell the filter with the operators in \
             the Iceberg REST `Expression` grammar."
        ))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use iceberg::spec::{NestedField, Schema};
    use serde_json::json;
    use std::sync::Arc;

    fn schema() -> SchemaRef {
        Arc::new(
            Schema::builder()
                .with_fields(vec![
                    NestedField::required(1, "region", Type::Primitive(PrimitiveType::String))
                        .into(),
                    NestedField::optional(2, "count", Type::Primitive(PrimitiveType::Long)).into(),
                    NestedField::optional(3, "ts", Type::Primitive(PrimitiveType::Date)).into(),
                    NestedField::optional(4, "score", Type::Primitive(PrimitiveType::Double))
                        .into(),
                ])
                .build()
                .expect("schema builds"),
        )
    }

    fn parse(json: Value) -> Result<Predicate> {
        parse_predicate(&json, &schema(), CaseSensitivity::Sensitive)
    }

    /// The inversion: widening is right for a request and wrong for a
    /// restriction. An unbindable term in a `@row_filter` would become
    /// `AlwaysTrue` and remove the filter at the moment it was meant to bite.
    #[test]
    fn a_policy_filter_refuses_what_a_client_filter_widens() {
        let schema = schema();
        let unbindable = json!({
            "type": "eq",
            "term": { "type": "transform", "transform": "day", "term": "ts" },
            "value": 1
        });

        assert_eq!(
            parse_predicate(&unbindable, &schema, CaseSensitivity::Sensitive).unwrap(),
            Predicate::AlwaysTrue,
            "a client filter widens: a superset costs time, not correctness"
        );

        let err = parse_policy_predicate(&unbindable, &schema, CaseSensitivity::Sensitive)
            .expect_err("a policy filter must refuse rather than widen");
        assert_eq!(err.kind(), ErrorKind::DataInvalid);
    }

    /// Refusal must reach a term nested anywhere, including under a negation
    /// where widening flips to `AlwaysFalse` and would silently select nothing.
    #[test]
    fn a_policy_filter_refuses_an_unbindable_term_at_any_depth() {
        let schema = schema();
        for filter in [
            json!({
                "type": "and",
                "left":  { "type": "eq", "term": "region", "value": "EU" },
                "right": { "type": "some-future-operator", "term": "region" }
            }),
            json!({
                "type": "not",
                "child": { "type": "some-future-operator", "term": "region" }
            }),
        ] {
            assert!(
                parse_policy_predicate(&filter, &schema, CaseSensitivity::Sensitive).is_err(),
                "should have been refused: {filter}"
            );
        }
    }

    /// A policy filter this catalog *can* bind is parsed exactly as a client's
    /// is — strictness changes what happens to the unbindable, nothing else.
    #[test]
    fn a_bindable_policy_filter_parses_identically() {
        let schema = schema();
        let filter = json!({ "type": "eq", "term": "region", "value": "EU" });
        assert_eq!(
            parse_policy_predicate(&filter, &schema, CaseSensitivity::Sensitive).unwrap(),
            parse_predicate(&filter, &schema, CaseSensitivity::Sensitive).unwrap()
        );
    }

    /// A term outside the grammar contributes nothing, so the plan is a
    /// superset. Dropping it instead would prune against a predicate nobody
    /// wrote and return too few files.
    #[test]
    fn an_unbindable_term_widens_to_everything() {
        let filter = json!({
            "type": "eq",
            "term": { "type": "transform", "transform": "day", "term": "ts" },
            "value": 1
        });
        assert_eq!(parse(filter).unwrap(), Predicate::AlwaysTrue);
    }

    /// The whole point of tracking polarity. Under one negation the widened
    /// value has to be `AlwaysFalse`, so that negating it yields "everything"
    /// rather than "nothing" — the direction that would drop real files.
    #[test]
    fn a_negated_unbindable_term_still_widens_to_everything() {
        let filter = json!({
            "type": "not",
            "child": {
                "type": "eq",
                "term": { "type": "transform", "transform": "day", "term": "ts" },
                "value": 1
            }
        });
        assert_eq!(parse(filter).unwrap(), Predicate::AlwaysTrue);
    }

    /// Two negations put the term back in positive position.
    #[test]
    fn double_negation_returns_to_positive_polarity() {
        let unbindable = json!({
            "type": "eq",
            "term": { "type": "transform", "transform": "day", "term": "ts" },
            "value": 1
        });
        let filter = json!({
            "type": "not",
            "child": { "type": "not", "child": unbindable }
        });
        assert_eq!(parse(filter).unwrap(), Predicate::AlwaysTrue);
    }

    /// A widened term inside a negated conjunction must not collapse the whole
    /// expression: `NOT(bindable AND unbindable)` still has to admit every file
    /// the bindable half would.
    #[test]
    fn widening_inside_a_negated_conjunction_stays_a_superset() {
        let filter = json!({
            "type": "not",
            "child": {
                "type": "and",
                "left":  { "type": "eq", "term": "region", "value": "EU" },
                "right": {
                    "type": "eq",
                    "term": { "type": "transform", "transform": "day", "term": "ts" },
                    "value": 1
                }
            }
        });
        assert_eq!(parse(filter).unwrap(), Predicate::AlwaysTrue);
    }

    /// A column the table does not have is a typo, not a newer grammar.
    /// Widening it would turn the typo into a silent full scan.
    #[test]
    fn an_unknown_column_is_refused_rather_than_widened() {
        let err = parse(json!({ "type": "eq", "term": "nope", "value": "x" })).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DataInvalid);
        assert!(err.to_string().contains("nope"));
    }

    /// The same rule as `an_unknown_column_is_refused_rather_than_widened`, for
    /// the operators that carry no literal.
    ///
    /// A unary predicate has nothing to type-check, so nothing else forces it to
    /// look the column up. It matters most for a `@row_filter`, whose promise is
    /// that a filter naming a column this table has not is *refused* — a
    /// restriction must never silently fail to apply.
    #[test]
    fn a_unary_predicate_on_an_unknown_column_is_an_error() {
        let schema = schema();
        for kind in ["is-null", "not-null", "is-nan", "not-nan"] {
            let filter = json!({ "type": kind, "term": "nope" });
            let err = parse_predicate(&filter, &schema, CaseSensitivity::Sensitive)
                .expect_err("an unknown column is a typo, not a newer grammar");
            assert_eq!(err.kind(), ErrorKind::DataInvalid);
            assert!(err.to_string().contains("nope"), "{kind}: {err}");

            parse_policy_predicate(&filter, &schema, CaseSensitivity::Sensitive)
                .expect_err("a policy filter must refuse it too");
        }
    }

    /// Only a float or a double can be NaN. On any other column the question is
    /// malformed, and answering it `false` would let `not-nan` select every row
    /// of a column that cannot have one.
    #[test]
    fn a_nan_check_on_a_non_floating_column_is_refused() {
        let schema = schema();
        for kind in ["is-nan", "not-nan"] {
            let err = parse_predicate(
                &json!({ "type": kind, "term": "region" }),
                &schema,
                CaseSensitivity::Sensitive,
            )
            .expect_err("region is a string");
            assert_eq!(err.kind(), ErrorKind::DataInvalid);
            assert!(err.to_string().contains("region"), "{kind}: {err}");
        }
    }

    #[test]
    fn a_unary_predicate_on_a_known_column_still_binds() {
        assert!(parse(json!({ "type": "is-null", "term": "ts" })).is_ok());
        assert!(parse(json!({ "type": "not-null", "child": "region" })).is_ok());
        assert!(parse(json!({ "type": "is-nan", "term": "score" })).is_ok());
        assert!(parse(json!({ "type": "not-nan", "term": "score" })).is_ok());
    }

    #[test]
    fn a_literal_that_does_not_fit_its_column_is_refused() {
        let err =
            parse(json!({ "type": "eq", "term": "count", "value": "not-a-number" })).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DataInvalid);
    }

    /// `case-sensitive: false` is a request to bind by name ignoring case, and
    /// binding is what happens here. Read only in the scan builder, this path
    /// answers `400` for exactly the names the flag allows.
    #[test]
    fn case_insensitive_binding_matches_a_differently_cased_column() {
        let filter = json!({ "type": "eq", "term": "REGION", "value": "EU" });
        assert!(
            parse_predicate(&filter, &schema(), CaseSensitivity::Sensitive).is_err(),
            "the default binds exactly"
        );
        assert!(parse_predicate(&filter, &schema(), CaseSensitivity::Insensitive).is_ok());
    }

    #[test]
    fn a_bare_boolean_is_a_filter() {
        assert_eq!(parse(json!(true)).unwrap(), Predicate::AlwaysTrue);
        assert_eq!(parse(json!(false)).unwrap(), Predicate::AlwaysFalse);
    }

    /// The columns a filter names are read from the grammar, so nothing has to
    /// be guessed — a literal that looks like a column name is not one.
    #[test]
    fn referenced_columns_reads_only_references() {
        let filter = json!({
            "type": "and",
            "left":  { "type": "eq", "term": "region", "value": "count" },
            "right": { "type": "is-null", "child": { "type": "reference", "name": "ts" } }
        });
        assert_eq!(
            referenced_columns(&filter).into_iter().collect::<Vec<_>>(),
            vec!["region".to_string(), "ts".to_string()]
        );
    }

    /// The check a policy set is validated with at load. It knows nothing about
    /// tables, so it must accept a column no table has yet.
    #[test]
    fn policy_filter_validation_accepts_an_unknown_column_and_rejects_a_non_filter() {
        assert!(
            validate_policy_filter(&json!({ "type": "eq", "term": "whatever", "value": 1 }))
                .is_ok()
        );
        assert!(validate_policy_filter(&json!({ "type": "eq" })).is_err());
        assert!(validate_policy_filter(&json!("region = 'EU'")).is_err());
    }

    /// The gap this check exists to close. A `@row_filter` is parsed with
    /// [`Strictness::Bindable`], which refuses an operator it cannot bind — so
    /// accepting one at load meant a misspelled operator installed cleanly and
    /// then turned every plan against every table into a `403`, with the
    /// load-time check saying nothing.
    #[test]
    fn a_policy_filter_naming_an_unbindable_operator_is_refused_at_load() {
        let misspelled = json!({ "type": "equals", "term": "region", "value": "EU" });
        assert!(validate_policy_filter(&misspelled).is_err());

        // And the runtime binder agrees, which is the invariant: what installs
        // is exactly what binds.
        let schema = schema();
        assert!(parse_policy_predicate(&misspelled, &schema, CaseSensitivity::Sensitive).is_err());
    }

    /// The same, for a *term* the binder cannot resolve to a column.
    #[test]
    fn a_policy_filter_over_a_transformed_term_is_refused_at_load() {
        let transformed = json!({
            "type": "eq",
            "term": { "type": "transform", "transform": "day", "term": "ts" },
            "value": 1
        });
        assert!(validate_policy_filter(&transformed).is_err());
        assert!(
            parse_policy_predicate(&transformed, &schema(), CaseSensitivity::Sensitive).is_err()
        );
    }

    /// The nanosecond timestamp types take the spec's string spelling, like
    /// their microsecond twins. Accepting only the integer made `timestamp_ns`
    /// the one temporal column a filter could not name the documented way.
    #[test]
    fn a_nanosecond_timestamp_literal_reads_the_spec_spelling() {
        let schema = Arc::new(
            Schema::builder()
                .with_fields(vec![
                    NestedField::optional(1, "ns", Type::Primitive(PrimitiveType::TimestampNs))
                        .into(),
                    NestedField::optional(2, "nstz", Type::Primitive(PrimitiveType::TimestamptzNs))
                        .into(),
                ])
                .build()
                .expect("schema builds"),
        );

        let from_string = |term: &str, value: &str| {
            parse_predicate(
                &json!({ "type": "eq", "term": term, "value": value }),
                &schema,
                CaseSensitivity::Sensitive,
            )
        };

        assert!(from_string("ns", "2024-01-01T00:00:00.000000001").is_ok());
        assert!(from_string("nstz", "2024-01-01T00:00:00.000000001+00:00").is_ok());

        // The integer form still works, because engines send it.
        assert!(
            parse_predicate(
                &json!({ "type": "eq", "term": "ns", "value": 1_700_000_000_000_000_000i64 }),
                &schema,
                CaseSensitivity::Sensitive,
            )
            .is_ok()
        );

        // And something that is neither is still a `400`.
        assert!(from_string("ns", "not a timestamp").is_err());
    }

    /// A client's filter is the other way round: the same two expressions widen
    /// rather than fail, because a superset of files costs time and not
    /// correctness.
    #[test]
    fn a_client_filter_still_widens_what_a_policy_filter_refuses() {
        let schema = schema();
        for filter in [
            json!({ "type": "equals", "term": "region", "value": "EU" }),
            json!({
                "type": "eq",
                "term": { "type": "transform", "transform": "day", "term": "ts" },
                "value": 1
            }),
        ] {
            assert_eq!(
                parse_predicate(&filter, &schema, CaseSensitivity::Sensitive).expect("widens"),
                Predicate::AlwaysTrue
            );
        }
    }
}
