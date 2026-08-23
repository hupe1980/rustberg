//! Server-side scan planning: `POST …/tables/{table}/plan`.
//!
//! The catalog reads the snapshot's manifests, prunes the files a filter cannot
//! match, and hands the engine the surviving scan tasks. That moves the manifest
//! read off every engine and onto one server that can cache it — and it is the
//! step that makes a *policy* decision about which files a caller is told about
//! at all.
//!
//! # Policy is part of the filter
//!
//! A `@row_filter` on a matching permit is an Iceberg [JSON
//! predicate](crate::predicate), so it is conjoined with the client's own filter
//! before pruning, and both halves come back as the task's `residual-filter`. A
//! caller under a row filter is therefore told about *fewer files* than one
//! without — which is the first half of row-level security, and the half a
//! catalog can actually perform.
//!
//! # What planning is, and is not
//!
//! Planning **selects**; on its own it does not enforce. A client that ignores
//! the plan and fetches a file directly still succeeds, because it may still
//! hold a credential. Planning becomes enforcement only when paired with
//! something that makes an unplanned file unfetchable, and nothing here does
//! that: a signature is confined to the whole table, not to the files one plan
//! named. So a filtered table is still refused a credential and a signature —
//! planning narrows a *cooperating* client, and says so.
//!
//! # Answered synchronously
//!
//! The spec allows `planTableScan` to answer `completed` with the tasks inline,
//! in which case `plan-tasks` and `fetchScanTasks` are never used. Rustberg
//! answers that way and issues no work to poll for: a plan id would mean
//! per-plan server-side state, which a replica set cannot share without a
//! session store, and that trades the stateless-replica property for an
//! optimisation that only matters on scans large enough to be rare.
//!
//! The `plan-id` the response carries is therefore an identifier for a plan that
//! is already finished. `GET`ting it reports that nothing is in progress, and
//! cancelling it succeeds because there is nothing to cancel.

use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use iceberg::spec::{DataContentType, DataFile, Datum, ManifestStatus, Schema, Struct, Type};
use iceberg::table::Table;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::extract::{Json, TablePath};
use super::guard::{self, Target};
use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, Obligations, RequestFacts};
use crate::error::{AppError, Result};
use crate::predicate::parse_predicate;

/// Most files one plan may return.
///
/// A plan is one response, so an unbounded scan is an unbounded body. Past this
/// the request is refused with a message naming the bound, rather than
/// truncated: a silently short plan is a query that quietly reads less than it
/// asked for.
const MAX_TASKS: usize = 25_000;

// ============================================================================
// Request
// ============================================================================

/// `PlanTableScanRequest`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PlanTableScanRequest {
    /// Snapshot to scan. Defaults to the table's current snapshot.
    #[serde(default)]
    pub snapshot_id: Option<i64>,
    /// Schema fields to project.
    #[serde(default)]
    pub select: Option<Vec<String>>,
    /// Filter, as an Iceberg JSON expression.
    #[serde(default)]
    pub filter: Option<Value>,
    /// Hint only; the plan is complete regardless.
    #[serde(default)]
    pub min_rows_requested: Option<i64>,
    /// Whether field names match case-sensitively.
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
    /// Use the schema the snapshot was written with, rather than the table's.
    #[serde(default)]
    pub use_snapshot_schema: bool,
    /// Incremental scan start (exclusive).
    #[serde(default)]
    pub start_snapshot_id: Option<i64>,
    /// Incremental scan end (inclusive).
    #[serde(default)]
    pub end_snapshot_id: Option<i64>,
    /// Fields to send column statistics for. Absent means none.
    #[serde(default)]
    pub stats_fields: Option<Vec<String>>,
}

const fn default_true() -> bool {
    true
}

// ============================================================================
// Response
// ============================================================================

/// `CompletedPlanningWithIDResult`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct CompletedPlan {
    status: &'static str,
    plan_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    delete_files: Vec<Value>,
    file_scan_tasks: Vec<Value>,
}

// ============================================================================
// Handler
// ============================================================================

/// `POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan`
///
/// # Errors
///
/// - `404` for a table the caller cannot see, or a snapshot that does not exist.
/// - `403` when a policy filter cannot be applied to this table, or when
///   `stats-fields` names a masked column.
/// - `400` for a filter this catalog cannot bind, or a scan larger than
///   this catalog's per-plan file limit.
/// - `501` for an incremental scan, which is not implemented.
pub async fn plan_table_scan(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    table: TablePath,
    _headers: HeaderMap,
    Json(payload): Json<PlanTableScanRequest>,
) -> Result<Response> {
    let (namespace, name) = (table.namespace().clone(), table.name().to_string());

    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&name),
        Action::Read,
    )
    .await?;

    if !state.capabilities.scan_planning {
        return Err(AppError::NotSupported(
            "This catalog federates a mount whose storage it does not manage, so it \
             cannot read the manifests a scan plan is built from. Plan client-side \
             against the metadata `loadTable` returns."
                .to_string(),
        ));
    }

    if payload.start_snapshot_id.is_some() || payload.end_snapshot_id.is_some() {
        return Err(AppError::NotSupported(
            "Incremental scan planning (start-snapshot-id / end-snapshot-id) is not \
             implemented. Plan the snapshot directly instead."
                .to_string(),
        ));
    }

    let loaded = state
        .catalog
        .load_table(&iceberg::TableIdent::new(namespace, name))
        .await?;

    let tasks = build_plan(&loaded, &payload, &authorized.obligations).await?;

    Ok((StatusCode::OK, axum::Json(tasks)).into_response())
}

/// `GET …/plan/{plan-id}`
///
/// Rustberg answers every plan synchronously, so there is never a plan in
/// progress to report on. The spec's error for a plan id the server does not
/// know is what this is.
///
/// # Errors
///
/// Always [`AppError::NoSuchPlan`], after the caller has been authorized — an
/// unauthorized caller must not learn that a plan id is unknown either.
pub async fn fetch_planning_result(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    table: TablePath,
) -> Result<Response> {
    guard::authorize(
        &state,
        &principal,
        &request,
        table.namespace(),
        Target::Table(table.name()),
        Action::Read,
    )
    .await?;

    Err(AppError::NoSuchPlan(
        "This catalog completes every plan in the response to planTableScan, so there is \
         no plan to poll for."
            .to_string(),
    ))
}

/// `DELETE …/plan/{plan-id}`
///
/// Cancelling a plan that already completed is a no-op, and reporting it as one
/// is what lets a client clean up unconditionally.
///
/// # Errors
///
/// Whatever the guard reports for a table the caller cannot see or use.
pub async fn cancel_planning(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    table: TablePath,
) -> Result<StatusCode> {
    guard::authorize(
        &state,
        &principal,
        &request,
        table.namespace(),
        Target::Table(table.name()),
        Action::Read,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Planning
// ============================================================================

/// Plans the scan and encodes it in the shape the spec defines.
async fn build_plan(
    table: &Table,
    request: &PlanTableScanRequest,
    obligations: &Obligations,
) -> Result<CompletedPlan> {
    let metadata = table.metadata();

    let snapshot = match request.snapshot_id {
        Some(id) => Some(metadata.snapshot_by_id(id).ok_or_else(|| {
            AppError::NoSuchSnapshot(format!("Snapshot {id} does not exist in this table"))
        })?),
        None => metadata.current_snapshot(),
    };

    let schema = match (request.use_snapshot_schema, snapshot) {
        (true, Some(snapshot)) => snapshot.schema(metadata).map_err(AppError::from)?,
        _ => metadata.current_schema().clone(),
    };

    // Validated before the empty-table shortcut below. A malformed filter must
    // be a `400` whether or not the table happens to hold data yet: accepting
    // one today and refusing it after the first commit is the worst possible
    // moment to find out.
    let requested = request
        .filter
        .as_ref()
        .map(|json| parse_predicate(json, &schema))
        .transpose()
        .map_err(AppError::from)?;

    // What policy permits this caller to see, as a predicate. Permits grant, so
    // the matching filters are OR-ed; the scan is the conjunction of that and
    // whatever the client asked for.
    let filter = match (requested, policy_predicate(obligations, &schema)?) {
        (Some(requested), Some(policy)) => Some(requested.and(policy)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    };

    let stats_fields = stats_field_ids(request.stats_fields.as_deref(), &schema, obligations)?;

    // The residual carries the policy filter too, or a cooperating engine
    // applies only half of what the plan was built from — and the half it drops
    // is the one policy cares about.
    let residual = residual_filter(request.filter.as_ref(), obligations);

    // A table with no snapshot has no files. That is a complete plan, not an
    // error: `CREATE TABLE` then `SELECT` is an ordinary sequence.
    let Some(snapshot) = snapshot else {
        return Ok(CompletedPlan {
            status: "completed",
            plan_id: new_plan_id(),
            delete_files: Vec::new(),
            file_scan_tasks: Vec::new(),
        });
    };

    let mut scan = table
        .scan()
        .snapshot_id(snapshot.snapshot_id())
        .with_case_sensitive(request.case_sensitive);
    if let Some(filter) = filter {
        scan = scan.with_filter(filter);
    }
    scan = match request.select.as_ref() {
        Some(columns) => scan.select(columns.clone()),
        None => scan.select_all(),
    };

    let tasks: Vec<iceberg::scan::FileScanTask> = scan
        .build()
        .map_err(AppError::from)?
        .plan_files()
        .await
        .map_err(AppError::from)?
        .try_collect()
        .await
        .map_err(AppError::from)?;

    if tasks.len() > MAX_TASKS {
        return Err(AppError::BadRequest(format!(
            "This scan plans {} files, over this catalog's limit of {MAX_TASKS} for one \
             response. Narrow the filter, or plan against a smaller snapshot.",
            tasks.len()
        )));
    }

    // Statistics are sent only for the fields the client named, and delete files
    // have to be described in full — both need the manifest entry rather than
    // the scan task, so the manifests are re-read only when one of them applies.
    let delete_paths: HashSet<&str> = tasks
        .iter()
        .flat_map(|task| task.deletes.iter().map(|d| d.file_path.as_str()))
        .collect();

    let wanted: HashSet<&str> = if stats_fields.is_some() {
        tasks
            .iter()
            .map(|task| task.data_file_path.as_str())
            .chain(delete_paths.iter().copied())
            .collect()
    } else {
        delete_paths.iter().copied().collect()
    };

    let files = if wanted.is_empty() {
        HashMap::new()
    } else {
        read_manifest_files(table, snapshot, &wanted).await?
    };

    // Delete files first: a task references them by index into this list.
    let mut delete_index: HashMap<String, usize> = HashMap::new();
    let mut delete_files = Vec::new();
    for path in &delete_paths {
        let (file, spec_id) = files.get(*path).ok_or_else(|| {
            AppError::Internal(format!(
                "the scan referenced delete file '{path}', which is not in the snapshot's \
                 manifests"
            ))
        })?;
        delete_index.insert((*path).to_string(), delete_files.len());
        delete_files.push(content_file_json(
            file,
            *spec_id,
            &schema,
            stats_fields.as_ref(),
        )?);
    }

    let mut file_scan_tasks = Vec::with_capacity(tasks.len());
    for task in &tasks {
        let data_file = match files.get(task.data_file_path.as_str()) {
            Some((file, spec_id)) => {
                content_file_json(file, *spec_id, &schema, stats_fields.as_ref())?
            }
            None => data_file_json_from_task(task)?,
        };

        let mut entry = Map::new();
        entry.insert("data-file".to_string(), data_file);

        if !task.deletes.is_empty() {
            let references: Vec<Value> = task
                .deletes
                .iter()
                .filter_map(|d| delete_index.get(&d.file_path))
                .map(|index| json!(index))
                .collect();
            entry.insert(
                "delete-file-references".to_string(),
                Value::Array(references),
            );
        }

        // The same residual on every task, rather than one narrowed per file.
        // That is always correct — the client applies it — and never claims a
        // pruning that did not happen.
        if let Some(residual) = residual.as_ref() {
            entry.insert("residual-filter".to_string(), residual.clone());
        }

        file_scan_tasks.push(Value::Object(entry));
    }

    Ok(CompletedPlan {
        status: "completed",
        plan_id: new_plan_id(),
        delete_files,
        file_scan_tasks,
    })
}

/// Names a plan that is already finished.
fn new_plan_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Reads the snapshot's manifests, keeping the entries `wanted` names.
async fn read_manifest_files(
    table: &Table,
    snapshot: &iceberg::spec::SnapshotRef,
    wanted: &HashSet<&str>,
) -> Result<HashMap<String, (DataFile, i32)>> {
    let manifest_list = table
        .manifest_list_reader(snapshot)
        .load()
        .await
        .map_err(AppError::from)?;

    let mut found = HashMap::new();
    for manifest_file in manifest_list.entries() {
        let manifest = manifest_file
            .load_manifest(table.file_io())
            .await
            .map_err(AppError::from)?;

        for entry in manifest.entries() {
            if entry.status() == ManifestStatus::Deleted {
                continue;
            }
            let path = entry.data_file().file_path();
            if wanted.contains(path) {
                // The spec id belongs to the manifest, not to the entry: a
                // `DataFile` does not carry it in public API.
                found.insert(
                    path.to_string(),
                    (entry.data_file().clone(), manifest_file.partition_spec_id),
                );
            }
        }

        if found.len() == wanted.len() {
            break;
        }
    }

    Ok(found)
}

/// The field ids to send statistics for, or `None` when the client asked for
/// none.
///
/// # Errors
///
/// [`AppError::BadRequest`] naming a field the schema does not have.
fn stats_field_ids(
    names: Option<&[String]>,
    schema: &Schema,
    obligations: &Obligations,
) -> Result<Option<HashSet<i32>>> {
    let Some(names) = names else { return Ok(None) };

    let mut ids = HashSet::new();
    for name in names {
        // Statistics carry a column's minimum and maximum value, so sending
        // them for a masked column publishes exactly what the mask hides.
        if obligations.column_masks.contains(name) {
            return Err(AppError::Forbidden(format!(
                "Policy withholds the column '{name}', and its statistics would name its \
                 minimum and maximum values."
            )));
        }

        let field = schema.field_by_name(name).ok_or_else(|| {
            AppError::BadRequest(format!(
                "stats-fields names '{name}', which this table has no"
            ))
        })?;
        ids.insert(field.id);
    }
    Ok(Some(ids))
}

/// What policy permits this caller to see, as one predicate.
///
/// The matching permits' filters are OR-ed, because permits grant: a caller
/// matched by a permit allowing `region = 'EU'` and one allowing
/// `region = 'US'` sees both. `None` means unrestricted, which is also what an
/// unannotated permit produces.
///
/// # Errors
///
/// [`AppError::Forbidden`] when a filter cannot be bound to *this* table, most
/// often because it names a column the table does not have. Refusing is the only
/// safe answer: a filter that cannot be applied is a restriction that would
/// silently not apply.
fn policy_predicate(
    obligations: &Obligations,
    schema: &iceberg::spec::SchemaRef,
) -> Result<Option<iceberg::expr::Predicate>> {
    let mut combined: Option<iceberg::expr::Predicate> = None;

    for filter in &obligations.row_filters {
        let predicate = parse_predicate(filter, schema).map_err(|e| {
            AppError::Forbidden(format!(
                "Policy attaches a row filter to this table that cannot be applied to it \
                 ({e}). Planning is refused rather than returning files the filter was \
                 meant to withhold."
            ))
        })?;
        combined = Some(match combined {
            Some(existing) => existing.or(predicate),
            None => predicate,
        });
    }

    Ok(combined)
}

/// The filter the client must still apply to the rows it reads.
///
/// The client's own filter conjoined with what policy permits. Both halves are
/// needed: pruning is conservative, so a file that survives may hold rows the
/// policy filter excludes, and an engine that applied only the half it sent
/// would read them.
fn residual_filter(requested: Option<&Value>, obligations: &Obligations) -> Option<Value> {
    let policy = obligations
        .row_filters
        .iter()
        .cloned()
        .reduce(|left, right| json!({ "type": "or", "left": left, "right": right }));

    match (requested, policy) {
        (Some(requested), Some(policy)) => {
            Some(json!({ "type": "and", "left": requested, "right": policy }))
        }
        (Some(only), None) => Some(only.clone()),
        (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

// ============================================================================
// Encoding a content file
// ============================================================================

/// Encodes a `DataFile` in the spec's `ContentFile` shape.
fn content_file_json(
    file: &DataFile,
    spec_id: i32,
    schema: &Schema,
    stats_fields: Option<&HashSet<i32>>,
) -> Result<Value> {
    let mut out = Map::new();

    out.insert(
        "content".to_string(),
        json!(match file.content_type() {
            DataContentType::Data => "data",
            DataContentType::PositionDeletes => "position-deletes",
            DataContentType::EqualityDeletes => "equality-deletes",
        }),
    );
    out.insert("file-path".to_string(), json!(file.file_path()));
    out.insert(
        "file-format".to_string(),
        json!(file.file_format().to_string().to_lowercase()),
    );
    out.insert("spec-id".to_string(), json!(spec_id));
    out.insert(
        "partition".to_string(),
        Value::Array(partition_json(file.partition())?),
    );
    out.insert(
        "file-size-in-bytes".to_string(),
        json!(file.file_size_in_bytes()),
    );
    out.insert("record-count".to_string(), json!(file.record_count()));

    if let Some(key_metadata) = file.key_metadata() {
        out.insert("key-metadata".to_string(), json!(to_hex(key_metadata)));
    }
    if let Some(offsets) = file.split_offsets()
        && !offsets.is_empty()
    {
        out.insert("split-offsets".to_string(), json!(offsets));
    }
    if let Some(sort_order_id) = file.sort_order_id() {
        out.insert("sort-order-id".to_string(), json!(sort_order_id));
    }
    if let Some(first_row_id) = file.first_row_id() {
        out.insert("first-row-id".to_string(), json!(first_row_id));
    }
    if let Some(equality_ids) = file.equality_ids()
        && !equality_ids.is_empty()
    {
        out.insert("equality-ids".to_string(), json!(equality_ids));
    }
    if let Some(offset) = file.content_offset() {
        out.insert("content-offset".to_string(), json!(offset));
    }
    if let Some(size) = file.content_size_in_bytes() {
        out.insert("content-size-in-bytes".to_string(), json!(size));
    }

    // Column statistics are sent only for the fields the client named. They
    // carry the min and max value of every column they describe, so sending
    // them unasked publishes the contents of columns a mask would hide.
    if let Some(wanted) = stats_fields {
        insert_count_map(&mut out, "column-sizes", file.column_sizes(), wanted);
        insert_count_map(&mut out, "value-counts", file.value_counts(), wanted);
        insert_count_map(
            &mut out,
            "null-value-counts",
            file.null_value_counts(),
            wanted,
        );
        insert_count_map(
            &mut out,
            "nan-value-counts",
            file.nan_value_counts(),
            wanted,
        );
        insert_value_map(
            &mut out,
            "lower-bounds",
            file.lower_bounds(),
            wanted,
            schema,
        )?;
        insert_value_map(
            &mut out,
            "upper-bounds",
            file.upper_bounds(),
            wanted,
            schema,
        )?;
    }

    Ok(Value::Object(out))
}

/// Encodes what a scan task knows, for the common case where the manifests were
/// not re-read.
///
/// The spec marks statistics optional, so a task without them is complete — and
/// a client that wants them asks with `stats-fields`.
fn data_file_json_from_task(task: &iceberg::scan::FileScanTask) -> Result<Value> {
    let mut out = Map::new();

    out.insert("content".to_string(), json!("data"));
    out.insert("file-path".to_string(), json!(task.data_file_path));
    out.insert(
        "file-format".to_string(),
        json!(task.data_file_format.to_string().to_lowercase()),
    );
    out.insert(
        "spec-id".to_string(),
        json!(
            task.partition_spec
                .as_ref()
                .map_or(0, |spec| spec.spec_id())
        ),
    );
    out.insert(
        "partition".to_string(),
        Value::Array(match task.partition.as_ref() {
            Some(partition) => partition_json(partition)?,
            None => Vec::new(),
        }),
    );
    out.insert(
        "file-size-in-bytes".to_string(),
        json!(task.file_size_in_bytes),
    );
    out.insert("record-count".to_string(), json!(task.record_count));

    Ok(Value::Object(out))
}

/// Encodes partition values as the spec's ordered list of primitive values.
fn partition_json(partition: &Struct) -> Result<Vec<Value>> {
    partition
        .iter()
        .map(|literal| match literal {
            Some(literal) => literal_json(literal),
            None => Ok(Value::Null),
        })
        .collect()
}

/// Encodes one literal without knowing its declared type.
///
/// A partition value's type comes from the partition spec's transform result,
/// which is not on the `DataFile`. Encoding from the literal itself gives the
/// same JSON for every type whose single-value form is its natural JSON —
/// numbers, strings, booleans — and hex for the binary ones.
fn literal_json(literal: &iceberg::spec::Literal) -> Result<Value> {
    use iceberg::spec::{Literal, PrimitiveLiteral};

    let Literal::Primitive(primitive) = literal else {
        return Err(AppError::Internal(
            "a partition value is not a primitive".to_string(),
        ));
    };

    Ok(match primitive {
        PrimitiveLiteral::Boolean(v) => json!(v),
        PrimitiveLiteral::Int(v) => json!(v),
        PrimitiveLiteral::Long(v) => json!(v),
        PrimitiveLiteral::Float(v) => json!(v.0),
        PrimitiveLiteral::Double(v) => json!(v.0),
        PrimitiveLiteral::String(v) => json!(v),
        PrimitiveLiteral::Binary(v) => json!(to_hex(v)),
        PrimitiveLiteral::Int128(v) => json!(v.to_string()),
        PrimitiveLiteral::UInt128(v) => json!(v.to_string()),
        other => {
            return Err(AppError::Internal(format!(
                "unsupported partition value: {other:?}"
            )));
        }
    })
}

/// Inserts a `CountMap`, restricted to the fields the client asked about.
fn insert_count_map(
    out: &mut Map<String, Value>,
    name: &str,
    values: &HashMap<i32, u64>,
    wanted: &HashSet<i32>,
) {
    let mut keys: Vec<i32> = values
        .keys()
        .copied()
        .filter(|id| wanted.contains(id))
        .collect();
    if keys.is_empty() {
        return;
    }
    keys.sort_unstable();

    let counts: Vec<Value> = keys.iter().map(|id| json!(values[id])).collect();
    out.insert(name.to_string(), json!({ "keys": keys, "values": counts }));
}

/// Inserts a `ValueMap`, restricted to the fields the client asked about.
fn insert_value_map(
    out: &mut Map<String, Value>,
    name: &str,
    values: &HashMap<i32, Datum>,
    wanted: &HashSet<i32>,
    schema: &Schema,
) -> Result<()> {
    let mut keys: Vec<i32> = values
        .keys()
        .copied()
        .filter(|id| wanted.contains(id))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }
    keys.sort_unstable();

    let mut encoded = Vec::with_capacity(keys.len());
    for id in &keys {
        let datum = &values[id];
        let field_type = schema
            .field_by_id(*id)
            .map(|field| field.field_type.as_ref().clone())
            .unwrap_or_else(|| Type::Primitive(datum.data_type().clone()));
        encoded.push(
            iceberg::spec::Literal::from(datum.clone())
                .try_into_json(&field_type)
                .map_err(AppError::from)?,
        );
    }

    out.insert(name.to_string(), json!({ "keys": keys, "values": encoded }));
    Ok(())
}

/// Lowercase hex, which is how the spec serialises a binary single value.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
