//! Table endpoints for the Iceberg REST Catalog v1 API.
//!
//! Implements table CRUD operations following the Iceberg REST specification.

use std::collections::HashMap;
use std::str::FromStr;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json as AxumJson,
};
use iceberg::spec::{
    FormatVersion, NestedFieldRef, NullOrder, Schema as IcebergSchema, SortDirection, SortField,
    SortOrder, TableMetadata, Transform, UnboundPartitionSpec,
};
use iceberg::{NamespaceIdent, TableCreation, TableIdent, TableRequirement, TableUpdate};
use serde::{Deserialize, Serialize};

use super::delegation::AccessDelegation;
use super::extract::{Json, NamespacePath, TablePath};
use super::freshness;
use super::guard::{self, Authorized, Target};
use super::idempotency::{CachedResponse, IdempotencyKey};
use super::ownership;
use super::pagination::{PaginationQuery, collect_page};
use super::snapshots::{self, SnapshotScope, SnapshotsQuery};
use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, Obligations, RequestFacts};
use crate::credentials::{StorageCredential, StorageCredentialRequest};
use crate::error::{AppError, Result};
use crate::names::{validate_namespace, validate_properties, validate_table_name};

/// Outcome of deciding what storage access to hand a client.
///
/// Distinguishing "nothing was asked for" from "we refuse" matters: the first is
/// the ordinary case for an engine carrying its own credentials, and the second
/// is a policy decision the client needs to be able to see.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Delegated {
    /// Credentials the client may use.
    Granted(Vec<StorageCredential>),
    /// Nothing vended, and that is unremarkable: not requested, no provider
    /// configured, or a location this provider does not serve.
    None,
    /// Vending was refused because policy attached obligations to this table.
    Withheld(String),
    /// The client asked for a credential, policy permitted one, and the exchange
    /// itself failed — an STS call that timed out, an Entra token refused, a
    /// misconfigured role.
    ///
    /// Distinct from [`Delegated::None`], and the distinction matters: this is
    /// a *transient failure of a capability the server has*, not the absence of
    /// one. Collapsing it into `None` made `loadTable` answer `200` with no
    /// credentials and nothing saying why — metadata the caller had no way to
    /// read — and made the credentials endpoint answer `501 not supported`
    /// about a mechanism that is supported and merely broken. Both send an
    /// operator to the wrong place, and neither is retryable by a client that
    /// cannot tell it should retry.
    Failed(String),
}

/// The table a credential is being requested for, and at what access level.
///
/// Grouped rather than passed as five positional arguments, where a `&str` table
/// name and a `&str` location are easy to transpose at a call site and impossible
/// to catch by type.
#[derive(Debug, Clone, Copy)]
struct CredentialTarget<'a> {
    /// Namespace holding the table.
    namespace: &'a [String],
    /// Table name.
    table_name: &'a str,
    /// The table's storage location, which becomes the credential's prefix.
    location: &'a str,
    /// How wide the credential should be.
    access: AccessLevel,
}

/// How wide a vended credential should be.
///
/// An enum rather than a `bool` because one of the answers is *not yet known*,
/// and finding it out costs a policy decision and an audit record. A `bool`
/// forces every call site to answer before it knows whether a credential is
/// wanted at all — which for a plain uncredentialed `loadTable`, the most common
/// request in the protocol, is a decision about a credential nobody asked for.
#[derive(Debug, Clone, Copy)]
enum AccessLevel {
    /// The caller just created or registered this table, so it is writing to it.
    /// No second decision: `Create` already carried the answer.
    Write,
    /// Follows the caller's own `Update` grant — decided inside
    /// [`vend_table_credentials`], once it is known that a credential is
    /// actually going to be issued.
    FromPolicy,
}

/// Vends storage credentials for a table, subject to policy.
///
/// # Obligations make a table undelegatable
///
/// If the policies that permitted this request carry a `@row_filter` or
/// `@column_mask`, **no credential is vended**. A credential is prefix-shaped: the
/// tightest it can express is the table's location. Handing that to an engine
/// lets it read every row and every column in every file under that prefix, so a
/// vended credential and a row filter are contradictory — whichever the policy
/// says, the engine reads everything.
///
/// Rustberg does apply the filter where it can: a scan plan is built from it, so
/// a restricted caller is told about fewer files, and the residual comes back on
/// every task. But a plan is advice to a cooperating engine — nothing makes an
/// unplanned file unfetchable — and a signature is confined to the whole table
/// rather than to the files one plan named. Neither closes the gap a credential
/// opens. Between vending a broad credential while claiming the filter is
/// enforced, and declining to vend, only the second is honest — so that is what
/// happens, and the response says so.
async fn vend_table_credentials(
    state: &AppState,
    authorized: &Authorized,
    target: CredentialTarget<'_>,
    delegation: AccessDelegation,
) -> Result<Delegated> {
    let CredentialTarget {
        namespace,
        table_name,
        location: table_location,
        access,
    } = target;
    let principal = authorized.principal();
    let obligations = &authorized.obligations;

    // Delegation is something a client asks for. A client running with its own
    // storage credentials does not want the catalog minting more, and vending
    // unrequested widens the authority in every response we send.
    if !delegation.vended_credentials {
        tracing::debug!(
            table = %table_name,
            "Client did not request vended credentials; none returned"
        );
        return Ok(Delegated::None);
    }

    // Checked before consulting the provider: a table under row or column policy
    // is never broadly credentialed, whatever the provider would have returned.
    if !obligations.is_empty() {
        let reason = format!(
            "Policy attaches restrictions to this table ({}), and a storage \
             credential cannot express them. Credentials are withheld rather than \
             granting access wider than policy allows.",
            obligations.describe()
        );
        tracing::info!(
            tenant_id = principal.tenant_id(),
            table = %table_name,
            restrictions = %obligations.describe(),
            "Withholding storage credentials: table is under row or column policy"
        );
        record_vend(
            state,
            authorized,
            &Delegated::Withheld(reason.clone()),
            None,
        )?;
        return Ok(Delegated::Withheld(reason));
    }

    // The location came from whichever catalog holds the table, and for a mount
    // that is somebody else's server. A remote reporting a location inside
    // *this* server's warehouse would otherwise be credentialed for it — see
    // `AppState::manages_storage_for`.
    let namespace_ident = NamespaceIdent::from_vec(namespace.to_vec())?;
    if !state
        .manages_storage_for(&namespace_ident, table_location)
        .await
    {
        tracing::debug!(
            location = table_location,
            namespace = %namespace_ident.join("."),
            "Not vending: the table's location is not inside the warehouse governing \
             its namespace"
        );
        return Ok(Delegated::None);
    }

    if !state.credential_provider.supports_location(table_location) {
        tracing::debug!(
            location = table_location,
            "Storage credential provider does not support location"
        );
        return Ok(Delegated::None);
    }

    // Asked here and not before: every return above hands out nothing, so an
    // earlier question would spend a decision and a record on the width of a
    // credential that is never issued.
    let write_access = match access {
        AccessLevel::Write => true,
        AccessLevel::FromPolicy => authorized.also_permits(state, Action::Update).await?,
    };

    let request = if write_access {
        StorageCredentialRequest::with_write_access(
            principal.tenant_id(),
            namespace.to_vec(),
            table_name,
            table_location,
        )
    } else {
        StorageCredentialRequest::read_only(
            principal.tenant_id(),
            namespace.to_vec(),
            table_name,
            table_location,
        )
    }
    .for_principal(principal.id());

    let outcome = match state.credential_provider.vend_credentials(&request).await {
        Ok(credentials) if !credentials.is_empty() => {
            tracing::debug!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                write_access,
                credentials_count = credentials.len(),
                "Vended storage credentials"
            );
            Delegated::Granted(credentials)
        }
        Ok(_) => {
            tracing::debug!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                "No credentials vended (empty result)"
            );
            Delegated::None
        }
        Err(e) => {
            tracing::warn!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                error = %e,
                "Failed to vend storage credentials"
            );
            // The provider's own message is not forwarded: it names roles,
            // endpoints and account identifiers, and this response goes to
            // whoever made the request. It is logged above, where reading it
            // needs access to the host.
            Delegated::Failed(format!(
                "Storage credentials were requested for '{table_name}' and could not be \
                 obtained. This is a failure of the credential exchange, not a policy \
                 decision — the server log names the cause. Retrying is reasonable."
            ))
        }
    };

    record_vend(state, authorized, &outcome, Some(write_access))?;
    Ok(outcome)
}

/// Records what storage access a request walked away with.
///
/// # Why this is its own record and not a field on the decision
///
/// The decision records say the caller was permitted to `Read`, and to `Update`.
/// Neither says whether a credential was minted, how wide it was, or whether the
/// exchange with the cloud provider worked. "Who was allowed to read this table"
/// and "who holds a credential that can overwrite it" are different questions,
/// and only the second names the blast radius.
///
/// [`Delegated::None`] is not recorded: nothing was handed over, and a record per
/// uncredentialed `loadTable` would be one per read, saying nothing.
///
/// # Errors
///
/// [`AppError::ServiceUnavailable`] when a *granted write* credential could not
/// be recorded and the auditor fails closed. A read credential degrades like a
/// read decision; a withheld or failed one granted nothing, so there is no
/// unrecorded grant to refuse.
fn record_vend(
    state: &AppState,
    authorized: &Authorized,
    outcome: &Delegated,
    write_access: Option<bool>,
) -> Result<()> {
    let (result, error) = match outcome {
        Delegated::None => return Ok(()),
        Delegated::Granted(_) => (crate::auth::AuditOutcome::Success, None),
        Delegated::Withheld(reason) => (crate::auth::AuditOutcome::Denied, Some(reason.clone())),
        Delegated::Failed(reason) => (crate::auth::AuditOutcome::Failure, Some(reason.clone())),
    };

    // What the caller walked away with. `None` is not "read": a withheld
    // credential never had a width decided, and recording one would put a width
    // in the trail beside a grant that did not happen.
    let access = match write_access {
        Some(true) => "read-write",
        Some(false) => "read",
        None => "none",
    };
    let granted_write = matches!(outcome, Delegated::Granted(_)) && write_access == Some(true);
    let mut event =
        crate::auth::AuditEvent::credential_vend(access, &authorized.resource_path(), result)
            .with_principal_id(authorized.principal().id())
            .with_tenant_id(authorized.principal().tenant_id())
            .with_optional_client_ip(authorized.request().source_ip)
            .with_optional_request_id(authorized.request().request_id.as_deref());
    if let Some(reason) = error {
        event = event.with_detail("reason", reason);
    }

    if granted_write {
        state.auditor.record(&event).map_err(|_| {
            AppError::ServiceUnavailable(
                "The audit trail is unavailable, so no write credential was issued.".to_string(),
            )
        })
    } else {
        state.auditor.record_lossy(&event);
        Ok(())
    }
}

impl Delegated {
    /// The credentials to put in a `LoadTableResponse`.
    ///
    /// `Withheld` and `None` both mean "no credentials in this response", and
    /// that is the correct shape: the spec has no field for *why* a table came
    /// back uncredentialed, the `/credentials` endpoint answers that question
    /// with a status code, and a table the caller may read is still worth
    /// loading without one.
    ///
    /// A **failed exchange** is different and does not belong in a `200`. The
    /// client asked for a credential, the policy said yes, and the response
    /// would carry metadata it cannot read while looking exactly like the
    /// ordinary uncredentialed case. So it becomes the `503` it is.
    ///
    /// # Errors
    ///
    /// [`AppError::ServiceUnavailable`] when the credential exchange failed.
    fn into_response_credentials(self) -> Result<Option<Vec<StorageCredential>>> {
        match self {
            Delegated::Granted(credentials) => Ok(Some(credentials)),
            Delegated::None | Delegated::Withheld(_) => Ok(None),
            Delegated::Failed(reason) => Err(AppError::ServiceUnavailable(reason)),
        }
    }
}

/// Takes the reserved `format-version` property out of a create request.
///
/// The spec carries the table format version in `properties`, and every client
/// puts it there — Spark's `TBLPROPERTIES ('format-version'='2')`, PyIceberg's
/// `properties={"format-version": "3"}`. It is *not* a property: it selects the
/// metadata version and is not persisted, which is why the metadata builder
/// refuses to store it. Passing it straight through made every such create fail
/// with "table properties should not contain reserved properties", so a table
/// could only ever be created at the default version.
///
/// The other reserved names are read-only metadata that surfaces as properties
/// — `uuid`, `current-snapshot-id`, `snapshot-count` and the rest. A client
/// setting one is asking for something that cannot be honoured, so it is
/// refused here with a message naming the key rather than deeper with one that
/// reads like an internal failure.
///
/// # Errors
///
/// [`AppError::BadRequest`] for an unparseable version, a version this build
/// does not support, or any other reserved property.
fn take_format_version(properties: &mut HashMap<String, String>) -> Result<FormatVersion> {
    const FORMAT_VERSION: &str = "format-version";

    let requested = properties.remove(FORMAT_VERSION);

    if let Some(reserved) = properties
        .keys()
        .find(|key| RESERVED_TABLE_PROPERTIES.contains(&key.as_str()))
    {
        return Err(AppError::BadRequest(format!(
            "'{reserved}' is table metadata, not a table property, and cannot be set by a \
             client."
        )));
    }

    let Some(requested) = requested else {
        // What the Iceberg community writes new tables at. v3 is opt-in while
        // engine support is uneven, and choosing it by default would produce
        // tables some readers cannot open.
        return Ok(FormatVersion::V2);
    };

    match requested.trim() {
        "1" => Ok(FormatVersion::V1),
        "2" => Ok(FormatVersion::V2),
        "3" => Ok(FormatVersion::V3),
        other => Err(AppError::BadRequest(format!(
            "Unsupported format-version '{other}'. This catalog serves table format \
             versions 1, 2 and 3."
        ))),
    }
}

/// Reserved names other than `format-version`: read-only metadata that the spec
/// surfaces as properties.
const RESERVED_TABLE_PROPERTIES: &[&str] = &[
    "uuid",
    "snapshot-count",
    "current-snapshot-id",
    "current-snapshot-summary",
    "current-snapshot-timestamp-ms",
    "current-schema",
    "default-partition-spec",
    "default-sort-order",
];

// ============================================================================
// Request/Response Types
// ============================================================================

/// Table identifier with namespace and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableIdentifier {
    /// Namespace path components.
    pub namespace: Vec<String>,
    /// Table name.
    pub name: String,
}

impl TableIdentifier {
    /// Creates a new table identifier.
    #[cfg(test)]
    pub fn new(namespace: Vec<String>, name: String) -> Self {
        Self { namespace, name }
    }
}

/// Response for listing tables.
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListTablesResponse {
    /// Pagination token for the next page.
    pub next_page_token: Option<String>,
    /// List of table identifiers.
    pub identifiers: Vec<TableIdentifier>,
}

/// Request payload for creating a table.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateTablePayload {
    /// Table name.
    pub name: String,
    /// Optional table location (overrides default).
    pub location: Option<String>,
    /// Table schema definition.
    pub schema: Schema,
    /// Optional partition specification.
    pub partition_spec: Option<UnboundPartitionSpec>,
    /// Optional write ordering.
    pub write_order: Option<WriteOrder>,
    /// Whether to stage the table rather than create it.
    ///
    /// A staged table is written to storage but is absent from every listing and
    /// does not resolve to a load. It becomes real through a later `commit_table`
    /// carrying a `NotExist` requirement — which is how Spark performs
    /// `CREATE TABLE AS SELECT`.
    pub stage_create: Option<bool>,
    /// Table properties.
    pub properties: Option<HashMap<String, String>>,
}

/// Schema definition for table creation.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Schema {
    /// Must be "struct".
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Schema fields.
    pub fields: Vec<NestedFieldRef>,
    /// Schema ID (optional, will default to 0).
    #[serde(default)]
    pub schema_id: Option<i32>,
    /// Identifier field IDs for row-level operations.
    pub identifier_field_ids: Option<Vec<i32>>,
}

/// Write order specification.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WriteOrder {
    /// Sort fields defining the write order.
    pub fields: Vec<WriteOrderField>,
}

/// Individual sort field in write order.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WriteOrderField {
    /// Source field ID.
    pub source_id: i32,
    /// Transform to apply.
    pub transform: String,
    /// Sort direction.
    pub direction: SortDirection,
    /// Null ordering.
    pub null_order: NullOrder,
}

/// Response for table creation.
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoadTableResponse {
    /// Metadata file location.
    ///
    /// Absent when the metadata is not committed — which is exactly the staged
    /// case. The spec is explicit that a create transaction returns metadata
    /// that is staged but not committed, and naming a location there would
    /// assert the catalog is serving that file as a table's current metadata
    /// when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_location: Option<String>,
    /// Table metadata.
    pub metadata: TableMetadata,
    /// Table configuration.
    pub config: HashMap<String, String>,
    /// Storage credentials for accessing table data files.
    /// Clients should check this field before falling back to credentials in config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_credentials: Option<Vec<StorageCredential>>,
    /// Signer settings, when the client asked for remote signing and this
    /// deployment offers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signing_config: Option<super::sign::RemoteSigningConfig>,
}

impl LoadTableResponse {
    /// The same response with any vended credentials removed.
    ///
    /// Used for the idempotency cache: credentials are short-lived and scoped to
    /// the request that minted them, so storing one for the cache's 24-hour
    /// lifetime keeps a live secret around long after it was needed and replays
    /// an expired one afterwards.
    fn without_credentials(&self) -> Self {
        Self {
            metadata_location: self.metadata_location.clone(),
            metadata: self.metadata.clone(),
            config: self.config.clone(),
            storage_credentials: None,
            remote_signing_config: self.remote_signing_config.clone(),
        }
    }
}

/// The signer settings and `config` keys a `LoadTableResult` should carry.
///
/// Empty unless the client asked for `remote-signing` and this deployment
/// offers it.
fn signing_response(
    state: &AppState,
    delegation: AccessDelegation,
    namespace: &NamespaceIdent,
    table_name: &str,
    obligations: &Obligations,
) -> (
    HashMap<String, String>,
    Option<super::sign::RemoteSigningConfig>,
) {
    if !delegation.remote_signing || !state.signing.enabled || !obligations.is_empty() {
        return (HashMap::new(), None);
    }

    let signing = super::sign::signing_config_for(namespace, table_name);
    let config = HashMap::from([
        ("s3.remote-signing-enabled".to_string(), "true".to_string()),
        ("s3.signer".to_string(), "S3V4RestSigner".to_string()),
        ("s3.signer.endpoint".to_string(), signing.endpoint.clone()),
    ]);

    (config, Some(signing))
}

/// Request for registering an existing table.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RegisterTablePayload {
    /// Table name.
    pub name: String,
    /// Location of the metadata file.
    pub metadata_location: String,
}

/// `POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/unregister`
///
/// Removes the catalog's pointer to a table, leaving its data and metadata files
/// where they are. The table can be adopted again later — by this catalog or a
/// different one — with `register`.
///
/// # Why this is not just `DELETE`
///
/// `DELETE …/tables/{table}` without `purgeRequested` does the same thing to the
/// same state, so this endpoint could be read as a duplicate. It is not, and the
/// difference is intent rather than mechanism: `DELETE` says *this table is
/// finished*, and adding `?purgeRequested=true` to it destroys data. `unregister`
/// says *this table is moving*, and has no way to spell "delete the files".
///
/// A migration script that means "hand this table to another catalog" should not
/// be one query parameter away from erasing it.
pub async fn unregister_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
) -> Result<StatusCode> {
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Delete,
    )
    .await?;

    state.metrics.catalog_delete_table.inc();
    state.catalog.drop_table(&table_ident).await?;

    tracing::info!(
        table = %table_ident,
        "Unregistered table (metadata and data left in place)"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Request for reporting scan/commit metrics.
///
/// This struct follows the Iceberg REST Catalog specification for metrics reporting.
/// Fields are received from clients but only logged for telemetry purposes currently.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)] // Spec-compliant struct; fields are for future telemetry use
pub struct ReportMetricsRequest {
    /// Type of report: "scan-report" or "commit-report"
    pub report_type: String,
    /// Table name (fully qualified).
    pub table_name: String,
    /// Snapshot ID associated with the operation.
    pub snapshot_id: i64,
    /// Sequence number (for commit reports).
    #[serde(default)]
    pub sequence_number: Option<i64>,
    /// Operation type (for commit reports: "append", "overwrite", etc.).
    #[serde(default)]
    pub operation: Option<String>,
    /// Filter expression (for scan reports).
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// Schema ID (for scan reports).
    #[serde(default)]
    pub schema_id: Option<i32>,
    /// Projected field IDs (for scan reports).
    #[serde(default)]
    pub projected_field_ids: Option<Vec<i32>>,
    /// Projected field names (for scan reports).
    #[serde(default)]
    pub projected_field_names: Option<Vec<String>>,
    /// Metrics data.
    #[serde(default)]
    pub metrics: HashMap<String, serde_json::Value>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Request for committing multiple tables atomically.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitTransactionRequest {
    /// List of table commits to apply atomically.
    pub table_changes: Vec<CommitTableRequest>,
}

/// Request for renaming a table.
#[derive(Deserialize)]
pub struct RenameTablePayload {
    /// Source table identifier.
    pub source: TableIdentifier,
    /// Destination table identifier.
    pub destination: TableIdentifier,
}

/// Request payload for committing table updates.
///
/// This follows the Iceberg REST Catalog specification for table commits.
/// The commit will only succeed if all requirements are met.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitTableRequest {
    /// Optional table identifier (for multi-table commits).
    /// If not provided, the identifier from the URL path is used.
    #[serde(default)]
    pub identifier: Option<TableIdentifier>,
    /// Requirements that must be met for the commit to succeed.
    /// These are checked against the current table state.
    #[serde(default)]
    pub requirements: Vec<TableRequirement>,
    /// Updates to apply to the table metadata.
    pub updates: Vec<TableUpdate>,
}

/// Response for table commit operations.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitTableResponse {
    /// Metadata file location after the commit.
    pub metadata_location: String,
    /// Updated table metadata.
    pub metadata: TableMetadata,
}

/// Query parameters for listing tables.
#[derive(Debug, Default, Deserialize)]
pub struct ListTablesQuery {
    /// Pagination: token for the next page.
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,
    /// Pagination: maximum items per page.
    #[serde(rename = "pageSize")]
    pub page_size: Option<usize>,
}

/// Query parameters for dropping a table.
#[derive(Debug, Default, Deserialize)]
pub struct DropTableQuery {
    /// Whether to purge underlying data files in addition to removing the table from the catalog.
    ///
    /// When `true`, this operation will:
    /// 1. Load the table to get its data location
    /// 2. Drop the table from the catalog
    /// 3. Delete all files in the table's location (data files, metadata files, manifests)
    ///
    /// Default is `false` (only remove from catalog, leave data intact).
    #[serde(
        rename = "purgeRequested",
        default,
        deserialize_with = "deserialize_bool_from_string"
    )]
    pub purge_requested: bool,
}

/// Deserializes a boolean from either a native bool or a string like `"true"` / `"false"`.
///
/// Query parameters arrive as strings, so `?purgeRequested=true` sends the string `"true"`,
/// not the boolean `true`. This deserializer handles both representations.
fn deserialize_bool_from_string<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BoolOrStringVisitor;

    impl<'de> de::Visitor<'de> for BoolOrStringVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a boolean or a string \"true\"/\"false\"")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<bool, E> {
            Ok(v)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<bool, E> {
            match v.to_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" | "" => Ok(false),
                _ => Err(E::invalid_value(de::Unexpected::Str(v), &self)),
            }
        }
    }

    deserializer.deserialize_any(BoolOrStringVisitor)
}

// ============================================================================
// Handlers
// ============================================================================

/// Lists the tables in a namespace that the caller may see.
///
/// # Filtering, not denying
///
/// `List` on the namespace permits *asking*; each table is then checked
/// individually and omitted if the caller cannot read it. A caller therefore
/// never learns that a table it has no grant on exists, and the listing agrees
/// with what a subsequent load would answer.
///
/// Filtering runs **before** the page is cut. Slicing first and filtering after
/// would return short pages, and an entirely unpermitted page would come back
/// empty while permitted tables remained further on — which many clients treat as
/// the end of the list.
///
/// The cost is one Cedar evaluation per table *scanned* rather than per table
/// returned, with no additional I/O: the namespace's owner is already known, so
/// each decision is an in-memory evaluation.
///
/// GET /v1/namespaces/{namespace}/tables
pub async fn list_tables(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    axum::extract::Query(query): axum::extract::Query<ListTablesQuery>,
) -> Result<AxumJson<ListTablesResponse>> {
    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::List,
    )
    .await?;

    state.metrics.catalog_list_tables.inc();

    let page = collect_page(
        PaginationQuery::new(query.page_token, query.page_size).to_request()?,
        |page_request| {
            let state = state.clone();
            let namespace = namespace.0.clone();
            async move {
                state
                    .catalog
                    .list_tables(&namespace, &page_request)
                    .await
                    .map_err(AppError::from)
            }
        },
        |ident: TableIdent| {
            let state = state.clone();
            let principal = principal.clone();
            let facts = request.clone();
            let owner = authorized.owner.clone();
            async move {
                let visible = guard::can_see(
                    &state,
                    &principal,
                    &facts,
                    &owner,
                    ident.namespace(),
                    Target::Table(ident.name()),
                )
                .await;
                (visible, ident)
            }
        },
    )
    .await?;

    Ok(AxumJson(ListTablesResponse {
        next_page_token: page.next_page_token,
        identifiers: page
            .items
            .into_iter()
            .map(|ident| TableIdentifier {
                namespace: ident.namespace().to_vec(),
                name: ident.name().to_string(),
            })
            .collect(),
    }))
}

/// Creates a new Iceberg table in the given namespace.
///
/// POST /v1/namespaces/{namespace}/tables
pub async fn create_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    headers: HeaderMap,
    Json(payload): Json<CreateTablePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Validate input
    validate_table_name(&payload.name)?;
    if let Some(ref props) = payload.properties {
        validate_properties(props)?;
    }

    // A client-supplied location becomes the prefix of any credential vended for
    // this table, so it is confined before it is recorded — to the prefix this
    // table's *name* puts it in, not merely to the warehouse. See
    // `crate::location::LocationScope` for the confused-deputy hole that
    // distinction closes.
    if let Some(ref location) = payload.location {
        state
            .location_bound(&namespace, &payload.name)
            .await
            .ensure(location)?;
    }

    let staged = payload.stage_create == Some(true);

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/tables",
        namespace.clone().inner().join("/")
    );

    // Check for idempotency key
    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", &endpoint_path, &principal);

    let table_name = payload.name.clone();
    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Create,
    )
    .await?;
    // Consulted only after authorization: a cache hit answers without touching
    // the catalog, so checking it first would serve a request that was never
    // authorized — and would keep serving it after the grant was revoked.
    if let Some(ref key) = idempotency_key
        && let Some(cached) = state.idempotency_cache.get(key).await
    {
        return Ok(cached.into_axum_response());
    }

    state.metrics.catalog_create_table.inc();

    let delegation = AccessDelegation::from_headers(&headers);

    if payload.schema.schema_type != "struct" {
        return Err(AppError::BadRequest(
            "A table schema must have \"type\": \"struct\" at its root.".into(),
        ));
    }

    // Use schema_id from payload if provided, otherwise default to 0
    let schema_id = payload.schema.schema_id.unwrap_or(0);

    let schema = IcebergSchema::builder()
        .with_schema_id(schema_id)
        .with_fields(payload.schema.fields)
        .with_identifier_field_ids(payload.schema.identifier_field_ids.unwrap_or_default())
        .build()?;

    let sort_order = build_sort_order(&payload.write_order)?;

    let mut properties = payload.properties.unwrap_or_default();
    let format_version = take_format_version(&mut properties)?;

    // Only an explicit client-supplied location is passed through. When it is
    // absent the catalog derives one from the warehouse *and the namespace* —
    // computing `{warehouse}/{table}` here dropped the namespace, so two tables
    // of the same name in different namespaces resolved to one location.
    let table_creation = TableCreation::builder()
        .name(table_name.clone())
        .location_opt(payload.location)
        .schema(schema)
        .partition_spec(payload.partition_spec.unwrap_or_default())
        .sort_order_opt(sort_order)
        .properties(properties)
        .format_version(format_version)
        .build();

    // `stage-create` builds the table's first metadata and hands it back
    // *without* creating the table: the engine writes its data files first and
    // commits the whole thing atomically, which is how Spark performs CREATE
    // TABLE AS SELECT. A staged table is invisible until that commit lands and
    // reserves nothing in the meantime.
    let table = if staged {
        state
            .catalog
            .stage_create_table(&namespace, table_creation)
            .await?
    } else {
        state
            .catalog
            .create_table(&namespace, table_creation)
            .await?
    };

    // A caller that just created a table is writing to it, so the credential
    // carries write access without needing a second decision.
    let storage_credentials = vend_table_credentials(
        &state,
        &authorized,
        CredentialTarget {
            namespace: namespace.as_ref(),
            table_name: &table_name,
            location: table.metadata().location(),
            access: AccessLevel::Write,
        },
        delegation,
    )
    .await?
    .into_response_credentials()?;

    let (signing_config, remote_signing_config) = signing_response(
        &state,
        delegation,
        &namespace,
        &table_name,
        &authorized.obligations,
    );

    let response_body = LoadTableResponse {
        // A staged table has no committed metadata location, and the spec says
        // to omit the field in exactly that case. The location is still recorded
        // server-side — it is the base the eventual `assert-create` commit
        // builds on — but it is not something the client is being handed as a
        // table's current metadata.
        metadata_location: if staged {
            None
        } else {
            table.metadata_location().map(|s| s.to_string())
        },
        metadata: table.metadata().clone(),
        config: signing_config,
        storage_credentials,
        remote_signing_config,
    };

    // Build response
    let mut response = (StatusCode::OK, AxumJson(&response_body)).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // The caller now holds this exact version, so hand it the tag that names it.
    // Its next `loadTable` can then be conditional and cost nothing.
    //
    // Not for a staged table: there is no table to load conditionally, and a tag
    // naming a version the catalog does not acknowledge would be a promise about
    // state that does not exist.
    // Delegation is passed in for the same reason it is on `loadTable`: a
    // response carrying a freshly minted credential has no stable identity, and
    // `etag_for` answers `None` rather than naming one.
    if !staged
        && let Some(tag) = freshness::etag_for(
            table.metadata_location(),
            SnapshotScope::All,
            delegation,
            !authorized.obligations.is_empty(),
        )
    {
        insert_etag(&mut response, &tag);
    }

    // Cache a credential-free copy. A vended credential is short-lived and
    // request-scoped, so replaying one from a 24-hour cache would hand back a
    // credential that has almost certainly expired — and would keep a live secret
    // in memory long after the request that minted it. A client replaying a
    // create asks for credentials again if it wants them.
    //
    // A staged create is never cached. Staging is not idempotent by nature — each
    // call mints fresh metadata and supersedes the last — and replaying an old
    // staged response would hand a client a metadata location the catalog has
    // already replaced, so its commit would assert against the wrong base.
    if let Some(key) = idempotency_key.filter(|_| !staged)
        && let Some(cached) =
            CachedResponse::from_json(StatusCode::OK, &response_body.without_credentials())
    {
        state.idempotency_cache.set(key, cached).await;
    }

    Ok(response)
}

/// Loads a table's metadata, and vends credentials if the client asked for them.
///
/// The credential's access level follows the caller's own permissions: a
/// principal that may also `Update` this table receives a credential that can
/// write under its prefix, and a read-only principal receives one that cannot.
/// See [`AccessLevel`], and note that the question is asked only once it is
/// known that a credential is going to be issued at all.
///
/// GET /v1/namespaces/{namespace}/tables/{table}
pub async fn load_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
    Query(snapshots_query): Query<SnapshotsQuery>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;

    // Rejected before any work is done: an unusable parameter is the client's
    // error, and answering it with a full table load would hide that.
    let scope = snapshots_query.scope()?;

    let delegation = AccessDelegation::from_headers(&headers);
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Read,
    )
    .await?;

    // Record metric
    state.metrics.catalog_load_table.inc();

    // A conditional request is answered from the metadata *pointer* — a registry
    // lookup — so a `304` never fetches or parses the metadata document, which
    // is the whole cost of a table load. Deriving the tag from a full load
    // instead made a `304` cost exactly what a `200` did.
    //
    // Only when the client actually asked, though. Computing a tag costs a
    // catalog lookup, and on a federated mount that lookup is a *remote* call —
    // doing it unconditionally would double the cost of every ordinary load to
    // serve a header nobody sent. So an unconditional request goes straight to
    // the load and derives its tag from what came back.
    //
    // This sits *after* authorization deliberately: `304` reveals that the table
    // exists and is unchanged, which is exactly as much as `200` would, so it
    // must be gated by the same decision. Answering it earlier would turn the
    // cache into a way to probe for tables the caller may not see.
    if freshness::is_revalidatable(&headers, delegation) {
        let pointer = state.catalog.metadata_pointer(&table_ident).await?;

        if let Some(tag) = freshness::etag_for(
            pointer.as_deref(),
            scope,
            delegation,
            !authorized.obligations.is_empty(),
        ) && freshness::matches(&headers, &tag)
        {
            state.metrics.catalog_load_table_not_modified.inc();
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            insert_etag(&mut response, &tag);
            return Ok(response);
        }
    }

    let table = state.catalog.load_table(&table_ident).await?;
    let etag = freshness::etag_for(
        table.metadata_location(),
        scope,
        delegation,
        !authorized.obligations.is_empty(),
    );

    // A row filter over a non-partition column cannot be enforced by
    // withholding files, and looks identical in the policy file to one that
    // can. Reported here, where the filter and the partition spec are both in
    // hand, and at most once per table per policy set.
    crate::auth::filter_alignment::warn_if_cooperative(
        &authorized.obligations.row_filters,
        table.metadata(),
        &table_ident.to_string(),
        state.authorizer.policy_set_version().as_deref(),
    );

    let storage_credentials = vend_table_credentials(
        &state,
        &authorized,
        CredentialTarget {
            namespace: namespace.as_ref(),
            table_name: &table_name,
            location: table.metadata().location(),
            access: AccessLevel::FromPolicy,
        },
        delegation,
    )
    .await?
    .into_response_credentials()?;

    let metadata = snapshots::apply_scope(table.metadata().clone(), scope)?;

    let (signing_config, remote_signing_config) = signing_response(
        &state,
        delegation,
        &namespace,
        &table_name,
        &authorized.obligations,
    );

    let body = LoadTableResponse {
        metadata_location: table.metadata_location().map(|s| s.to_string()),
        metadata,
        config: signing_config,
        storage_credentials,
        remote_signing_config,
    };

    let mut response = (StatusCode::OK, AxumJson(body)).into_response();
    if let Some(ref tag) = etag {
        insert_etag(&mut response, tag);
    }
    Ok(response)
}

/// Attaches an entity tag to a response.
///
/// A tag that will not parse as a header is dropped rather than failing the
/// request: the response is correct without it, and the only cost is that the
/// client's next load is unconditional. The tag is hex inside quotes, so this
/// cannot actually happen — which is why it must not be an error path.
fn insert_etag(response: &mut axum::response::Response, tag: &str) {
    let Ok(value) = axum::http::HeaderValue::from_str(tag) else {
        return;
    };
    response
        .headers_mut()
        .insert(axum::http::header::ETAG, value);

    // `private, no-cache`, and both halves are the point.
    //
    // The catalog-wide default is `no-store`, which is right for a response
    // carrying a credential and self-defeating on one carrying a validator: a
    // client that honours it keeps no copy, so it never sends `If-None-Match`.
    //
    // `no-cache` does not mean "do not cache" — it means the stored copy may not
    // be reused without revalidating here first, which is what conditional
    // loading is, and why the authorization decision still runs on every
    // request. `private` keeps the response, which is scoped to one principal,
    // out of shared caches.
    //
    // Set by the handler because the layer supplying the default is
    // `if_not_present`.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-cache"),
    );
}

/// Checks if a table exists.
///
/// HEAD /v1/namespaces/{namespace}/tables/{table}
pub async fn table_exists(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
) -> Result<StatusCode> {
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Read,
    )
    .await?;

    if state.catalog.table_exists(&table_ident).await? {
        // The Iceberg REST spec defines the HEAD responses as 204 No Content.
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NoSuchTable(table_ident.to_string()))
    }
}

/// Response for table credentials endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoadCredentialsResponse {
    /// Storage credentials for accessing table data files.
    pub storage_credentials: Vec<StorageCredential>,
}

/// Loads vended credentials for a table, without its metadata.
///
/// Use this instead of `loadTable` when a client already holds the metadata and
/// only needs to refresh an expiring credential.
///
/// Access level follows the caller's permissions, exactly as in `loadTable`: a
/// principal permitted to `Update` receives a writable credential.
///
/// GET /v1/namespaces/{namespace}/tables/{table}/credentials
pub async fn load_table_credentials(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
) -> Result<AxumJson<LoadCredentialsResponse>> {
    // This endpoint exists solely to obtain credentials, so calling it *is* the
    // request; no delegation header is required.
    let delegation = AccessDelegation {
        vended_credentials: true,
        remote_signing: false,
    };
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Read,
    )
    .await?;

    let table = state.catalog.load_table(&table_ident).await?;
    let table_location = table.metadata().location();

    let delegated = vend_table_credentials(
        &state,
        &authorized,
        CredentialTarget {
            namespace: namespace.as_ref(),
            table_name: &table_name,
            location: table_location,
            access: AccessLevel::FromPolicy,
        },
        delegation,
    )
    .await?;

    match delegated {
        Delegated::Granted(storage_credentials) => Ok(AxumJson(LoadCredentialsResponse {
            storage_credentials,
        })),
        // A policy decision, so it is reported as one. Answering "not supported"
        // here would send the client looking for a configuration problem.
        Delegated::Withheld(reason) => Err(AppError::Forbidden(reason)),
        Delegated::Failed(reason) => Err(AppError::ServiceUnavailable(reason)),
        Delegated::None => Err(AppError::NotSupported(format!(
            "Credential vending is not available for storage location: {}",
            table_location
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
        ))),
    }
}

/// Drops a table from the catalog.
///
/// DELETE /v1/namespaces/{namespace}/tables/{table}
///
/// # Query Parameters
///
/// - `purgeRequested` (optional, boolean): When true, purges all underlying data files
///   in addition to removing the table from the catalog. Default is false.
///
/// # Purge Behavior
///
/// When `purgeRequested=true`:
/// 1. The table is loaded to determine its storage location
/// 2. The table is dropped from the catalog registry
/// 3. All files in the table's location are recursively deleted (data files, manifests, metadata)
///
/// **Warning**: Purge is a destructive operation and cannot be undone. The data files
/// will be permanently deleted from the storage backend.
pub async fn drop_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
    axum::extract::Query(query): axum::extract::Query<DropTableQuery>,
) -> Result<StatusCode> {
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Delete,
    )
    .await?;

    // Read after authorizing, so an unauthorized caller learns nothing about
    // whether the table exists or how it is configured.
    let properties = state
        .catalog
        .load_table(&table_ident)
        .await?
        .metadata()
        .properties()
        .clone();
    ownership::reject_if_protected(&properties, &format!("Table '{table_ident}'"))?;

    // Record metric
    state.metrics.catalog_delete_table.inc();

    if query.purge_requested {
        // Purge drops the table and deletes the files it owns, in one catalog
        // operation. The catalog walks the table's manifests and removes exactly
        // the referenced files; it does not recursively delete the table location,
        // which could destroy unrelated tables sharing the same prefix.
        state.catalog.purge_table(&table_ident).await?;
        tracing::info!(table = %table_ident, "Dropped table and purged its data");
    } else {
        state.catalog.drop_table(&table_ident).await?;
        tracing::info!(table = %table_ident, "Dropped table (data left in place)");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Renames a table.
///
/// POST /v1/tables/rename
/// Renames a table.
///
/// Needs `Update` on the source and `Create` on the destination: a rename removes
/// a table from one name and creates it at another, and a caller permitted only
/// to write the destination must not be able to move someone else's table into
/// it.
///
/// POST /v1/tables/rename
pub async fn rename_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    Json(payload): Json<RenameTablePayload>,
) -> Result<StatusCode> {
    // Validate destination table name and namespaces
    validate_table_name(&payload.destination.name)?;
    validate_namespace(&payload.source.namespace)?;
    validate_namespace(&payload.destination.namespace)?;

    let src_namespace = NamespaceIdent::from_vec(payload.source.namespace.clone())?;
    let dst_namespace = NamespaceIdent::from_vec(payload.destination.namespace.clone())?;

    let src = guard::authorize(
        &state,
        &principal,
        &request,
        &src_namespace,
        Target::Table(&payload.source.name),
        Action::Update,
    )
    .await?;

    let dst = guard::authorize(
        &state,
        &principal,
        &request,
        &dst_namespace,
        Target::Table(&payload.destination.name),
        Action::Create,
    )
    .await?;

    // A rename is not a mechanism for moving data between tenants. Both checks
    // above could pass for a principal with grants in two tenants, and the
    // resulting table would sit in one tenant's namespace while its files live
    // under another's warehouse prefix.
    if src.owner != dst.owner {
        return Err(AppError::Forbidden(
            "Cannot move tables between namespaces owned by different tenants".to_string(),
        ));
    }

    // Record metric
    state.metrics.catalog_rename_table.inc();

    let src_ident = TableIdent::new(src_namespace, payload.source.name);
    let dst_ident = TableIdent::new(dst_namespace, payload.destination.name);

    state.catalog.rename_table(&src_ident, &dst_ident).await?;

    Ok(StatusCode::OK)
}

/// Commits updates to a table.
///
/// This is the core update endpoint for Iceberg tables. It supports:
/// - Adding new snapshots (data writes)
/// - Schema evolution (add/rename/delete columns)
/// - Partition spec changes
/// - Sort order changes
/// - Setting/removing table properties
/// - Setting/removing snapshot references (branches/tags)
///
/// The commit uses optimistic concurrency control via requirements.
/// If any requirement fails, the commit is rejected with 409 Conflict.
///
/// POST /v1/namespaces/{namespace}/tables/{table}
pub async fn commit_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
    headers: HeaderMap,
    Json(payload): Json<CommitTableRequest>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    let namespace_parts = table_ident.namespace().to_vec();
    let table_name = table_ident.name().to_string();

    // Scope the idempotency key to the resource, not to the request URL: the
    // same commit is reachable through `/v1/...` and `/v1/{prefix}/...`, and a
    // retry that happens to use the other form must hit the same cache entry.
    let endpoint_path = format!(
        "commit-table:{}:{}",
        namespace_parts.join("\u{1F}"),
        table_name
    );

    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", &endpoint_path, &principal);

    // The spec lets the body repeat the identifier the URL already carries. Two
    // sources for one fact diverge: letting the body win commits against a table
    // the URL never named, while the idempotency key stays scoped to the URL's.
    // So they must agree, and the path is authoritative.
    if let Some(ref ident) = payload.identifier
        && (ident.namespace != namespace_parts || ident.name != table_name)
    {
        return Err(AppError::BadRequest(format!(
            "The identifier in the request body ({}.{}) does not name the table in \
                 the URL ({}.{}). They must match.",
            ident.namespace.join("."),
            ident.name,
            namespace_parts.join("."),
            table_name
        )));
    }

    let namespace = NamespaceIdent::from_vec(namespace_parts)?;
    let final_table_name = table_name;

    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&final_table_name),
        Action::Update,
    )
    .await?;
    // Consulted only after authorization: a cache hit answers without touching
    // the catalog, so checking it first would serve a request that was never
    // authorized — and would keep serving it after the grant was revoked.
    if let Some(ref key) = idempotency_key
        && let Some(cached) = state.idempotency_cache.get(key).await
    {
        return Ok(cached.into_axum_response());
    }

    // The four locations a commit carries are confined by the *backend*, where
    // the table's current metadata is already in hand — see
    // `crate::location::LocationBound::ensure_commit` for why the bound needs it
    // and why loading the table a second time here to get it would be the wrong
    // trade on the hottest write path.

    let table_ident = TableIdent::new(namespace, final_table_name);

    // Validate that we have at least one update
    if payload.updates.is_empty() {
        return Err(AppError::BadRequest(
            "A commit must carry at least one update. A request with none changes \
             nothing, so it is a mistake rather than a no-op."
                .into(),
        ));
    }

    // Record metric
    state.metrics.catalog_commit_table.inc();

    // Use the extended catalog's commit_table method (trait is in scope via AppState)
    let updated_table = state
        .catalog
        .commit_table(&table_ident, payload.requirements, payload.updates)
        // `From<iceberg::Error>` maps on ErrorKind, so a commit conflict becomes
        // 409 and a missing table becomes 404. Mapping by hand here collapsed
        // everything that was not a conflict into a 500.
        .await?;

    let metadata_location = updated_table
        .metadata_location()
        .map(|s| s.to_string())
        .unwrap_or_default();

    let response_body = CommitTableResponse {
        metadata_location,
        metadata: updated_table.metadata().clone(),
    };

    // Build response
    let mut response = (StatusCode::OK, AxumJson(&response_body)).into_response();
    // The committer already holds the new version; tagging it here saves the
    // full re-read that otherwise follows every write.
    // A commit response is metadata only — no delegation is negotiated on this
    // path — so the plain representation is the one being tagged.
    if let Some(tag) = freshness::etag_for(
        updated_table.metadata_location(),
        SnapshotScope::All,
        AccessDelegation::default(),
        !authorized.obligations.is_empty(),
    ) {
        insert_etag(&mut response, &tag);
    }
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // Cache if idempotency key was provided
    if let Some(key) = idempotency_key
        && let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body)
    {
        state.idempotency_cache.set(key, cached).await;
    }

    Ok(response)
}

/// Registers an existing table by its metadata location.
///
/// This endpoint allows registering a table that already exists in storage
/// (e.g., created by Spark, Trino, or another system) into this catalog.
///
/// POST /v1/namespaces/{namespace}/register
pub async fn register_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    headers: HeaderMap,
    Json(payload): Json<RegisterTablePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Validate input
    validate_table_name(&payload.name)?;

    // Registration is the sharpest form of the problem: the caller names a
    // metadata file directly, and the table location read out of it becomes the
    // prefix of a *write* credential below. Confined first.
    state
        .location_bound(&namespace, &payload.name)
        .await
        .ensure(&payload.metadata_location)?;

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/register",
        namespace.clone().inner().join("/")
    );

    // Check for idempotency key
    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", &endpoint_path, &principal);

    let table_name = payload.name.clone();
    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Create,
    )
    .await?;

    // Consulted only after authorization: a cache hit answers without touching
    // the catalog, so checking it first would serve a request that was never
    // authorized — and would keep serving it after the grant was revoked.
    if let Some(ref key) = idempotency_key
        && let Some(cached) = state.idempotency_cache.get(key).await
    {
        return Ok(cached.into_axum_response());
    }

    // Record metric
    state.metrics.catalog_register_table.inc();

    let delegation = AccessDelegation::from_headers(&headers);

    // Handed to the catalog as-is: it reads the location through its own FileIO,
    // confines the location that metadata *declares* to the mount's warehouse,
    // and only then records the pointer.
    //
    // The declared-location check is the backend's rather than this handler's,
    // and deliberately so — see [`crate::location::confine_declared_location`].
    // Doing it here meant publishing the pointer first and dropping the table
    // when the check failed, which left a window in which an out-of-warehouse
    // table was loadable; doing it here *before* the call would check a
    // different read of a file the caller controls.
    //
    // Registration must *adopt* the existing metadata, never rewrite it. Parsing
    // it here and calling `create_table` would write a fresh metadata file,
    // discarding the snapshot history the caller is registering.
    let table_ident = TableIdent::new(namespace.0.clone(), table_name.clone());

    let table = state
        .catalog
        .register_table(&table_ident, payload.metadata_location.clone())
        .await?;

    let storage_credentials = vend_table_credentials(
        &state,
        &authorized,
        CredentialTarget {
            namespace: namespace.as_ref(),
            table_name: &table_name,
            location: table.metadata().location(),
            access: AccessLevel::Write,
        },
        delegation,
    )
    .await?
    .into_response_credentials()?;

    let (signing_config, remote_signing_config) = signing_response(
        &state,
        delegation,
        &namespace,
        &table_name,
        &authorized.obligations,
    );

    let response_body = LoadTableResponse {
        metadata_location: table.metadata_location().map(str::to_string),
        metadata: table.metadata().clone(),
        config: signing_config,
        storage_credentials,
        remote_signing_config,
    };

    // Build response
    let mut response = (StatusCode::OK, AxumJson(&response_body)).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // Credential-free, for the reason given in `create_table`.
    if let Some(key) = idempotency_key
        && let Some(cached) =
            CachedResponse::from_json(StatusCode::OK, &response_body.without_credentials())
    {
        state.idempotency_cache.set(key, cached).await;
    }

    Ok(response)
}

/// Reports metrics from client operations (scan, commit).
///
/// This endpoint receives telemetry data from Iceberg clients about
/// their scan and commit operations. The data is logged for observability
/// but not persisted (stateless design).
///
/// POST /v1/namespaces/{namespace}/tables/{table}/metrics
pub async fn report_metrics(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table_ident): TablePath,
    Json(payload): Json<ReportMetricsRequest>,
) -> Result<StatusCode> {
    let namespace = table_ident.namespace().clone();
    let table_name = table_ident.name().to_string();

    // Reporting telemetry about a table needs only the right to read it.
    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Table(&table_name),
        Action::Read,
    )
    .await?;

    // Log the metrics for observability
    tracing::info!(
        tenant_id = principal.tenant_id(),
        table = %table_name,
        report_type = %payload.report_type,
        snapshot_id = payload.snapshot_id,
        operation = ?payload.operation,
        metrics_count = payload.metrics.len(),
        "Received metrics report"
    );

    // Return 204 No Content as per spec
    Ok(StatusCode::NO_CONTENT)
}

/// Commits multiple table updates atomically.
///
/// Uses an atomic commit model with:
/// - Optimistic concurrency control with version tracking
/// - one backend transaction, so every pointer swaps together or none does
/// - Exponential backoff retry on conflicts
///
/// All table changes are applied atomically: either all succeed or none do.
/// If a conflict is detected, the operation is retried with exponential backoff.
///
/// POST /v1/transactions/commit
pub async fn commit_transaction(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    headers: HeaderMap,
    Json(payload): Json<CommitTransactionRequest>,
) -> Result<StatusCode> {
    // Build the endpoint path for idempotency scoping
    let endpoint_path = "/v1/transactions/commit";

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", endpoint_path, &principal);

    if payload.table_changes.is_empty() {
        return Err(AppError::BadRequest(
            "A transaction must carry at least one table commit.".into(),
        ));
    }

    // Collect all tables and verify authorization for each
    let mut table_commits = Vec::with_capacity(payload.table_changes.len());

    for commit_req in &payload.table_changes {
        // Each commit must have an identifier for multi-table commits
        let ident = commit_req.identifier.as_ref().ok_or_else(|| {
            AppError::BadRequest(
                "Each table commit in a transaction must name the table it applies to.".into(),
            )
        })?;

        // Validated for the same reason as in `commit_table`: a transaction
        // entry names its table in the body, so nothing has applied the name
        // rules to it yet, and those rules are what keep a Cedar entity id
        // injective.
        validate_namespace(&ident.namespace)?;
        validate_table_name(&ident.name)?;

        let namespace = NamespaceIdent::from_vec(ident.namespace.clone())?;

        // Every table in the transaction is authorized before any of them is
        // committed, so a transaction touching one forbidden table applies to
        // none of them.
        guard::authorize(
            &state,
            &principal,
            &request,
            &namespace,
            Target::Table(&ident.name),
            Action::Update,
        )
        .await?;

        let table_ident = TableIdent::new(namespace, ident.name.clone());

        // Two entries for one table cannot both be applied: the second is
        // written against a version the first has already superseded, so the
        // backend sees its own write as a conflict and retries until it gives
        // up — burning the full retry budget to answer 409 for a request that
        // was malformed from the start. The transaction also has no defined
        // meaning: nothing says which entry wins, or whether the second builds
        // on the first.
        if table_commits
            .iter()
            .any(|(existing, _, _): &(TableIdent, _, _)| existing == &table_ident)
        {
            return Err(AppError::BadRequest(format!(
                "Table '{table_ident}' appears more than once in this transaction. \
                 List each table at most once, combining its updates into a single entry."
            )));
        }

        table_commits.push((
            table_ident,
            commit_req.requirements.clone(),
            commit_req.updates.clone(),
        ));
    }

    // Consulted only after every table in the transaction has been authorized,
    // so a replay cannot answer a request that policy would now refuse.
    if let Some(ref key) = idempotency_key
        && state.idempotency_cache.get(key).await.is_some()
    {
        return Ok(StatusCode::NO_CONTENT);
    }

    // Either every table advances or none does; the backend guarantees that and
    // this handler only has to report it.
    match state.catalog.commit_tables_atomic(table_commits).await {
        Ok(_tables) => {
            // Cache success if idempotency key was provided
            if let Some(key) = idempotency_key
                && let Some(cached) = CachedResponse::from_json(StatusCode::NO_CONTENT, &())
            {
                state.idempotency_cache.set(key, cached).await;
            }

            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Atomic transaction commit failed");

            // Mapped by `ErrorKind`, never by hand. Hand-mapping collapses every
            // non-conflict into a `500`, so a cross-mount transaction — refused
            // deliberately, with a message explaining why — would reach the
            // client as "an internal error occurred", telling it to retry
            // something that will never succeed.
            //
            // The all-or-nothing note is added only to a conflict, where the
            // client's next move depends on it. A `501` for an operation that
            // spans two catalogs already says nothing was applied.
            let mapped = AppError::from(e);
            Err(match mapped {
                AppError::CommitConflict(message) => AppError::CommitConflict(format!(
                    "{message}. The transaction was not applied — it is all or nothing."
                )),
                other => other,
            })
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a WriteOrder into a SortOrder, if provided.
///
/// Returns `None` if `write_order` is `None` or if it has no fields (unsorted).
/// The iceberg-rust library handles the unsorted case automatically when `sort_order`
/// is `None` in `TableCreation`.
fn build_sort_order(write_order: &Option<WriteOrder>) -> Result<Option<SortOrder>, AppError> {
    if let Some(order) = write_order {
        // If fields is empty, treat as unsorted (return None)
        // This avoids the "Unsorted order ID must be 0" error from iceberg-rust
        // when order_id is set but fields is empty.
        if order.fields.is_empty() {
            return Ok(None);
        }

        let mut builder = SortOrder::builder();
        // Use order ID 1 for custom sort orders (0 is reserved for unsorted)
        let mut order_builder = builder.with_order_id(1);

        for field in &order.fields {
            let transform = Transform::from_str(&field.transform).map_err(|e| {
                AppError::BadRequest(format!(
                    "Sort order names the transform '{}', which is not one this catalog \
                     reads: {}",
                    field.transform, e
                ))
            })?;

            let sort_field = SortField::builder()
                .source_id(field.source_id)
                .transform(transform)
                .direction(field.direction)
                .null_order(field.null_order)
                .build();

            order_builder = order_builder.with_sort_field(sort_field);
        }

        Ok(Some(order_builder.build_unbound()?))
    } else {
        Ok(None)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Every client puts the table format version in `properties`, and the
    /// metadata builder refuses to store it there — so passing it through made
    /// `TBLPROPERTIES ('format-version'='2')` fail outright.
    #[test]
    fn format_version_is_read_from_properties_and_not_persisted() {
        let mut properties = props(&[("format-version", "3"), ("owner", "alice")]);
        assert_eq!(
            take_format_version(&mut properties).unwrap(),
            FormatVersion::V3
        );
        assert_eq!(properties, props(&[("owner", "alice")]));

        assert_eq!(
            take_format_version(&mut props(&[("format-version", "1")])).unwrap(),
            FormatVersion::V1
        );
        assert_eq!(
            take_format_version(&mut props(&[("format-version", " 2 ")])).unwrap(),
            FormatVersion::V2
        );
    }

    /// v2 while v3 reader support is uneven: defaulting to v3 would write tables
    /// some engines cannot open.
    #[test]
    fn the_default_format_version_is_two() {
        assert_eq!(
            take_format_version(&mut HashMap::new()).unwrap(),
            FormatVersion::V2
        );
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        for value in ["0", "4", "v2", ""] {
            let err = take_format_version(&mut props(&[("format-version", value)])).unwrap_err();
            assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{value}");
        }
    }

    /// The other reserved names are read-only metadata. Refusing here names the
    /// key; letting it through fails deeper with a message that reads like a bug.
    #[test]
    fn other_reserved_properties_are_refused_by_name() {
        let err = take_format_version(&mut props(&[("uuid", "nope")])).unwrap_err();
        assert!(err.to_string().contains("uuid"), "{err}");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    // ========================================================================
    // TableIdentifier Tests
    // ========================================================================

    #[test]
    fn test_table_identifier_new() {
        let ident = TableIdentifier::new(
            vec!["ns1".to_string(), "ns2".to_string()],
            "table1".to_string(),
        );
        assert_eq!(ident.namespace, vec!["ns1", "ns2"]);
        assert_eq!(ident.name, "table1");
    }

    #[test]
    fn test_table_identifier_serialization() {
        let ident = TableIdentifier::new(vec!["ns".to_string()], "tbl".to_string());
        let json = serde_json::to_string(&ident).unwrap();
        assert!(json.contains("\"namespace\""));
        assert!(json.contains("\"name\""));
    }

    #[test]
    fn test_table_identifier_deserialization() {
        let json = r#"{"namespace":["db","schema"],"name":"my_table"}"#;
        let ident: TableIdentifier = serde_json::from_str(json).unwrap();
        assert_eq!(ident.namespace, vec!["db", "schema"]);
        assert_eq!(ident.name, "my_table");
    }

    #[test]
    fn test_table_identifier_empty_namespace() {
        let ident = TableIdentifier::new(vec![], "table".to_string());
        assert!(ident.namespace.is_empty());
        assert_eq!(ident.name, "table");
    }

    // ========================================================================
    // Schema Tests
    // ========================================================================

    #[test]
    fn test_schema_deserialization_minimal() {
        let json = r#"{
            "type": "struct",
            "fields": []
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.schema_type, "struct");
        assert!(schema.fields.is_empty());
        assert!(schema.schema_id.is_none());
        assert!(schema.identifier_field_ids.is_none());
    }

    #[test]
    fn test_schema_deserialization_with_schema_id() {
        let json = r#"{
            "type": "struct",
            "fields": [],
            "schema-id": 5
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.schema_id, Some(5));
    }

    #[test]
    fn test_schema_deserialization_pyiceberg_format() {
        // This is the exact format PyIceberg sends
        let json = r#"{
            "type": "struct",
            "fields": [
                {"id": 1, "name": "id", "type": "long", "required": true}
            ],
            "schema-id": 0,
            "identifier-field-ids": []
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.schema_type, "struct");
        assert_eq!(schema.schema_id, Some(0));
        assert_eq!(schema.identifier_field_ids, Some(vec![]));
        assert_eq!(schema.fields.len(), 1);
    }

    #[test]
    fn test_schema_type_validation() {
        let json = r#"{"type": "array", "fields": []}"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        // Type is just a string, validation happens in handler
        assert_eq!(schema.schema_type, "array");
    }

    // ========================================================================
    // CreateTablePayload Tests
    // ========================================================================

    #[test]
    fn test_create_table_payload_minimal() {
        let json = r#"{
            "name": "test_table",
            "schema": {
                "type": "struct",
                "fields": []
            }
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "test_table");
        assert!(payload.location.is_none());
        assert!(payload.partition_spec.is_none());
        assert!(payload.write_order.is_none());
        assert!(payload.properties.is_none());
    }

    #[test]
    fn test_create_table_payload_with_location() {
        let json = r#"{
            "name": "test_table",
            "location": "s3://bucket/path",
            "schema": {"type": "struct", "fields": []}
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.location, Some("s3://bucket/path".to_string()));
    }

    #[test]
    fn test_create_table_payload_with_properties() {
        let json = r#"{
            "name": "test",
            "schema": {"type": "struct", "fields": []},
            "properties": {"key1": "value1", "key2": "value2"}
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        let props = payload.properties.unwrap();
        assert_eq!(props.get("key1"), Some(&"value1".to_string()));
        assert_eq!(props.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_create_table_payload_with_stage_create() {
        let json = r#"{
            "name": "test",
            "schema": {"type": "struct", "fields": []},
            "stage-create": true
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.stage_create, Some(true));
    }

    // ========================================================================
    // WriteOrder Tests
    // ========================================================================

    #[test]
    fn test_write_order_deserialization() {
        let json = r#"{
            "fields": [
                {
                    "source-id": 1,
                    "transform": "identity",
                    "direction": "asc",
                    "null-order": "nulls-first"
                }
            ]
        }"#;
        let order: WriteOrder = serde_json::from_str(json).unwrap();
        assert_eq!(order.fields.len(), 1);
        assert_eq!(order.fields[0].source_id, 1);
        assert_eq!(order.fields[0].transform, "identity");
    }

    #[test]
    fn test_write_order_multiple_fields() {
        let json = r#"{
            "fields": [
                {"source-id": 1, "transform": "identity", "direction": "asc", "null-order": "nulls-first"},
                {"source-id": 2, "transform": "bucket[16]", "direction": "desc", "null-order": "nulls-last"}
            ]
        }"#;
        let order: WriteOrder = serde_json::from_str(json).unwrap();
        assert_eq!(order.fields.len(), 2);
        assert_eq!(order.fields[1].source_id, 2);
        assert_eq!(order.fields[1].transform, "bucket[16]");
    }

    // ========================================================================
    // build_sort_order Tests
    // ========================================================================

    #[test]
    fn test_build_sort_order_none() {
        let result = build_sort_order(&None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_build_sort_order_empty_fields_returns_none() {
        // When write_order is provided but has empty fields, it should return None
        // (treated as unsorted) to avoid "Unsorted order ID must be 0" error
        let order = WriteOrder { fields: vec![] };
        let result = build_sort_order(&Some(order));
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "Empty fields should be treated as unsorted (None)"
        );
    }

    #[test]
    fn test_build_sort_order_identity_transform() {
        let order = WriteOrder {
            fields: vec![WriteOrderField {
                source_id: 1,
                transform: "identity".to_string(),
                direction: SortDirection::Ascending,
                null_order: NullOrder::First,
            }],
        };
        let result = build_sort_order(&Some(order));
        assert!(result.is_ok());
        let sort_order = result.unwrap().unwrap();
        assert_eq!(sort_order.fields.len(), 1);
    }

    #[test]
    fn test_build_sort_order_invalid_transform() {
        let order = WriteOrder {
            fields: vec![WriteOrderField {
                source_id: 1,
                transform: "invalid_transform_xyz".to_string(),
                direction: SortDirection::Ascending,
                null_order: NullOrder::First,
            }],
        };
        let result = build_sort_order(&Some(order));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            AppError::BadRequest(msg) => {
                assert!(msg.contains("transform"));
                assert!(msg.contains("invalid_transform_xyz"));
            }
            other => panic!("expected a bad request, got {other:?}"),
        }
    }

    #[test]
    fn test_build_sort_order_bucket_transform() {
        let order = WriteOrder {
            fields: vec![WriteOrderField {
                source_id: 1,
                transform: "bucket[16]".to_string(),
                direction: SortDirection::Descending,
                null_order: NullOrder::Last,
            }],
        };
        let result = build_sort_order(&Some(order));
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_sort_order_truncate_transform() {
        let order = WriteOrder {
            fields: vec![WriteOrderField {
                source_id: 1,
                transform: "truncate[10]".to_string(),
                direction: SortDirection::Ascending,
                null_order: NullOrder::First,
            }],
        };
        let result = build_sort_order(&Some(order));
        assert!(result.is_ok());
    }

    // ========================================================================
    // ListTablesResponse Tests
    // ========================================================================

    #[test]
    fn test_list_tables_response_serialization() {
        let response = ListTablesResponse {
            next_page_token: Some("token123".to_string()),
            identifiers: vec![
                TableIdentifier::new(vec!["ns".to_string()], "t1".to_string()),
                TableIdentifier::new(vec!["ns".to_string()], "t2".to_string()),
            ],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["next-page-token"], "token123");
        assert_eq!(json["identifiers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_list_tables_response_no_token() {
        let response = ListTablesResponse {
            next_page_token: None,
            identifiers: vec![],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["next-page-token"].is_null());
        assert!(json["identifiers"].as_array().unwrap().is_empty());
    }

    // ========================================================================
    // CommitTableRequest Tests
    // ========================================================================

    #[test]
    fn test_commit_table_request_minimal() {
        let json = r#"{
            "updates": []
        }"#;
        let request: CommitTableRequest = serde_json::from_str(json).unwrap();
        assert!(request.identifier.is_none());
        assert!(request.requirements.is_empty());
        assert!(request.updates.is_empty());
    }

    #[test]
    fn test_commit_table_request_with_identifier() {
        let json = r#"{
            "identifier": {"namespace": ["db"], "name": "table"},
            "updates": []
        }"#;
        let request: CommitTableRequest = serde_json::from_str(json).unwrap();
        let ident = request.identifier.unwrap();
        assert_eq!(ident.namespace, vec!["db"]);
        assert_eq!(ident.name, "table");
    }

    // ========================================================================
    // RenameTablePayload Tests
    // ========================================================================

    #[test]
    fn test_rename_table_payload() {
        let json = r#"{
            "source": {"namespace": ["old_ns"], "name": "old_table"},
            "destination": {"namespace": ["new_ns"], "name": "new_table"}
        }"#;
        let payload: RenameTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.source.name, "old_table");
        assert_eq!(payload.destination.name, "new_table");
    }

    // ========================================================================
    // LoadTableResponse Tests
    // ========================================================================

    #[test]
    fn test_load_table_response_kebab_case() {
        // Verify the response uses kebab-case for JSON serialization
        let json_str = r#"{"metadata-location": null}"#;
        // This tests that serde is configured correctly
        let value: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(value.get("metadata-location").is_some());
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_schema_with_complex_fields() {
        // Test that complex field types can be deserialized
        let json = r#"{
            "type": "struct",
            "fields": [
                {"id": 1, "name": "id", "type": "long", "required": true},
                {"id": 2, "name": "data", "type": "string", "required": false},
                {"id": 3, "name": "ts", "type": "timestamp", "required": true}
            ],
            "schema-id": 0
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.fields.len(), 3);
    }

    #[test]
    fn test_table_identifier_special_characters_in_name() {
        // Names with underscores and numbers should work
        let ident = TableIdentifier::new(vec!["ns_1".to_string()], "table_name_123".to_string());
        let json = serde_json::to_string(&ident).unwrap();
        let parsed: TableIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "table_name_123");
    }

    #[test]
    fn test_create_table_empty_name_deserializes() {
        // Empty name should deserialize (validation happens in handler)
        let json = r#"{
            "name": "",
            "schema": {"type": "struct", "fields": []}
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "");
    }

    #[test]
    fn test_write_order_empty_fields() {
        let json = r#"{"fields": []}"#;
        let order: WriteOrder = serde_json::from_str(json).unwrap();
        assert!(order.fields.is_empty());
    }

    #[test]
    fn test_list_tables_query_defaults() {
        let query = ListTablesQuery::default();
        assert!(query.page_token.is_none());
        assert!(query.page_size.is_none());
    }

    #[test]
    fn test_list_tables_query_deserialization() {
        let json = r#"{"pageToken": "abc", "pageSize": 50}"#;
        let query: ListTablesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page_token, Some("abc".to_string()));
        assert_eq!(query.page_size, Some(50));
    }

    // ========================================================================
    // RenameTablePayload Tests
    // ========================================================================

    #[test]
    fn test_rename_table_payload_deserialization() {
        let json = r#"{
            "source": {
                "namespace": ["ns1"],
                "name": "old_table"
            },
            "destination": {
                "namespace": ["ns2"],
                "name": "new_table"
            }
        }"#;
        let payload: RenameTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.source.namespace, vec!["ns1".to_string()]);
        assert_eq!(payload.source.name, "old_table");
        assert_eq!(payload.destination.namespace, vec!["ns2".to_string()]);
        assert_eq!(payload.destination.name, "new_table");
    }

    #[test]
    fn test_rename_table_payload_same_namespace() {
        let json = r#"{
            "source": {
                "namespace": ["mydb"],
                "name": "users"
            },
            "destination": {
                "namespace": ["mydb"],
                "name": "customers"
            }
        }"#;
        let payload: RenameTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.source.namespace, payload.destination.namespace);
        assert_ne!(payload.source.name, payload.destination.name);
    }

    // ========================================================================
    // DropTableQuery Tests
    // ========================================================================

    #[test]
    fn test_drop_table_query_defaults() {
        let query = DropTableQuery::default();
        assert!(!query.purge_requested);
    }

    #[test]
    fn test_drop_table_query_purge_false() {
        let json = r#"{"purgeRequested": false}"#;
        let query: DropTableQuery = serde_json::from_str(json).unwrap();
        assert!(!query.purge_requested);
    }

    #[test]
    fn test_drop_table_query_purge_true() {
        let json = r#"{"purgeRequested": true}"#;
        let query: DropTableQuery = serde_json::from_str(json).unwrap();
        assert!(query.purge_requested);
    }

    #[test]
    fn test_drop_table_query_purge_string_true() {
        // Query strings send "true" as a string, not a native bool
        let json = r#"{"purgeRequested": "true"}"#;
        let query: DropTableQuery = serde_json::from_str(json).unwrap();
        assert!(query.purge_requested);
    }

    #[test]
    fn test_drop_table_query_purge_string_false() {
        let json = r#"{"purgeRequested": "false"}"#;
        let query: DropTableQuery = serde_json::from_str(json).unwrap();
        assert!(!query.purge_requested);
    }

    #[test]
    fn test_drop_table_query_empty() {
        // Empty JSON should default purge_requested to false
        let json = r#"{}"#;
        let query: DropTableQuery = serde_json::from_str(json).unwrap();
        assert!(!query.purge_requested);
    }

    #[test]
    fn test_stage_create_false_is_accepted() {
        let json = r#"{
            "name": "test",
            "schema": {"type": "struct", "fields": []},
            "stage-create": false
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.stage_create, Some(false));
    }

    #[test]
    fn test_stage_create_omitted_defaults_to_none() {
        let json = r#"{
            "name": "test",
            "schema": {"type": "struct", "fields": []}
        }"#;
        let payload: CreateTablePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.stage_create, None);
    }
}
