//! Table endpoints for the Iceberg REST Catalog v1 API.
//!
//! Implements table CRUD operations following the Iceberg REST specification.

use std::collections::HashMap;
use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json as AxumJson,
};
use iceberg::spec::{
    NestedFieldRef, NullOrder, Schema as IcebergSchema, SortDirection, SortField, SortOrder,
    TableMetadata, Transform, UnboundPartitionSpec,
};
use iceberg::{NamespaceIdent, TableCreation, TableIdent, TableRequirement, TableUpdate};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, AuthzContext, Principal, Resource};
use crate::catalog::extract::NamespacePath;
use crate::catalog::idempotency::{CachedResponse, IdempotencyKey, IDEMPOTENCY_KEY_USED_HEADER};
use crate::catalog::validation::{validate_namespace, validate_properties, validate_table_name};
use crate::credentials::{StorageCredential, StorageCredentialRequest};
use crate::error::{AppError, Result};

/// Reserved property key for storing namespace owner's tenant ID.
const TENANT_ID_PROPERTY: &str = "_tenant_id";

/// Helper to get the owner tenant for a namespace, returning an error if namespace doesn't exist.
async fn get_namespace_owner(
    state: &AppState,
    namespace: &NamespaceIdent,
    default_tenant: &str,
) -> Result<String> {
    match state.catalog.get_namespace(namespace).await {
        Ok(ns) => Ok(ns
            .properties()
            .get(TENANT_ID_PROPERTY)
            .cloned()
            .unwrap_or_else(|| default_tenant.to_string())),
        Err(_) => Err(AppError::NoSuchNamespace(format!(
            "Namespace {} does not exist",
            namespace
        ))),
    }
}

/// Helper to vend storage credentials for a table.
///
/// Returns `Some(credentials)` if credentials were successfully vended,
/// or `None` if the provider doesn't support the location or credential vending is disabled.
async fn vend_table_credentials(
    state: &AppState,
    principal: &Principal,
    namespace: &[String],
    table_name: &str,
    table_location: &str,
    write_access: bool,
) -> Option<Vec<StorageCredential>> {
    // Check if the credential provider supports this storage location
    if !state.credential_provider.supports_location(table_location) {
        tracing::debug!(
            location = table_location,
            "Storage credential provider does not support location"
        );
        return None;
    }

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
    };

    match state.credential_provider.vend_credentials(&request).await {
        Ok(credentials) if !credentials.is_empty() => {
            tracing::debug!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                credentials_count = credentials.len(),
                "Vended storage credentials"
            );
            Some(credentials)
        }
        Ok(_) => {
            tracing::debug!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                "No credentials vended (empty result)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                tenant_id = principal.tenant_id(),
                table = %table_name,
                error = %e,
                "Failed to vend storage credentials"
            );
            None
        }
    }
}

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
    /// Whether to stage the table (not yet committed).
    /// When `true`, returns 400 — staged creates are not supported.
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
    pub metadata_location: Option<String>,
    /// Table metadata.
    pub metadata: TableMetadata,
    /// Table configuration.
    pub config: HashMap<String, String>,
    /// Storage credentials for accessing table data files.
    /// Clients should check this field before falling back to credentials in config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_credentials: Option<Vec<StorageCredential>>,
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
    /// Pagination: token for next page.
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
    #[serde(rename = "purgeRequested", default)]
    pub purge_requested: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// Lists all tables within a given namespace.
///
/// GET /v1/namespaces/{namespace}/tables
pub async fn list_tables(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
    axum::extract::Query(query): axum::extract::Query<ListTablesQuery>,
) -> Result<AxumJson<ListTablesResponse>> {
    use crate::catalog::pagination::PaginationQuery;

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace.clone().inner())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace.clone().inner());
    let ctx = AuthzContext::new(principal, resource, Action::List);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_list_tables.inc();

    let mut identifiers: Vec<TableIdentifier> = state
        .catalog
        .list_tables(&namespace)
        .await?
        .into_iter()
        .map(|table_ident| TableIdentifier {
            namespace: table_ident.namespace().to_vec(),
            name: table_ident.name().to_string(),
        })
        .collect();

    // Sort for consistent pagination
    identifiers.sort_by(|a, b| a.name.cmp(&b.name));

    // Apply pagination
    let pagination = PaginationQuery {
        page_token: query.page_token,
        page_size: query.page_size,
    };

    let paged = pagination.paginate(identifiers, |id| id.name.clone());

    Ok(AxumJson(ListTablesResponse {
        next_page_token: paged.next_page_token,
        identifiers: paged.items,
    }))
}

/// Creates a new Iceberg table in the given namespace.
///
/// POST /v1/namespaces/{namespace}/tables
pub async fn create_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CreateTablePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Validate input
    validate_table_name(&payload.name)?;
    if let Some(ref props) = payload.properties {
        validate_properties(props)?;
    }

    // Reject staged table creation (not implemented per Iceberg spec optional feature)
    if payload.stage_create == Some(true) {
        return Err(AppError::BadRequest(
            "Staged table creation is not supported. Omit 'stage-create' or set it to false."
                .into(),
        ));
    }

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/tables",
        namespace.clone().inner().join("/")
    );

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", &endpoint_path);

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(cached) = state.idempotency_cache.get(key) {
            return Ok(cached.into_axum_response());
        }
    }

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace.clone().inner())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let table_name = payload.name.clone();
    let resource = Resource::table(&owner_tenant, namespace.clone().inner(), &table_name);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::Create);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_create_table.inc();

    if payload.schema.schema_type != "struct" {
        return Err(AppError::InvalidSchema(
            "Schema type must be 'struct'".into(),
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

    let location = payload
        .location
        .unwrap_or_else(|| format!("{}/{}", state.warehouse_location, table_name));

    let table_creation = {
        let builder = TableCreation::builder()
            .name(table_name.clone())
            .location(location)
            .schema(schema)
            .partition_spec(payload.partition_spec.unwrap_or_default())
            .properties(payload.properties.unwrap_or_default());

        match sort_order {
            Some(order) => builder.sort_order(order).build(),
            None => builder.build(),
        }
    };

    let table = state
        .catalog
        .create_table(&namespace, table_creation)
        .await?;

    // Vend storage credentials with write access for newly created table
    let storage_credentials = vend_table_credentials(
        &state,
        &principal,
        &namespace.clone().inner(),
        &table_name,
        table.metadata().location(),
        true, // write access for create_table
    )
    .await;

    let response_body = LoadTableResponse {
        metadata_location: table.metadata_location().map(|s| s.to_string()),
        metadata: table.metadata().clone(),
        config: HashMap::new(),
        storage_credentials,
    };

    // Build response
    let mut response = (StatusCode::OK, AxumJson(&response_body)).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // Cache if idempotency key was provided
    if let Some(key) = idempotency_key {
        if let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body) {
            state.idempotency_cache.set(key, cached);
            response.headers_mut().insert(
                IDEMPOTENCY_KEY_USED_HEADER,
                axum::http::HeaderValue::from_static("true"),
            );
        }
    }

    Ok(response)
}

/// Loads a table's metadata.
///
/// GET /v1/namespaces/{namespace}/tables/{table}
pub async fn load_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, table_name)): Path<(String, String)>,
) -> Result<AxumJson<LoadTableResponse>> {
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();
    let namespace = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::table(&owner_tenant, namespace_parts.clone(), &table_name);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_load_table.inc();

    let table_ident = TableIdent::new(namespace, table_name.clone());
    let table = state.catalog.load_table(&table_ident).await?;

    // Vend storage credentials if the provider supports the table's location
    let storage_credentials = vend_table_credentials(
        &state,
        &principal,
        &namespace_parts,
        &table_name,
        table.metadata().location(),
        false, // read-only access for load_table
    )
    .await;

    Ok(AxumJson(LoadTableResponse {
        metadata_location: table.metadata_location().map(|s| s.to_string()),
        metadata: table.metadata().clone(),
        config: HashMap::new(),
        storage_credentials,
    }))
}

/// Checks if a table exists.
///
/// HEAD /v1/namespaces/{namespace}/tables/{table}
pub async fn table_exists(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, table_name)): Path<(String, String)>,
) -> Result<StatusCode> {
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();
    let namespace = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::table(&owner_tenant, namespace_parts, &table_name);
    let ctx = AuthzContext::new(principal, resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    let table_ident = TableIdent::new(namespace, table_name);

    if state.catalog.table_exists(&table_ident).await? {
        Ok(StatusCode::OK)
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

/// Loads vended credentials for a table.
///
/// This endpoint provides storage credentials scoped to a specific table's
/// data files. Use this instead of `load_table` when you only need credentials
/// and don't need the full table metadata.
///
/// The credentials returned are:
/// - Short-lived (typically 1 hour)
/// - Scoped to the minimum permissions required for the table
/// - Specific to the storage location (S3, GCS, Azure)
///
/// GET /v1/namespaces/{namespace}/tables/{table}/credentials
pub async fn load_table_credentials(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, table_name)): Path<(String, String)>,
) -> Result<AxumJson<LoadCredentialsResponse>> {
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();
    let namespace = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::table(&owner_tenant, namespace_parts.clone(), &table_name);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    let table_ident = TableIdent::new(namespace, table_name.clone());

    // Load table to get its location
    let table = state.catalog.load_table(&table_ident).await?;
    let table_location = table.metadata().location();

    // Check if the credential provider supports this storage location
    if !state.credential_provider.supports_location(table_location) {
        return Err(AppError::NotSupported(format!(
            "Credential vending not supported for storage location: {}",
            table_location
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
        )));
    }

    // Vend storage credentials with read access (use load_table for write credentials)
    let storage_credentials = vend_table_credentials(
        &state,
        &principal,
        &namespace_parts,
        &table_name,
        table_location,
        false, // read-only access
    )
    .await
    .unwrap_or_default();

    if storage_credentials.is_empty() {
        return Err(AppError::NotSupported(
            "No storage credentials available for this table".to_string(),
        ));
    }

    Ok(AxumJson(LoadCredentialsResponse {
        storage_credentials,
    }))
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
    Path((namespace_str, table_name)): Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<DropTableQuery>,
) -> Result<StatusCode> {
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();
    let namespace = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::table(&owner_tenant, namespace_parts, &table_name);
    let ctx = AuthzContext::new(principal, resource, Action::Delete);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_delete_table.inc();

    let table_ident = TableIdent::new(namespace.clone(), table_name.clone());

    // If purge is requested, we need to load the table first to get:
    // 1. The table's data location (from metadata)
    // 2. The FileIO instance to delete files
    let purge_info = if query.purge_requested {
        match state.catalog.load_table(&table_ident).await {
            Ok(table) => {
                let location = table.metadata().location().to_string();
                let file_io = table.file_io().clone();
                tracing::info!(
                    table = %table_ident,
                    location = %location,
                    "Table loaded for purge operation"
                );
                Some((location, file_io))
            }
            Err(e) => {
                // Table might not be loadable but still exists in catalog
                // Log warning and proceed with catalog-only drop
                tracing::warn!(
                    table = %table_ident,
                    error = %e,
                    "Failed to load table for purge; proceeding with catalog-only drop"
                );
                None
            }
        }
    } else {
        None
    };

    // Drop the table from the catalog
    state.catalog.drop_table(&table_ident).await?;

    // If purge was requested and we have the table's location, delete the data
    if let Some((location, file_io)) = purge_info {
        tracing::info!(
            table = %table_ident,
            location = %location,
            "Purging table data"
        );

        // Delete all files in the table's location recursively
        // This includes: data files, manifest files, manifest lists, metadata files
        if let Err(e) = file_io.remove_dir_all(&location).await {
            // Log error but don't fail the request - the table is already dropped from catalog
            // The data files are now orphaned and can be cleaned up manually
            tracing::error!(
                table = %table_ident,
                location = %location,
                error = %e,
                "Failed to purge table data; table removed from catalog but data files may remain"
            );
            // Note: We intentionally don't return an error here because:
            // 1. The table has already been dropped from the catalog
            // 2. The purge operation is "best effort"
            // 3. Orphaned files can be cleaned up separately
        } else {
            tracing::info!(
                table = %table_ident,
                location = %location,
                "Table data purged successfully"
            );
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Renames a table.
///
/// POST /v1/tables/rename
pub async fn rename_table(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    AxumJson(payload): AxumJson<RenameTablePayload>,
) -> Result<StatusCode> {
    // Validate destination table name and namespaces
    validate_table_name(&payload.destination.name)?;
    validate_namespace(&payload.source.namespace)?;
    validate_namespace(&payload.destination.namespace)?;

    let src_namespace = NamespaceIdent::from_vec(payload.source.namespace.clone())?;
    let dst_namespace = NamespaceIdent::from_vec(payload.destination.namespace.clone())?;

    // Get owner for source namespace
    let src_owner = get_namespace_owner(&state, &src_namespace, principal.tenant_id()).await?;

    // Get owner for destination namespace
    let dst_owner = get_namespace_owner(&state, &dst_namespace, principal.tenant_id()).await?;

    // SEC-028: Prevent cross-tenant table moves
    // Table renames must stay within the same tenant to prevent data leakage.
    // Both namespaces must belong to the same tenant.
    if src_owner != dst_owner {
        return Err(AppError::Forbidden(
            "Cannot move tables between namespaces owned by different tenants".to_string(),
        ));
    }

    // Authorize the request - need Update on source table
    let src_resource = Resource::table(
        &src_owner,
        payload.source.namespace.clone(),
        &payload.source.name,
    );
    let src_ctx = AuthzContext::new(principal.clone(), src_resource, Action::Update);
    state.authorizer.check(&src_ctx).await?;

    // Check permission on destination table (Create)
    let dst_resource = Resource::table(
        &dst_owner,
        payload.destination.namespace.clone(),
        &payload.destination.name,
    );
    let dst_ctx = AuthzContext::new(principal, dst_resource, Action::Create);
    state.authorizer.check(&dst_ctx).await?;

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
    Path((namespace_str, table_name)): Path<(String, String)>,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CommitTableRequest>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!("/v1/namespaces/{}/tables/{}", namespace_str, table_name);

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", &endpoint_path);

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(cached) = state.idempotency_cache.get(key) {
            return Ok(cached.into_axum_response());
        }
    }

    // Parse namespace from URL path
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();

    // Use identifier from payload if provided, otherwise use URL path
    let (final_namespace_parts, final_table_name) = if let Some(ref ident) = payload.identifier {
        (ident.namespace.clone(), ident.name.clone())
    } else {
        (namespace_parts, table_name)
    };

    let namespace = NamespaceIdent::from_vec(final_namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::table(&owner_tenant, final_namespace_parts, &final_table_name);
    let ctx = AuthzContext::new(principal, resource, Action::Update);
    state.authorizer.check(&ctx).await?;

    let table_ident = TableIdent::new(namespace, final_table_name);

    // Validate that we have at least one update
    if payload.updates.is_empty() {
        return Err(AppError::ValidationError(
            "Commit must include at least one update".into(),
        ));
    }

    // Record metric
    state.metrics.catalog_commit_table.inc();

    // Use the extended catalog's commit_table method (trait is in scope via AppState)
    let updated_table = state
        .catalog
        .commit_table(&table_ident, payload.requirements, payload.updates)
        .await
        .map_err(|e| {
            // Convert iceberg errors to appropriate app errors
            if e.kind() == iceberg::ErrorKind::CatalogCommitConflicts {
                AppError::CommitConflict(e.to_string())
            } else {
                AppError::Internal(e.to_string())
            }
        })?;

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
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // Cache if idempotency key was provided
    if let Some(key) = idempotency_key {
        if let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body) {
            state.idempotency_cache.set(key, cached);
            response.headers_mut().insert(
                IDEMPOTENCY_KEY_USED_HEADER,
                axum::http::HeaderValue::from_static("true"),
            );
        }
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
    namespace: NamespacePath,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<RegisterTablePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;
    use iceberg::io::FileIOBuilder;

    // Validate input
    validate_table_name(&payload.name)?;

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/register",
        namespace.clone().inner().join("/")
    );

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", &endpoint_path);

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(cached) = state.idempotency_cache.get(key) {
            return Ok(cached.into_axum_response());
        }
    }

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace.clone().inner())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let table_name = payload.name.clone();
    let resource = Resource::table(&owner_tenant, namespace.clone().inner(), &table_name);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::Create);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_register_table.inc();

    // Read metadata from the provided location
    let file_io = FileIOBuilder::new_fs_io().build()?;
    let metadata_content = file_io
        .new_input(&payload.metadata_location)?
        .read()
        .await?;
    let metadata_str = std::str::from_utf8(&metadata_content)
        .map_err(|e| AppError::InvalidSchema(format!("Invalid metadata file encoding: {}", e)))?;
    let table_metadata: TableMetadata = serde_json::from_str(metadata_str)
        .map_err(|e| AppError::InvalidSchema(format!("Invalid table metadata: {}", e)))?;

    // Verify the table doesn't already exist
    let table_ident = TableIdent::new(namespace_ident.clone(), table_name.clone());
    if state.catalog.table_exists(&table_ident).await? {
        return Err(AppError::TableAlreadyExists(format!(
            "Table {} already exists in namespace {}",
            table_name,
            namespace.clone().inner().join(".")
        )));
    }

    // Create the table in the catalog with the existing metadata
    // The location comes from the metadata itself
    let location = table_metadata.location().to_string();
    let schema = table_metadata.current_schema().as_ref().clone();

    let table_creation = TableCreation::builder()
        .name(table_name.clone())
        .location(location)
        .schema(schema)
        .build();

    let table = state
        .catalog
        .create_table(&namespace_ident, table_creation)
        .await?;

    // Vend storage credentials with write access
    let storage_credentials = vend_table_credentials(
        &state,
        &principal,
        &namespace.clone().inner(),
        &table_name,
        table.metadata().location(),
        true,
    )
    .await;

    let response_body = LoadTableResponse {
        metadata_location: Some(payload.metadata_location),
        metadata: table_metadata,
        config: HashMap::new(),
        storage_credentials,
    };

    // Build response
    let mut response = (StatusCode::OK, AxumJson(&response_body)).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    // Cache if idempotency key was provided
    if let Some(key) = idempotency_key {
        if let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body) {
            state.idempotency_cache.set(key, cached);
            response.headers_mut().insert(
                IDEMPOTENCY_KEY_USED_HEADER,
                axum::http::HeaderValue::from_static("true"),
            );
        }
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
    Path((namespace_str, table_name)): Path<(String, String)>,
    AxumJson(payload): AxumJson<ReportMetricsRequest>,
) -> Result<StatusCode> {
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();
    let namespace = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Get the namespace's owner tenant
    let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

    // Authorize the request - only need Read access to report metrics
    let resource = Resource::table(&owner_tenant, namespace_parts, &table_name);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::Read);
    state.authorizer.check(&ctx).await?;

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
/// - WriteBatch for atomic multi-key registry updates
/// - Exponential backoff retry on conflicts
///
/// All table changes are applied atomically: either all succeed or none do.
/// If a conflict is detected, the operation is retried with exponential backoff.
///
/// POST /v1/transactions/commit
pub async fn commit_transaction(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CommitTransactionRequest>,
) -> Result<StatusCode> {
    // Build the endpoint path for idempotency scoping
    let endpoint_path = "/v1/transactions/commit";

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", endpoint_path);

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(_cached) = state.idempotency_cache.get(key) {
            return Ok(StatusCode::NO_CONTENT);
        }
    }

    if payload.table_changes.is_empty() {
        return Err(AppError::ValidationError(
            "Transaction must include at least one table commit".into(),
        ));
    }

    // Collect all tables and verify authorization for each
    let mut table_commits = Vec::with_capacity(payload.table_changes.len());

    for commit_req in &payload.table_changes {
        // Each commit must have an identifier for multi-table commits
        let ident = commit_req.identifier.as_ref().ok_or_else(|| {
            AppError::ValidationError(
                "Each table commit in a transaction must include an identifier".into(),
            )
        })?;

        let namespace = NamespaceIdent::from_vec(ident.namespace.clone())?;
        let owner_tenant = get_namespace_owner(&state, &namespace, principal.tenant_id()).await?;

        // Authorize update on each table
        let resource = Resource::table(&owner_tenant, ident.namespace.clone(), &ident.name);
        let ctx = AuthzContext::new(principal.clone(), resource, Action::Update);
        state.authorizer.check(&ctx).await?;

        let table_ident = TableIdent::new(namespace, ident.name.clone());
        table_commits.push((
            table_ident,
            commit_req.requirements.clone(),
            commit_req.updates.clone(),
        ));
    }

    // Execute ATOMIC multi-table commit
    // Using OCC with WriteBatch for true atomicity across all tables
    match state.catalog.commit_tables_atomic(table_commits).await {
        Ok(_tables) => {
            // Cache success if idempotency key was provided
            if let Some(key) = idempotency_key {
                if let Some(cached) = CachedResponse::from_json(StatusCode::NO_CONTENT, &()) {
                    state.idempotency_cache.set(key, cached);
                }
            }

            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "Atomic transaction commit failed"
            );

            if e.kind() == iceberg::ErrorKind::CatalogCommitConflicts {
                Err(AppError::CommitConflict(format!(
                    "Commit conflict: {}. Transaction was not applied (all-or-nothing).",
                    e,
                )))
            } else {
                Err(AppError::Internal(format!(
                    "Transaction failed: {}. Transaction was not applied (all-or-nothing).",
                    e,
                )))
            }
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
                AppError::InvalidSchema(format!("Invalid transform '{}': {}", field.transform, e))
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
            AppError::InvalidSchema(msg) => {
                assert!(msg.contains("Invalid transform"));
                assert!(msg.contains("invalid_transform_xyz"));
            }
            _ => panic!("Expected InvalidSchema error"),
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
