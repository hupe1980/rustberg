//! View endpoints for the Iceberg REST Catalog v1 API.
//!
//! Implements view CRUD operations following the Iceberg REST specification.
//! Views are virtual tables defined by SQL queries that get evaluated at query time.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Json as AxumJson},
};
use iceberg::spec::{
    NestedFieldRef, Schema as IcebergSchema, ViewMetadata, ViewMetadataBuilder, ViewRepresentations,
};
use iceberg::{NamespaceIdent, ViewCreation, ViewUpdate};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, AuthzContext, Resource};
use crate::catalog::extract::NamespacePath;
use crate::catalog::idempotency::{CachedResponse, IdempotencyKey, IDEMPOTENCY_KEY_USED_HEADER};
use crate::catalog::pagination::PaginationQuery;
use crate::catalog::validation::{validate_namespace, validate_properties, validate_table_name};
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

// ============================================================================
// Request/Response Types
// ============================================================================

/// View identifier with namespace and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewIdentifier {
    /// Namespace path components.
    pub namespace: Vec<String>,
    /// View name.
    pub name: String,
}

/// Response for listing views.
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListViewsResponse {
    /// Pagination token for the next page.
    pub next_page_token: Option<String>,
    /// List of view identifiers.
    pub identifiers: Vec<ViewIdentifier>,
}

/// SQL representation for view creation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SqlRepresentation {
    /// The SQL expression that defines the view.
    pub sql: String,
    /// The SQL dialect (e.g., "spark", "trino", "presto").
    pub dialect: String,
}

/// Schema definition for view creation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ViewSchema {
    /// Must be "struct".
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Schema fields.
    pub fields: Vec<NestedFieldRef>,
    /// Schema ID (optional, will default to 0).
    #[serde(default)]
    pub schema_id: Option<i32>,
}

/// Request payload for creating a view.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateViewPayload {
    /// View name.
    pub name: String,
    /// Optional view location (overrides default).
    pub location: Option<String>,
    /// View schema definition.
    pub schema: ViewSchema,
    /// View version information.
    pub view_version: CreateViewVersion,
    /// View properties.
    pub properties: Option<HashMap<String, String>>,
}

/// View version for creation request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CreateViewVersion {
    /// Schema ID for this view version (reserved for future use).
    #[serde(default)]
    #[allow(dead_code)]
    schema_id: Option<i32>,
    /// SQL representations of the view.
    pub representations: Vec<SqlRepresentation>,
    /// Default catalog for unqualified references.
    pub default_catalog: Option<String>,
    /// Default namespace for single identifier references.
    pub default_namespace: Vec<String>,
    /// Summary metadata about the version.
    #[serde(default)]
    pub summary: HashMap<String, String>,
}

/// Response for view load/create operations.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LoadViewResponse {
    /// Metadata file location.
    pub metadata_location: String,
    /// View metadata.
    pub metadata: ViewMetadata,
}

/// Request for renaming a view.
#[derive(Debug, Deserialize)]
pub struct RenameViewPayload {
    /// Source view identifier.
    pub source: ViewIdentifier,
    /// Destination view identifier.
    pub destination: ViewIdentifier,
}

/// Request payload for committing view updates.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitViewRequest {
    /// Optional view identifier (for future multi-view commits).
    #[serde(default)]
    #[allow(dead_code)]
    identifier: Option<ViewIdentifier>,
    /// Requirements that must be met for the commit to succeed.
    #[serde(default)]
    pub requirements: Vec<ViewRequirement>,
    /// Updates to apply to the view metadata.
    pub updates: Vec<ViewUpdate>,
}

/// View requirement for commit validation.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ViewRequirement {
    /// Asserts that the view UUID matches.
    #[serde(rename = "assert-view-uuid")]
    AssertViewUuid {
        /// Expected view UUID.
        uuid: String,
    },
}

/// Response for view commit operations.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommitViewResponse {
    /// Metadata file location after the commit.
    pub metadata_location: String,
    /// Updated view metadata.
    pub metadata: ViewMetadata,
}

/// Query parameters for listing views.
#[derive(Debug, Default, Deserialize)]
pub struct ListViewsQuery {
    /// Pagination: token for next page.
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,
    /// Pagination: maximum items per page.
    #[serde(rename = "pageSize")]
    pub page_size: Option<usize>,
}

// ============================================================================
// In-Memory View Storage
// ============================================================================

/// Type alias for view storage map: (namespace, name) -> (metadata_location, metadata).
type ViewMap = HashMap<(Vec<String>, String), (String, ViewMetadata)>;

/// In-memory view storage for development/testing.
///
/// For production, this should be backed by SlateDB or similar persistent storage.
#[derive(Debug, Default)]
pub struct ViewStorage {
    /// Views indexed by (namespace, name) -> (metadata_location, metadata).
    views: RwLock<ViewMap>,
}

impl ViewStorage {
    /// Creates a new view storage.
    pub fn new() -> Self {
        Self {
            views: RwLock::new(HashMap::new()),
        }
    }

    /// Lists all views in a namespace.
    pub fn list_views(&self, namespace: &[String]) -> Vec<String> {
        let views = self.views.read();
        views
            .keys()
            .filter(|(ns, _)| ns == namespace)
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Checks if a view exists.
    pub fn view_exists(&self, namespace: &[String], name: &str) -> bool {
        let views = self.views.read();
        views.contains_key(&(namespace.to_vec(), name.to_string()))
    }

    /// Loads a view by namespace and name.
    pub fn load_view(&self, namespace: &[String], name: &str) -> Option<(String, ViewMetadata)> {
        let views = self.views.read();
        views.get(&(namespace.to_vec(), name.to_string())).cloned()
    }

    /// Creates a new view. Returns error if view already exists.
    pub fn create_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;

        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if let Entry::Vacant(e) = views.entry(key) {
            e.insert((metadata_location, metadata));
            Ok(())
        } else {
            Err(AppError::ViewAlreadyExists(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    /// Updates an existing view. Returns error if view doesn't exist.
    pub fn update_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;

        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if let Entry::Occupied(mut e) = views.entry(key) {
            e.insert((metadata_location, metadata));
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    /// Drops a view. Returns error if view doesn't exist.
    pub fn drop_view(&self, namespace: &[String], name: &str) -> Result<()> {
        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if views.remove(&key).is_some() {
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    /// Renames a view. Returns error if source doesn't exist or dest exists.
    pub fn rename_view(
        &self,
        src_namespace: &[String],
        src_name: &str,
        dest_namespace: &[String],
        dest_name: &str,
    ) -> Result<()> {
        let mut views = self.views.write();
        let src_key = (src_namespace.to_vec(), src_name.to_string());
        let dest_key = (dest_namespace.to_vec(), dest_name.to_string());

        if views.contains_key(&dest_key) {
            return Err(AppError::ViewAlreadyExists(format!(
                "{}.{}",
                dest_namespace.join("."),
                dest_name
            )));
        }

        if let Some((loc, metadata)) = views.remove(&src_key) {
            // Update location if moving to different namespace
            let new_location = if src_namespace != dest_namespace {
                loc.replace(&src_namespace.join("/"), &dest_namespace.join("/"))
            } else {
                loc.replace(src_name, dest_name)
            };

            views.insert(dest_key, (new_location, metadata));
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                src_namespace.join("."),
                src_name
            )))
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Lists all views within a given namespace.
///
/// GET /v1/namespaces/{namespace}/views
pub async fn list_views(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
    axum::extract::Query(query): axum::extract::Query<ListViewsQuery>,
) -> Result<AxumJson<ListViewsResponse>> {
    // Get namespace parts
    let namespace_parts = namespace.clone().inner();

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace_parts.clone());
    let ctx = AuthzContext::new(principal, resource, Action::List);
    state.authorizer.check(&ctx).await?;

    // List views from storage
    let view_names = state.view_storage.list_views(&namespace_parts);

    let mut identifiers: Vec<ViewIdentifier> = view_names
        .into_iter()
        .map(|name| ViewIdentifier {
            namespace: namespace_parts.clone(),
            name,
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

    Ok(AxumJson(ListViewsResponse {
        next_page_token: paged.next_page_token,
        identifiers: paged.items,
    }))
}

/// Creates a new Iceberg view in the given namespace.
///
/// POST /v1/namespaces/{namespace}/views
pub async fn create_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CreateViewPayload>,
) -> Result<axum::response::Response> {
    // Validate input
    validate_table_name(&payload.name)?; // Same validation rules apply
    if let Some(ref props) = payload.properties {
        validate_properties(props)?;
    }

    // Get namespace parts
    let namespace_parts = namespace.clone().inner();

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!("/v1/namespaces/{}/views", namespace_parts.join("/"));

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", &endpoint_path);

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(cached) = state.idempotency_cache.get(key) {
            return Ok(cached.into_axum_response());
        }
    }

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace_parts.clone());
    let ctx = AuthzContext::new(principal, resource, Action::Create);
    state.authorizer.check(&ctx).await?;

    // Validate schema type
    if payload.schema.schema_type != "struct" {
        return Err(AppError::InvalidSchema(
            "Schema type must be 'struct'".to_string(),
        ));
    }

    // Build the schema
    let schema = IcebergSchema::builder()
        .with_fields(payload.schema.fields.clone())
        .with_schema_id(payload.schema.schema_id.unwrap_or(0))
        .build()?;

    // Build view representations - use serde to construct since ViewRepresentations
    // has a private constructor but implements Deserialize
    let representations_json: Vec<serde_json::Value> = payload
        .view_version
        .representations
        .into_iter()
        .map(|rep| {
            serde_json::json!({
                "type": "sql",
                "sql": rep.sql,
                "dialect": rep.dialect
            })
        })
        .collect();

    let representations: ViewRepresentations =
        serde_json::from_value(serde_json::Value::Array(representations_json)).map_err(|e| {
            AppError::ValidationError(format!("Invalid view representations: {}", e))
        })?;

    if representations.is_empty() {
        return Err(AppError::ValidationError(
            "View must have at least one SQL representation".to_string(),
        ));
    }

    // Build the default namespace
    let default_namespace = NamespaceIdent::from_vec(payload.view_version.default_namespace)?;

    // Generate view location
    let view_location = payload.location.unwrap_or_else(|| {
        format!(
            "{}/{}/{}",
            state.warehouse_location,
            namespace_parts.join("/"),
            payload.name
        )
    });

    let metadata_location = format!("{}/metadata/v1.metadata.json", view_location);

    // Build ViewCreation
    let view_creation = ViewCreation::builder()
        .name(payload.name.clone())
        .location(view_location.clone())
        .schema(schema)
        .default_namespace(default_namespace)
        .default_catalog(payload.view_version.default_catalog)
        .representations(representations)
        .summary(payload.view_version.summary)
        .properties(payload.properties.unwrap_or_default())
        .build();

    // Build ViewMetadata from ViewCreation
    let build_result = ViewMetadataBuilder::from_view_creation(view_creation)?.build()?;
    let view_metadata = build_result.metadata;

    // Store the view
    state.view_storage.create_view(
        &namespace_parts,
        &payload.name,
        metadata_location.clone(),
        view_metadata.clone(),
    )?;

    tracing::info!(
        namespace = %namespace_ident,
        view = %payload.name,
        location = %view_location,
        "Created view"
    );

    let response_body = LoadViewResponse {
        metadata_location,
        metadata: view_metadata,
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

/// Loads metadata for an existing view.
///
/// GET /v1/namespaces/{namespace}/views/{view}
pub async fn load_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, view_name)): Path<(String, String)>,
) -> Result<AxumJson<LoadViewResponse>> {
    // Parse namespace path
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();

    validate_namespace(&namespace_parts)?;
    validate_table_name(&view_name)?;

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request
    let resource = Resource::view(&owner_tenant, &namespace_parts, &view_name);
    let ctx = AuthzContext::new(principal, resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    // Load view from storage
    let (metadata_location, metadata) = state
        .view_storage
        .load_view(&namespace_parts, &view_name)
        .ok_or_else(|| {
            AppError::NoSuchView(format!("{}.{}", namespace_parts.join("."), view_name))
        })?;

    Ok(AxumJson(LoadViewResponse {
        metadata_location,
        metadata,
    }))
}

/// Checks if a view exists.
///
/// HEAD /v1/namespaces/{namespace}/views/{view}
pub async fn view_exists(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, view_name)): Path<(String, String)>,
) -> Result<StatusCode> {
    // Parse namespace path
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();

    validate_namespace(&namespace_parts)?;
    validate_table_name(&view_name)?;

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request
    let resource = Resource::view(&owner_tenant, &namespace_parts, &view_name);
    let ctx = AuthzContext::new(principal, resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    // Check if view exists
    if state.view_storage.view_exists(&namespace_parts, &view_name) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NoSuchView(format!(
            "{}.{}",
            namespace_parts.join("."),
            view_name
        )))
    }
}

/// Drops (deletes) a view.
///
/// DELETE /v1/namespaces/{namespace}/views/{view}
pub async fn drop_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, view_name)): Path<(String, String)>,
) -> Result<StatusCode> {
    // Parse namespace path
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();

    validate_namespace(&namespace_parts)?;
    validate_table_name(&view_name)?;

    // Get the namespace's owner tenant
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request
    let resource = Resource::view(&owner_tenant, &namespace_parts, &view_name);
    let ctx = AuthzContext::new(principal, resource, Action::Delete);
    state.authorizer.check(&ctx).await?;

    // Drop the view
    state.view_storage.drop_view(&namespace_parts, &view_name)?;

    tracing::info!(
        namespace = namespace_parts.join("."),
        view = %view_name,
        "Dropped view"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Commits updates to a view.
///
/// POST /v1/namespaces/{namespace}/views/{view}
pub async fn commit_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((namespace_str, view_name)): Path<(String, String)>,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CommitViewRequest>,
) -> Result<axum::response::Response> {
    // Parse namespace path
    let namespace_parts: Vec<String> = namespace_str.split('\u{1F}').map(str::to_string).collect();

    validate_namespace(&namespace_parts)?;
    validate_table_name(&view_name)?;

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/views/{}",
        namespace_parts.join("/"),
        view_name
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
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    let owner_tenant = get_namespace_owner(&state, &namespace_ident, principal.tenant_id()).await?;

    // Authorize the request
    let resource = Resource::view(&owner_tenant, &namespace_parts, &view_name);
    let ctx = AuthzContext::new(principal, resource, Action::Update);
    state.authorizer.check(&ctx).await?;

    // Load current view
    let (current_metadata_location, current_metadata) = state
        .view_storage
        .load_view(&namespace_parts, &view_name)
        .ok_or_else(|| {
            AppError::NoSuchView(format!("{}.{}", namespace_parts.join("."), view_name))
        })?;

    // Validate requirements
    for requirement in &payload.requirements {
        match requirement {
            ViewRequirement::AssertViewUuid { uuid } => {
                let expected_uuid = Uuid::parse_str(uuid)
                    .map_err(|_| AppError::ValidationError(format!("Invalid UUID: {}", uuid)))?;
                if current_metadata.uuid() != expected_uuid {
                    return Err(AppError::CommitConflict(format!(
                        "View UUID mismatch: expected {}, found {}",
                        expected_uuid,
                        current_metadata.uuid()
                    )));
                }
            }
        }
    }

    // Apply updates using ViewMetadataBuilder
    let mut metadata_builder = current_metadata.into_builder();

    for update in payload.updates {
        metadata_builder = apply_view_update(metadata_builder, update)?;
    }

    let build_result = metadata_builder.build()?;
    let new_metadata = build_result.metadata;

    // Generate new metadata location
    let new_metadata_location = generate_new_view_metadata_location(&current_metadata_location)?;

    // Update storage
    state.view_storage.update_view(
        &namespace_parts,
        &view_name,
        new_metadata_location.clone(),
        new_metadata.clone(),
    )?;

    tracing::info!(
        namespace = namespace_parts.join("."),
        view = %view_name,
        "Committed view updates"
    );

    let response_body = CommitViewResponse {
        metadata_location: new_metadata_location,
        metadata: new_metadata,
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

/// Applies a single ViewUpdate to the metadata builder.
fn apply_view_update(
    builder: ViewMetadataBuilder,
    update: ViewUpdate,
) -> Result<ViewMetadataBuilder> {
    match update {
        ViewUpdate::AssignUuid { uuid } => Ok(builder.assign_uuid(uuid)),
        ViewUpdate::UpgradeFormatVersion { format_version } => builder
            .upgrade_format_version(format_version)
            .map_err(Into::into),
        ViewUpdate::AddSchema { schema, .. } => {
            // Note: last_column_id is not supported in ViewMetadataBuilder
            Ok(builder.add_schema(schema))
        }
        ViewUpdate::SetLocation { location } => Ok(builder.set_location(location)),
        ViewUpdate::SetProperties { updates } => {
            builder.set_properties(updates).map_err(Into::into)
        }
        ViewUpdate::RemoveProperties { removals } => Ok(builder.remove_properties(&removals)),
        ViewUpdate::AddViewVersion { view_version } => {
            builder.add_version(view_version).map_err(Into::into)
        }
        ViewUpdate::SetCurrentViewVersion { view_version_id } => builder
            .set_current_version_id(view_version_id)
            .map_err(Into::into),
    }
}

/// Renames a view.
///
/// POST /v1/views/rename
pub async fn rename_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    AxumJson(payload): AxumJson<RenameViewPayload>,
) -> Result<StatusCode> {
    // Validate source
    validate_namespace(&payload.source.namespace)?;
    validate_table_name(&payload.source.name)?;

    // Validate destination
    validate_namespace(&payload.destination.namespace)?;
    validate_table_name(&payload.destination.name)?;

    // Get source namespace owner
    let src_namespace_ident = NamespaceIdent::from_vec(payload.source.namespace.clone())?;
    let src_owner =
        get_namespace_owner(&state, &src_namespace_ident, principal.tenant_id()).await?;

    // Get destination namespace owner
    let dest_namespace_ident = NamespaceIdent::from_vec(payload.destination.namespace.clone())?;
    let dest_owner =
        get_namespace_owner(&state, &dest_namespace_ident, principal.tenant_id()).await?;

    // Prevent cross-tenant renames
    if src_owner != dest_owner {
        return Err(AppError::Forbidden(
            "Cannot rename view across tenants".to_string(),
        ));
    }

    // Authorize delete on source
    let src_resource = Resource::view(&src_owner, &payload.source.namespace, &payload.source.name);
    let delete_ctx = AuthzContext::new(principal.clone(), src_resource, Action::Delete);
    state.authorizer.check(&delete_ctx).await?;

    // Authorize create on destination namespace
    let dest_resource = Resource::namespace(&dest_owner, payload.destination.namespace.clone());
    let create_ctx = AuthzContext::new(principal, dest_resource, Action::Create);
    state.authorizer.check(&create_ctx).await?;

    // Perform the rename
    state.view_storage.rename_view(
        &payload.source.namespace,
        &payload.source.name,
        &payload.destination.namespace,
        &payload.destination.name,
    )?;

    tracing::info!(
        source = format!(
            "{}.{}",
            payload.source.namespace.join("."),
            payload.source.name
        ),
        destination = format!(
            "{}.{}",
            payload.destination.namespace.join("."),
            payload.destination.name
        ),
        "Renamed view"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Generates a new metadata location by incrementing the version number.
fn generate_new_view_metadata_location(current_location: &str) -> Result<String> {
    use std::path::Path;

    let path = Path::new(current_location);
    let parent = path.parent().map(|p| p.to_string_lossy().to_string());
    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| AppError::Internal("Invalid metadata location".to_string()))?;

    // Parse version from filename like "v1.metadata.json" -> "v2.metadata.json"
    if let Some(version_str) = filename.strip_prefix('v').and_then(|s| s.split('.').next()) {
        if let Ok(version) = version_str.parse::<i32>() {
            let new_filename = format!("v{}.metadata.json", version + 1);
            return Ok(format!(
                "{}/{}",
                parent.unwrap_or_else(|| ".".to_string()),
                new_filename
            ));
        }
    }

    // Fallback: append timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    Ok(format!(
        "{}/v{}.metadata.json",
        parent.unwrap_or_else(|| ".".to_string()),
        timestamp
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_identifier_serialization() {
        let id = ViewIdentifier {
            namespace: vec!["db".to_string(), "schema".to_string()],
            name: "my_view".to_string(),
        };

        let json = serde_json::to_string(&id).unwrap();
        assert!(json.contains("\"namespace\""));
        assert!(json.contains("\"name\""));
    }

    #[test]
    fn test_view_storage_basic_operations() {
        let storage = ViewStorage::new();
        let namespace = vec!["test".to_string()];

        // Initially empty
        assert!(storage.list_views(&namespace).is_empty());
        assert!(!storage.view_exists(&namespace, "view1"));

        // Create representations using serde (since ViewRepresentations has private constructor)
        let representations: ViewRepresentations = serde_json::from_value(serde_json::json!([
            {"type": "sql", "sql": "SELECT 1", "dialect": "spark"}
        ]))
        .unwrap();

        // Create a mock ViewMetadata
        let view_creation = ViewCreation::builder()
            .name("view1".to_string())
            .location("/test/view1".to_string())
            .schema(
                IcebergSchema::builder()
                    .with_fields(vec![])
                    .build()
                    .unwrap(),
            )
            .default_namespace(NamespaceIdent::new("default".to_string()))
            .representations(representations)
            .build();

        let build_result = ViewMetadataBuilder::from_view_creation(view_creation)
            .unwrap()
            .build()
            .unwrap();
        let metadata = build_result.metadata;

        // Create view
        storage
            .create_view(
                &namespace,
                "view1",
                "/test/metadata.json".to_string(),
                metadata.clone(),
            )
            .unwrap();

        // Verify exists
        assert!(storage.view_exists(&namespace, "view1"));
        assert_eq!(storage.list_views(&namespace), vec!["view1".to_string()]);

        // Load view
        let (loc, loaded) = storage.load_view(&namespace, "view1").unwrap();
        assert_eq!(loc, "/test/metadata.json");
        assert_eq!(loaded.uuid(), metadata.uuid());

        // Cannot create duplicate
        let result = storage.create_view(
            &namespace,
            "view1",
            "/other.json".to_string(),
            metadata.clone(),
        );
        assert!(result.is_err());

        // Drop view
        storage.drop_view(&namespace, "view1").unwrap();
        assert!(!storage.view_exists(&namespace, "view1"));

        // Cannot drop non-existent
        let result = storage.drop_view(&namespace, "view1");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_new_view_metadata_location() {
        let loc =
            generate_new_view_metadata_location("/warehouse/db/view/metadata/v1.metadata.json")
                .unwrap();
        assert!(loc.contains("v2.metadata.json"));

        let loc2 =
            generate_new_view_metadata_location("/warehouse/db/view/metadata/v99.metadata.json")
                .unwrap();
        assert!(loc2.contains("v100.metadata.json"));
    }

    #[test]
    fn test_sql_representation_deserialization() {
        let json = r#"{"sql": "SELECT * FROM t", "dialect": "spark"}"#;
        let rep: SqlRepresentation = serde_json::from_str(json).unwrap();
        assert_eq!(rep.sql, "SELECT * FROM t");
        assert_eq!(rep.dialect, "spark");
    }

    #[test]
    fn test_view_requirement_deserialization() {
        let json =
            r#"{"type": "assert-view-uuid", "uuid": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let req: ViewRequirement = serde_json::from_str(json).unwrap();
        match req {
            ViewRequirement::AssertViewUuid { uuid } => {
                assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            }
        }
    }
}
