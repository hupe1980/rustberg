//! View endpoints for the Iceberg REST Catalog v1 API.
//!
//! Implements view CRUD operations following the Iceberg REST specification.
//! Views are virtual tables defined by SQL queries that get evaluated at query time.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Json as AxumJson},
};
use iceberg::spec::{
    NestedFieldRef, Schema as IcebergSchema, ViewMetadata, ViewMetadataBuilder, ViewRepresentations,
};
use iceberg::{NamespaceIdent, TableIdent, ViewCreation, ViewUpdate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::extract::{Json, NamespacePath, ViewPath};
use super::guard::{self, Target};
use super::idempotency::{CachedResponse, IdempotencyKey};
use super::pagination::{PaginationQuery, collect_page};
use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, RequestFacts};
use crate::error::{AppError, Result};
use crate::names::{validate_namespace, validate_properties, validate_table_name};

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
    #[allow(dead_code)] // Deserialized per Iceberg REST spec; reserved for future use
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

/// Request body for `register-view`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RegisterViewPayload {
    /// View name to register under.
    pub name: String,
    /// Location of the existing view metadata file.
    pub metadata_location: String,
}

/// `POST /v1/{prefix}/namespaces/{namespace}/register-view`
///
/// Adopts view metadata that already exists in storage, the mirror of
/// `register` for tables. The metadata file is read, never rewritten, so the
/// view's version history survives being moved between catalogs.
pub async fn register_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    Json(payload): Json<RegisterViewPayload>,
) -> Result<AxumJson<LoadViewResponse>> {
    validate_table_name(&payload.name)?;

    let namespace_parts = namespace.clone().inner();
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;

    // Confined before it is recorded, for the reason `registerTable` is: the
    // location becomes something this catalog manages and hands out. The bound
    // is this view's own prefix, and under federation the warehouse it is built
    // from is the mount's rather than the server's. See
    // `crate::location::LocationScope`.
    state
        .location_bound(&namespace_ident, &payload.name)
        .await
        .ensure(&payload.metadata_location)?;

    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace_ident,
        Target::View(&payload.name),
        Action::Create,
    )
    .await?;

    let view_ident = TableIdent::new(namespace_ident, payload.name.clone());
    let (metadata_location, metadata) = state
        .catalog
        .register_view(&view_ident, payload.metadata_location.clone())
        .await?;

    // As with a registered table, the metadata file being inside the warehouse
    // does not mean the view it describes is: the file can declare any
    // `location` it likes. A rejection has to undo the pointer, which is all
    // registration wrote.
    if let Err(rejected) = state
        .location_bound(view_ident.namespace(), view_ident.name())
        .await
        .ensure(metadata.location())
    {
        if let Err(cleanup) = state.catalog.drop_view(&view_ident).await {
            tracing::error!(
                view = %view_ident,
                error = %cleanup,
                "Failed to unregister a view whose metadata pointed outside the warehouse"
            );
        }
        tracing::warn!(
            tenant_id = principal.tenant_id(),
            view = %view_ident,
            declared_location = %metadata.location(),
            "Refused to register a view whose metadata declares a location outside the warehouse"
        );
        return Err(rejected);
    }

    tracing::info!(view = %view_ident, "Registered existing view");

    Ok(AxumJson(LoadViewResponse {
        metadata_location,
        metadata,
    }))
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
    /// Optional view identifier, which the spec lets the body repeat.
    ///
    /// It is *checked*, not honoured: the URL is authoritative, and a body that
    /// names a different view is a client error. Accepting and ignoring it is
    /// worse than either — a field that reads like it selects the view and does
    /// not, in a path that authorizes.
    #[serde(default)]
    pub identifier: Option<ViewIdentifier>,
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
    /// Pagination: token for the next page.
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,
    /// Pagination: maximum items per page.
    #[serde(rename = "pageSize")]
    pub page_size: Option<usize>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Lists the views in a namespace that the caller may see.
///
/// Filtered per view, before the page is cut, for the reasons given on
/// [`list_tables`](super::table::list_tables).
///
/// GET /v1/namespaces/{namespace}/views
pub async fn list_views(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    axum::extract::Query(query): axum::extract::Query<ListViewsQuery>,
) -> Result<AxumJson<ListViewsResponse>> {
    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::List,
    )
    .await?;

    let page = collect_page(
        PaginationQuery::new(query.page_token, query.page_size).to_request()?,
        |page_request| {
            let state = state.clone();
            let namespace = namespace.0.clone();
            async move {
                state
                    .catalog
                    .list_views(&namespace, &page_request)
                    .await
                    .map_err(AppError::from)
            }
        },
        |ident: iceberg::TableIdent| {
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
                    Target::View(ident.name()),
                )
                .await;
                (visible, ident)
            }
        },
    )
    .await?;

    Ok(AxumJson(ListViewsResponse {
        next_page_token: page.next_page_token,
        identifiers: page
            .items
            .into_iter()
            .map(|ident| ViewIdentifier {
                namespace: ident.namespace().to_vec(),
                name: ident.name().to_string(),
            })
            .collect(),
    }))
}

/// Creates a new Iceberg view in the given namespace.
///
/// POST /v1/namespaces/{namespace}/views
pub async fn create_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    headers: HeaderMap,
    Json(payload): Json<CreateViewPayload>,
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
    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", &endpoint_path, &principal);

    // Authorized against the *view* being created, not its namespace, so a
    // view-scoped policy governs it exactly as a table-scoped policy governs
    // `createTable`. Authorizing the namespace instead meant any principal who
    // could create anything in the namespace could create a view a policy
    // specifically forbade.
    let namespace_ident = NamespaceIdent::from_vec(namespace_parts.clone())?;
    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace_ident,
        Target::View(&payload.name),
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

    // Validate schema type
    if payload.schema.schema_type != "struct" {
        return Err(AppError::BadRequest(
            "A view schema must have \"type\": \"struct\" at its root.".to_string(),
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
            AppError::BadRequest(format!("View representations could not be read: {e}"))
        })?;

    if representations.is_empty() {
        return Err(AppError::BadRequest(
            "A view must carry at least one SQL representation.".to_string(),
        ));
    }

    // Build the default namespace
    let default_namespace = NamespaceIdent::from_vec(payload.view_version.default_namespace)?;

    // Generate view location. A client-supplied one is confined for the same
    // reason a table's is — see `crate::location::LocationScope`.
    //
    // The warehouse is the one governing *this namespace*, which under
    // federation is the mount's rather than the server's. A table gets its
    // default location from the catalog that will hold it and so never has this
    // problem; views build theirs here, which is the chance to pick the wrong
    // one — and then fail the confinement check that correctly used the right
    // one. `canonical_prefix` is the same function the check reads, so the
    // default this builds is one the check accepts by construction.
    let view_location = match payload.location {
        Some(location) => {
            state
                .location_bound(&namespace_ident, &payload.name)
                .await
                .ensure(&location)?;
            location
        }
        None => crate::location::canonical_prefix(
            &state.warehouse_for(&namespace_ident).await,
            &namespace_parts,
            &payload.name,
        ),
    };

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
    let view_ident = TableIdent::new(namespace_ident.clone(), payload.name.clone());

    // The catalog writes the metadata file and returns where it put it, so the
    // location handed back always names a file that exists.
    let (metadata_location, view_metadata) = state
        .catalog
        .create_view(&view_ident, view_metadata)
        .await?;

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
    if let Some(key) = idempotency_key
        && let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body)
    {
        state.idempotency_cache.set(key, cached).await;
    }

    Ok(response)
}

/// Loads metadata for an existing view.
///
/// GET /v1/namespaces/{namespace}/views/{view}
pub async fn load_view(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    ViewPath(view_ident): ViewPath,
) -> Result<AxumJson<LoadViewResponse>> {
    // The extractor already decoded and validated both segments.
    let view_name = view_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        view_ident.namespace(),
        Target::View(&view_name),
        Action::Read,
    )
    .await?;

    // The error is kept rather than flattened to "no such view": a backend that
    // is unreachable is not a view that is gone, and reporting the second sends
    // an operator after the wrong thing.
    let (metadata_location, metadata) = state.catalog.load_view(&view_ident).await?;

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
    RequestFacts(request): RequestFacts,
    ViewPath(view_ident): ViewPath,
) -> Result<StatusCode> {
    // The extractor already decoded and validated both segments.
    let namespace_parts = view_ident.namespace().to_vec();
    let view_name = view_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        view_ident.namespace(),
        Target::View(&view_name),
        Action::Read,
    )
    .await?;

    // Check if view exists
    if state.catalog.view_exists(&view_ident).await? {
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
    RequestFacts(request): RequestFacts,
    ViewPath(view_ident): ViewPath,
) -> Result<StatusCode> {
    // The extractor already decoded and validated both segments.
    let namespace_parts = view_ident.namespace().to_vec();
    let view_name = view_ident.name().to_string();

    guard::authorize(
        &state,
        &principal,
        &request,
        view_ident.namespace(),
        Target::View(&view_name),
        Action::Delete,
    )
    .await?;

    // Read after authorizing, so an unauthorized caller learns nothing about
    // whether the view exists or how it is configured.
    let (_, metadata) = state.catalog.load_view(&view_ident).await?;
    super::ownership::reject_if_protected(metadata.properties(), &format!("View '{view_ident}'"))?;

    // Drop the view
    state.catalog.drop_view(&view_ident).await?;

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
    RequestFacts(request): RequestFacts,
    ViewPath(view_ident): ViewPath,
    headers: HeaderMap,
    Json(payload): Json<CommitViewRequest>,
) -> Result<axum::response::Response> {
    // The extractor already decoded and validated both segments.
    let namespace_parts = view_ident.namespace().to_vec();
    let view_name = view_ident.name().to_string();

    // Build the endpoint path for idempotency scoping
    let endpoint_path = format!(
        "/v1/namespaces/{}/views/{}",
        namespace_parts.join("/"),
        view_name
    );

    // Check for idempotency key
    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", &endpoint_path, &principal);

    // One fact, one source. See `CommitViewRequest::identifier`.
    if let Some(ref ident) = payload.identifier
        && (ident.namespace != namespace_parts || ident.name != view_name)
    {
        return Err(AppError::BadRequest(format!(
            "The identifier in the request body ({}.{}) does not name the view in the \
                 URL ({}.{}). They must match.",
            ident.namespace.join("."),
            ident.name,
            namespace_parts.join("."),
            view_name
        )));
    }

    guard::authorize(
        &state,
        &principal,
        &request,
        view_ident.namespace(),
        Target::View(&view_name),
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

    // Loaded with the error kept. Collapsing every failure into "no such view"
    // reports a backend outage as a missing view, which sends an operator after
    // the wrong thing and can make a client recreate what is still there.
    // `From<iceberg::Error>` already maps a genuine miss to `404`.
    // The location is the compare-and-swap witness, not a spare value: the
    // updates below are applied to the document it names, so the pointer must
    // still be it when the swap happens or this commit silently overwrites one
    // that landed in between. See `CatalogStore::update_view`.
    let (current_metadata_location, current_metadata) =
        state.catalog.load_view(&view_ident).await?;

    // A view commit can move the view, the same way a table commit can move a
    // table, and it gets the same answer. Checked here rather than in the
    // backend because this is where the *current* location is in hand — a view
    // commit applies its updates in the handler and hands the store finished
    // metadata, which is the mirror image of a table commit. Same rule, same
    // place: wherever the current metadata already is. See
    // `crate::location::LocationBound::ensure_view_commit`.
    state
        .location_bound(view_ident.namespace(), view_ident.name())
        .await
        .ensure_view_commit(current_metadata.location(), &payload.updates)?;

    // Validate requirements
    for requirement in &payload.requirements {
        match requirement {
            ViewRequirement::AssertViewUuid { uuid } => {
                let expected_uuid = Uuid::parse_str(uuid)
                    .map_err(|_| AppError::BadRequest(format!("'{uuid}' is not a UUID.")))?;
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

    // Update storage
    let (new_metadata_location, new_metadata) = state
        .catalog
        .update_view(&view_ident, &current_metadata_location, new_metadata)
        .await?;

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
    if let Some(key) = idempotency_key
        && let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body)
    {
        state.idempotency_cache.set(key, cached).await;
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
    RequestFacts(request): RequestFacts,
    Json(payload): Json<RenameViewPayload>,
) -> Result<StatusCode> {
    // Validate source
    validate_namespace(&payload.source.namespace)?;
    validate_table_name(&payload.source.name)?;

    // Validate destination
    validate_namespace(&payload.destination.namespace)?;
    validate_table_name(&payload.destination.name)?;

    let src_namespace_ident = NamespaceIdent::from_vec(payload.source.namespace.clone())?;
    let dest_namespace_ident = NamespaceIdent::from_vec(payload.destination.namespace.clone())?;

    // `Update` on the source and `Create` on the destination, matching
    // `renameTable`. Requiring `Delete` on the source instead would stop the
    // documented `writer` role — create and update, deliberately not delete —
    // from renaming a view while still allowing it to rename a table.
    let src = guard::authorize(
        &state,
        &principal,
        &request,
        &src_namespace_ident,
        Target::View(&payload.source.name),
        Action::Update,
    )
    .await?;

    let dest = guard::authorize(
        &state,
        &principal,
        &request,
        &dest_namespace_ident,
        Target::View(&payload.destination.name),
        Action::Create,
    )
    .await?;

    // A rename is not a mechanism for moving data between tenants.
    if src.owner != dest.owner {
        return Err(AppError::Forbidden(
            "Cannot move views between namespaces owned by different tenants".to_string(),
        ));
    }

    // Perform the rename
    let src_ident = TableIdent::new(src_namespace_ident, payload.source.name.clone());
    let dest_ident = TableIdent::new(dest_namespace_ident, payload.destination.name.clone());

    state.catalog.rename_view(&src_ident, &dest_ident).await?;

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

// ============================================================================
// Tests
// ============================================================================
