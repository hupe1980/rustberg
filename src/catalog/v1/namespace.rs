use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json as AxumJson,
};
use iceberg::NamespaceIdent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, AuthzContext, Resource};
use crate::catalog::extract::NamespacePath;
use crate::catalog::idempotency::{CachedResponse, IdempotencyKey, IDEMPOTENCY_KEY_USED_HEADER};
use crate::catalog::pagination::PaginationQuery;
use crate::catalog::validation::{validate_namespace, validate_properties};
use crate::error::{AppError, Result};

/// Reserved property key for storing namespace owner's tenant ID.
const TENANT_ID_PROPERTY: &str = "_tenant_id";

#[derive(Deserialize)]
pub struct ListNamespaceQuery {
    /// Parent namespace for hierarchical listing.
    parent: Option<String>,
    /// Pagination: token for next page.
    #[serde(rename = "pageToken")]
    page_token: Option<String>,
    /// Pagination: maximum items per page.
    #[serde(rename = "pageSize")]
    page_size: Option<usize>,
}

#[derive(Serialize)]
pub struct ListNamespaceResponse {
    namespaces: Vec<Vec<String>>,
    /// Token for fetching the next page (absent if no more results).
    #[serde(rename = "next-page-token", skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateNamespacePayload {
    namespace: Vec<String>,
    properties: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
pub struct CreateNamespaceResponse {
    namespace: Vec<String>,
    properties: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct GetNamespaceResponse {
    namespace: Vec<String>,
    properties: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct UpdateNamespacePropertiesPayload {
    removals: Vec<String>,            // List of properties to remove
    updates: HashMap<String, String>, // Properties to update
}

#[derive(Serialize)]
pub struct UpdateNamespacePropertiesResponse {
    updated: Vec<String>, // List of property keys that were added or updated
    removed: Vec<String>, // List of properties that were removed
    missing: Vec<String>, // List of properties requested for removal but not found
}

pub async fn list_namespaces(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Query(query): Query<ListNamespaceQuery>,
) -> Result<AxumJson<ListNamespaceResponse>> {
    // Authorize the request
    let tenant_id = principal.tenant_id().to_string();
    let resource = Resource::catalog(&tenant_id);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::List);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_list_namespaces.inc();

    let maybe_parent = query
        .parent
        .as_deref()
        .map(|parent| NamespaceIdent::new(parent.to_string()));

    let namespaces = state.catalog.list_namespaces(maybe_parent.as_ref()).await?;

    // Filter namespaces to only show those owned by the requesting tenant
    let mut namespace_lists: Vec<Vec<String>> = Vec::new();
    for namespace in namespaces {
        // Check if this namespace belongs to the requesting tenant
        if let Ok(ns) = state.catalog.get_namespace(&namespace).await {
            let owner = ns.properties().get(TENANT_ID_PROPERTY).map(|s| s.as_str());
            // Include if: no owner set (legacy) OR owner matches tenant
            if owner.is_none() || owner == Some(&tenant_id) {
                namespace_lists.push(namespace.inner().clone());
            }
        }
    }

    // Sort for consistent pagination
    namespace_lists.sort();

    // Apply pagination
    let pagination = PaginationQuery {
        page_token: query.page_token,
        page_size: query.page_size,
    };

    let paged = pagination.paginate(namespace_lists, |ns| ns.join("/"));

    Ok(AxumJson(ListNamespaceResponse {
        namespaces: paged.items,
        next_page_token: paged.next_page_token,
    }))
}

pub async fn create_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<CreateNamespacePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Validate input
    validate_namespace(&payload.namespace)?;
    if let Some(ref props) = payload.properties {
        validate_properties(props)?;
    }

    // Check for idempotency key
    let idempotency_key = IdempotencyKey::from_headers(&headers, "POST", "/v1/namespaces");

    // If idempotency key present, check cache first
    if let Some(ref key) = idempotency_key {
        if let Some(cached) = state.idempotency_cache.get(key) {
            return Ok(cached.into_axum_response());
        }
    }

    // Authorize the request
    let tenant_id = principal.tenant_id().to_string();
    let resource = Resource::namespace(&tenant_id, payload.namespace.clone());
    let ctx = AuthzContext::new(principal, resource, Action::Create);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_create_namespace.inc();

    let namespace_ident = NamespaceIdent::from_vec(payload.namespace.clone())?;

    // Add tenant_id to properties for ownership tracking
    let mut properties: HashMap<String, String> = payload.properties.unwrap_or_default();
    properties.insert(TENANT_ID_PROPERTY.to_string(), tenant_id);

    // Create the namespace
    let namespace = state
        .catalog
        .create_namespace(&namespace_ident, properties.clone())
        .await?;

    // Return properties without internal _tenant_id
    let mut response_props = namespace.properties().clone();
    response_props.remove(TENANT_ID_PROPERTY);

    let response_body = CreateNamespaceResponse {
        namespace: namespace.name().to_vec(),
        properties: response_props,
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

pub async fn get_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
) -> Result<AxumJson<GetNamespaceResponse>> {
    // Load namespace first to get its owner
    let ns = state.catalog.get_namespace(&namespace).await?;

    // Get the namespace's owner tenant
    let owner_tenant = ns
        .properties()
        .get(TENANT_ID_PROPERTY)
        .cloned()
        .unwrap_or_else(|| principal.tenant_id().to_string()); // Legacy: assume current tenant if not set

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace.clone().inner());
    let ctx = AuthzContext::new(principal, resource, Action::Read);
    state.authorizer.check(&ctx).await?;

    // Return properties without internal _tenant_id
    let mut response_props = ns.properties().clone();
    response_props.remove(TENANT_ID_PROPERTY);

    Ok(AxumJson(GetNamespaceResponse {
        namespace: ns.name().to_vec(),
        properties: response_props,
    }))
}

pub async fn namespace_exists(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
) -> Result<StatusCode> {
    // Try to load the namespace to check ownership
    match state.catalog.get_namespace(&namespace).await {
        Ok(ns) => {
            // Get the namespace's owner tenant
            let owner_tenant = ns
                .properties()
                .get(TENANT_ID_PROPERTY)
                .cloned()
                .unwrap_or_else(|| principal.tenant_id().to_string());

            // Authorize the request against the actual owner
            let resource = Resource::namespace(&owner_tenant, namespace.clone().inner());
            let ctx = AuthzContext::new(principal, resource, Action::Read);
            state.authorizer.check(&ctx).await?;

            Ok(StatusCode::OK)
        }
        Err(_) => Err(AppError::NoSuchNamespace(
            "The given namespace does not exist".to_string(),
        )),
    }
}

pub async fn delete_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
) -> Result<StatusCode> {
    // Load namespace first to get its owner
    let ns = state.catalog.get_namespace(&namespace).await?;

    // Get the namespace's owner tenant
    let owner_tenant = ns
        .properties()
        .get(TENANT_ID_PROPERTY)
        .cloned()
        .unwrap_or_else(|| principal.tenant_id().to_string());

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace.clone().inner());
    let ctx = AuthzContext::new(principal, resource, Action::Delete);
    state.authorizer.check(&ctx).await?;

    // Record metric
    state.metrics.catalog_delete_namespace.inc();

    state.catalog.drop_namespace(&namespace).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_namespace_properties(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    namespace: NamespacePath,
    AxumJson(payload): AxumJson<UpdateNamespacePropertiesPayload>,
) -> Result<AxumJson<UpdateNamespacePropertiesResponse>> {
    // Validate input
    validate_properties(&payload.updates)?;

    // Fetch the current namespace properties
    let ns = state.catalog.get_namespace(&namespace).await?;

    // Get the namespace's owner tenant
    let owner_tenant = ns
        .properties()
        .get(TENANT_ID_PROPERTY)
        .cloned()
        .unwrap_or_else(|| principal.tenant_id().to_string());

    // Authorize the request against the actual owner
    let resource = Resource::namespace(&owner_tenant, namespace.clone().inner());
    let ctx = AuthzContext::new(principal, resource, Action::Update);
    state.authorizer.check(&ctx).await?;

    let mut properties = ns.properties().clone();

    let mut removed = Vec::new();
    let mut missing = Vec::new();

    // Remove specified properties
    for removal in payload.removals {
        if properties.remove(&removal).is_some() {
            removed.push(removal);
        } else {
            missing.push(removal);
        }
    }

    // Apply updates
    let mut updated = Vec::new();
    for (key, value) in payload.updates {
        properties.insert(key.clone(), value); // Insert or update the property
        updated.push(key);
    }

    // Update the namespace with the modified properties
    state
        .catalog
        .update_namespace(&namespace, properties)
        .await?; // Automatically convert iceberg::Error to AppError

    Ok(AxumJson(UpdateNamespacePropertiesResponse {
        updated,
        removed,
        missing,
    }))
}
// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ListNamespaceQuery Tests
    // ========================================================================

    #[test]
    fn test_list_namespace_query_default() {
        let json = "{}";
        let query: ListNamespaceQuery = serde_json::from_str(json).unwrap();
        assert!(query.parent.is_none());
        assert!(query.page_token.is_none());
        assert!(query.page_size.is_none());
    }

    #[test]
    fn test_list_namespace_query_with_parent() {
        let json = r#"{"parent": "db"}"#;
        let query: ListNamespaceQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.parent, Some("db".to_string()));
    }

    #[test]
    fn test_list_namespace_query_pagination() {
        let json = r#"{"pageToken": "xyz", "pageSize": 100}"#;
        let query: ListNamespaceQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page_token, Some("xyz".to_string()));
        assert_eq!(query.page_size, Some(100));
    }

    // ========================================================================
    // ListNamespaceResponse Tests
    // ========================================================================

    #[test]
    fn test_list_namespace_response_serialization() {
        let response = ListNamespaceResponse {
            namespaces: vec![vec!["ns1".to_string()], vec!["ns2".to_string()]],
            next_page_token: Some("token".to_string()),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["namespaces"].as_array().unwrap().len(), 2);
        assert_eq!(json["next-page-token"], "token");
    }

    #[test]
    fn test_list_namespace_response_no_token() {
        let response = ListNamespaceResponse {
            namespaces: vec![],
            next_page_token: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        // next-page-token should be omitted when None
        assert!(json.get("next-page-token").is_none());
    }

    // ========================================================================
    // CreateNamespacePayload Tests
    // ========================================================================

    #[test]
    fn test_create_namespace_payload_minimal() {
        let json = r#"{"namespace": ["db", "schema"]}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.namespace, vec!["db", "schema"]);
        assert!(payload.properties.is_none());
    }

    #[test]
    fn test_create_namespace_payload_with_properties() {
        let json = r#"{
            "namespace": ["ns"],
            "properties": {"owner": "alice", "location": "s3://bucket/ns"}
        }"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        let props = payload.properties.unwrap();
        assert_eq!(props.get("owner"), Some(&"alice".to_string()));
        assert_eq!(props.get("location"), Some(&"s3://bucket/ns".to_string()));
    }

    #[test]
    fn test_create_namespace_payload_single_level() {
        let json = r#"{"namespace": ["production"]}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.namespace.len(), 1);
        assert_eq!(payload.namespace[0], "production");
    }

    #[test]
    fn test_create_namespace_payload_empty_namespace() {
        // Empty namespace array should deserialize (validation in handler)
        let json = r#"{"namespace": []}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        assert!(payload.namespace.is_empty());
    }

    // ========================================================================
    // CreateNamespaceResponse Tests
    // ========================================================================

    #[test]
    fn test_create_namespace_response_serialization() {
        let mut props = HashMap::new();
        props.insert("key".to_string(), "value".to_string());
        let response = CreateNamespaceResponse {
            namespace: vec!["ns".to_string()],
            properties: props,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["namespace"][0], "ns");
        assert_eq!(json["properties"]["key"], "value");
    }

    // ========================================================================
    // GetNamespaceResponse Tests
    // ========================================================================

    #[test]
    fn test_get_namespace_response_serialization() {
        let mut props = HashMap::new();
        props.insert("location".to_string(), "s3://bucket".to_string());
        let response = GetNamespaceResponse {
            namespace: vec!["db".to_string(), "schema".to_string()],
            properties: props,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["namespace"].as_array().unwrap().len(), 2);
        assert_eq!(json["properties"]["location"], "s3://bucket");
    }

    // ========================================================================
    // UpdateNamespacePropertiesPayload Tests
    // ========================================================================

    #[test]
    fn test_update_namespace_properties_payload_removals_only() {
        let json = r#"{"removals": ["key1", "key2"], "updates": {}}"#;
        let payload: UpdateNamespacePropertiesPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.removals, vec!["key1", "key2"]);
        assert!(payload.updates.is_empty());
    }

    #[test]
    fn test_update_namespace_properties_payload_updates_only() {
        let json = r#"{"removals": [], "updates": {"new_key": "new_value"}}"#;
        let payload: UpdateNamespacePropertiesPayload = serde_json::from_str(json).unwrap();
        assert!(payload.removals.is_empty());
        assert_eq!(
            payload.updates.get("new_key"),
            Some(&"new_value".to_string())
        );
    }

    #[test]
    fn test_update_namespace_properties_payload_mixed() {
        let json = r#"{
            "removals": ["old_key"],
            "updates": {"new_key": "value", "another": "val2"}
        }"#;
        let payload: UpdateNamespacePropertiesPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.removals.len(), 1);
        assert_eq!(payload.updates.len(), 2);
    }

    // ========================================================================
    // UpdateNamespacePropertiesResponse Tests
    // ========================================================================

    #[test]
    fn test_update_namespace_properties_response_all_fields() {
        let response = UpdateNamespacePropertiesResponse {
            updated: vec!["a".to_string(), "b".to_string()],
            removed: vec!["c".to_string()],
            missing: vec!["d".to_string()],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["updated"].as_array().unwrap().len(), 2);
        assert_eq!(json["removed"].as_array().unwrap().len(), 1);
        assert_eq!(json["missing"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_update_namespace_properties_response_no_missing() {
        let response = UpdateNamespacePropertiesResponse {
            updated: vec!["key".to_string()],
            removed: vec![],
            missing: vec![],
        };
        let json = serde_json::to_value(&response).unwrap();
        // missing should be empty array when no properties were missing
        assert!(json["missing"].as_array().unwrap().is_empty());
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_namespace_with_special_characters() {
        // Underscores and numbers are typically valid
        let json = r#"{"namespace": ["ns_1", "schema_2"]}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.namespace[0], "ns_1");
        assert_eq!(payload.namespace[1], "schema_2");
    }

    #[test]
    fn test_deeply_nested_namespace() {
        let json = r#"{"namespace": ["a", "b", "c", "d", "e"]}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.namespace.len(), 5);
    }

    #[test]
    fn test_properties_with_empty_value() {
        let json = r#"{"namespace": ["ns"], "properties": {"key": ""}}"#;
        let payload: CreateNamespacePayload = serde_json::from_str(json).unwrap();
        let props = payload.properties.unwrap();
        assert_eq!(props.get("key"), Some(&"".to_string()));
    }

    #[test]
    fn test_tenant_id_property_constant() {
        // Verify the constant is correctly defined
        assert_eq!(TENANT_ID_PROPERTY, "_tenant_id");
    }
}
