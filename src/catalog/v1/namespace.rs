use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json as AxumJson,
};
use iceberg::NamespaceIdent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::extract::{Json, NamespacePath};
use super::guard::{self, Target};
use super::idempotency::{CachedResponse, IdempotencyKey};
use super::ownership::{
    owner_of, preserve_reserved, reject_if_protected, reject_reserved, set_owner, strip_reserved,
};
use super::pagination::{PaginationQuery, collect_page};
use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, RequestFacts, Resource};
use crate::error::{AppError, Result};
use crate::names::{validate_namespace, validate_properties};

#[derive(Deserialize)]
pub struct ListNamespaceQuery {
    /// Parent namespace for hierarchical listing.
    parent: Option<String>,
    /// Pagination: token for the next page.
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

/// Lists the namespaces the caller may see.
///
/// # Filtering is a policy decision, not a tenant comparison
///
/// Each candidate is authorized individually against its own recorded owner, so
/// the listing agrees with what a subsequent load would answer.
///
/// Comparing the recorded owner against the caller's tenant instead would be
/// wrong twice over: it duplicates an isolation rule the policies already
/// express, and it ignores narrower grants, so a `forbid` on one namespace would
/// be enforced on load and invisible in the listing.
///
/// A namespace recording no owner is shown to nobody: it cannot be attributed to
/// a tenant, so no policy can decide it.
pub async fn list_namespaces(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    Query(query): Query<ListNamespaceQuery>,
) -> Result<AxumJson<ListNamespaceResponse>> {
    // `parent` is a multi-level namespace encoded with the unit separator, the
    // same as in a path segment. Treating the whole value as one level made
    // `?parent=a\u{1F}b` search for a namespace literally named "a\u{1F}b".
    let maybe_parent = query
        .parent
        .as_deref()
        .map(|parent| {
            let parts: Vec<String> = parent
                .split(crate::names::PART_SEPARATOR)
                .map(str::to_string)
                .collect();
            validate_namespace(&parts)?;
            NamespaceIdent::from_vec(parts).map_err(AppError::from)
        })
        .transpose()?;

    match maybe_parent.as_ref() {
        // `?parent=X` names a resource, so it is authorized like one — the same
        // guard `listTables` puts in front of its namespace, and for the same
        // reason.
        //
        // Without it this parameter is the enumeration oracle every path-based
        // handler closes, reached through a query string: the backend answers
        // `NoSuchNamespace` for a parent that does not exist and an empty page
        // for one that exists and belongs to somebody else. The page reveals
        // nothing — every child is filtered below — but the *status code*
        // separates "not there" from "not yours", and a caller can walk a whole
        // foreign tree with it one guess at a time.
        Some(parent) => {
            guard::authorize(
                &state,
                &principal,
                &request,
                parent,
                Target::Namespace,
                Action::List,
            )
            .await?;
        }
        // The root, where there is nothing to name. The decision is "may you
        // enumerate your own catalog", and each namespace found is authorized on
        // its own merits below.
        None => {
            guard::authorize_catalog(&state, &principal, &request, Action::List).await?;
        }
    }

    // Record metric
    state.metrics.catalog_list_namespaces.inc();

    let page = collect_page(
        PaginationQuery::new(query.page_token, query.page_size).to_request()?,
        |request| {
            let state = state.clone();
            let parent = maybe_parent.clone();
            async move {
                state
                    .catalog
                    .list_namespaces(parent.as_ref(), &request)
                    .await
                    .map_err(AppError::from)
            }
        },
        |namespace| {
            let state = state.clone();
            let principal = principal.clone();
            let facts = request.clone();
            async move {
                // A namespace with no recorded owner is shown to nobody: it
                // cannot be attributed to a tenant, so no policy can decide it.
                let Ok(ns) = state.catalog.get_namespace(&namespace).await else {
                    return (false, namespace);
                };
                let Some(owner) = owner_of(ns.properties()).map(str::to_string) else {
                    return (false, namespace);
                };
                let visible = guard::can_see(
                    &state,
                    &principal,
                    &facts,
                    &owner,
                    &namespace,
                    Target::Namespace,
                )
                .await;
                (visible, namespace)
            }
        },
    )
    .await?;

    Ok(AxumJson(ListNamespaceResponse {
        namespaces: page.items.iter().map(|ns| ns.as_ref().clone()).collect(),
        next_page_token: page.next_page_token,
    }))
}

/// Creates a namespace, stamped with the tenant that owns the subtree it joins.
///
/// # Ownership is inherited, never asserted
///
/// A **root** namespace has no parent to inherit from, so it is authorized
/// against the caller's own tenant and stamped with it. That is correct here
/// and only here: nothing exists yet, and the caller is asking to create a tree
/// of its own.
///
/// A **nested** namespace is a different request. It joins a tree that already
/// has an owner, and authorizing it against the *caller's* tenant would let a
/// principal in tenant `b` plant `finance.secret` inside tenant `a`'s
/// `finance` — invisible to `a`, undeletable by `a` (the parent is no longer
/// empty), and with no error naming why. So the parent is resolved through the
/// ordinary guard, the decision is made against the owner recorded *there*, and
/// the child inherits it.
///
/// Inheritance is also what keeps the Cedar hierarchy honest. Ancestors are
/// derived by truncating the entity id, and the id begins with the owning
/// tenant — so a child owned by `b` under a parent owned by `a` would sit under
/// `Namespace::"b\u{1F}finance"`, which is not a namespace that exists. One
/// owner per subtree makes the derived chain the real one.
pub async fn create_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    headers: HeaderMap,
    Json(payload): Json<CreateNamespacePayload>,
) -> Result<axum::response::Response> {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::IntoResponse;

    // Validate input
    validate_namespace(&payload.namespace)?;
    if let Some(ref props) = payload.properties {
        validate_properties(props)?;
        // Ownership lives in a reserved property; a client that could write it
        // could create a namespace already owned by another tenant.
        reject_reserved(props.keys())?;
    }

    // Check for idempotency key
    let idempotency_key =
        IdempotencyKey::from_headers(&headers, "POST", "/v1/namespaces", &principal);

    // Whose tree is this? A root namespace starts one; a nested namespace joins
    // the one its parent already belongs to. See the doc comment above for why
    // the difference is a security boundary rather than a formality.
    let tenant_id = match payload.namespace.split_last() {
        Some((_, [])) | None => {
            let tenant_id = principal.tenant_id().to_string();
            guard::authorize_new(
                &state,
                &principal,
                &request,
                Resource::namespace(&tenant_id, payload.namespace.clone()),
                Action::Create,
            )
            .await?;
            tenant_id
        }
        Some((_, parent)) => {
            let parent = NamespaceIdent::from_vec(parent.to_vec())?;
            guard::authorize(
                &state,
                &principal,
                &request,
                &parent,
                Target::Namespace,
                Action::Create,
            )
            .await?
            .owner
        }
    };
    // Consulted only after authorization: a cache hit answers without touching
    // the catalog, so checking it first would serve a request that was never
    // authorized — and would keep serving it after the grant was revoked.
    if let Some(ref key) = idempotency_key
        && let Some(cached) = state.idempotency_cache.get(key).await
    {
        return Ok(cached.into_axum_response());
    }

    // Record metric
    state.metrics.catalog_create_namespace.inc();

    let namespace_ident = NamespaceIdent::from_vec(payload.namespace.clone())?;

    // Record the owning tenant. Client-supplied reserved keys were rejected above,
    // so this cannot be overridden from the request.
    let mut properties: HashMap<String, String> = payload.properties.unwrap_or_default();
    set_owner(&mut properties, &tenant_id);

    // Create the namespace
    let namespace = state
        .catalog
        .create_namespace(&namespace_ident, properties.clone())
        .await?;

    let mut response_props = namespace.properties().clone();
    strip_reserved(&mut response_props);

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
    if let Some(key) = idempotency_key
        && let Some(cached) = CachedResponse::from_json(StatusCode::OK, &response_body)
    {
        state.idempotency_cache.set(key, cached).await;
    }

    Ok(response)
}

pub async fn get_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
) -> Result<AxumJson<GetNamespaceResponse>> {
    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::Read,
    )
    .await?;

    let ns = state.catalog.get_namespace(&namespace).await?;

    let mut response_props = ns.properties().clone();
    strip_reserved(&mut response_props);

    Ok(AxumJson(GetNamespaceResponse {
        namespace: ns.name().to_vec(),
        properties: response_props,
    }))
}

pub async fn namespace_exists(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
) -> Result<StatusCode> {
    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::Read,
    )
    .await?;

    // The Iceberg REST spec defines the HEAD responses as 204 No Content.
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_namespace(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
) -> Result<StatusCode> {
    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::Delete,
    )
    .await?;

    let existing = state.catalog.get_namespace(&namespace).await?;
    reject_if_protected(
        existing.properties(),
        &format!("Namespace '{}'", namespace.join(".")),
    )?;

    // Record metric
    state.metrics.catalog_delete_namespace.inc();

    state.catalog.drop_namespace(&namespace).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_namespace_properties(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    namespace: NamespacePath,
    Json(payload): Json<UpdateNamespacePropertiesPayload>,
) -> Result<AxumJson<UpdateNamespacePropertiesResponse>> {
    // Validate input
    validate_properties(&payload.updates)?;
    // Without these two checks, `updates` could set the ownership key to another
    // tenant and `removals` could erase it — either one is a tenant takeover.
    reject_reserved(payload.updates.keys())?;
    reject_reserved(payload.removals.iter())?;

    guard::authorize(
        &state,
        &principal,
        &request,
        &namespace,
        Target::Namespace,
        Action::Update,
    )
    .await?;

    let ns = state.catalog.get_namespace(&namespace).await?;
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

    // Defence in depth: even if a reserved key slipped through validation, the
    // server-managed values are restored before the write.
    preserve_reserved(ns.properties(), &mut properties);

    state
        .catalog
        .update_namespace(&namespace, properties)
        .await?;

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
}
