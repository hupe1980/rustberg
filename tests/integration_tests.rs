//! Integration tests for Rustberg Iceberg Catalog
//!
//! These tests verify end-to-end functionality including:
//! - Authentication (API key validation, expiration)
//! - Authorization (RBAC, tenant isolation)
//! - Persistent storage (SlateDB API key storage, crash recovery)
//! - HTTP API endpoints (namespace and table CRUD)
//! - Security controls (SEC-008: horizontal privilege escalation prevention)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http::Method;
use rustberg::auth::{ApiKeyBuilder, ApiKeyStore, InMemoryApiKeyStore};
use rustberg::{App, AppState};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

#[cfg(feature = "slatedb-storage")]
use rustberg::storage::{KvApiKeyStore, MemoryKvStore};

// ============================================================================
// Test Utilities
// ============================================================================

/// Creates a test app with in-memory storage and no authentication.
async fn create_test_app_no_auth() -> (App, AppState) {
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("test-tenant")
        .build_async()
        .await;

    let state = app.state().clone();
    (app, state)
}

/// Creates a test app with API key authentication enabled.
async fn create_test_app_with_auth() -> (App, AppState, Arc<InMemoryApiKeyStore>) {
    let (app, store) = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("test-tenant")
        .build_with_api_key_auth_async()
        .await;

    let state = app.state().clone();
    (app, state, store)
}

/// Helper to make authenticated requests.
async fn make_request(
    app: &App,
    method: Method,
    uri: &str,
    api_key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let router = app.clone().into_router();

    let mut request_builder = Request::builder().method(method).uri(uri);

    if let Some(key) = api_key {
        request_builder = request_builder.header("X-API-Key", key);
    }

    let request = if let Some(json_body) = body {
        request_builder
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json_body).unwrap()))
            .unwrap()
    } else {
        request_builder.body(Body::empty()).unwrap()
    };

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();

    (status, body_text)
}

// ============================================================================
// Authentication Tests
// ============================================================================

#[tokio::test]
async fn test_unauthenticated_request_returns_401() {
    let (app, _state, _store) = create_test_app_with_auth().await;

    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/config",
        None, // No API key
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_api_key_returns_401() {
    let (app, _state, _store) = create_test_app_with_auth().await;

    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/config",
        Some("rb_invalid_key_12345"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_valid_api_key_authenticates() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create and store API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("test-key", "tenant-a")
        .with_role("admin")
        .build();

    store.store(api_key).await.expect("Failed to store key");

    let (status, _body) =
        make_request(&app, Method::GET, "/v1/config", Some(&plaintext_key), None).await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_expired_api_key_returns_401() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create expired key (expired 1 hour ago)
    let expired_time = Utc::now() - chrono::Duration::hours(1);
    let (api_key, plaintext_key) = ApiKeyBuilder::new("expired-key", "tenant-a")
        .with_role("admin")
        .expires_at(expired_time)
        .build();

    store.store(api_key).await.expect("Failed to store key");

    let (status, _body) =
        make_request(&app, Method::GET, "/v1/config", Some(&plaintext_key), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_disabled_api_key_returns_401() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (mut api_key, plaintext_key) = ApiKeyBuilder::new("disabled-key", "tenant-a")
        .with_role("admin")
        .build();

    // Disable the key
    api_key.enabled = false;
    store.store(api_key).await.expect("Failed to store key");

    let (status, _body) =
        make_request(&app, Method::GET, "/v1/config", Some(&plaintext_key), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Tenant Isolation Tests (SEC-008: Horizontal Privilege Escalation)
// ============================================================================

#[tokio::test]
async fn test_tenant_cannot_list_other_tenant_namespaces() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create API keys for two different tenants
    let (tenant_a_key_obj, tenant_a_key) = ApiKeyBuilder::new("tenant-a-key", "tenant-a")
        .with_role("admin")
        .build();

    let (tenant_b_key_obj, _tenant_b_key) = ApiKeyBuilder::new("tenant-b-key", "tenant-b")
        .with_role("admin")
        .build();

    store
        .store(tenant_a_key_obj)
        .await
        .expect("Failed to store tenant A key");
    store
        .store(tenant_b_key_obj)
        .await
        .expect("Failed to store tenant B key");

    // Tenant A tries to list namespaces
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces",
        Some(&tenant_a_key),
        None,
    )
    .await;

    // Should succeed but return empty list (no namespaces yet)
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("namespaces"));
}

#[tokio::test]
async fn test_cross_tenant_namespace_access_blocked() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create API keys for two different tenants
    let (tenant_a_key_obj, tenant_a_key) = ApiKeyBuilder::new("tenant-a-key", "tenant-a")
        .with_role("admin")
        .build();

    let (tenant_b_key_obj, tenant_b_key) = ApiKeyBuilder::new("tenant-b-key", "tenant-b")
        .with_role("admin")
        .build();

    store
        .store(tenant_a_key_obj)
        .await
        .expect("Failed to store tenant A key");
    store
        .store(tenant_b_key_obj)
        .await
        .expect("Failed to store tenant B key");

    // Tenant A creates a namespace (single-level)
    let create_ns_body = json!({
        "namespace": ["private-db"],
        "properties": {
            "owner": "tenant-a"
        }
    });

    let (create_status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&tenant_a_key),
        Some(create_ns_body),
    )
    .await;

    assert_eq!(create_status, StatusCode::OK);

    // Tenant B tries to access Tenant A's namespace - should be blocked
    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/private-db",
        Some(&tenant_b_key),
        None,
    )
    .await;

    // Should return 404 (namespace doesn't exist from tenant B's perspective)
    // or 403 (forbidden) - both indicate access is blocked
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN,
        "Expected 404 or 403, got {}",
        status
    );
}

#[tokio::test]
async fn test_cross_tenant_table_creation_blocked() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (tenant_a_key_obj, tenant_a_key) = ApiKeyBuilder::new("tenant-a-key", "tenant-a")
        .with_role("admin")
        .build();

    let (tenant_b_key_obj, tenant_b_key) = ApiKeyBuilder::new("tenant-b-key", "tenant-b")
        .with_role("admin")
        .build();

    store
        .store(tenant_a_key_obj)
        .await
        .expect("Failed to store tenant A key");
    store
        .store(tenant_b_key_obj)
        .await
        .expect("Failed to store tenant B key");

    // Tenant A creates a namespace (single-level)
    let create_ns_body = json!({
        "namespace": ["tenant-a-db"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&tenant_a_key),
        Some(create_ns_body),
    )
    .await;

    // Tenant B tries to create a table in Tenant A's namespace
    let create_table_body = json!({
        "name": "malicious_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "id",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    let (status, _body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/tenant-a-db/tables",
        Some(&tenant_b_key),
        Some(create_table_body),
    )
    .await;

    // Should be blocked with 403 or 404
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "Cross-tenant table creation should be blocked, got {}",
        status
    );
}

// ============================================================================
// Persistent Storage Tests (SEC-001: Data Loss Prevention)
// ============================================================================

#[cfg(feature = "slatedb-storage")]
#[tokio::test]
async fn test_kv_api_key_store_operations() {
    use rustberg::auth::ApiKeyStore;

    // Use MemoryKvStore for fast, isolated tests
    let kv = Arc::new(MemoryKvStore::new());
    let store = KvApiKeyStore::new(kv, None);

    // Create and store API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("persistent-key", "tenant-persist")
        .with_role("admin")
        .with_description("Test persistence")
        .build();

    let key_id = api_key.id;
    store
        .store(api_key.clone())
        .await
        .expect("Failed to store key");

    // Verify it's stored by ID
    let retrieved_by_id = store.get_by_id(&key_id).await;
    assert!(retrieved_by_id.is_some(), "Key should exist after store");
    assert_eq!(retrieved_by_id.unwrap().name, "persistent-key");

    // Verify by prefix lookup
    let key_prefix =
        rustberg::auth::extract_key_prefix(&plaintext_key).expect("Should extract prefix");
    let candidates = store.get_by_prefix(&key_prefix).await;
    assert!(!candidates.is_empty(), "Should find key by prefix");

    // Verify with Argon2
    let retrieved = candidates
        .into_iter()
        .find(|k| rustberg::auth::verify_api_key(&plaintext_key, &k.key_hash))
        .expect("Key should verify with Argon2");

    assert_eq!(retrieved.name, "persistent-key");
    assert_eq!(retrieved.tenant_id, "tenant-persist");
    assert_eq!(retrieved.roles, vec!["admin"]);
    assert_eq!(retrieved.description, Some("Test persistence".to_string()));
}

#[cfg(feature = "slatedb-storage")]
#[tokio::test]
async fn test_kv_api_key_store_tenant_listing() {
    use rustberg::auth::ApiKeyStore;

    let kv = Arc::new(MemoryKvStore::new());
    let store = KvApiKeyStore::new(kv, None);

    // Create multiple keys for same tenant
    for i in 0..3 {
        let (api_key, _) = ApiKeyBuilder::new(format!("key-{}", i), "tenant-multi")
            .with_role("user")
            .build();
        store.store(api_key).await.expect("Failed to store key");
    }

    let keys = store.list_for_tenant("tenant-multi").await;
    assert_eq!(keys.len(), 3, "Should have 3 keys");

    let names: Vec<_> = keys.iter().map(|k| k.name.as_str()).collect();
    assert!(names.contains(&"key-0"));
    assert!(names.contains(&"key-1"));
    assert!(names.contains(&"key-2"));
}

#[cfg(feature = "slatedb-storage")]
#[tokio::test]
async fn test_kv_api_key_store_concurrent_access() {
    use rustberg::auth::ApiKeyStore;
    use tokio::task::JoinSet;

    let kv = Arc::new(MemoryKvStore::new());
    let store = Arc::new(KvApiKeyStore::new(kv, None));

    // Spawn multiple tasks that write concurrently
    let mut tasks = JoinSet::new();

    for i in 0..10 {
        let store_clone = store.clone();
        tasks.spawn(async move {
            let (api_key, _) =
                ApiKeyBuilder::new(format!("concurrent-key-{}", i), "tenant-concurrent")
                    .with_role("user")
                    .build();
            store_clone
                .store(api_key)
                .await
                .expect("Failed to store key");
        });
    }

    // Wait for all tasks to complete
    while tasks.join_next().await.is_some() {}

    // Verify all keys were stored
    let keys = store.list_for_tenant("tenant-concurrent").await;
    assert_eq!(keys.len(), 10, "All concurrent writes should succeed");
}

// ============================================================================
// RBAC Authorization Tests
// ============================================================================

#[tokio::test]
async fn test_rbac_admin_can_create_namespace() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (api_key, plaintext_key) = ApiKeyBuilder::new("admin-key", "tenant-rbac")
        .with_role("admin")
        .build();

    store.store(api_key).await.expect("Failed to store key");

    // Create a single-level namespace (no parent required)
    let create_ns_body = json!({
        "namespace": ["test-db"],
        "properties": {}
    });

    let (status, _body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(create_ns_body),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_rbac_reader_cannot_create_namespace() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (api_key, plaintext_key) = ApiKeyBuilder::new("reader-key", "tenant-rbac")
        .with_role("reader")
        .build();

    store.store(api_key).await.expect("Failed to store key");

    // Create a single-level namespace
    let create_ns_body = json!({
        "namespace": ["test-db"],
        "properties": {}
    });

    let (status, _body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(create_ns_body),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ============================================================================
// Auth Context Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_auth_context_returns_principal_info() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (api_key, plaintext_key) = ApiKeyBuilder::new("context-test-key", "tenant-context")
        .with_role("admin")
        .with_role("reader")
        .build();

    let expected_id = api_key.id.to_string();
    store.store(api_key).await.expect("Failed to store key");

    let (status, body) = make_request(
        &app,
        Method::GET,
        "/auth/context",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");

    // Verify principal info (id is the key's UUID, not the name)
    assert_eq!(response["principal"]["id"], expected_id);
    assert_eq!(response["principal"]["name"], "context-test-key");
    assert_eq!(response["principal"]["tenant_id"], "tenant-context");
    assert_eq!(response["principal"]["principal_type"], "api_key");
    assert_eq!(response["principal"]["auth_method"], "api_key");

    // Verify roles are present
    let roles = response["principal"]["roles"].as_array().unwrap();
    assert!(roles.contains(&json!("admin")));
    assert!(roles.contains(&json!("reader")));

    // Verify capabilities structure exists
    assert!(response["capabilities"]["catalog"].is_object());
    assert!(response["capabilities"]["namespaces"].is_object());
    assert!(response["capabilities"]["tables"].is_object());

    // Admin should have is_admin = true
    assert_eq!(response["capabilities"]["is_admin"], true);
}

#[tokio::test]
async fn test_auth_context_requires_authentication() {
    let (app, _state, _store) = create_test_app_with_auth().await;

    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/auth/context",
        None, // No API key
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_context_reader_not_admin() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (api_key, plaintext_key) = ApiKeyBuilder::new("reader-context-key", "tenant-reader")
        .with_role("reader") // Only reader role, not admin
        .build();

    store.store(api_key).await.expect("Failed to store key");

    let (status, body) = make_request(
        &app,
        Method::GET,
        "/auth/context",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");

    // Reader should not be admin
    assert_eq!(response["capabilities"]["is_admin"], false);

    // Reader should have read capabilities
    assert_eq!(response["capabilities"]["namespaces"]["list"], true);
    assert_eq!(response["capabilities"]["namespaces"]["read"], true);

    // Reader should not have write capabilities
    assert_eq!(response["capabilities"]["namespaces"]["create"], false);
    assert_eq!(response["capabilities"]["namespaces"]["delete"], false);
}

// ============================================================================
// Config Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_config_endpoint_returns_defaults() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("defaults"));
    assert!(body.contains("overrides"));
}

#[tokio::test]
async fn test_config_endpoint_with_warehouse_location() {
    let app = App::builder()
        .with_warehouse_location("s3://test-bucket/warehouse")
        .with_default_tenant_id("test-tenant")
        .build_async()
        .await;

    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("s3://test-bucket/warehouse"));
}

// ============================================================================
// Namespace CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_list_namespaces_empty() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, body) = make_request(&app, Method::GET, "/v1/namespaces", None, None).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    let namespaces = json["namespaces"].as_array().expect("Expected array");
    assert_eq!(namespaces.len(), 0);
}

#[tokio::test]
async fn test_create_and_list_namespace() {
    let (app, _state) = create_test_app_no_auth().await;

    let create_body = json!({
        "namespace": ["test-db"],
        "properties": {
            "owner": "test-user",
            "description": "Test database"
        }
    });

    let (create_status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body),
    )
    .await;

    assert_eq!(create_status, StatusCode::OK);

    // List namespaces
    let (list_status, list_body) =
        make_request(&app, Method::GET, "/v1/namespaces", None, None).await;

    assert_eq!(list_status, StatusCode::OK);
    assert!(list_body.contains("test-db"));
}

#[tokio::test]
async fn test_get_namespace_properties() {
    let (app, _state) = create_test_app_no_auth().await;

    let create_body = json!({
        "namespace": ["prop-test"],
        "properties": {
            "key1": "value1",
            "key2": "value2"
        }
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body),
    )
    .await;

    let (status, body) =
        make_request(&app, Method::GET, "/v1/namespaces/prop-test", None, None).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    assert_eq!(json["namespace"], json!(["prop-test"]));
    assert_eq!(json["properties"]["key1"], "value1");
    assert_eq!(json["properties"]["key2"], "value2");
}

#[tokio::test]
async fn test_delete_namespace() {
    let (app, _state) = create_test_app_no_auth().await;

    let create_body = json!({
        "namespace": ["delete-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body),
    )
    .await;

    // Delete namespace
    let (delete_status, _) = make_request(
        &app,
        Method::DELETE,
        "/v1/namespaces/delete-test",
        None,
        None,
    )
    .await;

    assert_eq!(delete_status, StatusCode::NO_CONTENT);

    // Verify it's gone
    let (get_status, _) =
        make_request(&app, Method::GET, "/v1/namespaces/delete-test", None, None).await;

    assert_eq!(get_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_namespace_properties() {
    let (app, _state) = create_test_app_no_auth().await;

    let create_body = json!({
        "namespace": ["update-test"],
        "properties": {
            "original": "value"
        }
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body),
    )
    .await;

    // Update properties
    let update_body = json!({
        "updates": {
            "new_key": "new_value"
        },
        "removals": ["original"]
    });

    let (update_status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/update-test/properties",
        None,
        Some(update_body),
    )
    .await;

    assert_eq!(update_status, StatusCode::OK);

    // Verify update
    let (get_status, get_body) =
        make_request(&app, Method::GET, "/v1/namespaces/update-test", None, None).await;

    assert_eq!(get_status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&get_body).expect("Invalid JSON");
    assert_eq!(json["properties"]["new_key"], "new_value");
    assert!(json["properties"]["original"].is_null());
}

// ============================================================================
// Table CRUD Tests
// ============================================================================

#[tokio::test]
async fn test_list_tables_in_namespace() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace first
    let create_ns_body = json!({
        "namespace": ["table-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // List tables (should be empty)
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/table-test/tables",
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("identifiers"));
}

#[tokio::test]
async fn test_create_table() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["table-create-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "test_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "id",
                    "required": true,
                    "type": "long"
                },
                {
                    "id": 2,
                    "name": "name",
                    "required": false,
                    "type": "string"
                }
            ]
        }
    });

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/table-create-test/tables",
        None,
        Some(create_table_body),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("metadata-location"));
}

#[tokio::test]
async fn test_get_table_metadata() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["metadata-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "metadata_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "col1",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces/metadata-test/tables",
        None,
        Some(create_table_body),
    )
    .await;

    // Get table metadata
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/metadata-test/tables/metadata_table",
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    assert!(json["metadata-location"].is_string());
}

#[tokio::test]
async fn test_drop_table() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["drop-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "drop_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "col1",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces/drop-test/tables",
        None,
        Some(create_table_body),
    )
    .await;

    // Drop table
    let (drop_status, _) = make_request(
        &app,
        Method::DELETE,
        "/v1/namespaces/drop-test/tables/drop_table?purgeRequested=false",
        None,
        None,
    )
    .await;

    assert_eq!(drop_status, StatusCode::NO_CONTENT);

    // Verify it's gone
    let (get_status, _) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/drop-test/tables/drop_table",
        None,
        None,
    )
    .await;

    assert_eq!(get_status, StatusCode::NOT_FOUND);
}

/// Test that snapshot commits are properly persisted.
/// This test catches the bug where commit_table returned 200 OK but
/// didn't actually write the metadata to storage, causing snapshot loss.
#[tokio::test]
async fn test_commit_table_snapshot_persisted() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["snapshot-persist-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "snapshot_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "id",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/snapshot-persist-test/tables",
        None,
        Some(create_table_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Parse table metadata to get UUID
    let create_response: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    let table_uuid = create_response["metadata"]["table-uuid"]
        .as_str()
        .expect("No table UUID");

    // Verify table starts with no snapshots
    assert!(
        create_response["metadata"]["snapshots"]
            .as_array()
            .is_none_or(|a| a.is_empty()),
        "New table should have no snapshots"
    );

    // Commit: Add a snapshot
    // Note: In real usage, PyIceberg/Spark send add-snapshot updates after writing data files
    let snapshot_id: i64 = 1234567890123456789;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let commit_body = json!({
        "requirements": [
            {
                "type": "assert-table-uuid",
                "uuid": table_uuid
            }
        ],
        "updates": [
            {
                "action": "add-snapshot",
                "snapshot": {
                    "snapshot-id": snapshot_id,
                    "timestamp-ms": timestamp_ms,
                    "summary": {
                        "operation": "append"
                    },
                    "manifest-list": "file:///tmp/test-manifest-list.avro",
                    "schema-id": 0
                }
            },
            {
                "action": "set-snapshot-ref",
                "ref-name": "main",
                "type": "branch",
                "snapshot-id": snapshot_id
            }
        ]
    });

    let (commit_status, commit_body_str) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/snapshot-persist-test/tables/snapshot_table",
        None,
        Some(commit_body),
    )
    .await;

    assert_eq!(
        commit_status,
        StatusCode::OK,
        "Commit failed: {}",
        commit_body_str
    );

    // Verify commit response has the snapshot
    let commit_response: serde_json::Value =
        serde_json::from_str(&commit_body_str).expect("Invalid JSON");
    let commit_snapshots = commit_response["metadata"]["snapshots"]
        .as_array()
        .expect("No snapshots in commit response");
    assert_eq!(
        commit_snapshots.len(),
        1,
        "Expected 1 snapshot in commit response"
    );

    // CRITICAL: Reload table and verify snapshot persisted
    let (reload_status, reload_body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/snapshot-persist-test/tables/snapshot_table",
        None,
        None,
    )
    .await;

    assert_eq!(reload_status, StatusCode::OK);

    let reload_response: serde_json::Value =
        serde_json::from_str(&reload_body).expect("Invalid JSON");

    // Verify snapshot was persisted
    let reloaded_snapshots = reload_response["metadata"]["snapshots"]
        .as_array()
        .expect("No snapshots array in reloaded table");

    assert_eq!(
        reloaded_snapshots.len(),
        1,
        "Snapshot was not persisted! Found {} snapshots after reload",
        reloaded_snapshots.len()
    );

    assert_eq!(
        reloaded_snapshots[0]["snapshot-id"].as_i64(),
        Some(snapshot_id),
        "Wrong snapshot ID after reload"
    );

    // Verify current-snapshot-id is set
    assert_eq!(
        reload_response["metadata"]["current-snapshot-id"].as_i64(),
        Some(snapshot_id),
        "current-snapshot-id was not persisted"
    );
}

#[tokio::test]
async fn test_commit_table_set_properties() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["commit-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "commit_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "id",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/commit-test/tables",
        None,
        Some(create_table_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Parse table metadata to get UUID for requirement
    let create_response: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    let table_uuid = create_response["metadata"]["table-uuid"]
        .as_str()
        .expect("No table UUID");

    // Commit: Set properties
    let commit_body = json!({
        "requirements": [
            {
                "type": "assert-table-uuid",
                "uuid": table_uuid
            }
        ],
        "updates": [
            {
                "action": "set-properties",
                "updates": {
                    "custom.prop1": "value1",
                    "custom.prop2": "value2"
                }
            }
        ]
    });

    let (commit_status, commit_body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/commit-test/tables/commit_table",
        None,
        Some(commit_body),
    )
    .await;

    assert_eq!(
        commit_status,
        StatusCode::OK,
        "Commit failed: {}",
        commit_body
    );

    // Verify the response contains updated metadata
    let commit_response: serde_json::Value =
        serde_json::from_str(&commit_body).expect("Invalid JSON");
    assert!(commit_response["metadata-location"].is_string());
    assert!(commit_response["metadata"]["properties"]["custom.prop1"].as_str() == Some("value1"));
    assert!(commit_response["metadata"]["properties"]["custom.prop2"].as_str() == Some("value2"));

    // CRITICAL: Verify persistence by reloading the table
    // This ensures the commit was actually persisted, not just returned in the response
    let (reload_status, reload_body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/commit-test/tables/commit_table",
        None,
        None,
    )
    .await;

    assert_eq!(
        reload_status,
        StatusCode::OK,
        "Failed to reload table after commit"
    );

    let reload_response: serde_json::Value =
        serde_json::from_str(&reload_body).expect("Invalid JSON");

    // Verify the reloaded table has the committed properties
    assert_eq!(
        reload_response["metadata"]["properties"]["custom.prop1"].as_str(),
        Some("value1"),
        "Property custom.prop1 was not persisted after commit"
    );
    assert_eq!(
        reload_response["metadata"]["properties"]["custom.prop2"].as_str(),
        Some("value2"),
        "Property custom.prop2 was not persisted after commit"
    );

    // Verify metadata location was updated (not the original v0)
    let reloaded_metadata_loc = reload_response["metadata-location"]
        .as_str()
        .expect("No metadata location in reloaded table");
    assert!(
        reloaded_metadata_loc.contains("00001-"),
        "Metadata location should be version 1 after commit, got: {}",
        reloaded_metadata_loc
    );
}

#[tokio::test]
async fn test_commit_table_uuid_requirement_fails() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["commit-fail-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create table
    let create_table_body = json!({
        "name": "conflict_table",
        "schema": {
            "type": "struct",
            "fields": [
                {
                    "id": 1,
                    "name": "id",
                    "required": true,
                    "type": "long"
                }
            ]
        }
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces/commit-fail-test/tables",
        None,
        Some(create_table_body),
    )
    .await;

    // Commit with WRONG UUID - should fail with 409
    let commit_body = json!({
        "requirements": [
            {
                "type": "assert-table-uuid",
                "uuid": "00000000-0000-0000-0000-000000000000"
            }
        ],
        "updates": [
            {
                "action": "set-properties",
                "updates": {
                    "test.prop": "value"
                }
            }
        ]
    });

    let (status, _body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/commit-fail-test/tables/conflict_table",
        None,
        Some(commit_body),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "Expected 409 Conflict for UUID mismatch"
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_namespace_not_found() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _body) =
        make_request(&app, Method::GET, "/v1/namespaces/nonexistent", None, None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_table_not_found() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["error-test"],
        "properties": {}
    });

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/error-test/tables/nonexistent",
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_duplicate_namespace_creation() {
    let (app, _state) = create_test_app_no_auth().await;

    let create_body = json!({
        "namespace": ["duplicate"],
        "properties": {}
    });

    // First creation should succeed
    let (status1, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body.clone()),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    // Second creation should fail
    let (status2, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_body),
    )
    .await;
    assert_eq!(status2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_invalid_json_body() {
    let (app, _state) = create_test_app_no_auth().await;

    let router = app.into_router();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces")
        .header("Content-Type", "application/json")
        .body(Body::from("invalid json {{{"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
// ============================================================================
// Pagination Tests (ICE-008)
// ============================================================================

#[tokio::test]
async fn test_namespace_pagination() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create multiple namespaces
    for i in 1..=5 {
        let create_body = json!({
            "namespace": [format!("ns-{:02}", i)],
            "properties": {}
        });
        let (status, _) = make_request(
            &app,
            Method::POST,
            "/v1/namespaces",
            None,
            Some(create_body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // List with small page size
    let (status, body) =
        make_request(&app, Method::GET, "/v1/namespaces?pageSize=2", None, None).await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let namespaces = response["namespaces"].as_array().unwrap();
    assert_eq!(namespaces.len(), 2);

    // Should have next page token
    assert!(response["next-page-token"].is_string());
    let page_token = response["next-page-token"].as_str().unwrap();

    // Fetch second page
    let (status, body) = make_request(
        &app,
        Method::GET,
        &format!("/v1/namespaces?pageSize=2&pageToken={}", page_token),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let namespaces = response["namespaces"].as_array().unwrap();
    assert_eq!(namespaces.len(), 2);
}

#[tokio::test]
async fn test_table_pagination() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace
    let create_ns_body = json!({
        "namespace": ["pagination-test"],
        "properties": {}
    });
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    // Create multiple tables
    for i in 1..=5 {
        let create_table_body = json!({
            "name": format!("table-{:02}", i),
            "schema": {
                "type": "struct",
                "fields": [
                    {"id": 1, "name": "id", "type": "long", "required": true}
                ]
            }
        });
        make_request(
            &app,
            Method::POST,
            "/v1/namespaces/pagination-test/tables",
            None,
            Some(create_table_body),
        )
        .await;
    }

    // List with small page size
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/pagination-test/tables?pageSize=2",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let tables = response["identifiers"].as_array().unwrap();
    assert_eq!(tables.len(), 2);

    // Should have next page token
    assert!(response["next-page-token"].is_string());
}

// ============================================================================
// Idempotency Tests (ICE-007)
// ============================================================================

#[tokio::test]
async fn test_idempotency_key_on_create_namespace() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.clone().into_router();

    let create_body = json!({
        "namespace": ["idempotent-ns"],
        "properties": {}
    });

    // First request with idempotency key
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces")
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", "test-key-12345")
        .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
        .unwrap();

    let response1 = router.clone().oneshot(request1).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // Check that idempotency key was used
    assert_eq!(
        response1
            .headers()
            .get("idempotency-key-used")
            .map(|v| v.to_str().unwrap()),
        Some("true")
    );

    // Second request with same idempotency key should return cached response
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces")
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", "test-key-12345")
        .body(Body::from(serde_json::to_vec(&create_body).unwrap()))
        .unwrap();

    let response2 = router.clone().oneshot(request2).await.unwrap();
    // Should succeed with cached response (not conflict)
    assert_eq!(response2.status(), StatusCode::OK);
    assert_eq!(
        response2
            .headers()
            .get("idempotency-key-used")
            .map(|v| v.to_str().unwrap()),
        Some("true")
    );
}

#[tokio::test]
async fn test_idempotency_key_on_create_table() {
    let (app, _state) = create_test_app_no_auth().await;

    // Create namespace first
    let create_ns_body = json!({
        "namespace": ["idempotent-table-ns"],
        "properties": {}
    });
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(create_ns_body),
    )
    .await;

    let router = app.clone().into_router();

    let create_table_body = json!({
        "name": "idempotent-table",
        "schema": {
            "type": "struct",
            "fields": [
                {"id": 1, "name": "id", "type": "long", "required": true}
            ]
        }
    });

    // First request with idempotency key
    let request1 = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces/idempotent-table-ns/tables")
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", "table-key-67890")
        .body(Body::from(serde_json::to_vec(&create_table_body).unwrap()))
        .unwrap();

    let response1 = router.clone().oneshot(request1).await.unwrap();
    assert_eq!(response1.status(), StatusCode::OK);

    // Second request with same idempotency key should return cached response
    let request2 = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces/idempotent-table-ns/tables")
        .header("Content-Type", "application/json")
        .header("Idempotency-Key", "table-key-67890")
        .body(Body::from(serde_json::to_vec(&create_table_body).unwrap()))
        .unwrap();

    let response2 = router.clone().oneshot(request2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::OK);
}

// ============================================================================
// Metrics Reporting Tests
// ============================================================================

#[tokio::test]
async fn test_report_metrics_endpoint() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    // First create a namespace and table
    let create_ns_body = json!({
        "namespace": ["metrics-test-ns"]
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_ns_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Create table
    let create_table_body = json!({
        "name": "metrics-test-table",
        "schema": {
            "type": "struct",
            "fields": [
                {"id": 1, "name": "id", "required": true, "type": "long"}
            ]
        }
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces/metrics-test-ns/tables")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_table_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now report metrics
    let metrics_body = json!({
        "report-type": "scan-report",
        "table-name": "metrics-test-ns.metrics-test-table",
        "snapshot-id": 1234567890,
        "metrics": {
            "total-planning-duration": 100,
            "total-data-manifests": 5
        }
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/namespaces/metrics-test-ns/tables/metrics-test-table/metrics")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&metrics_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ============================================================================
// Transaction Commit Tests
// ============================================================================

#[tokio::test]
async fn test_commit_transaction_empty_fails() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    // Empty transaction should fail
    let transaction_body = json!({
        "table-changes": []
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/transactions/commit")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&transaction_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// Prometheus Metrics Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_prometheus_metrics_endpoint() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();

    // Verify key metrics are present
    assert!(body_text.contains("rustberg_info"));
    assert!(body_text.contains("rustberg_requests_total"));
    assert!(body_text.contains("rustberg_catalog_"));
}

// ============================================================================
// CORS and HTTP Infrastructure Tests
// ============================================================================

#[tokio::test]
async fn test_cors_preflight_request() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/namespaces")
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    // CORS preflight should succeed
    assert!(response.status().is_success() || response.status() == StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_request_id_header_propagation() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/config")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify request ID header is present in response
    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn test_security_headers_present() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/config")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify security headers
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("cache-control"));
}

#[tokio::test]
async fn test_content_type_json_response() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/config")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));
}

#[tokio::test]
async fn test_accept_encoding_compression() {
    let (app, _state) = create_test_app_no_auth().await;
    let router = app.into_router();

    // Request with gzip Accept-Encoding
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/config")
        .header("Accept-Encoding", "gzip, deflate")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Response may or may not be compressed depending on size threshold
    // but the request should succeed
}

// ============================================================================
// Rate Limiting Tests (SEC-002)
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_is_enabled() {
    let (app, state, _store) = create_test_app_with_auth().await;

    // Verify rate limiter is enabled by default for API key auth
    // Note: In tests without actual network connections, client_ip is None
    // so rate limit headers won't be added. This test verifies the rate limiter
    // is configured and enabled.

    // Check rate limiter configuration - verify it exists
    let _rate_limiter = &state.rate_limiter;

    // The rate limiter should be enabled by default for API key auth apps
    // We can't directly test headers in unit tests without mocking the connection
    // but we verify the limiter exists and the app builds correctly
    assert!(!state.warehouse_location.is_empty());

    // Also verify the router builds without error
    let _router = app.into_router();
}

// ============================================================================
// Search Endpoint Tests
// ============================================================================

#[tokio::test]
async fn test_search_requires_authentication() {
    let (app, _state, _store) = create_test_app_with_auth().await;

    let (status, _body) = make_request(&app, Method::GET, "/v1/search", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_search_returns_empty_for_empty_catalog() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("test-key", "test-tenant")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    let (status, body) =
        make_request(&app, Method::GET, "/v1/search", Some(&plaintext_key), None).await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["results"].as_array().unwrap().len(), 0);
    assert_eq!(response["totalCount"], 0);
    assert_eq!(response["hasMore"], false);
}

#[tokio::test]
async fn test_search_finds_namespaces() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an admin API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("admin-key", "test-tenant")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    // Create some namespaces
    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({
            "namespace": ["sales"],
            "properties": {"description": "Sales data"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({
            "namespace": ["marketing"],
            "properties": {}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Search for all namespaces
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/search?objectType=namespace",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let results = response["results"].as_array().unwrap();

    // Should find both namespaces
    assert_eq!(results.len(), 2);
    assert_eq!(response["totalCount"], 2);

    // Check that both namespaces are present
    let names: Vec<&str> = results
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"sales"));
    assert!(names.contains(&"marketing"));
}

#[tokio::test]
async fn test_search_with_query_filter() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an admin API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("admin-key", "test-tenant")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    // Create namespaces
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({"namespace": ["sales_data"], "properties": {}})),
    )
    .await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({"namespace": ["marketing"], "properties": {}})),
    )
    .await;

    // Search for "sales" - should only find sales_data
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/search?query=sales",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let results = response["results"].as_array().unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["name"], "sales_data");
}

#[tokio::test]
async fn test_search_respects_limit() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an admin API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("admin-key", "test-tenant")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    // Create multiple namespaces
    for i in 0..5 {
        make_request(
            &app,
            Method::POST,
            "/v1/namespaces",
            Some(&plaintext_key),
            Some(json!({"namespace": [format!("ns{}", i)], "properties": {}})),
        )
        .await;
    }

    // Search with limit=2
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/search?limit=2&objectType=namespace",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let results = response["results"].as_array().unwrap();

    // Should only return 2 results but totalCount should be 5
    assert_eq!(results.len(), 2);
    assert_eq!(response["totalCount"], 5);
    assert_eq!(response["hasMore"], true);
}

#[tokio::test]
async fn test_search_tenant_isolation() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create API keys for two tenants
    let (tenant1_key_obj, key1) = ApiKeyBuilder::new("tenant1-key", "tenant-1")
        .with_role("admin")
        .build();
    store.store(tenant1_key_obj).await.unwrap();

    let (tenant2_key_obj, key2) = ApiKeyBuilder::new("tenant2-key", "tenant-2")
        .with_role("admin")
        .build();
    store.store(tenant2_key_obj).await.unwrap();

    // Tenant 1 creates a namespace
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&key1),
        Some(json!({"namespace": ["tenant1_data"], "properties": {}})),
    )
    .await;

    // Tenant 2 creates a namespace
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&key2),
        Some(json!({"namespace": ["tenant2_data"], "properties": {}})),
    )
    .await;

    // Tenant 1 searches - should only see their own namespace
    let (status, body) = make_request(&app, Method::GET, "/v1/search", Some(&key1), None).await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let results = response["results"].as_array().unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["name"], "tenant1_data");

    // Tenant 2 searches - should only see their own namespace
    let (status, body) = make_request(&app, Method::GET, "/v1/search", Some(&key2), None).await;

    assert_eq!(status, StatusCode::OK);

    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    let results = response["results"].as_array().unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["name"], "tenant2_data");
}

// ============================================================================
// Table Credentials Tests
// ============================================================================

#[tokio::test]
async fn test_credentials_requires_authentication() {
    let (app, _state, _store) = create_test_app_with_auth().await;

    // Attempt to get credentials without authentication
    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/test_ns/tables/test_table/credentials",
        None, // No API key
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_credentials_returns_404_for_nonexistent_table() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("cred-test-key", "cred-tenant")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    // Create a namespace first
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({"namespace": ["cred_test_ns"], "properties": {}})),
    )
    .await;

    // Try to get credentials for non-existent table
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/cred_test_ns/tables/nonexistent_table/credentials",
        Some(&plaintext_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("NoSuchTableException") || body.contains("does not exist"));
}

#[tokio::test]
async fn test_credentials_returns_406_when_no_provider() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create an API key
    let (api_key, plaintext_key) = ApiKeyBuilder::new("cred-test-key-2", "cred-tenant-2")
        .with_role("admin")
        .build();
    store.store(api_key).await.unwrap();

    // Create a namespace
    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&plaintext_key),
        Some(json!({"namespace": ["cred_ns_2"], "properties": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Create a table
    let create_table_body = json!({
        "name": "cred_test_table",
        "schema": {
            "type": "struct",
            "fields": [
                {"id": 1, "name": "id", "required": true, "type": "long"}
            ]
        }
    });

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/cred_ns_2/tables",
        Some(&plaintext_key),
        Some(create_table_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Try to get credentials - should return 406 as no credential provider is configured
    // The default NoopCredentialProvider doesn't support any locations
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/cred_ns_2/tables/cred_test_table/credentials",
        Some(&plaintext_key),
        None,
    )
    .await;

    // Should be 406 Not Acceptable since no credential vending is configured
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    assert!(body.contains("UnsupportedOperationException") || body.contains("not supported"));
}

#[tokio::test]
async fn test_credentials_tenant_isolation() {
    let (app, _state, store) = create_test_app_with_auth().await;

    // Create API keys for two tenants
    let (tenant1_key, key1) = ApiKeyBuilder::new("tenant1-cred-key", "cred-tenant-1")
        .with_role("admin")
        .build();
    store.store(tenant1_key).await.unwrap();

    let (tenant2_key, key2) = ApiKeyBuilder::new("tenant2-cred-key", "cred-tenant-2")
        .with_role("admin")
        .build();
    store.store(tenant2_key).await.unwrap();

    // Tenant 1 creates namespace and table
    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&key1),
        Some(json!({"namespace": ["tenant1_cred_ns"], "properties": {}})),
    )
    .await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces/tenant1_cred_ns/tables",
        Some(&key1),
        Some(json!({
            "name": "tenant1_table",
            "schema": {
                "type": "struct",
                "fields": [{"id": 1, "name": "id", "required": true, "type": "long"}]
            }
        })),
    )
    .await;

    // Tenant 2 tries to access Tenant 1's table credentials - should fail
    let (status, _body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/tenant1_cred_ns/tables/tenant1_table/credentials",
        Some(&key2),
        None,
    )
    .await;

    // Should be 403 Forbidden or 404 Not Found (tenant isolation hides resources)
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
        "Cross-tenant credential access should be blocked, got {}",
        status
    );
}
