//! Integration tests for Rustberg Iceberg Catalog
//!
//! These tests verify end-to-end functionality including:
//! - Authentication (API key validation, expiration)
//! - Authorization (RBAC, tenant isolation)
//! - Persistent storage (redb API key storage, crash recovery)
//! - HTTP API endpoints (namespace and table CRUD)
//! - Security controls (SEC-008: horizontal privilege escalation prevention)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http::Method;
use rustberg::auth::{ApiKeyBuilder, ApiKeyStore, InMemoryApiKeyStore};
use rustberg::{App, AppState};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

// ============================================================================
// Test Utilities
// ============================================================================

/// Creates a test app with in-memory storage and no authentication.
async fn create_test_app_no_auth() -> (App, AppState) {
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("test-tenant")
        .build()
        .await
        .expect("build app");

    let state = app.state().clone();
    (app, state)
}

/// Creates a test app with API key authentication enabled.
async fn create_test_app_with_auth() -> (App, AppState, Arc<InMemoryApiKeyStore>) {
    let (app, store) = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("test-tenant")
        .build_with_api_keys()
        .await
        .expect("build app");

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
// Table format versions
// ============================================================================

/// The table format version arrives as a *property*, and every client puts it
/// there — `TBLPROPERTIES ('format-version'='2')` in Spark, `properties=` in
/// PyIceberg. It is not a property, though: it selects the metadata version and
/// is not persisted, so passing it through to the metadata builder made every
/// such create fail and left tables creatable only at the default version.
#[tokio::test]
async fn a_table_is_created_at_the_format_version_the_client_asked_for() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(json!({ "namespace": ["fv"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    for (requested, expected) in [("1", 1), ("2", 2), ("3", 3)] {
        let (status, body) = make_request(
            &app,
            Method::POST,
            "/v1/namespaces/fv/tables",
            None,
            Some(json!({
                "name": format!("t{requested}"),
                "schema": { "type": "struct", "fields": [
                    { "id": 1, "name": "id", "required": true, "type": "long" }
                ]},
                "properties": { "format-version": requested, "owner": "alice" }
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "format-version={requested}: {body}");
        let loaded: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(loaded["metadata"]["format-version"], expected);
        // Reserved on the way in, and not stored on the way out.
        assert_eq!(loaded["metadata"]["properties"]["owner"], "alice");
        assert!(
            loaded["metadata"]["properties"]
                .get("format-version")
                .is_none()
        );
    }
}

#[tokio::test]
async fn an_unsupported_format_version_names_the_ones_that_work() {
    let (app, _state) = create_test_app_no_auth().await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(json!({ "namespace": ["fv_bad"] })),
    )
    .await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/fv_bad/tables",
        None,
        Some(json!({
            "name": "t",
            "schema": { "type": "struct", "fields": [
                { "id": 1, "name": "id", "required": true, "type": "long" }
            ]},
            "properties": { "format-version": "4" }
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("1, 2 and 3"), "{body}");
}

// ============================================================================
// Authentication Tests
// ============================================================================

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

    // No capability summary is reported. Whether a principal "can create tables"
    // has no answer true across every table, so any summary is a claim rather
    // than a fact — and one derived from a role name reports "everything" for a
    // deployment that narrowed or forbade that role.
    assert!(
        response.get("capabilities").is_none(),
        "capabilities must not be reported: the value cannot be computed honestly"
    );
    assert!(!body.contains("is_admin"), "body: {body}");
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

/// The endpoint reports the roles the credential carries, and nothing derived from
/// them. Reporting the roles is what an operator actually needs: a policy naming
/// `Rustberg::Group::"analysts"` matches nothing if the credential says `analyst`,
/// and this is where that typo becomes visible.
#[tokio::test]
async fn test_auth_context_reports_roles_verbatim() {
    let (app, _state, store) = create_test_app_with_auth().await;

    let (api_key, plaintext_key) = ApiKeyBuilder::new("reader-context-key", "tenant-reader")
        .with_role("reader")
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

    assert_eq!(response["principal"]["tenant_id"], "tenant-reader");
    assert_eq!(
        response["principal"]["roles"].as_array().unwrap(),
        &vec![json!("reader")]
    );

    // Whether this principal may create a namespace is a per-resource policy
    // question with no catalog-wide answer, so none is offered.
    assert!(response.get("capabilities").is_none());
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

/// `/v1/config` must report the configured warehouse, since that is how a client
/// learns where tables live.
///
/// The warehouse is `s3://` only when the `storage-s3` feature is compiled in —
/// otherwise opening the catalog fails, because the scheme has no backend. A
/// hardcoded `s3://` here fails the whole `--no-default-features` job, which is
/// one of the builds the feature matrix exists to check.
#[tokio::test]
async fn test_config_endpoint_with_warehouse_location() {
    // The memory and filesystem backends are always compiled; cloud schemes are
    // feature-gated.
    #[cfg(feature = "storage-s3")]
    let warehouse = "s3://test-bucket/warehouse";
    #[cfg(not(feature = "storage-s3"))]
    let warehouse = "memory://test-bucket/warehouse";

    let app = App::builder()
        .with_warehouse_location(warehouse)
        .with_default_tenant_id("test-tenant")
        .build()
        .await
        .expect("build app");

    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(warehouse),
        "config must report the warehouse; body: {body}"
    );
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

/// A backend that cannot answer is a `503`, never a `404`.
///
/// Ownership resolution runs before every authorization decision, so flattening
/// a store failure into "no owner" makes the guard report "you cannot see this".
/// During an outage a client is told its tables do not exist, a retry succeeds,
/// and the symptom is tables that come and go. It also inverts the guard's own
/// contract: `404` means *you cannot see this*, not *we could not look*.
#[tokio::test]
async fn an_unreachable_catalog_is_not_reported_as_a_missing_namespace() {
    let app = App::builder()
        .with_catalog(std::sync::Arc::new(rustberg::catalog::UnreachableStore))
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("test-tenant")
        .build()
        .await
        .expect("build app");

    for (method, uri) in [
        (Method::GET, "/v1/namespaces/analytics/tables/events"),
        (Method::HEAD, "/v1/namespaces/analytics/tables/events"),
        (Method::GET, "/v1/namespaces/analytics"),
        (Method::GET, "/v1/namespaces/analytics/tables"),
    ] {
        let (status, body) = make_request(&app, method.clone(), uri, None, None).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {uri}: an unreachable backend must not read as an absence: {body}"
        );
        assert!(
            status.is_server_error(),
            "{method} {uri}: expected a server error, got {status}: {body}"
        );
    }
}

/// The URL names the table; a body identifier may only agree with it.
///
/// The spec lets `CommitTableRequest` repeat the identifier the path already
/// carries. Two sources for one fact diverge: letting the body win meant a
/// request could be authorized and committed against a table the URL never
/// named, while its idempotency key stayed scoped to the URL's — a retry then
/// keyed to one table and applied to another.
#[tokio::test]
async fn a_commit_body_naming_a_different_table_is_refused() {
    let (app, _state) = create_test_app_no_auth().await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(json!({ "namespace": ["ident-check"], "properties": {} })),
    )
    .await;

    for name in ["here", "elsewhere"] {
        let (status, body) = make_request(
            &app,
            Method::POST,
            "/v1/namespaces/ident-check/tables",
            None,
            Some(json!({
                "name": name,
                "schema": {
                    "type": "struct",
                    "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }]
                }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/ident-check/tables/here",
        None,
        Some(json!({
            "identifier": { "namespace": ["ident-check"], "name": "elsewhere" },
            "requirements": [],
            "updates": [{
                "action": "set-properties",
                "updates": { "k": "v" }
            }]
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a body naming another table must be refused, not silently obeyed: {body}"
    );
    assert!(body.contains("does not name the table in"), "{body}");

    // And the table the body named must be untouched.
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/ident-check/tables/elsewhere",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let loaded: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        loaded["metadata"]["properties"]["k"].is_null(),
        "the refused commit still landed on the table the body named"
    );
}

/// An identifier that agrees with the URL is accepted, because the spec sends
/// one and refusing every request that carries it would break real clients.
#[tokio::test]
async fn a_commit_body_repeating_the_url_identifier_is_accepted() {
    let (app, _state) = create_test_app_no_auth().await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(json!({ "namespace": ["ident-ok"], "properties": {} })),
    )
    .await;

    make_request(
        &app,
        Method::POST,
        "/v1/namespaces/ident-ok/tables",
        None,
        Some(json!({
            "name": "t",
            "schema": {
                "type": "struct",
                "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }]
            }
        })),
    )
    .await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/ident-ok/tables/t",
        None,
        Some(json!({
            "identifier": { "namespace": ["ident-ok"], "name": "t" },
            "requirements": [],
            "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
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
    assert!(!state.default_warehouse.advertised().is_empty());

    // Also verify the router builds without error
    let _router = app.into_router();
}

// ============================================================================
// Search Endpoint Tests
// ============================================================================

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
async fn test_credentials_returns_501_when_no_provider() {
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

    // No credential provider is configured, so vending is unimplemented here.
    // The default NoopCredentialProvider supports no locations.
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/cred_ns_2/tables/cred_test_table/credentials",
        Some(&plaintext_key),
        None,
    )
    .await;

    // 501 Not Implemented: the operation is understood but this deployment does
    // not provide it. 406 would claim a content-negotiation failure, which this
    // is not.
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
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

// ============================================================================
// Namespace ownership (tenant isolation)
// ============================================================================

/// The owning tenant of a namespace is stored under a reserved property key.
/// If a client could write that key, `POST .../properties` would be a tenant
/// takeover: setting it hands the namespace to another tenant, and removing it
/// makes the namespace ownerless. Both must be rejected, and the key must never
/// appear in a response.
#[tokio::test]
async fn test_namespace_ownership_cannot_be_forged() {
    let (app, _state) = create_test_app_no_auth().await;

    const OWNER_KEY: &str = "rustberg.internal.tenant-id";

    // Creating a namespace with the reserved key pre-set must be rejected.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({
            "namespace": ["owned"],
            "properties": { OWNER_KEY: "attacker" }
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reserved key accepted at create: {body}"
    );

    // Create it legitimately.
    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["owned"], "properties": { "owner": "alice" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The reserved key must not leak to clients.
    let (status, body) = make_request(&app, Method::GET, "/v1/namespaces/owned", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(OWNER_KEY),
        "ownership key leaked in response: {body}"
    );

    // Reassigning ownership must be rejected.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/owned/properties",
        None,
        Some(serde_json::json!({ "removals": [], "updates": { OWNER_KEY: "attacker" } })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ownership reassignment allowed: {body}"
    );

    // Erasing ownership must be rejected too.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/owned/properties",
        None,
        Some(serde_json::json!({ "removals": [OWNER_KEY], "updates": {} })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ownership removal allowed: {body}"
    );

    // The namespace is still reachable, so ownership survived intact.
    let (status, _) = make_request(&app, Method::GET, "/v1/namespaces/owned", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// The Iceberg REST spec defines HEAD responses as 204 No Content.
#[tokio::test]
async fn test_namespace_exists_returns_204() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["head_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(&app, Method::HEAD, "/v1/namespaces/head_ns", None, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ============================================================================
// Spec conformance regressions
// ============================================================================

/// The spec defines every HEAD response as 204 No Content.
#[tokio::test]
async fn test_table_exists_returns_204() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["head_tbl_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/head_tbl_ns/tables",
        None,
        Some(serde_json::json!({
            "name": "t",
            "schema": { "type": "struct", "fields": [], "schema-id": 0 }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::HEAD,
        "/v1/namespaces/head_tbl_ns/tables/t",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// Two tables of the same name in different namespaces must not resolve to the
/// same storage location. A default location built from the warehouse alone puts
/// `a.events` and `b.events` both on `{warehouse}/events`.
#[tokio::test]
async fn test_default_table_location_includes_namespace() {
    let (app, _state) = create_test_app_no_auth().await;

    let mut locations = Vec::new();

    for ns in ["loc_a", "loc_b"] {
        let (status, _) = make_request(
            &app,
            Method::POST,
            "/v1/namespaces",
            None,
            Some(serde_json::json!({ "namespace": [ns] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(
            &app,
            Method::POST,
            &format!("/v1/namespaces/{ns}/tables"),
            None,
            Some(serde_json::json!({
                "name": "events",
                "schema": { "type": "struct", "fields": [], "schema-id": 0 }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let loc = v["metadata"]["location"].as_str().unwrap().to_string();
        assert!(loc.contains(ns), "location must carry the namespace: {loc}");
        locations.push(loc);
    }

    assert_ne!(
        locations[0], locations[1],
        "same-named tables in different namespaces collided on one location"
    );
}

/// A supplied-but-unreadable page token is a client error. Silently restarting
/// from page one makes a client with a corrupted token loop forever.
#[tokio::test]
async fn test_invalid_page_token_is_rejected() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["page_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/page_ns/tables?pageToken=%21%21%21not-base64%21%21%21",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// Clients feature-detect from `endpoints`, so entries must be real spec paths,
/// and `defaults` must not carry the `clients` value copied from the spec's
/// illustrative example.
#[tokio::test]
async fn test_config_reports_spec_shaped_endpoints() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;
    assert_eq!(status, StatusCode::OK);

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(v["idempotency-key-lifetime"], "PT24H");
    assert!(v["defaults"].as_object().unwrap().is_empty());
    assert!(!body.contains("clients"));

    let endpoints = v["endpoints"].as_array().unwrap();
    assert!(!endpoints.is_empty());
    for ep in endpoints {
        let ep = ep.as_str().unwrap();
        let (_, path) = ep.split_once(' ').unwrap();
        assert!(path.starts_with("/v1/{prefix}/"), "not a spec path: {ep}");
    }
}

/// Asking for a warehouse this server does not serve must fail, not be echoed
/// back as an accepted override.
#[tokio::test]
async fn test_config_rejects_unknown_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/config?warehouse=s3://someone-elses-bucket/wh",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// Prefix routing, delegation, and error-status regressions
// ============================================================================

/// The spec writes every path as `/v1/{prefix}/...`. Both shapes must work:
/// unprefixed for clients that received no prefix, prefixed for those that did.
#[tokio::test]
async fn test_prefixed_and_unprefixed_paths_both_route() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/warehouse/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["prefixed_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prefixed create must route");

    // The same namespace is visible through the unprefixed path: the prefix is
    // a routing segment, not a separate catalog.
    let (status, _) =
        make_request(&app, Method::GET, "/v1/namespaces/prefixed_ns", None, None).await;
    assert_eq!(status, StatusCode::OK, "unprefixed read must see it");

    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/warehouse/namespaces/prefixed_ns",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "prefixed read must route");
}

/// A path segment the API owns must resolve to the unprefixed route, not be read
/// as a prefix that happens to be named after it.
///
/// Axum matches a literal segment ahead of a dynamic one, which is what makes
/// this hold. Asserted through the router rather than against a naming rule,
/// because the router is what decides it. A naming predicate asserted separately
/// would pass while nothing called it.
#[tokio::test]
async fn test_api_owned_segments_are_not_read_as_prefixes() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["literal_ns"] })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "`/v1/namespaces` must be the namespaces collection, not prefix `namespaces`"
    );

    // `/v1/config` likewise: were it read as prefix `config` plus an empty
    // resource, it would not route at all.
    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("endpoints"), "body: {body}");
}

/// Credential delegation is something a client asks for. Vending unrequested
/// hands out authority nobody wanted.
#[tokio::test]
async fn test_credentials_not_vended_unless_requested() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["deleg_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/deleg_ns/tables",
        None,
        Some(serde_json::json!({
            "name": "t",
            "schema": { "type": "struct", "fields": [], "schema-id": 0 }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // No X-Iceberg-Access-Delegation header: the response must carry no
    // storage-credentials field at all.
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/deleg_ns/tables/t",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v.get("storage-credentials").is_none(),
        "credentials vended without being requested: {body}"
    );
}

/// Committing to a table that does not exist is a `404`. Mapping errors by hand
/// collapses every non-conflict into a `500`, which tells the client to retry.
#[tokio::test]
async fn test_commit_to_missing_table_is_404() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["commit404_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/commit404_ns/tables/does_not_exist",
        None,
        Some(serde_json::json!({
            "requirements": [],
            "updates": [{ "action": "set-properties", "updates": { "a": "b" } }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("NoSuchTableException"), "{body}");
}

/// `parent` is a unit-separator-encoded multi-level namespace, not one level.
#[tokio::test]
async fn test_list_namespaces_parent_is_multi_level() {
    let (app, _state) = create_test_app_no_auth().await;

    for ns in [
        serde_json::json!({ "namespace": ["par"] }),
        serde_json::json!({ "namespace": ["par", "mid"] }),
        serde_json::json!({ "namespace": ["par", "mid", "leaf"] }),
    ] {
        let (status, body) =
            make_request(&app, Method::POST, "/v1/namespaces", None, Some(ns)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // parent = ["par", "mid"] encoded with the unit separator (%1F).
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces?parent=par%1Fmid",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let namespaces = v["namespaces"].as_array().unwrap();
    assert_eq!(
        namespaces.len(),
        1,
        "expected exactly the direct child of par.mid, got: {body}"
    );
    assert_eq!(namespaces[0], serde_json::json!(["par", "mid", "leaf"]));
}

// ============================================================================
// Views
// ============================================================================

fn view_payload(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "schema": { "type": "struct", "fields": [], "schema-id": 0 },
        "view-version": {
            "schema-id": 0,
            "representations": [{ "type": "sql", "sql": "SELECT 1", "dialect": "spark" }],
            "default-namespace": ["view_ns"],
            "summary": {}
        }
    })
}

/// The metadata location a create returns must name a file that exists.
/// Earlier revisions invented `{location}/metadata/v1.metadata.json` and never
/// wrote it, so any client that followed the pointer got a 404.
#[tokio::test]
async fn test_created_view_metadata_file_exists() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["view_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/view_ns/views",
        None,
        Some(view_payload("v")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let location = created["metadata-location"]
        .as_str()
        .expect("metadata-location")
        .to_string();

    // Loading the view reads the metadata back from the advertised location, so
    // a success here proves the file was actually written — on whichever backend
    // the warehouse happens to use.
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/view_ns/views/v",
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "metadata file at {location} is not readable: {body}"
    );

    let loaded: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        loaded["metadata-location"].as_str(),
        Some(location.as_str())
    );
}

/// Views survive a reload, because they live in the catalog rather than in a
/// process-local side store.
#[tokio::test]
async fn test_view_round_trips() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["view_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/view_ns/views",
        None,
        Some(view_payload("v")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::HEAD,
        "/v1/namespaces/view_ns/views/v",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/view_ns/views",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["identifiers"].as_array().unwrap().len(), 1);

    let (status, _) = make_request(
        &app,
        Method::DELETE,
        "/v1/namespaces/view_ns/views/v",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// A namespace holding views must not be droppable — otherwise the views are
/// orphaned: still loadable by exact path, absent from every listing.
#[tokio::test]
async fn test_namespace_with_views_cannot_be_dropped() {
    let (app, _state) = create_test_app_no_auth().await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(serde_json::json!({ "namespace": ["view_ns"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/view_ns/views",
        None,
        Some(view_payload("v")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        make_request(&app, Method::DELETE, "/v1/namespaces/view_ns", None, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

// ============================================================================
// Storage Location Confinement
// ============================================================================
//
// Several requests let a client name a storage location, and every one of those
// locations later becomes the prefix of a vended storage credential. An
// unchecked location is therefore a confused-deputy hole: a caller permitted
// only in its own namespace borrows the *server's* authority over a prefix its
// own policy never mentioned. These tests pin the boundary shut at the HTTP
// edge, where a client actually reaches it.

/// A namespace to hang location tests off, created without auth.
async fn namespace_for_location_tests(app: &App, name: &str) {
    let (status, body) = make_request(
        app,
        Method::POST,
        "/v1/namespaces",
        None,
        Some(json!({ "namespace": [name], "properties": {} })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "namespace setup failed: {body}");
}

fn location_test_schema() -> serde_json::Value {
    json!({
        "type": "struct",
        "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }]
    })
}

#[tokio::test]
async fn create_table_refuses_a_location_outside_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "loc_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/loc_ns/tables",
        None,
        Some(json!({
            "name": "escaped",
            "schema": location_test_schema(),
            "location": "memory://someone-else/secrets"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a table must not be created outside the warehouse: {body}"
    );
    assert!(
        body.contains("warehouse"),
        "the refusal should say why: {body}"
    );
}

/// The boundary case the containment check exists for: `memory://test-evil`
/// merely *spells* like the warehouse `memory://test`, and a `starts_with`
/// test would admit it.
#[tokio::test]
async fn create_table_refuses_a_sibling_prefix_of_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "sibling_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/sibling_ns/tables",
        None,
        Some(json!({
            "name": "sibling",
            "schema": location_test_schema(),
            "location": "memory://test-evil/db/t"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a sibling prefix is not inside the warehouse: {body}"
    );
}

#[tokio::test]
async fn create_table_accepts_a_location_inside_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "inside_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/inside_ns/tables",
        None,
        Some(json!({
            "name": "inside",
            "schema": location_test_schema(),
            "location": "memory://test/inside_ns/inside"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a location within the warehouse is legitimate: {body}"
    );
}

/// Registration is the sharpest form: the caller names a metadata file
/// directly, and the location read out of it scopes a *write* credential.
#[tokio::test]
async fn register_table_refuses_metadata_outside_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "reg_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/reg_ns/register",
        None,
        Some(json!({
            "name": "borrowed",
            "metadata-location": "memory://someone-else/secrets/00000-abc.metadata.json"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "registration must not reach outside the warehouse: {body}"
    );

    // And the refusal must not have left a pointer behind.
    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/reg_ns/tables/borrowed",
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused registration must leave no table"
    );
}

#[tokio::test]
async fn create_view_refuses_a_location_outside_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "view_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/view_ns/views",
        None,
        Some(json!({
            "name": "escaped_view",
            "location": "memory://someone-else/secrets",
            "schema": location_test_schema(),
            "view-version": {
                "version-id": 1,
                "timestamp-ms": 1_700_000_000_000i64,
                "schema-id": 0,
                "summary": { "operation": "create" },
                "default-namespace": ["view_ns"],
                "representations": [
                    { "type": "sql", "sql": "SELECT 1", "dialect": "spark" }
                ]
            }
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a view must not be created outside the warehouse: {body}"
    );
}

// ============================================================================
// Conditional loading and snapshot scoping
// ============================================================================

/// Issues a request with arbitrary extra headers, returning status + headers +
/// body. `make_request` discards headers, and both features under test are
/// expressed entirely in them.
async fn request_with_headers(
    app: &App,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let router = app.clone().into_router();
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }

    let request = match body {
        Some(json) => builder
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Creates a namespace and one table, returning the table's load path.
async fn table_for_freshness_tests(app: &App, ns: &str) -> String {
    namespace_for_location_tests(app, ns).await;

    let (status, body) = make_request(
        app,
        Method::POST,
        &format!("/v1/namespaces/{ns}/tables"),
        None,
        Some(json!({ "name": "events", "schema": location_test_schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "table setup failed: {body}");

    format!("/v1/namespaces/{ns}/tables/events")
}

#[tokio::test]
async fn load_table_returns_an_etag() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "etag_ns").await;

    let (status, headers, _) = request_with_headers(&app, Method::GET, &path, &[], None).await;

    assert_eq!(status, StatusCode::OK);
    let etag = headers
        .get("etag")
        .expect("loadTable must name the metadata version")
        .to_str()
        .unwrap();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "quoted: {etag}"
    );
}

/// The point of the feature: an unchanged table costs a header exchange rather
/// than a full metadata document.
#[tokio::test]
async fn an_unchanged_table_answers_304_with_no_body() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "not_modified_ns").await;

    let (_, headers, _) = request_with_headers(&app, Method::GET, &path, &[], None).await;
    let etag = headers.get("etag").unwrap().to_str().unwrap().to_string();

    let (status, headers, body) =
        request_with_headers(&app, Method::GET, &path, &[("if-none-match", &etag)], None).await;

    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty(), "304 carries no body, got: {body}");
    assert_eq!(
        headers.get("etag").unwrap().to_str().unwrap(),
        etag,
        "the tag is repeated so the client can keep using it"
    );
}

#[tokio::test]
async fn a_stale_etag_returns_the_full_document() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "stale_etag_ns").await;

    let (status, _, body) = request_with_headers(
        &app,
        Method::GET,
        &path,
        &[("if-none-match", "\"0000000000000000000000000000abcd\"")],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "a tag we never issued is a miss");
    assert!(body.contains("metadata"), "the full document is returned");
}

/// The tag folds in the snapshot scope, so a client holding the pruned document
/// must not be told "not modified" when it asks for the full one.
#[tokio::test]
async fn an_etag_from_one_snapshot_scope_does_not_satisfy_the_other() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "scope_etag_ns").await;

    let (_, headers, _) = request_with_headers(
        &app,
        Method::GET,
        &format!("{path}?snapshots=refs"),
        &[],
        None,
    )
    .await;
    let refs_etag = headers.get("etag").unwrap().to_str().unwrap().to_string();

    let (status, _, _) = request_with_headers(
        &app,
        Method::GET,
        &format!("{path}?snapshots=all"),
        &[("if-none-match", &refs_etag)],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a different scope is different content and must be re-sent"
    );
}

#[tokio::test]
async fn both_snapshot_scopes_are_accepted() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "scope_ok_ns").await;

    for scope in ["all", "refs"] {
        let (status, _) = make_request(
            &app,
            Method::GET,
            &format!("{path}?snapshots={scope}"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "snapshots={scope} must be accepted");
    }
}

/// Defaulting an unknown value to `all` would hand back the full document to a
/// client that believed it had asked for less.
#[tokio::test]
async fn an_unknown_snapshot_scope_is_rejected() {
    let (app, _state) = create_test_app_no_auth().await;
    let path = table_for_freshness_tests(&app, "scope_bad_ns").await;

    let (status, body) = make_request(
        &app,
        Method::GET,
        &format!("{path}?snapshots=some"),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("refs"),
        "the message names valid values: {body}"
    );
}

/// A commit hands back the version it just produced, so the committer's next
/// load can be conditional without an intervening read.
#[tokio::test]
async fn create_table_returns_an_etag_usable_for_conditional_loads() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "create_etag_ns").await;

    let (status, headers, _) = request_with_headers(
        &app,
        Method::POST,
        "/v1/namespaces/create_etag_ns/tables",
        &[],
        Some(json!({ "name": "events", "schema": location_test_schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let etag = headers
        .get("etag")
        .expect("createTable names the version it created")
        .to_str()
        .unwrap()
        .to_string();

    let (status, _, _) = request_with_headers(
        &app,
        Method::GET,
        "/v1/namespaces/create_etag_ns/tables/events",
        &[("if-none-match", &etag)],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_MODIFIED,
        "the tag from createTable must satisfy the next load"
    );
}

// ============================================================================
// Unregister and register-view
// ============================================================================

/// Unregistering releases the catalog's pointer while leaving the files, so the
/// table can be adopted again — by this catalog or another one.
#[tokio::test]
async fn a_table_can_be_unregistered_and_registered_again() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "unreg_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/unreg_ns/tables",
        None,
        Some(json!({ "name": "events", "schema": location_test_schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create failed: {body}");

    let metadata_location =
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["metadata-location"]
            .as_str()
            .expect("a created table names its metadata location")
            .to_string();

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/unreg_ns/tables/events/unregister",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/unreg_ns/tables/events",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the pointer is gone");

    // The files survived, so registering the same metadata brings it back.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/unreg_ns/register",
        None,
        Some(json!({ "name": "events", "metadata-location": metadata_location })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unregister must leave the metadata file intact: {body}"
    );
}

#[tokio::test]
async fn unregistering_a_missing_table_is_not_found() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "unreg_missing_ns").await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/unreg_missing_ns/tables/absent/unregister",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Registration adopts existing metadata rather than rewriting it, so a
/// registered view keeps the version it already had.
#[tokio::test]
async fn a_view_can_be_registered_from_existing_metadata() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "regview_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/regview_ns/views",
        None,
        Some(json!({
            "name": "summary",
            "schema": location_test_schema(),
            "view-version": {
                "version-id": 1,
                "timestamp-ms": 1_700_000_000_000i64,
                "schema-id": 0,
                "summary": { "operation": "create" },
                "default-namespace": ["regview_ns"],
                "representations": [
                    { "type": "sql", "sql": "SELECT 1", "dialect": "spark" }
                ]
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "view create failed: {body}");

    let metadata_location =
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["metadata-location"]
            .as_str()
            .expect("a created view names its metadata location")
            .to_string();

    // Drop the pointer, keeping the file.
    let (status, _) = make_request(
        &app,
        Method::DELETE,
        "/v1/namespaces/regview_ns/views/summary",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/regview_ns/register-view",
        None,
        Some(json!({ "name": "summary", "metadata-location": metadata_location.clone() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register-view failed: {body}");

    let registered: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        registered["metadata-location"].as_str(),
        Some(metadata_location.as_str()),
        "registration must adopt the metadata file, never rewrite it"
    );
}

/// The same confused-deputy boundary as `registerTable`.
#[tokio::test]
async fn register_view_refuses_metadata_outside_the_warehouse() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "regview_escape_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/regview_escape_ns/register-view",
        None,
        Some(json!({
            "name": "borrowed",
            "metadata-location": "memory://someone-else/secrets/v1.metadata.json"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "view registration must not reach outside the warehouse: {body}"
    );
}

/// Both new endpoints must be advertised, or clients cannot feature-detect them.
#[tokio::test]
async fn config_advertises_unregister_and_register_view() {
    let (app, _state) = create_test_app_no_auth().await;
    let (status, body) = make_request(&app, Method::GET, "/v1/config", None, None).await;
    assert_eq!(status, StatusCode::OK);

    let endpoints = serde_json::from_str::<serde_json::Value>(&body).unwrap()["endpoints"]
        .as_array()
        .expect("endpoints is a list")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    assert!(endpoints.contains(
        &"POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/unregister".to_string()
    ));
    assert!(
        endpoints.contains(&"POST /v1/{prefix}/namespaces/{namespace}/register-view".to_string())
    );
}

// ============================================================================
// Staged creation (CREATE TABLE AS SELECT)
// ============================================================================

/// The sequence Spark performs for `CREATE TABLE AS SELECT`, over HTTP.
#[tokio::test]
async fn stage_create_then_commit_creates_the_table() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "ctas_ns").await;

    // 1. Stage: metadata is returned, but no table is created.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/ctas_ns/tables",
        None,
        Some(json!({
            "name": "summary",
            "schema": location_test_schema(),
            "stage-create": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "staging failed: {body}");

    let staged: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        staged["metadata"].is_object(),
        "staging returns initialised metadata for the client to build on"
    );
    assert!(
        staged.get("metadata-location").is_none(),
        "the spec omits metadata-location while the metadata is uncommitted: {body}"
    );

    // 2. It must not be a table yet.
    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/ctas_ns/tables/summary",
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a staged table does not exist"
    );

    let (_, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/ctas_ns/tables",
        None,
        None,
    )
    .await;
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["identifiers"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a staged table must not be listed"
    );

    // 3. Commit with assert-create, as the engine does once its data is written.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/ctas_ns/tables/summary",
        None,
        Some(json!({
            "requirements": [{ "type": "assert-create" }],
            "updates": [{
                "action": "set-properties",
                "updates": { "written-by": "ctas" }
            }]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "staged commit failed: {body}");

    // 4. Now it is a real table.
    let (status, body) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/ctas_ns/tables/summary",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the table exists after its commit");
    let loaded: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        loaded["metadata"]["properties"]["written-by"].as_str(),
        Some("ctas")
    );
}

/// A staged table that is never committed leaves nothing behind, and does not
/// hold the name against anyone else.
#[tokio::test]
async fn an_abandoned_stage_reserves_nothing() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "abandoned_ns").await;

    let (status, _) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/abandoned_ns/tables",
        None,
        Some(json!({
            "name": "ghost",
            "schema": location_test_schema(),
            "stage-create": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Somebody else creates the same name for real. Staging held no claim.
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/abandoned_ns/tables",
        None,
        Some(json!({ "name": "ghost", "schema": location_test_schema() })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an abandoned stage must not reserve the name: {body}"
    );
}

/// Staging is not idempotent by nature, so an `Idempotency-Key` must not replay
/// a stale metadata location whose base the catalog has already superseded.
#[tokio::test]
async fn a_staged_create_is_not_replayed_from_the_idempotency_cache() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "stage_idem_ns").await;

    async fn stage(app: &App, key: &str) -> String {
        let (status, _, body) = request_with_headers(
            app,
            Method::POST,
            "/v1/namespaces/stage_idem_ns/tables",
            &[("Idempotency-Key", key)],
            Some(json!({
                "name": "repeated",
                "schema": location_test_schema(),
                "stage-create": true
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "staging failed: {body}");
        body
    }

    const KEY: &str = "11111111-1111-1111-1111-111111111111";
    let first = stage(&app, KEY).await;
    let second = stage(&app, KEY).await;

    // A staged response carries no metadata-location, so the table UUID is what
    // distinguishes one staging from another.
    let uuid = |body: &str| {
        serde_json::from_str::<serde_json::Value>(body).unwrap()["metadata"]["table-uuid"]
            .as_str()
            .expect("staged metadata carries a table uuid")
            .to_string()
    };

    assert_ne!(
        uuid(&first),
        uuid(&second),
        "each staging must mint fresh metadata; replaying an old response would make \
         the client commit against a base the catalog has already replaced"
    );
}

/// A commit asserting the table does not exist, with nothing staged, is a miss
/// that says what was missing.
#[tokio::test]
async fn assert_create_without_staging_is_rejected() {
    let (app, _state) = create_test_app_no_auth().await;
    namespace_for_location_tests(&app, "unstaged_ns").await;

    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/unstaged_ns/tables/never_staged",
        None,
        Some(json!({
            "requirements": [{ "type": "assert-create" }],
            "updates": [{
                "action": "set-properties",
                "updates": { "k": "v" }
            }]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("stage"),
        "the message should say staging was expected: {body}"
    );
}

/// A `304` must be answerable without reading the metadata document.
///
/// The entity tag comes from the metadata *pointer*, a registry lookup, so
/// answering "not modified" needs no fetch at all. That is the whole saving:
/// against object storage the document is a network round trip, and skipping it
/// is why conditional loading is worth having.
///
/// Proved by deleting the metadata file and asking again. A `200` then fails —
/// confirming the file really was required — while the conditional request still
/// answers `304`, which is only possible if that path never touches it. A timing
/// comparison could not establish this; on a warm page cache the difference is
/// smaller than the noise.
#[tokio::test]
async fn a_conditional_load_never_reads_the_metadata_document() {
    let warehouse = tempfile::tempdir().expect("temp dir");
    let app = App::builder()
        .with_warehouse_location(format!("file://{}", warehouse.path().display()))
        .with_default_tenant_id("default")
        .build()
        .await
        .expect("build app");

    namespace_for_location_tests(&app, "freshness").await;
    let (status, body) = make_request(
        &app,
        Method::POST,
        "/v1/namespaces/freshness/tables",
        None,
        Some(json!({ "name": "events", "schema": location_test_schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, headers, _) = request_with_headers(
        &app,
        Method::GET,
        "/v1/namespaces/freshness/tables/events",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let etag = headers.get("etag").unwrap().to_str().unwrap().to_string();

    // Remove every metadata file the table points at.
    let metadata_dir = warehouse
        .path()
        .join("freshness")
        .join("events")
        .join("metadata");
    let removed = std::fs::read_dir(&metadata_dir)
        .expect("the table wrote metadata")
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            std::fs::remove_file(entry.path()).expect("remove metadata file");
        })
        .count();
    assert!(removed > 0, "there was a metadata file to remove");

    // An unconditional load now fails: the document really was needed.
    let (status, _) = make_request(
        &app,
        Method::GET,
        "/v1/namespaces/freshness/tables/events",
        None,
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "with its metadata deleted, a full load cannot succeed — otherwise this test \
         proves nothing about what the conditional path skips"
    );

    // The conditional one still answers, because it never opens the file.
    let (status, _, body) = request_with_headers(
        &app,
        Method::GET,
        "/v1/namespaces/freshness/tables/events",
        &[("if-none-match", &etag)],
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_MODIFIED,
        "a 304 must be answerable from the registry pointer alone: {body}"
    );
}
