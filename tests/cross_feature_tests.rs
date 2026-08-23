//! Where two features meet.
//!
//! Every bug the audit rounds found lived here rather than inside a feature:
//! conditional loading was correct and federation was correct, and together they
//! doubled every remote read; location confinement was correct and mounts were
//! correct, and together they rejected every federated table. Each feature's own
//! tests passed throughout.
//!
//! So these exercise *combinations* on purpose. The suite is organised by pair,
//! and a new feature should gain a section here rather than only its own file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use rustberg::catalog::{Capabilities, CatalogStore, Mount, RedbCatalog};
use rustberg::credentials::{
    StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

/// The tenant everything here belongs to, matching the anonymous principal's.
const TENANT: &str = "default";

/// A catalog with its own warehouse.
async fn catalog(label: &str) -> (Arc<dyn CatalogStore>, TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    let warehouse = dir.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).expect("warehouse dir");
    let warehouse_url = format!("file://{}", warehouse.to_string_lossy());

    let store = RedbCatalog::open(dir.path().join(format!("{label}.redb")), &warehouse_url)
        .await
        .expect("open catalog");

    (Arc::new(store) as Arc<dyn CatalogStore>, dir, warehouse_url)
}

/// A catalog that also serves as the policy store, which is what a redb or
/// Postgres catalog is: one database to configure and back up.
async fn catalog_with_policy_store(
    label: &str,
) -> (
    (
        Arc<dyn CatalogStore>,
        Arc<dyn rustberg::auth::policy_store::PolicyStore>,
    ),
    TempDir,
    String,
) {
    let dir = TempDir::new().expect("temp dir");
    let warehouse = dir.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).expect("warehouse dir");
    let warehouse_url = format!("file://{}", warehouse.to_string_lossy());

    let store = Arc::new(
        RedbCatalog::open(dir.path().join(format!("{label}.redb")), &warehouse_url)
            .await
            .expect("open catalog"),
    );

    (
        (
            store.clone() as Arc<dyn CatalogStore>,
            store as Arc<dyn rustberg::auth::policy_store::PolicyStore>,
        ),
        dir,
        warehouse_url,
    )
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    send_as(app, method, uri, None, body).await
}

async fn send_as(
    app: &App,
    method: Method,
    uri: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(key) = key {
        builder = builder.header("X-API-Key", key);
    }

    let request = match body {
        Some(json) => {
            builder = builder.header("Content-Type", "application/json");
            builder
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap()
        }
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = app.clone().into_router().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON: {e}\n{body}"))
}

fn schema() -> serde_json::Value {
    json!({
        "type": "struct",
        "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }]
    })
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × staged creation
// ════════════════════════════════════════════════════════════════════════════

/// Spark's CTAS against a table that lives in a mount.
///
/// Staging records a note in the mount's own catalog, and the `assert-create`
/// commit has to find it there — routed by a namespace whose first segment is
/// the mount name, which the staging call also had to strip.
#[tokio::test]
async fn a_staged_create_works_inside_a_mount() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;

    // Stage.
    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "summary", "schema": schema(), "stage-create": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "staging inside a mount: {body}");

    // Invisible until committed — in the mount, not just in the native catalog.
    let (status, _) = send(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/summary",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Commit.
    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables/summary",
        Some(json!({
            "requirements": [{ "type": "assert-create" }],
            "updates": [{ "action": "set-properties", "updates": { "written-by": "ctas" } }]
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "staged commit inside a mount: {body}"
    );

    let (status, body) = send(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/summary",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse(&body)["metadata"]["properties"]["written-by"].as_str(),
        Some("ctas")
    );
}

/// A read-only mount cannot be staged into, and says so rather than accepting a
/// stage that could never be committed.
#[tokio::test]
async fn a_read_only_mount_refuses_staging() {
    let (native, _n, _nw) = catalog("native").await;
    let (legacy, _l, legacy_warehouse) = catalog("legacy").await;

    // The namespace has to exist *before* the mount goes read-only: a read-only
    // mount cannot create one, and without it the request is refused as a
    // missing namespace long before the capability check is reached.
    legacy
        .create_namespace(
            &iceberg::NamespaceIdent::from_vec(vec!["db".to_string()]).unwrap(),
            {
                let mut properties = HashMap::new();
                properties.insert(
                    "rustberg.internal.tenant-id".to_string(),
                    TENANT.to_string(),
                );
                properties
            },
        )
        .await
        .expect("seed the mount's namespace");

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "legacy".to_string(),
            store: legacy,
            capabilities: Capabilities::read_only(),
            owner: TENANT.to_string(),
            warehouse: Some(legacy_warehouse),
        }])
        .build()
        .await
        .expect("build app");

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/legacy%1Fdb/tables",
        Some(json!({ "name": "t", "schema": schema(), "stage-create": true })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "a read-only mount must refuse staging: {body}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × credential vending
// ════════════════════════════════════════════════════════════════════════════

/// Records what it was asked to vend for, and refuses anything outside the
/// prefixes it was configured with — like every real provider.
#[derive(Debug)]
struct RecordingProvider {
    allowed: Vec<String>,
    asked: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl StorageCredentialProvider for RecordingProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        self.asked
            .lock()
            .unwrap()
            .push(request.table_location.clone());

        let permitted = self
            .allowed
            .iter()
            .any(|prefix| rustberg::location::is_within(prefix, &request.table_location));

        if !permitted {
            return Err(StorageCredentialVendingError::PermissionDenied(format!(
                "'{}' is outside the permitted prefixes",
                request.table_location
            )));
        }

        Ok(vec![StorageCredential {
            prefix: request.table_location.clone(),
            config: HashMap::from([("test.token".to_string(), "granted".to_string())]),
        }])
    }

    fn supports_location(&self, _location: &str) -> bool {
        true
    }
}

/// A table in a mount must get credentials.
///
/// This failed silently before: the provider's prefixes defaulted to the
/// server's warehouse alone, so a mounted table's prefix was refused — and a
/// refused vend still returns `200`, just without credentials. The client got
/// metadata it had no way to read and nothing saying why.
#[tokio::test]
async fn a_mounted_table_gets_credentials_vended() {
    let (native, _n, native_warehouse) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let asked = Arc::new(Mutex::new(Vec::new()));
    let provider = Arc::new(RecordingProvider {
        // Exactly what the builder now derives: every managed warehouse.
        allowed: vec![native_warehouse.clone(), prod_warehouse.clone()],
        asked: asked.clone(),
    });

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location(native_warehouse)
        .with_default_tenant_id(TENANT)
        .with_credential_provider(provider)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse.clone()),
        }])
        .build()
        .await
        .expect("build app");

    let asked_warehouse = prod_warehouse;

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;

    // Delegation is something a client asks for.
    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/namespaces/prod%1Fdb/tables/events")
                .header("X-Iceberg-Access-Delegation", "vended-credentials")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    let loaded = parse(&body);

    let credentials = loaded["storage-credentials"]
        .as_array()
        .unwrap_or_else(|| panic!("a mounted table must be credentialed: {body}"));
    assert!(
        !credentials.is_empty(),
        "a refused vend returns 200 with no credentials, which is the silent \
         failure this checks for: {body}"
    );

    // And the prefix asked about was the mount's, not the server's.
    let asked = asked.lock().unwrap();
    assert!(
        asked
            .iter()
            .any(|location| rustberg::location::is_within(&asked_warehouse, location)),
        "the provider should have been asked about the mount's warehouse \
         ({asked_warehouse}), got: {asked:?}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × authorization
// ════════════════════════════════════════════════════════════════════════════

fn key(name: &str, tenant: &str, role: &str) -> (ApiKey, String) {
    let (api_key, secret) = ApiKeyBuilder::new(name, tenant).with_role(role).build();
    (api_key, secret.to_string())
}

const POLICIES: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };
"#;

/// A mount declares its owning tenant, and that decides visibility.
///
/// The interesting half is the *negative* one: a principal from another tenant
/// must get `404`, not `403`, because a mount that exists but is not yours is
/// exactly the existence oracle the guard closes for ordinary namespaces.
#[tokio::test]
async fn a_mounts_owner_decides_who_can_see_it() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let (acme_key, acme_secret) = key("acme-admin", "acme", "admin");
    let (other_key, other_secret) = key("other-admin", "other", "admin");

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![acme_key, other_key])
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: "acme".to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    // The owning tenant can use it.
    let (status, body) = send_as(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&acme_secret),
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the mount's own tenant: {body}");

    // Another tenant cannot — and cannot learn that it exists.
    let (status, _) = send_as(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb",
        Some(&other_secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a mount owned by another tenant must be invisible, not forbidden — \
         `403` would confirm it exists"
    );

    let (status, _) = send_as(
        &app,
        Method::GET,
        "/v1/namespaces/prod",
        Some(&other_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "including the mount root");
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × policy administration
// ════════════════════════════════════════════════════════════════════════════

/// A policy change applies to mounted namespaces too.
///
/// Policy lives in the *native* catalog while the table lives in a mount, so
/// this checks the two are actually connected: a revocation that only covered
/// the catalog holding the policy would leave every federated table wide open.
#[tokio::test]
async fn a_policy_change_reaches_mounted_tables() {
    let (native, _n, _nw) = catalog_with_policy_store("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let (admin_key, admin_secret) = key("admin", "acme", "admin");
    let (reader_key, reader_secret) = key("reader", "acme", "reader");

    let permissive = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"reader",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let app = App::builder()
        .with_catalog(native.0.clone())
        .with_policy_store(native.1)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id("acme")
        .with_policies(permissive)
        .with_api_keys(vec![admin_key, reader_key])
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: "acme".to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    send_as(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(&admin_secret),
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;

    // The reader can see the mounted namespace.
    let (status, _) = send_as(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb",
        Some(&reader_secret),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Revoke the reader, at runtime.
    let (status, body) = send_as(
        &app,
        Method::PUT,
        "/management/v1/policies",
        Some(&admin_secret),
        Some(json!({ "source": POLICIES, "note": "revoke reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The revocation reaches the mount.
    let (status, _) = send_as(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb",
        Some(&reader_secret),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a policy change must govern mounted namespaces too, or federated tables \
         are outside the policy engine entirely"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × register / unregister
// ════════════════════════════════════════════════════════════════════════════

/// A table can be handed between the mount and its own catalog without ever
/// touching its files — which is what `unregister` plus `register` is for.
#[tokio::test]
async fn a_mounted_table_can_be_unregistered_and_registered_again() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let metadata_location = parse(&body)["metadata-location"]
        .as_str()
        .expect("a created table names its metadata")
        .to_string();

    let (status, _) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables/events/unregister",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/events",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Registering it back needs the *mount's* warehouse to be the one the
    // confinement check uses.
    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/register",
        Some(json!({ "name": "events", "metadata-location": metadata_location })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "re-registering into the mount it came from: {body}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Federation × conditional loading
// ════════════════════════════════════════════════════════════════════════════

/// Conditional loading must work through a mount, and the tag must track the
/// mounted table rather than something in the native catalog.
#[tokio::test]
async fn a_mounted_table_supports_conditional_loading() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;

    let uri = "/v1/namespaces/prod%1Fdb/tables/events";

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .expect("a mounted table names its version")
        .to_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("If-None-Match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);

    // A commit must move the tag, or a client caches a stale table forever.
    send(
        &app,
        Method::POST,
        uri,
        Some(json!({
            "requirements": [],
            "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
        })),
    )
    .await;

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("If-None-Match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a commit inside a mount must invalidate the tag"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Staged creation × federation × transactions
// ════════════════════════════════════════════════════════════════════════════

/// A transaction that stages one table and commits it alongside another, all
/// inside one mount.
#[tokio::test]
async fn a_staged_table_can_be_committed_in_a_transaction_within_a_mount() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse),
        }])
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;

    // One real table, one staged.
    send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "existing", "schema": schema() })),
    )
    .await;
    let (status, _) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "staged", "schema": schema(), "stage-create": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/transactions/commit",
        Some(json!({
            "table-changes": [
                {
                    "identifier": { "namespace": ["prod", "db"], "name": "existing" },
                    "requirements": [],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                },
                {
                    "identifier": { "namespace": ["prod", "db"], "name": "staged" },
                    "requirements": [{ "type": "assert-create" }],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                }
            ]
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "one transaction may both update and create, inside one mount: {body}"
    );

    for name in ["existing", "staged"] {
        let (status, body) = send(
            &app,
            Method::GET,
            &format!("/v1/namespaces/prod%1Fdb/tables/{name}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name} should exist: {body}");
        assert_eq!(
            parse(&body)["metadata"]["properties"]["k"].as_str(),
            Some("v")
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Supplied catalog × policy administration
// ════════════════════════════════════════════════════════════════════════════

/// A catalog supplied from outside is not required to store policy, so runtime
/// policy administration is off unless a store is supplied too.
///
/// This is the honest half of the contract: the endpoints report `501` rather
/// than half-working against a store that does not exist.
#[tokio::test]
async fn a_supplied_catalog_without_a_policy_store_has_no_policy_administration() {
    let (native, _n, _nw) = catalog("native").await;
    let (admin_key, admin_secret) = key("admin", "acme", "admin");

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![admin_key])
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    let (status, body) = send_as(
        &app,
        Method::GET,
        "/management/v1/policies",
        Some(&admin_secret),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "without a policy store there is nothing to administer: {body}"
    );
}

/// Supplying one turns it on — and the same object may serve as both, which is
/// what keeps a deployment to a single database.
#[tokio::test]
async fn supplying_a_policy_store_enables_policy_administration() {
    let (native, _n, _nw) = catalog_with_policy_store("native").await;
    let (admin_key, admin_secret) = key("admin", "acme", "admin");

    let app = App::builder()
        .with_catalog(native.0)
        .with_policy_store(native.1)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![admin_key])
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    let (status, body) = send_as(
        &app,
        Method::GET,
        "/management/v1/policies",
        Some(&admin_secret),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        parse(&body)["sequence"],
        1,
        "the supplied policy set was seeded as the first revision"
    );

    // And it is administrable, not merely readable.
    let (status, body) = send_as(
        &app,
        Method::PUT,
        "/management/v1/policies",
        Some(&admin_secret),
        Some(json!({ "source": POLICIES, "note": "no-op" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(parse(&body)["sequence"], 2);
}

/// A view created in a mount, with no explicit location, must land in that
/// mount's warehouse.
///
/// Tables get their default location from the catalog that will hold them, so
/// a mounted table lands in the mount's warehouse without the handler knowing
/// anything. Views build their location in the handler, which is a chance to
/// use the wrong warehouse — and then fail the confinement check that correctly
/// uses the right one.
#[tokio::test]
async fn a_view_created_in_a_mount_defaults_into_that_mounts_warehouse() {
    let (native, _n, _nw) = catalog("native").await;
    let (prod, _p, prod_warehouse) = catalog("prod").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: prod,
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(prod_warehouse.clone()),
        }])
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/views",
        Some(json!({
            "name": "summary",
            "schema": schema(),
            "view-version": {
                "version-id": 1,
                "timestamp-ms": 1_700_000_000_000i64,
                "schema-id": 0,
                "summary": { "operation": "create" },
                "default-namespace": ["prod", "db"],
                "representations": [
                    { "type": "sql", "sql": "SELECT 1", "dialect": "spark" }
                ]
            }
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a view with no location must default into its mount's warehouse: {body}"
    );

    assert!(
        parse(&body)["metadata"]["location"]
            .as_str()
            .expect("a view names its location")
            .starts_with(prod_warehouse.trim_end_matches('/')),
        "the view landed outside the mount's warehouse: {body}"
    );
}
