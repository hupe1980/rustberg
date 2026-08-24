//! Federation over HTTP: several catalogs behind one endpoint.
//!
//! The unit tests in `catalog::federated` cover routing in isolation. These go
//! through the real stack — authorization, handlers, serialisation — because the
//! interesting failures are at the seams: a mounted name that comes back without
//! its prefix is unaddressable, and a mount whose ownership does not resolve is
//! invisible to everybody.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::catalog::{Capabilities, CatalogStore, Mount, RedbCatalog};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

/// The tenant every catalog here belongs to.
///
/// A mount declares its owner, and it must match the tenant owning the rest of
/// the catalog — otherwise a rename between a mount and the native catalog is
/// refused as *cross-tenant* long before routing is reached, which is correct
/// but not what these tests are about. Unauthenticated requests run as the
/// anonymous principal, whose tenant is `default`.
const TENANT: &str = "default";

/// Opens a native catalog in its own directory, with its own warehouse.
async fn catalog(label: &str) -> (Arc<dyn CatalogStore>, TempDir) {
    let (store, dir, _warehouse) = catalog_with_warehouse(label).await;
    (store, dir)
}

/// The same, also reporting the warehouse URL — which a mount must declare.
async fn catalog_with_warehouse(label: &str) -> (Arc<dyn CatalogStore>, TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    let warehouse = dir.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).expect("warehouse dir");
    let warehouse_url = rustberg::location::url_from_path(&warehouse);

    let store = RedbCatalog::open(dir.path().join(format!("{label}.redb")), &warehouse_url)
        .await
        .expect("open catalog");

    (Arc::new(store) as Arc<dyn CatalogStore>, dir, warehouse_url)
}

struct Federation {
    app: App,
    _dirs: Vec<TempDir>,
}

/// A server with a native catalog plus two mounts: one writable, one read-only.
async fn federation() -> Federation {
    let (native, native_dir) = catalog("native").await;
    let (prod, prod_dir, prod_warehouse) = catalog_with_warehouse("prod").await;
    let (legacy, legacy_dir, legacy_warehouse) = catalog_with_warehouse("legacy").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![
            Mount {
                name: "prod".to_string(),
                store: prod,
                capabilities: Capabilities::full(),
                owner: TENANT.to_string(),
                warehouse: Some(prod_warehouse),
            },
            Mount {
                name: "legacy".to_string(),
                store: legacy,
                capabilities: Capabilities::read_only(),
                owner: TENANT.to_string(),
                warehouse: Some(legacy_warehouse),
            },
        ])
        .build()
        .await
        .expect("build app");

    Federation {
        app,
        _dirs: vec![native_dir, prod_dir, legacy_dir],
    }
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
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

// ── Routing ─────────────────────────────────────────────────────────────────

/// The top-level listing is the mounts plus whatever the native catalog holds,
/// as one tree.
#[tokio::test]
async fn mounts_appear_as_top_level_namespaces() {
    let f = federation().await;

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["scratch"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(&f.app, Method::GET, "/v1/namespaces", None).await;
    assert_eq!(status, StatusCode::OK);

    let names: Vec<String> = parse(&body)["namespaces"]
        .as_array()
        .expect("a namespace listing")
        .iter()
        .map(|n| n.as_array().unwrap()[0].as_str().unwrap().to_string())
        .collect();

    assert!(names.contains(&"prod".to_string()), "{names:?}");
    assert!(names.contains(&"legacy".to_string()), "{names:?}");
    assert!(
        names.contains(&"scratch".to_string()),
        "the native catalog is still there: {names:?}"
    );
}

/// A table created under a mount lives in that mount's catalog and is addressed
/// through the mount name — the client never learns where the boundary is.
#[tokio::test]
async fn a_table_under_a_mount_round_trips_through_its_mount_name() {
    let f = federation().await;

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "analytics"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces/prod%1Fanalytics/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create under a mount: {body}");

    let (status, body) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/prod%1Fanalytics/tables/events",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "load under a mount: {body}");

    // Listing must report the identifier the client can address.
    let (status, body) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/prod%1Fanalytics/tables",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let identifiers = parse(&body)["identifiers"].as_array().unwrap().clone();
    assert_eq!(identifiers.len(), 1);
    let namespace: Vec<String> = identifiers[0]["namespace"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        namespace,
        vec!["prod".to_string(), "analytics".to_string()],
        "a listed name must carry the mount prefix, or the client cannot address it"
    );
}

/// Two mounts are separate catalogs, so the same name in each is two tables.
#[tokio::test]
async fn the_same_name_in_two_mounts_is_two_tables() {
    let f = federation().await;

    for mount in ["prod"] {
        send(
            &f.app,
            Method::POST,
            "/v1/namespaces",
            Some(json!({ "namespace": [mount, "db"] })),
        )
        .await;
        send(
            &f.app,
            Method::POST,
            &format!("/v1/namespaces/{mount}%1Fdb/tables"),
            Some(json!({ "name": "events", "schema": schema() })),
        )
        .await;
    }

    // The native catalog gets one too, at an unmounted name.
    send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["db"] })),
    )
    .await;
    let (status, _) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Both resolve, independently.
    let (a, _) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/events",
        None,
    )
    .await;
    let (b, _) = send(&f.app, Method::GET, "/v1/namespaces/db/tables/events", None).await;
    assert_eq!(a, StatusCode::OK);
    assert_eq!(b, StatusCode::OK);

    // Dropping one leaves the other alone.
    send(
        &f.app,
        Method::DELETE,
        "/v1/namespaces/prod%1Fdb/tables/events",
        None,
    )
    .await;

    let (a, _) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/events",
        None,
    )
    .await;
    let (b, _) = send(&f.app, Method::GET, "/v1/namespaces/db/tables/events", None).await;
    assert_eq!(a, StatusCode::NOT_FOUND);
    assert_eq!(
        b,
        StatusCode::OK,
        "a drop in one catalog must not reach into another"
    );
}

// ── Capabilities ────────────────────────────────────────────────────────────

/// A read-only mount serves reads and refuses writes, naming itself.
#[tokio::test]
async fn a_read_only_mount_refuses_writes() {
    let f = federation().await;

    // Reading the mount root works.
    let (status, _) = send(&f.app, Method::GET, "/v1/namespaces/legacy", None).await;
    assert_eq!(status, StatusCode::OK, "a read-only mount is readable");

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["legacy", "db"] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "a write to a read-only mount is refused: {body}"
    );
    assert!(
        body.contains("legacy"),
        "the refusal names the mount responsible: {body}"
    );
}

/// `GET /v1/config` publishes the intersection, so one read-only mount removes
/// every mutating endpoint from what the catalog promises.
#[tokio::test]
async fn config_advertises_only_what_every_mount_supports() {
    let f = federation().await;

    let (status, body) = send(&f.app, Method::GET, "/v1/config", None).await;
    assert_eq!(status, StatusCode::OK);

    let endpoints: Vec<String> = parse(&body)["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert!(!endpoints.is_empty(), "reads are still advertised");
    for endpoint in &endpoints {
        assert!(
            endpoint.starts_with("GET ")
                || endpoint.starts_with("HEAD ")
                // Telemetry reporting writes nothing to the catalog, so it
                // survives a read-only mount.
                || endpoint.ends_with("/metrics"),
            "a catalog containing a read-only mount must not promise {endpoint}"
        );
    }
}

/// And what the intersection removes from the *advertisement* it must not remove
/// from the mounts that have it.
///
/// Scan planning is the case worth driving end to end: `AppState` carries the
/// advertised set, so a handler checking it compiles and reads plausibly — and
/// then one read-only mount switches planning off for every native table in the
/// catalog. `/v1/config` stops promising `/plan`; `POST …/plan` under a capable
/// namespace must keep working.
#[tokio::test]
async fn a_capability_the_intersection_dropped_still_works_where_it_exists() {
    let f = federation().await;

    // The advertisement no longer promises planning: `legacy` is read-only.
    let (_, config) = send(&f.app, Method::GET, "/v1/config", None).await;
    let endpoints: Vec<String> = parse(&config)["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        !endpoints.iter().any(|e| e.ends_with("/plan")),
        "one mount that cannot plan removes the promise: {endpoints:?}"
    );

    // A table in the writable mount, which can.
    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables/events/plan",
        Some(json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "planning must still work on a mount that supports it: {body}"
    );
    assert_eq!(parse(&body)["status"], "completed");
}

/// Without a read-only mount, everything is advertised again — the intersection
/// is not a one-way ratchet applied to the whole server.
#[tokio::test]
async fn a_fully_capable_federation_advertises_everything() {
    let (native, _native_dir) = catalog("native").await;
    let (prod, _prod_dir, prod_warehouse) = catalog_with_warehouse("prod").await;

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

    let (_, body) = send(&app, Method::GET, "/v1/config", None).await;
    let endpoints: Vec<String> = parse(&body)["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert!(
        endpoints.iter().any(|e| e.starts_with("POST ")),
        "every mount is writable, so writes are advertised"
    );
}

// ── What cannot cross a mount ───────────────────────────────────────────────

/// Renaming between two catalogs cannot be atomic, so it is refused rather than
/// sequenced into a drop that might not be followed by a create.
#[tokio::test]
async fn a_rename_across_mounts_is_refused() {
    let f = federation().await;

    send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    send(
        &f.app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["elsewhere"] })),
    )
    .await;

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/tables/rename",
        Some(json!({
            "source": { "namespace": ["prod", "db"], "name": "events" },
            "destination": { "namespace": ["elsewhere"], "name": "events" }
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(body.contains("across mounts"), "{body}");

    // And the source is untouched.
    let (status, _) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/events",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a refused rename changes nothing");
}

/// Atomicity is a property of one backend, so a transaction spanning two is
/// refused rather than left half-applied.
#[tokio::test]
async fn a_transaction_across_mounts_is_refused() {
    let f = federation().await;

    for namespace in [json!(["prod", "db"]), json!(["local"])] {
        send(
            &f.app,
            Method::POST,
            "/v1/namespaces",
            Some(json!({ "namespace": namespace })),
        )
        .await;
    }
    send(
        &f.app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({ "name": "a", "schema": schema() })),
    )
    .await;
    send(
        &f.app,
        Method::POST,
        "/v1/namespaces/local/tables",
        Some(json!({ "name": "b", "schema": schema() })),
    )
    .await;

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/transactions/commit",
        Some(json!({
            "table-changes": [
                {
                    "identifier": { "namespace": ["prod", "db"], "name": "a" },
                    "requirements": [],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                },
                {
                    "identifier": { "namespace": ["local"], "name": "b" },
                    "requirements": [],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                }
            ]
        })),
    )
    .await;

    // `501`, not `500`. This is a deliberate refusal with a reason, and
    // reporting it as a server fault sends the client into a retry loop and the
    // operator looking for a crash — which is what hand-mapping every
    // non-conflict to `Internal` does.
    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "a cross-catalog transaction is refused, not failed: {body}"
    );
    assert!(
        body.contains("cannot span catalogs"),
        "the refusal should say why: {body}"
    );

    // Neither table advanced.
    for (ns, name) in [("prod%1Fdb", "a"), ("local", "b")] {
        let (_, body) = send(
            &f.app,
            Method::GET,
            &format!("/v1/namespaces/{ns}/tables/{name}"),
            None,
        )
        .await;
        assert!(
            parse(&body)["metadata"]["properties"].get("k").is_none(),
            "no part of a refused transaction may be visible in {ns}.{name}"
        );
    }
}

/// Within one mount, a transaction works normally — the refusal is about
/// crossing catalogs, not about being mounted.
#[tokio::test]
async fn a_transaction_inside_one_mount_succeeds() {
    let f = federation().await;

    send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    for name in ["a", "b"] {
        send(
            &f.app,
            Method::POST,
            "/v1/namespaces/prod%1Fdb/tables",
            Some(json!({ "name": name, "schema": schema() })),
        )
        .await;
    }

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/transactions/commit",
        Some(json!({
            "table-changes": [
                {
                    "identifier": { "namespace": ["prod", "db"], "name": "a" },
                    "requirements": [],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                },
                {
                    "identifier": { "namespace": ["prod", "db"], "name": "b" },
                    "requirements": [],
                    "updates": [{ "action": "set-properties", "updates": { "k": "v" } }]
                }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    for name in ["a", "b"] {
        let (_, body) = send(
            &f.app,
            Method::GET,
            &format!("/v1/namespaces/prod%1Fdb/tables/{name}"),
            None,
        )
        .await;
        assert_eq!(
            parse(&body)["metadata"]["properties"]["k"].as_str(),
            Some("v"),
            "{name} should have been committed"
        );
    }
}

// ── Configuration errors ────────────────────────────────────────────────────

/// Two mounts claiming one name is a startup failure, not a silent winner.
#[tokio::test]
async fn duplicate_mount_names_fail_to_build() {
    let (native, _native_dir) = catalog("native").await;
    let (a, _a_dir) = catalog("a").await;
    let (b, _b_dir) = catalog("b").await;

    let result = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_mounts(vec![
            Mount {
                name: "prod".to_string(),
                store: a,
                capabilities: Capabilities::full(),
                owner: TENANT.to_string(),
                warehouse: None,
            },
            Mount {
                name: "prod".to_string(),
                store: b,
                capabilities: Capabilities::full(),
                owner: TENANT.to_string(),
                warehouse: None,
            },
        ])
        .build()
        .await;

    assert!(result.is_err(), "two mounts cannot share a name");
}

// ============================================================================
// A remote REST mount
// ============================================================================
//
// The adapter is only interesting against a real server, so these run one
// Rustberg over TCP and mount it from another. That exercises the whole path a
// federated request takes — URL encoding, paging, JSON, metadata round-tripping
// — against a catalog that genuinely does not share memory with the caller.

/// Runs `app` on an ephemeral port until the returned guard is dropped.
struct Upstream {
    base: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve(app: App) -> Upstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local addr").port();

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_router().into_make_service()).await;
    });

    // The listener is already bound, so the server accepts as soon as the task
    // is polled; one yield is enough to get there.
    tokio::task::yield_now().await;

    Upstream {
        base: format!("http://127.0.0.1:{port}"),
        handle,
    }
}

/// An upstream Rustberg holding one namespace with one table.
async fn upstream_with_a_table() -> (Upstream, TempDir) {
    let (store, dir) = catalog("upstream").await;
    let app = App::builder()
        .with_catalog(store)
        .with_warehouse_location("memory://upstream")
        .with_default_tenant_id(TENANT)
        .build()
        .await
        .expect("build upstream");

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["sales"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/sales/tables",
        Some(json!({ "name": "orders", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    (serve(app).await, dir)
}

/// An upstream catalog holding `count` tables in one namespace, so paging
/// across the hop can be exercised.
async fn upstream_with_tables(count: usize) -> (Upstream, TempDir) {
    let (store, dir) = catalog("upstream").await;
    let app = App::builder()
        .with_catalog(store)
        .with_warehouse_location("memory://upstream")
        .with_default_tenant_id(TENANT)
        .build()
        .await
        .expect("build upstream");

    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["sales"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for index in 0..count {
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/namespaces/sales/tables",
            Some(json!({ "name": format!("t{index:02}"), "schema": schema() })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    (serve(app).await, dir)
}

/// Walking a mounted catalog one page at a time must reach every table, once.
///
/// Emitting an item's *name* as its cursor while reporting the remote's opaque
/// `pageToken` as the page's `next` puts two unrelated cursor spaces in one
/// page: the token a client gets back is a table name, which the remote either
/// rejects or reads as "start over", so a paging client loops or silently loses
/// rows — and every single-page test passes throughout.
///
/// Swept across page sizes, because that only shows where a page boundary
/// falls, and one size proves nothing.
#[tokio::test]
async fn paging_through_a_mounted_catalog_returns_every_table_once() {
    let (upstream, _up_dir) = upstream_with_tables(7).await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let expected: Vec<String> = (0..7).map(|i| format!("t{i:02}")).collect();

    for page_size in 1..=8 {
        let mut seen: Vec<String> = Vec::new();
        let mut token: Option<String> = None;

        // Bounded so a cursor that fails to advance fails the test rather than
        // hanging it — which is exactly how the defect behaved.
        for _ in 0..32 {
            let uri = match &token {
                Some(t) => format!(
                    "/v1/namespaces/partner%1Fsales/tables?pageSize={page_size}&pageToken={t}"
                ),
                None => format!("/v1/namespaces/partner%1Fsales/tables?pageSize={page_size}"),
            };

            let (status, body) = send(&app, Method::GET, &uri, None).await;
            assert_eq!(status, StatusCode::OK, "pageSize={page_size}: {body}");

            let value = parse(&body);
            for identifier in value["identifiers"].as_array().unwrap() {
                seen.push(identifier["name"].as_str().unwrap().to_string());
            }

            match value["next-page-token"].as_str() {
                Some(next) => token = Some(next.to_string()),
                None => break,
            }
        }

        seen.sort();
        assert_eq!(
            seen, expected,
            "pageSize={page_size}: paging a mount must yield every table exactly once"
        );
    }
}

/// A downstream server mounting `upstream` read-only at `partner`.
async fn downstream_mounting(upstream: &Upstream) -> (App, TempDir) {
    let (native, dir) = catalog("downstream").await;

    let remote = rustberg::catalog::RestCatalog::connect(&upstream.base, None)
        .await
        .expect("connect to the upstream catalog");
    let capabilities = remote.capabilities();

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://downstream")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "partner".to_string(),
            store: Arc::new(remote),
            capabilities,
            owner: TENANT.to_string(),
            warehouse: None,
        }])
        .build()
        .await
        .expect("build downstream");

    (app, dir)
}

/// The end-to-end claim: a table in somebody else's catalog is loadable through
/// this one, under this one's namespace tree.
#[tokio::test]
async fn a_table_in_a_remote_catalog_loads_through_the_mount() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (status, body) = send(
        &app,
        Method::GET,
        "/v1/namespaces/partner%1Fsales/tables/orders",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "federated load failed: {body}");

    let loaded = parse(&body);
    assert!(
        loaded["metadata"]["table-uuid"].is_string(),
        "the remote's metadata came through: {body}"
    );
    assert!(
        loaded["metadata"]["schemas"].is_array(),
        "including its schema"
    );
}

/// Listings must come back prefixed, or a client is handed names it cannot
/// address.
#[tokio::test]
async fn a_remote_listing_is_reported_under_the_mount_name() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (status, body) = send(
        &app,
        Method::GET,
        "/v1/namespaces/partner%1Fsales/tables",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let identifiers = parse(&body)["identifiers"].as_array().unwrap().clone();
    assert_eq!(identifiers.len(), 1);

    let namespace: Vec<String> = identifiers[0]["namespace"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(namespace, vec!["partner".to_string(), "sales".to_string()]);
    assert_eq!(identifiers[0]["name"], "orders");
}

/// Namespaces under the mount list too, so a client can walk the tree.
#[tokio::test]
async fn remote_namespaces_list_under_the_mount() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (status, body) = send(&app, Method::GET, "/v1/namespaces?parent=partner", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let namespaces: Vec<Vec<String>> = parse(&body)["namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            n.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        })
        .collect();

    assert!(
        namespaces.contains(&vec!["partner".to_string(), "sales".to_string()]),
        "expected the remote's namespace under the mount: {namespaces:?}"
    );
}

/// A remote mount is read-only, and says where the write belongs instead.
#[tokio::test]
async fn a_write_to_a_remote_mount_is_refused() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (status, body) = send(
        &app,
        Method::DELETE,
        "/v1/namespaces/partner%1Fsales/tables/orders",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");

    // And the table is still there.
    let (status, _) = send(
        &app,
        Method::GET,
        "/v1/namespaces/partner%1Fsales/tables/orders",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a refused write changed nothing");
}

/// A table the remote does not have is a miss, not a fault — `404` must survive
/// the hop rather than becoming a `500`.
#[tokio::test]
async fn a_missing_remote_table_is_not_found() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (status, _) = send(
        &app,
        Method::GET,
        "/v1/namespaces/partner%1Fsales/tables/absent",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Mounting a remote read-only removes writes from what the catalog advertises,
/// exactly as a read-only native mount does.
#[tokio::test]
async fn a_remote_mount_narrows_the_advertised_endpoints() {
    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (app, _down_dir) = downstream_mounting(&upstream).await;

    let (_, body) = send(&app, Method::GET, "/v1/config", None).await;
    let endpoints: Vec<String> = parse(&body)["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for endpoint in &endpoints {
        assert!(
            endpoint.starts_with("GET ")
                || endpoint.starts_with("HEAD ")
                || endpoint.ends_with("/metrics"),
            "a read-only remote mount must not leave {endpoint} advertised"
        );
    }
}

/// A mount that cannot be reached is a startup failure, not a subtree that
/// silently looks empty.
#[tokio::test]
async fn connecting_to_an_unreachable_catalog_fails() {
    // Port 1 is reserved and nothing listens there.
    let result = rustberg::catalog::RestCatalog::connect("http://127.0.0.1:1", None).await;
    assert!(result.is_err(), "an unreachable mount must not connect");
}

// ── Building mounts from configuration ──────────────────────────────────────
//
// The tests above construct mounts directly, which is how a library embedding
// Rustberg does it. The *binary* goes through `build_mount` and a config file,
// and that path had no coverage — a `rest` backend that the config layer did not
// recognise passed every test above and failed on the first real deployment.

use rustberg::config::MountConfig;

fn mount_config(backend: &str, catalog_url: &str) -> MountConfig {
    MountConfig {
        backend: backend.to_string(),
        catalog_url: catalog_url.to_string(),
        warehouse_location: String::new(),
        owner: TENANT.to_string(),
        read_only: false,
        token_env: None,
    }
}

#[tokio::test]
async fn a_rest_backend_is_buildable_from_configuration() {
    let (upstream, _up_dir) = upstream_with_a_table().await;

    let mount = rustberg::AppBuilder::build_mount(
        "partner",
        &mount_config("rest", &upstream.base),
        rustberg::location::LocationScope::default(),
    )
    .await
    .expect("a rest mount builds from configuration");

    assert_eq!(mount.name, "partner");
    assert!(
        !mount.capabilities.write,
        "a remote mount is served read-only"
    );
    assert!(
        mount.capabilities.views,
        "the upstream advertises view endpoints, so the mount reports views"
    );
}

#[tokio::test]
async fn a_native_backend_is_buildable_from_configuration() {
    let dir = TempDir::new().expect("temp dir");
    let warehouse = dir.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).expect("warehouse dir");

    let mut config = mount_config("native", &rustberg::location::url_from_path(dir.path()));
    config.warehouse_location = rustberg::location::url_from_path(warehouse);

    let mount = rustberg::AppBuilder::build_mount(
        "local",
        &config,
        rustberg::location::LocationScope::default(),
    )
    .await
    .expect("a native mount builds from configuration");

    assert!(mount.capabilities.write, "a native mount is writable");
}

#[tokio::test]
async fn a_read_only_native_backend_keeps_its_views_readable() {
    let dir = TempDir::new().expect("temp dir");
    let warehouse = dir.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).expect("warehouse dir");

    let mut config = mount_config("native", &rustberg::location::url_from_path(dir.path()));
    config.warehouse_location = rustberg::location::url_from_path(warehouse);
    config.read_only = true;

    let mount = rustberg::AppBuilder::build_mount(
        "archive",
        &config,
        rustberg::location::LocationScope::default(),
    )
    .await
    .expect("mount builds");

    assert!(!mount.capabilities.write);
    assert!(
        mount.capabilities.views,
        "read-only means 'will not change your views', not 'has no views'"
    );
}

/// An unknown backend is a startup failure naming what is available.
#[tokio::test]
async fn an_unknown_backend_is_refused_with_the_valid_options() {
    let err = rustberg::AppBuilder::build_mount(
        "bad",
        &mount_config("glue", "arn:whatever"),
        rustberg::location::LocationScope::default(),
    )
    .await
    .expect_err("glue is not implemented");

    let message = err.to_string();
    assert!(message.contains("glue"), "{message}");
    assert!(
        message.contains("native") && message.contains("rest"),
        "the refusal should name the backends that do exist: {message}"
    );
}

/// A named-but-unset token variable is a startup failure, not an anonymous
/// connection that fails later with the remote's `401`.
#[tokio::test]
async fn a_missing_mount_token_is_a_startup_failure() {
    let (upstream, _up_dir) = upstream_with_a_table().await;

    let mut config = mount_config("rest", &upstream.base);
    config.token_env = Some("RUSTBERG_TEST_MOUNT_TOKEN_UNSET".to_string());

    let err = rustberg::AppBuilder::build_mount(
        "partner",
        &config,
        rustberg::location::LocationScope::default(),
    )
    .await
    .expect_err("a named-but-unset token must fail");

    let message = err.to_string();
    assert!(
        message.contains("RUSTBERG_TEST_MOUNT_TOKEN_UNSET"),
        "{message}"
    );
    assert!(
        message.contains("token_env"),
        "names the setting: {message}"
    );
}

/// An ordinary load of a federated table must cost **one** remote round trip.
///
/// The entity tag comes from the catalog's metadata pointer, and a remote
/// catalog has no pointer-only endpoint — asking for one is a full load. So
/// computing a tag for a client that never sent `If-None-Match` would double
/// the cost of every federated read to serve a header nobody asked about.
///
/// Counted rather than timed: the failure is an extra request, not a slow one.
#[tokio::test]
async fn an_unconditional_federated_load_makes_one_remote_call() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Wraps a catalog and counts the loads that reach it.
    #[derive(Debug)]
    struct Counting {
        inner: Arc<dyn CatalogStore>,
        loads: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl CatalogStore for Counting {
        fn namespace_prefix_for(&self, _: &iceberg::NamespaceIdent) -> Option<String> {
            None
        }

        fn capabilities_for(
            &self,
            _: Option<&iceberg::NamespaceIdent>,
        ) -> rustberg::catalog::Capabilities {
            rustberg::catalog::Capabilities::full()
        }

        async fn load_table(
            &self,
            table: &iceberg::TableIdent,
        ) -> iceberg::Result<iceberg::table::Table> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load_table(table).await
        }

        async fn metadata_pointer(
            &self,
            table: &iceberg::TableIdent,
        ) -> iceberg::Result<Option<String>> {
            // A remote catalog answers this with a full load, so it counts too.
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.metadata_pointer(table).await
        }

        // Everything else delegates untouched.
        async fn list_namespaces(
            &self,
            parent: Option<&iceberg::NamespaceIdent>,
            page: &rustberg::catalog::PageRequest,
        ) -> iceberg::Result<rustberg::catalog::Page<iceberg::NamespaceIdent>> {
            self.inner.list_namespaces(parent, page).await
        }
        async fn create_namespace(
            &self,
            n: &iceberg::NamespaceIdent,
            p: std::collections::HashMap<String, String>,
        ) -> iceberg::Result<iceberg::Namespace> {
            self.inner.create_namespace(n, p).await
        }
        async fn get_namespace(
            &self,
            n: &iceberg::NamespaceIdent,
        ) -> iceberg::Result<iceberg::Namespace> {
            self.inner.get_namespace(n).await
        }
        async fn namespace_exists(&self, n: &iceberg::NamespaceIdent) -> iceberg::Result<bool> {
            self.inner.namespace_exists(n).await
        }
        async fn update_namespace(
            &self,
            n: &iceberg::NamespaceIdent,
            p: std::collections::HashMap<String, String>,
        ) -> iceberg::Result<()> {
            self.inner.update_namespace(n, p).await
        }
        async fn drop_namespace(&self, n: &iceberg::NamespaceIdent) -> iceberg::Result<()> {
            self.inner.drop_namespace(n).await
        }
        async fn list_tables(
            &self,
            n: &iceberg::NamespaceIdent,
            page: &rustberg::catalog::PageRequest,
        ) -> iceberg::Result<rustberg::catalog::Page<iceberg::TableIdent>> {
            self.inner.list_tables(n, page).await
        }
        async fn create_table(
            &self,
            n: &iceberg::NamespaceIdent,
            c: iceberg::TableCreation,
        ) -> iceberg::Result<iceberg::table::Table> {
            self.inner.create_table(n, c).await
        }
        async fn stage_create_table(
            &self,
            n: &iceberg::NamespaceIdent,
            c: iceberg::TableCreation,
        ) -> iceberg::Result<iceberg::table::Table> {
            self.inner.stage_create_table(n, c).await
        }
        async fn table_exists(&self, t: &iceberg::TableIdent) -> iceberg::Result<bool> {
            self.inner.table_exists(t).await
        }
        async fn register_table(
            &self,
            t: &iceberg::TableIdent,
            l: String,
        ) -> iceberg::Result<iceberg::table::Table> {
            self.inner.register_table(t, l).await
        }
        async fn commit_table(
            &self,
            t: &iceberg::TableIdent,
            r: Vec<iceberg::TableRequirement>,
            u: Vec<iceberg::TableUpdate>,
        ) -> iceberg::Result<iceberg::table::Table> {
            self.inner.commit_table(t, r, u).await
        }
        async fn commit_tables_atomic(
            &self,
            c: Vec<(
                iceberg::TableIdent,
                Vec<iceberg::TableRequirement>,
                Vec<iceberg::TableUpdate>,
            )>,
        ) -> iceberg::Result<Vec<iceberg::table::Table>> {
            self.inner.commit_tables_atomic(c).await
        }
        async fn rename_table(
            &self,
            s: &iceberg::TableIdent,
            d: &iceberg::TableIdent,
        ) -> iceberg::Result<()> {
            self.inner.rename_table(s, d).await
        }
        async fn drop_table(&self, t: &iceberg::TableIdent) -> iceberg::Result<()> {
            self.inner.drop_table(t).await
        }
        async fn purge_table(&self, t: &iceberg::TableIdent) -> iceberg::Result<()> {
            self.inner.purge_table(t).await
        }
        async fn list_views(
            &self,
            n: &iceberg::NamespaceIdent,
            page: &rustberg::catalog::PageRequest,
        ) -> iceberg::Result<rustberg::catalog::Page<iceberg::TableIdent>> {
            self.inner.list_views(n, page).await
        }
        async fn view_exists(&self, v: &iceberg::TableIdent) -> iceberg::Result<bool> {
            self.inner.view_exists(v).await
        }
        async fn load_view(
            &self,
            v: &iceberg::TableIdent,
        ) -> iceberg::Result<(String, iceberg::spec::ViewMetadata)> {
            self.inner.load_view(v).await
        }
        async fn register_view(
            &self,
            v: &iceberg::TableIdent,
            l: String,
        ) -> iceberg::Result<(String, iceberg::spec::ViewMetadata)> {
            self.inner.register_view(v, l).await
        }
        async fn create_view(
            &self,
            v: &iceberg::TableIdent,
            m: iceberg::spec::ViewMetadata,
        ) -> iceberg::Result<(String, iceberg::spec::ViewMetadata)> {
            self.inner.create_view(v, m).await
        }
        async fn update_view(
            &self,
            v: &iceberg::TableIdent,
            expected: &str,
            m: iceberg::spec::ViewMetadata,
        ) -> iceberg::Result<(String, iceberg::spec::ViewMetadata)> {
            self.inner.update_view(v, expected, m).await
        }
        async fn drop_view(&self, v: &iceberg::TableIdent) -> iceberg::Result<()> {
            self.inner.drop_view(v).await
        }
        async fn rename_view(
            &self,
            s: &iceberg::TableIdent,
            d: &iceberg::TableIdent,
        ) -> iceberg::Result<()> {
            self.inner.rename_view(s, d).await
        }
        async fn warehouse_for(&self, n: &iceberg::NamespaceIdent) -> Option<String> {
            self.inner.warehouse_for(n).await
        }
        async fn storage_health_check(
            &self,
        ) -> iceberg::Result<rustberg::catalog::StorageHealthStatus> {
            self.inner.storage_health_check().await
        }
    }

    let (upstream, _up_dir) = upstream_with_a_table().await;
    let (native, _native_dir) = catalog("downstream").await;

    let remote = rustberg::catalog::RestCatalog::connect(&upstream.base, None)
        .await
        .expect("connect");
    let capabilities = remote.capabilities();

    let loads = Arc::new(AtomicUsize::new(0));
    let counting = Counting {
        inner: Arc::new(remote),
        loads: loads.clone(),
    };

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://downstream")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "partner".to_string(),
            store: Arc::new(counting),
            capabilities,
            owner: TENANT.to_string(),
            warehouse: None,
        }])
        .build()
        .await
        .expect("build app");

    loads.store(0, Ordering::SeqCst);
    let (status, _) = send(
        &app,
        Method::GET,
        "/v1/namespaces/partner%1Fsales/tables/orders",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        loads.load(Ordering::SeqCst),
        1,
        "an unconditional load must reach the remote once; computing an entity tag \
         nobody asked for would double every federated read"
    );
}

/// A table created under a mount, at a location inside **that mount's**
/// warehouse, must be accepted.
///
/// Locations are confined to the warehouse to close a confused-deputy hole, but
/// a mount has its own warehouse — that is the point of mounting. Checking
/// every location against the *main* warehouse would reject legitimate tables
/// in every mount that stores its data somewhere else, which is all of them.
#[tokio::test]
async fn a_table_may_be_created_in_its_own_mounts_warehouse() {
    let (native, _native_dir) = catalog("native").await;

    let mount_dir = TempDir::new().expect("temp dir");
    let mount_warehouse = mount_dir.path().join("warehouse");
    std::fs::create_dir_all(&mount_warehouse).expect("warehouse dir");
    let mount_warehouse_url = rustberg::location::url_from_path(&mount_warehouse);

    let prod = RedbCatalog::open(
        mount_dir.path().join("prod.redb"),
        mount_warehouse_url.clone(),
    )
    .await
    .expect("open mount catalog");

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: Arc::new(prod),
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(rustberg::location::url_from_path(mount_warehouse)),
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
        Some(json!({
            "name": "events",
            "schema": schema(),
            "location": format!("{mount_warehouse_url}/db/events")
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a location inside the mount's own warehouse is legitimate: {body}"
    );
}

/// Widening the check to the mount's warehouse must not have removed it.
///
/// A mount governs its own warehouse; it does not govern anywhere else. A table
/// created under a mount at a location outside *that* warehouse is the same
/// confused-deputy hole the check exists to close.
#[tokio::test]
async fn a_mount_still_confines_locations_to_its_own_warehouse() {
    let (native, _native_dir) = catalog("native").await;

    let mount_dir = TempDir::new().expect("temp dir");
    let mount_warehouse = mount_dir.path().join("warehouse");
    std::fs::create_dir_all(&mount_warehouse).expect("warehouse dir");

    let prod = RedbCatalog::open(
        mount_dir.path().join("prod.redb"),
        rustberg::location::url_from_path(&mount_warehouse),
    )
    .await
    .expect("open mount catalog");

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![Mount {
            name: "prod".to_string(),
            store: Arc::new(prod),
            capabilities: Capabilities::full(),
            owner: TENANT.to_string(),
            warehouse: Some(rustberg::location::url_from_path(mount_warehouse)),
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
        Some(json!({
            "name": "escaped",
            "schema": schema(),
            "location": "file:///somewhere/else/entirely"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mount confines locations to its own warehouse, not to nowhere: {body}"
    );

    // And the main warehouse is not a way in either: a mount's tables belong in
    // the mount's warehouse.
    let (status, body) = send(
        &app,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        Some(json!({
            "name": "wrong_warehouse",
            "schema": schema(),
            "location": "memory://native/db/wrong_warehouse"
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the server's own warehouse is not this mount's: {body}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Root listing: two cursor spaces, one page token
// ────────────────────────────────────────────────────────────────────────────

/// Walking the root listing must yield every name exactly once, at any page
/// size.
///
/// The root draws on two sources — the mount table and the native catalog —
/// whose cursors are unrelated. Prepending the mounts to every backend page
/// breaks that three ways at once: the page exceeds the requested size, the
/// mounts repeat on every page, and, worst, a page that ends on a mount hands
/// the native catalog a cursor from the wrong space. `RedbCatalog` seeks to
/// whatever it is given and a root scan has no prefix to reject it against, so
/// every namespace sorting below that string is skipped — silently, with a `200`
/// and no error anywhere.
///
/// Sweeping the page size is the point: that only shows when a page boundary
/// falls inside the mount list, so a single page size proves nothing.
#[tokio::test]
async fn root_listing_pages_over_mounts_and_native_without_loss() {
    let (native, native_dir) = catalog("native").await;
    let (prod, prod_dir, prod_warehouse) = catalog_with_warehouse("prod").await;
    let (legacy, legacy_dir, legacy_warehouse) = catalog_with_warehouse("legacy").await;

    let app = App::builder()
        .with_catalog(native)
        .with_warehouse_location("memory://native")
        .with_default_tenant_id(TENANT)
        .with_mounts(vec![
            Mount {
                name: "prod".to_string(),
                store: prod,
                capabilities: Capabilities::full(),
                owner: TENANT.to_string(),
                warehouse: Some(prod_warehouse),
            },
            Mount {
                name: "legacy".to_string(),
                store: legacy,
                capabilities: Capabilities::read_only(),
                owner: TENANT.to_string(),
                warehouse: Some(legacy_warehouse),
            },
        ])
        .build()
        .await
        .expect("build app");

    let _dirs = (native_dir, prod_dir, legacy_dir);

    // Created through the API so each carries a recorded owner — a namespace
    // with none is invisible to everybody, which would hide the very rows this
    // test is checking are not lost. Named to straddle the mount names
    // lexically, so a cursor from the wrong space skips some and keeps others
    // rather than failing obviously.
    for name in ["alpha", "beta", "zulu"] {
        let (status, body) = send(
            &app,
            Method::POST,
            "/v1/namespaces",
            Some(json!({ "namespace": [name] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create {name}: {body}");
    }

    let expected = vec!["alpha", "beta", "legacy", "prod", "zulu"];

    for page_size in 1..=6 {
        let mut seen: Vec<String> = Vec::new();
        let mut token: Option<String> = None;

        for _ in 0..40 {
            let uri = match &token {
                Some(t) => format!(
                    "/v1/namespaces?pageSize={page_size}&pageToken={}",
                    urlencode(t)
                ),
                None => format!("/v1/namespaces?pageSize={page_size}"),
            };
            let (status, body) = send(&app, Method::GET, &uri, None).await;
            assert_eq!(status, StatusCode::OK, "page size {page_size}: {body}");

            let json: serde_json::Value = serde_json::from_str(&body).expect("json");
            let namespaces = json["namespaces"].as_array().expect("namespaces array");
            assert!(
                namespaces.len() <= page_size,
                "page size {page_size} exceeded: got {} entries",
                namespaces.len()
            );
            for entry in namespaces {
                seen.push(
                    entry.as_array().expect("namespace parts")[0]
                        .as_str()
                        .expect("part")
                        .to_string(),
                );
            }

            match json["next-page-token"].as_str() {
                Some(next) => token = Some(next.to_string()),
                None => break,
            }
        }

        seen.sort();
        assert_eq!(
            seen, expected,
            "page size {page_size} did not recover every namespace exactly once"
        );
    }
}

/// A mount whose name already exists underneath makes that namespace
/// unreachable, so the server refuses to start rather than hiding it.
///
/// Routing sends every request for the mount's name to the mount, so the native
/// namespace could be listed but never loaded — a subtree that silently does not
/// exist, which is what C1 already refuses for a mount that cannot be opened.
#[tokio::test]
async fn a_mount_shadowing_a_native_namespace_refuses_to_start() {
    let (native, _native_dir) = catalog("native").await;
    native
        .create_namespace(
            &iceberg::NamespaceIdent::from_vec(vec!["prod".to_string()]).unwrap(),
            std::collections::HashMap::new(),
        )
        .await
        .expect("create namespace");

    let (prod, _prod_dir, prod_warehouse) = catalog_with_warehouse("prod").await;

    let result = App::builder()
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
        .await;

    let err = result.err().expect("a shadowing mount must not start");
    let message = err.to_string();
    assert!(
        message.contains("prod") && message.contains("shadows"),
        "the error must name the mount and say what it hides: {message}"
    );
}

/// Percent-encodes a page token for use in a query string.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
