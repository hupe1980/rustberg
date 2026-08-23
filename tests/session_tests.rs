//! The in-process surface, and its equivalence to the HTTP one.
//!
//! `Session` exists so that a host embedding Rustberg does not have to drive
//! HTTP shapes to get an authorized catalog. The whole risk in that is drift: a
//! second surface that enforces *almost* what the first does is worse than no
//! second surface, because it looks correct and is exercised by nobody.
//!
//! So these tests are written as **equivalence** wherever an equivalence exists.
//! Each one drives the same operation, as the same principal, against the same
//! catalog, through both paths and asserts the outcomes agree. Testing the two
//! separately would pass even when they had diverged, which is exactly the
//! failure this file exists to catch.

use std::collections::HashMap;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use iceberg::{NamespaceIdent, TableIdent};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder, Principal};
use rustberg::catalog::session::page;
use rustberg::error::AppError;
use serde_json::json;
use tower::ServiceExt;

const TENANT: &str = "acme";

/// Policies giving `analysts` read and list under one namespace subtree only.
///
/// Deliberately narrower than the built-in roles: the interesting equivalences
/// are the *denials*, and a principal permitted everything proves nothing about
/// whether the two paths agree on refusing.
const POLICIES: &str = r#"
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

permit(
  principal in Rustberg::Group::"analysts",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource in Rustberg::Namespace::"acme\u{1F}open"
);

permit(
  principal in Rustberg::Group::"analysts",
  action == Rustberg::Action::"List",
  resource == Rustberg::Tenant::"acme"
);
"#;

fn key(name: &str, roles: &[&str]) -> (ApiKey, String) {
    let mut builder = ApiKeyBuilder::new(name, TENANT);
    for role in roles {
        builder = builder.with_role(*role);
    }
    let (api_key, secret) = builder.build();
    (api_key, secret.to_string())
}

fn principal(id: &str, roles: &[&str]) -> Principal {
    Principal::embedded(id, TENANT)
        .with_roles(roles.iter().copied())
        .build()
}

fn ns(parts: &[&str]) -> NamespaceIdent {
    NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect()).unwrap()
}

fn table(namespace: &[&str], name: &str) -> TableIdent {
    TableIdent::new(ns(namespace), name.to_string())
}

/// An app seeded with two namespaces: one an analyst may read, one it may not.
async fn seeded() -> (App, String, String) {
    let (admin_key, admin_secret) = key("admin", &["admin"]);
    let (analyst_key, analyst_secret) = key("analyst", &["analysts"]);

    let (app, _keys) = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id(TENANT)
        .with_policies(POLICIES)
        .with_api_keys(vec![admin_key, analyst_key])
        .build_with_api_keys()
        .await
        .expect("build app");

    // Seeded through the API so each namespace carries a recorded owner; a
    // namespace with none is invisible to everybody and would make every
    // assertion below vacuously true.
    for name in ["open", "secret"] {
        let (status, body) = http(
            &app,
            Method::POST,
            "/v1/namespaces",
            &admin_secret,
            Some(json!({ "namespace": [name] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seed {name}: {body}");
    }

    (app, admin_secret, analyst_secret)
}

async fn http(
    app: &App,
    method: Method,
    uri: &str,
    api_key: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let router = app.clone().into_router();
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", api_key);

    let request = match body {
        Some(json) => {
            builder = builder.header("Content-Type", "application/json");
            builder.body(Body::from(serde_json::to_vec(&json).unwrap()))
        }
        None => builder.body(Body::empty()),
    }
    .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

// ────────────────────────────────────────────────────────────────────────────
// Equivalence
// ────────────────────────────────────────────────────────────────────────────

/// A namespace the caller may not see is `404` on both paths, not `403`.
///
/// This is the guarantee that costs the most to lose and is the easiest to lose
/// quietly: if the in-process path reported "forbidden" where HTTP reports "no
/// such namespace", a host built on it would leak the existence of every other
/// tenant's namespaces while every HTTP test kept passing.
#[tokio::test]
async fn an_invisible_namespace_is_not_found_on_both_paths() {
    let (app, _admin, analyst) = seeded().await;

    let (status, _) = http(&app, Method::GET, "/v1/namespaces/secret", &analyst, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "HTTP hides it");

    let session = app.as_principal(principal("analyst", &["analysts"]));
    let err = session
        .get_namespace(&ns(&["secret"]))
        .await
        .expect_err("in-process must hide it too");

    assert!(
        matches!(err, AppError::NoSuchNamespace(_)),
        "must not be Forbidden — that would confirm the namespace exists: {err:?}"
    );
    assert_eq!(
        err.status_code(),
        StatusCode::NOT_FOUND,
        "the two paths must agree on the status"
    );
}

/// A namespace the caller may see resolves identically on both paths.
#[tokio::test]
async fn a_visible_namespace_loads_on_both_paths() {
    let (app, _admin, analyst) = seeded().await;

    let (status, body) = http(&app, Method::GET, "/v1/namespaces/open", &analyst, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let session = app.as_principal(principal("analyst", &["analysts"]));
    let loaded = session
        .get_namespace(&ns(&["open"]))
        .await
        .expect("in-process must load it too");

    assert_eq!(loaded.name(), &ns(&["open"]));
}

/// Listing filters to the same set through both paths.
///
/// The analyst may `List` the catalog root but may only `Read` `open`, so
/// exactly one of the two namespaces is visible. A path that filtered on the
/// wrong action, or forgot to filter, would show both.
#[tokio::test]
async fn listing_filters_to_the_same_set_on_both_paths() {
    let (app, _admin, analyst) = seeded().await;

    let (status, body) = http(&app, Method::GET, "/v1/namespaces", &analyst, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut over_http: Vec<String> = parsed["namespaces"]
        .as_array()
        .expect("namespaces")
        .iter()
        .map(|n| n[0].as_str().unwrap().to_string())
        .collect();
    over_http.sort();

    let session = app.as_principal(principal("analyst", &["analysts"]));
    let mut in_process: Vec<String> = session
        .list_namespaces(None, page(100))
        .await
        .expect("list")
        .items
        .iter()
        .map(|n| n.join("."))
        .collect();
    in_process.sort();

    assert_eq!(
        over_http,
        vec!["open".to_string()],
        "HTTP shows only `open`"
    );
    assert_eq!(
        in_process, over_http,
        "the in-process listing must show exactly what HTTP shows"
    );
}

/// A write the caller may not perform is refused on both paths.
///
/// The analyst holds `Read` and `List` on `open` and nothing else, so creating a
/// table there is denied — but *visibly*, as `403`, because the caller can
/// already see the namespace. That distinction is the other half of the `404`
/// rule and is just as easy to get wrong in a second implementation.
#[tokio::test]
async fn a_forbidden_write_is_refused_visibly_on_both_paths() {
    let (app, _admin, analyst) = seeded().await;

    let (status, _) = http(
        &app,
        Method::POST,
        "/v1/namespaces/open/tables",
        &analyst,
        Some(json!({
            "name": "denied",
            "schema": { "type": "struct", "schema-id": 0, "fields": [] }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "HTTP refuses visibly");

    let session = app.as_principal(principal("analyst", &["analysts"]));
    let err = session
        .create_table(
            &ns(&["open"]),
            iceberg::TableCreation::builder()
                .name("denied".to_string())
                .schema(
                    iceberg::spec::Schema::builder()
                        .with_schema_id(0)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .await
        .expect_err("in-process must refuse too");

    assert_eq!(
        err.status_code(),
        StatusCode::FORBIDDEN,
        "the caller can see the namespace, so the refusal is visible: {err:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Behaviour only the in-process path has
// ────────────────────────────────────────────────────────────────────────────

/// The full lifecycle works without a router.
///
/// This is the DX claim itself: a host holds the catalog as Rust types.
#[tokio::test]
async fn a_host_drives_the_whole_lifecycle_in_process() {
    let (app, _admin, _analyst) = seeded().await;
    let session = app.as_principal(principal("admin", &["admin"]));

    session
        .create_namespace(&ns(&["lab"]), HashMap::new())
        .await
        .expect("create namespace");
    assert!(session.namespace_exists(&ns(&["lab"])).await.unwrap());

    let creation = iceberg::TableCreation::builder()
        .name("events".to_string())
        .schema(
            iceberg::spec::Schema::builder()
                .with_schema_id(0)
                .build()
                .unwrap(),
        )
        .build();
    session
        .create_table(&ns(&["lab"]), creation)
        .await
        .expect("create table");

    let ident = table(&["lab"], "events");
    assert!(session.table_exists(&ident).await.unwrap());
    session.load_table(&ident).await.expect("load table");

    let listed: Vec<String> = session
        .list_tables(&ns(&["lab"]), page(100))
        .await
        .expect("list tables")
        .items
        .iter()
        .map(|t| t.name().to_string())
        .collect();
    assert_eq!(listed, vec!["events".to_string()]);

    session
        .rename_table(&ident, &table(&["lab"], "renamed"))
        .await
        .expect("rename");
    assert!(!session.table_exists(&ident).await.unwrap());

    session
        .drop_table(&table(&["lab"], "renamed"), false)
        .await
        .expect("drop table");
    session
        .drop_namespace(&ns(&["lab"]))
        .await
        .expect("drop namespace");
    assert!(!session.namespace_exists(&ns(&["lab"])).await.unwrap());
}

/// A client-supplied location outside the warehouse is refused in-process too.
///
/// This is the confused-deputy check. An in-process path that skipped it would
/// let a host record a table whose files live under somebody else's prefix — and
/// that location later becomes the prefix of any credential the *HTTP* path
/// vends for the table, so the hole would open on the surface that still checks.
#[tokio::test]
async fn a_location_outside_the_warehouse_is_refused_in_process() {
    let (app, _admin, _analyst) = seeded().await;
    let session = app.as_principal(principal("admin", &["admin"]));

    let creation = iceberg::TableCreation::builder()
        .name("escapee".to_string())
        .schema(
            iceberg::spec::Schema::builder()
                .with_schema_id(0)
                .build()
                .unwrap(),
        )
        .location("memory://somewhere-else/loot".to_string())
        .build();

    let err = session
        .create_table(&ns(&["open"]), creation)
        .await
        .expect_err("must be confined to the warehouse");

    assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{err:?}");
}

/// A namespace's recorded owner cannot be supplied by the caller.
///
/// Ownership is what every later decision authorizes against, so a caller able
/// to set it could place a namespace in another tenant and then act on it.
#[tokio::test]
async fn a_caller_cannot_set_the_recorded_owner() {
    let (app, _admin, _analyst) = seeded().await;
    let session = app.as_principal(principal("admin", &["admin"]));

    let mut properties = HashMap::new();
    properties.insert(
        "rustberg.internal.tenant-id".to_string(),
        "somebody-else".to_string(),
    );

    let err = session
        .create_namespace(&ns(&["forged"]), properties)
        .await
        .expect_err("reserved properties must be refused");

    assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{err:?}");
}

/// A session reports the obligations policy attached, so a host can honour them.
///
/// In-process there is no credential to withhold, so the no-broad-credentials
/// invariant can
/// only be *reported* rather than enforced. A host reading table files directly
/// has to check this — and it can only do that if it is exposed.
#[tokio::test]
async fn obligations_are_reported_to_the_host() {
    let (admin_key, admin_secret) = key("admin", &["admin"]);
    // A row filter is an Iceberg predicate, so a Cedar annotation carries it as
    // JSON — with the quotes escaped, because a Cedar annotation is a string.
    const RESTRICTED: &str = r#"
@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
permit(
  principal in Rustberg::Group::"restricted",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
);
"#;
    let policies = format!("{POLICIES}{RESTRICTED}");

    let (app, _keys) = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id(TENANT)
        .with_policies(&policies)
        .with_api_keys(vec![admin_key])
        .build_with_api_keys()
        .await
        .expect("build app");

    let (status, body) = http(
        &app,
        Method::POST,
        "/v1/namespaces",
        &admin_secret,
        Some(json!({ "namespace": ["data"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let admin = app.as_principal(principal("admin", &["admin"]));
    admin
        .create_table(
            &ns(&["data"]),
            iceberg::TableCreation::builder()
                .name("people".to_string())
                .schema(
                    iceberg::spec::Schema::builder()
                        .with_schema_id(0)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .await
        .expect("create table");

    let ident = table(&["data"], "people");

    // An unrestricted grant carries nothing.
    assert!(
        admin.obligations_for(&ident).await.unwrap().is_empty(),
        "an admin's grant attaches no filter"
    );

    // A grant carrying `@row_filter` reports it, so the host can refuse to read.
    let restricted = app.as_principal(principal("restricted-user", &["restricted"]));
    let obligations = restricted
        .obligations_for(&ident)
        .await
        .expect("restricted principal may still read metadata");
    assert!(
        !obligations.is_empty(),
        "a @row_filter must be visible to an embedding host, or it cannot honour it"
    );
}

/// A session is never printed with the secrets its state carries.
#[tokio::test]
async fn debug_output_names_the_principal_and_nothing_else() {
    let (app, _admin, _analyst) = seeded().await;
    let session = app.as_principal(principal("analyst", &["analysts"]));

    let rendered = format!("{session:?}");
    assert!(rendered.contains("analyst"), "the principal is useful");
    assert!(
        !rendered.contains("authenticator") && !rendered.contains("credential"),
        "state internals must not be rendered: {rendered}"
    );
}

/// Every API `site/content/docs/library.md` shows still exists and still has that signature.
///
/// The project already validates its documented TOML against the config schema
/// and its documented policies against the Cedar schema, for the same reason: a
/// guide that no longer compiles is worse than no guide, because a reader trusts
/// it. This is that check for the library page, which is the one surface whose
/// whole value is that a host can copy it and have it work.
///
/// Outcomes are ignored deliberately — the assertion is that the calls type-check
/// and run, not that this fixture has the tables.
#[tokio::test]
async fn the_documented_library_api_still_compiles() {
    use rustberg::auth::RequestContext;
    use rustberg::catalog::session::page_after;

    let app = App::builder()
        .with_catalog_url("memory://")
        .with_warehouse_location("memory://wh")
        .with_default_tenant_id(TENANT)
        .build()
        .await
        .expect("build");

    let principal = Principal::embedded("svc-etl", TENANT)
        .with_role("writer")
        .build();

    let session = app.as_principal(principal.clone());
    let _forwarding_a_callers_address = app
        .as_principal(principal)
        .with_request_context(RequestContext::from_ip("10.0.0.1".parse().unwrap()));

    let namespace = ns(&["analytics", "web"]);
    let events = table(&["analytics", "web"], "events");

    let _ = session.load_table(&events).await;
    let _ = session.list_tables(&namespace, page(100)).await;
    let _ = session
        .list_tables(&namespace, page_after("tok", 100))
        .await;
    let _ = session.obligations_for(&events).await;
    let _ = session.list_namespaces(None, page(10)).await;
}

/// A session is safe to hold across tasks, which a host will do.
#[test]
fn a_session_is_send_and_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<rustberg::catalog::Session>();
}
