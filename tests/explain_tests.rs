//! The administrator's what-if: what another principal would be granted on a
//! table, computed by the same authorizer and the same grade a real request
//! gets — and refused to anybody who could not already learn the answer.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use serde_json::{Value, json};
use tower::ServiceExt;

const POLICIES: &str = r#"
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
@column_mask("email")
permit(principal in Rustberg::Group::"eu",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
       resource) when { resource.tenant == principal.tenant };

// May read every rule, and no table.
permit(principal in Rustberg::Group::"auditor",
       action == Rustberg::Action::"Read",
       resource is Rustberg::PolicySet) when { resource.tenant == principal.tenant };

// May read tables, and no rule.
permit(principal in Rustberg::Group::"loader",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
       resource is Rustberg::Table) when { resource.tenant == principal.tenant };
permit(principal in Rustberg::Group::"loader",
       action == Rustberg::Action::"List",
       resource is Rustberg::Namespace) when { resource.tenant == principal.tenant };
"#;

struct Fixture {
    app: App,
    admin: String,
    analyst: String,
    auditor: String,
    loader: String,
}

fn key(name: &str, role: &str) -> (ApiKey, String) {
    let (key, secret) = ApiKeyBuilder::new(name, "acme").with_role(role).build();
    (key, secret.to_string())
}

async fn fixture() -> Fixture {
    let (admin_key, admin) = key("admin", "admin");
    let (analyst_key, analyst) = key("analyst", "eu");
    let (auditor_key, auditor) = key("auditor", "auditor");
    let (loader_key, loader) = key("loader", "loader");

    let (app, _) = App::builder()
        .with_warehouse_location("memory://explain")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![admin_key, analyst_key, auditor_key, loader_key])
        .build_with_api_keys()
        .await
        .expect("build app");

    let f = Fixture {
        app,
        admin,
        analyst,
        auditor,
        loader,
    };

    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces",
        &f.admin,
        Some(json!({ "namespace": ["sales"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &f.app,
        Method::POST,
        "/v1/namespaces/sales/tables",
        &f.admin,
        Some(json!({
            "name": "orders",
            "schema": { "type": "struct", "fields": [
                { "id": 1, "name": "id", "required": true, "type": "long" },
                { "id": 2, "name": "region", "required": false, "type": "string" },
                { "id": 3, "name": "email", "required": false, "type": "string" }
            ]}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    f
}

async fn send_full(
    app: &App,
    method: Method,
    uri: &str,
    secret: &str,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", secret);
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
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    secret: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let (status, _, body) = send_full(app, method, uri, secret, body).await;
    (status, body)
}

const EXPLAIN: &str = "/management/v1/namespaces/sales/tables/orders/explain";

/// The answer about a restricted principal is what that principal would get:
/// the same restrictions, and the same grade its own load carries.
#[tokio::test]
async fn explain_a_restricted_principal_agrees_with_its_own_load() {
    let f = fixture().await;

    let (status, body) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=analyst&kind=api_key&roles=eu"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["decision"], "allow");
    assert_eq!(
        answer["principal"]["tenant"], "acme",
        "always the asker's tenant"
    );
    assert!(
        answer["read-restrictions"]["required-row-filter"].is_object(),
        "{body}"
    );
    assert_eq!(answer["enforcement"]["grade"], "cooperative");
    assert_eq!(answer["enforcement"]["columns"], json!(["region"]));
    assert_eq!(answer["enforcement"]["masked"], true);
    let remedy = answer["enforcement"]["remedy"].as_str().unwrap();
    assert!(
        remedy.contains("ALTER TABLE sales.orders ADD PARTITION FIELD region"),
        "{remedy}"
    );

    // What the analyst itself is told.
    let (status, headers, load) = send_full(
        &f.app,
        Method::GET,
        "/v1/namespaces/sales/tables/orders",
        &f.analyst,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["rustberg-enforcement"].to_str().unwrap(),
        answer["enforcement"]["header"].as_str().unwrap(),
        "the what-if and the real request are one function"
    );
    let load: Value = serde_json::from_str(&load).unwrap();
    assert_eq!(load["read-restrictions"], answer["read-restrictions"]);
}

/// An unrestricted principal is told so, with no restrictions and grade `none`.
#[tokio::test]
async fn explain_an_unrestricted_principal() {
    let f = fixture().await;
    let (status, body) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=boss&roles=admin"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["decision"], "allow");
    assert!(answer.get("read-restrictions").is_none(), "{body}");
    assert_eq!(answer["enforcement"]["grade"], "none");
}

/// A principal nothing permits is denied, and an empty list of matched
/// policies says it failed closed rather than being forbidden.
#[tokio::test]
async fn explain_a_denied_principal() {
    let f = fixture().await;
    let (status, body) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=nobody"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["decision"], "deny");
    assert_eq!(answer["matched-policies"], json!([]));
    assert!(answer.get("enforcement").is_none());
}

/// Somebody who may not read the policy set learns nothing from the what-if.
#[tokio::test]
async fn explain_is_refused_without_policy_read() {
    let f = fixture().await;
    let (status, _) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=analyst&kind=api_key&roles=eu"),
        &f.loader,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Somebody who may read every rule but not the table is answered exactly as
/// loading the table would answer them — the what-if is no way to learn that a
/// table exists.
#[tokio::test]
async fn explain_does_not_reveal_an_unreadable_table() {
    let f = fixture().await;

    let (load_status, _) = send(
        &f.app,
        Method::GET,
        "/v1/namespaces/sales/tables/orders",
        &f.auditor,
        None,
    )
    .await;
    let (status, body) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=analyst&kind=api_key&roles=eu"),
        &f.auditor,
        None,
    )
    .await;
    assert_eq!(status, load_status, "{body}");
    assert!(!body.contains("region"), "no obligations leak: {body}");

    let (missing, _) = send(
        &f.app,
        Method::GET,
        "/management/v1/namespaces/sales/tables/nope/explain?principal=x",
        &f.auditor,
        None,
    )
    .await;
    assert_eq!(
        missing, status,
        "an existing and a missing table look the same"
    );
}

#[tokio::test]
async fn explain_refuses_an_unknown_kind() {
    let f = fixture().await;
    let (status, body) = send(
        &f.app,
        Method::GET,
        &format!("{EXPLAIN}?principal=x&kind=robot"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The same answer read by table: who of the principals the rules name may
/// read it, and in what form.
#[tokio::test]
async fn access_lists_who_sees_what() {
    let f = fixture().await;
    let (status, body) = send(
        &f.app,
        Method::GET,
        "/management/v1/namespaces/sales/tables/orders/access",
        &f.admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let answer: Value = serde_json::from_str(&body).unwrap();
    let of = |group: &str| {
        answer["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["principal"]["roles"] == json!([group]))
            .cloned()
            .unwrap_or_else(|| panic!("{group} listed: {body}"))
    };
    assert_eq!(of("admin")["access"], "everything");
    assert_eq!(of("eu")["access"], "filtered-and-masked");
    assert_eq!(of("eu")["grade"]["grade"], "cooperative");
    assert_eq!(of("auditor")["access"], "nothing");

    let (status, _) = send(
        &f.app,
        Method::GET,
        "/management/v1/namespaces/sales/tables/orders/access",
        &f.loader,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "needs policy Read");
}
