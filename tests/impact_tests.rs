//! The review's consequences: what a candidate policy set changes, for whom,
//! computed by the authorizers — the one in force and the one `PUT` would
//! install — never by a second reading of policy.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use serde_json::{Value, json};
use tower::ServiceExt;

const IN_FORCE: &str = r#"
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

// Marketing may list everything.
permit(principal in Rustberg::Group::"marketing",
       action == Rustberg::Action::"List",
       resource) when { resource.tenant == principal.tenant };

// Every rule, and no table.
permit(principal in Rustberg::Group::"reviewer",
       action == Rustberg::Action::"Read",
       resource is Rustberg::PolicySet) when { resource.tenant == principal.tenant };

// Tables only, and no rule.
permit(principal in Rustberg::Group::"loader",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
       resource is Rustberg::Table) when { resource.tenant == principal.tenant };
"#;

struct Fixture {
    app: App,
    admin: String,
    loader: String,
    reviewer: String,
}

fn key(name: &str, role: &str) -> (ApiKey, String) {
    let (key, secret) = ApiKeyBuilder::new(name, "acme").with_role(role).build();
    (key, secret.to_string())
}

async fn fixture() -> Fixture {
    let (admin_key, admin) = key("admin", "admin");
    let (loader_key, loader) = key("loader", "loader");
    let (reviewer_key, reviewer) = key("reviewer", "reviewer");
    let (app, _) = App::builder()
        .with_warehouse_location("memory://impact")
        .with_default_tenant_id("acme")
        .with_policies(IN_FORCE)
        .with_api_keys(vec![admin_key, loader_key, reviewer_key])
        .build_with_api_keys()
        .await
        .expect("build app");
    let f = Fixture {
        app,
        admin,
        loader,
        reviewer,
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
    for table in ["orders", "leads"] {
        let (status, body) = send(
            &f.app,
            Method::POST,
            "/v1/namespaces/sales/tables",
            &f.admin,
            Some(json!({
                "name": table,
                "schema": { "type": "struct", "fields": [
                    { "id": 1, "name": "id", "required": true, "type": "long" },
                    { "id": 2, "name": "email", "required": false, "type": "string" }
                ]}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    f
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    secret: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn impact(f: &Fixture, secret: &str, source: &str) -> (StatusCode, Value) {
    let (status, body) = send(
        &f.app,
        Method::POST,
        "/management/v1/policies/impact",
        secret,
        Some(json!({ "source": source })),
    )
    .await;
    (
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    )
}

/// The one-line widening the review exists for: `List` becomes `List, Read`
/// for a group, and every table that group can now read is listed — and
/// nothing else is.
#[tokio::test]
async fn widening_a_groups_actions_lists_what_it_gains() {
    let f = fixture().await;
    let candidate = IN_FORCE.replace(
        r#"action == Rustberg::Action::"List","#,
        r#"action in [Rustberg::Action::"List", Rustberg::Action::"Read"],"#,
    );

    let (status, answer) = impact(&f, &f.admin, &candidate).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let changes = answer["changes"].as_array().expect("changes");
    let gained: Vec<(&str, &str, &str)> = changes
        .iter()
        .map(|c| {
            (
                c["principal"]["roles"][0].as_str().unwrap_or(""),
                c["resource"].as_str().unwrap(),
                c["action"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(
        gained.contains(&("marketing", "sales.orders", "Read")),
        "{answer}"
    );
    assert!(
        gained.contains(&("marketing", "sales.leads", "Read")),
        "{answer}"
    );
    assert!(changes.iter().all(|c| c["change"] == "gains"), "{answer}");
    assert!(
        changes
            .iter()
            .all(|c| c["principal"]["roles"] == json!(["marketing"])),
        "nobody else changed: {answer}"
    );
    let orders = changes
        .iter()
        .find(|c| c["resource"] == "sales.orders")
        .unwrap();
    assert_eq!(orders["after"]["grade"], "none", "an unrestricted read");
}

/// Every row says what the what-if would answer under the candidate — they are
/// one function. Checked by installing the candidate and asking.
#[tokio::test]
async fn every_row_agrees_with_the_what_if() {
    let f = fixture().await;
    let candidate = IN_FORCE.replace(
        r#"// Marketing may list everything."#,
        "@column_mask(\"email\")\npermit(principal in Rustberg::Group::\"marketing\", action == Rustberg::Action::\"Read\", resource) when { resource.tenant == principal.tenant };",
    );
    let (status, answer) = impact(&f, &f.admin, &candidate).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let rows = answer["changes"].as_array().unwrap().clone();
    assert!(!rows.is_empty(), "{answer}");

    let (status, body) = send(
        &f.app,
        Method::PUT,
        "/management/v1/policies",
        &f.admin,
        Some(json!({ "source": candidate })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for row in rows
        .iter()
        .filter(|r| r["action"] == "Read" && r["resource"] != "policy set")
    {
        let (ns, table) = row["resource"].as_str().unwrap().split_once('.').unwrap();
        let roles = row["principal"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let (status, body) = send(
            &f.app,
            Method::GET,
            &format!(
                "/management/v1/namespaces/{ns}/tables/{table}/explain?principal=x&roles={roles}"
            ),
            &f.admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let explained: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(explained["decision"], "allow", "{row} vs {explained}");
        assert_eq!(
            explained["enforcement"]["grade"], row["after"]["grade"],
            "{row} vs {explained}"
        );
    }
}

/// A change to comments alone changes nobody's access.
#[tokio::test]
async fn a_comment_changes_nothing() {
    let f = fixture().await;
    let candidate = format!("// reviewed\n{IN_FORCE}");
    let (status, answer) = impact(&f, &f.admin, &candidate).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["changes"], json!([]), "{answer}");
}

/// The answer says what it enumerated: principals, tables, whether it was cut.
#[tokio::test]
async fn the_answer_says_what_it_checked() {
    let f = fixture().await;
    let (status, answer) = impact(&f, &f.admin, IN_FORCE).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let checked = &answer["checked"];
    assert_eq!(checked["tables"], 2);
    assert_eq!(checked["truncated"], false);
    let roles: Vec<&Value> = checked["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| &p["roles"])
        .collect();
    for group in ["admin", "marketing", "loader"] {
        assert!(
            roles.contains(&&json!([group])),
            "{group} is checked: {answer}"
        );
    }
    assert!(
        checked["principals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["kind"] == "anyone"),
        "a member of no group is checked: {answer}"
    );
    assert!(answer["note"].as_str().unwrap().contains("not a proof"));
    assert!(
        checked["principals"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["tenant"] == "acme"),
        "every subject is in the asker's tenant: {answer}"
    );
}

/// Reviewing needs the same permission as reading the policy set.
#[tokio::test]
async fn impact_needs_policy_read() {
    let f = fixture().await;
    let (status, _) = impact(&f, &f.loader, IN_FORCE).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A candidate that does not validate is refused as an install would refuse it.
#[tokio::test]
async fn an_invalid_candidate_is_refused_like_an_install() {
    let f = fixture().await;
    let (status, answer) = impact(&f, &f.admin, "permit(principal, action, resource").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
}

/// A reviewer who may read every rule but no table learns no table's name
/// from the review, whatever the candidate grants on it.
#[tokio::test]
async fn the_review_lists_only_tables_the_asker_may_read() {
    let f = fixture().await;
    let candidate = IN_FORCE.replace(
        r#"action == Rustberg::Action::"List","#,
        r#"action in [Rustberg::Action::"List", Rustberg::Action::"Read"],"#,
    );
    let (status, answer) = impact(&f, &f.reviewer, &candidate).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["checked"]["tables"], 0, "{answer}");
    let body = answer.to_string();
    assert!(
        !body.contains("orders") && !body.contains("leads"),
        "{body}"
    );
}
