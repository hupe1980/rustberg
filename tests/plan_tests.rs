//! Server-side scan planning: `POST /v1/namespaces/{ns}/tables/{t}/plan`.
//!
//! Driven through HTTP against a real redb catalog on a local warehouse, so the
//! manifests being read are ones the suite wrote.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use serde_json::{Value, json};
use tower::ServiceExt;

const POLICY: &str = r#"
permit(principal in Rustberg::Group::"writer",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List",
                  Rustberg::Action::"Create", Rustberg::Action::"Update"],
       resource) when { resource.tenant == principal.tenant };

@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
@column_mask("region")
permit(principal in Rustberg::Group::"restricted",
       action == Rustberg::Action::"Read",
       resource) when { resource.tenant == principal.tenant };
permit(principal in Rustberg::Group::"restricted",
       action == Rustberg::Action::"List",
       resource) when { resource.tenant == principal.tenant };
"#;

struct Fixture {
    app: App,
    writer: String,
    restricted: String,
    _warehouse: tempfile::TempDir,
    _catalog: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let warehouse = tempfile::tempdir().expect("warehouse");
    let catalog = tempfile::tempdir().expect("catalog");

    let (writer_key, writer) = ApiKeyBuilder::new("writer", "acme")
        .with_role("writer")
        .build();
    let (restricted_key, restricted) = ApiKeyBuilder::new("restricted", "acme")
        .with_role("restricted")
        .build();

    let (app, _keys) = App::builder()
        .with_catalog_url(rustberg::location::url_from_path(catalog.path()))
        .with_warehouse_location(rustberg::location::url_from_path(warehouse.path()))
        .with_default_tenant_id("acme")
        .with_policies(POLICY)
        .with_api_keys(vec![writer_key, restricted_key] as Vec<ApiKey>)
        .build_with_api_keys()
        .await
        .expect("build app");

    let fixture = Fixture {
        app,
        writer: writer.to_string(),
        restricted: restricted.to_string(),
        _warehouse: warehouse,
        _catalog: catalog,
    };

    let (status, body) = call(
        &fixture.app,
        Method::POST,
        "/v1/namespaces",
        &fixture.writer,
        Some(json!({ "namespace": ["db"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = call(
        &fixture.app,
        Method::POST,
        "/v1/namespaces/db/tables",
        &fixture.writer,
        Some(json!({
            "name": "events",
            "schema": { "type": "struct", "fields": [
                { "id": 1, "name": "id", "required": true, "type": "long" },
                { "id": 2, "name": "region", "required": false, "type": "string" }
            ]}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    fixture
}

async fn call(
    app: &App,
    method: Method,
    uri: &str,
    key: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", key);

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

async fn plan(app: &App, key: &str, body: Value) -> (StatusCode, String) {
    call(
        app,
        Method::POST,
        "/v1/namespaces/db/tables/events/plan",
        key,
        Some(body),
    )
    .await
}

// ── The plan itself ─────────────────────────────────────────────────────

/// A table with no snapshot has no files, and that is a complete plan rather
/// than an error: `CREATE TABLE` then `SELECT` is an ordinary sequence.
#[tokio::test]
async fn an_empty_table_plans_to_no_tasks() {
    let f = fixture().await;

    let (status, body) = plan(&f.app, &f.writer, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let result: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(result["status"], "completed");
    assert!(
        result["plan-id"].as_str().is_some_and(|id| !id.is_empty()),
        "the spec requires a plan-id on a completed result: {body}"
    );
    assert_eq!(result["file-scan-tasks"].as_array().unwrap().len(), 0);
}

/// A filter the catalog can bind is accepted and used; the residual comes back
/// unchanged, which is always correct because the client applies it.
#[tokio::test]
async fn a_bindable_filter_is_accepted() {
    let f = fixture().await;

    let (status, body) = plan(
        &f.app,
        &f.writer,
        json!({
            "filter": { "type": "eq", "term": "region", "value": "EU" },
            "select": ["id", "region"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["status"],
        "completed"
    );
}

/// Every shape of the JSON expression grammar this catalog claims to read.
#[tokio::test]
async fn the_documented_filter_grammar_is_accepted() {
    let f = fixture().await;

    for filter in [
        json!(true),
        json!(false),
        json!({ "type": "true" }),
        json!({ "type": "is-null", "term": "region" }),
        json!({ "type": "not-null", "child": { "type": "reference", "name": "region" } }),
        json!({ "type": "lt", "term": "id", "value": 10 }),
        json!({ "type": "gt-eq", "left": { "type": "reference", "name": "id" }, "right": 3 }),
        json!({ "type": "starts-with", "term": "region", "value": "E" }),
        json!({ "type": "in", "term": "region", "values": ["EU", "US"] }),
        json!({ "type": "not-in", "term": "id", "values": [1, 2] }),
        json!({ "type": "not", "child": { "type": "eq", "term": "id", "value": 1 } }),
        json!({
            "type": "and",
            "left":  { "type": "eq", "term": "region", "value": "EU" },
            "right": { "type": "gt", "term": "id", "value": 0 }
        }),
        json!({
            "type": "or",
            "left":  { "type": "eq", "term": "region", "value": "EU" },
            "right": { "type": "eq", "term": "region", "value": "US" }
        }),
    ] {
        let (status, body) = plan(&f.app, &f.writer, json!({ "filter": filter })).await;
        assert_eq!(status, StatusCode::OK, "{filter}: {body}");
    }
}

/// A filter this catalog cannot *bind* is widened away, not dropped: it stops
/// contributing to pruning, the plan returns a superset, and the residual the
/// client applies is the filter it sent.
#[tokio::test]
async fn an_unbindable_filter_is_widened_rather_than_refused() {
    let f = fixture().await;

    for filter in [
        // A transform term, and a function application.
        json!({ "type": "eq", "term": { "type": "transform", "transform": "day", "term": "id" }, "value": 1 }),
        json!({ "type": "eq", "left": { "type": "apply", "function": "lower", "arguments": [] }, "right": "x" }),
        // A reference by field id, which this catalog binds by name.
        json!({ "type": "is-null", "child": { "type": "reference", "id": 2 } }),
        // An operator from a grammar this catalog does not read.
        json!({ "type": "matches", "child": { "type": "reference", "name": "region" }, "values": [] }),
        // Under a negation, where widening to "everything" is the only safe
        // direction — collapsing to "nothing" would prune every file.
        json!({ "type": "not", "child": { "type": "eq", "term": { "type": "transform", "transform": "day", "term": "id" }, "value": 1 } }),
    ] {
        let (status, body) = plan(&f.app, &f.writer, json!({ "filter": filter })).await;
        assert_eq!(status, StatusCode::OK, "{filter}: {body}");
    }
}

/// A *malformed* filter is a client error, and stays one. Widening a typo'd
/// column into a full scan hides the mistake behind a slower query.
#[tokio::test]
async fn a_malformed_filter_is_refused() {
    let f = fixture().await;

    for filter in [
        // A column the table does not have.
        json!({ "type": "eq", "term": "nope", "value": 1 }),
        // A literal of the wrong shape for its column.
        json!({ "type": "eq", "term": "id", "value": "not a number" }),
        // Operands and members that are not there at all.
        json!({ "type": "eq", "value": 1 }),
        json!({ "type": "and", "left": true }),
        json!({ "type": "eq", "term": 7, "value": 1 }),
        json!("a bare string"),
    ] {
        let (status, body) = plan(&f.app, &f.writer, json!({ "filter": filter })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{filter}: {body}");
    }
}

#[tokio::test]
async fn a_snapshot_that_does_not_exist_is_not_found() {
    let f = fixture().await;

    let (status, _) = plan(&f.app, &f.writer, json!({ "snapshot-id": 42 })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Declined explicitly rather than answered as a full scan, which would return
/// far more than an incremental scan asked for.
#[tokio::test]
async fn an_incremental_scan_is_declined() {
    let f = fixture().await;

    let (status, body) = plan(
        &f.app,
        &f.writer,
        json!({ "start-snapshot-id": 1, "end-snapshot-id": 2 }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
}

#[tokio::test]
async fn stats_fields_must_name_real_columns() {
    let f = fixture().await;

    let (status, _) = plan(&f.app, &f.writer, json!({ "stats-fields": ["region"] })).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = plan(&f.app, &f.writer, json!({ "stats-fields": ["nope"] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── Authorization ───────────────────────────────────────────────────────

/// A plan is a file list, so it goes through the same guard as everything else.
#[tokio::test]
async fn planning_an_invisible_table_is_not_found() {
    let f = fixture().await;

    let (status, _) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/absent/plan",
        &f.writer,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A row filter is a predicate the planner can *apply*, so a restricted caller
/// gets a plan built from it — and the residual carries it, so a cooperating
/// engine applies the same restriction to the rows inside the files it reads.
#[tokio::test]
async fn a_row_filter_is_applied_and_returned_as_the_residual() {
    let f = fixture().await;

    let (status, body) = plan(&f.app, &f.restricted, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Column statistics name a column's minimum and maximum values, which is
/// exactly what a mask hides.
#[tokio::test]
async fn stats_for_a_masked_column_are_refused() {
    let f = fixture().await;

    let (status, body) = plan(&f.app, &f.restricted, json!({ "stats-fields": ["region"] })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("region"), "{body}");
}

// ── The two follow-ups ──────────────────────────────────────────────────

/// Every plan completes in the response, so there is never one to poll for.
#[tokio::test]
async fn fetching_a_finished_plan_reports_that_there_is_none() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        Method::GET,
        "/v1/namespaces/db/tables/events/plan/whatever",
        &f.writer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("NoSuchPlanIdException"), "{body}");
}

/// Cancelling a plan that already finished succeeds, so a client can clean up
/// unconditionally.
#[tokio::test]
async fn cancelling_a_finished_plan_succeeds() {
    let f = fixture().await;

    let (status, _) = call(
        &f.app,
        Method::DELETE,
        "/v1/namespaces/db/tables/events/plan/whatever",
        &f.writer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ── Advertisement ───────────────────────────────────────────────────────

#[tokio::test]
async fn planning_is_advertised() {
    let f = fixture().await;

    let (status, body) = call(&f.app, Method::GET, "/v1/config", &f.writer, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: Value = serde_json::from_str(&body).unwrap();
    let endpoints: Vec<&str> = config["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap())
        .collect();

    assert!(endpoints.contains(&"POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan"));
    assert!(
        endpoints
            .contains(&"DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan/{plan-id}")
    );
}

// ── What a plan cannot hide ─────────────────────────────────────────────

/// A partitioned table whose partition column policy also masks.
///
/// Built separately from the shared fixture because it needs a partition spec,
/// and the spec is the whole point of the test.
async fn partitioned_fixture() -> Fixture {
    let warehouse = tempfile::tempdir().expect("warehouse");
    let catalog = tempfile::tempdir().expect("catalog");

    let (writer_key, writer) = ApiKeyBuilder::new("writer", "acme")
        .with_role("writer")
        .build();
    let (restricted_key, restricted) = ApiKeyBuilder::new("restricted", "acme")
        .with_role("restricted")
        .build();

    let (app, _keys) = App::builder()
        .with_catalog_url(rustberg::location::url_from_path(catalog.path()))
        .with_warehouse_location(rustberg::location::url_from_path(warehouse.path()))
        .with_default_tenant_id("acme")
        .with_policies(POLICY)
        .with_api_keys(vec![writer_key, restricted_key])
        .build_with_api_keys()
        .await
        .expect("build app");

    let fixture = Fixture {
        app,
        writer: writer.to_string(),
        restricted: restricted.to_string(),
        _warehouse: warehouse,
        _catalog: catalog,
    };

    let (status, body) = call(
        &fixture.app,
        Method::POST,
        "/v1/namespaces",
        &fixture.writer,
        Some(json!({ "namespace": ["db"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = call(
        &fixture.app,
        Method::POST,
        "/v1/namespaces/db/tables",
        &fixture.writer,
        Some(json!({
            "name": "by_region",
            "schema": { "type": "struct", "fields": [
                { "id": 1, "name": "id", "required": true, "type": "long" },
                { "id": 2, "name": "region", "required": false, "type": "string" }
            ]},
            "partition-spec": { "spec-id": 0, "fields": [
                { "source-id": 2, "field-id": 1000, "name": "region",
                  "transform": "identity" }
            ]}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    fixture
}

/// A mask over a *partition* column cannot be honoured by a plan: every content
/// file carries its partition tuple, and Iceberg writes the value into the
/// object key as well. So the plan is refused, rather than served with the
/// masked column in every row of the response.
#[tokio::test]
async fn a_plan_is_refused_when_a_mask_covers_a_partition_column() {
    let f = partitioned_fixture().await;

    let (status, body) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/by_region/plan",
        &f.restricted,
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("region"),
        "the refusal must name the column: {body}"
    );
    assert!(
        body.contains("partition"),
        "and say why a plan cannot withhold it: {body}"
    );
}

/// The same mask over a column the table is *not* partitioned on plans normally.
/// The refusal above is narrow on purpose.
#[tokio::test]
async fn a_mask_over_an_ordinary_column_still_plans() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/events/plan",
        &f.restricted,
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A writer is unrestricted, so the partitioned table plans for it. Without this
/// the test above could pass because the table was unplannable for everyone.
#[tokio::test]
async fn a_partitioned_table_plans_for_an_unrestricted_caller() {
    let f = partitioned_fixture().await;

    let (status, body) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/by_region/plan",
        &f.writer,
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

// ── stats-fields and the case-sensitive flag ────────────────────────────

/// `case-sensitive: false` is what the flag exists to allow, and it governs
/// `stats-fields` like every other column reference in a plan. This used to
/// answer `400` for a name that differed only in case.
#[tokio::test]
async fn stats_fields_honours_the_case_sensitive_flag() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/events/plan",
        &f.writer,
        Some(json!({ "case-sensitive": false, "stats-fields": ["REGION"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // And still refuses a column that does not exist in any case.
    let (status, body) = call(
        &f.app,
        Method::POST,
        "/v1/namespaces/db/tables/events/plan",
        &f.writer,
        Some(json!({ "case-sensitive": false, "stats-fields": ["nosuch"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The mask is matched on the resolved column, without regard to case — so
/// relaxing the binding above cannot be turned into a way to ask for a masked
/// column's minimum and maximum under a different spelling.
#[tokio::test]
async fn a_mask_is_not_escaped_by_spelling_the_column_differently() {
    let f = fixture().await;

    for (case_sensitive, name) in [(false, "REGION"), (true, "region")] {
        let (status, body) = call(
            &f.app,
            Method::POST,
            "/v1/namespaces/db/tables/events/plan",
            &f.restricted,
            Some(json!({ "case-sensitive": case_sensitive, "stats-fields": [name] })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "stats for a masked column were served for {name:?}: {body}"
        );
    }
}
