//! Authorization behaviour at the HTTP boundary.
//!
//! The Cedar unit tests in `src/auth/cedar.rs` prove that policies *evaluate*
//! correctly. These prove that the server *acts* on the result: that a listing
//! shows only what a caller may see, that a denial does not reveal whether a
//! resource exists, and that a table under row or column policy is not handed a
//! storage credential.
//!
//! Each test names the failure it prevents.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder, InMemoryApiKeyStore};
use tower::ServiceExt;

/// Builds an app with the given Cedar policies and API keys.
async fn app_with(policies: &str, keys: Vec<ApiKey>) -> (App, Arc<InMemoryApiKeyStore>) {
    App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(policies)
        .with_api_keys(keys)
        .build_with_api_keys()
        .await
        .expect("build app")
}

/// Creates a key with the given roles, returning it and its plaintext secret.
fn key(name: &str, tenant: &str, roles: &[&str]) -> (ApiKey, String) {
    // The secret is zeroizing; tests keep a plain copy for the request header.
    let mut builder = ApiKeyBuilder::new(name, tenant);
    for role in roles {
        builder = builder.with_role(*role);
    }
    let (api_key, secret) = builder.build();
    (api_key, secret.to_string())
}

async fn request(
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
            builder
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap()
        }
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Creates a namespace and a table in it, as an admin.
async fn seed(app: &App, admin: &str, namespace: &str, tables: &[&str]) {
    let (status, body) = request(
        app,
        Method::POST,
        "/v1/namespaces",
        admin,
        Some(serde_json::json!({ "namespace": [namespace] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed namespace failed: {body}");

    for table in tables {
        let (status, body) = request(
            app,
            Method::POST,
            &format!("/v1/namespaces/{namespace}/tables"),
            admin,
            Some(serde_json::json!({
                "name": table,
                "schema": { "type": "struct", "fields": [] }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seed table failed: {body}");
    }
}

// ============================================================================
// Existence must not leak through the status code
// ============================================================================

/// Resolving which tenant owns a namespace necessarily happens before the policy
/// decision, so a naive implementation answers `404` for a namespace that does
/// not exist and `403` for one that exists but belongs to someone else. That
/// difference lets any authenticated caller enumerate every other tenant's
/// namespaces by reading status codes.
#[tokio::test]
async fn a_forbidden_namespace_is_indistinguishable_from_a_missing_one() {
    // `acme` may do anything in its own tenant; `other` has a grant only in its.
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (outsider_key, outsider_secret) = key("outsider", "other", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key, outsider_key]).await;

    seed(&app, &admin_secret, "secret_ns", &["secret_table"]).await;

    // Exists, owned by `acme`, and `other` has no grant on it.
    let (existing, _) = request(
        &app,
        Method::GET,
        "/v1/namespaces/secret_ns",
        &outsider_secret,
        None,
    )
    .await;

    // Does not exist at all.
    let (missing, _) = request(
        &app,
        Method::GET,
        "/v1/namespaces/no_such_ns",
        &outsider_secret,
        None,
    )
    .await;

    assert_eq!(
        existing,
        StatusCode::NOT_FOUND,
        "a namespace the caller cannot see must be reported as missing"
    );
    assert_eq!(missing, StatusCode::NOT_FOUND);
    assert_eq!(
        existing, missing,
        "the status code is an oracle for enumerating other tenants' namespaces"
    );
}

/// The same guarantee for a table, which is where an attacker would actually look:
/// namespace names are often guessable, table names less so.
#[tokio::test]
async fn a_forbidden_table_is_indistinguishable_from_a_missing_one() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (outsider_key, outsider_secret) = key("outsider", "other", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key, outsider_key]).await;

    seed(&app, &admin_secret, "shared_ns", &["real_table"]).await;

    let (real, real_body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/shared_ns/tables/real_table",
        &outsider_secret,
        None,
    )
    .await;
    let (fake, _) = request(
        &app,
        Method::GET,
        "/v1/namespaces/shared_ns/tables/imaginary_table",
        &outsider_secret,
        None,
    )
    .await;

    assert_eq!(real, StatusCode::NOT_FOUND, "body: {real_body}");
    assert_eq!(fake, StatusCode::NOT_FOUND);

    // The error type must match too — a client branches on it, and a differing
    // type reopens the oracle one level down.
    assert!(
        real_body.contains("NoSuchTableException"),
        "body: {real_body}"
    );
}

/// A caller that *can* see a resource but lacks the specific action still gets
/// `403`, because that reveals only what it already knew. Collapsing everything
/// to `404` would make legitimate permission errors undiagnosable.
#[tokio::test]
async fn a_visible_resource_with_a_missing_grant_is_forbidden_not_missing() {
    // The reader may read, and nothing else.
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"reader",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (reader_key, reader_secret) = key("reader", "acme", &["reader"]);
    let (app, _store) = app_with(policies, vec![admin_key, reader_key]).await;

    seed(&app, &admin_secret, "ns", &["t"]).await;

    // Readable.
    let (status, _) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables/t",
        &reader_secret,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Not droppable — and the caller can see it, so say so plainly.
    let (status, body) = request(
        &app,
        Method::DELETE,
        "/v1/namespaces/ns/tables/t",
        &reader_secret,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a visible resource must give a diagnosable error: {body}"
    );
}

// ============================================================================
// Listings filter
// ============================================================================

/// `List` on a namespace permits *asking*; each table is then checked on its own.
/// This previously returned every table in the namespace to anyone holding `List`,
/// so a table-scoped `forbid` was enforced on load and invisible in the listing.
#[tokio::test]
async fn listing_tables_omits_those_the_caller_cannot_read() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"analyst",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
        forbid(
          principal in Rustberg::Group::"analyst",
          action,
          resource == Rustberg::Table::"acme\u{1F}ns\u{1F}restricted"
        );
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (analyst_key, analyst_secret) = key("analyst", "acme", &["analyst"]);
    let (app, _store) = app_with(policies, vec![admin_key, analyst_key]).await;

    seed(&app, &admin_secret, "ns", &["public", "restricted"]).await;

    // The admin sees both.
    let (status, body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables",
        &admin_secret,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("public"), "body: {body}");
    assert!(body.contains("restricted"), "admin body: {body}");

    // The analyst sees only what it may read.
    let (status, body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables",
        &analyst_secret,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("public"), "body: {body}");
    assert!(
        !body.contains("restricted"),
        "a forbidden table must not appear in the listing: {body}"
    );
}

/// Namespace listing filters through policy, not through a tenant-string
/// comparison. The comparison was hardcoded, so a principal whose grant covered
/// one namespace was shown every namespace in its tenant.
#[tokio::test]
async fn listing_namespaces_honours_a_narrower_grant() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        // The analyst may enumerate the catalog, but may only read one namespace.
        permit(
          principal in Rustberg::Group::"analyst",
          action == Rustberg::Action::"List",
          resource == Rustberg::Tenant::"acme"
        );
        permit(
          principal in Rustberg::Group::"analyst",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource in Rustberg::Namespace::"acme\u{1F}visible"
        );
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (analyst_key, analyst_secret) = key("analyst", "acme", &["analyst"]);
    let (app, _store) = app_with(policies, vec![admin_key, analyst_key]).await;

    seed(&app, &admin_secret, "visible", &[]).await;
    seed(&app, &admin_secret, "hidden", &[]).await;

    let (status, body) = request(&app, Method::GET, "/v1/namespaces", &analyst_secret, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("visible"), "body: {body}");
    assert!(
        !body.contains("hidden"),
        "a namespace outside the grant must not be listed: {body}"
    );

    // The admin, whose grant is tenant-wide, still sees both.
    let (_, body) = request(&app, Method::GET, "/v1/namespaces", &admin_secret, None).await;
    assert!(
        body.contains("visible") && body.contains("hidden"),
        "{body}"
    );
}

// ============================================================================
// Obligations withhold credentials
// ============================================================================

/// A credential is prefix-shaped and cannot express a row filter, so the only
/// honest response is to withhold it — computing the filter and then vending
/// anyway serves the table in full while the operator believes rows are
/// filtered. Asserted through the dedicated credentials
/// endpoint, where withholding is visible as a status rather than an absent field.
#[tokio::test]
async fn a_row_filtered_table_is_refused_credentials() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
        permit(
          principal in Rustberg::Group::"eu-analyst",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (analyst_key, analyst_secret) = key("analyst", "acme", &["eu-analyst"]);
    let (app, _store) = app_with(policies, vec![admin_key, analyst_key]).await;

    seed(&app, &admin_secret, "ns", &["events"]).await;

    // Reading the metadata is permitted — the filter restricts data, not metadata.
    let (status, _) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables/events",
        &analyst_secret,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables/events/credentials",
        &analyst_secret,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a row-filtered table must not be handed a credential: {body}"
    );
    assert!(
        body.contains("row filter"),
        "the refusal must say why: {body}"
    );
    // The filter expression itself must not come back: it embeds the values it
    // compares against.
    assert!(!body.contains("region"), "filter expression leaked: {body}");
    assert!(!body.contains("'EU'"), "filter value leaked: {body}");
}

/// A column mask is equally unenforceable by a credential: the masked bytes are in
/// the Parquet the engine would download.
#[tokio::test]
async fn a_column_masked_table_is_refused_credentials() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        @column_mask("ssn")
        permit(
          principal in Rustberg::Group::"limited",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (limited_key, limited_secret) = key("limited", "acme", &["limited"]);
    let (app, _store) = app_with(policies, vec![admin_key, limited_key]).await;

    seed(&app, &admin_secret, "ns", &["people"]).await;

    let (status, body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables/people/credentials",
        &limited_secret,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    // Column *names* are safe to report, and are what an operator needs to see.
    assert!(body.contains("ssn"), "body: {body}");
}

/// An unrestricted grant is unaffected: the common path must not regress into
/// refusing credentials for every table.
#[tokio::test]
async fn an_unrestricted_grant_is_not_refused_credentials() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    seed(&app, &admin_secret, "ns", &["events"]).await;

    let (status, body) = request(
        &app,
        Method::GET,
        "/v1/namespaces/ns/tables/events/credentials",
        &admin_secret,
        None,
    )
    .await;

    // No credential provider is configured in this test, so vending is
    // unavailable — but it must fail as "not supported", never as a policy
    // refusal. Confusing the two sends an operator hunting the wrong problem.
    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "an unrestricted grant must not be refused on policy grounds: {body}"
    );
    assert!(!body.contains("row filter"), "body: {body}");
}

// ============================================================================
// What authentication covers
// ============================================================================

/// Health and readiness must answer without a credential.
///
/// Authentication is on by default, and the Helm chart probes `/health` and
/// `/ready` with no credentials — so layering auth onto the whole router makes
/// every pod fail its liveness probe and restart-loop.
#[tokio::test]
async fn probes_and_metrics_do_not_require_a_credential() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, _secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    for path in ["/health", "/ready", "/metrics"] {
        let router = app.clone().into_router();
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must not require authentication: a probe cannot hold a credential"
        );
    }
}

/// The corollary: removing auth from the probes must not have removed it from the
/// catalog. Asserted for one endpoint per protected group.
#[tokio::test]
async fn catalog_endpoints_still_require_a_credential() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, _secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    for path in ["/v1/config", "/v1/namespaces", "/auth/context"] {
        let router = app.clone().into_router();
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must require authentication"
        );
    }
}

/// `loadTable` must not carry credentials for a restricted table either — the
/// refusal cannot be limited to the endpoint that exists to hand them out.
#[tokio::test]
async fn load_table_omits_credentials_for_a_restricted_table() {
    let policies = r#"
        @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin_secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    seed(&app, &admin_secret, "ns", &["events"]).await;

    let router = app.clone().into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/namespaces/ns/tables/events")
                .header("X-API-Key", &admin_secret)
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
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(
        body.get("storage-credentials").is_none(),
        "a restricted table must not carry credentials: {body}"
    );
}

// ============================================================================
// Paging
// ============================================================================

/// Paging must walk the whole listing exactly once: every table seen, none seen
/// twice, and the walk must terminate.
///
/// This is the property the previous implementation could not offer. It
/// materialised every row on every request and sliced, so the page token was a
/// position in a filtered view rather than a backend cursor — and filtering after
/// slicing could return an empty page while matches remained further on.
#[tokio::test]
async fn paging_visits_every_table_exactly_once() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, admin) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    let names: Vec<String> = (0..25).map(|i| format!("t{i:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    seed(&app, &admin, "ns", &refs).await;

    let mut seen: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    let mut requests = 0;

    loop {
        requests += 1;
        assert!(requests < 50, "paging failed to terminate");

        let uri = match &token {
            Some(t) => format!("/v1/namespaces/ns/tables?pageSize=4&pageToken={t}"),
            None => "/v1/namespaces/ns/tables?pageSize=4".to_string(),
        };
        let (status, body) = request(&app, Method::GET, &uri, &admin, None).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let page: Vec<String> = json["identifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap().to_string())
            .collect();

        assert!(
            page.len() <= 4,
            "page exceeded the requested size: {page:?}"
        );
        seen.extend(page);

        match json["next-page-token"].as_str() {
            Some(t) => token = Some(t.to_string()),
            None => break,
        }
    }

    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();

    assert_eq!(
        seen.len(),
        unique.len(),
        "a table was returned twice: {seen:?}"
    );
    assert_eq!(unique, names, "paging did not cover the listing exactly");
    assert!(
        requests > 1,
        "the test must actually exercise more than one page"
    );
}

/// Paging and filtering together: the caller may read only some tables, and must
/// still receive all of those and none of the others, across page boundaries.
///
/// The dangerous case is a backend page whose rows are *entirely* hidden. Slicing
/// first and filtering after would return an empty page, which clients treat as
/// the end of the list — silently truncating the result. Here the hidden tables
/// form one contiguous run of 20, far wider than the 2-row page size, so at least
/// one page must be filled entirely from beyond the run.
#[tokio::test]
async fn paging_across_hidden_tables_loses_nothing() {
    let all: Vec<String> = (0..24).map(|i| format!("t{i:02}")).collect();
    let visible = |name: &str| name[1..].parse::<usize>().unwrap() < 4;

    let mut policy = String::from(
        r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"partial",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#,
    );
    // Cedar cannot express "names beginning with t0", so each hidden table is
    // forbidden by name. Explicit, and exactly what a real deployment would write.
    for name in all.iter().filter(|n| !visible(n)) {
        policy.push_str(&format!(
            "forbid(principal in Rustberg::Group::\"partial\", action, \
             resource == Rustberg::Table::\"acme\\u{{1F}}ns\\u{{1F}}{name}\");\n"
        ));
    }

    let (admin_key, admin) = key("admin", "acme", &["admin"]);
    let (partial_key, partial) = key("partial", "acme", &["partial"]);
    let (app, _store) = app_with(&policy, vec![admin_key, partial_key]).await;

    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    seed(&app, &admin, "ns", &refs).await;

    let mut seen: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    let mut requests = 0;

    loop {
        requests += 1;
        assert!(requests < 60, "paging failed to terminate");

        let uri = match &token {
            Some(t) => format!("/v1/namespaces/ns/tables?pageSize=2&pageToken={t}"),
            None => "/v1/namespaces/ns/tables?pageSize=2".to_string(),
        };
        let (status, body) = request(&app, Method::GET, &uri, &partial, None).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        for id in json["identifiers"].as_array().unwrap() {
            seen.push(id["name"].as_str().unwrap().to_string());
        }

        match json["next-page-token"].as_str() {
            Some(t) => token = Some(t.to_string()),
            None => break,
        }
    }

    let expected: Vec<String> = all.iter().filter(|n| visible(n)).cloned().collect();

    seen.sort();
    assert_eq!(
        seen, expected,
        "filtering across page boundaries lost or leaked rows"
    );
}

// ============================================================================
// Idempotency
// ============================================================================

/// An `Idempotency-Key` is chosen by the client, so two principals routinely pick
/// the same value. A cache entry must belong to one principal.
///
/// Keying only on method and path — as this once did — made the header a
/// cross-tenant read primitive: send another tenant's key to the same path and
/// receive their cached response, which for `createTable` carries the full table
/// metadata.
#[tokio::test]
async fn an_idempotency_key_is_scoped_to_one_principal() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    let (a_key, alice) = key("alice", "acme", &["admin"]);
    let (b_key, bob) = key("bob", "other", &["admin"]);
    let (app, _store) = app_with(policies, vec![a_key, b_key]).await;

    let shared_key = "01895c3e-8844-7fff-a5cb-7a583a3e51fe";

    // Alice creates a namespace using the shared idempotency key.
    let router = app.clone().into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/namespaces")
                .header("X-API-Key", &alice)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", shared_key)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "namespace": ["alice_private"],
                        "properties": {"secret": "alice-only"}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Bob sends the *same* key to the same path. He must not receive Alice's
    // response — he must get his own operation carried out.
    let router = app.clone().into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/namespaces")
                .header("X-API-Key", &bob)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", shared_key)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "namespace": ["bob_own"] })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();

    assert!(
        !body.contains("alice_private") && !body.contains("alice-only"),
        "Bob received Alice's cached response: {body}"
    );
    assert!(
        body.contains("bob_own"),
        "Bob's own request was not carried out: {body}"
    );
}

/// A replay must be authorized like any other request. A cache hit answers
/// without touching the catalog, so a lookup ahead of the policy check serves a
/// request that was never authorized — and keeps serving it after a grant is
/// revoked.
#[tokio::test]
async fn an_idempotent_replay_is_still_authorized() {
    // The writer may create; the reader may not.
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"reader",
          action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let (admin_key, admin) = key("admin", "acme", &["admin"]);
    let (reader_key, reader) = key("reader", "acme", &["reader"]);
    let (app, _store) = app_with(policies, vec![admin_key, reader_key]).await;

    seed(&app, &admin, "ns", &[]).await;

    let idem = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let create = || {
        serde_json::json!({
            "name": "t",
            "schema": { "type": "struct", "fields": [] }
        })
    };

    // The admin creates a table with an idempotency key.
    let router = app.clone().into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/namespaces/ns/tables")
                .header("X-API-Key", &admin)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", idem)
                .body(Body::from(serde_json::to_vec(&create()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The reader replays it. Even with the very same key, this must be refused —
    // the reader has no Create grant.
    let router = app.clone().into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/namespaces/ns/tables")
                .header("X-API-Key", &reader)
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", idem)
                .body(Body::from(serde_json::to_vec(&create()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "an unauthorized replay was served from cache"
    );
}

/// The same principal replaying its own key gets the same answer — the point of
/// the header. Asserted so the fixes above cannot be "achieved" by disabling
/// idempotency altogether.
#[tokio::test]
async fn a_replay_by_the_same_principal_is_idempotent() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, admin) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;
    seed(&app, &admin, "ns", &[]).await;

    let idem = "11111111-2222-3333-4444-555555555555";
    let send = |app: App, secret: String| async move {
        let router = app.into_router();
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/namespaces/ns/tables")
                    .header("X-API-Key", secret)
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", idem)
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "name": "once",
                            "schema": { "type": "struct", "fields": [] }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    };

    let (first_status, _) = send(app.clone(), admin.clone()).await;
    assert_eq!(first_status, StatusCode::OK);

    // Without idempotency this second create would be a 409.
    let (second_status, second_body) = send(app.clone(), admin.clone()).await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "the replay was not served idempotently: {second_body}"
    );

    // And the table exists exactly once.
    let (_, body) = request(&app, Method::GET, "/v1/namespaces/ns/tables", &admin, None).await;
    assert_eq!(body.matches("\"once\"").count(), 1, "body: {body}");
}

// ============================================================================
// Advertised capabilities
// ============================================================================

/// Every endpoint `/v1/config` advertises must actually be routed.
///
/// Clients feature-detect from that list, so an entry the server does not serve
/// is a lie that surfaces as a mid-operation failure rather than a clean
/// "unsupported". This walks the advertised list and checks each path reaches a
/// handler.
///
/// A routed path answers with Rustberg's error envelope (`{"error": …}`) even
/// when the resource is absent; an unrouted one gets axum's bare 404 with no
/// body, and a wrong method gets 405. Both are failures here.
#[tokio::test]
async fn every_advertised_endpoint_is_actually_routed() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, admin) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    // Read the advertised list from the running server rather than a copy.
    let (status, body) = request(&app, Method::GET, "/v1/config", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let config: serde_json::Value = serde_json::from_str(&body).unwrap();
    let endpoints: Vec<String> = config["endpoints"]
        .as_array()
        .expect("endpoints")
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();

    assert!(endpoints.len() >= 20, "expected a full endpoint list");

    for endpoint in &endpoints {
        let (verb, path) = endpoint.split_once(' ').expect("`<VERB> <path>`");

        // Substitute concrete, non-existent names. The resource is absent, so a
        // routed handler answers 4xx with our envelope — which is what we check.
        let uri = path
            .replace("/{prefix}", "")
            .replace("{namespace}", "no_such_ns")
            .replace("{table}", "no_such_table")
            .replace("{view}", "no_such_view");

        let method = Method::from_bytes(verb.as_bytes()).expect("valid verb");
        let needs_body = matches!(verb, "POST");
        let (status, body) = request(
            &app,
            method,
            &uri,
            &admin,
            needs_body.then(|| serde_json::json!({})),
        )
        .await;

        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{endpoint} is advertised but {verb} is not routed"
        );

        // HEAD has no body by definition, so the envelope check cannot apply.
        if verb != "HEAD" {
            assert!(
                status.is_success() || body.contains("\"error\""),
                "{endpoint} is advertised but not routed (status {status}, body {body:?})"
            );
        }
    }
}

// ============================================================================
// The token endpoint Rustberg deliberately does not implement
// ============================================================================

/// `oauth/tokens` is marked *deprecated for removal* by the Iceberg REST spec,
/// which states plainly that implementing it is not recommended. Rustberg does
/// not issue tokens.
///
/// The route exists only to say so. A client configured with `credential=`
/// exchanges here before any catalog call, and an unrouted path answers
/// `401 Authentication required` — which sends the reader looking for a bad key
/// instead of a wrong property.
#[tokio::test]
async fn the_token_endpoint_explains_itself_without_a_credential() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, _secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    // No credential: a client asking for a token does not have one yet.
    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/oauth/tokens")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=client_credentials"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_IMPLEMENTED,
        "must answer, not demand the credential the caller is trying to obtain"
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let message = body["error"]["message"].as_str().expect("error envelope");

    // The message has to name the fix, or it is just a nicer dead end.
    assert!(message.contains("token"), "{message}");
    assert!(message.contains("credential"), "{message}");
    assert_eq!(body["error"]["type"], "UnsupportedOperationException");
}

/// With OIDC configured, `/v1/config` tells clients where to authenticate. This
/// is the migration the spec recommends in place of the deprecated endpoint.
#[tokio::test]
async fn config_advertises_the_identity_providers_token_endpoint() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(policies)
        .with_api_keys(vec![admin_key])
        .with_oauth2_server_uri("https://idp.example.com/oauth2/token")
        .build_with_api_keys()
        .await
        .expect("build app");

    let (status, body) = request(&app, Method::GET, "/v1/config", &secret, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        config["overrides"]["oauth2-server-uri"],
        "https://idp.example.com/oauth2/token"
    );
}

/// Without OIDC there is nowhere to point, so nothing is advertised. Sending an
/// empty or guessed value would send credentials to the wrong host.
#[tokio::test]
async fn config_advertises_no_token_endpoint_when_none_is_configured() {
    let policies = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (admin_key, secret) = key("admin", "acme", &["admin"]);
    let (app, _store) = app_with(policies, vec![admin_key]).await;

    let (_, body) = request(&app, Method::GET, "/v1/config", &secret, None).await;
    let config: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(config["overrides"].get("oauth2-server-uri").is_none());
}
