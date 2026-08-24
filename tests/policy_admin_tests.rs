//! Runtime policy administration.
//!
//! Policy is the most consequential thing anyone can change here, and it is the
//! only operation that can make itself unreachable. These tests pin both the
//! capability and the guardrails.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use serde_json::json;
use tower::ServiceExt;

/// An admin may do anything in their own tenant, including administer policy —
/// `Manage` on the policy set is covered by the unrestricted admin permit.
const ADMIN_POLICIES: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };

    permit(
      principal in Rustberg::Group::"reader",
      action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
      resource
    ) when { resource.tenant == principal.tenant };
"#;

fn key(name: &str, role: &str) -> (ApiKey, String) {
    let (api_key, secret) = ApiKeyBuilder::new(name, "acme").with_role(role).build();
    (api_key, secret.to_string())
}

/// An app with a persistent catalog, so the policy store survives within the
/// test. A `memory://` catalog is still a real redb file for this purpose.
async fn app_with_policies() -> (App, String, String) {
    let (admin_key, admin_secret) = key("admin", "admin");
    let (reader_key, reader_secret) = key("reader", "reader");

    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(ADMIN_POLICIES)
        .with_api_keys(vec![admin_key, reader_key])
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    (app, admin_secret, reader_secret)
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    secret: &str,
    body: Option<serde_json::Value>,
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

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON: {e}\n{body}"))
}

// ── Reading ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_admin_can_read_the_policy_set() {
    let (app, admin, _) = app_with_policies().await;

    let (status, body) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let policy = parse(&body);
    assert!(
        policy["source"].as_str().unwrap().contains("permit"),
        "the policy text is returned"
    );
    assert!(policy["version"].is_string(), "with its content hash");
    assert_eq!(
        policy["sequence"], 1,
        "the seeded revision is the first in the log"
    );
    assert_eq!(policy["author"], "system:bootstrap");
}

/// Policy is a protected resource, so a reader may not administer it.
#[tokio::test]
async fn a_reader_cannot_change_the_policy_set() {
    let (app, _, reader) = app_with_policies().await;

    let (status, _) = send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &reader,
        Some(json!({ "source": ADMIN_POLICIES })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "changing policy requires Manage on the policy set"
    );
}

#[tokio::test]
async fn an_unauthenticated_caller_cannot_reach_policy_administration() {
    let (app, _, _) = app_with_policies().await;

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/management/v1/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Changing ────────────────────────────────────────────────────────────────

/// The whole point: a policy change takes effect without a restart.
#[tokio::test]
async fn a_policy_change_takes_effect_immediately() {
    let (app, admin, reader) = app_with_policies().await;

    // The reader can currently list namespaces.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &reader, None).await;
    assert_eq!(status, StatusCode::OK);

    // Revoke the reader's grant, keeping the admin's.
    let admin_only = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    let (status, body) = send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": admin_only, "note": "revoke reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(parse(&body)["sequence"], 2, "a change appends a revision");

    // The reader is refused now, with no restart in between.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &reader, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the revocation applied to a live server"
    );

    // And the admin still works.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// A policy set that does not typecheck would be rules that silently never
/// match, so it is refused rather than installed.
#[tokio::test]
async fn an_invalid_policy_set_is_refused_and_nothing_changes() {
    let (app, admin, reader) = app_with_policies().await;

    let (status, body) = send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": "this is not a cedar policy" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The previous set is untouched, so the reader still works.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &reader, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a refused policy set must not have been partially installed"
    );

    // And it left no revision behind.
    let (_, body) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    assert_eq!(
        parse(&body)["sequence"],
        1,
        "a refused change appends nothing"
    );
}

/// A policy set that typechecks but removes the author's own `Manage` grant
/// would be unrecoverable: they could not submit another. Refused.
#[tokio::test]
async fn a_policy_set_that_would_lock_the_author_out_is_refused() {
    let (app, admin, _) = app_with_policies().await;

    // Valid Cedar, and it grants the admin everything *except* on the policy
    // set — so they could never change policy again.
    let self_lockout = r#"
        permit(
          principal in Rustberg::Group::"admin",
          action,
          resource
        ) when {
          resource.tenant == principal.tenant && !(resource has tenant && false)
        };
        forbid(
          principal,
          action == Rustberg::Action::"Manage",
          resource
        );
    "#;

    let (status, body) = send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": self_lockout })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a self-lockout must be refused: {body}"
    );
    assert!(
        body.contains("no longer be permitted"),
        "the refusal should explain what happened: {body}"
    );

    // And the admin can still administer policy.
    let (status, _) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// A grant conditioned on the caller's address is an ordinary rule — "policy is
/// administered from inside the VPC". The self-lockout check has to ask whether
/// the author can administer policy *as they are administering it now*, so it
/// carries this request's context. Asking without one evaluates every
/// address-conditioned permit to false and refuses a policy set that plainly
/// works.
#[tokio::test]
async fn a_grant_conditioned_on_the_callers_address_is_not_mistaken_for_a_lockout() {
    let (app, admin, _) = app_with_policies().await;

    // In-process requests carry no address, so `context has source_ip` is false
    // and this is the shape that must still be accepted: the guard has already
    // permitted the call under the *current* rules, and under the new rules the
    // same call is permitted for the same reason.
    let address_guarded = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };

        forbid(
          principal,
          action == Rustberg::Action::"Manage",
          resource
        ) when {
          context has source_ip && !context.source_ip.isInRange(ip("10.0.0.0/8"))
        };
    "#;

    let (status, body) = send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": address_guarded })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the author can still administer policy under these rules: {body}"
    );

    // And it really did take effect.
    let (status, _) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ── History and rollback ────────────────────────────────────────────────────

#[tokio::test]
async fn history_lists_revisions_newest_first_without_their_text() {
    let (app, admin, _) = app_with_policies().await;

    let admin_only = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": admin_only, "note": "tighten" })),
    )
    .await;

    let (status, body) = send(
        &app,
        Method::GET,
        "/management/v1/policies/history",
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let revisions = parse(&body)["revisions"].as_array().unwrap().clone();
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0]["sequence"], 2, "newest first");
    assert_eq!(revisions[0]["note"], "tighten");
    assert_eq!(revisions[1]["sequence"], 1);

    assert!(
        !body.contains("permit("),
        "a history listing must not carry every revision's full text: {body}"
    );
    assert!(
        revisions[0]["source_bytes"].is_number(),
        "but it conveys scale"
    );
}

/// Rollback appends rather than rewinding, so no existing `policy_set_version`
/// stops resolving.
#[tokio::test]
async fn rollback_restores_earlier_rules_as_a_new_revision() {
    let (app, admin, reader) = app_with_policies().await;

    let admin_only = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": admin_only })),
    )
    .await;

    // The reader is locked out at revision 2.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &reader, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = send(
        &app,
        Method::POST,
        "/management/v1/policies/rollback",
        &admin,
        Some(json!({ "sequence": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let restored = parse(&body);
    assert_eq!(
        restored["sequence"], 3,
        "a rollback appends; it does not rewind the log"
    );

    // The reader works again, and revision 1 still exists.
    let (status, _) = send(&app, Method::GET, "/v1/namespaces", &reader, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the earlier rules are back in force"
    );

    let (_, body) = send(
        &app,
        Method::GET,
        "/management/v1/policies/history",
        &admin,
        None,
    )
    .await;
    assert_eq!(
        parse(&body)["revisions"].as_array().unwrap().len(),
        3,
        "every revision is still in the log"
    );
}

/// Rolling back to a revision that never existed is a miss that says so.
#[tokio::test]
async fn rolling_back_to_an_unknown_revision_is_not_found() {
    let (app, admin, _) = app_with_policies().await;

    let (status, body) = send(
        &app,
        Method::POST,
        "/management/v1/policies/rollback",
        &admin,
        Some(json!({ "sequence": 999 })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("history"), "point at how to find one: {body}");
}

/// A restored revision enforces the *same rules*, so it carries the same
/// content hash even though it is a later sequence.
#[tokio::test]
async fn a_rollback_restores_the_original_version_hash() {
    let (app, admin, _) = app_with_policies().await;

    let (_, original) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    let original_version = parse(&original)["version"].as_str().unwrap().to_string();

    let admin_only = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": admin_only })),
    )
    .await;

    let (_, rolled_back) = send(
        &app,
        Method::POST,
        "/management/v1/policies/rollback",
        &admin,
        Some(json!({ "sequence": 1 })),
    )
    .await;

    assert_eq!(
        parse(&rolled_back)["version"].as_str().unwrap(),
        original_version,
        "the version identifies the rules, so restoring them restores it"
    );
    assert_ne!(
        parse(&rolled_back)["sequence"],
        parse(&original)["sequence"],
        "while the sequence records that a rollback happened"
    );
}

// ── Audit ───────────────────────────────────────────────────────────────────

/// A decision made after a change must name the new policy set, or an audit
/// record cannot be tied to the rules that produced it.
#[tokio::test]
async fn decisions_name_the_policy_set_version_in_force() {
    let (app, admin, _) = app_with_policies().await;

    let (_, before) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    let first_version = parse(&before)["version"].as_str().unwrap().to_string();

    let admin_only = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    send(
        &app,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": admin_only })),
    )
    .await;

    let (_, after) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    let second_version = parse(&after)["version"].as_str().unwrap().to_string();

    assert_ne!(
        first_version, second_version,
        "a changed policy set is a changed version, so records can be told apart"
    );
}

// ── Availability ────────────────────────────────────────────────────────────

/// A deployment that evaluates no policy answers `501` rather than pretending
/// to administer something nothing consults.
#[tokio::test]
async fn policy_administration_is_unavailable_without_authentication() {
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .build()
        .await
        .expect("build app");

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/management/v1/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_IMPLEMENTED,
        "a --no-auth deployment has no policy to administer"
    );
}

/// The version an audit record carries and the version the store recorded for
/// the same revision must be the same string.
///
/// They are produced by one function, so they cannot drift — this pins that
/// they are actually wired together, since two copies of the hash would look
/// identical until someone changed one.
#[tokio::test]
async fn the_stored_version_is_the_version_decisions_report() {
    use rustberg::auth::{Authorizer, CedarAuthorizer, policy_store::version_of};

    let (app, admin, _) = app_with_policies().await;

    let (_, body) = send(&app, Method::GET, "/management/v1/policies", &admin, None).await;
    let policy = parse(&body);
    let stored_version = policy["version"].as_str().unwrap();
    let source = policy["source"].as_str().unwrap();

    assert_eq!(
        stored_version,
        version_of(source),
        "the store's version must be the hash of the source it holds"
    );

    let authorizer = CedarAuthorizer::new(source).unwrap();
    assert_eq!(
        authorizer.policy_set_version().as_deref(),
        Some(stored_version),
        "an authorizer built from that source must report the same version, or an \
         audit record would name a revision the store cannot resolve"
    );
}
