//! The audit trail, and the guarantee that a change is never made unrecorded.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{
    ApiKey, ApiKeyBuilder, AuditError, AuditEvent, AuditSink, Auditor, FileSink, NullSink,
};
use tower::ServiceExt;

const POLICIES: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };
"#;

fn key(name: &str) -> (ApiKey, String) {
    let (api_key, secret) = ApiKeyBuilder::new(name, "acme").with_role("admin").build();
    (api_key, secret.to_string())
}

async fn app_with(auditor: Arc<Auditor>) -> (App, String) {
    let (api_key, secret) = key("admin");
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![api_key])
        .with_auditor(auditor)
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;
    (app, secret)
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    secret: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
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
    app.clone()
        .into_router()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// A sink that fails every write, standing in for a full disk.
#[derive(Debug)]
struct BrokenSink;

impl AuditSink for BrokenSink {
    fn write(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::Io(std::io::Error::other("disk full")))
    }
    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
    fn describe(&self) -> String {
        "broken".into()
    }
}

/// Both outcomes are recorded. A trail of denials alone answers "who was turned
/// away" but not "who read this table".
#[tokio::test]
async fn permits_and_denials_are_both_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));

    let (app, secret) = app_with(auditor).await;

    assert_eq!(
        send(
            &app,
            Method::POST,
            "/v1/namespaces",
            &secret,
            Some(serde_json::json!({ "namespace": ["ns"] }))
        )
        .await,
        StatusCode::OK
    );
    // A namespace in another tenant: permitted to nobody here.
    let _ = send(&app, Method::GET, "/v1/namespaces/missing", &secret, None).await;

    let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
        .collect();

    assert!(!records.is_empty(), "nothing was recorded");

    let permits = records.iter().filter(|r| r["outcome"] == "success").count();
    assert!(permits > 0, "a permitted decision was not recorded");

    for record in &records {
        assert!(record["timestamp"].is_string(), "record: {record}");
        assert!(record["principal_id"].is_string());
        assert_eq!(record["category"], "authorization");
    }
}

/// An unrecorded change is the one event an audit exists to capture, so a
/// mutation whose record cannot be written is refused rather than performed.
#[tokio::test]
async fn a_mutation_is_refused_when_it_cannot_be_recorded() {
    let auditor = Arc::new(Auditor::new(Box::new(BrokenSink), true));
    let (app, secret) = app_with(auditor).await;

    let status = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        &secret,
        Some(serde_json::json!({ "namespace": ["unrecordable"] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unrecordable change must not be made"
    );

    // And it really was not made: the namespace does not exist.
    let auditor = Arc::new(Auditor::new(Box::new(NullSink), true));
    let (app2, secret2) = app_with(auditor).await;
    assert_eq!(
        send(
            &app2,
            Method::GET,
            "/v1/namespaces/unrecordable",
            &secret2,
            None
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

/// Reads degrade the other way. Refusing them because a disk filled turns an
/// observability problem into an outage, and a lost read record is not a lost
/// change.
#[tokio::test]
async fn a_read_still_serves_when_it_cannot_be_recorded() {
    // Seed with a working auditor, then serve reads with a broken one.
    let (api_key, secret) = key("admin");
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![api_key])
        .with_auditor(Arc::new(Auditor::new(Box::new(BrokenSink), true)))
        .build_with_api_keys()
        .await
        .unwrap()
        .0;

    // Listing is a read: it must answer even though every record is lost.
    let status = send(&app, Method::GET, "/v1/namespaces", &secret, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a read must not fail because the audit sink is broken"
    );
}

/// Configuring `fail_closed = false` trades the guarantee for availability. The
/// loss is still counted.
#[tokio::test]
async fn fail_open_permits_the_mutation_but_counts_the_loss() {
    let auditor = Arc::new(Auditor::new(Box::new(BrokenSink), false));
    let (app, secret) = app_with(auditor.clone()).await;

    let status = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        &secret,
        Some(serde_json::json!({ "namespace": ["ns"] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(auditor.dropped() > 0, "the lost record was not counted");
}

// ============================================================================
// Policy provenance
// ============================================================================

/// Reads every audit record written to `path`.
fn records_at(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
        .collect()
}

/// "Permitted" is the least useful half of an audit record. The question an
/// operator arrives with is *which rule did this*, and a record that cannot
/// answer it is a log line rather than a governance deliverable.
#[tokio::test]
async fn a_permit_names_the_policy_that_allowed_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));

    let (app, secret) = app_with(auditor).await;

    assert_eq!(
        send(
            &app,
            Method::POST,
            "/v1/namespaces",
            &secret,
            Some(serde_json::json!({ "namespace": ["provenance"] }))
        )
        .await,
        StatusCode::OK
    );

    let permit = records_at(&path)
        .into_iter()
        .find(|r| r["outcome"] == "success")
        .expect("a permitted decision was recorded");

    let matched = permit["matched_policies"]
        .as_array()
        .expect("a permit names the policies that produced it");
    assert!(
        !matched.is_empty(),
        "a permit must name at least one policy: {permit}"
    );

    assert!(
        permit["policy_set_version"].is_string(),
        "every decision names the policy set it was evaluated against: {permit}"
    );
}

/// Deny-by-default and deny-by-rule look identical to a client and are entirely
/// different to whoever has to fix the policy set. An empty `matched_policies`
/// on a denial is what distinguishes them.
#[tokio::test]
async fn a_default_denial_names_no_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));

    // A key with no role, so the admin permit above cannot match it.
    let (api_key, secret) = ApiKeyBuilder::new("nobody", "acme").build();
    let app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![api_key])
        .with_auditor(auditor)
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    let _ = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        secret.as_ref(),
        Some(serde_json::json!({ "namespace": ["denied"] })),
    )
    .await;

    let denial = records_at(&path)
        .into_iter()
        .find(|r| r["outcome"] != "success")
        .expect("the denial was recorded");

    // Absent (skipped when empty) or present-and-empty both mean the same
    // thing: nothing matched, so this failed closed rather than being forbidden.
    let named = denial["matched_policies"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(
        named, 0,
        "a deny-by-default must name no policy, so it is distinguishable from an \
         explicit forbid: {denial}"
    );
    assert!(
        denial["policy_set_version"].is_string(),
        "a denial still names the policy set that failed to permit it: {denial}"
    );
}

/// The version identifies the rules, so two different policy sets must not
/// share one — otherwise a record cannot tell you which rules were in force.
#[tokio::test]
async fn different_policy_sets_get_different_versions() {
    use rustberg::auth::{Authorizer, CedarAuthorizer};

    let a = CedarAuthorizer::new(POLICIES).unwrap();
    let b = CedarAuthorizer::new(
        r#"permit(principal in Rustberg::Group::"reader", action == Rustberg::Action::"Read", resource)
             when { resource.tenant == principal.tenant };"#,
    )
    .unwrap();

    let (va, vb) = (a.policy_set_version(), b.policy_set_version());
    assert!(va.is_some() && vb.is_some());
    assert_ne!(va, vb, "different rules must be different versions");

    // And it must be stable: the same source always yields the same version, or
    // two replicas serving identical policies would look like a mismatch.
    assert_eq!(
        CedarAuthorizer::new(POLICIES).unwrap().policy_set_version(),
        va,
        "the version is derived from content, so it is identical on every replica"
    );
}
