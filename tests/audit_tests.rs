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
    // A key with no role, so the admin permit cannot match it: this produces a
    // decision that was made and refused, rather than a `404` from a namespace
    // that never existed.
    let (nobody, nobody_secret) = {
        let (k, s) = ApiKeyBuilder::new("nobody", "acme").build();
        (k, s.to_string())
    };
    let denied_app = App::builder()
        .with_warehouse_location("memory://test")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![nobody])
        .with_auditor(Arc::new(Auditor::new(
            Box::new(FileSink::open(&path).unwrap()),
            true,
        )))
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;
    let _ = send(
        &denied_app,
        Method::POST,
        "/v1/namespaces",
        &nobody_secret,
        Some(serde_json::json!({ "namespace": ["denied"] })),
    )
    .await;

    let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
        .collect();

    assert!(!records.is_empty(), "nothing was recorded");

    let decisions: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["category"] == "authorization")
        .collect();
    assert!(
        decisions.iter().any(|r| r["outcome"] == "success"),
        "a permitted decision was not recorded"
    );
    assert!(
        decisions.iter().any(|r| r["outcome"] == "denied"),
        "a refused decision was not recorded"
    );

    for record in &decisions {
        assert!(record["timestamp"].is_string(), "record: {record}");
        assert!(record["principal_id"].is_string());
        assert_eq!(record["action"], "decision");
        // The Cedar action is a field, not a `details` entry: `action` names
        // the kind of event, so the useful half must not be free-form.
        assert!(record["operation"].is_string(), "record: {record}");
    }
}

/// Authentication belongs in the same file as authorization.
///
/// Routed anywhere else — stderr with the application log, say — a deployment
/// that configured `sink = "file"` gets a file saying what callers were
/// permitted to do and never who they were, and the record saying a credential
/// was rejected lands where the audit pipeline is not reading.
#[tokio::test]
async fn authentication_reaches_the_same_sink_as_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));

    let (app, secret) = app_with(auditor).await;

    assert_eq!(
        send(&app, Method::GET, "/v1/namespaces", &secret, None).await,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, Method::GET, "/v1/namespaces", "not-a-key", None).await,
        StatusCode::UNAUTHORIZED
    );

    let records = records_at(&path);

    let accepted = records
        .iter()
        .find(|r| r["category"] == "authentication" && r["outcome"] == "success")
        .expect("an accepted credential was not recorded");
    assert_eq!(accepted["action"], "authenticate");
    assert_eq!(accepted["operation"], "api_key");
    assert!(
        accepted["principal_id"].is_string(),
        "an accepted credential names who it established: {accepted}"
    );
    assert_eq!(accepted["tenant_id"], "acme");

    let rejected = records
        .iter()
        .find(|r| r["category"] == "authentication" && r["outcome"] == "denied")
        .expect("a rejected credential was not recorded");
    assert_eq!(
        rejected.get("principal_id"),
        None,
        "a rejection establishes no principal: {rejected}"
    );
}

/// **Every** way a presented credential fails is recorded, not only the obvious
/// three.
///
/// A forged JWT signature is `InvalidToken`, an expired one is too, and an
/// expired API key is `TokenExpired`. Miss those and the auth-failure rate limit
/// stops bounding the most expensive rejection this server serves, and the trail
/// stops holding it.
///
/// A request carrying *no* credential stays unrecorded, and that half matters
/// too: it is an unconfigured client reaching an authenticated server, and
/// counting it would let a health checker exhaust everyone else's budget.
///
/// Driven through an authenticator that returns a chosen error, because it is
/// the only way to reach the token variants: an app configured with API keys
/// alone reads every bearer token as a key and answers `ApiKeyNotFound`.
#[tokio::test]
async fn every_shape_of_rejected_credential_is_recorded() {
    /// Fails every request with the error it was built with.
    #[derive(Debug)]
    struct Rejects(fn() -> rustberg::auth::AuthError);

    #[async_trait::async_trait]
    impl rustberg::auth::Authenticator for Rejects {
        async fn authenticate(
            &self,
            _headers: &axum::http::HeaderMap,
        ) -> Result<rustberg::auth::Principal, rustberg::auth::AuthError> {
            Err((self.0)())
        }

        fn auth_method(&self) -> rustberg::auth::AuthMethod {
            rustberg::auth::AuthMethod::Bearer
        }
    }

    // Every way a presented token fails, and one way nothing was presented.
    let cases: [(fn() -> rustberg::auth::AuthError, bool); 6] = [
        (
            || rustberg::auth::AuthError::InvalidToken("bad signature".into()),
            true,
        ),
        (
            || rustberg::auth::AuthError::MalformedToken("not three segments".into()),
            true,
        ),
        (|| rustberg::auth::AuthError::TokenExpired, true),
        (|| rustberg::auth::AuthError::ExpiredCredentials, true),
        (|| rustberg::auth::AuthError::ApiKeyDisabled, true),
        // Nothing was presented, so there is nothing to record.
        (|| rustberg::auth::AuthError::Unauthenticated, false),
    ];

    for (make, expect_record) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));

        let app = App::builder()
            .with_warehouse_location("memory://test")
            .with_default_tenant_id("acme")
            .with_policies(POLICIES)
            .with_authenticator(Arc::new(Rejects(make)))
            .with_auditor(auditor)
            .build()
            .await
            .expect("build app");

        let response = app
            .clone()
            .into_router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/namespaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{:?}", make());

        let denials = records_at(&path)
            .into_iter()
            .filter(|r| r["category"] == "authentication" && r["outcome"] == "denied")
            .count();

        assert_eq!(
            denials,
            usize::from(expect_record),
            "{:?} should {}have been recorded",
            make(),
            if expect_record { "" } else { "not " }
        );
    }
}

/// The same rule end to end, through the real API-key authenticator.
///
/// About the *record* rather than the classification: every rejection says why,
/// and a request carrying no credential leaves none.
#[tokio::test]
async fn a_rejected_credential_is_recorded_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(&path).unwrap()), true));
    let (app, _secret) = app_with(auditor).await;

    // All three are read as API keys: this deployment configures no JWT
    // authenticator, so `Authorization: Bearer …` carries a key here.
    let rejected: [(&str, &str); 3] = [
        ("X-API-Key", "rb_this-key-does-not-exist"),
        ("Authorization", "Bearer not.a.jwt"),
        (
            "Authorization",
            "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.bm90LWEtc2ln",
        ),
    ];

    for (header, value) in rejected {
        let response = app
            .clone()
            .into_router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/namespaces")
                    .header(header, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{header}: {value}"
        );
    }

    // And one carrying nothing at all.
    let anonymous = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/namespaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let denials: Vec<_> = records_at(&path)
        .into_iter()
        .filter(|r| r["category"] == "authentication" && r["outcome"] == "denied")
        .collect();

    assert_eq!(
        denials.len(),
        rejected.len(),
        "one record per presented credential, and none for the anonymous          request: {denials:#?}"
    );
    for denial in &denials {
        assert!(
            denial["details"]["reason"].is_string(),
            "a rejection says why: {denial}"
        );
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
        .find(|r| r["category"] == "authorization" && r["outcome"] == "success")
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
        .find(|r| r["category"] == "authorization" && r["outcome"] != "success")
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

// ════════════════════════════════════════════════════════════════════════════
// Storage access
// ════════════════════════════════════════════════════════════════════════════
//
// Vending a credential is where policy becomes enforcement. Without a record the
// trail holds a permitted `Read` of a table and no evidence that the caller
// walked away with something that could overwrite it.

/// Vends a fixed credential for anything, so these tests are about the record
/// rather than about any cloud provider's exchange.
#[derive(Debug)]
struct StubProvider;

#[async_trait::async_trait]
impl rustberg::credentials::StorageCredentialProvider for StubProvider {
    async fn vend_credentials(
        &self,
        request: &rustberg::credentials::StorageCredentialRequest,
    ) -> Result<
        Vec<rustberg::credentials::StorageCredential>,
        rustberg::credentials::StorageCredentialVendingError,
    > {
        Ok(vec![rustberg::credentials::StorageCredential {
            prefix: request.table_location.clone(),
            config: std::collections::HashMap::from([(
                "test.token".to_string(),
                "granted".to_string(),
            )]),
        }])
    }

    fn supports_location(&self, _location: &str) -> bool {
        true
    }
}

/// Builds an app with a credential provider and one table, recording to `path`.
async fn vending_app(path: &std::path::Path, role: &str, policies: &str) -> (App, String) {
    let (api_key, secret) = ApiKeyBuilder::new("caller", "acme").with_role(role).build();
    let auditor = Arc::new(Auditor::new(Box::new(FileSink::open(path).unwrap()), true));

    let app = App::builder()
        .with_warehouse_location("memory://vending")
        .with_default_tenant_id("acme")
        .with_policies(policies)
        .with_api_keys(vec![api_key])
        .with_credential_provider(Arc::new(StubProvider))
        .with_auditor(auditor)
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    let secret = secret.to_string();
    assert_eq!(
        send(
            &app,
            Method::POST,
            "/v1/namespaces",
            &secret,
            Some(serde_json::json!({ "namespace": ["db"] }))
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            Method::POST,
            "/v1/namespaces/db/tables",
            &secret,
            Some(serde_json::json!({
                "name": "events",
                "schema": { "type": "struct", "fields": [
                    { "id": 1, "name": "id", "required": true, "type": "long" }
                ]}
            }))
        )
        .await,
        StatusCode::OK
    );

    (app, secret)
}

/// Asks for a table with credential delegation, which is the header a client
/// sends to opt in.
async fn load_with_credentials(app: &App, secret: &str) -> StatusCode {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/namespaces/db/tables/events")
        .header("X-API-Key", secret)
        .header("X-Iceberg-Access-Delegation", "vended-credentials")
        .body(Body::empty())
        .unwrap();
    app.clone()
        .into_router()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// The decision record says the caller could `Read`. Only the vending record
/// says whether what it received could also write, which is the fact that names
/// the blast radius.
#[tokio::test]
async fn a_vended_credential_is_recorded_with_its_access_level() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let (app, secret) = vending_app(&path, "admin", POLICIES).await;

    assert_eq!(load_with_credentials(&app, &secret).await, StatusCode::OK);

    let vends: Vec<serde_json::Value> = records_at(&path)
        .into_iter()
        .filter(|r| r["action"] == "vend_credentials")
        .collect();

    let vend = vends.last().expect("a vended credential was not recorded");
    assert_eq!(vend["category"], "storage_access");
    assert_eq!(vend["outcome"], "success");
    assert_eq!(
        vend["operation"], "read-write",
        "an admin may Update, so the credential could write: {vend}"
    );
    assert_eq!(vend["resource_id"], "acme/db/events");
}

/// A reader gets a read credential, and the trail says so. Without the
/// distinction the record would be worth no more than the decision above it.
#[tokio::test]
async fn a_read_only_caller_is_recorded_as_receiving_a_read_credential() {
    const READ_ONLY: &str = r#"
        permit(principal in Rustberg::Group::"reader",
               action in [Rustberg::Action::"Read", Rustberg::Action::"List",
                          Rustberg::Action::"Create"],
               resource) when { resource.tenant == principal.tenant };
    "#;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let (app, secret) = vending_app(&path, "reader", READ_ONLY).await;

    assert_eq!(load_with_credentials(&app, &secret).await, StatusCode::OK);

    let vend = records_at(&path)
        .into_iter()
        .rfind(|r| r["action"] == "vend_credentials")
        .expect("a vended credential was not recorded");

    assert_eq!(vend["operation"], "read");

    // And the `Update` decision that decided it is in the trail rather than
    // being asked speculatively and dropped.
    assert!(
        records_at(&path).iter().any(|r| r["action"] == "decision"
            && r["operation"] == "Update"
            && r["outcome"] == "denied"),
        "the refused Update decision is missing"
    );
}

/// An uncredentialed `loadTable` writes no vending record. One per read would
/// say nothing, and would be the most common line in the file.
#[tokio::test]
async fn a_load_that_asked_for_nothing_records_no_vending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let (app, secret) = vending_app(&path, "admin", POLICIES).await;

    assert_eq!(
        send(
            &app,
            Method::GET,
            "/v1/namespaces/db/tables/events",
            &secret,
            None
        )
        .await,
        StatusCode::OK
    );

    assert!(
        !records_at(&path)
            .iter()
            .any(|r| r["action"] == "vend_credentials"),
        "nothing was vended, so nothing should be recorded"
    );
}

/// The two halves of the fail-closed rule, on one broken sink.
///
/// A mutation that cannot be recorded is refused; a read that cannot be recorded
/// still serves. The refusal-is-not-a-grant half of the rule needs a path that
/// reaches storage access without mutating first, and lives in
/// `signing_tests.rs`.
#[tokio::test]
async fn a_broken_sink_refuses_mutations_and_serves_reads() {
    let (api_key, secret) = ApiKeyBuilder::new("caller", "acme")
        .with_role("admin")
        .build();
    let app = App::builder()
        .with_warehouse_location("memory://broken")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![api_key])
        .with_credential_provider(Arc::new(StubProvider))
        .with_auditor(Arc::new(Auditor::new(Box::new(BrokenSink), true)))
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;
    let secret = secret.to_string();

    assert_eq!(
        send(
            &app,
            Method::POST,
            "/v1/namespaces",
            &secret,
            Some(serde_json::json!({ "namespace": ["db"] }))
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unrecordable mutation is refused"
    );

    assert_eq!(
        send(&app, Method::GET, "/v1/namespaces", &secret, None).await,
        StatusCode::OK,
        "a read must not be taken down by a broken sink"
    );
}

/// A denied mutation changed nothing, so there is no unrecorded change to
/// refuse. Answering `503` would replace a policy answer with an availability
/// one, and tell a caller to retry when what it needs is a permit.
#[tokio::test]
async fn a_denied_mutation_is_denied_not_unavailable() {
    // A key with no role, so the admin permit cannot match it.
    let (api_key, secret) = ApiKeyBuilder::new("nobody", "acme").build();
    let app = App::builder()
        .with_warehouse_location("memory://denied")
        .with_default_tenant_id("acme")
        .with_policies(POLICIES)
        .with_api_keys(vec![api_key])
        .with_auditor(Arc::new(Auditor::new(Box::new(BrokenSink), true)))
        .build_with_api_keys()
        .await
        .expect("build app")
        .0;

    let status = send(
        &app,
        Method::POST,
        "/v1/namespaces",
        secret.as_ref(),
        Some(serde_json::json!({ "namespace": ["denied"] })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a broken sink must not turn a refusal into an outage"
    );
}
