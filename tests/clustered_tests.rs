//! Two replicas, one Postgres, over HTTP.
//!
//! The store-level Postgres tests prove the backend behaves under concurrency.
//! These prove the *deployment* does: two complete servers sharing one database,
//! which is what a Kubernetes Deployment with `replicas: 2` actually is.
//!
//! That shape is where a whole class of bug lives — anything held in one
//! process's memory works perfectly on a single node and fails intermittently
//! behind a load balancer, which is the worst failure mode available because it
//! passes every local test.
//!
//! Docker-only, so `#[ignore]`d by default:
//!
//! ```text
//! cargo test --features catalog-postgres --test clustered_tests -- --ignored
//! ```

#![cfg(feature = "catalog-postgres")]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{ApiKey, ApiKeyBuilder};
use serde_json::json;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tower::ServiceExt;

const POLICIES: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };

    permit(
      principal in Rustberg::Group::"reader",
      action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
      resource
    ) when { resource.tenant == principal.tenant };
"#;

const ADMIN_ONLY: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };
"#;

/// A Postgres container and the warehouse its replicas share.
struct Cluster {
    _container: ContainerAsync<GenericImage>,
    dsn: String,
    warehouse: tempfile::TempDir,
}

impl Cluster {
    async fn start() -> Self {
        // Debian-based, deliberately, and **not** `-alpine`. Alpine is musl,
        // whose `strcoll` is byte comparison, so every locale there behaves like
        // `C` — which is exactly the property `listings_come_back_in_byte_order`
        // exists to check, making the test vacuous on the image that was here
        // before. Real deployments run glibc: the Debian image, RDS, Cloud SQL,
        // Aurora. There `en_US.utf8` orders `aa, ab, Ärger, _underscore, Zulu`
        // and byte order gives `Zulu, _underscore, aa, ab`, which is a different
        // listing from redb's for the same catalog.
        let container = GenericImage::new("postgres", "16")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_PASSWORD", "rustberg")
            .with_env_var("POSTGRES_USER", "rustberg")
            .with_env_var("POSTGRES_DB", "rustberg")
            .start()
            .await
            .expect("start postgres");

        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("postgres port");

        Self {
            _container: container,
            dsn: format!("postgres://rustberg:rustberg@127.0.0.1:{port}/rustberg"),
            warehouse: tempfile::tempdir().expect("warehouse dir"),
        }
    }

    /// Starts another replica against the same database and warehouse.
    ///
    /// Every replica is a complete server: its own catalog handle, its own
    /// policy set loaded from the shared store, its own poller.
    async fn replica(&self, keys: Vec<ApiKey>) -> App {
        App::builder()
            .with_catalog_url(&self.dsn)
            .with_warehouse_location(rustberg::location::url_from_path(self.warehouse.path()))
            .with_default_tenant_id("acme")
            .with_policies(POLICIES)
            .with_api_keys(keys)
            .build_with_api_keys()
            .await
            .expect("build replica")
            .0
    }
}

fn key(name: &str, role: &str) -> (ApiKey, String) {
    let (api_key, secret) = ApiKeyBuilder::new(name, "acme").with_role(role).build();
    (api_key, secret.to_string())
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

fn schema() -> serde_json::Value {
    json!({
        "type": "struct",
        "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }]
    })
}

/// Polls until `check` passes, or fails after `within`.
///
/// Replicas converge by polling, so a cross-replica assertion is inherently
/// eventual. Asserting immediately would be a race; sleeping a fixed time would
/// be slow *and* a race.
async fn eventually<F, Fut>(within: std::time::Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

// ── Catalog state ───────────────────────────────────────────────────────────

/// A table created through one replica is immediately visible through another.
///
/// Catalog state is in Postgres rather than in either process, so this needs no
/// convergence window — unlike policy, which is cached and polled.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_table_created_on_one_replica_is_visible_on_the_other() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let a = cluster.replica(vec![admin_key.clone()]).await;
    let b = cluster.replica(vec![admin_key]).await;

    let (status, body) = send(
        &a,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["shared"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &a,
        Method::POST,
        "/v1/namespaces/shared/tables",
        &admin,
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &b,
        Method::GET,
        "/v1/namespaces/shared/tables/events",
        &admin,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "catalog state lives in Postgres, so it needs no convergence: {body}"
    );
}

/// Spark's CTAS, staged on one replica and committed on another.
///
/// This is the property that decides whether staged creation works behind a
/// load balancer at all. Holding staged metadata in process memory would pass
/// every single-node test and fail here.
/// A retry that lands on a different replica must not execute a second time.
///
/// The idempotency cache is in-process, so before it was backed by the shared
/// database this was the one thing an `Idempotency-Key` exists to prevent — while
/// `/v1/config` advertised a reuse window regardless.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn an_idempotent_retry_on_another_replica_executes_once() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let first = cluster.replica(vec![admin_key.clone()]).await;
    let second = cluster.replica(vec![admin_key]).await;

    let (status, _) = send(
        &first,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["retry"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let create = json!({ "name": "events", "schema": schema() });
    let request = |app: &App| {
        let app = app.clone();
        let admin = admin.clone();
        let create = create.clone();
        async move {
            let request = Request::builder()
                .method(Method::POST)
                .uri("/v1/namespaces/retry/tables")
                .header("X-API-Key", &admin)
                .header("Idempotency-Key", "retry-across-replicas")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&create).unwrap()))
                .unwrap();
            let response = app.into_router().oneshot(request).await.unwrap();
            response.status()
        }
    };

    assert_eq!(request(&first).await, StatusCode::OK, "the first attempt");
    assert_eq!(
        request(&second).await,
        StatusCode::OK,
        "the retry is answered from the shared receipt, not re-executed — without \
         which this is a 409 for a table the caller believes it has not created"
    );
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_table_staged_on_one_replica_commits_on_the_other() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let a = cluster.replica(vec![admin_key.clone()]).await;
    let b = cluster.replica(vec![admin_key]).await;

    send(
        &a,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["ctas"] })),
    )
    .await;

    let (status, body) = send(
        &a,
        Method::POST,
        "/v1/namespaces/ctas/tables",
        &admin,
        Some(json!({ "name": "summary", "schema": schema(), "stage-create": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "staging on replica A: {body}");

    // Invisible on both.
    for (label, replica) in [("A", &a), ("B", &b)] {
        let (status, _) = send(
            replica,
            Method::GET,
            "/v1/namespaces/ctas/tables/summary",
            &admin,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a staged table is invisible on replica {label}"
        );
    }

    // The commit lands on the other replica, as a load balancer would send it.
    let (status, body) = send(
        &b,
        Method::POST,
        "/v1/namespaces/ctas/tables/summary",
        &admin,
        Some(json!({
            "requirements": [{ "type": "assert-create" }],
            "updates": [{ "action": "set-properties", "updates": { "by": "replica-b" } }]
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replica B must be able to commit what replica A staged: {body}"
    );

    for (label, replica) in [("A", &a), ("B", &b)] {
        let (status, body) = send(
            replica,
            Method::GET,
            "/v1/namespaces/ctas/tables/summary",
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "replica {label}: {body}");
        assert_eq!(
            parse(&body)["metadata"]["properties"]["by"].as_str(),
            Some("replica-b")
        );
    }
}

// ── Policy ──────────────────────────────────────────────────────────────────

/// A policy change made through one replica reaches the other.
///
/// Policy is the one thing each replica caches, so this is the assertion that
/// matters most: a revocation applied to only the pod that received it means
/// the cluster enforces two rule sets, and which one a caller gets is whichever
/// pod the load balancer picked.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_revocation_on_one_replica_reaches_the_other() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");
    let (reader_key, reader) = key("reader", "reader");

    let a = cluster
        .replica(vec![admin_key.clone(), reader_key.clone()])
        .await;
    let b = cluster.replica(vec![admin_key, reader_key]).await;

    send(
        &a,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["governed"] })),
    )
    .await;

    // The reader works on both replicas to begin with.
    for (label, replica) in [("A", &a), ("B", &b)] {
        let (status, _) = send(
            replica,
            Method::GET,
            "/v1/namespaces/governed",
            &reader,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "reader should start permitted on {label}"
        );
    }

    // Revoke through replica A.
    let (status, body) = send(
        &a,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": ADMIN_ONLY, "note": "revoke reader" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A applies it immediately.
    let (status, _) = send(&a, Method::GET, "/v1/namespaces/governed", &reader, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the replica that received the change applies it at once"
    );

    // B converges by polling.
    let converged = eventually(std::time::Duration::from_secs(30), || async {
        let (status, _) = send(&b, Method::GET, "/v1/namespaces/governed", &reader, None).await;
        status == StatusCode::NOT_FOUND
    })
    .await;

    assert!(
        converged,
        "replica B never picked up the revocation — a policy change that reaches \
         only one pod means the cluster enforces two different rule sets"
    );
}

/// Both replicas converge on the same policy set, so an audit record from
/// either is comparable with the other.
///
/// Asserted on what each replica *enforces* — `sequence` — and not on
/// `latest_sequence`, which both read from the shared store and would therefore
/// agree even if neither had converged. An earlier version of this test made
/// exactly that mistake and passed with the poller disabled.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn replicas_converge_on_one_policy_version() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let a = cluster.replica(vec![admin_key.clone()]).await;
    let b = cluster.replica(vec![admin_key]).await;

    /// What the answering replica is enforcing: its loaded sequence and the
    /// version that goes with it.
    async fn in_force(app: &App, secret: &str) -> (u64, String) {
        let (_, body) = send(app, Method::GET, "/management/v1/policies", secret, None).await;
        let policy = parse(&body);
        (
            policy["sequence"].as_u64().unwrap_or_default(),
            policy["version"].as_str().unwrap_or_default().to_string(),
        )
    }

    assert_eq!(
        in_force(&a, &admin).await,
        in_force(&b, &admin).await,
        "replicas that loaded the same policy set enforce the same revision"
    );

    send(
        &a,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": ADMIN_ONLY })),
    )
    .await;

    let expected = in_force(&a, &admin).await;
    assert_eq!(
        expected.0, 2,
        "the replica that received the change enforces the new revision at once"
    );

    let converged = eventually(std::time::Duration::from_secs(30), || {
        let expected = expected.clone();
        let admin = admin.clone();
        let b = b.clone();
        async move { in_force(&b, &admin).await == expected }
    })
    .await;

    assert!(
        converged,
        "replica B never converged on revision {}; audit records from the two \
         replicas would name different rule sets for the same moment",
        expected.0
    );
}

/// A replica that has not converged says so, rather than reporting the store's
/// newest revision as though it were in force.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_replica_reports_both_what_it_enforces_and_what_exists() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let a = cluster.replica(vec![admin_key.clone()]).await;
    let b = cluster.replica(vec![admin_key]).await;

    // Both are up to date to begin with, and say so.
    let (_, body) = send(&b, Method::GET, "/management/v1/policies", &admin, None).await;
    let policy = parse(&body);
    assert_eq!(
        policy["sequence"], policy["latest_sequence"],
        "an up-to-date replica reports matching sequences: {body}"
    );

    send(
        &a,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": ADMIN_ONLY })),
    )
    .await;

    // Whatever B reports, the two fields must be consistent with each other:
    // either it has converged, or it names the older revision it still enforces.
    let (_, body) = send(&b, Method::GET, "/management/v1/policies", &admin, None).await;
    let policy = parse(&body);
    let enforced = policy["sequence"].as_u64().unwrap();
    let latest = policy["latest_sequence"].as_u64().unwrap();

    assert_eq!(latest, 2, "the store holds the new revision: {body}");
    assert!(
        enforced <= latest,
        "a replica cannot enforce a revision the store does not have: {body}"
    );

    // And it does converge.
    assert!(
        eventually(std::time::Duration::from_secs(30), || async {
            let (_, body) = send(&b, Method::GET, "/management/v1/policies", &admin, None).await;
            let policy = parse(&body);
            policy["sequence"] == policy["latest_sequence"]
        })
        .await,
        "the replica should eventually report itself up to date"
    );
}

/// A rollback propagates like any other change — it is a new revision, not a
/// rewind, so there is nothing special for a replica to notice.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_rollback_reaches_the_other_replica() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");
    let (reader_key, reader) = key("reader", "reader");

    let a = cluster
        .replica(vec![admin_key.clone(), reader_key.clone()])
        .await;
    let b = cluster.replica(vec![admin_key, reader_key]).await;

    send(
        &a,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["governed"] })),
    )
    .await;

    // Revoke, and wait for B.
    send(
        &a,
        Method::PUT,
        "/management/v1/policies",
        &admin,
        Some(json!({ "source": ADMIN_ONLY })),
    )
    .await;
    assert!(
        eventually(std::time::Duration::from_secs(30), || async {
            let (status, _) = send(&b, Method::GET, "/v1/namespaces/governed", &reader, None).await;
            status == StatusCode::NOT_FOUND
        })
        .await,
        "B should have picked up the revocation first"
    );

    // Roll back to the seeded revision.
    let (status, body) = send(
        &a,
        Method::POST,
        "/management/v1/policies/rollback",
        &admin,
        Some(json!({ "sequence": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert!(
        eventually(std::time::Duration::from_secs(30), || async {
            let (status, _) = send(&b, Method::GET, "/v1/namespaces/governed", &reader, None).await;
            status == StatusCode::OK
        })
        .await,
        "a rollback must reach the other replica; it is an ordinary new revision"
    );
}

/// Two replicas writing policy at once must not lose one of the changes.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn concurrent_policy_writes_from_two_replicas_are_both_recorded() {
    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let a = cluster.replica(vec![admin_key.clone()]).await;
    let b = cluster.replica(vec![admin_key]).await;

    let write = |app: App, secret: String, note: &'static str| async move {
        send(
            &app,
            Method::PUT,
            "/management/v1/policies",
            &secret,
            Some(json!({ "source": ADMIN_ONLY, "note": note })),
        )
        .await
    };

    let (first, second) = tokio::join!(
        write(a.clone(), admin.clone(), "from-a"),
        write(b.clone(), admin.clone(), "from-b")
    );

    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(second.0, StatusCode::OK, "{}", second.1);

    let (_, body) = send(
        &a,
        Method::GET,
        "/management/v1/policies/history",
        &admin,
        None,
    )
    .await;
    let revisions = parse(&body)["revisions"].as_array().unwrap().clone();

    let notes: Vec<&str> = revisions
        .iter()
        .filter_map(|r| r["note"].as_str())
        .collect();
    assert!(notes.contains(&"from-a"), "{notes:?}");
    assert!(notes.contains(&"from-b"), "{notes:?}");

    let sequences: Vec<u64> = revisions
        .iter()
        .map(|r| r["sequence"].as_u64().unwrap())
        .collect();
    let unique: std::collections::BTreeSet<u64> = sequences.iter().copied().collect();
    assert_eq!(
        unique.len(),
        sequences.len(),
        "two revisions shared a sequence, so one rule set overwrote another: {sequences:?}"
    );
}

// ── Federation over a clustered backend ─────────────────────────────────────

/// A mount backed by Postgres, shared between two replicas.
///
/// Federation and clustering are the two deployment shapes most likely to be
/// used together — one endpoint over several catalogs, run with more than one
/// pod — so they are exercised together.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_postgres_backed_mount_works_across_replicas() {
    use rustberg::catalog::{Capabilities, CatalogStore, Mount, PostgresCatalog};
    use std::sync::Arc;

    let cluster = Cluster::start().await;
    let (admin_key, admin) = key("admin", "admin");

    let mount_warehouse = tempfile::tempdir().expect("mount warehouse");
    let mount_warehouse_url = rustberg::location::url_from_path(mount_warehouse.path());

    // Each replica opens its own handle on the mounted catalog, exactly as it
    // does on its own.
    let replica = |keys: Vec<ApiKey>| {
        let dsn = cluster.dsn.clone();
        let warehouse = rustberg::location::url_from_path(cluster.warehouse.path());
        let mount_warehouse_url = mount_warehouse_url.clone();
        async move {
            let mounted = PostgresCatalog::connect(&dsn, &mount_warehouse_url)
                .await
                .expect("connect mounted catalog");

            App::builder()
                .with_catalog_url(&dsn)
                .with_warehouse_location(warehouse)
                .with_default_tenant_id("acme")
                .with_policies(POLICIES)
                .with_api_keys(keys)
                .with_mounts(vec![Mount {
                    name: "prod".to_string(),
                    store: Arc::new(mounted) as Arc<dyn CatalogStore>,
                    capabilities: Capabilities::full(),
                    owner: "acme".to_string(),
                    warehouse: Some(mount_warehouse_url),
                }])
                .build_with_api_keys()
                .await
                .expect("build replica")
                .0
        }
    };

    let a = replica(vec![admin_key.clone()]).await;
    let b = replica(vec![admin_key]).await;

    let (status, body) = send(
        &a,
        Method::POST,
        "/v1/namespaces",
        &admin,
        Some(json!({ "namespace": ["prod", "db"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &a,
        Method::POST,
        "/v1/namespaces/prod%1Fdb/tables",
        &admin,
        Some(json!({ "name": "events", "schema": schema() })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create through a mount on A: {body}"
    );

    let (status, body) = send(
        &b,
        Method::GET,
        "/v1/namespaces/prod%1Fdb/tables/events",
        &admin,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a mounted table created on A must be visible on B: {body}"
    );
}
