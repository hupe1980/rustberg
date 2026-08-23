//! The four numbers this project publishes, measured and gated.
//!
//! # These gate regressions, not machines
//!
//! Each budget carries a design target *and* a much looser ceiling. CI runners
//! are shared and noisy, and a gate that flakes gets disabled — at which point
//! it protects nothing at all. The ceilings catch order-of-magnitude
//! regressions, the kind that come from an accidental clone in a hot path or a
//! lock held across an await. The measured value is printed either way, so the
//! truth about where the number sits is always visible.
//!
//! Run them:
//!
//! ```text
//! cargo test --all-features --test performance_tests -- --ignored --nocapture
//! ```
//!
//! They are `#[ignore]`d so an ordinary `cargo test` stays fast; CI runs them
//! explicitly.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rustberg::App;
use rustberg::auth::{
    Action, AuthMethod, Authorizer, AuthzContext, CedarAuthorizer, PrincipalBuilder, PrincipalType,
    Resource,
};
use rustberg::observability::perf::{Budget, Measurement, measure, measure_async};
use serde_json::json;
use tower::ServiceExt;

/// Samples per measurement. Enough that a p99 means something, small enough
/// that the suite stays quick.
const SAMPLES: usize = 500;

/// Reports a measurement and fails when it is over budget.
fn gate(measurement: Measurement, budget: Budget) {
    println!("{}", measurement.describe());

    if measurement.p99 > budget.target {
        // Not a failure: the target is what the architecture aims at, the
        // ceiling is what breaks the build. Saying so keeps the two distinct.
        println!(
            "   note: over the {:?} design target, under the {:?} ceiling",
            budget.target, budget.ceiling
        );
    }

    assert!(
        budget.admits(&measurement),
        "{}",
        budget.explain(&measurement)
    );
}

const POLICIES: &str = r#"
    permit(principal in Rustberg::Group::"admin", action, resource)
      when { resource.tenant == principal.tenant };

    permit(
      principal in Rustberg::Group::"reader",
      action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
      resource
    ) when { resource.tenant == principal.tenant };

    forbid(principal, action == Rustberg::Action::"Delete", resource)
      when { context.utc_hour < 6 };
"#;

fn authz_context() -> AuthzContext {
    let principal = PrincipalBuilder::new(
        "bench-user",
        "Bench",
        PrincipalType::User,
        "acme",
        AuthMethod::ApiKey,
    )
    .with_role("reader")
    .build();

    AuthzContext::new(
        principal,
        Resource::table("acme", ["analytics", "web"], "events"),
        Action::Read,
    )
}

/// **Authorization overhead.** Target < 1 ms p99 for a point operation.
///
/// This runs on every single request, so it is the number with the most
/// leverage: a regression here is paid by everything.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn authorization_stays_under_budget() {
    let authorizer = Arc::new(CedarAuthorizer::new(POLICIES).expect("policies compile"));
    let context = authz_context();

    let measurement = measure_async("authorization (point op)", SAMPLES, || {
        let authorizer = authorizer.clone();
        let context = context.clone();
        async move {
            let outcome = authorizer.decide(&context).await;
            assert!(outcome.is_allowed(), "the benchmark must exercise a permit");
        }
    })
    .await;

    gate(
        measurement,
        Budget::new(Duration::from_millis(1), Duration::from_millis(10)),
    );
}

/// **`loadTable` p99.** Target < 5 ms native.
///
/// Measured through the whole HTTP stack — routing, authentication,
/// authorization, catalog read, metadata parse, serialisation — because that is
/// what a client waits for.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn load_table_stays_under_budget() {
    let app = App::builder()
        .with_warehouse_location("memory://bench")
        .with_default_tenant_id("default")
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["bench"] })),
    )
    .await;
    send(
        &app,
        Method::POST,
        "/v1/namespaces/bench/tables",
        Some(json!({
            "name": "events",
            "schema": {
                "type": "struct",
                "fields": [
                    { "id": 1, "name": "id", "required": true, "type": "long" },
                    { "id": 2, "name": "ts", "required": false, "type": "timestamp" },
                    { "id": 3, "name": "payload", "required": false, "type": "string" }
                ]
            }
        })),
    )
    .await;

    let measurement = measure_async("loadTable (full stack)", SAMPLES, || {
        let app = app.clone();
        async move {
            let status = send(
                &app,
                Method::GET,
                "/v1/namespaces/bench/tables/events",
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "the benchmark must exercise a hit");
        }
    })
    .await;

    gate(
        measurement,
        Budget::new(Duration::from_millis(5), Duration::from_millis(50)),
    );
}

/// **Conditional `loadTable`.** No stated target; reported because it is the
/// point of `ETag` support.
///
/// This only *reports*. What a `304` skips is the metadata fetch, and on a
/// laptop with a warm page cache that fetch is nearly free — so a timing
/// assertion here would measure scheduler noise and flake. The saving is real
/// and grows with warehouse latency, which is exactly the case a local
/// benchmark cannot reproduce.
///
/// The property is proved deterministically instead, in
/// `integration_tests::a_conditional_load_never_reads_the_metadata_document`:
/// a `304` is answered correctly after the metadata file has been deleted,
/// which is only possible if the path never touches it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn conditional_and_full_loads_are_reported() {
    let warehouse = tempfile::tempdir().expect("temp dir");
    let app = App::builder()
        .with_warehouse_location(format!("file://{}", warehouse.path().display()))
        .with_default_tenant_id("default")
        .build()
        .await
        .expect("build app");

    send(
        &app,
        Method::POST,
        "/v1/namespaces",
        Some(json!({ "namespace": ["bench"] })),
    )
    .await;
    send(
        &app,
        Method::POST,
        "/v1/namespaces/bench/tables",
        Some(json!({
            "name": "events",
            "schema": { "type": "struct", "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }] }
        })),
    )
    .await;

    let response = app
        .clone()
        .into_router()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/namespaces/bench/tables/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag = response
        .headers()
        .get("etag")
        .expect("loadTable names the version")
        .to_str()
        .unwrap()
        .to_string();

    let full = measure_async("loadTable 200", SAMPLES, || {
        let app = app.clone();
        async move {
            send(
                &app,
                Method::GET,
                "/v1/namespaces/bench/tables/events",
                None,
            )
            .await;
        }
    })
    .await;

    let conditional = measure_async("loadTable 304", SAMPLES, || {
        let app = app.clone();
        let etag = etag.clone();
        async move {
            let response = app
                .into_router()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/v1/namespaces/bench/tables/events")
                        .header("If-None-Match", etag)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        }
    })
    .await;

    println!("{}", full.describe());
    println!("{}", conditional.describe());
}

/// **Cold start.** Target < 100 ms to serving, policy compiled and validated.
///
/// Measured as build-to-first-successful-request, which is what "to serving"
/// means: a process that has bound a port but cannot answer is not serving.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn cold_start_stays_under_budget() {
    // Fewer samples: each one builds a whole application including a fresh
    // catalog, and the number is stable enough not to need five hundred.
    const STARTS: usize = 20;

    let mut samples = Vec::with_capacity(STARTS);
    for _ in 0..STARTS {
        let started = Instant::now();

        let app = App::builder()
            .with_warehouse_location("memory://bench")
            .with_default_tenant_id("default")
            .with_policies(POLICIES)
            .build()
            .await
            .expect("build app");

        let status = send(&app, Method::GET, "/v1/config", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "cold start ends at the first answer"
        );

        samples.push(started.elapsed());
    }

    gate(
        Measurement::from_samples("cold start (to first answer)", samples),
        Budget::new(Duration::from_millis(100), Duration::from_millis(1000)),
    );
}

/// **Policy compilation.** Not published, but it is inside cold start and is
/// the part that grows with a deployment's policy set.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn policy_compilation_stays_under_budget() {
    let measurement = measure("policy compile + validate", 100, || {
        CedarAuthorizer::new(POLICIES).expect("policies compile");
    });

    gate(
        measurement,
        Budget::new(Duration::from_millis(50), Duration::from_millis(500)),
    );
}

/// **Footprint.** Target < 50 MB RSS idle.
///
/// Reported on Linux, where CI runs. Elsewhere the number cannot be read
/// without platform-specific unsafe code, and this crate will not carry that
/// for a diagnostic — so it is skipped rather than guessed at.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "performance gate; run with --ignored"]
async fn idle_footprint_stays_under_budget() {
    let _app = App::builder()
        .with_warehouse_location("memory://bench")
        .with_default_tenant_id("default")
        .with_policies(POLICIES)
        .build()
        .await
        .expect("build app");

    match rustberg::observability::perf::resident_bytes() {
        Some(bytes) => {
            let mib = bytes as f64 / (1024.0 * 1024.0);
            println!("{:<28} {mib:.1} MiB resident", "idle footprint");

            // Generous, for the same reason the latency ceilings are: this
            // catches a leak or an accidental preallocation, not a busy runner.
            assert!(
                mib < 250.0,
                "idle footprint is {mib:.1} MiB, far over the 50 MiB target — \
                 something is being held that should not be"
            );
        }
        None => println!("idle footprint: not measurable on this platform; skipped"),
    }
}

/// Issues a request and returns its status.
async fn send(app: &App, method: Method, uri: &str, body: Option<serde_json::Value>) -> StatusCode {
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

    app.clone()
        .into_router()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}
