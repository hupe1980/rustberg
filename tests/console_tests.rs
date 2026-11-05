//! The console: served from the binary, public, under its own content security policy — and never
//! loosening the one every API response carries.

#![cfg(feature = "ui")]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rustberg::App;
use tower::ServiceExt;

async fn get(app: &App, uri: &str) -> axum::response::Response {
    app.clone()
        .into_router()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn app(console: bool) -> App {
    App::builder()
        .with_catalog_url("memory://")
        .with_console(console)
        .build()
        .await
        .expect("build app")
}

fn csp(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// The page can run its own script and talk to this origin, and nothing else — and it can never be
/// framed, which is what keeps a policy editor out of a clickjacking page.
#[tokio::test]
async fn the_console_is_served_with_its_own_csp() {
    let app = app(true).await;
    for uri in ["/ui", "/ui/"] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let policy = csp(&response);
        assert!(policy.contains("default-src 'self'"), "{uri}: {policy}");
        assert!(policy.contains("script-src 'self'"), "{uri}: {policy}");
        assert!(policy.contains("frame-ancestors 'none'"), "{uri}: {policy}");
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html"),
            "{uri}"
        );
    }
}

/// Serving a page that runs script must not loosen what every API response says: an API response is
/// data, and `default-src 'none'` is what keeps a browser from ever executing it.
#[tokio::test]
async fn api_responses_keep_default_src_none() {
    let app = app(true).await;
    let response = get(&app, "/health").await;
    assert_eq!(
        csp(&response),
        "default-src 'none'; frame-ancestors 'none'",
        "the console's policy leaked onto the API"
    );
}

/// A file is served by its exact name or not at all: no directory walk, no traversal, no index.
#[tokio::test]
async fn only_embedded_files_are_served() {
    let app = app(true).await;
    for uri in [
        "/ui/nope.js",
        "/ui/../Cargo.toml",
        "/ui/%2e%2e/Cargo.toml",
        "/ui/src/main.ts",
    ] {
        let response = get(&app, uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

/// An operator who wants a headless server switches the console off, and the routes are gone.
#[tokio::test]
async fn switching_the_console_off_removes_its_routes() {
    let app = app(false).await;
    let response = get(&app, "/ui/").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// After an upgrade a browser must not mix an old script into a new console: the page is revalidated every
/// time and names files by content hash, and those are cached for good.
#[tokio::test]
async fn the_page_is_revalidated_and_its_files_are_immutable() {
    let app = app(true).await;
    let index = get(&app, "/ui/").await;
    assert_eq!(index.headers()[header::CACHE_CONTROL], "no-cache");

    let body = axum::body::to_bytes(index.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    // A debug build without the console serves a fallback page naming no files; nothing more to check.
    let Some(start) = html.find("/ui/app-") else {
        return;
    };
    let script = &html[start..start + html[start..].find('"').unwrap()];
    let asset = get(&app, script).await;
    assert_eq!(asset.status(), StatusCode::OK, "{script}");
    assert_eq!(
        asset.headers()[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
}
