use axum::{
    extract::{FromRequestParts, Path},
    http::{request::Parts, StatusCode},
};
use std::ops::Deref;

use iceberg::NamespaceIdent;

use super::validation::validate_namespace;

pub struct NamespacePath(pub NamespaceIdent);

impl<S> FromRequestParts<S> for NamespacePath
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let path_params = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid namespace path: {err}"),
                )
            })?;

        let raw_namespace = path_params.0;

        let namespace_parts: Vec<String> =
            raw_namespace.split('\u{1F}').map(str::to_string).collect();

        if namespace_parts.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Empty namespace".into()));
        }

        // SEC-025: Validate namespace parts against security rules
        // (path traversal, null bytes, control chars, reserved names, etc.)
        if let Err(e) = validate_namespace(&namespace_parts) {
            return Err((StatusCode::BAD_REQUEST, e.to_string()));
        }

        // Safely create a NamespaceIdent
        match NamespaceIdent::from_vec(namespace_parts) {
            Ok(ident) => Ok(NamespacePath(ident)),
            Err(err) => Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!("Invalid namespace: {}", err),
            )),
        }
    }
}

impl Deref for NamespacePath {
    type Target = NamespaceIdent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Helper: build a minimal router that exercises `NamespacePath` and returns
    /// either the parsed parts (200) or the rejection message (4xx).
    fn test_router() -> Router {
        async fn handler(ns: NamespacePath) -> String {
            ns.0.iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("|")
        }
        Router::new().route("/v1/namespaces/{namespace}", get(handler))
    }

    async fn call(router: &Router, path: &str) -> (StatusCode, String) {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body).to_string();
        (status, text)
    }

    // ========================================================================
    // Happy-path tests
    // ========================================================================

    #[tokio::test]
    async fn test_single_level_namespace() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/production").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "production");
    }

    #[tokio::test]
    async fn test_multi_level_namespace() {
        // \u{1F} is the unit separator used by Iceberg REST spec for hierarchical namespaces
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/db%1Fschema%1Ftable_zone").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "db|schema|table_zone");
    }

    #[tokio::test]
    async fn test_namespace_with_hyphens_and_dots() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/my-db.v2").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "my-db.v2");
    }

    // ========================================================================
    // Rejection tests — security-relevant input validation
    // ========================================================================

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let router = test_router();
        // URL-encoded ".." = %2E%2E
        let (status, body) = call(&router, "/v1/namespaces/%2E%2E").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("traversal") || body.contains("dot"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_null_byte_rejected() {
        let router = test_router();
        // URL-encoded null = %00
        let (status, body) = call(&router, "/v1/namespaces/test%00ns").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("null") || body.contains("control"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_control_char_rejected() {
        let router = test_router();
        // Tab = %09
        let (status, body) = call(&router, "/v1/namespaces/test%09ns").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("control"), "body: {body}");
    }

    #[tokio::test]
    async fn test_windows_reserved_name_rejected() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/CON").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("reserved") || body.contains("Windows"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_hidden_name_rejected() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/.hidden").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("dot"), "body: {body}");
    }

    #[tokio::test]
    async fn test_invalid_chars_rejected() {
        let router = test_router();
        // Space in namespace
        let (status, body) = call(&router, "/v1/namespaces/my%20ns").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("invalid") || body.contains("character"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_multi_level_with_traversal_rejected() {
        let router = test_router();
        // db + \x1F + ..
        let (status, body) = call(&router, "/v1/namespaces/db%1F%2E%2E").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("traversal") || body.contains("dot"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_too_deep_namespace_rejected() {
        let router = test_router();
        // 15 levels separated by \x1F — exceeds MAX_NAMESPACE_DEPTH (10)
        let levels: Vec<&str> = (0..15).map(|_| "level").collect();
        let path = format!("/v1/namespaces/{}", levels.join("%1F"));
        let (status, body) = call(&router, &path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("depth") || body.contains("maximum"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn test_overlong_name_rejected() {
        let router = test_router();
        let long = "a".repeat(300);
        let path = format!("/v1/namespaces/{long}");
        let (status, body) = call(&router, &path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("maximum length") || body.contains("exceeds"),
            "body: {body}"
        );
    }
}
