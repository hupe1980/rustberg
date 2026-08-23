//! Request extractors for the catalog API: path segments and JSON bodies.
//!
//! Every route is served twice — as `/v1/...` and as `/v1/{prefix}/...` — so the
//! number of path parameters differs between the two. Positional extraction
//! (`Path<(String, String)>`) therefore cannot be used: under the prefixed route
//! it sees an extra segment and rejects the request.
//!
//! These extractors look parameters up **by name**, which is stable whether or
//! not a prefix is present. They are also the single place the unit-separator
//! encoding of multi-level namespaces is decoded, rather than each handler
//! re-splitting the string itself.

use axum::{
    extract::{FromRequest, FromRequestParts, Path, Request},
    http::{StatusCode, request::Parts},
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::ops::Deref;

use iceberg::{NamespaceIdent, TableIdent};

use super::validation::{validate_name, validate_namespace};
use crate::error::AppError;

/// A JSON body extractor that reports failures in the Iceberg error shape.
///
/// `axum::Json`'s own rejection is a plain-text `422` — it does not go through
/// [`AppError`], so a malformed body produced a response with no `error` object
/// at all. The Iceberg REST spec defines every error as
/// `{"error": {"message", "type", "code"}}`, and a client that parses the error
/// body fails to parse that one, turning a clear "you sent the wrong field" into
/// an unhandled client-side error.
///
/// This maps the rejection onto [`AppError::BadRequest`], which is both the
/// right envelope and the right status: a body the server cannot deserialise is
/// a bad request, not an unprocessable entity.
///
/// The rejection text is passed through. It names fields of Rustberg's own API —
/// `missing field \`namespace\`` — which is exactly what the caller needs and
/// reveals nothing about the server's state.
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|axum::Json(value)| Json(value))
            .map_err(|rejection| AppError::BadRequest(rejection.body_text()))
    }
}

/// Separator for the levels of a multi-level namespace in a path segment.
const NAMESPACE_SEPARATOR: char = '\u{1F}';

type Rejection = (StatusCode, String);

async fn path_params<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
) -> Result<HashMap<String, String>, Rejection> {
    Path::<HashMap<String, String>>::from_request_parts(parts, state)
        .await
        .map(|p| p.0)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {e}")))
}

fn require<'a>(params: &'a HashMap<String, String>, key: &str) -> Result<&'a str, Rejection> {
    params.get(key).map(String::as_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Missing path parameter: {key}"),
        )
    })
}

/// Decodes and validates a multi-level namespace from a path segment.
fn parse_namespace(raw: &str) -> Result<NamespaceIdent, Rejection> {
    let parts: Vec<String> = raw.split(NAMESPACE_SEPARATOR).map(str::to_string).collect();

    // Rejects path traversal, null bytes, control characters, reserved names and
    // over-deep namespaces before any of it reaches storage.
    validate_namespace(&parts).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    NamespaceIdent::from_vec(parts)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid namespace: {e}")))
}

/// The `{namespace}` path segment, decoded and validated.
pub struct NamespacePath(pub NamespaceIdent);

impl<S: Send + Sync> FromRequestParts<S> for NamespacePath {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let params = path_params(parts, state).await?;
        Ok(NamespacePath(parse_namespace(require(
            &params,
            "namespace",
        )?)?))
    }
}

impl Deref for NamespacePath {
    type Target = NamespaceIdent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The `{namespace}` and `{table}` segments as a validated [`TableIdent`].
pub struct TablePath(pub TableIdent);

impl<S: Send + Sync> FromRequestParts<S> for TablePath {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let params = path_params(parts, state).await?;
        let namespace = parse_namespace(require(&params, "namespace")?)?;
        let name = require(&params, "table")?;

        validate_name(name, "Table name").map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        Ok(TablePath(TableIdent::new(namespace, name.to_string())))
    }
}

impl Deref for TablePath {
    type Target = TableIdent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The `{namespace}` and `{view}` segments as a validated [`TableIdent`].
///
/// Views share `TableIdent`: at the identifier level a view is a named object in
/// a namespace, exactly as a table is.
pub struct ViewPath(pub TableIdent);

impl<S: Send + Sync> FromRequestParts<S> for ViewPath {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let params = path_params(parts, state).await?;
        let namespace = parse_namespace(require(&params, "namespace")?)?;
        let name = require(&params, "view")?;

        validate_name(name, "View name").map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        Ok(ViewPath(TableIdent::new(namespace, name.to_string())))
    }
}

impl Deref for ViewPath {
    type Target = TableIdent;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
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
