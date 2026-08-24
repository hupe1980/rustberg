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
    http::request::Parts,
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::ops::Deref;

use iceberg::{NamespaceIdent, TableIdent};

use crate::error::AppError;
use crate::names::{validate_name, validate_namespace};

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
use crate::names::PART_SEPARATOR as NAMESPACE_SEPARATOR;

/// Path rejections go through [`AppError`] for the same reason [`Json`]'s do.
///
/// Axum's own rejection is plain text, and the Iceberg REST spec defines *every*
/// error as `{"error": {"message", "type", "code"}}`. A client that parses the
/// error body fails to parse a bare string, so "you sent an invalid namespace"
/// arrives as an unhandled client-side error instead of the sentence it is.
type Rejection = AppError;

/// A path that could not be read, in the Iceberg error shape.
fn bad_path(message: impl Into<String>) -> Rejection {
    AppError::BadRequest(message.into())
}

async fn path_params<S: Send + Sync>(
    parts: &mut Parts,
    state: &S,
) -> Result<HashMap<String, String>, Rejection> {
    Path::<HashMap<String, String>>::from_request_parts(parts, state)
        .await
        .map(|p| p.0)
        .map_err(|e| bad_path(format!("Invalid path: {e}")))
}

fn require<'a>(params: &'a HashMap<String, String>, key: &str) -> Result<&'a str, Rejection> {
    params
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| bad_path(format!("Missing path parameter: {key}")))
}

/// Decodes and validates a multi-level namespace from a path segment.
fn parse_namespace(raw: &str) -> Result<NamespaceIdent, Rejection> {
    let parts: Vec<String> = raw.split(NAMESPACE_SEPARATOR).map(str::to_string).collect();

    // Rejects path traversal, null bytes, control characters, reserved names and
    // over-deep namespaces before any of it reaches storage.
    // Already an `AppError` with the right shape; passed through rather than
    // restated, so the sentence a caller reads is the one the validator wrote.
    validate_namespace(&parts)?;

    NamespaceIdent::from_vec(parts).map_err(|e| bad_path(format!("Invalid namespace: {e}")))
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

        validate_name(name, "Table name")?;

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

        validate_name(name, "View name")?;

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
    use axum::http::StatusCode;
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

    /// A rejected path answers in the Iceberg error shape, like every other
    /// error this server produces.
    ///
    /// Axum's own path rejection is plain text. A client parses `error.message`
    /// out of a JSON envelope and gets a parse failure instead — turning "your
    /// namespace has a `..` in it" into an unhandled client-side error. The body
    /// extractor was fixed for this and the path extractors were not, which is
    /// the half a caller reaches by typo rather than by writing wrong code.
    #[tokio::test]
    async fn a_rejected_path_answers_in_the_iceberg_error_shape() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/analytics%1F..").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"));
        assert_eq!(parsed["error"]["code"], 400, "{body}");
        assert!(
            parsed["error"]["message"].is_string(),
            "an error carries a message: {body}"
        );
        assert!(
            parsed["error"]["type"].is_string(),
            "an error carries a type: {body}"
        );
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let router = test_router();
        // URL-encoded ".." = %2E%2E
        let (status, body) = call(&router, "/v1/namespaces/%2E%2E").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("directory"), "body: {body}");
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

    /// A path separator inside a segment would place the table somewhere other
    /// than where the catalog recorded it.
    #[tokio::test]
    async fn an_encoded_separator_inside_a_segment_is_rejected() {
        let router = test_router();
        let (status, body) = call(&router, "/v1/namespaces/my%2Fns").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("path separator"), "body: {body}");
    }

    /// Names Iceberg permits reach the handler rather than being refused at the
    /// door. An allowlist narrow enough to reject these protects nothing.
    #[tokio::test]
    async fn ordinary_names_other_catalogs_accept_are_not_refused() {
        let router = test_router();
        for (path, expected) in [
            ("/v1/namespaces/my%20ns", "my ns"),
            ("/v1/namespaces/CON", "CON"),
            ("/v1/namespaces/.hidden", ".hidden"),
            ("/v1/namespaces/%E5%88%86%E6%9E%90", "分析"),
        ] {
            let (status, body) = call(&router, path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(body, expected);
        }
    }

    #[tokio::test]
    async fn test_multi_level_with_traversal_rejected() {
        let router = test_router();
        // db + \x1F + ..
        let (status, body) = call(&router, "/v1/namespaces/db%1F%2E%2E").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("directory"), "body: {body}");
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
