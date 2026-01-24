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
