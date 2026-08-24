//! Application error types and error response formatting.
//!
//! This module defines error types that map to Iceberg REST Catalog API
//! error responses, ensuring consistent error handling across the service.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Result type alias using AppError.
pub type Result<T, E = AppError> = std::result::Result<T, E>;

/// Inner error model following Iceberg REST Catalog specification.
#[derive(Debug, Serialize)]
pub struct ErrorModel {
    /// Human-readable error message.
    pub message: String,
    /// Error type identifier (e.g., "NoSuchNamespaceException").
    #[serde(rename = "type")]
    pub error_type: String,
    /// HTTP status code.
    pub code: u16,
    /// Always empty, and serialised only for spec shape.
    ///
    /// The spec allows a stack trace here. Rustberg never sends one: a trace
    /// names source paths and symbols, and this field goes to whoever made the
    /// failing request — including one that failed *because* it was not
    /// permitted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<String>,
}

/// Error response wrapper following Iceberg REST Catalog specification.
/// All error responses are wrapped in an "error" key per the spec.
#[derive(Debug, Serialize)]
pub struct IcebergErrorResponse {
    /// The error details.
    pub error: ErrorModel,
}

/// Application error types.
///
/// These errors are designed to match the Iceberg REST Catalog API
/// specification for consistent client behavior.

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    // ========================================================================
    // 400 Bad Request
    // ========================================================================
    /// The request is wrong, and the message says how.
    ///
    /// One variant for every `400`, because a caller cannot act on a finer
    /// distinction than `BadRequestException`: splitting it by *kind* of
    /// wrongness would be a fork in every `match` that buys nothing on the wire.
    /// What makes an error useful is the sentence, not the variant.
    ///
    /// And the message is that sentence, unprefixed — `"The namespace contains
    /// U+200B, which…"`, not `"Bad request: the namespace contains…"` beside a
    /// `type` that already says so. A prefix belongs to the variants whose
    /// payload is a bare identifier, where `Table does not exist:
    /// analytics.events` is the whole sentence and the prefix is the verb.
    #[error("{0}")]
    BadRequest(String),

    // ========================================================================
    // 401 Unauthorized errors
    // ========================================================================
    /// Authentication required but not provided.
    #[error("Authentication required")]
    Unauthenticated,

    /// Invalid credentials provided.
    #[error("Invalid credentials")]
    InvalidCredentials,

    // ========================================================================
    // 403 Forbidden errors
    // ========================================================================
    /// Access denied due to insufficient permissions.
    /// Carries a sentence, so it carries no prefix — see [`AppError::BadRequest`].
    #[error("{0}")]
    Forbidden(String),

    // ========================================================================
    // 404 Not Found errors
    // ========================================================================
    /// Requested namespace does not exist.
    #[error("Namespace does not exist: {0}")]
    NoSuchNamespace(String),

    /// Requested table does not exist.
    #[error("Table does not exist: {0}")]
    NoSuchTable(String),

    /// Requested view does not exist.
    #[error("View does not exist: {0}")]
    NoSuchView(String),

    /// Requested snapshot does not exist.
    #[error("{0}")]
    NoSuchSnapshot(String),

    /// Requested reference (branch/tag) does not exist.
    #[error("Reference does not exist: {0}")]
    NoSuchReference(String),

    /// Requested scan plan does not exist.
    #[error("{0}")]
    NoSuchPlan(String),

    /// Requested scan plan task does not exist.
    #[error("{0}")]
    NoSuchPlanTask(String),

    // ========================================================================
    // 406 Not Acceptable / Unsupported Operation
    // ========================================================================
    /// Operation not supported by the server.
    ///
    /// Carries a sentence, so it carries no prefix — see [`AppError::BadRequest`].
    #[error("{0}")]
    NotSupported(String),

    // ========================================================================
    // 409 Conflict errors
    // ========================================================================
    /// Namespace already exists.
    #[error("Namespace already exists: {0}")]
    NamespaceAlreadyExists(String),

    /// Table already exists.
    #[error("Table already exists: {0}")]
    TableAlreadyExists(String),

    /// View already exists.
    #[error("View already exists: {0}")]
    ViewAlreadyExists(String),

    /// Concurrent modification conflict.
    ///
    /// Carries a sentence, so it carries no prefix — see [`AppError::BadRequest`].
    #[error("{0}")]
    CommitConflict(String),

    /// Namespace is not empty (cannot be deleted).
    #[error("Namespace not empty: {0}")]
    NamespaceNotEmpty(String),

    /// The resource is marked protected from deletion.
    ///
    /// `409` rather than `403`: the caller is permitted, and the resource is in
    /// a state that forbids the operation.
    #[error("{0}")]
    Protected(String),

    // ========================================================================
    // 429 Too Many Requests
    // ========================================================================
    /// The caller exceeded its rate limit.
    #[error("Rate limit exceeded")]
    RateLimited,

    // ========================================================================
    // 422 Unprocessable Entity errors
    // ========================================================================
    /// Request is syntactically correct but semantically invalid.
    ///
    /// Carries a sentence, so it carries no prefix — see [`AppError::BadRequest`].
    #[error("{0}")]
    UnprocessableEntity(String),

    // ========================================================================
    // 500 Internal Server Error
    // ========================================================================
    /// Unexpected internal error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// IO error during storage operations.
    #[error("Storage error: {0}")]
    StorageError(String),

    // ========================================================================
    // 503 Service Unavailable
    // ========================================================================
    /// Service is temporarily unavailable.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

/// Error type for a path this catalog does not route.
///
/// Not an [`AppError`] variant, because nothing *raises* it: it is filled in by
/// the outermost layer for a response the router already produced. It lives here
/// so every `type` string this server can emit is in one file — which is what
/// `every_error_type_is_documented` reads.
pub const NOT_FOUND_TYPE: &str = "NotFoundException";

/// Error type for a routed path called with the wrong method. See
/// [`NOT_FOUND_TYPE`].
pub const METHOD_NOT_ALLOWED_TYPE: &str = "MethodNotAllowedException";

/// The **only** `type` a rejected credential is answered with.
///
/// Naming the reason is a credential oracle. The API key path is constant-time
/// on purpose — a lookup that misses still verifies against a dummy hash, so
/// timing cannot separate a real prefix from an invented one — and `disabled`
/// and `expired` are reachable only *after* that comparison succeeds, so either
/// one is a positive answer to "is this key real". That is what somebody working
/// through a dump of leaked credentials is asking.
///
/// So every rejection answers identically and the reason goes to the audit
/// record, where the operator can read it and nobody can probe it.
///
/// Named here beside the constants above because every `type` string this server
/// can emit belongs in one file — which is what `every_error_type_is_documented`
/// reads, across both `error_type` matches.
pub const UNAUTHORIZED_TYPE: &str = "NotAuthorizedException";

/// The **only** `type` a rate-limited request is answered with.
///
/// One string, named once, so a client feature-detecting on `error.type` sees
/// the same thing whichever layer refused it — this crate's error enum or the
/// rate limiter's own response.
pub const RATE_LIMITED_TYPE: &str = "TooManyRequestsException";

/// The challenge every `401` carries.
///
/// RFC 9110 §11.6.1 makes this a **MUST**: a `401` without a
/// `WWW-Authenticate` header is not a well-formed refusal, and a client that
/// negotiates its scheme from the challenge — `curl --anyauth`, a generated
/// OpenAPI client, anything driven by an HTTP library's auth layer — is left
/// with a status code and no way to know what to send.
///
/// `Bearer` is the accurate challenge for **both** mechanisms rather than a
/// convenient approximation of one: the API key path reads
/// `Authorization: Bearer <key>` as readily as it reads `X-API-Key`, which is
/// what lets a client configured with PyIceberg's `token` property work against
/// a key-only deployment. `X-API-Key` is a header and not an auth scheme, so it
/// cannot appear here; the refusal's own sentence names it.
///
/// No `error=` parameter. RFC 6750 allows one, and it would separate "you sent
/// no token" from "the token you sent is bad" — a distinction the caller already
/// holds, since it chose what to send, but not one worth spending the rule in
/// [`UNAUTHORIZED_TYPE`] on for a parameter nothing reads.
pub const WWW_AUTHENTICATE_CHALLENGE: &str = "Bearer realm=\"rustberg\"";

impl AppError {
    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            // 400 Bad Request
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,

            // 401 Unauthorized
            AppError::Unauthenticated | AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,

            // 403 Forbidden
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,

            // 404 Not Found
            AppError::NoSuchNamespace(_)
            | AppError::NoSuchTable(_)
            | AppError::NoSuchView(_)
            | AppError::NoSuchSnapshot(_)
            | AppError::NoSuchReference(_)
            | AppError::NoSuchPlan(_)
            | AppError::NoSuchPlanTask(_) => StatusCode::NOT_FOUND,

            // 501 Not Implemented — the operation is understood but unsupported.
            // (406 would claim a content-negotiation failure, which this is not.)
            AppError::NotSupported(_) => StatusCode::NOT_IMPLEMENTED,

            // 409 Conflict
            AppError::NamespaceAlreadyExists(_)
            | AppError::TableAlreadyExists(_)
            | AppError::ViewAlreadyExists(_)
            | AppError::CommitConflict(_)
            | AppError::NamespaceNotEmpty(_)
            | AppError::Protected(_) => StatusCode::CONFLICT,

            // 429 Too Many Requests
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,

            // 422 Unprocessable Entity
            AppError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,

            // 500 Internal Server Error
            AppError::Internal(_) | AppError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // 503 Service Unavailable
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Returns the error type string for the response body.
    pub fn error_type(&self) -> &'static str {
        match self {
            AppError::BadRequest(_) => "BadRequestException",
            AppError::Unauthenticated | AppError::InvalidCredentials => UNAUTHORIZED_TYPE,
            AppError::Forbidden(_) => "ForbiddenException",
            AppError::NoSuchNamespace(_) => "NoSuchNamespaceException",
            AppError::NoSuchTable(_) => "NoSuchTableException",
            AppError::NoSuchView(_) => "NoSuchViewException",
            AppError::NoSuchSnapshot(_) => "NoSuchSnapshotException",
            AppError::NoSuchReference(_) => "NoSuchReferenceException",
            AppError::NoSuchPlan(_) => "NoSuchPlanIdException",
            AppError::NoSuchPlanTask(_) => "NoSuchPlanTaskException",
            AppError::NotSupported(_) => "UnsupportedOperationException",
            AppError::NamespaceAlreadyExists(_) => "AlreadyExistsException",
            AppError::TableAlreadyExists(_) => "AlreadyExistsException",
            AppError::ViewAlreadyExists(_) => "AlreadyExistsException",
            AppError::CommitConflict(_) => "CommitFailedException",
            AppError::NamespaceNotEmpty(_) => "NamespaceNotEmptyException",
            AppError::Protected(_) => "ProtectedException",
            AppError::RateLimited => RATE_LIMITED_TYPE,
            AppError::UnprocessableEntity(_) => "UnprocessableEntityException",
            AppError::Internal(_) => "InternalServerError",
            AppError::StorageError(_) => "InternalServerError",
            AppError::ServiceUnavailable(_) => "ServiceUnavailableException",
        }
    }
}

/// Converts from AuthError to AppError.
///
/// **Security Note**: Authentication failure details are intentionally hidden
/// to prevent credential enumeration attacks. All auth failures return generic
/// "Invalid credentials" to clients.
impl From<crate::auth::AuthError> for AppError {
    fn from(err: crate::auth::AuthError) -> Self {
        use crate::auth::AuthError;

        match err {
            AuthError::Unauthenticated => AppError::Unauthenticated,
            // All credential failures map to generic InvalidCredentials
            // to prevent credential enumeration attacks
            AuthError::InvalidCredentials(_)
            | AuthError::TokenExpired
            | AuthError::MalformedToken(_)
            | AuthError::ApiKeyNotFound
            | AuthError::ApiKeyDisabled
            | AuthError::ExpiredCredentials
            | AuthError::InvalidToken(_) => AppError::InvalidCredentials,
            AuthError::Forbidden(msg) => AppError::Forbidden(msg),
            AuthError::ResourceNotFound(msg) => AppError::NoSuchNamespace(msg),
            AuthError::RateLimitExceeded => AppError::RateLimited,
            AuthError::StorageError(msg) => AppError::StorageError(msg),
            AuthError::External(msg) => {
                AppError::ServiceUnavailable(format!("External service error: {}", msg))
            }
            AuthError::Configuration(msg) => {
                AppError::Internal(format!("Configuration error: {}", msg))
            }
            AuthError::Internal(msg) => AppError::Internal(msg),
        }
    }
}

/// Converts from iceberg::Error to AppError.
impl From<iceberg::Error> for AppError {
    fn from(err: iceberg::Error) -> Self {
        use iceberg::ErrorKind;

        match err.kind() {
            // Matched on kind, never on message text: a status code that
            // depends on wording changes when someone rewords an error.
            ErrorKind::NamespaceNotFound => AppError::NoSuchNamespace(err.message().to_string()),
            ErrorKind::TableNotFound => AppError::NoSuchTable(err.message().to_string()),
            ErrorKind::NamespaceAlreadyExists => {
                AppError::NamespaceAlreadyExists(err.message().to_string())
            }
            ErrorKind::TableAlreadyExists => {
                AppError::TableAlreadyExists(err.message().to_string())
            }
            ErrorKind::CatalogCommitConflicts => {
                AppError::CommitConflict(err.message().to_string())
            }
            // "System is not in a state required for the operation" — the
            // catalog uses this for a namespace that still has children.
            ErrorKind::PreconditionFailed => AppError::NamespaceNotEmpty(err.message().to_string()),
            ErrorKind::FeatureUnsupported => AppError::NotSupported(err.message().to_string()),
            ErrorKind::DataInvalid => AppError::BadRequest(err.message().to_string()),
            ErrorKind::Unexpected => AppError::Internal(err.message().to_string()),
            // ErrorKind is #[non_exhaustive]; a kind added upstream is an
            // internal error rather than a guess at its meaning.
            _ => AppError::Internal(format!("Iceberg error: {}", err.message())),
        }
    }
}

impl IntoResponse for AppError {
    /// Renders the error as the spec's `IcebergErrorResponse`.
    ///
    /// # What the client is told, and what the operator is told
    ///
    /// A failure that is the *caller's* — a missing table, a conflict, a
    /// forbidden action — is described in full: the caller supplied the input
    /// and can act on the answer.
    ///
    /// A failure that is the *server's* is described generically, because the
    /// detail is a database host, an object-store key, or a query. That detail
    /// is **logged**, not discarded: a `500` a client cannot read must still be
    /// one an operator can.
    ///
    /// Both halves are unconditional. Keying either on the build profile would
    /// make the behaviour under test differ from the behaviour in production,
    /// which is the one place it matters.
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Sanitised on the wire in every build, and logged in every build.
        let safe_message = match &self {
            AppError::Internal(msg) | AppError::StorageError(msg) => {
                tracing::error!(error = %msg, kind = self.error_type(), "Request failed");
                "An internal error occurred. Check the server log for the cause.".to_string()
            }
            AppError::ServiceUnavailable(msg) => {
                tracing::warn!(error = %msg, "Request refused: a dependency is unavailable");
                "Service temporarily unavailable. Please try again later.".to_string()
            }
            // Never says *which* part of the credential failed.
            AppError::InvalidCredentials => "Invalid credentials provided".to_string(),
            // Everything else describes the caller's own request back to it.
            _ => self.to_string(),
        };

        let body = ErrorModel {
            message: safe_message,
            error_type: self.error_type().to_string(),
            code: status.as_u16(),
            stack: Vec::new(),
        };

        // Wrap in IcebergErrorResponse per Iceberg REST Catalog spec
        let response = IcebergErrorResponse { error: body };

        let mut response = (status, Json(response)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(WWW_AUTHENTICATE_CHALLENGE),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Status Code Tests
    // ========================================================================

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            AppError::BadRequest("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::NoSuchNamespace("ns".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::TableAlreadyExists("t".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::Forbidden("no access".into()).status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn a_bad_request_is_400() {
        assert_eq!(
            AppError::BadRequest("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    /// The message is the whole message: no variant that carries a sentence
    /// prefixes it with a restatement of its own type, which the `type` field
    /// beside it already carries.
    #[test]
    fn a_sentence_carrying_error_does_not_repeat_its_own_type() {
        for error in [
            AppError::BadRequest("Names must be NFC.".into()),
            AppError::Forbidden("Names must be NFC.".into()),
            AppError::NotSupported("Names must be NFC.".into()),
            AppError::CommitConflict("Names must be NFC.".into()),
            AppError::UnprocessableEntity("Names must be NFC.".into()),
            AppError::NoSuchSnapshot("Names must be NFC.".into()),
            AppError::NoSuchPlan("Names must be NFC.".into()),
            AppError::NoSuchPlanTask("Names must be NFC.".into()),
        ] {
            assert_eq!(
                error.to_string(),
                "Names must be NFC.",
                "{:?} pastes a prefix in front of a message that is already a sentence",
                error
            );
        }
    }

    /// And the ones whose payload is a bare identifier keep theirs, because
    /// there the prefix *is* the sentence.
    #[test]
    fn an_identifier_carrying_error_keeps_its_verb() {
        assert_eq!(
            AppError::NoSuchTable("analytics.events".into()).to_string(),
            "Table does not exist: analytics.events"
        );
        assert_eq!(
            AppError::NamespaceNotEmpty("analytics".into()).to_string(),
            "Namespace not empty: analytics"
        );
    }

    #[test]
    fn test_all_401_errors() {
        assert_eq!(
            AppError::Unauthenticated.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::InvalidCredentials.status_code(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn test_all_403_errors() {
        assert_eq!(
            AppError::Forbidden("".into()).status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_all_404_errors() {
        assert_eq!(
            AppError::NoSuchNamespace("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::NoSuchTable("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::NoSuchView("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::NoSuchSnapshot("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::NoSuchReference("".into()).status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_all_409_errors() {
        assert_eq!(
            AppError::NamespaceAlreadyExists("".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::TableAlreadyExists("".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::ViewAlreadyExists("".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::CommitConflict("".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::NamespaceNotEmpty("".into()).status_code(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn test_all_422_errors() {
        assert_eq!(
            AppError::UnprocessableEntity("".into()).status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn test_all_500_errors() {
        assert_eq!(
            AppError::Internal("".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::StorageError("".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_all_503_errors() {
        assert_eq!(
            AppError::ServiceUnavailable("".into()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    // ========================================================================
    // Error Type Tests (Exception names for API compliance)
    // ========================================================================

    #[test]
    fn test_error_types() {
        assert_eq!(
            AppError::NoSuchNamespace("ns".into()).error_type(),
            "NoSuchNamespaceException"
        );
        assert_eq!(
            AppError::NoSuchTable("t".into()).error_type(),
            "NoSuchTableException"
        );
        assert_eq!(
            AppError::CommitConflict("conflict".into()).error_type(),
            "CommitFailedException"
        );
    }

    #[test]
    fn test_error_types_400() {
        assert_eq!(
            AppError::BadRequest("".into()).error_type(),
            "BadRequestException"
        );
    }

    #[test]
    fn test_error_types_401() {
        assert_eq!(
            AppError::Unauthenticated.error_type(),
            "NotAuthorizedException"
        );
        assert_eq!(
            AppError::InvalidCredentials.error_type(),
            "NotAuthorizedException"
        );
    }

    #[test]
    fn test_error_types_403() {
        assert_eq!(
            AppError::Forbidden("".into()).error_type(),
            "ForbiddenException"
        );
    }

    #[test]
    fn test_error_types_404() {
        assert_eq!(
            AppError::NoSuchNamespace("".into()).error_type(),
            "NoSuchNamespaceException"
        );
        assert_eq!(
            AppError::NoSuchTable("".into()).error_type(),
            "NoSuchTableException"
        );
        assert_eq!(
            AppError::NoSuchView("".into()).error_type(),
            "NoSuchViewException"
        );
        assert_eq!(
            AppError::NoSuchSnapshot("".into()).error_type(),
            "NoSuchSnapshotException"
        );
        assert_eq!(
            AppError::NoSuchReference("".into()).error_type(),
            "NoSuchReferenceException"
        );
    }

    #[test]
    fn test_error_types_409() {
        assert_eq!(
            AppError::NamespaceAlreadyExists("".into()).error_type(),
            "AlreadyExistsException"
        );
        assert_eq!(
            AppError::TableAlreadyExists("".into()).error_type(),
            "AlreadyExistsException"
        );
        assert_eq!(
            AppError::ViewAlreadyExists("".into()).error_type(),
            "AlreadyExistsException"
        );
        assert_eq!(
            AppError::CommitConflict("".into()).error_type(),
            "CommitFailedException"
        );
        assert_eq!(
            AppError::NamespaceNotEmpty("".into()).error_type(),
            "NamespaceNotEmptyException"
        );
    }

    #[test]
    fn test_error_types_422() {
        assert_eq!(
            AppError::UnprocessableEntity("".into()).error_type(),
            "UnprocessableEntityException"
        );
    }

    #[test]
    fn test_error_types_500() {
        assert_eq!(
            AppError::Internal("".into()).error_type(),
            "InternalServerError"
        );
        assert_eq!(
            AppError::StorageError("".into()).error_type(),
            "InternalServerError"
        );
    }

    #[test]
    fn test_error_types_503() {
        assert_eq!(
            AppError::ServiceUnavailable("".into()).error_type(),
            "ServiceUnavailableException"
        );
    }

    // ========================================================================
    // Display Tests
    // ========================================================================

    #[test]
    fn test_error_display() {
        let err = AppError::NoSuchNamespace("my_namespace".into());
        assert_eq!(err.to_string(), "Namespace does not exist: my_namespace");
    }

    #[test]
    fn test_error_display_bad_request() {
        let err = AppError::BadRequest("The request names no 'name' field.".into());
        assert_eq!(err.to_string(), "The request names no 'name' field.");
    }

    #[test]
    fn test_error_display_forbidden() {
        let err = AppError::Forbidden("Not permitted to read table 'db.foo'".into());
        assert_eq!(err.to_string(), "Not permitted to read table 'db.foo'");
    }

    #[test]
    fn test_error_display_commit_conflict() {
        let err = AppError::CommitConflict("Table modified concurrently.".into());
        assert_eq!(err.to_string(), "Table modified concurrently.");
    }

    #[test]
    fn test_error_display_unauthenticated() {
        let err = AppError::Unauthenticated;
        assert_eq!(err.to_string(), "Authentication required");
    }

    // ========================================================================
    // ErrorModel Tests
    // ========================================================================

    /// The API reference claims to list *the exact* `type` values this server
    /// emits. This is what makes that claim checkable.
    ///
    /// Both directions matter. A type missing from the table is a client
    /// branching on a string the documentation never mentions; a type in the
    /// table and not in the code is a client branching on one that never
    /// arrives.
    ///
    /// The set is read out of this file rather than written down twice — a
    /// second list would be the thing that drifts.
    #[test]
    fn every_error_type_is_documented() {
        use std::collections::BTreeSet;

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

        // **Both** `error_type` matches, not just this file's.
        //
        // Scanning only `src/error.rs` is how the authentication layer came to
        // emit `ApiKeyNotFoundException`, `TokenExpiredException` and two more
        // for one status code while this table documented `NotAuthorizedException`
        // — a type nothing produced, sitting next to four nobody had written
        // down. A gate that reads one of two vocabularies is a gate on neither.
        let body: String = ["src/error.rs", "src/auth/error.rs"]
            .iter()
            .map(|file| {
                let source = std::fs::read_to_string(root.join(file))
                    .unwrap_or_else(|e| panic!("read {file}: {e}"));
                let start = source
                    .find("pub fn error_type(&self)")
                    .unwrap_or_else(|| panic!("{file} has an error_type"));
                let end = source[start..]
                    .find("\n    }")
                    .unwrap_or_else(|| panic!("{file}'s match ends"))
                    + start;
                source[start..end].to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");

        // The constants are chained rather than scanned for: an arm that names
        // one is the point — it is how two layers stay on one string — so there
        // is no literal in the source to find.
        let emitted: BTreeSet<String> = body
            .split('"')
            .filter(|s| s.ends_with("Exception") || *s == "InternalServerError")
            .map(str::to_string)
            .chain([
                NOT_FOUND_TYPE.to_string(),
                METHOD_NOT_ALLOWED_TYPE.to_string(),
                UNAUTHORIZED_TYPE.to_string(),
                RATE_LIMITED_TYPE.to_string(),
            ])
            .collect();
        assert!(
            emitted.len() > 15,
            "the scan found almost nothing: {emitted:?}"
        );

        let doc =
            std::fs::read_to_string(root.join("site/content/docs/api.md")).expect("read api.md");
        let table = {
            let start = doc
                .find("| Code | Type | Description |")
                .expect("the table");
            let end = doc[start..].find("\n\n").expect("its end") + start;
            &doc[start..end]
        };
        let documented: BTreeSet<String> = table
            .lines()
            .filter_map(|line| line.split('|').nth(2))
            .map(|cell| cell.trim().to_string())
            .filter(|cell| cell.ends_with("Exception") || cell == "InternalServerError")
            .collect();

        let missing: Vec<_> = emitted.difference(&documented).collect();
        assert!(
            missing.is_empty(),
            "these types are emitted but not in the API reference's error table: {missing:?}"
        );
        let invented: Vec<_> = documented.difference(&emitted).collect();
        assert!(
            invented.is_empty(),
            "these types are documented but never emitted: {invented:?}"
        );
    }

    #[test]
    fn test_error_model_serialization() {
        let model = ErrorModel {
            message: "test error".to_string(),
            error_type: "TestException".to_string(),
            code: 400,
            stack: vec![],
        };
        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["message"], "test error");
        assert_eq!(json["type"], "TestException");
        assert_eq!(json["code"], 400);
        // stack should be omitted when empty
        assert!(json.get("stack").is_none());
    }

    #[test]
    fn test_error_model_with_stack() {
        let model = ErrorModel {
            message: "error with stack".to_string(),
            error_type: "InternalServerError".to_string(),
            code: 500,
            stack: vec!["frame1".to_string(), "frame2".to_string()],
        };
        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["stack"].as_array().unwrap().len(), 2);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_error_with_empty_message() {
        let err = AppError::BadRequest("".into());
        assert_eq!(err.to_string(), "");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_error_with_special_characters() {
        let err = AppError::NoSuchTable("table<>&\"'".into());
        assert!(err.to_string().contains("table<>&\"'"));
    }

    #[test]
    fn test_error_with_unicode() {
        let err = AppError::NoSuchNamespace("名前空間".into());
        assert!(err.to_string().contains("名前空間"));
    }

    #[test]
    fn test_error_with_very_long_message() {
        let long_msg = "x".repeat(10000);
        let err = AppError::Internal(long_msg.clone());
        assert!(err.to_string().contains(&long_msg));
    }

    // ========================================================================
    // From Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_iceberg_error_data_invalid() {
        // DataInvalid Iceberg errors map to 400 Bad Request
        let iceberg_err = iceberg::Error::new(iceberg::ErrorKind::DataInvalid, "invalid data");
        let app_err: AppError = iceberg_err.into();
        assert_eq!(app_err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_from_iceberg_error_unexpected() {
        // Unexpected Iceberg errors map to 500 Internal Server Error
        let iceberg_err = iceberg::Error::new(iceberg::ErrorKind::Unexpected, "unexpected error");
        let app_err: AppError = iceberg_err.into();
        assert_eq!(app_err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
