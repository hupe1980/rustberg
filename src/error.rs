//! Application error types and error response formatting.
//!
//! This module defines error types that map to Iceberg REST Catalog API
//! error responses, ensuring consistent error handling across the service.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
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
    /// Optional stack trace (only in debug mode).
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
#[allow(dead_code)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppError {
    // ========================================================================
    // 400 Bad Request errors
    // ========================================================================
    /// Invalid request data or parameters.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Invalid namespace identifier.
    #[error("Invalid namespace: {0}")]
    InvalidNamespace(String),

    /// Invalid table identifier.
    #[error("Invalid table identifier: {0}")]
    InvalidTableIdentifier(String),

    /// Invalid schema definition.
    #[error("Invalid schema: {0}")]
    InvalidSchema(String),

    /// Request body failed validation.
    #[error("Validation error: {0}")]
    ValidationError(String),

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
    #[error("Access denied: {0}")]
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
    #[error("Snapshot does not exist: {0}")]
    NoSuchSnapshot(String),

    /// Requested reference (branch/tag) does not exist.
    #[error("Reference does not exist: {0}")]
    NoSuchReference(String),

    // ========================================================================
    // 406 Not Acceptable / Unsupported Operation
    // ========================================================================
    /// Operation not supported by the server.
    #[error("Not supported: {0}")]
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
    #[error("Commit conflict: {0}")]
    CommitConflict(String),

    /// Namespace is not empty (cannot be deleted).
    #[error("Namespace not empty: {0}")]
    NamespaceNotEmpty(String),

    // ========================================================================
    // 422 Unprocessable Entity errors
    // ========================================================================
    /// Request is syntactically correct but semantically invalid.
    #[error("Unprocessable entity: {0}")]
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

impl AppError {
    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            // 400 Bad Request
            AppError::BadRequest(_)
            | AppError::InvalidNamespace(_)
            | AppError::InvalidTableIdentifier(_)
            | AppError::InvalidSchema(_)
            | AppError::ValidationError(_) => StatusCode::BAD_REQUEST,

            // 401 Unauthorized
            AppError::Unauthenticated | AppError::InvalidCredentials => StatusCode::UNAUTHORIZED,

            // 403 Forbidden
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,

            // 404 Not Found
            AppError::NoSuchNamespace(_)
            | AppError::NoSuchTable(_)
            | AppError::NoSuchView(_)
            | AppError::NoSuchSnapshot(_)
            | AppError::NoSuchReference(_) => StatusCode::NOT_FOUND,

            // 406 Not Acceptable / Unsupported Operation
            AppError::NotSupported(_) => StatusCode::NOT_ACCEPTABLE,

            // 409 Conflict
            AppError::NamespaceAlreadyExists(_)
            | AppError::TableAlreadyExists(_)
            | AppError::ViewAlreadyExists(_)
            | AppError::CommitConflict(_)
            | AppError::NamespaceNotEmpty(_) => StatusCode::CONFLICT,

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
            AppError::InvalidNamespace(_) => "BadRequestException",
            AppError::InvalidTableIdentifier(_) => "BadRequestException",
            AppError::InvalidSchema(_) => "BadRequestException",
            AppError::ValidationError(_) => "BadRequestException",
            AppError::Unauthenticated => "NotAuthorizedException",
            AppError::InvalidCredentials => "NotAuthorizedException",
            AppError::Forbidden(_) => "ForbiddenException",
            AppError::NoSuchNamespace(_) => "NoSuchNamespaceException",
            AppError::NoSuchTable(_) => "NoSuchTableException",
            AppError::NoSuchView(_) => "NoSuchViewException",
            AppError::NoSuchSnapshot(_) => "NoSuchSnapshotException",
            AppError::NoSuchReference(_) => "NoSuchReferenceException",
            AppError::NotSupported(_) => "UnsupportedOperationException",
            AppError::NamespaceAlreadyExists(_) => "AlreadyExistsException",
            AppError::TableAlreadyExists(_) => "AlreadyExistsException",
            AppError::ViewAlreadyExists(_) => "AlreadyExistsException",
            AppError::CommitConflict(_) => "CommitFailedException",
            AppError::NamespaceNotEmpty(_) => "NamespaceNotEmptyException",
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
            AuthError::RateLimitExceeded => {
                AppError::ServiceUnavailable("Rate limit exceeded".to_string())
            }
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
            ErrorKind::DataInvalid => AppError::BadRequest(err.message().to_string()),
            ErrorKind::FeatureUnsupported => {
                AppError::UnprocessableEntity(err.message().to_string())
            }
            ErrorKind::Unexpected => AppError::Internal(err.message().to_string()),
            _ => {
                // Try to detect specific error types from the message
                let message = err.message().to_lowercase();

                // Check for "not found" / "does not exist" / "no such" patterns
                let is_not_found = message.contains("not found")
                    || message.contains("does not exist")
                    || message.contains("no such");

                let is_already_exists = message.contains("already exists");

                if is_not_found {
                    if message.contains("namespace") {
                        return AppError::NoSuchNamespace(err.message().to_string());
                    } else if message.contains("table") {
                        return AppError::NoSuchTable(err.message().to_string());
                    } else if message.contains("view") {
                        return AppError::NoSuchView(err.message().to_string());
                    } else if message.contains("snapshot") {
                        return AppError::NoSuchSnapshot(err.message().to_string());
                    }
                    // Generic not found - default to namespace for unknown entity types
                    return AppError::NoSuchNamespace(err.message().to_string());
                } else if is_already_exists {
                    if message.contains("namespace") {
                        return AppError::NamespaceAlreadyExists(err.message().to_string());
                    } else if message.contains("table") {
                        return AppError::TableAlreadyExists(err.message().to_string());
                    }
                    // Generic already exists - default to namespace
                    return AppError::NamespaceAlreadyExists(err.message().to_string());
                } else if message.contains("not empty") {
                    return AppError::NamespaceNotEmpty(err.message().to_string());
                }

                AppError::Internal(format!("Iceberg error: {}", err.message()))
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Sanitize error messages for production
        // Don't expose internal details to clients
        let safe_message = match &self {
            // Internal errors: hide details in production
            AppError::Internal(msg) | AppError::StorageError(msg) => {
                if cfg!(debug_assertions) {
                    msg.clone()
                } else {
                    // Generic message for production to prevent information leakage
                    "An internal error occurred. Please contact support if the problem persists."
                        .to_string()
                }
            }
            // Service errors: hide implementation details
            AppError::ServiceUnavailable(msg) => {
                if cfg!(debug_assertions) {
                    msg.clone()
                } else {
                    "Service temporarily unavailable. Please try again later.".to_string()
                }
            }
            // Auth errors: don't reveal which credential failed
            AppError::InvalidCredentials => "Invalid credentials provided".to_string(),
            // All other errors are safe to expose
            _ => self.to_string(),
        };

        // Only include stack traces in debug builds
        let stack = if cfg!(debug_assertions) {
            let backtrace = std::backtrace::Backtrace::capture();
            backtrace
                .to_string()
                .lines()
                .take(20) // Limit stack trace length
                .map(|s| s.to_string())
                .collect()
        } else {
            vec![]
        };

        let body = ErrorModel {
            message: safe_message,
            error_type: self.error_type().to_string(),
            code: status.as_u16(),
            stack,
        };

        // Wrap in IcebergErrorResponse per Iceberg REST Catalog spec
        let response = IcebergErrorResponse { error: body };

        (status, Json(response)).into_response()
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
    fn test_all_400_errors() {
        assert_eq!(
            AppError::BadRequest("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::InvalidNamespace("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::InvalidTableIdentifier("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::InvalidSchema("".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::ValidationError("".into()).status_code(),
            StatusCode::BAD_REQUEST
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
        assert_eq!(
            AppError::InvalidNamespace("".into()).error_type(),
            "BadRequestException"
        );
        assert_eq!(
            AppError::InvalidTableIdentifier("".into()).error_type(),
            "BadRequestException"
        );
        assert_eq!(
            AppError::InvalidSchema("".into()).error_type(),
            "BadRequestException"
        );
        assert_eq!(
            AppError::ValidationError("".into()).error_type(),
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
        let err = AppError::BadRequest("missing field 'name'".into());
        assert_eq!(err.to_string(), "Bad request: missing field 'name'");
    }

    #[test]
    fn test_error_display_forbidden() {
        let err = AppError::Forbidden("no access to table foo".into());
        assert_eq!(err.to_string(), "Access denied: no access to table foo");
    }

    #[test]
    fn test_error_display_commit_conflict() {
        let err = AppError::CommitConflict("table modified concurrently".into());
        assert_eq!(
            err.to_string(),
            "Commit conflict: table modified concurrently"
        );
    }

    #[test]
    fn test_error_display_unauthenticated() {
        let err = AppError::Unauthenticated;
        assert_eq!(err.to_string(), "Authentication required");
    }

    // ========================================================================
    // ErrorModel Tests
    // ========================================================================

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
        assert_eq!(err.to_string(), "Bad request: ");
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
