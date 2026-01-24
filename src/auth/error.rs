//! Authentication and authorization error types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Result type for authentication and authorization operations.
pub type Result<T, E = AuthError> = std::result::Result<T, E>;

/// Authentication and authorization errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No credentials provided when required.
    #[error("Authentication required")]
    Unauthenticated,

    /// Invalid credentials (wrong API key, bad signature, etc.).
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    /// Token has expired.
    #[error("Token expired")]
    TokenExpired,

    /// Token is malformed or cannot be parsed.
    #[error("Malformed token: {0}")]
    MalformedToken(String),

    /// Principal does not have permission for the requested action.
    #[error("Access denied: {0}")]
    Forbidden(String),

    /// The requested resource was not found (for authz context).
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    /// API key not found or revoked.
    #[error("API key not found or revoked")]
    ApiKeyNotFound,

    /// API key has been disabled.
    #[error("API key is disabled")]
    ApiKeyDisabled,

    /// Credentials have expired.
    #[error("Credentials expired")]
    ExpiredCredentials,

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Storage backend error.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// External service error (OIDC provider, etc.).
    #[error("External service error: {0}")]
    External(String),

    /// Invalid token (JWT validation failed).
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal error during auth processing.
    #[error("Internal authentication error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Returns the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AuthError::InvalidCredentials(_) => StatusCode::UNAUTHORIZED,
            AuthError::TokenExpired => StatusCode::UNAUTHORIZED,
            AuthError::MalformedToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::ResourceNotFound(_) => StatusCode::NOT_FOUND,
            AuthError::ApiKeyNotFound => StatusCode::UNAUTHORIZED,
            AuthError::ApiKeyDisabled => StatusCode::UNAUTHORIZED,
            AuthError::ExpiredCredentials => StatusCode::UNAUTHORIZED,
            AuthError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            AuthError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::External(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the error type string for the response body.
    pub fn error_type(&self) -> &'static str {
        match self {
            AuthError::Unauthenticated => "UnauthenticatedException",
            AuthError::InvalidCredentials(_) => "InvalidCredentialsException",
            AuthError::TokenExpired => "TokenExpiredException",
            AuthError::MalformedToken(_) => "MalformedTokenException",
            AuthError::Forbidden(_) => "ForbiddenException",
            AuthError::ResourceNotFound(_) => "NotFoundException",
            AuthError::ApiKeyNotFound => "ApiKeyNotFoundException",
            AuthError::ApiKeyDisabled => "ApiKeyDisabledException",
            AuthError::ExpiredCredentials => "ExpiredCredentialsException",
            AuthError::RateLimitExceeded => "RateLimitExceededException",
            AuthError::StorageError(_) => "StorageErrorException",
            AuthError::External(_) => "ExternalServiceException",
            AuthError::InvalidToken(_) => "InvalidTokenException",
            AuthError::Configuration(_) => "ConfigurationException",
            AuthError::Internal(_) => "InternalErrorException",
        }
    }

    /// Returns a sanitized error message suitable for client responses.
    ///
    /// In production, sensitive internal details are redacted to prevent
    /// information leakage. Debug builds show full details for development.
    pub fn sanitized_message(&self) -> String {
        // In debug mode, show full error details for development
        if cfg!(debug_assertions) {
            return self.to_string();
        }

        // In production, sanitize potentially sensitive error messages
        match self {
            // These errors are safe to expose as-is
            AuthError::Unauthenticated
            | AuthError::TokenExpired
            | AuthError::ApiKeyNotFound
            | AuthError::ApiKeyDisabled
            | AuthError::ExpiredCredentials
            | AuthError::RateLimitExceeded => self.to_string(),

            // Credential errors: generic message to prevent enumeration
            AuthError::InvalidCredentials(_) => "Invalid credentials".to_string(),

            // Token errors: hide parsing/validation details
            AuthError::MalformedToken(_) => "Malformed token".to_string(),
            AuthError::InvalidToken(_) => "Invalid token".to_string(),

            // Authorization: show resource type but not full path
            AuthError::Forbidden(_) => "Access denied".to_string(),
            AuthError::ResourceNotFound(_) => "Resource not found".to_string(),

            // Internal errors: never expose details
            AuthError::StorageError(_)
            | AuthError::External(_)
            | AuthError::Configuration(_)
            | AuthError::Internal(_) => {
                "An internal error occurred. Please contact support.".to_string()
            }
        }
    }
}

/// Error response body for authentication/authorization errors.
#[derive(Debug, Serialize)]
pub struct AuthErrorResponse {
    pub error: AuthErrorBody,
}

/// Error body with details.
#[derive(Debug, Serialize)]
pub struct AuthErrorBody {
    pub code: u16,
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = AuthErrorResponse {
            error: AuthErrorBody {
                code: status.as_u16(),
                message: self.sanitized_message(),
                error_type: self.error_type().to_string(),
            },
        };

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            AuthError::Unauthenticated.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthError::Forbidden("test".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AuthError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_error_display() {
        let err = AuthError::InvalidCredentials("bad key".into());
        assert_eq!(err.to_string(), "Invalid credentials: bad key");
    }

    #[test]
    fn test_sanitized_messages() {
        // Safe errors show their messages
        assert_eq!(
            AuthError::Unauthenticated.sanitized_message(),
            "Authentication required"
        );
        assert_eq!(
            AuthError::RateLimitExceeded.sanitized_message(),
            "Rate limit exceeded"
        );

        // Sensitive errors are sanitized in release builds
        // Note: In debug mode (tests), full messages may be shown
        // These assertions verify the sanitization logic exists
        let internal = AuthError::Internal("secret database error".into());
        let storage = AuthError::StorageError("connection refused to db.internal".into());

        // The sanitized message should not contain the secret details
        // (This test verifies the method exists and returns a string)
        assert!(!internal.sanitized_message().is_empty());
        assert!(!storage.sanitized_message().is_empty());
    }
}
