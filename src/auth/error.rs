//! Authentication and authorization error types.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
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

    /// Whether a caller **presented a credential that did not verify**.
    ///
    /// Two things read it. The **auth-failure rate limit**, because verifying a
    /// JWT signature is public-key cryptography an unauthenticated caller can
    /// ask for as fast as it opens sockets. And the **audit trail**, because a
    /// credential presented and rejected is a recorded event.
    ///
    /// # One method, not a `matches!` at each call site
    ///
    /// Spelled inline it reads as the obvious three —
    /// `InvalidCredentials | ApiKeyNotFound | ApiKeyDisabled` — and leaves out
    /// every way a *token* fails: a forged signature and an expired token are
    /// both `InvalidToken`, an expired API key is `TokenExpired`. The match below
    /// is exhaustive with no wildcard, so a new variant does not compile until
    /// somebody decides which side of the line it is on.
    ///
    /// # Excluded, deliberately
    ///
    /// [`Unauthenticated`](Self::Unauthenticated): no credential was presented.
    /// That is an unconfigured client reaching an authenticated server, and
    /// counting it lets a stray health checker exhaust the budget of everyone
    /// behind its address.
    ///
    /// The four server-fault variants: an unreachable identity provider is this
    /// server's problem, and turning it into a rate limit answers an outage by
    /// locking out every client that noticed. They are not authentication
    /// decisions either, so recording them would put a fiction in the trail.
    ///
    /// [`Forbidden`](Self::Forbidden), [`ResourceNotFound`](Self::ResourceNotFound)
    /// and [`RateLimitExceeded`](Self::RateLimitExceeded) are decided after a
    /// caller is identified, and recorded by the guard and the limiter.
    pub const fn credential_was_rejected(&self) -> bool {
        match self {
            AuthError::InvalidCredentials(_)
            | AuthError::InvalidToken(_)
            | AuthError::MalformedToken(_)
            | AuthError::TokenExpired
            | AuthError::ExpiredCredentials
            | AuthError::ApiKeyNotFound
            | AuthError::ApiKeyDisabled => true,

            AuthError::Unauthenticated
            | AuthError::Forbidden(_)
            | AuthError::ResourceNotFound(_)
            | AuthError::RateLimitExceeded
            | AuthError::StorageError(_)
            | AuthError::External(_)
            | AuthError::Configuration(_)
            | AuthError::Internal(_) => false,
        }
    }

    /// Returns the error type string for the response body.
    pub fn error_type(&self) -> &'static str {
        match self {
            // Every credential rejection answers the same, and so does a request
            // that carried none. Splitting them told a caller whether the key it
            // tried exists — see `crate::error::UNAUTHORIZED_TYPE`. The
            // distinction survives in the audit record, which carries the
            // specific reason.
            //
            // Grouped by hand rather than by calling `credential_was_rejected`,
            // because `Unauthenticated` is deliberately on this side of the line
            // and the other side of that one: it is not a rejected credential
            // (the rate limiter must not count it), and it must not be
            // distinguishable from one either.
            AuthError::Unauthenticated
            | AuthError::InvalidCredentials(_)
            | AuthError::TokenExpired
            | AuthError::MalformedToken(_)
            | AuthError::ApiKeyNotFound
            | AuthError::ApiKeyDisabled
            | AuthError::ExpiredCredentials
            | AuthError::InvalidToken(_) => crate::error::UNAUTHORIZED_TYPE,

            AuthError::Forbidden(_) => "ForbiddenException",
            AuthError::ResourceNotFound(_) => crate::error::NOT_FOUND_TYPE,
            AuthError::RateLimitExceeded => crate::error::RATE_LIMITED_TYPE,

            // Nothing about the caller's credential, so nothing to conceal — and
            // all three are this server's fault, which is why they share the one
            // type `AppError` uses for the same condition.
            AuthError::StorageError(_)
            | AuthError::External(_)
            | AuthError::Configuration(_)
            | AuthError::Internal(_) => "InternalServerError",
        }
    }

    /// Returns a sanitized error message suitable for client responses.
    ///
    /// Sensitive internal detail is redacted, and the full text goes to the
    /// application log instead, so nothing is lost to whoever operates the
    /// server.
    ///
    /// # Unconditional, in every build
    ///
    /// Keying this on `cfg!(debug_assertions)` is tempting and wrong twice over,
    /// and [`AppError`](crate::error::AppError) argues both:
    ///
    /// - The behaviour under test would differ from the behaviour in
    ///   production, which is the one place a difference matters.
    /// - "Debug build" is not "development". A debug binary is what an engineer
    ///   points at a real identity provider, and `External` carries whatever the
    ///   JWKS fetch said — a URL, an internal hostname, sometimes a token in a
    ///   query string.
    ///
    /// Redacting in both builds costs a developer nothing: the full text is on
    /// stderr a line earlier.
    pub fn sanitized_message(&self) -> String {
        match self {
            // One sentence for every way a credential can be refused, and for a
            // request that carried none.
            //
            // The message used to name the reason — "API key not found or
            // revoked", "Token expired" — and that was the same oracle the type
            // string was. `ApiKeyDisabled` and `ExpiredCredentials` are reachable
            // only *after* the constant-time hash comparison succeeds, so each
            // one confirmed that the key presented is real. The API key path goes
            // out of its way to be constant-time against exactly that question;
            // answering it in prose gave it away.
            //
            // It names the two mechanisms because that is configuration, not a
            // secret, and a client with a JWT pointed at a key-only deployment
            // otherwise has nothing to go on.
            AuthError::Unauthenticated
            | AuthError::InvalidCredentials(_)
            | AuthError::TokenExpired
            | AuthError::MalformedToken(_)
            | AuthError::ApiKeyNotFound
            | AuthError::ApiKeyDisabled
            | AuthError::ExpiredCredentials
            | AuthError::InvalidToken(_) => "This request needs a valid credential: an \
                 `X-API-Key` header, or a bearer token this catalog's identity provider \
                 issued. The server log and the audit trail name which check failed."
                .to_string(),

            AuthError::RateLimitExceeded => self.to_string(),

            // Authorization: show resource type but not full path
            AuthError::Forbidden(_) => "Access denied".to_string(),
            AuthError::ResourceNotFound(_) => "Resource not found".to_string(),

            // Internal errors: never expose details, and log them so the
            // redaction costs the operator nothing.
            AuthError::StorageError(detail)
            | AuthError::External(detail)
            | AuthError::Configuration(detail)
            | AuthError::Internal(detail) => {
                tracing::error!(
                    error = %detail,
                    kind = self.error_type(),
                    "Authentication failed for a reason that is this server's own"
                );
                "An internal error occurred. Check the server log for the cause.".to_string()
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

        let mut response = (status, Json(body)).into_response();

        // RFC 9110 makes this a MUST on every `401`. See
        // `crate::error::WWW_AUTHENTICATE_CHALLENGE` for why `Bearer` is the
        // honest challenge even where the credential is an API key.
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(crate::error::WWW_AUTHENTICATE_CHALLENGE),
            );
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way a *presented* credential fails counts and is recorded.
    ///
    /// This list was three variants spelled inline in the auth middleware, which
    /// left out every way a token fails — a forged JWT signature, an expired
    /// one, an expired API key. The auth-failure rate limit therefore did not
    /// bound the most expensive rejection this server serves, and the audit
    /// trail did not hold it.
    #[test]
    fn every_rejected_credential_counts_as_one() {
        for error in [
            AuthError::InvalidCredentials("wrong".into()),
            AuthError::InvalidToken("bad signature".into()),
            AuthError::MalformedToken("not three segments".into()),
            AuthError::TokenExpired,
            AuthError::ExpiredCredentials,
            AuthError::ApiKeyNotFound,
            AuthError::ApiKeyDisabled,
        ] {
            assert!(
                error.credential_was_rejected(),
                "{error:?} is a presented credential that did not verify"
            );
            assert_eq!(
                error.status_code(),
                StatusCode::UNAUTHORIZED,
                "{error:?} should be a 401, or it is not an authentication outcome"
            );
        }
    }

    /// No credential, or this server's own fault. Neither is a caller to
    /// penalise, and neither is an authentication decision to record.
    #[test]
    fn nothing_else_counts_as_a_rejected_credential() {
        for error in [
            // The ordinary shape of the internet: a client that has not been
            // configured yet. Counting it would let a health checker exhaust
            // the failure budget of everyone behind its address.
            AuthError::Unauthenticated,
            // Decided after the caller is already identified, and recorded by
            // the guard and the limiter respectively.
            AuthError::Forbidden("no".into()),
            AuthError::ResourceNotFound("no".into()),
            AuthError::RateLimitExceeded,
            // This server's problem. Turning an identity-provider outage into a
            // rate limit would answer it by locking out every client that
            // noticed.
            AuthError::StorageError("down".into()),
            AuthError::External("jwks unreachable".into()),
            AuthError::Configuration("bad".into()),
            AuthError::Internal("oops".into()),
        ] {
            assert!(
                !error.credential_was_rejected(),
                "{error:?} is not a rejected credential"
            );
        }
    }

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

    /// Every way a credential can be refused answers **identically**, in both
    /// the type and the message.
    ///
    /// This is the whole point of the constant-time comparison in the API key
    /// path. `ApiKeyDisabled` and `ExpiredCredentials` are reachable only after
    /// that comparison *succeeds*, so an answer that named either confirmed the
    /// key presented is real — which is what somebody working through a dump of
    /// leaked credentials is trying to find out. `Unauthenticated` is in the set
    /// too: "you sent nothing" and "what you sent is wrong" must not be
    /// separable either, or the same walk works one step earlier.
    #[test]
    fn every_credential_refusal_is_the_same_answer() {
        let refusals = [
            AuthError::Unauthenticated,
            AuthError::InvalidCredentials("bad key".into()),
            AuthError::TokenExpired,
            AuthError::MalformedToken("not three segments".into()),
            AuthError::ApiKeyNotFound,
            AuthError::ApiKeyDisabled,
            AuthError::ExpiredCredentials,
            AuthError::InvalidToken("bad signature".into()),
        ];

        let answer = (
            refusals[0].status_code(),
            refusals[0].error_type(),
            refusals[0].sanitized_message(),
        );
        assert_eq!(answer.0, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.1, crate::error::UNAUTHORIZED_TYPE);

        for error in &refusals {
            assert_eq!(
                (
                    error.status_code(),
                    error.error_type(),
                    error.sanitized_message()
                ),
                answer,
                "{error:?} is distinguishable from the others, which tells a caller \
                 something about a credential it does not hold"
            );
        }

        // And nothing in the answer names the specific failure.
        let message = answer.2.to_lowercase();
        for leak in ["expired", "disabled", "revoked", "not found", "malformed"] {
            assert!(
                !message.contains(leak),
                "the refusal names '{leak}': {}",
                answer.2
            );
        }
    }

    #[test]
    fn test_sanitized_messages() {
        assert_eq!(
            AuthError::RateLimitExceeded.sanitized_message(),
            "Rate limit exceeded"
        );

        // Sensitive detail never reaches the wire, in any build — which is what
        // makes the assertion below writable at all. Keyed on
        // `cfg!(debug_assertions)`, this test would exercise the *unredacted*
        // path while production ran the other one.
        for (error, secret) in [
            (
                AuthError::Internal("secret database error".into()),
                "secret database error",
            ),
            (
                AuthError::StorageError("connection refused to db.internal".into()),
                "db.internal",
            ),
            (
                AuthError::External("https://idp.internal/jwks?key=hunter2".into()),
                "idp.internal",
            ),
            (
                AuthError::Configuration("bad audience in /etc/rustberg.toml".into()),
                "/etc/rustberg.toml",
            ),
        ] {
            let message = error.sanitized_message();
            assert!(
                !message.contains(secret),
                "{error:?} leaked '{secret}' to the client as: {message}"
            );
            assert!(!message.is_empty());
        }

        // A credential error carries none of the detail it was constructed with
        // — see `every_credential_refusal_is_the_same_answer` for the stronger
        // claim that it carries the same detail as every *other* refusal too.
        for (error, secret) in [
            (
                AuthError::InvalidCredentials("key rb_abc… has the wrong hash".into()),
                "rb_abc",
            ),
            (
                AuthError::InvalidToken("signature verification failed for kid=abc".into()),
                "kid=abc",
            ),
            (
                AuthError::MalformedToken("expected 3 segments, found 2".into()),
                "3 segments",
            ),
        ] {
            let message = error.sanitized_message();
            assert!(
                !message.contains(secret),
                "{error:?} leaked '{secret}' to the client as: {message}"
            );
        }
    }
}
