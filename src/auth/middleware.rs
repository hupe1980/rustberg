//! Authentication middleware for Axum.
//!
//! This module provides middleware that authenticates incoming requests,
//! enforces rate limits, emits audit logs, and injects the Principal into request extensions.

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::audit::{log_auth_failure, log_auth_success, log_rate_limit};
use super::authn::Authenticator;
use super::error::AuthError;
use super::principal::Principal;
use super::rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};

// ============================================================================
// AuthState for Middleware
// ============================================================================

/// Shared state for authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    pub authenticator: Arc<dyn Authenticator>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AuthState {
    /// Creates a new auth state with the given authenticator.
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            authenticator,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::disabled())),
        }
    }

    /// Creates a new auth state with the given authenticator and rate limiter.
    pub fn with_rate_limiter(
        authenticator: Arc<dyn Authenticator>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            authenticator,
            rate_limiter,
        }
    }
}

// ============================================================================
// Authentication Middleware Function
// ============================================================================

/// Middleware that authenticates requests and injects the Principal.
///
/// On successful authentication, the Principal is inserted into request
/// extensions and can be extracted using the `AuthenticatedPrincipal` extractor.
///
/// On failure, returns a 401 Unauthorized response.
/// On rate limit exceeded, returns a 429 Too Many Requests response.
pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP for rate limiting
    // Only trust proxy headers if explicitly configured (prevents IP spoofing attacks)
    let trust_proxy = auth_state.rate_limiter.trust_proxy_headers();
    let client_ip = extract_client_ip(&request, trust_proxy);

    // Check rate limit before authentication
    if let Some(ip) = client_ip {
        if let Err(exceeded) = auth_state.rate_limiter.check_ip_limit(&ip) {
            // Audit log: rate limit triggered
            log_rate_limit(&ip.to_string(), None, "ip");
            return exceeded.into_response();
        }
    }

    // Extract headers for authentication
    let headers = request.headers().clone();

    match auth_state.authenticator.authenticate(&headers).await {
        Ok(principal) => {
            // Record successful auth (clears failure counter)
            if let Some(ip) = client_ip {
                auth_state.rate_limiter.record_auth_success(&ip);
            }

            // Audit log: authentication success
            let auth_method = match principal.auth_method() {
                super::principal::AuthMethod::ApiKey => "api_key",
                super::principal::AuthMethod::Bearer => "jwt",
                super::principal::AuthMethod::None => "anonymous",
                _ => "other",
            };
            log_auth_success(
                principal.id(),
                principal.tenant_id(),
                client_ip.as_ref().map(|ip| ip.to_string()).as_deref(),
                auth_method,
            );

            // Check if the principal has expired
            if principal.is_expired() {
                return AuthError::TokenExpired.into_response();
            }

            // Check per-tenant rate limit for authenticated requests
            if let Err(exceeded) = auth_state
                .rate_limiter
                .check_tenant_limit(principal.tenant_id())
            {
                // Audit log: tenant rate limit triggered
                log_rate_limit(
                    &client_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    Some(principal.tenant_id()),
                    "tenant",
                );
                return add_rate_limit_headers(exceeded.into_response(), None);
            }

            // Insert principal and rate limit info into request extensions
            request.extensions_mut().insert(principal);

            // Continue to the next handler
            let mut response = next.run(request).await;

            // Add rate limit headers to successful response.
            // SECURITY: Use peek_ip_limit (read-only) instead of check_ip_limit
            // to avoid consuming a second token from the bucket per request.
            if let Some(ip) = client_ip {
                if let Some(info) = auth_state.rate_limiter.peek_ip_limit(&ip) {
                    response = add_rate_limit_headers(response, Some(info));
                }
            }

            response
        }
        Err(e) => {
            // Record auth failure
            if let Some(ip) = client_ip {
                // Only record failures for invalid credentials, not missing credentials
                if matches!(
                    e,
                    AuthError::InvalidCredentials(_)
                        | AuthError::ApiKeyNotFound
                        | AuthError::ApiKeyDisabled
                ) {
                    auth_state.rate_limiter.record_auth_failure(&ip);

                    // Audit log: authentication failure
                    log_auth_failure(Some(&ip.to_string()), &e.to_string());
                }
            }
            e.into_response()
        }
    }
}

/// Middleware that requires authentication (denies anonymous).
pub async fn require_auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP for rate limiting
    // Only trust proxy headers if explicitly configured (prevents IP spoofing attacks)
    let trust_proxy = auth_state.rate_limiter.trust_proxy_headers();
    let client_ip = extract_client_ip(&request, trust_proxy);

    // Check rate limit before authentication
    if let Some(ip) = client_ip {
        if let Err(exceeded) = auth_state.rate_limiter.check_ip_limit(&ip) {
            log_rate_limit(&ip.to_string(), None, "ip");
            return exceeded.into_response();
        }
    }

    // Extract headers for authentication
    let headers = request.headers().clone();

    match auth_state.authenticator.authenticate(&headers).await {
        Ok(principal) => {
            // Record successful auth
            if let Some(ip) = client_ip {
                auth_state.rate_limiter.record_auth_success(&ip);
            }

            // Audit log: authentication success
            let auth_method = match principal.auth_method() {
                super::principal::AuthMethod::ApiKey => "api_key",
                super::principal::AuthMethod::Bearer => "jwt",
                super::principal::AuthMethod::None => "anonymous",
                _ => "other",
            };
            log_auth_success(
                principal.id(),
                principal.tenant_id(),
                client_ip.as_ref().map(|ip| ip.to_string()).as_deref(),
                auth_method,
            );

            // Check if the principal has expired
            if principal.is_expired() {
                return AuthError::TokenExpired.into_response();
            }

            // Deny anonymous principals
            if principal.is_anonymous() {
                return AuthError::Unauthenticated.into_response();
            }

            // Check per-tenant rate limit
            if let Err(exceeded) = auth_state
                .rate_limiter
                .check_tenant_limit(principal.tenant_id())
            {
                log_rate_limit(
                    &client_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    Some(principal.tenant_id()),
                    "tenant",
                );
                return exceeded.into_response();
            }

            // Insert principal into request extensions
            request.extensions_mut().insert(principal);

            // Continue to the next handler
            let mut response = next.run(request).await;

            // Add rate limit headers.
            // SECURITY: Use peek_ip_limit (read-only) instead of check_ip_limit
            // to avoid consuming a second token from the bucket per request.
            if let Some(ip) = client_ip {
                if let Some(info) = auth_state.rate_limiter.peek_ip_limit(&ip) {
                    response = add_rate_limit_headers(response, Some(info));
                }
            }

            response
        }
        Err(e) => {
            // Record auth failure
            if let Some(ip) = client_ip {
                if matches!(
                    e,
                    AuthError::InvalidCredentials(_)
                        | AuthError::ApiKeyNotFound
                        | AuthError::ApiKeyDisabled
                ) {
                    auth_state.rate_limiter.record_auth_failure(&ip);
                    log_auth_failure(Some(&ip.to_string()), &e.to_string());
                }
            }
            e.into_response()
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extracts the client IP address from the request.
///
/// If `trust_proxy_headers` is true, checks the following in order:
/// 1. `X-Forwarded-For` header (first IP)
/// 2. `X-Real-IP` header
/// 3. Connected socket address
///
/// If `trust_proxy_headers` is false (default), only uses the connected socket address.
///
/// **SECURITY NOTE**: Only trust proxy headers when running behind a known, trusted
/// reverse proxy. Untrusted proxy headers allow attackers to spoof their IP address
/// and bypass rate limiting.
fn extract_client_ip(request: &Request<Body>, trust_proxy_headers: bool) -> Option<IpAddr> {
    // Only check proxy headers if explicitly trusted
    if trust_proxy_headers {
        // Try X-Forwarded-For first (common for proxied requests)
        if let Some(xff) = request.headers().get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                // X-Forwarded-For can contain multiple IPs; take the first
                if let Some(first_ip) = xff_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = request.headers().get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fall back to connected address (from ConnectInfo extension)
    // This is always safe to use as it's the actual TCP connection source
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Adds rate limit headers to a response.
fn add_rate_limit_headers(mut response: Response, info: Option<RateLimitInfo>) -> Response {
    if let Some(info) = info {
        for (name, value) in info.headers() {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

// ============================================================================
// Principal Extractor
// ============================================================================

/// Extractor for authenticated principals.
///
/// Use this in route handlers to access the authenticated principal.
/// Returns 401 if no principal is present in extensions.
///
/// # Example
///
/// ```no_run
/// use axum::response::IntoResponse;
/// use rustberg::auth::AuthenticatedPrincipal;
///
/// async fn handler(AuthenticatedPrincipal(principal): AuthenticatedPrincipal) -> impl IntoResponse {
///     format!("Hello, {}!", principal.name())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal(pub Principal);

impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(AuthenticatedPrincipal)
            .ok_or((StatusCode::UNAUTHORIZED, "Authentication required"))
    }
}

impl std::ops::Deref for AuthenticatedPrincipal {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ============================================================================
// Optional Principal Extractor
// ============================================================================

/// Extractor for optionally authenticated principals.
///
/// Returns Some(Principal) if authenticated, None otherwise.
/// Does not fail if authentication is missing.
#[derive(Debug, Clone)]
pub struct OptionalPrincipal(pub Option<Principal>);

impl<S> FromRequestParts<S> for OptionalPrincipal
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalPrincipal(
            parts.extensions.get::<Principal>().cloned(),
        ))
    }
}

impl std::ops::Deref for OptionalPrincipal {
    type Target = Option<Principal>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authn::{AllowAllAuthenticator, DenyAllAuthenticator};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler(AuthenticatedPrincipal(principal): AuthenticatedPrincipal) -> String {
        format!("Hello, {}!", principal.name())
    }

    fn create_test_app(authenticator: Arc<dyn Authenticator>) -> Router {
        let auth_state = AuthState::new(authenticator);

        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                auth_middleware,
            ))
            .with_state(auth_state)
    }

    #[tokio::test]
    async fn test_auth_middleware_allows_authenticated() {
        let app = create_test_app(Arc::new(AllowAllAuthenticator));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_denies_unauthenticated() {
        let app = create_test_app(Arc::new(DenyAllAuthenticator));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
