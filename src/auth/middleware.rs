//! Authentication middleware for Axum.
//!
//! This module provides middleware that authenticates incoming requests,
//! enforces rate limits, emits audit logs, and injects the Principal into request extensions.

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::audit::{log_auth_failure, log_auth_success, log_rate_limit};
use super::authn::Authenticator;
use super::authz::RequestContext;
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

/// Authenticates a request, and attaches everything downstream decides from.
///
/// Two things go into the request extensions and both are load-bearing: the
/// [`Principal`], read by the `AuthenticatedPrincipal` extractor, and the
/// [`RequestContext`] — source address and request id — read by `RequestFacts`.
/// The second is what a Cedar policy sees as `context.source_ip` and what an
/// audit record carries as its request id, so a path that establishes a
/// principal without it produces decisions that cannot be attributed and
/// address-conditioned policies that silently never match.
///
/// # Why there is only one of these
///
/// A second copy that differed only in rejecting anonymous callers would be a
/// hundred lines of security-critical sequencing kept honest by nothing. The
/// behaviour needs no second copy: a deployment that must refuse anonymous
/// callers configures an authenticator that does not mint them, and every
/// catalog route authorizes against a policy set that grants one nothing.
///
/// Returns `401` when authentication fails and `429` when a rate limit is
/// exceeded, in both cases without running the handler.
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
    if let Some(ip) = client_ip
        && let Err(exceeded) = auth_state.rate_limiter.check_ip_limit(&ip)
    {
        // Audit log: rate limit triggered
        log_rate_limit(&ip.to_string(), None, "ip");
        return exceeded.into_response();
    }

    // Extract headers for authentication
    let headers = request.headers().clone();

    match auth_state.authenticator.authenticate(&headers).await {
        Ok(principal) => {
            // Record successful auth (clears failure counter)
            if let Some(ip) = client_ip {
                auth_state.rate_limiter.record_auth_success(&ip);
            }

            // Expiry is checked before the record is written, not after. A
            // credential that has run out is a rejected request, and an audit
            // trail that records it as a success describes something that did
            // not happen — which is the one thing a governance product's audit
            // stream cannot do.
            if principal.is_expired() {
                if let Some(ip) = client_ip {
                    log_auth_failure(Some(&ip.to_string()), "credential expired");
                }
                return AuthError::TokenExpired.into_response();
            }

            // Audit log: authentication success
            let auth_method = match principal.auth_method() {
                super::principal::AuthMethod::ApiKey => "api_key",
                super::principal::AuthMethod::Bearer => "jwt",
                super::principal::AuthMethod::None => "anonymous",
                super::principal::AuthMethod::External => "host",
                _ => "other",
            };
            log_auth_success(
                principal.id(),
                principal.tenant_id(),
                client_ip.as_ref().map(|ip| ip.to_string()).as_deref(),
                auth_method,
            );

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

            // Insert the principal and the request facts policies may read.
            // The address comes from the same resolution the rate limiter used,
            // so a policy and a rate limit can never disagree about who the
            // caller is.
            request.extensions_mut().insert(principal);

            let mut facts = match client_ip {
                Some(ip) => RequestContext::from_ip(ip),
                None => RequestContext::default(),
            };
            if let Some(id) = request
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .and_then(sanitize_request_id)
            {
                facts = facts.with_request_id(id);
            }
            request.extensions_mut().insert(facts);

            // Continue to the next handler
            let mut response = next.run(request).await;

            // Add rate limit headers to successful response.
            // SECURITY: Use peek_ip_limit (read-only) instead of check_ip_limit
            // to avoid consuming a second token from the bucket per request.
            if let Some(ip) = client_ip
                && let Some(info) = auth_state.rate_limiter.peek_ip_limit(&ip)
            {
                response = add_rate_limit_headers(response, Some(info));
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
        if let Some(xff) = request.headers().get("x-forwarded-for")
            && let Ok(xff_str) = xff.to_str()
        {
            // X-Forwarded-For can contain multiple IPs; take the first
            if let Some(first_ip) = xff_str.split(',').next()
                && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
            {
                return Some(ip);
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = request.headers().get("x-real-ip")
            && let Ok(ip_str) = real_ip.to_str()
            && let Ok(ip) = ip_str.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }

    // Fall back to connected address (from ConnectInfo extension)
    // This is always safe to use as it's the actual TCP connection source
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Longest client-supplied request id that reaches an audit record.
///
/// A UUID is 36 characters and every tracing convention in use is shorter than
/// this. The bound is what matters, not the exact number.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Accepts a correlation id only if it is safe to carry into an audit record.
///
/// # Why a client-supplied value is bounded and filtered
///
/// `SetRequestIdLayer` deliberately preserves an inbound `x-request-id` so a
/// trace survives the hop, and that value then becomes the `request_id` on every
/// audit record the request produces. Two things follow that a tracing header
/// does not have to worry about and an audit trail does.
///
/// It is **unbounded**: a header may be kilobytes, so an unauthenticated caller
/// could inflate the audit stream by a large multiple of the requests it sends —
/// against a trail that is a deliverable, and that fails mutating requests
/// closed when its sink cannot keep up. And it is **arbitrary bytes**, which end
/// up in a field operators grep and pipe.
///
/// Anything outside a conservative token alphabet is dropped rather than
/// truncated or escaped: a correlation id is opaque, so a client that sends
/// something unusual loses correlation on that request and nothing else. The
/// server-generated UUID still identifies it, because `SetRequestIdLayer` only
/// declines to *overwrite* — it always ensures one exists.
fn sanitize_request_id(id: &str) -> Option<String> {
    let id = id.trim();
    if id.is_empty() || id.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        .then(|| id.to_string())
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
// Request Context Extractor
// ============================================================================

/// Extractor for the per-request facts a policy may read.
///
/// Never rejects. When the middleware could not establish a source address — an
/// in-process call, or a connection with no `ConnectInfo` — this yields an empty
/// context, and a policy conditioned on the address is unsatisfied. That is the
/// safe direction: a `when` guarding on the address does not permit, and an
/// `unless` guarding on it does not exempt.
///
/// # Example
///
/// ```no_run
/// use rustberg::auth::{AuthenticatedPrincipal, RequestContext};
/// use rustberg::auth::middleware::RequestFacts;
///
/// async fn handler(
///     AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
///     RequestFacts(request): RequestFacts,
/// ) -> String {
///     format!("{} from {:?}", principal.id(), request.source_ip)
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RequestFacts(pub RequestContext);

impl<S> FromRequestParts<S> for RequestFacts
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestFacts(
            parts
                .extensions
                .get::<RequestContext>()
                .cloned()
                .unwrap_or_default(),
        ))
    }
}

impl std::ops::Deref for RequestFacts {
    type Target = RequestContext;

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
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
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

    // ── The correlation id that reaches an audit record ───────────────────

    #[test]
    fn an_ordinary_correlation_id_is_kept() {
        for id in [
            "01895c3e-8844-7fff-a5cb-7a583a3e51fe",
            "req_12345",
            "trace.span:01",
        ] {
            assert_eq!(sanitize_request_id(id), Some(id.to_string()), "{id}");
        }
    }

    /// A header may be kilobytes, and every one of them would land in the audit
    /// stream — an amplifier handed to a caller that has not authenticated yet,
    /// against a trail that fails mutations closed when its sink cannot keep up.
    #[test]
    fn an_oversized_correlation_id_is_dropped() {
        assert_eq!(
            sanitize_request_id(&"a".repeat(MAX_REQUEST_ID_LEN + 1)),
            None
        );
        assert!(sanitize_request_id(&"a".repeat(MAX_REQUEST_ID_LEN)).is_some());
    }

    /// Dropped rather than escaped or truncated: a correlation id is opaque, so
    /// a client that sends something unusual loses correlation on that request
    /// and nothing else — the layer still ensures a server-generated one exists.
    #[test]
    fn a_correlation_id_outside_the_token_alphabet_is_dropped() {
        for id in [
            "",
            "   ",
            "a b",
            "id\"quoted\"",
            "id,with,commas",
            "id/slash",
        ] {
            assert_eq!(sanitize_request_id(id), None, "{id:?} must not be carried");
        }
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
