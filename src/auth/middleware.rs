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

use super::audit::AuditEvent;
use super::audit_sink::Auditor;
use super::authn::Authenticator;
use super::authz::RequestContext;
use super::error::AuthError;
use super::principal::Principal;
use super::rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};
use crate::remote_ip::{RemoteIp, X_FORWARDED_FOR, X_REAL_IP};

// ============================================================================
// AuthState for Middleware
// ============================================================================

/// Shared state for authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    pub authenticator: Arc<dyn Authenticator>,
    pub rate_limiter: Arc<RateLimiter>,
    /// How the caller's address is worked out.
    ///
    /// Deliberately *not* part of the rate-limiter's configuration. The address
    /// decides three separate things — the rate-limit bucket,
    /// `context.source_ip` in a Cedar policy, and the address on an audit record
    /// — so hanging it off one of the three would let switching rate limiting
    /// off silently change what every address-conditioned policy sees.
    pub remote_ip: RemoteIp,
    /// Where authentication and rate-limit records go.
    ///
    /// The same auditor the catalog guard writes decisions through: there is one
    /// trail, so "was this request authenticated" and "what was it then allowed
    /// to do" are answered by one file.
    pub auditor: Arc<Auditor>,
}

impl AuthState {
    /// Creates a new auth state with the given authenticator.
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            authenticator,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::disabled())),
            remote_ip: RemoteIp::direct(),
            auditor: Arc::new(Auditor::disabled()),
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
            remote_ip: RemoteIp::direct(),
            auditor: Arc::new(Auditor::disabled()),
        }
    }

    /// The same state, resolving caller addresses behind trusted proxies.
    pub fn with_remote_ip(mut self, remote_ip: RemoteIp) -> Self {
        self.remote_ip = remote_ip;
        self
    }

    /// The same state, recording through `auditor`.
    ///
    /// Must be the process's one auditor; see the field.
    pub fn with_auditor(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = auditor;
        self
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
    // One resolution, read by the rate limiter, by `context.source_ip`, and by
    // the audit record. See `remote_ip` for why a forwarding chain is walked
    // from the right.
    let client_ip = extract_client_ip(&request, &auth_state.remote_ip);

    // Read before anything can be refused, so a `401` or a `429` joins to the
    // client's own log line as well as a served request does. Those refusals are
    // the records somebody is watching this stream for.
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_id);

    // Check rate limit before authentication
    if let Some(ip) = client_ip
        && let Err(exceeded) = auth_state.rate_limiter.check_ip_limit(&ip)
    {
        auth_state.auditor.record_lossy(
            &AuditEvent::rate_limit("ip")
                .with_client_ip(ip)
                .with_optional_request_id(request_id.as_deref()),
        );
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
            let auth_method = match principal.auth_method() {
                super::principal::AuthMethod::ApiKey => "api_key",
                super::principal::AuthMethod::Bearer => "jwt",
                super::principal::AuthMethod::None => "anonymous",
                super::principal::AuthMethod::External => "host",
                _ => "other",
            };

            if principal.is_expired() {
                // Recorded whether or not the address resolved: a failure this
                // server cannot attribute is more worth keeping, not less.
                auth_state.auditor.record_lossy(
                    &AuditEvent::authentication(auth_method, false)
                        .with_optional_client_ip(client_ip)
                        .with_optional_request_id(request_id.as_deref())
                        .with_detail("reason", "credential expired"),
                );
                return AuthError::TokenExpired.into_response();
            }

            auth_state.auditor.record_lossy(
                &AuditEvent::authentication(auth_method, true)
                    .with_principal_id(principal.id())
                    .with_tenant_id(principal.tenant_id())
                    .with_optional_client_ip(client_ip)
                    .with_optional_request_id(request_id.as_deref()),
            );

            // Check per-tenant rate limit for authenticated requests
            if let Err(exceeded) = auth_state
                .rate_limiter
                .check_tenant_limit(principal.tenant_id())
            {
                auth_state.auditor.record_lossy(
                    &AuditEvent::rate_limit("tenant")
                        .with_principal_id(principal.id())
                        .with_tenant_id(principal.tenant_id())
                        .with_optional_client_ip(client_ip)
                        .with_optional_request_id(request_id.as_deref()),
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
            if let Some(id) = request_id {
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
            // A *presented* credential that did not verify is the event worth
            // both counting and recording. A request that carried none is not:
            // it is an unauthenticated caller reaching an authenticated server,
            // which is the ordinary shape of a client that has not been
            // configured yet, and counting it would let a stray health checker
            // exhaust the failure budget of everyone sharing its address.
            //
            // The classification lives on `AuthError` rather than here: listed
            // inline, it reads as three variants and leaves out every way a
            // *token* fails — a forged JWT signature is `InvalidToken`, the most
            // expensive rejection this server serves and the cheapest to
            // provoke. See `AuthError::credential_was_rejected`.
            if e.credential_was_rejected() {
                if let Some(ip) = client_ip {
                    auth_state.rate_limiter.record_auth_failure(&ip);
                }
                // Outside the address check, so a deployment whose forwarding
                // chain cannot be read — the case `remote_ip` resolves to
                // *unknown* — still audits its failed authentications.
                auth_state.auditor.record_lossy(
                    &AuditEvent::authentication("unknown", false)
                        .with_optional_client_ip(client_ip)
                        .with_optional_request_id(request_id.as_deref())
                        .with_detail("reason", e.to_string()),
                );
            }
            e.into_response()
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// The caller's address, per this deployment's trusted-proxy configuration.
///
/// The rule and the reasoning live in [`crate::remote_ip`]; this only pulls the
/// headers and the peer address out of the request and hands them over.
fn extract_client_ip(request: &Request<Body>, resolver: &RemoteIp) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // Skipped entirely when no proxy is trusted: the headers cannot change the
    // answer, and cloning them per request to prove that would be waste.
    if !resolver.trusts_any_proxy() {
        return resolver.resolve(peer, &[], None);
    }

    let forwarded: Vec<&str> = request
        .headers()
        .get_all(X_FORWARDED_FOR)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let real_ip = request
        .headers()
        .get(X_REAL_IP)
        .and_then(|value| value.to_str().ok());

    resolver.resolve(peer, &forwarded, real_ip)
}

/// Longest client-supplied request id that reaches an audit record.
///
/// A UUID is 36 characters and every tracing convention in use is shorter than
/// this. The bound is what matters, not the exact number.
/// Longest inbound `x-request-id` this server will carry.
///
/// Every audit record names one, so an unbounded id is an unbounded row and a
/// caller could inflate the trail by a large multiple of the requests it sent.
pub const MAX_REQUEST_ID_LEN: usize = 128;

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
/// The header a request id travels in, named once.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Removes an inbound `x-request-id` this server will not carry, so the layer
/// that mints one replaces it.
///
/// An inbound id is preserved so a trace survives the hop, and bounded so a
/// caller cannot inflate the audit trail with it. The bound has to *replace*
/// rather than ignore: `PropagateRequestIdLayer` echoes whatever it found, so an
/// id dropped only from the record leaves the response naming one thing and the
/// trail naming nothing — which lets a caller unjoin its own requests from the
/// trail by sending a two-kilobyte id.
///
/// Sits outside `SetRequestIdLayer`, which leaves an existing header alone and
/// mints only when there is none.
pub async fn strip_unusable_request_id(mut request: Request<Body>, next: Next) -> Response {
    let unusable = request
        .headers()
        .get_all(REQUEST_ID_HEADER)
        .iter()
        // A repeat is unusable for the same reason a bad character is: which one
        // the trail would name is then a coin toss.
        .try_fold(0usize, |count, value| match (count, value.to_str()) {
            (0, Ok(id)) if is_usable_request_id(id) => Ok(1),
            _ => Err(()),
        })
        .is_err();

    if unusable {
        request.headers_mut().remove(REQUEST_ID_HEADER);
    }

    next.run(request).await
}

/// Whether an inbound `x-request-id` is one this server will carry.
///
/// Read in two places, which is why it is a function rather than a check at each
/// of them: [`strip_unusable_request_id`], which runs *outside* the layer that
/// mints one, and this middleware, which reads whatever survived. If those two
/// disagreed the record and the echoed header would name different things —
/// which is the one thing a request id exists not to do.
pub fn is_usable_request_id(id: &str) -> bool {
    let id = id.trim();
    !id.is_empty()
        && id.len() <= MAX_REQUEST_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

fn sanitize_request_id(id: &str) -> Option<String> {
    is_usable_request_id(id).then(|| id.trim().to_string())
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

    /// The two readers of the rule have to agree, or the id echoed to the client
    /// and the id in the audit record name different things.
    #[test]
    fn the_layer_and_the_record_agree_on_what_is_usable() {
        for id in [
            "9af89211-3ef2-4e97-b516-ffc00ae2274b",
            "trace:abc.123_x",
            &"a".repeat(MAX_REQUEST_ID_LEN),
        ] {
            assert!(is_usable_request_id(id), "{id} should be carried");
            assert_eq!(sanitize_request_id(id).as_deref(), Some(id.trim()));
        }

        for id in [
            "",
            "   ",
            &"a".repeat(MAX_REQUEST_ID_LEN + 1),
            "has space",
            "nul\u{0}",
        ] {
            assert!(!is_usable_request_id(id), "{id:?} should be replaced");
            assert_eq!(sanitize_request_id(id), None);
        }
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
