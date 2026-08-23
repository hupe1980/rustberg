//! Authentication and authorization.
//!
//! The two are deliberately separate concerns with a single meeting point, the
//! [`Principal`]:
//!
//! ```text
//!   credential ──▶ Authenticator ──▶ Principal ──▶ Authorizer ──▶ decision
//!                  (who are you?)                  (may you?)      + obligations
//! ```
//!
//! **Authentication** lives at the edge, in [`middleware`], because an embedding
//! host has already authenticated its caller and should not have to attach a JWKS
//! client to say so. It establishes a [`Principal`] and puts it in the request
//! extensions alongside the [`RequestContext`] a policy may read.
//!
//! **Authorization** is [`Authorizer`], with [`CedarAuthorizer`] as the shipping
//! implementation. It takes a principal, an action and a resource and returns a
//! decision plus any [`Obligations`] the matching policies carry.
//!
//! Also here: rate limiting ([`RateLimiter`], per-IP and per-tenant, applied
//! ahead of authentication so an unauthenticated flood is cheap to shed) and
//! [`audit`].

pub mod audit;
pub mod audit_sink;
mod authn;
mod authz;
pub mod cedar;
mod error;
pub mod filter_alignment;
mod jwt_authn;
pub mod middleware;
pub mod policy_store;
mod principal;
mod rate_limit;
pub mod reloadable;
pub mod routes;
mod store;

// Re-export authenticators
pub use authn::{
    API_KEY_HEADER, AUTHORIZATION_HEADER, AllowAllAuthenticator, ApiKeyAuthenticator,
    Authenticator, ChainAuthenticator, DenyAllAuthenticator,
};

// Re-export JWT/OIDC authentication
pub use jwt_authn::{JwtAuthenticator, JwtConfig};

// Re-export authorization
pub use authz::{
    Action, AllowAllAuthorizer, Authorizer, AuthzContext, AuthzDecision, AuthzOutcome,
    DenyAllAuthorizer, Obligations, RequestContext, Resource, ResourceType,
};

// Re-export audit logging
pub use audit::{
    AuditAction, AuditCategory, AuditEvent, AuditOutcome, AuditSeverity, log_auth_failure,
    log_auth_success, log_rate_limit,
};
pub use audit_sink::{AuditError, AuditSink, Auditor, FileSink, NullSink, StdoutSink};

// Re-export Cedar policy-based authorization
pub use cedar::{CedarAuthorizer, DEFAULT_POLICIES};
pub use error::{AuthError, AuthErrorBody, AuthErrorResponse, Result as AuthResult};

// Re-export middleware
pub use middleware::{
    AuthState, AuthenticatedPrincipal, OptionalPrincipal, RequestFacts, auth_middleware,
};

// Re-export principal types
pub use principal::{AuthMethod, Principal, PrincipalBuilder, PrincipalType};

// Re-export rate limiting
pub use rate_limit::{
    LimitType, RateLimitConfig, RateLimitConfigBuilder, RateLimitErrorBody, RateLimitErrorResponse,
    RateLimitExceeded, RateLimitInfo, RateLimiter,
};

// Re-export store types
pub use store::{
    ApiKey, ApiKeyBuilder, ApiKeyStore, InMemoryApiKeyStore, extract_key_prefix, hash_api_key,
    verify_api_key,
};
