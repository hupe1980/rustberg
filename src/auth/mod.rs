//! Authentication and Authorization module.
//!
//! This module provides a comprehensive auth system including:
//! - Multiple authentication methods (API keys, bearer tokens)
//! - Role-based access control (RBAC)
//! - Policy-based access control using AWS Cedar
//! - Tenant isolation
//! - Rate limiting (per-IP, per-tenant, auth failure tracking)
//! - Audit logging for security events
//! - Middleware for protecting routes
//! - Auth introspection endpoints for clients

pub mod audit;
mod authn;
mod authz;
pub mod cedar_authz;
mod error;
mod jwt_authn;
mod middleware;
mod principal;
mod rate_limit;
pub mod routes;
mod store;

// Re-export authenticators
pub use authn::{
    AllowAllAuthenticator, ApiKeyAuthenticator, Authenticator, ChainAuthenticator,
    DenyAllAuthenticator, API_KEY_HEADER, AUTHORIZATION_HEADER,
};

// Re-export JWT/OIDC authentication
pub use jwt_authn::{JwtAuthenticator, JwtConfig};

// Re-export authorization
pub use authz::{
    Action, AllowAllAuthorizer, AuthzContext, AuthzDecision, Authorizer, ChainAuthorizer,
    DenyAllAuthorizer, RbacAuthorizer, Resource, ResourceType, TenantIsolationAuthorizer,
};

// Re-export Cedar policy-based authorization
pub use cedar_authz::{
    AddPolicyRequest, CedarAuthorizer, PolicyListResponse, PolicyResponse, PolicyStore,
};

// Re-export audit logging
pub use audit::{
    AuditAction, AuditCategory, AuditEvent, AuditOutcome, AuditSeverity,
    log_auth_failure, log_auth_success, log_authz_denied, log_namespace_operation,
    log_rate_limit, log_table_operation,
};

// Re-export errors
pub use error::{AuthError, AuthErrorBody, AuthErrorResponse, Result as AuthResult};

// Re-export middleware
pub use middleware::{
    auth_middleware, require_auth_middleware, AuthState, AuthenticatedPrincipal, OptionalPrincipal,
};

// Re-export principal types
pub use principal::{AuthMethod, Principal, PrincipalBuilder, PrincipalType};

// Re-export rate limiting
pub use rate_limit::{
    LimitType, RateLimitConfig, RateLimitConfigBuilder, RateLimitErrorBody,
    RateLimitErrorResponse, RateLimitExceeded, RateLimitInfo, RateLimiter,
};

// Re-export store types
pub use store::{
    extract_key_prefix, hash_api_key, verify_api_key, ApiKey, ApiKeyBuilder, ApiKeyStore,
    InMemoryApiKeyStore,
};
