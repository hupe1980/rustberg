//! Principal represents an authenticated identity in the system.
//!
//! A principal carries identity information, roles, and tenant context
//! for use in authorization decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents an authenticated identity in the system.
///
/// Principals are created by authenticators and carry identity information
/// through the request lifecycle. They are immutable after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Unique identifier for this principal (e.g., user ID, service account ID)
    id: String,

    /// Human-readable name for display purposes
    name: String,

    /// Type of principal (user, service, api_key)
    principal_type: PrincipalType,

    /// Tenant ID for multi-tenancy isolation
    tenant_id: String,

    /// Roles assigned to this principal
    roles: HashSet<String>,

    /// Custom attributes for ABAC policies
    attributes: std::collections::HashMap<String, String>,

    /// When this principal's authentication expires
    expires_at: Option<DateTime<Utc>>,

    /// When this principal was authenticated
    authenticated_at: DateTime<Utc>,

    /// Authentication method used
    auth_method: AuthMethod,
}

impl Principal {
    /// Creates a new principal with required fields.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        principal_type: PrincipalType,
        tenant_id: impl Into<String>,
        auth_method: AuthMethod,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            principal_type,
            tenant_id: tenant_id.into(),
            roles: HashSet::new(),
            attributes: std::collections::HashMap::new(),
            expires_at: None,
            authenticated_at: Utc::now(),
            auth_method,
        }
    }

    /// Creates an anonymous principal (for testing or when auth is disabled).
    pub fn anonymous() -> Self {
        Self::new(
            "anonymous",
            "Anonymous User",
            PrincipalType::Anonymous,
            "default",
            AuthMethod::None,
        )
    }

    /// Creates a system principal for internal operations.
    pub fn system() -> Self {
        let mut principal = Self::new(
            "system",
            "System",
            PrincipalType::System,
            "system",
            AuthMethod::Internal,
        );
        principal.roles.insert("system".to_string());
        principal
    }

    /// Returns the principal's unique identifier.
    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the principal's display name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the principal type.
    #[inline]
    pub fn principal_type(&self) -> &PrincipalType {
        &self.principal_type
    }

    /// Returns the tenant ID for this principal.
    #[inline]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Returns the roles assigned to this principal.
    #[inline]
    pub fn roles(&self) -> &HashSet<String> {
        &self.roles
    }

    /// Checks if the principal has a specific role.
    #[inline]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Returns the custom attributes.
    #[inline]
    pub fn attributes(&self) -> &std::collections::HashMap<String, String> {
        &self.attributes
    }

    /// Gets a specific attribute value.
    #[inline]
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Returns when authentication expires, if set.
    #[inline]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Checks if this principal's authentication has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Returns when this principal was authenticated.
    #[inline]
    pub fn authenticated_at(&self) -> DateTime<Utc> {
        self.authenticated_at
    }

    /// Returns the authentication method used.
    #[inline]
    pub fn auth_method(&self) -> &AuthMethod {
        &self.auth_method
    }

    /// Checks if this is a system principal.
    #[inline]
    pub fn is_system(&self) -> bool {
        matches!(self.principal_type, PrincipalType::System)
    }

    /// Checks if this is an anonymous principal.
    #[inline]
    pub fn is_anonymous(&self) -> bool {
        matches!(self.principal_type, PrincipalType::Anonymous)
    }
}

/// Builder for constructing principals with optional fields.
#[derive(Debug, Default)]
pub struct PrincipalBuilder {
    id: String,
    name: String,
    principal_type: PrincipalType,
    tenant_id: String,
    roles: HashSet<String>,
    attributes: std::collections::HashMap<String, String>,
    expires_at: Option<DateTime<Utc>>,
    auth_method: AuthMethod,
}

impl PrincipalBuilder {
    /// Creates a new builder with required fields.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        principal_type: PrincipalType,
        tenant_id: impl Into<String>,
        auth_method: AuthMethod,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            principal_type,
            tenant_id: tenant_id.into(),
            roles: HashSet::new(),
            attributes: std::collections::HashMap::new(),
            expires_at: None,
            auth_method,
        }
    }

    /// Adds a role to the principal.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// Adds multiple roles to the principal.
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles.extend(roles.into_iter().map(|r| r.into()));
        self
    }

    /// Adds an attribute to the principal.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Sets the expiration time.
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Builds the principal.
    pub fn build(self) -> Principal {
        Principal {
            id: self.id,
            name: self.name,
            principal_type: self.principal_type,
            tenant_id: self.tenant_id,
            roles: self.roles,
            attributes: self.attributes,
            expires_at: self.expires_at,
            authenticated_at: Utc::now(),
            auth_method: self.auth_method,
        }
    }
}

/// Type of principal identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    /// Human user
    User,
    /// Service account or machine identity
    Service,
    /// API key authentication
    ApiKey,
    /// Anonymous/unauthenticated
    #[default]
    Anonymous,
    /// Internal system operations
    System,
}

/// Method used to authenticate the principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No authentication (anonymous)
    #[default]
    None,
    /// API key in header
    ApiKey,
    /// Bearer token (JWT)
    Bearer,
    /// Basic authentication
    Basic,
    /// Mutual TLS client certificate
    MutualTls,
    /// Internal system call
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_creation() {
        let principal = Principal::new(
            "user-123",
            "Test User",
            PrincipalType::User,
            "tenant-1",
            AuthMethod::ApiKey,
        );

        assert_eq!(principal.id(), "user-123");
        assert_eq!(principal.name(), "Test User");
        assert_eq!(principal.tenant_id(), "tenant-1");
        assert!(!principal.is_expired());
        assert!(!principal.is_system());
        assert!(!principal.is_anonymous());
    }

    #[test]
    fn test_principal_builder() {
        let principal = PrincipalBuilder::new(
            "user-456",
            "Builder User",
            PrincipalType::User,
            "tenant-2",
            AuthMethod::Bearer,
        )
        .with_role("admin")
        .with_role("reader")
        .with_attribute("department", "engineering")
        .build();

        assert!(principal.has_role("admin"));
        assert!(principal.has_role("reader"));
        assert!(!principal.has_role("writer"));
        assert_eq!(principal.get_attribute("department"), Some("engineering"));
    }

    #[test]
    fn test_anonymous_principal() {
        let anon = Principal::anonymous();
        assert!(anon.is_anonymous());
        assert!(!anon.is_system());
        assert_eq!(anon.id(), "anonymous");
    }

    #[test]
    fn test_system_principal() {
        let system = Principal::system();
        assert!(system.is_system());
        assert!(system.has_role("system"));
    }

    #[test]
    fn test_principal_expiration() {
        let expired = PrincipalBuilder::new(
            "user-exp",
            "Expired User",
            PrincipalType::User,
            "tenant",
            AuthMethod::ApiKey,
        )
        .expires_at(Utc::now() - chrono::Duration::hours(1))
        .build();

        assert!(expired.is_expired());

        let valid = PrincipalBuilder::new(
            "user-valid",
            "Valid User",
            PrincipalType::User,
            "tenant",
            AuthMethod::ApiKey,
        )
        .expires_at(Utc::now() + chrono::Duration::hours(1))
        .build();

        assert!(!valid.is_expired());
    }
}
