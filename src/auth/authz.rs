//! Authorization system for fine-grained access control.
//!
//! This module provides a policy-based authorization system supporting
//! both Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use super::error::{AuthError, Result};
use super::principal::Principal;

// ============================================================================
// Resource and Action Types
// ============================================================================

/// Types of resources that can be protected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// The catalog itself
    Catalog,
    /// A namespace within the catalog
    Namespace,
    /// A table within a namespace
    Table,
    /// A view within a namespace
    View,
    /// A snapshot of a table
    Snapshot,
    /// A branch or tag reference
    Reference,
    /// API key management
    ApiKey,
    /// System administration
    System,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Catalog => write!(f, "catalog"),
            ResourceType::Namespace => write!(f, "namespace"),
            ResourceType::Table => write!(f, "table"),
            ResourceType::View => write!(f, "view"),
            ResourceType::Snapshot => write!(f, "snapshot"),
            ResourceType::Reference => write!(f, "reference"),
            ResourceType::ApiKey => write!(f, "api_key"),
            ResourceType::System => write!(f, "system"),
        }
    }
}

/// Actions that can be performed on resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read/get a resource
    Read,
    /// Create a new resource
    Create,
    /// Update an existing resource
    Update,
    /// Delete a resource
    Delete,
    /// List resources
    List,
    /// Manage (admin-level access)
    Manage,
    /// Grant/revoke access to others
    Grant,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Read => write!(f, "read"),
            Action::Create => write!(f, "create"),
            Action::Update => write!(f, "update"),
            Action::Delete => write!(f, "delete"),
            Action::List => write!(f, "list"),
            Action::Manage => write!(f, "manage"),
            Action::Grant => write!(f, "grant"),
        }
    }
}

/// A specific resource instance being accessed.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Type of the resource.
    pub resource_type: ResourceType,
    /// Tenant the resource belongs to.
    pub tenant_id: String,
    /// Optional catalog name (for multi-catalog deployments).
    pub catalog: Option<String>,
    /// Optional namespace path.
    pub namespace: Option<Vec<String>>,
    /// Optional table/view name.
    pub name: Option<String>,
    /// Additional attributes for ABAC.
    pub attributes: HashMap<String, String>,
}

impl Resource {
    /// Creates a new catalog resource.
    pub fn catalog(tenant_id: impl Into<String>) -> Self {
        Self {
            resource_type: ResourceType::Catalog,
            tenant_id: tenant_id.into(),
            catalog: None,
            namespace: None,
            name: None,
            attributes: HashMap::new(),
        }
    }

    /// Creates a new namespace resource.
    pub fn namespace(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            resource_type: ResourceType::Namespace,
            tenant_id: tenant_id.into(),
            catalog: None,
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: None,
            attributes: HashMap::new(),
        }
    }

    /// Creates a new table resource.
    pub fn table(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
        table_name: impl Into<String>,
    ) -> Self {
        Self {
            resource_type: ResourceType::Table,
            tenant_id: tenant_id.into(),
            catalog: None,
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: Some(table_name.into()),
            attributes: HashMap::new(),
        }
    }

    /// Creates a new view resource.
    pub fn view(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
        view_name: impl Into<String>,
    ) -> Self {
        Self {
            resource_type: ResourceType::View,
            tenant_id: tenant_id.into(),
            catalog: None,
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: Some(view_name.into()),
            attributes: HashMap::new(),
        }
    }

    /// Sets an attribute on the resource.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Returns the full resource path as a string.
    pub fn path(&self) -> String {
        let mut parts = vec![self.tenant_id.clone()];

        if let Some(catalog) = &self.catalog {
            parts.push(catalog.clone());
        }

        if let Some(namespace) = &self.namespace {
            parts.extend(namespace.clone());
        }

        if let Some(name) = &self.name {
            parts.push(name.clone());
        }

        parts.join("/")
    }
}

// ============================================================================
// Authorization Context
// ============================================================================

/// Context for making authorization decisions.
#[derive(Debug, Clone)]
pub struct AuthzContext {
    /// The principal making the request.
    pub principal: Principal,
    /// The resource being accessed.
    pub resource: Resource,
    /// The action being performed.
    pub action: Action,
    /// Additional context attributes.
    pub context: HashMap<String, String>,
}

impl AuthzContext {
    /// Creates a new authorization context.
    pub fn new(principal: Principal, resource: Resource, action: Action) -> Self {
        Self {
            principal,
            resource,
            action,
            context: HashMap::new(),
        }
    }

    /// Adds a context attribute.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

// ============================================================================
// Authorization Decision
// ============================================================================

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied with a reason.
    Deny(String),
}

impl AuthzDecision {
    /// Returns true if access is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow)
    }

    /// Returns true if access is denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, AuthzDecision::Deny(_))
    }

    /// Converts to a Result, returning Err with AuthError::Forbidden if denied.
    pub fn into_result(self) -> Result<()> {
        match self {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny(reason) => Err(AuthError::Forbidden(reason)),
        }
    }
}

// ============================================================================
// Authorizer Trait
// ============================================================================

/// Trait for authorization implementations.
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Checks if the given context is authorized.
    async fn authorize(&self, ctx: &AuthzContext) -> AuthzDecision;

    /// Checks authorization and returns a Result.
    ///
    /// This method also emits audit log events for authorization denials.
    async fn check(&self, ctx: &AuthzContext) -> Result<()> {
        let decision = self.authorize(ctx).await;

        if decision.is_denied() {
            // Emit audit log for authorization denial
            use super::audit::log_authz_denied;
            log_authz_denied(
                ctx.principal.id(),
                ctx.principal.tenant_id(),
                &ctx.resource.resource_type.to_string(),
                &ctx.resource.path(),
                &ctx.action.to_string(),
            );
        }

        decision.into_result()
    }
}

// ============================================================================
// AllowAllAuthorizer
// ============================================================================

/// Authorizer that allows all requests.
///
/// **WARNING**: For development/testing only.
pub struct AllowAllAuthorizer;

#[async_trait]
impl Authorizer for AllowAllAuthorizer {
    async fn authorize(&self, _ctx: &AuthzContext) -> AuthzDecision {
        AuthzDecision::Allow
    }
}

// ============================================================================
// DenyAllAuthorizer
// ============================================================================

/// Authorizer that denies all requests.
pub struct DenyAllAuthorizer;

#[async_trait]
impl Authorizer for DenyAllAuthorizer {
    async fn authorize(&self, _ctx: &AuthzContext) -> AuthzDecision {
        AuthzDecision::Deny("Access denied by default policy".into())
    }
}

// ============================================================================
// RbacAuthorizer
// ============================================================================

/// Role-Based Access Control authorizer.
///
/// Grants access based on role-to-permission mappings.
pub struct RbacAuthorizer {
    /// Maps role names to allowed (ResourceType, Action) pairs.
    role_permissions: HashMap<String, Vec<(ResourceType, Action)>>,
}

impl RbacAuthorizer {
    /// Creates a new RBAC authorizer with default admin role.
    pub fn new() -> Self {
        let mut role_permissions = HashMap::new();

        // Admin role has full access
        role_permissions.insert(
            "admin".to_string(),
            vec![
                (ResourceType::Catalog, Action::Manage),
                (ResourceType::Namespace, Action::Manage),
                (ResourceType::Table, Action::Manage),
                (ResourceType::View, Action::Manage),
                (ResourceType::Snapshot, Action::Manage),
                (ResourceType::Reference, Action::Manage),
                (ResourceType::ApiKey, Action::Manage),
                (ResourceType::System, Action::Manage),
            ],
        );

        // System role (internal operations)
        role_permissions.insert("system".to_string(), role_permissions["admin"].clone());

        // Reader role
        role_permissions.insert(
            "reader".to_string(),
            vec![
                (ResourceType::Catalog, Action::Read),
                (ResourceType::Namespace, Action::Read),
                (ResourceType::Namespace, Action::List),
                (ResourceType::Table, Action::Read),
                (ResourceType::Table, Action::List),
                (ResourceType::View, Action::Read),
                (ResourceType::View, Action::List),
                (ResourceType::Snapshot, Action::Read),
                (ResourceType::Snapshot, Action::List),
            ],
        );

        // Writer role (reader + write)
        role_permissions.insert(
            "writer".to_string(),
            vec![
                // Read permissions
                (ResourceType::Catalog, Action::Read),
                (ResourceType::Namespace, Action::Read),
                (ResourceType::Namespace, Action::List),
                (ResourceType::Table, Action::Read),
                (ResourceType::Table, Action::List),
                (ResourceType::View, Action::Read),
                (ResourceType::View, Action::List),
                (ResourceType::Snapshot, Action::Read),
                (ResourceType::Snapshot, Action::List),
                // Write permissions
                (ResourceType::Namespace, Action::Create),
                (ResourceType::Namespace, Action::Update),
                (ResourceType::Table, Action::Create),
                (ResourceType::Table, Action::Update),
                (ResourceType::View, Action::Create),
                (ResourceType::View, Action::Update),
                (ResourceType::Snapshot, Action::Create),
            ],
        );

        Self { role_permissions }
    }

    /// Adds a custom role with specified permissions.
    pub fn with_role(
        mut self,
        role: impl Into<String>,
        permissions: Vec<(ResourceType, Action)>,
    ) -> Self {
        self.role_permissions.insert(role.into(), permissions);
        self
    }

    /// Checks if the action is implied by Manage permission.
    fn is_manage_implied(action: &Action) -> bool {
        // Manage implies all other actions
        matches!(
            action,
            Action::Read
                | Action::Create
                | Action::Update
                | Action::Delete
                | Action::List
                | Action::Grant
        )
    }
}

impl Default for RbacAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Authorizer for RbacAuthorizer {
    async fn authorize(&self, ctx: &AuthzContext) -> AuthzDecision {
        // System principals always allowed
        if ctx.principal.is_system() {
            return AuthzDecision::Allow;
        }

        // Check each role the principal has
        for role in ctx.principal.roles() {
            if let Some(permissions) = self.role_permissions.get(role) {
                for (resource_type, action) in permissions {
                    // Check for exact match
                    if resource_type == &ctx.resource.resource_type && action == &ctx.action {
                        return AuthzDecision::Allow;
                    }

                    // Check if Manage permission implies the requested action
                    if resource_type == &ctx.resource.resource_type
                        && action == &Action::Manage
                        && Self::is_manage_implied(&ctx.action)
                    {
                        return AuthzDecision::Allow;
                    }
                }
            }
        }

        AuthzDecision::Deny(format!(
            "Principal '{}' does not have '{}' permission on '{}'",
            ctx.principal.id(),
            ctx.action,
            ctx.resource.resource_type
        ))
    }
}

// ============================================================================
// TenantIsolationAuthorizer
// ============================================================================

/// Authorizer that enforces tenant isolation.
///
/// Wraps another authorizer and ensures principals can only access
/// resources within their own tenant.
pub struct TenantIsolationAuthorizer {
    inner: Arc<dyn Authorizer>,
}

impl TenantIsolationAuthorizer {
    /// Creates a new tenant isolation authorizer.
    pub fn new(inner: Arc<dyn Authorizer>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl Authorizer for TenantIsolationAuthorizer {
    async fn authorize(&self, ctx: &AuthzContext) -> AuthzDecision {
        // System principals bypass tenant isolation
        if ctx.principal.is_system() {
            return self.inner.authorize(ctx).await;
        }

        // Check tenant match
        if ctx.principal.tenant_id() != ctx.resource.tenant_id {
            return AuthzDecision::Deny(format!(
                "Cross-tenant access denied: principal tenant '{}' cannot access resource in tenant '{}'",
                ctx.principal.tenant_id(),
                ctx.resource.tenant_id
            ));
        }

        // Delegate to inner authorizer
        self.inner.authorize(ctx).await
    }
}

// ============================================================================
// ChainAuthorizer
// ============================================================================

/// Authorizer that chains multiple authorizers.
///
/// All authorizers must allow for the request to be allowed.
pub struct ChainAuthorizer {
    authorizers: Vec<Arc<dyn Authorizer>>,
}

impl ChainAuthorizer {
    /// Creates a new chain authorizer.
    pub fn new(authorizers: Vec<Arc<dyn Authorizer>>) -> Self {
        Self { authorizers }
    }

    /// Adds an authorizer to the chain.
    pub fn with(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizers.push(authorizer);
        self
    }
}

#[async_trait]
impl Authorizer for ChainAuthorizer {
    async fn authorize(&self, ctx: &AuthzContext) -> AuthzDecision {
        for authorizer in &self.authorizers {
            let decision = authorizer.authorize(ctx).await;
            if decision.is_denied() {
                return decision;
            }
        }
        AuthzDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{AuthMethod, PrincipalBuilder, PrincipalType};

    fn test_principal(roles: Vec<&str>, tenant: &str) -> Principal {
        let mut builder = PrincipalBuilder::new(
            "test-user",
            "Test User",
            PrincipalType::User,
            tenant,
            AuthMethod::ApiKey,
        );
        for role in roles {
            builder = builder.with_role(role);
        }
        builder.build()
    }

    #[tokio::test]
    async fn test_allow_all_authorizer() {
        let authorizer = AllowAllAuthorizer;
        let principal = test_principal(vec![], "tenant-1");
        let resource = Resource::namespace("tenant-1", ["ns1"]);
        let ctx = AuthzContext::new(principal, resource, Action::Read);

        assert!(authorizer.authorize(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_deny_all_authorizer() {
        let authorizer = DenyAllAuthorizer;
        let principal = test_principal(vec!["admin"], "tenant-1");
        let resource = Resource::namespace("tenant-1", ["ns1"]);
        let ctx = AuthzContext::new(principal, resource, Action::Read);

        assert!(authorizer.authorize(&ctx).await.is_denied());
    }

    #[tokio::test]
    async fn test_rbac_admin_role() {
        let authorizer = RbacAuthorizer::new();
        let principal = test_principal(vec!["admin"], "tenant-1");
        let resource = Resource::table("tenant-1", ["ns1"], "table1");
        let ctx = AuthzContext::new(principal, resource, Action::Delete);

        assert!(authorizer.authorize(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_rbac_reader_role() {
        let authorizer = RbacAuthorizer::new();
        let principal = test_principal(vec!["reader"], "tenant-1");

        // Reader can read
        let resource = Resource::table("tenant-1", ["ns1"], "table1");
        let ctx = AuthzContext::new(principal.clone(), resource, Action::Read);
        assert!(authorizer.authorize(&ctx).await.is_allowed());

        // Reader cannot delete
        let resource = Resource::table("tenant-1", ["ns1"], "table1");
        let ctx = AuthzContext::new(principal, resource, Action::Delete);
        assert!(authorizer.authorize(&ctx).await.is_denied());
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let inner = Arc::new(AllowAllAuthorizer);
        let authorizer = TenantIsolationAuthorizer::new(inner);

        // Same tenant - allowed
        let principal = test_principal(vec!["admin"], "tenant-1");
        let resource = Resource::namespace("tenant-1", ["ns1"]);
        let ctx = AuthzContext::new(principal, resource, Action::Read);
        assert!(authorizer.authorize(&ctx).await.is_allowed());

        // Different tenant - denied
        let principal = test_principal(vec!["admin"], "tenant-1");
        let resource = Resource::namespace("tenant-2", ["ns1"]);
        let ctx = AuthzContext::new(principal, resource, Action::Read);
        assert!(authorizer.authorize(&ctx).await.is_denied());
    }

    #[tokio::test]
    async fn test_system_principal_bypasses_isolation() {
        let inner = Arc::new(AllowAllAuthorizer);
        let authorizer = TenantIsolationAuthorizer::new(inner);

        let principal = Principal::system();
        let resource = Resource::namespace("any-tenant", ["ns1"]);
        let ctx = AuthzContext::new(principal, resource, Action::Delete);

        assert!(authorizer.authorize(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_chain_authorizer() {
        let tenant_authz = Arc::new(TenantIsolationAuthorizer::new(Arc::new(AllowAllAuthorizer)));
        let rbac_authz = Arc::new(RbacAuthorizer::new());
        let chain = ChainAuthorizer::new(vec![tenant_authz, rbac_authz]);

        // Admin in correct tenant - allowed
        let principal = test_principal(vec!["admin"], "tenant-1");
        let resource = Resource::table("tenant-1", ["ns1"], "table1");
        let ctx = AuthzContext::new(principal, resource, Action::Delete);
        assert!(chain.authorize(&ctx).await.is_allowed());

        // Reader in correct tenant trying to delete - denied
        let principal = test_principal(vec!["reader"], "tenant-1");
        let resource = Resource::table("tenant-1", ["ns1"], "table1");
        let ctx = AuthzContext::new(principal, resource, Action::Delete);
        assert!(chain.authorize(&ctx).await.is_denied());
    }

    #[test]
    fn test_resource_path() {
        let resource = Resource::table("tenant-1", ["ns1", "ns2"], "my_table");
        assert_eq!(resource.path(), "tenant-1/ns1/ns2/my_table");
    }
}
