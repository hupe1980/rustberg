//! Auth routes for introspection endpoints.
//!
//! This module provides endpoints for clients to introspect their authentication
//! and authorization context, enabling RBAC-aware UIs and CLI tools.

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use super::middleware::AuthenticatedPrincipal;
use super::principal::{AuthMethod, PrincipalType};
use super::{Action, Authorizer, Resource};
use crate::app::AppState;

// ============================================================================
// Auth Context Response Types
// ============================================================================

/// Response for `/auth/context` endpoint.
///
/// Provides the authenticated principal's identity and capabilities,
/// enabling clients to adapt their behavior based on permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContextResponse {
    /// The authenticated principal's information.
    pub principal: PrincipalInfo,
    /// Capabilities the principal has in the current context.
    pub capabilities: Capabilities,
    /// Server-side feature flags that may affect available actions.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub features: HashMap<String, bool>,
}

/// Information about the authenticated principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalInfo {
    /// Unique identifier for the principal.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Type of principal (user, service, api_key, etc.).
    pub principal_type: String,
    /// Tenant ID for multi-tenancy isolation.
    pub tenant_id: String,
    /// Roles assigned to this principal.
    pub roles: Vec<String>,
    /// Authentication method used (api_key, jwt, etc.).
    pub auth_method: String,
    /// When the authentication expires (ISO 8601), if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Capabilities the principal has for various resource types.
///
/// This allows clients (CLI, SDK, future UI) to know what actions
/// are permitted without making trial requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Actions allowed on the catalog itself.
    pub catalog: ActionSet,
    /// Actions allowed on namespaces.
    pub namespaces: ActionSet,
    /// Actions allowed on tables.
    pub tables: ActionSet,
    /// Whether the principal has admin privileges.
    pub is_admin: bool,
}

/// Set of allowed actions for a resource type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionSet {
    pub list: bool,
    pub read: bool,
    pub create: bool,
    pub update: bool,
    pub delete: bool,
    pub manage: bool,
}

impl ActionSet {
    /// Creates an ActionSet with all permissions granted.
    pub fn all() -> Self {
        Self {
            list: true,
            read: true,
            create: true,
            update: true,
            delete: true,
            manage: true,
        }
    }

    /// Creates an ActionSet with read-only permissions.
    pub fn read_only() -> Self {
        Self {
            list: true,
            read: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// Route Handlers
// ============================================================================

/// Handler for `GET /auth/context`.
///
/// Returns the authenticated principal's identity and capabilities.
/// This endpoint is useful for:
/// - CLI tools to understand what operations are available
/// - SDKs to adapt their behavior based on permissions
/// - Future UIs to show/hide features based on RBAC
///
/// # Security
///
/// This endpoint requires authentication. It only reveals information
/// about the authenticated principal, not about other users or the system.
pub async fn get_auth_context(
    State(app_state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
) -> Result<Json<AuthContextResponse>, (StatusCode, &'static str)> {
    // Convert principal type to string
    let principal_type = match principal.principal_type() {
        PrincipalType::User => "user",
        PrincipalType::Service => "service",
        PrincipalType::ApiKey => "api_key",
        PrincipalType::System => "system",
        PrincipalType::Anonymous => "anonymous",
    };

    // Convert auth method to string
    let auth_method = match principal.auth_method() {
        AuthMethod::ApiKey => "api_key",
        AuthMethod::Bearer => "jwt",
        AuthMethod::MutualTls => "mtls",
        AuthMethod::Basic => "basic",
        AuthMethod::Internal => "internal",
        AuthMethod::None => "none",
    };

    // Format expiration time
    let expires_at = principal.expires_at().map(|dt| dt.to_rfc3339());

    // Build principal info
    let principal_info = PrincipalInfo {
        id: principal.id().to_string(),
        name: principal.name().to_string(),
        principal_type: principal_type.to_string(),
        tenant_id: principal.tenant_id().to_string(),
        roles: principal.roles().iter().cloned().collect(),
        auth_method: auth_method.to_string(),
        expires_at,
    };

    // Evaluate capabilities for each resource type
    let capabilities = evaluate_capabilities(&principal, &app_state).await;

    // Build feature flags (currently empty, but extensible)
    let features = HashMap::new();

    Ok(Json(AuthContextResponse {
        principal: principal_info,
        capabilities,
        features,
    }))
}

/// Evaluates the principal's capabilities across resource types.
///
/// This queries the authorizer to determine what actions are allowed
/// for catalog, namespace, and table resources.
async fn evaluate_capabilities(
    principal: &super::Principal,
    app_state: &AppState,
) -> Capabilities {
    let tenant_id = principal.tenant_id();

    // Check if principal has admin/system role
    let is_admin = principal.is_system()
        || principal.has_role("admin")
        || principal.has_role("system")
        || principal.has_role("catalog-admin");

    // For admin users, grant all capabilities
    if is_admin {
        return Capabilities {
            catalog: ActionSet::all(),
            namespaces: ActionSet::all(),
            tables: ActionSet::all(),
            is_admin: true,
        };
    }

    // Evaluate catalog capabilities
    let catalog = evaluate_resource_capabilities(
        principal,
        &app_state.authorizer,
        Resource::catalog(tenant_id),
    )
    .await;

    // Evaluate namespace capabilities (using a dummy namespace for capability check)
    let namespaces = evaluate_resource_capabilities(
        principal,
        &app_state.authorizer,
        Resource::namespace(tenant_id, vec!["*"]),
    )
    .await;

    // Evaluate table capabilities (using a dummy table for capability check)
    let tables = evaluate_resource_capabilities(
        principal,
        &app_state.authorizer,
        Resource::table(tenant_id, vec!["*"], "*"),
    )
    .await;

    Capabilities {
        catalog,
        namespaces,
        tables,
        is_admin: false,
    }
}

/// Evaluates capabilities for a specific resource type.
async fn evaluate_resource_capabilities(
    principal: &super::Principal,
    authorizer: &Arc<dyn Authorizer>,
    resource: Resource,
) -> ActionSet {
    use super::AuthzContext;

    let mut action_set = ActionSet::default();

    // Check List action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::List);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.list = true;
    }

    // Check Read action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Read);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.read = true;
    }

    // Check Create action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Create);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.create = true;
    }

    // Check Update action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Update);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.update = true;
    }

    // Check Delete action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Delete);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.delete = true;
    }

    // Check Manage action
    let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Manage);
    if authorizer.authorize(&ctx).await.is_allowed() {
        action_set.manage = true;
    }

    action_set
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Creates the auth routes.
///
/// # Endpoints
///
/// - `GET /auth/context` - Returns the authenticated principal's context and capabilities
pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/auth/context", get(get_auth_context))
        .with_state(app_state)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_set_all() {
        let actions = ActionSet::all();
        assert!(actions.list);
        assert!(actions.read);
        assert!(actions.create);
        assert!(actions.update);
        assert!(actions.delete);
        assert!(actions.manage);
    }

    #[test]
    fn test_action_set_read_only() {
        let actions = ActionSet::read_only();
        assert!(actions.list);
        assert!(actions.read);
        assert!(!actions.create);
        assert!(!actions.update);
        assert!(!actions.delete);
        assert!(!actions.manage);
    }

    #[test]
    fn test_action_set_default() {
        let actions = ActionSet::default();
        assert!(!actions.list);
        assert!(!actions.read);
        assert!(!actions.create);
        assert!(!actions.update);
        assert!(!actions.delete);
        assert!(!actions.manage);
    }

    #[test]
    fn test_principal_info_serialization() {
        let info = PrincipalInfo {
            id: "user123".to_string(),
            name: "Test User".to_string(),
            principal_type: "user".to_string(),
            tenant_id: "tenant1".to_string(),
            roles: vec!["reader".to_string(), "writer".to_string()],
            auth_method: "api_key".to_string(),
            expires_at: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("user123"));
        assert!(json.contains("Test User"));
        assert!(json.contains("reader"));
    }

    #[test]
    fn test_auth_context_response_serialization() {
        let response = AuthContextResponse {
            principal: PrincipalInfo {
                id: "user123".to_string(),
                name: "Test User".to_string(),
                principal_type: "user".to_string(),
                tenant_id: "tenant1".to_string(),
                roles: vec!["admin".to_string()],
                auth_method: "jwt".to_string(),
                expires_at: Some("2026-01-25T12:00:00Z".to_string()),
            },
            capabilities: Capabilities {
                catalog: ActionSet::all(),
                namespaces: ActionSet::all(),
                tables: ActionSet::all(),
                is_admin: true,
            },
            features: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&response).unwrap();
        assert!(json.contains("user123"));
        assert!(json.contains("is_admin"));
        assert!(json.contains("expires_at"));
    }
}
