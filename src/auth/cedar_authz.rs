//! Cedar policy-based authorization.
//!
//! This module provides fine-grained, attribute-based access control using
//! AWS Cedar policy language. Cedar policies are human-readable, validatable,
//! and auditable - making them ideal for compliance and security-critical
//! environments.
//!
//! # Cedar Schema
//!
//! Rustberg uses the following Cedar entity types:
//!
//! - **Principal**: `User` (with tenant, roles as attributes)
//! - **Action**: Iceberg operations (Read, Create, Update, Delete, etc.)
//! - **Resource**: Catalog entities (Namespace, Table, View, etc.)
//!
//! # Example Policies
//!
//! ```cedar
//! // Only admins can create namespaces
//! permit(
//!   principal in Role::"admin",
//!   action == Action::"CreateNamespace",
//!   resource
//! );
//!
//! // Data engineers can write to non-production namespaces
//! permit(
//!   principal in Role::"data-engineer",
//!   action in [Action::"CreateTable", Action::"UpdateTable"],
//!   resource
//! ) when {
//!   !resource.namespace.starts_with("prod")
//! };
//!
//! // Time-based access control
//! permit(
//!   principal,
//!   action == Action::"Read",
//!   resource
//! ) when {
//!   context.time >= "09:00:00" && context.time <= "17:00:00"
//! };
//!
//! // IP-based restrictions for sensitive namespaces
//! forbid(
//!   principal,
//!   action,
//!   resource in Namespace::"sensitive"
//! ) unless {
//!   context.source_ip.isInRange(ip("10.0.0.0/8"))
//! };
//! ```

use async_trait::async_trait;
use cedar_policy::{
    Authorizer as CedarAuthorizerEngine, Context, Decision, Entities, EntityId, EntityTypeName,
    EntityUid, Policy, PolicyId, PolicySet, Request, Schema,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::authz::{Action, AuthzContext, AuthzDecision, Authorizer, Resource, ResourceType};
use super::error::{AuthError, Result};

// ============================================================================
// Cedar Schema Definition (Cedar schema format)
// ============================================================================

/// Rustberg's Cedar schema defining entity types and actions.
const RUSTBERG_CEDAR_SCHEMA: &str = r#"
namespace Rustberg {
    entity User {
        tenant: String,
        roles: Set<String>,
    };
    
    entity Role;
    
    entity Namespace {
        tenant: String,
        path: String,
    };
    
    entity Table in [Namespace] {
        tenant: String,
        namespace: String,
        name: String,
    };
    
    entity View in [Namespace] {
        tenant: String,
        namespace: String,
        name: String,
    };
    
    action Read appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
    
    action List appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
    
    action Create appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
    
    action Update appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
    
    action Delete appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
    
    action Manage appliesTo {
        principal: [User],
        resource: [Namespace, Table, View]
    };
}
"#;

// ============================================================================
// Policy Storage
// ============================================================================

/// Storage for Cedar policies with versioning and hot-reload support.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    policies: Arc<RwLock<PolicySet>>,
    schema: Arc<Schema>,
}

impl PolicyStore {
    /// Creates a new policy store with default policies.
    pub fn new() -> Result<Self> {
        let schema = Schema::from_str(RUSTBERG_CEDAR_SCHEMA)
            .map_err(|e| AuthError::Internal(format!("Invalid Cedar schema: {}", e)))?;

        let mut policy_set = PolicySet::new();

        // Default policy: System principals have full access
        let system_policy = Policy::parse(
            Some(PolicyId::from_str("system-full-access").unwrap()),
            r#"permit(
                principal == Rustberg::User::"system",
                action,
                resource
            );"#,
        )
        .map_err(|e| AuthError::Internal(format!("Invalid default policy: {}", e)))?;
        policy_set.add(system_policy).map_err(|e| {
            AuthError::Internal(format!("Failed to add system policy: {}", e))
        })?;

        // Default policy: Admins have full access within their tenant
        let admin_policy = Policy::parse(
            Some(PolicyId::from_str("admin-full-access").unwrap()),
            r#"permit(
                principal,
                action,
                resource
            ) when {
                principal has roles &&
                principal.roles.contains("admin") &&
                principal.tenant == resource.tenant
            };"#,
        )
        .map_err(|e| AuthError::Internal(format!("Invalid admin policy: {}", e)))?;
        policy_set.add(admin_policy).map_err(|e| {
            AuthError::Internal(format!("Failed to add admin policy: {}", e))
        })?;

        // Default policy: Readers can list and read
        let reader_policy = Policy::parse(
            Some(PolicyId::from_str("reader-access").unwrap()),
            r#"permit(
                principal,
                action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
                resource
            ) when {
                principal has roles &&
                principal.roles.contains("reader") &&
                principal.tenant == resource.tenant
            };"#,
        )
        .map_err(|e| AuthError::Internal(format!("Invalid reader policy: {}", e)))?;
        policy_set.add(reader_policy).map_err(|e| {
            AuthError::Internal(format!("Failed to add reader policy: {}", e))
        })?;

        // Default policy: Writers can create and update
        let writer_policy = Policy::parse(
            Some(PolicyId::from_str("writer-access").unwrap()),
            r#"permit(
                principal,
                action in [Rustberg::Action::"Read", Rustberg::Action::"List", Rustberg::Action::"Create", Rustberg::Action::"Update"],
                resource
            ) when {
                principal has roles &&
                principal.roles.contains("writer") &&
                principal.tenant == resource.tenant
            };"#,
        )
        .map_err(|e| AuthError::Internal(format!("Invalid writer policy: {}", e)))?;
        policy_set.add(writer_policy).map_err(|e| {
            AuthError::Internal(format!("Failed to add writer policy: {}", e))
        })?;

        Ok(Self {
            policies: Arc::new(RwLock::new(policy_set)),
            schema: Arc::new(schema),
        })
    }

    /// Adds a new policy to the store.
    pub async fn add_policy(&self, id: String, policy_text: &str) -> Result<()> {
        let policy_id = PolicyId::from_str(&id)
            .map_err(|e| AuthError::Internal(format!("Invalid policy ID: {}", e)))?;
        let policy = Policy::parse(Some(policy_id), policy_text)
            .map_err(|e| AuthError::Internal(format!("Invalid policy: {}", e)))?;

        // Validate against schema
        // Note: Schema validation requires the cedar-policy-validator crate
        // For now, we just parse and add

        let mut policies = self.policies.write().await;
        policies
            .add(policy)
            .map_err(|e| AuthError::Internal(format!("Failed to add policy: {}", e)))?;

        Ok(())
    }

    /// Removes a policy from the store.
    pub async fn remove_policy(&self, id: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        
        // Convert PolicySet to Vec, filter, and rebuild
        let current_policies: Vec<_> = policies.policies().cloned().collect();
        let mut new_policy_set = PolicySet::new();
        
        let policy_id_to_remove = PolicyId::from_str(id)
            .map_err(|e| AuthError::Internal(format!("Invalid policy ID: {}", e)))?;
        
        for policy in current_policies {
            if policy.id() != &policy_id_to_remove {
                new_policy_set.add(policy).map_err(|e| {
                    AuthError::Internal(format!("Failed to rebuild policy set: {}", e))
                })?;
            }
        }
        
        *policies = new_policy_set;
        Ok(())
    }

    /// Lists all policy IDs in the store.
    pub async fn list_policies(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        policies
            .policies()
            .map(|p| p.id().to_string())
            .collect()
    }

    /// Gets a policy by ID.
    pub async fn get_policy(&self, id: &str) -> Option<String> {
        let policies = self.policies.read().await;
        let policy = policies
            .policies()
            .find(|p| p.id().to_string() == id)?;
        Some(policy.to_string())
    }

    /// Gets a read lock on the policy set for authorization.
    pub(crate) async fn policies(&self) -> tokio::sync::RwLockReadGuard<'_, PolicySet> {
        self.policies.read().await
    }

    /// Gets the Cedar schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new().expect("Default PolicyStore creation failed")
    }
}

// ============================================================================
// Cedar Authorizer
// ============================================================================

/// Cedar-based authorizer implementing fine-grained, policy-based access control.
pub struct CedarAuthorizer {
    policy_store: Arc<PolicyStore>,
    authorizer: CedarAuthorizerEngine,
}

impl CedarAuthorizer {
    /// Creates a new Cedar authorizer.
    pub fn new(policy_store: Arc<PolicyStore>) -> Self {
        Self {
            policy_store,
            authorizer: CedarAuthorizerEngine::new(),
        }
    }

    /// Converts Rustberg Action to Cedar Action EntityUid.
    fn action_to_cedar(action: &Action) -> Result<EntityUid> {
        let action_name = match action {
            Action::Read => "Read",
            Action::List => "List",
            Action::Create => "Create",
            Action::Update => "Update",
            Action::Delete => "Delete",
            Action::Manage => "Manage",
            Action::Grant => "Manage", // Map Grant to Manage
        };

        let type_name = EntityTypeName::from_str("Rustberg::Action")
            .map_err(|e| AuthError::Internal(format!("Invalid action type: {}", e)))?;
        let entity_id = EntityId::from_str(action_name)
            .map_err(|e| AuthError::Internal(format!("Invalid action ID: {}", e)))?;
        
        Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
    }

    /// Converts Rustberg Resource to Cedar Resource EntityUid.
    fn resource_to_cedar(resource: &Resource) -> Result<EntityUid> {
        let (resource_type_name, resource_id) = match resource.resource_type {
            ResourceType::Namespace => {
                let id = resource.namespace.as_ref()
                    .map(|ns| ns.join("/"))
                    .unwrap_or_else(|| "root".to_string());
                ("Namespace", id)
            }
            ResourceType::Table => {
                let ns = resource.namespace.as_ref()
                    .map(|ns| ns.join("/"))
                    .unwrap_or_else(|| "root".to_string());
                let name = resource.name.as_ref()
                    .ok_or_else(|| AuthError::Internal("Table resource missing name".into()))?;
                ("Table", format!("{}/{}", ns, name))
            }
            ResourceType::View => {
                let ns = resource.namespace.as_ref()
                    .map(|ns| ns.join("/"))
                    .unwrap_or_else(|| "root".to_string());
                let name = resource.name.as_ref()
                    .ok_or_else(|| AuthError::Internal("View resource missing name".into()))?;
                ("View", format!("{}/{}", ns, name))
            }
            _ => {
                // For other resource types, use a generic approach
                ("Namespace", resource.path())
            }
        };

        let type_name = EntityTypeName::from_str(&format!("Rustberg::{}", resource_type_name))
            .map_err(|e| AuthError::Internal(format!("Invalid resource type: {}", e)))?;
        let entity_id = EntityId::from_str(&resource_id)
            .map_err(|e| AuthError::Internal(format!("Invalid resource ID: {}", e)))?;
        
        Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
    }

    /// Converts Rustberg AuthzContext to Cedar entities and request.
    fn build_cedar_request(ctx: &AuthzContext) -> Result<(Request, Entities)> {
        // Build principal
        let principal_type = EntityTypeName::from_str("Rustberg::User")
            .map_err(|e| AuthError::Internal(format!("Invalid principal type: {}", e)))?;
        let principal_id = EntityId::from_str(ctx.principal.id())
            .map_err(|e| AuthError::Internal(format!("Invalid principal ID: {}", e)))?;
        let principal_uid = EntityUid::from_type_name_and_id(principal_type, principal_id);

        // Build action
        let action_uid = Self::action_to_cedar(&ctx.action)?;

        // Build resource
        let resource_uid = Self::resource_to_cedar(&ctx.resource)?;

        // Build context (additional attributes like IP, time, etc.)
        let context = Context::empty();

        // Build request
        let request = Request::new(
            principal_uid.clone(),
            action_uid,
            resource_uid.clone(),
            context,
            None, // No schema for now
        )
        .map_err(|e| AuthError::Internal(format!("Failed to create Cedar request: {}", e)))?;

        // Build entities (principal with attributes, resource with attributes)
        let roles_vec: Vec<&str> = ctx.principal.roles().iter().map(|s| s.as_str()).collect();
        let entities_json = serde_json::json!([
            {
                "uid": { "__entity": { "type": "Rustberg::User", "id": ctx.principal.id() } },
                "attrs": {
                    "tenant": ctx.principal.tenant_id(),
                    "roles": roles_vec
                },
                "parents": []
            },
            {
                "uid": { "__entity": { "type": resource_uid.type_name().to_string(), "id": resource_uid.id().escaped() } },
                "attrs": {
                    "tenant": &ctx.resource.tenant_id
                },
                "parents": []
            }
        ]);

        let entities = Entities::from_json_value(entities_json, None)
            .map_err(|e| AuthError::Internal(format!("Failed to create Cedar entities: {}", e)))?;

        Ok((request, entities))
    }
}

#[async_trait]
impl Authorizer for CedarAuthorizer {
    #[allow(clippy::clone_on_copy)]
    async fn authorize(&self, ctx: &AuthzContext) -> AuthzDecision {
        // Build Cedar request and entities
        let (request, entities) = match Self::build_cedar_request(ctx) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to build Cedar request: {}", e);
                return AuthzDecision::Deny(format!("Internal authorization error: {}", e));
            }
        };

        // Get policies and evaluate - using clone() since Decision::clone() returns owned value
        // needed for proper lifetime handling
        let decision = {
            let policies = self.policy_store.policies().await;
            let response = self.authorizer.is_authorized(&request, &policies, &entities);
            response.decision().clone()
        };

        match decision {
            Decision::Allow => AuthzDecision::Allow,
            Decision::Deny => {
                AuthzDecision::Deny(format!(
                    "Access denied: principal '{}' does not have '{}' permission on '{}'",
                    ctx.principal.id(),
                    ctx.action,
                    ctx.resource.resource_type
                ))
            }
        }
    }
}

// ============================================================================
// Policy Management Types
// ============================================================================

/// Request to add a new policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPolicyRequest {
    /// Unique policy ID.
    pub id: String,
    /// Cedar policy text.
    pub policy: String,
    /// Optional description.
    pub description: Option<String>,
}

/// Response for policy operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Policy ID.
    pub id: String,
    /// Cedar policy text.
    pub policy: String,
}

/// List of policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyListResponse {
    /// List of policy IDs.
    pub policies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{AuthMethod, PrincipalBuilder, PrincipalType};

    #[tokio::test]
    async fn test_policy_store_creation() {
        let store = PolicyStore::new().unwrap();
        let policies = store.list_policies().await;
        
        // Should have default policies
        assert!(policies.contains(&"system-full-access".to_string()));
        assert!(policies.contains(&"admin-full-access".to_string()));
        assert!(policies.contains(&"reader-access".to_string()));
        assert!(policies.contains(&"writer-access".to_string()));
    }

    #[tokio::test]
    async fn test_add_custom_policy() {
        let store = PolicyStore::new().unwrap();
        
        let custom_policy = r#"
            permit(
                principal,
                action == Action::"Read",
                resource
            ) when {
                principal.roles.contains("viewer")
            };
        "#;
        
        store.add_policy("viewer-read".to_string(), custom_policy).await.unwrap();
        
        let policies = store.list_policies().await;
        assert!(policies.contains(&"viewer-read".to_string()));
    }

    #[tokio::test]
    async fn test_remove_policy() {
        let store = PolicyStore::new().unwrap();
        
        let custom_policy = r#"
            permit(
                principal,
                action == Action::"Delete",
                resource
            ) when {
                principal.roles.contains("deleter")
            };
        "#;
        
        store.add_policy("deleter-policy".to_string(), custom_policy).await.unwrap();
        assert!(store.list_policies().await.contains(&"deleter-policy".to_string()));
        
        store.remove_policy("deleter-policy").await.unwrap();
        assert!(!store.list_policies().await.contains(&"deleter-policy".to_string()));
    }

    #[tokio::test]
    async fn test_cedar_authorizer_admin_access() {
        let store = Arc::new(PolicyStore::new().unwrap());
        let authorizer = CedarAuthorizer::new(store);

        let principal = PrincipalBuilder::new(
            "admin-user",
            "Admin User",
            PrincipalType::User,
            "tenant1",
            AuthMethod::ApiKey,
        )
        .with_role("admin")
        .build();

        let resource = Resource::namespace("tenant1", vec!["db", "schema"]);

        let ctx = AuthzContext::new(principal, resource, Action::Create);

        let decision = authorizer.authorize(&ctx).await;
        assert!(decision.is_allowed(), "Admin should have full access");
    }

    #[tokio::test]
    async fn test_cedar_authorizer_reader_access() {
        let store = Arc::new(PolicyStore::new().unwrap());
        let authorizer = CedarAuthorizer::new(store);

        let principal = PrincipalBuilder::new(
            "reader-user",
            "Reader User",
            PrincipalType::User,
            "tenant1",
            AuthMethod::ApiKey,
        )
        .with_role("reader")
        .build();

        let resource = Resource::table("tenant1", vec!["db"], "table1");

        // Reader can read
        let ctx = AuthzContext::new(principal.clone(), resource.clone(), Action::Read);
        let decision = authorizer.authorize(&ctx).await;
        assert!(decision.is_allowed(), "Reader should be able to read");

        // Reader cannot create
        let ctx = AuthzContext::new(principal, resource, Action::Create);
        let decision = authorizer.authorize(&ctx).await;
        assert!(decision.is_denied(), "Reader should not be able to create");
    }

    #[tokio::test]
    async fn test_cedar_authorizer_tenant_isolation() {
        let store = Arc::new(PolicyStore::new().unwrap());
        let authorizer = CedarAuthorizer::new(store);

        let principal = PrincipalBuilder::new(
            "user1",
            "User One",
            PrincipalType::User,
            "tenant1",
            AuthMethod::ApiKey,
        )
        .with_role("admin")
        .build();

        // Try to access resource in different tenant
        let resource = Resource::table("tenant2", vec!["db"], "table1");

        let ctx = AuthzContext::new(principal, resource, Action::Read);
        let decision = authorizer.authorize(&ctx).await;
        assert!(decision.is_denied(), "Cross-tenant access should be denied");
    }

    #[tokio::test]
    async fn test_cedar_authorizer_system_principal() {
        let store = Arc::new(PolicyStore::new().unwrap());
        let authorizer = CedarAuthorizer::new(store);

        let principal = PrincipalBuilder::new(
            "system",
            "System",
            PrincipalType::System,
            "_system",
            AuthMethod::Internal,
        )
        .build();

        let resource = Resource::table("tenant1", vec!["db"], "table1");

        let ctx = AuthzContext::new(principal, resource, Action::Manage);
        let decision = authorizer.authorize(&ctx).await;
        assert!(decision.is_allowed(), "System principal should have full access");
    }
}
