//! API key storage and management.
//!
//! This module provides the storage layer for API keys including
//! an in-memory implementation suitable for development and testing.
//!
//! # Security Model
//!
//! API keys are stored with:
//! - A **key prefix** (first 8 chars of key material) for O(1) lookup
//! - An **Argon2id hash** of the full key for verification
//!
//! This design provides:
//! - Fast lookup without full table scans
//! - Strong protection against database breaches (Argon2id)
//! - Resistance to timing attacks (constant-time verification)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Represents an API key with associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier for this API key.
    pub id: Uuid,

    /// Human-readable name for this key.
    pub name: String,

    /// First 8 characters of the key material (after `rb_` prefix).
    /// Used for fast O(1) lookup before Argon2 verification.
    pub key_prefix: String,

    /// Argon2id hash of the full API key (PHC format).
    /// Contains algorithm, parameters, salt, and hash.
    pub key_hash: String,

    /// Tenant this key belongs to.
    pub tenant_id: String,

    /// Roles granted to this key.
    pub roles: Vec<String>,

    /// Whether this key is enabled.
    pub enabled: bool,

    /// When this key was created.
    pub created_at: DateTime<Utc>,

    /// When this key expires (None = never).
    pub expires_at: Option<DateTime<Utc>>,

    /// When this key was last used.
    pub last_used_at: Option<DateTime<Utc>>,

    /// Number of times this key has been used.
    pub usage_count: u64,

    /// Description/notes about this key.
    pub description: Option<String>,
}

impl ApiKey {
    /// Checks if this key has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }
}

/// Length of the key prefix used for lookup (chars after `rb_`).
const KEY_PREFIX_LEN: usize = 8;

/// Extracts the prefix from an API key for lookup.
///
/// The prefix is the first 8 characters after the `rb_` prefix.
pub fn extract_key_prefix(key: &str) -> Option<String> {
    if key.starts_with("rb_") && key.len() >= 3 + KEY_PREFIX_LEN {
        Some(key[3..3 + KEY_PREFIX_LEN].to_string())
    } else {
        None
    }
}

/// Builder for creating API keys.
#[derive(Debug, Default)]
pub struct ApiKeyBuilder {
    name: String,
    tenant_id: String,
    roles: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    description: Option<String>,
}

impl ApiKeyBuilder {
    /// Creates a new builder with required fields.
    pub fn new(name: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tenant_id: tenant_id.into(),
            roles: Vec::new(),
            expires_at: None,
            description: None,
        }
    }

    /// Adds a role to the key.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Adds multiple roles to the key.
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles.extend(roles.into_iter().map(|r| r.into()));
        self
    }

    /// Sets the expiration time.
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Builds the API key and returns both the key object and the plaintext key.
    ///
    /// The plaintext key should be shown to the user once and never stored.
    /// Uses Argon2id for secure password hashing.
    pub fn build(self) -> (ApiKey, String) {
        let plaintext_key = generate_api_key();
        let key_prefix = extract_key_prefix(&plaintext_key)
            .expect("Generated key should have valid prefix");
        let key_hash = hash_api_key(&plaintext_key);

        let api_key = ApiKey {
            id: Uuid::new_v4(),
            name: self.name,
            key_prefix,
            key_hash,
            tenant_id: self.tenant_id,
            roles: self.roles,
            enabled: true,
            created_at: Utc::now(),
            expires_at: self.expires_at,
            last_used_at: None,
            usage_count: 0,
            description: self.description,
        };

        (api_key, plaintext_key)
    }

    /// Builds the API key from an existing plaintext key.
    ///
    /// Useful for testing or importing keys.
    pub fn build_with_key(self, plaintext_key: &str) -> ApiKey {
        let key_prefix = extract_key_prefix(plaintext_key)
            .unwrap_or_else(|| plaintext_key[..8.min(plaintext_key.len())].to_string());
        let key_hash = hash_api_key(plaintext_key);

        ApiKey {
            id: Uuid::new_v4(),
            name: self.name,
            key_prefix,
            key_hash,
            tenant_id: self.tenant_id,
            roles: self.roles,
            enabled: true,
            created_at: Utc::now(),
            expires_at: self.expires_at,
            last_used_at: None,
            usage_count: 0,
            description: self.description,
        }
    }
}

/// Generates a secure random API key.
///
/// Format: `rb_` prefix followed by 32 random bytes encoded as base64.
fn generate_api_key() -> String {
    use rand::RngCore;

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    format!("rb_{}", base64_encode(&key_bytes))
}

/// Base64 URL-safe encoding without padding.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hashes an API key using Argon2id for secure storage.
///
/// Uses OWASP-recommended parameters for password hashing:
/// - Memory: 19 MiB
/// - Iterations: 2
/// - Parallelism: 1
///
/// Returns a PHC-format string that is self-describing and includes
/// the salt, allowing verification without additional state.
pub fn hash_api_key(key: &str) -> String {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Algorithm, Argon2, Params, Version,
    };
    use rand::rngs::OsRng;

    let params = Params::new(19 * 1024, 2, 1, None).expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);

    argon2
        .hash_password(key.as_bytes(), &salt)
        .expect("Argon2 hashing failed")
        .to_string()
}

/// Verifies an API key against an Argon2id hash.
///
/// Returns `true` if the key matches the hash, `false` otherwise.
/// This operation is constant-time to prevent timing attacks.
pub fn verify_api_key(key: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Algorithm, Argon2, Params, Version,
    };

    let params = Params::new(19 * 1024, 2, 1, None).expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => argon2.verify_password(key.as_bytes(), &parsed_hash).is_ok(),
        Err(_) => false,
    }
}

/// Storage trait for API keys.
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Retrieves API keys by their prefix (first 8 chars of key material).
    /// May return multiple keys if prefixes collide (rare but possible).
    async fn get_by_prefix(&self, key_prefix: &str) -> Vec<ApiKey>;

    /// Retrieves an API key by its ID.
    async fn get_by_id(&self, id: &Uuid) -> Option<ApiKey>;

    /// Lists all API keys for a tenant.
    async fn list_for_tenant(&self, tenant_id: &str) -> Vec<ApiKey>;

    /// Stores a new API key.
    async fn store(&self, key: ApiKey) -> Result<(), String>;

    /// Updates an existing API key.
    async fn update(&self, key: ApiKey) -> Result<(), String>;

    /// Deletes an API key by ID.
    async fn delete(&self, id: &Uuid) -> Result<(), String>;

    /// Records a usage of the API key.
    async fn record_usage(&self, id: &Uuid) -> Result<(), String>;

    /// Disables an API key.
    async fn disable(&self, id: &Uuid) -> Result<(), String>;

    /// Enables an API key.
    async fn enable(&self, id: &Uuid) -> Result<(), String>;
}

// ============================================================================
// InMemoryApiKeyStore
// ============================================================================

/// In-memory implementation of ApiKeyStore.
///
/// Suitable for development, testing, and single-node deployments.
/// Data is lost on restart.
pub struct InMemoryApiKeyStore {
    /// Keys indexed by ID.
    keys_by_id: DashMap<Uuid, ApiKey>,
    /// Keys indexed by prefix (for lookup during authentication).
    /// Multiple keys may share the same prefix (collision), so we store a Vec.
    keys_by_prefix: DashMap<String, Vec<Uuid>>,
    /// Keys indexed by tenant (for listing).
    keys_by_tenant: DashMap<String, Vec<Uuid>>,
    /// Usage counters (separate for concurrent updates).
    usage_counters: DashMap<Uuid, AtomicU64>,
}

impl InMemoryApiKeyStore {
    /// Creates a new empty store.
    pub fn new() -> Self {
        Self {
            keys_by_id: DashMap::new(),
            keys_by_prefix: DashMap::new(),
            keys_by_tenant: DashMap::new(),
            usage_counters: DashMap::new(),
        }
    }

    /// Creates a store with pre-populated keys (useful for testing).
    pub fn with_keys(keys: impl IntoIterator<Item = ApiKey>) -> Self {
        let store = Self::new();
        for key in keys {
            // Use blocking since this is initialization
            let _ = store.store_sync(key);
        }
        store
    }

    fn store_sync(&self, key: ApiKey) -> Result<(), String> {
        let id = key.id;
        let prefix = key.key_prefix.clone();
        let tenant = key.tenant_id.clone();

        // Store the key
        self.keys_by_id.insert(id, key);
        
        // Add to prefix index (allows collisions)
        self.keys_by_prefix
            .entry(prefix)
            .or_default()
            .push(id);
            
        self.usage_counters.insert(id, AtomicU64::new(0));

        // Add to tenant index
        self.keys_by_tenant
            .entry(tenant)
            .or_default()
            .push(id);

        Ok(())
    }
}

impl Default for InMemoryApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApiKeyStore for InMemoryApiKeyStore {
    async fn get_by_prefix(&self, key_prefix: &str) -> Vec<ApiKey> {
        self.keys_by_prefix
            .get(key_prefix)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.keys_by_id.get(id).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_by_id(&self, id: &Uuid) -> Option<ApiKey> {
        self.keys_by_id.get(id).map(|r| r.clone())
    }

    async fn list_for_tenant(&self, tenant_id: &str) -> Vec<ApiKey> {
        self.keys_by_tenant
            .get(tenant_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.keys_by_id.get(id).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn store(&self, key: ApiKey) -> Result<(), String> {
        self.store_sync(key)
    }

    async fn update(&self, key: ApiKey) -> Result<(), String> {
        let id = key.id;
        if !self.keys_by_id.contains_key(&id) {
            return Err("API key not found".into());
        }

        self.keys_by_id.insert(id, key);
        Ok(())
    }

    async fn delete(&self, id: &Uuid) -> Result<(), String> {
        let key = self.keys_by_id.remove(id).ok_or("API key not found")?;

        // Remove from prefix index
        if let Some(mut ids) = self.keys_by_prefix.get_mut(&key.1.key_prefix) {
            ids.retain(|i| i != id);
        }

        // Remove from tenant index
        if let Some(mut ids) = self.keys_by_tenant.get_mut(&key.1.tenant_id) {
            ids.retain(|i| i != id);
        }

        // Remove usage counter
        self.usage_counters.remove(id);

        Ok(())
    }

    async fn record_usage(&self, id: &Uuid) -> Result<(), String> {
        if let Some(counter) = self.usage_counters.get(id) {
            counter.fetch_add(1, Ordering::Relaxed);

            // Update last_used_at
            if let Some(mut key) = self.keys_by_id.get_mut(id) {
                key.last_used_at = Some(Utc::now());
                key.usage_count = counter.load(Ordering::Relaxed);
            }

            Ok(())
        } else {
            Err("API key not found".into())
        }
    }

    async fn disable(&self, id: &Uuid) -> Result<(), String> {
        if let Some(mut key) = self.keys_by_id.get_mut(id) {
            key.enabled = false;
            Ok(())
        } else {
            Err("API key not found".into())
        }
    }

    async fn enable(&self, id: &Uuid) -> Result<(), String> {
        if let Some(mut key) = self.keys_by_id.get_mut(id) {
            key.enabled = true;
            Ok(())
        } else {
            Err("API key not found".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_builder() {
        let (key, plaintext) = ApiKeyBuilder::new("test-key", "tenant-1")
            .with_role("admin")
            .with_role("reader")
            .with_description("Test API key")
            .build();

        assert_eq!(key.name, "test-key");
        assert_eq!(key.tenant_id, "tenant-1");
        assert!(key.enabled);
        assert!(!key.is_expired());
        assert!(plaintext.starts_with("rb_"));
        assert_eq!(key.roles, vec!["admin", "reader"]);
    }

    #[test]
    fn test_api_key_expiration() {
        let key = ApiKeyBuilder::new("expired-key", "tenant-1")
            .expires_at(Utc::now() - chrono::Duration::hours(1))
            .build_with_key("test-key");

        assert!(key.is_expired());

        let key = ApiKeyBuilder::new("valid-key", "tenant-1")
            .expires_at(Utc::now() + chrono::Duration::hours(1))
            .build_with_key("rb_test-key-12345");

        assert!(!key.is_expired());
    }

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryApiKeyStore::new();

        // Use a proper key format with rb_ prefix for valid prefix extraction
        let test_key = "rb_my-secret-key-12345";
        let key = ApiKeyBuilder::new("test-key", "tenant-1")
            .with_role("admin")
            .build_with_key(test_key);

        let key_prefix = key.key_prefix.clone();
        let key_id = key.id;

        // Store the key
        store.store(key.clone()).await.unwrap();

        // Retrieve by prefix and verify with Argon2
        let candidates = store.get_by_prefix(&key_prefix).await;
        assert_eq!(candidates.len(), 1);
        let retrieved = candidates.into_iter()
            .find(|k| verify_api_key(test_key, &k.key_hash));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-key");

        // Retrieve by ID
        let retrieved = store.get_by_id(&key_id).await;
        assert!(retrieved.is_some());

        // List for tenant
        let keys = store.list_for_tenant("tenant-1").await;
        assert_eq!(keys.len(), 1);

        // Record usage
        store.record_usage(&key_id).await.unwrap();
        let retrieved = store.get_by_id(&key_id).await.unwrap();
        assert_eq!(retrieved.usage_count, 1);
        assert!(retrieved.last_used_at.is_some());

        // Disable
        store.disable(&key_id).await.unwrap();
        let retrieved = store.get_by_id(&key_id).await.unwrap();
        assert!(!retrieved.enabled);

        // Enable
        store.enable(&key_id).await.unwrap();
        let retrieved = store.get_by_id(&key_id).await.unwrap();
        assert!(retrieved.enabled);

        // Delete
        store.delete(&key_id).await.unwrap();
        assert!(store.get_by_id(&key_id).await.is_none());
    }

    #[tokio::test]
    async fn test_store_same_prefix_different_keys() {
        // With Argon2, storing keys with the same prefix is allowed
        // (they have different Argon2 hashes)
        let store = InMemoryApiKeyStore::new();

        let key1 = ApiKeyBuilder::new("key-1", "tenant-1").build_with_key("rb_same-prefix-key1");
        let key2 = ApiKeyBuilder::new("key-2", "tenant-1").build_with_key("rb_same-prefix-key2");

        // Both keys have the same prefix but different full keys
        assert_eq!(key1.key_prefix, key2.key_prefix);
        assert_ne!(key1.key_hash, key2.key_hash);

        // Both can be stored
        store.store(key1.clone()).await.unwrap();
        store.store(key2.clone()).await.unwrap();

        // Both can be retrieved by prefix
        let candidates = store.get_by_prefix(&key1.key_prefix).await;
        assert_eq!(candidates.len(), 2);

        // Can verify the correct one with Argon2
        let found = candidates.iter()
            .find(|k| verify_api_key("rb_same-prefix-key1", &k.key_hash));
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "key-1");
    }
}
