//! Persistent API key storage using the generic KvStore abstraction.
//!
//! This provides API key storage that works with any KvStore backend:
//! - **MemoryKvStore**: For testing
//! - **SlateDB + file://**: Single-node local storage (pure Rust, no C++)
//! - **SlateDB + s3://**: K8s horizontal scaling with shared object storage
//!
//! # Key Schema
//!
//! Uses key prefixes to emulate column families:
//! - `apikey:id:{uuid}` → Encrypted ApiKey JSON
//! - `apikey:prefix:{prefix}:{uuid}` → UUID bytes (pointer to primary)
//! - `apikey:tenant:{tenant}:{uuid}` → Encrypted ApiKey JSON
//!
//! # Encryption
//!
//! All ApiKey data is encrypted at rest using the provided EncryptionProvider.
//! Only the index keys are stored in plaintext for lookups.

use crate::auth::{ApiKey, ApiKeyStore};
use crate::crypto::{EncryptionProvider, NoopEncryptionProvider};
use crate::storage::kv_store::{KvStore, WriteBatch};
use async_trait::async_trait;
use chrono::Utc;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

/// Key prefix constants for the different indexes
const PREFIX_BY_ID: &[u8] = b"apikey:id:";
const PREFIX_BY_PREFIX: &[u8] = b"apikey:prefix:";
const PREFIX_BY_TENANT: &[u8] = b"apikey:tenant:";

/// Errors that can occur during storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("API key not found: {0}")]
    NotFound(String),

    #[error("API key already exists: {0}")]
    AlreadyExists(String),

    #[error("Encryption error: {0}")]
    Encryption(String),
}

/// Result type for storage operations.
pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// Persistent storage backend for API keys using the generic KvStore interface.
///
/// Features:
/// - Works with any KvStore backend (SlateDB, Memory, etc.)
/// - Atomic batch operations
/// - Multiple indexes (by ID, prefix, tenant)
/// - **Encryption-at-rest** using AES-256-GCM
/// - **K8s horizontal scaling** when using SlateDB + S3
pub struct KvApiKeyStore {
    kv: Arc<dyn KvStore>,
    encryption: Arc<dyn EncryptionProvider>,
}

impl fmt::Debug for KvApiKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvApiKeyStore")
            .field("kv", &self.kv)
            .field("encryption", &"<EncryptionProvider>")
            .finish()
    }
}

impl KvApiKeyStore {
    /// Create a new API key store using the provided KvStore backend.
    ///
    /// # Arguments
    /// * `kv` - The underlying key-value store (SlateDB, Memory, etc.)
    /// * `encryption` - Optional encryption provider (defaults to no encryption)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use rustberg::storage::{MemoryKvStore, KvApiKeyStore};
    /// use rustberg::crypto::Aes256GcmProvider;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // For testing with in-memory store
    /// let kv = Arc::new(MemoryKvStore::new());
    /// let store = KvApiKeyStore::new(kv.clone(), None);
    ///
    /// // For production with encryption
    /// let key = [0u8; 32]; // Your encryption key
    /// let encryption = Arc::new(Aes256GcmProvider::new(&key)?);
    /// let store = KvApiKeyStore::new(kv, Some(encryption));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(kv: Arc<dyn KvStore>, encryption: Option<Arc<dyn EncryptionProvider>>) -> Self {
        let encryption = encryption.unwrap_or_else(|| Arc::new(NoopEncryptionProvider));
        Self { kv, encryption }
    }

    /// Returns the underlying KvStore backend name.
    pub fn backend_name(&self) -> &'static str {
        self.kv.backend_name()
    }

    /// Returns true if this backend supports horizontal scaling.
    pub fn supports_horizontal_scaling(&self) -> bool {
        self.kv.supports_horizontal_scaling()
    }

    /// Build the primary key for an API key by ID.
    fn key_by_id(id: &Uuid) -> Vec<u8> {
        let mut key = PREFIX_BY_ID.to_vec();
        key.extend_from_slice(id.to_string().as_bytes());
        key
    }

    /// Build the secondary key for prefix lookup.
    /// Format: apikey:prefix:{prefix}:{id}
    fn key_by_prefix(prefix: &str, id: &Uuid) -> Vec<u8> {
        let mut key = PREFIX_BY_PREFIX.to_vec();
        key.extend_from_slice(prefix.as_bytes());
        key.push(b':');
        key.extend_from_slice(id.to_string().as_bytes());
        key
    }

    /// Build the prefix for scanning all keys with a given prefix.
    fn prefix_scan_key(prefix: &str) -> Vec<u8> {
        let mut key = PREFIX_BY_PREFIX.to_vec();
        key.extend_from_slice(prefix.as_bytes());
        key.push(b':');
        key
    }

    /// Build the tenant index key.
    fn key_by_tenant(tenant_id: &str, id: &Uuid) -> Vec<u8> {
        let mut key = PREFIX_BY_TENANT.to_vec();
        key.extend_from_slice(tenant_id.as_bytes());
        key.push(b':');
        key.extend_from_slice(id.to_string().as_bytes());
        key
    }

    /// Build the tenant prefix for scanning.
    fn tenant_prefix(tenant_id: &str) -> Vec<u8> {
        let mut key = PREFIX_BY_TENANT.to_vec();
        key.extend_from_slice(tenant_id.as_bytes());
        key.push(b':');
        key
    }

    /// Encrypts data before storage.
    fn encrypt(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        self.encryption
            .encrypt(data)
            .map_err(|e| StorageError::Encryption(e.to_string()))
    }

    /// Decrypts data after retrieval.
    fn decrypt(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        self.encryption
            .decrypt(data)
            .map_err(|e| StorageError::Encryption(e.to_string()))
    }

    /// Convert KvResult to StorageResult
    fn map_kv_error(err: crate::storage::kv_store::KvError) -> StorageError {
        StorageError::Database(err.to_string())
    }

    /// Store an API key with all indexes atomically.
    async fn store_internal(&self, api_key: &ApiKey) -> StorageResult<()> {
        let serialized = serde_json::to_vec(api_key)?;
        let encrypted = self.encrypt(&serialized)?;

        // Check if key already exists
        let id_key = Self::key_by_id(&api_key.id);
        if self
            .kv
            .get(&id_key)
            .await
            .map_err(Self::map_kv_error)?
            .is_some()
        {
            return Err(StorageError::AlreadyExists(api_key.id.to_string()));
        }

        // Build atomic batch
        let mut batch = WriteBatch::new();

        // Primary index: id -> Encrypted ApiKey
        batch.put(id_key, encrypted.clone());

        // Secondary index: prefix:id -> id string (for prefix lookup)
        batch.put(
            Self::key_by_prefix(&api_key.key_prefix, &api_key.id),
            api_key.id.to_string().as_bytes().to_vec(),
        );

        // Tenant index: tenant:id -> Encrypted ApiKey
        batch.put(
            Self::key_by_tenant(&api_key.tenant_id, &api_key.id),
            encrypted,
        );

        self.kv
            .write_batch(batch)
            .await
            .map_err(Self::map_kv_error)?;
        Ok(())
    }

    /// Retrieve an API key by its unique ID.
    async fn get_by_id_internal(&self, id: &Uuid) -> StorageResult<Option<ApiKey>> {
        let key = Self::key_by_id(id);
        let value = self.kv.get(&key).await.map_err(Self::map_kv_error)?;

        match value {
            Some(encrypted_bytes) => {
                let decrypted = self.decrypt(&encrypted_bytes)?;
                let api_key: ApiKey = serde_json::from_slice(&decrypted)?;
                Ok(Some(api_key))
            }
            None => Ok(None),
        }
    }

    /// Retrieve all API keys matching a given prefix.
    ///
    /// This is the primary lookup path for authentication. Multiple keys
    /// may share the same prefix (8 chars), so we return all candidates
    /// for verification via Argon2.
    async fn get_by_prefix_internal(&self, key_prefix: &str) -> StorageResult<Vec<ApiKey>> {
        let scan_prefix = Self::prefix_scan_key(key_prefix);
        let entries = self
            .kv
            .scan_prefix(&scan_prefix)
            .await
            .map_err(Self::map_kv_error)?;

        let mut keys = Vec::new();
        for entry in entries {
            // Value is the UUID string
            let id_str = String::from_utf8_lossy(&entry.value);
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Ok(Some(api_key)) = self.get_by_id_internal(&id).await {
                    keys.push(api_key);
                }
            }
        }

        Ok(keys)
    }

    /// List all API keys for a specific tenant.
    async fn list_by_tenant_internal(&self, tenant_id: &str) -> StorageResult<Vec<ApiKey>> {
        let prefix = Self::tenant_prefix(tenant_id);
        let entries = self
            .kv
            .scan_prefix(&prefix)
            .await
            .map_err(Self::map_kv_error)?;

        let mut keys = Vec::new();
        for entry in entries {
            match self.decrypt(&entry.value) {
                Ok(decrypted) => match serde_json::from_slice::<ApiKey>(&decrypted) {
                    Ok(api_key) => keys.push(api_key),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize API key: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to decrypt API key: {}", e);
                }
            }
        }

        Ok(keys)
    }

    /// Update an existing API key.
    async fn update_internal(&self, api_key: &ApiKey) -> StorageResult<()> {
        let serialized = serde_json::to_vec(api_key)?;
        let encrypted = self.encrypt(&serialized)?;

        // Verify key exists
        let id_key = Self::key_by_id(&api_key.id);
        if self
            .kv
            .get(&id_key)
            .await
            .map_err(Self::map_kv_error)?
            .is_none()
        {
            return Err(StorageError::NotFound(api_key.id.to_string()));
        }

        // Build atomic batch
        let mut batch = WriteBatch::new();

        // Update primary index
        batch.put(id_key, encrypted.clone());

        // Update tenant index
        batch.put(
            Self::key_by_tenant(&api_key.tenant_id, &api_key.id),
            encrypted,
        );

        // Note: We don't update the prefix index because the prefix never changes

        self.kv
            .write_batch(batch)
            .await
            .map_err(Self::map_kv_error)?;
        Ok(())
    }

    /// Delete an API key by ID.
    ///
    /// Removes the key from all indexes atomically.
    async fn delete_internal(&self, id: &Uuid) -> StorageResult<()> {
        // First, retrieve the key to get prefix and tenant for index cleanup
        let api_key = self
            .get_by_id_internal(id)
            .await?
            .ok_or_else(|| StorageError::NotFound(id.to_string()))?;

        // Build atomic batch
        let mut batch = WriteBatch::new();

        // Delete from all indexes
        batch.delete(Self::key_by_id(id));
        batch.delete(Self::key_by_prefix(&api_key.key_prefix, id));
        batch.delete(Self::key_by_tenant(&api_key.tenant_id, id));

        self.kv
            .write_batch(batch)
            .await
            .map_err(Self::map_kv_error)?;
        Ok(())
    }
}

#[async_trait]
impl ApiKeyStore for KvApiKeyStore {
    async fn get_by_prefix(&self, key_prefix: &str) -> Vec<ApiKey> {
        self.get_by_prefix_internal(key_prefix)
            .await
            .unwrap_or_default()
    }

    async fn get_by_id(&self, id: &Uuid) -> Option<ApiKey> {
        self.get_by_id_internal(id).await.ok().flatten()
    }

    async fn list_for_tenant(&self, tenant_id: &str) -> Vec<ApiKey> {
        self.list_by_tenant_internal(tenant_id)
            .await
            .unwrap_or_default()
    }

    async fn store(&self, key: ApiKey) -> Result<(), String> {
        self.store_internal(&key).await.map_err(|e| e.to_string())
    }

    async fn update(&self, key: ApiKey) -> Result<(), String> {
        self.update_internal(&key).await.map_err(|e| e.to_string())
    }

    async fn delete(&self, id: &Uuid) -> Result<(), String> {
        self.delete_internal(id).await.map_err(|e| e.to_string())
    }

    async fn record_usage(&self, id: &Uuid) -> Result<(), String> {
        // Get the current key
        let mut api_key = self.get_by_id(id).await.ok_or("API key not found")?;

        // Update usage fields
        api_key.last_used_at = Some(Utc::now());
        api_key.usage_count += 1;

        // Store updated key
        self.update(api_key).await
    }

    async fn disable(&self, id: &Uuid) -> Result<(), String> {
        let mut api_key = self.get_by_id(id).await.ok_or("API key not found")?;
        api_key.enabled = false;
        self.update(api_key).await
    }

    async fn enable(&self, id: &Uuid) -> Result<(), String> {
        let mut api_key = self.get_by_id(id).await.ok_or("API key not found")?;
        api_key.enabled = true;
        self.update(api_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Aes256GcmProvider;
    use crate::storage::MemoryKvStore;

    fn create_test_api_key(name: &str, prefix: &str, hash: &str) -> ApiKey {
        ApiKey {
            id: Uuid::new_v4(),
            name: name.to_string(),
            key_prefix: prefix.to_string(),
            key_hash: hash.to_string(),
            tenant_id: "test-tenant".to_string(),
            roles: vec!["user".to_string()],
            enabled: true,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            usage_count: 0,
            description: None,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve_by_id() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("test-key", "abc12345", "hash123");
        let id = api_key.id;

        store.store(api_key).await.unwrap();

        let retrieved = store.get_by_id(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-key");
    }

    #[tokio::test]
    async fn test_store_and_retrieve_by_prefix() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("prefix-key", "uniq1234", "unique_hash_123");
        let prefix = api_key.key_prefix.clone();

        store.store(api_key).await.unwrap();

        let candidates = store.get_by_prefix(&prefix).await;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "prefix-key");
    }

    #[tokio::test]
    async fn test_multiple_keys_same_prefix() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        // Create multiple keys with the same prefix (simulating collision)
        let key1 = create_test_api_key("key1", "sameprfx", "hash1_unique");
        let key2 = create_test_api_key("key2", "sameprfx", "hash2_unique");

        store.store(key1).await.unwrap();
        store.store(key2).await.unwrap();

        // Both should be returned for the same prefix
        let candidates = store.get_by_prefix("sameprfx").await;
        assert_eq!(candidates.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_tenant() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        // Create multiple keys for same tenant
        let key1 = create_test_api_key("key1", "prefix01", "hash1_unique");
        let key2 = create_test_api_key("key2", "prefix02", "hash2_unique");

        store.store(key1).await.unwrap();
        store.store(key2).await.unwrap();

        let keys = store.list_for_tenant("test-tenant").await;
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_update() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let mut api_key = create_test_api_key("update-key", "update12", "update_hash_123");
        let id = api_key.id;

        store.store(api_key.clone()).await.unwrap();

        // Update the key
        api_key.name = "updated-name".to_string();
        api_key.enabled = false;
        store.update(api_key).await.unwrap();

        let retrieved = store.get_by_id(&id).await.unwrap();
        assert_eq!(retrieved.name, "updated-name");
        assert!(!retrieved.enabled);
    }

    #[tokio::test]
    async fn test_delete() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("delete-key", "delete12", "delete_hash_123");
        let id = api_key.id;
        let prefix = api_key.key_prefix.clone();

        store.store(api_key).await.unwrap();
        assert!(store.get_by_id(&id).await.is_some());

        store.delete(&id).await.unwrap();

        // All lookups should fail
        assert!(store.get_by_id(&id).await.is_none());
        assert!(store.get_by_prefix(&prefix).await.is_empty());
    }

    #[tokio::test]
    async fn test_record_usage() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("usage-key", "usage123", "usage_hash_123");
        let id = api_key.id;

        store.store(api_key).await.unwrap();

        // Record usage
        store.record_usage(&id).await.unwrap();
        store.record_usage(&id).await.unwrap();

        let retrieved = store.get_by_id(&id).await.unwrap();
        assert_eq!(retrieved.usage_count, 2);
        assert!(retrieved.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_enable_disable() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("toggle-key", "toggle12", "toggle_hash_123");
        let id = api_key.id;

        store.store(api_key).await.unwrap();

        // Disable
        store.disable(&id).await.unwrap();
        assert!(!store.get_by_id(&id).await.unwrap().enabled);

        // Enable
        store.enable(&id).await.unwrap();
        assert!(store.get_by_id(&id).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_with_encryption() {
        let kv = Arc::new(MemoryKvStore::new());
        let key = Aes256GcmProvider::generate_key();
        let encryption = Arc::new(Aes256GcmProvider::new(&key).unwrap());
        let store = KvApiKeyStore::new(kv, Some(encryption));

        let api_key = create_test_api_key("encrypted-key", "encrypt1", "encrypted_hash_123");
        let id = api_key.id;
        let prefix = api_key.key_prefix.clone();

        // Store with encryption
        store.store(api_key).await.unwrap();

        // Retrieve and decrypt
        let retrieved = store.get_by_id(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "encrypted-key");

        // Also verify prefix lookup works
        let candidates = store.get_by_prefix(&prefix).await;
        assert_eq!(candidates.len(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_key_rejected() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("dup-key", "dup12345", "dup_hash_123");

        store.store(api_key.clone()).await.unwrap();

        // Second store should fail
        let result = store.store(api_key).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[tokio::test]
    async fn test_update_nonexistent_fails() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let api_key = create_test_api_key("nonexistent", "nonexist", "nonexistent_hash");

        let result = store.update(api_key).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_fails() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        let result = store.delete(&Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_backend_name() {
        let kv = Arc::new(MemoryKvStore::new());
        let store = KvApiKeyStore::new(kv, None);

        assert_eq!(store.backend_name(), "memory");
        assert!(!store.supports_horizontal_scaling());
    }
}
