//! Persistent idempotency store for safe retries across restarts.
//!
//! This module provides a persistent backing store for idempotency keys,
//! preventing replay attacks after server restart.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    IdempotencyCache                         │
//! │  ┌─────────────────────┐   ┌─────────────────────────────┐  │
//! │  │   L1: DashMap       │   │   L2: IdempotencyStore      │  │
//! │  │   (fast lookups)    │───│   (persistent backing)      │  │
//! │  └─────────────────────┘   └─────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! - **L1 Cache**: In-memory DashMap for sub-millisecond lookups
//! - **L2 Store**: SlateDB persistence for durability across restarts
//! - **Write-through**: Both layers updated on set
//! - **Read-through**: L1 miss falls back to L2

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use crate::error::{AppError, Result};

// ============================================================================
// IdempotencyStore Trait
// ============================================================================

/// Persistent entry for an idempotency key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyEntry {
    /// The idempotency key value.
    pub key: String,
    /// The scope (method:path).
    pub scope: String,
    /// HTTP status code of the cached response.
    pub status_code: u16,
    /// Response body (typically small JSON).
    pub response_body: Vec<u8>,
    /// Content type of the response.
    pub content_type: Option<String>,
    /// Unix timestamp (millis) when this entry was created.
    pub created_at_ms: u64,
    /// TTL in milliseconds.
    pub ttl_ms: u64,
}

impl IdempotencyEntry {
    /// Creates a new idempotency entry.
    pub fn new(
        key: String,
        scope: String,
        status_code: u16,
        response_body: Vec<u8>,
        content_type: Option<String>,
        ttl: Duration,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            key,
            scope,
            status_code,
            response_body,
            content_type,
            created_at_ms: now,
            ttl_ms: ttl.as_millis() as u64,
        }
    }

    /// Checks if this entry has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        now > self.created_at_ms + self.ttl_ms
    }

    /// Returns the storage key for this entry.
    pub fn storage_key(&self) -> String {
        format!("idempotency:{}:{}", self.scope, self.key)
    }
}

/// Trait for idempotency key storage backends.
#[async_trait]
pub trait IdempotencyStore: Send + Sync + std::fmt::Debug {
    /// Gets an idempotency entry by key and scope.
    /// Returns None if not found or expired.
    async fn get(&self, scope: &str, key: &str) -> Result<Option<IdempotencyEntry>>;

    /// Stores an idempotency entry.
    async fn set(&self, entry: IdempotencyEntry) -> Result<()>;

    /// Removes an idempotency entry.
    async fn remove(&self, scope: &str, key: &str) -> Result<()>;

    /// Cleans up all expired entries.
    /// Returns the number of entries removed.
    async fn cleanup_expired(&self) -> Result<usize>;

    /// Returns the count of stored entries.
    async fn count(&self) -> Result<usize>;
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// Type alias for the in-memory map.
type IdempotencyMap = HashMap<String, IdempotencyEntry>;

/// In-memory idempotency store for development/testing.
///
/// **Warning:** Entries are lost on server restart.
#[derive(Debug, Default)]
pub struct MemoryIdempotencyStore {
    entries: RwLock<IdempotencyMap>,
}

impl MemoryIdempotencyStore {
    /// Creates a new in-memory idempotency store.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn make_key(scope: &str, key: &str) -> String {
        format!("{}:{}", scope, key)
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotencyStore {
    async fn get(&self, scope: &str, key: &str) -> Result<Option<IdempotencyEntry>> {
        let map_key = Self::make_key(scope, key);
        let entries = self.entries.read();

        match entries.get(&map_key) {
            Some(entry) if !entry.is_expired() => Ok(Some(entry.clone())),
            Some(_) => {
                // Entry is expired, remove it
                drop(entries);
                let mut entries = self.entries.write();
                entries.remove(&map_key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, entry: IdempotencyEntry) -> Result<()> {
        let map_key = format!("{}:{}", entry.scope, entry.key);
        let mut entries = self.entries.write();
        entries.insert(map_key, entry);
        Ok(())
    }

    async fn remove(&self, scope: &str, key: &str) -> Result<()> {
        let map_key = Self::make_key(scope, key);
        let mut entries = self.entries.write();
        entries.remove(&map_key);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        Ok(before - entries.len())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.entries.read().len())
    }
}

// ============================================================================
// SlateDB Implementation
// ============================================================================

#[cfg(feature = "slatedb-storage")]
mod slatedb_impl {
    use super::*;
    use slatedb::Db;

    /// Persistent idempotency store backed by SlateDB.
    ///
    /// Entries are stored with key pattern: `idempotency:{scope}:{key}`
    pub struct SlateDbIdempotencyStore {
        /// SlateDB instance.
        db: Arc<Db>,
    }

    impl std::fmt::Debug for SlateDbIdempotencyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SlateDbIdempotencyStore")
                .finish_non_exhaustive()
        }
    }

    impl SlateDbIdempotencyStore {
        /// Creates a new SlateDB-backed idempotency store.
        pub fn new(db: Arc<Db>) -> Self {
            Self { db }
        }

        /// Generates a storage key for an idempotency entry.
        fn storage_key(scope: &str, key: &str) -> Vec<u8> {
            format!("idempotency:{}:{}", scope, key).into_bytes()
        }

        /// Prefix for scanning all idempotency entries.
        fn prefix() -> &'static [u8] {
            b"idempotency:"
        }
    }

    #[async_trait]
    impl IdempotencyStore for SlateDbIdempotencyStore {
        async fn get(&self, scope: &str, key: &str) -> Result<Option<IdempotencyEntry>> {
            let storage_key = Self::storage_key(scope, key);

            match self.db.get(&storage_key).await {
                Ok(Some(value)) => {
                    let entry: IdempotencyEntry = serde_json::from_slice(&value).map_err(|e| {
                        AppError::Internal(format!(
                            "Failed to deserialize idempotency entry: {}",
                            e
                        ))
                    })?;

                    if entry.is_expired() {
                        // Remove expired entry
                        self.db
                            .delete(&storage_key)
                            .await
                            .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;
                        Ok(None)
                    } else {
                        Ok(Some(entry))
                    }
                }
                Ok(None) => Ok(None),
                Err(e) => Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }
        }

        async fn set(&self, entry: IdempotencyEntry) -> Result<()> {
            let storage_key = Self::storage_key(&entry.scope, &entry.key);
            let value = serde_json::to_vec(&entry).map_err(|e| {
                AppError::Internal(format!("Failed to serialize idempotency entry: {}", e))
            })?;

            self.db
                .put(&storage_key, &value)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            Ok(())
        }

        async fn remove(&self, scope: &str, key: &str) -> Result<()> {
            let storage_key = Self::storage_key(scope, key);
            self.db
                .delete(&storage_key)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;
            Ok(())
        }

        async fn cleanup_expired(&self) -> Result<usize> {
            let prefix = Self::prefix();
            let mut removed = 0;

            // Scan all idempotency entries
            let mut iter = self
                .db
                .scan_prefix(prefix)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            let mut keys_to_delete = Vec::new();

            while let Some(kv) = iter
                .next()
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?
            {
                if let Ok(entry) = serde_json::from_slice::<IdempotencyEntry>(&kv.value) {
                    if entry.is_expired() {
                        keys_to_delete.push(kv.key.to_vec());
                    }
                }
            }

            // Delete expired entries
            for key in keys_to_delete {
                if self.db.delete(&key).await.is_ok() {
                    removed += 1;
                }
            }

            tracing::debug!(removed = removed, "Cleaned up expired idempotency entries");
            Ok(removed)
        }

        async fn count(&self) -> Result<usize> {
            let prefix = Self::prefix();
            let mut count = 0;

            let mut iter = self
                .db
                .scan_prefix(prefix)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            while iter
                .next()
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?
                .is_some()
            {
                count += 1;
            }

            Ok(count)
        }
    }
}

#[cfg(feature = "slatedb-storage")]
pub use slatedb_impl::SlateDbIdempotencyStore;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry() -> IdempotencyEntry {
        IdempotencyEntry::new(
            "test-key-123".to_string(),
            "POST:/tables".to_string(),
            201,
            b"{\"name\": \"my_table\"}".to_vec(),
            Some("application/json".to_string()),
            Duration::from_secs(3600),
        )
    }

    #[tokio::test]
    async fn test_memory_store_set_and_get() {
        let store = MemoryIdempotencyStore::new();
        let entry = create_test_entry();

        store.set(entry.clone()).await.unwrap();

        let retrieved = store
            .get(&entry.scope, &entry.key)
            .await
            .unwrap()
            .expect("entry should exist");

        assert_eq!(retrieved.key, entry.key);
        assert_eq!(retrieved.status_code, 201);
    }

    #[tokio::test]
    async fn test_memory_store_expiry() {
        let store = MemoryIdempotencyStore::new();

        // Create entry with very short TTL
        let entry = IdempotencyEntry::new(
            "expiring-key".to_string(),
            "POST:/test".to_string(),
            200,
            vec![],
            None,
            Duration::from_millis(1), // 1ms TTL
        );

        store.set(entry.clone()).await.unwrap();

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = store.get(&entry.scope, &entry.key).await.unwrap();
        assert!(result.is_none(), "expired entry should not be returned");
    }

    #[tokio::test]
    async fn test_memory_store_remove() {
        let store = MemoryIdempotencyStore::new();
        let entry = create_test_entry();

        store.set(entry.clone()).await.unwrap();
        assert!(store.get(&entry.scope, &entry.key).await.unwrap().is_some());

        store.remove(&entry.scope, &entry.key).await.unwrap();
        assert!(store.get(&entry.scope, &entry.key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_store_cleanup() {
        let store = MemoryIdempotencyStore::new();

        // Add expired and non-expired entries
        let expired = IdempotencyEntry::new(
            "expired".to_string(),
            "POST:/a".to_string(),
            200,
            vec![],
            None,
            Duration::from_millis(1),
        );

        let valid = IdempotencyEntry::new(
            "valid".to_string(),
            "POST:/b".to_string(),
            200,
            vec![],
            None,
            Duration::from_secs(3600),
        );

        store.set(expired).await.unwrap();
        store.set(valid.clone()).await.unwrap();

        // Wait for first to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_entry_is_expired() {
        let expired = IdempotencyEntry {
            key: "test".to_string(),
            scope: "POST:/test".to_string(),
            status_code: 200,
            response_body: vec![],
            content_type: None,
            created_at_ms: 0, // Epoch = definitely expired
            ttl_ms: 1000,
        };

        assert!(expired.is_expired());

        let valid = IdempotencyEntry::new(
            "test".to_string(),
            "POST:/test".to_string(),
            200,
            vec![],
            None,
            Duration::from_secs(3600),
        );

        assert!(!valid.is_expired());
    }
}

#[cfg(test)]
#[cfg(feature = "slatedb-storage")]
mod slatedb_tests {
    use super::*;
    use object_store::local::LocalFileSystem;
    use object_store::ObjectStore;
    use slatedb::Db;
    use tempfile::TempDir;

    async fn create_test_store() -> (SlateDbIdempotencyStore, TempDir) {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(temp_dir.path()).unwrap());

        let db = Arc::new(
            Db::builder("idempotency", object_store)
                .build()
                .await
                .expect("failed to create SlateDB"),
        );

        (SlateDbIdempotencyStore::new(db), temp_dir)
    }

    fn create_test_entry() -> IdempotencyEntry {
        IdempotencyEntry::new(
            "slatedb-key-456".to_string(),
            "POST:/namespaces".to_string(),
            201,
            b"{\"namespace\": [\"db\"]}".to_vec(),
            Some("application/json".to_string()),
            Duration::from_secs(3600),
        )
    }

    #[tokio::test]
    async fn test_slatedb_store_set_and_get() {
        let (store, _temp) = create_test_store().await;
        let entry = create_test_entry();

        store.set(entry.clone()).await.unwrap();

        let retrieved = store
            .get(&entry.scope, &entry.key)
            .await
            .unwrap()
            .expect("entry should exist");

        assert_eq!(retrieved.key, entry.key);
        assert_eq!(retrieved.status_code, 201);
    }

    #[tokio::test]
    async fn test_slatedb_store_persistence() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(temp_dir.path()).unwrap());

        let entry = create_test_entry();

        // Create entry in first instance
        {
            let db = Arc::new(
                Db::builder("idempotency", object_store.clone())
                    .build()
                    .await
                    .expect("failed to create SlateDB"),
            );
            let store = SlateDbIdempotencyStore::new(db.clone());

            store.set(entry.clone()).await.unwrap();

            // Flush to disk
            db.flush().await.expect("flush should succeed");
        }

        // Verify in new instance (simulates restart)
        {
            let db = Arc::new(
                Db::builder("idempotency", object_store.clone())
                    .build()
                    .await
                    .expect("failed to reopen SlateDB"),
            );
            let store = SlateDbIdempotencyStore::new(db);

            let retrieved = store
                .get(&entry.scope, &entry.key)
                .await
                .unwrap()
                .expect("entry should survive restart");

            assert_eq!(retrieved.key, entry.key);
            assert_eq!(retrieved.status_code, 201);
        }
    }

    #[tokio::test]
    async fn test_slatedb_store_cleanup_expired() {
        let (store, _temp) = create_test_store().await;

        // Add expired entry
        let expired = IdempotencyEntry {
            key: "old-key".to_string(),
            scope: "POST:/old".to_string(),
            status_code: 200,
            response_body: vec![],
            content_type: None,
            created_at_ms: 0, // Epoch = definitely expired
            ttl_ms: 1,
        };

        let valid = IdempotencyEntry::new(
            "new-key".to_string(),
            "POST:/new".to_string(),
            200,
            vec![],
            None,
            Duration::from_secs(3600),
        );

        store.set(expired).await.unwrap();
        store.set(valid.clone()).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.count().await.unwrap(), 1);

        // Valid entry still exists
        assert!(store.get(&valid.scope, &valid.key).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_slatedb_store_remove() {
        let (store, _temp) = create_test_store().await;
        let entry = create_test_entry();

        store.set(entry.clone()).await.unwrap();
        store.remove(&entry.scope, &entry.key).await.unwrap();

        assert!(store.get(&entry.scope, &entry.key).await.unwrap().is_none());
    }
}
