//! Generic key-value store abstraction for metadata storage.
//!
//! This module provides a backend-agnostic interface for storing catalog metadata,
//! enabling horizontal scaling through different storage backends:
//!
//! - **SlateDB (file://)**: Single-node local storage (default)
//! - **SlateDB (s3://)**: Distributed storage via S3/GCS/MinIO for K8s horizontal scaling
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    KvStore Trait                                 │
//! │  get() / put() / delete() / scan() / write_batch()             │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   SlateDB       │ │   SlateDB       │ │   Memory        │
//! │   (file://)     │ │   (s3://)       │ │   (Testing)     │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! # K8s Horizontal Scaling
//!
//! With SlateDB backend pointing to S3/MinIO:
//! - Multiple pods can read/write to shared storage
//! - CAS (Compare-and-Swap) via object storage provides coordination
//! - No external leader election needed (SlateDB handles fencing)

use async_trait::async_trait;
use std::fmt::Debug;

/// Errors that can occur during KV store operations.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    /// Key not found in the store.
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Key already exists (for create operations).
    #[error("Key already exists: {0}")]
    AlreadyExists(String),

    /// Backend storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Conflict during concurrent modification.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Operation not supported by this backend.
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type for KV store operations.
pub type KvResult<T> = std::result::Result<T, KvError>;

/// A key-value pair returned from scan operations.
#[derive(Debug, Clone)]
pub struct KeyValue {
    /// The key bytes.
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// Options for write operations.
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    /// Wait for durable persistence before returning.
    /// Setting to `false` trades durability for lower latency.
    pub sync: bool,
}

/// A batch of write operations to be applied atomically.
#[derive(Debug, Default)]
pub struct WriteBatch {
    /// Operations in the batch.
    pub operations: Vec<BatchOperation>,
}

/// A single operation in a write batch.
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Put a key-value pair.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Delete a key.
    Delete { key: Vec<u8> },
}

impl WriteBatch {
    /// Creates a new empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a put operation to the batch.
    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.operations.push(BatchOperation::Put {
            key: key.into(),
            value: value.into(),
        });
    }

    /// Adds a delete operation to the batch.
    pub fn delete(&mut self, key: impl Into<Vec<u8>>) {
        self.operations
            .push(BatchOperation::Delete { key: key.into() });
    }

    /// Returns true if the batch has no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Returns the number of operations in the batch.
    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

/// Generic key-value store interface for catalog metadata.
///
/// Implementations must be thread-safe (`Send + Sync`) and support
/// concurrent access from multiple Tokio tasks.
#[async_trait]
pub trait KvStore: Send + Sync + Debug {
    /// Get a value by key.
    ///
    /// Returns `None` if the key doesn't exist.
    async fn get(&self, key: &[u8]) -> KvResult<Option<Vec<u8>>>;

    /// Put a key-value pair.
    ///
    /// Overwrites any existing value for the key.
    async fn put(&self, key: &[u8], value: &[u8]) -> KvResult<()>;

    /// Put a key-value pair with options.
    async fn put_with_options(&self, key: &[u8], value: &[u8], opts: WriteOptions) -> KvResult<()> {
        // Default implementation ignores options
        let _ = opts;
        self.put(key, value).await
    }

    /// Delete a key.
    ///
    /// Returns `Ok(())` even if the key doesn't exist (idempotent).
    async fn delete(&self, key: &[u8]) -> KvResult<()>;

    /// Check if a key exists.
    async fn exists(&self, key: &[u8]) -> KvResult<bool> {
        Ok(self.get(key).await?.is_some())
    }

    /// Scan keys with a given prefix.
    ///
    /// Returns all key-value pairs where the key starts with `prefix`.
    /// Results are returned in lexicographic order by key.
    async fn scan_prefix(&self, prefix: &[u8]) -> KvResult<Vec<KeyValue>>;

    /// Scan a range of keys.
    ///
    /// Returns all key-value pairs where `start <= key < end`.
    /// Results are returned in lexicographic order by key.
    async fn scan_range(&self, start: &[u8], end: &[u8]) -> KvResult<Vec<KeyValue>>;

    /// Execute a batch of operations atomically.
    ///
    /// Either all operations succeed or none do.
    async fn write_batch(&self, batch: WriteBatch) -> KvResult<()>;

    /// Execute a batch with options.
    async fn write_batch_with_options(&self, batch: WriteBatch, opts: WriteOptions) -> KvResult<()> {
        // Default implementation ignores options
        let _ = opts;
        self.write_batch(batch).await
    }

    /// Close the store and release resources.
    ///
    /// After close, operations may return errors.
    async fn close(&self) -> KvResult<()>;

    /// Returns the backend name for diagnostics.
    fn backend_name(&self) -> &'static str;

    /// Returns true if this backend supports horizontal scaling.
    ///
    /// SlateDB with file:// returns false (single-node only).
    /// SlateDB with s3:// returns true (shared object storage).
    fn supports_horizontal_scaling(&self) -> bool {
        false
    }
}

/// Configuration for KV store backends.
#[derive(Debug, Clone, Default)]
pub enum KvStoreConfig {
    /// In-memory store (testing only).
    #[default]
    Memory,

    /// SlateDB with object storage (distributed, K8s-ready).
    #[cfg(feature = "slatedb-storage")]
    SlateDb {
        /// Object storage URL (file://, s3://bucket/prefix, gs://bucket/prefix, etc.)
        object_store_url: String,
        /// AWS region (for S3).
        aws_region: Option<String>,
        /// Local cache directory for SlateDB.
        cache_dir: Option<String>,
    },
}

// ============================================================================
// In-Memory Implementation (for testing)
// ============================================================================

use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;

/// In-memory KV store for testing.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
    data: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryKvStore {
    /// Creates a new in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KvStore for MemoryKvStore {
    async fn get(&self, key: &[u8]) -> KvResult<Option<Vec<u8>>> {
        Ok(self.data.read().get(key).cloned())
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> KvResult<()> {
        self.data.write().insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> KvResult<()> {
        self.data.write().remove(key);
        Ok(())
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> KvResult<Vec<KeyValue>> {
        let data = self.data.read();
        let results: Vec<KeyValue> = data
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| KeyValue {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        Ok(results)
    }

    async fn scan_range(&self, start: &[u8], end: &[u8]) -> KvResult<Vec<KeyValue>> {
        let data = self.data.read();
        let results: Vec<KeyValue> = data
            .range(start.to_vec()..end.to_vec())
            .map(|(k, v)| KeyValue {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        Ok(results)
    }

    async fn write_batch(&self, batch: WriteBatch) -> KvResult<()> {
        let mut data = self.data.write();
        for op in batch.operations {
            match op {
                BatchOperation::Put { key, value } => {
                    data.insert(key, value);
                }
                BatchOperation::Delete { key } => {
                    data.remove(&key);
                }
            }
        }
        Ok(())
    }

    async fn close(&self) -> KvResult<()> {
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store_basic_operations() {
        let store = MemoryKvStore::new();

        // Test put and get
        store.put(b"key1", b"value1").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));

        // Test overwrite
        store.put(b"key1", b"value2").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), Some(b"value2".to_vec()));

        // Test delete
        store.delete(b"key1").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), None);

        // Test delete non-existent (should be idempotent)
        store.delete(b"key1").await.unwrap();
    }

    #[tokio::test]
    async fn test_memory_store_scan_prefix() {
        let store = MemoryKvStore::new();

        store.put(b"user:1", b"alice").await.unwrap();
        store.put(b"user:2", b"bob").await.unwrap();
        store.put(b"user:3", b"charlie").await.unwrap();
        store.put(b"tenant:1", b"acme").await.unwrap();

        let results = store.scan_prefix(b"user:").await.unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].key, b"user:1");
        assert_eq!(results[1].key, b"user:2");
        assert_eq!(results[2].key, b"user:3");

        let results = store.scan_prefix(b"tenant:").await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_memory_store_write_batch() {
        let store = MemoryKvStore::new();

        let mut batch = WriteBatch::new();
        batch.put(b"key1", b"value1");
        batch.put(b"key2", b"value2");
        batch.put(b"key3", b"value3");
        store.write_batch(batch).await.unwrap();

        assert_eq!(store.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(store.get(b"key2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(store.get(b"key3").await.unwrap(), Some(b"value3".to_vec()));

        // Test batch with delete
        let mut batch = WriteBatch::new();
        batch.delete(b"key2");
        batch.put(b"key4", b"value4");
        store.write_batch(batch).await.unwrap();

        assert_eq!(store.get(b"key2").await.unwrap(), None);
        assert_eq!(store.get(b"key4").await.unwrap(), Some(b"value4".to_vec()));
    }

    #[tokio::test]
    async fn test_memory_store_exists() {
        let store = MemoryKvStore::new();

        assert!(!store.exists(b"key1").await.unwrap());
        store.put(b"key1", b"value1").await.unwrap();
        assert!(store.exists(b"key1").await.unwrap());
    }
}
