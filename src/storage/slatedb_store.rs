//! SlateDB storage backend for distributed K8s deployments.
//!
//! SlateDB is a cloud-native embedded LSM-tree that stores data on object storage
//! (S3, GCS, Azure Blob, MinIO). This enables true horizontal scaling:
//!
//! - Multiple Rustberg pods can share the same SlateDB instance
//! - CAS (Compare-and-Swap) via object storage provides coordination
//! - No external leader election needed (SlateDB handles fencing with writer_epoch)
//!
//! # K8s Deployment
//!
//! ```yaml
//! apiVersion: apps/v1
//! kind: Deployment
//! spec:
//!   replicas: 3  # Horizontal scaling!
//!   template:
//!     spec:
//!       containers:
//!       - name: rustberg
//!         env:
//!         - name: STORAGE_BACKEND
//!           value: "slatedb"
//!         - name: SLATEDB_OBJECT_STORE
//!           value: "s3://my-bucket/rustberg-catalog"
//!         - name: AWS_REGION
//!           value: "us-east-1"
//! ```

use super::kv_store::{BatchOperation, KeyValue, KvError, KvResult, KvStore, WriteBatch, WriteOptions};
use async_trait::async_trait;
use slatedb::object_store::ObjectStore;
use slatedb::{Db, Settings};
use std::sync::Arc;
use tokio::sync::RwLock;

/// SlateDB-backed KV store for distributed deployments.
///
/// This backend stores data on object storage (S3/GCS/MinIO/Azure),
/// enabling multiple Rustberg pods to share state for K8s HA.
pub struct SlateDbStore {
    /// The SlateDB database instance.
    db: RwLock<Option<Db>>,
    /// Object store URL for diagnostics.
    object_store_url: String,
    /// Settings (kept for reference).
    _settings: Settings,
}

impl std::fmt::Debug for SlateDbStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlateDbStore")
            .field("object_store_url", &self.object_store_url)
            .finish()
    }
}

impl SlateDbStore {
    /// Opens or creates a SlateDB store on the given object storage.
    ///
    /// # Arguments
    ///
    /// * `path` - The path prefix within the object store (e.g., "/rustberg/catalog")
    /// * `object_store` - The object store implementation (S3, GCS, MinIO, etc.)
    /// * `object_store_url` - The URL for diagnostics/logging
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use object_store::aws::AmazonS3Builder;
    /// use rustberg::storage::SlateDbStore;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let s3 = AmazonS3Builder::from_env()
    ///     .with_bucket_name("my-bucket")
    ///     .build()?;
    ///
    /// let store = SlateDbStore::open(
    ///     "/rustberg/catalog",
    ///     Arc::new(s3),
    ///     "s3://my-bucket/rustberg/catalog".to_string(),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open(
        path: &str,
        object_store: Arc<dyn ObjectStore>,
        object_store_url: String,
    ) -> KvResult<Self> {
        let path = slatedb::object_store::path::Path::from(path);

        let settings = Settings::default();

        let db: Db = Db::open(path, object_store)
            .await
            .map_err(|e| KvError::Storage(format!("Failed to open SlateDB: {}", e)))?;

        tracing::info!(
            object_store_url = %object_store_url,
            "Opened SlateDB store for distributed mode"
        );

        Ok(Self {
            db: RwLock::new(Some(db)),
            object_store_url,
            _settings: settings,
        })
    }

    /// Opens a SlateDB store from an object store URL.
    ///
    /// Supported URL schemes:
    /// - `s3://bucket/prefix` - Amazon S3
    /// - `gs://bucket/prefix` - Google Cloud Storage
    /// - `az://container/prefix` - Azure Blob Storage
    /// - `memory://` - In-memory (testing only)
    ///
    /// For S3, set AWS credentials via environment variables:
    /// - `AWS_ACCESS_KEY_ID`
    /// - `AWS_SECRET_ACCESS_KEY`
    /// - `AWS_REGION`
    pub async fn open_url(url: &str) -> KvResult<Self> {
        let (object_store, path) = parse_object_store_url(url)?;
        Self::open(&path, object_store, url.to_string()).await
    }

    /// Returns a reference to the underlying database, or an error if closed.
    async fn db(&self) -> KvResult<impl std::ops::Deref<Target = Db> + '_> {
        use tokio::sync::RwLockReadGuard;

        struct DbGuard<'a>(RwLockReadGuard<'a, Option<Db>>);

        impl<'a> std::ops::Deref for DbGuard<'a> {
            type Target = Db;

            fn deref(&self) -> &Self::Target {
                self.0.as_ref().unwrap()
            }
        }

        let guard = self.db.read().await;
        if guard.is_none() {
            return Err(KvError::Storage("Database is closed".to_string()));
        }
        Ok(DbGuard(guard))
    }
}

#[async_trait]
impl KvStore for SlateDbStore {
    async fn get(&self, key: &[u8]) -> KvResult<Option<Vec<u8>>> {
        let db = self.db().await?;
        db.get(key)
            .await
            .map(|opt| opt.map(|b| b.to_vec()))
            .map_err(|e| KvError::Storage(format!("SlateDB get error: {}", e)))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> KvResult<()> {
        let db = self.db().await?;
        db.put(key, value)
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB put error: {}", e)))
    }

    async fn put_with_options(&self, key: &[u8], value: &[u8], opts: WriteOptions) -> KvResult<()> {
        // SlateDB 0.10 doesn't have sync options in put_with_options
        // All writes go to memtable first, then flush to object storage
        let _ = opts; // Ignore for now - SlateDB handles durability via flush
        self.put(key, value).await
    }

    async fn delete(&self, key: &[u8]) -> KvResult<()> {
        let db = self.db().await?;
        db.delete(key)
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB delete error: {}", e)))
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> KvResult<Vec<KeyValue>> {
        let db = self.db().await?;

        // Calculate the end key for prefix scan
        let end = increment_bytes(prefix);

        let mut results = Vec::new();
        let mut iter = if let Some(end) = end {
            db.scan(prefix.to_vec()..end)
                .await
                .map_err(|e| KvError::Storage(format!("SlateDB scan error: {}", e)))?
        } else {
            // If prefix is all 0xFF, scan to the end
            db.scan(prefix.to_vec()..)
                .await
                .map_err(|e| KvError::Storage(format!("SlateDB scan error: {}", e)))?
        };

        while let Some(kv) = iter
            .next()
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB iteration error: {}", e)))?
        {
            // Double-check prefix match (iterator might overshoot)
            if !kv.key.starts_with(prefix) {
                break;
            }
            results.push(KeyValue {
                key: kv.key.to_vec(),
                value: kv.value.to_vec(),
            });
        }

        Ok(results)
    }

    async fn scan_range(&self, start: &[u8], end: &[u8]) -> KvResult<Vec<KeyValue>> {
        let db = self.db().await?;

        let mut results = Vec::new();
        let mut iter = db
            .scan(start.to_vec()..end.to_vec())
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB scan error: {}", e)))?;

        while let Some(kv) = iter
            .next()
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB iteration error: {}", e)))?
        {
            results.push(KeyValue {
                key: kv.key.to_vec(),
                value: kv.value.to_vec(),
            });
        }

        Ok(results)
    }

    async fn write_batch(&self, batch: WriteBatch) -> KvResult<()> {
        let db = self.db().await?;

        let mut slate_batch = slatedb::WriteBatch::new();
        for op in batch.operations {
            match op {
                BatchOperation::Put { key, value } => {
                    slate_batch.put(&key, &value);
                }
                BatchOperation::Delete { key } => {
                    slate_batch.delete(&key);
                }
            }
        }

        db.write(slate_batch)
            .await
            .map_err(|e| KvError::Storage(format!("SlateDB batch write error: {}", e)))
    }

    async fn close(&self) -> KvResult<()> {
        let mut guard = self.db.write().await;
        if let Some(db) = guard.take() {
            db.close()
                .await
                .map_err(|e| KvError::Storage(format!("SlateDB close error: {}", e)))?;
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "slatedb"
    }

    fn supports_horizontal_scaling(&self) -> bool {
        true
    }
}

/// Increments a byte array to get the exclusive end bound for prefix scans.
///
/// Returns `None` if the input is all 0xFF bytes (overflow).
fn increment_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut result = bytes.to_vec();

    for i in (0..result.len()).rev() {
        if result[i] < 0xFF {
            result[i] += 1;
            return Some(result);
        } else {
            result[i] = 0;
        }
    }

    // All bytes were 0xFF, prefix covers everything to the end
    None
}

/// Parses an object store URL and returns the appropriate ObjectStore and path.
fn parse_object_store_url(url: &str) -> KvResult<(Arc<dyn ObjectStore>, String)> {
    use slatedb::object_store::memory::InMemory;
    use slatedb::object_store::local::LocalFileSystem;

    if url.starts_with("memory://") {
        let path = url.strip_prefix("memory://").unwrap_or("/");
        return Ok((Arc::new(InMemory::new()), path.to_string()));
    }

    if url.starts_with("file://") || url.starts_with("/") {
        let path = if url.starts_with("file://") {
            url.strip_prefix("file://").unwrap()
        } else {
            url
        };
        let local = LocalFileSystem::new();
        return Ok((Arc::new(local), path.to_string()));
    }

    #[cfg(feature = "slatedb-storage")]
    {
        use slatedb::object_store::aws::AmazonS3Builder;
        use slatedb::object_store::gcp::GoogleCloudStorageBuilder;
        use slatedb::object_store::azure::MicrosoftAzureBuilder;

        if url.starts_with("s3://") {
            let without_scheme = url.strip_prefix("s3://").unwrap();
            let (bucket, path) = without_scheme
                .split_once('/')
                .unwrap_or((without_scheme, ""));

            let s3 = AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .build()
                .map_err(|e| KvError::Config(format!("Failed to create S3 client: {}", e)))?;

            return Ok((Arc::new(s3), format!("/{}", path)));
        }

        if url.starts_with("gs://") {
            let without_scheme = url.strip_prefix("gs://").unwrap();
            let (bucket, path) = without_scheme
                .split_once('/')
                .unwrap_or((without_scheme, ""));

            let gcs = GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()
                .map_err(|e| KvError::Config(format!("Failed to create GCS client: {}", e)))?;

            return Ok((Arc::new(gcs), format!("/{}", path)));
        }

        if url.starts_with("az://") || url.starts_with("azure://") {
            let without_scheme = if url.starts_with("az://") {
                url.strip_prefix("az://").unwrap()
            } else {
                url.strip_prefix("azure://").unwrap()
            };
            let (container, path) = without_scheme
                .split_once('/')
                .unwrap_or((without_scheme, ""));

            let azure = MicrosoftAzureBuilder::from_env()
                .with_container_name(container)
                .build()
                .map_err(|e| KvError::Config(format!("Failed to create Azure client: {}", e)))?;

            return Ok((Arc::new(azure), format!("/{}", path)));
        }
    }

    Err(KvError::Config(format!(
        "Unsupported object store URL scheme: {}",
        url
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_slatedb_basic_operations() {
        let store = SlateDbStore::open_url("memory://test").await.unwrap();

        // Test put and get
        store.put(b"key1", b"value1").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));

        // Test overwrite
        store.put(b"key1", b"value2").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), Some(b"value2".to_vec()));

        // Test delete
        store.delete(b"key1").await.unwrap();
        assert_eq!(store.get(b"key1").await.unwrap(), None);

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_slatedb_scan_prefix() {
        let store = SlateDbStore::open_url("memory://test").await.unwrap();

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

        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_slatedb_write_batch() {
        let store = SlateDbStore::open_url("memory://test").await.unwrap();

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

        store.close().await.unwrap();
    }

    #[test]
    fn test_increment_bytes() {
        assert_eq!(increment_bytes(b"abc"), Some(b"abd".to_vec()));
        assert_eq!(increment_bytes(b"ab\xff"), Some(b"ac\x00".to_vec()));
        assert_eq!(increment_bytes(b"\xff\xff\xff"), None);
        // Empty bytes: no bytes to increment, so returns None (equivalent to "all 0xFF" case)
        assert_eq!(increment_bytes(b""), None);
    }

    #[tokio::test]
    async fn test_slatedb_supports_horizontal_scaling() {
        let store = SlateDbStore::open_url("memory://test").await.unwrap();
        assert!(store.supports_horizontal_scaling());
        assert_eq!(store.backend_name(), "slatedb");
        store.close().await.unwrap();
    }
}
