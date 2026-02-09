//! View storage abstraction layer for Iceberg views.
//!
//! Provides both in-memory and persistent (SlateDB) implementations of view storage.
//! Views store metadata about virtual tables defined by SQL queries.

use std::collections::HashMap;

use async_trait::async_trait;
use iceberg::spec::ViewMetadata;
use parking_lot::RwLock;

use crate::error::{AppError, Result};

// ============================================================================
// ViewStore Trait
// ============================================================================

/// Trait for view storage implementations.
///
/// Provides async methods for CRUD operations on Iceberg views.
/// Implementations include in-memory storage (for development) and
/// SlateDB-backed storage (for production persistence).
#[async_trait]
pub trait ViewStore: Send + Sync + std::fmt::Debug {
    /// Lists all view names in a namespace.
    async fn list_views(&self, namespace: &[String]) -> Result<Vec<String>>;

    /// Checks if a view exists.
    async fn view_exists(&self, namespace: &[String], name: &str) -> Result<bool>;

    /// Loads a view by namespace and name.
    /// Returns (metadata_location, metadata) if found.
    async fn load_view(
        &self,
        namespace: &[String],
        name: &str,
    ) -> Result<Option<(String, ViewMetadata)>>;

    /// Creates a new view. Returns error if view already exists.
    async fn create_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()>;

    /// Updates an existing view. Returns error if view doesn't exist.
    async fn update_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()>;

    /// Drops a view. Returns error if view doesn't exist.
    async fn drop_view(&self, namespace: &[String], name: &str) -> Result<()>;

    /// Renames a view. Returns error if source doesn't exist or dest exists.
    async fn rename_view(
        &self,
        src_namespace: &[String],
        src_name: &str,
        dest_namespace: &[String],
        dest_name: &str,
    ) -> Result<()>;
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// Type alias for view storage map: (namespace, name) -> (metadata_location, metadata).
type ViewMap = HashMap<(Vec<String>, String), (String, ViewMetadata)>;

/// In-memory view storage for development/testing.
///
/// **Warning:** Views are lost on server restart. For production, use
/// `SlateDbViewStore` with persistent storage.
#[derive(Debug, Default)]
pub struct MemoryViewStore {
    /// Views indexed by (namespace, name) -> (metadata_location, metadata).
    views: RwLock<ViewMap>,
}

impl MemoryViewStore {
    /// Creates a new in-memory view store.
    pub fn new() -> Self {
        Self {
            views: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ViewStore for MemoryViewStore {
    async fn list_views(&self, namespace: &[String]) -> Result<Vec<String>> {
        let views = self.views.read();
        Ok(views
            .keys()
            .filter(|(ns, _)| ns == namespace)
            .map(|(_, name)| name.clone())
            .collect())
    }

    async fn view_exists(&self, namespace: &[String], name: &str) -> Result<bool> {
        let views = self.views.read();
        Ok(views.contains_key(&(namespace.to_vec(), name.to_string())))
    }

    async fn load_view(
        &self,
        namespace: &[String],
        name: &str,
    ) -> Result<Option<(String, ViewMetadata)>> {
        let views = self.views.read();
        Ok(views.get(&(namespace.to_vec(), name.to_string())).cloned())
    }

    async fn create_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;

        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if let Entry::Vacant(e) = views.entry(key) {
            e.insert((metadata_location, metadata));
            Ok(())
        } else {
            Err(AppError::ViewAlreadyExists(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    async fn update_view(
        &self,
        namespace: &[String],
        name: &str,
        metadata_location: String,
        metadata: ViewMetadata,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;

        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if let Entry::Occupied(mut e) = views.entry(key) {
            e.insert((metadata_location, metadata));
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    async fn drop_view(&self, namespace: &[String], name: &str) -> Result<()> {
        let mut views = self.views.write();
        let key = (namespace.to_vec(), name.to_string());

        if views.remove(&key).is_some() {
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                namespace.join("."),
                name
            )))
        }
    }

    async fn rename_view(
        &self,
        src_namespace: &[String],
        src_name: &str,
        dest_namespace: &[String],
        dest_name: &str,
    ) -> Result<()> {
        let mut views = self.views.write();
        let src_key = (src_namespace.to_vec(), src_name.to_string());
        let dest_key = (dest_namespace.to_vec(), dest_name.to_string());

        if views.contains_key(&dest_key) {
            return Err(AppError::ViewAlreadyExists(format!(
                "{}.{}",
                dest_namespace.join("."),
                dest_name
            )));
        }

        if let Some((loc, metadata)) = views.remove(&src_key) {
            // Update location if moving to different namespace
            let new_location = if src_namespace != dest_namespace {
                loc.replace(&src_namespace.join("/"), &dest_namespace.join("/"))
            } else {
                loc.replace(src_name, dest_name)
            };

            views.insert(dest_key, (new_location, metadata));
            Ok(())
        } else {
            Err(AppError::NoSuchView(format!(
                "{}.{}",
                src_namespace.join("."),
                src_name
            )))
        }
    }
}

// ============================================================================
// SlateDB Implementation
// ============================================================================

#[cfg(feature = "slatedb-storage")]
mod slatedb_impl {
    use super::*;
    use serde::{Deserialize, Serialize};
    use slatedb::Db;
    use std::sync::Arc;

    /// Metadata stored for each view in the catalog registry.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ViewRegistryEntry {
        /// View namespace parts
        pub namespace: Vec<String>,
        /// View name
        pub name: String,
        /// Current metadata location (s3://bucket/view/metadata/v1.json)
        pub metadata_location: String,
        /// Serialized view metadata (JSON)
        pub metadata: ViewMetadata,
        /// Version for optimistic concurrency control (CAS)
        #[serde(default)]
        pub version: u64,
    }

    /// Persistent view storage backed by SlateDB.
    ///
    /// Views are stored with key schema: `view:{namespace}:{view_name}`
    /// This provides persistence across server restarts.
    pub struct SlateDbViewStore {
        /// SlateDB instance
        db: Arc<Db>,
    }

    // Manual Debug impl since Db doesn't implement Debug
    impl std::fmt::Debug for SlateDbViewStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SlateDbViewStore").finish_non_exhaustive()
        }
    }

    impl SlateDbViewStore {
        /// Creates a new SlateDB-backed view store.
        ///
        /// # Arguments
        ///
        /// * `db` - Shared SlateDB instance (same as used by SlateCatalog)
        pub fn new(db: Arc<Db>) -> Self {
            Self { db }
        }

        /// Generates a view key for SlateDB storage.
        fn view_key(namespace: &[String], name: &str) -> Vec<u8> {
            format!("view:{}:{}", namespace.join("."), name).into_bytes()
        }

        /// Prefix for scanning all views in a namespace.
        fn view_prefix(namespace: &[String]) -> String {
            format!("view:{}:", namespace.join("."))
        }
    }

    #[async_trait]
    impl ViewStore for SlateDbViewStore {
        async fn list_views(&self, namespace: &[String]) -> Result<Vec<String>> {
            let prefix = Self::view_prefix(namespace);

            // Scan all keys with the namespace prefix
            let mut iter = self
                .db
                .scan_prefix(prefix.as_bytes())
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            let mut names = Vec::new();
            while let Some(kv) = iter
                .next()
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?
            {
                if let Ok(entry) = serde_json::from_slice::<ViewRegistryEntry>(&kv.value) {
                    names.push(entry.name);
                }
            }

            Ok(names)
        }

        async fn view_exists(&self, namespace: &[String], name: &str) -> Result<bool> {
            let key = Self::view_key(namespace, name);
            match self.db.get(&key).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }
        }

        async fn load_view(
            &self,
            namespace: &[String],
            name: &str,
        ) -> Result<Option<(String, ViewMetadata)>> {
            let key = Self::view_key(namespace, name);

            match self.db.get(&key).await {
                Ok(Some(value)) => {
                    let entry: ViewRegistryEntry = serde_json::from_slice(&value).map_err(|e| {
                        AppError::Internal(format!("Failed to deserialize view entry: {}", e))
                    })?;
                    Ok(Some((entry.metadata_location, entry.metadata)))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }
        }

        async fn create_view(
            &self,
            namespace: &[String],
            name: &str,
            metadata_location: String,
            metadata: ViewMetadata,
        ) -> Result<()> {
            let key = Self::view_key(namespace, name);
            let view_name = format!("{}.{}", namespace.join("."), name);

            // Check if view already exists
            match self.db.get(&key).await {
                Ok(Some(_)) => {
                    return Err(AppError::ViewAlreadyExists(view_name));
                }
                Ok(None) => {}
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }

            let entry = ViewRegistryEntry {
                namespace: namespace.to_vec(),
                name: name.to_string(),
                metadata_location,
                metadata,
                version: 0,
            };

            let value = serde_json::to_vec(&entry).map_err(|e| {
                AppError::Internal(format!("Failed to serialize view entry: {}", e))
            })?;

            // CAS: Re-verify view still doesn't exist before writing
            match self.db.get(&key).await {
                Ok(Some(_)) => {
                    return Err(AppError::CommitConflict(format!(
                        "View {} was created by another process during our create operation",
                        view_name
                    )));
                }
                Ok(None) => {}
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }

            self.db
                .put(&key, &value)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            Ok(())
        }

        async fn update_view(
            &self,
            namespace: &[String],
            name: &str,
            metadata_location: String,
            metadata: ViewMetadata,
        ) -> Result<()> {
            let key = Self::view_key(namespace, name);
            let view_name = format!("{}.{}", namespace.join("."), name);

            // Load current entry to get version for CAS
            let current_entry: ViewRegistryEntry = match self.db.get(&key).await {
                Ok(Some(value)) => serde_json::from_slice(&value).map_err(|e| {
                    AppError::Internal(format!("Failed to deserialize view entry: {}", e))
                })?,
                Ok(None) => {
                    return Err(AppError::NoSuchView(view_name));
                }
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            };

            let expected_version = current_entry.version;

            // CAS: Re-read and verify version hasn't changed before writing
            let verify_entry: ViewRegistryEntry = match self.db.get(&key).await {
                Ok(Some(value)) => serde_json::from_slice(&value).map_err(|e| {
                    AppError::Internal(format!("Failed to deserialize view entry: {}", e))
                })?,
                Ok(None) => {
                    return Err(AppError::Internal(format!(
                        "View {} disappeared during update",
                        view_name
                    )));
                }
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            };

            if verify_entry.version != expected_version {
                return Err(AppError::CommitConflict(format!(
                    "View {} was modified by another process (expected version {}, found {})",
                    view_name, expected_version, verify_entry.version
                )));
            }

            let entry = ViewRegistryEntry {
                namespace: namespace.to_vec(),
                name: name.to_string(),
                metadata_location,
                metadata,
                version: expected_version + 1,
            };

            let value = serde_json::to_vec(&entry).map_err(|e| {
                AppError::Internal(format!("Failed to serialize view entry: {}", e))
            })?;

            self.db
                .put(&key, &value)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            Ok(())
        }

        async fn drop_view(&self, namespace: &[String], name: &str) -> Result<()> {
            let key = Self::view_key(namespace, name);

            // Check if view exists
            match self.db.get(&key).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(AppError::NoSuchView(format!(
                        "{}.{}",
                        namespace.join("."),
                        name
                    )));
                }
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }

            self.db
                .delete(&key)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            Ok(())
        }

        async fn rename_view(
            &self,
            src_namespace: &[String],
            src_name: &str,
            dest_namespace: &[String],
            dest_name: &str,
        ) -> Result<()> {
            let src_key = Self::view_key(src_namespace, src_name);
            let dest_key = Self::view_key(dest_namespace, dest_name);
            let src_view_name = format!("{}.{}", src_namespace.join("."), src_name);
            let dest_view_name = format!("{}.{}", dest_namespace.join("."), dest_name);

            // Check if destination already exists
            match self.db.get(&dest_key).await {
                Ok(Some(_)) => {
                    return Err(AppError::ViewAlreadyExists(dest_view_name));
                }
                Ok(None) => {}
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }

            // Load source entry and capture version for CAS
            let current_entry: ViewRegistryEntry = match self.db.get(&src_key).await {
                Ok(Some(value)) => serde_json::from_slice(&value).map_err(|e| {
                    AppError::Internal(format!("Failed to deserialize view entry: {}", e))
                })?,
                Ok(None) => {
                    return Err(AppError::NoSuchView(src_view_name));
                }
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            };

            let expected_version = current_entry.version;

            // Update location if moving to different namespace
            let new_location = if src_namespace != dest_namespace {
                current_entry
                    .metadata_location
                    .replace(&src_namespace.join("/"), &dest_namespace.join("/"))
            } else {
                current_entry.metadata_location.replace(src_name, dest_name)
            };

            // CAS: Verify source hasn't changed and dest still doesn't exist
            let verify_src_entry: ViewRegistryEntry = match self.db.get(&src_key).await {
                Ok(Some(value)) => serde_json::from_slice(&value).map_err(|e| {
                    AppError::Internal(format!("Failed to deserialize view entry: {}", e))
                })?,
                Ok(None) => {
                    return Err(AppError::CommitConflict(format!(
                        "View {} was dropped during rename",
                        src_view_name
                    )));
                }
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            };

            if verify_src_entry.version != expected_version {
                return Err(AppError::CommitConflict(format!(
                    "View {} was modified during rename (expected version {}, found {})",
                    src_view_name, expected_version, verify_src_entry.version
                )));
            }

            match self.db.get(&dest_key).await {
                Ok(Some(_)) => {
                    return Err(AppError::CommitConflict(format!(
                        "View {} was created during rename",
                        dest_view_name
                    )));
                }
                Ok(None) => {}
                Err(e) => return Err(AppError::Internal(format!("SlateDB error: {}", e))),
            }

            // Create new entry at destination
            let new_entry = ViewRegistryEntry {
                namespace: dest_namespace.to_vec(),
                name: dest_name.to_string(),
                metadata_location: new_location,
                metadata: current_entry.metadata,
                version: 0, // Reset version for renamed view
            };

            let new_value = serde_json::to_vec(&new_entry).map_err(|e| {
                AppError::Internal(format!("Failed to serialize view entry: {}", e))
            })?;

            // Use WriteBatch for atomic rename (put dest + delete src)
            use slatedb::WriteBatch;
            let mut batch = WriteBatch::new();
            batch.put(&dest_key, &new_value);
            batch.delete(&src_key);

            self.db
                .write(batch)
                .await
                .map_err(|e| AppError::Internal(format!("SlateDB error: {}", e)))?;

            Ok(())
        }
    }
}

#[cfg(feature = "slatedb-storage")]
pub use slatedb_impl::SlateDbViewStore;

// ============================================================================
// Compatibility Alias
// ============================================================================

/// Type alias for backwards compatibility.
///
/// **Deprecated:** Use `MemoryViewStore` or `SlateDbViewStore` directly.
pub type ViewStorage = MemoryViewStore;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use iceberg::spec::{
        NestedField, NestedFieldRef, PrimitiveType, Schema, Type, ViewMetadataBuilder,
        ViewRepresentations,
    };
    use iceberg::{NamespaceIdent, ViewCreation};

    /// Helper to create test view metadata
    fn create_test_view_metadata() -> ViewMetadata {
        let schema = Schema::builder()
            .with_fields(vec![NestedFieldRef::from(NestedField::required(
                1,
                "id",
                Type::Primitive(PrimitiveType::Long),
            ))])
            .build()
            .expect("schema should be valid");

        // Create representations using serde (ViewRepresentations has private constructor)
        let representations: ViewRepresentations = serde_json::from_value(serde_json::json!([
            {"type": "sql", "sql": "SELECT * FROM test", "dialect": "spark"}
        ]))
        .expect("representations should be valid");

        let view_creation = ViewCreation::builder()
            .name("test_view".to_string())
            .location("/test/views/test_view".to_string())
            .schema(schema)
            .default_namespace(NamespaceIdent::new("test".to_string()))
            .representations(representations)
            .build();

        let build_result = ViewMetadataBuilder::from_view_creation(view_creation)
            .expect("view creation should be valid")
            .build()
            .expect("metadata should be valid");

        build_result.metadata
    }

    #[tokio::test]
    async fn test_memory_view_store_create_and_load() {
        let store = MemoryViewStore::new();
        let namespace = vec!["test".to_string()];
        let name = "my_view";
        let metadata = create_test_view_metadata();
        let location = "s3://bucket/views/test/my_view".to_string();

        // Create view
        store
            .create_view(&namespace, name, location.clone(), metadata.clone())
            .await
            .expect("create should succeed");

        // Verify exists
        assert!(store.view_exists(&namespace, name).await.unwrap());

        // Load and verify
        let (loaded_loc, loaded_meta) = store
            .load_view(&namespace, name)
            .await
            .unwrap()
            .expect("view should exist");
        assert_eq!(loaded_loc, location);
        assert_eq!(loaded_meta.uuid(), metadata.uuid());
    }

    #[tokio::test]
    async fn test_memory_view_store_list_views() {
        let store = MemoryViewStore::new();
        let namespace = vec!["test".to_string()];

        // Create multiple views
        for i in 1..=3 {
            let metadata = create_test_view_metadata();
            store
                .create_view(
                    &namespace,
                    &format!("view_{}", i),
                    format!("s3://bucket/view_{}", i),
                    metadata,
                )
                .await
                .expect("create should succeed");
        }

        let views = store.list_views(&namespace).await.unwrap();
        assert_eq!(views.len(), 3);
    }

    #[tokio::test]
    async fn test_memory_view_store_update() {
        let store = MemoryViewStore::new();
        let namespace = vec!["test".to_string()];
        let name = "my_view";
        let metadata = create_test_view_metadata();

        // Create view
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                metadata.clone(),
            )
            .await
            .expect("create should succeed");

        // Update view
        let new_metadata = create_test_view_metadata();
        store
            .update_view(&namespace, name, "s3://bucket/v2".to_string(), new_metadata)
            .await
            .expect("update should succeed");

        // Verify updated
        let (loc, _) = store.load_view(&namespace, name).await.unwrap().unwrap();
        assert_eq!(loc, "s3://bucket/v2");
    }

    #[tokio::test]
    async fn test_memory_view_store_drop() {
        let store = MemoryViewStore::new();
        let namespace = vec!["test".to_string()];
        let name = "my_view";

        // Create and drop
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("create should succeed");

        store
            .drop_view(&namespace, name)
            .await
            .expect("drop should succeed");

        // Verify gone
        assert!(!store.view_exists(&namespace, name).await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_view_store_rename() {
        let store = MemoryViewStore::new();
        let src_ns = vec!["src".to_string()];
        let dest_ns = vec!["dest".to_string()];
        let metadata = create_test_view_metadata();

        // Create source view
        store
            .create_view(
                &src_ns,
                "old_view",
                "s3://bucket/src/old_view".to_string(),
                metadata,
            )
            .await
            .expect("create should succeed");

        // Rename
        store
            .rename_view(&src_ns, "old_view", &dest_ns, "new_view")
            .await
            .expect("rename should succeed");

        // Verify source gone, dest exists
        assert!(!store.view_exists(&src_ns, "old_view").await.unwrap());
        assert!(store.view_exists(&dest_ns, "new_view").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_view_store_duplicate_create_fails() {
        let store = MemoryViewStore::new();
        let namespace = vec!["test".to_string()];
        let name = "my_view";

        // Create view
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("first create should succeed");

        // Duplicate create should fail
        let result = store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v2".to_string(),
                create_test_view_metadata(),
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// SlateDB View Store Tests
// ============================================================================

#[cfg(test)]
#[cfg(feature = "slatedb-storage")]
mod slatedb_tests {
    use super::*;
    use iceberg::spec::{
        NestedField, NestedFieldRef, PrimitiveType, Schema, Type, ViewMetadataBuilder,
        ViewRepresentations,
    };
    use iceberg::{NamespaceIdent, ViewCreation};
    use object_store::local::LocalFileSystem;
    use object_store::ObjectStore;
    use slatedb::Db;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Helper to create test view metadata
    fn create_test_view_metadata() -> ViewMetadata {
        let schema = Schema::builder()
            .with_fields(vec![NestedFieldRef::from(NestedField::required(
                1,
                "id",
                Type::Primitive(PrimitiveType::Long),
            ))])
            .build()
            .expect("schema should be valid");

        let representations: ViewRepresentations = serde_json::from_value(serde_json::json!([
            {"type": "sql", "sql": "SELECT * FROM test", "dialect": "spark"}
        ]))
        .expect("representations should be valid");

        let view_creation = ViewCreation::builder()
            .name("test_view".to_string())
            .location("/test/views/test_view".to_string())
            .schema(schema)
            .default_namespace(NamespaceIdent::new("test".to_string()))
            .representations(representations)
            .build();

        let build_result = ViewMetadataBuilder::from_view_creation(view_creation)
            .expect("view creation should be valid")
            .build()
            .expect("metadata should be valid");

        build_result.metadata
    }

    /// Helper to create a SlateDB-backed view store for testing
    async fn create_test_store() -> (SlateDbViewStore, TempDir) {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(temp_dir.path()).unwrap());

        let db = Arc::new(
            Db::builder("views", object_store)
                .build()
                .await
                .expect("failed to create SlateDB"),
        );

        (SlateDbViewStore::new(db), temp_dir)
    }

    #[tokio::test]
    async fn test_slatedb_view_store_create_and_load() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["production".to_string()];
        let name = "sales_view";
        let metadata = create_test_view_metadata();
        let location = "s3://bucket/views/production/sales_view".to_string();

        // Create view
        store
            .create_view(&namespace, name, location.clone(), metadata.clone())
            .await
            .expect("create should succeed");

        // Verify exists
        assert!(store.view_exists(&namespace, name).await.unwrap());

        // Load and verify
        let (loaded_loc, loaded_meta) = store
            .load_view(&namespace, name)
            .await
            .unwrap()
            .expect("view should exist");
        assert_eq!(loaded_loc, location);
        assert_eq!(loaded_meta.uuid(), metadata.uuid());
    }

    #[tokio::test]
    async fn test_slatedb_view_store_list_views() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["analytics".to_string()];

        // Create multiple views
        for i in 1..=5 {
            let metadata = create_test_view_metadata();
            store
                .create_view(
                    &namespace,
                    &format!("kpi_view_{}", i),
                    format!("s3://bucket/views/analytics/kpi_view_{}", i),
                    metadata,
                )
                .await
                .expect("create should succeed");
        }

        let views = store.list_views(&namespace).await.unwrap();
        assert_eq!(views.len(), 5);
    }

    #[tokio::test]
    async fn test_slatedb_view_store_update_with_version() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["db".to_string()];
        let name = "versioned_view";

        // Create view (version 0)
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("create should succeed");

        // First update (version 1)
        store
            .update_view(
                &namespace,
                name,
                "s3://bucket/v2".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("first update should succeed");

        // Second update (version 2)
        store
            .update_view(
                &namespace,
                name,
                "s3://bucket/v3".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("second update should succeed");

        // Verify current location
        let (loc, _) = store.load_view(&namespace, name).await.unwrap().unwrap();
        assert_eq!(loc, "s3://bucket/v3");
    }

    #[tokio::test]
    async fn test_slatedb_view_store_drop() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["temp".to_string()];
        let name = "temp_view";

        // Create and drop
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("create should succeed");

        assert!(store.view_exists(&namespace, name).await.unwrap());

        store
            .drop_view(&namespace, name)
            .await
            .expect("drop should succeed");

        // Verify gone
        assert!(!store.view_exists(&namespace, name).await.unwrap());
    }

    #[tokio::test]
    async fn test_slatedb_view_store_atomic_rename() {
        let (store, _temp) = create_test_store().await;
        let src_ns = vec!["staging".to_string()];
        let dest_ns = vec!["production".to_string()];

        // Create source view
        store
            .create_view(
                &src_ns,
                "draft_view",
                "s3://bucket/staging/draft_view".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("create should succeed");

        // Rename atomically
        store
            .rename_view(&src_ns, "draft_view", &dest_ns, "live_view")
            .await
            .expect("rename should succeed");

        // Verify source gone, dest exists
        assert!(!store.view_exists(&src_ns, "draft_view").await.unwrap());
        assert!(store.view_exists(&dest_ns, "live_view").await.unwrap());

        // Location should be updated
        let (loc, _) = store
            .load_view(&dest_ns, "live_view")
            .await
            .unwrap()
            .unwrap();
        assert!(loc.contains("production"));
    }

    #[tokio::test]
    async fn test_slatedb_view_store_duplicate_create_fails() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["test".to_string()];
        let name = "unique_view";

        // First create succeeds
        store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v1".to_string(),
                create_test_view_metadata(),
            )
            .await
            .expect("first create should succeed");

        // Duplicate create fails
        let result = store
            .create_view(
                &namespace,
                name,
                "s3://bucket/v2".to_string(),
                create_test_view_metadata(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AppError::ViewAlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_slatedb_view_store_drop_nonexistent_fails() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["empty".to_string()];

        let result = store.drop_view(&namespace, "ghost_view").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AppError::NoSuchView(_)));
    }

    #[tokio::test]
    async fn test_slatedb_view_store_rename_to_existing_fails() {
        let (store, _temp) = create_test_store().await;
        let namespace = vec!["ns".to_string()];

        // Create two views
        store
            .create_view(
                &namespace,
                "view_a",
                "s3://bucket/a".to_string(),
                create_test_view_metadata(),
            )
            .await
            .unwrap();

        store
            .create_view(
                &namespace,
                "view_b",
                "s3://bucket/b".to_string(),
                create_test_view_metadata(),
            )
            .await
            .unwrap();

        // Rename view_a to view_b should fail
        let result = store
            .rename_view(&namespace, "view_a", &namespace, "view_b")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AppError::ViewAlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_slatedb_view_store_persistence() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(temp_dir.path()).unwrap());

        // Create view in first instance
        {
            let db = Arc::new(
                Db::builder("views", object_store.clone())
                    .build()
                    .await
                    .expect("failed to create SlateDB"),
            );
            let store = SlateDbViewStore::new(db.clone());
            let namespace = vec!["persistent".to_string()];

            store
                .create_view(
                    &namespace,
                    "durable_view",
                    "s3://bucket/durable".to_string(),
                    create_test_view_metadata(),
                )
                .await
                .expect("create should succeed");

            // Flush to ensure persistence
            db.flush().await.expect("flush should succeed");
        }

        // Verify in new instance (simulates restart)
        {
            let db = Arc::new(
                Db::builder("views", object_store.clone())
                    .build()
                    .await
                    .expect("failed to reopen SlateDB"),
            );
            let store = SlateDbViewStore::new(db);
            let namespace = vec!["persistent".to_string()];

            // View should still exist
            assert!(store.view_exists(&namespace, "durable_view").await.unwrap());

            let (loc, _) = store
                .load_view(&namespace, "durable_view")
                .await
                .unwrap()
                .expect("view should exist after restart");
            assert_eq!(loc, "s3://bucket/durable");
        }
    }

    #[tokio::test]
    async fn test_slatedb_view_store_multi_namespace() {
        let (store, _temp) = create_test_store().await;

        // Create views in different namespaces
        let ns1 = vec!["org1".to_string(), "team1".to_string()];
        let ns2 = vec!["org1".to_string(), "team2".to_string()];
        let ns3 = vec!["org2".to_string()];

        for i in 1..=3 {
            store
                .create_view(
                    &ns1,
                    &format!("view_{}", i),
                    format!("s3://bucket/ns1/view_{}", i),
                    create_test_view_metadata(),
                )
                .await
                .unwrap();
        }

        for i in 1..=2 {
            store
                .create_view(
                    &ns2,
                    &format!("report_{}", i),
                    format!("s3://bucket/ns2/report_{}", i),
                    create_test_view_metadata(),
                )
                .await
                .unwrap();
        }

        store
            .create_view(
                &ns3,
                "dashboard",
                "s3://bucket/ns3/dashboard".to_string(),
                create_test_view_metadata(),
            )
            .await
            .unwrap();

        // List views per namespace
        assert_eq!(store.list_views(&ns1).await.unwrap().len(), 3);
        assert_eq!(store.list_views(&ns2).await.unwrap().len(), 2);
        assert_eq!(store.list_views(&ns3).await.unwrap().len(), 1);

        // Empty namespace
        let empty = vec!["nonexistent".to_string()];
        assert_eq!(store.list_views(&empty).await.unwrap().len(), 0);
    }
}
