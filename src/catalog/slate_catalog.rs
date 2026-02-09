//! SlateDB-backed persistent catalog implementation.
//!
//! This module provides a production-grade persistent catalog using SlateDB
//! as the storage backend for catalog metadata (namespace/table registry),
//! combined with Iceberg's FileIO for table metadata files.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SlateCatalog                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │   SlateDB (Catalog Registry)     FileIO (Table Metadata)    │
//! │   ├─ namespace:db               ├─ s3://bucket/db/t1/       │
//! │   ├─ namespace:db.schema        │   └─ metadata/v1.json     │
//! │   ├─ table:db:users             ├─ s3://bucket/db/t2/       │
//! │   └─ table:db.schema:events     │   └─ metadata/v2.json     │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Backends
//!
//! - Local filesystem (`file://`)
//! - Amazon S3 (`s3://`)
//! - Google Cloud Storage (`gs://`)
//! - Azure Blob Storage (`az://`)
//! - MinIO (S3-compatible)

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use iceberg::io::FileIO;
use iceberg::spec::{TableMetadata, TableMetadataBuilder};
use iceberg::table::Table;
use iceberg::{
    Catalog, Error, ErrorKind, MetadataLocation, Namespace, NamespaceIdent, Result, TableCommit,
    TableCreation, TableIdent, TableRequirement, TableUpdate,
};
use serde::{Deserialize, Serialize};
use slatedb::{Db, WriteBatch};

use super::CatalogExt;

/// Metadata stored for each namespace in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamespaceMetadata {
    /// Namespace identifier parts
    namespace: Vec<String>,
    /// Namespace properties
    properties: HashMap<String, String>,
}

/// Metadata stored for each table in the catalog registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TableRegistryEntry {
    /// Table namespace parts
    namespace: Vec<String>,
    /// Table name
    name: String,
    /// Current metadata location (s3://bucket/table/metadata/v1.json)
    metadata_location: String,
    /// Version for optimistic concurrency control (CAS)
    /// Incremented on each update. Used to detect concurrent modifications.
    #[serde(default)]
    version: u64,
}

/// A persistent catalog implementation backed by SlateDB + FileIO.
///
/// This catalog uses:
/// - **SlateDB** for catalog registry (namespaces, table locations)
/// - **Iceberg FileIO** for reading/writing table metadata files
///
/// # Key Schema
///
/// - Namespaces: `namespace:{parts_joined_by_dot}`
/// - Tables: `table:{namespace}:{table_name}`
///
/// # Example
///
/// ```rust,no_run
/// use rustberg::catalog::SlateCatalog;
/// use slatedb::Db;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create SlateDB for catalog registry
/// let db = Db::builder("catalog", Arc::new(object_store::memory::InMemory::new()))
///     .build()
///     .await?;
///
/// // Create catalog with S3 warehouse
/// let catalog = SlateCatalog::new(
///     Arc::new(db),
///     "s3://my-bucket/warehouse".to_string()
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct SlateCatalog {
    /// SlateDB for catalog registry
    db: Arc<Db>,
    /// Iceberg FileIO for metadata operations
    file_io: FileIO,
    /// Warehouse location for table data
    warehouse_location: String,
    /// Timeout configuration for FileIO operations
    io_timeouts: IoTimeoutConfig,
}

/// Configuration for FileIO operation timeouts.
///
/// Prevents stalled S3/GCS/Azure connections from blocking workers indefinitely.
#[derive(Debug, Clone)]
pub struct IoTimeoutConfig {
    /// Timeout for metadata read operations (e.g., loading table metadata).
    /// Default: 60 seconds
    pub read_timeout: std::time::Duration,

    /// Timeout for metadata write operations (e.g., committing table changes).
    /// Default: 30 seconds
    pub write_timeout: std::time::Duration,
}

impl Default for IoTimeoutConfig {
    fn default() -> Self {
        Self {
            read_timeout: std::time::Duration::from_secs(60),
            write_timeout: std::time::Duration::from_secs(30),
        }
    }
}

impl IoTimeoutConfig {
    /// Creates a new timeout configuration.
    pub fn new(read_timeout: std::time::Duration, write_timeout: std::time::Duration) -> Self {
        Self {
            read_timeout,
            write_timeout,
        }
    }

    /// Creates configuration with custom read timeout.
    pub fn with_read_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Creates configuration with custom write timeout.
    pub fn with_write_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.write_timeout = timeout;
        self
    }
}

// Manual Debug impl since Db doesn't implement Debug
impl std::fmt::Debug for SlateCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlateCatalog")
            .field("warehouse_location", &self.warehouse_location)
            .finish_non_exhaustive()
    }
}

impl SlateCatalog {
    /// Creates a new SlateDB-backed catalog.
    ///
    /// # Arguments
    ///
    /// * `db` - SlateDB instance for catalog registry
    /// * `warehouse_location` - Base path for table data storage (s3://, gs://, file://)
    ///
    /// # Errors
    ///
    /// Returns error if FileIO cannot be created for the warehouse location.
    pub async fn new(db: Arc<Db>, warehouse_location: String) -> Result<Self> {
        Self::with_timeouts(db, warehouse_location, IoTimeoutConfig::default()).await
    }

    /// Creates a new SlateDB-backed catalog with custom timeout configuration.
    ///
    /// # Arguments
    ///
    /// * `db` - SlateDB instance for catalog registry
    /// * `warehouse_location` - Base path for table data storage
    /// * `io_timeouts` - Timeout configuration for FileIO operations
    pub async fn with_timeouts(
        db: Arc<Db>,
        warehouse_location: String,
        io_timeouts: IoTimeoutConfig,
    ) -> Result<Self> {
        // Normalize and ensure warehouse directory exists for local paths
        let warehouse_location = Self::normalize_and_ensure_local_directory(&warehouse_location)?;

        // Create FileIO from warehouse location
        let file_io = FileIO::from_path(&warehouse_location)?.build()?;

        Ok(Self {
            db,
            file_io,
            warehouse_location,
            io_timeouts,
        })
    }

    /// Creates a new SlateDB-backed catalog with custom FileIO properties.
    ///
    /// Use this for configuring AWS credentials, regions, etc.
    pub async fn with_props(
        db: Arc<Db>,
        warehouse_location: String,
        props: HashMap<String, String>,
    ) -> Result<Self> {
        Self::with_props_and_timeouts(db, warehouse_location, props, IoTimeoutConfig::default())
            .await
    }

    /// Creates a catalog with custom FileIO properties and timeout configuration.
    pub async fn with_props_and_timeouts(
        db: Arc<Db>,
        warehouse_location: String,
        props: HashMap<String, String>,
        io_timeouts: IoTimeoutConfig,
    ) -> Result<Self> {
        // Normalize and ensure warehouse directory exists for local paths
        let warehouse_location = Self::normalize_and_ensure_local_directory(&warehouse_location)?;

        let file_io = FileIO::from_path(&warehouse_location)?
            .with_props(props)
            .build()?;

        Ok(Self {
            db,
            file_io,
            warehouse_location,
            io_timeouts,
        })
    }

    /// Normalizes the warehouse location and ensures the directory exists for local paths.
    ///
    /// This handles:
    /// - `file://relative/path` → converts to absolute and creates directory
    /// - `file:///absolute/path` → creates directory  
    /// - `/absolute/path` → creates directory
    /// - `relative/path` → converts to absolute and creates directory
    /// - `s3://`, `gs://`, `az://` → returned unchanged (cloud storage)
    ///
    /// Returns the normalized warehouse location.
    fn normalize_and_ensure_local_directory(warehouse_location: &str) -> Result<String> {
        // Check for cloud storage schemes - return unchanged
        if warehouse_location.starts_with("s3://")
            || warehouse_location.starts_with("gs://")
            || warehouse_location.starts_with("az://")
            || warehouse_location.starts_with("memory://")
        {
            return Ok(warehouse_location.to_string());
        }

        // Extract path from file:// URL or use as-is
        let path = if warehouse_location.starts_with("file://") {
            warehouse_location
                .strip_prefix("file://")
                .unwrap_or(warehouse_location)
        } else {
            warehouse_location
        };

        // Convert relative paths to absolute
        let absolute_path = if std::path::Path::new(path).is_absolute() {
            std::path::PathBuf::from(path)
        } else {
            std::env::current_dir()
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Unexpected,
                        format!("Failed to get current directory: {}", e),
                    )
                })?
                .join(path)
        };

        // Create the directory
        std::fs::create_dir_all(&absolute_path).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!(
                    "Failed to create warehouse directory '{}': {}",
                    absolute_path.display(),
                    e
                ),
            )
        })?;

        // Return normalized file:// URL with absolute path
        let normalized = format!("file://{}", absolute_path.display());
        tracing::info!(
            original = %warehouse_location,
            normalized = %normalized,
            "Normalized warehouse location"
        );

        Ok(normalized)
    }

    /// Generates a namespace key for SlateDB storage.
    fn namespace_key(namespace: &NamespaceIdent) -> Vec<u8> {
        format!("namespace:{}", namespace.join(".")).into_bytes()
    }

    /// Generates a table key for SlateDB storage.
    fn table_key(table: &TableIdent) -> Vec<u8> {
        format!("table:{}:{}", table.namespace.join("."), table.name).into_bytes()
    }

    /// Prefix for scanning all tables in a namespace
    fn table_prefix(namespace: &NamespaceIdent) -> String {
        format!("table:{}:", namespace.join("."))
    }

    /// Generates the table data location within the warehouse.
    fn table_location(&self, table: &TableIdent) -> String {
        format!(
            "{}/{}/{}",
            self.warehouse_location,
            table.namespace.join("/"),
            table.name
        )
    }

    /// Converts SlateDB error to Iceberg error.
    fn convert_error(err: slatedb::Error) -> Error {
        Error::new(ErrorKind::Unexpected, format!("SlateDB error: {}", err))
    }

    /// Constructs NamespaceIdent from parts, returning an error for empty parts.
    fn make_namespace_ident(parts: Vec<String>) -> Result<NamespaceIdent> {
        NamespaceIdent::from_vec(parts).map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Invalid namespace identifier in stored data: {}", e),
            )
        })
    }

    /// Reads table metadata with timeout protection.
    ///
    /// Wraps `TableMetadata::read_from` with a configurable timeout to prevent
    /// stalled S3/GCS/Azure connections from blocking workers indefinitely.
    async fn read_metadata_with_timeout(&self, location: &str) -> Result<TableMetadata> {
        tokio::time::timeout(
            self.io_timeouts.read_timeout,
            TableMetadata::read_from(&self.file_io, location),
        )
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::Unexpected,
                format!(
                    "Timeout reading table metadata from '{}' after {:?}",
                    location, self.io_timeouts.read_timeout
                ),
            )
        })?
    }

    /// Writes table metadata with timeout protection.
    ///
    /// Wraps `TableMetadata::write_to` with a configurable timeout to prevent
    /// stalled connections from blocking workers indefinitely.
    async fn write_metadata_with_timeout(
        &self,
        metadata: &TableMetadata,
        location: &str,
    ) -> Result<()> {
        tokio::time::timeout(
            self.io_timeouts.write_timeout,
            metadata.write_to(&self.file_io, location),
        )
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::Unexpected,
                format!(
                    "Timeout writing table metadata to '{}' after {:?}",
                    location, self.io_timeouts.write_timeout
                ),
            )
        })?
    }
}

#[async_trait]
impl Catalog for SlateCatalog {
    /// Lists namespaces, optionally filtered by parent namespace.
    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
    ) -> Result<Vec<NamespaceIdent>> {
        let prefix = if let Some(p) = parent {
            format!("namespace:{}.", p.join("."))
        } else {
            "namespace:".to_string()
        };

        let mut namespaces = Vec::new();
        let mut iter = self
            .db
            .scan_prefix(prefix.as_bytes())
            .await
            .map_err(Self::convert_error)?;

        while let Some(kv) = iter.next().await.map_err(Self::convert_error)? {
            if let Ok(metadata) = serde_json::from_slice::<NamespaceMetadata>(&kv.value) {
                // Filter by parent if specified
                if let Some(parent_ns) = parent {
                    let parent_parts: Vec<&str> = parent_ns.iter().map(|s| s.as_str()).collect();
                    if metadata.namespace.len() == parent_parts.len() + 1
                        && metadata.namespace[..parent_parts.len()]
                            .iter()
                            .zip(parent_parts.iter())
                            .all(|(a, b)| a == *b)
                    {
                        namespaces.push(Self::make_namespace_ident(metadata.namespace)?);
                    }
                } else if metadata.namespace.len() == 1 {
                    // Top-level namespace
                    namespaces.push(Self::make_namespace_ident(metadata.namespace)?);
                }
            }
        }

        Ok(namespaces)
    }

    /// Creates a new namespace with the given properties.
    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        let key = Self::namespace_key(namespace);

        // Check if namespace already exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::NamespaceAlreadyExists,
                format!("Namespace already exists: {}", namespace.join(".")),
            ));
        }

        // Create namespace metadata
        let metadata = NamespaceMetadata {
            namespace: namespace.iter().map(|s| s.to_string()).collect(),
            properties: properties.clone(),
        };

        // Serialize and store
        let value = serde_json::to_vec(&metadata).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize namespace metadata: {}", e),
            )
        })?;

        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        Ok(Namespace::with_properties(namespace.clone(), properties))
    }

    /// Gets a namespace by its identifier.
    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        let key = Self::namespace_key(namespace);

        let value = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NamespaceNotFound,
                    format!("Namespace not found: {}", namespace.join(".")),
                )
            })?;

        let metadata: NamespaceMetadata = serde_json::from_slice(&value).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to deserialize namespace metadata: {}", e),
            )
        })?;

        Ok(Namespace::with_properties(
            namespace.clone(),
            metadata.properties,
        ))
    }

    /// Checks if a namespace exists.
    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        let key = Self::namespace_key(namespace);
        Ok(self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_some())
    }

    /// Updates namespace properties (replaces all properties).
    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()> {
        let key = Self::namespace_key(namespace);

        // Check namespace exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!("Namespace not found: {}", namespace.join(".")),
            ));
        }

        // Create updated metadata
        let metadata = NamespaceMetadata {
            namespace: namespace.iter().map(|s| s.to_string()).collect(),
            properties,
        };

        // Store updated metadata
        let new_value = serde_json::to_vec(&metadata).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize namespace metadata: {}", e),
            )
        })?;

        self.db
            .put(&key, &new_value)
            .await
            .map_err(Self::convert_error)?;

        Ok(())
    }

    /// Drops a namespace.
    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        let key = Self::namespace_key(namespace);

        // Check if namespace exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!("Namespace not found: {}", namespace.join(".")),
            ));
        }

        // Check if namespace has tables
        let prefix = Self::table_prefix(namespace);
        let mut iter = self
            .db
            .scan_prefix(prefix.as_bytes())
            .await
            .map_err(Self::convert_error)?;

        if iter.next().await.map_err(Self::convert_error)?.is_some() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!("Namespace not empty: {}", namespace.join(".")),
            ));
        }

        // Delete namespace
        self.db.delete(&key).await.map_err(Self::convert_error)?;

        Ok(())
    }

    /// Lists tables in a namespace.
    async fn list_tables(&self, namespace: &NamespaceIdent) -> Result<Vec<TableIdent>> {
        // Check namespace exists
        if !self.namespace_exists(namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!("Namespace not found: {}", namespace.join(".")),
            ));
        }

        let prefix = Self::table_prefix(namespace);
        let mut tables = Vec::new();

        let mut iter = self
            .db
            .scan_prefix(prefix.as_bytes())
            .await
            .map_err(Self::convert_error)?;

        while let Some(kv) = iter.next().await.map_err(Self::convert_error)? {
            if let Ok(entry) = serde_json::from_slice::<TableRegistryEntry>(&kv.value) {
                tables.push(TableIdent::new(
                    Self::make_namespace_ident(entry.namespace)?,
                    entry.name,
                ));
            }
        }

        Ok(tables)
    }

    /// Creates a new table with full metadata persistence.
    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        // Verify namespace exists
        if !self.namespace_exists(namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!("Namespace not found: {}", namespace.join(".")),
            ));
        }

        let table_name = creation.name.clone();
        let table_ident = TableIdent::new(namespace.clone(), table_name);
        let key = Self::table_key(&table_ident);

        // Check if table already exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!("Table already exists: {}", table_ident.name()),
            ));
        }

        // Determine table location
        let (creation, location) = match creation.location.clone() {
            Some(loc) => (creation, loc),
            None => {
                let location = self.table_location(&table_ident);
                let new_creation = TableCreation {
                    location: Some(location.clone()),
                    ..creation
                };
                (new_creation, location)
            }
        };

        // Build table metadata from creation spec
        let metadata = TableMetadataBuilder::from_table_creation(creation)?
            .build()?
            .metadata;

        // Generate metadata location and write to storage (with timeout protection)
        let metadata_location = MetadataLocation::new_with_table_location(&location).to_string();
        self.write_metadata_with_timeout(&metadata, &metadata_location)
            .await?;

        // Register table in SlateDB
        let registry_entry = TableRegistryEntry {
            namespace: namespace.iter().map(|s| s.to_string()).collect(),
            name: table_ident.name().to_string(),
            metadata_location: metadata_location.clone(),
            version: 0, // Initial version
        };

        let value = serde_json::to_vec(&registry_entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        // Build and return the Table
        Table::builder()
            .file_io(self.file_io.clone())
            .metadata_location(metadata_location)
            .metadata(metadata)
            .identifier(table_ident)
            .build()
    }

    /// Loads a table by reading metadata from storage.
    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        let key = Self::table_key(table);

        let value = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::TableNotFound,
                    format!(
                        "Table not found: {}.{}",
                        table.namespace.join("."),
                        table.name
                    ),
                )
            })?;

        let entry: TableRegistryEntry = serde_json::from_slice(&value).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to deserialize table registry entry: {}", e),
            )
        })?;

        // Read table metadata from storage (with timeout protection)
        let metadata = self
            .read_metadata_with_timeout(&entry.metadata_location)
            .await?;

        Table::builder()
            .identifier(table.clone())
            .metadata(metadata)
            .metadata_location(entry.metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }

    /// Drops a table (removes from registry, optionally purges data).
    async fn drop_table(&self, table: &TableIdent) -> Result<()> {
        let key = Self::table_key(table);

        // Check if table exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::TableNotFound,
                format!(
                    "Table not found: {}.{}",
                    table.namespace.join("."),
                    table.name
                ),
            ));
        }

        // Delete from registry (does not purge data files)
        self.db.delete(&key).await.map_err(Self::convert_error)?;

        Ok(())
    }

    /// Checks if a table exists.
    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        let key = Self::table_key(table);
        Ok(self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_some())
    }

    /// Renames a table.
    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        let src_key = Self::table_key(src);
        let dest_key = Self::table_key(dest);

        // Get source table metadata
        let value = self
            .db
            .get(&src_key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::TableNotFound,
                    format!(
                        "Source table not found: {}.{}",
                        src.namespace.join("."),
                        src.name
                    ),
                )
            })?;

        // Check destination doesn't exist
        if self
            .db
            .get(&dest_key)
            .await
            .map_err(Self::convert_error)?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!(
                    "Destination table already exists: {}.{}",
                    dest.namespace.join("."),
                    dest.name
                ),
            ));
        }

        // Check destination namespace exists
        if !self.namespace_exists(&dest.namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!(
                    "Destination namespace not found: {}",
                    dest.namespace.join(".")
                ),
            ));
        }

        // Update registry entry with new name/namespace
        let mut entry: TableRegistryEntry = serde_json::from_slice(&value).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to deserialize table registry entry: {}", e),
            )
        })?;

        entry.namespace = dest.namespace.iter().map(|s| s.to_string()).collect();
        entry.name = dest.name.clone();

        let new_value = serde_json::to_vec(&entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        // Use WriteBatch for atomic put + delete (CRITICAL-003 fix)
        let mut batch = WriteBatch::new();
        batch.put(&dest_key, &new_value);
        batch.delete(&src_key);

        self.db.write(batch).await.map_err(Self::convert_error)?;

        Ok(())
    }

    /// Registers an existing table from its metadata location.
    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table> {
        let key = Self::table_key(table);

        // Check if table already exists
        if self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .is_some()
        {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!(
                    "Table already exists: {}.{}",
                    table.namespace.join("."),
                    table.name
                ),
            ));
        }

        // Check namespace exists
        if !self.namespace_exists(&table.namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!("Namespace not found: {}", table.namespace.join(".")),
            ));
        }

        // Read metadata from location to verify it's valid (with timeout protection)
        let metadata = self.read_metadata_with_timeout(&metadata_location).await?;

        // Register in catalog
        let entry = TableRegistryEntry {
            namespace: table.namespace.iter().map(|s| s.to_string()).collect(),
            name: table.name.clone(),
            metadata_location: metadata_location.clone(),
            version: 0, // Initial registration
        };

        let value = serde_json::to_vec(&entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        Table::builder()
            .identifier(table.clone())
            .metadata(metadata)
            .metadata_location(metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }

    /// Commits table updates (schema changes, snapshot commits, etc.)
    async fn update_table(&self, mut commit: TableCommit) -> Result<Table> {
        let table_ident = commit.identifier().clone();
        let key = Self::table_key(&table_ident);

        // Load current table and registry entry
        let current_table = self.load_table(&table_ident).await?;
        let current_metadata = current_table.metadata().clone();
        let current_location = current_table
            .metadata_location()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Table has no metadata location"))?;

        // Load current registry entry to get version (CRITICAL-001 fix)
        let current_entry_bytes = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| Error::new(ErrorKind::TableNotFound, "Table not found during update"))?;
        let current_entry: TableRegistryEntry = serde_json::from_slice(&current_entry_bytes)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;
        let expected_version = current_entry.version;

        // Apply requirements checks
        for req in commit.take_requirements() {
            req.check(Some(&current_metadata))?;
        }

        // Apply updates to metadata
        let mut builder = TableMetadataBuilder::new_from_metadata(
            current_metadata.clone(),
            Some(current_location.to_string()),
        );

        for update in commit.take_updates() {
            builder = update.apply(builder)?;
        }

        let new_metadata = builder.build()?.metadata;

        // Generate new metadata location and write
        let table_location = current_table.metadata().location();

        let new_metadata_location = MetadataLocation::new_with_table_location(table_location)
            .with_next_version()
            .to_string();

        self.write_metadata_with_timeout(&new_metadata, &new_metadata_location)
            .await?;

        // CAS: Re-read and verify version hasn't changed (CRITICAL-001 fix)
        let verify_entry_bytes = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| {
                Error::new(ErrorKind::TableNotFound, "Table disappeared during update")
            })?;
        let verify_entry: TableRegistryEntry = serde_json::from_slice(&verify_entry_bytes)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;

        if verify_entry.version != expected_version {
            return Err(Error::new(
                ErrorKind::CatalogCommitConflicts,
                format!(
                    "Commit conflict: table was modified by another process (expected version {}, found {})",
                    expected_version, verify_entry.version
                ),
            ));
        }

        // Update registry with new metadata location and incremented version
        let entry = TableRegistryEntry {
            namespace: table_ident
                .namespace
                .iter()
                .map(|s| s.to_string())
                .collect(),
            name: table_ident.name().to_string(),
            metadata_location: new_metadata_location.clone(),
            version: expected_version + 1, // Increment version
        };

        let value = serde_json::to_vec(&entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        Table::builder()
            .identifier(table_ident)
            .metadata(new_metadata)
            .metadata_location(new_metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }
}

#[async_trait]
impl CatalogExt for SlateCatalog {
    async fn commit_table(
        &self,
        table_ident: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        let key = Self::table_key(table_ident);

        // Load current table and registry entry (CRITICAL-001 fix: capture version for CAS)
        let table = self.load_table(table_ident).await?;

        // Load current registry entry to get version
        let current_entry_bytes = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| Error::new(ErrorKind::TableNotFound, "Table not found"))?;
        let current_entry: TableRegistryEntry = serde_json::from_slice(&current_entry_bytes)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;
        let expected_version = current_entry.version;
        let expected_metadata_location = current_entry.metadata_location.clone();

        // Check all requirements against current metadata
        for requirement in &requirements {
            requirement.check(Some(table.metadata()))?;
        }

        // Get current metadata location
        let current_metadata_location = table
            .metadata_location()
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "Table has no metadata location"))?;

        // Apply all updates to build new metadata
        let mut metadata_builder = table
            .metadata()
            .clone()
            .into_builder(Some(current_metadata_location.to_string()));

        for update in updates {
            metadata_builder = update.apply(metadata_builder)?;
        }

        // Build the new metadata
        let new_metadata = metadata_builder.build()?;

        // Generate new metadata location
        let table_location = table.metadata().location();
        let new_metadata_location = MetadataLocation::new_with_table_location(table_location)
            .with_next_version()
            .to_string();

        // Write the new metadata file to storage (with timeout protection)
        self.write_metadata_with_timeout(&new_metadata.metadata, &new_metadata_location)
            .await?;

        // CAS: Re-read and verify version hasn't changed (CRITICAL-001 fix)
        let verify_entry_bytes = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| {
                Error::new(ErrorKind::TableNotFound, "Table disappeared during commit")
            })?;
        let verify_entry: TableRegistryEntry = serde_json::from_slice(&verify_entry_bytes)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;

        if verify_entry.version != expected_version
            || verify_entry.metadata_location != expected_metadata_location
        {
            return Err(Error::new(
                ErrorKind::CatalogCommitConflicts,
                format!(
                    "Commit conflict: table was modified by another process (expected version {}, found {})",
                    expected_version, verify_entry.version
                ),
            ));
        }

        // Read metadata from the new location to verify it's valid (with timeout protection)
        let metadata = self
            .read_metadata_with_timeout(&new_metadata_location)
            .await?;

        // Update the registry entry with new metadata location and incremented version
        let entry = TableRegistryEntry {
            namespace: table_ident
                .namespace
                .iter()
                .map(|s| s.to_string())
                .collect(),
            name: table_ident.name().to_string(),
            metadata_location: new_metadata_location.clone(),
            version: expected_version + 1, // Increment version
        };

        let value = serde_json::to_vec(&entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        // Atomically update the registry
        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        Table::builder()
            .identifier(table_ident.clone())
            .metadata(metadata)
            .metadata_location(new_metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }

    async fn update_table_metadata_location(
        &self,
        table_ident: &TableIdent,
        new_metadata_location: String,
    ) -> Result<Table> {
        let key = Self::table_key(table_ident);

        // Load current registry entry to get version (CRITICAL-001 fix)
        let current_entry_bytes = self
            .db
            .get(&key)
            .await
            .map_err(Self::convert_error)?
            .ok_or_else(|| Error::new(ErrorKind::TableNotFound, "Table not found"))?;
        let current_entry: TableRegistryEntry = serde_json::from_slice(&current_entry_bytes)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;
        let expected_version = current_entry.version;

        // Read metadata from the new location to verify it's valid (with timeout protection)
        let metadata = self
            .read_metadata_with_timeout(&new_metadata_location)
            .await?;

        // Update the registry entry with the new metadata location and incremented version
        let entry = TableRegistryEntry {
            namespace: table_ident
                .namespace
                .iter()
                .map(|s| s.to_string())
                .collect(),
            name: table_ident.name().to_string(),
            metadata_location: new_metadata_location.clone(),
            version: expected_version + 1, // Increment version
        };

        let value = serde_json::to_vec(&entry).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize table registry entry: {}", e),
            )
        })?;

        // Atomically update the registry
        self.db
            .put(&key, &value)
            .await
            .map_err(Self::convert_error)?;

        Table::builder()
            .identifier(table_ident.clone())
            .metadata(metadata)
            .metadata_location(new_metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }

    /// Atomically commits changes to multiple tables in a single transaction.
    ///
    /// This is an atomic multi-table commit that uses:
    /// 1. Optimistic concurrency control with version tracking
    /// 2. WriteBatch for atomic multi-key updates
    /// 3. Exponential backoff retry on conflicts
    ///
    /// All table changes are applied atomically: either all succeed or none do.
    async fn commit_tables_atomic(
        &self,
        table_changes: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        use std::time::Duration;
        use tokio::time::sleep;

        const MAX_RETRIES: u32 = 10;
        const BASE_BACKOFF_MS: u64 = 10;

        // Fast path: single table uses existing commit_table (already atomic)
        if table_changes.len() == 1 {
            let (ident, reqs, updates) = table_changes.into_iter().next().unwrap();
            let table = self.commit_table(&ident, reqs, updates).await?;
            return Ok(vec![table]);
        }

        // Multi-table atomic commit with retry loop
        for attempt in 0..MAX_RETRIES {
            match self.try_commit_tables_atomic(&table_changes).await {
                Ok(tables) => return Ok(tables),
                Err(e) if e.kind() == ErrorKind::CatalogCommitConflicts => {
                    // Exponential backoff before retry
                    let backoff_ms = BASE_BACKOFF_MS * (1 << attempt.min(6)); // Cap at ~640ms
                    tracing::debug!(
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        backoff_ms = backoff_ms,
                        "Commit conflict detected, retrying"
                    );
                    sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(e) => return Err(e),
            }
        }

        Err(Error::new(
            ErrorKind::CatalogCommitConflicts,
            format!(
                "Failed to commit atomic transaction after {} retries",
                MAX_RETRIES
            ),
        ))
    }

    async fn storage_health_check(&self) -> Result<super::StorageHealthStatus> {
        use std::time::Instant;

        let start = Instant::now();

        // Determine backend type from warehouse location
        let backend_type = if self.warehouse_location.starts_with("s3://") {
            "s3"
        } else if self.warehouse_location.starts_with("gs://") {
            "gcs"
        } else if self.warehouse_location.starts_with("az://")
            || self.warehouse_location.starts_with("abfs://")
        {
            "azure"
        } else if self.warehouse_location.starts_with("file://") {
            "file"
        } else if self.warehouse_location.starts_with("memory://") {
            "memory"
        } else {
            "unknown"
        };

        // Perform a read operation to verify storage connectivity
        // Try to check if the warehouse location is accessible
        match self.file_io.exists(&self.warehouse_location).await {
            Ok(_) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                Ok(super::StorageHealthStatus::healthy(
                    backend_type,
                    latency_ms,
                ))
            }
            Err(e) => {
                // If the path doesn't exist, that's OK - storage is still reachable
                // Check for actual connectivity errors
                let err_str = e.to_string();
                if err_str.contains("NotFound") || err_str.contains("not found") {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    Ok(super::StorageHealthStatus::healthy(
                        backend_type,
                        latency_ms,
                    ))
                } else {
                    Ok(super::StorageHealthStatus::unhealthy(
                        backend_type,
                        format!("Storage check failed: {}", e),
                    ))
                }
            }
        }
    }
}

impl SlateCatalog {
    /// Internal helper for atomic multi-table commit (single attempt).
    ///
    /// Returns `Err(CatalogCommitConflicts)` if any table was modified concurrently.
    async fn try_commit_tables_atomic(
        &self,
        table_changes: &[(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)],
    ) -> Result<Vec<Table>> {
        // Phase 1: Load all tables and capture their versions
        let mut table_states: Vec<(
            &TableIdent,
            Table,
            TableRegistryEntry,
            Vec<u8>, // registry key
        )> = Vec::with_capacity(table_changes.len());

        for (ident, _, _) in table_changes {
            let key = Self::table_key(ident);
            let table = self.load_table(ident).await?;

            let entry_bytes = self
                .db
                .get(&key)
                .await
                .map_err(Self::convert_error)?
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::TableNotFound,
                        format!("Table not found: {}", ident),
                    )
                })?;
            let entry: TableRegistryEntry = serde_json::from_slice(&entry_bytes).map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to deserialize entry: {}", e),
                )
            })?;

            table_states.push((ident, table, entry, key));
        }

        // Phase 2: Validate all requirements BEFORE writing any metadata
        for ((ident, requirements, _), (_, table, _, _)) in
            table_changes.iter().zip(table_states.iter())
        {
            for requirement in requirements {
                requirement.check(Some(table.metadata())).map_err(|e| {
                    Error::new(
                        e.kind(),
                        format!("Requirement failed for table {}: {}", ident, e.message()),
                    )
                })?;
            }
        }

        // Phase 3: Build new metadata and write metadata files for all tables
        // (ident, new_metadata_location, new_entry, key, expected_version, expected_metadata_location)
        #[allow(clippy::type_complexity)]
        let mut prepared_updates: Vec<(
            &TableIdent,
            String,             // new metadata location
            TableRegistryEntry, // new registry entry
            Vec<u8>,            // registry key
            u64,                // expected version
            String,             // expected metadata location
        )> = Vec::with_capacity(table_changes.len());

        for ((ident, _, updates), (_, table, current_entry, key)) in
            table_changes.iter().zip(table_states.iter())
        {
            let current_metadata_location = table.metadata_location().ok_or_else(|| {
                Error::new(ErrorKind::DataInvalid, "Table has no metadata location")
            })?;

            // Apply all updates to build new metadata
            let mut metadata_builder = table
                .metadata()
                .clone()
                .into_builder(Some(current_metadata_location.to_string()));

            for update in updates {
                metadata_builder = update.clone().apply(metadata_builder)?;
            }

            let new_metadata = metadata_builder.build()?;

            // Generate new metadata location
            let table_location = table.metadata().location();
            let new_metadata_location = MetadataLocation::new_with_table_location(table_location)
                .with_next_version()
                .to_string();

            // Write metadata file with timeout protection (safe - orphan files don't cause issues)
            self.write_metadata_with_timeout(&new_metadata.metadata, &new_metadata_location)
                .await?;

            // Prepare new registry entry
            let new_entry = TableRegistryEntry {
                namespace: ident.namespace.iter().map(|s| s.to_string()).collect(),
                name: ident.name().to_string(),
                metadata_location: new_metadata_location.clone(),
                version: current_entry.version + 1,
            };

            prepared_updates.push((
                ident,
                new_metadata_location,
                new_entry,
                key.clone(),
                current_entry.version,
                current_entry.metadata_location.clone(),
            ));
        }

        // Phase 4: Verify no concurrent modifications (optimistic lock check)
        for (ident, _, _, key, expected_version, expected_location) in &prepared_updates {
            let verify_bytes = self
                .db
                .get(key)
                .await
                .map_err(Self::convert_error)?
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::TableNotFound,
                        format!("Table disappeared during commit: {}", ident),
                    )
                })?;
            let verify_entry: TableRegistryEntry =
                serde_json::from_slice(&verify_bytes).map_err(|e| {
                    Error::new(
                        ErrorKind::Unexpected,
                        format!("Failed to deserialize entry: {}", e),
                    )
                })?;

            if verify_entry.version != *expected_version
                || &verify_entry.metadata_location != expected_location
            {
                return Err(Error::new(
                    ErrorKind::CatalogCommitConflicts,
                    format!(
                        "Commit conflict on table {}: expected version {}, found {}",
                        ident, expected_version, verify_entry.version
                    ),
                ));
            }
        }

        // Phase 5: Atomic batch write of ALL registry entries
        let mut batch = WriteBatch::new();
        for (_, _, new_entry, key, _, _) in &prepared_updates {
            let value = serde_json::to_vec(new_entry).map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to serialize table registry entry: {}", e),
                )
            })?;
            batch.put(key, &value);
        }

        self.db.write(batch).await.map_err(Self::convert_error)?;

        // Phase 6: Build and return updated Table objects (with timeout protection)
        let mut result_tables = Vec::with_capacity(prepared_updates.len());
        for (ident, new_metadata_location, _, _, _, _) in prepared_updates {
            let metadata = self
                .read_metadata_with_timeout(&new_metadata_location)
                .await?;
            let table = Table::builder()
                .identifier(ident.clone())
                .metadata(metadata)
                .metadata_location(new_metadata_location)
                .file_io(self.file_io.clone())
                .build()?;
            result_tables.push(table);
        }

        Ok(result_tables)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_key() {
        let ns = NamespaceIdent::from_vec(vec!["db".to_string(), "schema".to_string()]).unwrap();
        let key = SlateCatalog::namespace_key(&ns);
        assert_eq!(String::from_utf8_lossy(&key), "namespace:db.schema");
    }

    #[test]
    fn test_table_key() {
        let ns = NamespaceIdent::from_vec(vec!["db".to_string()]).unwrap();
        let table = TableIdent::new(ns, "my_table".to_string());
        let key = SlateCatalog::table_key(&table);
        assert_eq!(String::from_utf8_lossy(&key), "table:db:my_table");
    }

    #[test]
    fn test_table_prefix() {
        let ns = NamespaceIdent::from_vec(vec!["db".to_string(), "schema".to_string()]).unwrap();
        let prefix = SlateCatalog::table_prefix(&ns);
        assert_eq!(prefix, "table:db.schema:");
    }
}
