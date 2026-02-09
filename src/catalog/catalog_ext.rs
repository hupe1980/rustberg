//! Extended catalog trait for Rustberg-specific operations.
//!
//! The iceberg-rust `Catalog` trait's `update_table` method requires a `TableCommit`
//! whose builder is `pub(crate)`. This module provides an extension trait that allows
//! us to update tables directly from HTTP request payloads.

use std::fmt::Debug;

use async_trait::async_trait;
use iceberg::table::Table;
use iceberg::{Catalog, Error, ErrorKind, Result, TableIdent, TableRequirement, TableUpdate};

/// Extension trait for Iceberg catalogs that provides direct table update capabilities.
///
/// This trait is needed because the Iceberg REST API receives `TableUpdate` and
/// `TableRequirement` directly in the commit request, but the iceberg-rust crate's
/// `TableCommit` builder is `pub(crate)` and cannot be constructed externally.
#[async_trait]
pub trait CatalogExt: Catalog {
    /// Updates a table's metadata directly with the given updates and requirements.
    ///
    /// This method:
    /// 1. Loads the current table
    /// 2. Validates all requirements against current metadata
    /// 3. Applies all updates to build new metadata
    /// 4. Persists the updated table
    ///
    /// Returns a 409 Conflict error if any requirement fails.
    async fn commit_table(
        &self,
        table_ident: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table>;

    /// Updates the metadata location for an existing table in the catalog registry.
    ///
    /// This is used internally by `commit_table` to atomically update the catalog's
    /// pointer to the new metadata file after writing it to storage.
    ///
    /// Unlike `register_table`, this method expects the table to already exist.
    async fn update_table_metadata_location(
        &self,
        table_ident: &TableIdent,
        new_metadata_location: String,
    ) -> Result<Table>;

    /// Atomically commits changes to multiple tables in a single transaction.
    ///
    /// This is the atomic multi-table commit implementation that ensures
    /// all changes succeed or all fail together. It uses optimistic concurrency control
    /// with retry logic to handle concurrent modifications.
    ///
    /// # Arguments
    /// * `table_changes` - A list of (table_ident, requirements, updates) tuples
    ///
    /// # Returns
    /// * `Ok(Vec<Table>)` - The updated tables after successful commit
    /// * `Err` - If any requirement fails or if the commit cannot be applied atomically
    ///
    /// # Atomicity Guarantee
    /// Either all table changes are applied atomically, or none are. If a conflict
    /// is detected (another transaction modified any of the tables), this method
    /// will retry with exponential backoff up to a configured number of retries.
    async fn commit_tables_atomic(
        &self,
        table_changes: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>>;

    /// Performs a storage backend health check.
    ///
    /// This method validates connectivity to the underlying storage backend (S3/GCS/Azure/local).
    /// Used by the `/ready` endpoint to ensure the catalog can read and write table metadata.
    ///
    /// # Returns
    /// * `Ok(StorageHealthStatus)` - Storage health details including backend type and latency
    /// * `Err` - If the storage backend is unreachable or misconfigured
    async fn storage_health_check(&self) -> Result<StorageHealthStatus>;
}

/// Storage backend health status.
#[derive(Debug, Clone)]
pub struct StorageHealthStatus {
    /// Backend type (e.g., "s3", "gcs", "azure", "file", "memory")
    pub backend_type: String,
    /// Whether the backend is healthy
    pub healthy: bool,
    /// Health check latency in milliseconds
    pub latency_ms: u64,
    /// Optional status message
    pub message: Option<String>,
}

impl StorageHealthStatus {
    /// Creates a healthy status.
    pub fn healthy(backend_type: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            backend_type: backend_type.into(),
            healthy: true,
            latency_ms,
            message: None,
        }
    }

    /// Creates an unhealthy status with a message.
    pub fn unhealthy(backend_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            healthy: false,
            latency_ms: 0,
            message: Some(message.into()),
        }
    }
}

/// Wrapper around any `Catalog` that implements `CatalogExt`.
#[derive(Debug)]
pub struct ExtendedCatalog<C: Catalog> {
    inner: C,
}

impl<C: Catalog> ExtendedCatalog<C> {
    /// Creates a new extended catalog wrapping the given catalog.
    pub fn new(inner: C) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<C: Catalog + Send + Sync> Catalog for ExtendedCatalog<C> {
    async fn list_namespaces(
        &self,
        parent: Option<&iceberg::NamespaceIdent>,
    ) -> Result<Vec<iceberg::NamespaceIdent>> {
        self.inner.list_namespaces(parent).await
    }

    async fn create_namespace(
        &self,
        namespace: &iceberg::NamespaceIdent,
        properties: std::collections::HashMap<String, String>,
    ) -> Result<iceberg::Namespace> {
        self.inner.create_namespace(namespace, properties).await
    }

    async fn get_namespace(
        &self,
        namespace: &iceberg::NamespaceIdent,
    ) -> Result<iceberg::Namespace> {
        self.inner.get_namespace(namespace).await
    }

    async fn namespace_exists(&self, namespace: &iceberg::NamespaceIdent) -> Result<bool> {
        self.inner.namespace_exists(namespace).await
    }

    async fn update_namespace(
        &self,
        namespace: &iceberg::NamespaceIdent,
        properties: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        self.inner.update_namespace(namespace, properties).await
    }

    async fn drop_namespace(&self, namespace: &iceberg::NamespaceIdent) -> Result<()> {
        self.inner.drop_namespace(namespace).await
    }

    async fn list_tables(&self, namespace: &iceberg::NamespaceIdent) -> Result<Vec<TableIdent>> {
        self.inner.list_tables(namespace).await
    }

    async fn create_table(
        &self,
        namespace: &iceberg::NamespaceIdent,
        creation: iceberg::TableCreation,
    ) -> Result<Table> {
        self.inner.create_table(namespace, creation).await
    }

    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        self.inner.load_table(table).await
    }

    async fn drop_table(&self, table: &TableIdent) -> Result<()> {
        self.inner.drop_table(table).await
    }

    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        self.inner.table_exists(table).await
    }

    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        self.inner.rename_table(src, dest).await
    }

    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table> {
        self.inner.register_table(table, metadata_location).await
    }

    async fn update_table(&self, commit: iceberg::TableCommit) -> Result<Table> {
        self.inner.update_table(commit).await
    }
}

#[async_trait]
impl<C: Catalog + Send + Sync> CatalogExt for ExtendedCatalog<C> {
    async fn commit_table(
        &self,
        table_ident: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        // Load current table
        let table = self.inner.load_table(table_ident).await?;

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
        let new_metadata_location = generate_new_metadata_location(current_metadata_location)?;

        // Write the new metadata file to storage
        // This is critical for persistence - without this, snapshots are lost!
        new_metadata
            .metadata
            .write_to(table.file_io(), &new_metadata_location)
            .await?;

        // Update the catalog registry with the new metadata location
        self.update_table_metadata_location(table_ident, new_metadata_location)
            .await
    }

    async fn update_table_metadata_location(
        &self,
        table_ident: &TableIdent,
        new_metadata_location: String,
    ) -> Result<Table> {
        // HIGH-004: Drop-and-register pattern for MemoryCatalog compatibility.
        //
        // ⚠️ WARNING: NOT PRODUCTION SAFE!
        //
        // This implementation uses drop-then-register because MemoryCatalog's
        // register_table returns an error if the table already exists, and there's
        // no update_table_location method in the Catalog trait.
        //
        // RISKS:
        // - If server crashes between drop and register, the table entry is lost
        // - The metadata file still exists in storage, allowing manual recovery
        // - For production, use SlateCatalog which has atomic update_table support
        //
        // The order MUST be drop-first because:
        // 1. MemoryCatalog.register_table fails if table exists
        // 2. We cannot use a temp name because metadata file path must match
        //
        // MITIGATION:
        // - Log extensively for crash recovery forensics
        // - SlateCatalog is recommended for all production deployments

        tracing::debug!(
            table = %table_ident,
            new_location = %new_metadata_location,
            "Updating table metadata location using drop-and-register pattern"
        );

        // Drop the existing table entry
        self.inner.drop_table(table_ident).await?;

        // Register with the new metadata location
        // If this fails, the table entry is lost but metadata file remains in storage
        match self
            .inner
            .register_table(table_ident, new_metadata_location.clone())
            .await
        {
            Ok(table) => Ok(table),
            Err(e) => {
                tracing::error!(
                    table = %table_ident,
                    metadata_location = %new_metadata_location,
                    error = %e,
                    "CRITICAL: Table dropped but re-registration failed. \
                     Table entry is lost. Metadata file still exists at the \
                     specified location and can be manually recovered."
                );
                Err(e)
            }
        }
    }

    async fn commit_tables_atomic(
        &self,
        table_changes: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        // Single-table commits are trivially atomic — delegate normally
        if table_changes.len() <= 1 {
            let mut results = Vec::with_capacity(table_changes.len());
            for (ident, reqs, updates) in table_changes {
                let table = self.commit_table(&ident, reqs, updates).await?;
                results.push(table);
            }
            return Ok(results);
        }

        // Multi-table atomic commits are NOT supported by the MemoryCatalog backend.
        // Rather than silently degrading to non-atomic sequential commits (which
        // could leave partial state on failure), we reject the request explicitly.
        // Use SlateCatalog with slatedb-storage feature for true atomic multi-table commits.
        Err(Error::new(
            ErrorKind::FeatureUnsupported,
            format!(
                "Atomic multi-table commit ({} tables) not supported by this catalog backend. \
                 Enable slatedb-storage feature and use a persistent storage backend for true atomic commits.",
                table_changes.len()
            ),
        ))
    }

    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        // ExtendedCatalog wraps MemoryCatalog which has no external storage.
        // We report it as healthy since there's nothing to check.
        Ok(StorageHealthStatus::healthy("memory", 0))
    }
}

/// Generates a new metadata location by incrementing the version number.
fn generate_new_metadata_location(current_location: &str) -> Result<String> {
    use std::path::Path;

    let path = Path::new(current_location);
    let parent = path.parent().map(|p| p.to_string_lossy().to_string());
    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "Invalid metadata location"))?;

    // Parse version from filename (e.g., "00001-uuid.metadata.json")
    let version = filename
        .split('-')
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    let new_version = version + 1;
    let new_uuid = uuid::Uuid::new_v4();
    let new_filename = format!("{:05}-{}.metadata.json", new_version, new_uuid);

    match parent {
        Some(p) if !p.is_empty() => Ok(format!("{}/{}", p, new_filename)),
        _ => Ok(new_filename),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_new_metadata_location() {
        let current = "s3://bucket/warehouse/db/table/metadata/00001-abc.metadata.json";
        let new_loc = generate_new_metadata_location(current).unwrap();

        assert!(new_loc.starts_with("s3://bucket/warehouse/db/table/metadata/00002-"));
        assert!(new_loc.ends_with(".metadata.json"));
    }

    #[test]
    fn test_generate_new_metadata_location_local() {
        let current = "/tmp/warehouse/metadata/00005-xyz.metadata.json";
        let new_loc = generate_new_metadata_location(current).unwrap();

        assert!(new_loc.starts_with("/tmp/warehouse/metadata/00006-"));
        assert!(new_loc.ends_with(".metadata.json"));
    }
}
