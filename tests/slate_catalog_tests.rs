//! Integration tests for SlateCatalog with FileIO.
//!
//! These tests verify the complete table lifecycle:
//! - Namespace operations (create, list, delete)
//! - Table operations (create, load, update, drop)
//! - Metadata persistence through FileIO
//! - Registry persistence through SlateDB

#![cfg(feature = "slatedb-storage")]

use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, NamespaceIdent, TableCreation, TableIdent};
use rustberg::catalog::SlateCatalog;
use slatedb::Db;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

/// Creates a test SlateCatalog with local filesystem storage.
async fn create_test_catalog() -> (SlateCatalog, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let warehouse_path = temp_dir.path().join("warehouse");
    let catalog_path = temp_dir.path().join("catalog");

    // Create directories
    std::fs::create_dir_all(&warehouse_path).expect("Failed to create warehouse dir");
    std::fs::create_dir_all(&catalog_path).expect("Failed to create catalog dir");

    // Create local filesystem object store for SlateDB
    let object_store = Arc::new(
        object_store::local::LocalFileSystem::new_with_prefix(&catalog_path)
            .expect("Failed to create LocalFileSystem"),
    );

    // Create SlateDB instance
    let db = Db::builder("db", object_store)
        .build()
        .await
        .expect("Failed to create SlateDB");

    // Create SlateCatalog with local warehouse
    let warehouse_location = format!("file://{}", warehouse_path.to_string_lossy());
    let catalog = SlateCatalog::new(Arc::new(db), warehouse_location)
        .await
        .expect("Failed to create SlateCatalog");

    (catalog, temp_dir)
}

/// Creates a simple schema for testing.
fn test_schema() -> Schema {
    Schema::builder()
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            NestedField::optional(2, "name", Type::Primitive(PrimitiveType::String)).into(),
            NestedField::optional(3, "created_at", Type::Primitive(PrimitiveType::Timestamp))
                .into(),
        ])
        .build()
        .expect("Failed to build schema")
}

// ============================================================================
// Namespace Tests
// ============================================================================

#[tokio::test]
async fn test_namespace_create_and_list() {
    let (catalog, _temp) = create_test_catalog().await;

    // Create namespace
    let ns = NamespaceIdent::new("test_db".to_string());
    let mut props = HashMap::new();
    props.insert("owner".to_string(), "admin".to_string());

    catalog
        .create_namespace(&ns, props.clone())
        .await
        .expect("Failed to create namespace");

    // List namespaces
    let namespaces = catalog
        .list_namespaces(None)
        .await
        .expect("Failed to list namespaces");
    assert_eq!(namespaces.len(), 1);
    assert_eq!(namespaces[0], ns);

    // Get namespace properties
    let namespace = catalog
        .get_namespace(&ns)
        .await
        .expect("Failed to get namespace");
    assert_eq!(
        namespace.properties().get("owner"),
        Some(&"admin".to_string())
    );
}

#[tokio::test]
async fn test_namespace_exists() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("check_db".to_string());

    // Should not exist initially
    assert!(!catalog
        .namespace_exists(&ns)
        .await
        .expect("Failed to check namespace"));

    // Create and verify exists
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");
    assert!(catalog
        .namespace_exists(&ns)
        .await
        .expect("Failed to check namespace"));
}

#[tokio::test]
async fn test_namespace_update_properties() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("update_db".to_string());
    let mut initial_props = HashMap::new();
    initial_props.insert("version".to_string(), "1".to_string());

    catalog
        .create_namespace(&ns, initial_props)
        .await
        .expect("Failed to create namespace");

    // Update properties
    let mut new_props = HashMap::new();
    new_props.insert("version".to_string(), "2".to_string());
    new_props.insert("description".to_string(), "Updated namespace".to_string());

    catalog
        .update_namespace(&ns, new_props)
        .await
        .expect("Failed to update namespace");

    // Verify properties updated
    let namespace = catalog
        .get_namespace(&ns)
        .await
        .expect("Failed to get namespace");
    assert_eq!(
        namespace.properties().get("version"),
        Some(&"2".to_string())
    );
    assert_eq!(
        namespace.properties().get("description"),
        Some(&"Updated namespace".to_string())
    );
}

#[tokio::test]
async fn test_namespace_drop() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("drop_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Drop namespace
    catalog
        .drop_namespace(&ns)
        .await
        .expect("Failed to drop namespace");

    // Verify gone
    assert!(!catalog
        .namespace_exists(&ns)
        .await
        .expect("Failed to check namespace"));
}

#[tokio::test]
async fn test_namespace_drop_not_empty_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("nonempty_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create a table in the namespace
    let creation = TableCreation::builder()
        .name("test_table".to_string())
        .schema(test_schema())
        .build();
    catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    // Drop should fail
    let result = catalog.drop_namespace(&ns).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_nested_namespace() {
    let (catalog, _temp) = create_test_catalog().await;

    // Create parent namespace first
    let parent_ns = NamespaceIdent::new("parent".to_string());
    catalog
        .create_namespace(&parent_ns, HashMap::new())
        .await
        .expect("Failed to create parent namespace");

    // Create nested namespace
    let child_ns =
        NamespaceIdent::from_vec(vec!["parent".to_string(), "child".to_string()]).unwrap();
    catalog
        .create_namespace(&child_ns, HashMap::new())
        .await
        .expect("Failed to create child namespace");

    // List top-level should return parent
    let top_level = catalog
        .list_namespaces(None)
        .await
        .expect("Failed to list namespaces");
    assert!(top_level.contains(&parent_ns));

    // List with parent should return child
    let children = catalog
        .list_namespaces(Some(&parent_ns))
        .await
        .expect("Failed to list child namespaces");
    assert!(children.contains(&child_ns));
}

// ============================================================================
// Table Creation Tests
// ============================================================================

#[tokio::test]
async fn test_table_create_and_load() {
    let (catalog, _temp) = create_test_catalog().await;

    // Create namespace first
    let ns = NamespaceIdent::new("tables_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create table
    let creation = TableCreation::builder()
        .name("users".to_string())
        .schema(test_schema())
        .build();

    let table = catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    // Verify table identifier
    assert_eq!(table.identifier().name(), "users");
    assert_eq!(table.identifier().namespace(), &ns);

    // Verify schema has 3 fields (using as_struct().fields() pattern)
    assert_eq!(
        table.metadata().current_schema().as_struct().fields().len(),
        3
    );

    // Load table again
    let table_ident = TableIdent::new(ns.clone(), "users".to_string());
    let loaded = catalog
        .load_table(&table_ident)
        .await
        .expect("Failed to load table");

    // Should have same metadata (using uuid() method)
    assert_eq!(loaded.metadata().uuid(), table.metadata().uuid());
}

#[tokio::test]
async fn test_table_create_with_location() {
    let (catalog, temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("loc_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create table with custom location
    let custom_location = format!(
        "file://{}/custom_table",
        temp.path().join("warehouse").to_string_lossy()
    );
    let creation = TableCreation::builder()
        .name("custom_table".to_string())
        .schema(test_schema())
        .location(custom_location.clone())
        .build();

    let table = catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    // Verify custom location was used
    assert_eq!(table.metadata().location(), &custom_location);
}

#[tokio::test]
async fn test_table_create_with_properties() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("props_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let mut props = HashMap::new();
    props.insert("write.format.default".to_string(), "parquet".to_string());
    props.insert("commit.retry.num-retries".to_string(), "5".to_string());

    let creation = TableCreation::builder()
        .name("props_table".to_string())
        .schema(test_schema())
        .properties(props)
        .build();

    let table = catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    // Verify properties were set
    assert_eq!(
        table.metadata().properties().get("write.format.default"),
        Some(&"parquet".to_string())
    );
}

#[tokio::test]
async fn test_table_create_in_nonexistent_namespace_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("nonexistent_db".to_string());
    let creation = TableCreation::builder()
        .name("orphan_table".to_string())
        .schema(test_schema())
        .build();

    let result = catalog.create_table(&ns, creation).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_table_create_duplicate_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("dup_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create first table
    let creation1 = TableCreation::builder()
        .name("dup_table".to_string())
        .schema(test_schema())
        .build();
    catalog
        .create_table(&ns, creation1)
        .await
        .expect("Failed to create first table");

    // Try to create duplicate - should fail
    let creation2 = TableCreation::builder()
        .name("dup_table".to_string())
        .schema(test_schema())
        .build();
    let result = catalog.create_table(&ns, creation2).await;
    assert!(result.is_err());
}

// ============================================================================
// Table Operations Tests
// ============================================================================

#[tokio::test]
async fn test_table_list() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("list_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create multiple tables
    for name in ["table1", "table2", "table3"] {
        let creation = TableCreation::builder()
            .name(name.to_string())
            .schema(test_schema())
            .build();
        catalog
            .create_table(&ns, creation)
            .await
            .expect("Failed to create table");
    }

    // List tables
    let tables = catalog
        .list_tables(&ns)
        .await
        .expect("Failed to list tables");
    assert_eq!(tables.len(), 3);

    let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"table1"));
    assert!(names.contains(&"table2"));
    assert!(names.contains(&"table3"));
}

#[tokio::test]
async fn test_table_exists() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("exists_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let table_ident = TableIdent::new(ns.clone(), "check_table".to_string());

    // Should not exist initially
    assert!(!catalog
        .table_exists(&table_ident)
        .await
        .expect("Failed to check table"));

    // Create and verify
    let creation = TableCreation::builder()
        .name("check_table".to_string())
        .schema(test_schema())
        .build();
    catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    assert!(catalog
        .table_exists(&table_ident)
        .await
        .expect("Failed to check table"));
}

#[tokio::test]
async fn test_table_drop() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("drop_table_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let creation = TableCreation::builder()
        .name("drop_me".to_string())
        .schema(test_schema())
        .build();
    catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    let table_ident = TableIdent::new(ns.clone(), "drop_me".to_string());

    // Drop table
    catalog
        .drop_table(&table_ident)
        .await
        .expect("Failed to drop table");

    // Verify gone
    assert!(!catalog
        .table_exists(&table_ident)
        .await
        .expect("Failed to check table"));
}

#[tokio::test]
async fn test_table_rename_same_namespace() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("rename_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let creation = TableCreation::builder()
        .name("old_name".to_string())
        .schema(test_schema())
        .build();
    let table = catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");
    let original_uuid = table.metadata().uuid();

    let src = TableIdent::new(ns.clone(), "old_name".to_string());
    let dest = TableIdent::new(ns.clone(), "new_name".to_string());

    // Rename
    catalog
        .rename_table(&src, &dest)
        .await
        .expect("Failed to rename table");

    // Verify old name gone, new name exists
    assert!(!catalog
        .table_exists(&src)
        .await
        .expect("Failed to check table"));
    assert!(catalog
        .table_exists(&dest)
        .await
        .expect("Failed to check table"));

    // Verify it's the same table (same UUID)
    let loaded = catalog
        .load_table(&dest)
        .await
        .expect("Failed to load table");
    assert_eq!(loaded.metadata().uuid(), original_uuid);
}

#[tokio::test]
async fn test_table_rename_cross_namespace() {
    let (catalog, _temp) = create_test_catalog().await;

    // Create two namespaces
    let ns1 = NamespaceIdent::new("source_db".to_string());
    let ns2 = NamespaceIdent::new("target_db".to_string());
    catalog
        .create_namespace(&ns1, HashMap::new())
        .await
        .expect("Failed to create namespace");
    catalog
        .create_namespace(&ns2, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let creation = TableCreation::builder()
        .name("moving_table".to_string())
        .schema(test_schema())
        .build();
    let table = catalog
        .create_table(&ns1, creation)
        .await
        .expect("Failed to create table");
    let original_uuid = table.metadata().uuid();

    let src = TableIdent::new(ns1.clone(), "moving_table".to_string());
    let dest = TableIdent::new(ns2.clone(), "moved_table".to_string());

    // Rename across namespaces
    catalog
        .rename_table(&src, &dest)
        .await
        .expect("Failed to rename table");

    // Verify
    assert!(!catalog
        .table_exists(&src)
        .await
        .expect("Failed to check table"));
    assert!(catalog
        .table_exists(&dest)
        .await
        .expect("Failed to check table"));

    let loaded = catalog
        .load_table(&dest)
        .await
        .expect("Failed to load table");
    assert_eq!(loaded.metadata().uuid(), original_uuid);
}

// Note: TableCommit tests are skipped because TableCommit::builder() is pub(crate) in iceberg 0.8.0
// The update_table functionality is tested through the HTTP API integration tests instead.

// ============================================================================
// Persistence Tests
// ============================================================================

#[tokio::test]
async fn test_metadata_persists_to_filesystem() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let warehouse_path = temp_dir.path().join("warehouse");
    let catalog_path = temp_dir.path().join("catalog");

    std::fs::create_dir_all(&warehouse_path).expect("Failed to create warehouse dir");
    std::fs::create_dir_all(&catalog_path).expect("Failed to create catalog dir");

    let warehouse_location = format!("file://{}", warehouse_path.to_string_lossy());
    let ns = NamespaceIdent::new("persist_db".to_string());
    let table_ident = TableIdent::new(ns.clone(), "persist_table".to_string());

    // First: Create catalog, namespace, and table
    {
        let object_store = Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(&catalog_path)
                .expect("Failed to create LocalFileSystem"),
        );

        let db = Db::builder("db", object_store)
            .build()
            .await
            .expect("Failed to create SlateDB");

        let catalog = SlateCatalog::new(Arc::new(db), warehouse_location.clone())
            .await
            .expect("Failed to create SlateCatalog");

        catalog
            .create_namespace(&ns, HashMap::new())
            .await
            .expect("Failed to create namespace");

        let creation = TableCreation::builder()
            .name("persist_table".to_string())
            .schema(test_schema())
            .build();
        catalog
            .create_table(&ns, creation)
            .await
            .expect("Failed to create table");
    }

    // Second: Reopen catalog and verify data persisted
    {
        let object_store = Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(&catalog_path)
                .expect("Failed to create LocalFileSystem"),
        );

        let db = Db::builder("db", object_store)
            .build()
            .await
            .expect("Failed to create SlateDB");

        let catalog = SlateCatalog::new(Arc::new(db), warehouse_location)
            .await
            .expect("Failed to create SlateCatalog");

        // Verify namespace persisted
        assert!(catalog
            .namespace_exists(&ns)
            .await
            .expect("Failed to check namespace"));

        // Verify table persisted with correct metadata
        let table = catalog
            .load_table(&table_ident)
            .await
            .expect("Failed to load table");
        assert_eq!(
            table.metadata().current_schema().as_struct().fields().len(),
            3
        );
    }
}

#[tokio::test]
async fn test_metadata_file_written_to_warehouse() {
    let (catalog, temp) = create_test_catalog().await;
    let _warehouse_path = temp.path().join("warehouse");

    let ns = NamespaceIdent::new("file_check_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let creation = TableCreation::builder()
        .name("file_check_table".to_string())
        .schema(test_schema())
        .build();
    let table = catalog
        .create_table(&ns, creation)
        .await
        .expect("Failed to create table");

    // Get the metadata location
    let metadata_location = table
        .metadata_location()
        .expect("Table should have metadata location");

    // Strip file:// prefix and verify file exists
    let file_path = metadata_location
        .strip_prefix("file://")
        .unwrap_or(metadata_location);
    assert!(
        std::path::Path::new(file_path).exists(),
        "Metadata file should exist at: {}",
        file_path
    );

    // Verify it's valid JSON
    let content = std::fs::read_to_string(file_path).expect("Failed to read metadata file");
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("Metadata should be valid JSON");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_load_nonexistent_table_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("error_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let table_ident = TableIdent::new(ns, "nonexistent".to_string());
    let result = catalog.load_table(&table_ident).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_nonexistent_namespace_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("does_not_exist".to_string());
    let result = catalog.get_namespace(&ns).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_drop_nonexistent_namespace_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("ghost_db".to_string());
    let result = catalog.drop_namespace(&ns).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_drop_nonexistent_table_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("ghost_table_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let table_ident = TableIdent::new(ns, "ghost_table".to_string());
    let result = catalog.drop_table(&table_ident).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_rename_nonexistent_source_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("rename_fail_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    let src = TableIdent::new(ns.clone(), "source".to_string());
    let dest = TableIdent::new(ns, "dest".to_string());

    let result = catalog.rename_table(&src, &dest).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rename_to_existing_fails() {
    let (catalog, _temp) = create_test_catalog().await;

    let ns = NamespaceIdent::new("rename_conflict_db".to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("Failed to create namespace");

    // Create both source and destination tables
    for name in ["source_table", "dest_table"] {
        let creation = TableCreation::builder()
            .name(name.to_string())
            .schema(test_schema())
            .build();
        catalog
            .create_table(&ns, creation)
            .await
            .expect("Failed to create table");
    }

    let src = TableIdent::new(ns.clone(), "source_table".to_string());
    let dest = TableIdent::new(ns, "dest_table".to_string());

    let result = catalog.rename_table(&src, &dest).await;
    assert!(result.is_err());
}
