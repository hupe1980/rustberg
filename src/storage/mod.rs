//! Persistent storage abstractions and implementations.
//!
//! This module provides storage backends for API keys and catalog metadata,
//! ensuring data survives server restarts and crashes.
//!
//! # Storage Backends
//!
//! | Backend | Feature | Horizontal Scaling | Use Case |
//! |---------|---------|-------------------|----------|
//! | Memory | (always) | ❌ | Testing only |
//! | SlateDB + file:// | `slatedb-storage` | ❌ | Single-node production |
//! | SlateDB + s3:// | `slatedb-storage` | ✅ | K8s HA with S3/GCS/MinIO |
//!
//! # Pure Rust Storage
//!
//! This implementation uses **SlateDB** for all persistent storage, avoiding
//! the C++ dependency of RocksDB. SlateDB is a 100% Rust LSM-tree implementation
//! that stores data on object storage (S3, GCS, Azure, MinIO, or local files).
//!
//! # K8s Horizontal Scaling
//!
//! For K8s deployments with multiple replicas, use SlateDB with shared object storage:
//!
//! ```yaml
//! env:
//! - name: SLATEDB_OBJECT_STORE
//!   value: "s3://my-bucket/rustberg-catalog"
//! ```
//!
//! # Single-Node Mode
//!
//! For single-node deployments without external object storage:
//!
//! ```yaml
//! env:
//! - name: SLATEDB_OBJECT_STORE
//!   value: "file:///data/rustberg"
//! ```

pub mod kv_store;
pub mod kv_api_key_store;

#[cfg(feature = "slatedb-storage")]
pub mod slatedb_store;

pub use kv_store::{KvError, KvResult, KvStore, KvStoreConfig, MemoryKvStore, WriteBatch, KeyValue};
pub use kv_api_key_store::{KvApiKeyStore, StorageError, StorageResult};

#[cfg(feature = "slatedb-storage")]
pub use slatedb_store::SlateDbStore;
