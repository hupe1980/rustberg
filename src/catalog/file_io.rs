//! Construction of the Iceberg [`FileIO`] used to read and write table metadata.
//!
//! As of iceberg-rust 0.10 the core crate ships only the local-filesystem and
//! in-memory storage backends; cloud object stores live in
//! `iceberg-storage-opendal` behind per-service feature flags. This module is the
//! single place that decides which factory backs the catalog's `FileIO`, so the
//! rest of the codebase never has to care which backends were compiled in.
//!
//! Keeping the cloud backends optional is also what keeps the default build free
//! of native-tls/OpenSSL: only the services actually enabled are compiled.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use iceberg::io::{FileIO, FileIOBuilder};
use iceberg::{Error, ErrorKind, Result};
use iceberg_storage_opendal::OpenDalResolvingStorageFactory;

/// Storage properties every [`FileIO`] in this process is built with.
///
/// Empty until [`set_storage_properties`] is called, which the server does once
/// at startup from `[storage.properties]`.
static STORAGE_PROPERTIES: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Records the storage properties every catalog opened afterwards will use.
///
/// # Why this is set once, process-wide
///
/// These are deployment facts about *where the bytes live* — an S3 endpoint, a
/// region, whether to use path-style addressing — and every catalog this process
/// opens reads and writes through the same object store. Threading them through
/// `RedbCatalog::open`, `PostgresCatalog::connect`, the REST adapter and the
/// mount builder would put the same value in five signatures so that it could be
/// the same value in all five.
///
/// There was nothing here at all before: `build_file_io` was called with an empty
/// map from every one of those call sites, so a warehouse on `s3://` worked only
/// if OpenDAL happened to find ambient credentials, and a MinIO or Ceph endpoint
/// — the thing the repository's own `just minio` recipe and the `storage` Compose
/// profile set up — could not be reached at all. Three enabled Cargo features
/// pointed at a configuration surface that did not exist.
///
/// # What it cannot express
///
/// One set of properties, so two mounts on two different S3 accounts with
/// different endpoints are not expressible. That is stated rather than worked
/// around: keys are scheme-prefixed (`s3.`, `gcs.`, `adls.`), so *different
/// clouds* compose fine, and it is two accounts on one cloud that do not. A
/// deployment needing that runs a process per account, which is the same answer
/// mounts give to two topologies.
///
/// Returns `false` if properties were already set — the second caller loses, and
/// says so, rather than silently serving with the first caller's configuration.
pub fn set_storage_properties(props: HashMap<String, String>) -> bool {
    STORAGE_PROPERTIES.set(props).is_ok()
}

/// Builds a [`FileIO`] able to serve every storage scheme compiled into this binary.
///
/// The resolving factory picks a backend from the scheme of each path it is given
/// (`file://`, `s3://`, `gs://`, `abfss://`, …), so one `FileIO` can serve a
/// warehouse regardless of where it lives. Paths whose scheme was not compiled in
/// fail at first use with a message naming the missing feature.
///
/// Backend configuration comes from [`set_storage_properties`]; keys follow the
/// Iceberg property names (`s3.region`, `s3.endpoint`, `gcs.project-id`, …).
pub fn build_file_io() -> Result<FileIO> {
    Ok(FileIOBuilder::new(storage_factory())
        .with_props(STORAGE_PROPERTIES.get().cloned().unwrap_or_default())
        .build())
}

/// The storage factory backing every catalog in this binary.
///
/// Shared so that a catalog constructed by an upstream crate resolves the same
/// set of schemes as the embedded one — otherwise a warehouse that works on one
/// backend fails on the other for reasons the operator cannot see.
pub fn storage_factory() -> Arc<OpenDalResolvingStorageFactory> {
    Arc::new(OpenDalResolvingStorageFactory::new())
}

/// Returns an error naming the Cargo feature needed for `location`'s scheme, if
/// that scheme is known but was not compiled in.
///
/// Checked eagerly at startup so a misconfigured warehouse fails fast with an
/// actionable message, instead of failing on the first table write.
pub fn ensure_scheme_supported(location: &str) -> Result<()> {
    let scheme = match location.split_once("://") {
        // No scheme means a bare local path, which the always-present filesystem
        // backend handles.
        None => return Ok(()),
        Some((scheme, _)) => scheme,
    };

    let required_feature = match scheme {
        "file" | "memory" => return Ok(()),
        "s3" | "s3a" | "s3n" if cfg!(feature = "storage-s3") => return Ok(()),
        "gs" | "gcs" if cfg!(feature = "storage-gcs") => return Ok(()),
        "abfs" | "abfss" | "az" | "adls" if cfg!(feature = "storage-azure") => return Ok(()),
        "s3" | "s3a" | "s3n" => "storage-s3",
        "gs" | "gcs" => "storage-gcs",
        "abfs" | "abfss" | "az" | "adls" => "storage-azure",
        other => {
            return Err(Error::new(
                ErrorKind::FeatureUnsupported,
                format!(
                    "Unsupported storage scheme '{other}://' in location '{location}'. \
                     Supported schemes: file, memory, s3, gs, abfss."
                ),
            ));
        }
    };

    Err(Error::new(
        ErrorKind::FeatureUnsupported,
        format!(
            "Storage scheme '{scheme}://' requires the '{required_feature}' Cargo feature, \
             which was not enabled in this build."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_paths_need_no_feature() {
        assert!(ensure_scheme_supported("/var/lib/rustberg").is_ok());
        assert!(ensure_scheme_supported("file:///var/lib/rustberg").is_ok());
        assert!(ensure_scheme_supported("memory://warehouse").is_ok());
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let err = ensure_scheme_supported("hdfs://cluster/warehouse").unwrap_err();
        assert!(err.message().contains("Unsupported storage scheme"));
    }

    #[test]
    fn compiled_in_cloud_schemes_are_accepted() {
        // The default feature set enables every cloud backend.
        if cfg!(feature = "storage-s3") {
            assert!(ensure_scheme_supported("s3://bucket/warehouse").is_ok());
        }
        if cfg!(feature = "storage-gcs") {
            assert!(ensure_scheme_supported("gs://bucket/warehouse").is_ok());
        }
        if cfg!(feature = "storage-azure") {
            assert!(ensure_scheme_supported("abfss://fs@acct.dfs.core.windows.net/wh").is_ok());
        }
    }

    #[test]
    fn file_io_builds_for_local_warehouse() {
        assert!(build_file_io().is_ok());
    }
}
