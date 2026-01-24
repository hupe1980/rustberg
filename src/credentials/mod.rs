//! Storage Credential Vending (ICE-002)
//!
//! This module implements storage credential vending as per the Iceberg REST Catalog
//! specification. When clients load a table, the catalog can provide temporary
//! credentials for accessing the table's data files in cloud storage (S3, GCS, Azure).
//!
//! # Architecture
//!
//! The credential vending system uses a provider pattern:
//! - `StorageCredentialProvider` - trait defining credential vending interface
//! - `AwsStsCredentialProvider` - AWS STS AssumeRole implementation
//! - `GcsCredentialProvider` - Google Cloud Storage OAuth2 implementation
//! - `AzureCredentialProvider` - Azure Blob/ADLS Gen2 SAS token implementation
//! - `NoopCredentialProvider` - Default provider that returns no credentials
//!
//! # Security Considerations
//!
//! - Credentials should be short-lived (default: 1 hour)
//! - Each tenant should have isolated IAM roles/permissions
//! - Credentials should be scoped to the minimum required permissions
//! - Session names should include audit information (tenant, table)

#[cfg(feature = "aws-credentials")]
pub mod aws;
mod azure;
#[cfg(feature = "gcp-credentials")]
mod gcs;
mod provider;

pub use provider::{
    NoopCredentialProvider, StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};

#[cfg(feature = "aws-credentials")]
pub use aws::AwsStsCredentialProvider;

pub use azure::{AzureConfig, AzureCredentialProvider};

#[cfg(feature = "gcp-credentials")]
pub use gcs::{GcsConfig, GcsCredentialProvider};
