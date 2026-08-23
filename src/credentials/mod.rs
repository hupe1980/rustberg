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
//! - `NoopCredentialProvider` - Default provider that returns no credentials
//!
//! # What "vending" requires
//!
//! A provider must perform a real **token exchange** and hand back a credential
//! that is short-lived, scoped to the requested table's prefix, and no broader
//! than the caller's own policy allows. AWS does this with STS `AssumeRole`;
//! GCS with an OAuth2 access token.
//!
//! Passing a statically configured secret through to the client is *not*
//! vending, and is worse than declining to vend: an `adls.account-key` grants
//! full control of the entire storage account to any caller permitted to read
//! one table.
//!
//! # Two delegation forms, not one
//!
//! Vending is the cheap form: one credential, scoped to a table prefix, valid
//! for an hour, and Rustberg is out of the loop for its whole lifetime.
//! [`RequestSigner`] is the strong form: the engine holds nothing, every object
//! request is authorized against the live policy set and signed individually,
//! and a revocation takes effect on the next read. A client chooses between
//! them with `X-Iceberg-Access-Delegation`; a deployment chooses which it
//! offers.
//!
//! Azure therefore uses **user-delegation SAS** issued through Microsoft Entra —
//! short-lived, path-scoped, and bounded by the service principal's own RBAC —
//! never a shared account secret. Rustberg has no code path that can emit an
//! account key.

#[cfg(feature = "aws-credentials")]
pub mod aws;
#[cfg(feature = "azure-credentials")]
pub mod azure;
mod build;
#[cfg(feature = "gcp-credentials")]
mod gcs;
mod provider;
mod signer;

pub use build::{build_credential_provider, build_request_signer};
pub use provider::{
    NoopCredentialProvider, StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};
pub use signer::{
    HeaderMultiMap, NoopRequestSigner, RequestSigner, SignRequest, SignedRequest, SigningError,
};

#[cfg(feature = "remote-signing")]
pub use signer::AwsSigV4Signer;

#[cfg(feature = "aws-credentials")]
pub use aws::AwsStsCredentialProvider;

#[cfg(feature = "azure-credentials")]
pub use azure::{AzureConfig, AzureSasCredentialProvider};

#[cfg(feature = "gcp-credentials")]
pub use gcs::{GcsConfig, GcsCredentialProvider};
