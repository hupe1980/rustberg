//! Remote request signing: the delegation form where the engine holds no
//! credential at all.
//!
//! A vended credential is a *standing* grant: for its lifetime the holder reads
//! and writes every object under a table's prefix without Rustberg seeing any of
//! it, and revoking a policy does not revoke it. Signing inverts that — every
//! request is authorized against the policy set at that moment, so a revocation
//! takes effect on the next object read. The cost is a round trip per object,
//! which is why both forms exist and the client picks with
//! `X-Iceberg-Access-Delegation`.
//!
//! This module is the **signing primitive only**: given a request that has
//! already been authorized, produce the headers that make it valid to the
//! storage service. It knows nothing about tables, policy or locations —
//! [`catalog::v1::sign`] owns all of that. A signer that also decided what was
//! permitted would be a second authorization implementation.
//!
//! [`catalog::v1::sign`]: crate::catalog::v1::sign

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use thiserror::Error;

/// Multi-valued header map, in the shape the REST spec's `MultiValuedMap` takes.
pub type HeaderMultiMap = BTreeMap<String, Vec<String>>;

/// Why a request could not be signed.
#[derive(Debug, Error)]
pub enum SigningError {
    /// No signer is configured for this storage service.
    #[error("Remote signing is not configured for this storage location")]
    NotConfigured,

    /// The request cannot be expressed as something signable.
    #[error("Request cannot be signed: {0}")]
    Unsignable(String),

    /// The server's own credentials could not be resolved or used.
    #[error("Signing failed: {0}")]
    Failed(String),
}

/// One storage request a client wants signed.
///
/// Borrowed rather than owned: the caller has already parsed and validated all
/// of it, and copying a request body that may be kilobytes of delete keys to
/// hand it one layer down is waste.
#[derive(Debug, Clone, Copy)]
pub struct SignRequest<'a> {
    /// HTTP method, uppercase.
    pub method: &'a str,
    /// The full request URI, **exactly as the client sent it**.
    ///
    /// Not a re-serialised parse of it: a signature covers the bytes on the
    /// wire, and a URL library that normalises a path or reorders a query
    /// produces a signature for a request the client will not make.
    pub uri: &'a str,
    /// Region the client will send the request to.
    pub region: &'a str,
    /// Headers the client will send.
    pub headers: &'a HeaderMultiMap,
    /// Request body, when the client supplied one.
    ///
    /// Only `DeleteObjects` sends one, because its keys are in the body rather
    /// than the path and the signature has to cover them.
    pub body: Option<&'a str>,
}

/// The headers to add to the client's request, and the URI to send it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// URI the client should use.
    pub uri: String,
    /// **Only the headers signing added.**
    ///
    /// Not the client's own headers echoed back. The two reference clients
    /// merge this map differently — the Java client lets the original request
    /// win on any key collision, while PyIceberg *appends* every returned
    /// header to the request it already built — so returning the client's own
    /// headers is either a no-op or a duplicate of every one of them. Returning
    /// exactly the new ones is correct under both.
    pub headers: HeaderMultiMap,
}

/// Signs storage requests on a caller's behalf.
#[async_trait]
pub trait RequestSigner: Send + Sync + Debug {
    /// Signs `request`.
    ///
    /// # Errors
    ///
    /// [`SigningError`] when no signer serves this location, the request is not
    /// signable, or the server's own credentials could not be used.
    async fn sign(&self, request: SignRequest<'_>) -> Result<SignedRequest, SigningError>;

    /// Whether this signer serves the storage service `location` lives in.
    fn supports_location(&self, location: &str) -> bool;

    /// Storage locations this signer will sign for, as prefixes.
    ///
    /// The same rule vending follows: an empty list signs for nothing. A signer
    /// that signed for any location its own credentials could reach would be the
    /// confused deputy `location` exists to prevent, one layer down — and worse
    /// here than in vending, because a signature is minted per request and would
    /// never look like a misconfiguration.
    fn allowed_prefixes(&self) -> &[String];
}

/// A signer that signs nothing, and says so.
///
/// The default. A deployment that has not configured remote signing answers
/// `501` on the sign endpoint rather than `500`, and `/v1/config` does not
/// advertise the endpoint at all.
#[derive(Debug, Clone, Default)]
pub struct NoopRequestSigner;

#[async_trait]
impl RequestSigner for NoopRequestSigner {
    async fn sign(&self, _request: SignRequest<'_>) -> Result<SignedRequest, SigningError> {
        Err(SigningError::NotConfigured)
    }

    fn supports_location(&self, _location: &str) -> bool {
        false
    }

    fn allowed_prefixes(&self) -> &[String] {
        &[]
    }
}

// ============================================================================
// AWS SigV4
// ============================================================================

#[cfg(feature = "remote-signing")]
mod sigv4 {
    use super::{HeaderMultiMap, RequestSigner, SignRequest, SignedRequest, SigningError};
    use async_trait::async_trait;
    use aws_credential_types::provider::ProvideCredentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        sign as aws_sign,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    /// Headers excluded from the signature.
    ///
    /// Each is either rewritten in flight or added by the SDK after signing, so
    /// including it produces a signature for headers that will not arrive:
    ///
    /// - `range` is set per retry by the client after it has the signature.
    /// - `x-amz-date` is *replaced* by the one this signature is computed with.
    /// - `amz-sdk-invocation-id` and `amz-sdk-retry` change on every retry, and
    ///   the AWS SDKs deliberately leave them out of the canonical request for
    ///   exactly that reason.
    ///
    /// Getting this list wrong fails one way only — `SignatureDoesNotMatch` from
    /// S3, which names no field — so it is pinned by test rather than by hope.
    const UNSIGNED_HEADERS: &[&str] = &[
        "range",
        "x-amz-date",
        "amz-sdk-invocation-id",
        "amz-sdk-retry",
        // Added by this signer itself; signing over the client's own value would
        // sign a header the response then overwrites.
        "authorization",
        "x-amz-content-sha256",
        "x-amz-security-token",
    ];

    /// AWS SigV4 signer for S3 and S3-compatible storage.
    pub struct AwsSigV4Signer {
        credentials: aws_credential_types::provider::SharedCredentialsProvider,
        allowed_prefixes: Vec<String>,
    }

    impl std::fmt::Debug for AwsSigV4Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AwsSigV4Signer")
                .field("allowed_prefixes", &self.allowed_prefixes)
                .finish_non_exhaustive()
        }
    }

    impl AwsSigV4Signer {
        /// Builds a signer over the ambient AWS credential chain.
        ///
        /// The chain is the same one the STS provider uses, so a deployment that
        /// can vend can also sign, with no second set of secrets to configure.
        pub async fn new(region: impl Into<String>, allowed_prefixes: Vec<String>) -> Self {
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(region.into()))
                .load()
                .await;

            Self {
                credentials: config.credentials_provider().unwrap_or_else(|| {
                    aws_credential_types::provider::SharedCredentialsProvider::new(NoCredentials)
                }),
                allowed_prefixes,
            }
        }

        /// Builds a signer over an explicit credentials provider.
        pub fn with_credentials(
            credentials: aws_credential_types::provider::SharedCredentialsProvider,
            allowed_prefixes: Vec<String>,
        ) -> Self {
            Self {
                credentials,
                allowed_prefixes,
            }
        }
    }

    /// A provider that has nothing, so that a misconfigured deployment fails at
    /// the first signature with a message rather than at startup with a panic.
    #[derive(Debug)]
    struct NoCredentials;

    impl ProvideCredentials for NoCredentials {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            aws_credential_types::provider::future::ProvideCredentials::ready(Err(
                aws_credential_types::provider::error::CredentialsError::not_loaded(
                    "no AWS credentials are available to sign with",
                ),
            ))
        }
    }

    #[async_trait]
    impl RequestSigner for AwsSigV4Signer {
        async fn sign(&self, request: SignRequest<'_>) -> Result<SignedRequest, SigningError> {
            let credentials = self
                .credentials
                .provide_credentials()
                .await
                .map_err(|e| SigningError::Failed(format!("no usable AWS credentials: {e}")))?;
            let identity = credentials.into();

            let mut settings = SigningSettings::default();
            // `Single` matches what the AWS SDKs do for S3: the object key in the
            // path is already percent-encoded by the client, and encoding it a
            // second time would sign a different key than the one requested.
            settings.percent_encoding_mode = PercentEncodingMode::Single;
            settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

            let params = v4::SigningParams::builder()
                .identity(&identity)
                .region(request.region)
                .name("s3")
                .time(SystemTime::now())
                .settings(settings)
                .build()
                .map_err(|e| SigningError::Failed(format!("invalid signing parameters: {e}")))?
                .into();

            // A body is signed only when the client sent one — which it does
            // exactly for `DeleteObjects`, whose keys live in the body and
            // therefore have to be covered by the signature. Everything else is
            // an unsigned payload, because the catalog never sees the bytes an
            // engine is about to upload.
            let body = match request.body {
                Some(body) => SignableBody::Bytes(body.as_bytes()),
                None => SignableBody::UnsignedPayload,
            };

            let headers: Vec<(String, String)> = request
                .headers
                .iter()
                .filter(|(name, _)| !UNSIGNED_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
                .flat_map(|(name, values)| {
                    values
                        .iter()
                        .map(move |value| (name.clone(), value.clone()))
                })
                .collect();

            let signable = SignableRequest::new(
                request.method,
                request.uri,
                headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                body,
            )
            .map_err(|e| SigningError::Unsignable(format!("{e}")))?;

            let (instructions, _signature) = aws_sign(signable, &params)
                .map_err(|e| SigningError::Failed(format!("{e}")))?
                .into_parts();

            let mut signed: HeaderMultiMap = HeaderMultiMap::new();
            for (name, value) in instructions.headers() {
                signed.insert(name.to_string(), vec![value.to_string()]);
            }

            // Query-string signing is not used here — `SigningSettings` defaults
            // to header signing — so there are no parameters to fold into the
            // URI and it goes back exactly as it arrived.
            debug_assert!(instructions.params().is_empty());

            Ok(SignedRequest {
                uri: request.uri.to_string(),
                headers: signed,
            })
        }

        fn supports_location(&self, location: &str) -> bool {
            let scheme = location.split_once("://").map(|(s, _)| s);
            matches!(scheme, Some("s3" | "s3a" | "s3n"))
        }

        fn allowed_prefixes(&self) -> &[String] {
            &self.allowed_prefixes
        }
    }
}

#[cfg(feature = "remote-signing")]
pub use sigv4::AwsSigV4Signer;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_default_signer_signs_nothing() {
        let signer = NoopRequestSigner;
        assert!(!signer.supports_location("s3://bucket/wh"));
        assert!(signer.allowed_prefixes().is_empty());

        let headers = HeaderMultiMap::new();
        let err = signer
            .sign(SignRequest {
                method: "GET",
                uri: "https://bucket.s3.eu-west-1.amazonaws.com/wh/t/data.parquet",
                region: "eu-west-1",
                headers: &headers,
                body: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, SigningError::NotConfigured));
    }
}
