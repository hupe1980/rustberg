//! Azure credential vending, via user-delegation SAS.
//!
//! # Why this is not an account key
//!
//! The obvious Azure implementation is to hand the client `adls.account-key`.
//! That is not vending, and it is worse than declining: an account key grants
//! full control of the *entire storage account* — every container, every blob,
//! delete included — to anyone permitted to read one table. It cannot be scoped,
//! and it does not expire.
//!
//! A **user-delegation SAS** is the real thing. It is signed with a key Azure
//! issues through Microsoft Entra, carries an explicit expiry, and is scoped to
//! a path prefix. The permissions it grants are the *intersection* of what the
//! SAS says and what the Entra principal is allowed by RBAC, so a SAS can only
//! ever narrow the server's own rights — never widen them. That is the same
//! downgrade-only property the S3 session policy provides.
//!
//! # How a token is produced
//!
//! ```text
//!   Entra client-credentials  ──▶  access token for storage.azure.com
//!             │
//!             ▼
//!   POST /?restype=service&comp=userdelegationkey  ──▶  delegation key
//!             │                                          (valid up to 7 days,
//!             │                                           cached here)
//!             ▼
//!   HMAC-SHA256(string-to-sign, key)  ──▶  SAS query string, one table prefix
//! ```
//!
//! The delegation key is cached because obtaining it costs two network round
//! trips and it is valid for days; the **SAS itself is never cached**, because
//! it is scoped to one table and one permission set and reusing it across
//! requests would hand a reader a writer's token.
//!
//! # Scope
//!
//! `sr=d` — directory scope — is what makes this table-shaped. A SAS with
//! `sr=b` covers one blob, and `sr=c` covers a whole container; a table is a
//! prefix holding many blobs, which is exactly what directory scope expresses.
//! It requires `sdd`, the directory depth beneath the container, which is
//! derived from the prefix rather than configured.

use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

use super::provider::{
    StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};

/// Storage service REST version these tokens are signed for.
///
/// Pinned rather than tracking the newest: the string-to-sign layout changes
/// between versions, and `sv` in the token must name the version the signature
/// was actually built for. Bumping it means changing the field list below in
/// the same commit.
const SIGNED_VERSION: &str = "2020-12-06";

/// Default lifetime of a vended SAS.
const DEFAULT_DURATION_SECONDS: i64 = 3600;

/// Refresh the delegation key this long before it expires.
///
/// A key that expires mid-request produces a SAS that Azure rejects, and the
/// client cannot tell that from a permissions problem. An hour of margin costs
/// one extra fetch per week.
const KEY_REFRESH_MARGIN: i64 = 3600;

/// How long a delegation key is requested for. Azure permits seven days; one
/// keeps the blast radius of a leaked key small while still amortising the
/// fetch across essentially every request.
const KEY_LIFETIME_HOURS: i64 = 24;

/// Configuration for Azure credential vending.
#[derive(Debug, Clone)]
pub struct AzureConfig {
    /// Storage account name, without the domain.
    pub account: String,
    /// Microsoft Entra tenant the service principal lives in.
    pub tenant_id: String,
    /// Service principal's application (client) ID.
    pub client_id: String,
    /// Service principal's secret.
    pub client_secret: String,
    /// Locations this provider may vend for. Empty allows any.
    pub allowed_prefixes: Vec<String>,
    /// Lifetime of a vended SAS, in seconds.
    pub duration_seconds: i64,
}

impl AzureConfig {
    /// A configuration for `account`, authenticating as the given principal.
    pub fn new(
        account: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            account: account.into(),
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            allowed_prefixes: Vec::new(),
            duration_seconds: DEFAULT_DURATION_SECONDS,
        }
    }

    /// Restricts vending to these prefixes.
    pub fn with_allowed_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.allowed_prefixes = prefixes;
        self
    }

    /// Sets the lifetime of a vended SAS.
    pub fn with_duration_seconds(mut self, seconds: i64) -> Self {
        self.duration_seconds = seconds;
        self
    }
}

/// A user delegation key, as Azure returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationKey {
    /// Object ID of the principal that requested it (`skoid`).
    pub object_id: String,
    /// Entra tenant (`sktid`).
    pub tenant_id: String,
    /// Start of validity (`skt`).
    pub start: String,
    /// End of validity (`ske`).
    pub expiry: String,
    /// Service the key is for; always `b` (`sks`).
    pub service: String,
    /// Storage version that issued it (`skv`).
    pub version: String,
    /// The key itself, base64. This signs the SAS and is never sent anywhere.
    pub value: String,
}

/// A delegation key and when it stops being usable.
#[derive(Debug)]
struct CachedKey {
    key: DelegationKey,
    expires_at: DateTime<Utc>,
}

/// Vends Azure user-delegation SAS tokens scoped to one table prefix.
pub struct AzureSasCredentialProvider {
    config: AzureConfig,
    http: reqwest::Client,
    cached_key: RwLock<Option<CachedKey>>,
}

impl std::fmt::Debug for AzureSasCredentialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureSasCredentialProvider")
            .field("account", &self.config.account)
            // Never the client secret or the delegation key.
            .finish_non_exhaustive()
    }
}

/// A location split into the parts a SAS needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdlsLocation {
    /// Filesystem, which is the blob container.
    pub container: String,
    /// Storage account.
    pub account: String,
    /// Path within the container, without leading or trailing slashes.
    pub path: String,
}

impl AzureSasCredentialProvider {
    /// Builds a provider for `config`.
    pub fn new(config: AzureConfig) -> Result<Self, StorageCredentialVendingError> {
        if config.account.trim().is_empty() {
            return Err(StorageCredentialVendingError::ConfigurationError(
                "Azure credential vending requires a storage account name".to_string(),
            ));
        }

        Ok(Self {
            config,
            http: super::provider::exchange_client(),
            cached_key: RwLock::new(None),
        })
    }

    /// Whether `location` falls under one of the configured prefixes.
    ///
    /// Segment-wise, like every other provider — see [`crate::location`].
    fn is_location_allowed(config: &AzureConfig, location: &str) -> bool {
        crate::location::is_vendable(&config.allowed_prefixes, location)
    }

    /// Splits `abfss://container@account.dfs.core.windows.net/path` apart.
    ///
    /// Returns `None` for anything that is not an ADLS Gen2 URL, so a
    /// misaddressed location is refused rather than signed for a container name
    /// parsed out of the wrong place.
    pub fn split_location(location: &str) -> Option<AdlsLocation> {
        let rest = location
            .strip_prefix("abfss://")
            .or_else(|| location.strip_prefix("abfs://"))?;

        let (container, remainder) = rest.split_once('@')?;
        if container.is_empty() {
            return None;
        }

        // `account.dfs.core.windows.net/path…`
        let (host, path) = match remainder.split_once('/') {
            Some((host, path)) => (host, path),
            None => (remainder, ""),
        };
        let account = host.split('.').next()?;
        if account.is_empty() {
            return None;
        }

        Some(AdlsLocation {
            container: container.to_string(),
            account: account.to_string(),
            path: path.trim_matches('/').to_string(),
        })
    }

    /// Directory depth beneath the container, as `sdd` requires.
    ///
    /// The container root is depth zero, so `warehouse/db/table` is three.
    fn directory_depth(path: &str) -> usize {
        path.split('/').filter(|s| !s.is_empty()).count()
    }

    /// The permission string for the requested access level.
    ///
    /// Read-only is `r` plus `l` — listing is how an engine discovers the files
    /// under a table prefix, and a scan that cannot list cannot start. Writing
    /// adds create, write and delete, which a compaction or expiry job needs.
    fn permissions(write_access: bool) -> &'static str {
        if write_access { "racwdl" } else { "rl" }
    }

    /// The canonical resource a SAS is signed against.
    ///
    /// Always `/blob/{account}/{container}/{path}`, even for Data Lake URLs:
    /// ADLS Gen2 and Blob Storage are the same service behind two endpoints, and
    /// the signature is defined over the blob form.
    fn canonicalized_resource(location: &AdlsLocation) -> String {
        if location.path.is_empty() {
            format!("/blob/{}/{}", location.account, location.container)
        } else {
            format!(
                "/blob/{}/{}/{}",
                location.account, location.container, location.path
            )
        }
    }

    /// The string a user-delegation SAS signature is computed over.
    ///
    /// The field order is fixed by the storage service for the signed version
    /// and every field is present even when empty — a missing newline shifts
    /// every later field and produces a signature Azure rejects with a message
    /// that names none of this. Unused fields are deliberately blank rather than
    /// omitted.
    pub fn string_to_sign(
        location: &AdlsLocation,
        key: &DelegationKey,
        permissions: &str,
        start: &str,
        expiry: &str,
    ) -> String {
        [
            permissions,                             // sp
            start,                                   // st
            expiry,                                  // se
            &Self::canonicalized_resource(location), // canonicalizedResource
            &key.object_id,                          // skoid
            &key.tenant_id,                          // sktid
            &key.start,                              // skt
            &key.expiry,                             // ske
            &key.service,                            // sks
            &key.version,                            // skv
            "",                                      // saoid
            "",                                      // suoid
            "",                                      // scid
            "",                                      // sip
            "https",                                 // spr
            SIGNED_VERSION,                          // sv
            "d",                                     // sr — directory scope
            "",                                      // snapshot time
            "",                                      // ses
            "",                                      // rscc
            "",                                      // rscd
            "",                                      // rsce
            "",                                      // rscl
            "",                                      // rsct
        ]
        .join("\n")
    }

    /// Signs `string_to_sign` with the delegation key.
    ///
    /// The key arrives base64-encoded and the signature is HMAC-SHA256 over the
    /// UTF-8 string, base64-encoded in turn.
    pub fn sign(
        string_to_sign: &str,
        key_value: &str,
    ) -> Result<String, StorageCredentialVendingError> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let key = base64::engine::general_purpose::STANDARD
            .decode(key_value)
            .map_err(|e| {
                StorageCredentialVendingError::ConfigurationError(format!(
                    "The user delegation key is not valid base64: {e}"
                ))
            })?;

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).map_err(|e| {
            StorageCredentialVendingError::ConfigurationError(format!(
                "The user delegation key is not a usable HMAC key: {e}"
            ))
        })?;
        mac.update(string_to_sign.as_bytes());

        Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
    }

    /// Builds the full SAS query string for one table prefix.
    pub fn build_sas(
        location: &AdlsLocation,
        key: &DelegationKey,
        write_access: bool,
        start: DateTime<Utc>,
        expiry: DateTime<Utc>,
    ) -> Result<String, StorageCredentialVendingError> {
        let permissions = Self::permissions(write_access);
        let start = format_time(start);
        let expiry = format_time(expiry);

        let signature = Self::sign(
            &Self::string_to_sign(location, key, permissions, &start, &expiry),
            &key.value,
        )?;

        // `sdd` is required by directory scope and is not part of the
        // string-to-sign; it tells the service how much of the canonical
        // resource is directory rather than blob name.
        let depth = Self::directory_depth(&location.path);

        Ok([
            format!("sp={permissions}"),
            format!("st={}", encode(&start)),
            format!("se={}", encode(&expiry)),
            format!("skoid={}", encode(&key.object_id)),
            format!("sktid={}", encode(&key.tenant_id)),
            format!("skt={}", encode(&key.start)),
            format!("ske={}", encode(&key.expiry)),
            format!("sks={}", encode(&key.service)),
            format!("skv={}", encode(&key.version)),
            "spr=https".to_string(),
            format!("sv={SIGNED_VERSION}"),
            "sr=d".to_string(),
            format!("sdd={depth}"),
            format!("sig={}", encode(&signature)),
        ]
        .join("&"))
    }

    /// The delegation key, fetching a new one when the cached one is near
    /// expiry.
    async fn delegation_key(&self) -> Result<DelegationKey, StorageCredentialVendingError> {
        if let Some(cached) = self.cached_key.read().await.as_ref()
            && cached.expires_at > Utc::now() + Duration::seconds(KEY_REFRESH_MARGIN)
        {
            return Ok(cached.key.clone());
        }

        let key = self.fetch_delegation_key().await?;
        let expires_at = DateTime::parse_from_rfc3339(&key.expiry)
            .map(|t| t.with_timezone(&Utc))
            // A key whose expiry cannot be parsed is treated as expiring now, so
            // it is fetched again next time rather than cached forever.
            .unwrap_or_else(|_| Utc::now());

        *self.cached_key.write().await = Some(CachedKey {
            key: key.clone(),
            expires_at,
        });

        Ok(key)
    }

    /// Obtains an Entra access token for the storage service.
    async fn entra_token(&self) -> Result<String, StorageCredentialVendingError> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let response = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("scope", "https://storage.azure.com/.default"),
            ])
            .send()
            .await
            .map_err(|e| {
                StorageCredentialVendingError::AzureError(format!(
                    "Could not reach Microsoft Entra: {e}"
                ))
            })?;

        if !response.status().is_success() {
            // The body carries Entra's own error code, which is what an
            // operator needs; it contains no secret.
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageCredentialVendingError::AzureError(format!(
                "Microsoft Entra refused the service principal ({status}): {body}"
            )));
        }

        let token: TokenResponse = response.json().await.map_err(|e| {
            StorageCredentialVendingError::AzureError(format!(
                "Malformed token response from Microsoft Entra: {e}"
            ))
        })?;

        Ok(token.access_token)
    }

    /// Asks the storage account for a user delegation key.
    async fn fetch_delegation_key(&self) -> Result<DelegationKey, StorageCredentialVendingError> {
        let token = self.entra_token().await?;

        let start = Utc::now() - Duration::minutes(5);
        let expiry = start + Duration::hours(KEY_LIFETIME_HOURS);
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
            format_time(start),
            format_time(expiry)
        );

        let url = format!(
            "https://{}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
            self.config.account
        );

        let response = self
            .http
            .post(&url)
            .bearer_auth(token)
            .header("x-ms-version", SIGNED_VERSION)
            .header("Content-Type", "application/xml")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                StorageCredentialVendingError::AzureError(format!(
                    "Could not reach the storage account: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageCredentialVendingError::AzureError(format!(
                "The storage account refused a user delegation key ({status}): {body}. \
                 The service principal needs the Storage Blob Data role on the account."
            )));
        }

        let xml = response.text().await.map_err(|e| {
            StorageCredentialVendingError::AzureError(format!(
                "Malformed delegation key response: {e}"
            ))
        })?;

        parse_delegation_key(&xml)
    }
}

/// Extracts a delegation key from the storage service's XML response.
///
/// Parsed by locating each element rather than with a full XML parser. The
/// response is a flat, fixed set of elements defined by the REST API, so a
/// parser would add a dependency to handle generality that cannot occur — and
/// every field is validated as present, so a shape change fails loudly rather
/// than producing a half-built key.
pub fn parse_delegation_key(xml: &str) -> Result<DelegationKey, StorageCredentialVendingError> {
    fn element(xml: &str, name: &str) -> Option<String> {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(xml[start..end].trim().to_string())
    }

    let missing = |field: &str| {
        StorageCredentialVendingError::AzureError(format!(
            "The user delegation key response is missing <{field}>"
        ))
    };

    Ok(DelegationKey {
        object_id: element(xml, "SignedOid").ok_or_else(|| missing("SignedOid"))?,
        tenant_id: element(xml, "SignedTid").ok_or_else(|| missing("SignedTid"))?,
        start: element(xml, "SignedStart").ok_or_else(|| missing("SignedStart"))?,
        expiry: element(xml, "SignedExpiry").ok_or_else(|| missing("SignedExpiry"))?,
        service: element(xml, "SignedService").ok_or_else(|| missing("SignedService"))?,
        version: element(xml, "SignedVersion").ok_or_else(|| missing("SignedVersion"))?,
        value: element(xml, "Value").ok_or_else(|| missing("Value"))?,
    })
}

/// Azure's accepted ISO-8601 form: whole seconds, UTC, `Z`.
///
/// Fractional seconds are accepted in a SAS but must match between the token
/// and the string-to-sign; emitting whole seconds everywhere removes a way for
/// the two to disagree.
fn format_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Percent-encodes a query parameter value.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[async_trait]
impl StorageCredentialProvider for AzureSasCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        if !Self::is_location_allowed(&self.config, &request.table_location) {
            return Err(StorageCredentialVendingError::PermissionDenied(format!(
                "Location '{}' is outside the prefixes this provider may vend for",
                request.table_location
            )));
        }

        let location = Self::split_location(&request.table_location).ok_or_else(|| {
            StorageCredentialVendingError::AzureError(format!(
                "Cannot scope credentials: '{}' is not an ADLS Gen2 location",
                request.table_location
            ))
        })?;

        // A SAS is signed for one account. Vending for a different one would
        // produce a token the service rejects, which reads to a client as a
        // permissions problem rather than a configuration one.
        if !location.account.eq_ignore_ascii_case(&self.config.account) {
            return Err(StorageCredentialVendingError::PermissionDenied(format!(
                "This provider vends for storage account '{}', not '{}'",
                self.config.account, location.account
            )));
        }

        let key = self.delegation_key().await?;

        let start = Utc::now() - Duration::minutes(5);
        let expiry = Utc::now() + Duration::seconds(self.config.duration_seconds);
        let sas = Self::build_sas(&location, &key, request.write_access, start, expiry)?;

        let prefix = if location.path.is_empty() {
            request.table_location.clone()
        } else {
            format!("{}/", request.table_location.trim_end_matches('/'))
        };

        Ok(vec![StorageCredential::adls(
            prefix,
            &location.account,
            sas,
        )])
    }

    fn supports_location(&self, location: &str) -> bool {
        location.starts_with("abfss://") || location.starts_with("abfs://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DelegationKey {
        DelegationKey {
            object_id: "11111111-1111-1111-1111-111111111111".to_string(),
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            start: "2026-01-01T00:00:00Z".to_string(),
            expiry: "2026-01-02T00:00:00Z".to_string(),
            service: "b".to_string(),
            version: SIGNED_VERSION.to_string(),
            // "secret-key-material" base64-encoded.
            value: "c2VjcmV0LWtleS1tYXRlcmlhbA==".to_string(),
        }
    }

    fn location() -> AdlsLocation {
        AzureSasCredentialProvider::split_location(
            "abfss://warehouse@acct.dfs.core.windows.net/wh/db/events",
        )
        .expect("a valid ADLS location")
    }

    // ── Location parsing ────────────────────────────────────────────────

    #[test]
    fn an_adls_url_splits_into_container_account_and_path() {
        let parsed = location();
        assert_eq!(parsed.container, "warehouse");
        assert_eq!(parsed.account, "acct");
        assert_eq!(parsed.path, "wh/db/events");
    }

    #[test]
    fn both_abfs_schemes_are_accepted() {
        assert!(
            AzureSasCredentialProvider::split_location("abfs://fs@acct.dfs.core.windows.net/p")
                .is_some()
        );
        assert!(
            AzureSasCredentialProvider::split_location("abfss://fs@acct.dfs.core.windows.net/p")
                .is_some()
        );
    }

    /// A misaddressed location must be refused, not parsed into a container
    /// name taken from the wrong part of the string.
    #[test]
    fn a_non_adls_location_is_refused() {
        for location in [
            "s3://bucket/wh",
            "gs://bucket/wh",
            "https://acct.dfs.core.windows.net/fs/p",
            "abfss://acct.dfs.core.windows.net/p", // no container
            "abfss://@acct.dfs.core.windows.net/p", // empty container
        ] {
            assert!(
                AzureSasCredentialProvider::split_location(location).is_none(),
                "should not have parsed: {location}"
            );
        }
    }

    #[test]
    fn a_container_root_has_an_empty_path() {
        let parsed =
            AzureSasCredentialProvider::split_location("abfss://fs@acct.dfs.core.windows.net")
                .expect("valid");
        assert_eq!(parsed.path, "");
    }

    // ── Scope ───────────────────────────────────────────────────────────

    /// `sdd` counts directories beneath the container, so it has to track the
    /// prefix rather than be configured.
    #[test]
    fn directory_depth_counts_path_segments() {
        assert_eq!(AzureSasCredentialProvider::directory_depth(""), 0);
        assert_eq!(AzureSasCredentialProvider::directory_depth("wh"), 1);
        assert_eq!(
            AzureSasCredentialProvider::directory_depth("wh/db/events"),
            3
        );
        assert_eq!(
            AzureSasCredentialProvider::directory_depth("/wh/db/events/"),
            3,
            "leading and trailing slashes are not directories"
        );
    }

    /// ADLS and Blob are one service; the signature is defined over the blob
    /// form regardless of which endpoint the URL used.
    #[test]
    fn the_canonical_resource_is_always_blob_shaped() {
        assert_eq!(
            AzureSasCredentialProvider::canonicalized_resource(&location()),
            "/blob/acct/warehouse/wh/db/events"
        );
    }

    #[test]
    fn a_container_root_canonicalizes_without_a_trailing_slash() {
        let root = AdlsLocation {
            container: "warehouse".to_string(),
            account: "acct".to_string(),
            path: String::new(),
        };
        assert_eq!(
            AzureSasCredentialProvider::canonicalized_resource(&root),
            "/blob/acct/warehouse"
        );
    }

    // ── Permissions ─────────────────────────────────────────────────────

    /// A read-only credential must not carry a single mutating permission.
    #[test]
    fn read_only_grants_no_writes() {
        let permissions = AzureSasCredentialProvider::permissions(false);
        for forbidden in ['w', 'd', 'c', 'a'] {
            assert!(
                !permissions.contains(forbidden),
                "read-only must not grant '{forbidden}': {permissions}"
            );
        }
    }

    /// Listing is how an engine finds the files under a table prefix; a scan
    /// that cannot list cannot start.
    #[test]
    fn read_only_can_still_list() {
        assert!(AzureSasCredentialProvider::permissions(false).contains('l'));
    }

    #[test]
    fn write_access_grants_what_a_commit_needs() {
        let permissions = AzureSasCredentialProvider::permissions(true);
        for expected in ['r', 'w', 'd', 'l'] {
            assert!(permissions.contains(expected), "{permissions}");
        }
    }

    // ── String-to-sign ──────────────────────────────────────────────────

    /// The field count is fixed by the storage version. A missing newline
    /// shifts every later field and produces a signature Azure rejects with a
    /// message that names none of this.
    #[test]
    fn the_string_to_sign_has_exactly_the_documented_fields() {
        let sts = AzureSasCredentialProvider::string_to_sign(
            &location(),
            &key(),
            "rl",
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
        );

        assert_eq!(
            sts.split('\n').count(),
            24,
            "the 2020-12-06 layout has 24 fields:\n{sts}"
        );
    }

    #[test]
    fn the_string_to_sign_places_every_field_in_order() {
        let sts = AzureSasCredentialProvider::string_to_sign(
            &location(),
            &key(),
            "rl",
            "2026-01-01T00:00:00Z",
            "2026-01-01T01:00:00Z",
        );
        let fields: Vec<&str> = sts.split('\n').collect();

        assert_eq!(fields[0], "rl", "sp");
        assert_eq!(fields[1], "2026-01-01T00:00:00Z", "st");
        assert_eq!(fields[2], "2026-01-01T01:00:00Z", "se");
        assert_eq!(fields[3], "/blob/acct/warehouse/wh/db/events");
        assert_eq!(fields[4], key().object_id, "skoid");
        assert_eq!(fields[5], key().tenant_id, "sktid");
        assert_eq!(fields[6], key().start, "skt");
        assert_eq!(fields[7], key().expiry, "ske");
        assert_eq!(fields[8], "b", "sks");
        assert_eq!(fields[9], SIGNED_VERSION, "skv");
        assert_eq!(fields[14], "https", "spr — HTTPS is required");
        assert_eq!(fields[15], SIGNED_VERSION, "sv");
        assert_eq!(fields[16], "d", "sr — directory scope");
    }

    /// The signed version and the `sv` in the token must be the same string, or
    /// the service verifies against a different field layout than was signed.
    #[test]
    fn the_signed_version_matches_the_token_version() {
        let sas = AzureSasCredentialProvider::build_sas(
            &location(),
            &key(),
            false,
            Utc::now(),
            Utc::now() + Duration::hours(1),
        )
        .expect("builds");

        assert!(sas.contains(&format!("sv={SIGNED_VERSION}")));

        let sts = AzureSasCredentialProvider::string_to_sign(&location(), &key(), "rl", "x", "y");
        assert!(sts.contains(SIGNED_VERSION));
    }

    // ── Signing ─────────────────────────────────────────────────────────

    /// Known answer, so a change to the signing primitive cannot pass unnoticed.
    ///
    /// A wrong signature is the failure mode Azure reports worst: the service
    /// answers `AuthenticationFailed` with no indication of *which* field was
    /// mis-signed, and it looks identical to a permissions problem. Pinning the
    /// value against an independent implementation is the only cheap way to
    /// know the primitive itself is right.
    ///
    /// ```text
    /// $ echo -n "hello" | openssl dgst -sha256 -mac HMAC \
    ///     -macopt key:secret-key-material -binary | base64
    /// AqDpOJqvDyGHF2E2IT/0eN0zJVEiAbnpAaZgHkIGNxU=
    /// ```
    #[test]
    fn the_signature_matches_an_independent_implementation() {
        // `key().value` is base64 for "secret-key-material".
        assert_eq!(
            AzureSasCredentialProvider::sign("hello", &key().value).unwrap(),
            "AqDpOJqvDyGHF2E2IT/0eN0zJVEiAbnpAaZgHkIGNxU="
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let a = AzureSasCredentialProvider::sign("hello", &key().value).unwrap();
        let b = AzureSasCredentialProvider::sign("hello", &key().value).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_string_signs_differently() {
        let a = AzureSasCredentialProvider::sign("hello", &key().value).unwrap();
        let b = AzureSasCredentialProvider::sign("hellp", &key().value).unwrap();
        assert_ne!(a, b);
    }

    /// HMAC-SHA256 with a known key and message, checked against the value
    /// produced by `openssl dgst -sha256 -mac HMAC -macopt key:secret-key-material`.
    #[test]
    fn the_signature_is_hmac_sha256_base64() {
        let signature = AzureSasCredentialProvider::sign("hello", &key().value).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&signature)
            .expect("base64");
        assert_eq!(decoded.len(), 32, "SHA-256 produces 32 bytes");
    }

    #[test]
    fn a_malformed_key_is_reported_rather_than_panicking() {
        assert!(AzureSasCredentialProvider::sign("hello", "not base64!!!").is_err());
    }

    // ── Token assembly ──────────────────────────────────────────────────

    #[test]
    fn a_sas_carries_every_required_parameter() {
        let sas = AzureSasCredentialProvider::build_sas(
            &location(),
            &key(),
            false,
            Utc::now(),
            Utc::now() + Duration::hours(1),
        )
        .expect("builds");

        for required in [
            "sp=",
            "st=",
            "se=",
            "skoid=",
            "sktid=",
            "skt=",
            "ske=",
            "sks=",
            "skv=",
            "spr=https",
            "sv=",
            "sr=d",
            "sdd=",
            "sig=",
        ] {
            assert!(sas.contains(required), "missing {required} in: {sas}");
        }
    }

    /// A token scoped to a table must not be usable for its siblings, which is
    /// the whole point of directory scope.
    #[test]
    fn two_tables_get_different_signatures() {
        let a = AzureSasCredentialProvider::split_location(
            "abfss://fs@acct.dfs.core.windows.net/wh/db/a",
        )
        .unwrap();
        let b = AzureSasCredentialProvider::split_location(
            "abfss://fs@acct.dfs.core.windows.net/wh/db/b",
        )
        .unwrap();

        let start = Utc::now();
        let expiry = start + Duration::hours(1);

        let sas_a =
            AzureSasCredentialProvider::build_sas(&a, &key(), false, start, expiry).unwrap();
        let sas_b =
            AzureSasCredentialProvider::build_sas(&b, &key(), false, start, expiry).unwrap();

        assert_ne!(sas_a, sas_b, "a SAS must be scoped to its own prefix");
    }

    #[test]
    fn read_and_write_tokens_differ() {
        let start = Utc::now();
        let expiry = start + Duration::hours(1);

        let read = AzureSasCredentialProvider::build_sas(&location(), &key(), false, start, expiry)
            .unwrap();
        let write = AzureSasCredentialProvider::build_sas(&location(), &key(), true, start, expiry)
            .unwrap();

        assert!(read.contains("sp=rl"));
        assert!(write.contains("sp=racwdl"));
        assert_ne!(read, write);
    }

    #[test]
    fn the_secret_never_appears_in_the_token() {
        let sas = AzureSasCredentialProvider::build_sas(
            &location(),
            &key(),
            false,
            Utc::now(),
            Utc::now() + Duration::hours(1),
        )
        .unwrap();

        assert!(
            !sas.contains(&key().value),
            "the delegation key signs the token and is never part of it"
        );
        assert!(!sas.contains("secret-key-material"));
    }

    // ── Delegation key parsing ──────────────────────────────────────────

    const KEY_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
        <UserDelegationKey>
          <SignedOid>11111111-1111-1111-1111-111111111111</SignedOid>
          <SignedTid>22222222-2222-2222-2222-222222222222</SignedTid>
          <SignedStart>2026-01-01T00:00:00Z</SignedStart>
          <SignedExpiry>2026-01-02T00:00:00Z</SignedExpiry>
          <SignedService>b</SignedService>
          <SignedVersion>2020-12-06</SignedVersion>
          <Value>c2VjcmV0LWtleS1tYXRlcmlhbA==</Value>
        </UserDelegationKey>"#;

    #[test]
    fn a_delegation_key_response_parses() {
        let parsed = parse_delegation_key(KEY_XML).expect("parses");
        assert_eq!(parsed, key());
    }

    /// A response missing a field must fail loudly rather than produce a
    /// half-built key that signs tokens the service rejects.
    #[test]
    fn a_missing_field_is_an_error() {
        let truncated = KEY_XML.replace("<Value>c2VjcmV0LWtleS1tYXRlcmlhbA==</Value>", "");
        let err = parse_delegation_key(&truncated).unwrap_err();
        assert!(err.to_string().contains("Value"), "{err}");
    }

    // ── Prefix confinement ──────────────────────────────────────────────

    #[test]
    fn a_sibling_prefix_is_not_allowed() {
        let config = AzureConfig::new("acct", "t", "c", "s")
            .with_allowed_prefixes(vec!["abfss://fs@acct.dfs.core.windows.net/wh".to_string()]);

        assert!(AzureSasCredentialProvider::is_location_allowed(
            &config,
            "abfss://fs@acct.dfs.core.windows.net/wh/db/t"
        ));
        assert!(!AzureSasCredentialProvider::is_location_allowed(
            &config,
            "abfss://fs@acct.dfs.core.windows.net/wh-evil/db/t"
        ));
    }

    #[test]
    fn a_provider_needs_an_account() {
        assert!(AzureSasCredentialProvider::new(AzureConfig::new("", "t", "c", "s")).is_err());
    }

    #[tokio::test]
    async fn it_supports_only_adls_locations() {
        let provider =
            AzureSasCredentialProvider::new(AzureConfig::new("acct", "t", "c", "s")).unwrap();

        assert!(provider.supports_location("abfss://fs@acct.dfs.core.windows.net/p"));
        assert!(!provider.supports_location("s3://bucket/wh"));
        assert!(!provider.supports_location("gs://bucket/wh"));
    }
}
