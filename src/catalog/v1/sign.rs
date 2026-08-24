//! `POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/sign`
//!
//! Remote signing: the engine holds no storage credential, and every object
//! request it wants to make is authorized here and signed individually.
//!
//! # What has to be true before a signature is minted
//!
//! 1. The caller may `Read` the table (and `Update` it, for anything mutating).
//! 2. The table carries no row filter or column mask — a signature is
//!    file-shaped and cannot express a predicate.
//! 3. The request is one of the operations this endpoint knows how to
//!    authorize.
//! 4. Every location the request touches is inside the table's own location.
//!
//! The last two are what this module is mostly about, because neither is
//! reliably in the path.
//!
//! # The operation is not the method
//!
//! S3 dispatches on a *sub-resource* in the query string, so one `PUT` to one
//! key is `PutObject`, `PutObjectAcl`, `PutObjectTagging` or `RestoreObject`
//! depending on a parameter a location check never reads. Only the first writes
//! data: `PUT …/f.parquet?acl` with `x-amz-acl: public-read` is inside the table
//! location, passes every containment check, and publishes the object to the
//! internet.
//!
//! So the signed set is an **allowlist** — object access, multipart upload,
//! `DeleteObjects`, `ListObjectsV2` — and the access-granting headers
//! (`x-amz-acl`, `x-amz-grant-*`) go with the refused sub-resources. A signature
//! permits *this* request, never an unbounded set of later ones.
//!
//! # The locations are not always in the path
//!
//! `DeleteObjects` puts its keys in an XML body and `ListObjectsV2` its prefix
//! in the query string; both address the *bucket*, so reading only the path
//! would authorize them against all of it.
//!
//! `CopyObject` puts its *source* in a header. `PUT …/mytable/data/x.parquet`
//! with `x-amz-copy-source: /other-bucket/secrets/private.parquet` has a
//! destination inside the caller's own table, and asks S3 to fill it with an
//! object the caller may not read, fetched with this server's storage role. The
//! caller then reads its own table back, within policy. Signing only the
//! destination therefore buys a read of everything that role reaches, so the
//! source is confined exactly like the destination.
//!
//! Anything this module cannot resolve to a location, or to an operation it
//! recognises, is refused: unrecognised is not permitted.

use std::collections::BTreeMap;

use axum::{
    extract::State,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::extract::{Json, TablePath};
use super::guard::{self, Target};
use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, RequestFacts};
use crate::credentials::{HeaderMultiMap, SignRequest, SigningError};
use crate::error::{AppError, Result};

/// Largest `DeleteObjects` body accepted, in bytes.
///
/// S3 caps one call at a thousand keys, which is comfortably inside this.
const MAX_BODY: usize = 64 * 1024;

/// `RemoteSignRequest`.
#[derive(Debug, Deserialize)]
pub struct RemoteSignRequest {
    /// Region the client will send the request to.
    #[serde(default)]
    pub region: String,
    /// Full request URI.
    pub uri: String,
    /// HTTP method.
    pub method: String,
    /// Headers the client will send.
    #[serde(default)]
    pub headers: HeaderMultiMap,
    /// Signer properties, echoed from `remote-signing-config`. Unused here.
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    /// Body, sent only for `DeleteObjects`.
    #[serde(default)]
    pub body: Option<String>,
    /// Storage provider. Defaults to `s3` for backwards compatibility.
    #[serde(default)]
    pub provider: Option<String>,
}

/// `RemoteSignResult`.
#[derive(Debug, Serialize)]
pub struct RemoteSignResponse {
    /// URI the client should send the request to.
    pub uri: String,
    /// Headers to add to the request.
    pub headers: HeaderMultiMap,
}

/// What a signed request does, in the vocabulary policy speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignedOp {
    /// Reads an object, or lists a prefix.
    Read,
    /// Writes or deletes an object.
    Write,
}

/// The locations a request touches, and how they must be contained.
#[derive(Debug, PartialEq, Eq)]
struct Addressed {
    /// The request URI as this endpoint read it, and the only one it will sign.
    ///
    /// # Why the caller's own spelling is not signed back
    ///
    /// Every location below is derived from a URI parsed with a URL parser, and
    /// a URL parser *resolves* the path: `.` and `..` segments are removed, and
    /// under a special scheme a backslash is a path separator. So
    /// `…/other/../wh/db/t/x` and `…/other\..\..\wh\db\t\x` both read here as
    /// `…/wh/db/t/x` — squarely inside the table — while S3 takes the raw path
    /// literally and would act on a key under `other/`. Containment would have
    /// passed on a string the request never used, which is the same hazard as a
    /// query parameter sent twice, one layer down.
    ///
    /// Refusing every URI a parser would rewrite is the wrong shape of answer:
    /// it turns an ordinary key carrying an unusual byte into a `400` for no
    /// safety gained. What has to hold is that the string checked, the string
    /// signed and the string handed back are **one string** — so a client that
    /// sends S3 anything else is refused by S3 itself, and containment is
    /// enforced rather than blacklisted.
    uri: String,
    /// `s3://bucket/key` for each object, or the single prefix of a listing.
    locations: Vec<String>,
    /// True when `locations` are list prefixes rather than object keys.
    ///
    /// S3 matches a list prefix as a raw string, so `…/t` also returns the keys
    /// of `…/t2`. A prefix therefore has to sit strictly *inside* the table
    /// location, where an object key may equal it.
    prefixes: bool,
}

/// How a bucket is read out of a request URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlStyle {
    /// AWS hostnames are recognised; anything else is path style.
    Auto,
    /// `host/bucket/key`.
    Path,
    /// `bucket.host/key`.
    VirtualHost,
}

impl UrlStyle {
    /// Parses the configured value. Anything unrecognised is a startup failure
    /// rather than a silent fallback.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] naming the accepted values.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "path" | "path-style" => Ok(Self::Path),
            "virtual-host" | "virtual" | "vhost" => Ok(Self::VirtualHost),
            other => Err(AppError::Internal(format!(
                "Unknown credentials.signing.url_style '{other}'. Valid values are 'auto', \
                 'path' and 'virtual-host'."
            ))),
        }
    }
}

/// Everything the endpoint needs to know about how storage is addressed.
#[derive(Debug, Clone, Default)]
pub struct SigningEndpointConfig {
    /// Whether the endpoint is served at all.
    pub enabled: bool,
    /// How to read a bucket out of a URI.
    pub url_style: Option<UrlStyle>,
    /// Host of a custom S3 endpoint, when one is used.
    pub endpoint_host: Option<String>,
    /// Region used when a client sends none.
    pub fallback_region: Option<String>,
}

/// What `LoadTableResult` tells a client about remote signing.
///
/// Present only when the client asked for `remote-signing` and this deployment
/// offers it — the spec makes signing something a client opts into, and a
/// response that switched it on unasked would send every object read through a
/// server the client had not planned to depend on.
///
/// Three keys go into `config` rather than one because clients disagree about
/// which activates signing: Java reads `s3.remote-signing-enabled`, PyIceberg
/// reads `s3.signer`, and both resolve `s3.signer.endpoint` against the catalog
/// URI. `remote-signing-config` alongside them is the current spelling, which
/// newer clients prefer and older ones ignore.
pub fn signing_config_for(namespace: &iceberg::NamespaceIdent, table: &str) -> RemoteSigningConfig {
    let path = format!(
        "v1/namespaces/{}/tables/{}/sign",
        encode_path_segment(&namespace.join(&crate::names::PART_SEPARATOR.to_string())),
        encode_path_segment(table)
    );

    RemoteSigningConfig {
        endpoint: path,
        properties: BTreeMap::new(),
        headers: HeaderMultiMap::new(),
    }
}

/// `RemoteSigningConfig`, plus the endpoint the deprecated properties name.
#[derive(Debug, Clone, Serialize)]
pub struct RemoteSigningConfig {
    /// Relative path of this table's sign endpoint.
    #[serde(skip)]
    pub endpoint: String,
    /// Static properties the client must echo in every sign request.
    pub properties: BTreeMap<String, String>,
    /// Static headers the client must send to the sign endpoint.
    pub headers: HeaderMultiMap,
}

/// Percent-encodes everything a path segment may not carry literally.
fn encode_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `POST …/tables/{table}/sign`
///
/// # Errors
///
/// - `501` when this deployment does not offer remote signing.
/// - `404`/`403` per [`guard`], for a table the caller cannot see or use.
/// - `400` for a URI, method or body this endpoint cannot resolve to a location.
/// - `403` when the request reaches outside the table, or the table is under
///   row or column policy.
/// - `503` when the signature itself could not be produced.
pub async fn sign_request(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    table: TablePath,
    Json(payload): Json<RemoteSignRequest>,
) -> Result<Response> {
    if !state.signing.enabled {
        return Err(AppError::NotSupported(
            "This catalog does not offer remote signing. Request `vended-credentials` \
             instead, or configure [credentials.signing]."
                .to_string(),
        ));
    }

    // `s3` is the only provider the spec defines a signature for, and an absent
    // value means `s3` for backwards compatibility.
    if let Some(provider) = payload.provider.as_deref()
        && !provider.eq_ignore_ascii_case("s3")
    {
        return Err(AppError::BadRequest(format!(
            "Remote signing is implemented for the 's3' provider only, not '{provider}'."
        )));
    }

    if payload.body.as_ref().is_some_and(|b| b.len() > MAX_BODY) {
        return Err(AppError::BadRequest(format!(
            "Request body to sign is larger than {MAX_BODY} bytes."
        )));
    }

    let method = payload.method.trim().to_ascii_uppercase();
    let (namespace, name) = (table.namespace(), table.name());

    let authorized = guard::authorize(
        &state,
        &principal,
        &request,
        namespace,
        Target::Table(name),
        Action::Read,
    )
    .await?;

    // Before every refusal below, so each of them records *what* was refused.
    // Only parsing of a body the caller already sent, and after the
    // authorization above, so nothing is done for a caller not permitted here.
    let (addressed, operation) = resolve(&method, &payload, &state.signing)?;

    // Same rule as vending: a signature says "this object may be read", which is
    // every row and every column in it.
    if !authorized.obligations.is_empty() {
        record_signature(&state, &authorized, operation, &addressed, false)?;
        return Err(AppError::Forbidden(format!(
            "Policy attaches restrictions to this table ({}), and a signed request cannot \
             express them. Signing is withheld rather than granting access wider than \
             policy allows.",
            authorized.obligations.describe()
        )));
    }

    // A signature that writes grants write access to the warehouse, so the
    // decision behind it is recorded like any other mutation — see
    // `Authorized::also_permits`. Asked speculatively, a signed `DeleteObjects`
    // over every data file in a table and a signed `GET` of one of them would
    // leave the same two records.
    if operation == SignedOp::Write && !authorized.also_permits(&state, Action::Update).await? {
        record_signature(&state, &authorized, operation, &addressed, false)?;
        return Err(AppError::Forbidden(format!(
            "Not permitted to write table '{}.{}'",
            namespace.join("."),
            name
        )));
    }

    let table_location = state
        .catalog
        .load_table(&iceberg::TableIdent::new(
            namespace.clone(),
            name.to_string(),
        ))
        .await?
        .metadata()
        .location()
        .to_string();

    // Rustberg signs only for storage it manages. A federated mount's warehouse
    // is somebody else's, and a signature for it would be this server lending
    // authority over data it does not own.
    //
    // Two questions, because one of them is not enough. The signer's prefixes say
    // what this deployment configured; the namespace's own warehouse says which
    // of those this *table* may live in. Without the second, a mount reporting a
    // table whose location points into this server's warehouse would be signed
    // for — the mount's own catalog chose that string, and §7 treats what a mount
    // returns as untrusted input. See `AppState::manages_storage_for`.
    if !state.manages_storage_for(namespace, &table_location).await
        || !crate::location::is_vendable(state.request_signer.allowed_prefixes(), &table_location)
    {
        record_signature(&state, &authorized, operation, &addressed, false)?;
        return Err(AppError::Forbidden(
            "This catalog does not sign requests for the storage this table lives in.".to_string(),
        ));
    }

    if let Err(refused) = confine(&addressed, &table_location) {
        // A request that reached outside its table is the most interesting thing
        // this endpoint sees; without a record the attempt is visible only in
        // whatever the client chose to report.
        record_signature(&state, &authorized, operation, &addressed, false)?;
        return Err(refused);
    }

    // Signed *before* the record that says a signature was issued, which is the
    // opposite of the order every mutation here uses, for a reason that only
    // applies to this one.
    //
    // A catalog mutation is durable the moment it happens, so it has to be
    // recorded first or a failed record leaves an unrecorded change. A signature
    // is not: it is a string in this process, and a caller that never receives
    // it received nothing. So minting it first costs no grant — the failure
    // paths below and the fail-closed record after both return an error and drop
    // it on the floor — and it buys a trail that does not claim a signature the
    // signer then failed to produce. §9's rule is that the trail never describes
    // something that did not happen; recording first broke that in the quiet
    // direction, by over-reporting a grant.
    let signed = state
        .request_signer
        .sign(SignRequest {
            method: &method,
            // Not `payload.uri`: the containment check above ran on the parsed
            // URI, so the signature has to be over that same spelling or the
            // check was performed on a string the request never used. See
            // `Addressed::uri`.
            uri: &addressed.uri,
            region: pick_region(&payload.region, &state.signing),
            headers: &payload.headers,
            body: payload.body.as_deref(),
        })
        .await
        .map_err(|e| match e {
            SigningError::NotConfigured => AppError::NotSupported(
                "This catalog does not offer remote signing for this storage service.".to_string(),
            ),
            SigningError::Unsignable(reason) => AppError::BadRequest(reason),
            SigningError::Failed(reason) => {
                tracing::warn!(error = %reason, "Failed to sign a storage request");
                AppError::ServiceUnavailable(
                    "The request could not be signed. Retrying is reasonable.".to_string(),
                )
            }
        })?;

    // Fail-closed for a write, and the signature is discarded rather than
    // returned if it cannot be recorded — so the grant does not outlive the
    // record that was supposed to describe it.
    record_signature(&state, &authorized, operation, &addressed, true)?;

    let mut response = (
        StatusCode::OK,
        axum::Json(RemoteSignResponse {
            uri: signed.uri,
            headers: signed.headers,
        }),
    )
        .into_response();

    // Clients cache a signature keyed on the request only when this says they
    // may. A read is stable enough to reuse; a write must be signed each time.
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(match operation {
            SignedOp::Read => "private",
            SignedOp::Write => "no-cache",
        }),
    );

    Ok(response)
}

/// The region to sign for: the client's, or the configured fallback.
fn pick_region<'a>(requested: &'a str, config: &'a SigningEndpointConfig) -> &'a str {
    if !requested.trim().is_empty() {
        return requested;
    }
    config.fallback_region.as_deref().unwrap_or("us-east-1")
}

// ============================================================================
// Resolving what a request addresses
// ============================================================================

/// S3 sub-resources this endpoint knows how to authorize.
///
/// `delete` and `uploads` are flags; `uploadId` carries the id of a multipart
/// upload already in progress. Each names an operation whose effect is confined
/// to the object or objects the containment check below resolves.
const ALLOWED_SUBRESOURCES: &[&str] = &["delete", "uploads", "uploadId"];

/// S3 sub-resources this endpoint refuses.
///
/// Every one of them turns a request on an object into a request *about* an
/// object: who may read it (`acl`, `policy`, `ownershipControls`), how long it
/// survives (`retention`, `legal-hold`, `object-lock`, `lifecycle`), what it
/// costs (`requestPayment`, `restore`, `intelligent-tiering`), or what leaves
/// the bucket (`replication`, `notification`, `logging`, `inventory`).
///
/// Listed explicitly rather than derived by refusing every unknown parameter:
/// clients and SDKs add ordinary query parameters of their own — `x-id`,
/// response-header overrides, list continuation tokens — and refusing those
/// would break working deployments for no safety gained. What matters is the
/// set S3 itself dispatches on, and that set is closed and documented.
const REFUSED_SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "attributes",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "location",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "restore",
    "retention",
    "select",
    "tagging",
    "torrent",
    "versioning",
    "versions",
    "website",
];

/// Request headers this endpoint refuses to sign.
///
/// `x-amz-acl` and the `x-amz-grant-*` family hand access to somebody who never
/// went through this server at all — `x-amz-acl: public-read` on an object
/// inside the table location passes every containment check and publishes the
/// file to the internet. A signature authorizes one request; it must never
/// authorize an unbounded set of future ones.
fn is_refused_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "x-amz-acl" || name.starts_with("x-amz-grant-")
}

/// Header naming the object a `CopyObject` or `UploadPartCopy` reads from.
const COPY_SOURCE_HEADER: &str = "x-amz-copy-source";

/// Refuses a query string that names any parameter twice.
///
/// # Why a repeat is a hole rather than an oddity
///
/// Everything below reads a parameter *once*: `delete` and `list-type` decide
/// which operation this is, and `prefix` is the only location a `ListObjectsV2`
/// has. A repeat splits that into two questions with two answers — which one
/// this endpoint checks, and which one S3 acts on — and the second is not
/// specified anywhere. `?list-type=2&prefix=wh/db/t/&prefix=` therefore reads as
/// a listing confined to one table here and, if S3 takes the last value, as a
/// listing of the whole bucket there. The containment check would have passed on
/// a string the request never used.
///
/// Every repeat is refused rather than only the parameters that are read today,
/// because the set that matters is the set S3 dispatches on, and that grows.
/// Nothing legitimate is lost: the AWS SDKs build these query strings, and none
/// of them emits a duplicate key. The refusal names the parameter, so a client
/// that somehow does can be fixed rather than guessed at.
///
/// # Errors
///
/// [`AppError::BadRequest`] naming the first repeated parameter.
fn reject_repeated_query_parameters(url: &reqwest::Url) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for (name, _) in url.query_pairs() {
        if !seen.insert(name.clone().into_owned()) {
            return Err(AppError::BadRequest(format!(
                "The query string names '{name}' more than once. Which value S3 acts on is \
                 not defined, so the parameter this endpoint authorized would not \
                 necessarily be the one that takes effect."
            )));
        }
    }
    Ok(())
}

/// Works out which locations a request touches, and whether it writes.
fn resolve(
    method: &str,
    payload: &RemoteSignRequest,
    config: &SigningEndpointConfig,
) -> Result<(Addressed, SignedOp)> {
    let url = reqwest::Url::parse(&payload.uri)
        .map_err(|e| AppError::BadRequest(format!("URI to sign is not a URL: {e}")))?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "URI to sign must be http or https".to_string(),
        ));
    }

    // A fragment is never sent to a server, so signing over one would sign a
    // string the client cannot reproduce — the same mismatch this whole section
    // is about, arriving from the other end. It names nothing S3 acts on, so
    // there is nothing to preserve by accepting it.
    if url.fragment().is_some() {
        return Err(AppError::BadRequest(
            "URI to sign carries a '#' fragment, which is never sent to the storage \
             service. The signature would cover a string the request cannot reproduce."
                .to_string(),
        ));
    }

    // The one spelling of this request that anything downstream sees. Taken
    // from the parsed URL rather than from `payload.uri`, so the locations
    // resolved below and the canonical request signed later are derived from
    // the same string — see `Addressed::uri`.
    let canonical = url.as_str().to_string();

    // Before anything below reads a parameter, because each of them reads one
    // once and a repeat makes "the" value ambiguous.
    reject_repeated_query_parameters(&url)?;

    for name in payload.headers.keys() {
        if is_refused_header(name) {
            return Err(AppError::BadRequest(format!(
                "This endpoint does not sign requests carrying '{name}': it grants access \
                 to callers who never went through this catalog, which no per-request \
                 signature can take back."
            )));
        }
    }

    if let Some(refused) = refused_subresource(&url) {
        return Err(AppError::BadRequest(format!(
            "This endpoint signs object access, not '?{refused}'. That request changes who \
             may reach the object, how long it survives, or how the bucket behaves — none \
             of which a table-scoped signature can authorize."
        )));
    }

    let (bucket, key) = split_bucket_and_key(&url, config)?;

    // The source of a server-side copy. Resolved before anything else uses
    // `Addressed`, because it is confined the same way the destination is: the
    // copy runs with this server's storage role, so an unconfined source is an
    // unconfined read of every bucket that role can reach.
    let copy_source = copy_source_location(&payload.headers)?;

    let is_delete_objects = method == "POST" && has_query_flag(&url, "delete");
    let is_list_objects = method == "GET" && has_query_value(&url, "list-type", "2");

    if let Some(source) = copy_source.as_deref() {
        if is_delete_objects || is_list_objects || key.is_empty() {
            return Err(AppError::BadRequest(format!(
                "'{COPY_SOURCE_HEADER}' names the source of a copy, and this request does \
                 not address an object to copy into."
            )));
        }
        if method != "PUT" {
            return Err(AppError::BadRequest(format!(
                "'{COPY_SOURCE_HEADER}' is only meaningful on a PUT, not on a {method}."
            )));
        }
        return Ok((
            Addressed {
                uri: canonical,
                locations: vec![format!("s3://{bucket}/{key}"), source.to_string()],
                prefixes: false,
            },
            SignedOp::Write,
        ));
    }

    if is_delete_objects {
        let body = payload.body.as_deref().ok_or_else(|| {
            AppError::BadRequest(
                "A DeleteObjects request carries its keys in the body, and none was sent."
                    .to_string(),
            )
        })?;
        require_bucket_addressed(&key, "DeleteObjects")?;

        let keys = delete_keys(body)?;
        return Ok((
            Addressed {
                uri: canonical,
                locations: keys.iter().map(|k| format!("s3://{bucket}/{k}")).collect(),
                prefixes: false,
            },
            SignedOp::Write,
        ));
    }

    if is_list_objects {
        require_bucket_addressed(&key, "ListObjectsV2")?;
        let prefix = url
            .query_pairs()
            .find(|(name, _)| name == "prefix")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| {
                AppError::BadRequest(
                    "A listing must name the prefix it is scoped to, or it addresses the \
                     whole bucket."
                        .to_string(),
                )
            })?;
        return Ok((
            Addressed {
                uri: canonical,
                locations: vec![format!("s3://{bucket}/{prefix}")],
                prefixes: true,
            },
            SignedOp::Read,
        ));
    }

    let operation = match method {
        "GET" | "HEAD" => SignedOp::Read,
        "PUT" | "POST" | "DELETE" | "PATCH" => SignedOp::Write,
        other => {
            return Err(AppError::BadRequest(format!(
                "Method '{other}' cannot be signed."
            )));
        }
    };

    if key.is_empty() {
        return Err(AppError::BadRequest(
            "This request addresses the bucket rather than an object, and is not one of the \
             bucket-level operations that can be authorized (DeleteObjects, ListObjectsV2)."
                .to_string(),
        ));
    }

    Ok((
        Addressed {
            uri: canonical,
            locations: vec![format!("s3://{bucket}/{key}")],
            prefixes: false,
        },
        operation,
    ))
}

/// Requests whose locations come from the body or the query string must address
/// the bucket itself: S3 dispatches on the path, so a key there would turn the
/// signed request into an object operation that ignores what was authorized.
fn require_bucket_addressed(key: &str, operation: &str) -> Result<()> {
    if key.is_empty() {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        "A {operation} request addresses the bucket, but this URI names the object \
         '{key}'."
    )))
}

/// The first S3 sub-resource in the query string that this endpoint refuses.
///
/// Matched case-sensitively, because S3 does: `?acl` is a sub-resource and
/// `?ACL` is an ordinary parameter it ignores.
fn refused_subresource(url: &reqwest::Url) -> Option<String> {
    url.query_pairs()
        .map(|(name, _)| name.into_owned())
        .find(|name| {
            REFUSED_SUBRESOURCES.contains(&name.as_str())
                && !ALLOWED_SUBRESOURCES.contains(&name.as_str())
        })
}

/// The object a `x-amz-copy-source` header names, as an `s3://` location.
///
/// The header is `/{bucket}/{key}` or `{bucket}/{key}`, percent-encoded, with an
/// optional `?versionId=…`. Anything else is refused: a source this cannot read
/// exactly is one it cannot confine, and an unconfined source is a read of every
/// bucket this server's storage role can reach.
///
/// # Errors
///
/// [`AppError::BadRequest`] for a header sent more than once, sent with more
/// than one value, or not of the shape above.
fn copy_source_location(headers: &HeaderMultiMap) -> Result<Option<String>> {
    let mut found: Option<&str> = None;
    for (name, values) in headers {
        if !name.eq_ignore_ascii_case(COPY_SOURCE_HEADER) {
            continue;
        }
        // Two values would be signed as two, and S3 would act on one of them.
        // Which one is not something this endpoint should be guessing about.
        if found.is_some() || values.len() != 1 {
            return Err(AppError::BadRequest(format!(
                "'{COPY_SOURCE_HEADER}' was sent more than once, so which object would be \
                 copied is undefined."
            )));
        }
        found = Some(values[0].as_str());
    }

    let Some(raw) = found else { return Ok(None) };

    // The version, if any, selects among an object's versions; it never changes
    // which object, so containment is decided without it.
    let path = raw.split('?').next().unwrap_or(raw).trim();
    let path = path.strip_prefix('/').unwrap_or(path);

    let mut segments = Vec::new();
    for raw_segment in path.split('/') {
        if raw_segment.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw_segment)?;
        if decoded.contains('/') || decoded.contains('\\') || decoded.contains('\0') {
            return Err(AppError::BadRequest(format!(
                "'{COPY_SOURCE_HEADER}' has a segment that decodes into a separator."
            )));
        }
        segments.push(decoded);
    }

    if segments.len() < 2 {
        return Err(AppError::BadRequest(format!(
            "'{COPY_SOURCE_HEADER}' must name a bucket and a key, as '/bucket/key'."
        )));
    }

    let bucket = segments.remove(0);
    Ok(Some(format!("s3://{bucket}/{}", segments.join("/"))))
}

/// Whether the query string carries `name` with no value, as `?delete` does.
fn has_query_flag(url: &reqwest::Url, name: &str) -> bool {
    url.query_pairs()
        .any(|(key, value)| key == name && value.is_empty())
}

/// Whether the query string carries `name=value`.
fn has_query_value(url: &reqwest::Url, name: &str, value: &str) -> bool {
    url.query_pairs()
        .any(|(key, actual)| key == name && actual == value)
}

/// Splits a request URL into `(bucket, key)`.
///
/// The key comes back percent-decoded, because containment is about the object
/// S3 will address rather than about how the client spelled it. A segment whose
/// decoding introduces a separator is refused: `%2F` hides a `/` from the URL
/// parser, so the path that was checked and the path that gets signed would be
/// two different things.
fn split_bucket_and_key(
    url: &reqwest::Url,
    config: &SigningEndpointConfig,
) -> Result<(String, String)> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("URI to sign has no host".to_string()))?
        .to_ascii_lowercase();

    let style = config.url_style.unwrap_or(UrlStyle::Auto);
    let virtual_bucket = match style {
        UrlStyle::Path => None,
        UrlStyle::VirtualHost => Some(host.clone()),
        UrlStyle::Auto => virtual_host_bucket(&host, config.endpoint_host.as_deref()),
    };

    let mut segments: Vec<String> = Vec::new();
    for raw in url.path().split('/').filter(|s| !s.is_empty()) {
        let decoded = percent_decode(raw)?;
        if decoded.contains('/') || decoded.contains('\\') || decoded.contains('\0') {
            return Err(AppError::BadRequest(
                "URI to sign has a path segment that decodes into a separator.".to_string(),
            ));
        }
        segments.push(decoded);
    }

    match virtual_bucket {
        Some(bucket) => Ok((bucket, segments.join("/"))),
        None => {
            if segments.is_empty() {
                return Err(AppError::BadRequest(
                    "URI to sign names no bucket.".to_string(),
                ));
            }
            let bucket = segments.remove(0);
            Ok((bucket, segments.join("/")))
        }
    }
}

/// The bucket a virtual-host-style URL carries, or `None` for path style.
///
/// AWS's own hostnames are recognised by shape: the first label that is `s3` or
/// starts with `s3-` separates the bucket from the endpoint, so
/// `s3.eu-west-1.amazonaws.com` is path style and
/// `my.bucket.s3.eu-west-1.amazonaws.com` is virtual-host with a dotted bucket.
///
/// For a custom endpoint, a configured `endpoint_host` distinguishes the two;
/// without one the answer is path style, which is what MinIO, Ceph and R2
/// deployments use. Guessing wrong fails closed — the bucket is read from the
/// wrong place, so containment does not match and the request is refused.
fn virtual_host_bucket(host: &str, endpoint_host: Option<&str>) -> Option<String> {
    if let Some(rest) = host.strip_suffix(".amazonaws.com") {
        let labels: Vec<&str> = rest.split('.').collect();
        let marker = labels
            .iter()
            .position(|label| *label == "s3" || label.starts_with("s3-"))?;
        return (marker > 0).then(|| labels[..marker].join("."));
    }

    let endpoint = endpoint_host?.to_ascii_lowercase();
    host.strip_suffix(&format!(".{endpoint}"))
        .map(str::to_string)
}

/// Decodes percent-escapes in one path segment.
///
/// # Errors
///
/// [`AppError::BadRequest`] for a malformed escape or a result that is not
/// UTF-8. Both are refusals rather than lossy repairs: a key this cannot read
/// exactly is one it cannot authorize.
fn percent_decode(segment: &str) -> Result<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| {
                    AppError::BadRequest("URI to sign has a malformed escape.".to_string())
                })?;
            out.push(hex);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(out)
        .map_err(|_| AppError::BadRequest("URI to sign is not valid UTF-8.".to_string()))
}

// ============================================================================
// DeleteObjects body
// ============================================================================

/// The object keys a `DeleteObjects` body names.
///
/// # Why this is not an XML parser
///
/// The body is machine-generated by an AWS SDK and has exactly one shape:
///
/// ```xml
/// <Delete><Object><Key>db/t/data/f.parquet</Key></Object></Delete>
/// ```
///
/// Everything else is refused — comments, CDATA, doctypes, processing
/// instructions, numeric character references, attributes anywhere but the root
/// element, and any element that is not `Delete`, `Object`, `Key` or `Quiet`.
/// Refusing is safe: the client falls back to individual `DELETE` requests,
/// each of which is authorized on its own.
///
/// That restriction is the whole design. A general parser brings namespace and
/// attribute machinery this has no use for, and that machinery is where the
/// denial-of-service bugs in XML libraries live — reachable here through a body
/// a caller chooses. This scanner is linear in the body length and allocates
/// only the keys it returns.
///
/// # Errors
///
/// [`AppError::BadRequest`] for anything not of the shape above, and for a body
/// naming no objects.
fn delete_keys(body: &str) -> Result<Vec<String>> {
    let refuse = |why: &str| {
        AppError::BadRequest(format!(
            "DeleteObjects body could not be read ({why}). This endpoint accepts only the \
             plain `<Delete><Object><Key>…</Key></Object></Delete>` form."
        ))
    };

    let bytes = body.as_bytes();
    let mut at = 0usize;
    // The element names currently open, outermost first. Never deeper than
    // Delete → Object → Key.
    let mut open: Vec<&str> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut root_closed = false;

    while at < bytes.len() {
        let Some(offset) = body[at..].find('<') else {
            // Trailing text outside any element must be whitespace.
            require_blank(&body[at..], &refuse)?;
            break;
        };

        let text = &body[at..at + offset];
        match open.last().copied() {
            Some("Key") => keys.push(decode_entities(text, &refuse)?),
            // Content of an element this endpoint does not read.
            Some("Quiet") | Some("VersionId") => {}
            _ => require_blank(text, &refuse)?,
        }

        at += offset;

        // `<?xml …?>` is the only thing outside an element that is not a tag,
        // and only before the root. Everything else beginning `<?` or `<!` —
        // comments, CDATA, doctypes — is refused rather than skipped.
        if body[at..].starts_with("<?") {
            if !open.is_empty() {
                return Err(refuse("a processing instruction inside an element"));
            }
            let close = body[at..]
                .find("?>")
                .ok_or_else(|| refuse("an unterminated declaration"))?;
            at += close + 2;
            continue;
        }
        if body[at..].starts_with("<!") {
            return Err(refuse("a comment, CDATA section or doctype"));
        }

        let close = body[at..]
            .find('>')
            .ok_or_else(|| refuse("an unterminated tag"))?;
        let tag = &body[at + 1..at + close];
        at += close + 1;

        if let Some(name) = tag.strip_prefix('/') {
            let name = name.trim();
            match open.pop() {
                Some(expected) if expected == name => {}
                _ => return Err(refuse("a mismatched closing tag")),
            }
            root_closed |= open.is_empty();
            continue;
        }

        // One root element, and nothing after it.
        if root_closed {
            return Err(refuse("content after the root element"));
        }

        let self_closing = tag.ends_with('/');
        let tag = tag.trim_end_matches('/').trim();
        let (name, attributes) = match tag.find(char::is_whitespace) {
            Some(index) => (&tag[..index], tag[index..].trim()),
            None => (tag, ""),
        };

        // The root may carry `xmlns`, which every SDK sends. Nothing else may
        // carry anything: an attribute on `Key` has no meaning here and would
        // only be a place to hide something this scanner does not read.
        if !attributes.is_empty() && !(open.is_empty() && name == "Delete") {
            return Err(refuse("an attribute on an element that takes none"));
        }

        let expected_depth = match name {
            "Delete" => 0,
            "Object" => 1,
            // `Quiet` sits beside `Object`; it changes the response shape and
            // names no key.
            "Quiet" => 1,
            "Key" | "VersionId" => 2,
            _ => return Err(refuse("an unexpected element")),
        };
        if open.len() != expected_depth {
            return Err(refuse("an element in the wrong place"));
        }

        if self_closing {
            root_closed |= open.is_empty();
        } else {
            open.push(name);
        }
    }

    if !open.is_empty() {
        return Err(refuse("an unclosed element"));
    }
    if keys.is_empty() {
        return Err(refuse("no objects"));
    }

    Ok(keys)
}

/// Refuses anything but whitespace between elements.
fn require_blank(text: &str, refuse: &impl Fn(&str) -> AppError) -> Result<()> {
    if text.trim().is_empty() {
        Ok(())
    } else {
        Err(refuse("text outside an element"))
    }
}

/// Resolves the five predefined entities, and refuses every other `&`.
///
/// Numeric character references are refused rather than decoded: a key
/// containing one is not something an SDK produces, and decoding is one more
/// place for the key that was authorized to differ from the key that was signed.
fn decode_entities(text: &str, refuse: &impl Fn(&str) -> AppError) -> Result<String> {
    if !text.contains('&') {
        return Ok(text.to_string());
    }

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        let tail = &rest[index..];
        let (entity, resolved) = ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
            .iter()
            .zip(['&', '<', '>', '"', '\''])
            .find(|(entity, _)| tail.starts_with(**entity))
            .ok_or_else(|| refuse("an entity reference this endpoint does not resolve"))?;
        out.push(resolved);
        rest = &tail[entity.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

// ============================================================================
// Containment
// ============================================================================

/// Refuses a request that reaches outside `table_location`.
///
/// # Errors
///
/// [`AppError::Forbidden`] naming the first location that falls outside. The
/// table's own location is named too: the caller is permitted to read the table,
/// so it already knows where that is.
fn confine(addressed: &Addressed, table_location: &str) -> Result<()> {
    for location in &addressed.locations {
        let contained = if addressed.prefixes {
            crate::location::is_prefix_within(table_location, location)
        } else {
            crate::location::is_within(table_location, location)
        };

        if !contained {
            return Err(AppError::Forbidden(format!(
                "The request addresses '{location}', which is outside table location \
                 '{table_location}'."
            )));
        }
    }
    Ok(())
}

/// Records what was signed, or what was refused.
///
/// # Why the locations are on the record
///
/// A vended credential is prefix-shaped, so its record names a table and that is
/// the whole story. A signature is request-shaped: the fact worth keeping is not
/// that a caller signed *something* for a table but that it signed a
/// `DeleteObjects` naming nine hundred of its data files. For a deployment that
/// chose signing over vending, "what happened to this object" is the question it
/// chose signing to be able to answer.
///
/// Many locations are truncated to the first few plus a count, so the record
/// stays one line. Every one of them is inside the table the record names — the
/// containment check ran first.
///
/// # Errors
///
/// [`AppError::ServiceUnavailable`] when a *minted write* signature could not be
/// recorded and the auditor fails closed. Reads degrade the other way, like a
/// read decision; a refused signature authorized nothing, so there is no
/// unrecorded grant to refuse.
fn record_signature(
    state: &AppState,
    authorized: &guard::Authorized,
    operation: SignedOp,
    addressed: &Addressed,
    allowed: bool,
) -> Result<()> {
    /// Locations named individually before the record falls back to a count.
    const NAMED: usize = 8;

    let verb = match operation {
        SignedOp::Read => "read",
        SignedOp::Write => "write",
    };

    let locations = if addressed.locations.len() > NAMED {
        format!(
            "{} (and {} more)",
            addressed.locations[..NAMED].join(" "),
            addressed.locations.len() - NAMED
        )
    } else {
        addressed.locations.join(" ")
    };

    let event = crate::auth::AuditEvent::request_sign(verb, &authorized.resource_path(), allowed)
        .with_principal_id(authorized.principal().id())
        .with_tenant_id(authorized.principal().tenant_id())
        .with_optional_client_ip(authorized.request().source_ip)
        .with_optional_request_id(authorized.request().request_id.as_deref())
        .with_detail("locations", locations)
        .with_detail("location_count", addressed.locations.len().to_string());

    if operation == SignedOp::Write && allowed {
        state.auditor.record(&event).map_err(|_| {
            AppError::ServiceUnavailable(
                "The audit trail is unavailable, so no signature was issued.".to_string(),
            )
        })
    } else {
        state.auditor.record_lossy(&event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SigningEndpointConfig {
        SigningEndpointConfig {
            enabled: true,
            url_style: Some(UrlStyle::Auto),
            endpoint_host: None,
            fallback_region: None,
        }
    }

    fn request(uri: &str) -> RemoteSignRequest {
        RemoteSignRequest {
            region: "eu-west-1".to_string(),
            uri: uri.to_string(),
            method: "GET".to_string(),
            headers: HeaderMultiMap::new(),
            properties: BTreeMap::new(),
            body: None,
            provider: None,
        }
    }

    fn url(uri: &str) -> reqwest::Url {
        reqwest::Url::parse(uri).unwrap()
    }

    // ── URL styles ──────────────────────────────────────────────────────

    #[test]
    fn aws_virtual_host_urls_yield_the_bucket_from_the_host() {
        for host in [
            "wh.s3.amazonaws.com",
            "wh.s3.eu-west-1.amazonaws.com",
            "wh.s3-eu-west-1.amazonaws.com",
            "wh.s3.dualstack.eu-west-1.amazonaws.com",
        ] {
            assert_eq!(
                virtual_host_bucket(host, None).as_deref(),
                Some("wh"),
                "{host}"
            );
        }
    }

    #[test]
    fn aws_path_style_urls_yield_no_host_bucket() {
        for host in [
            "s3.amazonaws.com",
            "s3.eu-west-1.amazonaws.com",
            "s3-eu-west-1.amazonaws.com",
        ] {
            assert_eq!(virtual_host_bucket(host, None), None, "{host}");
        }
    }

    /// A bucket name may contain dots, and then so does the hostname.
    #[test]
    fn a_dotted_bucket_survives_virtual_host_parsing() {
        assert_eq!(
            virtual_host_bucket("my.dotted.bucket.s3.eu-west-1.amazonaws.com", None).as_deref(),
            Some("my.dotted.bucket")
        );
    }

    #[test]
    fn a_custom_endpoint_is_path_style_unless_told_otherwise() {
        assert_eq!(virtual_host_bucket("minio:9000", None), None);
        assert_eq!(virtual_host_bucket("minio", Some("minio")), None);
        assert_eq!(
            virtual_host_bucket("wh.minio", Some("minio")).as_deref(),
            Some("wh")
        );
    }

    #[test]
    fn path_style_takes_the_bucket_from_the_first_segment() {
        let (bucket, key) = split_bucket_and_key(
            &url("https://s3.eu-west-1.amazonaws.com/wh/db/t/data/f.parquet"),
            &config(),
        )
        .unwrap();
        assert_eq!(bucket, "wh");
        assert_eq!(key, "db/t/data/f.parquet");
    }

    #[test]
    fn virtual_host_style_takes_the_whole_path_as_the_key() {
        let (bucket, key) = split_bucket_and_key(
            &url("https://wh.s3.eu-west-1.amazonaws.com/db/t/data/f.parquet"),
            &config(),
        )
        .unwrap();
        assert_eq!(bucket, "wh");
        assert_eq!(key, "db/t/data/f.parquet");
    }

    #[test]
    fn a_percent_encoded_key_decodes_to_what_s3_addresses() {
        let (_, key) = split_bucket_and_key(
            &url("https://wh.s3.amazonaws.com/db/t/data/region%3DEU/f%20g.parquet"),
            &config(),
        )
        .unwrap();
        assert_eq!(key, "db/t/data/region=EU/f g.parquet");
    }

    /// `%2F` hides a separator from the URL parser, so the path that would be
    /// checked and the path that gets signed are two different things.
    #[test]
    fn a_segment_that_decodes_into_a_separator_is_refused() {
        let err = split_bucket_and_key(
            &url("https://wh.s3.amazonaws.com/db/t%2F..%2Fother/f.parquet"),
            &config(),
        )
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    /// A URL parser resolves dot segments and, under a special scheme, reads a
    /// backslash as a separator. So a URI whose *raw* path leaves the table
    /// reads here as one that does not — and S3, which takes the key literally,
    /// would act on the raw one.
    ///
    /// The answer is not to refuse the spelling but to sign the resolved one:
    /// what was checked is what is signed and what is handed back. The signature
    /// then does not verify against anything else, so the escape stops being
    /// reachable rather than being enumerated.
    #[test]
    fn the_signed_uri_is_the_one_containment_was_checked_against() {
        for raw in [
            "https://wh.s3.amazonaws.com/other/../db/t/data/f.parquet",
            r"https://wh.s3.amazonaws.com/other\..\..\db\t\data\f.parquet",
            "https://wh.s3.amazonaws.com/db/t/data/x/%2E%2E/f.parquet",
        ] {
            let payload = request(raw);
            let (addressed, _) = resolve("GET", &payload, &config())
                .unwrap_or_else(|e| panic!("{raw} should resolve: {e}"));

            assert_eq!(
                addressed.locations,
                vec!["s3://wh/db/t/data/f.parquet"],
                "{raw} resolves inside the table"
            );
            assert!(
                confine(&addressed, "s3://wh/db/t").is_ok(),
                "{raw} passes containment"
            );
            assert_eq!(
                addressed.uri, "https://wh.s3.amazonaws.com/db/t/data/f.parquet",
                "{raw} must be signed as the path that was checked, not as sent"
            );
            assert_ne!(
                addressed.uri, raw,
                "{raw} was signed verbatim, so S3 would act on a key nothing checked"
            );
        }
    }

    /// A fragment never reaches the storage service, so a signature covering one
    /// covers a string the request cannot reproduce.
    #[test]
    fn a_uri_carrying_a_fragment_is_refused() {
        let payload = request("https://wh.s3.amazonaws.com/db/t/data/f.parquet#frag");
        assert_eq!(
            resolve("GET", &payload, &config())
                .unwrap_err()
                .status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    // ── Operations ──────────────────────────────────────────────────────

    #[test]
    fn a_get_reads_one_object() {
        let payload = request("https://wh.s3.amazonaws.com/db/t/data/f.parquet");
        let (addressed, op) = resolve("GET", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Read);
        assert_eq!(addressed.locations, vec!["s3://wh/db/t/data/f.parquet"]);
        assert!(!addressed.prefixes);
    }

    #[test]
    fn a_put_writes_one_object() {
        let payload = request("https://wh.s3.amazonaws.com/db/t/data/f.parquet");
        let (_, op) = resolve("PUT", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Write);
    }

    #[test]
    fn a_multipart_upload_addresses_its_own_key() {
        let payload = request("https://wh.s3.amazonaws.com/db/t/data/f.parquet?uploads");
        let (addressed, op) = resolve("POST", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Write);
        assert_eq!(addressed.locations, vec!["s3://wh/db/t/data/f.parquet"]);
    }

    /// The keys are in the body, so reading only the path would authorize the
    /// whole bucket.
    #[test]
    fn delete_objects_is_authorized_against_the_keys_in_its_body() {
        let mut payload = request("https://wh.s3.amazonaws.com/?delete");
        payload.body = Some(
            "<Delete><Object><Key>db/t/data/a.parquet</Key></Object>\
             <Object><Key>db/t/data/b.parquet</Key></Object></Delete>"
                .to_string(),
        );

        let (addressed, op) = resolve("POST", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Write);
        assert_eq!(
            addressed.locations,
            vec!["s3://wh/db/t/data/a.parquet", "s3://wh/db/t/data/b.parquet"]
        );
    }

    #[test]
    fn delete_objects_without_a_body_is_refused() {
        let payload = request("https://wh.s3.amazonaws.com/?delete");
        assert!(resolve("POST", &payload, &config()).is_err());
    }

    /// S3 dispatches on the path: a key here would make the signed request an
    /// object delete that ignores the body this authorization read.
    #[test]
    fn delete_objects_naming_an_object_in_the_path_is_refused() {
        let mut payload = request("https://wh.s3.amazonaws.com/db/t/x?delete");
        payload.body = Some("<Delete><Object><Key>db/t/a</Key></Object></Delete>".to_string());
        assert!(resolve("POST", &payload, &config()).is_err());
    }

    #[test]
    fn a_listing_is_authorized_against_its_prefix() {
        let payload = request("https://wh.s3.amazonaws.com/?list-type=2&prefix=db/t/data/");
        let (addressed, op) = resolve("GET", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Read);
        assert_eq!(addressed.locations, vec!["s3://wh/db/t/data/"]);
        assert!(addressed.prefixes);
    }

    #[test]
    fn a_listing_without_a_prefix_is_refused() {
        let payload = request("https://wh.s3.amazonaws.com/?list-type=2");
        assert!(resolve("GET", &payload, &config()).is_err());
    }

    /// Every bucket-level sub-resource other than the two that carry a location
    /// — `?versions`, `?uploads` at bucket scope, `?location` — is unresolvable
    /// and therefore refused.
    #[test]
    fn an_unrecognised_bucket_level_request_is_refused() {
        let payload = request("https://wh.s3.amazonaws.com/?versions");
        assert!(resolve("GET", &payload, &config()).is_err());
    }

    #[test]
    fn an_unsignable_method_is_refused() {
        let payload = request("https://wh.s3.amazonaws.com/db/t/f");
        assert!(resolve("OPTIONS", &payload, &config()).is_err());
    }

    #[test]
    fn a_non_http_uri_is_refused() {
        let payload = request("s3://wh/db/t/f");
        assert!(resolve("GET", &payload, &config()).is_err());
    }

    // ── Containment ─────────────────────────────────────────────────────

    #[test]
    fn an_object_inside_the_table_is_allowed() {
        let addressed = Addressed {
            uri: "https://wh.s3.amazonaws.com/db/t/data/f.parquet".to_string(),
            locations: vec!["s3://wh/db/t/data/f.parquet".to_string()],
            prefixes: false,
        };
        assert!(confine(&addressed, "s3://wh/db/t").is_ok());
    }

    #[test]
    fn an_object_in_a_sibling_table_is_refused() {
        let addressed = Addressed {
            uri: "https://wh.s3.amazonaws.com/db/other/data/f.parquet".to_string(),
            locations: vec!["s3://wh/db/other/data/f.parquet".to_string()],
            prefixes: false,
        };
        assert!(confine(&addressed, "s3://wh/db/t").is_err());
    }

    /// One key outside the table refuses the whole batch: a partially signed
    /// delete is not something the client could act on.
    #[test]
    fn one_stray_key_refuses_the_whole_delete() {
        let addressed = Addressed {
            uri: "https://wh.s3.amazonaws.com/?delete".to_string(),
            locations: vec![
                "s3://wh/db/t/data/a".to_string(),
                "s3://wh/db/other/data/b".to_string(),
            ],
            prefixes: false,
        };
        assert!(confine(&addressed, "s3://wh/db/t").is_err());
    }

    /// S3 matches a list prefix as a raw string, so a prefix that stops at the
    /// table location also returns the keys of same-prefixed siblings.
    #[test]
    fn a_list_prefix_must_sit_strictly_inside_the_table() {
        let table = "s3://wh/db/t";
        let prefix = |p: &str| Addressed {
            uri: "https://wh.s3.amazonaws.com/?list-type=2".to_string(),
            locations: vec![p.to_string()],
            prefixes: true,
        };

        assert!(confine(&prefix("s3://wh/db/t/"), table).is_ok());
        assert!(confine(&prefix("s3://wh/db/t/data/"), table).is_ok());
        assert!(
            confine(&prefix("s3://wh/db/t"), table).is_err(),
            "this prefix also matches s3://wh/db/t2/..."
        );
        assert!(confine(&prefix("s3://wh/db/"), table).is_err());
    }

    // ── DeleteObjects bodies ────────────────────────────────────────────

    #[test]
    fn the_ordinary_delete_body_yields_its_keys() {
        let keys = delete_keys(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n\
               <Object><Key>db/t/a.parquet</Key></Object>\n\
               <Object><Key>db/t/b.parquet</Key><VersionId>v2</VersionId></Object>\n\
               <Quiet>true</Quiet>\n\
             </Delete>",
        )
        .unwrap();

        assert_eq!(keys, vec!["db/t/a.parquet", "db/t/b.parquet"]);
    }

    #[test]
    fn predefined_entities_resolve_in_a_key() {
        let keys =
            delete_keys("<Delete><Object><Key>a&amp;b/c.parquet</Key></Object></Delete>").unwrap();
        assert_eq!(keys, vec!["a&b/c.parquet"]);
    }

    /// Everything this scanner does not fully understand is refused, because a
    /// key it reads differently from S3 is a key nobody authorized.
    #[test]
    fn anything_unusual_is_refused() {
        for body in [
            "",
            "<Delete></Delete>",
            "<Delete><Object></Object></Delete>",
            // Comment, CDATA, doctype, entity declaration.
            "<Delete><!-- x --><Object><Key>a</Key></Object></Delete>",
            "<Delete><Object><Key><![CDATA[a]]></Key></Object></Delete>",
            "<!DOCTYPE Delete><Delete><Object><Key>a</Key></Object></Delete>",
            // Numeric character reference and an unknown entity.
            "<Delete><Object><Key>a&#47;b</Key></Object></Delete>",
            "<Delete><Object><Key>a&xxe;b</Key></Object></Delete>",
            // Attributes where none belong.
            "<Delete><Object><Key foo=\"bar\">a</Key></Object></Delete>",
            // Structure.
            "<Delete><Key>a</Key></Delete>",
            "<Delete><Object><Key>a</Key></Delete></Object>",
            "<Delete><Object><Key>a</Key></Object>",
            "<Other><Object><Key>a</Key></Object></Other>",
            "stray text<Delete><Object><Key>a</Key></Object></Delete>",
            "<Delete><Object><Key>a</Key></Object></Delete><Delete/>",
        ] {
            assert!(
                delete_keys(body).is_err(),
                "should have been refused: {body}"
            );
        }
    }

    /// Linear in the body length, whatever it contains — the property a general
    /// XML parser's attribute and namespace handling is where DoS bugs live.
    #[test]
    fn a_pathological_body_is_refused_rather_than_chewed_on() {
        let attributes = "a=\"1\" ".repeat(20_000);
        assert!(delete_keys(&format!("<Delete><Object {attributes}/></Delete>")).is_err());
    }

    // ── Operations this endpoint refuses to sign ────────────────────────

    fn with_headers(uri: &str, method: &str, headers: &[(&str, &str)]) -> RemoteSignRequest {
        let mut request = request(uri);
        request.method = method.to_string();
        request.headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), vec![(*value).to_string()]))
            .collect();
        request
    }

    /// The exfiltration primitive this endpoint would otherwise be. The
    /// destination is squarely inside the caller's own table; the source is
    /// somebody else's bucket, fetched with *this server's* storage role.
    #[test]
    fn a_copy_source_is_resolved_and_confined_like_the_destination() {
        let payload = with_headers(
            "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/stolen.parquet",
            "PUT",
            &[("x-amz-copy-source", "/other-bucket/secrets/private.parquet")],
        );

        let (addressed, op) = resolve("PUT", &payload, &config()).unwrap();
        assert_eq!(op, SignedOp::Write);
        assert!(
            addressed
                .locations
                .contains(&"s3://other-bucket/secrets/private.parquet".to_string()),
            "the copy source must be one of the locations confinement sees"
        );
        assert!(
            confine(&addressed, "s3://wh/db/t").is_err(),
            "a source outside the table must be refused"
        );
    }

    #[test]
    fn a_copy_within_the_table_is_still_signed() {
        let payload = with_headers(
            "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/b.parquet",
            "PUT",
            &[("x-amz-copy-source", "wh/db/t/data/a.parquet")],
        );
        let (addressed, _) = resolve("PUT", &payload, &config()).unwrap();
        assert!(confine(&addressed, "s3://wh/db/t").is_ok());
    }

    #[test]
    fn a_copy_source_this_cannot_read_exactly_is_refused() {
        for value in ["", "/", "just-a-bucket", "/bucket/a%ZZb"] {
            let payload = with_headers(
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/x.parquet",
                "PUT",
                &[("x-amz-copy-source", value)],
            );
            assert!(
                resolve("PUT", &payload, &config()).is_err(),
                "should have been refused: {value:?}"
            );
        }
    }

    #[test]
    fn a_copy_source_on_something_that_is_not_a_put_is_refused() {
        let payload = with_headers(
            "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/x.parquet",
            "GET",
            &[("x-amz-copy-source", "/wh/db/t/data/a.parquet")],
        );
        assert!(resolve("GET", &payload, &config()).is_err());
    }

    /// `?acl` is inside the table location and passes every containment check
    /// there is. It also publishes the object to the internet.
    #[test]
    fn a_subresource_that_changes_who_may_read_is_refused() {
        for subresource in ["acl", "tagging", "retention", "legal-hold", "policy"] {
            let uri =
                format!("https://wh.s3.eu-west-1.amazonaws.com/db/t/data/x.parquet?{subresource}");
            let mut payload = request(&uri);
            payload.method = "PUT".to_string();
            assert!(
                resolve("PUT", &payload, &config()).is_err(),
                "should have been refused: ?{subresource}"
            );
        }
    }

    #[test]
    fn the_operations_engines_actually_use_are_still_signed() {
        for (method, uri) in [
            (
                "GET",
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/d/x.parquet",
            ),
            (
                "POST",
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/d/x.parquet?uploads",
            ),
            (
                "PUT",
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/d/x.parquet?partNumber=1&uploadId=u",
            ),
            (
                "GET",
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/d/x.parquet?versionId=v&x-id=GetObject",
            ),
        ] {
            let mut payload = request(uri);
            payload.method = method.to_string();
            let (addressed, _) = resolve(method, &payload, &config())
                .unwrap_or_else(|e| panic!("{method} {uri} should be signable: {e}"));
            assert!(confine(&addressed, "s3://wh/db/t").is_ok());
        }
    }

    #[test]
    fn a_header_that_grants_access_to_somebody_else_is_refused() {
        for header in ["x-amz-acl", "X-Amz-Grant-Read", "x-amz-grant-full-control"] {
            let payload = with_headers(
                "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/x.parquet",
                "PUT",
                &[(header, "public-read")],
            );
            assert!(
                resolve("PUT", &payload, &config()).is_err(),
                "should have been refused: {header}"
            );
        }
    }

    #[test]
    fn url_style_parses_the_documented_values() {
        assert_eq!(UrlStyle::parse("auto").unwrap(), UrlStyle::Auto);
        assert_eq!(UrlStyle::parse("path").unwrap(), UrlStyle::Path);
        assert_eq!(
            UrlStyle::parse("virtual-host").unwrap(),
            UrlStyle::VirtualHost
        );
        assert!(UrlStyle::parse("guess").is_err());
    }
}
