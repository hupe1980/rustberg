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
//! 3. Every location the request touches is inside the table's own location.
//!
//! The third is the one this module is mostly about, because "the location a
//! request touches" is not always in the path. `DeleteObjects` puts its keys in
//! an XML body, and `ListObjectsV2` puts its prefix in the query string. Both
//! address the *bucket*, so a check that only read the path would authorize
//! them against `s3://bucket` and sign a delete for any key in it.
//!
//! Anything this module cannot resolve to a location is refused. That is the
//! whole safety argument: unrecognised is not permitted.

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
        encode_path_segment(&namespace.join("\u{1F}")),
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

    // Same rule as vending: a signature says "this object may be read", which is
    // every row and every column in it.
    if !authorized.obligations.is_empty() {
        return Err(AppError::Forbidden(format!(
            "Policy attaches restrictions to this table ({}), and a signed request cannot \
             express them. Signing is withheld rather than granting access wider than \
             policy allows.",
            authorized.obligations.describe()
        )));
    }

    let (addressed, operation) = resolve(&method, &payload, &state.signing)?;

    if operation == SignedOp::Write && !authorized.also_permits(&state, Action::Update).await {
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
    if !crate::location::is_vendable(state.request_signer.allowed_prefixes(), &table_location) {
        return Err(AppError::Forbidden(
            "This catalog does not sign requests for the storage this table lives in.".to_string(),
        ));
    }

    confine(&addressed, &table_location)?;

    let signed = state
        .request_signer
        .sign(SignRequest {
            method: &method,
            uri: &payload.uri,
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

    let (bucket, key) = split_bucket_and_key(&url, config)?;

    let is_delete_objects = method == "POST" && has_query_flag(&url, "delete");
    let is_list_objects = method == "GET" && has_query_value(&url, "list-type", "2");

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
            "DeleteObjects body could not be read ({why}). This endpoint accepts only the              plain `<Delete><Object><Key>…</Key></Object></Delete>` form."
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
            locations: vec!["s3://wh/db/t/data/f.parquet".to_string()],
            prefixes: false,
        };
        assert!(confine(&addressed, "s3://wh/db/t").is_ok());
    }

    #[test]
    fn an_object_in_a_sibling_table_is_refused() {
        let addressed = Addressed {
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
