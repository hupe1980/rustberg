//! A read-only mount over somebody else's Iceberg REST catalog.
//!
//! # Why this client is hand-written
//!
//! `iceberg-catalog-rest` exists and implements [`iceberg::Catalog`]. It is the
//! obvious choice and it is the wrong one here, for two reasons that are both
//! about this crate's own constraints rather than the quality of that one:
//!
//! - **It cannot page.** `Catalog::list_tables` returns `Vec<TableIdent>`, so
//!   every listing materialises the whole namespace. That is precisely the
//!   limitation [`CatalogStore`](super::store) was defined to escape, and
//!   adopting it for federated mounts would bring it back exactly where the
//!   catalog is remote and the cost is highest.
//! - **It pins a second HTTP stack.** It depends on `reqwest` 0.12 with
//!   `default-features = false` and no TLS feature, while this crate is on 0.13
//!   with rustls. Two semver-incompatible reqwest trees would ship in one
//!   binary, and the older one would have no TLS backend at all — so `https://`
//!   mounts, the only kind anyone federates, would fail to connect.
//!
//! The subset needed for a read-only mount is eight endpoints of ordinary JSON.
//! Writing it directly costs less than working around either problem.
//!
//! # Why read-only
//!
//! Proxying a commit is possible — the requirements and updates would be
//! forwarded verbatim — but a write that lands in a catalog Rustberg does not
//! own is a different promise from one it does. Reads are the case federation is
//! actually for: one endpoint, one identity, over catalogs that already exist.
//! Writes stay with whoever owns them.
//!
//! # Capabilities are negotiated, not assumed
//!
//! The remote's own `GET /v1/config` lists the endpoints it serves, and
//! [`RestCatalog::connect`] derives this mount's capabilities from it. A remote
//! that does not serve views produces a mount that reports no views, rather than
//! one that offers them and fails on use.

use std::collections::HashMap;

use async_trait::async_trait;
use iceberg::spec::{TableMetadata, ViewMetadata};
use iceberg::table::Table;
use iceberg::{
    Error, ErrorKind, Namespace, NamespaceIdent, Result, Runtime, TableCreation, TableIdent,
    TableRequirement, TableUpdate,
};
use serde::Deserialize;

use super::capabilities::Capabilities;
use super::store::{CatalogStore, Entry, Page, PageRequest, StorageHealthStatus};

/// Separator the Iceberg REST spec uses between namespace levels in a path.
///
/// A unit separator, percent-encoded in the URL. Joining on `.` would be
/// ambiguous for a namespace whose name contains one.
/// The same separator this crate keys on, sent across the hop.
///
/// A remote catalog's REST path encodes a multi-level namespace with the unit
/// separator, which is also what the registries key on and what a request
/// arrives with — so this is [`crate::names::PART_SEPARATOR`], not a second
/// opinion about it.
const NAMESPACE_SEPARATOR: char = crate::names::PART_SEPARATOR;

/// Separates a remote page token from the offset into the page it produced.
///
/// A record separator, because a remote token is opaque and may contain
/// anything printable; splitting once from the left keeps the parse exact
/// whatever the token turns out to be.
const REMOTE_CURSOR_SEP: char = '\u{1E}';

/// How long to wait for a mounted catalog to accept a connection.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait for a mounted catalog to answer.
///
/// Comfortably under the server's own 30-second request timeout, so a stalled
/// mount surfaces as an error naming the mount rather than as a timeout naming
/// nothing.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A position **inside** a remote catalog's listing.
///
/// # Why a token is not enough
///
/// This crate's paging contract says an [`Entry`]'s cursor resumes immediately
/// after that one item ([`crate::catalog::store`]), and the authorization filter
/// depends on it: [`collect_page`] stops the moment a page is full, which is
/// usually part-way through a batch, and resumes from the last row it *kept*.
///
/// A remote catalog cannot express that. Its `pageToken` names the start of a
/// whole page and nothing finer, so there is no token meaning "after the third
/// of these ten". Handing the remote anything else — an item's own name, say —
/// sends it a token from a cursor space it has never heard of: it either rejects
/// the request or restarts from the beginning, and a client paging through the
/// mount loops or silently loses rows.
///
/// So a cursor here is the **pair**: the token that produced a page, and how far
/// into that page the position is. Resuming re-fetches the page and drops the
/// first `skip` items, which is exact as long as the remote's own ordering is
/// stable — the assumption every page token already makes.
///
/// The re-fetch is paid only when a page really does fill mid-batch. The last
/// item of a remote page is named by the remote's *next* token with a zero skip
/// instead, so an unfiltered listing walks the mount one round trip per page.
///
/// [`collect_page`]: crate::catalog::v1::pagination::collect_page
#[derive(Debug, Default, PartialEq, Eq)]
struct RemoteCursor {
    /// Token that produced the page this position is inside. `None` is the
    /// first page.
    token: Option<String>,
    /// Items at the front of that page already served.
    skip: usize,
}

impl RemoteCursor {
    /// Reads a cursor previously produced by [`Self::at`] or
    /// [`Self::start_of`].
    ///
    /// Anything else — absent, forged, or written by an older build — restarts
    /// the listing. A client then sees rows it has already seen, which is
    /// visible and recoverable; passing an unrecognised value to the remote as
    /// a page token is not.
    fn parse(cursor: Option<&str>) -> Self {
        let Some(raw) = cursor else {
            return Self::default();
        };
        let Some((skip, token)) = raw.split_once(REMOTE_CURSOR_SEP) else {
            return Self::default();
        };
        let Ok(skip) = skip.parse::<usize>() else {
            return Self::default();
        };
        Self {
            token: (!token.is_empty()).then(|| token.to_string()),
            skip,
        }
    }

    /// This cursor's page, resumed after its `skip`-th item.
    fn at(&self, skip: usize) -> String {
        format!(
            "{skip}{REMOTE_CURSOR_SEP}{}",
            self.token.as_deref().unwrap_or_default()
        )
    }

    /// The first item of the page `token` fetches.
    fn start_of(token: &str) -> String {
        format!("0{REMOTE_CURSOR_SEP}{token}")
    }
}

/// A mounted remote Iceberg REST catalog.
pub struct RestCatalog {
    client: reqwest::Client,
    /// Base URI, without a trailing slash.
    uri: String,
    /// Bearer token presented to the remote, if it requires one.
    token: Option<String>,
    capabilities: Capabilities,
    file_io: iceberg::io::FileIO,
    runtime: Runtime,
}

impl std::fmt::Debug for RestCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestCatalog")
            .field("uri", &self.uri)
            .field("capabilities", &self.capabilities)
            // Never the token.
            .finish_non_exhaustive()
    }
}

/// The remote's `GET /v1/config` response, as much of it as matters here.
#[derive(Debug, Deserialize)]
struct RemoteConfig {
    #[serde(default)]
    endpoints: Vec<String>,
}

/// A paged listing of namespaces.
#[derive(Debug, Deserialize)]
struct ListNamespacesResponse {
    #[serde(default)]
    namespaces: Vec<Vec<String>>,
    #[serde(rename = "next-page-token", default)]
    next_page_token: Option<String>,
}

/// A paged listing of tables or views.
#[derive(Debug, Deserialize)]
struct ListTabularsResponse {
    #[serde(default)]
    identifiers: Vec<RemoteIdentifier>,
    #[serde(rename = "next-page-token", default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteIdentifier {
    namespace: Vec<String>,
    name: String,
}

/// A loaded namespace.
#[derive(Debug, Deserialize)]
struct GetNamespaceResponse {
    namespace: Vec<String>,
    #[serde(default)]
    properties: HashMap<String, String>,
}

/// A loaded table.
#[derive(Debug, Deserialize)]
struct LoadTableResponse {
    #[serde(rename = "metadata-location", default)]
    metadata_location: Option<String>,
    metadata: TableMetadata,
}

/// A loaded view.
#[derive(Debug, Deserialize)]
struct LoadViewResponse {
    #[serde(rename = "metadata-location")]
    metadata_location: String,
    metadata: ViewMetadata,
}

impl RestCatalog {
    /// Connects to `uri` and negotiates capabilities from its config response.
    ///
    /// # Errors
    ///
    /// Returns an error when the remote cannot be reached or does not answer
    /// `GET /v1/config`. Both are startup failures: a mount that silently did
    /// not connect would make its namespace subtree look empty rather than
    /// unavailable, and empty is indistinguishable from "you may not see this".
    pub async fn connect(uri: &str, token: Option<String>) -> Result<Self> {
        let uri = uri.trim_end_matches('/').to_string();
        // Bounded, because a mount is on the request path of every call into
        // its subtree. Without these a remote that accepts a connection and
        // then stops answering holds a Rustberg worker until the server's own
        // 30-second request timeout fires, and the caller learns nothing about
        // which of the two stalled.
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // A mount carries a bearer token that belongs to *this* server, and
            // a redirect is the remote choosing where that token goes next. A
            // catalog URI does not legitimately redirect, so following one is
            // all risk and no function.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("rustberg/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::new(ErrorKind::Unexpected, format!("HTTP client: {e}")))?;

        let mut request = client.get(format!("{uri}/v1/config"));
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await.map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Could not reach the catalog at {uri}: {e}"),
            )
        })?;

        if !response.status().is_success() {
            return Err(Error::new(
                ErrorKind::Unexpected,
                format!(
                    "The catalog at {uri} answered {} to GET /v1/config",
                    response.status()
                ),
            ));
        }

        let config: RemoteConfig = read_json(response, "GET /v1/config").await?;

        let capabilities = Self::negotiate(&config.endpoints);

        tracing::info!(
            uri = %uri,
            views = capabilities.views,
            "Connected to a remote Iceberg REST catalog"
        );

        Ok(Self {
            client,
            uri,
            token,
            capabilities,
            // The mount reads metadata files itself, so it needs a `FileIO` that
            // can resolve whatever scheme the remote's warehouse uses.
            file_io: super::file_io::build_file_io()?,
            runtime: Runtime::try_current()?,
        })
    }

    /// What this mount can do, given what the remote says it serves.
    ///
    /// Always read-only, then narrowed further: a remote that advertises no view
    /// endpoints produces a mount reporting no views. An empty `endpoints` list
    /// means the remote predates the field, and the spec's baseline includes
    /// views — assuming otherwise would hide views that are there.
    fn negotiate(endpoints: &[String]) -> Capabilities {
        if endpoints.is_empty() {
            return Capabilities::read_only();
        }

        let serves_views = endpoints
            .iter()
            .any(|endpoint| endpoint.starts_with("GET ") && endpoint.contains("/views/"));

        if serves_views {
            Capabilities::read_only()
        } else {
            Capabilities::read_only_without_views()
        }
    }

    /// The capabilities negotiated at connection time.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Percent-encodes a namespace into one path segment.
    fn encode_namespace(namespace: &NamespaceIdent) -> String {
        encode_segment(&namespace.as_ref().join(&NAMESPACE_SEPARATOR.to_string()))
    }

    /// Issues a GET and decodes the body.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let response = self.send(path, &[]).await?;
        self.decode(response, path).await
    }

    /// Issues a GET with query parameters and decodes the body.
    async fn get_with<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Option<T>> {
        let response = self.send(path, query).await?;
        self.decode(response, path).await
    }

    async fn send(&self, path: &str, query: &[(&str, String)]) -> Result<reqwest::Response> {
        // Built here rather than through `RequestBuilder::query`, which is
        // feature-gated in `reqwest` and therefore absent from some of this
        // crate's feature combinations. Encoding it directly also means the
        // escaping is the same one used for path segments, rather than two
        // implementations that could disagree about a namespace separator.
        let url = format!("{}{path}{}", self.uri, encode_query(query));

        let mut request = self.client.get(url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        request.send().await.map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Request to the mounted catalog failed ({path}): {e}"),
            )
        })
    }

    /// Turns a response into a value, `None`, or an error.
    ///
    /// `404` becomes `None` rather than an error so callers can distinguish
    /// "not there" from "could not ask", which are different answers to give a
    /// client. Every other failure keeps the remote's status in the message: an
    /// operator debugging a mount needs to know whether the remote refused them
    /// or fell over.
    async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
        path: &str,
    ) -> Result<Option<T>> {
        let status = response.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !status.is_success() {
            // A `401`/`403` from the remote is *this mount's* credential being
            // rejected, never the caller's — Rustberg presents its own token and
            // forwards nobody else's. Saying so is the difference between an
            // operator checking `token_env` and an operator checking a policy
            // that was never involved.
            let detail = match status.as_u16() {
                401 | 403 => {
                    " — the mount's own credential was rejected, so check its \
                     configured token rather than this caller's permissions"
                }
                _ => "",
            };
            return Err(Error::new(
                ErrorKind::Unexpected,
                format!("The mounted catalog answered {status} for {path}{detail}"),
            ));
        }

        read_json(response, path).await.map(Some)
    }

    /// Paging parameters, in the spelling the spec uses.
    ///
    /// The size asked for is the caller's limit **plus** whatever the cursor
    /// says to drop, so that a resumed page still yields a full one after the
    /// skip. See [`RemoteCursor`] for why a skip exists at all.
    ///
    /// Capped at [`MAX_PAGE_SIZE`](crate::catalog::MAX_PAGE_SIZE), which is the
    /// most this crate asks any source for. When the cap bites, the resumed page
    /// is *short* rather than wrong — [`collect_page`] loops until it is full —
    /// and [`Self::repage`] handles the case where the remote comes back with
    /// fewer rows than the position being resumed to.
    ///
    /// [`collect_page`]: crate::catalog::v1::pagination::collect_page
    fn page_query(page: &PageRequest, resume: &RemoteCursor) -> Vec<(&'static str, String)> {
        let size = page
            .effective_limit()
            .saturating_add(resume.skip)
            .min(crate::catalog::MAX_PAGE_SIZE);
        let mut query = vec![("pageSize", size.to_string())];
        if let Some(token) = &resume.token {
            query.push(("pageToken", token.clone()));
        }
        query
    }

    /// Turns one remote page into a [`Page`] whose cursors mean what this
    /// crate's paging contract says they mean.
    ///
    /// `items` are the identifiers the remote returned, in its order. The first
    /// `resume.skip` of them were already served on an earlier request and are
    /// dropped here.
    fn repage<T>(
        items: Vec<T>,
        next_token: Option<String>,
        resume: &RemoteCursor,
        limit: usize,
    ) -> Page<T> {
        let total = items.len();

        // A skip names a position *inside* a page that held more than `skip`
        // items, so a re-fetch that comes back shorter than that has broken the
        // assumption the cursor was minted under — the remote paged differently,
        // or its data moved.
        //
        // Skipping the whole page would be the quiet failure: `entries` comes
        // back empty, `collect_page` advances to the page after this one, and
        // every row between the resume point and the end of this page is never
        // served. Restarting the page instead repeats rows the client has
        // already seen, which it can see happening. That is the same trade
        // `RemoteCursor::parse` makes for a token it does not recognise.
        let skip = if resume.skip > 0 && resume.skip >= total {
            tracing::warn!(
                skip = resume.skip,
                returned = total,
                "A mounted catalog returned fewer rows than the position being resumed to. \
                 Restarting this page rather than stepping over the rows in it."
            );
            0
        } else {
            resume.skip
        };

        let mut entries = Vec::with_capacity(total.saturating_sub(skip).min(limit));

        for (index, item) in items.into_iter().enumerate().skip(skip).take(limit) {
            // The last item of a remote page is best resumed with the remote's
            // own next-page token: it says the same thing as "skip this whole
            // page" and costs no re-fetch. Every other position has no token of
            // its own, so it is named by (this page's token, how far into it).
            let cursor = match (index + 1 == total, &next_token) {
                (true, Some(token)) => RemoteCursor::start_of(token),
                _ => resume.at(index + 1),
            };
            entries.push(Entry { cursor, item });
        }

        Page {
            entries,
            next: next_token.as_deref().map(RemoteCursor::start_of),
        }
    }

    /// Fetches a table's `loadTable` response, or `None` if the remote says it
    /// is not there.
    async fn load_table_response(&self, table: &TableIdent) -> Result<Option<LoadTableResponse>> {
        let path = format!(
            "/v1/namespaces/{}/tables/{}",
            Self::encode_namespace(table.namespace()),
            encode_segment(table.name())
        );
        self.get::<LoadTableResponse>(&path).await
    }

    /// Decodes the identifiers of a table or view listing.
    fn identifiers(remote: Vec<RemoteIdentifier>) -> Result<Vec<TableIdent>> {
        remote
            .into_iter()
            .map(|identifier| {
                Ok(TableIdent::new(
                    NamespaceIdent::from_vec(identifier.namespace)?,
                    identifier.name,
                ))
            })
            .collect()
    }

    /// Everything a mutating call answers with.
    fn read_only(operation: &str) -> Error {
        Error::new(
            ErrorKind::FeatureUnsupported,
            format!(
                "This is a federated mount over a remote catalog, which Rustberg serves \
                 read-only. {operation} must be performed against the catalog that owns it."
            ),
        )
    }
}

/// Builds a query string, or an empty one when there is nothing to send.
/// Largest response body accepted from a mounted catalog.
///
/// A `rest` mount is somebody else's catalog, so its response is untrusted input
/// on the request path of every call into that subtree. `Response::json` reads
/// to the end of the stream, so without a ceiling a remote that answers
/// `Content-Length: 40GB` — or lies about the length and keeps writing — takes
/// the whole server down, and there is no engine or client involved to blame.
///
/// The bound is generous by the standards of what actually crosses this hop: a
/// page of identifiers is kilobytes, and the largest thing here is one table's
/// metadata document, which is megabytes only after a long snapshot history.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Reads a JSON body, refusing one larger than [`MAX_RESPONSE_BYTES`].
///
/// Read chunk by chunk rather than through `Response::json`, which allocates
/// whatever arrives before anything gets to look at it — the check has to happen
/// while the body is still being read, or it is a report rather than a limit.
async fn read_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    what: &str,
) -> Result<T> {
    let mut body: Vec<u8> = Vec::new();

    loop {
        let chunk = response.chunk().await.map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Reading the mounted catalog's response failed ({what}): {e}"),
            )
        })?;
        let Some(chunk) = chunk else { break };

        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Error::new(
                ErrorKind::Unexpected,
                format!(
                    "The mounted catalog's response to {what} is larger than \
                     {MAX_RESPONSE_BYTES} bytes and was not read."
                ),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|e| {
        Error::new(
            ErrorKind::Unexpected,
            format!("Malformed response from the mounted catalog ({what}): {e}"),
        )
    })
}

fn encode_query(pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }

    let mut out = String::from("?");
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&encode_segment(key));
        out.push('=');
        out.push_str(&encode_segment(value));
    }
    out
}

/// Percent-encodes a path segment.
///
/// Namespaces contain a unit separator and may contain any Unicode; leaving them
/// raw would produce a URL the remote parses differently or rejects.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
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
impl CatalogStore for RestCatalog {
    // ── Namespaces ──────────────────────────────────────────────────────

    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: &PageRequest,
    ) -> Result<Page<NamespaceIdent>> {
        let resume = RemoteCursor::parse(page.after.as_deref());
        let mut query = Self::page_query(page, &resume);
        if let Some(parent) = parent {
            query.push((
                "parent",
                parent.as_ref().join(&NAMESPACE_SEPARATOR.to_string()),
            ));
        }

        let Some(response) = self
            .get_with::<ListNamespacesResponse>("/v1/namespaces", &query)
            .await?
        else {
            return Ok(Page::empty());
        };

        let mut namespaces = Vec::with_capacity(response.namespaces.len());
        for parts in response.namespaces {
            namespaces.push(NamespaceIdent::from_vec(parts)?);
        }

        Ok(Self::repage(
            namespaces,
            response.next_page_token,
            &resume,
            page.effective_limit(),
        ))
    }

    async fn create_namespace(
        &self,
        _namespace: &NamespaceIdent,
        _properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        Err(Self::read_only("Creating a namespace"))
    }

    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        let path = format!("/v1/namespaces/{}", Self::encode_namespace(namespace));

        let Some(response) = self.get::<GetNamespaceResponse>(&path).await? else {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join("."),
            ));
        };

        Ok(Namespace::with_properties(
            NamespaceIdent::from_vec(response.namespace)?,
            response.properties,
        ))
    }

    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        let path = format!("/v1/namespaces/{}", Self::encode_namespace(namespace));
        Ok(self.get::<GetNamespaceResponse>(&path).await?.is_some())
    }

    async fn update_namespace(
        &self,
        _namespace: &NamespaceIdent,
        _properties: HashMap<String, String>,
    ) -> Result<()> {
        Err(Self::read_only("Updating namespace properties"))
    }

    async fn drop_namespace(&self, _namespace: &NamespaceIdent) -> Result<()> {
        Err(Self::read_only("Dropping a namespace"))
    }

    // ── Tables ──────────────────────────────────────────────────────────

    async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        let path = format!(
            "/v1/namespaces/{}/tables",
            Self::encode_namespace(namespace)
        );

        let resume = RemoteCursor::parse(page.after.as_deref());
        let Some(response) = self
            .get_with::<ListTabularsResponse>(&path, &Self::page_query(page, &resume))
            .await?
        else {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join("."),
            ));
        };

        Ok(Self::repage(
            Self::identifiers(response.identifiers)?,
            response.next_page_token,
            &resume,
            page.effective_limit(),
        ))
    }

    async fn create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
        Err(Self::read_only("Creating a table"))
    }

    async fn stage_create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
        Err(Self::read_only("Staged table creation"))
    }

    async fn metadata_pointer(&self, table: &TableIdent) -> Result<Option<String>> {
        // A remote has no cheaper way to answer this than a full load — the
        // spec has no pointer-only endpoint — so this is the one backend where
        // the shortcut saves nothing. It is still correct, and the local
        // backends where it does save are the common case.
        Ok(self
            .load_table_response(table)
            .await?
            .and_then(|response| response.metadata_location))
    }

    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        let Some(response) = self.load_table_response(table).await? else {
            return Err(Error::new(ErrorKind::TableNotFound, format!("{table}")));
        };

        let mut builder = Table::builder()
            .runtime(self.runtime.clone())
            .identifier(table.clone())
            .metadata(response.metadata)
            .file_io(self.file_io.clone());

        if let Some(location) = response.metadata_location {
            builder = builder.metadata_location(location);
        }

        builder.build()
    }

    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        // Only a `404` is "no". An unreachable or erroring remote propagates,
        // because reporting a table as absent during an outage is worse than
        // reporting the outage: a client told the table is gone may recreate
        // it, and an ownership lookup told a namespace is gone answers `404` to
        // a caller whose grant is intact.
        Ok(self.load_table_response(table).await?.is_some())
    }

    async fn register_table(&self, _: &TableIdent, _: String) -> Result<Table> {
        Err(Self::read_only("Registering a table"))
    }

    async fn commit_table(
        &self,
        _: &TableIdent,
        _: Vec<TableRequirement>,
        _: Vec<TableUpdate>,
    ) -> Result<Table> {
        Err(Self::read_only("Committing to a table"))
    }

    async fn commit_tables_atomic(
        &self,
        _: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        Err(Self::read_only("A multi-table transaction"))
    }

    async fn rename_table(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
        Err(Self::read_only("Renaming a table"))
    }

    async fn drop_table(&self, _: &TableIdent) -> Result<()> {
        Err(Self::read_only("Dropping a table"))
    }

    async fn purge_table(&self, _: &TableIdent) -> Result<()> {
        Err(Self::read_only("Purging a table"))
    }

    // ── Views ───────────────────────────────────────────────────────────

    async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        if !self.capabilities.views {
            return Ok(Page::empty());
        }

        let path = format!("/v1/namespaces/{}/views", Self::encode_namespace(namespace));

        let resume = RemoteCursor::parse(page.after.as_deref());
        let Some(response) = self
            .get_with::<ListTabularsResponse>(&path, &Self::page_query(page, &resume))
            .await?
        else {
            return Ok(Page::empty());
        };

        Ok(Self::repage(
            Self::identifiers(response.identifiers)?,
            response.next_page_token,
            &resume,
            page.effective_limit(),
        ))
    }

    async fn view_exists(&self, view: &TableIdent) -> Result<bool> {
        if !self.capabilities.views {
            return Ok(false);
        }
        let path = format!(
            "/v1/namespaces/{}/views/{}",
            Self::encode_namespace(view.namespace()),
            encode_segment(view.name())
        );
        Ok(self.get::<LoadViewResponse>(&path).await?.is_some())
    }

    async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)> {
        if !self.capabilities.views {
            return Err(Error::new(
                ErrorKind::FeatureUnsupported,
                "The mounted catalog does not serve views",
            ));
        }

        let path = format!(
            "/v1/namespaces/{}/views/{}",
            Self::encode_namespace(view.namespace()),
            encode_segment(view.name())
        );

        let Some(response) = self.get::<LoadViewResponse>(&path).await? else {
            return Err(Error::new(ErrorKind::TableNotFound, format!("{view}")));
        };

        Ok((response.metadata_location, response.metadata))
    }

    async fn register_view(&self, _: &TableIdent, _: String) -> Result<(String, ViewMetadata)> {
        Err(Self::read_only("Registering a view"))
    }

    async fn create_view(&self, _: &TableIdent, _: ViewMetadata) -> Result<(String, ViewMetadata)> {
        Err(Self::read_only("Creating a view"))
    }

    async fn update_view(
        &self,
        _: &TableIdent,
        _: &str,
        _: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        Err(Self::read_only("Updating a view"))
    }

    async fn drop_view(&self, _: &TableIdent) -> Result<()> {
        Err(Self::read_only("Dropping a view"))
    }

    async fn rename_view(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
        Err(Self::read_only("Renaming a view"))
    }

    // ── Operations ──────────────────────────────────────────────────────

    async fn warehouse_for(&self, _namespace: &NamespaceIdent) -> Option<String> {
        // A remote mount stores nothing of its own, and it is read-only, so no
        // client-supplied location is ever recorded through it.
        None
    }

    /// A remote mount stores nothing of its own, so it lays nothing out.
    fn namespace_prefix_for(&self, _namespace: &NamespaceIdent) -> Option<String> {
        None
    }

    /// What the remote's own `/v1/config` said it serves, negotiated once when
    /// the mount was opened — never assumed, and never widened by what this
    /// server can do.
    fn capabilities_for(&self, _namespace: Option<&NamespaceIdent>) -> Capabilities {
        self.capabilities()
    }

    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        let started = std::time::Instant::now();

        match self.send("/v1/config", &[]).await {
            Ok(response) if response.status().is_success() => Ok(StorageHealthStatus::healthy(
                "rest",
                started.elapsed().as_millis() as u64,
            )),
            Ok(response) => Ok(StorageHealthStatus::unhealthy(
                "rest",
                format!("The mounted catalog answered {}", response.status()),
            )),
            Err(e) => Ok(StorageHealthStatus::unhealthy("rest", e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(parts: &[&str]) -> NamespaceIdent {
        NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[test]
    fn a_namespace_is_one_encoded_path_segment() {
        // The unit separator must be percent-encoded, or the remote sees two
        // path segments where the spec says one.
        assert_eq!(RestCatalog::encode_namespace(&ns(&["a", "b"])), "a%1Fb");
        assert_eq!(RestCatalog::encode_namespace(&ns(&["plain"])), "plain");
    }

    #[test]
    fn reserved_characters_are_encoded() {
        assert_eq!(encode_segment("a/b"), "a%2Fb");
        assert_eq!(encode_segment("a b"), "a%20b");
        assert_eq!(encode_segment("a?b#c"), "a%3Fb%23c");
    }

    #[test]
    fn unreserved_characters_are_left_alone() {
        assert_eq!(encode_segment("events-2024_v1.0~x"), "events-2024_v1.0~x");
    }

    #[test]
    fn non_ascii_is_encoded_as_utf8_bytes() {
        assert_eq!(encode_segment("café"), "caf%C3%A9");
    }

    #[test]
    fn an_empty_query_adds_nothing_to_the_url() {
        assert_eq!(encode_query(&[]), "");
    }

    #[test]
    fn a_query_is_encoded_and_joined() {
        let query = vec![
            ("pageSize", "10".to_string()),
            ("parent", "a\u{1F}b".to_string()),
        ];
        assert_eq!(encode_query(&query), "?pageSize=10&parent=a%1Fb");
    }

    fn ident(name: &str) -> TableIdent {
        TableIdent::new(ns(&["analytics"]), name.to_string())
    }

    #[test]
    fn paging_uses_the_spec_spelling() {
        let resume = RemoteCursor::parse(Some(&RemoteCursor::start_of("cursor-1")));
        let query = RestCatalog::page_query(&PageRequest::first(25), &resume);
        assert!(query.contains(&("pageSize", "25".to_string())));
        assert!(query.contains(&("pageToken", "cursor-1".to_string())));
    }

    #[test]
    fn a_first_page_sends_no_token() {
        let query = RestCatalog::page_query(&PageRequest::first(10), &RemoteCursor::default());
        assert!(query.iter().all(|(k, _)| *k != "pageToken"));
    }

    /// A resumed position asks the remote for the skipped rows *as well*, or the
    /// page it hands back is short by exactly the skip.
    #[test]
    fn a_skip_is_added_to_the_requested_page_size() {
        let resume = RemoteCursor {
            token: Some("t".to_string()),
            skip: 3,
        };
        let query = RestCatalog::page_query(&PageRequest::first(10), &resume);
        assert!(query.contains(&("pageSize", "13".to_string())));
    }

    #[test]
    fn a_requested_page_size_never_exceeds_the_maximum() {
        let resume = RemoteCursor {
            token: None,
            skip: 900,
        };
        let query = RestCatalog::page_query(&PageRequest::first(1000), &resume);
        assert!(query.contains(&("pageSize", crate::catalog::MAX_PAGE_SIZE.to_string())));
    }

    // ── Cursor space ─────────────────────────────────────────────────────

    #[test]
    fn a_cursor_round_trips_through_its_encoding() {
        let cursor = RemoteCursor {
            token: Some("opaque\u{1F}token".to_string()),
            skip: 7,
        };
        assert_eq!(RemoteCursor::parse(Some(&cursor.at(7))), cursor);
        assert_eq!(
            RemoteCursor::parse(Some(&RemoteCursor::start_of("tok"))),
            RemoteCursor {
                token: Some("tok".to_string()),
                skip: 0
            }
        );
    }

    /// An unrecognised cursor restarts rather than reaching the remote. Passing
    /// it through as a page token is what loses rows silently.
    #[test]
    fn an_unrecognised_cursor_restarts_the_listing() {
        assert_eq!(RemoteCursor::parse(None), RemoteCursor::default());
        assert_eq!(
            RemoteCursor::parse(Some("events")),
            RemoteCursor::default(),
            "a bare name means nothing to the remote and must not become a page token"
        );
        assert_eq!(
            RemoteCursor::parse(Some("notanumber\u{1E}tok")),
            RemoteCursor::default()
        );
    }

    /// The whole point: every cursor this adapter emits must parse back into a
    /// remote page token, never into an item name.
    #[test]
    fn every_emitted_cursor_is_a_remote_position() {
        let page = RestCatalog::repage(
            vec![ident("a"), ident("b"), ident("c")],
            Some("next-tok".to_string()),
            &RemoteCursor::default(),
            10,
        );

        for entry in &page.entries {
            let parsed = RemoteCursor::parse(Some(&entry.cursor));
            assert!(
                parsed.token.is_none() || parsed.token.as_deref() == Some("next-tok"),
                "cursor {:?} names something the remote never issued",
                entry.cursor
            );
        }
    }

    /// A remote whose page came back shorter than the resume point has broken
    /// the assumption the cursor was minted under. Stepping over the page would
    /// lose every row in it silently; restarting it repeats rows the client can
    /// see.
    #[test]
    fn a_page_that_shrank_below_the_resume_point_is_restarted_not_skipped() {
        let resume = RemoteCursor {
            token: Some("tok".to_string()),
            skip: 5,
        };

        let page = RestCatalog::repage(
            vec![ident("a"), ident("b"), ident("c")],
            Some("next-tok".to_string()),
            &resume,
            10,
        );

        assert_eq!(
            page.entries.len(),
            3,
            "every row the remote returned must be served, not stepped over"
        );
    }

    /// The ordinary resumed page: the skip is inside what came back, so it is
    /// applied exactly.
    #[test]
    fn a_resumed_page_drops_exactly_what_it_already_served() {
        let resume = RemoteCursor {
            token: Some("tok".to_string()),
            skip: 2,
        };

        let page = RestCatalog::repage(
            vec![ident("a"), ident("b"), ident("c"), ident("d")],
            None,
            &resume,
            10,
        );

        let names: Vec<String> = page.entries.iter().map(|e| e.item.name.clone()).collect();
        assert_eq!(names, vec!["c".to_string(), "d".to_string()]);
    }

    /// The last item of a page is named by the remote's own next token, so an
    /// unfiltered walk costs one round trip per page rather than re-fetching.
    #[test]
    fn the_last_item_of_a_page_uses_the_remotes_next_token() {
        let page = RestCatalog::repage(
            vec![ident("a"), ident("b")],
            Some("next-tok".to_string()),
            &RemoteCursor::default(),
            10,
        );

        assert_eq!(page.entries[0].cursor, RemoteCursor::default().at(1));
        assert_eq!(page.entries[1].cursor, RemoteCursor::start_of("next-tok"));
        assert_eq!(
            page.next.as_deref(),
            Some(&*RemoteCursor::start_of("next-tok"))
        );
    }

    /// Resuming mid-page drops exactly the rows already served, and no more.
    #[test]
    fn a_resumed_page_drops_the_rows_already_served() {
        let resume = RemoteCursor {
            token: Some("t".to_string()),
            skip: 2,
        };
        let page = RestCatalog::repage(
            vec![ident("a"), ident("b"), ident("c"), ident("d")],
            None,
            &resume,
            10,
        );

        let names: Vec<&str> = page.entries.iter().map(|e| e.item.name()).collect();
        assert_eq!(names, vec!["c", "d"]);
        assert!(
            page.next.is_none(),
            "no remote token means the listing ended"
        );
    }

    /// A page shorter than the skip is an inconsistency, not a smaller page: the
    /// skip was minted from a fetch of the *same* token that returned more rows
    /// than this. Whatever is served, the listing must keep a token so the
    /// caller does not read the short page as the end of the list.
    #[test]
    fn a_page_shorter_than_the_skip_still_advances() {
        let resume = RemoteCursor {
            token: Some("t".to_string()),
            skip: 5,
        };
        let page = RestCatalog::repage(
            vec![ident("a"), ident("b")],
            Some("next-tok".to_string()),
            &resume,
            10,
        );

        assert_eq!(
            page.next.as_deref(),
            Some(&*RemoteCursor::start_of("next-tok")),
            "without a token the caller would read this as the end of the list"
        );
        assert!(
            !page.entries.is_empty(),
            "the rows the remote did return must be served, not stepped over"
        );
    }

    /// A remote that serves views produces a mount that serves views.
    #[test]
    fn views_are_negotiated_from_the_remotes_endpoints() {
        let with_views = vec![
            "GET /v1/{prefix}/namespaces".to_string(),
            "GET /v1/{prefix}/namespaces/{namespace}/views/{view}".to_string(),
        ];
        assert!(RestCatalog::negotiate(&with_views).views);

        let without = vec![
            "GET /v1/{prefix}/namespaces".to_string(),
            "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}".to_string(),
        ];
        assert!(!RestCatalog::negotiate(&without).views);
    }

    /// A remote predating the `endpoints` field says nothing, and the spec
    /// baseline includes views — assuming otherwise would hide views that exist.
    #[test]
    fn an_empty_endpoint_list_assumes_the_baseline() {
        assert!(RestCatalog::negotiate(&[]).views);
    }

    /// Whatever the remote advertises, a mount never writes.
    #[test]
    fn negotiation_never_produces_a_writable_mount() {
        let everything = vec![
            "POST /v1/{prefix}/namespaces".to_string(),
            "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}".to_string(),
            "GET /v1/{prefix}/namespaces/{namespace}/views/{view}".to_string(),
        ];
        let negotiated = RestCatalog::negotiate(&everything);

        assert!(!negotiated.write);
        assert!(!negotiated.multi_table_commit);
        assert!(!negotiated.register);
        assert!(!negotiated.stage_create);
        assert!(!negotiated.purge);
    }

    /// A refusal must say where the write should go instead.
    #[test]
    fn a_read_only_refusal_is_actionable() {
        let err = RestCatalog::read_only("Dropping a table");
        assert_eq!(err.kind(), ErrorKind::FeatureUnsupported);
        assert!(err.message().contains("Dropping a table"));
        assert!(err.message().contains("catalog that owns it"));
    }
}
