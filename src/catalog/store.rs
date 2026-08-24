//! The catalog trait Rustberg serves, and the paging vocabulary it uses.
//!
//! # Why this is not `iceberg::Catalog`
//!
//! `iceberg::Catalog` is a **client** trait: it models talking to a catalog from
//! the outside. Rustberg is the catalog. The two need different shapes, and the
//! mismatch is not cosmetic:
//!
//! - **Commits are unreachable through it.** The only commit method is
//!   `update_table(TableCommit)`, and `TableCommit` has private fields with a
//!   `pub(crate)` build method. That is deliberate upstream — the maintainers
//!   declined to open it, on the grounds that callers should use `Transaction`,
//!   which derives requirements itself. A REST server is handed
//!   `(requirements, updates)` verbatim and must apply exactly those, so
//!   `Transaction` is the wrong direction. Implementing the trait therefore
//!   forced a `update_table` method that no caller could reach.
//! - **It has no views.** Not one view method exists on it.
//! - **It has no paging.** `list_tables` returns `Vec<TableIdent>`, so a backend
//!   cannot return a page even when its storage is a sorted index that could
//!   answer one directly. Paging then has to happen in the handler, over the
//!   whole materialised list.
//!
//! Implementing it bought nothing in return: nothing consumes Rustberg's
//! backends *as* an `iceberg::Catalog`. So this trait replaces it, and the
//! `iceberg` crate is used for what it is excellent at — the spec types
//! ([`Table`], [`TableMetadata`], [`TableIdent`], [`ViewMetadata`], `FileIO`,
//! requirement checking).
//!
//! Federation is unaffected and stays open: a federated mount wraps somebody
//! else's `iceberg::Catalog` *client* behind this trait. Such a mount is
//! read-only and reports no view support — which is the honest capability
//! statement, and exactly what the upstream constraint implies.
//!
//! [`TableMetadata`]: iceberg::spec::TableMetadata

use std::collections::HashMap;
use std::fmt::Debug;

/// Joins namespace levels inside a stored key, and separates a namespace from a
/// name.
///
/// Re-exported from [`crate::names`] rather than defined here. Both backends
/// have to agree on them character for character — the conformance tests assert
/// the two page in the same order, and a per-file constant makes that assertion
/// vacuous — and so do the four subsystems *outside* the registry that build the
/// same string: the path a request arrives on, the Cedar entity id a policy
/// names, the `rest` mount's wire path, and the signer endpoint. One definition,
/// in the module that explains why a validated name can never contain either.
pub use crate::names::{NAME_SEPARATOR, PART_SEPARATOR};

use async_trait::async_trait;
use iceberg::spec::ViewMetadata;
use iceberg::table::Table;
use iceberg::{
    Namespace, NamespaceIdent, Result, TableCreation, TableIdent, TableRequirement, TableUpdate,
};

use super::capabilities::Capabilities;

/// Reports a stale v3 row-lineage assignment as the commit conflict it is.
///
/// # What goes wrong without this
///
/// Format version 3 gives every row an id. The table carries `next-row-id`, a
/// writer stamps its snapshot with `first-row-id` taken from the metadata it
/// read, and the commit advances the counter by the rows it added. Two writers
/// that read the same metadata therefore stamp the *same* `first-row-id`, and
/// the second one to arrive is stale.
///
/// That is a lost race, and the answer to a lost race is `409
/// CommitFailedException`: the client refreshes, re-derives `first-row-id` from
/// the new `next-row-id`, and commits again. `iceberg-rust`'s metadata builder
/// catches the condition — correctly — but reports it as `DataInvalid`, which
/// this server maps to `400`. A `400` says *your request is malformed*, and no
/// client retries one. Concurrent writers on a v3 table would see their second
/// write rejected permanently, with a message about row ids.
///
/// # Why the condition is re-checked here rather than the message re-read
///
/// Matching upstream's error text would break silently the first time it was
/// reworded. The precondition is one comparison and is written in the spec, so
/// it is asked directly. Upstream still enforces it either way — if this check
/// ever drifted, the outcome would be the old `400`, not an unsafe accept.
///
/// # Errors
///
/// [`ErrorKind::CatalogCommitConflicts`] naming both row ids, or nothing when
/// the commit is not a stale v3 snapshot.
pub(crate) fn reject_stale_row_lineage(
    ident: &TableIdent,
    base: &iceberg::spec::TableMetadata,
    updates: &[TableUpdate],
) -> Result<()> {
    if base.format_version() < iceberg::spec::FormatVersion::V3 {
        return Ok(());
    }

    for update in updates {
        if let TableUpdate::AddSnapshot { snapshot } = update
            && let Some((first_row_id, _added)) = snapshot.row_range()
            && first_row_id < base.next_row_id()
        {
            return Err(iceberg::Error::new(
                iceberg::ErrorKind::CatalogCommitConflicts,
                format!(
                    "Commit conflict on table {ident}: the snapshot assigns row ids from                      {first_row_id}, but another writer has already taken them — this table                      is at {}. Refresh the table and commit again; the new snapshot must                      start at the table's current next-row-id.",
                    base.next_row_id()
                ),
            ));
        }
    }

    Ok(())
}

/// Largest page a caller may ask for.
///
/// Bounds the work one request can cause. A caller wanting more pages more
/// cheaply raises `page_size` up to this; beyond it, the answer is more requests.
pub const MAX_PAGE_SIZE: usize = 1000;

/// Page size used when a request does not ask for one.
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// Where to resume a listing, and how much to return.
///
/// The cursor is the **last key of the previous page**, in the backend's own sort
/// order, so resuming is a seek rather than a scan-and-skip. That is what makes
/// paging cost the same on page one thousand as on page one.
#[derive(Debug, Clone)]
pub struct PageRequest {
    /// Resume strictly after this key. `None` starts at the beginning.
    pub after: Option<String>,
    /// Maximum items to return. Clamped to [`MAX_PAGE_SIZE`].
    pub limit: usize,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            after: None,
            limit: DEFAULT_PAGE_SIZE,
        }
    }
}

impl PageRequest {
    /// A request for the first page of `limit` items.
    pub fn first(limit: usize) -> Self {
        Self {
            after: None,
            limit: limit.clamp(1, MAX_PAGE_SIZE),
        }
    }

    /// A request resuming after `cursor`.
    pub fn after(cursor: impl Into<String>, limit: usize) -> Self {
        Self {
            after: Some(cursor.into()),
            limit: limit.clamp(1, MAX_PAGE_SIZE),
        }
    }

    /// The limit, clamped to the permitted range.
    ///
    /// Applied by the backend rather than trusted from the caller, so a bad limit
    /// cannot turn into an unbounded scan.
    pub fn effective_limit(&self) -> usize {
        self.limit.clamp(1, MAX_PAGE_SIZE)
    }

    /// How many rows to fetch to know whether another page exists.
    ///
    /// One more than the limit: if the extra row materialises there is more to
    /// come, and it is discarded. This avoids a second count query and, more
    /// importantly, avoids reporting a next-page cursor for a page that turns out
    /// to be the last — which makes a client fetch one guaranteed-empty page.
    pub fn probe_limit(&self) -> usize {
        self.effective_limit().saturating_add(1)
    }
}

/// One item of a listing, with the cursor that resumes immediately after it.
///
/// The cursor travels with the item because a caller may stop part-way through a
/// page — the authorization filter does exactly that, keeping items until the
/// page is full. Resuming then has to name the last item *kept*, not the last
/// item the backend returned, or the ones in between are skipped silently.
#[derive(Debug, Clone)]
pub struct Entry<T> {
    /// Backend key of this item; resuming after it yields the next one.
    pub cursor: String,
    /// The item itself.
    pub item: T,
}

/// One page of results, and where to resume.
#[derive(Debug, Clone)]
pub struct Page<T> {
    /// Items in this page, in the backend's sort order.
    pub entries: Vec<Entry<T>>,
    /// Cursor for the next page, absent when the source is exhausted.
    ///
    /// Absent means *there is definitively nothing more*. Present means there may
    /// be — a caller must keep going until it is absent rather than stopping on a
    /// short or empty page, since filtering can empty a page whose successors
    /// still hold matches.
    pub next: Option<String>,
}

impl<T> Page<T> {
    /// An empty, exhausted page.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            next: None,
        }
    }

    /// Builds a page from rows fetched with [`PageRequest::probe_limit`].
    ///
    /// Truncates to the real limit and reports a cursor only when the probe
    /// proved another row exists.
    pub fn from_probe(mut rows: Vec<Entry<T>>, request: &PageRequest) -> Self {
        let limit = request.effective_limit();
        if rows.len() > limit {
            rows.truncate(limit);
            let next = rows.last().map(|e| e.cursor.clone());
            Self {
                entries: rows,
                next,
            }
        } else {
            Self {
                entries: rows,
                next: None,
            }
        }
    }

    /// True when the source is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.next.is_none()
    }

    /// The items, discarding cursors.
    pub fn into_items(self) -> Vec<T> {
        self.entries.into_iter().map(|e| e.item).collect()
    }

    /// Maps the items, preserving cursors.
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            entries: self
                .entries
                .into_iter()
                .map(|e| Entry {
                    cursor: e.cursor,
                    item: f(e.item),
                })
                .collect(),
            next: self.next,
        }
    }
}

/// Health of the backing metadata store.
#[derive(Debug, Clone)]
pub struct StorageHealthStatus {
    /// Backend type, e.g. `redb`, `postgres`.
    pub backend_type: String,
    /// Whether the backend answered.
    pub healthy: bool,
    /// Round-trip time of the check.
    pub latency_ms: u64,
    /// Why it is unhealthy, when it is.
    pub message: Option<String>,
}

impl StorageHealthStatus {
    /// A healthy result.
    pub fn healthy(backend_type: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            backend_type: backend_type.into(),
            healthy: true,
            latency_ms,
            message: None,
        }
    }

    /// An unhealthy result.
    pub fn unhealthy(backend_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            healthy: false,
            latency_ms: 0,
            message: Some(message.into()),
        }
    }
}

/// The catalog Rustberg serves: namespaces, tables, views, and commits.
///
/// Errors are [`iceberg::Error`], because its `ErrorKind` already names exactly
/// the conditions the REST spec distinguishes — `TableNotFound`,
/// `NamespaceAlreadyExists`, `CatalogCommitConflicts` — and
/// `From<iceberg::Error> for AppError` maps them to status codes by kind. A
/// bespoke error enum would restate that vocabulary with nothing added.
#[async_trait]
pub trait CatalogStore: Debug + Send + Sync {
    // ── Namespaces ──────────────────────────────────────────────────────

    /// Lists namespaces directly beneath `parent`, or top-level ones when it is
    /// `None`.
    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: &PageRequest,
    ) -> Result<Page<NamespaceIdent>>;

    /// Creates a namespace with the given properties.
    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace>;

    /// Loads a namespace and its properties.
    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace>;

    /// Returns true if the namespace exists.
    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool>;

    /// Replaces a namespace's properties wholesale.
    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()>;

    /// Drops a namespace, which must be empty.
    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()>;

    // ── Tables ──────────────────────────────────────────────────────────

    /// Lists tables in a namespace.
    async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>>;

    /// Creates a table, writing its first metadata file.
    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table>;

    /// Builds a table's first metadata without making the table visible.
    ///
    /// This is `stage-create`, and it is how Spark performs `CREATE TABLE AS
    /// SELECT`: the engine needs somewhere to write data files *before* the
    /// table exists, then commits the whole thing atomically. A staged table is
    /// absent from every listing, does not resolve to a load, and does not
    /// reserve its name — two clients may stage the same name, and the first to
    /// commit wins.
    ///
    /// It becomes real through [`commit_table`](Self::commit_table) carrying a
    /// [`TableRequirement::NotExist`] requirement. Until then it is a metadata
    /// file and a note to self.
    async fn stage_create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table>;

    /// Loads a table's current metadata.
    async fn load_table(&self, table: &TableIdent) -> Result<Table>;

    /// The table's current metadata *pointer*, without reading the file.
    ///
    /// A registry lookup and nothing else. [`load_table`](Self::load_table) also
    /// fetches and parses the metadata document, which is the expensive part and
    /// is pure waste when the caller only needs to know *which version* is
    /// current.
    ///
    /// That is exactly the conditional-load case: an `ETag` is derived from this
    /// pointer, so answering `304 Not Modified` needs the pointer and never the
    /// document. Deriving the tag from a full load made a `304` cost the same as
    /// a `200`, which is the one thing conditional loading exists to avoid.
    ///
    /// `None` when the table does not exist.
    async fn metadata_pointer(&self, table: &TableIdent) -> Result<Option<String>>;

    /// Returns true if the table exists.
    async fn table_exists(&self, table: &TableIdent) -> Result<bool>;

    /// Adopts metadata that already exists in storage.
    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table>;

    /// Applies `requirements` and `updates` to one table.
    ///
    /// This is the method `iceberg::Catalog` cannot express, and the reason this
    /// trait exists. Requirements are checked against current metadata; if any
    /// fails, the commit is rejected with `CatalogCommitConflicts` and the client
    /// retries.
    async fn commit_table(
        &self,
        table: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table>;

    /// Commits several tables atomically: either all advance or none do.
    ///
    /// A backend that cannot span tables in one transaction must reject a
    /// multi-table request rather than degrade into a sequence that can be
    /// observed half-applied.
    async fn commit_tables_atomic(
        &self,
        commits: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>>;

    /// Renames a table, possibly across namespaces.
    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()>;

    /// Drops a table, leaving its data files in place.
    async fn drop_table(&self, table: &TableIdent) -> Result<()>;

    /// Drops a table and deletes the files its metadata references.
    async fn purge_table(&self, table: &TableIdent) -> Result<()>;

    // ── Views ───────────────────────────────────────────────────────────
    //
    // First-class here rather than in a side store, so a view shares a
    // transaction domain with tables: a namespace cannot be dropped while it
    // still holds views, and a view's metadata is written the same way a
    // table's is.

    /// Lists views in a namespace.
    async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>>;

    /// Returns true if the view exists.
    async fn view_exists(&self, view: &TableIdent) -> Result<bool>;

    /// Loads a view's metadata and the location it was read from.
    async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)>;

    /// Adopts view metadata that already exists in storage.
    ///
    /// The mirror of [`register_table`](Self::register_table): the metadata file
    /// is read, never rewritten, so the view's version history survives being
    /// moved between catalogs.
    async fn register_view(
        &self,
        view: &TableIdent,
        metadata_location: String,
    ) -> Result<(String, ViewMetadata)>;

    /// Creates a view, writing its metadata file and registering the pointer.
    async fn create_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)>;

    /// Replaces a view's metadata, writing a new file and swapping the pointer
    /// **only if** it still points where the caller last read.
    ///
    /// # Why the expected location is a parameter
    ///
    /// A view commit is a read-modify-write that spans this trait: the handler
    /// loads the metadata, applies the updates the client sent, and hands back a
    /// finished document. A table commit does not — it hands over
    /// `(requirements, updates)` and the *store* reads the base, so its
    /// compare-and-swap witnesses the same read the updates were applied to.
    ///
    /// Without this parameter a view store can only compare against a read of
    /// its own, taken after the handler's. That is not a compare-and-swap, it is
    /// a re-read: a commit landing between the handler's load and the store's
    /// read is confirmed rather than detected, and the caller's updates
    /// overwrite it. Invariant 2 says concurrent writers never lose an update,
    /// and views are the path where that is easiest to get wrong precisely
    /// because the pointer swap *looks* atomic on its own.
    ///
    /// So the witness travels with the request: this is the `metadata_location`
    /// [`Self::load_view`] returned, and a store that finds anything else
    /// answers [`ErrorKind::CatalogCommitConflicts`] so the client refreshes and
    /// retries.
    ///
    /// [`ErrorKind::CatalogCommitConflicts`]: iceberg::ErrorKind::CatalogCommitConflicts
    async fn update_view(
        &self,
        view: &TableIdent,
        expected_metadata_location: &str,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)>;

    /// Drops a view.
    async fn drop_view(&self, view: &TableIdent) -> Result<()>;

    /// Renames a view.
    async fn rename_view(&self, src: &TableIdent, dest: &TableIdent) -> Result<()>;

    // ── Operations ──────────────────────────────────────────────────────

    /// The warehouse that governs `namespace`.
    ///
    /// Client-supplied locations are confined to the warehouse, and under
    /// federation "the warehouse" is not one place: each mount has its own, and
    /// that is the point of mounting. Checking every location against a single
    /// warehouse would reject legitimate tables in every mount whose data lives
    /// somewhere else — which is all of them.
    ///
    /// A backend with no warehouse of its own returns `None`, and the caller
    /// falls back to the server's. A federated mount over a remote catalog is
    /// the case: it stores nothing itself.
    async fn warehouse_for(&self, namespace: &NamespaceIdent) -> Option<String>;

    /// Where this backend keeps `namespace`'s resources: `<warehouse>/<levels…>`.
    ///
    /// The counterpart to [`warehouse_for`](Self::warehouse_for), and it has to
    /// route the same way. A mount's name is a segment of the namespace *here*
    /// and not a segment of the path *there*, so a caller that built this prefix
    /// from the federated namespace would bound a mounted table to
    /// `…/prod/db/events` while the mount keeps it at `…/db/events` — and every
    /// register into a mount would fail a check against a path nothing uses.
    ///
    /// `None` from a backend that stores nothing, which is a `rest` mount. It
    /// refuses every write on capability grounds long before a location is
    /// checked, so the caller falls back to this server's own layout rather than
    /// inventing a bound for storage nobody here manages.
    fn namespace_prefix_for(&self, namespace: &NamespaceIdent) -> Option<String>;

    /// What this backend can do for `namespace`.
    ///
    /// Distinct from the set `GET /v1/config` publishes, which is the
    /// **intersection** across every mount — the only promise a single
    /// `endpoints` list can honestly make (see
    /// [`capabilities`](super::capabilities)). A *refusal* is per-request, so a
    /// handler asks this one: one read-only mount must remove an operation from
    /// what the catalog advertises without removing it from the native tables
    /// beside it.
    ///
    /// `None` asks about the backend as a whole rather than about one
    /// namespace, which is what folding the advertised set needs. It is a
    /// separate case rather than an empty [`NamespaceIdent`] because there is no
    /// such value — `iceberg` refuses one — and because "every namespace" and
    /// "this namespace" are genuinely different questions to a router.
    ///
    /// Synchronous, and deliberately: a capability is a fact the process
    /// already holds, negotiated once at startup. A capability check that could
    /// touch the network would be one more thing to fail on the request path.
    fn capabilities_for(&self, namespace: Option<&NamespaceIdent>) -> Capabilities;

    /// Checks that the metadata store is reachable, for `/ready`.
    async fn storage_health_check(&self) -> Result<StorageHealthStatus>;
}

/// A [`CatalogStore`] whose every operation fails.
///
/// Exists so a test can ask what the layers above do when the backend is
/// *unreachable*, which must not give the same answer as a resource being
/// *absent*. See [`crate::catalog::v1::guard`].
#[derive(Debug)]
pub struct UnreachableStore;

impl UnreachableStore {
    fn down<T>() -> Result<T> {
        Err(iceberg::Error::new(
            iceberg::ErrorKind::Unexpected,
            "the metadata store is unreachable",
        ))
    }
}

#[async_trait]
impl CatalogStore for UnreachableStore {
    async fn list_namespaces(
        &self,
        _: Option<&NamespaceIdent>,
        _: &PageRequest,
    ) -> Result<Page<NamespaceIdent>> {
        Self::down()
    }
    async fn create_namespace(
        &self,
        _: &NamespaceIdent,
        _: HashMap<String, String>,
    ) -> Result<Namespace> {
        Self::down()
    }
    async fn get_namespace(&self, _: &NamespaceIdent) -> Result<Namespace> {
        Self::down()
    }
    async fn namespace_exists(&self, _: &NamespaceIdent) -> Result<bool> {
        Self::down()
    }
    async fn update_namespace(&self, _: &NamespaceIdent, _: HashMap<String, String>) -> Result<()> {
        Self::down()
    }
    async fn drop_namespace(&self, _: &NamespaceIdent) -> Result<()> {
        Self::down()
    }
    async fn list_tables(&self, _: &NamespaceIdent, _: &PageRequest) -> Result<Page<TableIdent>> {
        Self::down()
    }
    async fn create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
        Self::down()
    }
    async fn stage_create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
        Self::down()
    }
    async fn load_table(&self, _: &TableIdent) -> Result<Table> {
        Self::down()
    }
    async fn metadata_pointer(&self, _: &TableIdent) -> Result<Option<String>> {
        Self::down()
    }
    async fn table_exists(&self, _: &TableIdent) -> Result<bool> {
        Self::down()
    }
    async fn register_table(&self, _: &TableIdent, _: String) -> Result<Table> {
        Self::down()
    }
    async fn commit_table(
        &self,
        _: &TableIdent,
        _: Vec<TableRequirement>,
        _: Vec<TableUpdate>,
    ) -> Result<Table> {
        Self::down()
    }
    async fn commit_tables_atomic(
        &self,
        _: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        Self::down()
    }
    async fn rename_table(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
        Self::down()
    }
    async fn drop_table(&self, _: &TableIdent) -> Result<()> {
        Self::down()
    }
    async fn purge_table(&self, _: &TableIdent) -> Result<()> {
        Self::down()
    }
    async fn list_views(&self, _: &NamespaceIdent, _: &PageRequest) -> Result<Page<TableIdent>> {
        Self::down()
    }
    async fn view_exists(&self, _: &TableIdent) -> Result<bool> {
        Self::down()
    }
    async fn load_view(&self, _: &TableIdent) -> Result<(String, ViewMetadata)> {
        Self::down()
    }
    async fn register_view(&self, _: &TableIdent, _: String) -> Result<(String, ViewMetadata)> {
        Self::down()
    }
    async fn create_view(&self, _: &TableIdent, _: ViewMetadata) -> Result<(String, ViewMetadata)> {
        Self::down()
    }
    async fn update_view(
        &self,
        _: &TableIdent,
        _: &str,
        _: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        Self::down()
    }
    async fn drop_view(&self, _: &TableIdent) -> Result<()> {
        Self::down()
    }
    async fn rename_view(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
        Self::down()
    }
    async fn warehouse_for(&self, _: &NamespaceIdent) -> Option<String> {
        None
    }
    fn namespace_prefix_for(&self, _: &NamespaceIdent) -> Option<String> {
        None
    }
    /// Everything, so a caller's refusal comes from the store being down rather
    /// than from a capability that was never the reason.
    fn capabilities_for(&self, _: Option<&NamespaceIdent>) -> Capabilities {
        Capabilities::full()
    }
    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        Ok(StorageHealthStatus::unhealthy("unreachable", "test double"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(keys: &[&str]) -> Vec<Entry<&'static str>> {
        keys.iter()
            .map(|k| Entry {
                cursor: k.to_string(),
                item: Box::leak(k.to_string().into_boxed_str()) as &'static str,
            })
            .collect()
    }

    #[test]
    fn limit_is_clamped_rather_than_trusted() {
        // A caller-supplied limit must not become an unbounded scan.
        assert_eq!(PageRequest::first(10_000).effective_limit(), MAX_PAGE_SIZE);
        assert_eq!(PageRequest::first(0).effective_limit(), 1);
        assert_eq!(PageRequest::first(50).effective_limit(), 50);
    }

    #[test]
    fn probe_fetches_one_more_than_the_limit() {
        assert_eq!(PageRequest::first(50).probe_limit(), 51);
    }

    /// A full page with nothing after it must report no cursor, or the client
    /// fetches a guaranteed-empty page to discover the end.
    #[test]
    fn an_exactly_full_page_reports_no_cursor() {
        let request = PageRequest::first(3);
        let page = Page::from_probe(entries(&["a", "b", "c"]), &request);
        assert_eq!(page.entries.len(), 3);
        assert!(page.is_exhausted(), "no further rows were probed");
    }

    #[test]
    fn an_overfull_probe_truncates_and_reports_a_cursor() {
        let request = PageRequest::first(3);
        // The backend returned probe_limit() = 4 rows, so a fourth exists.
        let page = Page::from_probe(entries(&["a", "b", "c", "d"]), &request);
        assert_eq!(page.entries.len(), 3);
        assert_eq!(
            page.next.as_deref(),
            Some("c"),
            "the cursor is the last item returned, not the probed one"
        );
    }

    #[test]
    fn a_short_page_is_the_last_page() {
        let page = Page::from_probe(entries(&["a"]), &PageRequest::first(10));
        assert_eq!(page.entries.len(), 1);
        assert!(page.is_exhausted());
    }

    #[test]
    fn an_empty_page_is_the_last_page() {
        let page: Page<&str> = Page::from_probe(Vec::new(), &PageRequest::first(10));
        assert!(page.entries.is_empty());
        assert!(page.is_exhausted());
    }

    /// Each entry carries its own cursor, so a caller that stops part-way through
    /// resumes after the item it kept rather than after the whole batch.
    #[test]
    fn every_entry_carries_its_own_cursor() {
        let page = Page::from_probe(entries(&["a", "b", "c", "d"]), &PageRequest::first(3));
        let cursors: Vec<&str> = page.entries.iter().map(|e| e.cursor.as_str()).collect();
        assert_eq!(cursors, vec!["a", "b", "c"]);
    }

    #[test]
    fn map_preserves_cursors() {
        let page = Page::from_probe(entries(&["a", "b"]), &PageRequest::first(5));
        let mapped = page.map(|s| s.to_uppercase());
        assert_eq!(mapped.entries[0].item, "A");
        assert_eq!(mapped.entries[0].cursor, "a");
    }
}
