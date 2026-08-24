//! Embedded catalog backed by [redb].
//!
//! The catalog's job is to swap a pointer — a table's current metadata location
//! — atomically, under concurrent writers. redb gives exactly that: ACID
//! multi-key transactions over a single file, in pure Rust with no C
//! dependencies, so the binary still cross-compiles statically.
//!
//! # Layout
//!
//! ```text
//!   redb (registry)                    FileIO (metadata files)
//!   ├─ namespaces                      ├─ {warehouse}/db/t1/metadata/00001-….json
//!   │   n␟db            → properties   └─ {warehouse}/db/t2/metadata/00002-….json
//!   │   n␟db␟schema     → properties
//!   └─ tables
//!       t␟db␞users      → pointer + version
//!       t␟db␟schema␞evt → pointer + version
//! ```
//!
//! # Key encoding
//!
//! Namespace levels join with `␟` (0x1F) and a name is terminated with `␞`
//! (0x1E). Both are rejected by name validation, so the encoding is injective
//! and prefix scans are exact. Joining on `.` — which *is* a legal name
//! character — would make `["a.b"]` and `["a", "b"]` collide on one entry, so
//! tables created in one namespace would be visible and overwritable from the
//! other.
//!
//! # Concurrency
//!
//! A commit reads the registry entry, writes the new metadata file, then swaps
//! the pointer — all inside one redb write transaction, with the entry's version
//! re-checked before the swap. redb serialises write transactions, so the
//! read-modify-write cannot interleave and no update is lost.
//!
//! Metadata files are named with a fresh UUID and never overwritten, so a commit
//! that is later abandoned leaves an unreferenced file rather than corrupting a
//! live one.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use iceberg::io::FileIO;
use iceberg::spec::{TableMetadata, TableMetadataBuilder, ViewMetadata};
use iceberg::table::Table;
use iceberg::{
    Error, ErrorKind, MetadataLocation, Namespace, NamespaceIdent, Result, Runtime, TableCreation,
    TableIdent, TableRequirement, TableUpdate,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::store::{
    CatalogStore, Entry, NAME_SEPARATOR, PART_SEPARATOR, Page, PageRequest, StorageHealthStatus,
};

/// The layout of the records in this file, as this binary reads them.
///
/// Bumped by any change to what is stored — a new relation, a renamed field, a
/// different key encoding. Symmetric with the Postgres backend's stamp, and for
/// the same reason: opening a database written by another build cannot reshape
/// it, so a relation this build expects is silently empty and a record whose
/// shape moved is silently misread or fails to parse deep inside a request.
///
/// redb being a *file* makes this more likely rather than less. The file
/// outlives the binary that wrote it, sitting in a volume somebody mounts into
/// the next image, and nothing about "table not found" points at the schema.
///
/// Not a migration target. Rustberg is pre-release and ships none; what the
/// stamp buys is a sentence naming both versions instead of a catalog that
/// appears to have lost its tables.
const SCHEMA_VERSION: u32 = 1;

/// How many times a conflicting commit is retried before answering 409.
const COMMIT_MAX_RETRIES: u32 = 10;

/// Base delay for commit retry backoff.
const COMMIT_BASE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);

/// Upper bound on commit retry backoff.
const COMMIT_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(320);

/// Namespace registry: key → JSON [`NamespaceRecord`].
const NAMESPACES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespaces");

/// Table registry: key → JSON [`TableRecord`].
const TABLES: TableDefinition<&str, &[u8]> = TableDefinition::new("tables");

/// Policy revisions, keyed by zero-padded sequence so the natural key order is
/// the log order.
///
/// Padded to twenty digits — the full width of a `u64` — because redb orders
/// keys lexicographically, and `"10"` sorts before `"9"` without it.
const POLICIES: TableDefinition<&str, &[u8]> = TableDefinition::new("policy_revisions");

/// Staged tables: created with `stage-create`, not yet committed.
///
/// A separate table rather than a flag on [`TABLES`]: every listing, load and
/// existence check reads that table, and a `staged` column would make each of
/// them one forgotten `WHERE` away from exposing a table that does not exist
/// yet. Here the isolation is structural — nothing that reads `TABLES` can see
/// a staged entry, because it is not in it.
const STAGED: TableDefinition<&str, &[u8]> = TableDefinition::new("staged_tables");

/// View registry: key → JSON [`ViewRecord`].
///
/// Views live in the same file and the same transaction domain as tables, so a
/// namespace cannot be dropped out from under them and a view cannot be created
/// in a namespace that is concurrently being removed.
const VIEWS: TableDefinition<&str, &[u8]> = TableDefinition::new("views");

/// Bookkeeping about the file itself, keyed by name.
///
/// One key so far: `schema_version`. See [`SCHEMA_VERSION`].
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// The key under which [`SCHEMA_VERSION`] is stamped.
const SCHEMA_VERSION_KEY: &str = "schema_version";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamespaceRecord {
    namespace: Vec<String>,
    properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TableRecord {
    namespace: Vec<String>,
    name: String,
    metadata_location: String,
    /// Incremented on every commit; re-checked before a pointer swap.
    version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ViewRecord {
    namespace: Vec<String>,
    name: String,
    metadata_location: String,
    version: u64,
}

/// Embedded catalog over a single redb file.
pub struct RedbCatalog {
    db: Arc<Database>,
    file_io: FileIO,
    warehouse_location: String,
    location_scope: crate::location::LocationScope,
    runtime: Runtime,
}

impl std::fmt::Debug for RedbCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbCatalog")
            .field("warehouse_location", &self.warehouse_location)
            .finish_non_exhaustive()
    }
}

/// Refuses a name already held in this namespace, by a table **or** a view.
///
/// # Why one namespace holds one kind of thing per name
///
/// The spec says so on four endpoints — `createTable`, `createView`,
/// `renameTable` and `renameView` each answer `409` for *"the identifier already
/// exists as a table or view"* — and here it is more than an interoperability
/// rule. Both kinds are laid out at `<warehouse>/<namespace>/<name>`, so a
/// collision puts two different metadata documents in one directory, and a purge
/// of the table deletes the view's files along with its own. Two callers each
/// see a resource that works, right up until one of them drops theirs.
///
/// # Sound inside a write transaction, and only there
///
/// redb serialises writers, so nothing can take the name between this read and
/// the insert that follows it in the same transaction. Called outside one it
/// would be exactly the check-then-act race that the Postgres backend spends a
/// shared primary key to avoid — see `rustberg_object_names` there, which is the
/// same rule expressed as a constraint because that backend has no serialisation
/// to lean on.
fn reject_taken_name(txn: &redb::WriteTransaction, key: &str, display: &str) -> Result<()> {
    let taken = {
        let tables = txn.open_table(TABLES).map_err(db_err)?;
        tables.get(key).map_err(db_err)?.is_some()
    } || {
        let views = txn.open_table(VIEWS).map_err(db_err)?;
        views.get(key).map_err(db_err)?.is_some()
    };

    if taken {
        return Err(Error::new(
            ErrorKind::TableAlreadyExists,
            display.to_string(),
        ));
    }
    Ok(())
}

fn db_err(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Unexpected, format!("redb error: {e}"))
}

fn json_err(e: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::Unexpected,
        format!("Corrupt registry entry: {e}"),
    )
}

impl RedbCatalog {
    /// Opens (or creates) a catalog at `path`, serving `warehouse_location`.
    pub async fn open(
        path: impl AsRef<Path>,
        warehouse_location: impl Into<String>,
    ) -> Result<Self> {
        let warehouse_location = warehouse_location.into();
        let warehouse_location = Self::normalize_warehouse(&warehouse_location)?;

        // Fail fast when the warehouse scheme was not compiled in, rather than
        // on the first table write.
        super::file_io::ensure_scheme_supported(&warehouse_location)?;
        let file_io = super::file_io::build_file_io()?;

        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(db_err)?;
        }

        let db = Database::create(path).map_err(db_err)?;

        // Create both tables up front so a read-only transaction never fails on
        // a missing table before anything has been written.
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(NAMESPACES).map_err(db_err)?;
        txn.open_table(TABLES).map_err(db_err)?;
        txn.open_table(VIEWS).map_err(db_err)?;
        txn.open_table(STAGED).map_err(db_err)?;
        txn.open_table(POLICIES).map_err(db_err)?;
        // Inside the same transaction that creates the relations, so the file is
        // never half-initialised: either it carries this build's layout and says
        // so, or it carries neither.
        Self::stamp_or_check_schema(&txn)?;
        txn.commit().map_err(db_err)?;

        Ok(Self {
            db: Arc::new(db),
            file_io,
            warehouse_location,
            location_scope: crate::location::LocationScope::default(),
            // Captured once so a catalog built outside a runtime fails here
            // rather than on the first table operation.
            runtime: Runtime::try_current()?,
        })
    }

    /// Sets how far inside the warehouse a **registered** resource may declare
    /// its location.
    ///
    /// Defaults to [`LocationScope::Table`](crate::location::LocationScope::Table),
    /// which is what keeps a location-scoped credential a faithful enforcement
    /// of a namespace-scoped grant. Read that type before widening it.
    #[must_use]
    pub fn with_location_scope(mut self, scope: crate::location::LocationScope) -> Self {
        self.location_scope = scope;
        self
    }

    async fn get_staged_record(&self, table: &TableIdent) -> Result<Option<TableRecord>> {
        let key = Self::table_key(table);
        self.blocking(move |db| {
            let txn = db.begin_read().map_err(db_err)?;
            let staged = txn.open_table(STAGED).map_err(db_err)?;
            match staged.get(key.as_str()).map_err(db_err)? {
                Some(v) => serde_json::from_slice(v.value())
                    .map(Some)
                    .map_err(json_err),
                None => Ok(None),
            }
        })
        .await
    }

    async fn get_view_record(&self, view: &TableIdent) -> Result<Option<ViewRecord>> {
        let key = Self::table_key(view);
        self.blocking(move |db| {
            let txn = db.begin_read().map_err(db_err)?;
            let table = txn.open_table(VIEWS).map_err(db_err)?;
            match table.get(key.as_str()).map_err(db_err)? {
                Some(v) => serde_json::from_slice(v.value())
                    .map(Some)
                    .map_err(json_err),
                None => Ok(None),
            }
        })
        .await
    }

    /// Writes view metadata as JSON.
    ///
    /// `ViewMetadata` has no `write_to` helper of its own, unlike `TableMetadata`,
    /// so the same convention is applied here by hand.
    async fn write_view_metadata(&self, metadata: &ViewMetadata, location: &str) -> Result<()> {
        let json = serde_json::to_vec(metadata).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to serialize view metadata: {e}"),
            )
        })?;
        self.file_io.new_output(location)?.write(json.into()).await
    }

    async fn read_view_metadata(&self, location: &str) -> Result<ViewMetadata> {
        let bytes = self.file_io.new_input(location)?.read().await?;
        serde_json::from_slice(&bytes).map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to parse view metadata at {location}: {e}"),
            )
        })
    }

    /// The underlying registry database.
    ///
    /// Exposed so other server state — API keys — can live in a table inside the
    /// same file, keeping a deployment's durable footprint to one directory.
    pub fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Normalises a warehouse location, creating the directory for local paths.
    /// Stamps a fresh database with this build's schema version, or refuses one
    /// stamped with another.
    ///
    /// Runs inside the caller's write transaction. redb serialises write
    /// transactions, so the read and the write below cannot be raced by a second
    /// process — and a second process cannot open the file at all, which is the
    /// whole reason this backend is the embedded one.
    ///
    /// An **unstamped** file is treated as this version rather than refused. A
    /// database with no relations in it is a database this call is about to
    /// create, and refusing one would make the first start fail. A file that
    /// predates the stamp and *does* hold data is the one case this cannot tell
    /// apart, and it is the pre-release case the release notes cover.
    fn stamp_or_check_schema(txn: &redb::WriteTransaction) -> Result<()> {
        let mut meta = txn.open_table(META).map_err(db_err)?;

        let found: Option<u32> = match meta.get(SCHEMA_VERSION_KEY).map_err(db_err)? {
            Some(value) => serde_json::from_slice(value.value()).map_err(json_err)?,
            None => None,
        };

        match found {
            Some(version) if version != SCHEMA_VERSION => Err(Error::new(
                ErrorKind::Unexpected,
                format!(
                    "This catalog file was written with Rustberg catalog schema v{version}, \
                     and this binary reads v{SCHEMA_VERSION}. Opening it cannot reshape it, \
                     so relations this build expects would be empty and records whose shape \
                     moved would be misread — which shows up as missing tables rather than \
                     as a schema error. Rustberg is pre-release and ships no migrations: \
                     point `catalog.url` at a new file, or move this one aside."
                ),
            )),
            Some(_) => Ok(()),
            None => {
                let encoded = serde_json::to_vec(&SCHEMA_VERSION).map_err(json_err)?;
                meta.insert(SCHEMA_VERSION_KEY, encoded.as_slice())
                    .map_err(db_err)?;
                Ok(())
            }
        }
    }

    fn normalize_warehouse(location: &str) -> Result<String> {
        if location.contains("://") && !location.starts_with("file://") {
            return Ok(location.to_string());
        }

        let path = location.strip_prefix("file://").unwrap_or(location);
        let absolute = if Path::new(path).is_absolute() {
            std::path::PathBuf::from(path)
        } else {
            std::env::current_dir().map_err(db_err)?.join(path)
        };
        std::fs::create_dir_all(&absolute).map_err(db_err)?;

        Ok(format!("file://{}", absolute.display()))
    }

    /// Runs a registry operation on the blocking pool.
    ///
    /// redb is synchronous, and `begin_write` blocks until any in-flight write
    /// transaction commits — including its fsync. Calling it directly from an
    /// async method would park a Tokio worker for that whole duration, and with
    /// one worker per core a handful of concurrent commits would stall the
    /// entire server, health checks included. Every redb access therefore goes
    /// through here.
    async fn blocking<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> Result<T> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(|e| Error::new(ErrorKind::Unexpected, format!("Registry task failed: {e}")))?
    }

    fn namespace_key(ns: &NamespaceIdent) -> String {
        Self::namespace_key_of(ns.as_ref())
    }

    /// The same key, from parts that are not yet a validated identifier — a
    /// parent path sliced off the front of one, for instance.
    fn namespace_key_of(parts: &[String]) -> String {
        parts.join(&PART_SEPARATOR.to_string())
    }

    /// Prefix matching every namespace strictly beneath `ns`.
    fn namespace_child_prefix(ns: &NamespaceIdent) -> String {
        format!("{}{PART_SEPARATOR}", Self::namespace_key(ns))
    }

    fn table_key(table: &TableIdent) -> String {
        format!(
            "{}{NAME_SEPARATOR}{}",
            Self::namespace_key(&table.namespace),
            table.name
        )
    }

    /// Prefix matching every table in `ns`, and no table outside it.
    fn table_prefix(ns: &NamespaceIdent) -> String {
        format!("{}{NAME_SEPARATOR}", Self::namespace_key(ns))
    }

    /// Where a paged scan begins: the prefix, or just past the cursor.
    ///
    /// The cursor is a storage key, so resuming is a seek into the sorted index
    /// rather than a scan that counts rows and discards them. Appending `\0` —
    /// which name validation forbids — makes the bound exclusive without needing
    /// `Bound::Excluded`, and keeps the caller's cursor from being returned twice.
    ///
    /// A cursor that does not belong to this prefix is ignored rather than
    /// honoured: it would otherwise let a caller seek into another namespace's
    /// range by editing a page token.
    fn scan_start(prefix: &str, page: &PageRequest) -> String {
        match page.after.as_deref() {
            Some(cursor) if cursor.starts_with(prefix) => format!("{cursor}\0"),
            _ => prefix.to_string(),
        }
    }

    /// Lists tables or views in a namespace — the two differ only by which redb
    /// table they read, since both are keyed `namespace␞name`.
    async fn list_tabulars(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
        definition: TableDefinition<'static, &'static str, &'static [u8]>,
    ) -> Result<Page<TableIdent>> {
        if self.get_namespace_record(namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        let prefix = Self::table_prefix(namespace);
        let end = Self::prefix_end(&prefix);
        let start = Self::scan_start(&prefix, page);
        let probe = page.probe_limit();

        // Only the keys are read. A name lives in its key, so listing never
        // deserialises a metadata record — which is what makes a page cost the
        // same whether the table has one snapshot or ten thousand.
        let keys = self
            .blocking(move |db| {
                let txn = db.begin_read().map_err(db_err)?;
                let table = txn.open_table(definition).map_err(db_err)?;
                let mut out: Vec<String> = Vec::new();
                for entry in table.range(start.as_str()..end.as_str()).map_err(db_err)? {
                    let (key, _) = entry.map_err(db_err)?;
                    out.push(key.value().to_string());
                    if out.len() >= probe {
                        break;
                    }
                }
                Ok(out)
            })
            .await?;

        let namespace = namespace.clone();
        let rows = keys
            .into_iter()
            .map(|key| {
                let name = key
                    .rsplit(NAME_SEPARATOR)
                    .next()
                    .expect("a tabular key always carries the name separator")
                    .to_string();
                Entry {
                    cursor: key,
                    item: TableIdent::new(namespace.clone(), name),
                }
            })
            .collect();

        Ok(Page::from_probe(rows, page))
    }

    /// Exclusive upper bound for a prefix scan.
    fn prefix_end(prefix: &str) -> String {
        // `\u{FFFF}` sorts above every character a validated name may contain.
        format!("{prefix}\u{FFFF}")
    }

    /// The prefix a resource registered into this catalog may declare.
    ///
    /// The check lives here rather than in the handler for one reason: what a
    /// vended credential is later scoped to is the location recorded *inside*
    /// the metadata document, not the path the caller handed in. So the file
    /// being at a legitimate path proves nothing — a file at one may declare any
    /// location it likes. Checking after the pointer is published leaves a window
    /// in which a table declaring somebody else's prefix is loadable; checking
    /// before it, from the handler, reads a file the caller controls and can
    /// change in between. There is exactly one read that is safe to check: the
    /// one the registry is about to record, which happens here.
    fn declared_bound(&self, namespace: &[String], name: &str) -> crate::location::LocationBound {
        crate::location::LocationBound::new(
            self.location_scope,
            &self.warehouse_location,
            &crate::location::namespace_prefix(&self.warehouse_location, namespace),
            name,
        )
    }

    fn table_location(&self, table: &TableIdent) -> String {
        format!(
            "{}/{}/{}",
            self.warehouse_location,
            table.namespace.as_ref().join("/"),
            table.name
        )
    }

    fn ident(parts: Vec<String>) -> Result<NamespaceIdent> {
        NamespaceIdent::from_vec(parts)
            .map_err(|e| Error::new(ErrorKind::DataInvalid, format!("Invalid namespace: {e}")))
    }

    async fn read_metadata(&self, location: &str) -> Result<TableMetadata> {
        TableMetadata::read_from(&self.file_io, location).await
    }

    fn build_table(
        &self,
        ident: TableIdent,
        metadata: TableMetadata,
        location: String,
    ) -> Result<Table> {
        Table::builder()
            .runtime(self.runtime.clone())
            .identifier(ident)
            .metadata(metadata)
            .metadata_location(location)
            .file_io(self.file_io.clone())
            .build()
    }

    async fn get_namespace_record(&self, ns: &NamespaceIdent) -> Result<Option<NamespaceRecord>> {
        let key = Self::namespace_key(ns);
        self.blocking(move |db| {
            let txn = db.begin_read().map_err(db_err)?;
            let table = txn.open_table(NAMESPACES).map_err(db_err)?;
            match table.get(key.as_str()).map_err(db_err)? {
                Some(v) => serde_json::from_slice(v.value())
                    .map(Some)
                    .map_err(json_err),
                None => Ok(None),
            }
        })
        .await
    }

    async fn get_table_record(&self, ident: &TableIdent) -> Result<Option<TableRecord>> {
        let key = Self::table_key(ident);
        self.blocking(move |db| {
            let txn = db.begin_read().map_err(db_err)?;
            let table = txn.open_table(TABLES).map_err(db_err)?;
            match table.get(key.as_str()).map_err(db_err)? {
                Some(v) => serde_json::from_slice(v.value())
                    .map(Some)
                    .map_err(json_err),
                None => Ok(None),
            }
        })
        .await
    }

    /// Location for the next metadata file, derived from the current one so the
    /// version counter advances monotonically across commits.
    fn next_metadata_location(current: &str, metadata: &TableMetadata) -> MetadataLocation {
        match MetadataLocation::from_str(current) {
            Ok(loc) => loc.with_next_version().with_new_metadata(metadata),
            // A registered table may point at a file that does not follow the
            // `<version>-<uuid>.metadata.json` convention; start a fresh
            // sequence rather than failing the commit.
            Err(_) => MetadataLocation::new_with_metadata(metadata.location(), metadata)
                .with_next_version(),
        }
    }
}

#[async_trait]
impl CatalogStore for RedbCatalog {
    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: &PageRequest,
    ) -> Result<Page<NamespaceIdent>> {
        let (prefix, depth) = match parent {
            Some(p) => {
                if self.get_namespace_record(p).await?.is_none() {
                    return Err(Error::new(
                        ErrorKind::NamespaceNotFound,
                        p.join(".").to_string(),
                    ));
                }
                (Self::namespace_child_prefix(p), p.len() + 1)
            }
            None => (String::new(), 1),
        };

        let end = Self::prefix_end(&prefix);
        let start = Self::scan_start(&prefix, page);
        let probe = page.probe_limit();

        let keys = self
            .blocking(move |db| {
                let txn = db.begin_read().map_err(db_err)?;
                let table = txn.open_table(NAMESPACES).map_err(db_err)?;
                let mut out: Vec<String> = Vec::new();
                for entry in table.range(start.as_str()..end.as_str()).map_err(db_err)? {
                    let (key, _) = entry.map_err(db_err)?;
                    let key = key.value();
                    // Depth is decided from the *key*, so a descendant that is not
                    // a direct child costs a separator count rather than a JSON
                    // parse. A deep subtree is still walked past — the scan is
                    // proportional to descendants, not to children — which is why
                    // the page is probed rather than the whole range read.
                    if key.matches(PART_SEPARATOR).count() + 1 == depth {
                        out.push(key.to_string());
                        if out.len() >= probe {
                            break;
                        }
                    }
                }
                Ok(out)
            })
            .await?;

        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            let ident = Self::ident(key.split(PART_SEPARATOR).map(str::to_string).collect())?;
            rows.push(Entry {
                cursor: key,
                item: ident,
            });
        }

        Ok(Page::from_probe(rows, page))
    }

    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        // A nested namespace needs its parent, or it would never appear in any
        // listing and be reachable only by exact path.
        //
        // Checked *inside* the write transaction, alongside the insert. redb
        // serialises write transactions, so that is the whole concurrency
        // control: a parent read before `begin_write` could be dropped between
        // the read and the insert, and the hole this refuses to create would
        // appear anyway. The Postgres backend gets the same guarantee from a
        // foreign key, which is why the two agree.
        let parent_key = (namespace.len() > 1)
            .then(|| Self::namespace_key_of(&namespace.as_ref()[..namespace.len() - 1]));
        let parent_display = namespace.as_ref()[..namespace.len().saturating_sub(1)].join(".");

        let key = Self::namespace_key(namespace);
        let record = NamespaceRecord {
            namespace: namespace.as_ref().clone(),
            properties: properties.clone(),
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let display = namespace.join(".");

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(NAMESPACES).map_err(db_err)?;

                if let Some(parent_key) = &parent_key
                    && table.get(parent_key.as_str()).map_err(db_err)?.is_none()
                {
                    return Err(Error::new(
                        ErrorKind::NamespaceNotFound,
                        format!("Parent namespace not found: {parent_display}"),
                    ));
                }

                if table.get(key.as_str()).map_err(db_err)?.is_some() {
                    return Err(Error::new(
                        ErrorKind::NamespaceAlreadyExists,
                        display.to_string(),
                    ));
                }
                table
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        Ok(Namespace::with_properties(namespace.clone(), properties))
    }

    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        let record = self.get_namespace_record(namespace).await?.ok_or_else(|| {
            Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            )
        })?;
        Ok(Namespace::with_properties(
            namespace.clone(),
            record.properties,
        ))
    }

    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        Ok(self.get_namespace_record(namespace).await?.is_some())
    }

    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()> {
        let key = Self::namespace_key(namespace);
        let record = NamespaceRecord {
            namespace: namespace.as_ref().clone(),
            properties,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let display = namespace.join(".");

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(NAMESPACES).map_err(db_err)?;
                if table.get(key.as_str()).map_err(db_err)?.is_none() {
                    return Err(Error::new(
                        ErrorKind::NamespaceNotFound,
                        display.to_string(),
                    ));
                }
                table
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }

    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        let key = Self::namespace_key(namespace);
        let table_prefix = Self::table_prefix(namespace);
        let table_end = Self::prefix_end(&table_prefix);
        let child_prefix = Self::namespace_child_prefix(namespace);
        let child_end = Self::prefix_end(&child_prefix);

        let display = namespace.join(".");

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut namespaces = txn.open_table(NAMESPACES).map_err(db_err)?;
                if namespaces.get(key.as_str()).map_err(db_err)?.is_none() {
                    return Err(Error::new(
                        ErrorKind::NamespaceNotFound,
                        display.to_string(),
                    ));
                }

                let tables = txn.open_table(TABLES).map_err(db_err)?;
                if tables
                    .range(table_prefix.as_str()..table_end.as_str())
                    .map_err(db_err)?
                    .next()
                    .is_some()
                {
                    return Err(Error::new(
                        ErrorKind::PreconditionFailed,
                        format!("Namespace not empty: {display}"),
                    ));
                }

                // Views share the namespace and must block the drop for the same
                // reason tables do: a view left behind is still loadable by
                // exact path but absent from every listing.
                let views = txn.open_table(VIEWS).map_err(db_err)?;
                if views
                    .range(table_prefix.as_str()..table_end.as_str())
                    .map_err(db_err)?
                    .next()
                    .is_some()
                {
                    return Err(Error::new(
                        ErrorKind::PreconditionFailed,
                        format!("Namespace still has views: {display}"),
                    ));
                }

                // Staged tables do not block the drop — they are not tables, and
                // a client that never committed one has no claim on the name.
                // They are removed with it, so nothing can later be promoted
                // into a namespace that no longer exists.
                {
                    let mut staged = txn.open_table(STAGED).map_err(db_err)?;
                    let doomed: Vec<String> = staged
                        .range(table_prefix.as_str()..table_end.as_str())
                        .map_err(db_err)?
                        .filter_map(|entry| entry.ok().map(|(k, _)| k.value().to_string()))
                        .collect();
                    for key in doomed {
                        staged.remove(key.as_str()).map_err(db_err)?;
                    }
                }

                // Dropping a parent would orphan its children: still loadable by
                // exact path, but absent from every listing.
                if namespaces
                    .range(child_prefix.as_str()..child_end.as_str())
                    .map_err(db_err)?
                    .next()
                    .is_some()
                {
                    return Err(Error::new(
                        ErrorKind::PreconditionFailed,
                        format!("Namespace has child namespaces: {display}"),
                    ));
                }

                namespaces.remove(key.as_str()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }

    async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        self.list_tabulars(namespace, page, TABLES).await
    }

    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        if self.get_namespace_record(namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        let ident = TableIdent::new(namespace.clone(), creation.name.clone());
        let key = Self::table_key(&ident);

        if self.get_table_record(&ident).await?.is_some() {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                ident.name().to_string(),
            ));
        }

        // Without an explicit location the table lives under the warehouse *and*
        // its namespace, so same-named tables in different namespaces cannot
        // collide on one path.
        let location = creation
            .location
            .clone()
            .unwrap_or_else(|| self.table_location(&ident));
        let creation = TableCreation {
            location: Some(location.clone()),
            ..creation
        };

        let metadata = TableMetadataBuilder::from_table_creation(creation)?
            .build()?
            .metadata;

        let metadata_location = MetadataLocation::new_with_metadata(&location, &metadata);
        metadata.write_to(&self.file_io, &metadata_location).await?;
        let metadata_location = metadata_location.to_string();

        let record = TableRecord {
            namespace: namespace.as_ref().clone(),
            name: ident.name().to_string(),
            metadata_location: metadata_location.clone(),
            version: 0,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;

        let display = ident.name().to_string();
        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                reject_taken_name(&txn, &key, &display)?;
                let mut table = txn.open_table(TABLES).map_err(db_err)?;
                table
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        self.build_table(ident, metadata, metadata_location)
    }

    async fn stage_create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        if self.get_namespace_record(namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        let ident = TableIdent::new(namespace.clone(), creation.name.clone());

        // A name already taken by a real table cannot be staged onto: the
        // eventual commit asserts the table does not exist and would fail, so
        // failing now says the same thing at the point the client can still act
        // on it.
        if self.get_table_record(&ident).await?.is_some() {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                ident.name().to_string(),
            ));
        }

        let location = creation
            .location
            .clone()
            .unwrap_or_else(|| self.table_location(&ident));
        let creation = TableCreation {
            location: Some(location.clone()),
            ..creation
        };

        let metadata = TableMetadataBuilder::from_table_creation(creation)?
            .build()?
            .metadata;

        let metadata_location = MetadataLocation::new_with_metadata(&location, &metadata);
        metadata.write_to(&self.file_io, &metadata_location).await?;
        let metadata_location = metadata_location.to_string();

        let record = TableRecord {
            namespace: namespace.as_ref().clone(),
            name: ident.name().to_string(),
            metadata_location: metadata_location.clone(),
            version: 0,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let key = Self::table_key(&ident);

        // Overwrites any earlier staging of the same name. Staging reserves
        // nothing, so a client that stages twice simply gets the later one;
        // refusing would strand a client that retried after a timeout.
        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut staged = txn.open_table(STAGED).map_err(db_err)?;
                staged
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        self.build_table(ident, metadata, metadata_location)
    }

    async fn metadata_pointer(&self, table: &TableIdent) -> Result<Option<String>> {
        Ok(self
            .get_table_record(table)
            .await?
            .map(|record| record.metadata_location))
    }

    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        let record = self.get_table_record(table).await?.ok_or_else(|| {
            Error::new(
                ErrorKind::TableNotFound,
                format!("{}.{}", table.namespace.join("."), table.name),
            )
        })?;

        let metadata = self.read_metadata(&record.metadata_location).await?;
        self.build_table(table.clone(), metadata, record.metadata_location)
    }

    async fn drop_table(&self, table: &TableIdent) -> Result<()> {
        let key = Self::table_key(table);
        let display = format!("{}.{}", table.namespace.join("."), table.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut tables = txn.open_table(TABLES).map_err(db_err)?;
                if tables.get(key.as_str()).map_err(db_err)?.is_none() {
                    return Err(Error::new(ErrorKind::TableNotFound, display.to_string()));
                }
                tables.remove(key.as_str()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }

    async fn purge_table(&self, table: &TableIdent) -> Result<()> {
        // Load before dropping: the metadata says which files this table owns.
        let loaded = self.load_table(table).await?;
        self.drop_table(table).await?;
        // Deletes exactly the files this table's metadata names, and only those
        // that live under storage the table owns. See `catalog::purge` for why
        // a catalog cannot use `iceberg::drop_table_data`: it deletes with the
        // *server's* role, from paths a caller wrote.
        crate::catalog::purge::purge_table_data(&loaded).await
    }

    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        Ok(self.get_table_record(table).await?.is_some())
    }

    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        if src == dest {
            return Ok(());
        }
        if self.get_namespace_record(&dest.namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!(
                    "Destination namespace not found: {}",
                    dest.namespace.join(".")
                ),
            ));
        }

        let src_key = Self::table_key(src);
        let dest_key = Self::table_key(dest);

        let dest_ns = dest.namespace.as_ref().clone();
        let dest_name = dest.name.clone();
        let src_display = format!("{}.{}", src.namespace.join("."), src.name);
        let dest_display = format!("{}.{}", dest.namespace.join("."), dest.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let tables = txn.open_table(TABLES).map_err(db_err)?;

                let mut record: TableRecord = match tables.get(src_key.as_str()).map_err(db_err)? {
                    Some(v) => serde_json::from_slice(v.value()).map_err(json_err)?,
                    None => {
                        return Err(Error::new(
                            ErrorKind::TableNotFound,
                            format!("Source table not found: {src_display}"),
                        ));
                    }
                };

                // Checked against both kinds: renaming onto a *view*'s name is
                // the same collision, and the spec answers it the same way.
                drop(tables);
                reject_taken_name(
                    &txn,
                    &dest_key,
                    &format!("Destination table already exists: {dest_display}"),
                )?;
                let mut tables = txn.open_table(TABLES).map_err(db_err)?;

                record.namespace = dest_ns;
                record.name = dest_name;
                // Bump so a commit that read the pre-rename entry cannot land.
                record.version += 1;

                let value = serde_json::to_vec(&record).map_err(json_err)?;
                tables
                    .insert(dest_key.as_str(), value.as_slice())
                    .map_err(db_err)?;
                tables.remove(src_key.as_str()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }

    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table> {
        if self.get_namespace_record(&table.namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                table.namespace.join(".").to_string(),
            ));
        }
        if self.get_table_record(table).await?.is_some() {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!("{}.{}", table.namespace.join("."), table.name),
            ));
        }

        // Validate the metadata before pointing the registry at it — and confine
        // the location it *declares*, which is what a vended credential is later
        // scoped to. Checked on the read the registry is about to record, so no
        // pointer to an out-of-warehouse table is ever published, not even for
        // the microseconds a check-after-publish would leave.
        let metadata = self.read_metadata(&metadata_location).await?;
        self.declared_bound(table.namespace.as_ref(), &table.name)
            .ensure_iceberg(metadata.location())?;

        let record = TableRecord {
            namespace: table.namespace.as_ref().clone(),
            name: table.name.clone(),
            metadata_location: metadata_location.clone(),
            version: 0,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let key = Self::table_key(table);

        let display = format!("{}.{}", table.namespace.join("."), table.name);
        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                reject_taken_name(&txn, &key, &display)?;
                let mut tables = txn.open_table(TABLES).map_err(db_err)?;
                tables
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        self.build_table(table.clone(), metadata, metadata_location)
    }

    async fn commit_table(
        &self,
        table_ident: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        let mut tables = self
            .commit_tables_atomic(vec![(table_ident.clone(), requirements, updates)])
            .await?;
        tables
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Commit returned no table"))
    }

    /// Commits one or more tables atomically.
    ///
    /// Every commit runs through this path, so there is one implementation of
    /// the protocol to reason about:
    ///
    /// 1. Read each table's registry entry and metadata; check its requirements.
    /// 2. Write the new metadata files. They carry fresh UUIDs, so a file
    ///    written for a commit that later aborts is merely unreferenced.
    /// 3. Swap every pointer in a single redb write transaction, re-verifying
    ///    each entry's version first.
    ///
    /// Either every table advances or none does.
    async fn commit_tables_atomic(
        &self,
        table_changes: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        if table_changes.is_empty() {
            return Ok(Vec::new());
        }

        // A conflict means another writer landed first, not that this commit is
        // invalid. Retrying re-reads the table and re-checks its requirements
        // against the *new* state, so a retry can only succeed if the commit is
        // still legitimate. Without this, concurrent writers to different tables
        // in one transaction fail each other far more often than they need to.
        let mut last_conflict = None;

        for attempt in 0..COMMIT_MAX_RETRIES {
            match self.try_commit_tables_atomic(&table_changes).await {
                Ok(tables) => return Ok(tables),
                Err(e) if e.kind() == ErrorKind::CatalogCommitConflicts => {
                    let backoff = Self::commit_backoff(attempt);
                    tracing::debug!(
                        attempt = attempt + 1,
                        backoff_ms = backoff.as_millis() as u64,
                        "Commit conflict, retrying"
                    );
                    last_conflict = Some(e);
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }

        Err(Error::new(
            ErrorKind::CatalogCommitConflicts,
            format!(
                "Failed to commit after {COMMIT_MAX_RETRIES} attempts: {}",
                last_conflict
                    .as_ref()
                    .map(|e| e.message())
                    .unwrap_or("concurrent modification")
            ),
        ))
    }

    async fn warehouse_for(&self, _namespace: &NamespaceIdent) -> Option<String> {
        Some(self.warehouse_location.clone())
    }

    /// `<warehouse>/<levels…>`, the same formula this backend uses to *assign* a
    /// location — read from `crate::location` so the side that checks one and
    /// the side that assigns one cannot drift apart.
    fn namespace_prefix_for(&self, namespace: &NamespaceIdent) -> Option<String> {
        Some(crate::location::namespace_prefix(
            &self.warehouse_location,
            namespace.as_ref(),
        ))
    }

    /// A native registry does everything the protocol defines. A deployment
    /// that wants one of these subtracted says so on the *mount*, which is
    /// where `read_only` lives — the store itself has no opinion.
    fn capabilities_for(
        &self,
        _namespace: Option<&NamespaceIdent>,
    ) -> crate::catalog::Capabilities {
        crate::catalog::Capabilities::full()
    }

    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        use std::time::Instant;
        let start = Instant::now();

        let backend = match self.warehouse_location.split_once("://") {
            Some(("s3" | "s3a" | "s3n", _)) => "s3",
            Some(("gs" | "gcs", _)) => "gcs",
            Some(("abfs" | "abfss" | "az" | "adls", _)) => "azure",
            Some(("file", _)) | None => "file",
            Some((other, _)) => other,
        };

        // A read transaction proves the registry is openable; the warehouse
        // check proves the metadata store is reachable.
        self.blocking(|db| db.begin_read().map(|_| ()).map_err(db_err))
            .await?;

        match self.file_io.exists(&self.warehouse_location).await {
            Ok(_) => Ok(StorageHealthStatus::healthy(
                backend,
                start.elapsed().as_millis() as u64,
            )),
            Err(e) => Ok(StorageHealthStatus::unhealthy(
                backend,
                format!("Storage check failed: {e}"),
            )),
        }
    }

    // ── Views ───────────────────────────────────────────────────────────

    async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        self.list_tabulars(namespace, page, VIEWS).await
    }

    async fn view_exists(&self, view: &TableIdent) -> Result<bool> {
        Ok(self.get_view_record(view).await?.is_some())
    }

    async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)> {
        let record = self.get_view_record(view).await?.ok_or_else(|| {
            Error::new(
                ErrorKind::TableNotFound,
                format!("{}.{}", view.namespace.join("."), view.name),
            )
        })?;

        let metadata = self.read_view_metadata(&record.metadata_location).await?;
        Ok((record.metadata_location, metadata))
    }

    async fn register_view(
        &self,
        view: &TableIdent,
        metadata_location: String,
    ) -> Result<(String, ViewMetadata)> {
        if self.get_namespace_record(&view.namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                view.namespace.join(".").to_string(),
            ));
        }

        // Read, never rewrite: registration adopts the caller's metadata, and
        // writing a fresh file would discard the version history being adopted.
        let metadata = self.read_view_metadata(&metadata_location).await?;
        self.declared_bound(view.namespace.as_ref(), &view.name)
            .ensure_iceberg(metadata.location())?;

        let record = ViewRecord {
            namespace: view.namespace.as_ref().clone(),
            name: view.name.clone(),
            metadata_location: metadata_location.clone(),
            version: 0,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let key = Self::table_key(view);
        let display = format!("{}.{}", view.namespace.join("."), view.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                reject_taken_name(&txn, &key, &display)?;
                let mut views = txn.open_table(VIEWS).map_err(db_err)?;
                views
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        Ok((metadata_location, metadata))
    }

    async fn create_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        if self.get_namespace_record(&view.namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                view.namespace.join(".").to_string(),
            ));
        }

        // The metadata file is written before the pointer is registered, so a
        // client that reads the location we hand back always finds a file there.
        // View metadata carries no compression setting, so the table-oriented
        // `new_with_metadata` has nothing to read; the path convention is all
        // that is borrowed here.
        #[allow(deprecated)]
        let location = MetadataLocation::new_with_table_location(metadata.location()).to_string();
        self.write_view_metadata(&metadata, &location).await?;

        let record = ViewRecord {
            namespace: view.namespace.as_ref().clone(),
            name: view.name.clone(),
            metadata_location: location.clone(),
            version: 0,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let key = Self::table_key(view);
        let display = format!("{}.{}", view.namespace.join("."), view.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                reject_taken_name(&txn, &key, &display)?;
                let mut views = txn.open_table(VIEWS).map_err(db_err)?;
                views
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        Ok((location, metadata))
    }

    async fn update_view(
        &self,
        view: &TableIdent,
        expected_metadata_location: &str,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        let current = self.get_view_record(view).await?.ok_or_else(|| {
            Error::new(
                ErrorKind::TableNotFound,
                format!("{}.{}", view.namespace.join("."), view.name),
            )
        })?;

        // Checked here as well as in the swap below, so a commit that lost the
        // race is refused before a metadata file is written for it. The swap is
        // what makes it safe; this only keeps the warehouse from collecting a
        // document nothing will ever point at.
        if current.metadata_location != expected_metadata_location {
            return Err(Error::new(
                ErrorKind::CatalogCommitConflicts,
                "View was modified concurrently",
            ));
        }

        // Derived from the current location so the version advances, and named
        // with a fresh UUID so an abandoned write leaves an unreferenced file
        // rather than clobbering the live one.
        let location = match MetadataLocation::from_str(&current.metadata_location) {
            Ok(loc) => loc.with_next_version(),
            Err(_) =>
            {
                #[allow(deprecated)]
                MetadataLocation::new_with_table_location(metadata.location()).with_next_version()
            }
        }
        .to_string();

        self.write_view_metadata(&metadata, &location).await?;

        let record = ViewRecord {
            namespace: view.namespace.as_ref().clone(),
            name: view.name.clone(),
            metadata_location: location.clone(),
            version: current.version + 1,
        };
        let value = serde_json::to_vec(&record).map_err(json_err)?;
        let key = Self::table_key(view);
        let expected = current.version;
        // The caller's witness, not this backend's own read. See
        // `CatalogStore::update_view`: the updates were applied to the document
        // at *that* location, so comparing against a later read would confirm a
        // concurrent commit rather than detect it.
        let expected_location = expected_metadata_location.to_string();

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut views = txn.open_table(VIEWS).map_err(db_err)?;
                let live: ViewRecord = match views.get(key.as_str()).map_err(db_err)? {
                    Some(v) => serde_json::from_slice(v.value()).map_err(json_err)?,
                    None => {
                        return Err(Error::new(
                            ErrorKind::CatalogCommitConflicts,
                            "View dropped during update",
                        ));
                    }
                };

                if live.version != expected || live.metadata_location != expected_location {
                    return Err(Error::new(
                        ErrorKind::CatalogCommitConflicts,
                        "View was modified concurrently",
                    ));
                }

                views
                    .insert(key.as_str(), value.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await?;

        Ok((location, metadata))
    }

    async fn drop_view(&self, view: &TableIdent) -> Result<()> {
        let key = Self::table_key(view);
        let display = format!("{}.{}", view.namespace.join("."), view.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut views = txn.open_table(VIEWS).map_err(db_err)?;
                if views.get(key.as_str()).map_err(db_err)?.is_none() {
                    return Err(Error::new(ErrorKind::TableNotFound, display.to_string()));
                }
                views.remove(key.as_str()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }

    async fn rename_view(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        if src == dest {
            return Ok(());
        }
        if self.get_namespace_record(&dest.namespace).await?.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!(
                    "Destination namespace not found: {}",
                    dest.namespace.join(".")
                ),
            ));
        }

        let src_key = Self::table_key(src);
        let dest_key = Self::table_key(dest);
        let dest_ns = dest.namespace.as_ref().clone();
        let dest_name = dest.name.clone();
        let src_display = format!("{}.{}", src.namespace.join("."), src.name);
        let dest_display = format!("{}.{}", dest.namespace.join("."), dest.name);

        self.blocking(move |db| {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let views = txn.open_table(VIEWS).map_err(db_err)?;

                let mut record: ViewRecord = match views.get(src_key.as_str()).map_err(db_err)? {
                    Some(v) => serde_json::from_slice(v.value()).map_err(json_err)?,
                    None => {
                        return Err(Error::new(
                            ErrorKind::TableNotFound,
                            format!("Source view not found: {src_display}"),
                        ));
                    }
                };

                drop(views);
                reject_taken_name(
                    &txn,
                    &dest_key,
                    &format!("Destination view already exists: {dest_display}"),
                )?;
                let mut views = txn.open_table(VIEWS).map_err(db_err)?;

                record.namespace = dest_ns;
                record.name = dest_name;
                record.version += 1;

                let value = serde_json::to_vec(&record).map_err(json_err)?;
                views
                    .insert(dest_key.as_str(), value.as_slice())
                    .map_err(db_err)?;
                views.remove(src_key.as_str()).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)
        })
        .await
    }
}

impl RedbCatalog {
    /// Exponential backoff with full jitter, capped at [`COMMIT_MAX_BACKOFF`].
    ///
    /// Jitter matters: without it, writers that collide once tend to collide
    /// again on every retry because they all wake at the same instant.
    fn commit_backoff(attempt: u32) -> std::time::Duration {
        let exp = COMMIT_BASE_BACKOFF.saturating_mul(1u32 << attempt.min(6));
        exp.min(COMMIT_MAX_BACKOFF)
            .mul_f64(rand::random::<f64>().clamp(0.0, 1.0))
    }

    /// One attempt of the atomic commit protocol.
    async fn try_commit_tables_atomic(
        &self,
        table_changes: &[(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)],
    ) -> Result<Vec<Table>> {
        // Phase 1 & 2 — validate and write metadata, outside the transaction.
        let mut prepared = Vec::with_capacity(table_changes.len());

        for (ident, requirements, updates) in table_changes {
            // Two shapes of commit arrive here. The ordinary one updates a table
            // that exists. The other *creates* one: a client that staged a table
            // with `stage-create` commits it carrying `assert-create`, and the
            // table deliberately does not exist until this moment. Telling those
            // apart is what the requirement list is for.
            let creating = requirements
                .iter()
                .any(|r| matches!(r, TableRequirement::NotExist));

            let (base, base_location, expected) = match self.get_table_record(ident).await? {
                Some(record) => {
                    let metadata = self.read_metadata(&record.metadata_location).await?;
                    let location = record.metadata_location.clone();
                    (metadata, location, Some(record))
                }
                None if creating => {
                    let staged = self.get_staged_record(ident).await?.ok_or_else(|| {
                        Error::new(
                            ErrorKind::TableNotFound,
                            format!(
                                "{ident} was not staged. A commit asserting the table does not \
                                 exist must follow a `stage-create`."
                            ),
                        )
                    })?;
                    let metadata = self.read_metadata(&staged.metadata_location).await?;
                    (metadata, staged.metadata_location, None)
                }
                None => return Err(Error::new(ErrorKind::TableNotFound, format!("{ident}"))),
            };

            // Requirements are checked against what the *catalog* holds, which
            // for a create is nothing — `assert-create` passes precisely because
            // there is no table, and any other requirement correctly fails
            // against `None`.
            let current = if expected.is_some() {
                Some(&base)
            } else {
                None
            };
            for requirement in requirements {
                requirement.check(current).map_err(|e| {
                    Error::new(
                        e.kind(),
                        format!("Requirement failed for table {ident}: {}", e.message()),
                    )
                })?;
            }

            // The staged metadata is the base, and the client's updates are
            // applied over it. They overlap — a staged create sends back the
            // schema and spec it was given — but the builder reuses an identical
            // schema, spec or sort order rather than duplicating it, so
            // re-applying them is a no-op and only the new snapshot lands.
            // A stale v3 row-id assignment is a lost race, not a malformed
            // request. Reported before the builder sees it, so it leaves as a
            // `409` the client will retry rather than a `400` it will not — see
            // `store::reject_stale_row_lineage`.
            super::store::reject_stale_row_lineage(ident, &base, updates)?;

            // The four locations a commit carries, checked here because this is
            // where the table's *current* location is already in hand. A handler
            // would have to load the table a second time to learn it, on the
            // hottest write path — and the bound needs it: rename never moves
            // files, so a renamed table's files are not under the prefix its new
            // name implies. See `location::LocationBound::ensure_commit`.
            self.declared_bound(ident.namespace.as_ref(), &ident.name)
                .ensure_commit(base.location(), updates)?;

            let mut builder = base.clone().into_builder(Some(base_location.clone()));
            for update in updates {
                builder = update.clone().apply(builder)?;
            }
            let new_metadata = builder.build()?.metadata;

            let new_location = Self::next_metadata_location(&base_location, &new_metadata);
            new_metadata.write_to(&self.file_io, &new_location).await?;

            prepared.push((
                ident.clone(),
                expected,
                new_metadata,
                new_location.to_string(),
            ));
        }

        // Phase 3 — swap every pointer in one transaction. redb serialises write
        // transactions, so the version re-check below cannot be raced. This runs
        // on the blocking pool: `begin_write` waits for any in-flight commit and
        // `commit` fsyncs, either of which would otherwise park a Tokio worker.
        let swaps: Vec<(String, Option<TableRecord>, TableRecord, String)> = prepared
            .iter()
            .map(|(ident, expected, _, new_location)| {
                (
                    Self::table_key(ident),
                    expected.clone(),
                    TableRecord {
                        namespace: ident.namespace.as_ref().clone(),
                        name: ident.name().to_string(),
                        metadata_location: new_location.clone(),
                        version: expected.as_ref().map_or(0, |e| e.version + 1),
                    },
                    ident.to_string(),
                )
            })
            .collect();

        let swap_result = self
            .blocking(move |db| {
                let txn = db.begin_write().map_err(db_err)?;
                {
                    let mut tables = txn.open_table(TABLES).map_err(db_err)?;
                    let mut staged = txn.open_table(STAGED).map_err(db_err)?;
                    let namespaces = txn.open_table(NAMESPACES).map_err(db_err)?;
                    // Opened here rather than through `reject_taken_name`, which
                    // opens `TABLES` itself and cannot while this transaction
                    // holds it mutably. Same question, asked with the handles
                    // this loop already has.
                    let views = txn.open_table(VIEWS).map_err(db_err)?;

                    for (key, expected, next, display) in &swaps {
                        // Checked inside the swap transaction, not before it: a
                        // namespace dropped between staging and commit would
                        // otherwise get a table created inside it, reachable by
                        // exact path and absent from every listing.
                        if expected.is_none() {
                            let ns_key = next.namespace.join(&PART_SEPARATOR.to_string());
                            if namespaces.get(ns_key.as_str()).map_err(db_err)?.is_none() {
                                return Err(Error::new(
                                    ErrorKind::NamespaceNotFound,
                                    format!(
                                        "Namespace {} was dropped while {display} was staged",
                                        next.namespace.join(".")
                                    ),
                                ));
                            }
                        }

                        // Decoded to an owned value immediately: the borrow guard
                        // must not outlive this check, because the insert below
                        // needs the table mutably.
                        let current: Option<TableRecord> = match tables
                            .get(key.as_str())
                            .map_err(db_err)?
                        {
                            Some(v) => Some(serde_json::from_slice(v.value()).map_err(json_err)?),
                            None => None,
                        };

                        match expected {
                            // Updating: the pointer must still be exactly what was
                            // read, or another writer landed first.
                            Some(expected) => {
                                let Some(current) = current else {
                                    return Err(Error::new(
                                        ErrorKind::CatalogCommitConflicts,
                                        format!("Table dropped during commit: {display}"),
                                    ));
                                };

                                if current.version != expected.version
                                    || current.metadata_location != expected.metadata_location
                                {
                                    return Err(Error::new(
                                        ErrorKind::CatalogCommitConflicts,
                                        format!(
                                        "Commit conflict on table {display}: expected version {}, \
                                         found {}",
                                        expected.version, current.version
                                    ),
                                    ));
                                }
                            }
                            // Creating: the assertion is that nothing is there. Two
                            // clients may stage the same name concurrently, so this
                            // is a real race and the loser must be told, not
                            // silently overwrite the winner.
                            //
                            // "Nothing" spans both kinds. Staging claims no name —
                            // a client that never committed has no hold on one —
                            // so a *view* may have taken it in between, and one
                            // namespace holds one thing per name.
                            None => {
                                if views.get(key.as_str()).map_err(db_err)?.is_some() {
                                    return Err(Error::new(
                                        ErrorKind::TableAlreadyExists,
                                        format!(
                                            "{display} was created as a view while this staged \
                                             commit was in flight"
                                        ),
                                    ));
                                }
                                if current.is_some() {
                                    return Err(Error::new(
                                        ErrorKind::CatalogCommitConflicts,
                                        format!(
                                        "Table {display} was created by another writer while this \
                                         staged commit was in flight"
                                    ),
                                    ));
                                }
                            }
                        }

                        let value = serde_json::to_vec(next).map_err(json_err)?;
                        tables
                            .insert(key.as_str(), value.as_slice())
                            .map_err(db_err)?;

                        // The staging note has served its purpose. Removed inside
                        // the same transaction, so a table is never both staged and
                        // real.
                        if expected.is_none() {
                            staged.remove(key.as_str()).map_err(db_err)?;
                        }
                    }
                }
                txn.commit().map_err(db_err)
            })
            .await;

        // A commit that loses its swap has already written its metadata file,
        // and nothing now points at it. Deleting it here is what keeps a
        // contended table from accumulating one abandoned file per lost race —
        // and it is unambiguously safe: this attempt wrote the file moments ago,
        // the pointer swap did not happen, so no reader can reach it.
        //
        // The retry loop above means a heavily contested commit may lose several
        // times; without this, each loss leaves litter that nothing ever
        // collects, because `FileIO` cannot enumerate a directory to find it
        // later. Cleaning up at the only moment the path is known is the whole
        // strategy.
        if let Err(failed) = swap_result {
            for (_, _, _, location) in &prepared {
                if let Err(e) = self.file_io.delete(location).await {
                    // The file becomes a genuine orphan. Worth a record, not
                    // worth failing the request over: the commit already failed,
                    // and the caller's error should be the commit's.
                    tracing::warn!(
                        location = %location,
                        error = %e,
                        "Could not delete the metadata file of a commit that did not land"
                    );
                }
            }
            return Err(failed);
        }

        // The metadata is what was just written, so there is nothing to re-read.
        prepared
            .into_iter()
            .map(|(ident, _, metadata, location)| self.build_table(ident, metadata, location))
            .collect()
    }
}

/// Zero-padded sequence key, so redb's lexicographic order is the log order.
fn policy_key(sequence: u64) -> String {
    format!("{sequence:020}")
}

#[async_trait]
impl crate::auth::policy_store::PolicyStore for RedbCatalog {
    async fn current(
        &self,
    ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>> {
        let found = self
            .blocking(|db| {
                let txn = db.begin_read().map_err(db_err)?;
                let table = txn.open_table(POLICIES).map_err(db_err)?;
                // Last key in order is the newest revision. Decoded into an
                // owned value before the table guard drops.
                let newest = match table.last().map_err(db_err)? {
                    Some((_, value)) => {
                        Some(serde_json::from_slice(value.value()).map_err(json_err)?)
                    }
                    None => None,
                };
                Ok(newest)
            })
            .await?;
        Ok(found)
    }

    async fn append(
        &self,
        source: &str,
        author: &str,
        note: Option<&str>,
    ) -> crate::error::Result<crate::auth::policy_store::PolicyRevision> {
        use crate::auth::policy_store::{PolicyRevision, now_ms, version_of};

        let source = source.to_string();
        let author = author.to_string();
        let note = note.map(str::to_string);

        let revision = self
            .blocking(move |db| {
                // Read and write in one transaction: redb serialises writers, so
                // two replicas cannot mint the same sequence. (A redb catalog is
                // single-process anyway, but the invariant should not depend on
                // that.)
                let txn = db.begin_write().map_err(db_err)?;
                let revision = {
                    let mut table = txn.open_table(POLICIES).map_err(db_err)?;
                    let next = match table.last().map_err(db_err)? {
                        Some((_, value)) => {
                            let previous: PolicyRevision =
                                serde_json::from_slice(value.value()).map_err(json_err)?;
                            previous.sequence + 1
                        }
                        None => 1,
                    };

                    let revision = PolicyRevision {
                        sequence: next,
                        version: version_of(&source),
                        source,
                        author,
                        created_at_ms: now_ms(),
                        note,
                    };

                    let encoded = serde_json::to_vec(&revision).map_err(json_err)?;
                    table
                        .insert(policy_key(next).as_str(), encoded.as_slice())
                        .map_err(db_err)?;
                    revision
                };
                txn.commit().map_err(db_err)?;
                Ok(revision)
            })
            .await?;

        Ok(revision)
    }

    async fn history(
        &self,
        limit: usize,
    ) -> crate::error::Result<Vec<crate::auth::policy_store::PolicyRevisionSummary>> {
        use crate::auth::policy_store::PolicyRevision;

        let summaries = self
            .blocking(move |db| {
                let txn = db.begin_read().map_err(db_err)?;
                let table = txn.open_table(POLICIES).map_err(db_err)?;

                let mut out = Vec::new();
                // Reversed: newest first is what a history listing means.
                for entry in table.iter().map_err(db_err)?.rev().take(limit) {
                    let (_, value) = entry.map_err(db_err)?;
                    let revision: PolicyRevision =
                        serde_json::from_slice(value.value()).map_err(json_err)?;
                    out.push(revision.summary());
                }
                Ok(out)
            })
            .await?;

        Ok(summaries)
    }

    async fn get(
        &self,
        sequence: u64,
    ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>> {
        let key = policy_key(sequence);
        let found = self
            .blocking(move |db| {
                let txn = db.begin_read().map_err(db_err)?;
                let table = txn.open_table(POLICIES).map_err(db_err)?;
                match table.get(key.as_str()).map_err(db_err)? {
                    Some(value) => serde_json::from_slice(value.value())
                        .map(Some)
                        .map_err(json_err),
                    None => Ok(None),
                }
            })
            .await?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(parts: &[&str]) -> NamespaceIdent {
        NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    fn show(key: &str) -> String {
        key.replace(PART_SEPARATOR, "<US>")
            .replace(NAME_SEPARATOR, "<RS>")
    }

    #[test]
    fn namespace_key_uses_unit_separator() {
        assert_eq!(
            show(&RedbCatalog::namespace_key(&ns(&["db", "schema"]))),
            "db<US>schema"
        );
    }

    #[test]
    fn table_key_separates_namespace_from_name() {
        let t = TableIdent::new(ns(&["db"]), "users".to_string());
        assert_eq!(show(&RedbCatalog::table_key(&t)), "db<RS>users");
    }

    /// Dots are legal in names, so joining on `.` would make these collide and
    /// let a table in one namespace be read and overwritten through the other.
    #[test]
    fn dotted_name_does_not_collide_with_nested_namespace() {
        assert_ne!(
            RedbCatalog::namespace_key(&ns(&["a.b"])),
            RedbCatalog::namespace_key(&ns(&["a", "b"]))
        );
        assert_ne!(
            RedbCatalog::table_key(&TableIdent::new(ns(&["a.b"]), "t".into())),
            RedbCatalog::table_key(&TableIdent::new(ns(&["a", "b"]), "t".into()))
        );
    }

    /// A prefix must not match a namespace that merely shares leading characters.
    #[test]
    fn table_prefix_does_not_match_siblings() {
        let prefix = RedbCatalog::table_prefix(&ns(&["db"]));
        for other in [ns(&["db2"]), ns(&["db", "schema"])] {
            let key = RedbCatalog::table_key(&TableIdent::new(other, "t".into()));
            assert!(
                !key.starts_with(&prefix),
                "prefix leaked into {}",
                show(&key)
            );
        }
    }

    #[test]
    fn namespace_child_prefix_matches_only_descendants() {
        let prefix = RedbCatalog::namespace_child_prefix(&ns(&["db"]));
        assert!(RedbCatalog::namespace_key(&ns(&["db", "schema"])).starts_with(&prefix));
        assert!(!RedbCatalog::namespace_key(&ns(&["db2"])).starts_with(&prefix));
        assert!(!RedbCatalog::namespace_key(&ns(&["db"])).starts_with(&prefix));
    }

    /// Regression: deriving the next location from the table location instead of
    /// the current metadata location restarts the counter, so every commit after
    /// the first writes `00001-<uuid>.metadata.json`.
    #[test]
    fn metadata_version_advances_across_commits() {
        let mut current = format!(
            "s3://bucket/wh/db/t/metadata/00003-{}.metadata.json",
            uuid::Uuid::new_v4()
        );
        for expected in ["00004", "00005", "00006"] {
            let next = MetadataLocation::from_str(&current)
                .unwrap()
                .with_next_version()
                .to_string();
            assert!(next.contains(&format!("/{expected}-")), "got {next}");
            current = next;
        }
    }

    // ── Paging cursors ────────────────────────────────────────────────────

    #[test]
    fn a_scan_with_no_cursor_starts_at_the_prefix() {
        let request = PageRequest::first(10);
        assert_eq!(
            RedbCatalog::scan_start("acme\u{1E}", &request),
            "acme\u{1E}"
        );
    }

    #[test]
    fn a_cursor_resumes_strictly_after_itself() {
        let request = PageRequest::after("acme\u{1E}events", 10);
        // The NUL suffix makes the bound exclusive without a separate
        // `Bound::Excluded`, and cannot collide with a validated name.
        assert_eq!(
            RedbCatalog::scan_start("acme\u{1E}", &request),
            "acme\u{1E}events\0"
        );
    }

    /// A page token is client-supplied. One naming another namespace's key must
    /// not seek there — it would let a caller read across a namespace boundary by
    /// editing a token, entirely bypassing the per-row authorization filter.
    #[test]
    fn a_cursor_from_another_namespace_is_ignored() {
        let request = PageRequest::after("secrets\u{1E}salaries", 10);
        assert_eq!(
            RedbCatalog::scan_start("acme\u{1E}", &request),
            "acme\u{1E}",
            "a foreign cursor must restart the scan, not redirect it"
        );
    }
}
