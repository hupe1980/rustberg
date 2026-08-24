//! Postgres-backed catalog, for deployments that need more than one replica.
//!
//! The embedded [`RedbCatalog`](super::RedbCatalog) is one file on local disk,
//! and redb holds an exclusive lock on it — a second process does not degrade
//! into contention, it fails to start with "Database already open". That makes
//! redb an excellent embedded catalog and a poor clustered one: `replicas: 1`, a
//! PersistentVolume, and `strategy: Recreate`.
//!
//! This backend keeps the registry in Postgres, so every replica shares one
//! catalog and concurrency is resolved by the database.
//!
//! ```text
//!   Postgres (registry)                 FileIO (metadata files)
//!   ┌──────────────────────┐            ┌────────────────────────┐
//!   │ namespace → props    │            │ s3://…/metadata/*.json │
//!   │ table → location     │───────────▶│  written here,         │
//!   │ view  → location     │            │  read by engines       │
//!   └──────────────────────┘            └────────────────────────┘
//!        every replica
//! ```
//!
//! # Why not `iceberg-catalog-sql`
//!
//! The upstream crate exists and implements [`Catalog`] over Postgres. It cannot
//! be used here, and the reason is structural rather than a matter of taste.
//!
//! A REST catalog server receives a commit as three raw values — an identifier,
//! a list of [`TableRequirement`]s and a list of [`TableUpdate`]s — and must
//! apply exactly those. The only [`Catalog`] method that accepts them is
//! `update_table(TableCommit)`, and in iceberg-rust 0.10.1 `TableCommit`'s
//! builder carries `#[builder(build_method(vis = "pub(crate)"))]`: the type
//! cannot be constructed outside the `iceberg` crate. The sanctioned
//! alternative, `Transaction`, accepts only typed actions through the
//! `TransactionAction` trait, which is itself `pub(crate)` and so cannot be
//! implemented downstream.
//!
//! So a third-party `Catalog` can be *read* from but never *committed to* by a
//! REST server. Rustberg therefore owns this registry, exactly as it owns the
//! redb one — the commit protocol below is the same three phases, with a SQL
//! transaction where redb has a write transaction.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use async_trait::async_trait;
use iceberg::io::FileIO;
use iceberg::spec::{TableMetadata, TableMetadataBuilder, ViewMetadata};
use iceberg::table::Table;
use iceberg::{
    Error, ErrorKind, MetadataLocation, Namespace, NamespaceIdent, Result, Runtime, TableCreation,
    TableIdent, TableRequirement, TableUpdate,
};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

use super::store::{CatalogStore, Entry, PART_SEPARATOR, Page, PageRequest, StorageHealthStatus};

/// The catalog schema this binary knows how to read.
///
/// Bumped by **any** change to the relations below — a new table, a new column,
/// a changed key, a changed collation. It is not a migration target and never
/// will be while Rustberg is pre-release: it exists so that a database created
/// by a different build is refused with a sentence naming both versions, rather
/// than served with relations that are silently not there. See
/// [`PostgresCatalog::reject_a_schema_this_build_does_not_know`].
const SCHEMA_VERSION: i32 = 1;

/// Maximum attempts for a commit losing its compare-and-swap.
const COMMIT_MAX_RETRIES: u32 = 10;

/// A catalog whose registry lives in Postgres.
#[derive(Debug)]
pub struct PostgresCatalog {
    pool: PgPool,
    file_io: FileIO,
    warehouse_location: String,
    location_scope: crate::location::LocationScope,
    /// Captured at construction so a catalog built outside a Tokio runtime
    /// fails here rather than at the first table read.
    runtime: Runtime,
}

impl PostgresCatalog {
    /// Connects to `uri`, creates the schema if absent, and prepares the catalog.
    ///
    /// The schema is created with `IF NOT EXISTS` on every start rather than
    /// through a migration tool: there is one version of it, and a replica
    /// starting against an already-initialised database must be a no-op, not a
    /// conflict.
    pub async fn connect(uri: &str, warehouse_location: &str) -> Result<Self> {
        super::file_io::ensure_scheme_supported(warehouse_location)?;

        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(uri)
            .await
            .map_err(sql_err)?;

        let catalog = Self {
            pool,
            file_io: super::file_io::build_file_io()?,
            warehouse_location: warehouse_location.trim_end_matches('/').to_string(),
            location_scope: crate::location::LocationScope::default(),
            runtime: Runtime::try_current()?,
        };

        catalog.create_schema().await?;
        Ok(catalog)
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

    /// Returns true if `url` names a Postgres database.
    pub fn handles(url: &str) -> bool {
        url.starts_with("postgres://") || url.starts_with("postgresql://")
    }

    /// Creates the tables and the constraints that keep them consistent.
    ///
    /// # The constraints are the concurrency control
    ///
    /// Every relationship below is a real `FOREIGN KEY`, and that is load-bearing
    /// rather than tidy. The obvious alternative — `SELECT` to check the parent
    /// exists, then `INSERT` — is wrong under Postgres's default `READ
    /// COMMITTED` isolation *even inside a transaction*: a concurrent
    /// `DROP NAMESPACE` that commits between the two statements is invisible to
    /// the reader, and the insert lands under a namespace that no longer exists.
    /// The mirror image is worse: `drop_namespace` checks for tables, a
    /// concurrent `createTable` commits, and the drop succeeds — leaving a table
    /// reachable by exact path and absent from every listing.
    ///
    /// A foreign key has no such window. Inserting a child takes a `FOR KEY
    /// SHARE` lock on the parent row, so a concurrent delete of that row blocks
    /// and then fails; deleting a parent with live children fails outright.
    /// Postgres does the serialisation that a check-then-act cannot.
    ///
    /// The redb backend gets the same guarantee for free — its write
    /// transactions are serialised — so the two backends agree, which is what
    /// the shared conformance tests assert.
    async fn create_schema(&self) -> Result<()> {
        // One statement per call: Postgres rejects multiple statements in an
        // extended-protocol query, which is what sqlx uses.
        //
        // # Every key column is `COLLATE "C"`
        //
        // Not cosmetic, and not a performance tweak. Three things depend on it:
        //
        // - **The two backends must agree.** redb is a byte-ordered B-tree, so
        //   its listings come back in byte order. A `TEXT` column takes the
        //   database's default collation, which on almost every real cluster is
        //   a locale — and a locale orders `Ä` next to `A`, ignores punctuation
        //   at the primary level, and changes between glibc releases. The
        //   conformance tests assert the two backends page identically; without
        //   `"C"` that holds only for names this repository happens to test.
        //
        // - **The separator must not be ignorable.** [`PART_SEPARATOR`] is
        //   U+001F, a control character, which locale collations treat as
        //   *completely ignorable*: `a␟b` and `ab` compare equal at every
        //   strength. Under the default deterministic collation a bytewise
        //   tie-break saves uniqueness — but ordering still interleaves a
        //   namespace's children with unrelated names, and under a
        //   non-deterministic ICU collation the primary key would reject one of
        //   two genuinely distinct namespaces.
        //
        // - **Keyset pagination is `name > $cursor`.** That is only a total
        //   order under a deterministic collation, and only the *same* order as
        //   `ORDER BY name` if both use one collation. A locale that sorts two
        //   distinct names equal makes the cursor skip rows or stall on them.
        //
        // Byte order also makes every index here directly usable for the range
        // scans the listings do, with no collation-aware comparison per row.
        for statement in [
            // `parent` is the namespace one level up, or NULL for a root. It
            // serves two things a separator-counting `LIKE` does badly: finding
            // direct children, which is an index seek rather than a scan over
            // every namespace, and refusing to drop a namespace that has any,
            // which is the self-reference and is checked by the database.
            "CREATE TABLE IF NOT EXISTS rustberg_namespaces (
                 name       TEXT COLLATE \"C\" PRIMARY KEY,
                 parent     TEXT COLLATE \"C\" REFERENCES rustberg_namespaces (name),
                 properties JSONB NOT NULL DEFAULT '{}'::jsonb
             )",
            "CREATE INDEX IF NOT EXISTS rustberg_namespaces_parent
                 ON rustberg_namespaces (parent, name)",
            // Every name a namespace holds, whatever it names.
            //
            // The spec makes a name unique across tables *and* views —
            // `createTable`, `createView`, `renameTable` and `renameView` each
            // answer `409` for "the identifier already exists as a table or
            // view" — and here it is more than an interoperability rule: both
            // kinds are laid out at `<warehouse>/<namespace>/<name>`, so a
            // collision puts two different metadata documents in one directory
            // and makes a purge of the table delete the view's files.
            //
            // A shared primary key is what makes that a **constraint** rather
            // than a check. `SELECT` proving the name is free and then
            // `INSERT`ing is not sound under `READ COMMITTED`, for exactly the
            // reason the namespace foreign keys exist a few lines up.
            //
            // Separate from the two relations rather than merged into one with a
            // `kind` column, for the reason `rustberg_staged_tables` is separate:
            // a discriminator leaves every listing and load one forgotten
            // `WHERE` away from returning the other kind.
            "CREATE TABLE IF NOT EXISTS rustberg_object_names (
                 namespace TEXT COLLATE \"C\" NOT NULL
                           REFERENCES rustberg_namespaces (name),
                 name      TEXT COLLATE \"C\" NOT NULL,
                 PRIMARY KEY (namespace, name)
             )",
            // The namespace foreign key lives on `rustberg_object_names` above
            // and reaches here through it, so dropping a namespace that still
            // holds anything fails on that row rather than on this one.
            "CREATE TABLE IF NOT EXISTS rustberg_tables (
                 namespace                  TEXT COLLATE \"C\" NOT NULL,
                 name                       TEXT COLLATE \"C\" NOT NULL,
                 metadata_location          TEXT NOT NULL,
                 previous_metadata_location TEXT,
                 PRIMARY KEY (namespace, name),
                 FOREIGN KEY (namespace, name)
                     REFERENCES rustberg_object_names (namespace, name)
                     ON DELETE CASCADE
             )",
            // Staged tables live in their own table, not behind a flag on
            // `rustberg_tables`. Every listing, load and existence check reads
            // that table, and a `staged` column would put each of them one
            // forgotten `WHERE` away from exposing a table that does not exist
            // yet. Separation makes that impossible rather than merely unlikely.
            //
            // `ON DELETE CASCADE`, unlike its siblings: a staged table is not a
            // table, and a client that never committed one has no claim on the
            // name. Dropping the namespace takes the staging notes with it, so
            // nothing can later be promoted into a namespace that is gone.
            "CREATE TABLE IF NOT EXISTS rustberg_staged_tables (
                 namespace         TEXT COLLATE \"C\" NOT NULL
                                   REFERENCES rustberg_namespaces (name)
                                   ON DELETE CASCADE,
                 name              TEXT COLLATE \"C\" NOT NULL,
                 metadata_location TEXT NOT NULL,
                 PRIMARY KEY (namespace, name)
             )",
            // Policy revisions: append-only, ordered by sequence. Editing a
            // revision in place would make an old audit record's
            // `policy_set_version` name something that no longer exists.
            "CREATE TABLE IF NOT EXISTS rustberg_policy_revisions (
                 sequence      BIGINT PRIMARY KEY,
                 version       TEXT NOT NULL,
                 source        TEXT NOT NULL,
                 author        TEXT NOT NULL,
                 created_at_ms BIGINT NOT NULL,
                 note          TEXT
             )",
            "CREATE TABLE IF NOT EXISTS rustberg_views (
                 namespace                  TEXT COLLATE \"C\" NOT NULL,
                 name                       TEXT COLLATE \"C\" NOT NULL,
                 metadata_location          TEXT NOT NULL,
                 PRIMARY KEY (namespace, name),
                 FOREIGN KEY (namespace, name)
                     REFERENCES rustberg_object_names (namespace, name)
                     ON DELETE CASCADE
             )",
            // Idempotency receipts, shared so that replicas agree. Held
            // in-process only, a retry that landed on another replica would
            // execute twice — the one thing the key exists to prevent, on the
            // deployment shape that has replicas at all. The in-process cache
            // stays in front of this as the fast path; see
            // `catalog::v1::idempotency`.
            "CREATE TABLE IF NOT EXISTS rustberg_idempotency (
                 key           TEXT COLLATE \"C\" PRIMARY KEY,
                 status        INTEGER NOT NULL,
                 content_type  TEXT,
                 body          BYTEA NOT NULL,
                 expires_at_ms BIGINT NOT NULL
             )",
            "CREATE INDEX IF NOT EXISTS rustberg_idempotency_expiry
                 ON rustberg_idempotency (expires_at_ms)",
        ] {
            sqlx::query(statement)
                .execute(&self.pool)
                .await
                .map_err(sql_err)?;
        }

        self.reject_a_schema_this_build_does_not_know().await
    }

    /// Refuses to serve a database this build's schema does not describe.
    ///
    /// `CREATE TABLE IF NOT EXISTS` is the right shape for a replica coming up
    /// against an already-initialised database, and it cannot reshape one: a
    /// relation added later is created empty while the rows that belong in it
    /// stay where they were, a column added later is simply absent. That
    /// surfaces as tables reporting themselves missing, which points at nothing.
    ///
    /// A stamp asks the question once and covers every future change, where a
    /// detector per change is a list somebody has to remember to extend.
    ///
    /// Refused rather than migrated: Rustberg is pre-release and ships no
    /// migrations, and recreating the database is the only answer that is safe
    /// without knowing how the existing rows got there. What matters is that the
    /// operator is told, in a sentence naming both versions.
    async fn reject_a_schema_this_build_does_not_know(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS rustberg_schema_version (
                 id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
                 version     INTEGER NOT NULL,
                 created_by  TEXT NOT NULL,
                 created_at_ms BIGINT NOT NULL
             )",
        )
        .execute(&self.pool)
        .await
        .map_err(sql_err)?;

        // Claims the stamp only if nothing has claimed it. `ON CONFLICT DO
        // NOTHING` rather than a read followed by a write, because several
        // replicas start at once and the check-then-act between them is the same
        // race the foreign keys above exist to avoid.
        sqlx::query(
            "INSERT INTO rustberg_schema_version (id, version, created_by, created_at_ms)
             VALUES (TRUE, $1, $2, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(SCHEMA_VERSION)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        )
        .execute(&self.pool)
        .await
        .map_err(sql_err)?;

        let (found, created_by): (i32, String) =
            sqlx::query_as("SELECT version, created_by FROM rustberg_schema_version WHERE id")
                .fetch_one(&self.pool)
                .await
                .map_err(sql_err)?;

        if found != SCHEMA_VERSION {
            return Err(Error::new(
                ErrorKind::Unexpected,
                format!(
                    "This database was created with Rustberg catalog schema v{found} (by \
                     version {created_by}), and this binary serves schema v{SCHEMA_VERSION}. \
                     `CREATE TABLE IF NOT EXISTS` cannot reshape an existing database, so \
                     serving it would mean reading relations and columns that are not there \
                     — which shows up as missing tables rather than as a schema error. \
                     Rustberg is pre-release and ships no migrations: point \
                     `catalog.url` at a fresh database, or drop the `rustberg_*` \
                     relations in this one and start again."
                ),
            ));
        }

        Ok(())
    }

    // ── Keys and locations ──────────────────────────────────────────────

    fn namespace_key(ns: &NamespaceIdent) -> String {
        ns.as_ref().join(&PART_SEPARATOR.to_string())
    }

    fn key_to_namespace(key: &str) -> NamespaceIdent {
        NamespaceIdent::from_vec(key.split(PART_SEPARATOR).map(str::to_string).collect())
            .unwrap_or_else(|_| NamespaceIdent::new(key.to_string()))
    }

    /// A storage key rendered the way a client wrote it, for an error message.
    fn key_to_display(key: &str) -> String {
        Self::key_to_namespace(key).join(".")
    }

    /// Reads a write that broke a namespace foreign key as "no such namespace".
    ///
    /// The insert is the check: `rustberg_tables`, `rustberg_views` and
    /// `rustberg_staged_tables` all reference `rustberg_namespaces`, so a
    /// namespace dropped concurrently makes the write fail rather than succeed
    /// into nothing.
    fn missing_namespace_or(e: sqlx::Error, namespace: &NamespaceIdent) -> Error {
        if is_foreign_key_violation(&e) {
            Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            )
        } else {
            sql_err(e)
        }
    }

    /// What is still inside a namespace whose drop the database refused.
    ///
    /// Best-effort and for the error message only — the refusal has already
    /// been decided by the constraint. A query that fails here yields the
    /// generic wording rather than turning a `409` into a `500`.
    async fn describe_occupants(&self, key: &str) -> &'static str {
        for (query, what) in [
            (
                "SELECT 1 AS present FROM rustberg_namespaces WHERE parent = $1 LIMIT 1",
                "child namespaces",
            ),
            (
                "SELECT 1 AS present FROM rustberg_tables WHERE namespace = $1 LIMIT 1",
                "tables",
            ),
            (
                "SELECT 1 AS present FROM rustberg_views WHERE namespace = $1 LIMIT 1",
                "views",
            ),
        ] {
            if let Ok(Some(_)) = sqlx::query(query)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
            {
                return what;
            }
        }
        "other objects"
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

    /// Claims `name` in `namespace_key` for a table or a view.
    ///
    /// `Ok(false)` when the name is already taken — by either kind, which is the
    /// point. The insert *is* the decision: two concurrent creates both reach
    /// here and only one wins the primary key, so nothing has to be checked
    /// first and nothing can be raced in between.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NamespaceNotFound`] when the namespace is gone — reported by
    /// the foreign key rather than by a `SELECT`, because a `SELECT` proving it
    /// still exists is stale the moment it returns.
    async fn claim_name(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        namespace: &NamespaceIdent,
        namespace_key: &str,
        name: &str,
    ) -> Result<bool> {
        let claimed = sqlx::query(
            "INSERT INTO rustberg_object_names (namespace, name)
             VALUES ($1, $2) ON CONFLICT (namespace, name) DO NOTHING",
        )
        .bind(namespace_key)
        .bind(name)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::missing_namespace_or(e, namespace))?;

        Ok(claimed.rows_affected() > 0)
    }

    /// Gives up a claim, so a rollback or a rename leaves nothing behind.
    async fn release_name(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        namespace_key: &str,
        name: &str,
    ) -> Result<()> {
        sqlx::query("DELETE FROM rustberg_object_names WHERE namespace = $1 AND name = $2")
            .bind(namespace_key)
            .bind(name)
            .execute(&mut **tx)
            .await
            .map_err(sql_err)?;
        Ok(())
    }

    /// Drops one object by releasing its name, which cascades to whichever
    /// relation holds it.
    ///
    /// `holder` names the relation the caller expects it in, so `dropTable` on a
    /// view reports the view missing instead of deleting it. The `EXISTS` and the
    /// `DELETE` are one statement, so that guard cannot be raced either.
    async fn release_if_held_by(&self, ident: &TableIdent, holder: &str) -> Result<bool> {
        let sql = format!(
            "DELETE FROM rustberg_object_names
             WHERE namespace = $1 AND name = $2
               AND EXISTS (SELECT 1 FROM {holder} WHERE namespace = $1 AND name = $2)"
        );
        let deleted = sqlx::query(&sql)
            .bind(Self::namespace_key(ident.namespace()))
            .bind(ident.name())
            .execute(&self.pool)
            .await
            .map_err(sql_err)?;

        Ok(deleted.rows_affected() > 0)
    }

    fn table_location(&self, ident: &TableIdent) -> String {
        format!(
            "{}/{}/{}",
            self.warehouse_location,
            ident.namespace().as_ref().join("/"),
            ident.name()
        )
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

    async fn read_metadata(&self, location: &str) -> Result<TableMetadata> {
        TableMetadata::read_from(&self.file_io, location).await
    }

    async fn table_pointer(&self, ident: &TableIdent) -> Result<Option<String>> {
        let row: Option<PgRow> = sqlx::query(
            "SELECT metadata_location FROM rustberg_tables WHERE namespace = $1 AND name = $2",
        )
        .bind(Self::namespace_key(ident.namespace()))
        .bind(ident.name())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(row.map(|r| r.get::<String, _>("metadata_location")))
    }

    async fn build_table(&self, ident: &TableIdent, metadata_location: &str) -> Result<Table> {
        let metadata = self.read_metadata(metadata_location).await?;

        Table::builder()
            .runtime(self.runtime.clone())
            .identifier(ident.clone())
            .metadata(metadata)
            .metadata_location(metadata_location.to_string())
            .file_io(self.file_io.clone())
            .build()
    }

    /// Validates `requirements` against current metadata and produces the next
    /// metadata, without touching the registry.
    ///
    /// Kept separate from the pointer swap so the expensive part — reading and
    /// writing object storage — happens outside any database transaction.
    async fn stage_commit(
        &self,
        ident: &TableIdent,
        requirements: &[TableRequirement],
        updates: &[TableUpdate],
    ) -> Result<StagedCommit> {
        // Two shapes of commit arrive here. The ordinary one updates a table
        // that exists. The other *creates* one: a client that staged a table
        // with `stage-create` commits it carrying `assert-create`, and the table
        // deliberately does not exist until this moment.
        let creating = requirements
            .iter()
            .any(|r| matches!(r, TableRequirement::NotExist));

        let (current_location, exists) = match self.table_pointer(ident).await? {
            Some(location) => (location, true),
            None if creating => {
                let staged = self.staged_pointer(ident).await?.ok_or_else(|| {
                    Error::new(
                        ErrorKind::TableNotFound,
                        format!(
                            "{ident} was not staged. A commit asserting the table does not exist \
                             must follow a `stage-create`."
                        ),
                    )
                })?;
                (staged, false)
            }
            None => return Err(Error::new(ErrorKind::TableNotFound, format!("{ident}"))),
        };

        let metadata = self.read_metadata(&current_location).await?;

        // Requirements are checked against what the *catalog* holds, which for a
        // create is nothing — `assert-create` passes precisely because there is
        // no table, and any other requirement correctly fails against `None`.
        let current = if exists { Some(&metadata) } else { None };
        for requirement in requirements {
            requirement.check(current).map_err(|e| {
                Error::new(
                    e.kind(),
                    format!("Requirement failed for table {ident}: {}", e.message()),
                )
            })?;
        }

        // The staged metadata is the base, and the client's updates are applied
        // over it. They overlap — a staged create sends back the schema and spec
        // it was given — but the builder reuses an identical schema, spec or
        // sort order rather than duplicating it, so re-applying them is a no-op
        // and only the new snapshot lands.
        // A stale v3 row-id assignment is a lost race, not a malformed request.
        // Reported before the builder sees it, so it leaves as a `409` the client
        // will retry rather than a `400` it will not — see
        // `store::reject_stale_row_lineage`.
        super::store::reject_stale_row_lineage(ident, &metadata, updates)?;

        // The four locations a commit carries, checked here because this is
        // where the table's *current* location is already in hand. A handler
        // would have to load the table a second time to learn it, on the hottest
        // write path — and the bound needs it: rename never moves files, so a
        // renamed table's files are not under the prefix its new name implies.
        // See `location::LocationBound::ensure_commit`.
        self.declared_bound(ident.namespace().as_ref(), ident.name())
            .ensure_commit(metadata.location(), updates)?;

        let mut builder = metadata
            .clone()
            .into_builder(Some(current_location.clone()));
        for update in updates {
            builder = update.clone().apply(builder)?;
        }
        let new_metadata = builder.build()?.metadata;

        let new_location = Self::next_metadata_location(&current_location, &new_metadata);
        new_metadata.write_to(&self.file_io, &new_location).await?;

        Ok(StagedCommit {
            ident: ident.clone(),
            current_location,
            new_location: new_location.to_string(),
            creating: !exists,
        })
    }

    /// Exponential backoff with full jitter.
    ///
    /// Jitter matters: without it, writers that collide once tend to collide
    /// again because they all wake at the same instant.
    fn commit_backoff(attempt: u32) -> std::time::Duration {
        let exp = std::time::Duration::from_millis(10).saturating_mul(1u32 << attempt.min(6));
        exp.min(std::time::Duration::from_millis(500))
            .mul_f64(rand::random::<f64>().clamp(0.0, 1.0))
    }
}

/// A commit whose metadata file is written and whose pointer is not yet moved.
struct StagedCommit {
    ident: TableIdent,
    current_location: String,
    new_location: String,
    /// True when this commit *creates* the table, promoting a `stage-create`
    /// rather than advancing an existing pointer.
    creating: bool,
}

#[async_trait]
impl CatalogStore for PostgresCatalog {
    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: &PageRequest,
    ) -> Result<Page<NamespaceIdent>> {
        let parent_key = match parent {
            Some(p) => {
                if !self.namespace_exists(p).await? {
                    return Err(Error::new(
                        ErrorKind::NamespaceNotFound,
                        p.join(".").to_string(),
                    ));
                }
                Some(Self::namespace_key(p))
            }
            None => None,
        };

        // "Direct children only" is the `parent` column, so this is an index
        // seek on `(parent, name)`. A `LIKE` prefix plus a separator count
        // computed with `length(replace(...))` is what no index can serve, and
        // would make every listing read every namespace in the catalog.
        //
        // `IS NOT DISTINCT FROM` rather than `=`, because the roots have a NULL
        // parent and `NULL = NULL` is not true.
        let rows = sqlx::query(
            "SELECT name FROM rustberg_namespaces \
             WHERE parent IS NOT DISTINCT FROM $1 \
               AND ($2::text IS NULL OR name > $2) \
             ORDER BY name LIMIT $3",
        )
        .bind(parent_key.as_deref())
        .bind(page.after.as_deref())
        .bind(page.probe_limit() as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_err)?;

        let entries = rows
            .into_iter()
            .map(|r| {
                let key: String = r.get("name");
                Entry {
                    item: Self::key_to_namespace(&key),
                    cursor: key,
                }
            })
            .collect();

        Ok(Page::from_probe(entries, page))
    }

    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        // A nested namespace requires its parent, so the tree cannot grow holes.
        // That is the self-reference on `parent`, not a check here: a `SELECT`
        // proving the parent exists is stale the instant it returns, and the
        // window it leaves is a namespace dropped between the check and the
        // insert.
        let parent = namespace
            .as_ref()
            .split_last()
            .filter(|(_, rest)| !rest.is_empty())
            .map(|(_, rest)| NamespaceIdent::from_vec(rest.to_vec()))
            .transpose()?
            .map(|parent| Self::namespace_key(&parent));

        let inserted = sqlx::query(
            "INSERT INTO rustberg_namespaces (name, parent, properties) VALUES ($1, $2, $3)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(Self::namespace_key(namespace))
        .bind(parent.as_deref())
        .bind(serde_json::to_value(&properties).map_err(json_err)?)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_foreign_key_violation(&e) {
                Error::new(
                    ErrorKind::NamespaceNotFound,
                    format!(
                        "Parent namespace not found: {}",
                        parent
                            .as_deref()
                            .map_or_else(String::new, Self::key_to_display)
                    ),
                )
            } else {
                sql_err(e)
            }
        })?;

        if inserted.rows_affected() == 0 {
            return Err(Error::new(
                ErrorKind::NamespaceAlreadyExists,
                namespace.join(".").to_string(),
            ));
        }

        Ok(Namespace::with_properties(namespace.clone(), properties))
    }

    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        let row = sqlx::query("SELECT properties FROM rustberg_namespaces WHERE name = $1")
            .bind(Self::namespace_key(namespace))
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err)?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NamespaceNotFound,
                    namespace.join(".").to_string(),
                )
            })?;

        let properties: HashMap<String, String> =
            serde_json::from_value(row.get("properties")).map_err(json_err)?;

        Ok(Namespace::with_properties(namespace.clone(), properties))
    }

    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        let row = sqlx::query("SELECT 1 AS present FROM rustberg_namespaces WHERE name = $1")
            .bind(Self::namespace_key(namespace))
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err)?;

        Ok(row.is_some())
    }

    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()> {
        let updated = sqlx::query("UPDATE rustberg_namespaces SET properties = $2 WHERE name = $1")
            .bind(Self::namespace_key(namespace))
            .bind(serde_json::to_value(&properties).map_err(json_err)?)
            .execute(&self.pool)
            .await
            .map_err(sql_err)?;

        if updated.rows_affected() == 0 {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        Ok(())
    }

    /// Drops a namespace, provided nothing lives in it.
    ///
    /// "Nothing lives in it" is enforced by the foreign keys, not by the
    /// `SELECT`s below. A check-then-delete has a window — a `createTable` that
    /// commits between the two is invisible to a `READ COMMITTED` reader — and
    /// what falls into it is a table under a namespace that no longer exists:
    /// loadable by exact path, absent from every listing, and impossible to drop
    /// through the API.
    ///
    /// So the delete is simply attempted, and the constraint refuses it. The
    /// queries run only *afterwards*, to turn `foreign_key_violation` into a
    /// sentence naming what is still in there — which the constraint cannot say
    /// and the caller needs to hear.
    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        let key = Self::namespace_key(namespace);

        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        let exists = sqlx::query("SELECT 1 AS present FROM rustberg_namespaces WHERE name = $1")
            .bind(&key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(sql_err)?;
        if exists.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        // Staged tables cascade with the namespace — they are not tables, and a
        // client that never committed one has no claim on the name.
        let deleted = sqlx::query("DELETE FROM rustberg_namespaces WHERE name = $1")
            .bind(&key)
            .execute(&mut *tx)
            .await;

        match deleted {
            Ok(_) => {
                tx.commit().await.map_err(sql_err)?;
                Ok(())
            }
            Err(e) if is_foreign_key_violation(&e) => {
                // The transaction is poisoned by the failed statement, so the
                // diagnostic runs on a fresh connection. It is allowed to be
                // approximate: the refusal already happened, and this only
                // decides which noun the message uses.
                tx.rollback().await.ok();
                Err(Error::new(
                    ErrorKind::PreconditionFailed,
                    format!(
                        "Namespace {} is not empty: it still contains {}",
                        namespace.join("."),
                        self.describe_occupants(&key).await
                    ),
                ))
            }
            Err(e) => Err(sql_err(e)),
        }
    }
    async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        if !self.namespace_exists(namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        // Keyset pagination: resume from the last name rather than OFFSET, so
        // page N costs the same as page 1 and a concurrent insert cannot shift
        // rows across a page boundary.
        let rows = sqlx::query(
            "SELECT name FROM rustberg_tables \
             WHERE namespace = $1 AND ($2::text IS NULL OR name > $2) \
             ORDER BY name LIMIT $3",
        )
        .bind(Self::namespace_key(namespace))
        .bind(page.after.as_deref())
        .bind(page.probe_limit() as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_err)?;

        let entries = rows
            .into_iter()
            .map(|r| {
                let name: String = r.get("name");
                Entry {
                    item: TableIdent::new(namespace.clone(), name.clone()),
                    cursor: name,
                }
            })
            .collect();

        Ok(Page::from_probe(entries, page))
    }

    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        // Not checked here: the foreign key on `rustberg_tables.namespace` is
        // what decides, so a namespace dropped concurrently loses the race
        // instead of falling through a check-then-act window.
        let ident = TableIdent::new(namespace.clone(), creation.name.clone());

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

        // The name claim is what decides the race: two concurrent creates both
        // write a metadata file, but only one wins the shared primary key. The
        // loser's file is unreferenced rather than corrupting anything — and the
        // key is shared with views, so "already exists as a table or view" is one
        // answer rather than two checks.
        let namespace_key = Self::namespace_key(namespace);
        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        if !Self::claim_name(&mut tx, namespace, &namespace_key, ident.name()).await? {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                ident.name().to_string(),
            ));
        }

        sqlx::query(
            "INSERT INTO rustberg_tables (namespace, name, metadata_location)
             VALUES ($1, $2, $3)",
        )
        .bind(&namespace_key)
        .bind(ident.name())
        .bind(&metadata_location)
        .execute(&mut *tx)
        .await
        .map_err(sql_err)?;

        tx.commit().await.map_err(sql_err)?;

        Table::builder()
            .runtime(self.runtime.clone())
            .identifier(ident)
            .metadata(metadata)
            .metadata_location(metadata_location)
            .file_io(self.file_io.clone())
            .build()
    }

    async fn stage_create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        if !self.namespace_exists(namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        let ident = TableIdent::new(namespace.clone(), creation.name.clone());

        // A name already taken by a real table cannot be staged onto: the
        // eventual commit asserts the table does not exist and would fail, so
        // failing now says the same thing while the client can still act on it.
        if self.table_pointer(&ident).await?.is_some() {
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

        // Overwrites any earlier staging of the same name. Staging reserves
        // nothing, so a client that stages twice simply gets the later one;
        // refusing would strand a client that retried after a timeout.
        sqlx::query(
            "INSERT INTO rustberg_staged_tables (namespace, name, metadata_location)
             VALUES ($1, $2, $3)
             ON CONFLICT (namespace, name) DO UPDATE SET metadata_location = EXCLUDED.metadata_location",
        )
        .bind(Self::namespace_key(namespace))
        .bind(ident.name())
        .bind(&metadata_location)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::missing_namespace_or(e, namespace))?;

        self.build_table(&ident, &metadata_location).await
    }

    async fn metadata_pointer(&self, table: &TableIdent) -> Result<Option<String>> {
        self.table_pointer(table).await
    }

    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        let location = self
            .table_pointer(table)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::TableNotFound, format!("{table}")))?;

        self.build_table(table, &location).await
    }

    async fn drop_table(&self, table: &TableIdent) -> Result<()> {
        // Releasing the name cascades to the row that holds it. Guarded on
        // `rustberg_tables` so `dropTable` against a *view* of the same name
        // reports the table missing rather than deleting the view.
        if !self.release_if_held_by(table, "rustberg_tables").await? {
            return Err(Error::new(ErrorKind::TableNotFound, format!("{table}")));
        }

        Ok(())
    }

    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        Ok(self.table_pointer(table).await?.is_some())
    }

    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        let dest_namespace = Self::namespace_key(dest.namespace());
        let target_namespace_exists =
            sqlx::query("SELECT 1 AS present FROM rustberg_namespaces WHERE name = $1")
                .bind(&dest_namespace)
                .fetch_optional(&mut *tx)
                .await
                .map_err(sql_err)?;

        if target_namespace_exists.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                dest.namespace().join(".").to_string(),
            ));
        }

        // Claiming the destination name is the collision check, and it covers a
        // view of that name as well as a table — which is what the spec's
        // "already exists as a table or view" asks for.
        if !Self::claim_name(&mut tx, dest.namespace(), &dest_namespace, dest.name()).await? {
            return Err(Error::new(ErrorKind::TableAlreadyExists, format!("{dest}")));
        }

        let renamed = sqlx::query(
            "UPDATE rustberg_tables SET namespace = $3, name = $4
             WHERE namespace = $1 AND name = $2",
        )
        .bind(Self::namespace_key(src.namespace()))
        .bind(src.name())
        .bind(&dest_namespace)
        .bind(dest.name())
        .execute(&mut *tx)
        .await
        .map_err(sql_err)?;

        if renamed.rows_affected() == 0 {
            // The destination claim succeeded, so the only way to be here is a
            // source that is not a table — absent, or a view of that name. The
            // rollback below gives the claim back.
            return Err(Error::new(ErrorKind::TableNotFound, format!("{src}")));
        }

        // The row moved, so the old name holds nothing. Released last, because
        // the cascade would take the row with it were it released first.
        Self::release_name(&mut tx, &Self::namespace_key(src.namespace()), src.name()).await?;

        tx.commit().await.map_err(sql_err)?;
        Ok(())
    }

    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table> {
        // Answered early so the caller is not charged for reading and confining
        // a metadata document that was never going to be adopted. It is not the
        // enforcement — the foreign key on the insert is, and it is what closes
        // the window this check leaves open.
        if !self.namespace_exists(table.namespace()).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                table.namespace().join(".").to_string(),
            ));
        }

        // Read and confine before the insert, never after it. The location the
        // metadata *declares* is what a vended credential is scoped to, and this
        // is the one read that is safe to check: the one being adopted.
        let metadata = self.read_metadata(&metadata_location).await?;
        self.declared_bound(table.namespace().as_ref(), table.name())
            .ensure_iceberg(metadata.location())?;

        let namespace_key = Self::namespace_key(table.namespace());
        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        let claimed =
            Self::claim_name(&mut tx, table.namespace(), &namespace_key, table.name()).await?;
        if claimed {
            sqlx::query(
                "INSERT INTO rustberg_tables (namespace, name, metadata_location)
                 VALUES ($1, $2, $3)",
            )
            .bind(&namespace_key)
            .bind(table.name())
            .bind(&metadata_location)
            .execute(&mut *tx)
            .await
            .map_err(sql_err)?;
            tx.commit().await.map_err(sql_err)?;
        }

        if !claimed {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!("{table}"),
            ));
        }

        self.build_table(table, &metadata_location).await
    }

    async fn purge_table(&self, table: &TableIdent) -> Result<()> {
        let loaded = self.load_table(table).await?;
        self.drop_table(table).await?;

        // Data deletion after the registry entry is gone: if this fails the
        // table is still dropped, and what remains is unreferenced files rather
        // than a live table missing its data.
        //
        // Confined to the storage the table owns. See `catalog::purge` for why a
        // catalog cannot use `iceberg::drop_table_data`: it deletes with the
        // *server's* role, from paths a caller wrote.
        crate::catalog::purge::purge_table_data(&loaded).await
    }

    async fn commit_table(
        &self,
        table_ident: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        self.commit_tables_atomic(vec![(table_ident.clone(), requirements, updates)])
            .await?
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "Commit produced no table"))
    }

    /// Commits several tables so that either all advance or none do.
    ///
    /// Three phases, matching the redb backend: validate requirements and write
    /// the new metadata files outside any transaction, then swap every pointer
    /// inside one SQL transaction, each swap conditional on the location it read.
    /// A swap that matches nothing means another writer moved that pointer
    /// first — the transaction rolls back and the whole commit retries, so no
    /// caller ever observes a half-applied transaction.
    async fn commit_tables_atomic(
        &self,
        table_changes: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        if table_changes.is_empty() {
            return Ok(Vec::new());
        }

        for attempt in 0..COMMIT_MAX_RETRIES {
            // Phase 1 & 2 — validate and write metadata, outside the transaction.
            let mut staged = Vec::with_capacity(table_changes.len());
            for (ident, requirements, updates) in &table_changes {
                staged.push(self.stage_commit(ident, requirements, updates).await?);
            }

            // Row locks are taken in a globally consistent order, not the order
            // the client happened to list the tables in. Two transactions that
            // touch {A, B} and {B, A} would otherwise each hold one row and wait
            // for the other, and Postgres would break the tie by aborting one
            // with a deadlock error — a failure caused purely by argument order.
            //
            // Sorting only the *locking* order keeps results in request order,
            // which is what the trait promises.
            let mut lock_order: Vec<usize> = (0..staged.len()).collect();
            lock_order.sort_by_key(|&i| {
                (
                    Self::namespace_key(staged[i].ident.namespace()),
                    staged[i].ident.name().to_string(),
                )
            });

            // Phase 3 — swap every pointer in one transaction.
            let mut tx = self.pool.begin().await.map_err(sql_err)?;
            let mut conflict = false;

            for entry in lock_order.iter().map(|&i| &staged[i]) {
                // A namespace dropped between staging and commit is caught by
                // the foreign key on the insert below, not by a check here: a
                // `SELECT` proving it still exists is stale the moment it
                // returns, and what falls through that window is a table inside
                // a namespace that is gone.
                let swapped = if entry.creating {
                    // Promoting a staged table. Staging claims no name — a
                    // client that never committed has no hold on one — so the
                    // claim happens here, and it is the assertion that the name
                    // is free: two clients may stage the same name concurrently,
                    // and a view may have taken it in between. The loser must be
                    // told rather than silently overwrite the winner.
                    let namespace_key = Self::namespace_key(entry.ident.namespace());
                    if !Self::claim_name(
                        &mut tx,
                        entry.ident.namespace(),
                        &namespace_key,
                        entry.ident.name(),
                    )
                    .await?
                    {
                        conflict = true;
                        break;
                    }

                    sqlx::query(
                        "INSERT INTO rustberg_tables (namespace, name, metadata_location)
                         VALUES ($1, $2, $3)",
                    )
                    .bind(&namespace_key)
                    .bind(entry.ident.name())
                    .bind(&entry.new_location)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        if is_foreign_key_violation(&e) {
                            Error::new(
                                ErrorKind::NamespaceNotFound,
                                format!(
                                    "Namespace {} was dropped while {} was staged",
                                    entry.ident.namespace().join("."),
                                    entry.ident
                                ),
                            )
                        } else {
                            sql_err(e)
                        }
                    })?
                } else {
                    sqlx::query(
                        "UPDATE rustberg_tables
                         SET previous_metadata_location = metadata_location,
                             metadata_location = $4
                         WHERE namespace = $1 AND name = $2 AND metadata_location = $3",
                    )
                    .bind(Self::namespace_key(entry.ident.namespace()))
                    .bind(entry.ident.name())
                    .bind(&entry.current_location)
                    .bind(&entry.new_location)
                    .execute(&mut *tx)
                    .await
                    .map_err(sql_err)?
                };

                if swapped.rows_affected() == 0 {
                    conflict = true;
                    break;
                }

                // The staging note has served its purpose. Removed inside the
                // same transaction, so a table is never both staged and real.
                if entry.creating {
                    sqlx::query(
                        "DELETE FROM rustberg_staged_tables WHERE namespace = $1 AND name = $2",
                    )
                    .bind(Self::namespace_key(entry.ident.namespace()))
                    .bind(entry.ident.name())
                    .execute(&mut *tx)
                    .await
                    .map_err(sql_err)?;
                }
            }

            if conflict {
                tx.rollback().await.map_err(sql_err)?;

                // This attempt wrote a metadata file per table and then lost its
                // swap, so nothing points at any of them. Deleting them here is
                // what keeps a contended table from accumulating one abandoned
                // file per lost race — `FileIO` cannot enumerate a directory, so
                // this is the only moment their paths are known.
                self.discard_written_metadata(&staged).await;

                tokio::time::sleep(Self::commit_backoff(attempt)).await;
                continue;
            }

            tx.commit().await.map_err(sql_err)?;

            let mut committed = Vec::with_capacity(staged.len());
            for entry in &staged {
                committed.push(self.build_table(&entry.ident, &entry.new_location).await?);
            }
            return Ok(committed);
        }

        Err(Error::new(
            ErrorKind::CatalogCommitConflicts,
            format!("Commit failed after {COMMIT_MAX_RETRIES} attempts due to concurrent updates"),
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
        let started = Instant::now();

        match sqlx::query("SELECT 1 AS ok").fetch_one(&self.pool).await {
            Ok(_) => Ok(StorageHealthStatus::healthy(
                "postgres",
                started.elapsed().as_millis() as u64,
            )),
            Err(e) => Ok(StorageHealthStatus::unhealthy(
                "postgres",
                format!("Catalog query failed: {e}"),
            )),
        }
    }

    // ── Views ───────────────────────────────────────────────────────────

    async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        if !self.namespace_exists(namespace).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                namespace.join(".").to_string(),
            ));
        }

        // Keyset pagination: resume from the last name rather than OFFSET, so
        // page N costs the same as page 1 and a concurrent insert cannot shift
        // rows across a page boundary.
        let rows = sqlx::query(
            "SELECT name FROM rustberg_views \
             WHERE namespace = $1 AND ($2::text IS NULL OR name > $2) \
             ORDER BY name LIMIT $3",
        )
        .bind(Self::namespace_key(namespace))
        .bind(page.after.as_deref())
        .bind(page.probe_limit() as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_err)?;

        let entries = rows
            .into_iter()
            .map(|r| {
                let name: String = r.get("name");
                Entry {
                    item: TableIdent::new(namespace.clone(), name.clone()),
                    cursor: name,
                }
            })
            .collect();

        Ok(Page::from_probe(entries, page))
    }

    async fn view_exists(&self, view: &TableIdent) -> Result<bool> {
        Ok(self.view_pointer(view).await?.is_some())
    }

    async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)> {
        let location = self
            .view_pointer(view)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::TableNotFound, format!("{view}")))?;

        let metadata = self.read_view_metadata(&location).await?;
        Ok((location, metadata))
    }

    async fn register_view(
        &self,
        view: &TableIdent,
        metadata_location: String,
    ) -> Result<(String, ViewMetadata)> {
        if !self.namespace_exists(view.namespace()).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                view.namespace().join(".").to_string(),
            ));
        }

        // Read, never rewrite: registration adopts the caller's metadata, and
        // writing a fresh file would discard the version history being adopted.
        let metadata = self.read_view_metadata(&metadata_location).await?;
        self.declared_bound(view.namespace().as_ref(), view.name())
            .ensure_iceberg(metadata.location())?;

        let namespace_key = Self::namespace_key(view.namespace());
        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        if !Self::claim_name(&mut tx, view.namespace(), &namespace_key, view.name()).await? {
            return Err(Error::new(ErrorKind::TableAlreadyExists, format!("{view}")));
        }

        sqlx::query(
            "INSERT INTO rustberg_views (namespace, name, metadata_location)
             VALUES ($1, $2, $3)",
        )
        .bind(&namespace_key)
        .bind(view.name())
        .bind(&metadata_location)
        .execute(&mut *tx)
        .await
        .map_err(sql_err)?;

        tx.commit().await.map_err(sql_err)?;

        Ok((metadata_location, metadata))
    }

    async fn create_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        if !self.namespace_exists(view.namespace()).await? {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                view.namespace().join(".").to_string(),
            ));
        }

        let location = self.view_metadata_location(view);
        self.write_view_metadata(&location, &metadata).await?;

        let namespace_key = Self::namespace_key(view.namespace());
        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        if !Self::claim_name(&mut tx, view.namespace(), &namespace_key, view.name()).await? {
            return Err(Error::new(ErrorKind::TableAlreadyExists, format!("{view}")));
        }

        sqlx::query(
            "INSERT INTO rustberg_views (namespace, name, metadata_location)
             VALUES ($1, $2, $3)",
        )
        .bind(&namespace_key)
        .bind(view.name())
        .bind(&location)
        .execute(&mut *tx)
        .await
        .map_err(sql_err)?;

        tx.commit().await.map_err(sql_err)?;

        Ok((location, metadata))
    }

    async fn update_view(
        &self,
        view: &TableIdent,
        expected_metadata_location: &str,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        let location = self.view_metadata_location(view);
        self.write_view_metadata(&location, &metadata).await?;

        // Conditional on the pointer the caller read. An unconditional `UPDATE`
        // here is a lost update, not a swap: two commits both write their own
        // metadata file — the names carry UUIDs, so neither corrupts the other —
        // and then the second `UPDATE` silently replaces the first's pointer.
        // Both callers are told they succeeded and one of them did not. See
        // `CatalogStore::update_view`.
        //
        // One statement, so there is no window: Postgres takes a row lock for
        // the `UPDATE` and re-evaluates the predicate against the committed row.
        let updated = sqlx::query(
            "UPDATE rustberg_views SET metadata_location = $3 \
             WHERE namespace = $1 AND name = $2 AND metadata_location = $4",
        )
        .bind(Self::namespace_key(view.namespace()))
        .bind(view.name())
        .bind(&location)
        .bind(expected_metadata_location)
        .execute(&self.pool)
        .await
        .map_err(sql_err)?;

        if updated.rows_affected() == 0 {
            // Nothing matched, and the two reasons need different answers: the
            // view is gone (`404`) or somebody else committed first (`409`, and
            // the client refreshes and retries). Asked afterwards rather than
            // before, so the ordinary path is one statement.
            let exists: Option<String> = sqlx::query_scalar(
                "SELECT metadata_location FROM rustberg_views WHERE namespace = $1 AND name = $2",
            )
            .bind(Self::namespace_key(view.namespace()))
            .bind(view.name())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err)?;

            return Err(match exists {
                Some(_) => Error::new(
                    ErrorKind::CatalogCommitConflicts,
                    "View was modified concurrently",
                ),
                None => Error::new(ErrorKind::TableNotFound, format!("{view}")),
            });
        }

        Ok((location, metadata))
    }

    async fn drop_view(&self, view: &TableIdent) -> Result<()> {
        if !self.release_if_held_by(view, "rustberg_views").await? {
            return Err(Error::new(ErrorKind::TableNotFound, format!("{view}")));
        }

        Ok(())
    }

    async fn rename_view(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        if src == dest {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(sql_err)?;

        let dest_namespace = Self::namespace_key(dest.namespace());
        let target_namespace_exists =
            sqlx::query("SELECT 1 AS present FROM rustberg_namespaces WHERE name = $1")
                .bind(&dest_namespace)
                .fetch_optional(&mut *tx)
                .await
                .map_err(sql_err)?;

        if target_namespace_exists.is_none() {
            return Err(Error::new(
                ErrorKind::NamespaceNotFound,
                format!(
                    "Destination namespace not found: {}",
                    dest.namespace().join(".")
                ),
            ));
        }

        // Claiming the destination name is the collision check, and it covers a
        // *table* of that name as well as a view — the spec's "already exists as
        // a table or view", from the other side.
        if !Self::claim_name(&mut tx, dest.namespace(), &dest_namespace, dest.name()).await? {
            return Err(Error::new(
                ErrorKind::TableAlreadyExists,
                format!("Destination view already exists: {dest}"),
            ));
        }

        let renamed = sqlx::query(
            "UPDATE rustberg_views SET namespace = $3, name = $4
             WHERE namespace = $1 AND name = $2",
        )
        .bind(Self::namespace_key(src.namespace()))
        .bind(src.name())
        .bind(&dest_namespace)
        .bind(dest.name())
        .execute(&mut *tx)
        .await
        .map_err(sql_err)?;

        if renamed.rows_affected() == 0 {
            // The destination claim succeeded, so the only way to be here is a
            // source that is not a view — absent, or a table of that name. The
            // rollback below gives the claim back.
            return Err(Error::new(
                ErrorKind::TableNotFound,
                format!("Source view not found: {src}"),
            ));
        }

        // The row moved, so the old name holds nothing. Released last, because
        // the cascade would take the row with it were it released first.
        Self::release_name(&mut tx, &Self::namespace_key(src.namespace()), src.name()).await?;

        tx.commit().await.map_err(sql_err)?;
        Ok(())
    }
}

impl PostgresCatalog {
    /// Deletes metadata files written by a commit attempt that did not land.
    ///
    /// Best-effort: the commit has already failed and the caller's error should
    /// be the commit's, not a cleanup failure. A file that cannot be deleted
    /// becomes a genuine orphan and is logged as one.
    async fn discard_written_metadata(&self, attempted: &[StagedCommit]) {
        for entry in attempted {
            if let Err(e) = self.file_io.delete(&entry.new_location).await {
                tracing::warn!(
                    location = %entry.new_location,
                    error = %e,
                    "Could not delete the metadata file of a commit that did not land"
                );
            }
        }
    }

    async fn staged_pointer(&self, table: &TableIdent) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT metadata_location FROM rustberg_staged_tables
             WHERE namespace = $1 AND name = $2",
        )
        .bind(Self::namespace_key(table.namespace()))
        .bind(table.name())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(row.map(|r| r.get::<String, _>("metadata_location")))
    }

    async fn view_pointer(&self, view: &TableIdent) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT metadata_location FROM rustberg_views WHERE namespace = $1 AND name = $2",
        )
        .bind(Self::namespace_key(view.namespace()))
        .bind(view.name())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(row.map(|r| r.get::<String, _>("metadata_location")))
    }

    /// A fresh, uniquely named metadata file for every view write.
    ///
    /// Never overwritten, so a write that is later abandoned leaves an
    /// unreferenced file rather than corrupting a live one.
    fn view_metadata_location(&self, view: &TableIdent) -> String {
        format!(
            "{}/{}/{}/metadata/{}.metadata.json",
            self.warehouse_location,
            view.namespace().as_ref().join("/"),
            view.name(),
            uuid::Uuid::new_v4()
        )
    }

    async fn write_view_metadata(&self, location: &str, metadata: &ViewMetadata) -> Result<()> {
        let json = serde_json::to_vec(metadata).map_err(json_err)?;
        self.file_io.new_output(location)?.write(json.into()).await
    }

    async fn read_view_metadata(&self, location: &str) -> Result<ViewMetadata> {
        let bytes = self.file_io.new_input(location)?.read().await?;
        serde_json::from_slice(&bytes).map_err(json_err)
    }
}

/// Postgres SQLSTATEs that mean "retry the whole transaction".
///
/// `40001` is a serialization failure and `40P01` a detected deadlock. Postgres
/// reports both by aborting one transaction, and in both cases the transaction
/// was not wrong — it lost a race. Mapping them to `CatalogCommitConflicts` puts
/// them on the commit-retry path instead of surfacing a 500 for what is an
/// ordinary concurrent-writer outcome.
const RETRYABLE_SQLSTATES: &[&str] = &["40001", "40P01"];

/// SQLSTATE for `foreign_key_violation`.
///
/// Every relationship in the schema is a real constraint (see
/// [`create_schema`](PostgresCatalog::create_schema)), so this is the code that
/// arrives when a namespace is dropped out from under a create, or a namespace
/// with live tables is dropped. It is an ordinary answer to the caller, never a
/// server fault, so it never becomes a `500`.
const FOREIGN_KEY_VIOLATION: &str = "23503";

/// Whether `e` is Postgres refusing to break a foreign key.
fn is_foreign_key_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code.as_ref() == FOREIGN_KEY_VIOLATION)
}

fn sql_err(e: sqlx::Error) -> Error {
    let kind = match e.as_database_error().and_then(|db| db.code()) {
        Some(code) if RETRYABLE_SQLSTATES.contains(&code.as_ref()) => {
            ErrorKind::CatalogCommitConflicts
        }
        _ => ErrorKind::Unexpected,
    };
    Error::new(kind, format!("Postgres catalog error: {e}"))
}

fn json_err(e: serde_json::Error) -> Error {
    Error::new(ErrorKind::Unexpected, format!("Malformed metadata: {e}"))
}

#[async_trait]
impl crate::auth::policy_store::PolicyStore for PostgresCatalog {
    async fn current(
        &self,
    ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>> {
        let row = sqlx::query(
            "SELECT sequence, version, source, author, created_at_ms, note
             FROM rustberg_policy_revisions
             ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(row.map(|r| policy_revision_from_row(&r)))
    }

    async fn append(
        &self,
        source: &str,
        author: &str,
        note: Option<&str>,
    ) -> crate::error::Result<crate::auth::policy_store::PolicyRevision> {
        use crate::auth::policy_store::{PolicyRevision, now_ms, version_of};

        let version = version_of(source);
        let created_at_ms = now_ms() as i64;

        // The sequence is chosen inside the insert, from the table itself, so
        // two replicas appending at the same instant cannot pick the same one:
        // the primary key rejects the loser, which then retries against the new
        // maximum. A `SELECT max()` followed by an `INSERT` would race.
        for _ in 0..8 {
            let inserted = sqlx::query(
                "INSERT INTO rustberg_policy_revisions
                     (sequence, version, source, author, created_at_ms, note)
                 SELECT COALESCE(MAX(sequence), 0) + 1, $1, $2, $3, $4, $5
                 FROM rustberg_policy_revisions
                 ON CONFLICT (sequence) DO NOTHING
                 RETURNING sequence",
            )
            .bind(&version)
            .bind(source)
            .bind(author)
            .bind(created_at_ms)
            .bind(note)
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err)?;

            if let Some(row) = inserted {
                return Ok(PolicyRevision {
                    sequence: row.get::<i64, _>("sequence") as u64,
                    version,
                    source: source.to_string(),
                    author: author.to_string(),
                    created_at_ms: created_at_ms as u64,
                    note: note.map(str::to_string),
                });
            }
        }

        Err(crate::error::AppError::Internal(
            "Could not append a policy revision: too many concurrent writers".to_string(),
        ))
    }

    async fn history(
        &self,
        limit: usize,
    ) -> crate::error::Result<Vec<crate::auth::policy_store::PolicyRevisionSummary>> {
        let rows = sqlx::query(
            "SELECT sequence, version, source, author, created_at_ms, note
             FROM rustberg_policy_revisions
             ORDER BY sequence DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(rows
            .iter()
            .map(|r| policy_revision_from_row(r).summary())
            .collect())
    }

    async fn get(
        &self,
        sequence: u64,
    ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>> {
        let row = sqlx::query(
            "SELECT sequence, version, source, author, created_at_ms, note
             FROM rustberg_policy_revisions WHERE sequence = $1",
        )
        .bind(sequence as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_err)?;

        Ok(row.map(|r| policy_revision_from_row(&r)))
    }
}

fn policy_revision_from_row(row: &PgRow) -> crate::auth::policy_store::PolicyRevision {
    crate::auth::policy_store::PolicyRevision {
        sequence: row.get::<i64, _>("sequence") as u64,
        version: row.get("version"),
        source: row.get("source"),
        author: row.get("author"),
        created_at_ms: row.get::<i64, _>("created_at_ms") as u64,
        note: row.get("note"),
    }
}

/// Idempotency receipts, shared by every replica on one database.
///
/// Expired rows are pruned opportunistically on write, a bounded batch at a
/// time: the table only grows with mutations that carried a key, and a separate
/// sweeper would be one more moving part for a few hundred rows.
#[async_trait]
impl crate::catalog::v1::idempotency::SharedIdempotencyStore for PostgresCatalog {
    async fn get(
        &self,
        key: &str,
    ) -> std::result::Result<Option<crate::catalog::v1::idempotency::CachedResponse>, String> {
        let now = crate::auth::policy_store::now_ms() as i64;

        let row = sqlx::query(
            "SELECT status, content_type, body FROM rustberg_idempotency
             WHERE key = $1 AND expires_at_ms > $2",
        )
        .bind(key)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let Some(row) = row else { return Ok(None) };

        let status: i32 = row.try_get("status").map_err(|e| e.to_string())?;
        let content_type: Option<String> =
            row.try_get("content_type").map_err(|e| e.to_string())?;
        let body: Vec<u8> = row.try_get("body").map_err(|e| e.to_string())?;

        let status = axum::http::StatusCode::from_u16(status as u16)
            .map_err(|_| format!("recorded status {status} is not a status code"))?;

        Ok(Some(crate::catalog::v1::idempotency::CachedResponse::new(
            status,
            axum::body::Bytes::from(body),
            content_type,
        )))
    }

    async fn put(
        &self,
        key: &str,
        response: &crate::catalog::v1::idempotency::CachedResponse,
        ttl: std::time::Duration,
    ) -> std::result::Result<(), String> {
        let now = crate::auth::policy_store::now_ms() as i64;
        let expires_at = now.saturating_add(ttl.as_millis().min(i64::MAX as u128) as i64);

        sqlx::query(
            "INSERT INTO rustberg_idempotency (key, status, content_type, body, expires_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(i32::from(response.status.as_u16()))
        .bind(response.content_type.as_deref())
        .bind(response.body.as_ref())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let _ = sqlx::query(
            "DELETE FROM rustberg_idempotency
             WHERE key IN (
                 SELECT key FROM rustberg_idempotency WHERE expires_at_ms <= $1 LIMIT 100
             )",
        )
        .bind(now)
        .execute(&self.pool)
        .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_postgres_urls() {
        assert!(PostgresCatalog::handles("postgres://user@host/db"));
        assert!(PostgresCatalog::handles("postgresql://user@host/db"));
        assert!(!PostgresCatalog::handles("file:///var/lib/rustberg"));
        assert!(!PostgresCatalog::handles("memory://"));
    }

    /// Namespace parts join with a unit separator, never a dot. `a.b` as a
    /// single name and `a` → `b` nested must not produce the same key, or a
    /// policy written for one would silently apply to the other.
    #[test]
    fn namespace_keys_are_unambiguous() {
        let dotted = NamespaceIdent::new("a.b".to_string());
        let nested = NamespaceIdent::from_vec(vec!["a".into(), "b".into()]).unwrap();

        assert_ne!(
            PostgresCatalog::namespace_key(&dotted),
            PostgresCatalog::namespace_key(&nested)
        );
    }

    #[test]
    fn namespace_keys_round_trip() {
        let ns = NamespaceIdent::from_vec(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        let key = PostgresCatalog::namespace_key(&ns);
        assert_eq!(PostgresCatalog::key_to_namespace(&key), ns);
    }
}
