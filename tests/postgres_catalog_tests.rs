//! Integration tests for the Postgres catalog backend.
//!
//! These exercise the code paths that unit tests cannot reach: the SQL itself,
//! the compare-and-swap commit protocol, and the behaviour of two catalog
//! handles sharing one database — which is the entire reason this backend
//! exists.
//!
//! Requirements:
//! - Docker must be running. Each test starts its own Postgres container.
//! - They are `#[ignore]`d so that platforms without Docker (the macOS and
//!   Windows CI runners) stay green; CI runs them explicitly on Linux:
//!
//! ```text
//! cargo test --features catalog-postgres --test postgres_catalog_tests -- --ignored
//! ```

#![cfg(feature = "catalog-postgres")]

use std::collections::HashMap;

use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{NamespaceIdent, TableCreation, TableIdent, TableUpdate};
use rustberg::catalog::{CatalogStore, PageRequest, PostgresCatalog};

mod common;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

/// A Postgres container plus the catalogs opened against it.
///
/// The container handle is kept alive for the duration of the test; dropping it
/// stops the database.
struct TestDb {
    _container: ContainerAsync<GenericImage>,
    dsn: String,
    warehouse: tempfile::TempDir,
}

impl TestDb {
    async fn start() -> Self {
        // Debian-based, deliberately, and **not** `-alpine`. Alpine is musl,
        // whose `strcoll` is byte comparison, so every locale there behaves like
        // `C` — which is exactly the property `listings_come_back_in_byte_order`
        // exists to check, making the test vacuous on the image that was here
        // before. Real deployments run glibc: the Debian image, RDS, Cloud SQL,
        // Aurora. There `en_US.utf8` orders `aa, ab, Ärger, _underscore, Zulu`
        // and byte order gives `Zulu, _underscore, aa, ab`, which is a different
        // listing from redb's for the same catalog.
        let container = GenericImage::new("postgres", "16")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_PASSWORD", "rustberg")
            .with_env_var("POSTGRES_USER", "rustberg")
            .with_env_var("POSTGRES_DB", "rustberg")
            .start()
            .await
            .expect("start postgres");

        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("postgres port");

        Self {
            _container: container,
            dsn: format!("postgres://rustberg:rustberg@127.0.0.1:{port}/rustberg"),
            warehouse: tempfile::tempdir().expect("warehouse dir"),
        }
    }

    /// Opens another catalog handle on the same database, as a second replica
    /// would.
    async fn catalog(&self) -> PostgresCatalog {
        PostgresCatalog::connect(
            &self.dsn,
            &rustberg::location::url_from_path(self.warehouse.path()),
        )
        .await
        .expect("connect catalog")
    }
}

fn test_schema() -> Schema {
    Schema::builder()
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            NestedField::optional(2, "name", Type::Primitive(PrimitiveType::String)).into(),
        ])
        .build()
        .expect("schema")
}

async fn create_table(catalog: &PostgresCatalog, ns: &NamespaceIdent, name: &str) -> TableIdent {
    catalog
        .create_table(
            ns,
            TableCreation::builder()
                .name(name.to_string())
                .schema(test_schema())
                .build(),
        )
        .await
        .expect("create table");

    TableIdent::new(ns.clone(), name.to_string())
}

async fn namespace(catalog: &PostgresCatalog, name: &str) -> NamespaceIdent {
    let ns = NamespaceIdent::new(name.to_string());
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("create namespace");
    ns
}

// ── Schema and basic operations ─────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn creates_its_schema_and_round_trips_a_namespace() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = NamespaceIdent::new("analytics".to_string());
    catalog
        .create_namespace(&ns, HashMap::from([("owner".into(), "data".into())]))
        .await
        .expect("create");

    let loaded = catalog.get_namespace(&ns).await.expect("get");
    assert_eq!(
        loaded.properties().get("owner").map(String::as_str),
        Some("data")
    );
    assert!(catalog.namespace_exists(&ns).await.expect("exists"));
}

/// Connecting twice must not fail: every replica runs the same schema creation
/// at startup, and the second one through has to be a no-op.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn schema_creation_is_idempotent_across_replicas() {
    let db = TestDb::start().await;

    let first = db.catalog().await;
    let second = db.catalog().await;

    let ns = namespace(&first, "shared").await;
    assert!(
        second.namespace_exists(&ns).await.expect("exists"),
        "a namespace created by one replica must be visible to the other"
    );
}

/// A database created by a build with a different schema is refused at startup.
///
/// `CREATE TABLE IF NOT EXISTS` cannot reshape a database that already exists,
/// so a schema change leaves the old rows in the old shape and the new relations
/// empty. That shows up as tables reporting themselves missing, which points at
/// nothing. The stamp turns it into one sentence naming both versions, and it
/// covers every future change rather than the one somebody remembered to detect.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_database_from_another_schema_version_is_refused() {
    let db = TestDb::start().await;

    // A first replica stamps the database.
    let _first = db.catalog().await;

    // Rewrite the stamp to a version this build does not serve, which is what a
    // database created by a different build looks like from here.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db.dsn)
        .await
        .expect("connect");
    sqlx::query("UPDATE rustberg_schema_version SET version = version + 1, created_by = $1")
        .bind("0.0.1-from-the-past")
        .execute(&pool)
        .await
        .expect("restamp");

    let err = PostgresCatalog::connect(
        &db.dsn,
        &rustberg::location::url_from_path(db.warehouse.path()),
    )
    .await
    .expect_err("a database this build does not describe must be refused");

    let message = err.to_string();
    assert!(
        message.contains("schema") && message.contains("0.0.1-from-the-past"),
        "the refusal must name both versions so an operator knows what happened, got: \
         {message}"
    );
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn rejects_duplicate_namespace() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "dup").await;
    let err = catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect_err("second create must fail");

    assert_eq!(err.kind(), iceberg::ErrorKind::NamespaceAlreadyExists);
}

/// A namespace still holding a table must not be droppable, or the table
/// becomes unreachable while its metadata files stay in the warehouse.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn refuses_to_drop_a_namespace_holding_tables() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "occupied").await;
    create_table(&catalog, &ns, "events").await;

    let err = catalog.drop_namespace(&ns).await.expect_err("must refuse");
    assert!(
        err.message().contains("not empty"),
        "error should say why: {err}"
    );
    assert!(
        err.message().contains("tables"),
        "and say what is in there: {err}"
    );
}

/// Every relationship in the schema is a real constraint, so each kind of
/// occupant blocks the drop and the message names which one.
///
/// This is not a `SELECT`-then-`DELETE`: under Postgres's default `READ
/// COMMITTED` isolation a concurrent `createTable` that commits between the two
/// is invisible to the reader, and the drop would succeed — leaving a table
/// reachable by exact path, absent from every listing, and impossible to remove
/// through the API. The foreign key has no such window.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn every_kind_of_occupant_blocks_a_namespace_drop() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    // A view.
    let with_view = namespace(&catalog, "has_view").await;
    let view = TableIdent::new(with_view.clone(), "v".to_string());
    catalog
        .create_view(
            &view,
            common::simple_view_metadata(&with_view, "v", "file:///tmp/rustberg-test/has_view/v"),
        )
        .await
        .expect("view is created");
    let err = catalog
        .drop_namespace(&with_view)
        .await
        .expect_err("a view blocks the drop");
    assert!(err.message().contains("views"), "{err}");

    // A child namespace.
    let parent = namespace(&catalog, "has_child").await;
    let child = NamespaceIdent::from_vec(vec!["has_child".into(), "inner".into()]).unwrap();
    catalog
        .create_namespace(&child, HashMap::new())
        .await
        .expect("child is created");
    let err = catalog
        .drop_namespace(&parent)
        .await
        .expect_err("a child namespace blocks the drop");
    assert!(err.message().contains("child namespaces"), "{err}");

    // Emptying it makes the drop succeed, so the constraint is not simply
    // refusing everything.
    catalog.drop_namespace(&child).await.expect("child drops");
    catalog.drop_namespace(&parent).await.expect("parent drops");
}

/// A staged table is not a table: it cascades with the namespace rather than
/// blocking its drop, so nothing can later be promoted into a namespace that is
/// gone.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_staged_table_does_not_block_a_namespace_drop() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "has_staged").await;
    let creation = iceberg::TableCreation::builder()
        .name("pending".to_string())
        .schema(test_schema())
        .build();
    catalog
        .stage_create_table(&ns, creation)
        .await
        .expect("staging succeeds");

    catalog
        .drop_namespace(&ns)
        .await
        .expect("a staged table has no claim on the name");
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn nested_namespaces_require_their_parent() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let nested = NamespaceIdent::from_vec(vec!["missing".into(), "child".into()]).unwrap();
    let err = catalog
        .create_namespace(&nested, HashMap::new())
        .await
        .expect_err("orphan namespace must be refused");

    assert_eq!(err.kind(), iceberg::ErrorKind::NamespaceNotFound);
}

/// `a` → `b` must not be listed as a child of an unrelated namespace, and a
/// grandchild must not appear as a direct child.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn lists_only_direct_children() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let root = namespace(&catalog, "root").await;
    let child = NamespaceIdent::from_vec(vec!["root".into(), "child".into()]).unwrap();
    catalog
        .create_namespace(&child, HashMap::new())
        .await
        .unwrap();
    let grandchild =
        NamespaceIdent::from_vec(vec!["root".into(), "child".into(), "leaf".into()]).unwrap();
    catalog
        .create_namespace(&grandchild, HashMap::new())
        .await
        .unwrap();

    let children = catalog
        .list_namespaces(Some(&root), &PageRequest::default())
        .await
        .expect("list")
        .into_items();
    assert_eq!(children, vec![child], "only the direct child");
}

// ── Tables ──────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn creates_loads_and_drops_a_table() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let ident = create_table(&catalog, &ns, "events").await;

    let loaded = catalog.load_table(&ident).await.expect("load");
    assert_eq!(loaded.identifier(), &ident);

    catalog.drop_table(&ident).await.expect("drop");
    assert!(!catalog.table_exists(&ident).await.expect("exists"));
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn rejects_duplicate_table() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    create_table(&catalog, &ns, "events").await;

    let err = catalog
        .create_table(
            &ns,
            TableCreation::builder()
                .name("events".to_string())
                .schema(test_schema())
                .build(),
        )
        .await
        .expect_err("duplicate must fail");

    assert_eq!(err.kind(), iceberg::ErrorKind::TableAlreadyExists);
}

/// Renaming onto an existing name must fail rather than silently replacing it.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn rename_refuses_to_clobber() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let src = create_table(&catalog, &ns, "a").await;
    let dest = create_table(&catalog, &ns, "b").await;

    let err = catalog
        .rename_table(&src, &dest)
        .await
        .expect_err("must not clobber");
    assert_eq!(err.kind(), iceberg::ErrorKind::TableAlreadyExists);

    // Both tables survive.
    assert!(catalog.table_exists(&src).await.unwrap());
    assert!(catalog.table_exists(&dest).await.unwrap());
}

// ── Commits ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn commit_advances_the_metadata_pointer() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let ident = create_table(&catalog, &ns, "events").await;

    let before = catalog.load_table(&ident).await.unwrap();
    let before_location = before.metadata_location().unwrap().to_string();

    let updated = catalog
        .commit_table(
            &ident,
            vec![],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("owner".to_string(), "analytics".to_string())]),
            }],
        )
        .await
        .expect("commit");

    assert_eq!(
        updated
            .metadata()
            .properties()
            .get("owner")
            .map(String::as_str),
        Some("analytics")
    );
    assert_ne!(
        updated.metadata_location().unwrap(),
        before_location,
        "a commit must write a new metadata file, never overwrite the old one"
    );
}

/// The point of the Postgres backend: two handles, as two replicas, committing
/// to the same table. Both must succeed and neither update may be lost.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn concurrent_commits_from_two_replicas_do_not_lose_updates() {
    let db = TestDb::start().await;
    let writer = db.catalog().await;

    let ns = namespace(&writer, "db").await;
    let ident = create_table(&writer, &ns, "events").await;

    let replica_a = db.catalog().await;
    let replica_b = db.catalog().await;
    let ident_a = ident.clone();
    let ident_b = ident.clone();

    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            replica_a
                .commit_table(
                    &ident_a,
                    vec![],
                    vec![TableUpdate::SetProperties {
                        updates: HashMap::from([("from_a".to_string(), "1".to_string())]),
                    }],
                )
                .await
        }),
        tokio::spawn(async move {
            replica_b
                .commit_table(
                    &ident_b,
                    vec![],
                    vec![TableUpdate::SetProperties {
                        updates: HashMap::from([("from_b".to_string(), "1".to_string())]),
                    }],
                )
                .await
        }),
    );

    a.expect("join a").expect("commit a succeeds");
    b.expect("join b").expect("commit b succeeds");

    // Both properties must be present. If the compare-and-swap were missing, the
    // second writer would have overwritten the first's metadata and one would be
    // gone — the classic lost update.
    let final_table = writer.load_table(&ident).await.expect("load");
    let props = final_table.metadata().properties();
    assert_eq!(props.get("from_a").map(String::as_str), Some("1"));
    assert_eq!(props.get("from_b").map(String::as_str), Some("1"));
}

/// A commit whose requirement no longer holds must be rejected, not applied.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn failing_requirement_rejects_the_commit() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let ident = create_table(&catalog, &ns, "events").await;

    let err = catalog
        .commit_table(
            &ident,
            vec![iceberg::TableRequirement::UuidMatch {
                uuid: uuid::Uuid::new_v4(), // deliberately not this table's UUID
            }],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("should_not".to_string(), "apply".to_string())]),
            }],
        )
        .await
        .expect_err("requirement must fail the commit");

    assert!(err.message().contains("Requirement failed"), "{err}");

    let table = catalog.load_table(&ident).await.unwrap();
    assert!(
        !table.metadata().properties().contains_key("should_not"),
        "a rejected commit must not be partially applied"
    );
}

/// A multi-table commit either applies everywhere or nowhere.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn multi_table_commit_is_atomic() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let first = create_table(&catalog, &ns, "orders").await;
    let second = create_table(&catalog, &ns, "customers").await;

    catalog
        .commit_tables_atomic(vec![
            (
                first.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("batch".to_string(), "1".to_string())]),
                }],
            ),
            (
                second.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("batch".to_string(), "1".to_string())]),
                }],
            ),
        ])
        .await
        .expect("atomic commit");

    for ident in [&first, &second] {
        let table = catalog.load_table(ident).await.unwrap();
        assert_eq!(
            table
                .metadata()
                .properties()
                .get("batch")
                .map(String::as_str),
            Some("1"),
            "{ident} should have advanced"
        );
    }
}

/// One failing requirement must abort the whole multi-table commit, leaving
/// every table untouched — including the ones whose requirements passed.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn multi_table_commit_rolls_back_on_one_failure() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let ns = namespace(&catalog, "db").await;
    let good = create_table(&catalog, &ns, "good").await;
    let bad = create_table(&catalog, &ns, "bad").await;

    let result = catalog
        .commit_tables_atomic(vec![
            (
                good.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("applied".to_string(), "yes".to_string())]),
                }],
            ),
            (
                bad.clone(),
                vec![iceberg::TableRequirement::UuidMatch {
                    uuid: uuid::Uuid::new_v4(),
                }],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("applied".to_string(), "yes".to_string())]),
                }],
            ),
        ])
        .await;

    assert!(result.is_err(), "the commit must fail as a whole");

    let table = catalog.load_table(&good).await.unwrap();
    assert!(
        !table.metadata().properties().contains_key("applied"),
        "the succeeding table must not have advanced"
    );
}

// ── Health ──────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn reports_healthy_while_the_database_is_up() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let health = catalog.storage_health_check().await.expect("health");
    assert!(health.healthy);
    assert_eq!(health.backend_type, "postgres");
}

// ── Keyset paging ───────────────────────────────────────────────────────

/// Paging is keyset-based: each page resumes from the previous page's last key
/// rather than an `OFFSET`. Walking the whole listing must therefore visit every
/// table exactly once, and terminate.
///
/// Worth testing against a real database because the SQL is hand-written — an
/// off-by-one in the `name > $2` bound would either repeat a row on every page
/// boundary or skip one.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn paging_tables_visits_each_exactly_once() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;
    let ns = namespace(&catalog, "paged").await;

    let expected: Vec<String> = (0..25).map(|i| format!("t{i:03}")).collect();
    for name in &expected {
        create_table(&catalog, &ns, name).await;
    }

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut requests = 0;

    loop {
        requests += 1;
        assert!(requests < 40, "paging failed to terminate");

        let page = catalog
            .list_tables(
                &ns,
                &PageRequest {
                    after: cursor.clone(),
                    limit: 4,
                },
            )
            .await
            .expect("list page");

        assert!(page.entries.len() <= 4, "page exceeded the limit");
        seen.extend(page.entries.iter().map(|e| e.item.name().to_string()));

        match &page.next {
            Some(next) => cursor = Some(next.clone()),
            None => break,
        }
    }

    assert_eq!(seen, expected, "keyset paging did not cover the listing");
    assert!(requests > 1, "the test must exercise more than one page");
}

/// The "direct children only" rule is applied in SQL so that `LIMIT` counts rows
/// the caller receives. Filtering after the limit would make a page of
/// grandchildren come back empty while direct children remained.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn paging_namespaces_counts_only_direct_children() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let root = NamespaceIdent::new("root".to_string());
    catalog
        .create_namespace(&root, HashMap::new())
        .await
        .unwrap();

    // Three direct children, each with a grandchild that must not be counted.
    for i in 0..3 {
        let child = NamespaceIdent::from_vec(vec!["root".into(), format!("c{i}")]).unwrap();
        catalog
            .create_namespace(&child, HashMap::new())
            .await
            .unwrap();
        let grandchild =
            NamespaceIdent::from_vec(vec!["root".into(), format!("c{i}"), "leaf".into()]).unwrap();
        catalog
            .create_namespace(&grandchild, HashMap::new())
            .await
            .unwrap();
    }

    // A limit of 2 must return two *children*, not two rows that include a
    // grandchild filtered out afterwards.
    let page = catalog
        .list_namespaces(Some(&root), &PageRequest::first(2))
        .await
        .expect("list");

    assert_eq!(
        page.entries.len(),
        2,
        "the limit must count direct children"
    );
    for entry in &page.entries {
        assert_eq!(entry.item.len(), 2, "a grandchild leaked into the page");
    }
    assert!(page.next.is_some(), "a third child remains");

    // And the walk covers all three.
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = catalog
            .list_namespaces(
                Some(&root),
                &PageRequest {
                    after: cursor.clone(),
                    limit: 2,
                },
            )
            .await
            .expect("list");
        seen.extend(page.entries.iter().map(|e| e.item.join(".")));
        match &page.next {
            Some(next) => cursor = Some(next.clone()),
            None => break,
        }
    }
    assert_eq!(seen, vec!["root.c0", "root.c1", "root.c2"]);
}

// ============================================================================
// Shared backend contract
// ============================================================================

/// Runs the contract in `tests/common` against Postgres.
///
/// redb runs the identical suite. This pairing is what catches a backend
/// drifting from the other — `drop_namespace` on a non-empty namespace once
/// answered 409 from redb and 500 from here, and nothing caught it because each
/// backend was checked only against itself.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn satisfies_the_shared_catalog_contract() {
    let db = TestDb::start().await;

    let warehouse = rustberg::location::url_from_path(db.warehouse.path());

    common::run_all(|| async {
        (
            std::sync::Arc::new(db.catalog().await) as std::sync::Arc<dyn CatalogStore>,
            warehouse.clone(),
        )
    })
    .await;
}

/// Two multi-table transactions naming the same tables in *opposite* order must
/// not deadlock each other.
///
/// Postgres takes a row lock per `UPDATE`. If one transaction locks `A` then
/// `B` while another locks `B` then `A`, each holds what the other needs and
/// Postgres breaks the tie by aborting one with SQLSTATE `40P01` — a failure
/// caused purely by the order the client happened to list its tables in.
///
/// The commit path sorts its row locks into a globally consistent order to make
/// that impossible. Nothing tested it, so this pins it: without the sort this
/// deadlocks often enough that a handful of rounds finds it.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn opposing_multi_table_commits_do_not_deadlock() {
    use iceberg::TableUpdate;
    use std::collections::HashMap;

    let db = TestDb::start().await;
    let catalog = std::sync::Arc::new(db.catalog().await);

    let ns = namespace(&catalog, "deadlock").await;
    let alpha = create_table(&catalog, &ns, "alpha").await;
    let beta = create_table(&catalog, &ns, "beta").await;

    // Several rounds: a deadlock is a race, so one attempt proves little.
    for round in 0..8 {
        let forward = {
            let catalog = catalog.clone();
            let (a, b) = (alpha.clone(), beta.clone());
            tokio::spawn(async move {
                catalog
                    .commit_tables_atomic(vec![
                        (a, vec![], vec![set_property("round", round)]),
                        (b, vec![], vec![set_property("round", round)]),
                    ])
                    .await
            })
        };

        let backward = {
            let catalog = catalog.clone();
            let (a, b) = (alpha.clone(), beta.clone());
            tokio::spawn(async move {
                catalog
                    .commit_tables_atomic(vec![
                        // Deliberately the other way round.
                        (b, vec![], vec![set_property("reverse", round)]),
                        (a, vec![], vec![set_property("reverse", round)]),
                    ])
                    .await
            })
        };

        for outcome in [forward.await.expect("task"), backward.await.expect("task")] {
            if let Err(e) = outcome {
                // A commit conflict is legitimate — the two transactions raced
                // and one lost, which is what retries are for. A deadlock is
                // not: it means the lock order was inconsistent.
                let message = e.message().to_lowercase();
                assert!(
                    !message.contains("deadlock") && !message.contains("40p01"),
                    "round {round}: commits deadlocked, so row locks were not taken \
                     in a consistent order: {e}"
                );
            }
        }
    }

    // And both tables must still be readable and consistent afterwards.
    catalog.load_table(&alpha).await.expect("alpha still loads");
    catalog.load_table(&beta).await.expect("beta still loads");

    fn set_property(key: &str, round: i32) -> TableUpdate {
        TableUpdate::SetProperties {
            updates: HashMap::from([(key.to_string(), round.to_string())]),
        }
    }
}

/// A table staged against one replica must be committable through another.
///
/// This is the property that decides whether staged creation can exist at all in
/// a clustered deployment. Holding staged metadata in process memory would make
/// `stage-create` work on a single node and fail intermittently behind a load
/// balancer — the worst possible failure shape, since it passes every local
/// test. Persisting the staging note in Postgres is what makes the two replicas
/// interchangeable, and this test is the proof.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_table_staged_on_one_replica_commits_on_another() {
    use iceberg::{TableRequirement, TableUpdate};
    use std::collections::HashMap;

    let db = TestDb::start().await;

    // Two independent handles on one database, exactly as two pods would be.
    let replica_a = db.catalog().await;
    let replica_b = db.catalog().await;

    let ns = namespace(&replica_a, "ctas").await;

    let creation = TableCreation::builder()
        .name("summary".to_string())
        .schema(test_schema())
        .build();
    replica_a
        .stage_create_table(&ns, creation)
        .await
        .expect("replica A stages the table");

    let ident = TableIdent::new(ns.clone(), "summary".to_string());

    // Neither replica may see it yet.
    assert!(
        !replica_b.table_exists(&ident).await.expect("exists"),
        "a staged table is invisible on every replica, not just the one that staged it"
    );

    // The commit lands on the *other* replica, as a load balancer would send it.
    replica_b
        .commit_table(
            &ident,
            vec![TableRequirement::NotExist],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("committed-by".to_string(), "replica-b".to_string())]),
            }],
        )
        .await
        .expect("replica B commits a table replica A staged");

    // And now both see the same real table.
    for (label, replica) in [("A", &replica_a), ("B", &replica_b)] {
        let loaded = replica
            .load_table(&ident)
            .await
            .unwrap_or_else(|e| panic!("replica {label} must see the committed table: {e}"));
        assert_eq!(
            loaded
                .metadata()
                .properties()
                .get("committed-by")
                .map(String::as_str),
            Some("replica-b"),
            "replica {label} must see the committed snapshot"
        );
    }
}

/// Two clients staging the same name is legal — staging reserves nothing — but
/// only one commit may win.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn two_stages_of_one_name_produce_exactly_one_table() {
    use iceberg::{TableRequirement, TableUpdate};
    use std::collections::HashMap;

    let db = TestDb::start().await;
    let catalog = db.catalog().await;
    let ns = namespace(&catalog, "race").await;

    for _ in 0..2 {
        let creation = TableCreation::builder()
            .name("contested".to_string())
            .schema(test_schema())
            .build();
        catalog
            .stage_create_table(&ns, creation)
            .await
            .expect("staging the same name twice is allowed");
    }

    let ident = TableIdent::new(ns, "contested".to_string());
    let commit = |tag: &'static str| {
        catalog.commit_table(
            &ident,
            vec![TableRequirement::NotExist],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("winner".to_string(), tag.to_string())]),
            }],
        )
    };

    commit("first").await.expect("the first commit wins");

    let second = commit("second").await;
    assert!(
        second.is_err(),
        "the second assert-create must lose: the table now exists"
    );

    let loaded = catalog.load_table(&ident).await.expect("load succeeds");
    assert_eq!(
        loaded
            .metadata()
            .properties()
            .get("winner")
            .map(String::as_str),
        Some("first"),
        "the loser must not have overwritten the winner"
    );
}

// ============================================================================
// Policy revisions across replicas
// ============================================================================

/// A policy change made through one replica must reach the others.
///
/// This is the property that decides whether runtime policy administration is
/// usable in a cluster at all. Without it, a revocation applies only to
/// whichever pod happened to receive the request, and the cluster enforces two
/// different rule sets with no way to tell which decided what.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn a_policy_change_on_one_replica_reaches_another() {
    use rustberg::auth::policy_store::PolicyStore;
    use rustberg::auth::reloadable::{ReloadableAuthorizer, spawn_policy_poller};
    use rustberg::auth::{Authorizer, CedarAuthorizer};
    use std::sync::Arc;
    use std::time::Duration;

    const FIRST: &str = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;
    const SECOND: &str = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
        permit(
          principal in Rustberg::Group::"reader",
          action == Rustberg::Action::"Read",
          resource
        ) when { resource.tenant == principal.tenant };
    "#;

    let db = TestDb::start().await;

    // Two handles on one database, as two pods would be.
    let writer: Arc<dyn PolicyStore> = Arc::new(db.catalog().await);
    let reader_store: Arc<dyn PolicyStore> = Arc::new(db.catalog().await);

    let seeded = writer
        .append(FIRST, "system:bootstrap", None)
        .await
        .expect("seed the policy store");

    // The second replica loads what exists and then polls aggressively, so the
    // test does not wait on the production interval.
    let follower = Arc::new(ReloadableAuthorizer::new(
        CedarAuthorizer::new(&seeded.source).expect("seeded policy compiles"),
        seeded.sequence,
    ));
    let _poller = spawn_policy_poller(reader_store, follower.clone(), Duration::from_millis(50));

    let before = follower.policy_set_version();
    assert_eq!(follower.loaded_sequence(), seeded.sequence);

    // The first replica changes policy.
    let updated = writer
        .append(SECOND, "alice", Some("grant readers"))
        .await
        .expect("append a revision");
    assert!(updated.sequence > seeded.sequence);

    // The follower converges.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while follower.loaded_sequence() < updated.sequence {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the follower never picked up revision {}: a policy change would apply to \
             only one replica",
            updated.sequence
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert_eq!(follower.loaded_sequence(), updated.sequence);
    assert_ne!(
        follower.policy_set_version(),
        before,
        "converging must actually change the rules in force, not just the sequence"
    );
    assert_eq!(
        follower.policy_set_version(),
        Some(updated.version.clone()),
        "the follower's version must be the one the store recorded, so audit records \
         from either replica are comparable"
    );
}

/// Revisions are append-only and monotonic even when two replicas write at
/// once, or a sequence could be reused and two different rule sets would share
/// one identity.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn concurrent_policy_writes_get_distinct_sequences() {
    use rustberg::auth::policy_store::PolicyStore;
    use std::sync::Arc;

    let db = TestDb::start().await;
    let a: Arc<dyn PolicyStore> = Arc::new(db.catalog().await);
    let b: Arc<dyn PolicyStore> = Arc::new(db.catalog().await);

    let policy = |n: usize| {
        format!(
            r#"permit(principal in Rustberg::Group::"g{n}", action, resource)
                 when {{ resource.tenant == principal.tenant }};"#
        )
    };

    let mut handles = Vec::new();
    for n in 0..8 {
        let store = if n % 2 == 0 { a.clone() } else { b.clone() };
        let source = policy(n);
        handles.push(tokio::spawn(async move {
            store.append(&source, "racer", None).await
        }));
    }

    let mut sequences = Vec::new();
    for handle in handles {
        let revision = handle.await.expect("task").expect("append succeeds");
        sequences.push(revision.sequence);
    }

    sequences.sort_unstable();
    let unique: std::collections::BTreeSet<u64> = sequences.iter().copied().collect();
    assert_eq!(
        unique.len(),
        sequences.len(),
        "two revisions shared a sequence, so one rule set overwrote another: {sequences:?}"
    );
}

// ── Ordering ────────────────────────────────────────────────────────────

/// Postgres and redb must page in the *same* order, or a client that migrates
/// between them silently sees a different listing — and `tests/redb_catalog_
/// tests.rs` asserts the same sequence against the same names.
///
/// This is what `COLLATE "C"` on every key column buys. Under a locale
/// collation `Ä` sorts beside `A`, `_` and `-` are ignored at the primary
/// level, and U+001F — the separator every namespace key is built from — is
/// *completely ignorable*, so `a␟b` and `ab` compare equal. None of that
/// matches a byte-ordered B-tree.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn listings_come_back_in_byte_order() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    // Chosen so a locale collation reorders them: `Z` before `a` only in byte
    // order, and the diacritic and the underscore both move under a locale.
    let names = ["Zulu", "_underscore", "aa", "ab", "Ärger", "zz"];
    for name in names {
        namespace(&catalog, name).await;
    }

    let listed: Vec<String> = catalog
        .list_namespaces(None, &PageRequest::first(100))
        .await
        .expect("list")
        .into_items()
        .into_iter()
        .map(|ns| ns.join("."))
        .collect();

    let mut expected: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    expected.sort_unstable();

    assert_eq!(
        listed, expected,
        "listings must come back in byte order, the order redb uses"
    );
}

/// Keyset pagination is `name > $cursor`. Under a collation that sorts two
/// distinct names equal, the cursor either stalls on a row or skips past one —
/// so every name must be visited exactly once, whatever the page size.
#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn paging_visits_every_name_exactly_once() {
    let db = TestDb::start().await;
    let catalog = db.catalog().await;

    let names = ["Zulu", "_underscore", "aa", "a-a", "a_a", "Ärger", "zz"];
    for name in names {
        namespace(&catalog, name).await;
    }

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..names.len() * 2 {
        let page = catalog
            .list_namespaces(
                None,
                &PageRequest {
                    after: cursor.clone(),
                    limit: 2,
                },
            )
            .await
            .expect("list");
        let next = page.next.clone();
        for entry in &page.entries {
            seen.push(entry.item.join("."));
        }
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    let mut expected: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    expected.sort_unstable();
    assert_eq!(seen, expected, "every name once, in byte order");
}
