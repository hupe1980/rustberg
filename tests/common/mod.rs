//! Behaviour every [`CatalogStore`] backend must share.
//!
//! # Why this exists
//!
//! redb and Postgres are two implementations of one trait, and the REST layer
//! above them cannot tell which it is talking to. It maps `ErrorKind` to an HTTP
//! status, so two backends that disagree about the *kind* of an error make the
//! same request answer differently depending on deployment — a client that
//! handles `409 Conflict` from the embedded catalog gets `500` from the
//! clustered one and treats a routine refusal as a server fault.
//!
//! That is not hypothetical: `drop_namespace` on a non-empty namespace returned
//! `PreconditionFailed` (409) from redb and `Unexpected` (500) from Postgres.
//! Each backend had its own test, each asserted only that *an* error came back,
//! and the divergence sat between them where no single test could see it.
//!
//! So the contract lives here once, and both backends run it. Assertions are on
//! [`ErrorKind`] rather than message text, because the kind is what becomes a
//! status code — a message can be reworded freely, a kind cannot.
//!
//! # Adding a backend
//!
//! Implement a fixture that hands back a `&dyn CatalogStore` over an empty
//! catalog and call [`run_all`]. Nothing here is redb- or Postgres-specific.

#![allow(dead_code)] // Each test binary uses a subset.

use std::collections::HashMap;

use iceberg::spec::{
    NestedField, PrimitiveType, Schema, Type, ViewMetadata, ViewMetadataBuilder,
    ViewRepresentations,
};
use iceberg::{ErrorKind, NamespaceIdent, TableCreation, TableIdent, ViewCreation};
use rustberg::catalog::{CatalogStore, PageRequest};

/// A schema with one column; the shape is irrelevant to every test here.
pub fn simple_schema() -> Schema {
    Schema::builder()
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("schema builds")
}

/// Creates a namespace, failing loudly if setup itself broke.
pub async fn given_namespace(catalog: &dyn CatalogStore, parts: &[&str]) -> NamespaceIdent {
    let ns = NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect())
        .expect("valid namespace");
    catalog
        .create_namespace(&ns, HashMap::new())
        .await
        .expect("namespace setup");
    ns
}

/// Creates a table, failing loudly if setup itself broke.
pub async fn given_table(
    catalog: &dyn CatalogStore,
    ns: &NamespaceIdent,
    name: &str,
) -> TableIdent {
    let creation = TableCreation::builder()
        .name(name.to_string())
        .schema(simple_schema())
        .build();
    catalog
        .create_table(ns, creation)
        .await
        .expect("table setup");
    TableIdent::new(ns.clone(), name.to_string())
}

/// Asserts an operation failed with exactly `expected`.
///
/// The kind is the whole point: it is what the REST layer turns into a status
/// code, so a backend returning the right message with the wrong kind still
/// answers the client wrongly.
#[track_caller]
pub fn assert_kind<T: std::fmt::Debug>(
    result: iceberg::Result<T>,
    expected: ErrorKind,
    what: &str,
) {
    match result {
        Ok(value) => panic!("{what}: expected {expected:?}, but the call succeeded: {value:?}"),
        Err(e) => assert_eq!(
            e.kind(),
            expected,
            "{what}: expected {expected:?}, got {:?} — the REST layer maps the kind to a status \
             code, so this changes what the client sees. Message was: {}",
            e.kind(),
            e.message()
        ),
    }
}

// ── The contract ────────────────────────────────────────────────────────────

/// A namespace holding tables must refuse to drop, as a precondition failure.
pub async fn drop_namespace_with_tables_is_precondition_failed(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["occupied_by_tables"]).await;
    given_table(catalog, &ns, "events").await;

    assert_kind(
        catalog.drop_namespace(&ns).await,
        ErrorKind::PreconditionFailed,
        "dropping a namespace that still holds tables",
    );
}

/// A namespace holding child namespaces must refuse to drop, for the same
/// reason: the children stay loadable by exact path but vanish from listings.
pub async fn drop_namespace_with_children_is_precondition_failed(catalog: &dyn CatalogStore) {
    let parent = given_namespace(catalog, &["occupied_by_children"]).await;
    given_namespace(catalog, &["occupied_by_children", "child"]).await;

    assert_kind(
        catalog.drop_namespace(&parent).await,
        ErrorKind::PreconditionFailed,
        "dropping a namespace that still has child namespaces",
    );
}

/// Dropping a namespace that was never created is a miss, not a fault.
pub async fn drop_missing_namespace_is_not_found(catalog: &dyn CatalogStore) {
    let ns = NamespaceIdent::new("never_created".to_string());
    assert_kind(
        catalog.drop_namespace(&ns).await,
        ErrorKind::NamespaceNotFound,
        "dropping a namespace that does not exist",
    );
}

/// Loading a namespace that was never created is a miss.
pub async fn load_missing_namespace_is_not_found(catalog: &dyn CatalogStore) {
    let ns = NamespaceIdent::new("absent_ns".to_string());
    assert_kind(
        catalog.get_namespace(&ns).await,
        ErrorKind::NamespaceNotFound,
        "loading a namespace that does not exist",
    );
}

/// Creating a namespace twice is a conflict on the name.
pub async fn duplicate_namespace_is_already_exists(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["dup_ns"]).await;
    assert_kind(
        catalog.create_namespace(&ns, HashMap::new()).await,
        ErrorKind::NamespaceAlreadyExists,
        "creating a namespace that already exists",
    );
}

/// Loading a table that was never created is a miss.
pub async fn load_missing_table_is_not_found(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["missing_table_ns"]).await;
    let table = TableIdent::new(ns, "absent".to_string());
    assert_kind(
        catalog.load_table(&table).await,
        ErrorKind::TableNotFound,
        "loading a table that does not exist",
    );
}

/// Creating a table twice is a conflict on the name.
pub async fn duplicate_table_is_already_exists(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["dup_table_ns"]).await;
    given_table(catalog, &ns, "events").await;

    let creation = TableCreation::builder()
        .name("events".to_string())
        .schema(simple_schema())
        .build();
    assert_kind(
        catalog.create_table(&ns, creation).await,
        ErrorKind::TableAlreadyExists,
        "creating a table that already exists",
    );
}

/// Creating a table in a namespace that does not exist is a namespace miss —
/// not a table miss, and not a success that invents the namespace.
pub async fn create_table_in_missing_namespace_is_not_found(catalog: &dyn CatalogStore) {
    let ns = NamespaceIdent::new("no_such_ns".to_string());
    let creation = TableCreation::builder()
        .name("orphan".to_string())
        .schema(simple_schema())
        .build();
    assert_kind(
        catalog.create_table(&ns, creation).await,
        ErrorKind::NamespaceNotFound,
        "creating a table in a namespace that does not exist",
    );
}

/// Registering into a namespace that does not exist is a namespace miss.
///
/// redb checked this and Postgres did not, so a pointer landed in a namespace
/// with no ownership record — which every authorization decision reads before it
/// decides anything. The table then answered `404` to every caller, including
/// its creator, while still occupying its name. A divergence each backend's own
/// suite was happy with, which is what this contract exists to catch.
pub async fn register_into_missing_namespace_is_not_found(catalog: &dyn CatalogStore) {
    let ns = NamespaceIdent::new("no_such_register_ns".to_string());
    let table = TableIdent::new(ns, "adopted".to_string());
    assert_kind(
        catalog
            .register_table(
                &table,
                "memory://nowhere/metadata/v1.metadata.json".to_string(),
            )
            .await,
        ErrorKind::NamespaceNotFound,
        "registering a table into a namespace that does not exist",
    );
}

/// A metadata document declaring a location outside the warehouse is refused,
/// and **nothing is published**.
///
/// The location a metadata file declares — not the path it was read from — is
/// what a vended credential is later scoped to, so adopting one that points
/// elsewhere hands the caller the server's own storage authority. Checking after
/// the pointer is published and undoing it with a drop leaves a window in which
/// the table is loadable; the second assertion is the one that pins it shut.
pub async fn registering_metadata_that_points_outside_the_warehouse_is_refused(
    catalog: &dyn CatalogStore,
    warehouse: &str,
) {
    let ns = given_namespace(catalog, &["register_confine_ns"]).await;

    // A real table, so its metadata document is well-formed and adoptable...
    let donor = given_table(catalog, &ns, "donor").await;
    let loaded = catalog.load_table(&donor).await.expect("load donor");
    let donor_metadata_location = loaded
        .metadata_location()
        .expect("a created table has a metadata location")
        .to_string();

    // ...but rewritten to declare somewhere else entirely.
    let smuggled = format!("{warehouse}/register_confine_ns/smuggled/metadata/v1.metadata.json");
    let mut document: serde_json::Value = serde_json::from_slice(
        &loaded
            .file_io()
            .new_input(&donor_metadata_location)
            .expect("input")
            .read()
            .await
            .expect("read donor metadata"),
    )
    .expect("parse donor metadata");
    document["location"] = serde_json::Value::String("s3://someone-elses-bucket/secrets".into());

    loaded
        .file_io()
        .new_output(&smuggled)
        .expect("output")
        .write(serde_json::to_vec(&document).expect("serialise").into())
        .await
        .expect("write smuggled metadata");

    let target = TableIdent::new(ns, "smuggled".to_string());
    assert_kind(
        catalog.register_table(&target, smuggled).await,
        ErrorKind::DataInvalid,
        "registering metadata that declares a location outside the warehouse",
    );

    // The check happens before anything is published, so there is nothing to
    // undo and no instant at which the table existed.
    assert_kind(
        catalog.load_table(&target).await,
        ErrorKind::TableNotFound,
        "a refused registration must leave no pointer behind",
    );
}

/// Dropping a table that was never created is a miss.
pub async fn drop_missing_table_is_not_found(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["drop_missing_ns"]).await;
    let table = TableIdent::new(ns, "absent".to_string());
    assert_kind(
        catalog.drop_table(&table).await,
        ErrorKind::TableNotFound,
        "dropping a table that does not exist",
    );
}

/// Renaming onto an occupied name must refuse rather than clobber.
pub async fn rename_onto_existing_table_is_already_exists(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["rename_clobber_ns"]).await;
    let src = given_table(catalog, &ns, "source").await;
    let dest = given_table(catalog, &ns, "occupied").await;

    assert_kind(
        catalog.rename_table(&src, &dest).await,
        ErrorKind::TableAlreadyExists,
        "renaming a table onto one that already exists",
    );
}

/// Renaming a table that does not exist is a miss.
pub async fn rename_missing_table_is_not_found(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["rename_missing_ns"]).await;
    let src = TableIdent::new(ns.clone(), "absent".to_string());
    let dest = TableIdent::new(ns, "target".to_string());

    assert_kind(
        catalog.rename_table(&src, &dest).await,
        ErrorKind::TableNotFound,
        "renaming a table that does not exist",
    );
}

/// A commit whose requirements no longer hold is a conflict, so the client
/// re-reads and retries rather than treating it as a permanent failure.
pub async fn failed_requirement_is_a_commit_conflict(catalog: &dyn CatalogStore) {
    use iceberg::TableRequirement;

    let ns = given_namespace(catalog, &["requirement_ns"]).await;
    let table = given_table(catalog, &ns, "events").await;

    // A UUID that is deliberately not this table's.
    let wrong_uuid = uuid::Uuid::nil();
    let result = catalog
        .commit_table(
            &table,
            vec![TableRequirement::UuidMatch { uuid: wrong_uuid }],
            vec![],
        )
        .await;

    assert_kind(
        result,
        ErrorKind::CatalogCommitConflicts,
        "committing with a requirement that does not hold",
    );
}

/// Listing must page over every table exactly once, with no repeats and no
/// gaps, however small the page.
pub async fn paging_visits_every_table_exactly_once(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["paging_ns"]).await;
    let expected: Vec<String> = (0..7).map(|i| format!("t{i}")).collect();
    for name in &expected {
        given_table(catalog, &ns, name).await;
    }

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = catalog
            .list_tables(
                &ns,
                &PageRequest {
                    after: cursor.clone(),
                    limit: 2,
                },
            )
            .await
            .expect("listing succeeds");

        for entry in &page.entries {
            seen.push(entry.item.name().to_string());
        }

        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    seen.sort();
    let mut want = expected.clone();
    want.sort();
    assert_eq!(
        seen, want,
        "paging must visit every table exactly once — no repeats, no gaps"
    );
}

/// A namespace listing returns direct children only; a grandchild belongs to
/// its own parent's listing, not this one.
pub async fn listing_returns_direct_children_only(catalog: &dyn CatalogStore) {
    let parent = given_namespace(catalog, &["tree"]).await;
    given_namespace(catalog, &["tree", "child"]).await;
    given_namespace(catalog, &["tree", "child", "grandchild"]).await;

    let page = catalog
        .list_namespaces(Some(&parent), &PageRequest::first(100))
        .await
        .expect("listing succeeds");

    let names: Vec<String> = page.entries.iter().map(|e| e.item.join(".")).collect();

    assert_eq!(
        names,
        vec!["tree.child".to_string()],
        "only direct children belong in this listing"
    );
}

/// Builds view metadata for a view at `location`.
///
/// Views are metadata-only, so this is all a backend needs to store one.
pub fn simple_view_metadata(
    namespace: &NamespaceIdent,
    name: &str,
    location: &str,
) -> ViewMetadata {
    let creation = ViewCreation::builder()
        .name(name.to_string())
        .location(location.to_string())
        .schema(simple_schema())
        .default_namespace(namespace.clone())
        // `ViewRepresentations` has private fields, so it is built through
        // serde exactly as the REST handler builds it.
        .representations(
            serde_json::from_value::<ViewRepresentations>(serde_json::json!([{
                "type": "sql",
                "sql": "SELECT 1",
                "dialect": "spark"
            }]))
            .expect("representation is well-formed"),
        )
        .summary(std::collections::HashMap::from([(
            "operation".to_string(),
            "create".to_string(),
        )]))
        .properties(HashMap::new())
        .build();

    ViewMetadataBuilder::from_view_creation(creation)
        .expect("view creation is valid")
        .build()
        .expect("view metadata builds")
        .metadata
}

/// Creates a view under `warehouse`, failing loudly if setup itself broke.
///
/// The location must be a real URL the backend's `FileIO` can resolve — views
/// are metadata-only, but the metadata is still a file that gets written.
pub async fn given_view(
    catalog: &dyn CatalogStore,
    warehouse: &str,
    ns: &NamespaceIdent,
    name: &str,
) -> TableIdent {
    let ident = TableIdent::new(ns.clone(), name.to_string());
    let location = view_location(warehouse, ns, name);
    catalog
        .create_view(&ident, simple_view_metadata(ns, name, &location))
        .await
        .expect("view setup");
    ident
}

/// Where a view's metadata lives, by the same convention tables use.
pub fn view_location(warehouse: &str, ns: &NamespaceIdent, name: &str) -> String {
    format!(
        "{}/{}/{name}",
        warehouse.trim_end_matches('/'),
        ns.join("/")
    )
}

// ── Views ───────────────────────────────────────────────────────────────────
//
// Views were absent from this contract entirely, which is exactly where two
// backends drift without either noticing: the view methods were written twice,
// months apart, against no shared statement of what they must do.

/// A view round-trips: created, found, loaded, listed, dropped.
pub async fn a_view_round_trips(catalog: &dyn CatalogStore, warehouse: &str) {
    let ns = given_namespace(catalog, &["view_roundtrip"]).await;
    let view = given_view(catalog, warehouse, &ns, "summary").await;

    assert!(
        catalog.view_exists(&view).await.expect("exists succeeds"),
        "a created view must exist"
    );

    let (location, metadata) = catalog.load_view(&view).await.expect("load succeeds");
    assert!(
        !location.is_empty(),
        "a loaded view names where it was read from"
    );
    assert_eq!(
        metadata.current_version_id(),
        1,
        "a new view is at version 1"
    );

    let page = catalog
        .list_views(&ns, &PageRequest::first(100))
        .await
        .expect("listing succeeds");
    let names: Vec<String> = page
        .entries
        .iter()
        .map(|e| e.item.name().to_string())
        .collect();
    assert_eq!(names, vec!["summary".to_string()]);

    catalog.drop_view(&view).await.expect("drop succeeds");
    assert!(
        !catalog.view_exists(&view).await.expect("exists succeeds"),
        "a dropped view must not exist"
    );
}

/// A view commit that lost its race is refused, not applied.
///
/// A view commit is a read-modify-write that spans the `CatalogStore` boundary:
/// the handler loads the metadata, applies the client's updates and hands back a
/// finished document. So the store cannot re-derive what the updates were based
/// on — it has to be *told*, and it has to compare against that rather than
/// against a read of its own. A backend that re-reads instead confirms a
/// concurrent commit rather than detecting it, and the second writer silently
/// overwrites the first. Invariant 2 says that cannot happen.
///
/// Two commits are built from the same load here, which is exactly the shape two
/// replicas produce. The first must win and the second must be told.
pub async fn a_second_view_commit_from_one_read_is_refused(
    catalog: &dyn CatalogStore,
    warehouse: &str,
) {
    let ns = given_namespace(catalog, &["view_cas"]).await;
    let view = given_view(catalog, warehouse, &ns, "summary").await;

    let (read_location, metadata) = catalog.load_view(&view).await.expect("load");

    // Two independent edits, both derived from the same read.
    let first = metadata
        .clone()
        .into_builder()
        .set_properties(HashMap::from([("edit".to_string(), "first".to_string())]))
        .expect("set first")
        .build()
        .expect("build first")
        .metadata;
    let second = metadata
        .into_builder()
        .set_properties(HashMap::from([("edit".to_string(), "second".to_string())]))
        .expect("set second")
        .build()
        .expect("build second")
        .metadata;

    catalog
        .update_view(&view, &read_location, first)
        .await
        .expect("the first commit from a fresh read must land");

    let err = catalog
        .update_view(&view, &read_location, second)
        .await
        .expect_err("a second commit from the same read has lost its race and must be refused");

    assert_eq!(
        err.kind(),
        iceberg::ErrorKind::CatalogCommitConflicts,
        "a lost race is a conflict the client retries, not any other failure: {err}"
    );

    let (_, live) = catalog.load_view(&view).await.expect("reload");
    assert_eq!(
        live.properties().get("edit").map(String::as_str),
        Some("first"),
        "the winner's edit must survive; the loser must not have overwritten it"
    );
}

/// Loading a view that was never created is a miss.
pub async fn load_missing_view_is_not_found(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["missing_view_ns"]).await;
    let view = TableIdent::new(ns, "absent".to_string());
    assert_kind(
        catalog.load_view(&view).await,
        ErrorKind::TableNotFound,
        "loading a view that does not exist",
    );
}

/// Dropping a view that was never created is a miss.
pub async fn drop_missing_view_is_not_found(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["drop_missing_view_ns"]).await;
    let view = TableIdent::new(ns, "absent".to_string());
    assert_kind(
        catalog.drop_view(&view).await,
        ErrorKind::TableNotFound,
        "dropping a view that does not exist",
    );
}

/// Creating a view twice is a conflict on the name.
pub async fn duplicate_view_is_already_exists(catalog: &dyn CatalogStore, warehouse: &str) {
    let ns = given_namespace(catalog, &["dup_view_ns"]).await;
    given_view(catalog, warehouse, &ns, "summary").await;

    let location = view_location(warehouse, &ns, "summary");
    assert_kind(
        catalog
            .create_view(
                &TableIdent::new(ns.clone(), "summary".to_string()),
                simple_view_metadata(&ns, "summary", &location),
            )
            .await,
        ErrorKind::TableAlreadyExists,
        "creating a view that already exists",
    );
}

/// Renaming a view onto an occupied name must refuse rather than clobber.
pub async fn rename_view_onto_existing_is_already_exists(
    catalog: &dyn CatalogStore,
    warehouse: &str,
) {
    let ns = given_namespace(catalog, &["rename_view_ns"]).await;
    let src = given_view(catalog, warehouse, &ns, "source").await;
    let dest = given_view(catalog, warehouse, &ns, "occupied").await;

    assert_kind(
        catalog.rename_view(&src, &dest).await,
        ErrorKind::TableAlreadyExists,
        "renaming a view onto one that already exists",
    );
}

/// A namespace holding views must refuse to drop, exactly as one holding
/// tables does. A view left behind is still loadable by exact path but absent
/// from every listing.
pub async fn drop_namespace_with_views_is_precondition_failed(
    catalog: &dyn CatalogStore,
    warehouse: &str,
) {
    let ns = given_namespace(catalog, &["occupied_by_views"]).await;
    given_view(catalog, warehouse, &ns, "summary").await;

    assert_kind(
        catalog.drop_namespace(&ns).await,
        ErrorKind::PreconditionFailed,
        "dropping a namespace that still holds views",
    );
}

/// One namespace holds one thing per name, whichever kind it is.
///
/// # Why this is not merely an interoperability rule
///
/// The spec says it on four endpoints — `createTable`, `createView`,
/// `renameTable` and `renameView` each answer `409` for *"the identifier already
/// exists as a table or view"* — and a catalog that allowed the collision would
/// hand every engine an ambiguous `SELECT * FROM db.events`.
///
/// Here it is worse than ambiguous. Both kinds are laid out at
/// `<warehouse>/<namespace>/<name>`, so a collision puts two different metadata
/// documents in one directory and a purge of the table deletes the view's files
/// along with its own. Two callers each see a resource that works, right up
/// until one of them drops theirs.
///
/// Asserted in the shared suite because the two backends reach it differently —
/// redb by a check inside a serialised write transaction, Postgres by a shared
/// primary key across both relations — and a conformance claim that held for one
/// of them would be worth nothing.
pub async fn a_view_and_a_table_cannot_share_a_name(catalog: &dyn CatalogStore, warehouse: &str) {
    let ns = given_namespace(catalog, &["shared_name_ns"]).await;

    // A view cannot take a table's name.
    given_table(catalog, &ns, "events").await;
    assert_kind(
        catalog
            .create_view(
                &TableIdent::new(ns.clone(), "events".into()),
                simple_view_metadata(&ns, "events", &view_location(warehouse, &ns, "events")),
            )
            .await,
        ErrorKind::TableAlreadyExists,
        "creating a view named after an existing table",
    );

    // And a table cannot take a view's.
    given_view(catalog, warehouse, &ns, "summary").await;
    assert_kind(
        catalog
            .create_table(
                &ns,
                TableCreation::builder()
                    .name("summary".into())
                    .schema(simple_schema())
                    .build(),
            )
            .await,
        ErrorKind::TableAlreadyExists,
        "creating a table named after an existing view",
    );

    // Neither attempt disturbed what was already there.
    assert!(
        catalog
            .table_exists(&TableIdent::new(ns.clone(), "events".into()))
            .await
            .unwrap()
    );
    assert!(
        catalog
            .view_exists(&TableIdent::new(ns.clone(), "summary".into()))
            .await
            .unwrap()
    );
    assert!(
        !catalog
            .view_exists(&TableIdent::new(ns.clone(), "events".into()))
            .await
            .unwrap()
    );
    assert!(
        !catalog
            .table_exists(&TableIdent::new(ns, "summary".into()))
            .await
            .unwrap()
    );
}

/// A rename may not land on a name the *other* kind already holds either.
pub async fn a_rename_cannot_land_on_the_other_kinds_name(
    catalog: &dyn CatalogStore,
    warehouse: &str,
) {
    let ns = given_namespace(catalog, &["rename_collision_ns"]).await;
    given_table(catalog, &ns, "t").await;
    given_view(catalog, warehouse, &ns, "v").await;

    assert_kind(
        catalog
            .rename_table(
                &TableIdent::new(ns.clone(), "t".into()),
                &TableIdent::new(ns.clone(), "v".into()),
            )
            .await,
        ErrorKind::TableAlreadyExists,
        "renaming a table onto a view's name",
    );

    assert_kind(
        catalog
            .rename_view(
                &TableIdent::new(ns.clone(), "v".into()),
                &TableIdent::new(ns.clone(), "t".into()),
            )
            .await,
        ErrorKind::TableAlreadyExists,
        "renaming a view onto a table's name",
    );

    // Both are still where they were.
    assert!(
        catalog
            .table_exists(&TableIdent::new(ns.clone(), "t".into()))
            .await
            .unwrap()
    );
    assert!(
        catalog
            .view_exists(&TableIdent::new(ns, "v".into()))
            .await
            .unwrap()
    );
}

// ── Commits ─────────────────────────────────────────────────────────────────

/// A commit advances the metadata pointer, and the old file is left in place.
pub async fn a_commit_advances_the_metadata_pointer(catalog: &dyn CatalogStore) {
    use iceberg::TableUpdate;

    let ns = given_namespace(catalog, &["commit_ns"]).await;
    let table = given_table(catalog, &ns, "events").await;

    let before = catalog.load_table(&table).await.expect("load succeeds");
    let before_location = before
        .metadata_location()
        .expect("a table has a location")
        .to_string();

    let committed = catalog
        .commit_table(
            &table,
            vec![],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("owner".to_string(), "analytics".to_string())]),
            }],
        )
        .await
        .expect("commit succeeds");

    assert_ne!(
        committed
            .metadata_location()
            .expect("a committed table has a location"),
        before_location,
        "a commit must write a new metadata file, never overwrite the live one"
    );
    assert_eq!(
        committed
            .metadata()
            .properties()
            .get("owner")
            .map(String::as_str),
        Some("analytics"),
        "the update must be reflected in the returned metadata"
    );

    // And the change must be durable, not just present in the response.
    let reloaded = catalog.load_table(&table).await.expect("reload succeeds");
    assert_eq!(
        reloaded
            .metadata()
            .properties()
            .get("owner")
            .map(String::as_str),
        Some("analytics")
    );
}

/// Committing to a table that does not exist is a miss, not a create.
pub async fn commit_to_missing_table_is_not_found(catalog: &dyn CatalogStore) {
    use iceberg::TableUpdate;

    let ns = given_namespace(catalog, &["commit_missing_ns"]).await;
    let table = TableIdent::new(ns, "absent".to_string());

    assert_kind(
        catalog
            .commit_table(
                &table,
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::new(),
                }],
            )
            .await,
        ErrorKind::TableNotFound,
        "committing to a table that does not exist",
    );
}

/// A multi-table commit is all-or-nothing. When one table's requirement fails,
/// the other must not have advanced — a half-applied transaction is the one
/// outcome the atomic API exists to rule out.
pub async fn a_failed_multi_table_commit_applies_to_neither(catalog: &dyn CatalogStore) {
    use iceberg::{TableRequirement, TableUpdate};

    let ns = given_namespace(catalog, &["atomic_ns"]).await;
    let first = given_table(catalog, &ns, "first").await;
    let second = given_table(catalog, &ns, "second").await;

    let before = catalog
        .load_table(&first)
        .await
        .expect("load succeeds")
        .metadata_location()
        .expect("a table has a location")
        .to_string();

    let result = catalog
        .commit_tables_atomic(vec![
            (
                first.clone(),
                vec![],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::from([("k".to_string(), "v".to_string())]),
                }],
            ),
            // This one cannot succeed: the UUID is deliberately not its own.
            (
                second.clone(),
                vec![TableRequirement::UuidMatch {
                    uuid: uuid::Uuid::nil(),
                }],
                vec![],
            ),
        ])
        .await;

    assert!(
        result.is_err(),
        "a failing requirement must fail the transaction"
    );

    let after = catalog
        .load_table(&first)
        .await
        .expect("load succeeds")
        .metadata_location()
        .expect("a table has a location")
        .to_string();

    assert_eq!(
        before, after,
        "the sibling table must not have advanced — the transaction was all-or-nothing"
    );
    assert!(
        catalog
            .load_table(&first)
            .await
            .expect("load succeeds")
            .metadata()
            .properties()
            .get("k")
            .is_none(),
        "no part of a rolled-back transaction may be visible"
    );
}

/// Rename moves a table across namespaces, and the old name stops resolving.
pub async fn rename_moves_a_table_across_namespaces(catalog: &dyn CatalogStore) {
    let from = given_namespace(catalog, &["rename_from"]).await;
    let to = given_namespace(catalog, &["rename_to"]).await;
    let src = given_table(catalog, &from, "events").await;
    let dest = TableIdent::new(to, "events".to_string());

    catalog
        .rename_table(&src, &dest)
        .await
        .expect("rename succeeds");

    assert!(
        !catalog.table_exists(&src).await.expect("exists succeeds"),
        "the old name must stop resolving"
    );
    assert!(
        catalog.table_exists(&dest).await.expect("exists succeeds"),
        "the new name must resolve"
    );
    // And it must be loadable there, not merely recorded.
    catalog
        .load_table(&dest)
        .await
        .expect("the moved table loads");
}

// ── Staged creation ─────────────────────────────────────────────────────────
//
// `stage-create` is how Spark performs CREATE TABLE AS SELECT: build the
// metadata, write data files against it, then commit the whole thing with an
// `assert-create` requirement. The invariant that matters is that a staged
// table is *not* a table until that commit lands.

/// A staged table is invisible: not loadable, not listed, not existing.
pub async fn a_staged_table_is_not_visible(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["staged_invisible"]).await;
    let creation = TableCreation::builder()
        .name("pending".to_string())
        .schema(simple_schema())
        .build();

    let staged = catalog
        .stage_create_table(&ns, creation)
        .await
        .expect("staging succeeds");
    assert!(
        staged.metadata_location().is_some(),
        "a staged table names the metadata the client will build on"
    );

    let ident = TableIdent::new(ns.clone(), "pending".to_string());
    assert!(
        !catalog.table_exists(&ident).await.expect("exists succeeds"),
        "a staged table does not exist yet"
    );
    assert_kind(
        catalog.load_table(&ident).await,
        ErrorKind::TableNotFound,
        "loading a table that is only staged",
    );

    let page = catalog
        .list_tables(&ns, &PageRequest::first(100))
        .await
        .expect("listing succeeds");
    assert!(
        page.entries.is_empty(),
        "a staged table must not appear in a listing"
    );
}

/// The whole point: staging then committing with `assert-create` produces a
/// real table carrying the committed snapshot.
pub async fn a_staged_table_becomes_real_on_commit(catalog: &dyn CatalogStore) {
    use iceberg::{TableRequirement, TableUpdate};

    let ns = given_namespace(catalog, &["staged_commit"]).await;
    let creation = TableCreation::builder()
        .name("events".to_string())
        .schema(simple_schema())
        .build();

    catalog
        .stage_create_table(&ns, creation)
        .await
        .expect("staging succeeds");

    let ident = TableIdent::new(ns.clone(), "events".to_string());
    let committed = catalog
        .commit_table(
            &ident,
            vec![TableRequirement::NotExist],
            vec![TableUpdate::SetProperties {
                updates: HashMap::from([("written-by".to_string(), "ctas".to_string())]),
            }],
        )
        .await
        .expect("committing a staged table succeeds");

    assert_eq!(
        committed
            .metadata()
            .properties()
            .get("written-by")
            .map(String::as_str),
        Some("ctas")
    );

    assert!(
        catalog.table_exists(&ident).await.expect("exists succeeds"),
        "the table exists once its staged commit lands"
    );
    let loaded = catalog.load_table(&ident).await.expect("load succeeds");
    assert_eq!(
        loaded
            .metadata()
            .current_schema()
            .as_struct()
            .fields()
            .len(),
        simple_schema().as_struct().fields().len(),
        "the staged schema survives the commit"
    );
    assert_eq!(
        loaded.metadata().schemas_iter().count(),
        1,
        "re-applying the staged schema must reuse it, not duplicate it"
    );
}

/// `assert-create` against a name that is already a real table is a conflict —
/// the client re-reads and decides, rather than clobbering.
pub async fn committing_a_stage_over_an_existing_table_conflicts(catalog: &dyn CatalogStore) {
    use iceberg::{TableRequirement, TableUpdate};

    let ns = given_namespace(catalog, &["staged_conflict"]).await;
    let creation = TableCreation::builder()
        .name("events".to_string())
        .schema(simple_schema())
        .build();
    catalog
        .stage_create_table(&ns, creation)
        .await
        .expect("staging succeeds");

    // Somebody else creates the table for real in the meantime.
    given_table(catalog, &ns, "events").await;

    let ident = TableIdent::new(ns, "events".to_string());
    assert_kind(
        catalog
            .commit_table(
                &ident,
                vec![TableRequirement::NotExist],
                vec![TableUpdate::SetProperties {
                    updates: HashMap::new(),
                }],
            )
            .await,
        ErrorKind::CatalogCommitConflicts,
        "committing a staged table onto a name that was taken meanwhile",
    );
}

/// Staging onto a name that is already a real table fails immediately, rather
/// than deferring an inevitable failure to commit time.
pub async fn staging_over_an_existing_table_is_already_exists(catalog: &dyn CatalogStore) {
    let ns = given_namespace(catalog, &["staged_taken"]).await;
    given_table(catalog, &ns, "events").await;

    let creation = TableCreation::builder()
        .name("events".to_string())
        .schema(simple_schema())
        .build();

    assert_kind(
        catalog.stage_create_table(&ns, creation).await,
        ErrorKind::TableAlreadyExists,
        "staging a name that is already a real table",
    );
}

/// A staged table holds no claim on its namespace, and cannot be promoted into
/// one that no longer exists.
pub async fn a_staged_table_does_not_block_or_outlive_its_namespace(catalog: &dyn CatalogStore) {
    use iceberg::{TableRequirement, TableUpdate};

    let ns = given_namespace(catalog, &["staged_ns"]).await;
    let creation = TableCreation::builder()
        .name("pending".to_string())
        .schema(simple_schema())
        .build();
    catalog
        .stage_create_table(&ns, creation)
        .await
        .expect("staging succeeds");

    // A staged table is not a table, so it must not keep the namespace alive.
    catalog
        .drop_namespace(&ns)
        .await
        .expect("a staged table must not block dropping its namespace");

    // And it must not be promotable afterwards, which would create a table
    // inside a namespace that does not exist.
    let ident = TableIdent::new(ns, "pending".to_string());
    let result = catalog
        .commit_table(
            &ident,
            vec![TableRequirement::NotExist],
            vec![TableUpdate::SetProperties {
                updates: HashMap::new(),
            }],
        )
        .await;
    assert!(
        result.is_err(),
        "a staged table must not be promotable into a dropped namespace"
    );
}

/// A commit that loses its swap must not leave its metadata file behind.
///
/// Every commit writes its metadata file *before* swapping the pointer, so one
/// that loses leaves a file nothing references. `FileIO` cannot enumerate a
/// directory, so nothing could ever find it afterwards — the only moment its
/// path is known is the moment the swap fails, which is where it gets deleted.
///
/// The losing swap is provoked deterministically by naming one table twice in a
/// single atomic commit. Both entries are prepared from the same base and both
/// write a file; the first swap then advances the pointer the second is
/// asserting, so the second necessarily loses. That is also precisely why the
/// REST layer rejects duplicate identifiers with `400` — here it is used
/// deliberately, to reach a path that is otherwise a race.
pub async fn a_lost_commit_leaves_no_metadata_file(catalog: &dyn CatalogStore, warehouse: &str) {
    use iceberg::TableUpdate;

    let ns = given_namespace(catalog, &["litter"]).await;
    let table = given_table(catalog, &ns, "events").await;

    let metadata_dir = std::path::Path::new(rustberg::location::path_from_url(warehouse))
        .join("litter")
        .join("events")
        .join("metadata");

    let count = || {
        std::fs::read_dir(&metadata_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    };

    let before = count();
    assert!(
        before > 0,
        "the created table wrote its first metadata file"
    );

    let update = || TableUpdate::SetProperties {
        updates: HashMap::from([("k".to_string(), "v".to_string())]),
    };

    let result = catalog
        .commit_tables_atomic(vec![
            (table.clone(), vec![], vec![update()]),
            (table.clone(), vec![], vec![update()]),
        ])
        .await;

    assert!(
        result.is_err(),
        "one table named twice cannot both advance from the same base"
    );

    assert_eq!(
        count(),
        before,
        "a commit that wrote its metadata and then lost the swap must delete it, or a \
         contended table accumulates one abandoned file per lost race — and the retry \
         loop means a single failed commit can leave several"
    );
}

/// Every contract test, in one call.
///
/// The fixture hands back a catalog handle per case. Cases never share a
/// namespace name — each one names its own — so a fixture backed by a single
/// database is fine and is what the Postgres suite does: spinning up a
/// container per case would cost far more than the isolation is worth here.
pub async fn run_all<F, Fut>(fresh_catalog: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = (std::sync::Arc<dyn CatalogStore>, String)>,
{
    /// Cases that need only the catalog.
    macro_rules! check {
        ($($case:ident),* $(,)?) => {
            $(
                {
                    let (catalog, _warehouse) = fresh_catalog().await;
                    $case(catalog.as_ref()).await;
                }
            )*
        };
    }

    /// Cases that also need somewhere to put a view's metadata file.
    macro_rules! check_in_warehouse {
        ($($case:ident),* $(,)?) => {
            $(
                {
                    let (catalog, warehouse) = fresh_catalog().await;
                    $case(catalog.as_ref(), &warehouse).await;
                }
            )*
        };
    }

    check!(
        drop_namespace_with_tables_is_precondition_failed,
        drop_namespace_with_children_is_precondition_failed,
        drop_missing_namespace_is_not_found,
        load_missing_namespace_is_not_found,
        duplicate_namespace_is_already_exists,
        load_missing_table_is_not_found,
        duplicate_table_is_already_exists,
        create_table_in_missing_namespace_is_not_found,
        register_into_missing_namespace_is_not_found,
        drop_missing_table_is_not_found,
        rename_onto_existing_table_is_already_exists,
        rename_missing_table_is_not_found,
        failed_requirement_is_a_commit_conflict,
        paging_visits_every_table_exactly_once,
        listing_returns_direct_children_only,
        // Views that need no warehouse
        load_missing_view_is_not_found,
        drop_missing_view_is_not_found,
        // Commits
        a_commit_advances_the_metadata_pointer,
        commit_to_missing_table_is_not_found,
        a_failed_multi_table_commit_applies_to_neither,
        rename_moves_a_table_across_namespaces,
        // Staged creation
        a_staged_table_is_not_visible,
        a_staged_table_becomes_real_on_commit,
        committing_a_stage_over_an_existing_table_conflicts,
        staging_over_an_existing_table_is_already_exists,
        a_staged_table_does_not_block_or_outlive_its_namespace,
    );

    check_in_warehouse!(
        a_view_round_trips,
        a_second_view_commit_from_one_read_is_refused,
        duplicate_view_is_already_exists,
        rename_view_onto_existing_is_already_exists,
        drop_namespace_with_views_is_precondition_failed,
        a_view_and_a_table_cannot_share_a_name,
        a_rename_cannot_land_on_the_other_kinds_name,
        a_lost_commit_leaves_no_metadata_file,
        registering_metadata_that_points_outside_the_warehouse_is_refused,
    );
}
