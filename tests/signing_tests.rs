//! Remote signing: `POST /v1/namespaces/{ns}/tables/{t}/sign`.
//!
//! The signature itself is AWS's, and these tests do not check it — they check
//! everything Rustberg decides *before* it is minted, which is where the
//! security lives. A stub signer stands in for SigV4, and a fixed catalog puts
//! one table at an `s3://` location, so the suite needs no credentials, no
//! network and no object store.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use iceberg::spec::{NestedField, PrimitiveType, Schema, TableMetadataBuilder, ViewMetadata};
use iceberg::table::Table;
use iceberg::{
    Error, ErrorKind, Namespace, NamespaceIdent, TableCreation, TableIdent, TableRequirement,
    TableUpdate,
};

/// The catalog trait speaks `iceberg::Result`; the signer speaks its own.
type Result<T> = iceberg::Result<T>;
use rustberg::App;
use rustberg::auth::ApiKeyBuilder;
use rustberg::catalog::{CatalogStore, Page, PageRequest, StorageHealthStatus};
use rustberg::credentials::{
    HeaderMultiMap, RequestSigner, SignRequest, SignedRequest, SigningError,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TENANT: &str = "acme";
const NAMESPACE: &str = "db";
const TABLE: &str = "events";
const WAREHOUSE: &str = "s3://wh";
const TABLE_LOCATION: &str = "s3://wh/db/events";

/// A catalog holding exactly one namespace and one table, at an `s3://`
/// location. Everything else is absent or unreachable, which is what keeps
/// these tests about the sign endpoint.
#[derive(Debug)]
struct FixedCatalog;

impl FixedCatalog {
    fn down<T>() -> Result<T> {
        Err(Error::new(
            ErrorKind::Unexpected,
            "not part of this fixture",
        ))
    }
}

#[async_trait::async_trait]
impl CatalogStore for FixedCatalog {
    fn namespace_prefix_for(&self, _: &iceberg::NamespaceIdent) -> Option<String> {
        None
    }

    fn capabilities_for(
        &self,
        _: Option<&iceberg::NamespaceIdent>,
    ) -> rustberg::catalog::Capabilities {
        rustberg::catalog::Capabilities::full()
    }

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
    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        if namespace.as_ref().as_slice() == [NAMESPACE.to_string()] {
            return Ok(Namespace::with_properties(
                namespace.clone(),
                HashMap::from([(
                    "rustberg.internal.tenant-id".to_string(),
                    TENANT.to_string(),
                )]),
            ));
        }
        Err(Error::new(
            ErrorKind::NamespaceNotFound,
            namespace.join("."),
        ))
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
    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        if table.namespace().as_ref().as_slice() != [NAMESPACE.to_string()] || table.name() != TABLE
        {
            return Err(Error::new(ErrorKind::TableNotFound, table.to_string()));
        }

        let schema = Schema::builder()
            .with_schema_id(0)
            .with_fields(vec![
                NestedField::required(1, "id", iceberg::spec::Type::Primitive(PrimitiveType::Long))
                    .into(),
            ])
            .build()?;

        let metadata = TableMetadataBuilder::from_table_creation(
            TableCreation::builder()
                .name(TABLE.to_string())
                .location(TABLE_LOCATION.to_string())
                .schema(schema)
                .build(),
        )?
        .build()?
        .metadata;

        Table::builder()
            .runtime(iceberg::Runtime::try_current()?)
            .identifier(table.clone())
            .metadata(metadata)
            .metadata_location(format!("{TABLE_LOCATION}/metadata/v1.metadata.json"))
            .file_io(rustberg::catalog::file_io::build_file_io()?)
            .build()
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
        Some(WAREHOUSE.to_string())
    }
    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        Ok(StorageHealthStatus::unhealthy("unreachable", "test double"))
    }
}

/// A signer that records nothing and signs everything it is handed.
///
/// Reaching it at all is the assertion: the endpoint refuses long before here
/// for anything a policy or a location check should stop.
#[derive(Debug)]
struct StubSigner {
    prefixes: Vec<String>,
}

#[async_trait::async_trait]
impl RequestSigner for StubSigner {
    async fn sign(
        &self,
        request: SignRequest<'_>,
    ) -> std::result::Result<SignedRequest, SigningError> {
        let mut headers = HeaderMultiMap::new();
        headers.insert(
            "Authorization".to_string(),
            vec![format!("STUB {} {}", request.method, request.region)],
        );
        Ok(SignedRequest {
            uri: request.uri.to_string(),
            headers,
        })
    }

    fn allowed_prefixes(&self) -> &[String] {
        &self.prefixes
    }
}

const POLICY: &str = r#"
permit(principal in Rustberg::Group::"reader",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
       resource) when { resource.tenant == principal.tenant };
permit(principal in Rustberg::Group::"writer",
       action in [Rustberg::Action::"Read", Rustberg::Action::"List",
                  Rustberg::Action::"Create", Rustberg::Action::"Update"],
       resource) when { resource.tenant == principal.tenant };
"#;

struct Fixture {
    app: App,
    writer: String,
    reader: String,
    /// Where the audit trail for this fixture was written, when one was asked
    /// for. Read with [`Fixture::records`].
    audit: Option<std::path::PathBuf>,
    /// Held so the directory outlives the fixture.
    _dir: Option<tempfile::TempDir>,
}

impl Fixture {
    /// The audit records this fixture has accumulated, in order.
    fn records(&self) -> Vec<Value> {
        let path = self.audit.as_ref().expect("fixture has no audit sink");
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
            .collect()
    }

    /// The storage-access records, which is what the signing tests below assert
    /// about.
    fn signatures(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["action"] == "sign_request")
            .collect()
    }
}

/// A catalog serving one table at `s3://wh/db/events`, with signing on.
async fn fixture() -> Fixture {
    fixture_with(vec![WAREHOUSE.to_string()], false).await
}

/// The same, recording its audit trail to a file the test can read.
async fn audited_fixture() -> Fixture {
    fixture_with(vec![WAREHOUSE.to_string()], true).await
}

async fn fixture_with_prefixes(prefixes: Vec<String>) -> Fixture {
    fixture_with(prefixes, false).await
}

/// A sink that fails every write, for the fail-closed tests.
#[derive(Debug)]
struct BrokenSink;

impl rustberg::auth::AuditSink for BrokenSink {
    fn write(
        &self,
        _: &rustberg::auth::AuditEvent,
    ) -> std::result::Result<(), rustberg::auth::AuditError> {
        Err(rustberg::auth::AuditError::Io(std::io::Error::other(
            "disk full",
        )))
    }
    fn flush(&self) -> std::result::Result<(), rustberg::auth::AuditError> {
        Ok(())
    }
    fn describe(&self) -> String {
        "broken".into()
    }
}

/// The same fixture, with a sink that fails every write and refuses to lose a
/// record.
async fn unrecordable_fixture() -> Fixture {
    let (writer_key, writer) = ApiKeyBuilder::new("writer", TENANT)
        .with_role("writer")
        .build();
    let (reader_key, reader) = ApiKeyBuilder::new("reader", TENANT)
        .with_role("reader")
        .build();

    let (app, _keys) = App::builder()
        .with_warehouse_location(WAREHOUSE)
        .with_default_tenant_id(TENANT)
        .with_catalog(Arc::new(FixedCatalog))
        .with_policies(POLICY)
        .with_api_keys(vec![writer_key, reader_key])
        .with_request_signer(Arc::new(StubSigner {
            prefixes: vec![WAREHOUSE.to_string()],
        }))
        .with_auditor(Arc::new(rustberg::auth::Auditor::new(
            Box::new(BrokenSink),
            true,
        )))
        .build_with_api_keys()
        .await
        .expect("build app");

    Fixture {
        app,
        writer: writer.to_string(),
        reader: reader.to_string(),
        audit: None,
        _dir: None,
    }
}

async fn fixture_with(prefixes: Vec<String>, audited: bool) -> Fixture {
    let (writer_key, writer) = ApiKeyBuilder::new("writer", TENANT)
        .with_role("writer")
        .build();
    let (reader_key, reader) = ApiKeyBuilder::new("reader", TENANT)
        .with_role("reader")
        .build();

    let mut builder = App::builder()
        .with_warehouse_location(WAREHOUSE)
        .with_default_tenant_id(TENANT)
        .with_catalog(Arc::new(FixedCatalog))
        .with_policies(POLICY)
        .with_api_keys(vec![writer_key, reader_key])
        .with_request_signer(Arc::new(StubSigner { prefixes }));

    let (dir, audit) = if audited {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        builder = builder.with_auditor(Arc::new(rustberg::auth::Auditor::new(
            Box::new(rustberg::auth::FileSink::open(&path).expect("open sink")),
            true,
        )));
        (Some(dir), Some(path))
    } else {
        (None, None)
    };

    let (app, _keys) = builder.build_with_api_keys().await.expect("build app");

    Fixture {
        app,
        writer: writer.to_string(),
        reader: reader.to_string(),
        audit,
        _dir: dir,
    }
}

async fn call(
    app: &App,
    method: &str,
    uri: &str,
    key: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    call_with_headers(app, method, uri, key, body, &[]).await
}

async fn call_with_headers(
    app: &App,
    method: &str,
    uri: &str,
    key: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", key);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }

    let request = match body {
        Some(json) => builder
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = app.clone().into_router().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn sign_body(method: &str, uri: &str) -> Value {
    json!({ "region": "eu-west-1", "method": method, "uri": uri, "headers": {} })
}

// ── The happy path ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_read_inside_the_table_is_signed() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let signed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        signed["uri"],
        "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet"
    );
    assert_eq!(signed["headers"]["Authorization"][0], "STUB GET eu-west-1");
}

/// A read may be cached against its request; a write may not.
#[tokio::test]
async fn the_response_says_whether_the_signature_may_be_cached() {
    let f = fixture().await;
    let uri = "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet";

    for (method, key, expected) in [
        ("GET", &f.reader, "private"),
        ("PUT", &f.writer, "no-cache"),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/namespaces/db/tables/events/sign")
            .header("X-API-Key", key)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&sign_body(method, uri)).unwrap(),
            ))
            .unwrap();

        let response = f.app.clone().into_router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            expected,
            "{method}"
        );
    }
}

// ── Authorization ───────────────────────────────────────────────────────

/// A reader may not have a `PUT` signed, even for its own table.
#[tokio::test]
async fn a_reader_cannot_have_a_write_signed() {
    let f = fixture().await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A table the caller cannot see is `404`, exactly as everywhere else.
#[tokio::test]
async fn signing_for_an_invisible_table_is_not_found() {
    let f = fixture().await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/absent/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/absent/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signing_without_a_credential_is_unauthorized() {
    let f = fixture().await;

    let request = Request::builder()
        .method("POST")
        .uri("/v1/namespaces/db/tables/events/sign")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&sign_body("GET", "https://wh.s3.amazonaws.com/db/events/f"))
                .unwrap(),
        ))
        .unwrap();

    let response = f.app.clone().into_router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Containment ─────────────────────────────────────────────────────────

/// The whole point: a caller authorized for one table cannot have a request
/// signed for another table's files.
#[tokio::test]
async fn a_request_for_another_tables_files_is_refused() {
    let f = fixture().await;

    for uri in [
        "https://wh.s3.eu-west-1.amazonaws.com/db/other/data/f.parquet",
        "https://wh.s3.eu-west-1.amazonaws.com/db/events-secret/data/f.parquet",
        "https://other.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        "https://wh.s3.eu-west-1.amazonaws.com/db/events/../other/f.parquet",
    ] {
        let (status, _) = call(
            &f.app,
            "POST",
            "/v1/namespaces/db/tables/events/sign",
            &f.reader,
            Some(sign_body("GET", uri)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
}

/// `DeleteObjects` addresses the bucket and names its keys in the body, so a
/// check that read only the path would authorize a delete of anything.
#[tokio::test]
async fn a_batch_delete_is_authorized_against_every_key_in_its_body() {
    let f = fixture().await;

    let permitted = json!({
        "region": "eu-west-1",
        "method": "POST",
        "uri": "https://wh.s3.eu-west-1.amazonaws.com/?delete",
        "headers": {},
        "body": "<Delete><Object><Key>db/events/data/a.parquet</Key></Object></Delete>"
    });
    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(permitted),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let smuggled = json!({
        "region": "eu-west-1",
        "method": "POST",
        "uri": "https://wh.s3.eu-west-1.amazonaws.com/?delete",
        "headers": {},
        "body": "<Delete><Object><Key>db/events/data/a.parquet</Key></Object>\
                 <Object><Key>db/other/data/b.parquet</Key></Object></Delete>"
    });
    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(smuggled),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "one key outside the table refuses the whole batch"
    );
}

/// S3 matches a list prefix as a raw string, so a prefix that stops at the table
/// location also returns a same-prefixed sibling's keys.
#[tokio::test]
async fn a_listing_must_be_scoped_below_the_table() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=db/events/data/",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=db/events",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Anything this endpoint cannot resolve to a location is refused rather than
/// signed against the bucket.
#[tokio::test]
async fn an_unresolvable_request_is_refused() {
    let f = fixture().await;

    for body in [
        sign_body("GET", "https://wh.s3.eu-west-1.amazonaws.com/?versions"),
        sign_body("GET", "s3://wh/db/events/f.parquet"),
        sign_body("TRACE", "https://wh.s3.eu-west-1.amazonaws.com/db/events/f"),
        json!({ "region": "eu-west-1", "method": "POST", "headers": {},
                "uri": "https://wh.s3.eu-west-1.amazonaws.com/?delete" }),
    ] {
        let (status, _) = call(
            &f.app,
            "POST",
            "/v1/namespaces/db/tables/events/sign",
            &f.writer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

/// A query parameter sent twice makes "the" value ambiguous, and the ambiguity
/// runs the wrong way.
///
/// This endpoint reads `prefix` once and confines the listing to it. S3 does not
/// specify which of two `prefix` values it acts on — so a request naming an
/// allowed prefix and then an empty one passes containment here and may list the
/// whole bucket there. The parameter that was authorized would not be the
/// parameter that took effect, so the request is refused instead.
#[tokio::test]
async fn a_query_parameter_sent_twice_is_refused() {
    let f = fixture().await;

    for uri in [
        // A second `prefix` that widens the listing to the whole bucket.
        "https://wh.s3.eu-west-1.amazonaws.com/?list-type=2&prefix=db/events/data/&prefix=",
        // A second `list-type`, which decides what this request even is.
        "https://wh.s3.eu-west-1.amazonaws.com/?list-type=2&list-type=1&prefix=db/events/data/",
        // A repeat on an ordinary parameter is refused too: the rule is about
        // the query string being unambiguous, not about today's parameter list.
        "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet?x-id=GetObject&x-id=PutObject",
    ] {
        let (status, body) = call(
            &f.app,
            "POST",
            "/v1/namespaces/db/tables/events/sign",
            &f.reader,
            Some(sign_body("GET", uri)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
    }
}

/// Rustberg signs only for storage it manages. A signer scoped elsewhere refuses
/// rather than lending the server's authority over data it does not own.
#[tokio::test]
async fn a_table_outside_the_signers_scope_is_refused() {
    let f = fixture_with_prefixes(vec!["s3://somewhere-else".to_string()]).await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Advertisement ───────────────────────────────────────────────────────

#[tokio::test]
async fn signing_is_advertised_and_offered_together() {
    let f = fixture().await;

    let (status, body) = call(&f.app, "GET", "/v1/config", &f.reader, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/sign"),
        "a configured signer is advertised: {body}"
    );

    // And a deployment without one neither advertises nor serves it.
    let (app, _) = plain_app().await;
    let (_, body) = call(&app, "GET", "/v1/config", "", None).await;
    assert!(!body.contains("/sign"), "{body}");
}

async fn plain_app() -> (App, String) {
    let app = App::builder()
        .with_warehouse_location("memory://plain")
        .with_default_tenant_id("acme")
        .build()
        .await
        .expect("build app");
    (app, String::new())
}

/// The client asks for signing with the delegation header; a response that
/// switched it on unasked would route every object read through a server the
/// client had not planned to depend on.
#[tokio::test]
async fn load_table_describes_the_signer_only_when_asked() {
    let f = fixture().await;

    let (_, body) = call(
        &f.app,
        "GET",
        "/v1/namespaces/db/tables/events",
        &f.reader,
        None,
    )
    .await;
    let loaded: Value = serde_json::from_str(&body).unwrap();
    assert!(loaded.get("remote-signing-config").is_none(), "{body}");

    let (_, body) = call_with_headers(
        &f.app,
        "GET",
        "/v1/namespaces/db/tables/events",
        &f.reader,
        None,
        &[("X-Iceberg-Access-Delegation", "remote-signing")],
    )
    .await;
    let loaded: Value = serde_json::from_str(&body).unwrap();
    assert!(loaded.get("remote-signing-config").is_some(), "{body}");
    assert_eq!(loaded["config"]["s3.remote-signing-enabled"], "true");
    assert_eq!(
        loaded["config"]["s3.signer.endpoint"],
        "v1/namespaces/db/tables/events/sign"
    );
}

// ── The operation, not only the location ────────────────────────────────

fn sign_body_with(method: &str, uri: &str, headers: &[(&str, &str)]) -> Value {
    let map: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(name, value)| ((*name).to_string(), json!([value])))
        .collect();
    json!({ "region": "eu-west-1", "method": method, "uri": uri, "headers": map })
}

/// The exfiltration primitive the endpoint would otherwise be. The destination
/// is inside the caller's own table and passes every containment check; the
/// source is somebody else's bucket, fetched with *this server's* storage role.
#[tokio::test]
async fn a_copy_source_outside_the_table_is_refused() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(sign_body_with(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/stolen.parquet",
            &[("x-amz-copy-source", "/other-bucket/secrets/private.parquet")],
        )),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("other-bucket"),
        "names what was refused: {body}"
    );
}

#[tokio::test]
async fn a_copy_within_the_table_is_signed_as_a_write() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(sign_body_with(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/b.parquet",
            &[("x-amz-copy-source", "/wh/db/events/data/a.parquet")],
        )),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A copy is a write, so a reader may not have one signed even entirely inside
/// the table it may read.
#[tokio::test]
async fn a_reader_cannot_have_a_copy_signed() {
    let f = fixture().await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body_with(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/b.parquet",
            &[("x-amz-copy-source", "/wh/db/events/data/a.parquet")],
        )),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// `?acl` is inside the table location and passes every containment check there
/// is. It also publishes the object to the internet.
#[tokio::test]
async fn a_subresource_that_changes_who_may_read_is_refused() {
    let f = fixture().await;

    for subresource in ["acl", "tagging", "retention", "legal-hold"] {
        let (status, body) = call(
            &f.app,
            "POST",
            "/v1/namespaces/db/tables/events/sign",
            &f.writer,
            Some(sign_body(
                "PUT",
                &format!(
                    "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet?{subresource}"
                ),
            )),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "?{subresource}: {body}");
    }
}

#[tokio::test]
async fn a_header_that_grants_access_to_somebody_else_is_refused() {
    let f = fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(sign_body_with(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
            &[("x-amz-acl", "public-read")],
        )),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The traffic an engine actually sends must keep working — a refusal that is
/// too broad is an outage rather than a control.
#[tokio::test]
async fn multipart_upload_and_ordinary_reads_are_still_signed() {
    let f = fixture().await;

    let base = "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet";
    for (method, uri) in [
        ("GET", base.to_string()),
        ("HEAD", base.to_string()),
        ("PUT", base.to_string()),
        ("POST", format!("{base}?uploads")),
        ("PUT", format!("{base}?partNumber=1&uploadId=abc")),
        ("POST", format!("{base}?uploadId=abc")),
        ("DELETE", format!("{base}?uploadId=abc")),
        ("GET", format!("{base}?versionId=v1&x-id=GetObject")),
    ] {
        let (status, body) = call(
            &f.app,
            "POST",
            "/v1/namespaces/db/tables/events/sign",
            &f.writer,
            Some(sign_body(method, &uri)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{method} {uri}: {body}");
    }
}

// ── The audit trail ─────────────────────────────────────────────────────
//
// Signing is where a deployment that vends no credentials puts its whole
// storage-access story, so the trail has to carry it. Without these records a
// signed `GET` of one file and a signed `DeleteObjects` over every file in the
// table are indistinguishable.

/// The record says which objects a signature covered, not merely that one was
/// minted for the table.
#[tokio::test]
async fn a_signature_is_recorded_with_the_objects_it_covers() {
    let f = audited_fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let signatures = f.signatures();
    assert_eq!(signatures.len(), 1, "{signatures:?}");
    let record = &signatures[0];

    assert_eq!(record["category"], "storage_access");
    assert_eq!(record["outcome"], "success");
    assert_eq!(record["operation"], "read");
    assert_eq!(record["resource_id"], "acme/db/events");
    assert!(record["principal_id"].is_string());
    assert_eq!(record["tenant_id"], "acme");
    assert_eq!(
        record["details"]["locations"],
        "s3://wh/db/events/data/f.parquet"
    );
}

/// A write signature and a read signature must be distinguishable in the trail.
/// They are the difference between "read this file" and "delete it".
#[tokio::test]
async fn a_write_signature_is_recorded_as_a_write() {
    let f = audited_fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(sign_body(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let signatures = f.signatures();
    assert_eq!(signatures.len(), 1, "{signatures:?}");
    assert_eq!(signatures[0]["operation"], "write");

    // And the decision that permitted the write is in the trail too, rather than
    // being asked speculatively and dropped.
    let updates: Vec<Value> = f
        .records()
        .into_iter()
        .filter(|r| r["action"] == "decision" && r["operation"] == "Update")
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "the Update decision behind a write signature was not recorded: {updates:?}"
    );
    assert_eq!(updates[0]["outcome"], "success");
}

/// A request that reached outside its table is the single most interesting
/// thing this endpoint sees, and it is recorded rather than only returned.
#[tokio::test]
async fn a_refused_signature_is_recorded_with_what_it_reached_for() {
    let f = audited_fixture().await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/other/secrets.parquet",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let signatures = f.signatures();
    assert_eq!(signatures.len(), 1, "{signatures:?}");
    assert_eq!(signatures[0]["outcome"], "denied");
    assert_eq!(
        signatures[0]["details"]["locations"], "s3://wh/db/other/secrets.parquet",
        "the trail must name what was reached for, not only that something was"
    );
}

/// A caller permitted to read but not write is refused a write signature, and
/// the refusal is recorded — as a denied `Update` decision and as a denied
/// signature, which are two different facts.
#[tokio::test]
async fn a_reader_refused_a_write_signature_is_recorded_twice() {
    let f = audited_fixture().await;

    let (status, _) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "DELETE",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let records = f.records();
    assert!(
        records.iter().any(|r| r["action"] == "decision"
            && r["operation"] == "Update"
            && r["outcome"] == "denied"),
        "the refused Update decision is missing: {records:?}"
    );
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "sign_request" && r["outcome"] == "denied"),
        "the refused signature is missing: {records:?}"
    );
}

/// A signature that writes and cannot be recorded is not minted.
///
/// This is the fail-closed rule applied to storage access: handing an engine the
/// authority to overwrite a data file is a change to what the world can do with
/// the warehouse, and losing that record while keeping the grant is the same
/// trade as losing a commit record and keeping the commit.
#[tokio::test]
async fn a_write_signature_is_refused_when_it_cannot_be_recorded() {
    let f = unrecordable_fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.writer,
        Some(sign_body(
            "PUT",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

/// A *read* signature is not, for the same reason a read decision is not:
/// refusing every object read because a disk filled turns an observability
/// problem into an outage, and a lost read record is not a lost grant of write
/// access.
#[tokio::test]
async fn a_read_signature_still_serves_when_it_cannot_be_recorded() {
    let f = unrecordable_fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "GET",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// And a *refused* signature answers the policy question, not an availability
/// one — even on a sink that cannot record the refusal.
///
/// The fail-closed rule is about an unrecorded grant. A refusal granted nothing,
/// so there is nothing unrecorded to refuse, and a `503` here would tell the
/// caller its request failed when in fact its policy said no.
#[tokio::test]
async fn a_refusal_is_still_a_refusal_when_it_cannot_be_recorded() {
    let f = unrecordable_fixture().await;

    let (status, body) = call(
        &f.app,
        "POST",
        "/v1/namespaces/db/tables/events/sign",
        &f.reader,
        Some(sign_body(
            "DELETE",
            "https://wh.s3.eu-west-1.amazonaws.com/db/events/data/f.parquet",
        )),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a policy denial must not surface as an outage: {body}"
    );
}
