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
    async fn update_view(&self, _: &TableIdent, _: ViewMetadata) -> Result<(String, ViewMetadata)> {
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

    fn supports_location(&self, location: &str) -> bool {
        location.starts_with("s3://")
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
}

/// A catalog serving one table at `s3://wh/db/events`, with signing on.
async fn fixture() -> Fixture {
    fixture_with_prefixes(vec![WAREHOUSE.to_string()]).await
}

async fn fixture_with_prefixes(prefixes: Vec<String>) -> Fixture {
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
        .with_request_signer(Arc::new(StubSigner { prefixes }))
        .build_with_api_keys()
        .await
        .expect("build app");

    Fixture {
        app,
        writer: writer.to_string(),
        reader: reader.to_string(),
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
