//! OpenAPI specification for Rustberg Iceberg REST Catalog.
//!
//! Provides OpenAPI 3.0 specification based on the Iceberg REST Catalog spec.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rustberg OpenAPI documentation.
pub struct ApiDoc;

impl ApiDoc {
    /// Returns the OpenAPI specification as JSON.
    pub fn json() -> String {
        serde_json::to_string_pretty(&Self::spec()).unwrap()
    }

    /// Returns the OpenAPI specification as YAML.
    pub fn yaml() -> String {
        OPENAPI_YAML.replace("{{VERSION}}", env!("CARGO_PKG_VERSION"))
    }

    /// Returns the OpenAPI specification as a struct.
    pub fn spec() -> OpenApiSpec {
        OpenApiSpec {
            openapi: "3.0.3".to_string(),
            info: Info {
                title: "Rustberg - Apache Iceberg REST Catalog".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: "A production-grade, single-binary Apache Iceberg REST Catalog server written in Rust. This API implements the Apache Iceberg REST Catalog Specification.".to_string(),
                license: License {
                    name: "Apache-2.0".to_string(),
                    url: "https://www.apache.org/licenses/LICENSE-2.0".to_string(),
                },
                contact: Contact {
                    name: "Rustberg".to_string(),
                    url: "https://github.com/hupe1980/rustberg".to_string(),
                },
            },
            servers: vec![Server {
                url: "/".to_string(),
                description: "Default server".to_string(),
            }],
            tags: vec![
                Tag { name: "config".to_string(), description: "Server configuration endpoints".to_string() },
                Tag { name: "namespaces".to_string(), description: "Namespace management operations".to_string() },
                Tag { name: "tables".to_string(), description: "Table management operations".to_string() },
                Tag { name: "health".to_string(), description: "Health check endpoints".to_string() },
                Tag { name: "metrics".to_string(), description: "Observability endpoints".to_string() },
            ],
            paths: HashMap::new(),
            components: Components {
                security_schemes: HashMap::new(),
                schemas: HashMap::new(),
            },
        }
    }
}

// ============================================================================
// Static OpenAPI YAML
// ============================================================================

const OPENAPI_YAML: &str = r##"openapi: "3.0.3"
info:
  title: "Rustberg - Apache Iceberg REST Catalog"
  version: "{{VERSION}}"
  description: |
    A production-grade, single-binary Apache Iceberg REST Catalog server written in Rust.
    
    This API implements the Apache Iceberg REST Catalog Specification.
  license:
    name: "Apache-2.0"
    url: "https://www.apache.org/licenses/LICENSE-2.0"
  contact:
    name: "Rustberg"
    url: "https://github.com/hupe1980/rustberg"

servers:
  - url: "/"
    description: "Default server"

tags:
  - name: config
    description: Server configuration endpoints
  - name: namespaces
    description: Namespace management operations
  - name: tables
    description: Table management operations
  - name: search
    description: Catalog search and discovery
  - name: auth
    description: Authentication introspection endpoints
  - name: health
    description: Health check endpoints
  - name: metrics
    description: Observability endpoints

paths:
  /v1/config:
    get:
      tags: [config]
      summary: Get server configuration
      operationId: getConfig
      security:
        - api_key: []
        - bearer_auth: []
      responses:
        "200":
          description: Server configuration
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ConfigResponse"
        "401":
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"

  /v1/namespaces:
    get:
      tags: [namespaces]
      summary: List all namespaces
      operationId: listNamespaces
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: pageToken
          in: query
          description: Pagination token
          schema:
            type: string
        - name: pageSize
          in: query
          description: Number of items to return
          schema:
            type: integer
      responses:
        "200":
          description: List of namespaces
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ListNamespacesResponse"
        "401":
          description: Unauthorized
    post:
      tags: [namespaces]
      summary: Create a namespace
      operationId: createNamespace
      security:
        - api_key: []
        - bearer_auth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CreateNamespaceRequest"
      responses:
        "200":
          description: Created namespace
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NamespaceResponse"
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "409":
          description: Namespace already exists

  /v1/namespaces/{namespace}:
    get:
      tags: [namespaces]
      summary: Get namespace metadata
      operationId: getNamespace
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          description: Namespace identifier
          schema:
            type: string
      responses:
        "200":
          description: Namespace metadata
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NamespaceResponse"
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found
    head:
      tags: [namespaces]
      summary: Check if namespace exists
      operationId: namespaceExists
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Namespace exists
        "404":
          description: Namespace not found
    delete:
      tags: [namespaces]
      summary: Delete a namespace
      operationId: deleteNamespace
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Namespace deleted
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found

  /v1/namespaces/{namespace}/properties:
    post:
      tags: [namespaces]
      summary: Update namespace properties
      operationId: updateNamespaceProperties
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/UpdateNamespaceRequest"
      responses:
        "200":
          description: Updated namespace properties
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/UpdateNamespaceResponse"
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found

  /v1/namespaces/{namespace}/tables:
    get:
      tags: [tables]
      summary: List tables in a namespace
      operationId: listTables
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: pageToken
          in: query
          schema:
            type: string
        - name: pageSize
          in: query
          schema:
            type: integer
      responses:
        "200":
          description: List of tables
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ListTablesResponse"
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found
    post:
      tags: [tables]
      summary: Create a table
      operationId: createTable
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CreateTableRequest"
      responses:
        "200":
          description: Created table
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/LoadTableResponse"
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found
        "409":
          description: Table already exists

  /v1/namespaces/{namespace}/tables/{table}:
    get:
      tags: [tables]
      summary: Load table metadata
      operationId: loadTable
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Table metadata
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/LoadTableResponse"
        "401":
          description: Unauthorized
        "404":
          description: Table not found
    head:
      tags: [tables]
      summary: Check if table exists
      operationId: tableExists
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Table exists
        "404":
          description: Table not found
    post:
      tags: [tables]
      summary: Commit table changes
      operationId: commitTable
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CommitTableRequest"
      responses:
        "200":
          description: Updated table metadata
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/CommitTableResponse"
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "404":
          description: Table not found
        "409":
          description: Commit conflict
    delete:
      tags: [tables]
      summary: Delete a table
      operationId: dropTable
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
        - name: purgeRequested
          in: query
          description: Whether to purge underlying data files
          schema:
            type: boolean
      responses:
        "204":
          description: Table deleted
        "401":
          description: Unauthorized
        "404":
          description: Table not found

  /v1/tables/rename:
    post:
      tags: [tables]
      summary: Rename a table
      operationId: renameTable
      security:
        - api_key: []
        - bearer_auth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/RenameTableRequest"
      responses:
        "204":
          description: Table renamed
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "404":
          description: Table not found

  /v1/namespaces/{namespace}/register:
    post:
      tags: [tables]
      summary: Register an existing table from metadata
      operationId: registerTable
      description: Register a table using a metadata file location. The table must not already exist in the catalog.
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/RegisterTableRequest"
      responses:
        "200":
          description: Registered table
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/LoadTableResponse"
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "404":
          description: Namespace not found
        "409":
          description: Table already exists

  /v1/namespaces/{namespace}/tables/{table}/metrics:
    post:
      tags: [tables]
      summary: Report scan or commit metrics
      operationId: reportMetrics
      description: Endpoint for clients to report table scan and commit metrics for telemetry.
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ReportMetricsRequest"
      responses:
        "204":
          description: Metrics accepted
        "401":
          description: Unauthorized
        "404":
          description: Table not found

  /v1/namespaces/{namespace}/tables/{table}/credentials:
    get:
      tags: [tables]
      summary: Load vended credentials for a table
      operationId: loadTableCredentials
      description: |
        Load storage credentials scoped to a specific table's data files.
        Use this endpoint when you need credentials to access table data
        but don't need the full table metadata.
        
        The credentials returned are:
        - Short-lived (typically 1 hour)
        - Scoped to minimum required permissions for the table
        - Specific to the storage location (S3, GCS, Azure)
        
        This endpoint requires credential vending to be configured on the server.
        Returns 406 if credential vending is not supported for the table's storage location.
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: namespace
          in: path
          required: true
          schema:
            type: string
        - name: table
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Vended storage credentials
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/LoadCredentialsResponse"
        "401":
          description: Unauthorized
        "403":
          description: Access denied
        "404":
          description: Table not found
        "406":
          description: Credential vending not supported for this table's storage location

  /v1/transactions/commit:
    post:
      tags: [tables]
      summary: Commit changes to multiple tables atomically
      operationId: commitTransaction
      description: Atomically commit changes to multiple tables. If any commit fails, previously committed changes are rolled back.
      security:
        - api_key: []
        - bearer_auth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/CommitTransactionRequest"
      responses:
        "204":
          description: Transaction committed
        "400":
          description: Invalid request
        "401":
          description: Unauthorized
        "409":
          description: Conflict during commit

  /health:
    get:
      tags: [health]
      summary: Health check
      operationId: health
      responses:
        "200":
          description: Service is healthy
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/HealthResponse"

  /ready:
    get:
      tags: [health]
      summary: Readiness check
      operationId: ready
      responses:
        "200":
          description: Service is ready
        "503":
          description: Service is not ready

  /metrics:
    get:
      tags: [metrics]
      summary: Prometheus metrics
      operationId: metrics
      responses:
        "200":
          description: Prometheus metrics in text format
          content:
            text/plain:
              schema:
                type: string

  /auth/context:
    get:
      tags: [auth]
      summary: Get authentication context
      description: |
        Returns the authenticated principal's identity and capabilities.
        Useful for CLI tools, SDKs, and UIs to understand what operations
        are available to the current user.
      operationId: getAuthContext
      security:
        - api_key: []
        - bearer_auth: []
      responses:
        "200":
          description: Authentication context
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/AuthContextResponse"
        "401":
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"

  /v1/search:
    get:
      tags: [search]
      summary: Search for tables and namespaces
      description: |
        Search for tables and namespaces across the catalog using substring matching.
        Results are filtered based on the authenticated principal's permissions -
        users only see objects they have at least Read access to.
        
        This endpoint is useful for:
        - CLI tools discovering available data
        - Web UIs presenting searchable catalogs
        - Data governance and discovery workflows
      operationId: search
      security:
        - api_key: []
        - bearer_auth: []
      parameters:
        - name: query
          in: query
          description: Search string for substring matching on names. Empty returns all accessible objects.
          schema:
            type: string
            default: ""
        - name: objectType
          in: query
          description: Filter by object type
          schema:
            type: string
            enum: [table, namespace, all]
            default: all
        - name: limit
          in: query
          description: Maximum number of results (1-1000)
          schema:
            type: integer
            minimum: 1
            maximum: 1000
            default: 100
        - name: recursive
          in: query
          description: Include child namespaces in search
          schema:
            type: boolean
            default: true
        - name: namespace
          in: query
          description: Filter to a specific namespace (dot-separated)
          schema:
            type: string
      responses:
        "200":
          description: Search results
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SearchResponse"
        "401":
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ErrorResponse"

components:
  securitySchemes:
    api_key:
      type: apiKey
      in: header
      name: X-API-Key
      description: API key authentication
    bearer_auth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT/OIDC authentication

  schemas:
    ErrorResponse:
      type: object
      properties:
        error:
          type: object
          properties:
            message:
              type: string
            type:
              type: string
            code:
              type: integer

    AuthContextResponse:
      type: object
      description: Authentication context with principal info and capabilities
      required: [principal, capabilities]
      properties:
        principal:
          type: object
          description: Information about the authenticated principal
          required: [id, name, principal_type, tenant_id, roles, auth_method]
          properties:
            id:
              type: string
              description: Unique identifier for the principal
            name:
              type: string
              description: Human-readable display name
            principal_type:
              type: string
              enum: [user, service, api_key, system, anonymous]
              description: Type of principal
            tenant_id:
              type: string
              description: Tenant ID for multi-tenancy isolation
            roles:
              type: array
              items:
                type: string
              description: Roles assigned to this principal
            auth_method:
              type: string
              enum: [api_key, jwt, mtls, basic, internal, none]
              description: Authentication method used
            expires_at:
              type: string
              format: date-time
              description: When the authentication expires (ISO 8601)
        capabilities:
          type: object
          description: Capabilities the principal has for various resource types
          required: [catalog, namespaces, tables, is_admin]
          properties:
            catalog:
              $ref: "#/components/schemas/ActionSet"
            namespaces:
              $ref: "#/components/schemas/ActionSet"
            tables:
              $ref: "#/components/schemas/ActionSet"
            is_admin:
              type: boolean
              description: Whether the principal has admin privileges
        features:
          type: object
          additionalProperties:
            type: boolean
          description: Server-side feature flags

    ActionSet:
      type: object
      description: Set of allowed actions for a resource type
      properties:
        list:
          type: boolean
        read:
          type: boolean
        create:
          type: boolean
        update:
          type: boolean
        delete:
          type: boolean
        manage:
          type: boolean

    SearchResponse:
      type: object
      description: Search results with pagination info
      required: [results, totalCount, hasMore]
      properties:
        results:
          type: array
          items:
            $ref: "#/components/schemas/SearchResult"
        totalCount:
          type: integer
          description: Total matching results (before limit applied)
        hasMore:
          type: boolean
          description: Whether more results exist beyond the limit

    SearchResult:
      type: object
      description: A single search result (table or namespace)
      required: [objectType, qualifiedName, name, namespace]
      properties:
        objectType:
          type: string
          enum: [table, namespace]
          description: Type of the object
        qualifiedName:
          type: string
          description: Fully qualified name (e.g., "production.sales.orders")
        name:
          type: string
          description: Object name (last component)
        namespace:
          type: array
          items:
            type: string
          description: Parent namespace path
        description:
          type: string
          description: Brief description from object properties
        updatedAt:
          type: string
          format: date-time
          description: Last modification timestamp

    ConfigResponse:
      type: object
      properties:
        defaults:
          type: object
          additionalProperties:
            type: string
        overrides:
          type: object
          additionalProperties:
            type: string

    NamespaceResponse:
      type: object
      required: [namespace]
      properties:
        namespace:
          type: array
          items:
            type: string
        properties:
          type: object
          additionalProperties:
            type: string

    ListNamespacesResponse:
      type: object
      required: [namespaces]
      properties:
        namespaces:
          type: array
          items:
            type: array
            items:
              type: string
        next-page-token:
          type: string

    CreateNamespaceRequest:
      type: object
      required: [namespace]
      properties:
        namespace:
          type: array
          items:
            type: string
        properties:
          type: object
          additionalProperties:
            type: string

    UpdateNamespaceRequest:
      type: object
      properties:
        removals:
          type: array
          items:
            type: string
        updates:
          type: object
          additionalProperties:
            type: string

    UpdateNamespaceResponse:
      type: object
      properties:
        updated:
          type: array
          items:
            type: string
        removed:
          type: array
          items:
            type: string
        missing:
          type: array
          items:
            type: string

    ListTablesResponse:
      type: object
      required: [identifiers]
      properties:
        identifiers:
          type: array
          items:
            $ref: "#/components/schemas/TableIdentifier"
        next-page-token:
          type: string

    TableIdentifier:
      type: object
      required: [namespace, name]
      properties:
        namespace:
          type: array
          items:
            type: string
        name:
          type: string

    CreateTableRequest:
      type: object
      required: [name, schema]
      properties:
        name:
          type: string
        schema:
          type: object
          description: Iceberg table schema
        partition-spec:
          type: object
          description: Partition specification
        write-order:
          type: object
          description: Sort order for writes
        location:
          type: string
          description: Custom table location
        properties:
          type: object
          additionalProperties:
            type: string

    LoadTableResponse:
      type: object
      required: [metadata-location, metadata]
      properties:
        metadata-location:
          type: string
        metadata:
          type: object
          description: Full table metadata
        config:
          type: object
          additionalProperties:
            type: string
          description: Storage configuration with credentials
        storage-credentials:
          type: array
          description: Vended storage credentials for table data access
          items:
            $ref: "#/components/schemas/StorageCredential"

    LoadCredentialsResponse:
      type: object
      required: [storage-credentials]
      description: Response containing vended storage credentials for table data access
      properties:
        storage-credentials:
          type: array
          items:
            $ref: "#/components/schemas/StorageCredential"

    StorageCredential:
      type: object
      required: [prefix, config]
      description: |
        A vended storage credential with a prefix indicating where it applies.
        Clients should select the credential with the longest matching prefix.
      properties:
        prefix:
          type: string
          description: Storage location prefix where this credential is valid (e.g., "s3://bucket/prefix/")
        config:
          type: object
          additionalProperties:
            type: string
          description: |
            Configuration map containing the actual credentials.
            For S3: s3.access-key-id, s3.secret-access-key, s3.session-token
            For GCS: gcs.oauth2.token
            For Azure: adls.sas-token.<account>

    CommitTableRequest:
      type: object
      required: [requirements, updates]
      properties:
        requirements:
          type: array
          items:
            type: object
        updates:
          type: array
          items:
            type: object

    CommitTableResponse:
      type: object
      required: [metadata-location, metadata]
      properties:
        metadata-location:
          type: string
        metadata:
          type: object

    RenameTableRequest:
      type: object
      required: [source, destination]
      properties:
        source:
          $ref: "#/components/schemas/TableIdentifier"
        destination:
          $ref: "#/components/schemas/TableIdentifier"

    RegisterTableRequest:
      type: object
      required: [name, metadata-location]
      properties:
        name:
          type: string
          description: Name of the table to register
        metadata-location:
          type: string
          description: Location of the table metadata JSON file

    ReportMetricsRequest:
      type: object
      required: [report-type, table-name, snapshot-id]
      properties:
        report-type:
          type: string
          enum: [scan-report, commit-report]
          description: Type of metrics report
        table-name:
          type: string
          description: Fully qualified table name
        snapshot-id:
          type: integer
          format: int64
          description: Snapshot ID associated with the operation
        sequence-number:
          type: integer
          format: int64
          description: Sequence number (for commit reports)
        operation:
          type: string
          description: Operation type (append, overwrite, etc.)
        filter:
          type: object
          description: Filter expression (for scan reports)
        schema-id:
          type: integer
          description: Schema ID (for scan reports)
        projected-field-ids:
          type: array
          items:
            type: integer
          description: Projected field IDs
        projected-field-names:
          type: array
          items:
            type: string
          description: Projected field names
        metrics:
          type: object
          additionalProperties: true
          description: Metrics data
        metadata:
          type: object
          additionalProperties:
            type: string
          description: Additional metadata

    CommitTransactionRequest:
      type: object
      required: [table-changes]
      properties:
        table-changes:
          type: array
          items:
            $ref: "#/components/schemas/CommitTableRequest"
          description: List of table commits to apply atomically

    HealthResponse:
      type: object
      required: [status]
      properties:
        status:
          type: string
          enum: [healthy, unhealthy]
        components:
          type: object
          additionalProperties:
            type: string
"##;

// ============================================================================
// OpenAPI Spec Structures (for JSON output)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: Info,
    pub servers: Vec<Server>,
    pub tags: Vec<Tag>,
    pub paths: HashMap<String, PathItem>,
    pub components: Components,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub title: String,
    pub version: String,
    pub description: String,
    pub license: License,
    pub contact: Contact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub tags: Vec<String>,
    pub summary: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<Parameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub required: bool,
    pub content: HashMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<HashMap<String, MediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Components {
    #[serde(rename = "securitySchemes")]
    pub security_schemes: HashMap<String, SecurityScheme>,
    pub schemas: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    #[serde(rename = "in", skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(rename = "bearerFormat", skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_json_generation() {
        let json = ApiDoc::json();
        assert!(json.contains("Rustberg"));
        assert!(json.contains("Apache Iceberg"));
    }

    #[test]
    fn test_openapi_yaml_generation() {
        let yaml = ApiDoc::yaml();
        assert!(yaml.contains("Rustberg"));
        assert!(yaml.contains("/v1/namespaces"));
        assert!(yaml.contains("/v1/config"));
        assert!(yaml.contains("api_key"));
        assert!(!yaml.contains("{{VERSION}}")); // Version should be replaced
    }
}
