+++
title = "Architecture"
description = "How a request flows through Rustberg: identity, routing, policy, the catalog, credentials, audit."
weight = 2
+++
## System Overview

Rustberg is built as a modular, layered architecture designed for security, performance, and extensibility.

```mermaid
graph TB
    subgraph Clients["Data Processing Clients"]
        Spark[Apache Spark]
        Trino[Trino/Presto]
        Flink[Apache Flink]
        PyIceberg[PyIceberg]
        DuckDB[DuckDB]
    end

    subgraph Rustberg["Rustberg Catalog Server"]
        subgraph API["API Layer"]
            REST[REST API<br/>Iceberg REST Spec]
            Auth[Authentication<br/>OIDC/JWT · API key]
        end
        
        subgraph Core["Core Services"]
            Catalog[Catalog Service]
            Policy[Cedar Policy Engine]
            Vend[Storage access<br/>vending · signing]
            Audit[Audit Sink]
        end
        
        subgraph Storage["Storage Layer"]
            redb[(redb<br/>Metadata Store)]
            Postgres[(PostgreSQL<br/>clustered)]
            FileIO[FileIO Abstraction]
        end
    end

    subgraph External["External Services"]
        subgraph ObjectStorage["Object Storage"]
            S3[(AWS S3)]
            GCS[(Google GCS)]
            ADLS[(Azure ADLS)]
        end
        
        
        subgraph Identity["Identity Provider"]
            OIDC[OIDC / JWKS]
        end
    end

    Clients --> REST
    REST --> Auth
    Auth --> Policy
    Policy --> Catalog
    Policy --> Vend
    Policy --> Audit
    Catalog --> redb
    Catalog --> Postgres
    Catalog --> FileIO
    FileIO --> ObjectStorage
    Vend --> ObjectStorage
    Auth --> Identity
    
    classDef clientNode fill:#e1f5fe,stroke:#01579b
    classDef apiNode fill:#fff3e0,stroke:#e65100
    classDef coreNode fill:#f3e5f5,stroke:#7b1fa2
    classDef storageNode fill:#e8f5e9,stroke:#2e7d32
    classDef externalNode fill:#fce4ec,stroke:#c2185b
    
    class Spark,Trino,Flink,PyIceberg,DuckDB clientNode
    class REST,Auth apiNode
    class Catalog,Policy,Vend,Audit coreNode
    class redb,Postgres,FileIO storageNode
    class S3,GCS,ADLS,OIDC externalNode
```

---

## Request Flow

Every request follows a strict security pipeline before reaching the catalog logic.

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant TLS as TLS Termination
    participant RateLimit as Rate Limiter
    participant Auth as Authenticator
    participant Cedar as Policy Engine
    participant Catalog as Catalog Service
    participant Storage as Storage Backend

    Client->>TLS: HTTPS Request
    TLS->>RateLimit: Decrypted Request
    
    alt Rate Limit Exceeded
        RateLimit-->>Client: 429 Too Many Requests
    end
    
    RateLimit->>Auth: Check Credentials
    
    alt Invalid Token/Key
        Auth-->>Client: 401 Unauthorized
    end
    
    Auth->>Cedar: Evaluate Policy
    Note over Cedar: Principal + Action + Resource
    
    alt Policy Denied
        Cedar-->>Client: 403 Forbidden
    end
    
    Cedar->>Catalog: Authorized Request
    Catalog->>Storage: Read/Write Data
    Storage-->>Catalog: Data/Acknowledgment
    Catalog-->>Client: Response
```

---

## Authentication Flow

### JWT/OIDC Authentication

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant Rustberg
    participant OIDC as OIDC Provider

    Note over Client: User logs in via OIDC
    Client->>OIDC: Authentication Request
    OIDC-->>Client: ID Token + Access Token
    
    Client->>Rustberg: API Request + Bearer Token
    Rustberg->>Rustberg: Validate Token Signature
    Rustberg->>Rustberg: Check Token Expiration
    Rustberg->>Rustberg: Extract Claims (sub, groups)
    Rustberg->>Rustberg: Map to Principal
    Rustberg-->>Client: Authorized Response
```

### API Key Authentication

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Rustberg
    participant Client

    Admin->>Rustberg: POST /admin/api-keys
    Note over Rustberg: Generate key pair
    Rustberg->>Rustberg: Hash with SHA-256
    Rustberg->>Rustberg: Store hash in redb
    Rustberg-->>Admin: API Key (shown once)
    
    Admin->>Client: Distribute API Key
    
    Client->>Rustberg: Request + X-Api-Key header
    Rustberg->>Rustberg: Lookup by key prefix
    Rustberg->>Rustberg: Verify hash (constant-time)
    Rustberg-->>Client: Authorized Response
```

---

## Authorization Model

### Cedar Policy Evaluation

```mermaid
flowchart TD
    Request[Incoming Request] --> Extract[Extract Context]
    Extract --> Principal[Build Principal<br/>User/Role/Groups]
    Extract --> Action[Map Action<br/>read/write/manage]
    Extract --> Resource[Build Resource<br/>Namespace/Table]
    
    Principal --> Evaluate{Cedar<br/>Evaluate}
    Action --> Evaluate
    Resource --> Evaluate
    
    Evaluate -->|permit| Allow[✓ Allow Request]
    Evaluate -->|forbid| Deny[✗ Deny Request]
    Evaluate -->|no decision| Default[Default Deny]
    
    Default --> Deny
    
    style Allow fill:#c8e6c9,stroke:#2e7d32
    style Deny fill:#ffcdd2,stroke:#c62828
```

### Policy Structure

```mermaid
graph LR
    subgraph Policy["Cedar Policy Set"]
        P1[Admin Policy<br/>permit all]
        P2[Reader Policy<br/>permit read]
        P3[Writer Policy<br/>permit write]
        P4[Deny Policy<br/>forbid sensitive]
    end
    
    subgraph Evaluation["Evaluation Order"]
        E1[1. Check forbid] --> E2[2. Check permit]
        E2 --> E3[3. Default deny]
    end
    
    P1 --> Evaluation
    P2 --> Evaluation
    P3 --> Evaluation
    P4 --> Evaluation
```

---

## Storage Architecture

### Catalog backends

The catalog is a *registry*: one metadata-file pointer per table. It is
deliberately small, because everything an engine actually reads lives in the
warehouse and is fetched directly.

```mermaid
graph TB
    subgraph Rustberg["Rustberg"]
        API[REST API]
        Registry[Catalog registry]
    end

    subgraph Backends["Registry backends — pick one"]
        Redb[(redb<br/>one local file<br/>one process)]
        Postgres[(PostgreSQL<br/>shared<br/>many replicas)]
    end

    subgraph Warehouse["Warehouse — object storage"]
        Meta[metadata JSON]
        Manifests[manifests]
        Data[data files]
    end

    API --> Registry
    Registry --> Redb
    Registry --> Postgres
    Registry -->|writes pointer targets| Meta
    Engine[Query engine] -->|loadTable| API
    Engine -->|reads directly| Manifests
    Engine -->|reads directly| Data
```

Both backends implement the same commit protocol:

1. Read the current pointer and metadata; check the request's requirements.
2. Apply the updates and write a **new** metadata file under a fresh name —
   never overwriting the old one.
3. Swap the pointer, conditional on it still holding the value read in step 1.

Step 3 is the compare-and-swap that makes lost updates impossible: in redb it is
a serializable write transaction, in Postgres a conditional `UPDATE` inside a
SQL transaction. A swap that matches nothing means another writer got there
first, and the commit retries with backoff.

---

## High Availability

### Multi-Region Deployment

```mermaid
graph TB
    subgraph Region1["Region: us-east-1"]
        LB1[Load Balancer]
        R1A[Rustberg Pod A]
        R1B[Rustberg Pod B]
        S1[(redb<br/>S3 Backend)]
    end
    
    subgraph Region2["Region: eu-west-1"]
        LB2[Load Balancer]
        R2A[Rustberg Pod A]
        R2B[Rustberg Pod B]
        S2[(redb<br/>S3 Backend)]
    end
    
    subgraph GlobalLB["Global Load Balancer"]
        GLB[Route53 / Cloud DNS]
    end
    
    subgraph Replication["Cross-Region Replication"]
        S3Rep[S3 CRR]
    end
    
    GLB --> LB1
    GLB --> LB2
    LB1 --> R1A
    LB1 --> R1B
    LB2 --> R2A
    LB2 --> R2B
    R1A --> S1
    R1B --> S1
    R2A --> S2
    R2B --> S2
    S1 <-->|Replicate| S3Rep
    S3Rep <--> S2
    
    style GLB fill:#fff9c4,stroke:#f57f17
```

---

## Performance Characteristics

### Latency Breakdown

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| Authentication | 1-5ms | JWT validation, API key lookup |
| Policy Evaluation | <1ms | Cedar is extremely fast |
| Metadata Read | 5-20ms | redb cache hit |
| Metadata Write | 10-50ms | Includes WAL sync |
| Table Creation | 50-200ms | Includes storage setup |

### Throughput Estimates

| Deployment | Read QPS | Write QPS | Memory |
|------------|----------|-----------|--------|
| Single Pod | 10,000 | 1,000 | 512MB |
| 3-Pod Cluster | 30,000 | 3,000 | 1.5GB |
| Production HA | 100,000+ | 10,000+ | 8GB+ |

---

## Component Dependencies

```mermaid
graph LR
    subgraph Core["Core Dependencies"]
        Axum[axum<br/>HTTP Framework]
        Tower[tower<br/>Middleware]
        Tokio[tokio<br/>Async Runtime]
    end
    
    subgraph Security["Security"]
        Rustls[rustls<br/>TLS]
        Sha2[sha2<br/>API key hashing]
        Cedar[cedar-policy<br/>Authorization]
    end
    
    subgraph Storage["Storage"]
        redb[redb<br/>Embedded catalog]
        sqlx[sqlx<br/>Postgres catalog]
        Opendal[iceberg-storage-opendal<br/>S3/GCS/ADLS]
    end
    
    subgraph Format["Data Format"]
        Iceberg[iceberg-rust<br/>Table Format]
        Arrow[arrow<br/>Columnar Data]
    end
    
    Axum --> Tower
    Tower --> Tokio
    Axum --> Rustls
    redb --> ObjectStore
    Iceberg --> Arrow
```

---

## Design Decisions

### Why two catalog backends?

**redb** for the embedded case: an ACID, multi-key, single-file database with no
C dependencies, so the binary still cross-compiles statically to musl. No
database to run, and a commit is a local transaction.

**Postgres** for the clustered case: redb takes an exclusive file lock, so it
cannot back more than one process. Postgres lets replicas share one registry
without Rustberg needing leader election or a consensus protocol of its own.

### Why a `CatalogStore` trait instead of `iceberg::Catalog`?

Both registries implement Rustberg's own `CatalogStore`, not `iceberg::Catalog`.
That is deliberate, and it is not a preference:

- **A server cannot commit through `iceberg::Catalog`.** The only commit method is
  `update_table(TableCommit)`, and `TableCommit` has private fields with a
  `pub(crate)` build method. Upstream declined to open it — *"users are not
  supposed to build `TableCommit` directly"* — and directs callers to
  `Transaction`, which derives requirements from typed actions. A REST server is
  handed `(requirements, updates)` verbatim and must apply exactly those, so that
  is the wrong direction.
- **The trait has no views.** Not one view method.
- **The trait cannot page.** `list_tables` returns a `Vec` with no cursor, so a
  backend cannot answer a page even though both registries store tables in a
  sorted index that can.

These are properties of the trait, so no other implementation — `sql`, `rest`,
`glue`, `s3tables` — escapes them. The `iceberg` crate is still used for
everything it does well: `TableMetadata`, `Table`, `ViewMetadata`, `FileIO`,
`TableRequirement::check`, `drop_table_data`, and `iceberg-storage-opendal` for
cloud object stores. Only the registry is written here.

Lakekeeper, the closest comparable project, reached the same conclusion and
defines its own catalog trait for the same reasons.

Federated backends will wrap somebody else's `iceberg::Catalog` *client* behind
`CatalogStore`; such a mount is read-only and reports `views: false`, because the
upstream trait cannot express a commit or a view.

### Why Cedar?

1. **Expressiveness**: Supports complex ABAC policies
2. **Performance**: Microsecond-level evaluation
3. **Safety**: Formal verification available
4. **Auditability**: Policies are human-readable

## Known Limitations

### Concurrency & Atomicity

| Operation | Status | Notes |
|-----------|--------|-------|
| Table Commit | ✅ CAS with version numbers | Returns 409 Conflict on concurrent modification |
| Table Rename | Atomic | One write transaction: the destination is inserted and the source removed together |
| Multi-table Transaction | Atomic | Every pointer swaps in one write transaction, re-verifying each version inside it |

**Optimistic concurrency control:** every commit swaps the metadata pointer
conditionally on the value it read. Rustberg retries a lost swap internally with
jittered backoff; a commit whose *requirements* no longer hold is not retried but
returned as `409 Conflict`, since re-running it would not help. This works the
same whether the registry is redb or Postgres — see
[deployment topology](#concurrency-and-deployment-topology).

**Multi-table atomicity:** `commit_tables_atomic` gives all-or-nothing semantics
across tables — one redb write transaction, or one SQL transaction with a
conditional `UPDATE` per table. If any table's pointer moved underneath, the
whole transaction rolls back and the commit retries, so no client observes a
half-applied transaction.

### Persistence

| Component | Where it lives | Survives a restart? |
|-----------|----------------|---------------------|
| Namespaces | Catalog registry (redb or Postgres) | Yes |
| Tables | Catalog registry + metadata files | Yes |
| Views | Catalog registry + metadata files | Yes |
| Idempotency receipts | Postgres, when the catalog is Postgres; otherwise in memory | With Postgres |
| API keys | Configuration, hashed in memory | **No** — they come from config or the environment on every start |

All *catalog metadata* persists. The rest is deliberate:

- **API keys are configuration, not state.** They arrive from a config file or a
  mounted secret and are hashed at startup, so there is no key store to encrypt,
  back up, or guard with a "who may mint keys" policy. Rotation is a config change.
  The trade is that revocation needs a restart; deployments that need runtime
  revocation use OIDC, where token lifetime belongs to the identity provider.
- **Idempotency receipts follow the catalog.** On Postgres they live in the same
  database, so a retry that lands on another replica is replayed rather than
  executed twice. On redb there is nothing to share: the file takes an exclusive
  lock, so there is only ever one process.

### Concurrency and deployment topology

Deployment topology follows from the catalog backend.

#### Postgres: many replicas

Replicas share one registry, so they are ordinary stateless pods — any number,
rolling updates, autoscaling. There is no leader election because there is no
leader: correctness comes from the conditional `UPDATE` in step 3 of the commit
protocol above. Two replicas committing to the same table concurrently both
succeed, one after retrying.

Idempotency receipts live in the same database, so a retry landing on a
different pod is replayed from the first response rather than executed twice.

#### redb: exactly one process

redb holds an exclusive lock on the catalog file. A second process does not
contend or corrupt — it fails to open the database:

```text
Failed to open redb catalog: Database already open. Cannot acquire lock.
```

That is a clean failure, and it means `replicas: 1` with `strategy: Recreate`.
A rolling update would start the new pod before the old one exits, and the new
pod could not open the file.

```
        ┌─────────────┐            ┌─────────────┐
        │  Rustberg   │            │  Rustberg   │  ✗ cannot start
        │ (replicas:1)│            │             │
        └──────┬──────┘            └──────┬──────┘
               │                          │
          ┌────▼──────────────────────────▼────┐
          │        catalog.redb (locked)       │
          └────────────────────────────────────┘
```

If you need more than one replica, that is what the Postgres backend is for.

#### Concurrent commits

Concurrency *inside* the process is handled properly. Commits run in a redb
serializable-snapshot transaction: the registry entry is read and swapped inside
one transaction, so a concurrent commit that touched the same table aborts rather
than silently overwriting.

- Two requests read version 5 and each build new metadata.
- The first commits; the entry becomes version 6.
- The second's transaction conflicts and is rejected with `409 Conflict`.

Clients should retry `409` with exponential backoff — the standard Iceberg
optimistic-commit contract.

#### Scaling reads

Not on redb. The exclusive lock is on the *file*, not on write access, so a
second process cannot open it read-only either. Scaling out means the Postgres
catalog.

## Security Layers

```mermaid
graph TB
    subgraph Layers["Defense in Depth"]
        L1[Network Security<br/>TLS 1.3]
        L2[Authentication<br/>OIDC/JWT, API keys]
        L3[Authorization<br/>Cedar ABAC]
        L4[Audit logging<br/>Structured events]
        L5[Audit<br/>Structured Logging]
    end
    
    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    
    style L1 fill:#e3f2fd,stroke:#1565c0
    style L2 fill:#e8f5e9,stroke:#2e7d32
    style L3 fill:#fff3e0,stroke:#ef6c00
    style L4 fill:#fce4ec,stroke:#c2185b
    style L5 fill:#f3e5f5,stroke:#7b1fa2
```
