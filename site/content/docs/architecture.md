+++
title = "Architecture"
description = "How a request flows through Rustberg: identity, routing, policy, the catalog, credentials, audit."
weight = 2
+++
## System Overview

Rustberg is a modular, layered server.

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

Every request passes the security pipeline before reaching catalog logic.

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
    participant Operator
    participant Rustberg
    participant Client

    Operator->>Operator: rustberg generate-key (secret shown once)
    Operator->>Rustberg: [[server.auth.api_keys]] entry + secret in env, restart
    Note over Rustberg: Hash at startup, keep no plaintext
    Client->>Rustberg: Request + Authorization: Bearer rb_…
    Rustberg->>Rustberg: Look up by prefix, verify hash (constant-time)
    Rustberg-->>Client: Response, as ApiKey::"<name>"
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

The catalog is a *registry*: one metadata-file pointer per table. Everything an
engine reads lives in the warehouse and is fetched directly.

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
2. Write a **new** metadata file with the updates under a fresh name; never
   overwrite the old one.
3. Swap the pointer, conditional on it still holding the value read in step 1.

Step 3 is a compare-and-swap (redb: serializable write transaction; Postgres:
conditional `UPDATE` in a SQL transaction), so lost updates are impossible. A
swap that matches nothing means another writer won; the commit retries with
backoff.

---

## High Availability

### Replicated deployment

```mermaid
graph TB
    LB[Load Balancer] --> R1[Rustberg pod]
    LB --> R2[Rustberg pod]
    LB --> R3[Rustberg pod]
    R1 --> PG[(Postgres catalog)]
    R2 --> PG
    R3 --> PG
    R1 -.-> WH[(Warehouse: S3 / GCS / ADLS)]
    R2 -.-> WH
    R3 -.-> WH
```

Pods are stateless and equal; Postgres holds the catalog and policy revisions.
The embedded redb catalog runs exactly one pod.

---

## Performance Characteristics

Measured figures — authorization overhead, `loadTable`, cold start, memory — and
how they are gated in CI are on [Performance](@/docs/benchmarks.md).

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
    Iceberg --> Arrow
```

---

## Design Decisions

### Why two catalog backends?

- **redb** (embedded): ACID, multi-key, single-file, no C dependencies, so the
  binary cross-compiles statically to musl. No database to run; a commit is a
  local transaction.
- **Postgres** (clustered): redb's exclusive file lock limits it to one process.
  Postgres lets replicas share one registry without leader election or a
  consensus protocol.

### Why a `CatalogStore` trait instead of `iceberg::Catalog`?

Both registries implement Rustberg's own `CatalogStore`, because
`iceberg::Catalog` cannot serve a REST catalog:

- **No server-side commit.** The only commit method is
  `update_table(TableCommit)`; `TableCommit` has private fields and a
  `pub(crate)` builder. Upstream declined to open it (*"users are not supposed to
  build `TableCommit` directly"*) and points to `Transaction`, which derives
  requirements from typed actions. A REST server must apply the
  `(requirements, updates)` it receives verbatim.
- **No views.** The trait has no view methods.
- **No paging.** `list_tables` returns a `Vec` with no cursor, although both
  registries store tables in a sorted index.

Every implementation (`sql`, `rest`, `glue`, `s3tables`) inherits these.
Rustberg still uses the `iceberg` crate for
`TableMetadata`, `Table`, `ViewMetadata`, `FileIO`, `TableRequirement::check`,
`drop_table_data`, and `iceberg-storage-opendal` for cloud object stores. Only
the registry is written here.

Lakekeeper, the closest comparable project, defines its own catalog trait for the
same reasons.

A federated `rest` mount is a read-only `CatalogStore` whose view support is
negotiated from the remote; see [Federation](@/docs/federation.md).

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
| Table Rename | Atomic | One write transaction inserts the destination and removes the source |
| Multi-table Transaction | Atomic | All pointers swap in one write transaction, each version re-verified inside it |

**Optimistic concurrency control:** every commit swaps the metadata pointer
conditionally on the value it read.

- A lost swap is retried internally with jittered backoff.
- A commit whose *requirements* no longer hold returns `409 Conflict` without
  retry.
- Same behaviour on redb and Postgres — see
  [deployment topology](#concurrency-and-deployment-topology).

**Multi-table atomicity:** `commit_tables_atomic` is all-or-nothing across tables
— one redb write transaction, or one SQL transaction with a conditional `UPDATE`
per table. If any pointer moved, the whole transaction rolls back and retries; no
client sees a half-applied transaction.

### Persistence

| Component | Where it lives | Survives a restart? |
|-----------|----------------|---------------------|
| Namespaces | Catalog registry (redb or Postgres) | Yes |
| Tables | Catalog registry + metadata files | Yes |
| Views | Catalog registry + metadata files | Yes |
| Idempotency receipts | Postgres, when the catalog is Postgres; otherwise in memory | With Postgres |
| API keys | Configuration, hashed in memory | **No** — reloaded from config or the environment on every start |

All *catalog metadata* persists.

- **API keys are configuration, not state**: read from a config file or
  mounted secret and hashed at startup; no key store to encrypt, back up, or
  protect. Rotation is a config change; revocation needs a restart. For runtime
  revocation use OIDC, where the identity provider owns token lifetime.
- **Idempotency receipts follow the catalog**: on Postgres, a retry on another
  replica is replayed, not executed twice; redb has only one process.

### Concurrency and deployment topology

Topology follows from the catalog backend.

#### Postgres: many replicas

Replicas are ordinary stateless pods: any number, rolling updates, autoscaling.
There is no leader; correctness comes from the conditional `UPDATE` in step 3 of
the commit protocol. Two replicas committing to one table concurrently both
succeed, one after retrying.

#### redb: exactly one process

redb locks the catalog file exclusively. A second process fails to open it rather
than contending or corrupting:

```text
Failed to open redb catalog: Database already open. Cannot acquire lock.
```

So: `replicas: 1` with `strategy: Recreate`. A rolling update starts the new pod
before the old one exits, and the new pod cannot open the file.

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

For more than one replica, use Postgres.

#### Concurrent commits

Within the process, a redb serializable-snapshot transaction reads and swaps
the registry entry, so a concurrent commit to the same table aborts instead of
overwriting:

- Two requests read version 5 and each build new metadata.
- The first commits; the entry becomes version 6.
- The second loses the swap, re-reads version 6 and re-applies its changes. It
  gets `409 Conflict` only if its requirements no longer hold, or retries run out.

Clients retry `409` with exponential backoff (standard Iceberg contract).

#### Scaling reads

Not on redb: the lock is on the *file*, so a second process cannot open it
read-only either. Scale out with Postgres.

## Security Layers

```mermaid
graph TB
    subgraph Layers["Defense in Depth"]
        L1[Network Security<br/>TLS 1.2/1.3]
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
