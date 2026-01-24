---
title: Architecture
layout: default
nav_order: 12
description: "Rustberg system architecture, data flows, and component interactions"
---

# Architecture
{: .no_toc }

Deep dive into Rustberg's internal architecture and design decisions.
{: .fs-6 .fw-300 }

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

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
            Auth[Authentication<br/>JWT/API Key/OAuth2]
        end
        
        subgraph Core["Core Services"]
            Catalog[Catalog Service]
            Policy[Cedar Policy Engine]
            Crypto[Encryption Service]
        end
        
        subgraph Storage["Storage Layer"]
            SlateDB[(SlateDB<br/>Metadata Store)]
            FileIO[FileIO Abstraction]
        end
    end

    subgraph External["External Services"]
        subgraph ObjectStorage["Object Storage"]
            S3[(AWS S3)]
            GCS[(Google GCS)]
            ADLS[(Azure ADLS)]
        end
        
        subgraph KMS["Key Management"]
            AWSKMS[AWS KMS]
            Vault[HashiCorp Vault]
            GCPKMS[GCP Cloud KMS]
            AzureKV[Azure Key Vault]
        end
        
        subgraph Identity["Identity Providers"]
            OIDC[OIDC Provider]
            OAuth[OAuth2 Server]
        end
    end

    Clients --> REST
    REST --> Auth
    Auth --> Policy
    Policy --> Catalog
    Catalog --> SlateDB
    Catalog --> FileIO
    FileIO --> ObjectStorage
    Crypto --> KMS
    Auth --> Identity
    
    classDef clientNode fill:#e1f5fe,stroke:#01579b
    classDef apiNode fill:#fff3e0,stroke:#e65100
    classDef coreNode fill:#f3e5f5,stroke:#7b1fa2
    classDef storageNode fill:#e8f5e9,stroke:#2e7d32
    classDef externalNode fill:#fce4ec,stroke:#c2185b
    
    class Spark,Trino,Flink,PyIceberg,DuckDB clientNode
    class REST,Auth apiNode
    class Catalog,Policy,Crypto coreNode
    class SlateDB,FileIO storageNode
    class S3,GCS,ADLS,AWSKMS,Vault,GCPKMS,AzureKV,OIDC,OAuth externalNode
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
    Rustberg->>Rustberg: Hash with Argon2id
    Rustberg->>Rustberg: Store hash in SlateDB
    Rustberg-->>Admin: API Key (shown once)
    
    Admin->>Client: Distribute API Key
    
    Client->>Rustberg: Request + X-Api-Key header
    Rustberg->>Rustberg: Lookup by key prefix
    Rustberg->>Rustberg: Verify Argon2id hash
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

## Encryption Architecture

### Envelope Encryption

```mermaid
flowchart LR
    subgraph KMS["Key Management Service"]
        MasterKey[Master Key<br/>KEK]
    end
    
    subgraph Rustberg["Rustberg"]
        DEK[Data Encryption Key<br/>AES-256]
        EncDEK[Encrypted DEK]
        Plaintext[Plaintext Data]
        Ciphertext[Encrypted Data]
    end
    
    subgraph Storage["Object Storage"]
        StoredDEK[(Encrypted DEK)]
        StoredData[(Encrypted Data)]
    end
    
    MasterKey -->|Encrypt| DEK
    DEK --> EncDEK
    DEK -->|Encrypt| Plaintext
    Plaintext --> Ciphertext
    EncDEK --> StoredDEK
    Ciphertext --> StoredData
    
    style MasterKey fill:#ffecb3,stroke:#ff6f00
    style DEK fill:#b3e5fc,stroke:#0288d1
```

### Encryption Flow

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant Rustberg
    participant KMS as KMS Provider
    participant Storage as Object Storage

    Note over Client: Write encrypted data
    Client->>Rustberg: Write Table Data
    
    Rustberg->>KMS: GenerateDataKey()
    KMS-->>Rustberg: {plaintext_dek, encrypted_dek}
    
    Rustberg->>Rustberg: Encrypt data with DEK
    Rustberg->>Rustberg: Zero plaintext DEK
    
    Rustberg->>Storage: Store encrypted data
    Rustberg->>Storage: Store encrypted DEK in metadata
    
    Rustberg-->>Client: Success

    Note over Client: Read encrypted data
    Client->>Rustberg: Read Table Data
    
    Rustberg->>Storage: Get encrypted DEK
    Rustberg->>KMS: DecryptDataKey(encrypted_dek)
    KMS-->>Rustberg: plaintext_dek
    
    Rustberg->>Storage: Get encrypted data
    Rustberg->>Rustberg: Decrypt data with DEK
    Rustberg->>Rustberg: Zero plaintext DEK
    
    Rustberg-->>Client: Decrypted data
```

---

## Storage Architecture

### SlateDB for Metadata

```mermaid
graph TB
    subgraph SlateDB["SlateDB (LSM-Tree)"]
        MemTable[MemTable<br/>Write Buffer]
        WAL[Write-Ahead Log]
        L0[Level 0 SST]
        L1[Level 1 SST]
        L2[Level 2 SST]
    end
    
    subgraph ObjectStore["Object Storage"]
        S3Bucket[(S3/GCS/ADLS<br/>SST Files)]
    end
    
    Write[Write] --> MemTable
    MemTable --> WAL
    MemTable -->|Flush| L0
    L0 -->|Compact| L1
    L1 -->|Compact| L2
    L2 --> S3Bucket
    
    Read[Read] --> MemTable
    MemTable -.->|Miss| L0
    L0 -.->|Miss| L1
    L1 -.->|Miss| L2
```

### Table Metadata Structure

```mermaid
graph TD
    subgraph Catalog["Catalog Structure"]
        NS[Namespace<br/>database.schema]
        Table[Table<br/>table_name]
        Metadata[Table Metadata]
    end
    
    subgraph TableMeta["Table Metadata"]
        Schema[Schema<br/>Column definitions]
        Partition[Partition Spec]
        Sort[Sort Order]
        Snapshots[Snapshots<br/>Point-in-time views]
        Properties[Properties<br/>Key-value config]
    end
    
    subgraph Snapshot["Snapshot"]
        Manifest[Manifest List]
        ManifestFile[Manifest Files]
        DataFile[Data Files<br/>Parquet/ORC/Avro]
    end
    
    NS --> Table
    Table --> Metadata
    Metadata --> Schema
    Metadata --> Partition
    Metadata --> Sort
    Metadata --> Snapshots
    Metadata --> Properties
    Snapshots --> Manifest
    Manifest --> ManifestFile
    ManifestFile --> DataFile
```

---

## High Availability

### Multi-Region Deployment

```mermaid
graph TB
    subgraph Region1["Region: us-east-1"]
        LB1[Load Balancer]
        R1A[Rustberg Pod A]
        R1B[Rustberg Pod B]
        S1[(SlateDB<br/>S3 Backend)]
    end
    
    subgraph Region2["Region: eu-west-1"]
        LB2[Load Balancer]
        R2A[Rustberg Pod A]
        R2B[Rustberg Pod B]
        S2[(SlateDB<br/>S3 Backend)]
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
| Metadata Read | 5-20ms | SlateDB cache hit |
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
        Argon2[argon2<br/>Password Hashing]
        AES[aes-gcm<br/>Encryption]
        Cedar[cedar-policy<br/>Authorization]
    end
    
    subgraph Storage["Storage"]
        SlateDB[slatedb<br/>Embedded DB]
        ObjectStore[object_store<br/>S3/GCS/Azure]
    end
    
    subgraph Format["Data Format"]
        Iceberg[iceberg-rust<br/>Table Format]
        Arrow[arrow<br/>Columnar Data]
    end
    
    Axum --> Tower
    Tower --> Tokio
    Axum --> Rustls
    SlateDB --> ObjectStore
    Iceberg --> Arrow
```

---

## Design Decisions

### Why SlateDB?

1. **Cloud-Native**: SST files stored directly in object storage
2. **No Operational Overhead**: No separate database to manage
3. **Cost-Effective**: Pay only for storage, not compute
4. **Durable**: Data survives pod restarts

### Why Cedar?

1. **Expressiveness**: Supports complex ABAC policies
2. **Performance**: Microsecond-level evaluation
3. **Safety**: Formal verification available
4. **Auditability**: Policies are human-readable

### Why Envelope Encryption?

1. **Key Isolation**: Master keys never leave KMS
2. **Performance**: Bulk encryption with local DEK
3. **Rotation**: Rotate master key without re-encrypting data
4. **Compliance**: Meets FIPS 140-2 requirements

---

## Security Layers

```mermaid
graph TB
    subgraph Layers["Defense in Depth"]
        L1[Network Security<br/>TLS 1.3, mTLS]
        L2[Authentication<br/>JWT, API Keys, OAuth2]
        L3[Authorization<br/>Cedar ABAC]
        L4[Data Protection<br/>AES-256-GCM]
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
