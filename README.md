<div align="center">

# Rustberg

**The policy layer for Apache Iceberg.**

One authenticated, policy-controlled Iceberg REST endpoint in front of every
catalog your organisation owns — a single Rust binary, and an embeddable crate.

[Documentation](https://hupe1980.github.io/rustberg) ·
[Getting started](https://hupe1980.github.io/rustberg/docs/getting-started/) ·
[API reference](https://hupe1980.github.io/rustberg/docs/api/) ·
[Security](https://hupe1980.github.io/rustberg/docs/security/)

<img src="https://img.shields.io/badge/tests-904%20%2B%2069%20client-brightgreen" alt="904 Rust tests, 69 client conformance tests">
<img src="https://img.shields.io/badge/unsafe-forbidden-brightgreen" alt="unsafe forbidden">
<img src="https://img.shields.io/badge/binary-~24%20MB-blue" alt="~24 MB binary">
<img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0">

</div>

---

## 🧊 What it is

Engines connect to one endpoint with one identity. Rustberg authenticates the
caller, authorizes every operation against [Cedar](https://www.cedarpolicy.com/)
policy, routes the request to the catalog that actually holds the table, hands
out storage access scoped to what policy allows, and records the decision.

```
   Spark · Trino · DuckDB · PyIceberg · Flink
                    │
                    │  one Iceberg REST endpoint, one identity
                    ▼
        ┌───────────────────────────┐
        │         Rustberg          │
        │  identity → policy →      │
        │  routing → storage →      │
        │  audit                    │
        └───────────────────────────┘
           │         │          │
     ┌─────┘         │          └──────────┐
     ▼               ▼                     ▼
  native          remote REST          AWS Glue
  redb ·        (Polaris · Lakekeeper   Hive · S3 Tables
  Postgres       · Unity · Nessie)       (not built)
```

Storing table pointers is solved. Governing who may read, who may write, and who
gets handed storage access — across catalogs an organisation did not choose to
have in the same place — is not. That is the product.

## 🚀 Quick start

```bash
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-linux-x86_64.tar.gz \
  | tar -xz

./rustberg-linux-x86_64 --dev --insecure-http
```

Authentication is on by default. With nothing configured, Rustberg mints one
admin key and prints it, rather than starting in a state that accepts nobody or
one that accepts everybody:

```text
WARN No API keys or OIDC configured — minted a temporary admin key.
WARN     X-API-Key: rb_sOYl2CxcSLwECS2K8Ri8Y14JgqsBpYydrX7hZqVRxrc
WARN     curl -H 'X-API-Key: rb_sOYl…' http://localhost:8000/v1/config
```

The key lives in memory only, so a restart mints a new one — configure
`[[server.auth.api_keys]]` or OIDC for anything lasting. Then point a client at
it:

```python
from pyiceberg.catalog.rest import RestCatalog

catalog = RestCatalog("rustberg", uri="http://localhost:8000", token="rb_...")
catalog.create_namespace("analytics")
```

Without `--dev`, Rustberg runs in production mode: it requires an explicit
`--catalog-url` and refuses wildcard CORS, so an ephemeral catalog never quietly
ends up holding real metadata.

<details>
<summary><strong>🐳 Docker, Helm, and building from source</strong></summary>

```bash
# Docker — take the key from the startup log
docker run -d -p 8000:8000 --name rustberg \
  -e RUSTBERG_INSECURE_HTTP=true ghcr.io/hupe1980/rustberg:latest
docker logs rustberg 2>&1 | grep X-API-Key

# Helm
helm install rustberg charts/rustberg \
  --set rustberg.storage.type=s3 \
  --set rustberg.storage.s3.bucket=my-catalog-bucket

# From source — Rust 1.94+
cargo build --release --all-features
```

</details>

## 🛡️ Why it exists

**Policy is the product.** Every other subsystem exists to make the policy
decision correct, fast and auditable.

- **Cedar, not a permission table.** Resources form a hierarchy, so one policy
  covers a whole namespace subtree — including tables that do not exist yet.
  Policies are validated at load, so a typo is a startup failure rather than a
  `permit` that silently never matches. Deny by default, including on evaluation
  error.
- **Listings filter, they do not deny.** A caller sees exactly the subset it may
  read and never learns the rest exists. A resource you cannot see is `404`, not
  `403`, so the status code is never an oracle.
- **Storage access only narrows, in two strengths.** Vend a short-lived
  credential scoped to one table prefix — STS session policies, GCS credential
  access boundaries, Azure user-delegation SAS, each a real downscoping exchange.
  Or hand the engine *nothing* and sign every object request, so a revoked grant
  takes effect on the next read rather than at the next expiry.
- **Scan planning that knows the policy.** `planTableScan` conjoins a permit's
  `@row_filter` with the client's own, so a restricted caller is told about fewer
  files. A filter this catalog cannot bind is *widened*, never dropped — pruning
  against a predicate nobody wrote returns too few files.
- **The audit trail is a deliverable.** Every decision names the policy that made
  it and the version of the policy set it came from. When the sink fails,
  mutating requests fail with it.
- **Federation under one identity.** Mount several catalogs — your own, or
  somebody else's Iceberg REST catalog — routed by top-level namespace. The mount
  is invisible on the wire, so a cross-catalog join is ordinary SQL.
- **A binary, or a crate.** `app.as_principal(p)` gives the same operations
  in-process, through the same authorization guard, with no router. The
  equivalence is tested as equivalence.

```cedar
// Analysts read anything under one namespace subtree, and nothing else.
permit(
  principal in Rustberg::Group::"analysts",
  action    in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource  in Rustberg::Namespace::"acme\u{1F}analytics"
);

// A pipeline writes to one namespace, outside business hours only.
permit(
  principal == Rustberg::User::"svc-etl",
  action    in [Rustberg::Action::"Create", Rustberg::Action::"Update"],
  resource  in Rustberg::Namespace::"acme\u{1F}analytics\u{1F}web"
) when { context.utc_hour < 6 || context.utc_hour > 20 };

// Nothing in production is reachable from outside the VPC.
// `context has source_ip` matters: without it, a request whose address is
// unknown would satisfy the exemption and the restriction would not apply.
forbid(
  principal, action,
  resource in Rustberg::Tenant::"prod"
) unless {
  context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
};
```

→ [Authorization](https://hupe1980.github.io/rustberg/docs/authorization/)

## 📦 Deployment shapes

| | Catalog | Replicas | Use it when |
|---|---|---|---|
| **Single binary** | embedded redb file | exactly one — redb takes an exclusive lock | development, CI, edge, single-node production |
| **Replicated** | Postgres | any number, stateless | Kubernetes, or anything that needs to scale out |
| **Embedded** | in-process | n/a | a Rust service that wants policy and storage access with no network hop |

The warehouse is independent of either: local filesystem, S3, GCS or ADLS.

→ [Catalog and warehouse](https://hupe1980.github.io/rustberg/docs/storage/) ·
[Kubernetes](https://hupe1980.github.io/rustberg/docs/kubernetes/) ·
[Library](https://hupe1980.github.io/rustberg/docs/library/)

## 🔌 Engine support

| Engine | Read | Write | Notes |
|---|---|---|---|
| PyIceberg | ✅ | ✅ | |
| Apache Spark | ✅ | ✅ | including atomic `CREATE TABLE AS SELECT` |
| Trino | ✅ | ✅ | |
| DuckDB | ✅ | — | read-only client |

Table format versions **1, 2 and 3** are served; new tables default to v2.

Conformance suites for PyIceberg, DuckDB and Trino run against the built binary
on every change.

→ [Client configuration](https://hupe1980.github.io/rustberg/docs/clients/)

## 🚧 What it does not do

Rustberg declines what it has not built, with a status code — never a silent
partial success.

- **A table under a row filter or column mask is refused a credential and a
  signature** rather than handed prefix-wide access. Planning still applies the
  filter, but a plan is advice: nothing makes an unplanned file unfetchable, so
  this is selection rather than enforcement against a hostile engine.
- **Asynchronous and incremental scan planning** are not implemented. Every plan
  is answered inline, and an incremental scan is declined with `501` rather than
  answered as a full one.
- **Glue, Hive Metastore and S3 Tables** mounts are not built. `native` (redb,
  Postgres) and `rest` are.
- **SQL UDFs** (`…/namespaces/{ns}/functions`) are not built.
- Rustberg **does not issue tokens**. `POST /v1/oauth/tokens` is deprecated in
  the spec, and token issuance belongs to your identity provider —
  `oauth2-server-uri` in the config response points at it.

→ [Known limitations](https://hupe1980.github.io/rustberg/docs/api/#known-limitations)

## ⚡ Measured

Release build, `--all-features`, asserted on every pull request with ceilings
that fail the build.

| | Target | Measured (p99) |
|---|---|---|
| Authorization overhead | < 1 ms for point operations | **31 µs** |
| `loadTable` | < 5 ms native | **370 µs** |
| Cold start to serving | < 100 ms | **45 ms** |
| Idle footprint | < 50 MB RSS | gated on Linux |

→ [Performance](https://hupe1980.github.io/rustberg/docs/benchmarks/)

## 🛠️ Development

```bash
just test          # cargo test --all-features
just lint          # clippy -D warnings, rustfmt
just site          # serve the documentation site (requires zola)
```

`just --list` shows the rest.

## 📄 License

[Apache License 2.0](LICENSE).
