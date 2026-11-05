+++
title = "Library"
description = "Using Rustberg as a Rust crate: the catalog, Cedar policy and credential vending in-process, no server."
weight = 14
+++
The catalog, policy engine and credential vending as Rust types: the server's
operations, authorized the same way, with no router.

## Two ways in

```rust
let app = App::builder()
    .with_catalog_url("file:///var/lib/rustberg/catalog.redb")
    .with_warehouse_location("s3://acme/warehouse")
    .with_policies(std::fs::read_to_string("policies.cedar")?)
    .build()
    .await?;
```

From there, either:

| | What you get | When |
|---|---|---|
| `app.as_principal(p)` | A [`Session`](#a-session) — typed Rust, authorized | Your service holds the catalog itself |
| `app.into_router()` | An `axum::Router` | You are serving the Iceberg REST API |

Both are the **same operations over the same authorization guard**, not two
implementations.

---

## A session

A session binds a principal, already authenticated by your identity system, to
the catalog.

```rust
use iceberg::{NamespaceIdent, TableIdent};
use rustberg::auth::Principal;
use rustberg::catalog::session::page;

let principal = Principal::embedded("svc-etl", "acme")
    .with_role("writer")
    .build();

let session = app.as_principal(principal);

let events = TableIdent::new(
    NamespaceIdent::from_vec(vec!["analytics".into(), "web".into()])?,
    "events".into(),
);

let table = session.load_table(&events).await?;
let tables = session.list_tables(events.namespace(), page(100)).await?;
```

### Views, including writing them

Create, load, commit and drop:

```rust
let summary = TableIdent::new(
    NamespaceIdent::from_vec(vec!["analytics".into()])?,
    "summary".into(),
);

let (location, metadata) = session.load_view(&summary).await?;

// Edit the metadata directly — in-process there is no wire format of updates to
// apply, so the host holds a `ViewMetadata` and changes it.
let edited = metadata
    .into_builder()
    .set_properties(std::collections::HashMap::from([
        ("comment".to_string(), "nightly rollup".to_string()),
    ]))?
    .build()?
    .metadata;

session.commit_view(&summary, &location, edited).await?;
```

`commit_view` takes the `location` that `load_view` returned as its
compare-and-swap witness. A stale location answers `409`; reload and re-apply.

### Authentication is yours

Rustberg does not authenticate an in-process caller; your host already has.

`app.into_router()` installs an authenticator for **every mechanism you
configure**, tried in order:

- `with_jwt_config`: OIDC
- `build_with_api_keys`: API keys
- `with_authenticator`: your own

Configuring nothing leaves every caller anonymous and logs a warning at startup.
A configured mechanism that cannot be built (e.g. OIDC without an audience) fails
`build()`.

`tenant` is the **caller's** tenant, never the resource's. Every policy compares
a resource's recorded owner against it, so a wrong value grants cross-tenant
access.

Roles become Cedar groups: `.with_role("writer")` makes
`principal in Rustberg::Group::"writer"` match.

### Policies that read the request context

A policy conditioned on `context.source_ip` **fails closed** in-process (there is
no connection). To let policy see a remote caller's address, forward it:

```rust
let session = app
    .as_principal(principal)
    .with_request_context(RequestContext::from_ip(caller_ip));
```

---

## What a session enforces

Everything the endpoint of the same name enforces:

- **Ownership resolution**: the tenant that owns the namespace decides, never
  the caller's claim.
- **The `404` rule**: a resource you cannot see is "not found", whether or not
  it exists. A `403` only tells you something you already knew.
- **Listing filters**: `list_namespaces`, `list_tables` and `list_views` return
  the subset you may read, filtered before the page is cut.
- **Location confinement**: a `location` passed to `create_table`, or a committed
  `set-location`, is confined to the prefix the table's name puts it in.
- **Cross-tenant rename refusal**: a rename cannot move data between tenants.
- **Audit**: every decision is recorded, permit and deny alike; a mutation whose
  record cannot be written fails.

### Paging

A short page carrying a token is normal and means *keep going*:

```rust
let mut token = None;
loop {
    let request = match &token {
        Some(t) => page_after(t.clone(), 100),
        None => page(100),
    };
    let result = session.list_tables(&namespace, request).await?;
    for ident in &result.items { /* … */ }

    match result.next_page_token {
        Some(next) => token = Some(next),
        None => break,
    }
}
```

Page until the token is **absent**; filtering can empty a page whose successors
still hold matches.

The token is opaque. A token Rustberg did not produce restarts the listing.

---

## What a session deliberately does not do

Four HTTP-only features are absent:

| | Why |
|---|---|
| Idempotency keys | They exist because HTTP retries. A function call does not. |
| Conditional loading (`If-None-Match`) | A wire optimisation. |
| Delegation negotiation | `X-Iceberg-Access-Delegation` is a request header. |
| Storage access | An in-process host reads its own storage; there is nothing to vend or sign. |

### The one real asymmetry

Over HTTP, a table under a `@row_filter` or `@column_mask` is refused storage
access ([invariant 4](@/docs/security.md)). In-process **there is no credential
to withhold**: your host already has its storage access.

The restriction is therefore *reported*, not enforced. A host that reads table
files directly must check it; `row_filters` are Iceberg predicates a host
planning its own scan can conjoin:

```rust
let obligations = session.obligations_for(&events).await?;
if !obligations.is_empty() {
    // Policy attaches a row filter or column mask to this table. Rustberg
    // cannot enforce it here — refuse, or apply it yourself. Each filter is an
    // Iceberg predicate, and they compose as a disjunction.
    for filter in &obligations.row_filters {
        // `serde_json::Value`, in the same grammar `planTableScan` reads.
    }
    return Err(/* … */);
}
```

---

## Serving HTTP as well

Both surfaces can run at once, sharing one catalog, policy set and audit stream:

```rust
let session = app.as_principal(principal);       // in-process work
let router  = app.clone().into_router();          // and the REST API
```

---

## Next Steps

- [Authorization](@/docs/authorization.md) - the policies a session evaluates
- [Federation](@/docs/federation.md) - mounting several catalogs
- [Security](@/docs/security.md) - the invariants, and what they rest on
- [API Reference](@/docs/api.md) - the HTTP surface
