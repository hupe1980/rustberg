+++
title = "Library"
description = "Using Rustberg as a Rust crate: the catalog, Cedar policy and credential vending in-process, no server."
weight = 13
+++
The catalog, the policy engine and credential vending as Rust types — the same
operations the server exposes, authorized the same way, with no router.

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

They are the **same operations over the same authorization guard**, not two
implementations. That matters more than it sounds: a second authorization path
that enforces *almost* the same rules is worse than no second path, because it
looks correct and nothing keeps it honest.

---

## A session

A session binds a principal — one your own identity system has already
authenticated — to the catalog.

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

### Authentication is yours

Rustberg does not authenticate an in-process caller. Your host has already
decided who it is and should not have to attach a JWKS client to say so.

If you also serve `app.into_router()`, that surface *does* need an authenticator,
and one is installed for **every mechanism you configure**: `with_jwt_config` for
OIDC, `build_with_api_keys` for API keys, `with_authenticator` for your own, and
any combination of them tried in order. Configuring nothing leaves every caller
anonymous — legitimate for an embedded host that never serves HTTP, and logged as
a warning at startup so it is never a surprise. A mechanism that is configured but
cannot be built (an OIDC config missing its audience, say) fails the `build()`
rather than being quietly dropped.

`tenant` is the load-bearing argument: every policy compares a resource's
recorded owner against it, so passing the wrong one grants access across a tenant
boundary. It is the **caller's** tenant, never the resource's.

Roles become Cedar groups, so `.with_role("writer")` is what makes
`principal in Rustberg::Group::"writer"` match.

### Policies that read the request context

A policy conditioned on `context.source_ip` **fails closed** in-process, because
there is genuinely no connection behind the call. If your host is itself serving
a remote caller and wants policy to see that caller's address, forward it:

```rust
let session = app
    .as_principal(principal)
    .with_request_context(RequestContext::from_ip(caller_ip));
```

---

## What a session enforces

Everything the endpoint of the same name enforces:

- **Ownership resolution** — the tenant that owns the namespace decides, never
  the caller's own claim about itself.
- **The `404` rule** — a resource you cannot see is "not found", whether or not
  it exists. A `403` only ever tells you something you already knew. This is
  what stops the error code becoming an oracle for enumerating another tenant's
  catalog.
- **Listing filters** — `list_namespaces`, `list_tables` and `list_views` return
  the subset you may read, filtered before the page is cut.
- **Location confinement** — a `location` you supply to `create_table` is
  confined to the warehouse of the namespace it goes in.
- **The cross-tenant rename refusal** — a rename is not a way to move data
  between tenants.
- **Audit** — every decision is recorded, permit and deny alike, and a mutation
  whose record cannot be written fails.

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

Page until the token is **absent**, not until a page looks small. Filtering can
empty a page whose successors still hold matches.

The token is opaque. One that Rustberg did not produce restarts the listing
rather than seeking, so a hand-built token silently repeats work instead of doing
what it looks like it does.

---

## What a session deliberately does not do

Four things exist only because HTTP does, and are absent:

| | Why |
|---|---|
| Idempotency keys | They exist because HTTP retries. A function call does not. |
| Conditional loading (`If-None-Match`) | A wire optimisation. |
| Delegation negotiation | `X-Iceberg-Access-Delegation` is a request header. |
| Storage access | An in-process host reads its own storage; there is nothing to vend or sign. |

### The one real asymmetry

A table under a `@row_filter` or `@column_mask` is refused storage access
over HTTP — that is [invariant 4](@/docs/security.md). In-process **there is
no credential to withhold**, because your host already holds whatever storage
access it has.

So the restriction is *reported* rather than enforced, and a host that reads
table files directly must check it. `row_filters` are Iceberg predicates, so a
host that plans its own scan can conjoin them:

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

This is not an oversight that better API design would close. Rustberg is not in
the data path of a caller that already has the bytes.

---

## Serving HTTP as well

Both surfaces can be live at once — they share one catalog, one policy set and
one audit stream:

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
