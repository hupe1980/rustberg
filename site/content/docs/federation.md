+++
title = "Federation"
description = "Mount several Iceberg catalogs under one endpoint and one identity, routed by top-level namespace."
weight = 8
+++
One authenticated endpoint in front of every catalog an organisation owns, so an
engine configures one catalog and sees one namespace tree.

## What it is for

Storing table pointers is solved. Governing who may read, who may write, and who
gets handed credentials — across catalogs an organisation did not choose to have
in the same place — is not.

A **mount** claims one top-level namespace and resolves it to a backend:

```
prod.analytics.events    →  mount "prod"     →  namespace analytics.events
partner.shared.orders    →  mount "partner"  →  namespace shared.orders
scratch.tmp              →  unmounted        →  the catalog in storage.catalog_url
```

Because the mount is invisible in the wire protocol, a cross-catalog query is
ordinary SQL — the engine does the join, and Rustberg makes both tables
addressable and both sets of credentials vendable under one identity:

```sql
SELECT *
FROM   prod.sales.orders o
JOIN   analytics.web.events e ON e.order_id = o.id
```

---

## Configuring a mount

Mounts are `[mount.<name>]` tables in the config file. The full key reference is
in [configuration](@/docs/configuration.md#federation); this is the shape:

```toml
[mount.prod]
backend            = "native"
catalog_url        = "postgres://user:pw@host/prod"
warehouse_location = "s3://prod-bucket/warehouse"
owner              = "acme"

[mount.partner]
backend     = "rest"
catalog_url = "https://catalog.partner.example"
owner       = "acme"
token_env   = "RUSTBERG_PARTNER_TOKEN"
read_only   = true
```

| Backend | What it mounts | Writes |
|---|---|---|
| `native` | Another Rustberg catalog — a redb file or a Postgres database | Yes |
| `rest` | Somebody else's Iceberg REST catalog | No, read-only |

**Mounting is additive.** Names no mount claims still reach the catalog
underneath, so adding a mount does not require moving anything.

**The mount name is stripped on the way down and restored on the way up.** A
mounted catalog has its own namespaces and has never heard of the name it is
mounted under; passing the name through would ask it for a namespace that does
not exist there.

---

## A mount declares its tenant

`owner` is **authoritative for the whole mount**, not a default.

Every namespace in the native catalog records the tenant that owns it, and
[authorization](@/docs/authorization.md) resolves that owner before it
decides anything. A mounted catalog cannot participate in that: its namespaces
are not Rustberg's and carry no ownership property. Since a namespace with no
recorded owner is invisible to everybody, reading ownership from a mount would
turn a working mount into an empty one.

Treating the backend's own properties as authoritative would be worse: whoever
can write to that catalog could then decide who owns it here. So the mount
declares it, and one mount means one tenant.

---

## What the mount table refuses

### A mount may not shadow an existing namespace

Routing sends every request for a mount's top-level name to that mount. If the
catalog underneath already holds a namespace of the same name, that namespace
becomes unreachable — listable but never loadable, with everything beneath it
gone.

Rustberg **refuses to start**, naming the mount and what it would hide. A subtree
that silently does not exist is worse than a server that does not come up. The
same rule applies to a mount that cannot be opened at all.

### Renames and transactions may not cross a mount

Atomicity is a property of one backend's transaction, and there is no protocol
between two of them. Rustberg could sequence the operations and would usually get
away with it; it would also, sometimes, leave a table dropped from one catalog
and never created in the other.

`renameTable` and `commitTransaction` across two mounts — or between a mount and
the catalog underneath — return **`501`** naming both sides.

---

## Capability negotiation

Backends differ, so each mount states what it supports and `GET /v1/config`
publishes the **intersection**:

```json
{
  "endpoints": [
    "GET /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}"
  ]
}
```

The union would be wrong. `endpoints` is one list describing one catalog, a
client feature-detects from it once at startup and then assumes, and an entry
that fails on some namespaces is worse than an absent one.

One read-only mount therefore removes every mutating endpoint from the
advertised list. Those operations **still work** on the mounts that support them
— the refusal is per-request, and what the intersection governs is only what is
*promised*. An unsupported operation is refused with `501` naming the mount
responsible.

For a `rest` mount, capabilities are negotiated from the remote catalog's own
`/v1/config` rather than assumed. One is decided here rather than there:
[scan planning](@/docs/api.md#scan-planning) reads a snapshot's manifests through
this server's own storage layer, and a mounted catalog's manifests are in storage
this server does not manage — so a `rest` mount reports it cannot plan, and one
such mount removes `/plan` from the advertised list.

---

## Listing the root

The top level of the tree is the union of two sources: the mount names, which are
configuration, and the top-level namespaces of the catalog underneath, which are
paged out of a sorted index.

Paging spans both. A page token carries which of the two it belongs to, because
the two cursor spaces are unrelated — handing a mount name to the catalog as a
cursor would make it seek to a position that means nothing there and skip rows
silently. A token that did not come from Rustberg restarts the listing rather
than seeking: repetition is visible to a client, and a wrong seek is not.

As everywhere else, listing **filters** rather than denies — a caller sees the
subset it may read and never learns the rest exists.

### Paging inside a `rest` mount

The same rule applies one level down, and it is the reason a remote mount does
not simply forward the remote's page token.

A Rustberg cursor names a position **after one item**, because the authorization
filter stops the moment a page is full and that is usually part-way through a
backend page. A remote catalog's `pageToken` names the start of a **page** and
nothing finer — there is no token meaning "after the third of these ten".

So a cursor inside a `rest` mount is the pair *(the token that fetched this page,
how far into it we are)*. Resuming re-fetches that page and drops the rows already
served, which is exact under the same stability assumption every page token makes.
The re-fetch is paid only when a page genuinely fills mid-batch: the last item of
a remote page is named by the remote's *next* token instead, so an unfiltered walk
through a mount is still one round trip per page.

None of this is visible to a client — the token stays opaque — but it is why a
mount's tokens are not the remote's tokens, and why a token from one cannot be
handed to the other.

### A mount root holds namespaces, not tables

`prod` is a synthetic namespace: it exists so that the mount is loadable,
listable and ownable, but the catalog behind it has no namespace of its own at
that level. `listTables` and `listViews` on a mount root therefore return an
**empty page**, and a table named directly under one — `prod.orders` with no
namespace between — is refused, saying so.

---

## Reachability

A mount sits on the request path of everything beneath it, so its failures are
bounded and reported as failures:

- **Connect and request timeouts** are enforced per call, well inside the
  server's own request timeout, so a remote that accepts a connection and then
  stops answering surfaces as an error naming the mount rather than as a timeout
  naming nothing.
- **An error is never reported as an absence.** Only a `404` from the remote
  means "not there". A connection failure, a `5xx`, or a rejected mount
  credential propagates as an error. Reporting those as "not found" would make a
  `HEAD` say a table had been deleted while it sat untouched — and, because
  ownership resolution runs before every authorization decision, would make a
  whole mount answer `404` to callers whose grants were intact.
- **`/ready` stays ready.** An unreachable mount is named in the health response
  but does not make the server unready: the namespaces that still work should
  keep working.

---

## Storage and credentials

**Each mount governs its own warehouse.** A client-supplied table or view
location is confined to the warehouse of the mount it is being created in, not to
the server's. Under federation "the warehouse" is not one place, and checking
every location against the server's own would reject every table in every mount
that stores data elsewhere.

**Credential vending covers every mount.** The prefixes a provider may vend for
default to every warehouse the server manages — its own and each mount's — so a
table in a mount gets credentials like any other. Getting this wrong is quiet
rather than loud: a refused vend is not an error, so `loadTable` still returns
`200` and the client receives metadata it has no way to read.

**A `rest` mount contributes no warehouse**, which is the correct asymmetry.
Rustberg does not own a remote catalog's storage and has no business minting
credentials for it.

---

## What is not built

| Backend | Status |
|---|---|
| `native` (redb, Postgres) | Shipping |
| `rest` (Polaris, Lakekeeper, Unity, Nessie) | Shipping, read-only |
| `glue` (AWS Glue) | Not built — needs the AWS SDK |
| `hms` (Hive Metastore) | Not built — needs a Thrift client |
| `s3tables` (S3 Tables) | Not built — needs the AWS SDK |

Read-only on `rest` is a deliberate boundary rather than a limitation of the
approach. Proxying a commit would be straightforward — requirements and updates
forwarded verbatim — but a write landing in a catalog Rustberg does not own is a
different promise from one it does.

---

## Next Steps

- [Configuration](@/docs/configuration.md#federation) - every mount key
- [Authorization](@/docs/authorization.md) - how ownership decides access
- [Storage](@/docs/storage.md) - catalog versus warehouse
- [API Reference](@/docs/api.md) - what `/v1/config` advertises
