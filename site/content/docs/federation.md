+++
title = "Federation"
description = "Mount several Iceberg catalogs under one endpoint and one identity, routed by top-level namespace."
weight = 8
+++
Mount other catalogs behind Rustberg's own, so an engine configures one catalog
and sees one namespace tree, governed by one identity.

## What it is for

A **mount** claims one top-level namespace and resolves it to a backend:

```
prod.analytics.events    →  mount "prod"     →  namespace analytics.events
partner.shared.orders    →  mount "partner"  →  namespace shared.orders
scratch.tmp              →  unmounted        →  the catalog in storage.catalog_url
```

Mounts are invisible in the wire protocol, so a cross-catalog query is ordinary
SQL. The engine does the join; Rustberg makes both tables addressable and vends
credentials for both under one identity:

```sql
SELECT *
FROM   prod.sales.orders o
JOIN   analytics.web.events e ON e.order_id = o.id
```

---

## Configuring a mount

Mounts are `[mount.<name>]` tables in the config file (full key reference:
[configuration](@/docs/configuration.md#federation)):

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

- **Mounting is additive.** Names no mount claims still reach the catalog
  underneath; nothing has to move.
- **The mount name is stripped on the way down and restored on the way up.** The
  mounted catalog never sees the name it is mounted under.

---

## A mount declares its tenant

`owner` is **authoritative for the whole mount**, not a default: one mount, one
tenant.

[Authorization](@/docs/authorization.md) resolves a namespace's owning tenant
before every decision. A mounted catalog's namespaces carry no Rustberg
ownership property, and the backend's own properties are not trusted (whoever
can write that catalog would otherwise decide ownership here).

---

## What the mount table refuses

### A mount may not shadow an existing namespace

If the catalog underneath already holds a namespace with the mount's name, the
mount would make it unreachable. Rustberg **refuses to start**, naming the mount
and what it would hide. It also refuses to start if a mount cannot be opened.

### Renames and transactions may not cross a mount

Atomicity holds only within one backend. `renameTable` and `commitTransaction`
across two mounts, or between a mount and the catalog underneath, return
**`501`** naming both sides.

---

## Capability negotiation

Each mount states what it supports; `GET /v1/config` publishes the
**intersection**:

```json
{
  "endpoints": [
    "GET /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}"
  ]
}
```

Clients feature-detect from `endpoints` once, so it lists only what every
namespace supports.

- One read-only mount removes every mutating endpoint from the advertised list.
  Those operations **still work** on mounts that support them; refusal is
  per-request, with `501` naming the responsible mount.
- A `rest` mount's capabilities are negotiated from the remote's own
  `/v1/config`.
- A `rest` mount cannot [plan scans](@/docs/api.md#scan-planning): its manifests
  live in storage this server does not manage. One such mount removes `/plan`
  from the advertised list.
- A `read_only` **native** mount keeps planning.
- Planning still works on native tables beside a `rest` mount: `POST …/plan`
  succeeds under `analytics.` and answers `501` under `partner.`, while
  `/v1/config` advertises neither.

---

## Listing the root

The top level is the union of the mount names (configuration) and the top-level
namespaces of the catalog underneath.

- Paging spans both; a page token records which source it belongs to.
- A token that did not come from Rustberg restarts the listing rather than
  seeking.
- Listing **filters** rather than denies: a caller sees only what it may read.

### Paging inside a `rest` mount

A remote mount does not forward the remote's page token. A Rustberg cursor names
a position **after one item**; a remote `pageToken` names only the start of a
**page**.

- A cursor inside a `rest` mount is the pair *(token that fetched this page,
  offset into it)*. Resuming re-fetches the page and drops rows already served.
- The re-fetch happens only when a page fills mid-batch; an unfiltered walk is
  one round trip per remote page.
- Tokens stay opaque. A mount's tokens are not the remote's, and cannot be
  exchanged.

### A mount root holds namespaces, not tables

`prod` is a synthetic namespace (loadable, listable, ownable) with nothing behind
it at that level. `listTables` and `listViews` on a mount root return an **empty
page**; a table directly under one (`prod.orders`) is refused with an explicit
error.

---

## Reachability

Mount failures are bounded and reported as failures:

- **Connect and request timeouts** are enforced per call, well inside the
  server's request timeout; a hung remote surfaces as an error naming the mount.
- **An error is never reported as an absence.** Only a remote `404` means "not
  there". Connection failures, `5xx` and rejected mount credentials propagate as
  errors.
- **`/ready` stays ready.** An unreachable mount is named in the health response
  but does not make the server unready.

---

## Storage and credentials

- **Each mount governs its own warehouse.** A client-supplied table or view
  location is confined to the warehouse of the mount it is created in.
- **Credential vending covers every mount.** Vendable prefixes default to every
  warehouse the server manages, its own and each mount's. A refused vend is not
  an error: `loadTable` still returns `200`, with metadata the client cannot
  read.
- **A `rest` mount contributes no warehouse.** Rustberg does not mint credentials
  for a remote catalog's storage.

---

## What is not built

| Backend | Status |
|---|---|
| `native` (redb, Postgres) | Shipping |
| `rest` (Polaris, Lakekeeper, Unity, Nessie) | Shipping, read-only |
| `glue` (AWS Glue) | Not built — needs the AWS SDK |
| `hms` (Hive Metastore) | Not built — needs a Thrift client |
| `s3tables` (S3 Tables) | Not built — needs the AWS SDK |

Read-only on `rest` is deliberate: Rustberg does not write into catalogs it does
not own.

---

## Next Steps

- [Configuration](@/docs/configuration.md#federation) - every mount key
- [Authorization](@/docs/authorization.md) - how ownership decides access
- [Storage](@/docs/storage.md) - catalog versus warehouse
- [API Reference](@/docs/api.md) - what `/v1/config` advertises
