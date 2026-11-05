+++
title = "Authorization"
description = "Cedar policies over a resource hierarchy: path-scoped grants, tenant isolation, row filters and column masks."
weight = 4
+++
## Overview

Rustberg authorizes every request with [Cedar](https://www.cedarpolicy.com/),
evaluating policies against a **principal**, an **action** and a **resource**;
the resource's position in a hierarchy is available to the policy.

- **Default deny** — no `permit` is a denial, and so is a policy that cannot be
  evaluated. See [When a policy cannot be
  evaluated](#when-a-policy-cannot-be-evaluated).
- **Path-scoped** — one policy covers a whole namespace subtree, including
  tables that do not exist yet.
- **Validated at startup** — a policy that does not typecheck against the schema
  is a startup failure.

---

## The resource hierarchy

Resources form a tree. Ancestors are derived by **truncating the identifier**,
with no lookup:

```text
Rustberg::Table::"acme␟analytics␟web␟events"
  in Rustberg::Namespace::"acme␟analytics␟web"
  in Rustberg::Namespace::"acme␟analytics"
  in Rustberg::Tenant::"acme"
```

A policy on `Namespace::"acme␟analytics"` applies to everything beneath it.

The tenant's policy set sits outside that tree, directly under the tenant:

```text
Rustberg::PolicySet::"acme"
  in Rustberg::Tenant::"acme"
```

Policy is a protected resource, so changing the rules is itself governed by the
rules: reading it needs `Read`, changing it needs `Manage`. See
[administering policy](#administering-policy-at-runtime).

### Identifier encoding

Path segments are joined with **`␟`** (unit separator, `U+001F`), never `.`.
Dots are legal in names, so `Namespace::"a.b"` could mean `["a", "b"]` or a
single namespace `"a.b"`, and a policy could match the wrong resource. Name
validation rejects `␟`, so the encoding is unambiguous.

In policies, escape it as `\u{1F}`:

```cedar
resource in Rustberg::Namespace::"acme\u{1F}analytics"
```

---

## Schema

```cedar
namespace Rustberg {
  entity Group;
  // A token's subject, and an API key by its configured name: two kinds, so a
  // token can never be the key that shares its name.
  entity User in [Group] { tenant: String };
  entity ApiKey in [Group] { tenant: String };

  entity Tenant { tenant: String };
  entity Namespace in [Namespace, Tenant] { tenant: String };
  entity Table in [Namespace] { tenant: String };
  entity View in [Namespace] { tenant: String };

  // The tenant's policy set: read with Read, changed with Manage. Policy is a
  // protected resource like any other, or the model is circular.
  entity PolicySet in [Tenant] { tenant: String };

  action Read, List, Create, Update, Delete, Manage
    appliesTo {
      principal: [User, ApiKey],
      resource: [Tenant, Namespace, Table, View, PolicySet],
      context: { utc_hour: Long, source_ip?: ipaddr }
    };
}
```

### Actions

| Action | Covers |
|--------|--------|
| `Read` | Load namespace, table or view metadata; also **grants visibility** — see below |
| `List` | Enumerate the catalog, or the tables and views in a namespace |
| `Create` | Create a namespace, table or view; register a table; the destination of a rename |
| `Update` | Commit to a table, update properties; the source of a rename |
| `Delete` | Drop a namespace, table or view |
| `Manage` | Administrative operations, including **changing the policy set** |

Action names are capitalised and live in the `Rustberg` namespace. A principal's
**roles become Cedar groups**: `Rustberg::Group::"analysts"` matches a principal
carrying the `analysts` role.

`Read` also makes a resource *visible*: it decides whether the resource appears
in a listing and whether a denial is `404` or `403`. See
[Visibility and error codes](#visibility-and-error-codes).

A rename needs `Update` on the source and `Create` on the destination, for
tables and views alike. It does **not** need `Delete`, so the `writer` role below
can rename its own tables.

### Context

| Attribute | Type | Notes |
|-----------|------|-------|
| `utc_hour` | `Long` | Hour of day, 0–23, **always UTC** |
| `source_ip` | `ipaddr` | Address the request came from. **Optional** — see below |

`utc_hour` is UTC, so a policy's meaning does not change with region or daylight
saving.

`source_ip` is absent when there is no connection, e.g. an in-process library
call. Guard on it with `context has source_ip` so the policy fails **closed**
when the address is unknown:

```cedar
// Correct: an unknown address does not satisfy the condition.
permit(
  principal in Rustberg::Group::"analysts",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
) when {
  context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
};
```

On a `forbid ... unless`, a missing guard would exempt every request whose
address is unknown:

```cedar
forbid(
  principal,
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"prod"
) unless {
  context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
};
```

> **The address is only as trustworthy as your proxy configuration.** By default
> Rustberg uses the socket address and ignores `X-Forwarded-For`. Behind a load
> balancer, list its subnet in `[server] trusted_proxies`; the forwarding chain
> is then walked from the right, so a client cannot prepend an address of its
> own choosing. See [Trusted proxies](@/docs/authentication.md#trusted-proxies).

---

## Default policies

Without configuration, Rustberg loads these:

```cedar
// Administrators: everything, within their own tenant.
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

// Readers: read and list only.
permit(
  principal in Rustberg::Group::"reader",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource
) when { resource.tenant == principal.tenant };

// Writers: read, list, create and update. Deleting is deliberately not granted.
permit(
  principal in Rustberg::Group::"writer",
  action in [
    Rustberg::Action::"Read",
    Rustberg::Action::"List",
    Rustberg::Action::"Create",
    Rustberg::Action::"Update"
  ],
  resource
) when { resource.tenant == principal.tenant };
```

Every rule requires the resource to belong to the caller's own tenant: **tenant
isolation is part of the policy**.

---

## Writing policies

### Scope a group to a namespace subtree

```cedar
permit(
  principal in Rustberg::Group::"analysts",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource in Rustberg::Namespace::"acme\u{1F}analytics"
);
```

### Grant one service account one namespace

An API key is the principal `Rustberg::ApiKey::"<name>"`, by its configured
`name`; a token is `Rustberg::User::"<sub>"`, by its subject. They are separate
kinds, so a token with subject `svc-etl` is never the key `svc-etl`:

```cedar
// The key configured as name = "svc-etl"
permit(
  principal == Rustberg::ApiKey::"svc-etl",
  action in [Rustberg::Action::"Create", Rustberg::Action::"Update"],
  resource in Rustberg::Namespace::"acme\u{1F}analytics\u{1F}web"
);

// A workload identity whose token carries sub = "svc-etl@example.com"
permit(
  principal == Rustberg::User::"svc-etl@example.com",
  action in [Rustberg::Action::"Create", Rustberg::Action::"Update"],
  resource in Rustberg::Namespace::"acme\u{1F}analytics\u{1F}web"
);
```

A rule on a group (`principal in Rustberg::Group::"…"`) applies to both kinds.
The console's **You** page shows how a rule names whoever is signed in.

### Carve out an exception

`forbid` always wins over `permit`:

```cedar
permit(
  principal in Rustberg::Group::"analysts",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
);

forbid(
  principal,
  action,
  resource in Rustberg::Namespace::"acme\u{1F}restricted"
);
```

### Condition on time

```cedar
permit(
  principal == Rustberg::ApiKey::"svc-batch",
  action == Rustberg::Action::"Update",
  resource in Rustberg::Namespace::"acme\u{1F}warehouse"
) when { context.utc_hour < 6 || context.utc_hour > 20 };
```

---

## Row filters and column masks

Cedar has no obligations of its own, so a `permit` carries them as annotations:

```cedar
@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
@column_mask("ssn,email")
permit(
  principal in Rustberg::Group::"eu-analysts",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
);
```

### Writing a row filter

`@row_filter` carries an **Iceberg predicate** in the JSON expression grammar a
client sends to [scan planning](@/docs/api.md#scan-planning), so the planner can
apply it. Rustberg implements no SQL dialect.

The annotation is a string, so inner quotes are escaped. The example above is:

```json
{ "type": "eq", "term": "region", "value": "EU" }
```

The accepted grammar is [the one the plan endpoint reads](@/docs/api.md#the-filter):
`and`, `or`, `not`, `is-null`, `not-null`, `is-nan`, `not-nan`, the comparisons,
and `in`/`not-in`.

**Both operand spellings are accepted**: the deprecated `term`/`value`, and
`left`/`right` (comparisons) or `child` (unary and set predicates), where the
operand is a reference carrying a name or a **field id**:

```json
{ "type": "eq",
  "left":  { "type": "reference", "id": 7 },
  "right": { "type": "literal", "value": "EU" } }
```

Prefer field ids in policies. A rename breaks a name reference — Rustberg
refuses rather than dropping the restriction, but reads fail until the policy is
edited — while a field id survives it.

**Checked at startup** (a failure stops startup, like a policy that does not
typecheck) — everything that needs no table:

- the filter is readable JSON and a predicate;
- every operator is in the grammar above (a misspelled `"type": "equals"` is
  refused);
- no term is wrapped in a `transform` or a function application, since it could
  never bind.

A reference **by field id** is accepted at startup; whether the id exists is a
per-table question.

**Checked per table**, since one policy covers tables that do not exist yet:
whether each column exists and each literal fits it. **A policy filter that
cannot be bound to a table selects no rows** — it becomes the constant `false`,
both in the `read-restrictions` a `loadTable` publishes and in the pruning
`planTableScan` performs.

A filter a *client* sends is treated the other way: an unbindable term is
widened away and the plan becomes a superset. That is safe for a request, where
the engine applies its own predicate, but would silently void a policy.

Filters from matching permits are OR-ed, and `false` is the identity of that
union. So a broad permit — `resource in Tenant::"acme"` with a filter on
`region`, where most tables have no `region` — withholds only what it would have
granted on those tables.

### Writing a column mask

`@column_mask` is a comma-separated list of column names, using the full dotted
path for a nested column (`user.ssn`). Entries are trimmed and empty entries
dropped, so a trailing comma is not a column named `""`. A column whose name
contains a comma cannot be masked.

**A mask on a struct covers everything inside it**, including fields added
later: `@column_mask("user")` withholds `user.ssn` and every field beneath
`user`. Matching is on path segments, so a top-level `username` is not covered.

**A mask naming a column the table never had is skipped.** That makes a broad
permit the way to say *"mask `ssn` wherever it appears"*:

```cedar
@column_mask("ssn")
permit(principal in Rustberg::Group::"analysts",
       action == Rustberg::Action::"Read",
       resource in Rustberg::Tenant::"acme");
```

Tables without `ssn` are unaffected.

**A mask naming a column the table *used to have* refuses the request.** If the
column was renamed or dropped, a scan plan and a table load both answer:

```
403 Forbidden
Policy withholds the column 'ssn', which this table had and no longer has — it
was renamed or dropped. The mask now withholds nothing, so the request is refused
rather than served with the restriction quietly missing. Update the policy to the
current name.
```

The table's **schema history** tells the two cases apart.

**Renaming a masked column breaks reads of that table until the policy is
updated.** Change the annotation in the same commit as the rename, or address
the column by field id.

### How they compose

A caller receives the **union of what the matching permits allow**:

| Annotation | Composition | Why |
|------------|-------------|-----|
| `@row_filter` | **OR** | Each permit grants rows; the caller sees all of them |
| `@column_mask` | **AND** (intersection) | A column is withheld only if *every* matching permit withholds it |

If one permit masks `ssn` and another does not, the second **grants** `ssn`, so
it is not masked.

> **An unannotated permit is unrestricted, and voids *both* annotations.** A
> broad `permit(principal in Group::"staff", …)` with neither annotation removes
> every restriction for anyone also in `staff`:
>
> - **Row filters** are OR-ed; unrestricted OR anything is unrestricted.
> - **Column masks** are intersected; a permit withholding nothing intersects
>   every mask down to nothing.
>
> This is the most likely way a deployment accidentally grants everything.

Rustberg reports it twice:

| When | What it reports | Precision |
|---|---|---|
| Policy load | Every permit missing an annotation, **asked once per annotation kind**, when the set also carries that kind | Over-reports — it does not check whether they can ever meet |
| A request | Which permits voided which restriction, `@row_filter` and `@column_mask` alike | Exact — no false positives |

> **"Unannotated" is per restriction, not per permit.**

Both permits below are annotated, but each is unannotated for the **other's**
kind:

```cedar
@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
permit(principal in Rustberg::Group::"analysts",
       action == Rustberg::Action::"Read",
       resource in Rustberg::Tenant::"acme");

@column_mask("ssn")
permit(principal in Rustberg::Group::"analysts",
       action == Rustberg::Action::"Read",
       resource in Rustberg::Tenant::"acme");
```

The first grants every column, the second every row, so the analyst sees every
row and every column. Rustberg names both at load, and again on the first
request that demonstrates it.

Write **one permit carrying both annotations** instead:

```cedar
@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
@column_mask("ssn")
permit(principal in Rustberg::Group::"analysts",
       action == Rustberg::Action::"Read",
       resource in Rustberg::Tenant::"acme");
```

The load-time check does not ask whether the two permits can match the same
request. The [symbolic compiler](https://docs.rs/cedar-policy-symcc) answers that
exactly, with a counterexample, but needs an SMT solver this server does not
carry; run it in your policy pipeline before installing a revision.

The request-time warning needs no analysis: Cedar reports which policies matched
that request.

Both name the offending permits by policy id. The request-time warning is
emitted once per resource per restriction per policy set; editing the policies
reports again.

A worked example of the mask half:

```cedar
// Intended: analysts see everything except ssn.
@column_mask("ssn")
permit(
  principal in Rustberg::Group::"analysts",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
);

// Also grants analysts, and withholds nothing. `ssn` is now visible.
permit(
  principal in Rustberg::Group::"staff",
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"acme"
);
```

An analyst also in `staff` matches both; the intersection of `{ssn}` and `{}` is
`{}`, so no column is withheld. Narrow or annotate the second permit. A `forbid`
would deny the read outright rather than mask one column.

### What an annotation actually does

**It withholds every *broad* form of storage access.** A storage credential is
**prefix-shaped** — the narrowest covers the table's location — and a signature
is table-shaped, so either would let an engine read every row and column.
Rustberg declines both and delegates through the plan, where the scope is exact:

| Request | Result |
|---|---|
| `loadTable` on an annotated table | `200`, metadata returned, **no** `storage-credentials` and no signer configuration; `config` sets `scan-planning-mode: server` |
| `GET .../credentials` on an annotated table | `403`, naming the restriction |
| `POST .../sign` on an annotated table | `403`, naming the restriction |
| `POST .../plan` on an annotated table | `200`, with a **pre-signed URL** per file the filter selected ([details](@/docs/api.md#server-side-planning-and-pre-signed-urls)) |
| `POST .../plan`, `@row_filter` naming a column this table lacks | `200`, selecting **no files** — the same `false` the table's `read-restrictions` publish |
| `POST .../plan`, `@column_mask` over a **partition** column | `403`, naming the column |
| Any of these, on an unannotated table | Access granted normally |

A refusal names masked columns but never quotes a filter expression, which
embeds the values it compares against.

**It prunes the scan plan.** [`planTableScan`](@/docs/api.md#scan-planning)
conjoins a `@row_filter` with the client's filter: a restricted caller is told
about fewer files, and each task's `residual-filter` carries both halves.
`stats-fields` naming a masked column is refused, since bounds are the column's
minimum and maximum values. The match is on the resolved column, ignoring case,
so `case-sensitive: false` does not bypass it.

Every check compares a mask's **full dotted path**: `@column_mask("user.ssn")`
withholds `user.ssn` and leaves an unrelated top-level `ssn` alone.

**A mask over a partition column refuses the plan.** Every file carries its
`partition` tuple, and Iceberg writes partition values into the object key
(`…/region=EU/00000-0-….parquet`), so the plan's `file-path` would leak the value
too. `planTableScan` answers `403` naming the column.

Every transform counts, not only identity (bucket 7 of 16 still narrows the
value), and so does every partition spec the table has had. A mask over any
other column plans normally.

An engine that plans through Rustberg reads only permitted rows. An engine with
its own storage credentials reads the table unfiltered, so the filter is
*selection* rather than enforcement until the two are tied together. See
[security](@/docs/security.md).

### Partition on the security boundary

This decides whether a filter can *ever* be real enforcement.

A catalog enforces a row filter by withholding files. That works only when the
filter's columns are partitioned with an **identity** transform: if `tenant_id`
is an identity partition field, other tenants' rows are in other files, and
withholding them holds against any engine.

Otherwise permitted and forbidden rows share Parquet row groups, and a catalog
can only deliver the file with a residual predicate. Enforcement is then
**cooperative**: it holds only if the engine applies it.

**A transform is not a boundary.** `days(ts)` puts a whole day in one file,
`bucket(16, id)` a sixteenth of all ids, `truncate(4, region)` both `EU` and
`EUROPE`. Pruning helps; enforcement does not follow.

Rustberg warns which case you have:

```text
WARN Row filter references columns this table does not partition on by identity,
     so it cannot be enforced by withholding files — a transformed partition puts
     permitted and forbidden rows in the same file. A scan plan applies the filter
     and returns it as the residual, so a cooperating engine honours it, but an
     engine using its own storage credentials reads the table unfiltered.
     table=analytics.events columns=["email"] policy_set_version=9f2c41ab7d0e5163
```

Columns are read exactly from the JSON predicate. The warning is emitted at most
once per table per policy set; editing the policies reports again.

| Filter | Table partitioned on | Enforceable by withholding files? |
|---|---|---|
| `tenant_id == "acme"` | `identity(tenant_id)` | **Yes** — architectural |
| `region == "EU"` | `identity(region)`, field named `reg` | **Yes** — the *source column* is compared, not the field's name |
| `ts == "2024-01-01T05:00"` | `days(ts)` | No — warned; the day's other rows are in the same file |
| `id == 42` | `bucket(16, id)` | No — warned; a sixteenth of all ids share the file |
| anything | nothing, or another column | No — warned |

The rule is conservative: a range filter whose bounds fall on a transform's
boundaries (`ts >= '2024-01-01' AND ts < '2024-01-02'` against `days(ts)`) *is*
enforceable but is warned about anyway.

---

## Protecting a resource from deletion

`rustberg.protected = "true"` on a table, view or namespace refuses `dropTable`,
`dropView`, `dropNamespace` and a purge with `409` until it is cleared. See
[the API reference](@/docs/api.md#drop-table).

It is an ordinary property: whoever can set it can clear it, so it stops
accidents only. To stop a deliberate delete, add a `forbid`, which the
property's holder cannot edit:

```cedar
forbid(
  principal,
  action == Rustberg::Action::"Delete",
  resource in Rustberg::Namespace::"acme\u{1F}prod"
) unless {
  principal in Rustberg::Group::"platform-admin"
};
```

The two compose: the property catches a mistake before it reaches the
authorizer; the policy catches it when someone means it.

---

## Administering policy at runtime

Policy is a **versioned, append-only log**, changed without restarts. Each change
is a new revision and old ones are never edited, so an audit record's
`policy_set_version` always names something that exists.

| | |
|---|---|
| `GET /management/v1/policies` | The policy set in force |
| `PUT /management/v1/policies` | Replace it, as a new revision |
| `GET /management/v1/policies/history` | Who changed it, when, and why |
| `GET /management/v1/policies/revisions/{sequence}` | One earlier revision, with its source |
| `POST /management/v1/policies/rollback` | Re-apply an earlier revision |

These live under `/management/v1`, not `/v1`, because administration is not part
of the Iceberg API that `GET /v1/config` describes. The
[console](@/docs/console.md) drives the same endpoints, with a diff to review
before every save.

### Changing the rules

```bash
curl -X PUT https://rustberg.example.com/management/v1/policies \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "source": "permit(principal in Rustberg::Group::\"admin\", action, resource) when { resource.tenant == principal.tenant };",
        "note": "revoke contractor access"
      }'
```

The submitted text **replaces** the policy set; nothing is merged.

It takes effect immediately on the receiving replica and within a few seconds on
the others, which poll the store and swap atomically. A request already being
evaluated finishes against the set it started with.

### Two guardrails

**A policy set that does not typecheck is refused** (`400`).

**A policy set that would lock you out is refused** (`400`): one that leaves you
unable to change policy again, recoverable only by a restart against a seed
file. To hand over deliberately, grant someone else `Manage` first.

### What a replica reports

`GET /management/v1/policies` answers for **the replica that received the
request**, which during a rolling change may not be on the newest revision:

```json
{
  "sequence": 7,
  "latest_sequence": 8,
  "version": "9f2c41ab7d0e5163",
  "source": "...",
  "author": "alice"
}
```

| Field | Means |
|---|---|
| `sequence` | The revision this replica is **enforcing** |
| `latest_sequence` | The newest revision in the store |

Equal means converged. A higher `latest_sequence` means this replica has not
caught up: normally for a second or two after a change, indefinitely if it
cannot reach the store.

To check every replica, ask each pod by its own address:

```bash
# Which replicas have converged? The image is distroless — no shell and no curl
# to `kubectl exec` — so ask each pod from outside, by its own address.
for pod in $(kubectl get pods -l app=rustberg -o name); do
  ip=$(kubectl get "$pod" -o jsonpath='{.status.podIP}')
  curl -sf -H "Authorization: Bearer $ADMIN_KEY" \
    "http://$ip:8000/management/v1/policies" \
    | jq -c '{pod: "'"$pod"'", enforcing: .sequence, latest: .latest_sequence}'
done
```

Run it inside the cluster (a debug pod, or `kubectl port-forward` per pod).
Asking the *Service* answers for whichever replica the load balancer picks.

### Sequence and version

| | Means | Changes when |
|---|---|---|
| `sequence` | *When*: revision 7 came after 6 | Every write, including a rollback |
| `version` | *What*: a content hash of the rules | Only when the rules differ |

A rollback appends a **new sequence** carrying an **old version**.

`version` is the string audit records carry, so a decision can be traced to the
exact text that produced it.

### Where policy comes from at startup

`server.auth.policy_file` **seeds an empty store** and is then not
authoritative, so changes made through the API survive a restart. When the two
diverge, startup warns:

```text
WARN The configured policy file differs from the stored policy set, and the
     STORE is authoritative. The file seeds an empty store only. Change policy
     through PUT /management/v1/policies.
```

A file that does not validate refuses to start and is not stored, so correcting
it is enough. A server whose effective policy set contains **no policies**
refuses to start.

Policy administration needs a deployment that evaluates policy *and* stores
revisions; both are automatic for a server Rustberg starts itself. The endpoints
answer `501` when either is missing:

- under `--no-auth`, where no policy is consulted;
- when the library's `with_catalog` supplies a catalog without
  `with_policy_store`. A redb or Postgres catalog implements both, so one object
  can serve as both.

---

## When a policy cannot be evaluated

Startup validation catches a policy that cannot be *typed*, not one that types
fine and raises at evaluation — e.g. `Long` arithmetic that overflows.

Cedar skips such a policy, which fails **open** for a `forbid`. Rustberg instead
denies any request where a policy failed to evaluate. The caller sees `404` or
`403` by the [visibility rule](#visibility-and-error-codes); the server log names
the policy:

```
ERROR A policy failed to evaluate. Cedar skips such a policy, so a forbid that
      errors would not have been applied; denying instead.
      errors=["while evaluating policy `policy1`: integer overflow"]
```

Fix the named policy.

---

## Visibility and error codes

`Read` decides whether a caller can *see* a resource. That drives two behaviours.

### Listings filter

`listNamespaces`, `listTables` and `listViews` return only what the caller may
read, matching what a load would answer.

Filtering happens **before** the page is cut, so a page is never short or empty
while permitted rows remain. It costs one in-memory policy evaluation
(microseconds, no extra I/O) per row *scanned*, not per row returned.

### A denial you cannot see is a 404

A forbidden resource you cannot read answers like a missing one, so status codes
cannot be used to enumerate other tenants' namespaces and tables:

| Caller can read it? | Action permitted? | Answer |
|---|---|---|
| — (does not exist) | — | `404` |
| no | no | `404` |
| yes | no | `403` |
| yes | yes | proceeds |

`404` means *you cannot see this*. `403` only tells a caller something it already
knew.

**A resource named in a query string is guarded too.** `GET
/v1/namespaces?parent=X` goes through the same guard as a path, so a parent in
another tenant is not distinguishable from one that does not exist.

**When debugging, `404` may mean "no `Read` grant".** Check for a missing `Read`
permit before a typo in the name.

**It never means "the backend is down".** An unreachable store is a `5xx`; only
the four rows above produce a `404`, so an intermittent `404` is a real change to
the resource or to policy.

---

## Troubleshooting

**Every request is denied.** No policy matched. Check that the principal's roles
map to the groups your policies name — `GET /auth/context` reports the roles the
credential carries (e.g. `analyst` vs `analysts`).

**A table exists but returns 404.** Most likely no policy permits `Read` on it.
See [Visibility and error codes](#visibility-and-error-codes).

**A policy seems to be ignored.** Check the identifier encoding — segments join
with `\u{1F}`, not `.`. `Namespace::"acme.analytics"` matches a namespace
literally called `acme.analytics`, not the nested one.

**An address-conditioned policy never matches.** Guard with `context has
source_ip`, and set `[server] trusted_proxies` behind a proxy — otherwise the
address is the proxy's.

**No credentials come back for one table.** A matching permit probably carries
`@row_filter` or `@column_mask`; annotated tables are not credentialed. See
[What an annotation actually does](#what-an-annotation-actually-does).

**Startup fails with a validation error.** A policy references an entity type,
action or attribute the schema does not define; such a policy would otherwise
never match.

**Every request to one resource is denied, and the log names a policy that
"failed to evaluate".** The policy typechecks but raises at run time. See
[When a policy cannot be evaluated](#when-a-policy-cannot-be-evaluated).

---

## Related

- [Authentication](@/docs/authentication.md) — how a principal and its roles are established
- [Security](@/docs/security.md) — enforcement boundaries
