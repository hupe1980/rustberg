+++
title = "Authorization"
description = "Cedar policies over a resource hierarchy: path-scoped grants, tenant isolation, row filters and column masks."
weight = 4
+++
## Overview

Rustberg authorizes every request with [Cedar](https://www.cedarpolicy.com/).
Cedar is a policy engine rather than a permission table: a decision comes from
evaluating policies against a **principal**, an **action** and a **resource**,
with the resource's position in a hierarchy available to the policy.

- **Default deny** — absence of a `permit` is a denial, including on evaluation
  error.
- **Path-scoped** — one policy covers a whole namespace subtree, including
  tables that do not exist yet.
- **Validated at startup** — a policy that does not typecheck against the schema
  is a startup failure, not a rule that silently never matches.

---

## The resource hierarchy

This is the part that matters. Resources form a tree, and ancestors are derived
by **truncating the identifier**, so no lookup is needed to know where a resource
sits:

```text
Rustberg::Table::"acme␟analytics␟web␟events"
  in Rustberg::Namespace::"acme␟analytics␟web"
  in Rustberg::Namespace::"acme␟analytics"
  in Rustberg::Tenant::"acme"
```

A policy on `Namespace::"acme␟analytics"` therefore applies to everything beneath
it.

One resource sits outside that tree, directly under the tenant:

```text
Rustberg::PolicySet::"acme"
  in Rustberg::Tenant::"acme"
```

That is the tenant's own policy set. Policy is a protected resource like any
other, or the model is circular — whoever can write policy can grant themselves
anything, so "may you change the rules" has to be one of the rules. Reading it
needs `Read`; changing it needs `Manage`. See
[administering policy](#administering-policy-at-runtime).

### Identifier encoding

Path segments are joined with **`␟`** (unit separator, `U+001F`), never `.`.

Dots are legal in namespace and table names, so a dotted identifier would be
ambiguous: `Namespace::"a.b"` could denote the namespace `["a", "b"]` or a single
namespace named `"a.b"`. In authorization, that ambiguity is a vulnerability — a
policy written for one resource would silently match another. Name validation
rejects `␟`, so the encoding is unambiguous.

When writing policies, escape it as `\u{1F}`:

```cedar
resource in Rustberg::Namespace::"acme\u{1F}analytics"
```

---

## Schema

```cedar
namespace Rustberg {
  entity Group;
  entity User in [Group] { tenant: String };

  entity Tenant { tenant: String };
  entity Namespace in [Namespace, Tenant] { tenant: String };
  entity Table in [Namespace] { tenant: String };
  entity View in [Namespace] { tenant: String };

  // The tenant's policy set: read with Read, changed with Manage. Policy is a
  // protected resource like any other, or the model is circular.
  entity PolicySet in [Tenant] { tenant: String };

  action Read, List, Create, Update, Delete, Manage
    appliesTo {
      principal: User,
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
**roles become Cedar groups**, so `Rustberg::Group::"analysts"` matches a
principal carrying the `analysts` role.

`Read` does double duty: besides permitting a metadata load it is what makes a
resource *visible*, which determines both whether it appears in a listing and
whether a denial reports `404` or `403`. See
[Visibility and error codes](#visibility-and-error-codes).

A rename needs `Update` on the source and `Create` on the destination — for
tables and views alike. It deliberately does **not** need `Delete`: the object is
moved, not destroyed, so the `writer` role below can rename its own tables.

### Context

| Attribute | Type | Notes |
|-----------|------|-------|
| `utc_hour` | `Long` | Hour of day, 0–23, **always UTC** |
| `source_ip` | `ipaddr` | Address the request came from. **Optional** — see below |

Time is UTC so a policy meaning "outside business hours" does not change meaning
when a replica moves region or a zone shifts for daylight saving.

`source_ip` is optional because there is not always an address: the library can be
called in-process, where no connection exists. Guard on it with `context has
source_ip` so the policy fails **closed** when the address is unknown:

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

The same guard matters even more on a `forbid ... unless`, where forgetting it
would exempt every request whose address is unknown:

```cedar
forbid(
  principal,
  action == Rustberg::Action::"Read",
  resource in Rustberg::Tenant::"prod"
) unless {
  context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
};
```

> **The address is only as trustworthy as your proxy configuration.** Rustberg
> uses the connected socket address unless `trust_proxy_headers` is enabled, in
> which case `X-Forwarded-For` is believed. Enable it only behind a proxy that
> overwrites that header, or a caller can spoof its way past an address-scoped
> policy.

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

Every rule is conditioned on the resource belonging to the caller's own tenant,
so **tenant isolation is part of the policy** rather than a separate layer that
has to be remembered.

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

```cedar
permit(
  principal == Rustberg::User::"svc-etl",
  action in [Rustberg::Action::"Create", Rustberg::Action::"Update"],
  resource in Rustberg::Namespace::"acme\u{1F}analytics\u{1F}web"
);
```

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
  principal == Rustberg::User::"svc-batch",
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

`@row_filter` carries an **Iceberg predicate**, in the same JSON expression
grammar a client sends to [scan planning](@/docs/api.md#scan-planning). That is
what lets the planner *apply* it rather than merely report it — a SQL string
could not be, because Rustberg does not implement a SQL dialect and a parser
that mis-modelled a predicate would be worse than one that never looked.

A Cedar annotation is a string, so the quotes inside are escaped. The example
above is this predicate:

```json
{ "type": "eq", "term": "region", "value": "EU" }
```

The accepted grammar is [the same one the plan endpoint reads](@/docs/api.md#the-filter):
`and`, `or`, `not`, `is-null`, `not-null`, `is-nan`, `not-nan`, the comparisons,
and `in`/`not-in`.

A filter that is not readable JSON, or not a predicate, is a **startup failure** —
the same answer a policy that does not typecheck gets, and for the same reason: a
restriction that silently does not apply is worse than one that refuses to
install.

### How they compose

A caller receives the **union of what the matching permits allow**, so the two
annotations compose in opposite directions:

| Annotation | Composition | Why |
|------------|-------------|-----|
| `@row_filter` | **OR** | Each permit grants rows; the caller sees all of them |
| `@column_mask` | **AND** (intersection) | A column is withheld only if *every* matching permit withholds it |

If one permit masks `ssn` and another does not, the second permit **grants**
`ssn` — so it is not masked. Unioning masks would withhold a column the caller
was granted.

> **An unannotated permit is unrestricted — and it voids *both* annotations.**
> A broad `permit(principal in Group::"staff", …)` carrying neither annotation
> removes every restriction for anyone who is also in `staff`. The two get there
> by opposite routes:
>
> - **Row filters** are OR-ed, and unrestricted OR anything is unrestricted.
> - **Column masks** are intersected, and a permit that withholds no column
>   intersects every mask down to nothing.
>
> Both are correct, and together they are the most likely way a deployment
> accidentally grants everything.

Because nothing looks wrong in the policy file when that happens, Rustberg says
so twice:

| When | What it reports | Precision |
|---|---|---|
| Policy load | Every unannotated permit, when the set also has annotated ones | Over-reports — it does not check whether they can ever meet |
| A request | Which permits voided which restriction, `@row_filter` and `@column_mask` alike | Exact — no false positives |

The load-time check is deliberately crude. Deciding whether two Cedar policies can
ever match the same request is undecidable in general, and an approximate warning
is one operators learn to ignore. The request-time one needs no analysis at all:
Cedar has already reported which policies matched *that* request, so if one
carried an annotation and another did not, the restriction was voided — as a fact.

Both name the offending permits by policy id. The request-time warning is emitted
once per resource per restriction per policy set; editing the policies reports
again, since the thing being warned about has changed.

A worked example of the mask half, which is the quieter one:

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

An analyst who is also in `staff` matches both, the intersection of `{ssn}` and
`{}` is `{}`, and no column is withheld. The fix is to narrow the second permit,
or to annotate it — not to add a `forbid`, which would deny the read outright
rather than mask one column.

### What an annotation actually does

Two things, and they are worth separating.

**It makes the table undelegatable.** Rustberg grants it no storage access at
all. A storage credential is **prefix-shaped** — the narrowest one Rustberg can
mint covers the table's location — so an engine holding it reads every row and
every column under that prefix whatever the policy says. A signature is
table-shaped for the same reason. Given the choice between granting one while
calling the filter enforced, and declining, Rustberg declines:

| Request | Result |
|---|---|
| `loadTable` on an annotated table | `200`, metadata returned, **no** `storage-credentials` and no signer configuration |
| `GET .../credentials` on an annotated table | `403`, naming the restriction |
| `POST .../sign` on an annotated table | `403`, naming the restriction |
| Any of these, on an unannotated table | Access granted normally |

The refusal names masked columns but never quotes a filter expression — a filter
embeds the values it compares against, and echoing it to a caller that was just
refused would leak the policy's contents.

**It prunes the scan plan.** A `@row_filter` is an Iceberg predicate, so
[`planTableScan`](@/docs/api.md#scan-planning) conjoins it with the client's own
filter: a restricted caller is told about fewer files, and the `residual-filter`
on each task carries both halves. `stats-fields` naming a masked column is
refused, because column bounds are the column's minimum and maximum values.

So an engine that plans through Rustberg reads only permitted rows. An engine
carrying its own storage credentials reads the table unfiltered, and nothing here
changes that — which is why the filter is *selection* rather than enforcement
until the two are tied together. See [security](@/docs/security.md).

### Partition on the security boundary

This is the most important practical guidance on this page, and it decides
whether a filter can *ever* become real enforcement.

A catalog enforces a row filter by not handing over files. That works exactly
when the filter's columns are **partition columns**: if `tenant_id` is a
partition field, another tenant's rows live in different files, and withholding
those files is enforcement that holds against any engine — hostile or not.

When the filter references a non-partition column, permitted and forbidden rows
share Parquet row groups. No file-level decision can separate them, and the best
any catalog can do is deliver the file and a residual predicate. Enforcement is
then **cooperative**: it holds only because the engine chose to apply it. AWS
Lake Formation is explicit about the same limit.

Both look identical in the policy file, so Rustberg tells you which you have:

```text
WARN Row filter references non-partition columns, so it cannot be enforced by
     withholding files. A scan plan applies it and returns it as the residual,
     so a cooperating engine honours it — but an engine using its own storage
     credentials reads the table unfiltered. Partition on the security boundary
     to make this enforcement architectural.
     table=analytics.events columns=["email"] policy_set_version=9f2c41ab7d0e5163
```

The columns are read exactly, not guessed at: a filter is a JSON predicate, so
the grammar says where a column reference can appear.

Emitted at most once per table per policy set — editing the policies reports
again, since you have changed the thing the warning is about.

| Filter | Table partitioned on | Enforceable by withholding files? |
|---|---|---|
| `tenant_id == "acme"` | `tenant_id` | **Yes** — architectural |
| `region == "EU"` | `days(ts)` | No — warned |
| anything | nothing | No — warned |

A partition spec of `days(ts)` **is** aligned with a filter on `ts`: the warning
compares the partition's *source column*, not the partition field's name.

---

## Administering policy at runtime

Policy is stored as a **versioned, append-only log** and can be changed without
restarting anything. A change is a new revision; the old one is never edited,
which is what keeps an audit record from last month reproducible — its
`policy_set_version` still names something that exists.

| | |
|---|---|
| `GET /management/v1/policies` | The policy set in force |
| `PUT /management/v1/policies` | Replace it, as a new revision |
| `GET /management/v1/policies/history` | Who changed it, when, and why |
| `POST /management/v1/policies/rollback` | Re-apply an earlier revision |

These live under `/management/v1`, not `/v1`: `GET /v1/config` claims to
describe the Iceberg API completely, and administration is not part of that
contract.

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

The submitted text **replaces** the policy set; nothing is merged. Silently
unioning your policy with rules you did not write is how an authorization system
comes to permit more than its operator believes.

The change takes effect immediately on the replica that received it, and within
a few seconds on the others — each polls the store and swaps atomically. A
request already being evaluated finishes against the set it started with, so no
decision ever sees a half-applied change.

### Two guardrails

**A policy set that does not typecheck is refused** (`400`), not installed. An
invalid `permit` is access that silently disappears; an invalid `forbid` is a
restriction that silently does not apply.

**A policy set that would lock you out is refused** (`400`). If the submitted
rules would leave you unable to change policy again, you could not undo the
change, and the only way back is a restart against a seed file. Deliberate
handover is still possible — grant someone else `Manage` first — but doing it by
accident is not.

### What a replica reports

`GET /management/v1/policies` answers for **the replica that received the
request**, which during a rolling change is not always the newest revision:

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

Equal means converged. `latest_sequence` higher means this replica has not
caught up yet — ordinarily for a second or two after a change, and indefinitely
if it cannot reach the store, which is exactly the case worth being able to see.

Reporting the store's newest as though it were in force would answer a question
nobody asked: an operator checking a pod wants to know what *that pod* does, and
a replica that had stopped converging would look identical to one that had.

```bash
# Which replicas have converged?
for pod in $(kubectl get pods -l app=rustberg -o name); do
  kubectl exec "$pod" -- curl -sf -H "Authorization: Bearer $ADMIN_KEY" \
    localhost:8000/management/v1/policies \
    | jq -c '{pod: "'"$pod"'", enforcing: .sequence, latest: .latest_sequence}'
done
```

### Sequence and version

Two identifiers, and they answer different questions:

| | Means | Changes when |
|---|---|---|
| `sequence` | *When*: revision 7 came after 6 | Every write, including a rollback |
| `version` | *What*: a content hash of the rules | Only when the rules differ |

A rollback appends a **new sequence** carrying an **old version** — the log
records that a rollback happened, while the version correctly says the rules are
the ones from before. Neither identifier alone could express that.

`version` is the same string audit records carry, so a decision can be traced to
the exact text that produced it.

### Where policy comes from at startup

`server.auth.policy_file` **seeds an empty store** and is then no longer
authoritative. If the file won on every start, every change made through the API
would vanish the moment a pod restarted.

When the two diverge, startup says so:

```text
WARN The configured policy file differs from the stored policy set, and the
     STORE is authoritative. The file seeds an empty store only. Change policy
     through PUT /management/v1/policies.
```

A server whose effective policy set contains **no policies** refuses to start:
it would accept nobody, including anyone trying to repair it.

Policy administration requires a deployment that evaluates policy *and* has
somewhere to store revisions. Both are automatic for a server Rustberg starts
itself. The endpoints answer `501` when either is missing:

- under `--no-auth`, where no policy is consulted;
- when the library's `with_catalog` supplies a catalog but `with_policy_store`
  is not also given — a catalog from outside is not required to store policy.
  A redb or Postgres catalog implements both, so one object can serve as both.

---

## Visibility and error codes

`Read` determines whether a caller can *see* a resource, and that drives two
behaviours.

### Listings filter

`listNamespaces`, `listTables` and `listViews` return only what the caller may
read. A table a caller has no grant on does not appear, so the caller never learns
it exists — and the listing agrees with what a subsequent load would answer.

Filtering happens **before** the page is cut, so a page is never short and never
comes back empty while permitted rows remain further on. The cost is one policy
evaluation per row *scanned* rather than per row returned; evaluation is
microseconds against an in-memory entity set, and no extra I/O is involved.

### A denial you cannot see is a 404

Identifying a resource requires resolving which tenant owns its namespace, which
happens before the policy decision. If a forbidden resource answered `403` while a
missing one answered `404`, the status code would let any authenticated caller
enumerate other tenants' namespaces and tables.

| Caller can read it? | Action permitted? | Answer |
|---|---|---|
| — (does not exist) | — | `404` |
| no | no | `404` |
| yes | no | `403` |
| yes | yes | proceeds |

So `404` always means *you cannot see this*, which is equally true whether or not
it exists. `403` only ever tells a caller something it already knew, which keeps
ordinary permission errors diagnosable.

**When debugging, `404` may mean "no `Read` grant".** If a table you know exists
reports `404`, check for a missing `Read` permit before checking for a typo in the
name.

**It never means "the backend is down".** A catalog that cannot answer — an
unreachable database, a mount whose remote is unavailable — is a `5xx`. Only
those four rows above produce a `404`, so an intermittent `404` is a real change
to the resource or to policy, not an outage. Nothing is given away by keeping the
two apart: a store failure is the same failure for every caller, permitted or
not, so unlike an existence check it is not an oracle.

---

## Troubleshooting

**Every request is denied.** Default deny is working and no policy matched.
Check that the principal's roles map to the groups your policies name — `GET
/auth/context` reports the roles the credential actually carries, which is where a
`analyst` vs `analysts` mismatch becomes visible.

**A table exists but returns 404.** Most likely no policy permits `Read` on it.
See [Visibility and error codes](#visibility-and-error-codes).

**A policy seems to be ignored.** Check the identifier encoding — segments join
with `\u{1F}`, not `.`. A policy naming `Namespace::"acme.analytics"` matches a
namespace literally called `acme.analytics`, not the nested one.

**An address-conditioned policy never matches.** Guard with `context has
source_ip`, and check `trust_proxy_headers` if Rustberg runs behind a proxy —
without it the address is the proxy's, not the client's.

**No credentials come back for one table.** Check whether a matching permit
carries `@row_filter` or `@column_mask`; annotated tables are deliberately not
credentialed. See [What an annotation actually does](#what-an-annotation-actually-does).

**Startup fails with a validation error.** A policy references an entity type,
action or attribute the schema does not define. This is deliberate: such a policy
would otherwise never match, silently granting nothing (for a `permit`) or
restricting nothing (for a `forbid`).

---

## Related

- [Authentication](@/docs/authentication.md) — how a principal and its roles are established
- [Security](@/docs/security.md) — enforcement boundaries
