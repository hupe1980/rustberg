+++
title = "Troubleshooting"
description = "Diagnosing the failures Rustberg actually produces, by symptom, with the command that confirms each."
weight = 15
+++
## Startup Issues

### macOS: "Cannot Be Opened" or "Unverified Developer"

**Symptom:** macOS blocks the binary with a security warning when trying to run it.

```
"rustberg-darwin-aarch64" cannot be opened because the developer cannot be verified.
```

**Solution:** Remove the quarantine attribute from the downloaded binary:

```bash
# Remove quarantine attribute
xattr -cr ./rustberg-darwin-aarch64

# Make executable
chmod +x ./rustberg-darwin-aarch64

# Now run it
./rustberg-darwin-aarch64
```

> This is required because the binary was downloaded from the internet and macOS Gatekeeper quarantines it by default.

### Server Won't Start

**Symptom:** Server exits immediately after starting.

**Check 1: Port already in use**

```bash
# Find process using port
lsof -i :8000

# Use different port
./rustberg --port 8182
```

**Check 2: Storage permissions**

```bash
# Local storage
ls -la /var/lib/rustberg
chmod 700 /var/lib/rustberg

# S3 permissions
aws sts get-caller-identity
aws s3 ls s3://my-bucket/
```

**Check 3: Config file syntax**

```bash
# Validate TOML
./rustberg --config config.toml 2>&1 | head -20
```

### CORS Origin Not Allowed

**Symptom:** Server exits with "CORS allows all origins" error.

```
❌ CORS allows all origins ("*") - not allowed in production
   Configure server.cors.allowed_origins in your config file
```

**Solution 1: Configure explicit CORS origins in config.toml**

```toml
[server.cors]
allowed_origins = ["https://your-app.example.com"]
```

**Solution 2: Use development mode for local testing**

```bash
# For local development only
./rustberg --dev --insecure-http
```

> Never use `--dev` in production. Always configure explicit CORS origins.

### TLS Certificate Errors

**Symptom:** `error: failed to load TLS certificate`

```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout

# Check key matches certificate
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
# Both should match

# Generate new self-signed cert
./rustberg generate-cert --common-name localhost
```

---

## Authentication Issues

### 401 Unauthorized

**Symptom:** All requests return 401.

**Check 1: API key format**

```bash
# Correct format
curl -H "Authorization: Bearer rb_..." \
     http://localhost:8000/v1/config

# Common mistakes:
# ❌ curl -H "Authorization: rb_..."   # Missing the "Bearer" scheme
# ❌ curl -H "Bearer rb_..."           # Not a header at all
```

**Check 2: API key validity**

```bash
# Every rejected credential is in the audit trail, with the reason.
jq -c 'select(.action == "authenticate" and .outcome == "denied")
       | {time: .timestamp, from: .client_ip, why: .details.reason}' \
  /var/log/rustberg/audit.jsonl | tail -10
```

A request carrying **no** credential is deliberately absent from this: it is an
unconfigured client rather than a failed authentication, and it answers `401`
without a record.

**Check 3: JWT configuration**

```bash
# Test JWKS endpoint
curl https://auth.example.com/.well-known/jwks.json | jq

# Decode JWT to check claims
echo 'eyJhbGc...' | cut -d. -f2 | base64 -d | jq

# Verify issuer and audience match config
```

### 403 Forbidden

**Symptom:** Authentication succeeds but authorization fails.

**Check 1: Cedar policy**

```bash
# Test policy with cedar CLI
cedar evaluate \
  --policies /etc/rustberg/policies/catalog.cedar \
  --principal 'User::"user@example.com"' \
  --action 'Action::"read"' \
  --resource 'Table::"analytics.events"'
```

**Check 2: Tenant isolation**

```bash
# Verify tenant_id in JWT/API key matches resource
jq -c 'select(.action == "decision" and .outcome == "denied")
       | {who: .principal_id, tenant: .tenant_id,
          did: .operation, what: .resource_id, rules: .matched_policies}' \
  /var/log/rustberg/audit.jsonl | tail -10
```

`operation` is spelled the way the policy file spells it, so a denial naming
`Update` greps straight against `Rustberg::Action::"Update"`.

**Check 3: Role assignment**

```bash
# Verify user has correct roles
# Check API key metadata or JWT claims
```

---

## Storage Issues

### Local Filesystem Errors

**Symptom:** `read-only filesystem or storage medium` error when using `file://` warehouse.

```
opendal::layers::retry: will retry after 2s because: Unexpected (temporary) at write, 
context: { service: fs, path: warehouse/... } => read-only filesystem or storage medium, 
source: Read-only file system (os error 30)
```

**Cause:** The warehouse directory doesn't exist or the path is malformed.

**Solution:** Rustberg automatically creates local directories and supports relative paths:

```bash
# Relative path (creates ./warehouse in current directory)
./rustberg --warehouse file://warehouse

# Absolute path
./rustberg --warehouse file:///var/lib/rustberg/warehouse

# Bare relative path also works
./rustberg --warehouse warehouse
```

> Rustberg automatically converts relative paths to absolute paths and creates the directory if it doesn't exist.

**Check directory permissions:**

```bash
# Verify the resolved path
ls -la $(pwd)/warehouse

# If permission denied, fix ownership
sudo chown -R $(whoami) /path/to/warehouse
```

### S3 Access Denied

**Symptom:** `AccessDenied` errors when accessing S3.

```bash
# Verify credentials
aws sts get-caller-identity

# Test bucket access
aws s3 ls s3://my-bucket/rustberg-catalog/

# Check bucket policy
aws s3api get-bucket-policy --bucket my-bucket

# Verify IAM permissions
aws iam get-user-policy --user-name myuser --policy-name rustberg
```

### GCS Permission Denied

**Symptom:** `403 Forbidden` when accessing GCS.

```bash
# Verify service account
gcloud auth list

# Test bucket access
gsutil ls gs://my-bucket/rustberg-catalog/

# Check IAM binding
gsutil iam get gs://my-bucket
```

### Azure Blob Access Denied

**Symptom:** `AuthorizationFailure` when accessing Azure.

```bash
# Verify credentials
az account show

# Test container access
az storage blob list \
  --account-name mystorageaccount \
  --container-name mycontainer

# Check the principal's roles (they become Cedar groups)
az role assignment list --assignee <service-principal-id>
```

### Local Storage Full

**Symptom:** `No space left on device`

```bash
# Check disk usage
df -h /var/lib/rustberg

# Clean old data (if safe)
du -sh /var/lib/rustberg/*

# Consider moving to larger disk or cloud storage
```

---

## Catalog Issues

### Refuses to start: "schema v… and this binary serves v…"

**Symptom:** startup fails naming two schema versions.

The catalog store was created by a build whose schema differs from this one's.
Both backends stamp their store — a `rustberg_schema_version` row in Postgres, a
`meta` entry in the redb file — and refuse one carrying another version.

Point `catalog.url` at a fresh database or file, or drop the `rustberg_*`
relations and start again. Rustberg is pre-release and ships no migrations.

The check is there because `CREATE TABLE IF NOT EXISTS` cannot reshape an
existing store: a relation added by a newer build is created empty while the old
rows stay as they are, which surfaces as tables reporting themselves missing.

### 404 during an outage

**Symptom:** tables that exist report `404`, and a retry a moment later works.

That is not what `404` means here, and it should not be what you see. Rustberg
reports an unreachable backend as a **server error**, never as an absence — a
`404` means *you cannot see this*, which covers both "does not exist" and "your
policy does not reach it", and nothing else.

If you are seeing intermittent `404`s, the resource really is coming and going:
something is dropping and recreating it, or a policy is being edited. Check the
audit stream for the decision, which names the rule:

```bash
jq -c 'select(.action == "decision")
       | {principal_id, operation, resource_id, outcome, matched_policies}' \
  audit.jsonl | tail -20
```

If instead you are seeing `500`s or `503`s, that *is* the backend — see the
storage and federation sections below.

### Table Not Found

**Symptom:** `NoSuchTableException` for existing table.

**Check 1: Correct namespace**

```bash
# List namespaces
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces | jq

# List tables in namespace
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces/my_namespace/tables | jq
```

**Check 2: Tenant isolation**

```bash
# Ensure API key has correct tenant_id
# Tables are isolated by tenant
```

### Commit Conflict

**Symptom:** `CommitFailedException` on table update.

This is normal behavior with optimistic concurrency. Solutions:

1. **Retry with backoff:**
   ```python
   from tenacity import retry, stop_after_attempt, wait_exponential

   @retry(stop=stop_after_attempt(3), wait=wait_exponential())
   def update_table():
       # Your update code
   ```

2. **Check for concurrent writers:**
   - Multiple processes updating same table
   - Consider serializing updates

### 409 on a view commit

**Symptom:** `409 CommitFailedException` from `POST …/views/{view}`, saying the
view was modified concurrently.

Another writer committed between your `loadView` and your commit. Reload and
re-apply — the same answer a table commit gets.

`assert-view-uuid` does not prevent it: it pins the view's *identity*, catching
one dropped and recreated under the same name, and every version of a view shares
a UUID. What prevents the lost update is the pointer swap, which is conditional
on the metadata location the load returned.

Seeing it constantly on a view nothing else writes usually means two replicas of
your own job.

### Namespace Already Exists

**Symptom:** `AlreadyExistsException` when creating namespace.

```bash
# Check if namespace exists
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces/my_namespace | jq

# If exists, use it or choose different name
```

### "Row filter references columns this table does not partition on by identity"

**Symptom:** a `WARN` at table load naming a table and some columns.

Not an error — a statement about what your policy can actually enforce. A row
filter is enforced by withholding files, which separates rows only when the
filter's columns are partitioned with an **identity** transform. Otherwise
permitted and forbidden rows share Parquet row groups and no file-level decision
separates them.

```bash
# Which columns is the table partitioned on, and with which transform?
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces/analytics/tables/events \
  | jq '.metadata."partition-specs"'
```

A transformed partition counts as *not* aligned: `days(ts)` holds a whole day in
one file, so a filter on `ts` still leaves forbidden rows in the files it
selects. The check is deliberately conservative, so a range filter falling
exactly on a transform's boundaries is warned about too.

Either partition on the column the filter uses with `identity`, or accept that
this table is protected only by Rustberg withholding credentials — an engine with
its own storage credentials reads it unfiltered. See
[authorization](@/docs/authorization.md#partition-on-the-security-boundary).

The warning appears once per table per policy set; editing your policies makes
it report again.

### 403 from `planTableScan` naming a policy row filter

**Symptom:** `403 Forbidden`: *"Policy attaches a row filter to this table that
cannot be applied to it (…). Planning is refused rather than returning files the
filter was meant to withhold."*

The `@row_filter` on the permit that matched cannot be **bound to this table**.
Three things cause it, and the message names which:

| In the message | Means |
|---|---|
| *"the filter names 'X', which this table has no"* | the column is missing, or spelled differently — check case, and check nested paths are dotted in full |
| *"a filter literal for a … column must be …"* | the value does not fit the column's type; a date is `"2023-01-01"`, a decimal and a UUID are strings, binary is hex |

A `403` and not a `400`: the request is fine, the *policy* is what does not apply
here. Refused and not ignored, because widening a restriction removes it —
`@row_filter("region = 'EU'")` would become "everything" at the moment it was
supposed to bite. The same term in a filter a **client** sent is widened away,
where a superset only costs time.

Only those two reach this point. A filter naming a transform, `apply`, a
field-id reference or an operator this catalog does not read cannot bind against
*any* table, so it is refused when the policy set **loads** — see below. What is
left here is the two questions that need a table in hand, and one policy covers
tables that do not exist yet. If the filter is meant for some tables and not
others, scope the permit to the namespace subtree they live in.

### Startup fails naming a `@row_filter`

**Symptom:** the server refuses to start: *"policy 'X' has a @row_filter that is
not a predicate: '…' is not an operator this catalog binds"* — or *"… is a
transform, a function application or a field id, none of which this catalog can
bind"*.

The filter is well-formed JSON and is not an expression this catalog can ever
apply. Usually a typo in the operator (`equals` for `eq`, `greater-than` for
`gt`), or a term wrapped in a `transform`.

It is a startup failure rather than a warning for the same reason a policy that
does not typecheck is: the alternative is a policy set that installs cleanly and
then answers `403` to every `planTableScan` against every table, at whichever
query happens to hit it first. The [accepted grammar](@/docs/api.md#the-filter)
is the one the plan endpoint reads.

### My policy file change did not apply

**Symptom:** you edited `policy_file`, restarted, and nothing changed.

Expected. The file **seeds an empty store**; once policy exists, the store is
authoritative. Startup says so:

```text
WARN The configured policy file differs from the stored policy set, and the
     STORE is authoritative.
```

Change policy through the API instead:

```bash
curl -X PUT http://localhost:8000/management/v1/policies \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -Rs '{source: ., note: "sync from file"}' < /etc/rustberg/policies/catalog.cedar)"
```

Check what is actually in force, and how it got there:

```bash
curl -H "Authorization: Bearer $ADMIN_KEY" \
     http://localhost:8000/management/v1/policies/history | jq
```

### A policy change was refused

| Status | Meaning | Fix |
|---|---|---|
| `400`, "not usable" | The Cedar text does not parse or typecheck | Read the message; it names the rule |
| `400`, "no longer be permitted" | The new rules would leave you unable to change policy again | Include a rule granting yourself `Manage` on the policy set. The check runs against *this* request, so a grant conditioned on `context.source_ip` is judged by the address you are calling from |
| `403` | You may not administer policy | You need `Manage` on `Rustberg::PolicySet` |
| `501` | This deployment evaluates no policy | You are running `--no-auth` |
| `503` | The revision was appended but could not be audited, so it was not put into force | Fix the audit sink and retry; the revision is already in the history |

Nothing is installed when a change is refused. A `400` or `403` appends no
revision either, so the previous policy set is untouched; a `503` leaves the
revision in the history but not enforced, which `GET /management/v1/policies`
shows as an enforced sequence behind the store's latest.

To undo a change that *was* applied:

```bash
curl -X POST http://localhost:8000/management/v1/policies/rollback \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sequence": 3}'
```

### Replicas disagree about policy

Replicas poll the store and converge within seconds. If `policy_set_version`
stays different between replicas' audit records, one cannot reach the database —
look for:

```text
WARN Could not read the policy store; continuing with the loaded policy set
```

A replica that cannot reach the store keeps serving the policy set it has, which
is deliberate: failing closed on a transient blip would turn a read-only outage
into a total one.

### Why was this request denied?

Every audit record names the rule that decided it:

```bash
jq -c 'select(.action == "decision" and .outcome == "denied")
       | {resource: .resource_id, principal: .principal_id, action: .operation,
          rules: .matched_policies, policies: .policy_set_version}' \
  /var/log/rustberg/audit.jsonl
```

| `matched_policies` | Meaning |
|---|---|
| Names one or more policies | An explicit `forbid` matched — go read that rule |
| Empty or absent | **Deny by default**: nothing forbade it and nothing permitted it. You are missing a `permit` |

A third shape shows up only in the server log, not in the record: an `ERROR`
saying *"A policy failed to evaluate"*, naming the policy and the reason. That
policy typechecked at load and raises at run time, and Cedar's own rule is to
skip such a policy — which would silently drop a `forbid`. Rustberg denies the
request instead. Fix the named policy; see [When a policy cannot be
evaluated](@/docs/authorization.md#when-a-policy-cannot-be-evaluated).

If `policy_set_version` differs between records, they were decided under
different policy files — which on a multi-replica deployment usually means one
replica did not pick up a policy change. Ask each one directly:

```bash
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
     localhost:8000/management/v1/policies | jq '{enforcing: .sequence, latest: .latest_sequence}'
```

`enforcing` below `latest` means that replica has not converged. If it stays
behind, it cannot reach the store — look for the warning in *Replicas disagree
about policy* above.

### Who could have written this file?

A decision record says a caller was permitted to `Read` a table. It does not say
what it walked away with. The storage-access records do:

```bash
# Every credential that could write, and who got it.
jq -c 'select(.action == "vend_credentials" and .operation == "read-write")
       | {time: .timestamp, who: .principal_id, table: .resource_id}' \
  /var/log/rustberg/audit.jsonl

# Every signature over a write, and the objects it covered.
jq -c 'select(.action == "sign_request" and .operation == "write")
       | {time: .timestamp, who: .principal_id, objects: .details.locations}' \
  /var/log/rustberg/audit.jsonl
```

A `vend_credentials` record marks the *start* of a window, not a single access:
the credential lives until it expires, and the object reads inside that window are
in the cloud provider's own trail, attributed to the principal because the STS
session name carries it. A signature is one request, so `sign_request` is exact.

An `outcome` of `denied` on either is worth reading; on a signature,
`details.locations` names what the caller reached for.

### A remote (`rest`) mount will not start

**Symptom:** *"Mount 'partner' could not connect"* at startup.

A `rest` mount reaches the remote's `GET /v1/config` before the server comes up.
That is deliberate: a subtree that silently looks empty is indistinguishable
from one you may not have permission to see.

```bash
# Is the remote reachable, and does it answer config?
curl -s -o /dev/null -w '%{http_code}\n' https://catalog.partner.example/v1/config

# With the token the mount will use
curl -s -H "Authorization: Bearer $RUSTBERG_PARTNER_TOKEN" \
     https://catalog.partner.example/v1/config | jq '.endpoints | length'
```

| Message | Cause |
|---|---|
| *"could not connect"* | Network, DNS, or TLS — the remote was not reached |
| *"answered 401"* / *"403"* | `token_env` is wrong, or the remote does not accept it |
| *"is not set"* / *"set but empty"* | `token_env` names a variable that does not exist |
| *"Malformed config response"* | The URI points at something that is not an Iceberg REST catalog |

`catalog_url` is the **base** URI, without `/v1`.

### A remote mount shows no views

Capabilities are negotiated from the remote's own `GET /v1/config`. If its
`endpoints` list contains no view entries, the mount reports no views rather
than offering them and failing on use.

```bash
curl -s https://catalog.partner.example/v1/config \
  | jq '[.endpoints[] | select(contains("/views"))]'
```

An empty list there is the answer. A remote that predates the `endpoints` field
returns nothing at all, and Rustberg assumes the spec baseline — which includes
views — rather than hiding views that are there.

### 400 naming a storage location this catalog "keeps elsewhere"

**Symptom:** `400 Bad Request`: *"Storage location '…' is outside
'<warehouse>/<namespace>/<name>', which is where this catalog keeps this
resource's files."*

A client-supplied location — the `location` on `createTable` or `createView`,
the file `registerTable` names, or `set-location` on a commit — points somewhere
other than the prefix the resource's own name puts it in.

A security boundary rather than a layout rule — see
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).

| Why it happens | What to do |
|---|---|
| A client sends a location it invented rather than one this catalog assigned | Omit `location` and let the catalog assign it — every reference client does |
| `registerTable` over a lake whose files are not where a name would put them | Set `storage.location_scope = "warehouse"`, having read [what that costs](@/docs/configuration.md#where-a-client-may-put-a-table-s-files) |
| A table really should move | It may move anywhere *under its own prefix*; elsewhere means creating it there and registering it |

A second, differently-worded refusal comes from the same rule: *"This commit
names the file '…', which is outside the table's own storage."* That one is
about `add-snapshot`, `set-statistics` or `set-partition-statistics` naming a
file the table does not own — a manifest list or Puffin file under some other
table's prefix. A commit records files the table owns; one it does not own would
be read by a scan plan and deleted by a purge.

Laying a table out underneath its own prefix is always fine —
`.../events/data/dt=2024-01-01/` needs nothing configured.

### 409 saying a table already exists, when you created a view

**Symptom:** `409 Conflict`: *"Table already exists: db.events"* from
`createView`, `renameView`, or the reverse from `createTable`.

A namespace holds one thing per name. Both kinds live at
`<warehouse>/<namespace>/<name>`, so a table and a view sharing a name would
share a directory — and `?purgeRequested=true` on the table would delete the
view's metadata. The spec asks for the same answer on all four of
`createTable`, `createView`, `renameTable` and `renameView`.

Rename or drop whichever you no longer want, or pick a different name. The error
names the identifier, not the kind that holds it; `HEAD .../tables/{name}` and
`HEAD .../views/{name}` say which.

### A mount refuses an operation with 501

**Symptom:** `501 Not Implemented`: *"Mount 'legacy' does not support writing"*.

The mount is configured `read_only = true`, or its backend cannot perform the
operation. This is deliberate — the alternative is reaching into a catalog
another system owns. Check the mount:

```bash
grep -A6 '\[mount\.' /etc/rustberg/config.toml
```

Related refusals:

| Message | Meaning |
|---|---|
| *"does not support writing"* | The mount is read-only |
| *"across mounts"* | A rename between two catalogs; it cannot be atomic |
| *"cannot span catalogs"* | A transaction touching two catalogs; same reason |

Rename and move a table *within* one mount, or copy it: registering the same
metadata in the destination and unregistering it at the source is the explicit,
non-atomic version of what Rustberg refuses to do implicitly.

### `/v1/config` advertises fewer endpoints than expected

**Symptom:** writes work, but `endpoints` lists only `GET` and `HEAD`. Or
`POST …/plan` works and `/plan` is not in the list.

One mount is read-only, and the list is the **intersection** of what every mount
supports. Those operations still work on the mounts that support them — a
refusal is decided per request, against the backend the namespace routes to —
and what the intersection governs is only what the catalog *promises*, because a
client feature-detects from that list once.

Scan planning is the case that surprises people, because a `rest` mount can
never plan: its manifests are in storage this server does not manage. One such
mount removes `/plan` from the list while every native table beside it goes on
planning normally.

```bash
curl -s localhost:8000/v1/config | jq '.endpoints'
```

If that is not what you want, either drop `read_only` from the mount or accept
that clients relying on feature detection will not attempt writes anywhere.

### A mounted namespace is invisible

**Symptom:** a mount exists in configuration but its namespaces return `404`.

Almost always the mount's `owner` does not match the tenant the caller belongs
to. `owner` is authoritative for the whole mount, so a mismatch makes everything
inside it invisible — which is the same answer `404` gives for "does not exist",
by design.

```bash
# What tenant is the caller?
curl -s -H "Authorization: Bearer $API_KEY" localhost:8000/auth/context \
  | jq .principal.tenant_id
```

Set the mount's `owner` to that tenant, or grant the caller a policy covering it.

### A mounted namespace or table reports 404 intermittently

**Symptom:** tables in a mount come and go — `HEAD` says `404`, a retry a moment
later succeeds — or a whole mount vanishes and reappears.

The remote catalog is unreachable or erroring, not empty. Rustberg reports that
as an error rather than as an absence, so the request itself will say so — and
the detail is in the **log**, not in `/ready`:

```bash
# /ready is unauthenticated, so it names a category and nothing else
curl -s localhost:8000/ready | jq '.components.storage'
# { "status": "degraded", "message": "redb unhealthy" }

# which mount, and why, is in the server log
grep 'Storage unhealthy' rustberg.log
# detail="Unreachable mounts: partner"
```

A mount that is down does **not** make the server unready — the namespaces that
still work keep working. If you are seeing `404` rather than an error, the remote
itself is answering `404`: check that the mount's `catalog_url` points at the
catalog root and not at a prefix, and that its token grants the namespaces you
expect.

Requests to a mount are bounded by their own connect and request timeouts, well
inside the server's, so a remote that stops answering fails fast and names the
mount rather than timing out anonymously.

### Listing a mount root returns nothing

**Symptom:** `GET /v1/namespaces/prod/tables` is `200` with an empty list, even
though `prod` clearly has tables.

A mount root holds **namespaces**, not tables. `prod` is synthetic — it exists so
the mount is loadable and ownable — and the catalog behind it has no namespace at
that level. The tables are one level down:

```bash
# The namespaces inside the mount
curl -s "localhost:8000/v1/namespaces?parent=prod" | jq '.namespaces'
# The tables in one of them
curl -s "localhost:8000/v1/namespaces/prod%1Fsales/tables" | jq '.identifiers'
```

Note the `%1F`: namespace levels are joined with a unit separator in the path,
not a dot.

### Storage location is outside the warehouse

**Symptom:** `400 Bad Request` on `createTable`, `createView`, `registerTable`
**or a commit**: *"Storage location '…' is outside this catalog's warehouse"*.

A catalog only manages locations inside its own warehouse, because the
credentials it vends are scoped to them. Check what the warehouse actually is:

```bash
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/config | jq '.overrides.warehouse'
```

Common causes:

| Cause | Fix |
|---|---|
| Registering a metadata file from another bucket | Copy it under the warehouse first |
| A different bucket, or a typo in it | Correct the location |
| A sibling prefix — `s3://bucket/wh-2` against warehouse `s3://bucket/wh` | These are different prefixes; containment is segment-wise, not textual |
| The metadata file's own `location` field points elsewhere | The file's path is checked *and* the `location` it declares; both must be inside |
| A **commit** carrying a path | `set-location`, `add-snapshot` (manifest list), `set-statistics` and `set-partition-statistics` (Puffin files) all name a location, and all four are checked |

To serve a location genuinely outside, widen `storage.warehouse_location` — but
note it also widens what credential vending may be scoped to.

**Why a commit is checked at all.** Storage access is scoped to *the table's
location*, so a caller able to move a table can point it at another tenant's
prefix in the same warehouse and be correctly credentialed — for the location it
chose. Nothing else about the request would look wrong. Engines do not hit this
in normal operation: PyIceberg, Spark and Trino all write manifest lists and
Puffin files under the table they belong to.

### A purge left files behind

**Symptom:** a `WARN` after `DELETE …?purgeRequested=true`: *"A purge skipped
files outside the table's own storage"*, and the named files are still there.

A purge deletes only what lives under the table's own `location`. Anything else
the metadata names is skipped and logged by path.

Two causes, and they want different responses:

- **The table sets `write.data.path` or `write.metadata.path` outside its
  location.** A second warning names the property. Delete the files yourself, or
  write data under the table's location so a purge covers it. Honouring the
  property would let one table name another's prefix, and confining it to the
  warehouse does not help — the warehouse is where the other tables are.
- **A manifest names a file the table does not own.** Manifests are written by
  the engine and are the one set of paths a catalog cannot check on commit.
  Deleting them would let a caller destroy another table's data by dropping its
  own. Remove them by hand once you have confirmed what they are.

- **A manifest could not be read.** A separate warning, *"A purge could not read
  every manifest this table referenced"*: the data files it names were not
  enumerated, so they were left. Usually a snapshot expired outside this catalog.
  If it names *every* manifest, check the catalog's read access to its warehouse.

### 501 on the credentials endpoint

**Symptom:** `501 Not Implemented`: *"Credential vending is not available for
storage location …"*.

Almost always: no `[credentials]` section is configured, which is the default.
Add one — see [configuration](@/docs/configuration.md#credentials).

While no provider covers this catalog's warehouses, the endpoint is also absent
from `/v1/config`, so a client that feature-detects will not call it — a `501`
here means something called it anyway:

```bash
curl -s localhost:8000/v1/config | jq '.endpoints[] | select(endswith("credentials"))'
```

Nothing there and a `501` from the endpoint are the same fact stated twice. It is
advertised only when the provider covers **every** warehouse the catalog serves,
so a federated deployment whose mount points at a bucket the provider does not
know about drops the advertisement for all of them while continuing to vend where
it can.

If a section *is* configured, the server would have refused to start, so check
that the running process actually loaded the file you edited:

```bash
# The server logs the config path it loaded at startup
journalctl -u rustberg | grep "Loaded configuration"
```

A `403` from the same endpoint is different: it means policy attaches a
`@row_filter` or `@column_mask` to the table, and a prefix-shaped credential
cannot express one. That is a policy outcome, not a misconfiguration.

A `503` is different again: the exchange itself failed — an STS call that timed
out, a role that cannot be assumed, an Entra secret that was rejected. The
server log names the cause, and retrying is reasonable.

### 501 on the sign endpoint

**Symptom:** `501 Not Implemented` from `POST …/tables/{table}/sign`.

Remote signing is off by default. Set `enabled = true` under
[`[credentials.signing]`](@/docs/configuration.md#remote-signing). While it is
off the endpoint is also absent from `/v1/config`, so a client that
feature-detects will not call it at all.

A `403` naming the table location usually means `url_style` is wrong for your
endpoint: the bucket is read from the wrong part of the URI, so containment does
not match the table. That failure direction is deliberate — a mis-read bucket is
refused rather than signed.

A `400` naming an operation means the request is not one this endpoint signs.
Object access, multipart upload, `DeleteObjects` and `ListObjectsV2` are signed;
sub-resources that change who may reach an object (`?acl`, `?tagging`,
`?retention`, …) and access-granting headers (`x-amz-acl`, `x-amz-grant-*`) are
not. A `x-amz-copy-source` pointing outside the table is a `403` like any other
location outside it.

A `400` naming a **repeated query parameter** means the URI sent the same
parameter twice. Which value S3 acts on is not specified, so the one this
endpoint checked would not necessarily be the one that takes effect — for
`prefix` on a listing that is the difference between one table and the whole
bucket. No AWS SDK emits a duplicate key, so this is worth reading as a bug in
whatever built the URI.

**`SignatureDoesNotMatch` from S3, on a request this endpoint signed.** Send the
`uri` from the response, not the one you asked about: the endpoint resolves the
URI, checks containment against the resolved form, and signs that. The two differ
whenever the URI carries a `.` or `..` segment, a backslash, or an escape written
differently. PyIceberg and the Java `S3V4RestSignerClient` already use it.

### The server stops responding under load

**Symptom:** requests hang rather than failing, after a period of normal
operation. Nothing in the logs.

Check what is reading **stdout**. The audit trail is written there as JSON Lines
on the request path, so a parent process that captured stdout into a pipe and is
not draining it will fill the 64 KB pipe buffer, and the next audit record blocks
the request that produced it. The threshold is traffic-dependent, which is why it
looks like a load problem.

Container runtimes, systemd and an interactive `| jq` all drain the stream
correctly. A wrapper script that collects output to inspect afterwards does not.
Point the audit sink at a file instead:

```toml
[audit]
sink = "file"
path = "/var/log/rustberg/audit.jsonl"
```

### CREATE TABLE AS SELECT fails

**Symptom:** Spark's `CREATE TABLE AS SELECT` or `REPLACE TABLE AS SELECT`
fails.

Staged creation *is* supported, so a failure here is a real error rather than a
missing feature. Read the status:

| Status | Meaning | Fix |
|---|---|---|
| `409` | The name was created by someone else between the stage and the commit | Re-run; the conflict is genuine |
| `404` naming staging | The commit carried `assert-create` but nothing was staged | Usually a client that reused a connection across a restart; re-run the statement |
| `404` naming the namespace | The namespace was dropped while the table was staged | Recreate the namespace |
| `400` | The metadata or updates were rejected | Check the message; the schema or a location is at fault |

A staged table that is never committed reserves nothing and needs no cleanup.

---

## Performance Issues

### Table loads are slow or transfer a lot of data

**Symptom:** `loadTable` responses are large and repeated often.

Two spec features cut this down, both supported:

```bash
# 1. Ask only for snapshots a branch or tag points at.
curl -H "Authorization: Bearer $API_KEY" \
     "http://localhost:8000/v1/namespaces/analytics/tables/events?snapshots=refs"

# 2. Echo the ETag back; an unchanged table answers 304 with no body.
curl -sD- -o/dev/null -H "Authorization: Bearer $API_KEY" \
     -H 'If-None-Match: "6f1c0a2b9d3e4f5061728394a5b6c7d8"' \
     "http://localhost:8000/v1/namespaces/analytics/tables/events"
```

How much this is helping is visible in the metrics — compare the two counters:

```bash
curl -s http://localhost:9090/metrics | grep 'operation="load_table"'
# rustberg_catalog_operations_total{operation="load_table",result="success"} 1240
# rustberg_catalog_operations_total{operation="load_table",result="not_modified"} 8613
```

A high `not_modified` share means conditional loading is working. A share near
zero means clients are not sending `If-None-Match`.

If tables carry very long snapshot histories, expiring old snapshots also
shrinks the document permanently.

### High Latency

**Symptom:** Requests take longer than expected.

**Check 1: Network latency**

```bash
# Test from client to server
curl -w "@curl-format.txt" -o /dev/null -s \
     http://localhost:8000/health

# curl-format.txt:
# time_namelookup:  %{time_namelookup}s\n
# time_connect:     %{time_connect}s\n
# time_appconnect:  %{time_appconnect}s\n
# time_total:       %{time_total}s\n
```

**Check 2: Storage backend latency**

```bash
# S3 latency
aws s3api head-object \
  --bucket my-bucket \
  --key rustberg-catalog/test
```

**Check 3: Rate limiting**

```bash
# Check for rate limit headers
curl -i -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/config | grep -i ratelimit
```

### Memory Usage High

**Symptom:** Memory usage exceeds the expected ~15 MB idle.

```bash
# Check actual usage
ps aux | grep rustberg

# Check for memory leaks
# Monitor over time
watch -n 5 'ps aux | grep rustberg'
```

Possible causes:
- A large idempotency cache — every retained response is held in memory
- Many concurrent connections
- Large request bodies

---

## Client Issues

### PyIceberg Connection Failed

```python
# Debug connection
import logging
logging.basicConfig(level=logging.DEBUG)

from pyiceberg.catalog import load_catalog
catalog = load_catalog("rustberg", uri="http://localhost:8000")
```

### Trino Connection Failed

```sql
-- Check catalog status
SHOW CATALOGS;

-- If missing, check connector config
-- catalog/rustberg.properties
```

---

## Debugging Tools

### Enable Debug Logging

```bash
# Via environment variable
RUST_LOG=debug ./rustberg

# Via config
[logging]
level = "debug"
```

> **Debug output is safe**: Rustberg uses custom `Debug` trait implementations that automatically redact sensitive data like API key hashes, secret access keys, and tokens. You can safely enable debug logging without leaking credentials.

### Health Checks

```bash
# Liveness
curl http://localhost:8000/health

# Readiness — catalog and storage, the two things that can be unreachable.
# Cached for two seconds, so probing harder does not probe more.
curl http://localhost:8000/ready

# Metrics
curl http://localhost:8000/metrics
```

### Audit Logs

```bash
# View recent auth events
tail -f /var/log/rustberg/audit.jsonl | jq

# Filter by event type
grep "authz_deny" audit.log | jq
```

### Request Tracing

```bash
# Include request ID in all requests
curl -H "X-Request-Id: debug-123" \
     -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces

# Find in logs
journalctl -u rustberg | grep "debug-123"
```

---

## Getting Help

### Collect Diagnostics

Before opening an issue, collect:

1. **Rustberg version:**
   ```bash
   ./rustberg --version
   ```

2. **Configuration (sanitized):**
   ```bash
   cat config.toml | grep -v -E "(key|secret|password|token)"
   ```

3. **Application logs.** They go to **stderr** — stdout carries the audit
   stream — so capture that stream from whatever supervises the process:
   ```bash
   journalctl -u rustberg -n 100        # systemd
   docker logs --tail 100 rustberg      # Docker
   ```

4. **System info:**
   ```bash
   uname -a
   ```

### Support Channels

- [GitHub Issues](https://github.com/hupe1980/rustberg/issues) - Bug reports

---

## Next Steps

- [Configuration](@/docs/configuration.md) - Full config reference
- [Security](@/docs/security.md) - enforcement boundaries and operating notes
- [API Reference](@/docs/api.md) - Endpoint documentation
