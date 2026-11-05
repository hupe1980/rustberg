+++
title = "Troubleshooting"
description = "Diagnosing the failures Rustberg actually produces, by symptom, with the command that confirms each."
weight = 16
+++
## Startup Issues

### macOS: "Cannot Be Opened" or "Unverified Developer"

**Symptom:** macOS blocks the binary with a security warning.

```
"rustberg-darwin-aarch64" cannot be opened because the developer cannot be verified.
```

**Cause:** Gatekeeper quarantines binaries downloaded from the internet.

**Fix:** Remove the quarantine attribute:

```bash
# Remove quarantine attribute
xattr -cr ./rustberg-darwin-aarch64

# Make executable
chmod +x ./rustberg-darwin-aarch64

# Now run it
./rustberg-darwin-aarch64
```

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

**Symptom:** Server exits with a "CORS allows all origins" error.

```
❌ CORS allows all origins ("*") - not allowed in production
   Configure server.cors.allowed_origins in your config file
```

**Fix 1:** Configure explicit origins in `config.toml`:

```toml
[server.cors]
allowed_origins = ["https://your-app.example.com"]
```

**Fix 2:** For local testing only, use development mode:

```bash
# For local development only
./rustberg --dev --insecure-http
```

> Never use `--dev` in production.

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

A request with **no** credential answers `401` without an audit record: it is an
unconfigured client, not a failed authentication.

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

For an API key, the principal is its configured name, of kind `ApiKey`:
`--principal 'ApiKey::"ci-pipeline"'`. A rule written for `User::"ci-pipeline"`
never matches a key.

**Check 2: Tenant isolation**

```bash
# Verify tenant_id in JWT/API key matches resource
jq -c 'select(.action == "decision" and .outcome == "denied")
       | {who: .principal_id, tenant: .tenant_id,
          did: .operation, what: .resource_id, rules: .matched_policies}' \
  /var/log/rustberg/audit.jsonl | tail -10
```

`operation` is spelled as in the policy file: a denial naming `Update` greps
against `Rustberg::Action::"Update"`.

**Check 3: Role assignment**

```bash
# Verify user has correct roles
# Check API key metadata or JWT claims
```

---

## Storage Issues

### Local Filesystem Errors

**Symptom:** `read-only filesystem or storage medium` with a `file://` warehouse.

```
opendal::layers::retry: will retry after 2s because: Unexpected (temporary) at write, 
context: { service: fs, path: warehouse/... } => read-only filesystem or storage medium, 
source: Read-only file system (os error 30)
```

**Cause:** The warehouse directory doesn't exist or the path is malformed.

**Fix:** Use one of these forms; relative paths become absolute and the
directory is created if missing:

```bash
# Relative path (creates ./warehouse in current directory)
./rustberg --warehouse file://warehouse

# Absolute path
./rustberg --warehouse file:///var/lib/rustberg/warehouse

# Bare relative path also works
./rustberg --warehouse warehouse
```

Then check permissions:

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

**Cause:** The catalog store was created by a build with a different schema.
Both backends stamp their store (a `rustberg_schema_version` row in Postgres, a
`meta` entry in the redb file) and refuse another version, because
`CREATE TABLE IF NOT EXISTS` cannot reshape an existing store.

**Fix:** Point `catalog_url` at a fresh database or file, or drop the
`rustberg_*` relations and restart. Rustberg is pre-release and ships no
migrations.

### 404 during an outage

**Symptom:** tables that exist report `404`, and a retry a moment later works.

**Cause:** Not the backend: an unreachable backend is a server error, never a
`404`. `404` means *you cannot see this* (does not exist, or your policy does not
reach it). The resource really comes and goes: something drops and recreates it,
or a policy is being edited.

**Fix:** Find the decision in the audit stream; it names the rule:

```bash
jq -c 'select(.action == "decision")
       | {principal_id, operation, resource_id, outcome, matched_policies}' \
  audit.jsonl | tail -20
```

`500`s or `503`s *are* the backend; see the storage and federation sections
below.

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

**Cause:** Normal under optimistic concurrency.

**Fix:**

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

**Cause:** Another writer committed between your `loadView` and your commit.
`assert-view-uuid` does not prevent this: every version of a view shares a UUID,
so it only catches a view dropped and recreated under the same name. The commit
itself is conditional on the metadata location the load returned.

**Fix:** Reload and re-apply, as for a table. Constant conflicts on a view
nothing else writes usually mean two replicas of your own job.

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

**Cause:** Not an error. Row filters are enforced by withholding files, which
separates rows only on **identity**-partitioned columns. Transformed partitions
are *not* aligned: `days(ts)` puts a whole day in one file, so forbidden rows
remain. Range filters on a transform's exact boundaries warn too.

```bash
# Which columns is the table partitioned on, and with which transform?
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/namespaces/analytics/tables/events \
  | jq '.metadata."partition-specs"'
```

**Fix:** Partition on the filter's column with `identity`, or accept that only
credential withholding protects the table (an engine with its own storage
credentials reads it unfiltered). See
[authorization](@/docs/authorization.md#partition-on-the-security-boundary).

The warning appears once per table per policy set.

### A restricted table returns no rows

**Symptom:** a table loads, `read-restrictions` carries `"required-row-filter":
false`, and `planTableScan` returns no files.

**Cause:** The matching permit's `@row_filter` cannot be **bound to this
table**, so it withholds everything rather than widening. (An unbindable
**client** filter is widened instead.) The server log names the filter and
reason at load.

| Cause | Check |
|---|---|
| The filter names a column this table does not have | Spelling and case; nested paths dotted in full |
| A literal does not fit its column's type | A date is `"2023-01-01"`, a decimal and a UUID are strings, binary is hex |

**Fix:** Correct the filter, or scope the permit to the namespace subtree of the
tables it is meant for. A filter using a transform, `apply`, or an unknown
operator is refused when the policy set **loads** (see below).

### Startup fails naming a `@row_filter`

**Symptom:** the server refuses to start: *"policy 'X' has a @row_filter that is
not a predicate: '…' is not an operator this catalog binds"* — or *"… is a
transform or a function application, neither of which this catalog can bind"*.

**Cause:** The filter is valid JSON but can never be applied — usually an
operator typo (`equals` for `eq`, `greater-than` for `gt`) or a term wrapped in
a `transform`. Loading it would make every `planTableScan` answer `403`.

**Fix:** Use the [accepted grammar](@/docs/api.md#the-filter).

### My policy file change did not apply

**Symptom:** you edited `policy_file`, restarted, and nothing changed.

**Cause:** The file only **seeds an empty store**; after that the store is
authoritative, as startup warns:

```text
WARN The configured policy file differs from the stored policy set, and the
     STORE is authoritative.
```

**Fix:** Change policy through the API:

```bash
curl -X PUT http://localhost:8000/management/v1/policies \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -Rs '{source: ., note: "sync from file"}' < /etc/rustberg/policies/catalog.cedar)"
```

Check what is in force, and its history:

```bash
curl -H "Authorization: Bearer $ADMIN_KEY" \
     http://localhost:8000/management/v1/policies/history | jq
```

### A policy change was refused

| Status | Meaning | Fix |
|---|---|---|
| `400`, "not usable" | The Cedar text does not parse or typecheck | The message names the rule |
| `400`, "no longer be permitted" | The new rules would lock you out of policy changes | Grant yourself `Manage` on the policy set. It is checked against *this* request, so a `context.source_ip` condition uses your current address |
| `403` | You may not administer policy | You need `Manage` on `Rustberg::PolicySet` |
| `501` | This deployment evaluates no policy | You are running `--no-auth` |
| `503` | The revision was appended but could not be audited, so it is not in force | Fix the audit sink and retry; the revision is in the history |

A refused change installs nothing; `400` and `403` append no revision. After a
`503`, `GET /management/v1/policies` shows an enforced sequence behind the
store's latest.

To undo an applied change:

```bash
curl -X POST http://localhost:8000/management/v1/policies/rollback \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sequence": 3}'
```

### Replicas disagree about policy

Replicas poll the store and converge within seconds. If `policy_set_version`
stays different across replicas' audit records, one cannot reach the database:

```text
WARN Could not read the policy store; continuing with the loaded policy set
```

That replica keeps serving its loaded policy set, so a blip does not become a
total outage.

### Why was this request denied?

Every audit record names the deciding rule:

```bash
jq -c 'select(.action == "decision" and .outcome == "denied")
       | {resource: .resource_id, principal: .principal_id, action: .operation,
          rules: .matched_policies, policies: .policy_set_version}' \
  /var/log/rustberg/audit.jsonl
```

| `matched_policies` | Meaning |
|---|---|
| Names one or more policies | An explicit `forbid` matched; read that rule |
| Empty or absent | **Deny by default**: no `permit` matched. Add one |

A third case is only in the server log: `ERROR` *"A policy failed to
evaluate"*, naming the policy and reason. The policy raises at run time;
Rustberg denies rather than skipping it as Cedar would. See [When a policy
cannot be evaluated](@/docs/authorization.md#when-a-policy-cannot-be-evaluated).

Differing `policy_set_version` values mean different policy sets decided the
records; with replicas, usually one missed a change. Ask each:

```bash
curl -s -H "Authorization: Bearer $ADMIN_KEY" \
     localhost:8000/management/v1/policies | jq '{enforcing: .sequence, latest: .latest_sequence}'
```

`enforcing` below `latest` means not converged; if it persists, see *Replicas
disagree about policy* above.

### Who could have written this file?

Decision records show what a caller was permitted, not what it got. The
storage-access records show that:

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

- `vend_credentials` starts a window lasting until the credential expires;
  object reads within it are in the cloud provider's trail, attributed via the
  STS session name.
- `sign_request` is one request, so it is exact.
- `denied` outcomes are worth reading; on a signature, `details.locations` names
  what the caller reached for.

### A remote (`rest`) mount will not start

**Symptom:** *"Mount 'partner' could not connect"* at startup.

**Cause:** A `rest` mount must reach the remote's `GET /v1/config` before the
server starts, so a subtree never silently looks empty.

```bash
# Is the remote reachable, and does it answer config?
curl -s -o /dev/null -w '%{http_code}\n' https://catalog.partner.example/v1/config

# With the token the mount will use
curl -s -H "Authorization: Bearer $RUSTBERG_PARTNER_TOKEN" \
     https://catalog.partner.example/v1/config | jq '.endpoints | length'
```

| Message | Cause |
|---|---|
| *"could not connect"* | Network, DNS, or TLS |
| *"answered 401"* / *"403"* | `token_env` is wrong, or the remote rejects it |
| *"is not set"* / *"set but empty"* | `token_env` names a missing variable |
| *"Malformed config response"* | The URI is not an Iceberg REST catalog |

**Fix:** `catalog_url` is the **base** URI, without `/v1`.

### A remote mount shows no views

**Cause:** The remote's `GET /v1/config` lists no view `endpoints`:

```bash
curl -s https://catalog.partner.example/v1/config \
  | jq '[.endpoints[] | select(contains("/views"))]'
```

An empty list is the answer. A remote with no `endpoints` field gets the spec
baseline, which includes views.

### 400 naming a storage location this catalog "keeps elsewhere"

**Symptom:** `400 Bad Request`: *"Storage location '…' is outside
'<warehouse>/<namespace>/<name>', which is where this catalog keeps this
resource's files."*

**Cause:** A client-supplied location (`location` on `createTable`/`createView`,
the `registerTable` file, or `set-location`) is outside the resource's own
prefix. A security boundary — see
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).

| Why it happens | What to do |
|---|---|
| The client invented a location | Omit `location`; the catalog assigns it, as every reference client expects |
| `registerTable` over a lake laid out differently | Set `storage.location_scope = "warehouse"`, having read [what that costs](@/docs/configuration.md#where-a-client-may-put-a-table-s-files) |
| A table should move | Anywhere *under its own prefix*; elsewhere means creating it there and registering it |

The same rule gives *"This commit names the file '…', which is outside the
table's own storage."* when `add-snapshot`, `set-statistics` or
`set-partition-statistics` names another table's manifest list or Puffin file
(a scan would read it, a purge delete it).

Subdirectories under the own prefix (`.../events/data/dt=2024-01-01/`) need no
configuration.

### 409 saying a table already exists, when you created a view

**Symptom:** `409 Conflict`: *"Table already exists: db.events"* from
`createView`, `renameView`, or the reverse from `createTable`.

**Cause:** One object per name per namespace (as the spec requires for
`createTable`, `createView`, `renameTable`, `renameView`). Both kinds live at
`<warehouse>/<namespace>/<name>`; a shared name would let `?purgeRequested=true`
on the table delete the view's metadata.

**Fix:** Rename or drop one, or choose another name.
`HEAD .../tables/{name}` and `HEAD .../views/{name}` show which kind holds it.

### A mount refuses an operation with 501

**Symptom:** `501 Not Implemented`: *"Mount 'legacy' does not support writing"*.

**Cause:** The mount is `read_only = true`, or its backend cannot perform the
operation:

```bash
grep -A6 '\[mount\.' /etc/rustberg/config.toml
```

| Message | Meaning |
|---|---|
| *"does not support writing"* | The mount is read-only |
| *"across mounts"* | A rename between two catalogs; it cannot be atomic |
| *"cannot span catalogs"* | A transaction touching two catalogs; same reason |

**Fix:** Rename within one mount. To move across, register the metadata in the
destination and unregister it at the source (explicit, non-atomic).

### `/v1/config` advertises fewer endpoints than expected

**Symptom:** writes work, but `endpoints` lists only `GET` and `HEAD`. Or
`POST …/plan` works and `/plan` is not in the list.

**Cause:** The list is the **intersection** across mounts — what the catalog
promises to feature-detecting clients. Requests still work per backend. One
read-only mount removes writes; one `rest` mount (which can never plan) removes
`/plan`.

```bash
curl -s localhost:8000/v1/config | jq '.endpoints'
```

**Fix:** Drop `read_only` from the mount, or accept that feature-detecting
clients do not attempt writes.

### A mounted namespace is invisible

**Symptom:** a mount exists in configuration but its namespaces return `404`.

**Cause:** Usually the mount's `owner` does not match the caller's tenant.
`owner` covers the whole mount.

```bash
# What tenant is the caller?
curl -s -H "Authorization: Bearer $API_KEY" localhost:8000/auth/context \
  | jq .principal.tenant_id
```

**Fix:** Set `owner` to that tenant, or grant the caller a covering policy.

### A mounted namespace or table reports 404 intermittently

**Symptom:** tables in a mount come and go — `HEAD` says `404`, a retry a moment
later succeeds — or a whole mount vanishes and reappears.

**Cause:** The remote is unreachable or erroring. Requests report an error, not
an absence; the detail is in the **log**, not `/ready`:

```bash
# /ready is unauthenticated, so it names a category and nothing else
curl -s localhost:8000/ready | jq '.components.storage'
# { "status": "degraded", "message": "redb unhealthy" }

# which mount, and why, is in the server log
grep 'Storage unhealthy' rustberg.log
# detail="Unreachable mounts: partner"
```

A down mount does **not** make the server unready. Mount requests time out
well inside the server's timeouts and name the mount.

**Fix:** A genuine `404` comes from the remote: check that `catalog_url` is the
catalog root, not a prefix, and that the token grants the namespaces.

### Listing a mount root returns nothing

**Symptom:** `GET /v1/namespaces/prod/tables` is `200` with an empty list, even
though `prod` clearly has tables.

**Cause:** `prod` is a synthetic mount root holding **namespaces**; tables are
one level down. Path levels are joined with `%1F`, not a dot:

```bash
# The namespaces inside the mount
curl -s "localhost:8000/v1/namespaces?parent=prod" | jq '.namespaces'
# The tables in one of them
curl -s "localhost:8000/v1/namespaces/prod%1Fsales/tables" | jq '.identifiers'
```

### Storage location is outside the warehouse

**Symptom:** `400 Bad Request` on `createTable`, `createView`, `registerTable`
**or a commit**: *"Storage location '…' is outside this catalog's warehouse"*.

**Cause:** The catalog manages only locations inside its warehouse, where vended
credentials are scoped:

```bash
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8000/v1/config | jq '.overrides.warehouse'
```

| Cause | Fix |
|---|---|
| Registering a metadata file from another bucket | Copy it under the warehouse first |
| A different bucket, or a typo in it | Correct the location |
| A sibling prefix — `s3://bucket/wh-2` against warehouse `s3://bucket/wh` | Containment is segment-wise, not textual |
| The metadata file's declared `location` points elsewhere | Both it and the file's path must be inside |
| A **commit** carrying a path | `set-location`, `add-snapshot` (manifest list), `set-statistics` and `set-partition-statistics` (Puffin files) are all checked |

Widening `storage.warehouse_location` allows outside locations, and widens
credential-vending scope too.

**Why a commit is checked at all.** Access is scoped to the table's location, so
moving a table onto another tenant's prefix would credential the caller for it.
PyIceberg, Spark and Trino do not hit this in normal operation.

### A purge left files behind

**Symptom:** a `WARN` after `DELETE …?purgeRequested=true`: *"A purge skipped
files outside the table's own storage"*, and the named files are still there.

**Cause:** A purge deletes only files under the table's `location` and logs
skipped paths:

- **`write.data.path` or `write.metadata.path` points outside the location.** A
  second warning names it. Delete the files yourself, or write under the
  table's location. (It could name another table's prefix.)
- **A manifest names a file the table does not own.** Manifests are
  engine-written and unchecked on commit; deleting such files could destroy
  another table's data. Remove them by hand once confirmed.
- **A manifest could not be read.** Warning *"A purge could not read every
  manifest this table referenced"*; its data files were not enumerated. Usually
  a snapshot expired outside this catalog. If it names *every* manifest, check
  the catalog's read access to its warehouse.

### 501 on the credentials endpoint

**Symptom:** `501 Not Implemented`: *"Credential vending is not available for
storage location …"*.

**Cause:** Usually no `[credentials]` section (the default).

**Fix:** Add one — see [configuration](@/docs/configuration.md#credentials).

The endpoint is advertised only when the provider covers **every** warehouse the
catalog serves (a mount on an unknown bucket drops it for all, while vending
continues where possible), so feature-detecting clients do not call it:

```bash
curl -s localhost:8000/v1/config | jq '.endpoints[] | select(endswith("credentials"))'
```

If a section *is* configured, the server would have refused to start; check
that it loaded the file you edited:

```bash
# The server logs the config path it loaded at startup
journalctl -u rustberg | grep "Loaded configuration"
```

- `403`: policy attaches a `@row_filter` or `@column_mask`, which a prefix-shaped
  credential cannot express. A policy outcome.
- `503`: the exchange failed (STS timeout, unassumable role, rejected Entra
  secret). The log names the cause; retrying is reasonable.

### 501 on the sign endpoint

**Symptom:** `501 Not Implemented` from `POST …/tables/{table}/sign`.

**Cause:** Remote signing is off by default (and unadvertised in
`/v1/config`).

**Fix:** Set `enabled = true` under
[`[credentials.signing]`](@/docs/configuration.md#remote-signing).

Other responses:

- **`403` naming the table location:** usually a wrong `url_style`, so the
  bucket is mis-read and refused.
- **`400` naming an operation:** not signable. Object access, multipart upload,
  `DeleteObjects` and `ListObjectsV2` are signed; access-changing sub-resources
  (`?acl`, `?tagging`, `?retention`, …) and headers (`x-amz-acl`,
  `x-amz-grant-*`) are not. An `x-amz-copy-source` outside the table is a `403`.
- **`400` naming a repeated query parameter:** S3 does not specify which value
  wins (for `prefix`: one table or the whole bucket). No AWS SDK does this; fix
  whatever built the URI.
- **`SignatureDoesNotMatch` from S3:** send the response's `uri`, which is the
  resolved form that was checked and signed. It differs for `.`/`..` segments,
  backslashes, or differently written escapes. PyIceberg and the Java
  `S3V4RestSignerClient` already do.

### The server stops responding under load

**Symptom:** requests hang rather than failing, after a period of normal
operation. Nothing in the logs.

**Cause:** Audit records go to **stdout** as JSON Lines, on the request path. An undrained
stdout pipe fills its 64 KB buffer and then blocks requests, at a
traffic-dependent threshold. Container runtimes,
systemd and `| jq` drain correctly; wrapper scripts collecting output may not.

**Fix:** Point the audit sink at a file:

```toml
[audit]
sink = "file"
path = "/var/log/rustberg/audit.jsonl"
```

### CREATE TABLE AS SELECT fails

**Symptom:** Spark's `CREATE TABLE AS SELECT` or `REPLACE TABLE AS SELECT`
fails.

**Cause:** Staged creation is supported; the status says what failed:

| Status | Meaning | Fix |
|---|---|---|
| `409` | Someone created the name between stage and commit | Re-run |
| `404` naming staging | The commit carried `assert-create` but nothing was staged | Usually a connection reused across a restart; re-run |
| `404` naming the namespace | The namespace was dropped while staged | Recreate the namespace |
| `400` | The metadata or updates were rejected | The message names the schema or location at fault |

Uncommitted staged tables reserve nothing and need no cleanup.

---

## Performance Issues

### Table loads are slow or transfer a lot of data

**Symptom:** `loadTable` responses are large and repeated often.

**Fix:** Use two supported spec features:

```bash
# 1. Ask only for snapshots a branch or tag points at.
curl -H "Authorization: Bearer $API_KEY" \
     "http://localhost:8000/v1/namespaces/analytics/tables/events?snapshots=refs"

# 2. Echo the ETag back; an unchanged table answers 304 with no body.
curl -sD- -o/dev/null -H "Authorization: Bearer $API_KEY" \
     -H 'If-None-Match: "6f1c0a2b9d3e4f5061728394a5b6c7d8"' \
     "http://localhost:8000/v1/namespaces/analytics/tables/events"
```

Compare the counters:

```bash
curl -s http://localhost:8000/metrics | grep 'operation="load_table"'
# rustberg_catalog_operations_total{operation="load_table",result="success"} 1240
# rustberg_catalog_operations_total{operation="load_table",result="not_modified"} 8613
```

A low `not_modified` share means clients do not send `If-None-Match`. Expiring
old snapshots shrinks the document permanently.

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

> Debug output is safe: custom `Debug` implementations redact API key hashes,
> secret access keys and tokens.

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

# Only denials
jq -c 'select(.action == "decision" and .outcome == "denied")' /var/log/rustberg/audit.jsonl
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

3. **Application logs** (on **stderr**; stdout carries the audit stream):
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
