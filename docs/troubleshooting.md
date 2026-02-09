---
layout: default
title: Troubleshooting
nav_order: 11
description: "Troubleshooting guide for common Rustberg issues"
permalink: /docs/troubleshooting
---

# Troubleshooting
{: .no_toc }

Solutions for common issues and debugging techniques.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

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

{: .note }
> This is required because the binary was downloaded from the internet and macOS Gatekeeper quarantines it by default.

### Server Won't Start

**Symptom:** Server exits immediately after starting.

**Check 1: Port already in use**

```bash
# Find process using port
lsof -i :8181

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

{: .warning }
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
curl -H "Authorization: Bearer rustberg_xxxxx" \
     http://localhost:8181/v1/config

# Common mistakes:
# ❌ curl -H "Authorization: rustberg_xxxxx"  # Missing "Bearer"
# ❌ curl -H "Bearer rustberg_xxxxx"          # Missing "Authorization:"
# ❌ curl -H "Authorization: Bearer  rustberg_xxxxx"  # Extra space
```

**Check 2: API key validity**

```bash
# Check if key was rotated or expired
# Verify in audit logs
grep "auth_failure" /var/log/rustberg/audit.log | tail -10
```

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
# Check audit log for specific denial reason
grep "authz_deny" /var/log/rustberg/audit.log | tail -10 | jq
```

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

{: .note }
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

# Check RBAC assignment
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

### Table Not Found

**Symptom:** `NoSuchTableException` for existing table.

**Check 1: Correct namespace**

```bash
# List namespaces
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8181/v1/namespaces | jq

# List tables in namespace
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8181/v1/namespaces/my_namespace/tables | jq
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

### Namespace Already Exists

**Symptom:** `AlreadyExistsException` when creating namespace.

```bash
# Check if namespace exists
curl -H "Authorization: Bearer $API_KEY" \
     http://localhost:8181/v1/namespaces/my_namespace | jq

# If exists, use it or choose different name
```

---

## Performance Issues

### High Latency

**Symptom:** Requests take longer than expected.

**Check 1: Network latency**

```bash
# Test from client to server
curl -w "@curl-format.txt" -o /dev/null -s \
     http://localhost:8181/health

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
     http://localhost:8181/v1/config | grep -i ratelimit
```

### Memory Usage High

**Symptom:** Memory usage exceeds expected ~9MB.

```bash
# Check actual usage
ps aux | grep rustberg

# Check for memory leaks
# Monitor over time
watch -n 5 'ps aux | grep rustberg'
```

Possible causes:
- Large number of cached DEKs (encryption)
- Many concurrent connections
- Large request bodies

---

## KMS Issues

### AWS KMS Access Denied

```bash
# Verify KMS permissions
aws kms describe-key --key-id <key-id>

# Test encrypt/decrypt
aws kms encrypt \
  --key-id <key-id> \
  --plaintext "test" \
  --output text --query CiphertextBlob
```

### Vault Connection Failed

```bash
# Test Vault connectivity
curl $VAULT_ADDR/v1/sys/health

# Verify token
vault token lookup

# Test transit engine
vault read transit/keys/rustberg-key
```

### GCP KMS Permission Denied

```bash
# Test KMS permissions
gcloud kms keys describe rustberg-key \
  --keyring=rustberg-keyring \
  --location=global
```

### Azure Key Vault Access Denied

```bash
# Test Key Vault access
az keyvault key show \
  --vault-name rustberg-vault \
  --name rustberg-key
```

---

## Client Issues

### PyIceberg Connection Failed

```python
# Debug connection
import logging
logging.basicConfig(level=logging.DEBUG)

from pyiceberg.catalog import load_catalog
catalog = load_catalog("rustberg", uri="http://localhost:8181")
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
RUSTBERG_LOG_LEVEL=debug ./rustberg

# Via config
[logging]
level = "debug"
```

{: .note }
> **Debug output is safe**: Rustberg uses custom `Debug` trait implementations that automatically redact sensitive data like API key hashes, secret access keys, and tokens. You can safely enable debug logging without leaking credentials.

### Health Checks

```bash
# Liveness
curl http://localhost:8181/health

# Readiness (includes storage health)
curl http://localhost:8181/ready

# Metrics (including KMS metrics if encryption is enabled)
curl http://localhost:8181/metrics
```

### Audit Logs

```bash
# View recent auth events
tail -f /var/log/rustberg/audit.log | jq

# Filter by event type
grep "authz_deny" audit.log | jq
```

### Request Tracing

```bash
# Include request ID in all requests
curl -H "X-Request-Id: debug-123" \
     -H "Authorization: Bearer $API_KEY" \
     http://localhost:8181/v1/namespaces

# Find in logs
grep "debug-123" /var/log/rustberg/app.log
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

3. **Error logs:**
   ```bash
   tail -100 /var/log/rustberg/app.log
   ```

4. **System info:**
   ```bash
   uname -a
   ```

### Support Channels

- [GitHub Issues](https://github.com/hupe1980/rustberg/issues) - Bug reports
- [GitHub Discussions](https://github.com/hupe1980/rustberg/discussions) - Questions

---

## Next Steps

- [Configuration](/rustberg/docs/configuration) - Full config reference
- [Security](/rustberg/docs/security) - Security best practices
- [API Reference](/rustberg/docs/api) - Endpoint documentation
