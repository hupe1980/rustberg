---
layout: default
title: Authentication
nav_order: 3
description: "Authentication methods for Rustberg: API Keys, JWT, OAuth 2.0"
permalink: /docs/authentication
---

# Authentication
{: .no_toc }

Secure your Rustberg deployment with multiple authentication methods.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Rustberg supports multiple authentication mechanisms:

| Method | Use Case | Production Ready |
|--------|----------|------------------|
| **API Keys** | Service-to-service, CI/CD | ✅ Recommended |
| **JWT/OIDC** | User authentication, SSO | ✅ Ready |
| **Chain Auth** | JWT with API Key fallback | ✅ Ready |

{: .security }
> All authentication is **required by default**. Anonymous access must be explicitly enabled (not recommended).

---

## API Key Authentication

### How It Works

1. Server generates API key with cryptographically secure random bytes
2. Key is hashed using **Argon2id** (PHC winner, OWASP recommended)
3. Client includes key in `Authorization: Bearer <key>` header
4. Server verifies using constant-time comparison

### Security Properties

| Property | Implementation |
|----------|----------------|
| **Hashing** | Argon2id (19 MiB memory, 2 iterations) |
| **Timing** | Constant-time verification |
| **Storage** | Prefix-indexed, PHC format hash |
| **Leakage** | Dummy hash prevents user enumeration |

### Creating API Keys

#### Programmatic (Recommended)

```rust
use rustberg::auth::ApiKeyStore;

// Create store (in-memory or persistent)
let store = ApiKeyStore::new();

// Generate new API key
let (key_id, plaintext) = store.create_key(
    "spark-etl",           // name
    Some("tenant-123"),    // tenant_id
    vec!["data-writer"],   // roles
).await?;

// plaintext = "rustberg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
// Store this securely! It cannot be retrieved later.
```

#### CLI Tool

```bash
# Generate API key (outputs to stdout)
./rustberg generate-key \
    --name "spark-etl" \
    --tenant "tenant-123" \
    --roles "data-writer,data-reader"
```

### Using API Keys

```bash
# HTTP Header
curl -H "Authorization: Bearer rustberg_xxxxx" \
     http://localhost:8181/v1/namespaces

# Query parameter (not recommended)
curl "http://localhost:8181/v1/namespaces?token=rustberg_xxxxx"
```

### Persistent API Key Storage

By default, API keys are stored in memory and lost on restart. For production:

```rust
use rustberg::App;

// Enable persistent API key storage
let (app, store) = App::builder()
    .with_storage_backend("s3://bucket/catalog")
    .with_encryption_key(encryption_key)  // Optional: encrypt at rest
    .build_with_persistent_api_key_auth_async()
    .await;
```

Or via configuration:

```toml
[storage]
object_store_url = "s3://bucket/catalog"

[auth]
persistent_api_keys = true
encryption_key_env = "RUSTBERG_MASTER_KEY"
```

---

## JWT Authentication

### JWKS Configuration

Rustberg validates JWTs against a JWKS (JSON Web Key Set) endpoint:

```toml
[auth.jwt]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "rustberg-catalog"
```

### Token Requirements

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | ✅ | Must match configured issuer |
| `aud` | ✅ | Must match configured audience |
| `exp` | ✅ | Token expiration time |
| `sub` | ✅ | User/service identifier |
| `tenant_id` | ⚠️ | Required for multi-tenant |
| `roles` | ⚠️ | Optional, for RBAC |

### Example JWT Payload

```json
{
  "iss": "https://auth.example.com",
  "aud": "rustberg-catalog",
  "sub": "user@example.com",
  "exp": 1706313600,
  "tenant_id": "tenant-123",
  "roles": ["data-reader", "data-writer"]
}
```

### Provider Examples

#### Auth0

```toml
[auth.jwt]
jwks_url = "https://your-tenant.auth0.com/.well-known/jwks.json"
issuer = "https://your-tenant.auth0.com/"
audience = "rustberg-api"
```

#### Keycloak

```toml
[auth.jwt]
jwks_url = "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
issuer = "https://keycloak.example.com/realms/myrealm"
audience = "rustberg"
```

#### Okta

```toml
[auth.jwt]
jwks_url = "https://your-org.okta.com/oauth2/default/v1/keys"
issuer = "https://your-org.okta.com/oauth2/default"
audience = "rustberg"
```

---

## Chain Authentication

Chain authentication tries multiple methods in order:

1. **JWT** - Check `Authorization: Bearer <jwt>` header
2. **API Key** - Fall back to `Authorization: Bearer <api_key>`

This enables:
- User authentication via SSO (JWT)
- Service accounts via API keys
- Gradual migration between methods

### Configuration

```toml
[auth]
chain_auth = true

[auth.jwt]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "rustberg"

[auth.api_key]
enabled = true
```

---

## Rate Limiting

Protect against abuse with token bucket rate limiting:

```toml
[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
trust_proxy_headers = false  # Set true behind load balancer
```

### Per-Tenant Limits

```toml
[rate_limit]
enabled = true
default_rps = 100

[rate_limit.tenants]
"tenant-premium" = 1000
"tenant-basic" = 50
```

---

## Security Best Practices

### API Keys

{: .important }
> - **Never** commit API keys to source control
> - **Rotate** keys periodically (90 days recommended)
> - **Use** separate keys per service/environment
> - **Monitor** key usage via audit logs

### JWT

{: .important }
> - **Validate** all claims (iss, aud, exp)
> - **Use** short-lived tokens (15 minutes recommended)
> - **Enable** token refresh flows
> - **Monitor** for unusual token patterns

### TLS

{: .security }
> Always use TLS in production. Rustberg warns when running without TLS.

```bash
# Enable TLS (recommended)
./rustberg --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem

# Self-signed for development
./rustberg generate-cert --common-name localhost
./rustberg --tls-cert ./cert.pem --tls-key ./key.pem
```

---

## Audit Logging

All authentication decisions are logged:

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "auth_success",
  "principal": "spark-etl",
  "tenant_id": "tenant-123",
  "method": "api_key",
  "ip": "10.0.0.5",
  "request_id": "abc123"
}
```

### Failed Authentication

```json
{
  "timestamp": "2026-01-24T12:00:01Z",
  "event": "auth_failure",
  "reason": "invalid_token",
  "method": "jwt",
  "ip": "10.0.0.6",
  "request_id": "def456"
}
```

{: .note }
> Secrets (tokens, keys) are **never** logged.

---

## Troubleshooting

### "401 Unauthorized"

1. Verify the API key/JWT is correct
2. Check the `Authorization` header format: `Bearer <token>`
3. Ensure the token hasn't expired
4. Verify JWKS URL is accessible

### "403 Forbidden"

Authentication succeeded but authorization failed:

1. Check tenant isolation (correct `tenant_id`?)
2. Verify roles/permissions in Cedar policies
3. Check audit logs for the specific denial reason

### JWT Validation Failures

```bash
# Debug JWT claims
echo 'eyJhbGc...' | cut -d. -f2 | base64 -d | jq

# Test JWKS endpoint
curl https://auth.example.com/.well-known/jwks.json | jq
```

---

## Next Steps

- [Authorization Guide](/rustberg/docs/authorization) - Cedar policies, RBAC, ABAC
- [Encryption Guide](/rustberg/docs/encryption) - Encrypt API keys at rest
- [API Reference](/rustberg/docs/api) - Authentication endpoints
