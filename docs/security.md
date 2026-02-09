---
layout: default
title: Security
nav_order: 9
description: "Security model, threat model, and best practices for Rustberg"
permalink: /docs/security
---

# Security
{: .no_toc }

Defense-in-depth security model and best practices.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Security Model

Rustberg implements **defense-in-depth** with multiple security layers:

```
TLS 1.2/1.3 ──► Rate Limiting ──► Authentication ──► Authorization ──► Validation ──► Audit
                    │
                    └─ IP tracking (spoofing protection)
```

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | API key/JWT authentication |
| Privilege escalation | Cedar authorization policies |
| Data tampering | AES-256-GCM encryption |
| Network eavesdropping | TLS 1.3 encryption |
| DoS attacks | Rate limiting, timeouts |
| Injection attacks | Input validation |
| Cross-tenant access | Tenant isolation |

### Out of Scope

| Threat | Reason |
|--------|--------|
| Physical access | Rely on infrastructure security |
| Supply chain attacks | Use audited dependencies |
| Side-channel attacks | Not applicable (no shared state) |
| Quantum attacks | AES-256 is quantum-resistant |

---

## Authentication Security

### API Keys

| Property | Implementation |
|----------|----------------|
| **Hashing** | Argon2id (OWASP recommended) |
| **Parameters** | 19 MiB memory, 2 iterations |
| **Timing** | Constant-time comparison |
| **Enumeration** | Dummy hash prevents timing leaks |

```rust
// Argon2id configuration
let params = Params::new(19456, 2, 1, Some(32))?;
```

### JWT Validation

| Check | Description |
|-------|-------------|
| Signature | RS256/RS384/RS512, ES256/ES384/ES512 |
| Issuer | Must match configured `iss` |
| Audience | Must match configured `aud` |
| Expiration | Token must not be expired |
| Not Before | Token must be active |

---

## Authorization Security

### Cedar Policy Engine

- **Default deny** - No access without explicit permit
- **Tenant isolation** - Mandatory `tenant_id` check
- **Least privilege** - Grant minimum necessary access
- **Audit trail** - Every decision logged

```cedar
// Example: Enforce tenant isolation
permit(principal, action, resource)
when {
    principal.tenant_id == resource.tenant_id
};
```

---

## Input Validation

All user input is validated:

| Validation | Implementation |
|------------|----------------|
| **Name length** | Max 255 characters |
| **Namespace depth** | Max 10 levels |
| **Properties count** | Max 100 per resource |
| **Path traversal** | Block `..` patterns |
| **Null bytes** | Block `\0` injection |
| **Control chars** | Block non-printable |
| **Hidden files** | Block `.` prefix |
| **Windows reserved** | Block CON, PRN, AUX, etc. |

```rust
// Character whitelist
const ALLOWED: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
```

---

## Encryption

### At Rest

| Component | Algorithm |
|-----------|-----------|
| Data | AES-256-GCM |
| Key wrapping | KMS provider-specific |
| Nonce | 96-bit random per encryption |
| Tag | 128-bit authentication |

### In Transit

| Component | Algorithm |
|-----------|-----------|
| TLS version | 1.2 or 1.3 |
| Implementation | rustls (memory-safe) |
| Cipher suites | AES-GCM, ChaCha20-Poly1305 |

### In Memory

| Protection | Implementation |
|------------|----------------|
| Zeroize | Secrets cleared on drop |
| Redacted Debug | Custom Debug traits redact sensitive fields |
| No Clone | Controlled copies |

Structs with custom Debug implementations that redact secrets:
- `ApiKey` - redacts `key_hash`
- `StorageCredential` - redacts config values containing `secret`, `token`, or `password`
- `DataEncryptionKey` - redacts `plaintext` key material

---

## Rate Limiting

Token bucket algorithm with:

| Feature | Value |
|---------|-------|
| Default limit | 100 req/s |
| Burst size | 200 requests |
| Per-tenant | Configurable |
| IP tracking | Respects X-Forwarded-For |

{: .security }
> Set `trust_proxy_headers = false` unless behind a trusted load balancer.

---

## Audit Logging

All security events are logged:

### Authentication

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "auth_success",
  "principal": "spark-etl",
  "method": "api_key",
  "ip": "10.0.0.5"
}
```

### Authorization

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "authz_deny",
  "principal": "user@example.com",
  "action": "delete",
  "resource": "Table::analytics.events",
  "reason": "no matching permit"
}
```

### Sensitive Operations

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "table_dropped",
  "principal": "admin",
  "resource": "analytics.events",
  "purge_requested": true
}
```

{: .note }
> Secrets (tokens, keys, passwords) are **never** logged.

---

## Secure Defaults

Rustberg is **secure by default**. Production mode (default) enforces:

| Setting | Default | Rationale |
|---------|---------|-----------|
| TLS | Required | Prevent eavesdropping |
| Authentication | Required | Prevent unauthorized access |
| CORS origins | Must be explicit | Prevent cross-origin attacks |
| trust_proxy_headers | false | Prevent IP spoofing |
| Rate limiting | Enabled | Prevent DoS |

### Development Mode

Use `--dev` flag or `RUSTBERG_DEV=1` to relax security for local development:

```bash
# Local development only
./rustberg --dev --insecure-http
```

{: .warning }
> Development mode allows wildcard CORS and disables some security checks.
> **Never use `--dev` in production.**

---

## Security Best Practices

### Deployment

{: .important }
> - **Always** use TLS in production
> - **Never** expose to public internet without auth
> - **Use** private networks when possible
> - **Enable** audit logging to SIEM

### API Keys

{: .important }
> - **Never** commit keys to source control
> - **Rotate** keys every 90 days
> - **Use** separate keys per service
> - **Revoke** unused keys immediately

### KMS

{: .important }
> - **Use** cloud KMS in production
> - **Limit** IAM permissions to minimum
> - **Enable** KMS audit logging
> - **Rotate** master keys annually

### Monitoring

{: .important }
> - **Alert** on auth failures
> - **Monitor** rate limit hits
> - **Review** audit logs regularly
> - **Track** unusual access patterns

---

## Security Hardening Checklist

### Before Production

- [ ] TLS certificates configured
- [ ] Authentication enabled
- [ ] Authorization policies defined
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] KMS configured (not EnvKeyProvider)
- [ ] Network policies applied
- [ ] Secrets stored securely

### Ongoing

- [ ] API keys rotated (90 days)
- [ ] KMS keys rotated (annual)
- [ ] Dependencies updated
- [ ] Audit logs reviewed
- [ ] Access patterns monitored
- [ ] Penetration testing (annual)

---

## Vulnerability Reporting

Found a security issue? Please report responsibly:

1. **Do not** open a public GitHub issue
2. **Email** security@example.com with details
3. **Include** reproduction steps
4. **Allow** 90 days for fix before disclosure

We will:
- Acknowledge within 48 hours
- Investigate and fix promptly
- Credit researchers (if desired)
- Not pursue legal action for good-faith reports

---

## Security Hardening

Rustberg includes the following security hardening measures:

| Feature | Area | Detail |
|---------|------|--------|
| **JWKS key cache purge** | JWT Auth | Revoked signing keys are rejected within JWKS cache TTL |
| **Rate-limit peek** | Middleware | Response headers no longer consume a second rate-limit token per request |
| **DEK cache SHA-256** | KMS | Cryptographic hash for DEK cache keys eliminates collision risk |
| **Azure KV version** | KMS | Version detection uses key URL hash for reliable rotation detection |
| **IdempotencyGuard** | Idempotency | RAII guard auto-cleans in-flight entries on failure/drop |
| **JWT size limit** | JWT Auth | Tokens >16 KB rejected before parsing (DoS prevention) |
| **Optimistic concurrency** | Catalog | Table commits use version-based CAS; returns 409 on conflict |
| **Atomic transactions** | Catalog | Multi-table commits are atomic via WriteBatch |

**Deployment:** Suitable for production with single or multiple concurrent writers. Implement client-side retry with backoff for commit conflicts.

---

## Compliance

Rustberg supports compliance requirements:

| Requirement | Support |
|-------------|---------|
| SOC 2 | Audit logging, access control |
| GDPR | Data encryption, access logs |
| HIPAA | Encryption at rest/transit |
| PCI DSS | Strong encryption, access control |

{: .note }
> Compliance depends on your overall architecture. Rustberg provides building blocks.

---

## Next Steps

- [Authentication](/rustberg/docs/authentication) - Configure auth
- [Authorization](/rustberg/docs/authorization) - Cedar policies
- [Encryption](/rustberg/docs/encryption) - KMS setup
