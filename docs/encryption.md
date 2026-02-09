---
layout: default
title: Encryption
nav_order: 6
description: "Encryption at rest with KMS: AWS KMS, HashiCorp Vault, GCP, Azure"
permalink: /docs/encryption
---

# Encryption
{: .no_toc }

Protect sensitive data with envelope encryption and KMS integration.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Rustberg implements **defense-in-depth** encryption:

| Layer | Protection | Implementation |
|-------|------------|----------------|
| **In Transit** | Network traffic | TLS 1.3 (rustls) |
| **At Rest** | Stored data | AES-256-GCM |
| **In Memory** | Secrets | Zeroize on drop |
| **Key Management** | Master keys | KMS providers |

---

## Encryption at Rest

### What's Encrypted

| Data | Encrypted | Notes |
|------|-----------|-------|
| API key metadata | ✅ | Name, tenant, roles |
| Table properties | ✅ | With EncryptedCatalog |
| Namespace properties | ✅ | With EncryptedCatalog |
| Index data | ❌ | Performance optimization |

### Algorithm

- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits, random per encryption
- **Tag**: 128 bits (authentication)

---

## KMS Providers

Rustberg supports 5 KMS providers:

| Provider | Feature Flag | Use Case |
|----------|--------------|----------|
| **EnvKeyProvider** | Default | Development |
| **AWS KMS** | `aws-kms` | AWS production |
| **HashiCorp Vault** | `vault-kms` | Multi-cloud |
| **GCP Cloud KMS** | `gcp-kms` | GCP production |
| **Azure Key Vault** | `azure-kms` | Azure production |

---

## EnvKeyProvider (Development)

Simple key provider using environment variable:

```bash
# Generate 32-byte key (base64)
export RUSTBERG_MASTER_KEY=$(openssl rand -base64 32)

# Start Rustberg
./rustberg --storage file:///data
```

### Configuration

```toml
[kms]
provider = "env"
key_env_var = "RUSTBERG_MASTER_KEY"
```

{: .warning }
> EnvKeyProvider is for development only. Use cloud KMS in production.

---

## AWS KMS

### Prerequisites

1. Create a KMS key in AWS Console
2. Configure IAM permissions

### IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789:key/your-key-id"
    }
  ]
}
```

### Configuration

```toml
[kms]
provider = "aws"
key_id = "arn:aws:kms:us-east-1:123456789:key/your-key-id"
aws_region = "us-east-1"
```

### Environment Variables

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1
```

---

## HashiCorp Vault

### Prerequisites

1. Running Vault instance
2. Transit secrets engine enabled
3. Named encryption key created

### Vault Setup

```bash
# Enable Transit engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/rustberg-key

# Create policy
vault policy write rustberg - <<EOF
path "transit/encrypt/rustberg-key" {
  capabilities = ["update"]
}
path "transit/decrypt/rustberg-key" {
  capabilities = ["update"]
}
EOF

# Create token
vault token create -policy=rustberg
```

### Configuration

```toml
[kms]
provider = "vault"
vault_addr = "https://vault.example.com:8200"
vault_token_env = "VAULT_TOKEN"
key_name = "rustberg-key"
transit_mount = "transit"
```

> **Important:** The `VAULT_TOKEN` environment variable **must** be set when using the Vault provider.
> Rustberg will refuse to start if this variable is missing — there is no fallback to a default token.

---

## GCP Cloud KMS

### Prerequisites

1. Create a key ring and crypto key in GCP Console
2. Configure service account permissions

### IAM Permissions

```bash
gcloud kms keys add-iam-policy-binding rustberg-key \
  --keyring=rustberg-keyring \
  --location=global \
  --member=serviceAccount:rustberg@project.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```

### Configuration

```toml
[kms]
provider = "gcp"
project_id = "your-project"
location = "global"
key_ring = "rustberg-keyring"
crypto_key = "rustberg-key"
```

---

## Azure Key Vault

### Prerequisites

1. Create a Key Vault in Azure Portal
2. Create an RSA key for encryption
3. Configure access policies

### Configuration

```toml
[kms]
provider = "azure"
vault_url = "https://rustberg-vault.vault.azure.net"
key_name = "rustberg-key"
```

### Environment Variables

```bash
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id
```

---

## Envelope Encryption

Rustberg uses **envelope encryption** for efficiency:

```
┌─────────────────────────────────────────────────────────┐
│                  Envelope Encryption                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. Generate random Data Encryption Key (DEK)           │
│     DEK = random(32 bytes)                              │
│                                                          │
│  2. Encrypt data with DEK (fast, local)                 │
│     ciphertext = AES-256-GCM(data, DEK)                 │
│                                                          │
│  3. Wrap DEK with KMS (one API call)                    │
│     wrapped_dek = KMS.encrypt(DEK)                      │
│                                                          │
│  4. Store: ciphertext + wrapped_dek                     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Benefits

| Benefit | Why |
|---------|-----|
| **Performance** | AES-GCM is fast (hardware accelerated) |
| **Reduced KMS calls** | One wrap/unwrap per DEK, not per record |
| **Key rotation** | Re-wrap DEKs without re-encrypting data |
| **Cost** | Fewer KMS API calls |
| **Integrity** | DEK cache keyed by SHA-256 of ciphertext for collision resistance |

---

## KMS Monitoring

When table encryption is enabled, Rustberg exports KMS metrics to the `/metrics` endpoint:

```text
# KMS operation counts
rustberg_kms_operations_total{operation="generate_key"} 42
rustberg_kms_operations_total{operation="decrypt_key"} 1234
rustberg_kms_operations_total{operation="encrypt_key"} 0

# Cache efficiency
rustberg_kms_cache_total{result="hit"} 1192
rustberg_kms_cache_total{result="miss"} 42

# Error and retry tracking
rustberg_kms_errors_total 3
rustberg_kms_retries_total 5
```

These metrics help you:
- Monitor KMS API usage for cost optimization
- Track cache hit rates (higher is better)
- Alert on elevated error rates
- Debug KMS connectivity issues

---

## TLS Configuration

### Self-Signed (Development)

```bash
# Generate self-signed certificate
./rustberg generate-cert --common-name localhost

# Start with the generated certificate
./rustberg \
  --tls-cert ./cert.pem \
  --tls-key ./key.pem
```

### Custom Certificates

```bash
./rustberg \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

{: .security }
> TLS is **required** in production. Use `--insecure-http` only for development.

---

## Memory Protection

### SecretBytes

Sensitive data uses `SecretBytes` wrapper:

```rust
use rustberg::crypto::secrets::SecretBytes;

let secret = SecretBytes::new(api_key.as_bytes());
// Secret is automatically zeroed when dropped
```

### Properties

| Property | Implementation |
|----------|----------------|
| **Zeroize on drop** | Memory cleared when out of scope |
| **No Debug** | Cannot accidentally log secrets |
| **No Clone** | Prevents uncontrolled copies |

---

## Security Best Practices

### Key Management

{: .important }
> - **Never** store keys in source control
> - **Use** cloud KMS in production
> - **Rotate** keys annually minimum
> - **Audit** key usage via KMS logs

### Network Security

{: .important }
> - **Always** use TLS in production
> - **Validate** server certificates
> - **Use** private networks when possible

---

## Next Steps

- [Authentication](/rustberg/docs/authentication) - Secure access
- [Storage Backends](/rustberg/docs/storage) - Persistent storage
- [API Reference](/rustberg/docs/api) - REST API documentation
