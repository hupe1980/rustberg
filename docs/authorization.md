---
layout: default
title: Authorization
nav_order: 4
description: "Authorization with Cedar policies: RBAC, ABAC, tenant isolation"
permalink: /docs/authorization
---

# Authorization
{: .no_toc }

Fine-grained access control with Cedar policy engine.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Rustberg uses [Cedar](https://www.cedarpolicy.com/) for authorization:

- **RBAC** - Role-based access control
- **ABAC** - Attribute-based access control
- **Default Deny** - No access without explicit permission
- **Hot Reload** - Update policies without restart
- **Audit Trail** - Every decision is logged

---

## Cedar Basics

### Policy Structure

```cedar
permit(
    principal == User::"alice",
    action == Action::"read",
    resource == Table::"analytics.events"
);
```

### Key Concepts

| Concept | Description | Example |
|---------|-------------|---------|
| **Principal** | Who is requesting | `User::"alice"`, `Role::"data-reader"` |
| **Action** | What they want to do | `Action::"read"`, `Action::"write"` |
| **Resource** | What they want to access | `Table::"analytics.events"` |
| **Context** | Additional attributes | `context.ip_address` |

---

## Built-in Actions

| Action | Description | Applies To |
|--------|-------------|------------|
| `list` | List resources | Namespaces, Tables, Views |
| `read` | Read metadata | Namespaces, Tables, Views |
| `write` | Create/update | Namespaces, Tables, Views |
| `delete` | Delete resources | Namespaces, Tables, Views |
| `admin` | Administrative ops | All resources |

---

## Policy Examples

### Role-Based Access (RBAC)

```cedar
// Data readers can list and read all tables
permit(
    principal in Role::"data-reader",
    action in [Action::"list", Action::"read"],
    resource
);

// Data writers can also write
permit(
    principal in Role::"data-writer",
    action in [Action::"list", Action::"read", Action::"write"],
    resource
);

// Admins have full access
permit(
    principal in Role::"admin",
    action,
    resource
);
```

### Tenant Isolation

```cedar
// Users can only access resources in their tenant
permit(
    principal,
    action,
    resource
) when {
    principal.tenant_id == resource.tenant_id
};
```

### Namespace-Level Access

```cedar
// Analytics team can access analytics namespace
permit(
    principal in Team::"analytics",
    action,
    resource
) when {
    resource.namespace == "analytics"
};

// Data science team can read all, write to ml namespace
permit(
    principal in Team::"data-science",
    action in [Action::"list", Action::"read"],
    resource
);

permit(
    principal in Team::"data-science",
    action == Action::"write",
    resource
) when {
    resource.namespace == "ml"
};
```

### IP-Based Restrictions

```cedar
// Only allow writes from internal network
permit(
    principal,
    action == Action::"write",
    resource
) when {
    context.ip_address like "10.0.*"
};
```

### Time-Based Access

```cedar
// Allow read access during business hours only
permit(
    principal in Role::"contractor",
    action == Action::"read",
    resource
) when {
    context.hour >= 9 && context.hour < 17
};
```

---

## Configuration

### Policy File

Create a Cedar policy file:

```cedar
// policies/catalog.cedar

// Default deny (implicit, but explicit is clearer)
forbid(principal, action, resource);

// Tenant isolation (required for multi-tenant)
permit(
    principal,
    action,
    resource
) when {
    principal.tenant_id == resource.tenant_id
};

// Role-based permissions
permit(
    principal in Role::"admin",
    action,
    resource
);

permit(
    principal in Role::"data-reader",
    action in [Action::"list", Action::"read"],
    resource
);

permit(
    principal in Role::"data-writer",
    action in [Action::"list", Action::"read", Action::"write"],
    resource
);
```

### TOML Configuration

```toml
[authorization]
engine = "cedar"
policy_file = "/etc/rustberg/policies/catalog.cedar"
hot_reload = true
hot_reload_interval_secs = 30
```

### Programmatic

```rust
use rustberg::auth::CedarAuthorizer;

let authorizer = CedarAuthorizer::from_file("policies/catalog.cedar")?;

// Or from string
let policy = r#"
permit(
    principal in Role::"admin",
    action,
    resource
);
"#;
let authorizer = CedarAuthorizer::from_policy_string(policy)?;
```

---

## Entity Types

### Principal Types

```cedar
// User (from API key or JWT)
User::"alice@example.com"

// Role (assigned via API key or JWT claim)
Role::"data-reader"

// Team (from JWT claim or mapping)
Team::"analytics"

// Service (machine identity)
Service::"spark-etl"
```

### Resource Types

```cedar
// Namespace
Namespace::"analytics"

// Table (namespace.table format)
Table::"analytics.events"

// View
View::"analytics.daily_summary"

// Snapshot
Snapshot::"analytics.events:1234567890"
```

---

## Principal Attributes

Available attributes on the principal:

| Attribute | Type | Description |
|-----------|------|-------------|
| `tenant_id` | String | Tenant identifier |
| `roles` | Set | Assigned roles |
| `email` | String | User email (JWT) |
| `groups` | Set | Group memberships |

### Example

```cedar
permit(
    principal,
    action,
    resource
) when {
    principal.tenant_id == "acme-corp" &&
    "admin" in principal.roles
};
```

---

## Resource Attributes

Available attributes on resources:

| Attribute | Type | Description |
|-----------|------|-------------|
| `tenant_id` | String | Owning tenant |
| `namespace` | String | Parent namespace |
| `created_by` | String | Creator principal |
| `tags` | Set | Custom tags |

### Example

```cedar
// Only creators can delete their tables
permit(
    principal,
    action == Action::"delete",
    resource
) when {
    principal == resource.created_by
};
```

---

## Context Attributes

Request context available in policies:

| Attribute | Type | Description |
|-----------|------|-------------|
| `ip_address` | String | Client IP |
| `user_agent` | String | HTTP User-Agent |
| `request_id` | String | Unique request ID |
| `timestamp` | Long | Request time (epoch) |
| `hour` | Long | Hour of day (0-23) |

---

## Hot Reloading

Policies can be updated without restart:

```toml
[authorization]
hot_reload = true
hot_reload_interval_secs = 30
```

When enabled:
1. Rustberg watches the policy file
2. On change, policies are recompiled
3. New policies take effect immediately
4. Invalid policies are rejected (old policies continue)

### Manual Reload

```bash
# Send SIGHUP to reload policies
kill -HUP $(pgrep rustberg)
```

---

## Audit Logging

Every authorization decision is logged:

### Permit

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "authz_permit",
  "principal": "alice@example.com",
  "action": "read",
  "resource": "Table::analytics.events",
  "policy": "data-reader-access",
  "duration_us": 45
}
```

### Deny

```json
{
  "timestamp": "2026-01-24T12:00:01Z",
  "event": "authz_deny",
  "principal": "bob@example.com",
  "action": "delete",
  "resource": "Table::analytics.events",
  "reason": "no matching permit policy",
  "duration_us": 23
}
```

---

## Best Practices

### 1. Start with Deny-All

```cedar
// Explicit deny-all (good for documentation)
forbid(principal, action, resource)
unless {
    // Explicit permits below will override
    false
};
```

### 2. Enforce Tenant Isolation

```cedar
// ALWAYS include tenant check
permit(principal, action, resource)
when {
    principal.tenant_id == resource.tenant_id
};
```

### 3. Use Roles, Not Users

```cedar
// ❌ Bad: User-specific policy
permit(principal == User::"alice", action, resource);

// ✅ Good: Role-based policy
permit(principal in Role::"admin", action, resource);
```

### 4. Principle of Least Privilege

```cedar
// ❌ Bad: Broad permissions
permit(principal in Role::"user", action, resource);

// ✅ Good: Specific permissions
permit(
    principal in Role::"user",
    action in [Action::"list", Action::"read"],
    resource
);
```

### 5. Log and Monitor

- Enable audit logging
- Alert on unusual deny patterns
- Review policies regularly

---

## Troubleshooting

### "403 Forbidden" Errors

1. Check the audit log for the deny reason
2. Verify the principal has correct roles
3. Ensure tenant_id matches
4. Test the policy in isolation:

```bash
# Use Cedar CLI to test policies
cedar evaluate \
  --policies policies/catalog.cedar \
  --principal 'User::"alice"' \
  --action 'Action::"read"' \
  --resource 'Table::"analytics.events"'
```

### Policy Syntax Errors

```bash
# Validate policy syntax
cedar validate --policies policies/catalog.cedar
```

### Performance Issues

Cedar policies are compiled and cached. If you have thousands of policies:

1. Consolidate similar policies
2. Use attribute-based rules instead of explicit lists
3. Consider policy sharding by tenant

---

## Next Steps

- [Authentication Guide](/rustberg/docs/authentication) - How principals are identified
- [API Reference](/rustberg/docs/api) - Endpoint permissions
- [Security Model](/rustberg/docs/security) - Defense in depth
