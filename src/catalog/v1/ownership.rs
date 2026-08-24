//! Namespace ownership tracking.
//!
//! Every namespace records the tenant that owns it. Ownership is what the
//! authorizer compares the caller's tenant against, so it decides cross-tenant
//! access for the namespace and for every table and view inside it.
//!
//! # Why ownership lives in properties
//!
//! The `Catalog` trait exposes namespace properties as the only per-namespace
//! key/value channel, so ownership is stored there under a reserved key. That is
//! only safe if clients cannot write the key themselves — otherwise
//! `POST /v1/namespaces/{ns}/properties` would be a tenant-takeover primitive:
//! setting `_tenant_id` to another tenant hands the namespace over, and removing
//! it makes the namespace unowned and therefore visible to every tenant.
//!
//! This module is the single place that enforces the invariant:
//!
//! - [`reject_reserved`] refuses client writes to any reserved key.
//! - [`strip_reserved`] removes reserved keys from responses.
//! - [`preserve_reserved`] carries server-managed keys across a property update.
//!
//! Handlers must route all namespace property traffic through these functions.
//!
//! Reading ownership for an authorization decision is not done here — that is
//! [`guard`](super::guard), which pairs the lookup with the policy check so the
//! two cannot drift apart or leak existence through their status codes.

use std::collections::HashMap;

use crate::error::{AppError, Result};

/// Prefix marking property keys that only the server may write.
///
/// Reserving a whole prefix (rather than a fixed list of keys) means new
/// server-managed properties cannot accidentally become client-writable.
pub const RESERVED_PROPERTY_PREFIX: &str = "rustberg.internal.";

/// Reserved property key holding the owning tenant's ID.
pub const TENANT_ID_PROPERTY: &str = "rustberg.internal.tenant-id";

/// Property marking a table, view or namespace as protected from deletion.
///
/// Set it to `true` and `dropTable`, `dropView`, `dropNamespace` and a purge are
/// refused with `409` until it is cleared.
///
/// # Deliberately *not* reserved, and deliberately not a security control
///
/// A caller who may set this may also clear it, because it is an ordinary
/// property written through `updateProperties` and `commitTable`. So it stops an
/// accident, not an adversary: the `DROP TABLE` typed against the wrong catalog,
/// the migration script pointed at prod, the cleanup job whose filter matched
/// one row too many. Every one of those is a *second* deliberate step away from
/// being possible, and none of them takes it.
///
/// Making it reserved — server-managed, unwritable by clients — would mean
/// protection could only ever be turned on, since the same handler that refuses
/// client writes to `rustberg.internal.*` would refuse the write that lifts it.
/// Gating it behind a separate action would be the real control, and would also
/// be a second authorization vocabulary for one boolean; `Delete` on the
/// resource is already the permission that decides whether it may be dropped at
/// all. Anyone who wants a hard stop writes a Cedar `forbid`, which is what that
/// is for and which the holder of the property cannot edit.
pub const PROTECTED_PROPERTY: &str = "rustberg.protected";

/// Whether `properties` marks the resource as protected from deletion.
///
/// Only the exact string `true`, case-insensitively and ignoring surrounding
/// whitespace. Anything else — `"yes"`, `"1"`, `""` — is not protection: a
/// value that looks like it might mean protected and does not is worse than an
/// absent one, because the operator believes the resource is safe.
pub fn is_protected(properties: &HashMap<String, String>) -> bool {
    properties
        .get(PROTECTED_PROPERTY)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

/// Refuses a deletion when `properties` marks the resource protected.
///
/// # Errors
///
/// [`AppError::Protected`] naming the property to clear. `409` rather than `403`:
/// the caller *is* permitted — the resource is in a state that forbids the
/// operation, and the fix is one property write rather than a policy change.
pub fn reject_if_protected(properties: &HashMap<String, String>, what: &str) -> Result<()> {
    if !is_protected(properties) {
        return Ok(());
    }
    Err(AppError::Protected(format!(
        "{what} is protected from deletion. Clear the '{PROTECTED_PROPERTY}' property \
         first, then retry."
    )))
}

/// Returns true if `key` is server-managed and must never be set by a client.
pub fn is_reserved(key: &str) -> bool {
    key.starts_with(RESERVED_PROPERTY_PREFIX)
}

/// Rejects client-supplied properties that target the reserved namespace.
///
/// # Errors
///
/// Returns [`AppError::BadRequest`] naming the first reserved key found.
pub fn reject_reserved<'a>(keys: impl IntoIterator<Item = &'a String>) -> Result<()> {
    for key in keys {
        if is_reserved(key) {
            return Err(AppError::BadRequest(format!(
                "Property key '{key}' is reserved: keys starting with \
                 '{RESERVED_PROPERTY_PREFIX}' are managed by the server"
            )));
        }
    }
    Ok(())
}

/// Removes every reserved key from a property map before it is returned to a client.
pub fn strip_reserved(properties: &mut HashMap<String, String>) {
    properties.retain(|key, _| !is_reserved(key));
}

/// Copies the server-managed properties of `current` into `next`.
///
/// Called after applying a client's removals and updates, so reserved keys
/// survive a property update regardless of what the client asked for.
pub fn preserve_reserved(current: &HashMap<String, String>, next: &mut HashMap<String, String>) {
    next.retain(|key, _| !is_reserved(key));
    for (key, value) in current {
        if is_reserved(key) {
            next.insert(key.clone(), value.clone());
        }
    }
}

/// Stamps a namespace's owning tenant into a freshly created property map.
pub fn set_owner(properties: &mut HashMap<String, String>, tenant_id: &str) {
    properties.insert(TENANT_ID_PROPERTY.to_string(), tenant_id.to_string());
}

/// Reads the owning tenant out of a namespace's properties.
///
/// Namespaces created before ownership tracking existed have no owner recorded.
/// Those are reported as unowned so the caller can decide the policy rather than
/// silently defaulting to the caller's own tenant, which would let any tenant
/// claim them.
pub fn owner_of(properties: &HashMap<String, String>) -> Option<&str> {
    properties.get(TENANT_ID_PROPERTY).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn tenant_id_key_is_reserved() {
        assert!(is_reserved(TENANT_ID_PROPERTY));
    }

    #[test]
    fn ordinary_keys_are_not_reserved() {
        assert!(!is_reserved("owner"));
        assert!(!is_reserved("location"));
        // The legacy key is no longer special; it is an ordinary client property.
        assert!(!is_reserved("_tenant_id"));
    }

    #[test]
    fn reject_reserved_blocks_ownership_writes() {
        let keys = [TENANT_ID_PROPERTY.to_string()];
        let err = reject_reserved(keys.iter()).unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn reject_reserved_allows_ordinary_keys() {
        let keys = ["owner".to_string(), "comment".to_string()];
        assert!(reject_reserved(keys.iter()).is_ok());
    }

    #[test]
    fn strip_reserved_hides_ownership_from_responses() {
        let mut p = props(&[(TENANT_ID_PROPERTY, "acme"), ("owner", "alice")]);
        strip_reserved(&mut p);
        assert_eq!(p, props(&[("owner", "alice")]));
    }

    #[test]
    fn preserve_reserved_survives_client_removal() {
        let current = props(&[(TENANT_ID_PROPERTY, "acme"), ("owner", "alice")]);
        // Client removed everything, including the reserved key.
        let mut next = HashMap::new();
        preserve_reserved(&current, &mut next);
        assert_eq!(owner_of(&next), Some("acme"));
    }

    #[test]
    fn preserve_reserved_overrides_client_forgery() {
        let current = props(&[(TENANT_ID_PROPERTY, "acme")]);
        // Client tried to hand the namespace to another tenant.
        let mut next = props(&[(TENANT_ID_PROPERTY, "attacker")]);
        preserve_reserved(&current, &mut next);
        assert_eq!(owner_of(&next), Some("acme"));
    }

    #[test]
    fn owner_of_reports_unowned() {
        assert_eq!(owner_of(&props(&[("owner", "alice")])), None);
    }
    // ── Protection ──────────────────────────────────────────────────────

    #[test]
    fn only_the_word_true_protects() {
        assert!(is_protected(&props(&[(PROTECTED_PROPERTY, "true")])));
        assert!(is_protected(&props(&[(PROTECTED_PROPERTY, "TRUE")])));
        assert!(is_protected(&props(&[(PROTECTED_PROPERTY, " true ")])));

        // A value that looks like it might mean protected and does not is worse
        // than an absent one: the operator believes the table is safe.
        for value in ["yes", "1", "on", "", "false", "True!"] {
            assert!(
                !is_protected(&props(&[(PROTECTED_PROPERTY, value)])),
                "{value:?} must not read as protection"
            );
        }
        assert!(!is_protected(&props(&[("other", "true")])));
    }

    #[test]
    fn a_protected_resource_is_refused_with_a_conflict() {
        let err = reject_if_protected(&props(&[(PROTECTED_PROPERTY, "true")]), "Table 'db.t'")
            .unwrap_err();

        assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
        assert!(
            err.to_string().contains("db.t"),
            "names the resource: {err}"
        );
        assert!(
            err.to_string().contains(PROTECTED_PROPERTY),
            "names the property to clear: {err}"
        );
    }

    #[test]
    fn an_unprotected_resource_is_not_refused() {
        assert!(reject_if_protected(&props(&[("owner", "alice")]), "Table 'db.t'").is_ok());
    }

    /// Protection is an ordinary property, so it survives a property update the
    /// way any other does — and can be cleared the same way. It is not reserved.
    #[test]
    fn protection_is_a_client_property_not_a_reserved_one() {
        assert!(!is_reserved(PROTECTED_PROPERTY));
        assert!(reject_reserved([PROTECTED_PROPERTY.to_string()].iter()).is_ok());
    }
}
