//! What a namespace, table or view may be called.
//!
//! # The rule, and where it comes from
//!
//! A name is not free-form, because it is used as three things at once, and each
//! use rules something out:
//!
//! | Used as | Rules out |
//! |---|---|
//! | A **path segment** in the table's storage location | `/`, `\`, `.`, `..` |
//! | A **segment of a Cedar entity id**, joined with `\u{1F}` | the unit separator, and every other character in general category `C` |
//! | A **field in an audit record** and a log line | the same, again |
//!
//! Plus a length bound, because every one of those is written somewhere with a
//! limit and because an unbounded name is an unbounded row.
//!
//! # Two names that render the same must not be two resources
//!
//! The second row is where an authorization layer differs from a database. A
//! Cedar policy names a resource by an id built from these segments, so a policy
//! that *appears* to cover a table and does not is the failure mode this crate
//! exists to prevent. Two spellings that display identically are refused:
//!
//! - **Invisible and directional characters.** `char::is_control` covers general
//!   category `Cc` and lets through `Cf`, which is where the hazard is:
//!   zero-width space, soft hyphen, the byte-order mark, and the bidirectional
//!   overrides. `events` and `events\u{200B}` are two tables no reviewer reading
//!   the policy file can tell apart. Refusing the whole `C` group covers
//!   private-use and unassigned code points too.
//! - **Normalization.** `café` is `caf\u{E9}` in NFC and `cafe\u{301}` in NFD:
//!   different keys, different entity ids, different storage paths. NFC is
//!   required and the others are *refused* rather than rewritten — a client that
//!   asked to create one name and got another back has been lied to — with the
//!   accepted spelling in the error.
//!
//! Both are the trailing-whitespace refusal below, generalised. Neither is a
//! homoglyph or mixed-script check: `а` (Cyrillic) and `a` are different letters
//! a legitimate deployment may both use.
//!
//! # And nothing beyond that
//!
//! An *allowlist* of ASCII alphanumerics, `_`, `-` and `.` is a far stronger
//! claim than anything above needs, and it rejects names Iceberg permits and
//! real deployments have: `分析.売上` and `café_visits` are legitimate tables.
//! Every engine, every object store and all three uses above handle UTF-8.
//!
//! Filesystem folklore is out for the same reason. **Windows device names**
//! (`CON`, `LPT1`, …) fail loudly at write time, on the one warehouse kind where
//! they fail at all. **A leading dot** makes a hidden file, and nothing here
//! depends on seeing it in `ls`. Neither is a security control, and enforcing
//! them costs interoperability to buy the appearance of rigour.

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

use crate::error::{AppError, Result};

/// The character that joins namespace parts, everywhere they are joined.
///
/// # Why it lives here
///
/// It is joined in six places that must agree character for character: the path
/// a request arrives on (`catalog::v1::extract`), the Cedar entity id a policy
/// names (`crate::auth`), the key both registries store
/// (`catalog::redb`, `catalog::postgres`), the path a `rest` mount sends to
/// somebody else's catalog (`catalog::rest`), the `?parent=` a listing filters
/// on, and the signer endpoint a `loadTable` hands back. Two of those disagreeing
/// is not a formatting bug: the entity id a policy names and the entity id a
/// request builds would be different strings, which is invariant 10 failing
/// silently and in the permissive direction.
///
/// It lives in this module because this module is the reason it can be used as a
/// separator at all — [`validate_name`] refuses general category `C`, which
/// includes this character, so no validated name can contain one and the
/// encoding is injective. Rule and reason in one file; the alternative is a
/// constant in one subsystem that five others reach into, which is the copy this
/// exists to prevent.
///
/// A unit separator and never `.`: a dotted key is ambiguous, because a
/// namespace literally named `a.b` and the nested namespace `a` → `b` render
/// identically, and in an authorization layer that ambiguity is a vulnerability
/// rather than a cosmetic flaw.
pub const PART_SEPARATOR: char = '\u{1F}';

/// Separates a namespace from the table or view name inside a stored key.
///
/// A record separator, which sorts *before* [`PART_SEPARATOR`], so a namespace's
/// own tables come before its child namespaces' in one byte-ordered scan. Held
/// to the same rule for the same reason: a validated name cannot contain it.
pub const NAME_SEPARATOR: char = '\u{1E}';

/// Maximum length of a name, in **characters**.
///
/// Characters rather than bytes, so the limit means the same thing for every
/// script. A name of 255 characters is at most 1020 bytes of UTF-8, which is
/// inside every limit downstream — an S3 key is capped at 1024 bytes per
/// *object*, and a name is one segment of one.
pub const MAX_NAME_LENGTH: usize = 255;

/// Maximum depth for hierarchical namespaces.
pub const MAX_NAMESPACE_DEPTH: usize = 10;

/// Maximum number of properties that can be set on a namespace or table.
pub const MAX_PROPERTIES_COUNT: usize = 100;

/// Maximum length for a property key.
pub const MAX_PROPERTY_KEY_LENGTH: usize = 255;

/// Maximum length for a property value.
pub const MAX_PROPERTY_VALUE_LENGTH: usize = 4096;

/// Characters that cannot appear in a name, whatever else it contains.
///
/// `/` and `\` are path separators in the storage location a name becomes part
/// of; a name carrying one would place a table somewhere other than where the
/// catalog recorded it, which is the confused-deputy hazard
/// [`crate::location`] exists to close, arriving through the front door.
const FORBIDDEN_IN_NAME: &[char] = &['/', '\\'];

/// Validates a single name segment (namespace level, table name, or view name).
///
/// # Errors
///
/// [`AppError::BadRequest`] naming what was wrong. See the module docs for the
/// rule and for what is deliberately *not* checked.
pub fn validate_name(name: &str, context: &str) -> Result<()> {
    if name.is_empty() {
        return Err(AppError::BadRequest(format!("{context} cannot be empty")));
    }

    // Counted in characters; see `MAX_NAME_LENGTH`.
    if name.chars().count() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "{context} exceeds maximum length of {MAX_NAME_LENGTH} characters"
        )));
    }

    // General category `C`: control (`Cc`), format (`Cf`), surrogate (`Cs`),
    // private use (`Co`) and unassigned (`Cn`). `Cc` covers NUL and the unit
    // separator the Cedar entity encoding depends on; `Cf` covers the invisible
    // and directional characters that make two names render identically. See
    // the module docs for why the wider group and not just `is_control`.
    if let Some(found) = name
        .chars()
        .find(|c| c.general_category_group() == GeneralCategoryGroup::Other)
    {
        return Err(AppError::BadRequest(format!(
            "{context} contains U+{:04X}, which is a control, formatting, private-use or \
             unassigned character. Names are compared byte for byte by the policy engine, so \
             a character that renders as nothing would make two different resources look like \
             one.",
            found as u32
        )));
    }

    // Unicode normalization, for the same reason as the whitespace check below:
    // two spellings that render identically must not be two resources.
    // `is_nfc_quick` answers `Maybe` for text it cannot decide from the quick
    // -check property alone, which is why the definitive comparison follows it
    // rather than replacing it: the quick check settles the overwhelming
    // majority of names without allocating.
    if is_nfc_quick(name.chars()) != IsNormalized::Yes {
        let normalized: String = name.nfc().collect();
        if normalized != name {
            return Err(AppError::BadRequest(format!(
                "{context} is not in Unicode normalization form NFC. Write it as \
                 '{normalized}', which is the same text in the form this catalog stores and \
                 the policy engine compares."
            )));
        }
    }

    if let Some(found) = name.chars().find(|c| FORBIDDEN_IN_NAME.contains(c)) {
        return Err(AppError::BadRequest(format!(
            "{context} contains '{found}', which is a path separator in the storage \
             location this name becomes part of"
        )));
    }

    // `.` and `..` are the two path segments that do not name a directory. Only
    // as *whole* segments: `..` inside a name — `a..b` — resolves to nothing and
    // is an ordinary name.
    if name == "." || name == ".." {
        return Err(AppError::BadRequest(format!(
            "{context} cannot be '{name}', which names a directory rather than a table"
        )));
    }

    // Leading and trailing whitespace survives round-tripping and makes two
    // visually identical names distinct — which in an authorization layer means
    // a policy that appears to cover a table and does not.
    if name.trim() != name {
        return Err(AppError::BadRequest(format!(
            "{context} has leading or trailing whitespace"
        )));
    }

    Ok(())
}

/// Validates a namespace identifier (list of name segments).
///
/// # Errors
///
/// Returns an error if:
/// - Namespace is empty
/// - Namespace exceeds maximum depth
/// - Any segment fails validation
pub fn validate_namespace(namespace: &[String]) -> Result<()> {
    if namespace.is_empty() {
        return Err(AppError::BadRequest(
            "Namespace cannot be empty".to_string(),
        ));
    }

    if namespace.len() > MAX_NAMESPACE_DEPTH {
        return Err(AppError::BadRequest(format!(
            "Namespace exceeds maximum depth of {MAX_NAMESPACE_DEPTH} levels"
        )));
    }

    for (i, segment) in namespace.iter().enumerate() {
        validate_name(segment, &format!("Namespace segment {}", i + 1))?;
    }

    Ok(())
}

/// Validates a table name.
pub fn validate_table_name(name: &str) -> Result<()> {
    validate_name(name, "Table name")
}

/// Validates a **tenant id**, which is a name in every sense above.
///
/// # Why an identity is checked by the same rule as a table
///
/// A tenant id is the *first segment* of every Cedar entity id the authorizer
/// builds: `Table::"acme␟analytics␟web␟events"` starts with the tenant. So it is
/// a path segment joined with `␟`, and the injectivity the whole module exists
/// for depends on it as much as on the table's own name.
///
/// It arrives from a **JWT claim**, which is the part that is easy to miss. Every
/// other input to that id comes through a request path and was validated on the
/// way in; this one comes through a token, where nothing had looked at it. A
/// tenant called `acme␟analytics` produces the same entity ids as tenant `acme`'s
/// namespace `analytics`, so a policy written for one silently covers the other —
/// the exact failure the module docs describe, arriving from the identity side
/// instead of the resource side.
///
/// # Errors
///
/// [`AppError::BadRequest`] naming what was wrong. Reported to the caller as a
/// rejected credential: the token is well-formed and signed, and still cannot be
/// turned into a principal this catalog can reason about.
pub fn validate_tenant_id(tenant: &str) -> Result<()> {
    validate_name(tenant, "Tenant id")
}

/// Validates a **principal id** — a JWT `sub`, or an API key's name.
///
/// # A weaker rule than a name, deliberately
///
/// A principal id becomes `User::"<id>"` and is never joined into a path, so the
/// separator and path-segment rules that apply to a tenant do not apply here.
/// Refusing `/` would reject the URL-shaped subjects some identity providers
/// issue, for no gain.
///
/// What does apply is everything about *rendering*: the id is written into every
/// audit record and every log line, and a `sub` carrying a newline forges a log
/// entry while one carrying `\u{202E}` reverses the rest of the line. General
/// category `C` covers both, and NFC keeps two spellings of one subject from
/// being two principals in the trail.
///
/// # Errors
///
/// [`AppError::BadRequest`] naming what was wrong.
pub fn validate_principal_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(AppError::BadRequest(
            "Principal id cannot be empty".to_string(),
        ));
    }

    if id.chars().count() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Principal id exceeds maximum length of {MAX_NAME_LENGTH} characters"
        )));
    }

    if let Some(found) = id
        .chars()
        .find(|c| c.general_category_group() == GeneralCategoryGroup::Other)
    {
        return Err(AppError::BadRequest(format!(
            "Principal id contains U+{:04X}, which is a control, formatting, private-use \
             or unassigned character. Every audit record and log line names the \
             principal, and a character that renders as nothing — or reverses what \
             follows it — makes that record unreadable or misleading.",
            found as u32
        )));
    }

    if is_nfc_quick(id.chars()) != IsNormalized::Yes {
        let normalized: String = id.nfc().collect();
        if normalized != id {
            return Err(AppError::BadRequest(
                "Principal id is not in Unicode normalization form NFC, so two spellings \
                 of one subject would be two principals in the audit trail."
                    .to_string(),
            ));
        }
    }

    if id.trim() != id {
        return Err(AppError::BadRequest(
            "Principal id has leading or trailing whitespace".to_string(),
        ));
    }

    Ok(())
}

/// Whether a **role** can be represented as a Cedar `Group` id.
///
/// # The third thing from a token that becomes an entity id
///
/// [`validate_tenant_id`] and [`validate_principal_id`] exist because a claim
/// becomes part of an entity id, and an entity id is what a policy names. A role
/// is the third: `roles_claim` yields `Group::"analysts"`, and
/// `permit(principal in Rustberg::Group::"analysts", …)` matches on that string
/// byte for byte.
///
/// So the same hazard applies — `analysts` and `analysts\u{200B}` are two groups
/// no reviewer reading the policy file can tell apart — and a role is written
/// into log lines, where `\u{202E}` reverses the rest of one.
///
/// # It is *dropped* rather than refused
///
/// A bad tenant or subject fails the credential: each is load-bearing, and
/// neither has a safe partial answer. A role is one grant among several, and an
/// unrepresentable one grants *nothing* — no policy names a string with an
/// invisible character in it — so dropping it is the deny-by-default direction,
/// where failing the credential would lock a caller out over a claim it does not
/// control.
///
/// Returns the code point that made the role unusable, for a caller that wants
/// to say so without echoing the value into the log it is protecting.
pub fn unusable_role_char(role: &str) -> Option<char> {
    if role.is_empty() || role.chars().count() > MAX_NAME_LENGTH {
        return Some('\u{0}');
    }

    if let Some(found) = role
        .chars()
        .find(|c| c.general_category_group() == GeneralCategoryGroup::Other)
    {
        return Some(found);
    }

    if is_nfc_quick(role.chars()) != IsNormalized::Yes && role.nfc().collect::<String>() != role {
        // No single character is at fault; name the first one that composes.
        return role.chars().find(|c| !c.is_ascii());
    }

    if role.trim() != role {
        return Some(' ');
    }

    None
}

/// The roles of `claimed` that can be represented, with the rest dropped and
/// reported.
///
/// `source` names where the roles came from, for the warning. See
/// [`unusable_role_char`] for why this drops rather than refuses.
pub fn usable_roles(claimed: Vec<String>, source: &str) -> Vec<String> {
    claimed
        .into_iter()
        .filter(|role| match unusable_role_char(role) {
            None => true,
            Some(found) => {
                // The role itself is never logged: it is the value whose
                // rendering is in question, and echoing it here would put the
                // thing being defended against into the line meant to report it.
                tracing::warn!(
                    source = %source,
                    code_point = format!("U+{:04X}", found as u32),
                    length = role.chars().count(),
                    "Dropping a role that cannot be a Cedar group id. It contains a \
                     control, formatting, private-use or unassigned character, is not in \
                     normalization form NFC, is empty, or is too long — so no policy could \
                     name it, and it would render misleadingly in this log. The principal \
                     keeps its other roles."
                );
                false
            }
        })
        .collect()
}

/// Validates a properties map.
///
/// # Errors
///
/// Returns an error if:
/// - Too many properties
/// - Any key exceeds maximum length
/// - Any value exceeds maximum length
pub fn validate_properties(properties: &std::collections::HashMap<String, String>) -> Result<()> {
    if properties.len() > MAX_PROPERTIES_COUNT {
        return Err(AppError::BadRequest(format!(
            "Too many properties (max: {MAX_PROPERTIES_COUNT})"
        )));
    }

    for (key, value) in properties {
        if key.len() > MAX_PROPERTY_KEY_LENGTH {
            return Err(AppError::BadRequest(format!(
                "Property key '{key}' exceeds maximum length of {MAX_PROPERTY_KEY_LENGTH}"
            )));
        }
        if value.len() > MAX_PROPERTY_VALUE_LENGTH {
            return Err(AppError::BadRequest(format!(
                "Property value for key '{key}' exceeds maximum length of {MAX_PROPERTY_VALUE_LENGTH}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole encoding rests on this: a validated name cannot contain either
    /// separator, so joining parts with one is injective and truncating an
    /// entity id back to its parent is exact.
    ///
    /// Both are general category `C`, so this follows from the rule rather than
    /// from a special case — which is why they live in this module. If somebody
    /// ever picked a printable separator, this is the test that would say so.
    #[test]
    fn a_validated_name_cannot_contain_either_separator() {
        for separator in [PART_SEPARATOR, NAME_SEPARATOR] {
            assert!(
                validate_name(&format!("ev{separator}ents"), "Table name").is_err(),
                "U+{:04X} must be refused in a name, or the encoding is not injective",
                separator as u32
            );
            assert!(
                validate_principal_id(&format!("svc{separator}etl")).is_err(),
                "and in a subject, which becomes a User entity id"
            );
            assert_eq!(
                unusable_role_char(&format!("anal{separator}ysts")),
                Some(separator),
                "and in a role, which becomes a Group entity id"
            );
        }
    }

    /// A namespace's own tables have to come before its child namespaces' in one
    /// byte-ordered scan, which is what makes a listing a single range seek.
    #[test]
    fn a_name_sorts_before_a_nested_namespace() {
        assert!(
            NAME_SEPARATOR < PART_SEPARATOR,
            "the record separator must sort before the unit separator"
        );
    }
    use std::collections::HashMap;

    // ── Roles ─────────────────────────────────────────────────────────────

    /// A role becomes `Group::"…"`, so it carries the same hazard as the tenant
    /// and the subject.
    #[test]
    fn a_role_that_cannot_be_a_group_id_is_reported() {
        assert_eq!(unusable_role_char("analysts"), None);
        assert_eq!(unusable_role_char("eu-analysts_2"), None);
        assert_eq!(
            unusable_role_char("分析"),
            None,
            "the rest of Unicode is fine"
        );

        // Zero-width space: `analysts` and this render identically, and a
        // reviewer reading a policy file cannot tell them apart.
        assert_eq!(unusable_role_char("analysts\u{200B}"), Some('\u{200B}'));
        // Right-to-left override reverses the rest of a log line.
        assert_eq!(unusable_role_char("\u{202E}stsylana"), Some('\u{202E}'));
        // The unit separator the entity encoding depends on.
        assert_eq!(unusable_role_char("a\u{1F}b"), Some('\u{1F}'));
        assert!(unusable_role_char("").is_some());
        assert!(unusable_role_char(&"x".repeat(MAX_NAME_LENGTH + 1)).is_some());
        assert!(unusable_role_char(" analysts ").is_some());
        // NFD: same glyphs, different bytes, so a policy naming the NFC
        // spelling would not match.
        assert!(unusable_role_char("cafe\u{301}").is_some());
        assert_eq!(
            unusable_role_char("caf\u{E9}"),
            None,
            "NFC is the accepted form"
        );
    }

    /// One unusable role costs its own grant and nothing else. Failing the whole
    /// credential would turn one malformed group in a large directory into a
    /// total lockout, for a claim the caller does not control.
    #[test]
    fn an_unusable_role_is_dropped_and_the_rest_survive() {
        let kept = usable_roles(
            vec![
                "analysts".to_string(),
                "admin\u{200B}".to_string(),
                "writers".to_string(),
            ],
            "roles",
        );
        assert_eq!(kept, vec!["analysts".to_string(), "writers".to_string()]);
    }

    // ── Identities ────────────────────────────────────────────────────────

    /// The tenant id is the first segment of every Cedar entity id, so a
    /// separator in it forges the ids of somebody else's subtree.
    ///
    /// `Table::"acme␟analytics␟web␟events"` is a table in tenant `acme`. A
    /// principal whose tenant claim reads `acme␟analytics` builds
    /// `Table::"acme␟analytics␟web␟events"` for *its own* namespace `web`, table
    /// `events` — the same string. A policy scoped to
    /// `Namespace::"acme␟analytics"` then covers resources it was never written
    /// for, and nothing in either the policy file or the token looks wrong.
    #[test]
    fn a_tenant_id_cannot_forge_another_tenants_entity_ids() {
        let err = validate_tenant_id("acme\u{1F}analytics").expect_err("a separator must not pass");
        assert!(err.to_string().contains("001F"), "{err}");

        // The same family, for the same reason names are checked for it: a
        // zero-width space renders as nothing.
        assert!(validate_tenant_id("acme\u{200B}").is_err());
        assert!(validate_tenant_id("acme\u{202E}").is_err());
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id(" acme").is_err());

        // And the ordinary case still works, including non-ASCII.
        assert!(validate_tenant_id("acme").is_ok());
        assert!(validate_tenant_id("acme-eu").is_ok());
        assert!(validate_tenant_id("分析").is_ok());
    }

    /// A principal id is checked for how it *renders*, not for path shape.
    ///
    /// It is never joined into an entity path, so `/` is fine — some identity
    /// providers issue URL-shaped subjects. What is not fine is anything that
    /// makes an audit record lie: a newline forges a log line, and a
    /// right-to-left override reverses the rest of one.
    #[test]
    fn a_principal_id_is_checked_for_rendering_not_for_path_shape() {
        // Shapes real identity providers issue.
        assert!(validate_principal_id("auth0|5f3c").is_ok());
        assert!(validate_principal_id("https://accounts.example/u/17").is_ok());
        assert!(validate_principal_id("alice@example.com").is_ok());
        assert!(validate_principal_id("00u1a2b3c").is_ok());
        // A tenant id could not contain these, and a subject may.
        assert!(validate_tenant_id("https://accounts.example/u/17").is_err());

        assert!(validate_principal_id("alice\nWARN forged log line").is_err());
        assert!(validate_principal_id("alice\u{202E}").is_err());
        assert!(validate_principal_id("alice\u{0}").is_err());
        assert!(validate_principal_id("").is_err());
        assert!(validate_principal_id(&"a".repeat(MAX_NAME_LENGTH + 1)).is_err());
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for name in [
            "my_namespace",
            "my-namespace",
            "MyNamespace123",
            "a.b.c",
            // A name may contain a space, an `@` or a `%`: none of them is a
            // path separator, and every engine and object store carries them.
            "my namespace",
            "team@acme",
            "100%_coverage",
            // A `..` that is not the whole segment names a directory perfectly
            // well.
            "a..b",
        ] {
            assert!(validate_name(name, "test").is_ok(), "{name}");
        }
    }

    /// The allowlist this replaced rejected every non-ASCII name, which Iceberg
    /// permits and real deployments have. A Spark job creating one got a `400`
    /// from the catalog and nothing that would help.
    #[test]
    fn a_name_may_be_written_in_any_script() {
        for name in [
            "分析",
            "売上_2026",
            "café_visits",
            "Ω_measurements",
            "события",
        ] {
            assert!(validate_name(name, "test").is_ok(), "{name}");
        }
    }

    /// Neither of these was a security control, and both cost interoperability.
    #[test]
    fn filesystem_folklore_is_not_enforced() {
        assert!(
            validate_name("CON", "Name").is_ok(),
            "a Windows device name"
        );
        assert!(validate_name("LPT1", "Name").is_ok());
        assert!(validate_name(".hidden", "Name").is_ok(), "a leading dot");
    }

    #[test]
    fn test_validate_name_empty() {
        let result = validate_name("", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(300);
        let result = validate_name(&long_name, "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    /// A name becomes a path segment in the table's storage location, so a
    /// separator inside one would place the table somewhere other than where
    /// the catalog recorded it.
    #[test]
    fn a_path_separator_is_refused() {
        for name in ["my/namespace", "my\\namespace", "../etc/passwd"] {
            let err = validate_name(name, "Namespace").unwrap_err();
            assert!(err.to_string().contains("path separator"), "{name}: {err}");
        }
    }

    /// The unit separator is what joins segments of a Cedar entity id, so a name
    /// carrying one could forge a resource path. It is a control character, so
    /// the one check covers it — but it is the reason the check exists.
    #[test]
    fn control_characters_are_refused_including_the_entity_separator() {
        for name in [
            "my\0namespace",
            "my\nnamespace",
            "my\tnamespace",
            "a\u{1F}b",
        ] {
            let err = validate_name(name, "Namespace").unwrap_err();
            assert!(err.to_string().contains("U+"), "{name:?}: {err}");
        }
    }

    /// `char::is_control` covers `Cc` only, so every one of these got through
    /// before: a zero-width space and a soft hyphen render as nothing, the BOM
    /// renders as nothing, and `\u{202E}` reverses everything after it in an
    /// audit line. Each pair below is one name a reviewer cannot distinguish
    /// from another and two resources the policy engine can.
    #[test]
    fn invisible_and_directional_characters_are_refused() {
        for name in [
            "events\u{200B}",  // zero-width space
            "eve\u{00AD}nts",  // soft hyphen
            "\u{FEFF}events",  // byte-order mark
            "events\u{202E}",  // right-to-left override
            "events\u{2066}",  // left-to-right isolate
            "events\u{E0001}", // language tag
            "events\u{E000}",  // private use
        ] {
            assert!(
                validate_name(name, "Table name").is_err(),
                "should have been refused: {name:?}"
            );
        }
    }

    /// `caf\u{E9}` and `cafe\u{301}` display identically and are different
    /// keys, different Cedar entity ids and different storage paths.
    #[test]
    fn only_nfc_is_accepted_and_the_error_names_the_spelling_that_is() {
        assert!(
            validate_name("caf\u{E9}", "Table name").is_ok(),
            "NFC is the accepted form"
        );

        let err = validate_name("cafe\u{301}", "Table name").unwrap_err();
        assert!(err.to_string().contains("NFC"), "{err}");
        assert!(
            err.to_string().contains("caf\u{E9}"),
            "the error must name the spelling that would be accepted: {err}"
        );
    }

    /// Full Unicode stays welcome — the point of dropping the ASCII allowlist.
    /// Only spellings that collide with another spelling are refused.
    #[test]
    fn ordinary_non_ascii_names_are_still_accepted() {
        for name in [
            "\u{5206}\u{6790}",
            "\u{58F2}\u{4E0A}",
            "caf\u{E9}_visits",
            "\u{43F}\u{440}\u{43E}\u{434}",
            "sales_2024",
        ] {
            assert!(validate_name(name, "Table name").is_ok(), "{name}");
        }
    }

    #[test]
    fn the_two_directory_names_are_refused() {
        assert!(validate_name(".", "Namespace").is_err());
        assert!(validate_name("..", "Namespace").is_err());
    }

    /// Two visually identical names that are distinct strings mean a policy
    /// that appears to cover a table and does not.
    #[test]
    fn surrounding_whitespace_is_refused() {
        assert!(validate_name(" events", "Table name").is_err());
        assert!(validate_name("events ", "Table name").is_err());
        assert!(validate_name("mid space", "Table name").is_ok());
    }

    /// Counted in characters, so the limit means the same thing in every script.
    #[test]
    fn the_length_limit_counts_characters() {
        assert!(validate_name(&"é".repeat(MAX_NAME_LENGTH), "Name").is_ok());
        assert!(validate_name(&"é".repeat(MAX_NAME_LENGTH + 1), "Name").is_err());
    }

    #[test]
    fn test_validate_namespace_valid() {
        assert!(validate_namespace(&["db".to_string()]).is_ok());
        assert!(validate_namespace(&["db".to_string(), "schema".to_string()]).is_ok());
    }

    #[test]
    fn test_validate_namespace_empty() {
        let result = validate_namespace(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_namespace_too_deep() {
        let deep: Vec<String> = (0..15).map(|i| format!("level{i}")).collect();
        let result = validate_namespace(&deep);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum depth"));
    }

    #[test]
    fn test_validate_properties_valid() {
        let mut props = HashMap::new();
        props.insert("key1".to_string(), "value1".to_string());
        props.insert("key2".to_string(), "value2".to_string());
        assert!(validate_properties(&props).is_ok());
    }

    #[test]
    fn test_validate_properties_too_many() {
        let props: HashMap<String, String> = (0..150)
            .map(|i| (format!("key{i}"), format!("value{i}")))
            .collect();
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many"));
    }

    #[test]
    fn test_validate_properties_key_too_long() {
        let mut props = HashMap::new();
        let long_key = "k".repeat(300);
        props.insert(long_key, "value".to_string());
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn test_validate_properties_value_too_long() {
        let mut props = HashMap::new();
        let long_value = "v".repeat(5000);
        props.insert("key".to_string(), long_value);
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("value"));
    }
}
