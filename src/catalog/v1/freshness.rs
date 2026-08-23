//! Conditional table loading: `ETag`, `If-None-Match`, and `304 Not Modified`.
//!
//! # What this buys
//!
//! `loadTable` is the single most repeated call an engine makes — every query
//! plan starts with one — and the response is the entire table metadata
//! document. On a table with a long snapshot history that is megabytes, resent
//! in full each time, almost always unchanged.
//!
//! The Iceberg REST spec closes that with ordinary HTTP conditional requests: a
//! server returns an `ETag` identifying the metadata version, the client echoes
//! it back in `If-None-Match`, and an unchanged table answers `304 Not
//! Modified` with no body at all.
//!
//! # What the tag is derived from
//!
//! The metadata location, because it already *is* the version identifier: every
//! commit writes a new file under a fresh UUID and swaps the pointer, so two
//! reads share a location exactly when they share the metadata.
//!
//! It is hashed rather than sent literally. A location is a storage path — a
//! bucket name and layout the client has no business learning from a cache
//! header, and one that would be echoed back through proxies and logs.
//!
//! The snapshot scope is folded into the hash as well, and it has to be. A
//! client that fetched `?snapshots=refs` holds a *pruned* document; if it then
//! asked for the full one while echoing that tag, a location-only tag would
//! match and it would be told "not modified" — leaving it with the pruned copy
//! and no way to discover the difference. Different content, different tag.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use super::snapshots::SnapshotScope;

/// Request header carrying the version a client already holds.
pub const IF_NONE_MATCH: &str = "if-none-match";

/// Builds the entity tag for one metadata version at one snapshot scope.
///
/// The result is a *strong* validator in quoted form, per RFC 9110: the bytes
/// are byte-for-byte identical whenever the tag matches, which is exactly the
/// guarantee the metadata location provides.
pub fn etag_for(metadata_location: Option<&str>, scope: SnapshotScope) -> Option<String> {
    // A table with no recorded metadata location has no version to name, so it
    // gets no tag rather than a fabricated one. Staged tables are the case.
    let location = metadata_location?;

    let mut hasher = Sha256::new();
    hasher.update(location.as_bytes());
    // A separator that cannot occur in either field, so no pair of inputs can
    // concatenate into the same byte string.
    hasher.update([0u8]);
    hasher.update(scope.as_str().as_bytes());

    let digest = hasher.finalize();
    // 128 bits of a SHA-256 digest. A collision is what would matter here — a
    // client served stale metadata — and at 128 bits they do not happen.
    let hex = digest
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    Some(format!("\"{hex}\""))
}

/// Whether the request is conditional at all.
///
/// Worth asking separately from [`matches()`], because computing an entity tag
/// costs a catalog lookup. For a federated mount that lookup is a *remote*
/// call, so computing a tag no client asked about would double the cost of
/// every ordinary load.
pub fn is_conditional(headers: &HeaderMap) -> bool {
    headers.contains_key(IF_NONE_MATCH)
}

/// Whether `headers` claims a version matching `etag`.
///
/// `If-None-Match` may carry a list, and `*` matches any existing
/// representation. Weak-comparison prefixes (`W/`) are accepted and compared on
/// the opaque part: this server only ever issues strong tags, so a `W/` prefix
/// can only have come from a proxy downgrading one of ours.
pub fn matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };

    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || strip_weak(candidate) == strip_weak(etag)
    })
}

/// Removes an RFC 9110 weak-validator prefix, leaving the opaque tag.
fn strip_weak(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(location: &str, scope: SnapshotScope) -> String {
        etag_for(Some(location), scope).expect("a located table has a tag")
    }

    fn if_none_match(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, value.parse().unwrap());
        headers
    }

    #[test]
    fn the_same_metadata_yields_the_same_tag() {
        let a = tag(
            "s3://b/wh/db/t/metadata/00001-abc.metadata.json",
            SnapshotScope::All,
        );
        let b = tag(
            "s3://b/wh/db/t/metadata/00001-abc.metadata.json",
            SnapshotScope::All,
        );
        assert_eq!(a, b, "a tag must be stable, or every request misses");
    }

    /// A commit writes a new metadata file, so the tag must move with it —
    /// otherwise a client is told "not modified" about a table that changed.
    #[test]
    fn a_new_metadata_version_yields_a_different_tag() {
        let before = tag(
            "s3://b/wh/db/t/metadata/00001-abc.metadata.json",
            SnapshotScope::All,
        );
        let after = tag(
            "s3://b/wh/db/t/metadata/00002-def.metadata.json",
            SnapshotScope::All,
        );
        assert_ne!(before, after);
    }

    /// The case a location-only tag gets wrong: same metadata, different
    /// response body. Sharing a tag would serve a client the pruned document
    /// when it asked for the full one.
    #[test]
    fn the_snapshot_scope_changes_the_tag() {
        let location = "s3://b/wh/db/t/metadata/00001-abc.metadata.json";
        assert_ne!(
            tag(location, SnapshotScope::All),
            tag(location, SnapshotScope::Refs),
            "different content must not share a validator"
        );
    }

    #[test]
    fn a_table_with_no_location_has_no_tag() {
        assert!(etag_for(None, SnapshotScope::All).is_none());
    }

    #[test]
    fn the_tag_does_not_leak_the_storage_path() {
        let t = tag(
            "s3://secret-bucket/warehouse/db/t/metadata/1.json",
            SnapshotScope::All,
        );
        assert!(!t.contains("secret-bucket"));
        assert!(!t.contains("warehouse"));
    }

    #[test]
    fn the_tag_is_a_quoted_strong_validator() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(t.starts_with('"') && t.ends_with('"'), "quoted: {t}");
        assert!(!t.starts_with("W/"), "strong, not weak: {t}");
        // 32 hex characters between the quotes.
        assert_eq!(t.len(), 34, "128 bits of digest: {t}");
        assert!(t[1..33].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_matching_tag_is_recognised() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(matches(&if_none_match(&t), &t));
    }

    #[test]
    fn a_different_tag_does_not_match() {
        let held = tag("s3://b/t/1.json", SnapshotScope::All);
        let current = tag("s3://b/t/2.json", SnapshotScope::All);
        assert!(!matches(&if_none_match(&held), &current));
    }

    #[test]
    fn a_request_without_the_header_is_not_conditional() {
        assert!(!is_conditional(&HeaderMap::new()));
        assert!(is_conditional(&if_none_match("\"anything\"")));
    }

    /// Even an unparseable value means the client is asking conditionally; it
    /// simply will not match.
    #[test]
    fn a_malformed_header_is_still_a_conditional_request() {
        assert!(is_conditional(&if_none_match("garbage")));
    }

    #[test]
    fn an_absent_header_never_matches() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(!matches(&HeaderMap::new(), &t));
    }

    /// `If-None-Match` is a list; a client holding several versions sends them
    /// all, and any one of them matching is a hit.
    #[test]
    fn a_list_matches_on_any_member() {
        let held = tag("s3://b/t/1.json", SnapshotScope::All);
        let other = tag("s3://b/t/9.json", SnapshotScope::All);
        let header = if_none_match(&format!("{other}, {held}"));
        assert!(matches(&header, &held));
    }

    #[test]
    fn a_wildcard_matches_any_version() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(matches(&if_none_match("*"), &t));
    }

    /// A proxy may downgrade a strong tag to a weak one in transit; the opaque
    /// part is what identifies the version.
    #[test]
    fn a_weakened_tag_still_matches() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(matches(&if_none_match(&format!("W/{t}")), &t));
    }

    #[test]
    fn a_malformed_header_is_simply_a_miss() {
        let t = tag("s3://b/t/1.json", SnapshotScope::All);
        assert!(!matches(&if_none_match("not-a-tag"), &t));
        assert!(!matches(&if_none_match(""), &t));
    }
}
