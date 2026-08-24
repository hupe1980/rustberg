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
//!
//! # Delegation decides whether there is a tag at all
//!
//! `loadTable` does not always return only metadata. When the client asks for
//! `X-Iceberg-Access-Delegation`, the same response carries storage access, and
//! that changes the question this module answers.
//!
//! **Vended credentials make the response uncacheable.** A credential is minted
//! per request and expires; a `304` carries no body, so a client that echoed a
//! tag and asked for credentials in the same breath would be told "unchanged"
//! and handed nothing to read the table with. There is no tag that fixes this,
//! because the correct answer is that this representation has no stable
//! identity — so [`etag_for`] returns `None` and the load is unconditional.
//!
//! **Remote signing is stable, and therefore folded in.** The signer block is
//! derived from the table's identity, not from a secret, so it caches — but a
//! response carrying it is a *different document* from one that does not, and a
//! shared tag would let a client that switched on signing be told its unsigned
//! copy was still current. Same hazard as the snapshot scope, same fix.
//!
//! It is folded in on the strength of what the client *asked for*, not what the
//! response turned out to contain. A deployment that does not offer signing
//! returns the same bytes either way, so the two tags name identical documents
//! — which costs one extra full load in a case nobody hits, and buys a rule that
//! does not silently start colliding the day signing is configured.
//!
//! **And so is the restriction, because it decides the same block.** A table
//! carrying a `@row_filter` or a `@column_mask` is refused delegation, so the
//! signer block is dropped from its response — the very block the paragraph
//! above folds in. Two callers asking for signing on one table therefore
//! receive two different documents whenever policy restricts one of them and
//! not the other, and without this input they would receive one tag.
//!
//! `Cache-Control: private` keeps a shared proxy out of it, so this is not a
//! poisoning the server can be talked into. What it is, is the rule stated twice
//! above — *different content, different tag* — with the third input that
//! changes the content. The case it costs is a client multiplexing identities
//! against one cache, and that is not an exotic one: a query engine's
//! coordinator is exactly that.
//!
//! Like delegation, it is the *restriction* that is folded in and not the
//! restriction's contents. A filter that changes while still being a filter
//! leaves the document the same shape, and anything that changed the table
//! itself has already changed the metadata location.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use super::delegation::AccessDelegation;
use super::snapshots::SnapshotScope;

/// Request header carrying the version a client already holds.
pub const IF_NONE_MATCH: &str = "if-none-match";

/// Builds the entity tag for one `loadTable` representation, or `None` when it
/// has no stable identity.
///
/// The result is a *strong* validator in quoted form, per RFC 9110: the bytes
/// are byte-for-byte identical whenever the tag matches, which is exactly the
/// guarantee the metadata location provides.
///
/// `None` means "do not cache and do not answer `304`" — see the module docs
/// for the two ways that happens.
pub fn etag_for(
    metadata_location: Option<&str>,
    scope: SnapshotScope,
    delegation: AccessDelegation,
    restricted: bool,
) -> Option<String> {
    // A table with no recorded metadata location has no version to name, so it
    // gets no tag rather than a fabricated one. Staged tables are the case.
    let location = metadata_location?;

    // A response that carries a freshly minted, expiring credential is not a
    // representation of the table; it is an event. Naming it with a validator
    // would let the next conditional load answer `304` and withhold the one
    // thing the client asked for.
    if delegation.vended_credentials {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(location.as_bytes());
    // A separator that cannot occur in either field, so no pair of inputs can
    // concatenate into the same byte string.
    hasher.update([0u8]);
    hasher.update(scope.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(if delegation.remote_signing {
        b"remote-signing".as_slice()
    } else {
        b"plain".as_slice()
    });
    hasher.update([0u8]);
    // The restriction decides the same block the line above does: a table under
    // a row filter or a column mask is refused delegation, so its response drops
    // the signer configuration. Two callers asking for signing on one table
    // therefore hold two different documents whenever policy restricts one of
    // them, and without this they would hold one tag.
    hasher.update(if restricted {
        b"restricted".as_slice()
    } else {
        b"unrestricted".as_slice()
    });

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

/// Whether a conditional load is worth attempting: the client sent a validator,
/// *and* the representation it would be validating has a stable identity.
///
/// Both halves save a lookup rather than deciding correctness — [`etag_for`] is
/// the authority on both questions and answers `None` when either fails. This
/// exists because computing a tag costs a catalog lookup, and on a federated
/// mount that lookup is a *remote* call: doing it for a header nobody sent, or
/// for a response that can never be revalidated, would double the cost of an
/// ordinary load to reach a branch that cannot be taken.
pub fn is_revalidatable(headers: &HeaderMap, delegation: AccessDelegation) -> bool {
    headers.contains_key(IF_NONE_MATCH) && !delegation.vended_credentials
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
        etag_for(Some(location), scope, AccessDelegation::default(), false)
            .expect("a located table has a tag")
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
        assert!(etag_for(None, SnapshotScope::All, AccessDelegation::default(), false).is_none());
    }

    /// The bug this exists to prevent: a client that echoes a tag *and* asks for
    /// credentials would be told "not modified" and handed a body-less `304`,
    /// leaving it with no credential to read the table with.
    #[test]
    fn a_credentialed_response_has_no_validator() {
        let delegation = AccessDelegation {
            vended_credentials: true,
            remote_signing: false,
        };
        assert!(
            etag_for(
                Some("s3://b/t/1.json"),
                SnapshotScope::All,
                delegation,
                false
            )
            .is_none()
        );
        assert!(!is_revalidatable(&if_none_match("\"x\""), delegation));
    }

    /// A signed load and a plain load are two different documents for the same
    /// metadata version, so they must not share a validator.
    #[test]
    fn remote_signing_changes_the_validator() {
        let signing = AccessDelegation {
            vended_credentials: false,
            remote_signing: true,
        };
        let plain = etag_for(
            Some("s3://b/t/1.json"),
            SnapshotScope::All,
            AccessDelegation::default(),
            false,
        );
        let signed = etag_for(Some("s3://b/t/1.json"), SnapshotScope::All, signing, false);
        assert!(plain.is_some() && signed.is_some());
        assert_ne!(plain, signed);
        assert!(is_revalidatable(&if_none_match("\"x\""), signing));
    }

    /// A restricted caller is refused delegation, so its response drops the
    /// signer block a permitted one receives — two documents, and before this
    /// they shared a validator.
    #[test]
    fn a_restricted_caller_does_not_share_a_tag_with_an_unrestricted_one() {
        let signing = AccessDelegation {
            vended_credentials: false,
            remote_signing: true,
        };
        let location = Some("s3://b/t/1.json");

        let unrestricted = etag_for(location, SnapshotScope::All, signing, false);
        let restricted = etag_for(location, SnapshotScope::All, signing, true);

        assert!(unrestricted.is_some() && restricted.is_some());
        assert_ne!(
            unrestricted, restricted,
            "the signer block is in one response and not the other, so the two must not \
             share a validator"
        );
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
        let none = AccessDelegation::default();
        assert!(!is_revalidatable(&HeaderMap::new(), none));
        assert!(is_revalidatable(&if_none_match("\"anything\""), none));
    }

    /// Even an unparseable value means the client is asking conditionally; it
    /// simply will not match.
    #[test]
    fn a_malformed_header_is_still_a_conditional_request() {
        assert!(is_revalidatable(
            &if_none_match("garbage"),
            AccessDelegation::default()
        ));
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
