//! Containment checks for storage locations.
//!
//! # Why this exists
//!
//! Several requests let a client name a storage location: `createTable` accepts
//! a `location`, `createView` the same, and `registerTable` names a metadata
//! file outright. Every one of those locations later becomes the prefix of a
//! **vended storage credential**.
//!
//! That makes an unchecked location a confused-deputy hole. A caller permitted
//! to create a table in its own namespace could register one whose metadata
//! lives under somebody else's prefix:
//!
//! ```text
//! POST /v1/namespaces/mine/register
//! { "name": "borrowed", "metadata-location": "s3://someone-else/secrets/…json" }
//! ```
//!
//! and then ask for credentials on it. The catalog's own role reaches that
//! prefix, so the credential it mints does too — the caller has borrowed the
//! server's authority to read a location its own policy never mentioned. So a
//! client-supplied location is confined to the warehouse, and the check happens
//! before the location is ever recorded.
//!
//! # Why `starts_with` is not the check
//!
//! The obvious implementation is a prefix test, and it is wrong at the segment
//! boundary:
//!
//! ```text
//! "s3://bucket/wh-evil/t".starts_with("s3://bucket/wh")  // true — different prefix!
//! ```
//!
//! A warehouse written without a trailing slash — the way every operator writes
//! it — therefore admits every sibling prefix that merely shares its spelling.
//! [`is_within`] compares whole segments, so `wh-evil` is not inside `wh`.
//!
//! # Scheme aliases
//!
//! `s3a://bucket/wh` and `s3://bucket/wh` are the same bucket, so a check that
//! treated them as different locations would reject legitimate Hadoop-style
//! paths — and, worse, invite an operator to widen the warehouse until they
//! passed. Aliases of one store are folded onto a canonical scheme, so the
//! comparison is about *where the bytes live* rather than how the URL was
//! spelled.

use crate::error::{AppError, Result};

/// Folds the aliases of one storage service onto a single scheme.
///
/// Only aliases of the *same* service are folded. Two schemes that resolve to
/// different stores must never collapse together, or containment would be
/// decided across a boundary that really exists.
fn canonical_scheme(scheme: &str) -> &str {
    match scheme {
        // Hadoop's S3 connectors, all the same bucket namespace.
        "s3" | "s3a" | "s3n" => "s3",
        // Google Cloud Storage, spelled either way.
        "gs" | "gcs" => "gs",
        // ADLS Gen2; the `s` is TLS on the wire, not a different filesystem.
        "abfs" | "abfss" | "az" | "adls" => "abfs",
        other => other,
    }
}

/// Splits a location into its canonical scheme and its path.
///
/// A bare path with no scheme is local, and is reported as `file` so that
/// `/srv/warehouse` and `file:///srv/warehouse` compare equal — operators write
/// both, and they mean the same directory.
fn split(location: &str) -> (String, &str) {
    match location.split_once("://") {
        Some((scheme, rest)) => (
            canonical_scheme(&scheme.to_ascii_lowercase()).to_string(),
            rest,
        ),
        None => ("file".to_string(), location),
    }
}

/// Splits a path into non-empty segments.
///
/// Empty segments are dropped so that `bucket//wh` and `bucket/wh` agree; a
/// doubled slash is a typo, not a different location.
fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// True when `candidate` is `root` itself, or something nested inside it.
///
/// Comparison is segment-wise, so a sibling prefix that merely shares spelling
/// with the root — `wh-evil` against `wh` — is *not* inside it.
///
/// A `..` segment anywhere in `candidate` makes the answer `false`. Resolving it
/// would let a location climb back out of a root it appeared to be under, and no
/// legitimate caller needs one.
pub fn is_within(root: &str, candidate: &str) -> bool {
    let (root_scheme, root_path) = split(root);
    let (candidate_scheme, candidate_path) = split(candidate);

    if root_scheme != candidate_scheme {
        return false;
    }

    let root_segments = segments(root_path);
    let candidate_segments = segments(candidate_path);

    // Checked before the length test: a traversal segment invalidates the
    // location regardless of how deep it appears.
    if candidate_segments.contains(&"..") {
        return false;
    }

    // Nested means "at least as deep, and identical as far as the root goes".
    if candidate_segments.len() < root_segments.len() {
        return false;
    }
    root_segments
        .iter()
        .zip(&candidate_segments)
        .all(|(a, b)| a == b)
}

/// True when `candidate` is strictly *inside* `root`, never equal to it.
///
/// For S3 list prefixes, which the service matches as raw strings: a prefix of
/// `wh/db/t` returns the keys of `wh/db/t2` as well, so a listing scoped to a
/// table has to name something below the table's location rather than the
/// location itself.
pub fn is_prefix_within(root: &str, candidate: &str) -> bool {
    let (root_scheme, root_path) = split(root);
    let (candidate_scheme, candidate_path) = split(candidate);

    if root_scheme != candidate_scheme {
        return false;
    }

    let root_segments = segments(root_path);
    let candidate_segments = segments(candidate_path);

    if candidate_segments.contains(&"..") || candidate_segments.len() < root_segments.len() {
        return false;
    }
    if !root_segments
        .iter()
        .zip(&candidate_segments)
        .all(|(a, b)| a == b)
    {
        return false;
    }

    // Deeper, or the same depth with a trailing slash — both name only what is
    // under the root. The same depth without one names the root as a string,
    // which matches its siblings too.
    candidate_segments.len() > root_segments.len() || candidate_path.ends_with('/')
}

/// Whether a credential provider may vend for `location`.
///
/// # An empty list grants nothing
///
/// The scope a provider will sign for is exactly the prefixes it was given, and
/// "none configured" means none — never "anywhere". Reading it the other way
/// makes a provider built without prefixes mint credentials for any bucket its
/// role can reach, which is the confused-deputy hole
/// [`ensure_within_warehouse`] exists to close, one layer down.
///
/// Failing closed costs a misconfigured deployment its credential vending,
/// which is visible and recoverable. Failing open costs it the blast radius of
/// the server's own storage role, silently.
pub fn is_vendable(allowed_prefixes: &[String], location: &str) -> bool {
    allowed_prefixes
        .iter()
        .any(|prefix| is_within(prefix, location))
}

/// Confines a client-supplied `location` to the `warehouse`.
///
/// # Errors
///
/// Returns [`AppError::BadRequest`] when `location` is empty or falls outside
/// `warehouse`. The message names the warehouse, because the caller is
/// permitted to know where it is allowed to write — it is the location it did
/// *not* get access to that stays unnamed.
pub fn ensure_within_warehouse(warehouse: &str, location: &str) -> Result<()> {
    if location.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Storage location must not be empty".to_string(),
        ));
    }

    if is_within(warehouse, location) {
        return Ok(());
    }

    Err(AppError::BadRequest(format!(
        "Storage location '{location}' is outside this catalog's warehouse \
         ('{warehouse}'). A catalog only manages locations within its own \
         warehouse, because the credentials it vends are scoped to them."
    )))
}

/// Confines the location a *metadata document* declares, at the moment a
/// catalog adopts it.
///
/// # Why this lives in the backend and not in the handler
///
/// `registerTable` names a metadata file, and the `location` recorded *inside*
/// that file is what a vended credential is later scoped to — not the path the
/// caller handed in. So the file path being inside the warehouse proves nothing;
/// a file at a legitimate path may declare any location it likes.
///
/// Checking after the pointer is published leaves a window in which a table
/// declaring somebody else's prefix is loadable. Checking before it, from the
/// handler, is worse: the caller controls that file, so the bytes checked and
/// the bytes adopted are two different reads of something that can change in
/// between.
///
/// There is exactly one read that is safe to check: **the one the catalog is
/// about to record**. That read happens inside the backend, so the check does
/// too, and no pointer is published at all.
///
/// A backend with no warehouse of its own (`None`) is not confined here. That is
/// a federated mount over somebody else's catalog, which stores nothing and
/// refuses registration on capability grounds before reaching this.
///
/// # Errors
///
/// An [`iceberg::Error`] rather than an [`AppError`], because the caller is a
/// [`CatalogStore`](crate::catalog::CatalogStore) and that is the vocabulary the
/// trait speaks. It maps to `400`.
pub fn confine_declared_location(warehouse: Option<&str>, declared: &str) -> iceberg::Result<()> {
    let Some(warehouse) = warehouse else {
        return Ok(());
    };

    if is_within(warehouse, declared) {
        return Ok(());
    }

    Err(iceberg::Error::new(
        iceberg::ErrorKind::DataInvalid,
        format!(
            "The metadata being registered declares the location '{declared}', which is \
             outside this catalog's warehouse ('{warehouse}'). A catalog only manages \
             locations within its own warehouse, because the credentials it vends are \
             scoped to them."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_location_inside_the_warehouse_is_accepted() {
        assert!(is_within("s3://bucket/wh", "s3://bucket/wh/db/events"));
        assert!(is_within("s3://bucket/wh/", "s3://bucket/wh/db/events"));
        assert!(is_within("s3://bucket/wh", "s3://bucket/wh"));
    }

    /// A string prefix test says `wh-evil` is inside `wh`, so a warehouse
    /// written without a trailing slash would admit every sibling that shares
    /// its spelling.
    #[test]
    fn a_sibling_prefix_is_not_inside_the_warehouse() {
        assert!("s3://bucket/wh-evil/t".starts_with("s3://bucket/wh"));
        assert!(!is_within("s3://bucket/wh", "s3://bucket/wh-evil/t"));
        assert!(!is_within("s3://bucket/wh", "s3://bucket/whatever"));
    }

    #[test]
    fn another_bucket_is_never_inside() {
        assert!(!is_within("s3://bucket/wh", "s3://other-bucket/wh/t"));
    }

    #[test]
    fn a_shallower_location_is_not_inside() {
        assert!(!is_within("s3://bucket/wh/deep", "s3://bucket/wh"));
    }

    /// Hadoop-style S3 URLs name the same bucket, so they must compare equal —
    /// otherwise an operator widens the warehouse until they pass.
    #[test]
    fn scheme_aliases_of_one_store_agree() {
        assert!(is_within("s3://bucket/wh", "s3a://bucket/wh/t"));
        assert!(is_within("s3a://bucket/wh", "s3://bucket/wh/t"));
        assert!(is_within("gs://bucket/wh", "gcs://bucket/wh/t"));
        assert!(is_within("abfss://fs@acct/wh", "abfs://fs@acct/wh/t"));
    }

    #[test]
    fn different_stores_never_agree() {
        assert!(!is_within("s3://bucket/wh", "gs://bucket/wh/t"));
        assert!(!is_within("s3://bucket/wh", "file:///bucket/wh/t"));
    }

    #[test]
    fn a_bare_path_is_a_local_path() {
        assert!(is_within("/srv/warehouse", "file:///srv/warehouse/db/t"));
        assert!(is_within("file:///srv/warehouse", "/srv/warehouse/db/t"));
        assert!(!is_within("/srv/warehouse", "/srv/warehouse-other/db/t"));
    }

    /// A traversal segment would let a location climb out of the root it
    /// appears to be under.
    #[test]
    fn traversal_is_refused() {
        assert!(!is_within("s3://bucket/wh", "s3://bucket/wh/../evil/t"));
        assert!(!is_within("/srv/wh", "/srv/wh/db/../../etc/passwd"));
    }

    #[test]
    fn doubled_slashes_do_not_change_the_location() {
        assert!(is_within("s3://bucket/wh", "s3://bucket//wh//db/t"));
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        assert!(is_within("s3://bucket/wh", "S3://bucket/wh/t"));
    }

    /// Bucket and key are case-sensitive in every object store here, so a
    /// differently-cased key is a different object and must not be admitted.
    #[test]
    fn the_path_is_case_sensitive() {
        assert!(!is_within("s3://bucket/wh", "s3://bucket/WH/t"));
    }

    #[test]
    fn ensure_reports_a_bad_request_with_both_locations_named() {
        let err = ensure_within_warehouse("s3://bucket/wh", "s3://elsewhere/t").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
        let msg = err.to_string();
        assert!(
            msg.contains("s3://elsewhere/t"),
            "names the rejected location"
        );
        assert!(msg.contains("s3://bucket/wh"), "names the warehouse");
    }

    #[test]
    fn an_empty_location_is_refused() {
        assert!(ensure_within_warehouse("s3://bucket/wh", "").is_err());
        assert!(ensure_within_warehouse("s3://bucket/wh", "   ").is_err());
    }

    #[test]
    fn ensure_accepts_the_ordinary_case() {
        assert!(ensure_within_warehouse("s3://bucket/wh", "s3://bucket/wh/db/t").is_ok());
    }

    /// The rule that keeps a provider from becoming a confused deputy: no
    /// configured scope is no scope, not universal scope.
    #[test]
    fn no_configured_prefix_vends_nothing() {
        assert!(!is_vendable(&[], "s3://bucket/wh/db/t"));
        assert!(!is_vendable(&[], "gs://anything/at/all"));
    }

    #[test]
    fn vending_follows_the_same_containment_as_confinement() {
        let allowed = vec!["s3://bucket/wh".to_string()];
        assert!(is_vendable(&allowed, "s3://bucket/wh/db/t"));
        assert!(
            is_vendable(&allowed, "s3a://bucket/wh/db/t"),
            "scheme alias"
        );
        assert!(
            !is_vendable(&allowed, "s3://bucket/wh-evil/t"),
            "sibling prefix"
        );
        assert!(!is_vendable(&allowed, "s3://other/wh/t"), "other bucket");
        assert!(
            !is_vendable(&allowed, "s3://bucket/wh/../evil/t"),
            "traversal"
        );
    }

    /// The check a `registerTable` performs before it publishes anything.
    #[test]
    fn a_declared_location_outside_the_warehouse_is_refused() {
        assert!(confine_declared_location(Some("s3://bucket/wh"), "s3://bucket/wh/db/t").is_ok());

        let err = confine_declared_location(Some("s3://bucket/wh"), "s3://elsewhere/secrets")
            .unwrap_err();
        assert_eq!(err.kind(), iceberg::ErrorKind::DataInvalid);
        assert!(err.to_string().contains("s3://elsewhere/secrets"));
        assert!(err.to_string().contains("s3://bucket/wh"));
    }

    /// The sibling-prefix hazard reaches this caller too.
    #[test]
    fn a_declared_sibling_prefix_is_refused() {
        assert!(confine_declared_location(Some("s3://bucket/wh"), "s3://bucket/wh-evil").is_err());
    }

    /// A backend that owns no warehouse cannot confine anything, and says so by
    /// not pretending to.
    #[test]
    fn a_backend_without_a_warehouse_confines_nothing() {
        assert!(confine_declared_location(None, "s3://anywhere/at/all").is_ok());
    }

    #[test]
    fn a_list_prefix_must_go_below_the_root() {
        assert!(is_prefix_within("s3://bucket/wh/t", "s3://bucket/wh/t/"));
        assert!(is_prefix_within(
            "s3://bucket/wh/t",
            "s3://bucket/wh/t/data/"
        ));
        // Matches `s3://bucket/wh/t2/...` as a raw string, so it is not inside.
        assert!(!is_prefix_within("s3://bucket/wh/t", "s3://bucket/wh/t"));
        assert!(!is_prefix_within("s3://bucket/wh/t", "s3://bucket/wh/"));
        assert!(!is_prefix_within("s3://bucket/wh/t", "s3://other/wh/t/"));
    }

    #[test]
    fn any_one_prefix_is_enough() {
        let allowed = vec!["s3://a/wh".to_string(), "s3://b/wh".to_string()];
        assert!(is_vendable(&allowed, "s3://b/wh/t"));
        assert!(!is_vendable(&allowed, "s3://c/wh/t"));
    }
}
