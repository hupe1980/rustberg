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

use iceberg::{TableUpdate, ViewUpdate};

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
///
/// The leading slash is kept in the returned path, and [`is_within`] compares
/// it, because [`segments`] throws that distinction away: without it the
/// *relative* path `srv/warehouse/x` splits into the same segments as the
/// absolute `/srv/warehouse/x` and would be admitted into a warehouse it does
/// not name. A relative table location has no meaning here anyway — it would be
/// resolved against whatever directory the process happened to start in.
fn split(location: &str) -> (String, &str) {
    match location.split_once("://") {
        Some((scheme, rest)) => (
            canonical_scheme(&scheme.to_ascii_lowercase()).to_string(),
            rest,
        ),
        None => ("file".to_string(), location),
    }
}

/// Whether a local path is rooted.
///
/// Only asked about the `file` scheme: after `scheme://` the remainder always
/// starts at an authority or a bucket, so there is no leading slash to compare.
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// Splits a path into non-empty segments.
///
/// Empty segments are dropped so that `bucket//wh` and `bucket/wh` agree; a
/// doubled slash is a typo, not a different location.
///
/// A `.` segment is **kept**, and that is deliberate. On a filesystem it means
/// "this directory" and could be dropped; in an object store it is an ordinary
/// key segment, and `wh/./t` and `wh/t` are two different objects. Dropping it
/// would make containment agree with the filesystem reading and disagree with
/// the store the credential is scoped to — and the comparison here has to be
/// about the bytes the storage service will address. `..` is refused outright by
/// the callers below rather than resolved, for the same reason.
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

    // A local path must be rooted the same way as the warehouse, or two
    // different directories compare equal — see `split`.
    if root_scheme == "file" && is_absolute(root_path) != is_absolute(candidate_path) {
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

    if root_scheme == "file" && is_absolute(root_path) != is_absolute(candidate_path) {
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
/// [`LocationBound`] exists to close, one layer down.
///
/// Failing closed costs a misconfigured deployment its credential vending,
/// which is visible and recoverable. Failing open costs it the blast radius of
/// the server's own storage role, silently.
/// The local path a `file://` location names.
///
/// # Why this is not `strip_prefix("file://")`
///
/// On Unix it is: `file:///var/lib/rustberg` strips to `/var/lib/rustberg` and
/// that is the path. On Windows the same URL is written `file:///C:/data`, and
/// stripping leaves `/C:/data` — which is not a Windows path. It has a root but
/// no drive prefix, so `Path::is_absolute` is false and joining it onto the
/// current directory yields `C:\…\C:\data`, a colon where none may be. The
/// operating system answers `ERROR_INVALID_NAME`, and the failure surfaces
/// wherever the path is first used rather than where it was built.
///
/// So a leading slash is dropped when a drive letter follows it. Both callers
/// that turn a configured URL into a path go through here — the warehouse the
/// registry creates, and the catalog file the server opens — because two copies
/// of this would be one edit away from disagreeing about where a deployment
/// keeps its data.
///
/// Nothing is percent-decoded. These URLs are written by an operator or by this
/// crate's own default-warehouse helper, neither of which encodes, and decoding
/// would change the meaning of a path that legitimately contains `%`.
#[must_use]
pub fn path_from_url(location: &str) -> &str {
    without_url_prefix(location, cfg!(windows))
}

/// The `file://` URL naming a local path — the inverse of [`path_from_url`].
///
/// # Why this is not `format!("file://{path}")`
///
/// On Unix it is: `/var/lib/rustberg` interpolates to `file:///var/lib/rustberg`,
/// three slashes and all. On Windows the same formatting yields
/// `file://C:\data\warehouse`, which is not a URL anyone can resolve — the
/// drive letter lands where the *authority* goes, and the separators are the
/// wrong ones. What comes back out of an object-store layer given that is
/// `/C:\data\warehouse`, a leading slash before a drive and mixed separators,
/// and the operating system answers `ERROR_INVALID_NAME` at the first read or
/// delete rather than where the URL was built.
///
/// So separators are normalised and a drive letter gets the third slash that
/// makes it a path rather than a host. Every place that turns a path into a
/// location goes through here — the warehouse a registry canonicalises, the
/// default warehouse for a server started without one — because a URL built one
/// way and read back another is a deployment that writes where nothing looks.
#[must_use]
pub fn url_from_path(path: impl AsRef<std::path::Path>) -> String {
    to_url(&path.as_ref().display().to_string(), cfg!(windows))
}

/// The rule [`url_from_path`] applies, with the platform as an argument so both
/// halves are testable from either.
fn to_url(path: &str, windows: bool) -> String {
    // Only on Windows: a backslash is an ordinary character in a Unix filename,
    // and rewriting it there would rename the file being addressed.
    let normalized = if windows {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };

    if windows && starts_with_drive_letter(&normalized) {
        format!("file:///{normalized}")
    } else {
        format!("file://{normalized}")
    }
}

/// The rule [`path_from_url`] applies, with the platform as an argument so both
/// halves are testable from either.
fn without_url_prefix(location: &str, windows: bool) -> &str {
    let rest = location.strip_prefix("file://").unwrap_or(location);

    if windows
        && let Some(after) = rest.strip_prefix('/')
        && starts_with_drive_letter(after)
    {
        return after;
    }

    rest
}

/// Whether `path` opens with a Windows drive specification — `C:`, `C:/`, `C:\`.
///
/// Checked rather than assumed, so `/etc/…` on a Unix path is left alone and a
/// directory genuinely named `C:` is only mishandled on the platform where it
/// cannot exist.
fn starts_with_drive_letter(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'/' || bytes[2] == b'\\')
}

pub fn is_vendable(allowed_prefixes: &[String], location: &str) -> bool {
    allowed_prefixes
        .iter()
        .any(|prefix| is_within(prefix, location))
}

/// How far a client may move a resource's storage.
///
/// # Why this is a choice at all, and why the default is the tight one
///
/// Every guarantee in this crate is written over the **namespace tree**: a Cedar
/// policy names `Namespace::"acme␟finance"`, and a caller either may reach what
/// is under it or may not. Storage access is written over a **path**: a vended
/// credential, and a signature, are scoped to the location the table declares.
///
/// Those two hierarchies are only the same hierarchy while a table's files stay
/// where its name puts them. Let a table declare any location in the warehouse
/// and the mapping breaks in one move: a caller with `Update` on one table of
/// its own points that table at `…/finance/secret`, asks for credentials, and is
/// handed a correctly-scoped credential for a prefix its policy never mentioned.
/// Nothing in that sequence is a bug in the authorizer — every step is
/// permitted. The location was simply not something the caller should have been
/// able to choose.
///
/// Apache Polaris draws the same line, from the same reasoning, and defaults the
/// same way (`ALLOW_UNSTRUCTURED_TABLE_LOCATION`, off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocationScope {
    /// A resource's files live under `<warehouse>/<namespace…>/<name>` — the
    /// layout the registries already assign, held to as a *rule*.
    ///
    /// The storage hierarchy is then the policy hierarchy, so a location-scoped
    /// credential is a faithful enforcement of a namespace-scoped grant. Two
    /// resources cannot overlap, because names are unique within a namespace and
    /// namespaces nest by segment — no lookup, no scan, nothing to race.
    #[default]
    Table,
    /// Anywhere inside the warehouse.
    ///
    /// What it is for: adopting a lake whose layout predates this catalog, where
    /// `registerTable` has to name files that are not where a name would put
    /// them.
    ///
    /// What it costs: the paragraph above, in full. A caller permitted to write
    /// **one** table can point it anywhere in the warehouse and be credentialed
    /// there. Only choose it where something outside Rustberg enforces the
    /// isolation — a bucket per tenant, say — or where every principal that can
    /// write is trusted with the whole warehouse.
    Warehouse,
}

impl LocationScope {
    /// Parses the configured value.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] naming the accepted values. Unrecognised is a
    /// startup failure rather than a silent fall back to either side: falling
    /// back to `Table` breaks a deployment that meant `Warehouse`, and falling
    /// back to `Warehouse` silently removes the bound.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "warehouse" => Ok(Self::Warehouse),
            other => Err(AppError::Internal(format!(
                "Unknown storage.location_scope '{other}'. Valid values are 'table' (the \
                 default: a resource's files live under <warehouse>/<namespace>/<name>) \
                 and 'warehouse' (anywhere in the warehouse, which lets a caller \
                 permitted to write one table be credentialed for any prefix in it)."
            ))),
        }
    }
}

/// The prefix a resource's storage must sit inside, and enough context to say
/// why when it does not.
///
/// One value built once per request, then asked about every location that
/// request carries — a `createTable` body, the four a `commitTable` carries, the
/// location a registered metadata file declares. Building it once is what keeps
/// those callers from each deciding the rule for themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationBound {
    root: String,
    scope: LocationScope,
}

impl LocationBound {
    /// The bound for one named resource, given the prefix its namespace occupies.
    ///
    /// `namespace_prefix` is where the backend holding this namespace keeps its
    /// resources — `warehouse` plus the namespace's own levels, *as that backend
    /// sees them*. It is passed in rather than derived here because under
    /// federation the two differ: a mount's name is a segment of the namespace
    /// **here** and not a segment of the path **there**, so building the prefix
    /// from the federated namespace produces `…/prod/db/events` for a table the
    /// mount itself keeps at `…/db/events`, and every register into a mount
    /// fails its own bound. [`CatalogStore::namespace_prefix_for`] is what
    /// routes it.
    ///
    /// Under [`LocationScope::Warehouse`] neither the prefix nor the name is
    /// used — the bound is the warehouse — and both are taken anyway so a caller
    /// cannot express "confine this, but I have not worked out to what".
    ///
    /// [`CatalogStore::namespace_prefix_for`]: crate::catalog::CatalogStore::namespace_prefix_for
    pub fn new(scope: LocationScope, warehouse: &str, namespace_prefix: &str, name: &str) -> Self {
        let root = match scope {
            LocationScope::Warehouse => warehouse.to_string(),
            LocationScope::Table => {
                format!("{}/{}", namespace_prefix.trim_end_matches('/'), name)
            }
        };
        Self { root, scope }
    }

    /// The prefix itself, for a caller that needs to build a default location
    /// rather than check one.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Confines one client-supplied location.
    ///
    /// # Errors
    ///
    /// [`AppError::BadRequest`] when `location` is empty or falls outside the
    /// bound. The message names the bound, because the caller is permitted to
    /// know where it *may* write — it is the location it did not get access to
    /// that stays unnamed.
    pub fn ensure(&self, location: &str) -> Result<()> {
        if location.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Storage location must not be empty".to_string(),
            ));
        }

        if is_within(&self.root, location) {
            return Ok(());
        }

        Err(AppError::BadRequest(self.explain(location)))
    }

    /// The same, as an [`iceberg::Error`], for a caller inside a
    /// [`CatalogStore`](crate::catalog::CatalogStore) — which speaks that
    /// vocabulary. Maps to `400`.
    ///
    /// # Errors
    ///
    /// [`iceberg::ErrorKind::DataInvalid`] when `location` falls outside.
    pub fn ensure_iceberg(&self, location: &str) -> iceberg::Result<()> {
        if is_within(&self.root, location) {
            return Ok(());
        }
        Err(iceberg::Error::new(
            iceberg::ErrorKind::DataInvalid,
            self.explain(location),
        ))
    }

    /// Confines every location a **table commit** carries, given where the
    /// table's files are *now*.
    ///
    /// # Why a commit carries any, and why two bounds
    ///
    /// `createTable` and `registerTable` obviously name a location. `commitTable`
    /// reads as "change the schema, add a snapshot" and names four:
    ///
    /// | Update | Names | Bounded by |
    /// |---|---|---|
    /// | `SetLocation` | the table's location — it *moves* the table | `self`, or `current` |
    /// | `AddSnapshot` | a manifest list, read by a plan and deleted by a purge | `current` |
    /// | `SetStatistics`, `SetPartitionStatistics` | a Puffin file, deleted by a purge | `current` |
    ///
    /// The three that name *files* are bounded by the table's own location:
    /// whatever it is, the table already owns it and a credential is already
    /// scoped to exactly that, so a file underneath grants nothing new. It has to
    /// be the location and not the name, because **rename** moves a registry
    /// entry and never the files — `db.old` renamed to `db.new` keeps its files
    /// at `…/db/old`, and a bound taken from the new name would make the table
    /// unwritable.
    ///
    /// `SetLocation` *changes* what a credential will be scoped to, so it is
    /// bounded by what the caller's name entitles it to. Anything under `current`
    /// passes too: that is reorganising where the table already is.
    ///
    /// What it cannot reach is the *contents* of a manifest, which lists data
    /// files by path; [`catalog::purge`](crate::catalog::purge) takes that end
    /// instead.
    ///
    /// # Errors
    ///
    /// [`iceberg::ErrorKind::DataInvalid`] naming the first location that falls
    /// outside, which maps to `400`. An [`iceberg::Error`] rather than an
    /// [`AppError`] because this runs inside a
    /// [`CatalogStore`](crate::catalog::CatalogStore) — the one place `current`
    /// is in hand without loading the table twice.
    pub fn ensure_commit(&self, current: &str, updates: &[TableUpdate]) -> iceberg::Result<()> {
        for update in updates {
            // Matched by variant rather than by scanning the serialised form for
            // anything path-shaped: a heuristic over JSON both misses a path
            // under an unexpected key and refuses a property value that merely
            // looks like one.
            //
            // The `_` arm is the risk, and it is bounded by
            // `commit_cannot_move_a_table_outside_its_bound`, which sends the
            // wire form of all four actions. Reviewed against `iceberg` 0.10; a
            // dependency bump that adds a location-carrying update needs a line
            // here.
            match update {
                TableUpdate::SetLocation { location } => {
                    if !is_within(&self.root, location) && !is_within(current, location) {
                        return Err(iceberg::Error::new(
                            iceberg::ErrorKind::DataInvalid,
                            self.explain(location),
                        ));
                    }
                }
                TableUpdate::AddSnapshot { snapshot } => {
                    Self::ensure_owned(current, snapshot.manifest_list())?;
                }
                TableUpdate::SetStatistics { statistics } => {
                    Self::ensure_owned(current, &statistics.statistics_path)?;
                }
                TableUpdate::SetPartitionStatistics {
                    partition_statistics,
                } => {
                    Self::ensure_owned(current, &partition_statistics.statistics_path)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The same rule for a **view commit**.
    ///
    /// A view has no snapshots and no statistics, so `SetLocation` is the only
    /// update that carries a path — but it carries it for the same reason and
    /// gets the same answer.
    ///
    /// # Errors
    ///
    /// [`iceberg::ErrorKind::DataInvalid`] naming the location that falls
    /// outside.
    pub fn ensure_view_commit(&self, current: &str, updates: &[ViewUpdate]) -> iceberg::Result<()> {
        for update in updates {
            if let ViewUpdate::SetLocation { location } = update
                && !is_within(&self.root, location)
                && !is_within(current, location)
            {
                return Err(iceberg::Error::new(
                    iceberg::ErrorKind::DataInvalid,
                    self.explain(location),
                ));
            }
        }
        Ok(())
    }

    /// The same rule again, for a view commit that arrives as **finished
    /// metadata** rather than as a list of updates.
    ///
    /// The HTTP handler applies the client's `ViewUpdate`s itself, so it can
    /// check each one; an in-process host holds a `ViewMetadata` and edits it,
    /// so what reaches this check is only the result. The question is the same —
    /// may this view live where it now says it does — and it must be asked, or
    /// the library surface would be the one way to move a view's storage outside
    /// the prefix its name puts it in.
    ///
    /// `current` is allowed for the reason a rename is: a view's files do not
    /// move when its registry entry does, so a document that already sits where
    /// the catalog put it stays legal.
    ///
    /// # Errors
    ///
    /// [`iceberg::ErrorKind::DataInvalid`] naming the location that falls
    /// outside.
    pub fn ensure_view_commit_metadata(
        &self,
        current: &str,
        metadata: &iceberg::spec::ViewMetadata,
    ) -> iceberg::Result<()> {
        let location = metadata.location();
        if is_within(&self.root, location) || is_within(current, location) {
            return Ok(());
        }
        Err(iceberg::Error::new(
            iceberg::ErrorKind::DataInvalid,
            self.explain(location),
        ))
    }

    /// Refuses a file the table does not own.
    fn ensure_owned(current: &str, location: &str) -> iceberg::Result<()> {
        if is_within(current, location) {
            return Ok(());
        }
        Err(iceberg::Error::new(
            iceberg::ErrorKind::DataInvalid,
            format!(
                "This commit names the file '{location}', which is outside the table's own \
                 storage ('{current}'). A commit records files the table owns; one it does \
                 not own would be read by a scan plan and deleted by a purge, neither of \
                 which this table is entitled to do to it."
            ),
        ))
    }

    /// Why a location was refused, in terms of the scope that refused it.
    ///
    /// The two scopes fail for different reasons and an operator reading the
    /// message has different work to do, so they do not share a sentence.
    fn explain(&self, location: &str) -> String {
        match self.scope {
            LocationScope::Table => format!(
                "Storage location '{location}' is outside '{}', which is where this \
                 catalog keeps this resource's files. A location-scoped credential is \
                 how a namespace-scoped grant is enforced, so a resource may not \
                 declare storage outside the prefix its name puts it in. Set \
                 `storage.location_scope = \"warehouse\"` to adopt a layout that \
                 predates this catalog — and read what that costs before you do.",
                self.root
            ),
            LocationScope::Warehouse => format!(
                "Storage location '{location}' is outside this catalog's warehouse \
                 ('{}'). A catalog only manages locations within its own warehouse, \
                 because the credentials it vends are scoped to them.",
                self.root
            ),
        }
    }
}

/// `<warehouse>/<namespace…>/<name>`: where the registries put a resource's
/// files, restated so a client-supplied location can be held to it.
///
/// Kept here rather than in each backend because it is the same rule read from
/// two sides — the side that *assigns* a location and the side that *checks*
/// one — and a copy is one edit away from the two disagreeing, silently and in
/// the direction that grants more.
pub fn canonical_prefix(warehouse: &str, namespace: &[String], name: &str) -> String {
    let mut prefix = join_segments(warehouse, namespace);
    prefix.push('/');
    prefix.push_str(name);
    prefix
}

/// `<warehouse>/<namespace…>`, with no trailing slash.
///
/// The prefix a backend keeps one namespace's resources under. Public because
/// every [`CatalogStore`](crate::catalog::CatalogStore) answers
/// `namespace_prefix_for` with it, and a per-backend copy is one edit away from
/// two backends laying out the same namespace differently.
pub fn namespace_prefix(warehouse: &str, namespace: &[String]) -> String {
    join_segments(warehouse, namespace)
}

/// `<warehouse>/<namespace…>`, with no trailing slash.
fn join_segments(warehouse: &str, namespace: &[String]) -> String {
    let mut out = warehouse.trim_end_matches('/').to_string();
    for level in namespace {
        out.push('/');
        out.push_str(level);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `file://` URL becomes a usable path on both platforms.
    ///
    /// The Windows half is where this earns its keep: `file:///C:/data` strips
    /// to `/C:/data`, which has a root but no drive prefix, so `is_absolute` is
    /// false and joining it onto the current directory produces a path with a
    /// colon where none may be. The operating system answers
    /// `ERROR_INVALID_NAME` somewhere far from where the path was built.
    #[test]
    fn a_file_url_becomes_a_path_on_either_platform() {
        // Unix, and Windows written the way a URL writes it.
        assert_eq!(
            without_url_prefix("file:///var/lib/rustberg", false),
            "/var/lib/rustberg"
        );
        assert_eq!(without_url_prefix("file:///C:/data", true), "C:/data");
        assert_eq!(without_url_prefix("file:///C:\\data", true), "C:\\data");
        assert_eq!(without_url_prefix("file:///C:", true), "C:");

        // Two slashes, no third: already a path.
        assert_eq!(without_url_prefix("file://C:/data", true), "C:/data");

        // No scheme at all passes through.
        assert_eq!(
            without_url_prefix("/var/lib/rustberg", false),
            "/var/lib/rustberg"
        );
        assert_eq!(without_url_prefix("C:/data", true), "C:/data");
    }

    /// Nothing outside this module spells the `file://` rule by hand.
    ///
    /// Both directions look like one line of string handling and are not, and
    /// the way that surfaces is a platform-specific failure a long way from the
    /// code that wrote it — a warehouse URL with a drive letter in the authority
    /// position, or a path with a leading slash before one. Every such spelling
    /// found so far was somebody reaching for the obvious `strip_prefix` or
    /// `format!`, in a place where the rule was not visible.
    ///
    /// So it is a gate rather than a convention. Literals are untouched: a fixed
    /// `"file:///tmp/x"` in a fixture names no real path and cannot be wrong.
    /// What is banned is *deriving* one from a path or a URL.
    #[test]
    fn the_file_url_rule_has_one_spelling() {
        const BANNED: &[(&str, &str)] = &[
            ("strip_prefix(\"file://\")", "location::path_from_url"),
            ("trim_start_matches(\"file://\")", "location::path_from_url"),
            ("format!(\"file://{}\"", "location::url_from_path"),
            ("format!(\"file:///{}\"", "location::url_from_path"),
        ];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut offences = Vec::new();

        let mut pending = vec![root.join("src"), root.join("tests")];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                // This module is where the rule lives.
                if path == root.join("src").join("location.rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for (number, line) in text.lines().enumerate() {
                    let code = line.trim_start();
                    if code.starts_with("//") {
                        continue;
                    }
                    for (banned, instead) in BANNED {
                        if code.contains(banned) {
                            offences.push(format!(
                                "{}:{}: `{banned}` — use `{instead}`",
                                path.strip_prefix(root).unwrap_or(&path).display(),
                                number + 1
                            ));
                        }
                    }
                }
            }
        }

        assert!(
            offences.is_empty(),
            "a `file://` URL and a local path are not the same string on every \
             platform, and these spell the conversion by hand:\n  {}",
            offences.join("\n  ")
        );
    }

    /// A path becomes a URL and comes back unchanged, on either platform.
    ///
    /// The round trip is the property that matters: a warehouse is written as a
    /// URL, read back as a path, and joined with namespace segments in between.
    /// If the two halves disagree the files land somewhere nothing looks for
    /// them, and the first sign of it is a read or a delete failing far away.
    #[test]
    fn a_path_and_its_url_round_trip() {
        // (path, platform, its URL, the path that comes back)
        for (path, windows, url, back) in [
            (
                "/var/lib/rustberg",
                false,
                "file:///var/lib/rustberg",
                "/var/lib/rustberg",
            ),
            (
                "C:/data/warehouse",
                true,
                "file:///C:/data/warehouse",
                "C:/data/warehouse",
            ),
            (
                "C:\\data\\warehouse",
                true,
                "file:///C:/data/warehouse",
                "C:/data/warehouse",
            ),
            ("/tmp/wh", true, "file:///tmp/wh", "/tmp/wh"),
        ] {
            assert_eq!(to_url(path, windows), url, "{path} -> url");
            assert_eq!(
                without_url_prefix(&to_url(path, windows), windows),
                back,
                "{path} -> url -> path"
            );
        }

        // The shape that broke Windows: two slashes and native separators.
        assert_ne!(
            to_url("C:\\data\\warehouse", true),
            "file://C:\\data\\warehouse",
            "a drive letter must not land in the authority position"
        );
    }

    /// The drive-letter rule applies on Windows only, so a Unix path that
    /// happens to look like one is left alone.
    #[test]
    fn a_unix_path_is_never_read_as_a_drive() {
        assert_eq!(without_url_prefix("file:///C:/data", false), "/C:/data");
        assert_eq!(
            without_url_prefix("file:///etc/rustberg", true),
            "/etc/rustberg"
        );
        // A single letter and no colon is a directory, not a drive.
        assert_eq!(without_url_prefix("file:///c/data", true), "/c/data");
    }

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

    /// Segment comparison drops the leading slash, so without an explicit test
    /// a *relative* path is admitted into an absolute warehouse — two different
    /// directories, decided equal.
    #[test]
    fn a_relative_path_is_not_inside_an_absolute_warehouse() {
        assert!(!is_within("/srv/warehouse", "srv/warehouse/db/t"));
        assert!(!is_within("file:///srv/warehouse", "srv/warehouse/db/t"));
        assert!(!is_within("srv/warehouse", "/srv/warehouse/db/t"));
        assert!(!is_prefix_within("/srv/wh/t", "srv/wh/t/data/"));
    }

    /// A traversal segment would let a location climb out of the root it
    /// appears to be under.
    #[test]
    fn traversal_is_refused() {
        assert!(!is_within("s3://bucket/wh", "s3://bucket/wh/../evil/t"));
        assert!(!is_within("/srv/wh", "/srv/wh/db/../../etc/passwd"));
    }

    /// `.` is an ordinary object key segment, so it is compared rather than
    /// resolved: `wh/./t` and `wh/t` are two different objects in S3.
    #[test]
    fn a_dot_segment_is_an_ordinary_segment() {
        assert!(is_within("s3://bucket/wh", "s3://bucket/wh/./t"));
        assert!(!is_within("s3://bucket/wh/./t", "s3://bucket/wh/t"));
        assert!(!is_within("s3://bucket/./wh", "s3://bucket/wh/t"));
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

    /// The bound every handler builds. `db` is the namespace, `events` the
    /// table, so under the default scope the resource's storage lives under
    /// `.../wh/db/events` and nothing wider is accepted.
    fn table_bound() -> LocationBound {
        LocationBound::new(
            LocationScope::Table,
            "s3://bucket/wh",
            "s3://bucket/wh/db",
            "events",
        )
    }

    fn warehouse_bound() -> LocationBound {
        LocationBound::new(
            LocationScope::Warehouse,
            "s3://bucket/wh",
            "s3://bucket/wh/db",
            "events",
        )
    }

    #[test]
    fn ensure_reports_a_bad_request_with_both_locations_named() {
        let err = warehouse_bound().ensure("s3://elsewhere/t").unwrap_err();
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
        assert!(warehouse_bound().ensure("").is_err());
        assert!(warehouse_bound().ensure("   ").is_err());
        assert!(table_bound().ensure("").is_err());
    }

    #[test]
    fn ensure_accepts_the_ordinary_case() {
        assert!(warehouse_bound().ensure("s3://bucket/wh/db/t").is_ok());
        assert!(table_bound().ensure("s3://bucket/wh/db/events").is_ok());
        assert!(
            table_bound()
                .ensure("s3://bucket/wh/db/events/data/f.parquet")
                .is_ok(),
            "a sub-layout under the resource's own prefix is its own business"
        );
    }

    /// The whole point of the default scope. Under `Warehouse` this location is
    /// accepted, and a caller with `Update` on `db.events` alone is credentialed
    /// for `finance/secret` — a prefix its policy never mentioned.
    #[test]
    fn another_namespaces_prefix_is_refused_under_the_default_scope() {
        let other = "s3://bucket/wh/finance/secret";

        assert!(
            warehouse_bound().ensure(other).is_ok(),
            "the loose scope is what it says it is"
        );
        assert!(
            table_bound().ensure(other).is_err(),
            "the default scope refuses another namespace's prefix"
        );
    }

    /// And a sibling *table* in the caller's own namespace, which is the same
    /// hole one level down: a Cedar policy can name an individual table.
    #[test]
    fn a_sibling_tables_prefix_is_refused_under_the_default_scope() {
        assert!(table_bound().ensure("s3://bucket/wh/db/salaries").is_err());
    }

    /// The sibling-spelling hazard reaches the tighter bound too.
    #[test]
    fn a_sibling_spelling_of_the_resource_prefix_is_refused() {
        assert!(
            table_bound()
                .ensure("s3://bucket/wh/db/events-evil")
                .is_err()
        );
        assert!(table_bound().ensure("s3://bucket/wh/db/events2").is_err());
    }

    /// The bound is the canonical prefix, and the canonical prefix is what the
    /// registries assign. If these two ever disagree, every default location
    /// this catalog creates fails its own check.
    #[test]
    fn the_default_location_a_registry_assigns_passes_its_own_bound() {
        let assigned = canonical_prefix("s3://bucket/wh", &["db".to_string()], "events");
        assert_eq!(assigned, "s3://bucket/wh/db/events");
        assert!(table_bound().ensure(&assigned).is_ok());

        // A trailing slash on the warehouse must not produce `wh//db/events`.
        assert_eq!(
            canonical_prefix("s3://bucket/wh/", &["db".to_string()], "events"),
            "s3://bucket/wh/db/events"
        );

        // Nested namespaces nest in the path, which is what makes two
        // namespaces' prefixes disjoint by construction.
        assert_eq!(
            canonical_prefix(
                "s3://bucket/wh",
                &["a".to_string(), "b".to_string()],
                "events"
            ),
            "s3://bucket/wh/a/b/events"
        );
    }

    /// An unrecognised scope is a startup failure, never a guess. Guessing tight
    /// breaks a deployment that meant loose; guessing loose removes a security
    /// bound without saying so.
    #[test]
    fn an_unknown_scope_is_refused_rather_than_defaulted() {
        assert_eq!(LocationScope::parse("table").unwrap(), LocationScope::Table);
        assert_eq!(
            LocationScope::parse(" WAREHOUSE ").unwrap(),
            LocationScope::Warehouse
        );
        assert!(LocationScope::parse("namespace").is_err());
        assert!(LocationScope::parse("").is_err());
        assert_eq!(LocationScope::default(), LocationScope::Table);
    }

    /// The rule that keeps a provider from becoming a confused deputy: no
    /// configured scope is no scope, not universal scope.    /// The rule that keeps a provider from becoming a confused deputy: no
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

    /// The check a `registerTable` performs before it publishes anything, in the
    /// `iceberg::Error` vocabulary the backend that runs it speaks.
    #[test]
    fn a_declared_location_outside_the_bound_is_refused() {
        assert!(
            table_bound()
                .ensure_iceberg("s3://bucket/wh/db/events")
                .is_ok()
        );

        let err = table_bound()
            .ensure_iceberg("s3://bucket/wh/finance/secret")
            .unwrap_err();
        assert_eq!(err.kind(), iceberg::ErrorKind::DataInvalid);
        assert!(err.to_string().contains("s3://bucket/wh/finance/secret"));
        assert!(err.to_string().contains("s3://bucket/wh/db/events"));
    }

    /// The sibling-prefix hazard reaches this caller too.
    #[test]
    fn a_declared_sibling_prefix_is_refused() {
        assert!(
            warehouse_bound()
                .ensure_iceberg("s3://bucket/wh-evil")
                .is_err()
        );
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
