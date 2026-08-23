//! One endpoint in front of several catalogs.
//!
//! # The mount table
//!
//! Each **top-level namespace** resolves to a backend:
//!
//! ```text
//!   prod.analytics.events    →  mount "prod"     → namespace analytics.events
//!   legacy.warehouse.orders  →  mount "legacy"   → namespace warehouse.orders
//!   scratch.tmp              →  (unmounted)      → the native catalog
//! ```
//!
//! The mount name is **stripped** on the way down and restored on the way up. A
//! mounted catalog has its own namespaces and has never heard of Rustberg's
//! mount name; passing it through would ask for a namespace that does not exist
//! there. Everything a mount returns is re-prefixed, so a client sees one
//! coherent tree and never learns where the boundary is.
//!
//! # Why this changes what a name resolves to, and not how a decision is made
//!
//! The authorization model already treats the top-level namespace as the unit of
//! ownership, so mounting slots in underneath it: [`guard`] still resolves an
//! owner and asks the same question of the same policy set. What changes is only
//! which backend answers `get_namespace`.
//!
//! [`guard`]: crate::catalog::v1::guard
//!
//! # Ownership is declared by the mount
//!
//! A mount states which tenant owns it, and that answer is authoritative for
//! everything inside. It has to be: a foreign catalog's namespaces carry no
//! Rustberg ownership property, so reading ownership from them would make every
//! federated namespace unowned — and an unowned namespace is invisible to
//! everybody, which would silently turn a working mount into an empty one.
//!
//! Declaring it also makes the boundary honest. A mount is somebody else's
//! catalog; Rustberg cannot police who writes what inside it, so claiming
//! per-namespace ownership there would be a promise it cannot keep. One mount,
//! one tenant.
//!
//! # What cannot cross a mount
//!
//! Renames and multi-table transactions are refused across mounts, because
//! neither can be made atomic between two independent catalogs. Rustberg could
//! *sequence* them and usually get away with it; it would also, sometimes, leave
//! a table dropped from one catalog and never created in the other. Refusing is
//! the only answer that is true in every case.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use iceberg::spec::ViewMetadata;
use iceberg::table::Table;
use iceberg::{
    Error, ErrorKind, Namespace, NamespaceIdent, Result, TableCreation, TableIdent,
    TableRequirement, TableUpdate,
};

use super::capabilities::{Capabilities, Capability};
use super::store::{CatalogStore, Entry, Page, PageRequest, StorageHealthStatus};
use crate::catalog::v1::ownership;

/// One mounted catalog.
pub struct Mount {
    /// Top-level namespace this mount answers for.
    pub name: String,
    /// The catalog behind it.
    pub store: Arc<dyn CatalogStore>,
    /// What it can do.
    pub capabilities: Capabilities,
    /// Tenant that owns everything in this mount.
    pub owner: String,
    /// Warehouse this mount's tables live in, when it has one of its own.
    ///
    /// `None` for a mount that stores nothing — a remote catalog is the case.
    /// Two things read it: the confinement check, which must confine a mounted
    /// table to *this* warehouse rather than the server's, and credential
    /// vending, which will not mint a credential for a prefix it was not told
    /// about.
    pub warehouse: Option<String>,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mount")
            .field("name", &self.name)
            .field("capabilities", &self.capabilities)
            .field("owner", &self.owner)
            .field("warehouse", &self.warehouse)
            .finish_non_exhaustive()
    }
}

/// A catalog that routes by top-level namespace.
#[derive(Debug)]
pub struct FederatedCatalog {
    mounts: HashMap<String, Arc<Mount>>,
    /// Answers for namespaces no mount claims.
    ///
    /// Keeping a native catalog underneath means mounting is additive: a
    /// deployment that adds one mount does not have to move everything else.
    default: Arc<dyn CatalogStore>,
}

impl FederatedCatalog {
    /// Builds a federated catalog over `default`, with `mounts` layered on top.
    ///
    /// # Errors
    ///
    /// Returns an error when two mounts claim the same name, or a mount name is
    /// not a usable namespace segment.
    pub fn new(default: Arc<dyn CatalogStore>, mounts: Vec<Mount>) -> Result<Self> {
        let mut table = HashMap::new();

        for mount in mounts {
            if mount.name.trim().is_empty() {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    "A mount name must not be empty",
                ));
            }
            // The name becomes a namespace segment, so it must survive the same
            // encoding every other segment does.
            if mount.name.contains('\u{1F}') || mount.name.contains('\u{1E}') {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!("Mount name '{}' contains a reserved separator", mount.name),
                ));
            }
            if table.contains_key(&mount.name) {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!("Two mounts are both named '{}'", mount.name),
                ));
            }
            table.insert(mount.name.clone(), Arc::new(mount));
        }

        Ok(Self {
            mounts: table,
            default,
        })
    }

    /// The mounts, for capability negotiation and diagnostics.
    pub fn mounts(&self) -> impl Iterator<Item = &Arc<Mount>> {
        self.mounts.values()
    }

    /// Every warehouse this catalog manages: the native one, plus each mount's.
    ///
    /// Credential vending is scoped to these. A mount whose warehouse is absent
    /// from the list gets no credentials vended for it — silently, because the
    /// provider refuses and the request still succeeds without them. That is
    /// safe and useless, so the list has to be complete.
    ///
    /// A mount with no warehouse of its own contributes nothing, which is
    /// correct: Rustberg does not own a remote catalog's storage and has no
    /// business minting credentials for it.
    pub fn warehouses(&self, native: &str) -> Vec<String> {
        let mut warehouses = vec![native.to_string()];
        let mut mounted: Vec<String> = self
            .mounts
            .values()
            .filter_map(|mount| mount.warehouse.clone())
            .collect();
        mounted.sort();
        mounted.dedup();
        warehouses.extend(mounted);
        warehouses
    }

    /// Lists the top level: every mount, then the native catalog's own roots.
    ///
    /// # Why the cursor is tagged
    ///
    /// The root listing draws on two sources whose cursors are unrelated — a
    /// mount name is configuration, a native cursor is a backend key. Handing
    /// one to the other is not a harmless mistake: `RedbCatalog` seeks to
    /// whatever cursor it is given, and a root scan has no prefix to reject it
    /// against, so a mount cursor makes it skip every namespace sorting below
    /// that string. Namespaces then vanish from the listing with no error.
    ///
    /// So a root cursor names the phase it belongs to, and only that phase ever
    /// reads it. An unrecognised cursor restarts the listing rather than being
    /// passed down — the same fail-safe `RedbCatalog::scan_start` applies to a
    /// forged token, for the same reason: a wrong seek loses rows silently,
    /// while a restart is merely repetition the client can see.
    ///
    /// The phase tag is also what positions the mounts by cursor rather than
    /// re-emitting them on every page.
    async fn list_root(&self, page: &PageRequest) -> Result<Page<NamespaceIdent>> {
        let limit = page.effective_limit();
        let mut entries: Vec<Entry<NamespaceIdent>> = Vec::with_capacity(limit);

        let resume = RootCursor::parse(page.after.as_deref());

        // ── Phase 1: mounts ────────────────────────────────────────────────
        //
        // Sorted, so the order is stable across pages and a cursor means the
        // same thing on the next request as it did on this one.
        if let RootCursor::Mounts { after } = &resume {
            let mut names: Vec<&String> = self.mounts.keys().collect();
            names.sort();

            for name in names {
                if entries.len() >= limit {
                    break;
                }
                if after.as_deref().is_some_and(|a| name.as_str() <= a) {
                    continue;
                }
                entries.push(Entry {
                    cursor: RootCursor::mount_token(name),
                    item: NamespaceIdent::from_vec(vec![name.clone()])?,
                });
            }
        }

        // The page filled during the mount phase. Whether anything follows —
        // another mount, or the native catalog — is unknown without asking, and
        // `next` means "there may be more" rather than "there is", so hand back
        // a token and let the next call answer. `collect_page` loops within one
        // request, so this costs a client no extra round trip.
        if entries.len() >= limit {
            let last = entries.last().expect("non-empty: len >= limit >= 1");
            return Ok(Page {
                next: Some(last.cursor.clone()),
                entries,
            });
        }

        // ── Phase 2: the native catalog ────────────────────────────────────
        let native_after = match &resume {
            RootCursor::Native { after } => after.clone(),
            // Falling out of the mount phase starts the native listing.
            RootCursor::Mounts { .. } => None,
        };
        let native = self
            .default
            .list_namespaces(
                None,
                &PageRequest {
                    after: native_after,
                    limit: limit - entries.len(),
                },
            )
            .await?;

        let next = native.next.map(|cursor| RootCursor::native_token(&cursor));
        for entry in native.entries {
            // A namespace a mount shadows is unreachable — every request for it
            // routes to the mount — so listing it would advertise something no
            // caller can load. `ensure_no_shadowing` refuses this at startup;
            // the skip keeps the listing honest if one is ever reached anyway.
            if entry
                .item
                .as_ref()
                .first()
                .is_some_and(|first| self.mounts.contains_key(first))
            {
                continue;
            }
            entries.push(Entry {
                cursor: RootCursor::native_token(&entry.cursor),
                item: entry.item,
            });
        }

        Ok(Page { entries, next })
    }

    /// Refuses to serve if a mount name shadows an existing native namespace.
    ///
    /// Routing sends every request for a mount's top-level name to that mount,
    /// so a native namespace of the same name becomes unreachable: it can be
    /// listed but never loaded, and everything beneath it disappears. That is
    /// the failure C1 already rejects for an unopenable mount — a subtree that
    /// silently does not exist — arriving by a different route, so it gets the
    /// same answer.
    ///
    /// Checked once at startup rather than per request. The collision cannot
    /// appear later: `create_namespace` on a mount root is refused, so the only
    /// way to have one is for the namespace to predate the mount.
    ///
    /// # Errors
    ///
    /// Names the mount and the namespace it would hide.
    pub async fn ensure_no_shadowing(&self) -> Result<()> {
        for name in self.mounts.keys() {
            let ident = NamespaceIdent::from_vec(vec![name.clone()])?;
            if self.default.namespace_exists(&ident).await? {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "Mount '{name}' shadows a namespace of the same name in the catalog \
                         underneath. Every request for '{name}' would route to the mount, so \
                         the existing namespace and everything in it would become unreachable. \
                         Rename the mount, or move the namespace, before starting."
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Capabilities every mount has, including the native default.
    ///
    /// This is what `GET /v1/config` publishes. See
    /// [`capabilities`](super::capabilities) for why the intersection.
    pub fn effective_capabilities(&self) -> Capabilities {
        self.mounts
            .values()
            .fold(Capabilities::full(), |acc, mount| {
                acc.intersect(mount.capabilities)
            })
    }

    /// Where a namespace lives, and what it is called there.
    ///
    /// `None` for the native default catalog, which sees names unchanged.
    fn route<'a>(&'a self, namespace: &NamespaceIdent) -> Routed<'a> {
        let Some(first) = namespace.as_ref().first() else {
            return Routed::Default;
        };

        match self.mounts.get(first) {
            Some(mount) => Routed::Mounted {
                mount,
                // The remainder, which may be empty — that is the mount root.
                inner: namespace.as_ref()[1..].to_vec(),
            },
            None => Routed::Default,
        }
    }

    /// Rejects an operation a mount cannot perform.
    fn require(mount: &Mount, capability: Capability) -> Result<()> {
        if capability.present_in(&mount.capabilities) {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::FeatureUnsupported,
            format!(
                "Mount '{}' does not support {capability}. It is served by a backend that \
                 cannot perform this operation, so it is refused rather than partially applied.",
                mount.name
            ),
        ))
    }

    /// Restores the mount prefix on a namespace coming back from a mount.
    fn prefixed(mount: &Mount, inner: &NamespaceIdent) -> Result<NamespaceIdent> {
        let mut parts = Vec::with_capacity(inner.as_ref().len() + 1);
        parts.push(mount.name.clone());
        parts.extend(inner.as_ref().iter().cloned());
        NamespaceIdent::from_vec(parts)
    }

    /// Restores the mount prefix on a table or view identifier.
    fn prefixed_ident(mount: &Mount, inner: &TableIdent) -> Result<TableIdent> {
        Ok(TableIdent::new(
            Self::prefixed(mount, inner.namespace())?,
            inner.name().to_string(),
        ))
    }

    /// Builds the identifier a mount should be asked about.
    ///
    /// # Errors
    ///
    /// A mount root has no inner namespace — the backend's own root is `[]`,
    /// which no catalog exposes — so naming a table directly under one is a
    /// request for something that cannot exist. Refused by name rather than by
    /// letting `NamespaceIdent::from_vec` answer "Namespace identifier can't be
    /// empty!", which tells an operator nothing about mounts.
    fn inner_ident(inner_namespace: Vec<String>, name: &str) -> Result<TableIdent> {
        Ok(TableIdent::new(
            Self::inner_namespace(inner_namespace)?,
            name.to_string(),
        ))
    }

    /// The namespace a mount should be asked about, refusing the mount root.
    fn inner_namespace(inner: Vec<String>) -> Result<NamespaceIdent> {
        if inner.is_empty() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                "A mount root is not a namespace: tables and views live in namespaces                  inside it, so create one first.",
            ));
        }
        NamespaceIdent::from_vec(inner)
    }

    /// Restores the mount prefix on a table coming back from a mount.
    ///
    /// A mount is asked about its own names, so what it returns is identified by
    /// them. Handing that straight back would give an embedding host — and
    /// anything else reading [`Table::identifier`] — a name that does not
    /// resolve through this catalog. The listings already re-prefix; so does
    /// everything that returns a single table.
    ///
    /// [`Table::identifier`]: iceberg::table::Table::identifier
    fn prefixed_table(mount: &Mount, table: Table) -> Result<Table> {
        let ident = Self::prefixed_ident(mount, table.identifier())?;

        let mut builder = Table::builder()
            .runtime(iceberg::Runtime::try_current()?)
            .identifier(ident)
            .metadata(table.metadata_ref())
            .file_io(table.file_io().clone())
            .readonly(table.readonly());
        if let Some(location) = table.metadata_location() {
            builder = builder.metadata_location(location);
        }
        builder.build()
    }

    /// The synthetic namespace a mount root resolves to.
    ///
    /// A mount root is not a namespace in the backend — the backend's own root
    /// is `[]`, which no catalog exposes. It exists so that `prod` is loadable,
    /// listable and, above all, *ownable*: authorization resolves an owner
    /// before it decides anything, so a mount root with no owner would be
    /// invisible and nothing beneath it would be reachable.
    fn mount_root(mount: &Mount) -> Result<Namespace> {
        let mut properties = HashMap::new();
        ownership::set_owner(&mut properties, &mount.owner);
        properties.insert("rustberg.mount".to_string(), mount.name.clone());

        Ok(Namespace::with_properties(
            NamespaceIdent::from_vec(vec![mount.name.clone()])?,
            properties,
        ))
    }

    /// Stamps the mount's owner onto whatever the backend returned.
    ///
    /// Authoritative rather than a fallback: a mounted catalog's properties are
    /// not under Rustberg's control, so honouring an ownership key found there
    /// would let whoever can write to that catalog reassign the tenant.
    fn own(mount: &Mount, namespace: Namespace) -> Namespace {
        let mut properties = namespace.properties().clone();
        ownership::set_owner(&mut properties, &mount.owner);
        Namespace::with_properties(namespace.name().clone(), properties)
    }
}

/// Separates a root cursor's phase tag from its payload.
///
/// The group separator, chosen because the two cursor spaces it joins already
/// use the other two: a native key contains `\u{1F}` between namespace parts and
/// `\u{1E}` before a name, and a mount name is forbidden both. So no payload can
/// contain this character, and splitting once from the left is exact.
const ROOT_CURSOR_SEP: char = '\u{1D}';

/// A position in the root listing, which spans two unrelated cursor spaces.
///
/// See [`FederatedCatalog::list_root`] for why the phase has to be carried
/// explicitly rather than inferred from the cursor's shape.
#[derive(Debug, PartialEq, Eq)]
enum RootCursor {
    /// Still listing mounts; resume after this name.
    Mounts { after: Option<String> },
    /// Listing the native catalog; resume after this backend cursor.
    Native { after: Option<String> },
}

impl RootCursor {
    /// Reads a cursor previously produced by [`Self::mount_token`] or
    /// [`Self::native_token`].
    ///
    /// Anything else — absent, forged, or left over from an older build —
    /// restarts the listing from the first mount. A client sees rows it has
    /// already seen, which is visible and recoverable; the alternative is
    /// seeking the native catalog to a string that means nothing there, which
    /// drops rows silently.
    fn parse(cursor: Option<&str>) -> Self {
        let Some((tag, rest)) = cursor.and_then(|c| c.split_once(ROOT_CURSOR_SEP)) else {
            return Self::Mounts { after: None };
        };
        let after = (!rest.is_empty()).then(|| rest.to_string());
        match tag {
            "m" => Self::Mounts { after },
            "n" => Self::Native { after },
            _ => Self::Mounts { after: None },
        }
    }

    /// A cursor resuming after mount `name`.
    fn mount_token(name: &str) -> String {
        format!("m{ROOT_CURSOR_SEP}{name}")
    }

    /// A cursor resuming after the native catalog's own `cursor`.
    fn native_token(cursor: &str) -> String {
        format!("n{ROOT_CURSOR_SEP}{cursor}")
    }
}

/// Where a request goes.
enum Routed<'a> {
    /// The native catalog underneath, with names unchanged.
    Default,
    /// A mount, with the mount prefix stripped.
    Mounted {
        mount: &'a Arc<Mount>,
        inner: Vec<String>,
    },
}

/// Refuses an operation that would span two mounts.
fn refuse_cross_mount(what: &str, src: &TableIdent, dest: &TableIdent) -> Error {
    Error::new(
        ErrorKind::FeatureUnsupported,
        format!(
            "Cannot {what} across mounts ({src} → {dest}). The two live in different \
             catalogs and the operation cannot be made atomic between them, so it is \
             refused rather than left half-applied."
        ),
    )
}

#[async_trait]
impl CatalogStore for FederatedCatalog {
    // ── Namespaces ──────────────────────────────────────────────────────

    async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: &PageRequest,
    ) -> Result<Page<NamespaceIdent>> {
        let Some(parent) = parent else {
            return self.list_root(page).await;
        };

        match self.route(parent) {
            Routed::Default => self.default.list_namespaces(Some(parent), page).await,
            Routed::Mounted { mount, inner } => {
                let inner_parent = if inner.is_empty() {
                    None
                } else {
                    Some(NamespaceIdent::from_vec(inner)?)
                };
                let page = mount
                    .store
                    .list_namespaces(inner_parent.as_ref(), page)
                    .await?;

                let mut entries = Vec::with_capacity(page.entries.len());
                for entry in page.entries {
                    entries.push(Entry {
                        cursor: entry.cursor,
                        item: Self::prefixed(mount, &entry.item)?,
                    });
                }
                Ok(Page {
                    entries,
                    next: page.next,
                })
            }
        }
    }

    async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        match self.route(namespace) {
            Routed::Default => self.default.create_namespace(namespace, properties).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                if inner.is_empty() {
                    return Err(Error::new(
                        ErrorKind::NamespaceAlreadyExists,
                        format!("'{}' is a mount and always exists", mount.name),
                    ));
                }
                let created = mount
                    .store
                    .create_namespace(&NamespaceIdent::from_vec(inner)?, properties)
                    .await?;
                Ok(Self::own(
                    mount,
                    Namespace::with_properties(
                        Self::prefixed(mount, created.name())?,
                        created.properties().clone(),
                    ),
                ))
            }
        }
    }

    async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        match self.route(namespace) {
            Routed::Default => self.default.get_namespace(namespace).await,
            Routed::Mounted { mount, inner } => {
                if inner.is_empty() {
                    return Self::mount_root(mount);
                }
                let found = mount
                    .store
                    .get_namespace(&NamespaceIdent::from_vec(inner)?)
                    .await?;
                Ok(Self::own(
                    mount,
                    Namespace::with_properties(
                        Self::prefixed(mount, found.name())?,
                        found.properties().clone(),
                    ),
                ))
            }
        }
    }

    async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        match self.route(namespace) {
            Routed::Default => self.default.namespace_exists(namespace).await,
            Routed::Mounted { mount, inner } => {
                if inner.is_empty() {
                    return Ok(true);
                }
                mount
                    .store
                    .namespace_exists(&NamespaceIdent::from_vec(inner)?)
                    .await
            }
        }
    }

    async fn update_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<()> {
        match self.route(namespace) {
            Routed::Default => self.default.update_namespace(namespace, properties).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                if inner.is_empty() {
                    return Err(Error::new(
                        ErrorKind::FeatureUnsupported,
                        format!(
                            "'{}' is a mount root; its properties are configuration, not \
                             catalog state",
                            mount.name
                        ),
                    ));
                }
                mount
                    .store
                    .update_namespace(&NamespaceIdent::from_vec(inner)?, properties)
                    .await
            }
        }
    }

    async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        match self.route(namespace) {
            Routed::Default => self.default.drop_namespace(namespace).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                if inner.is_empty() {
                    return Err(Error::new(
                        ErrorKind::FeatureUnsupported,
                        format!(
                            "'{}' is a mount and cannot be dropped through the API; remove it \
                             from configuration instead",
                            mount.name
                        ),
                    ));
                }
                mount
                    .store
                    .drop_namespace(&NamespaceIdent::from_vec(inner)?)
                    .await
            }
        }
    }

    // ── Tables ──────────────────────────────────────────────────────────

    async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        match self.route(namespace) {
            Routed::Default => self.default.list_tables(namespace, page).await,
            Routed::Mounted { mount, inner } => {
                // A mount root holds namespaces, never tables: the backend's own
                // root is `[]`, which no catalog exposes. An empty page is the
                // truthful answer and the one a client can act on — refusing the
                // listing would make an otherwise working mount look broken at
                // the first thing an engine does after `listNamespaces`.
                if inner.is_empty() {
                    return Ok(Page::empty());
                }
                let page = mount
                    .store
                    .list_tables(&NamespaceIdent::from_vec(inner)?, page)
                    .await?;
                let mut entries = Vec::with_capacity(page.entries.len());
                for entry in page.entries {
                    entries.push(Entry {
                        cursor: entry.cursor,
                        item: Self::prefixed_ident(mount, &entry.item)?,
                    });
                }
                Ok(Page {
                    entries,
                    next: page.next,
                })
            }
        }
    }

    async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        match self.route(namespace) {
            Routed::Default => self.default.create_table(namespace, creation).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                let table = mount
                    .store
                    .create_table(&Self::inner_namespace(inner)?, creation)
                    .await?;
                Self::prefixed_table(mount, table)
            }
        }
    }

    async fn stage_create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        match self.route(namespace) {
            Routed::Default => self.default.stage_create_table(namespace, creation).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::StageCreate)?;
                let table = mount
                    .store
                    .stage_create_table(&Self::inner_namespace(inner)?, creation)
                    .await?;
                Self::prefixed_table(mount, table)
            }
        }
    }

    async fn metadata_pointer(&self, table: &TableIdent) -> Result<Option<String>> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.metadata_pointer(table).await,
            Routed::Mounted { mount, inner } => {
                mount
                    .store
                    .metadata_pointer(&Self::inner_ident(inner, table.name())?)
                    .await
            }
        }
    }

    async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.load_table(table).await,
            Routed::Mounted { mount, inner } => {
                let loaded = mount
                    .store
                    .load_table(&Self::inner_ident(inner, table.name())?)
                    .await?;
                Self::prefixed_table(mount, loaded)
            }
        }
    }

    async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.table_exists(table).await,
            Routed::Mounted { mount, inner } => {
                mount
                    .store
                    .table_exists(&Self::inner_ident(inner, table.name())?)
                    .await
            }
        }
    }

    async fn register_table(&self, table: &TableIdent, metadata_location: String) -> Result<Table> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.register_table(table, metadata_location).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Register)?;
                let registered = mount
                    .store
                    .register_table(&Self::inner_ident(inner, table.name())?, metadata_location)
                    .await?;
                Self::prefixed_table(mount, registered)
            }
        }
    }

    async fn commit_table(
        &self,
        table: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        match self.route(table.namespace()) {
            Routed::Default => {
                self.default
                    .commit_table(table, requirements, updates)
                    .await
            }
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                let committed = mount
                    .store
                    .commit_table(
                        &Self::inner_ident(inner, table.name())?,
                        requirements,
                        updates,
                    )
                    .await?;
                Self::prefixed_table(mount, committed)
            }
        }
    }

    async fn commit_tables_atomic(
        &self,
        commits: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
    ) -> Result<Vec<Table>> {
        if commits.is_empty() {
            return Ok(Vec::new());
        }

        // Every table must live in the same place, because atomicity is a
        // property of one backend's transaction and there is no protocol between
        // two of them. A sequenced approximation would usually work and would
        // sometimes leave one catalog advanced and the other not.
        let mut target: Option<Option<String>> = None;
        for (ident, _, _) in &commits {
            let mount = match self.route(ident.namespace()) {
                Routed::Default => None,
                Routed::Mounted { mount, .. } => Some(mount.name.clone()),
            };
            match &target {
                None => target = Some(mount),
                Some(existing) if *existing == mount => {}
                Some(existing) => {
                    return Err(Error::new(
                        ErrorKind::FeatureUnsupported,
                        format!(
                            "A transaction cannot span catalogs: this one touches {} and {}. \
                             Atomicity is a property of one backend, and sequencing the two \
                             would risk leaving one advanced and the other not.",
                            describe_target(existing),
                            describe_target(&mount)
                        ),
                    ));
                }
            }
        }

        match self.route(commits[0].0.namespace()) {
            Routed::Default => self.default.commit_tables_atomic(commits).await,
            Routed::Mounted { mount, .. } => {
                Self::require(mount, Capability::MultiTableCommit)?;

                let mut inner = Vec::with_capacity(commits.len());
                for (ident, requirements, updates) in commits {
                    let stripped = ident.namespace().as_ref()[1..].to_vec();
                    inner.push((
                        Self::inner_ident(stripped, ident.name())?,
                        requirements,
                        updates,
                    ));
                }
                let committed = mount.store.commit_tables_atomic(inner).await?;
                committed
                    .into_iter()
                    .map(|table| Self::prefixed_table(mount, table))
                    .collect()
            }
        }
    }

    async fn rename_table(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        match (self.route(src.namespace()), self.route(dest.namespace())) {
            (Routed::Default, Routed::Default) => self.default.rename_table(src, dest).await,
            (
                Routed::Mounted {
                    mount: from,
                    inner: from_inner,
                },
                Routed::Mounted {
                    mount: to,
                    inner: to_inner,
                },
            ) if from.name == to.name => {
                Self::require(from, Capability::Write)?;
                from.store
                    .rename_table(
                        &Self::inner_ident(from_inner, src.name())?,
                        &Self::inner_ident(to_inner, dest.name())?,
                    )
                    .await
            }
            _ => Err(refuse_cross_mount("rename a table", src, dest)),
        }
    }

    async fn drop_table(&self, table: &TableIdent) -> Result<()> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.drop_table(table).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Write)?;
                mount
                    .store
                    .drop_table(&Self::inner_ident(inner, table.name())?)
                    .await
            }
        }
    }

    async fn purge_table(&self, table: &TableIdent) -> Result<()> {
        match self.route(table.namespace()) {
            Routed::Default => self.default.purge_table(table).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Purge)?;
                mount
                    .store
                    .purge_table(&Self::inner_ident(inner, table.name())?)
                    .await
            }
        }
    }

    // ── Views ───────────────────────────────────────────────────────────

    async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: &PageRequest,
    ) -> Result<Page<TableIdent>> {
        match self.route(namespace) {
            Routed::Default => self.default.list_views(namespace, page).await,
            Routed::Mounted { mount, inner } => {
                // A mount without views has none, which is an empty listing
                // rather than an error: listing is how a client discovers what
                // is there, and refusing it would make an otherwise usable mount
                // look broken.
                if !mount.capabilities.views || inner.is_empty() {
                    return Ok(Page::empty());
                }
                let page = mount
                    .store
                    .list_views(&NamespaceIdent::from_vec(inner)?, page)
                    .await?;
                let mut entries = Vec::with_capacity(page.entries.len());
                for entry in page.entries {
                    entries.push(Entry {
                        cursor: entry.cursor,
                        item: Self::prefixed_ident(mount, &entry.item)?,
                    });
                }
                Ok(Page {
                    entries,
                    next: page.next,
                })
            }
        }
    }

    async fn view_exists(&self, view: &TableIdent) -> Result<bool> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.view_exists(view).await,
            Routed::Mounted { mount, inner } => {
                if !mount.capabilities.views {
                    return Ok(false);
                }
                mount
                    .store
                    .view_exists(&Self::inner_ident(inner, view.name())?)
                    .await
            }
        }
    }

    async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.load_view(view).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Views)?;
                mount
                    .store
                    .load_view(&Self::inner_ident(inner, view.name())?)
                    .await
            }
        }
    }

    async fn register_view(
        &self,
        view: &TableIdent,
        metadata_location: String,
    ) -> Result<(String, ViewMetadata)> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.register_view(view, metadata_location).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Views)?;
                Self::require(mount, Capability::Register)?;
                mount
                    .store
                    .register_view(&Self::inner_ident(inner, view.name())?, metadata_location)
                    .await
            }
        }
    }

    async fn create_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.create_view(view, metadata).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Views)?;
                Self::require(mount, Capability::Write)?;
                mount
                    .store
                    .create_view(&Self::inner_ident(inner, view.name())?, metadata)
                    .await
            }
        }
    }

    async fn update_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.update_view(view, metadata).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Views)?;
                Self::require(mount, Capability::Write)?;
                mount
                    .store
                    .update_view(&Self::inner_ident(inner, view.name())?, metadata)
                    .await
            }
        }
    }

    async fn drop_view(&self, view: &TableIdent) -> Result<()> {
        match self.route(view.namespace()) {
            Routed::Default => self.default.drop_view(view).await,
            Routed::Mounted { mount, inner } => {
                Self::require(mount, Capability::Views)?;
                Self::require(mount, Capability::Write)?;
                mount
                    .store
                    .drop_view(&Self::inner_ident(inner, view.name())?)
                    .await
            }
        }
    }

    async fn rename_view(&self, src: &TableIdent, dest: &TableIdent) -> Result<()> {
        match (self.route(src.namespace()), self.route(dest.namespace())) {
            (Routed::Default, Routed::Default) => self.default.rename_view(src, dest).await,
            (
                Routed::Mounted {
                    mount: from,
                    inner: from_inner,
                },
                Routed::Mounted {
                    mount: to,
                    inner: to_inner,
                },
            ) if from.name == to.name => {
                Self::require(from, Capability::Views)?;
                Self::require(from, Capability::Write)?;
                from.store
                    .rename_view(
                        &Self::inner_ident(from_inner, src.name())?,
                        &Self::inner_ident(to_inner, dest.name())?,
                    )
                    .await
            }
            _ => Err(refuse_cross_mount("rename a view", src, dest)),
        }
    }

    // ── Operations ──────────────────────────────────────────────────────

    async fn warehouse_for(&self, namespace: &NamespaceIdent) -> Option<String> {
        match self.route(namespace) {
            Routed::Default => self.default.warehouse_for(namespace).await,
            // The mount's declared warehouse, not the backend's: a mount root
            // has no namespace to ask the backend about, and configuration is
            // where the answer comes from anyway.
            Routed::Mounted { mount, .. } => mount.warehouse.clone(),
        }
    }

    async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
        // The native catalog decides overall health. A mount that is down makes
        // its own namespaces fail, which the client sees directly; reporting the
        // whole server unready because a federated catalog is unreachable would
        // take down the namespaces that still work.
        let mut status = self.default.storage_health_check().await?;

        let mut unhealthy = Vec::new();
        for mount in self.mounts.values() {
            match mount.store.storage_health_check().await {
                Ok(check) if check.healthy => {}
                _ => unhealthy.push(mount.name.clone()),
            }
        }

        if !unhealthy.is_empty() {
            unhealthy.sort();
            status.message = Some(format!("Unreachable mounts: {}", unhealthy.join(", ")));
        }

        Ok(status)
    }
}

/// Names a routing target for an error message.
fn describe_target(target: &Option<String>) -> String {
    match target {
        Some(name) => format!("mount '{name}'"),
        None => "the native catalog".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(parts: &[&str]) -> NamespaceIdent {
        NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    /// A store that answers nothing; the routing tests only need identity.
    #[derive(Debug)]
    struct Nowhere;

    #[async_trait]
    impl CatalogStore for Nowhere {
        async fn list_namespaces(
            &self,
            _: Option<&NamespaceIdent>,
            _: &PageRequest,
        ) -> Result<Page<NamespaceIdent>> {
            Ok(Page::empty())
        }
        async fn create_namespace(
            &self,
            n: &NamespaceIdent,
            p: HashMap<String, String>,
        ) -> Result<Namespace> {
            Ok(Namespace::with_properties(n.clone(), p))
        }
        async fn get_namespace(&self, n: &NamespaceIdent) -> Result<Namespace> {
            Ok(Namespace::with_properties(n.clone(), HashMap::new()))
        }
        async fn namespace_exists(&self, _: &NamespaceIdent) -> Result<bool> {
            Ok(true)
        }
        async fn update_namespace(
            &self,
            _: &NamespaceIdent,
            _: HashMap<String, String>,
        ) -> Result<()> {
            Ok(())
        }
        async fn drop_namespace(&self, _: &NamespaceIdent) -> Result<()> {
            Ok(())
        }
        async fn list_tables(
            &self,
            _: &NamespaceIdent,
            _: &PageRequest,
        ) -> Result<Page<TableIdent>> {
            Ok(Page::empty())
        }
        async fn create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn stage_create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn metadata_pointer(&self, _: &TableIdent) -> Result<Option<String>> {
            Ok(None)
        }
        async fn load_table(&self, _: &TableIdent) -> Result<Table> {
            Err(Error::new(ErrorKind::TableNotFound, "test stub"))
        }
        async fn table_exists(&self, _: &TableIdent) -> Result<bool> {
            Ok(false)
        }
        async fn register_table(&self, _: &TableIdent, _: String) -> Result<Table> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn commit_table(
            &self,
            _: &TableIdent,
            _: Vec<TableRequirement>,
            _: Vec<TableUpdate>,
        ) -> Result<Table> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn commit_tables_atomic(
            &self,
            _: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
        ) -> Result<Vec<Table>> {
            Ok(Vec::new())
        }
        async fn rename_table(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn drop_table(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn purge_table(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn list_views(
            &self,
            _: &NamespaceIdent,
            _: &PageRequest,
        ) -> Result<Page<TableIdent>> {
            Ok(Page::empty())
        }
        async fn view_exists(&self, _: &TableIdent) -> Result<bool> {
            Ok(false)
        }
        async fn load_view(&self, _: &TableIdent) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::TableNotFound, "test stub"))
        }
        async fn register_view(&self, _: &TableIdent, _: String) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn create_view(
            &self,
            _: &TableIdent,
            _: ViewMetadata,
        ) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn update_view(
            &self,
            _: &TableIdent,
            _: ViewMetadata,
        ) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn drop_view(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn rename_view(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn warehouse_for(&self, _: &NamespaceIdent) -> Option<String> {
            None
        }
        async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
            Ok(StorageHealthStatus::healthy("stub", 0))
        }
    }

    fn mount(name: &str, capabilities: Capabilities) -> Mount {
        Mount {
            name: name.to_string(),
            store: Arc::new(Nowhere),
            capabilities,
            owner: "acme".to_string(),
            warehouse: Some(format!("file:///warehouses/{name}")),
        }
    }

    fn federated(mounts: Vec<Mount>) -> FederatedCatalog {
        FederatedCatalog::new(Arc::new(Nowhere), mounts).expect("mounts are valid")
    }

    /// A store that answers `load_table` with a table identified by whatever it
    /// was asked about — which is what a real mount does, in its *own* names.
    #[derive(Debug)]
    struct Echo;

    fn a_table(ident: TableIdent) -> Result<Table> {
        use iceberg::spec::{NestedField, PrimitiveType, Schema, TableMetadataBuilder, Type};

        let schema = Schema::builder()
            .with_fields(vec![
                NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            ])
            .build()?;
        let metadata = TableMetadataBuilder::new(
            schema,
            iceberg::spec::PartitionSpec::unpartition_spec(),
            iceberg::spec::SortOrder::unsorted_order(),
            "memory://warehouse/t".to_string(),
            iceberg::spec::FormatVersion::V2,
            HashMap::new(),
        )?
        .build()?
        .metadata;

        Table::builder()
            .runtime(iceberg::Runtime::try_current()?)
            .identifier(ident)
            .metadata(metadata)
            .metadata_location("memory://warehouse/t/metadata/v1.json")
            .file_io(crate::catalog::file_io::build_file_io()?)
            .build()
    }

    #[async_trait]
    impl CatalogStore for Echo {
        async fn list_namespaces(
            &self,
            _: Option<&NamespaceIdent>,
            _: &PageRequest,
        ) -> Result<Page<NamespaceIdent>> {
            Ok(Page::empty())
        }
        async fn create_namespace(
            &self,
            n: &NamespaceIdent,
            p: HashMap<String, String>,
        ) -> Result<Namespace> {
            Ok(Namespace::with_properties(n.clone(), p))
        }
        async fn get_namespace(&self, n: &NamespaceIdent) -> Result<Namespace> {
            Ok(Namespace::with_properties(n.clone(), HashMap::new()))
        }
        async fn namespace_exists(&self, _: &NamespaceIdent) -> Result<bool> {
            Ok(true)
        }
        async fn update_namespace(
            &self,
            _: &NamespaceIdent,
            _: HashMap<String, String>,
        ) -> Result<()> {
            Ok(())
        }
        async fn drop_namespace(&self, _: &NamespaceIdent) -> Result<()> {
            Ok(())
        }
        async fn list_tables(
            &self,
            _: &NamespaceIdent,
            _: &PageRequest,
        ) -> Result<Page<TableIdent>> {
            Ok(Page::empty())
        }
        async fn create_table(&self, n: &NamespaceIdent, c: TableCreation) -> Result<Table> {
            a_table(TableIdent::new(n.clone(), c.name))
        }
        async fn stage_create_table(&self, n: &NamespaceIdent, c: TableCreation) -> Result<Table> {
            a_table(TableIdent::new(n.clone(), c.name))
        }
        async fn metadata_pointer(&self, _: &TableIdent) -> Result<Option<String>> {
            Ok(None)
        }
        async fn load_table(&self, t: &TableIdent) -> Result<Table> {
            a_table(t.clone())
        }
        async fn table_exists(&self, _: &TableIdent) -> Result<bool> {
            Ok(true)
        }
        async fn register_table(&self, t: &TableIdent, _: String) -> Result<Table> {
            a_table(t.clone())
        }
        async fn commit_table(
            &self,
            t: &TableIdent,
            _: Vec<TableRequirement>,
            _: Vec<TableUpdate>,
        ) -> Result<Table> {
            a_table(t.clone())
        }
        async fn commit_tables_atomic(
            &self,
            commits: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
        ) -> Result<Vec<Table>> {
            commits.into_iter().map(|(t, _, _)| a_table(t)).collect()
        }
        async fn rename_table(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn drop_table(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn purge_table(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn list_views(
            &self,
            _: &NamespaceIdent,
            _: &PageRequest,
        ) -> Result<Page<TableIdent>> {
            Ok(Page::empty())
        }
        async fn view_exists(&self, _: &TableIdent) -> Result<bool> {
            Ok(false)
        }
        async fn load_view(&self, _: &TableIdent) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::TableNotFound, "test stub"))
        }
        async fn register_view(&self, _: &TableIdent, _: String) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn create_view(
            &self,
            _: &TableIdent,
            _: ViewMetadata,
        ) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn update_view(
            &self,
            _: &TableIdent,
            _: ViewMetadata,
        ) -> Result<(String, ViewMetadata)> {
            Err(Error::new(ErrorKind::FeatureUnsupported, "test stub"))
        }
        async fn drop_view(&self, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn rename_view(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
            Ok(())
        }
        async fn warehouse_for(&self, _: &NamespaceIdent) -> Option<String> {
            None
        }
        async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
            Ok(StorageHealthStatus::healthy("echo", 0))
        }
    }

    fn echo_mount(name: &str) -> Mount {
        Mount {
            name: name.to_string(),
            store: Arc::new(Echo),
            capabilities: Capabilities::full(),
            owner: "acme".to_string(),
            warehouse: Some(format!("memory://warehouses/{name}")),
        }
    }

    // ── A mount answers in its own names, and this catalog restores ours ──

    /// A mount is asked about `analytics.events` and answers about
    /// `analytics.events`. Handing that back unchanged gives an embedding host a
    /// name that does not resolve through this catalog — the listings already
    /// re-prefix, and every single-table path must agree with them.
    #[tokio::test]
    async fn a_loaded_table_carries_the_mounted_name() {
        let catalog = federated(vec![echo_mount("prod")]);
        let ident = TableIdent::new(ns(&["prod", "analytics"]), "events".to_string());

        let table = catalog.load_table(&ident).await.unwrap();
        assert_eq!(table.identifier(), &ident, "the mount prefix was dropped");
    }

    #[tokio::test]
    async fn every_table_returning_path_restores_the_mount_prefix() {
        let catalog = federated(vec![echo_mount("prod")]);
        let namespace = ns(&["prod", "analytics"]);
        let ident = TableIdent::new(namespace.clone(), "events".to_string());

        let creation = || {
            TableCreation::builder()
                .name("events".to_string())
                .schema(
                    iceberg::spec::Schema::builder()
                        .with_fields(vec![
                            iceberg::spec::NestedField::required(
                                1,
                                "id",
                                iceberg::spec::Type::Primitive(iceberg::spec::PrimitiveType::Long),
                            )
                            .into(),
                        ])
                        .build()
                        .unwrap(),
                )
                .build()
        };

        assert_eq!(
            catalog
                .create_table(&namespace, creation())
                .await
                .unwrap()
                .identifier(),
            &ident
        );
        assert_eq!(
            catalog
                .stage_create_table(&namespace, creation())
                .await
                .unwrap()
                .identifier(),
            &ident
        );
        assert_eq!(
            catalog
                .register_table(&ident, "memory://x/metadata/v1.json".to_string())
                .await
                .unwrap()
                .identifier(),
            &ident
        );
        assert_eq!(
            catalog
                .commit_table(&ident, vec![], vec![])
                .await
                .unwrap()
                .identifier(),
            &ident
        );
        let committed = catalog
            .commit_tables_atomic(vec![(ident.clone(), vec![], vec![])])
            .await
            .unwrap();
        assert_eq!(committed[0].identifier(), &ident);
    }

    // ── The mount root is not a namespace ─────────────────────────────────

    /// A mount root holds namespaces and no tables, and listing every
    /// namespace's tables is an engine's first move after `listNamespaces` — so
    /// this has to be an empty page rather than an error.
    #[tokio::test]
    async fn a_mount_root_lists_no_tables_rather_than_failing() {
        let catalog = federated(vec![echo_mount("prod")]);
        let root = ns(&["prod"]);

        let tables = catalog.list_tables(&root, &PageRequest::first(10)).await;
        assert!(tables.is_ok(), "a mount root must be listable: {tables:?}");
        assert!(tables.unwrap().entries.is_empty());

        let views = catalog.list_views(&root, &PageRequest::first(10)).await;
        assert!(views.is_ok());
        assert!(views.unwrap().entries.is_empty());
    }

    /// Naming a table directly under a mount root is a request for something
    /// that cannot exist, and the refusal has to say why.
    #[tokio::test]
    async fn a_table_directly_under_a_mount_root_is_refused_by_name() {
        let catalog = federated(vec![echo_mount("prod")]);
        let err = catalog
            .load_table(&TableIdent::new(ns(&["prod"]), "orphan".to_string()))
            .await
            .unwrap_err();

        assert!(
            err.message().contains("mount root"),
            "the message must name the cause: {}",
            err.message()
        );
    }

    #[test]
    fn two_mounts_cannot_share_a_name() {
        let err = FederatedCatalog::new(
            Arc::new(Nowhere),
            vec![
                mount("prod", Capabilities::full()),
                mount("prod", Capabilities::full()),
            ],
        )
        .unwrap_err();
        assert!(err.message().contains("both named"));
    }

    #[test]
    fn a_mount_name_cannot_contain_a_key_separator() {
        let err = FederatedCatalog::new(
            Arc::new(Nowhere),
            vec![mount("bad\u{1F}name", Capabilities::full())],
        )
        .unwrap_err();
        assert!(err.message().contains("reserved separator"));
    }

    /// The intersection is what `/v1/config` publishes, so one read-only mount
    /// must remove writing from what the catalog advertises.
    #[test]
    fn capabilities_are_the_intersection_across_mounts() {
        let catalog = federated(vec![
            mount("prod", Capabilities::full()),
            mount("legacy", Capabilities::read_only()),
        ]);
        assert_eq!(catalog.effective_capabilities(), Capabilities::read_only());
    }

    /// Credential vending is scoped to these, so a missing entry means a mount
    /// whose tables silently get no credentials.
    #[tokio::test]
    async fn every_mounts_warehouse_is_listed() {
        let catalog = federated(vec![
            mount("prod", Capabilities::full()),
            mount("legacy", Capabilities::read_only()),
        ]);

        let warehouses = catalog.warehouses("memory://native");
        assert!(warehouses.contains(&"memory://native".to_string()));
        assert!(warehouses.contains(&"file:///warehouses/prod".to_string()));
        assert!(warehouses.contains(&"file:///warehouses/legacy".to_string()));
    }

    /// A mount that stores nothing contributes nothing: Rustberg does not own a
    /// remote catalog's storage and must not mint credentials for it.
    #[tokio::test]
    async fn a_mount_without_a_warehouse_contributes_none() {
        let catalog = federated(vec![Mount {
            name: "partner".to_string(),
            store: Arc::new(Nowhere),
            capabilities: Capabilities::read_only(),
            owner: "acme".to_string(),
            warehouse: None,
        }]);

        assert_eq!(
            catalog.warehouses("memory://native"),
            vec!["memory://native".to_string()]
        );
    }

    /// The confinement check reads this, so a mounted namespace must report the
    /// mount's warehouse and not the server's.
    #[tokio::test]
    async fn a_mounted_namespace_reports_its_mounts_warehouse() {
        let catalog = federated(vec![mount("prod", Capabilities::full())]);

        assert_eq!(
            catalog.warehouse_for(&ns(&["prod", "db"])).await,
            Some("file:///warehouses/prod".to_string())
        );
        assert_eq!(
            catalog.warehouse_for(&ns(&["prod"])).await,
            Some("file:///warehouses/prod".to_string()),
            "a mount root has no namespace to ask the backend about"
        );
    }

    #[test]
    fn with_no_mounts_everything_is_supported() {
        assert_eq!(
            federated(vec![]).effective_capabilities(),
            Capabilities::full()
        );
    }

    /// The mount root has to be ownable, or authorization makes everything
    /// beneath it invisible.
    #[tokio::test]
    async fn a_mount_root_reports_the_declared_owner() {
        let catalog = federated(vec![mount("prod", Capabilities::full())]);
        let root = catalog.get_namespace(&ns(&["prod"])).await.unwrap();

        assert_eq!(ownership::owner_of(root.properties()), Some("acme"));
        assert_eq!(root.name(), &ns(&["prod"]));
    }

    /// A mounted catalog's own properties must not be able to reassign the
    /// tenant: whoever can write to that catalog would otherwise control who
    /// owns it here.
    #[tokio::test]
    async fn a_mounted_namespace_owner_is_the_mounts_not_the_backends() {
        #[derive(Debug)]
        struct Forged;
        #[async_trait]
        impl CatalogStore for Forged {
            async fn get_namespace(&self, n: &NamespaceIdent) -> Result<Namespace> {
                let mut properties = HashMap::new();
                ownership::set_owner(&mut properties, "attacker");
                Ok(Namespace::with_properties(n.clone(), properties))
            }
            // Everything else is unused here.
            async fn list_namespaces(
                &self,
                _: Option<&NamespaceIdent>,
                _: &PageRequest,
            ) -> Result<Page<NamespaceIdent>> {
                Ok(Page::empty())
            }
            async fn create_namespace(
                &self,
                n: &NamespaceIdent,
                p: HashMap<String, String>,
            ) -> Result<Namespace> {
                Ok(Namespace::with_properties(n.clone(), p))
            }
            async fn namespace_exists(&self, _: &NamespaceIdent) -> Result<bool> {
                Ok(true)
            }
            async fn update_namespace(
                &self,
                _: &NamespaceIdent,
                _: HashMap<String, String>,
            ) -> Result<()> {
                Ok(())
            }
            async fn drop_namespace(&self, _: &NamespaceIdent) -> Result<()> {
                Ok(())
            }
            async fn list_tables(
                &self,
                _: &NamespaceIdent,
                _: &PageRequest,
            ) -> Result<Page<TableIdent>> {
                Ok(Page::empty())
            }
            async fn create_table(&self, _: &NamespaceIdent, _: TableCreation) -> Result<Table> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn stage_create_table(
                &self,
                _: &NamespaceIdent,
                _: TableCreation,
            ) -> Result<Table> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn metadata_pointer(&self, _: &TableIdent) -> Result<Option<String>> {
                Ok(None)
            }
            async fn load_table(&self, _: &TableIdent) -> Result<Table> {
                Err(Error::new(ErrorKind::TableNotFound, "stub"))
            }
            async fn table_exists(&self, _: &TableIdent) -> Result<bool> {
                Ok(false)
            }
            async fn register_table(&self, _: &TableIdent, _: String) -> Result<Table> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn commit_table(
                &self,
                _: &TableIdent,
                _: Vec<TableRequirement>,
                _: Vec<TableUpdate>,
            ) -> Result<Table> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn commit_tables_atomic(
                &self,
                _: Vec<(TableIdent, Vec<TableRequirement>, Vec<TableUpdate>)>,
            ) -> Result<Vec<Table>> {
                Ok(Vec::new())
            }
            async fn rename_table(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
                Ok(())
            }
            async fn drop_table(&self, _: &TableIdent) -> Result<()> {
                Ok(())
            }
            async fn purge_table(&self, _: &TableIdent) -> Result<()> {
                Ok(())
            }
            async fn list_views(
                &self,
                _: &NamespaceIdent,
                _: &PageRequest,
            ) -> Result<Page<TableIdent>> {
                Ok(Page::empty())
            }
            async fn view_exists(&self, _: &TableIdent) -> Result<bool> {
                Ok(false)
            }
            async fn load_view(&self, _: &TableIdent) -> Result<(String, ViewMetadata)> {
                Err(Error::new(ErrorKind::TableNotFound, "stub"))
            }
            async fn register_view(
                &self,
                _: &TableIdent,
                _: String,
            ) -> Result<(String, ViewMetadata)> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn create_view(
                &self,
                _: &TableIdent,
                _: ViewMetadata,
            ) -> Result<(String, ViewMetadata)> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn update_view(
                &self,
                _: &TableIdent,
                _: ViewMetadata,
            ) -> Result<(String, ViewMetadata)> {
                Err(Error::new(ErrorKind::FeatureUnsupported, "stub"))
            }
            async fn drop_view(&self, _: &TableIdent) -> Result<()> {
                Ok(())
            }
            async fn rename_view(&self, _: &TableIdent, _: &TableIdent) -> Result<()> {
                Ok(())
            }
            async fn warehouse_for(&self, _: &NamespaceIdent) -> Option<String> {
                None
            }
            async fn storage_health_check(&self) -> Result<StorageHealthStatus> {
                Ok(StorageHealthStatus::healthy("stub", 0))
            }
        }

        let catalog = FederatedCatalog::new(
            Arc::new(Nowhere),
            vec![Mount {
                name: "prod".to_string(),
                store: Arc::new(Forged),
                capabilities: Capabilities::full(),
                owner: "acme".to_string(),
                warehouse: Some("file:///warehouses/prod".to_string()),
            }],
        )
        .unwrap();

        let found = catalog
            .get_namespace(&ns(&["prod", "analytics"]))
            .await
            .unwrap();
        assert_eq!(
            ownership::owner_of(found.properties()),
            Some("acme"),
            "the mount's declared owner is authoritative, not the backend's properties"
        );
    }

    /// Names coming back from a mount must carry the mount prefix, or a client
    /// would be handed identifiers it cannot address.
    #[tokio::test]
    async fn a_mounted_namespace_is_reported_under_its_mount() {
        let catalog = federated(vec![mount("prod", Capabilities::full())]);
        let found = catalog
            .get_namespace(&ns(&["prod", "analytics"]))
            .await
            .unwrap();
        assert_eq!(found.name(), &ns(&["prod", "analytics"]));
    }

    #[tokio::test]
    async fn the_top_level_listing_includes_every_mount() {
        let catalog = federated(vec![
            mount("prod", Capabilities::full()),
            mount("legacy", Capabilities::read_only()),
        ]);

        let page = catalog
            .list_namespaces(None, &PageRequest::first(100))
            .await
            .unwrap();
        let names: Vec<String> = page.entries.iter().map(|e| e.item.join(".")).collect();

        assert!(names.contains(&"prod".to_string()));
        assert!(names.contains(&"legacy".to_string()));
    }

    #[tokio::test]
    async fn a_read_only_mount_refuses_writes_naming_itself() {
        let catalog = federated(vec![mount("legacy", Capabilities::read_only())]);

        let err = catalog
            .drop_table(&TableIdent::new(ns(&["legacy", "db"]), "t".into()))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::FeatureUnsupported);
        assert!(err.message().contains("legacy"), "names the mount: {err}");
        assert!(err.message().contains("writing"));
    }

    /// A mount with no views lists none rather than erroring: listing is how a
    /// client discovers what is there.
    #[tokio::test]
    async fn a_mount_without_views_lists_none() {
        let catalog = federated(vec![mount("legacy", Capabilities::read_only())]);
        let page = catalog
            .list_views(&ns(&["legacy", "db"]), &PageRequest::first(10))
            .await
            .unwrap();
        assert!(page.entries.is_empty());
        assert!(
            !catalog
                .view_exists(&TableIdent::new(ns(&["legacy", "db"]), "v".into()))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_rename_across_mounts_is_refused() {
        let catalog = federated(vec![
            mount("a", Capabilities::full()),
            mount("b", Capabilities::full()),
        ]);

        let err = catalog
            .rename_table(
                &TableIdent::new(ns(&["a", "db"]), "t".into()),
                &TableIdent::new(ns(&["b", "db"]), "t".into()),
            )
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::FeatureUnsupported);
        assert!(err.message().contains("across mounts"));
    }

    /// Atomicity is a property of one backend; sequencing two would sometimes
    /// leave one advanced and the other not.
    #[tokio::test]
    async fn a_transaction_across_mounts_is_refused() {
        let catalog = federated(vec![
            mount("a", Capabilities::full()),
            mount("b", Capabilities::full()),
        ]);

        let err = catalog
            .commit_tables_atomic(vec![
                (
                    TableIdent::new(ns(&["a", "db"]), "t".into()),
                    vec![],
                    vec![],
                ),
                (
                    TableIdent::new(ns(&["b", "db"]), "t".into()),
                    vec![],
                    vec![],
                ),
            ])
            .await
            .unwrap_err();

        assert!(err.message().contains("cannot span catalogs"));
    }

    /// A transaction mixing a mount with the native catalog is the same problem.
    #[tokio::test]
    async fn a_transaction_spanning_a_mount_and_the_native_catalog_is_refused() {
        let catalog = federated(vec![mount("a", Capabilities::full())]);

        let err = catalog
            .commit_tables_atomic(vec![
                (
                    TableIdent::new(ns(&["a", "db"]), "t".into()),
                    vec![],
                    vec![],
                ),
                (TableIdent::new(ns(&["local"]), "t".into()), vec![], vec![]),
            ])
            .await
            .unwrap_err();

        assert!(err.message().contains("native catalog"), "{err}");
    }

    /// An unmounted name must reach the native catalog unchanged, so adding a
    /// mount does not disturb what was already there.
    #[tokio::test]
    async fn an_unmounted_namespace_goes_to_the_native_catalog() {
        let catalog = federated(vec![mount("prod", Capabilities::full())]);
        let found = catalog.get_namespace(&ns(&["scratch"])).await.unwrap();
        assert_eq!(found.name(), &ns(&["scratch"]));
        assert_eq!(
            ownership::owner_of(found.properties()),
            None,
            "the native catalog's own ownership rules still apply"
        );
    }
}
