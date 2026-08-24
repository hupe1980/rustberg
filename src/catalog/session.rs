//! The catalog as Rust, for a host that has already authenticated its caller.
//!
//! # What this is
//!
//! A [`Session`] binds a [`Principal`] to an [`AppState`] and exposes the
//! catalog operations the REST handlers expose, authorized the same way. It is
//! how *anything reachable through the server is reachable in-process*
//! stops being an aspiration. A host embedding Rustberg gets typed Rust with no
//! router, no serialisation, and no socket:
//!
//! ```no_run
//! # use iceberg::{NamespaceIdent, TableIdent};
//! # use rustberg::App;
//! # use rustberg::auth::Principal;
//! # async fn example(app: App) -> Result<(), Box<dyn std::error::Error>> {
//! let principal = Principal::embedded("svc-etl", "acme")
//!     .with_role("writer")
//!     .build();
//!
//! let session = app.as_principal(principal);
//! let events = TableIdent::new(
//!     NamespaceIdent::from_vec(vec!["analytics".into(), "web".into()])?,
//!     "events".into(),
//! );
//! let table = session.load_table(&events).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # There is deliberately no `"analytics.web.events".parse()`
//!
//! A dotted string is ambiguous: `a.b` is either the namespace `["a", "b"]` or a
//! single namespace named `a.b`, and both are legal Iceberg names. That
//! ambiguity is the reason entity ids join their segments with `\u{1F}` rather
//! than `.` — in an authorization layer, a name that can be read two ways is a
//! policy that matches the wrong resource.
//!
//! A convenience parser here would put that ambiguity back at the most
//! convenient possible place, so the segments are named explicitly. It is two
//! more lines and it cannot mean the wrong table.
//!
//! # There is one authorization implementation, and this is not it
//!
//! Every method here calls [`guard`] — the same function, with the same
//! arguments, that the handler of the same name calls. That is the whole design
//! constraint. A `Session` that decided access itself would be a second
//! authorization implementation, and this codebase has twice shipped a second
//! copy of a security-critical sequence that then drifted from the first: fifteen
//! handlers that each resolved ownership slightly differently, and an unused auth
//! middleware that silently stopped attaching the request context.
//!
//! So the rule for anything added here is: **if it does not go through `guard`,
//! it does not go here.**
//!
//! # What a session does not do
//!
//! Four things live at the HTTP layer and are deliberately absent, because each
//! one answers a question a Rust caller is better placed to answer itself:
//!
//! - **Credential vending.** A host holding the catalog in-process reads its own
//!   storage; it does not need a token minted for it. What it *does* need is to
//!   know when policy has restricted a table, which is why
//!   [`Session::obligations_for`] exists — see there for the invariant it keeps.
//! - **Idempotency keys.** They exist because HTTP retries. A function call does
//!   not.
//! - **Conditional loading.** `If-None-Match` is a wire optimisation.
//! - **Delegation negotiation.** `X-Iceberg-Access-Delegation` is a request
//!   header with no meaning here.
//!
//! Everything else — ownership resolution, the `404`-versus-`403` rule, listing
//! filters, location confinement, the cross-tenant rename refusal, audit — is
//! enforced here exactly as it is over HTTP, and
//! `tests/session_tests.rs` asserts that equivalence by driving both paths
//! against one catalog rather than by testing each separately.

use std::collections::HashMap;

use iceberg::spec::ViewMetadata;
use iceberg::table::Table;
use iceberg::{
    Namespace, NamespaceIdent, TableCreation, TableIdent, TableRequirement, TableUpdate,
};

use super::v1::guard::{self, Target};
use super::v1::ownership::{self, reject_if_protected, set_owner, strip_reserved};
use super::v1::pagination::{FilteredPage, collect_page};
use super::{MAX_PAGE_SIZE, PageRequest};
use crate::app::AppState;
use crate::auth::{Action, Obligations, Principal, RequestContext, Resource};
use crate::error::{AppError, Result};
use crate::names::{validate_namespace, validate_properties, validate_table_name};

/// One caller's authorized view of the catalog.
///
/// Created with [`App::as_principal`](crate::App::as_principal). Cheap to clone
/// and to make: it holds an `Arc`-backed state, a principal and the request
/// facts a policy may read.
///
/// # Errors
///
/// Every method reports the same errors the corresponding endpoint does, and for
/// the same reasons. In particular a resource the caller cannot *see* is
/// [`AppError::NoSuchTable`] / [`AppError::NoSuchNamespace`] rather than
/// [`AppError::Forbidden`], whether or not it exists — the status code must not
/// become an oracle for enumerating another tenant's catalog.
#[derive(Clone)]
pub struct Session {
    state: AppState,
    principal: Principal,
    facts: RequestContext,
}

impl std::fmt::Debug for Session {
    /// Names the principal and nothing else.
    ///
    /// `AppState` carries the authenticator, the credential provider and the
    /// live policy set; rendering it here would put them in whatever log a host
    /// writes a `Session` to.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("principal", &self.principal.id())
            .field("tenant", &self.principal.tenant_id())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Binds `principal` to `state`.
    pub(crate) fn new(state: AppState, principal: Principal) -> Self {
        Self {
            state,
            principal,
            facts: RequestContext::default(),
        }
    }

    /// Attaches the request facts a policy may read.
    ///
    /// A policy conditioned on `context.source_ip` cannot match without this, and
    /// **fails closed** when it is absent — which is the right default for an
    /// in-process call, where there is genuinely no connection behind the
    /// request. Supply it when the host is itself serving a remote caller and is
    /// forwarding that caller's address.
    pub fn with_request_context(mut self, facts: RequestContext) -> Self {
        self.facts = facts;
        self
    }

    /// The principal this session acts as.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    // ── Namespaces ──────────────────────────────────────────────────────

    /// Lists namespaces under `parent`, or the catalog root when `None`.
    ///
    /// **Filters rather than denies:** the caller sees exactly the subset it may
    /// read and never learns the rest exists. Filtering happens before the page
    /// is cut, so a page is never short merely because rows were removed from it.
    ///
    /// A short page carrying a token is normal and means *keep going* — a caller
    /// must page until the token is absent, not until a page looks small.
    pub async fn list_namespaces(
        &self,
        parent: Option<&NamespaceIdent>,
        page: PageRequest,
    ) -> Result<FilteredPage<NamespaceIdent>> {
        guard::authorize_catalog(&self.state, &self.principal, &self.facts, Action::List).await?;

        collect_page(
            page,
            |request| {
                let state = self.state.clone();
                let parent = parent.cloned();
                async move {
                    state
                        .catalog
                        .list_namespaces(parent.as_ref(), &request)
                        .await
                        .map_err(AppError::from)
                }
            },
            |namespace: NamespaceIdent| async move {
                // A namespace with no recorded owner is shown to nobody: it
                // cannot be attributed to a tenant, so no policy can decide it.
                let Ok(ns) = self.state.catalog.get_namespace(&namespace).await else {
                    return (false, namespace);
                };
                let Some(owner) = ownership::owner_of(ns.properties()).map(str::to_string) else {
                    return (false, namespace);
                };
                let visible = guard::can_see(
                    &self.state,
                    &self.principal,
                    &self.facts,
                    &owner,
                    &namespace,
                    Target::Namespace,
                )
                .await;
                (visible, namespace)
            },
        )
        .await
    }

    /// Loads a namespace and its properties.
    ///
    /// Rustberg's own bookkeeping keys are stripped, exactly as over HTTP, so a
    /// caller cannot read the recorded owner back out and cannot learn the
    /// internal property vocabulary.
    pub async fn get_namespace(&self, namespace: &NamespaceIdent) -> Result<Namespace> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            namespace,
            Target::Namespace,
            Action::Read,
        )
        .await?;

        let found = self.state.catalog.get_namespace(namespace).await?;
        let mut properties = found.properties().clone();
        strip_reserved(&mut properties);
        Ok(Namespace::with_properties(found.name().clone(), properties))
    }

    /// Whether the namespace exists *and* the caller may see it.
    ///
    /// The two are deliberately one answer. Reporting existence for a namespace
    /// the caller cannot read would be the enumeration oracle the `404` rule
    /// exists to close.
    pub async fn namespace_exists(&self, namespace: &NamespaceIdent) -> Result<bool> {
        match self.get_namespace(namespace).await {
            Ok(_) => Ok(true),
            Err(AppError::NoSuchNamespace(_)) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Creates a namespace owned by the caller's tenant.
    ///
    /// Authorized against the caller's own tenant, which is correct here and only
    /// here: the namespace does not exist yet, so there is no recorded owner to
    /// authorize against. Every later request on it authorizes against the owner
    /// written now, which is why that owner is stamped by Rustberg and cannot be
    /// supplied in `properties`.
    pub async fn create_namespace(
        &self,
        namespace: &NamespaceIdent,
        properties: HashMap<String, String>,
    ) -> Result<Namespace> {
        let parts = namespace.to_vec();
        validate_namespace(&parts)?;
        validate_properties(&properties)?;
        ownership::reject_reserved(properties.keys())?;

        let tenant_id = self.principal.tenant_id().to_string();
        guard::authorize_new(
            &self.state,
            &self.principal,
            &self.facts,
            Resource::namespace(&tenant_id, parts),
            Action::Create,
        )
        .await?;

        let mut properties = properties;
        set_owner(&mut properties, &tenant_id);

        let created = self
            .state
            .catalog
            .create_namespace(namespace, properties)
            .await?;

        let mut response = created.properties().clone();
        strip_reserved(&mut response);
        Ok(Namespace::with_properties(created.name().clone(), response))
    }

    /// Drops a namespace. Fails if it still holds tables or views.
    pub async fn drop_namespace(&self, namespace: &NamespaceIdent) -> Result<()> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            namespace,
            Target::Namespace,
            Action::Delete,
        )
        .await?;

        let existing = self.state.catalog.get_namespace(namespace).await?;
        reject_if_protected(
            existing.properties(),
            &format!("Namespace '{}'", namespace.join(".")),
        )?;

        self.state.catalog.drop_namespace(namespace).await?;
        Ok(())
    }

    // ── Tables ──────────────────────────────────────────────────────────

    /// Lists tables in `namespace`, filtered to what the caller may read.
    ///
    /// See [`list_namespaces`](Self::list_namespaces) on short pages and tokens.
    pub async fn list_tables(
        &self,
        namespace: &NamespaceIdent,
        page: PageRequest,
    ) -> Result<FilteredPage<TableIdent>> {
        let authorized = guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            namespace,
            Target::Namespace,
            Action::List,
        )
        .await?;

        collect_page(
            page,
            |request| {
                let state = self.state.clone();
                let namespace = namespace.clone();
                async move {
                    state
                        .catalog
                        .list_tables(&namespace, &request)
                        .await
                        .map_err(AppError::from)
                }
            },
            |ident: TableIdent| {
                let owner = authorized.owner.clone();
                async move {
                    let visible = guard::can_see(
                        &self.state,
                        &self.principal,
                        &self.facts,
                        &owner,
                        ident.namespace(),
                        Target::Table(ident.name()),
                    )
                    .await;
                    (visible, ident)
                }
            },
        )
        .await
    }

    /// Loads a table's current metadata.
    pub async fn load_table(&self, table: &TableIdent) -> Result<Table> {
        self.authorize_table(table, Action::Read).await?;
        Ok(self.state.catalog.load_table(table).await?)
    }

    /// Whether the table exists *and* the caller may see it.
    pub async fn table_exists(&self, table: &TableIdent) -> Result<bool> {
        match self.load_table(table).await {
            Ok(_) => Ok(true),
            Err(AppError::NoSuchTable(_)) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// What policy attached to the caller's grant on this table.
    ///
    /// # Why a host must read this
    ///
    /// A non-empty [`Obligations`] means the matching permits carry a
    /// `@row_filter` or `@column_mask`. Over HTTP that is enforced as a refusal
    /// to delegate: no storage credential is vended, and the credentials
    /// endpoint answers `403`, because a credential is prefix-shaped and cannot
    /// express a row filter.
    ///
    /// In-process there is no credential to withhold — the host already holds
    /// whatever storage access it has. So the invariant cannot be *enforced*
    /// here, only *reported*, and this method is that report. A host that reads
    /// table files directly after `load_table` must check this first and refuse
    /// on a non-empty result, or it becomes the hole the HTTP path closes.
    ///
    /// This is the one place the in-process surface is weaker than the endpoint,
    /// and it is weaker for a reason that cannot be engineered away: Rustberg is
    /// not in the data path of a caller that already has the bytes.
    pub async fn obligations_for(&self, table: &TableIdent) -> Result<Obligations> {
        let authorized = self.authorize_table(table, Action::Read).await?;
        Ok(authorized.obligations)
    }

    /// Creates a table.
    ///
    /// A client-supplied `location` is confined to the warehouse of the namespace
    /// it is created in — under federation each mount has its own, so this is not
    /// "the" warehouse — and then to the prefix this table's own name puts it
    /// in. An unconfined location is a confused-deputy hole: it later becomes
    /// the prefix of any credential vended for the table.
    pub async fn create_table(
        &self,
        namespace: &NamespaceIdent,
        creation: TableCreation,
    ) -> Result<Table> {
        validate_table_name(&creation.name)?;
        validate_properties(&creation.properties)?;

        if let Some(ref location) = creation.location {
            self.state
                .location_bound(namespace, &creation.name)
                .await
                .ensure(location)?;
        }

        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            namespace,
            Target::Table(&creation.name),
            Action::Create,
        )
        .await?;

        Ok(self.state.catalog.create_table(namespace, creation).await?)
    }

    /// Commits updates to a table, subject to its requirements.
    ///
    /// The requirements are applied exactly as given — this is the spec's
    /// optimistic-concurrency contract, and a conflict surfaces as
    /// [`AppError::CommitConflict`] rather than being retried into a lost update.
    ///
    /// Every location the updates carry is confined, exactly as over HTTP: the
    /// check lives in the backend, where the table's current metadata is already
    /// loaded, so both surfaces get it from one place. An embedding host is not a
    /// trusted caller — it is the *server*, and the principal it calls on behalf
    /// of is not.
    pub async fn commit_table(
        &self,
        table: &TableIdent,
        requirements: Vec<TableRequirement>,
        updates: Vec<TableUpdate>,
    ) -> Result<Table> {
        self.authorize_table(table, Action::Update).await?;
        Ok(self
            .state
            .catalog
            .commit_table(table, requirements, updates)
            .await?)
    }

    /// Drops a table. With `purge`, also deletes the files it references.
    ///
    /// Purge removes exactly the files the table's manifests name; it does not
    /// recursively delete the table's location, which could destroy an unrelated
    /// table sharing the prefix.
    pub async fn drop_table(&self, table: &TableIdent, purge: bool) -> Result<()> {
        self.authorize_table(table, Action::Delete).await?;

        reject_if_protected(
            self.state
                .catalog
                .load_table(table)
                .await?
                .metadata()
                .properties(),
            &format!("Table '{table}'"),
        )?;

        if purge {
            self.state.catalog.purge_table(table).await?;
        } else {
            self.state.catalog.drop_table(table).await?;
        }
        Ok(())
    }

    /// Renames a table, possibly across namespaces.
    ///
    /// Needs `Update` on the source and `Create` on the destination: a rename
    /// removes a table from one name and creates it at another, and a caller
    /// permitted only to write the destination must not be able to move somebody
    /// else's table into it.
    ///
    /// Refused when the two namespaces belong to different tenants. Both checks
    /// above can pass for a principal holding grants in two tenants, and the
    /// result would be a table sitting in one tenant's namespace with its files
    /// under another's warehouse prefix. A rename is not a mechanism for moving
    /// data between tenants.
    pub async fn rename_table(&self, source: &TableIdent, destination: &TableIdent) -> Result<()> {
        validate_table_name(destination.name())?;
        validate_namespace(source.namespace())?;
        validate_namespace(destination.namespace())?;

        let src = self.authorize_table(source, Action::Update).await?;
        let dst = guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            destination.namespace(),
            Target::Table(destination.name()),
            Action::Create,
        )
        .await?;

        if src.owner != dst.owner {
            return Err(AppError::Forbidden(
                "Cannot move tables between namespaces owned by different tenants".to_string(),
            ));
        }

        self.state.catalog.rename_table(source, destination).await?;
        Ok(())
    }

    // ── Views ───────────────────────────────────────────────────────────

    /// Lists views in `namespace`, filtered to what the caller may read.
    pub async fn list_views(
        &self,
        namespace: &NamespaceIdent,
        page: PageRequest,
    ) -> Result<FilteredPage<TableIdent>> {
        let authorized = guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            namespace,
            Target::Namespace,
            Action::List,
        )
        .await?;

        collect_page(
            page,
            |request| {
                let state = self.state.clone();
                let namespace = namespace.clone();
                async move {
                    state
                        .catalog
                        .list_views(&namespace, &request)
                        .await
                        .map_err(AppError::from)
                }
            },
            |ident: TableIdent| {
                let owner = authorized.owner.clone();
                async move {
                    let visible = guard::can_see(
                        &self.state,
                        &self.principal,
                        &self.facts,
                        &owner,
                        ident.namespace(),
                        Target::View(ident.name()),
                    )
                    .await;
                    (visible, ident)
                }
            },
        )
        .await
    }

    /// Loads a view's metadata and the location it was read from.
    pub async fn load_view(&self, view: &TableIdent) -> Result<(String, ViewMetadata)> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            view.namespace(),
            Target::View(view.name()),
            Action::Read,
        )
        .await?;

        Ok(self.state.catalog.load_view(view).await?)
    }

    /// Creates a view.
    ///
    /// A client-supplied location is confined to the prefix this view's own name
    /// puts it in, exactly as over HTTP — a view's metadata document sits at
    /// `<warehouse>/<namespace…>/<name>` beside a table's, and the two kinds
    /// share one namespace of names precisely so that they cannot collide there.
    pub async fn create_view(
        &self,
        view: &TableIdent,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        validate_table_name(view.name())?;

        self.state
            .location_bound(view.namespace(), view.name())
            .await
            .ensure(metadata.location())?;

        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            view.namespace(),
            Target::View(view.name()),
            Action::Create,
        )
        .await?;

        Ok(self.state.catalog.create_view(view, metadata).await?)
    }

    /// Commits new metadata for a view, if the pointer has not moved.
    ///
    /// `expected_metadata_location` is the location [`Self::load_view`] returned
    /// for the metadata these updates were derived from. It is the
    /// compare-and-swap witness, and it is a parameter rather than something the
    /// store re-derives because a view commit is a read-modify-write that spans
    /// the store boundary: comparing against a later read would confirm a
    /// concurrent commit instead of detecting it. A host that lost the race gets
    /// [`AppError::CommitConflict`] and reloads.
    ///
    /// This is the same call the HTTP handler makes, with the same guard and the
    /// same confinement — which is what `Session` promises. Building the new
    /// metadata is the host's, because in-process there is no wire format to
    /// apply: it holds a [`ViewMetadata`] and edits it.
    pub async fn commit_view(
        &self,
        view: &TableIdent,
        expected_metadata_location: &str,
        metadata: ViewMetadata,
    ) -> Result<(String, ViewMetadata)> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            view.namespace(),
            Target::View(view.name()),
            Action::Update,
        )
        .await?;

        let (current_location, current) = self.state.catalog.load_view(view).await?;
        self.state
            .location_bound(view.namespace(), view.name())
            .await
            .ensure_view_commit_metadata(current.location(), &metadata)?;

        // Refused before the store is asked, so a host that built its update
        // from a stale read is told here rather than by whichever backend it is
        // running on.
        if current_location != expected_metadata_location {
            return Err(AppError::CommitConflict(format!(
                "View '{view}' was modified since the metadata this commit was built from. \
                 Reload it and re-apply."
            )));
        }

        Ok(self
            .state
            .catalog
            .update_view(view, expected_metadata_location, metadata)
            .await?)
    }

    /// Drops a view.
    pub async fn drop_view(&self, view: &TableIdent) -> Result<()> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            view.namespace(),
            Target::View(view.name()),
            Action::Delete,
        )
        .await?;

        let (_, metadata) = self.state.catalog.load_view(view).await?;
        reject_if_protected(metadata.properties(), &format!("View '{view}'"))?;

        self.state.catalog.drop_view(view).await?;
        Ok(())
    }

    // ── Internals ───────────────────────────────────────────────────────

    /// Authorizes `action` on a table, resolving its namespace's owner first.
    async fn authorize_table(
        &self,
        table: &TableIdent,
        action: Action,
    ) -> Result<guard::Authorized> {
        guard::authorize(
            &self.state,
            &self.principal,
            &self.facts,
            table.namespace(),
            Target::Table(table.name()),
            action,
        )
        .await
    }
}

/// A page request for `limit` items, clamped to what a backend will answer.
///
/// Re-exported convenience so a host does not have to import the paging module
/// to ask for a page.
pub fn page(limit: usize) -> PageRequest {
    PageRequest::first(limit.clamp(1, MAX_PAGE_SIZE))
}

/// Resumes a listing after `cursor`.
///
/// `cursor` is the `next_page_token` of a previous [`FilteredPage`]. It is opaque
/// and must not be constructed by hand: a token that did not come from Rustberg
/// restarts the listing rather than seeking, so a hand-built one silently repeats
/// work instead of doing what it looks like it does.
pub fn page_after(cursor: impl Into<String>, limit: usize) -> PageRequest {
    PageRequest::after(cursor, limit.clamp(1, MAX_PAGE_SIZE))
}
