//! The authorization vocabulary: what is being accessed, by whom, and how the
//! answer is reported.
//!
//! The types here are deliberately independent of Cedar. [`CedarAuthorizer`] is
//! the only implementation that ships, but keeping the vocabulary separate is
//! what lets an embedding host substitute its own decision procedure without
//! reimplementing the resource model.
//!
//! [`CedarAuthorizer`]: super::CedarAuthorizer

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

use super::error::{AuthError, Result};
use super::principal::Principal;

// ============================================================================
// Resource and Action Types
// ============================================================================

/// Types of resources that can be protected.
///
/// One variant per thing the catalog API can actually name. Variants for
/// snapshots, references and API keys existed here once and were never
/// constructed: the endpoints that would have used them authorize against the
/// containing table, and API keys are configuration rather than a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// The catalog itself, addressed as the tenant root.
    Catalog,
    /// A namespace within the catalog.
    Namespace,
    /// A table within a namespace.
    Table,
    /// A view within a namespace.
    View,
    /// The tenant's policy set.
    ///
    /// Policy is itself a protected resource, or the model is circular: whoever
    /// can write policy can grant themselves anything, so "may you change the
    /// rules" has to be one of the rules.
    PolicySet,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Catalog => write!(f, "catalog"),
            ResourceType::Namespace => write!(f, "namespace"),
            ResourceType::Table => write!(f, "table"),
            ResourceType::View => write!(f, "view"),
            ResourceType::PolicySet => write!(f, "policy_set"),
        }
    }
}

/// Actions that can be performed on resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Load namespace, table or view metadata.
    Read,
    /// Create a namespace, table or view; register a table.
    Create,
    /// Commit to a table, update properties, rename.
    Update,
    /// Drop a namespace, table or view.
    Delete,
    /// List the children of a namespace or of the catalog.
    List,
    /// Administrative operations.
    Manage,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Read => write!(f, "read"),
            Action::Create => write!(f, "create"),
            Action::Update => write!(f, "update"),
            Action::Delete => write!(f, "delete"),
            Action::List => write!(f, "list"),
            Action::Manage => write!(f, "manage"),
        }
    }
}

/// A specific resource instance being accessed.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Type of the resource.
    pub resource_type: ResourceType,
    /// Tenant that owns the resource.
    ///
    /// This is the *recorded owner* read from the namespace, never the caller's
    /// own tenant — otherwise every caller would authorize against a resource
    /// tree it had named itself.
    pub tenant_id: String,
    /// Namespace path, absent for the catalog root.
    pub namespace: Option<Vec<String>>,
    /// Table or view name, absent for a namespace or the catalog root.
    pub name: Option<String>,
}

impl Resource {
    /// The catalog root for a tenant.
    pub fn catalog(tenant_id: impl Into<String>) -> Self {
        Self {
            resource_type: ResourceType::Catalog,
            tenant_id: tenant_id.into(),
            namespace: None,
            name: None,
        }
    }

    /// The tenant's policy set.
    ///
    /// Read with [`Action::Read`] and changed with [`Action::Manage`]. There is
    /// no separate action pair: `Manage` already means "administer this thing",
    /// and adding `WritePolicy` would leave every existing policy that grants
    /// `Manage` silently not covering the most privileged operation there is.
    pub fn policy_set(tenant_id: impl Into<String>) -> Self {
        Self {
            resource_type: ResourceType::PolicySet,
            tenant_id: tenant_id.into(),
            namespace: None,
            name: None,
        }
    }

    /// A namespace.
    pub fn namespace(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            resource_type: ResourceType::Namespace,
            tenant_id: tenant_id.into(),
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: None,
        }
    }

    /// A table.
    pub fn table(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
        table_name: impl Into<String>,
    ) -> Self {
        Self {
            resource_type: ResourceType::Table,
            tenant_id: tenant_id.into(),
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: Some(table_name.into()),
        }
    }

    /// A view.
    pub fn view(
        tenant_id: impl Into<String>,
        namespace: impl IntoIterator<Item = impl Into<String>>,
        view_name: impl Into<String>,
    ) -> Self {
        Self {
            resource_type: ResourceType::View,
            tenant_id: tenant_id.into(),
            namespace: Some(namespace.into_iter().map(|s| s.into()).collect()),
            name: Some(view_name.into()),
        }
    }

    /// Returns the full resource path as a string, for logs and audit records.
    pub fn path(&self) -> String {
        let mut parts = vec![self.tenant_id.clone()];

        if let Some(namespace) = &self.namespace {
            parts.extend(namespace.clone());
        }

        if let Some(name) = &self.name {
            parts.push(name.clone());
        }

        parts.join("/")
    }
}

// ============================================================================
// Request Context
// ============================================================================

/// Per-request facts a policy may read.
///
/// This is what makes conditional policies possible: without it a policy can
/// only speak about identity and resource, so "not from outside the VPC" or
/// "outside business hours" cannot be written at all.
///
/// It is deliberately a small fixed struct rather than a string map. Cedar
/// validates policies against a schema, and a schema can only declare
/// attributes that are known — an open-ended map would either go unvalidated or
/// have to be typed as strings, which would make `isInRange` on an address
/// impossible.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Address the request arrived from, when one could be established.
    ///
    /// `None` for in-process calls through the library, where there is no
    /// connection. A policy conditioned on the address then fails closed, which
    /// is the safe direction.
    pub source_ip: Option<IpAddr>,
    /// Correlation id, echoed to the client as `X-Request-Id`.
    ///
    /// Carried so an audit record and an application log line can be joined.
    /// Not readable from a policy: it is chosen per request and means nothing to
    /// an authorization decision.
    pub request_id: Option<String>,
}

impl RequestContext {
    /// A context carrying a source address.
    pub fn from_ip(source_ip: IpAddr) -> Self {
        Self {
            source_ip: Some(source_ip),
            request_id: None,
        }
    }

    /// Attaches the correlation id.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

// ============================================================================
// Authorization Context
// ============================================================================

/// Everything a decision is made from: principal, action, resource, request.
#[derive(Debug, Clone)]
pub struct AuthzContext {
    /// The principal making the request.
    pub principal: Principal,
    /// The resource being accessed.
    pub resource: Resource,
    /// The action being performed.
    pub action: Action,
    /// Per-request facts a policy may read.
    pub request: RequestContext,
}

impl AuthzContext {
    /// Creates an authorization context with no request facts.
    ///
    /// Use this for in-process calls. A policy conditioned on the source
    /// address will not be satisfiable, and therefore fails closed.
    pub fn new(principal: Principal, resource: Resource, action: Action) -> Self {
        Self {
            principal,
            resource,
            action,
            request: RequestContext::default(),
        }
    }

    /// Attaches the request facts a policy may read.
    pub fn with_request(mut self, request: RequestContext) -> Self {
        self.request = request;
        self
    }

    /// Returns the same context re-aimed at a different action.
    ///
    /// Used where one request needs two decisions — a rename needs `Update` on
    /// the source and `Create` on the destination, and a load needs to know
    /// whether `Update` is also permitted before choosing what credential to
    /// vend.
    pub fn for_action(&self, action: Action) -> Self {
        Self {
            action,
            ..self.clone()
        }
    }

    /// Returns the same context re-aimed at a different resource.
    ///
    /// Used by the list endpoints, which evaluate one decision per candidate
    /// child against an otherwise identical context.
    pub fn for_resource(&self, resource: Resource) -> Self {
        Self {
            resource,
            ..self.clone()
        }
    }
}

// ============================================================================
// Authorization Decision
// ============================================================================

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied with a reason.
    Deny(String),
}

impl AuthzDecision {
    /// Returns true if access is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow)
    }

    /// Returns true if access is denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, AuthzDecision::Deny(_))
    }

    /// Converts to a Result, returning Err with AuthError::Forbidden if denied.
    pub fn into_result(self) -> Result<()> {
        match self {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny(reason) => Err(AuthError::Forbidden(reason)),
        }
    }
}

// ============================================================================
// Obligations
// ============================================================================

/// Conditions attached to an allow decision.
///
/// A policy engine answers yes or no; an *obligation* is the "yes, but" —
/// permitted, subject to a restriction the enforcement point has to apply. Cedar
/// has no obligations of its own, so the Cedar authorizer carries them as
/// annotations on the policies that matched.
///
/// # What Rustberg does with them
///
/// It refuses to hand out storage credentials. That is the honest limit of what
/// a catalog can enforce: a catalog vends metadata pointers and credentials, and
/// once an engine holds a file URL and a credential it reads every row and every
/// column in that file. Filtering therefore cannot be enforced by *describing*
/// it — only by not giving out the means to bypass it.
///
/// So an obligation makes a table **undelegatable**: the request succeeds, the
/// metadata is returned, and no credential is vended. Enforcing the filter
/// itself needs server-side scan planning paired with remote signing, neither of
/// which Rustberg implements. Declining to vend is the enforceable half, and it
/// is chosen deliberately over vending a broad credential and calling the filter
/// enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Obligations {
    /// Row filters, to be combined as a disjunction.
    ///
    /// Each is an Iceberg [JSON predicate](crate::predicate), so it can be
    /// *applied* — the planner ORs them together and conjoins the result with
    /// the client's own filter. An opaque string could only be reported.
    ///
    /// Permits grant, so a caller sees the **union** of what the matching
    /// permits allow. An empty set means unrestricted — which is why a single
    /// unannotated permit voids the filters of every other matching permit.
    pub row_filters: Vec<serde_json::Value>,
    /// Columns withheld, as the **intersection** across matching permits.
    ///
    /// A column is withheld only if every matching permit withholds it: a permit
    /// that does not mask a column is granting it, and unioning masks would
    /// withhold something the caller was granted.
    pub column_masks: HashSet<String>,
}

impl Obligations {
    /// True when nothing qualifies the grant.
    ///
    /// The common case by far, and the fast path: a table with no row or column
    /// policy is delegatable and needs no further thought.
    pub fn is_empty(&self) -> bool {
        self.row_filters.is_empty() && self.column_masks.is_empty()
    }

    /// True when at least one matching permit imposed no row filter, so the
    /// caller may see every row.
    pub fn rows_unrestricted(&self) -> bool {
        self.row_filters.is_empty()
    }

    /// A one-line description of what is restricted, for logs and error bodies.
    ///
    /// Names the restricted columns but never the filter expressions: a filter
    /// can embed the values it compares against (`region == 'EU'`), and echoing
    /// it to a caller that was just refused a credential leaks the shape of the
    /// policy that refused it.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.row_filters.is_empty() {
            parts.push(format!("{} row filter(s)", self.row_filters.len()));
        }
        if !self.column_masks.is_empty() {
            let mut columns: Vec<&str> = self.column_masks.iter().map(String::as_str).collect();
            columns.sort_unstable();
            parts.push(format!("masked column(s): {}", columns.join(", ")));
        }
        if parts.is_empty() {
            "no restrictions".to_string()
        } else {
            parts.join("; ")
        }
    }
}

// ============================================================================
// Authorizer Trait
// ============================================================================

/// One authorization decision, and everything the audit trail needs to explain it.
///
/// # Why the matched policies travel with the decision
///
/// "Permitted" and "denied" are the least useful halves of an audit record. The
/// question an operator actually arrives with is *why* — which rule did this,
/// and was that rule the one they thought they were writing. A record that
/// cannot answer that is a log line, not a governance deliverable.
///
/// Cedar already knows: its diagnostics name the policies that produced the
/// result. Carrying them here means no implementation can forget to surface
/// them, exactly as [`Obligations`] does for row filters.
#[derive(Debug, Clone)]
pub struct AuthzOutcome {
    /// Permit or deny.
    pub decision: AuthzDecision,
    /// Restrictions the matching permits attached to the grant.
    pub obligations: Obligations,
    /// Ids of the policies that produced this result.
    ///
    /// On a permit, the permits that matched. On a denial, the *forbids* that
    /// matched — and an **empty** list on a denial is itself the answer: nothing
    /// forbade the request, nothing permitted it either, and it failed closed.
    /// Those are different situations to debug and the record distinguishes
    /// them.
    pub matched_policies: Vec<String>,
}

impl AuthzOutcome {
    /// A permit carrying no obligations and naming no policy.
    ///
    /// For authorizers that do not evaluate policy at all.
    pub fn allow() -> Self {
        Self {
            decision: AuthzDecision::Allow,
            obligations: Obligations::default(),
            matched_policies: Vec::new(),
        }
    }

    /// A denial with `reason`, naming no policy.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: AuthzDecision::Deny(reason.into()),
            obligations: Obligations::default(),
            matched_policies: Vec::new(),
        }
    }

    /// Whether the request was permitted.
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Whether the denial was the default rather than an explicit `forbid`.
    ///
    /// Deny-by-default and deny-by-rule look identical to a client and are
    /// entirely different to whoever has to fix the policy set.
    pub fn is_default_deny(&self) -> bool {
        self.decision.is_denied() && self.matched_policies.is_empty()
    }
}

/// Trait for authorization implementations.
///
/// [`decide`](Self::decide) is the single required method, and it returns an
/// [`AuthzOutcome`] rather than a bare decision. That shape is deliberate: an
/// implementation cannot forget to surface a row filter, a column mask, or the
/// policy that produced the result, and a caller that wants to ignore one has
/// to say so explicitly. A convenience method that dropped them would make
/// `@row_filter` silently ineffective and the audit trail silently uninformative.
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Decides `ctx`, returning the obligations and the policies that matched.
    ///
    /// Obligations are empty for a denial: nothing was granted, so there is
    /// nothing to qualify.
    async fn decide(&self, ctx: &AuthzContext) -> AuthzOutcome;

    /// An identifier for the policy set in force, recorded with every decision.
    ///
    /// Two records carrying the same version were evaluated against the same
    /// rules, which is what makes a decision reproducible after the policies
    /// have moved on. `None` when the authorizer evaluates no policy.
    fn policy_set_version(&self) -> Option<String> {
        None
    }

    /// Decides `ctx`, discarding obligations.
    ///
    /// Only correct where obligations cannot apply — a namespace or catalog
    /// resource, or a listing decision. For anything that hands out access to
    /// table *data*, use [`authorize`](Self::authorize).
    async fn authorize_ignoring_obligations(&self, ctx: &AuthzContext) -> AuthzDecision {
        self.decide(ctx).await.decision
    }

    /// Authorizes `ctx`, auditing a denial, and returns the obligations.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] when no policy permits the request.
    async fn authorize(&self, ctx: &AuthzContext) -> Result<Obligations> {
        let AuthzOutcome {
            decision,
            obligations,
            ..
        } = self.decide(ctx).await;

        if let AuthzDecision::Deny(reason) = decision {
            use super::audit::log_authz_denied;
            log_authz_denied(
                ctx.principal.id(),
                ctx.principal.tenant_id(),
                &ctx.resource.resource_type.to_string(),
                &ctx.resource.path(),
                &ctx.action.to_string(),
            );
            return Err(AuthError::Forbidden(reason));
        }

        Ok(obligations)
    }

    /// Authorizes `ctx` and discards the obligations.
    ///
    /// For resources that carry none: namespaces, the catalog root, listings.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Forbidden`] when no policy permits the request.
    async fn check(&self, ctx: &AuthzContext) -> Result<()> {
        self.authorize(ctx).await.map(|_| ())
    }

    /// Whether `ctx` is permitted, without auditing a denial.
    ///
    /// For speculative questions the caller asks on its own behalf rather than
    /// on the client's — "may this principal also write?", "should this row
    /// appear in the listing?" — where a denial is an ordinary outcome and not a
    /// security event worth a record.
    async fn permits(&self, ctx: &AuthzContext) -> bool {
        self.decide(ctx).await.is_allowed()
    }
}

// ============================================================================
// Fixed-answer authorizers
// ============================================================================

/// Authorizer that allows every request, with no obligations.
///
/// This is what `--no-auth` installs. It is not a fallback: the builder selects
/// it only when authentication is off, and never as a default when Cedar policy
/// construction fails.
pub struct AllowAllAuthorizer;

#[async_trait]
impl Authorizer for AllowAllAuthorizer {
    async fn decide(&self, _ctx: &AuthzContext) -> AuthzOutcome {
        AuthzOutcome::allow()
    }
}

/// Authorizer that denies every request.
pub struct DenyAllAuthorizer;

#[async_trait]
impl Authorizer for DenyAllAuthorizer {
    async fn decide(&self, _ctx: &AuthzContext) -> AuthzOutcome {
        AuthzOutcome::deny("Access denied by default policy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{AuthMethod, PrincipalBuilder, PrincipalType};
    use std::net::Ipv4Addr;

    fn test_principal(roles: Vec<&str>, tenant: &str) -> Principal {
        let mut builder = PrincipalBuilder::new(
            "test-user",
            "Test User",
            PrincipalType::User,
            tenant,
            AuthMethod::ApiKey,
        );
        for role in roles {
            builder = builder.with_role(role);
        }
        builder.build()
    }

    fn ctx() -> AuthzContext {
        AuthzContext::new(
            test_principal(vec!["reader"], "tenant-1"),
            Resource::table("tenant-1", ["ns"], "t"),
            Action::Read,
        )
    }

    // ── Fixed-answer authorizers ──────────────────────────────────────────

    #[tokio::test]
    async fn allow_all_permits_and_imposes_nothing() {
        let AuthzOutcome {
            decision,
            obligations,
            ..
        } = AllowAllAuthorizer.decide(&ctx()).await;
        assert!(decision.is_allowed());
        assert!(obligations.is_empty());
    }

    #[tokio::test]
    async fn deny_all_refuses() {
        assert!(DenyAllAuthorizer.decide(&ctx()).await.decision.is_denied());
        assert!(DenyAllAuthorizer.check(&ctx()).await.is_err());
        assert!(!DenyAllAuthorizer.permits(&ctx()).await);
    }

    /// `authorize` returns the obligations rather than dropping them. Dropping
    /// them is what made `@row_filter` silently ineffective.
    #[tokio::test]
    async fn authorize_surfaces_obligations() {
        let obligations = AllowAllAuthorizer.authorize(&ctx()).await.unwrap();
        assert!(obligations.is_empty());
    }

    // ── Context re-aiming ─────────────────────────────────────────────────

    /// Re-aiming preserves the principal and the request facts, or a follow-up
    /// question would be answered for a different caller.
    #[test]
    fn for_action_preserves_principal_and_request() {
        let base = ctx().with_request(RequestContext::from_ip(Ipv4Addr::new(10, 0, 0, 1).into()));
        let updated = base.for_action(Action::Update);

        assert_eq!(updated.action, Action::Update);
        assert_eq!(updated.principal.id(), base.principal.id());
        assert_eq!(updated.request.source_ip, base.request.source_ip);
        assert_eq!(updated.resource.path(), base.resource.path());
    }

    #[test]
    fn for_resource_preserves_action_and_request() {
        let base = ctx().with_request(RequestContext::from_ip(Ipv4Addr::new(10, 0, 0, 1).into()));
        let updated = base.for_resource(Resource::table("tenant-1", ["ns"], "other"));

        assert_eq!(updated.action, Action::Read);
        assert_eq!(updated.resource.name.as_deref(), Some("other"));
        assert_eq!(updated.request.source_ip, base.request.source_ip);
    }

    #[test]
    fn a_context_without_request_facts_has_no_address() {
        assert!(ctx().request.source_ip.is_none());
    }

    // ── Resource paths ────────────────────────────────────────────────────

    #[test]
    fn resource_path_includes_tenant_namespace_and_name() {
        let resource = Resource::table("tenant-1", ["ns1", "ns2"], "my_table");
        assert_eq!(resource.path(), "tenant-1/ns1/ns2/my_table");
    }

    #[test]
    fn namespace_and_catalog_paths_omit_the_missing_parts() {
        assert_eq!(Resource::namespace("t", ["a", "b"]).path(), "t/a/b");
        assert_eq!(Resource::catalog("t").path(), "t");
    }

    #[test]
    fn display_names_are_lowercase() {
        assert_eq!(ResourceType::Table.to_string(), "table");
        assert_eq!(ResourceType::View.to_string(), "view");
        assert_eq!(Action::Read.to_string(), "read");
        assert_eq!(Action::Manage.to_string(), "manage");
    }

    // ── Obligations ───────────────────────────────────────────────────────

    #[test]
    fn empty_obligations_are_empty() {
        assert!(Obligations::default().is_empty());
        assert!(Obligations::default().rows_unrestricted());
        assert_eq!(Obligations::default().describe(), "no restrictions");
    }

    #[test]
    fn a_row_filter_alone_makes_obligations_non_empty() {
        let obligations = Obligations {
            row_filters: vec![serde_json::json!({ "type": "eq", "term": "region", "value": "EU" })],
            ..Default::default()
        };
        assert!(!obligations.is_empty());
        assert!(!obligations.rows_unrestricted());
    }

    #[test]
    fn a_column_mask_alone_makes_obligations_non_empty() {
        let obligations = Obligations {
            column_masks: HashSet::from(["ssn".to_string()]),
            ..Default::default()
        };
        assert!(!obligations.is_empty());
        // Rows are unrestricted even though a column is masked; the two are
        // independent, and conflating them would withhold credentials for a
        // column-only policy under a row-filter justification.
        assert!(obligations.rows_unrestricted());
    }

    /// `describe` reaches an error body, so it must not echo filter expressions:
    /// a filter embeds the values it compares against.
    #[test]
    fn describe_counts_filters_without_quoting_them() {
        let obligations = Obligations {
            row_filters: vec![
                serde_json::json!({ "type": "eq", "term": "region", "value": "EU" }),
                serde_json::json!({ "type": "eq", "term": "tier", "value": "gold" }),
            ],
            column_masks: HashSet::from(["ssn".to_string(), "email".to_string()]),
        };

        let text = obligations.describe();
        assert!(text.contains("2 row filter(s)"), "{text}");
        assert!(!text.contains("region"), "filter expression leaked: {text}");
        assert!(!text.contains("EU"), "filter value leaked: {text}");

        // Column names are named, and in a stable order.
        assert!(text.contains("email, ssn"), "{text}");
    }
}
