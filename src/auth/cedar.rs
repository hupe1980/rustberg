//! Cedar-based authorization.
//!
//! Cedar is a policy engine rather than a permission table: a decision is the
//! result of evaluating policies against a *principal*, an *action* and a
//! *resource*, with the resource's place in a hierarchy available to the policy.
//! That hierarchy is what lets one policy cover a whole subtree, which is the
//! entire reason to use a policy engine here instead of a role/permission map.
//!
//! # The hierarchy is the point
//!
//! ```text
//! Table::"acme␟analytics␟web␟events"
//!   in Namespace::"acme␟analytics␟web"
//!   in Namespace::"acme␟analytics"
//!   in Tenant::"acme"
//! ```
//!
//! Ancestors are derived by **truncating the identifier**, so establishing them
//! costs no I/O — the path already says where a resource sits. A policy can then
//! say "readable anywhere under `acme␟analytics`" and have it apply to tables
//! that do not exist yet.
//!
//! Getting this wrong is silent: declaring the hierarchy in the schema but
//! building entities with empty parent sets makes `in` never match, so every
//! path-scoped policy fails shut while appearing configured. The tests in this
//! module exist to catch that.
//!
//! # Identifier encoding
//!
//! Path segments are joined with `␟` (unit separator, `\u{1F}`), never `.`. A
//! dotted id would be ambiguous — `Namespace::"a.b"` could denote the namespace
//! `["a", "b"]` or the single namespace named `"a.b"`, both legal — and in an
//! authorization layer ambiguity is a vulnerability: a policy written for one
//! resource would silently match another. Name validation rejects `␟`, so the
//! encoding is injective and truncation is exact.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use async_trait::async_trait;
use cedar_policy::{
    Authorizer as CedarEngine, Context, Decision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicyId, PolicySet, Request, RestrictedExpression, Schema, ValidationMode,
    Validator,
};

use super::authz::{
    Action, Authorizer, AuthzContext, AuthzDecision, AuthzOutcome, Obligations, ResourceType,
};
use super::error::{AuthError, Result};

/// Separator joining path segments inside an entity id.
const SEP: char = '\u{1F}';

/// Cedar schema for the catalog's entities and actions.
///
/// `Tenant` is the root of the resource tree. Under the federated design it
/// becomes the mount; the shape of the hierarchy does not change.
///
/// # Context attributes
///
/// `source_ip` is **optional** in the schema (`source_ip?`) because there is not
/// always an address to report: a library embedding calls the authorizer
/// in-process, with no connection behind the request. Declaring it optional is
/// what makes a policy conditioned on the address fail *closed* in that case —
/// `context has source_ip` is false, so a `when` guarding on it is unsatisfied
/// and an `unless` guarding on it does not exempt the request. Declaring it
/// required instead would make Cedar reject the whole request as ill-formed,
/// which the authorizer reports as a denial too, but with an error that looks
/// like a bug rather than a policy outcome.
const SCHEMA: &str = r#"
namespace Rustberg {
  entity Group;
  entity User in [Group] { tenant: String };

  entity Tenant { tenant: String };
  entity Namespace in [Namespace, Tenant] { tenant: String };
  entity Table in [Namespace] { tenant: String };
  entity View in [Namespace] { tenant: String };

  // The tenant's policy set: read with Read, changed with Manage. Policy is a
  // protected resource like any other, or the model is circular.
  entity PolicySet in [Tenant] { tenant: String };

  action Read, List, Create, Update, Delete, Manage
    appliesTo {
      principal: User,
      resource: [Tenant, Namespace, Table, View, PolicySet],
      context: { utc_hour: Long, source_ip?: ipaddr }
    };
}
"#;

/// Default policies reproducing the built-in roles.
///
/// The same grants a role-and-permission table would hardcode, with one
/// difference that matters: because they are policies, a deployment can narrow
/// them to a namespace subtree, add conditions, or replace them outright without
/// changing the server.
///
/// Every rule is conditioned on the resource belonging to the caller's own
/// tenant, so tenant isolation is part of the policy rather than a separate
/// layer that has to be remembered.
pub const DEFAULT_POLICIES: &str = r#"
// Administrators: everything, within their own tenant.
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

// Readers: read and list only.
permit(
  principal in Rustberg::Group::"reader",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource
) when { resource.tenant == principal.tenant };

// Writers: read, list, create and update. Deleting is deliberately not granted.
permit(
  principal in Rustberg::Group::"writer",
  action in [
    Rustberg::Action::"Read",
    Rustberg::Action::"List",
    Rustberg::Action::"Create",
    Rustberg::Action::"Update"
  ],
  resource
) when { resource.tenant == principal.tenant };
"#;

/// Annotation naming a row filter a permit implies.
pub const ROW_FILTER_ANNOTATION: &str = "row_filter";

/// Annotation naming a column a permit withholds.
pub const COLUMN_MASK_ANNOTATION: &str = "column_mask";

/// Authorizer backed by a Cedar policy set.
pub struct CedarAuthorizer {
    engine: CedarEngine,
    policies: PolicySet,
    schema: Schema,
    /// Content-derived identifier for this policy set, recorded with every
    /// audited decision. Computed once; read on every request.
    policy_set_version: String,
}

impl std::fmt::Debug for CedarAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarAuthorizer")
            .field("policies", &self.policies.policies().count())
            .finish_non_exhaustive()
    }
}

impl CedarAuthorizer {
    /// Builds an authorizer from Cedar policy source.
    ///
    /// Policies are validated against the schema here, so a misspelled entity
    /// type or action is a startup failure. Without validation such a policy
    /// simply never matches, which for a `permit` means access quietly
    /// disappears and for a `forbid` means a restriction quietly does not apply.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Configuration`] if the policies do not parse or do
    /// not validate.
    pub fn new(policy_src: &str) -> Result<Self> {
        let schema = Schema::from_cedarschema_str(SCHEMA)
            .map_err(|e| AuthError::Configuration(format!("Invalid Cedar schema: {e}")))?
            .0;

        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| AuthError::Configuration(format!("Invalid Cedar policy: {e}")))?;

        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            return Err(AuthError::Configuration(format!(
                "Cedar policy validation failed: {}",
                errors.join("; ")
            )));
        }

        Self::validate_row_filters(&policies)?;

        let authorizer = Self {
            engine: CedarEngine::new(),
            policies,
            schema,
            policy_set_version: Self::compute_policy_set_version(policy_src),
        };
        authorizer.warn_broad_permits();
        Ok(authorizer)
    }

    /// Refuses a policy set whose `@row_filter` is not a readable predicate.
    ///
    /// A row filter is an Iceberg [JSON predicate](crate::predicate), and one
    /// that cannot be read is a restriction that would silently not apply —
    /// the same failure an untypecheckable `forbid` is, and it gets the same
    /// answer.
    ///
    /// Shape only. Whether a column exists is a question about a table, and one
    /// policy covers tables that do not exist yet.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] naming the policy and what it got wrong.
    fn validate_row_filters(policies: &PolicySet) -> Result<()> {
        for policy in policies.policies() {
            let Some(filter) = policy.annotation(ROW_FILTER_ANNOTATION) else {
                continue;
            };

            let json: serde_json::Value = serde_json::from_str(filter).map_err(|e| {
                AuthError::Configuration(format!(
                    "policy '{}' has a @row_filter that is not JSON: {e}. A row filter is \
                     an Iceberg predicate expression, for example \
                     {{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}}.",
                    policy.id()
                ))
            })?;

            crate::predicate::validate_shape(&json).map_err(|e| {
                AuthError::Configuration(format!(
                    "policy '{}' has a @row_filter that is not a predicate: {e}",
                    policy.id()
                ))
            })?;
        }
        Ok(())
    }

    /// Notes at load time that this policy set can void its own row filters.
    ///
    /// Deliberately crude: it reports that *some* permit carries a filter while
    /// *some other* permit does not, without asking whether the two can ever
    /// match one request. Answering that is the overlap analysis
    /// [`Self::warn_voided`] explains is not worth attempting — undecidable in
    /// general, and approximate enough in practice that operators learn to
    /// ignore it.
    ///
    /// So this does not claim a filter *will* be voided. It says the policy set
    /// has the shape in which that happens, names the unannotated permits, and
    /// leaves the exact answer to `warn_voided` on the first request that
    /// actually demonstrates it. That division is the point: the cheap check runs
    /// before any traffic and over-reports, the exact one needs traffic and never
    /// over-reports.
    ///
    /// Silent for the overwhelmingly common case of a policy set with no filters
    /// at all.
    fn warn_broad_permits(&self) {
        let unannotated = self.broad_permits_over_restrictions();
        if unannotated.is_empty() {
            return;
        }

        tracing::warn!(
            unannotated_permits = ?unannotated,
            policy_set_version = %self.policy_set_version,
            "This policy set carries @row_filter or @column_mask on some permits and not \
             others. Wherever an unannotated permit matches the same request as a restricted \
             one, the restriction is voided and the caller sees every row and every column — \
             permits grant, so an unrestricted permit wins over a filtered one and a permit \
             withholding no column grants every column. Check the listed permits against the \
             restricted ones."
        );
    }

    /// Unannotated permits, when this policy set also has restricted ones.
    ///
    /// Empty when nothing can be voided: no annotations anywhere, or every
    /// permit annotated. Separated from the warning so it can be asserted on
    /// directly — a test that had to capture log output would be testing
    /// `tracing`.
    ///
    /// **Both** annotations count, because both are voided by the same shape of
    /// policy set even though they compose in opposite directions. Row filters
    /// are OR-ed, so an unannotated permit contributes "every row"; column masks
    /// are intersected, so an unannotated permit contributes "withhold nothing".
    /// Either way the restriction disappears, so warning about one and not the
    /// other would leave the quieter half of the hazard unreported.
    fn broad_permits_over_restrictions(&self) -> Vec<String> {
        let mut annotated = 0usize;
        let mut unannotated: Vec<String> = Vec::new();

        for policy in self.policies.policies() {
            // Only permits compose this way. A `forbid` restricts regardless of
            // whether it is annotated, so it can never void a restriction.
            if policy.effect() != cedar_policy::Effect::Permit {
                continue;
            }
            let restricted = policy.annotation(ROW_FILTER_ANNOTATION).is_some()
                || policy.annotation(COLUMN_MASK_ANNOTATION).is_some();
            if restricted {
                annotated += 1;
            } else {
                unannotated.push(policy.id().to_string());
            }
        }

        if annotated == 0 {
            return Vec::new();
        }
        unannotated.sort();
        unannotated
    }

    /// Whether the policy set contains no policies at all.
    ///
    /// Such a set denies everything, which is correct for a *fixed-answer*
    /// authorizer and a startup failure for a real deployment: it accepts
    /// nobody, including anyone trying to repair it.
    pub fn is_empty(&self) -> bool {
        self.policies.policies().count() == 0
    }

    /// An authorizer with no policies: everything is denied.
    ///
    /// Useful as an explicit "nothing is permitted yet" starting point.
    pub fn empty() -> Result<Self> {
        Self::new("")
    }

    /// An authorizer carrying [`DEFAULT_POLICIES`].
    pub fn with_default_policies() -> Result<Self> {
        Self::new(DEFAULT_POLICIES)
    }

    fn uid(entity_type: &str, id: &str) -> Result<EntityUid> {
        let type_name = EntityTypeName::from_str(&format!("Rustberg::{entity_type}"))
            .map_err(|e| AuthError::Internal(format!("Invalid entity type: {e}")))?;
        Ok(EntityUid::from_type_name_and_id(
            type_name,
            EntityId::from_str(id).unwrap_or_else(|_| unreachable!("EntityId parse is infallible")),
        ))
    }

    fn action_uid(action: &Action) -> Result<EntityUid> {
        let name = match action {
            Action::Read => "Read",
            Action::List => "List",
            Action::Create => "Create",
            Action::Update => "Update",
            Action::Delete => "Delete",
            Action::Manage => "Manage",
        };
        let type_name = EntityTypeName::from_str("Rustberg::Action")
            .map_err(|e| AuthError::Internal(format!("Invalid action type: {e}")))?;
        Ok(EntityUid::from_type_name_and_id(
            type_name,
            EntityId::from_str(name).unwrap_or_else(|_| unreachable!()),
        ))
    }

    /// Builds the resource entity and every ancestor it has.
    ///
    /// Returns the resource's own uid alongside the entities, since the caller
    /// needs it for the request.
    fn resource_entities(ctx: &AuthzContext) -> Result<(EntityUid, Vec<Entity>)> {
        let tenant = &ctx.resource.tenant_id;
        let mut entities = Vec::new();

        let attrs = || {
            HashMap::from([(
                "tenant".to_string(),
                RestrictedExpression::new_string(tenant.clone()),
            )])
        };
        let build = |uid: EntityUid, parents: HashSet<EntityUid>| -> Result<Entity> {
            Entity::new(uid, attrs(), parents)
                .map_err(|e| AuthError::Internal(format!("Invalid resource entity: {e}")))
        };

        // Root.
        let tenant_uid = Self::uid("Tenant", tenant)?;
        entities.push(build(tenant_uid.clone(), HashSet::new())?);

        // The policy set hangs directly off the tenant and has no namespace
        // path, so it is resolved before the namespace chain is walked.
        if ctx.resource.resource_type == ResourceType::PolicySet {
            let uid = Self::uid("PolicySet", tenant)?;
            entities.push(build(uid.clone(), HashSet::from([tenant_uid]))?);
            return Ok((uid, entities));
        }

        // Each namespace level is a child of the level above it, and the first
        // is a child of the tenant. Building the chain here is what makes
        // `resource in Namespace::"..."` work for descendants.
        let namespace = ctx.resource.namespace.clone().unwrap_or_default();
        let mut parent = tenant_uid.clone();
        let mut path = tenant.clone();

        for level in &namespace {
            path.push(SEP);
            path.push_str(level);
            let uid = Self::uid("Namespace", &path)?;
            entities.push(build(uid.clone(), HashSet::from([parent.clone()]))?);
            parent = uid;
        }

        // A named leaf is a table or a view; without a name the resource *is*
        // the namespace (or the tenant, when there is no namespace either).
        let resource_uid = match (&ctx.resource.name, &ctx.resource.resource_type) {
            (Some(name), kind) => {
                let leaf_type = match kind {
                    ResourceType::View => "View",
                    _ => "Table",
                };
                path.push(SEP);
                path.push_str(name);
                let uid = Self::uid(leaf_type, &path)?;
                entities.push(build(uid.clone(), HashSet::from([parent.clone()]))?);
                uid
            }
            (None, _) => parent,
        };

        Ok((resource_uid, entities))
    }

    /// Builds the principal entity and the groups it belongs to.
    fn principal_entities(ctx: &AuthzContext) -> Result<(EntityUid, Vec<Entity>)> {
        let uid = Self::uid("User", ctx.principal.id())?;

        let mut entities = Vec::new();
        let mut groups = HashSet::new();

        // Roles are the principal's groups. They come from the token or the API
        // key, so no lookup is needed here either.
        for role in ctx.principal.roles() {
            let group = Self::uid("Group", role)?;
            entities.push(Entity::new_no_attrs(group.clone(), HashSet::new()));
            groups.insert(group);
        }

        let attrs = HashMap::from([(
            "tenant".to_string(),
            RestrictedExpression::new_string(ctx.principal.tenant_id().to_string()),
        )]);

        entities.push(
            Entity::new(uid.clone(), attrs, groups)
                .map_err(|e| AuthError::Internal(format!("Invalid principal entity: {e}")))?,
        );

        Ok((uid, entities))
    }

    /// Evaluates `ctx`, returning the decision, the obligations the matching
    /// policies carry, and the ids of those policies.
    pub fn evaluate(&self, ctx: &AuthzContext) -> Result<AuthzOutcome> {
        let (principal_uid, principal_entities) = Self::principal_entities(ctx)?;
        let (resource_uid, resource_entities) = Self::resource_entities(ctx)?;

        let entities = Entities::from_entities(
            principal_entities.into_iter().chain(resource_entities),
            Some(&self.schema),
        )
        .map_err(|e| AuthError::Internal(format!("Failed to build Cedar entities: {e}")))?;

        // Time is supplied as UTC. A policy meaning "outside business hours"
        // must not change meaning when a replica moves region.
        let mut pairs = vec![(
            "utc_hour".to_string(),
            RestrictedExpression::new_long(i64::from(current_utc_hour())),
        )];

        // Omitted entirely when there is no address, rather than substituted with
        // a placeholder. A sentinel like 0.0.0.0 would silently satisfy or
        // violate `isInRange` checks; an absent optional attribute makes every
        // condition that reads it unsatisfied, which fails closed.
        if let Some(ip) = ctx.request.source_ip {
            pairs.push((
                "source_ip".to_string(),
                RestrictedExpression::new_ip(ip.to_string()),
            ));
        }

        let context = Context::from_pairs(pairs)
            .map_err(|e| AuthError::Internal(format!("Failed to build Cedar context: {e}")))?;

        let request = Request::new(
            principal_uid,
            Self::action_uid(&ctx.action)?,
            resource_uid,
            context,
            // Passing the schema makes Cedar reject a request that does not fit
            // it, rather than evaluating something the policies cannot describe.
            Some(&self.schema),
        )
        .map_err(|e| AuthError::Internal(format!("Invalid Cedar request: {e}")))?;

        let response = self
            .engine
            .is_authorized(&request, &self.policies, &entities);

        // Named on both branches. On a permit these are the permits that
        // matched; on a denial they are the *forbids* that matched, and an empty
        // list means nothing forbade the request and nothing permitted it
        // either. Both are worth being able to tell apart afterwards.
        let matched_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();

        match response.decision() {
            Decision::Allow => Ok(AuthzOutcome {
                decision: AuthzDecision::Allow,
                obligations: self
                    .collect_obligations(response.diagnostics().reason(), &ctx.resource.path()),
                matched_policies,
            }),
            Decision::Deny => {
                // The message distinguishes the two shapes of denial, because
                // they send an operator to different places: a forbid that
                // matched is a rule to read, and nothing matching is a missing
                // permit.
                let reason = if matched_policies.is_empty() {
                    format!(
                        "No policy permits '{}' on '{}'",
                        ctx.action,
                        ctx.resource.path()
                    )
                } else {
                    format!(
                        "Forbidden by policy on '{}' for '{}'",
                        ctx.resource.path(),
                        ctx.action
                    )
                };

                Ok(AuthzOutcome {
                    decision: AuthzDecision::Deny(reason),
                    obligations: Obligations::default(),
                    matched_policies,
                })
            }
        }
    }

    /// A stable identifier for this policy set, derived from its content.
    ///
    /// # Why content rather than a counter
    ///
    /// A version number needs somewhere authoritative to live and something to
    /// increment it — which is the policy administration API that does not exist
    /// yet. A content hash needs neither, is identical on every replica that
    /// loaded the same policies, and answers the question the audit trail
    /// actually asks: *were these two decisions evaluated against the same
    /// rules?* Two replicas serving different policy files are immediately
    /// visible as two versions in the stream.
    ///
    /// It is computed once at construction, because it is read on every audited
    /// decision.
    ///
    /// Delegated to [`policy_store::version_of`] rather than reimplemented, so
    /// the version stamped on an audit record and the version recorded against
    /// a stored revision are the same string *by construction*. Two copies of
    /// this that drifted would make a record's `policy_set_version` name a
    /// revision that does not exist.
    ///
    /// [`policy_store::version_of`]: super::policy_store::version_of
    fn compute_policy_set_version(policy_src: &str) -> String {
        super::policy_store::version_of(policy_src)
    }

    /// Reports a row filter that a broad, unannotated permit has just voided.
    ///
    /// # Why this is a runtime warning and not a startup check
    ///
    /// The hazard is real and is the most likely way a deployment accidentally
    /// grants everything: a `permit(principal in Group::"staff", …)` with no
    /// `@row_filter` voids every row filter for anyone who is also in `staff`.
    /// The composition is correct — permits grant, and unrestricted OR anything
    /// is unrestricted — which is exactly what makes it dangerous. Nothing looks
    /// wrong in the policy file.
    ///
    /// The obvious answer is to detect it at load time by finding unannotated
    /// permits that *overlap* annotated ones. That requires deciding whether two
    /// Cedar policies can ever match the same request, which is undecidable in
    /// general and approximate in practice: an analysis loose enough to be sound
    /// warns about policies that never actually meet, and operators learn to
    /// ignore it.
    ///
    /// Here there is nothing to approximate. Cedar has already told us which
    /// policies matched **this** request. If one carried a filter and another did
    /// not, the filter was voided — as a fact, for a request that really
    /// happened, naming the permit responsible. No false positives are possible.
    ///
    /// The cost is that it needs a request to fire, so it cannot fail a startup.
    /// [`Self::warn_broad_permits`] covers that half at load time, conservatively,
    /// which is the right place for the approximate check precisely because it is
    /// approximate.
    ///
    /// Reported once per resource per policy set, like the alignment warning:
    /// editing the policies reports again, since the operator has changed the
    /// thing the warning is about.
    fn warn_voided(&self, resource: &str, what: &str, unrestricted_permits: &[String]) {
        let key = format!("{}{SEP}{what}{SEP}{resource}", self.policy_set_version);
        if voided_reported().get(&key).is_some() {
            return;
        }
        voided_reported().insert(key, ());

        tracing::warn!(
            resource = %resource,
            restriction = %what,
            permits = ?unrestricted_permits,
            policy_set_version = %self.policy_set_version,
            "A policy restriction was voided: these permits also matched this request and \
             carry no {what}, so the caller is unrestricted. Permits grant — an unannotated \
             permit contributes every row to the union of filters, and withholds no column \
             from the intersection of masks. Narrow the listed permits or annotate them."
        );
    }

    /// Gathers row filters and column masks from the policies that matched.
    ///
    /// `resource` names what was being decided, so that a filter voided by a
    /// broad permit can be reported against it — see [`Self::warn_voided`].
    fn collect_obligations<'a>(
        &self,
        matched: impl Iterator<Item = &'a PolicyId>,
        resource: &str,
    ) -> Obligations {
        let mut row_filters = Vec::new();
        let mut mask_sets: Vec<HashSet<String>> = Vec::new();
        // Recorded as flags and lists rather than by clearing as we go, because
        // Cedar does not promise an order for matched policies: clearing would
        // make the result depend on whether the unannotated permit happened to
        // be visited first.
        let mut unfiltered_permits: Vec<String> = Vec::new();
        let mut unmasked_permits: Vec<String> = Vec::new();
        let mut any_mask = false;

        for id in matched {
            match self.policies.annotation(id, ROW_FILTER_ANNOTATION) {
                // Validated at load, so this cannot fail here — and if it
                // somehow did, treating the filter as absent would *widen* the
                // grant. Skipping the permit's contribution is the safe
                // direction: the caller keeps whatever the other permits allow.
                Some(filter) => match serde_json::from_str(filter) {
                    Ok(predicate) => row_filters.push(predicate),
                    Err(e) => {
                        tracing::error!(
                            policy = %id,
                            error = %e,
                            "A @row_filter that passed validation no longer parses; \
                             ignoring this permit's grant"
                        );
                        continue;
                    }
                },
                // An unannotated permit grants every row, and union with
                // "unrestricted" is unrestricted.
                None => unfiltered_permits.push(id.to_string()),
            }

            match self.policies.annotation(id, COLUMN_MASK_ANNOTATION) {
                Some(mask) => {
                    any_mask = true;
                    mask_sets.push(mask.split(',').map(|c| c.trim().to_string()).collect());
                }
                // A permit that withholds nothing grants every column, and
                // the intersection with the empty set is empty — exactly as
                // voiding as the row-filter case, and quieter.
                None => {
                    unmasked_permits.push(id.to_string());
                    mask_sets.push(HashSet::new());
                }
            }
        }

        // Each condition below is the *fact* that a restriction was voided, not
        // a guess at one: these permits matched this request, at least one
        // carried the annotation, and at least one did not.
        if !unfiltered_permits.is_empty() && !row_filters.is_empty() {
            self.warn_voided(resource, "@row_filter", &unfiltered_permits);
            row_filters.clear();
        }
        if !unmasked_permits.is_empty() && any_mask {
            self.warn_voided(resource, "@column_mask", &unmasked_permits);
        }

        // Intersection: a column is withheld only if every matching permit
        // withholds it.
        let column_masks = mask_sets
            .into_iter()
            .reduce(|acc, next| acc.intersection(&next).cloned().collect())
            .unwrap_or_default();

        Obligations {
            row_filters,
            column_masks,
        }
    }
}

/// Resources already reported as having had a filter voided.
///
/// Keyed by policy-set version and resource, so a policy edit reports again.
/// Bounded and self-expiring for the same reason the alignment cache is: an
/// unbounded set keyed by resource is a memory leak proportional to catalog size.
fn voided_reported() -> &'static moka::sync::Cache<String, ()> {
    use std::sync::OnceLock;
    use std::time::Duration;
    static REPORTED: OnceLock<moka::sync::Cache<String, ()>> = OnceLock::new();
    REPORTED.get_or_init(|| {
        moka::sync::Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(3600))
            .build()
    })
}

/// Current hour in UTC, 0–23.
fn current_utc_hour() -> u32 {
    use chrono::Timelike;
    chrono::Utc::now().hour()
}

#[async_trait]
impl Authorizer for CedarAuthorizer {
    async fn decide(&self, ctx: &AuthzContext) -> AuthzOutcome {
        match self.evaluate(ctx) {
            Ok(outcome) => outcome,
            // Deny by default, including on evaluation error: a policy engine
            // that fails open is worse than none, because it is trusted.
            Err(e) => {
                tracing::error!(error = %e, "Cedar evaluation failed; denying");
                AuthzOutcome::deny("Authorization evaluation failed")
            }
        }
    }

    fn policy_set_version(&self) -> Option<String> {
        Some(self.policy_set_version.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Principal;
    use crate::auth::authz::{RequestContext, Resource};
    use crate::auth::principal::{AuthMethod, PrincipalBuilder, PrincipalType};

    fn principal(roles: &[&str], tenant: &str) -> Principal {
        let mut b = PrincipalBuilder::new(
            "alice",
            "Alice",
            PrincipalType::User,
            tenant,
            AuthMethod::ApiKey,
        );
        for r in roles {
            b = b.with_role(*r);
        }
        b.build()
    }

    fn table_ctx(tenant: &str, ns: &[&str], name: &str, action: Action) -> AuthzContext {
        AuthzContext::new(
            principal(&["analysts"], tenant),
            Resource::table(tenant, ns.iter().map(|s| s.to_string()), name),
            action,
        )
    }

    // ── The hierarchy ─────────────────────────────────────────────────────

    /// The whole reason for Cedar: a policy on an ancestor must cover a
    /// descendant that the policy never names.
    #[test]
    fn policy_on_ancestor_namespace_covers_nested_table() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Namespace::"acme\u{1F}analytics"
               );"#,
        )
        .unwrap();

        let ctx = table_ctx("acme", &["analytics", "web"], "events", Action::Read);
        assert!(
            authz.evaluate(&ctx).unwrap().decision.is_allowed(),
            "hierarchy is not established: `in` did not match a descendant"
        );
    }

    #[test]
    fn policy_on_tenant_covers_everything_beneath_it() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               );"#,
        )
        .unwrap();

        let ctx = table_ctx("acme", &["a", "b", "c"], "t", Action::Read);
        assert!(authz.evaluate(&ctx).unwrap().decision.is_allowed());
    }

    /// A sibling subtree must not be swept in.
    #[test]
    fn policy_does_not_leak_to_sibling_namespace() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Namespace::"acme\u{1F}analytics"
               );"#,
        )
        .unwrap();

        let ctx = table_ctx("acme", &["finance"], "ledger", Action::Read);
        assert!(authz.evaluate(&ctx).unwrap().decision.is_denied());
    }

    /// Cross-tenant access must be denied even for the same paths, because the
    /// tenant is the root of the hierarchy.
    #[test]
    fn policy_does_not_cross_tenants() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               );"#,
        )
        .unwrap();

        let ctx = table_ctx("other", &["analytics"], "events", Action::Read);
        assert!(authz.evaluate(&ctx).unwrap().decision.is_denied());
    }

    /// Dots are legal in names, so a dotted encoding would make `["a.b"]` and
    /// `["a","b"]` the same entity and let one policy match the other resource.
    #[test]
    fn dotted_name_is_not_confused_with_nesting() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Namespace::"acme\u{1F}a\u{1F}b"
               );"#,
        )
        .unwrap();

        // Permitted: the genuine nested namespace a / b.
        let nested = table_ctx("acme", &["a", "b"], "t", Action::Read);
        assert!(authz.evaluate(&nested).unwrap().decision.is_allowed());

        // Denied: a single namespace whose name happens to be "a.b".
        let dotted = table_ctx("acme", &["a.b"], "t", Action::Read);
        assert!(
            authz.evaluate(&dotted).unwrap().decision.is_denied(),
            "dotted name collided with the nested namespace"
        );
    }

    // ── Default posture ───────────────────────────────────────────────────

    #[test]
    fn empty_policy_set_denies() {
        let authz = CedarAuthorizer::empty().unwrap();
        let ctx = table_ctx("acme", &["ns"], "t", Action::Read);
        assert!(authz.evaluate(&ctx).unwrap().decision.is_denied());
    }

    #[test]
    fn forbid_overrides_permit() {
        let authz = CedarAuthorizer::new(
            r#"
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            forbid(
              principal,
              action == Rustberg::Action::"Read",
              resource in Rustberg::Namespace::"acme\u{1F}secret"
            );"#,
        )
        .unwrap();

        assert!(
            authz
                .evaluate(&table_ctx("acme", &["public"], "t", Action::Read))
                .unwrap()
                .decision
                .is_allowed()
        );
        assert!(
            authz
                .evaluate(&table_ctx("acme", &["secret"], "t", Action::Read))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    #[test]
    fn action_is_discriminated() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               );"#,
        )
        .unwrap();

        assert!(
            authz
                .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
                .unwrap()
                .decision
                .is_allowed()
        );
        assert!(
            authz
                .evaluate(&table_ctx("acme", &["ns"], "t", Action::Delete))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    // ── Validation ────────────────────────────────────────────────────────

    /// A misspelled entity type would simply never match, so a `permit` would
    /// silently grant nothing. It must fail at load instead.
    #[test]
    fn misspelled_policy_is_rejected_at_load() {
        let err = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Namesapce::"acme"
               );"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("validation")
                || err.to_string().to_lowercase().contains("invalid")
        );
    }

    #[test]
    fn unparseable_policy_is_rejected_at_load() {
        assert!(CedarAuthorizer::new("this is not cedar").is_err());
    }

    // ── Voided row filters ────────────────────────────────────────────────

    /// The load-time check fires on the *shape* that permits voiding.
    ///
    /// It does not decide whether the two permits can actually meet — that is
    /// the overlap analysis this deliberately does not attempt — so a policy set
    /// mixing annotated and unannotated permits is reported whether or not any
    /// request will ever demonstrate it.
    #[test]
    fn a_policy_set_mixing_filtered_and_unfiltered_permits_has_the_voiding_shape() {
        let mixed = CedarAuthorizer::new(
            r#"
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            permit(
              principal in Rustberg::Group::"staff",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();
        assert_eq!(
            mixed.broad_permits_over_restrictions(),
            vec!["policy1".to_string()],
            "the unannotated permit is the one that voids"
        );

        // The common case — no filters anywhere — must stay silent, or the
        // warning is noise every deployment learns to ignore.
        let unfiltered = CedarAuthorizer::new(DEFAULT_POLICIES).unwrap();
        assert!(
            unfiltered.broad_permits_over_restrictions().is_empty(),
            "a policy set with no filters has nothing to void"
        );

        // Every permit annotated: nothing can void anything.
        let all_filtered = CedarAuthorizer::new(
            r#"
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"US\"}")
            permit(
              principal in Rustberg::Group::"us",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();
        assert!(all_filtered.broad_permits_over_restrictions().is_empty());
    }

    /// A `forbid` is not a permit and never voids a filter.
    ///
    /// Forbids restrict regardless of annotation, so counting an unannotated one
    /// as "grants every row" would warn about a policy that does the opposite.
    #[test]
    fn a_forbid_does_not_count_as_a_voiding_permit() {
        let authz = CedarAuthorizer::new(
            r#"
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            forbid(
              principal in Rustberg::Group::"contractors",
              action,
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();

        assert!(
            authz.broad_permits_over_restrictions().is_empty(),
            "a forbid restricts; it cannot grant the rows a filter excludes"
        );
    }

    // ── Obligations ───────────────────────────────────────────────────────

    #[test]
    fn row_filter_is_carried_from_the_matched_policy() {
        let authz = CedarAuthorizer::new(
            r#"@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
               permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               );"#,
        )
        .unwrap();

        let AuthzOutcome {
            decision,
            obligations,
            ..
        } = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap();

        assert!(decision.is_allowed());
        assert_eq!(
            obligations.row_filters,
            vec![serde_json::json!({ "type": "eq", "term": "region", "value": "EU" })]
        );
        assert!(!obligations.rows_unrestricted());
    }

    /// Permits grant, so their filters compose as a union.
    #[test]
    fn row_filters_from_several_permits_are_unioned() {
        let authz = CedarAuthorizer::new(
            r#"
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"US\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Namespace::"acme\u{1F}ns"
            );"#,
        )
        .unwrap();

        let obligations = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap()
            .obligations;

        assert_eq!(obligations.row_filters.len(), 2);
    }

    /// An unannotated permit grants every row, and unrestricted-OR-anything is
    /// unrestricted. This is correct, and it is the likeliest way a deployment
    /// accidentally grants everything.
    #[test]
    fn unannotated_permit_voids_row_filters() {
        let authz = CedarAuthorizer::new(
            r#"
            @row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Namespace::"acme\u{1F}ns"
            );
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();

        let obligations = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap()
            .obligations;

        assert!(
            obligations.rows_unrestricted(),
            "a broad unannotated permit must void the filters, not be ignored"
        );
    }

    /// Masks intersect: a permit that does not mask a column is granting it.
    #[test]
    fn column_masks_are_intersected_not_unioned() {
        let authz = CedarAuthorizer::new(
            r#"
            @column_mask("ssn,email")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Namespace::"acme\u{1F}ns"
            );
            @column_mask("ssn")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();

        let obligations = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap()
            .obligations;

        assert_eq!(
            obligations.column_masks,
            HashSet::from(["ssn".to_string()]),
            "email is granted by the second permit and must not be withheld"
        );
    }

    /// The mask half of the voiding hazard.
    ///
    /// Masks intersect, so an unannotated permit contributes "withhold nothing"
    /// and the intersection empties. That is exactly as voiding as the row-filter
    /// case, and the load-time check has to report the shape for both or the
    /// quieter half goes unreported.
    #[test]
    fn a_broad_permit_voids_a_column_mask_and_is_reported() {
        let authz = CedarAuthorizer::new(
            r#"
            @column_mask("ssn")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );"#,
        )
        .unwrap();

        assert_eq!(
            authz.broad_permits_over_restrictions(),
            vec!["policy1".to_string()],
            "a policy set that can void a mask has the same shape as one that can void a filter"
        );

        let obligations = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap()
            .obligations;

        assert!(
            obligations.column_masks.is_empty(),
            "the unannotated permit grants every column, so nothing is withheld"
        );
    }

    /// A mask on every matching permit survives; only a *missing* annotation
    /// voids. Otherwise the warning above would fire on correct policy sets.
    #[test]
    fn a_mask_on_every_permit_is_not_voided() {
        let authz = CedarAuthorizer::new(
            r#"
            @column_mask("ssn")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            @column_mask("ssn,email")
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Namespace::"acme\u{1F}ns"
            );"#,
        )
        .unwrap();

        assert!(authz.broad_permits_over_restrictions().is_empty());
        assert_eq!(
            authz
                .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
                .unwrap()
                .obligations
                .column_masks,
            HashSet::from(["ssn".to_string()])
        );
    }

    // ── Default policies ──────────────────────────────────────────────────

    fn ctx_for(role: &str, tenant: &str, resource_tenant: &str, action: Action) -> AuthzContext {
        AuthzContext::new(
            principal(&[role], tenant),
            Resource::table(resource_tenant, ["ns"], "t"),
            action,
        )
    }

    /// Extracts every ```` ```cedar ```` block from a Markdown document.
    fn cedar_blocks(doc: &str) -> Vec<&str> {
        let mut blocks = Vec::new();
        let mut rest = doc;
        while let Some(start) = rest.find("```cedar\n") {
            rest = &rest[start + "```cedar\n".len()..];
            let end = rest.find("```").expect("unterminated cedar block");
            blocks.push(&rest[..end]);
            rest = &rest[end..];
        }
        blocks
    }

    /// **Every** Cedar policy printed anywhere in the documentation must validate
    /// against the real schema. A policy that does not typecheck is a startup
    /// failure, so publishing one hands the reader a server that will not boot —
    /// and a `permit` that silently never matches is worse still.
    ///
    /// Covers every documentation file, not just `authorization.md`: an invalid
    /// policy in any page is one a reader will copy.
    #[test]
    fn every_documented_policy_validates() {
        // Each file is listed explicitly: `include_str!` needs a literal path, and
        // an explicit list means adding a page with policies is a deliberate act.
        let docs: &[(&str, &str)] = &[
            (
                "site/content/docs/authorization.md",
                include_str!("../../site/content/docs/authorization.md"),
            ),
            (
                "site/content/docs/security.md",
                include_str!("../../site/content/docs/security.md"),
            ),
            (
                "site/content/docs/authentication.md",
                include_str!("../../site/content/docs/authentication.md"),
            ),
            (
                "site/content/docs/configuration.md",
                include_str!("../../site/content/docs/configuration.md"),
            ),
            (
                "site/content/docs/getting-started.md",
                include_str!("../../site/content/docs/getting-started.md"),
            ),
            (
                "site/content/docs/kubernetes.md",
                include_str!("../../site/content/docs/kubernetes.md"),
            ),
            (
                "site/content/docs/architecture.md",
                include_str!("../../site/content/docs/architecture.md"),
            ),
            ("README.md", include_str!("../../README.md")),
            ("CONCEPT.md", include_str!("../../CONCEPT.md")),
        ];

        let mut checked = 0;
        for (path, doc) in docs {
            for block in cedar_blocks(doc) {
                // Schema blocks declare entities and actions; they are not policies.
                if !block.contains("permit(") && !block.contains("forbid(") {
                    continue;
                }
                CedarAuthorizer::new(block).unwrap_or_else(|e| {
                    panic!("policy in {path} does not validate: {e}\n---\n{block}")
                });
                checked += 1;
            }
        }

        // The landing page's example lives in the site template rather than in
        // Markdown, and it is the most-read policy Rustberg publishes — the
        // first thing anyone evaluating the project sees. Checked here so
        // moving it out of a `.md` file did not quietly drop it from the gate.
        checked += validate_landing_page_policies();

        assert!(
            checked >= 10,
            "expected to validate many documented policies, found {checked} — \
             has the block format changed?"
        );
    }

    /// Validates the Cedar sample printed on the site's landing page.
    ///
    /// It is inside an HTML template, so the block is delimited by
    /// `class="language-cedar"` rather than by a fence, and the three characters
    /// Cedar's comparison operators need are HTML-escaped.
    fn validate_landing_page_policies() -> usize {
        const TEMPLATE: &str = include_str!("../../site/templates/index.html");

        let mut checked = 0;
        for block in TEMPLATE.split("<code class=\"language-cedar\">").skip(1) {
            let block = block
                .split("</code>")
                .next()
                .expect("an opened code block is closed")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");

            CedarAuthorizer::new(&block).unwrap_or_else(|e| {
                panic!("policy on the landing page does not validate: {e}\n---\n{block}")
            });
            checked += 1;
        }

        assert!(
            checked > 0,
            "the landing page must still carry a Cedar example; if it moved, \
             point this at wherever it went rather than deleting the check"
        );
        checked
    }

    /// The schema block printed in the docs must be the schema the binary uses.
    /// A drifted copy teaches readers to write policies against attributes that
    /// do not exist.
    #[test]
    fn documented_schema_matches_the_real_one() {
        let doc = include_str!("../../site/content/docs/authorization.md");
        let documented = cedar_blocks(doc)
            .into_iter()
            .find(|b| b.contains("entity Namespace"))
            .expect("the authorization page must print the schema");

        let normalise = |s: &str| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .replace(", ", ",")
        };

        assert_eq!(
            normalise(documented),
            normalise(SCHEMA),
            "the schema in docs/authorization.md has drifted from SCHEMA"
        );
    }

    #[test]
    fn default_policies_validate() {
        CedarAuthorizer::with_default_policies().unwrap();
    }

    #[test]
    fn default_admin_may_do_anything_in_own_tenant() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        for action in [Action::Read, Action::Create, Action::Update, Action::Delete] {
            assert!(
                authz
                    .evaluate(&ctx_for("admin", "acme", "acme", action.clone()))
                    .unwrap()
                    .decision
                    .is_allowed(),
                "admin denied {action}"
            );
        }
    }

    /// Tenant isolation is expressed by the policies themselves, so it holds
    /// without a separate isolation layer running alongside the engine.
    #[test]
    fn default_policies_deny_across_tenants() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        assert!(
            authz
                .evaluate(&ctx_for("admin", "acme", "other", Action::Read))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    #[test]
    fn default_reader_cannot_write() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        assert!(
            authz
                .evaluate(&ctx_for("reader", "acme", "acme", Action::Read))
                .unwrap()
                .decision
                .is_allowed()
        );
        assert!(
            authz
                .evaluate(&ctx_for("reader", "acme", "acme", Action::Create))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    /// Preserved from the roles this replaces: a writer may create and update
    /// but not drop.
    #[test]
    fn default_writer_may_not_delete() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        assert!(
            authz
                .evaluate(&ctx_for("writer", "acme", "acme", Action::Create))
                .unwrap()
                .decision
                .is_allowed()
        );
        assert!(
            authz
                .evaluate(&ctx_for("writer", "acme", "acme", Action::Delete))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    #[test]
    fn unknown_role_gets_nothing() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        assert!(
            authz
                .evaluate(&ctx_for("intern", "acme", "acme", Action::Read))
                .unwrap()
                .decision
                .is_denied()
        );
    }

    #[test]
    fn denied_request_carries_no_obligations() {
        let authz = CedarAuthorizer::empty().unwrap();
        let obligations = authz
            .evaluate(&table_ctx("acme", &["ns"], "t", Action::Read))
            .unwrap()
            .obligations;
        assert_eq!(obligations, Obligations::default());
    }

    // ── Request context: source address ───────────────────────────────────

    /// A policy conditioned on the source address is what makes "only from inside
    /// the VPC" expressible. The schema declares `source_ip` as an optional
    /// `ipaddr`, so `isInRange` works on it.
    #[test]
    fn policy_can_condition_on_the_source_address() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               ) when {
                 context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
               };"#,
        )
        .unwrap();

        let inside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("10.1.2.3".parse().unwrap()));
        assert!(authz.evaluate(&inside).unwrap().decision.is_allowed());

        let outside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("203.0.113.7".parse().unwrap()));
        assert!(authz.evaluate(&outside).unwrap().decision.is_denied());
    }

    /// The shape from the design docs: a blanket `forbid` that an address range
    /// exempts. This is the one that matters most, because getting the optional
    /// attribute wrong here fails *open* — an `unless` on a missing attribute
    /// would exempt every request.
    #[test]
    fn forbid_unless_in_range_denies_when_the_address_is_unknown() {
        let authz = CedarAuthorizer::new(
            r#"
            permit(
              principal in Rustberg::Group::"analysts",
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            );
            forbid(
              principal,
              action == Rustberg::Action::"Read",
              resource in Rustberg::Tenant::"acme"
            ) unless {
              context has source_ip && context.source_ip.isInRange(ip("10.0.0.0/8"))
            };"#,
        )
        .unwrap();

        // In range: the forbid is exempted, the permit stands.
        let inside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("10.9.9.9".parse().unwrap()));
        assert!(authz.evaluate(&inside).unwrap().decision.is_allowed());

        // Out of range: forbidden.
        let outside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("198.51.100.1".parse().unwrap()));
        assert!(authz.evaluate(&outside).unwrap().decision.is_denied());

        // No address at all — an in-process call. The exemption must NOT apply,
        // or an embedding host silently bypasses every address-scoped forbid.
        let unknown = table_ctx("acme", &["ns"], "t", Action::Read);
        assert!(
            authz.evaluate(&unknown).unwrap().decision.is_denied(),
            "an absent source address must not exempt an address-scoped forbid"
        );
    }

    /// IPv6 must work, not just IPv4: an operator behind a v6 load balancer would
    /// otherwise find every address-conditioned policy failing shut.
    #[test]
    fn source_address_supports_ipv6() {
        let authz = CedarAuthorizer::new(
            r#"permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               ) when {
                 context has source_ip && context.source_ip.isInRange(ip("2001:db8::/32"))
               };"#,
        )
        .unwrap();

        let inside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("2001:db8::1".parse().unwrap()));
        assert!(authz.evaluate(&inside).unwrap().decision.is_allowed());

        let outside = table_ctx("acme", &["ns"], "t", Action::Read)
            .with_request(RequestContext::from_ip("2001:dead::1".parse().unwrap()));
        assert!(authz.evaluate(&outside).unwrap().decision.is_denied());
    }

    /// The default policies must not read the address, or every deployment would
    /// depend on the proxy configuration being right.
    #[test]
    fn default_policies_do_not_depend_on_the_address() {
        let authz = CedarAuthorizer::with_default_policies().unwrap();
        let no_address = ctx_for("reader", "acme", "acme", Action::Read);
        assert!(authz.evaluate(&no_address).unwrap().decision.is_allowed());
    }

    // ── The trait surface ─────────────────────────────────────────────────

    /// `decide` is the required method and must carry obligations through, since
    /// dropping them is exactly the bug this trait shape exists to prevent.
    #[tokio::test]
    async fn decide_carries_obligations_through_the_trait() {
        let authz = CedarAuthorizer::new(
            r#"@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
               permit(
                 principal in Rustberg::Group::"analysts",
                 action == Rustberg::Action::"Read",
                 resource in Rustberg::Tenant::"acme"
               );"#,
        )
        .unwrap();

        let AuthzOutcome {
            decision,
            obligations,
            ..
        } = authz
            .decide(&table_ctx("acme", &["ns"], "t", Action::Read))
            .await;

        assert!(decision.is_allowed());
        assert!(
            !obligations.is_empty(),
            "obligations were dropped crossing the trait boundary"
        );

        // And through `authorize`, which is what the handlers call.
        let obligations = authz
            .authorize(&table_ctx("acme", &["ns"], "t", Action::Read))
            .await
            .unwrap();
        assert_eq!(
            obligations.row_filters,
            vec![serde_json::json!({ "type": "eq", "term": "region", "value": "EU" })]
        );
    }
}
