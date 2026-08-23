//! The one place a catalog request is authorized.
//!
//! Every handler resolves the same three things before it acts: which tenant owns
//! the namespace, whether the caller may perform the action, and what obligations
//! the grant carries. Doing that inline in each handler produced fifteen copies
//! that had already drifted — some authorized against the caller's own tenant
//! instead of the recorded owner, some leaked existence through the status code,
//! some skipped the check for listings entirely.
//!
//! # Ownership before authorization
//!
//! A resource must be *identified* before it can be authorized, and identifying a
//! table means learning which tenant owns the namespace holding it. That
//! ownership lookup is the authorization input — never the caller's own tenant,
//! which the caller controls and could therefore use to authorize itself against
//! a resource tree it invented.
//!
//! # Why a denial is usually a 404
//!
//! Ownership resolution necessarily precedes the policy decision, so a naive
//! handler answers `404` for a namespace that does not exist and `403` for one
//! that exists but belongs to someone else. That difference is an oracle: an
//! authenticated caller enumerates every other tenant's namespaces by reading
//! status codes, which is exactly what the authorization layer exists to prevent.
//!
//! The rule here removes the difference without making errors useless:
//!
//! | Caller can *see* the resource? | Action permitted? | Answer |
//! |---|---|---|
//! | — (does not exist) | — | `404` |
//! | no | no | `404` |
//! | yes | no | `403` |
//! | yes | yes | proceed |
//!
//! "Can see" means `Read` is permitted on the resource. So `404` always means
//! *you cannot see this*, which is equally true whether or not it exists, and
//! `403` only ever tells a caller something it already knew. A caller with no
//! grant in another tenant gets `404` either way, and the oracle is closed.
//!
//! The extra decision costs one more Cedar evaluation on the failure path only,
//! and evaluation is microseconds against an in-memory entity set.

use iceberg::NamespaceIdent;

use super::ownership::owner_of;
use crate::app::AppState;
use crate::auth::{Action, AuthzContext, AuthzDecision, Obligations, Principal, RequestContext};
use crate::auth::{Resource, ResourceType};
use crate::error::{AppError, Result};

/// What a request is aimed at, for building the resource and the not-found error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// The namespace itself.
    Namespace,
    /// A table inside the namespace.
    Table(&'a str),
    /// A view inside the namespace.
    View(&'a str),
}

impl<'a> Target<'a> {
    fn resource(&self, owner: &str, namespace: &NamespaceIdent) -> Resource {
        let parts = namespace.to_vec();
        match self {
            Target::Namespace => Resource::namespace(owner, parts),
            Target::Table(name) => Resource::table(owner, parts, *name),
            Target::View(name) => Resource::view(owner, parts, *name),
        }
    }

    /// The 404 to answer with when the caller cannot see this resource.
    ///
    /// Matched to the resource kind so a client's error handling still works: an
    /// Iceberg client distinguishes `NoSuchTableException` from
    /// `NoSuchNamespaceException` and retries differently.
    fn not_found(&self, namespace: &NamespaceIdent) -> AppError {
        let ns = namespace.join(".");
        match self {
            Target::Namespace => AppError::NoSuchNamespace(ns),
            Target::Table(name) => AppError::NoSuchTable(format!("{ns}.{name}")),
            Target::View(name) => AppError::NoSuchView(format!("{ns}.{name}")),
        }
    }
}

/// An authorized request, and what the grant is qualified by.
#[derive(Debug)]
pub struct Authorized {
    /// Tenant that owns the namespace, as recorded in its properties.
    pub owner: String,
    /// Restrictions the matching policies attached to the grant.
    pub obligations: Obligations,
    /// The context the decision was made from, reusable for a follow-up question.
    ///
    /// Handlers use this to ask a *second* question without rebuilding the entity
    /// set — most importantly "may this caller also write?", which decides whether
    /// a vended credential is read-only.
    context: AuthzContext,
}

impl Authorized {
    /// Whether `action` is also permitted on the same resource.
    ///
    /// A denial here is an ordinary answer rather than a security event, so it is
    /// not audited: the caller is asking on its own behalf to decide how to serve
    /// a request that was already permitted.
    pub async fn also_permits(&self, state: &AppState, action: Action) -> bool {
        state
            .authorizer
            .permits(&self.context.for_action(action))
            .await
    }
}

/// Resolves ownership and authorizes `action` on `target` within `namespace`.
///
/// This is the entry point every handler uses. See the module docs for why a
/// denial is usually reported as `404`.
///
/// # Errors
///
/// - The target's not-found error when the namespace does not exist, records no
///   owner, or the caller cannot see the resource.
/// - [`AppError::Forbidden`] when the caller can see the resource but may not
///   perform this action on it.
pub async fn authorize(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    namespace: &NamespaceIdent,
    target: Target<'_>,
    action: Action,
) -> Result<Authorized> {
    let owner = match resolve_owner(state, namespace).await? {
        Some(owner) => owner,
        // Indistinguishable from "exists but you may not see it", by design.
        // A backend *failure* is not this case — see `resolve_owner`.
        None => return Err(target.not_found(namespace)),
    };

    let context = AuthzContext::new(
        principal.clone(),
        target.resource(&owner, namespace),
        action.clone(),
    )
    .with_request(request.clone());

    let outcome = state.authorizer.decide(&context).await;
    let allowed = outcome.is_allowed();

    record_decision(state, principal, request, &context, &action, &outcome)?;

    if !allowed {
        // Does the caller have any visibility at all? If not, saying "forbidden"
        // would confirm the resource exists.
        //
        // When the denied action *is* `Read` the answer is already known, and
        // short-circuiting to "visible" here would reopen the oracle for the
        // most common request of all.
        let visible = if action == Action::Read {
            false
        } else {
            state
                .authorizer
                .permits(&context.for_action(Action::Read))
                .await
        };

        return if visible {
            Err(AppError::Forbidden(format!(
                "Not permitted to {action} {}",
                describe(&target, namespace)
            )))
        } else {
            Err(target.not_found(namespace))
        };
    }

    Ok(Authorized {
        owner,
        obligations: outcome.obligations,
        context,
    })
}

/// Writes the audit record for one decision.
///
/// Mutations fail closed: if the record cannot be written, the request is
/// refused with `503` rather than performing an unrecorded change. Reads and
/// listings are recorded best-effort — refusing them because a disk filled turns
/// an observability problem into an outage, and a lost read record is not a lost
/// change.
///
/// # Errors
///
/// Returns [`AppError::ServiceUnavailable`] when a mutating request could not be
/// recorded and the auditor is configured to fail closed.
fn record_decision(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    context: &AuthzContext,
    action: &Action,
    outcome: &crate::auth::AuthzOutcome,
) -> Result<()> {
    let mut event = crate::auth::AuditEvent::decision(
        &action.to_string(),
        &context.resource.resource_type.to_string(),
        &context.resource.path(),
        outcome.is_allowed(),
    )
    .with_principal_id(principal.id())
    .with_tenant_id(principal.tenant_id())
    // Which rule decided, and which policy set it came from. Without these the
    // record says what happened but never why, which is the half an operator
    // actually needs.
    .with_policy_provenance(
        &outcome.matched_policies,
        state.authorizer.policy_set_version(),
    );

    if let Some(ip) = request.source_ip {
        event = event.with_client_ip_addr(ip);
    }
    if let Some(id) = request.request_id.as_deref() {
        event = event.with_request_id(id);
    }

    if is_mutating(action) {
        state.auditor.record(&event).map_err(|_| {
            AppError::ServiceUnavailable(
                "The audit trail is unavailable, so this change was not made.".to_string(),
            )
        })
    } else {
        state.auditor.record_lossy(&event);
        Ok(())
    }
}

/// Whether an action changes catalog state.
const fn is_mutating(action: &Action) -> bool {
    match action {
        Action::Create | Action::Update | Action::Delete | Action::Manage => true,
        Action::Read | Action::List => false,
    }
}

/// Authorizes an operation on the catalog root, where there is no namespace to own.
///
/// Only `listNamespaces` needs this. The root is the caller's own tenant, which is
/// sound here precisely because nothing is being addressed: the decision is "may
/// you enumerate your own catalog", and each candidate namespace is then
/// authorized individually against *its* recorded owner.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] when no policy permits the action.
pub async fn authorize_catalog(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    action: Action,
) -> Result<AuthzContext> {
    let context = AuthzContext::new(
        principal.clone(),
        Resource::catalog(principal.tenant_id()),
        action,
    )
    .with_request(request.clone());

    authorize_context(state, principal, request, context).await
}

/// Authorizes a resource that has no recorded owner yet.
///
/// Only `createNamespace` needs this: the namespace does not exist, so there is
/// nothing to look up, and the caller is asking to create it in its own tenant.
/// The decision is recorded like any other.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] when no policy permits the action, or
/// [`AppError::ServiceUnavailable`] when the decision could not be recorded.
pub async fn authorize_new(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    resource: Resource,
    action: Action,
) -> Result<AuthzContext> {
    let context =
        AuthzContext::new(principal.clone(), resource, action).with_request(request.clone());
    authorize_context(state, principal, request, context).await
}

/// Decides a prepared context, records it, and reports a denial as `403`.
///
/// Used where there is no resource to hide: the caller named its own tenant, so
/// a denial reveals nothing it did not already supply.
async fn authorize_context(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    context: AuthzContext,
) -> Result<AuthzContext> {
    let action = context.action.clone();
    let outcome = state.authorizer.decide(&context).await;

    record_decision(state, principal, request, &context, &action, &outcome)?;

    match outcome.decision {
        AuthzDecision::Allow => Ok(context),
        AuthzDecision::Deny(reason) => Err(AppError::Forbidden(reason)),
    }
}

/// Reads the recorded owner of `namespace`, or `None` if it is unusable.
///
/// `None` covers both "does not exist" and "exists but records no owner". The
/// second is not an internal error to report to the caller: an unowned namespace
/// cannot be attributed to any tenant, so no policy can decide it, and treating
/// it as the caller's own would let any tenant adopt it. It is logged, because it
/// means something wrote a namespace outside the normal path.
///
/// # A backend failure is not an absence
///
/// Flattening a store error into `None` — `get_namespace(…).await.ok()?` — makes
/// this module's table report it as `404`, on the path of *every* authorized
/// request. During an outage a client is told the namespace does not exist,
/// which is indistinguishable from someone having dropped it; a retry succeeds,
/// so the symptom is tables that come and go.
///
/// Propagating reveals nothing: a store failure is the same failure for every
/// caller, permitted or not, so it is not an oracle. Only `NamespaceNotFound`
/// means "no".
///
/// # Errors
///
/// Whatever the catalog returned, other than a genuine miss.
async fn resolve_owner(state: &AppState, namespace: &NamespaceIdent) -> Result<Option<String>> {
    let ns = match state.catalog.get_namespace(namespace).await {
        Ok(ns) => ns,
        Err(e) if e.kind() == iceberg::ErrorKind::NamespaceNotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    match owner_of(ns.properties()) {
        Some(owner) => Ok(Some(owner.to_string())),
        None => {
            tracing::warn!(
                namespace = %namespace.join("."),
                "Namespace records no owning tenant; treating it as invisible"
            );
            Ok(None)
        }
    }
}

/// Whether a caller may see a resource, for filtering a listing.
///
/// Listing asks this once per candidate. It is a plain `Read` decision with no
/// audit record: a row omitted from a page is not a denied request, and auditing
/// every filtered row would bury real denials under listing noise.
pub async fn can_see(
    state: &AppState,
    principal: &Principal,
    request: &RequestContext,
    owner: &str,
    namespace: &NamespaceIdent,
    target: Target<'_>,
) -> bool {
    let context = AuthzContext::new(
        principal.clone(),
        target.resource(owner, namespace),
        Action::Read,
    )
    .with_request(request.clone());

    state.authorizer.permits(&context).await
}

/// Human-readable name of the target, for an error message.
fn describe(target: &Target<'_>, namespace: &NamespaceIdent) -> String {
    let ns = namespace.join(".");
    match target {
        Target::Namespace => format!("namespace '{ns}'"),
        Target::Table(name) => format!("table '{ns}.{name}'"),
        Target::View(name) => format!("view '{ns}.{name}'"),
    }
}

/// The resource type a target maps to, for audit records.
impl From<Target<'_>> for ResourceType {
    fn from(target: Target<'_>) -> Self {
        match target {
            Target::Namespace => ResourceType::Namespace,
            Target::Table(_) => ResourceType::Table,
            Target::View(_) => ResourceType::View,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(parts: &[&str]) -> NamespaceIdent {
        NamespaceIdent::from_vec(parts.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[test]
    fn not_found_matches_the_resource_kind() {
        let namespace = ns(&["analytics", "web"]);

        // Iceberg clients branch on the exception type, so a table miss must not
        // be reported as a namespace miss.
        assert!(matches!(
            Target::Namespace.not_found(&namespace),
            AppError::NoSuchNamespace(_)
        ));
        assert!(matches!(
            Target::Table("events").not_found(&namespace),
            AppError::NoSuchTable(_)
        ));
        assert!(matches!(
            Target::View("summary").not_found(&namespace),
            AppError::NoSuchView(_)
        ));
    }

    #[test]
    fn not_found_names_the_full_path() {
        let namespace = ns(&["analytics", "web"]);
        let err = Target::Table("events").not_found(&namespace);
        assert_eq!(
            err.to_string(),
            "Table does not exist: analytics.web.events"
        );
    }

    #[test]
    fn resource_carries_the_recorded_owner_not_the_caller() {
        let namespace = ns(&["analytics"]);
        let resource = Target::Table("events").resource("acme", &namespace);

        assert_eq!(resource.tenant_id, "acme");
        assert_eq!(resource.resource_type, ResourceType::Table);
        assert_eq!(resource.name.as_deref(), Some("events"));
        assert_eq!(
            resource.namespace.as_deref(),
            Some(&["analytics".to_string()][..])
        );
    }

    #[test]
    fn view_target_builds_a_view_resource() {
        // A view authorized as a table would be matched by table-scoped policies,
        // which is a silent widening.
        let resource = Target::View("summary").resource("acme", &ns(&["analytics"]));
        assert_eq!(resource.resource_type, ResourceType::View);
    }

    #[test]
    fn describe_is_readable() {
        let namespace = ns(&["analytics", "web"]);
        assert_eq!(
            describe(&Target::Table("events"), &namespace),
            "table 'analytics.web.events'"
        );
        assert_eq!(
            describe(&Target::Namespace, &namespace),
            "namespace 'analytics.web'"
        );
    }
}
