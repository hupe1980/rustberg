//! Reading and changing the policy set over HTTP.
//!
//! # Why this is not under `/v1`
//!
//! `/v1` is the Iceberg REST API, and `GET /v1/config` advertises exactly what
//! lives there so clients can feature-detect. Administering Rustberg is not part
//! of that contract, and putting it there would either pollute the endpoint list
//! with paths no Iceberg client can interpret, or leave undocumented routes
//! sitting inside a namespace that claims to be fully described. So it lives
//! under `/management/v1`, where it is unambiguously Rustberg's own surface.
//!
//! # The four operations
//!
//! | | |
//! |---|---|
//! | `GET /management/v1/policies` | The policy set in force |
//! | `PUT /management/v1/policies` | Replace it, as a new revision |
//! | `GET /management/v1/policies/history` | Who changed it, and when |
//! | `POST /management/v1/policies/rollback` | Re-apply an earlier revision |
//!
//! Rollback **appends** rather than rewinding: the log records that a rollback
//! happened, at a new sequence, carrying the old content hash. Deleting
//! revisions would make an old audit record's `policy_set_version` name
//! something that no longer exists.
//!
//! # Changing policy is authorized by policy
//!
//! `Manage` on the tenant's [`Resource::policy_set`], evaluated by the policy
//! set that is currently in force. The model is deliberately circular and that
//! is the point: whoever can write policy can grant themselves anything, so
//! "may you change the rules" has to be one of the rules. The circle is broken
//! at startup by a bootstrap administrator supplied out of band.

use axum::{
    extract::{Query, State},
    response::Json as AxumJson,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::policy_store::{PolicyRevision, PolicyRevisionSummary};
use crate::auth::{
    Action, AuthenticatedPrincipal, CedarAuthorizer, Principal, RequestFacts, Resource,
};
use crate::catalog::v1::guard;
use crate::error::{AppError, Result};

/// Most revisions one history request may return.
const MAX_HISTORY: usize = 200;

/// Default history page size.
const DEFAULT_HISTORY: usize = 50;

/// The policy set in force, with its provenance.
///
/// "In force" means *on the replica that answered*, which is not always the
/// newest revision in the store: replicas converge by polling, so during a
/// rolling change one may still be enforcing the previous set. Reporting the
/// store's latest instead would answer a question nobody asked — an operator
/// checking a pod wants to know what that pod does — and would make a replica
/// that had stopped converging indistinguishable from one that had.
///
/// [`latest_sequence`](Self::latest_sequence) exposes the difference.
#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    /// Monotonic revision number.
    pub sequence: u64,
    /// Content hash; the same string audit records carry.
    pub version: String,
    /// The Cedar policy text.
    pub source: String,
    /// Principal that wrote this revision.
    pub author: String,
    /// When it was written, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Why it was written, when the author said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Newest revision recorded in the store.
    ///
    /// Equal to `sequence` when this replica is up to date. Higher means it has
    /// not converged yet — ordinarily a second or two after a change, and
    /// indefinitely if it cannot reach the store.
    pub latest_sequence: u64,
}

impl PolicyResponse {
    /// Builds a response for the revision `in_force`, alongside the store's
    /// newest.
    fn new(in_force: PolicyRevision, latest_sequence: u64) -> Self {
        Self {
            sequence: in_force.sequence,
            version: in_force.version,
            source: in_force.source,
            author: in_force.author,
            created_at_ms: in_force.created_at_ms,
            note: in_force.note,
            latest_sequence,
        }
    }
}

/// Request body for replacing the policy set.
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    /// The complete Cedar policy text. This **replaces** the current set;
    /// nothing is merged, because silently unioning a submitted policy with
    /// rules the author did not write is how an authorization system permits
    /// more than its operator believes.
    pub source: String,
    /// Why, for the history listing.
    #[serde(default)]
    pub note: Option<String>,
}

/// Request body for a rollback.
#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    /// The revision to re-apply.
    pub sequence: u64,
    /// Why, for the history listing.
    #[serde(default)]
    pub note: Option<String>,
}

/// Query parameters for the history listing.
#[derive(Debug, Default, Deserialize)]
pub struct HistoryQuery {
    /// Maximum revisions to return; clamped to an internal ceiling so a
    /// caller-supplied limit cannot become an unbounded read.
    pub limit: Option<usize>,
}

/// The history listing.
#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    /// Revisions, newest first.
    pub revisions: Vec<PolicyRevisionSummary>,
}

/// The policy administration surface, when the deployment has one.
///
/// `None` for a deployment whose authorizer does not evaluate policy — the
/// `--no-auth` development mode — where the endpoints answer `501` rather than
/// pretending to administer something that is not consulted.
fn admin(state: &AppState) -> Result<&crate::app::PolicyAdmin> {
    state.policy_admin.as_ref().ok_or_else(|| {
        AppError::NotSupported(
            "Policy administration is not available: this deployment does not evaluate \
             policy. It is enabled whenever authentication is on."
                .to_string(),
        )
    })
}

/// `GET /management/v1/policies`
pub async fn get_policies(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
) -> Result<AxumJson<PolicyResponse>> {
    let admin = admin(&state)?;

    guard::authorize_new(
        &state,
        &principal,
        &request,
        Resource::policy_set(principal.tenant_id()),
        Action::Read,
    )
    .await?;

    let latest = admin.store.current().await?.ok_or_else(|| {
        AppError::Internal(
            "No policy revision is recorded, which should be impossible after startup.".to_string(),
        )
    })?;

    // What *this* replica is enforcing, which during a rolling change is not
    // necessarily the newest. Falling back to the store's latest covers a policy
    // set loaded from a file rather than the store, whose sequence is zero.
    let loaded = admin.authorizer.loaded_sequence();
    let in_force = match admin.store.get(loaded).await? {
        Some(revision) => revision,
        None => latest.clone(),
    };

    Ok(AxumJson(PolicyResponse::new(in_force, latest.sequence)))
}

/// `PUT /management/v1/policies`
pub async fn update_policies(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    crate::catalog::v1::extract::Json(payload): crate::catalog::v1::extract::Json<
        UpdatePolicyRequest,
    >,
) -> Result<AxumJson<PolicyResponse>> {
    // Checked before authorizing so an unadministrable deployment answers `501`
    // rather than `403`: the caller's grant is not the problem.
    admin(&state)?;

    guard::authorize_new(
        &state,
        &principal,
        &request,
        Resource::policy_set(principal.tenant_id()),
        Action::Manage,
    )
    .await?;

    let revision = apply(&state, &principal, &request, payload.source, payload.note).await?;
    // The write just installed it here, so what is in force is what was written.
    let sequence = revision.sequence;
    Ok(AxumJson(PolicyResponse::new(revision, sequence)))
}

/// `POST /management/v1/policies/rollback`
pub async fn rollback_policies(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    crate::catalog::v1::extract::Json(payload): crate::catalog::v1::extract::Json<RollbackRequest>,
) -> Result<AxumJson<PolicyResponse>> {
    let admin = admin(&state)?;

    guard::authorize_new(
        &state,
        &principal,
        &request,
        Resource::policy_set(principal.tenant_id()),
        Action::Manage,
    )
    .await?;

    let target = admin.store.get(payload.sequence).await?.ok_or_else(|| {
        // `NoSuchReference` is the catalog's "you named something that is
        // not there" and maps to 404; a revision number is exactly that.
        AppError::NoSuchReference(format!(
            "No policy revision {}. Use GET /management/v1/policies/history to see \
                 which revisions exist.",
            payload.sequence
        ))
    })?;

    let note = payload
        .note
        .unwrap_or_else(|| format!("Rollback to revision {}", payload.sequence));

    // Appended as a new revision rather than rewinding the log. The history
    // then says a rollback happened *and* what it restored, and no existing
    // `policy_set_version` stops resolving.
    let revision = apply(&state, &principal, &request, target.source, Some(note)).await?;
    let sequence = revision.sequence;
    Ok(AxumJson(PolicyResponse::new(revision, sequence)))
}

/// `GET /management/v1/policies/history`
pub async fn policy_history(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    Query(query): Query<HistoryQuery>,
) -> Result<AxumJson<HistoryResponse>> {
    let admin = admin(&state)?;

    guard::authorize_new(
        &state,
        &principal,
        &request,
        Resource::policy_set(principal.tenant_id()),
        Action::Read,
    )
    .await?;

    let limit = query.limit.unwrap_or(DEFAULT_HISTORY).clamp(1, MAX_HISTORY);
    let revisions = admin.store.history(limit).await?;

    Ok(AxumJson(HistoryResponse { revisions }))
}

/// Validates, records and installs a new policy set.
///
/// The order is deliberate: nothing is written until the candidate is known to
/// be usable, and nothing is installed until it is written. A policy set that
/// was installed but not recorded would vanish on restart while the audit trail
/// claimed it applied.
async fn apply(
    state: &AppState,
    principal: &Principal,
    request: &crate::auth::RequestContext,
    source: String,
    note: Option<String>,
) -> Result<PolicyRevision> {
    let admin = admin(state)?;

    // 1. It must parse and typecheck. A policy that does not validate would be
    //    a rule that silently never matches — for a `permit`, access that
    //    disappears; for a `forbid`, a restriction that quietly does not apply.
    let candidate = CedarAuthorizer::new(&source).map_err(|e| {
        AppError::BadRequest(format!("The submitted policy set is not usable: {e}"))
    })?;

    // 2. The author must still be able to administer policy under the new set.
    //
    //    Without this check the most privileged operation in the system is also
    //    the only one that can make itself unreachable: an operator who submits
    //    a policy set that omits their own `Manage` grant loses the ability to
    //    submit another, and the only way back is a restart against a policy
    //    file. That is a footgun with no upside, so it is refused.
    //
    //    Deliberate lockout is still possible — grant someone else `Manage`
    //    first, or edit the seed file and restart. What is refused is doing it
    //    by accident.
    //    Asked with *this* request's context, not a bare one. A grant may be
    //    conditioned on `context.source_ip` — "policy is administered from
    //    inside the VPC" is an ordinary rule — and a context-free check
    //    evaluates that to false, refusing a policy set whose author can plainly
    //    use it. Carrying the request asks the question that actually matters:
    //    under the new rules, would the call being made right now still be
    //    permitted?
    let self_check = crate::auth::AuthzContext::new(
        principal.clone(),
        Resource::policy_set(principal.tenant_id()),
        Action::Manage,
    )
    .with_request(request.clone());
    if !crate::auth::Authorizer::permits(&candidate, &self_check).await {
        return Err(AppError::BadRequest(
            "Refused: under the submitted policy set you would no longer be permitted to \
             change policy, and could not undo this. Include a rule granting yourself \
             'Manage' on the policy set, or make the change through a different \
             administrator."
                .to_string(),
        ));
    }

    // 3. Recorded before it is installed, so a restart cannot lose it.
    let revision = admin
        .store
        .append(&source, principal.id(), note.as_deref())
        .await?;

    // 4. Audited, and audited *before* the swap so that failing is honest.
    //
    //    The guard already recorded the `Manage` decision, fail-closed like
    //    every mutation. What that record cannot carry is which revision the
    //    decision produced — and without the sequence and the content hash, an
    //    audit record from next month naming a `policy_set_version` cannot be
    //    traced back to who installed it. That is the join the whole trail
    //    depends on, so losing it fails the request rather than the record.
    //
    //    Recording after the swap would make failing a lie: the rules would
    //    already be in force. Here the revision is durable but not enforced,
    //    which is a state `GET /management/v1/policies` already reports — it
    //    names the revision this replica enforces and the store's latest beside
    //    it, and they simply differ.
    let event =
        crate::auth::AuditEvent::decision("Manage", "policy_set", principal.tenant_id(), true)
            .with_principal_id(principal.id())
            .with_tenant_id(principal.tenant_id())
            // Carried like every other record. This is the one an investigation
            // arrives at last — "who installed the rules that permitted that" —
            // so it is the worst one to be unable to join to an address and a
            // request id.
            .with_optional_client_ip(request.source_ip)
            .with_optional_request_id(request.request_id.as_deref())
            .with_detail("policy_sequence", revision.sequence.to_string())
            .with_detail("policy_version", revision.version.clone());
    state.auditor.record(&event).map_err(|_| {
        AppError::ServiceUnavailable(
            "The audit trail is unavailable, so this policy set was recorded but not put \
             into force. Retry once auditing is working; the revision is already in the \
             history."
                .to_string(),
        )
    })?;

    // 5. Installed. Requests already in flight finish against the previous set.
    admin.authorizer.swap(candidate, revision.sequence);

    tracing::info!(
        sequence = revision.sequence,
        version = %revision.version,
        author = principal.id(),
        "Policy set replaced"
    );

    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_limit_is_clamped_rather_than_trusted() {
        let clamp = |limit: Option<usize>| limit.unwrap_or(DEFAULT_HISTORY).clamp(1, MAX_HISTORY);

        assert_eq!(clamp(None), DEFAULT_HISTORY);
        assert_eq!(clamp(Some(0)), 1);
        assert_eq!(clamp(Some(10_000)), MAX_HISTORY);
        assert_eq!(clamp(Some(10)), 10);
    }

    fn revision(sequence: u64) -> PolicyRevision {
        PolicyRevision {
            sequence,
            version: "abc123".to_string(),
            source: "permit(principal, action, resource);".to_string(),
            author: "alice".to_string(),
            created_at_ms: 1_700_000_000_000,
            note: None,
        }
    }

    #[test]
    fn a_revision_serializes_with_its_provenance() {
        let json = serde_json::to_value(PolicyResponse::new(revision(4), 4)).unwrap();

        assert_eq!(json["sequence"], 4);
        assert_eq!(json["version"], "abc123");
        assert_eq!(json["author"], "alice");
        assert!(json.get("note").is_none(), "an absent note is omitted");
    }

    /// An up-to-date replica reports the same sequence twice, which is how an
    /// operator sees at a glance that it has converged.
    #[test]
    fn an_up_to_date_replica_reports_matching_sequences() {
        let json = serde_json::to_value(PolicyResponse::new(revision(7), 7)).unwrap();
        assert_eq!(json["sequence"], json["latest_sequence"]);
    }

    /// A replica mid-convergence reports what it enforces, and what exists.
    ///
    /// Reporting the store's latest as though it were in force would make a
    /// replica that had stopped converging look identical to one that had.
    #[test]
    fn a_lagging_replica_reports_both_sequences() {
        let json = serde_json::to_value(PolicyResponse::new(revision(5), 9)).unwrap();

        assert_eq!(json["sequence"], 5, "what this replica enforces");
        assert_eq!(json["latest_sequence"], 9, "what the store holds");
    }
}
