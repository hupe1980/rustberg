//! `POST /management/v1/policies/impact`
//!
//! What a candidate policy set would change, for whom: the consequences a
//! review shows above the text diff — *marketing gains Read on `sales.orders`,
//! cooperative, `email` masked*.
//!
//! # One function, two authorizers
//!
//! Both sides are [`Authorizer::decide`](crate::auth::Authorizer::decide): the
//! authorizer in force, and a candidate built by [`CedarAuthorizer::new`] —
//! exactly what `PUT` would install. Restrictions are what
//! [`restrictions::for_table`](crate::catalog::v1::restrictions::for_table)
//! publishes and grades are what
//! [`enforcement::grade`](crate::catalog::v1::enforcement::grade) computes. No
//! second reading of policy exists here to drift from the first.
//!
//! # What it enumerates, and says it did
//!
//! Principals that exist only in an identity provider cannot be listed, so the
//! subjects come from the two policy texts: every principal a scope names
//! exactly, one member of each group a scope names, and one member of no group.
//! All in the asker's tenant. Tables are the ones the asker may read. The
//! answer names both, and a fixed bound on evaluations cuts — and says so —
//! rather than running unbounded. It is exact for what it lists and a proof for
//! nobody else; the analyser in CI is the proof.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json as AxumJson;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::filter_alignment::Enforcement;
use crate::auth::{
    Action, AuthMethod, AuthenticatedPrincipal, Authorizer, AuthzContext, CedarAuthorizer,
    NamedPrincipals, Principal, PrincipalBuilder, PrincipalType, RequestFacts, Resource,
};
use crate::catalog::PageRequest;
use crate::catalog::v1::guard;
use crate::error::{AppError, Result};

/// Evaluations one review may perform: one per (subject, resource, action),
/// each deciding both sides. Deterministic, so a test can reach it.
pub const MAX_EVALUATIONS: usize = 50_000;

/// Namespaces walked at most, whatever the bound leaves.
const MAX_NAMESPACES: usize = 10_000;

const TABLE_ACTIONS: [Action; 3] = [Action::Read, Action::Update, Action::Delete];
const POLICY_ACTIONS: [Action; 2] = [Action::Read, Action::Manage];

#[derive(Debug, Deserialize)]
pub struct ImpactRequest {
    /// The candidate Cedar text, as `PUT` would take it.
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct ImpactResponse {
    pub checked: Checked,
    pub changes: Vec<Change>,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Checked {
    pub principals: Vec<Subject>,
    pub tables: usize,
    pub evaluations: usize,
    pub truncated: bool,
    pub unchecked_tables: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subject {
    /// `api_key`, `user`, `group` (one member of `roles[0]`), or `anyone`.
    pub kind: &'static str,
    pub id: String,
    pub roles: Vec<String>,
    /// Always the asker's: a review never crosses a tenant.
    pub tenant: String,
}

#[derive(Debug, Serialize)]
pub struct Change {
    pub principal: Subject,
    /// `namespace.table`, or `policy set`.
    pub resource: String,
    pub action: &'static str,
    /// `gains`, `loses`, or `restriction` (still permitted, under different
    /// obligations).
    pub change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Side>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Side>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Side {
    pub grade: &'static str,
    pub header: String,
}

const NOTE: &str = "Exact for the principals and tables listed; not a proof for anyone else.";

/// `POST /management/v1/policies/impact`
///
/// # Errors
///
/// `501` where policy is not administered here; `403` without `Read` on the
/// policy set; `400` for a candidate an install would refuse.
pub async fn impact(
    State(state): State<AppState>,
    AuthenticatedPrincipal(asker): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    crate::catalog::v1::extract::Json(payload): crate::catalog::v1::extract::Json<ImpactRequest>,
) -> Result<AxumJson<ImpactResponse>> {
    let admin = state.policy_admin.as_ref().ok_or_else(|| {
        AppError::NotSupported(
            "Policy administration is not available: this deployment does not evaluate \
             policy. It is enabled whenever authentication is on."
                .to_string(),
        )
    })?;

    guard::authorize_new(
        &state,
        &asker,
        &request,
        Resource::policy_set(asker.tenant_id()),
        Action::Read,
    )
    .await?;

    let candidate = CedarAuthorizer::new(&payload.source).map_err(|e| {
        AppError::BadRequest(format!("The submitted policy set is not usable: {e}"))
    })?;

    // The subjects come from both texts: a rule the candidate removes names
    // somebody who may lose access.
    let in_force_source = match admin.store.get(admin.authorizer.loaded_sequence()).await? {
        Some(revision) => revision.source,
        None => admin
            .store
            .current()
            .await?
            .map(|r| r.source)
            .unwrap_or_default(),
    };
    let mut named = candidate.named_principals();
    if let Ok(in_force) = CedarAuthorizer::new(&in_force_source) {
        merge(&mut named, in_force.named_principals());
    }
    let subjects = subjects(&named, asker.tenant_id());

    let tables = readable_tables(&state, &asker).await?;
    // Counted before anything is evaluated: the policy set's rows first, then
    // as many whole tables as the rest of the bound allows.
    let checked_tables = tables_within_bound(subjects.len(), tables.len(), MAX_EVALUATIONS);

    let mut changes = Vec::new();
    let mut evaluations = 0;

    // The policy set itself: who gains the right to read or change the rules.
    for (subject, principal) in &subjects {
        for action in POLICY_ACTIONS {
            let context = AuthzContext::new(
                principal.clone(),
                Resource::policy_set(asker.tenant_id()),
                action.clone(),
            );
            evaluations += 1;
            if let Some(change) = compare(&*state.authorizer, &candidate, &context).await {
                changes.push(Change {
                    principal: subject.clone(),
                    resource: "policy set".to_string(),
                    action: action_name(&action),
                    change,
                    before: None,
                    after: None,
                });
            }
        }
    }

    // Tables, graded where read access or its restrictions changed.
    let mut loaded = BTreeMap::new();
    for (namespace, name, owner) in tables.iter().take(checked_tables) {
        let display = format!("{}.{name}", namespace.join("."));
        for (subject, principal) in &subjects {
            for action in TABLE_ACTIONS {
                let context = AuthzContext::new(
                    principal.clone(),
                    Resource::table(owner, namespace.to_vec(), name),
                    action.clone(),
                );
                evaluations += 1;
                let before = state.authorizer.decide(&context).await;
                let after = Authorizer::decide(&candidate, &context).await;
                let change = match (before.is_allowed(), after.is_allowed()) {
                    (false, true) => "gains",
                    (true, false) => "loses",
                    (true, true)
                        if action == Action::Read && before.obligations != after.obligations =>
                    {
                        "restriction"
                    }
                    _ => continue,
                };
                let (mut before_side, mut after_side) = (None, None);
                if action == Action::Read {
                    let ident = iceberg::TableIdent::new(namespace.clone(), name.clone());
                    if !loaded.contains_key(&display) {
                        loaded.insert(display.clone(), state.catalog.load_table(&ident).await.ok());
                    }
                    if let Some(Some(table)) = loaded.get(&display) {
                        let snapshot = table.metadata().current_snapshot();
                        if before.is_allowed() {
                            before_side = Some(side(
                                &crate::catalog::v1::enforcement::grade(
                                    table,
                                    snapshot,
                                    &before.obligations,
                                )
                                .await,
                            ));
                        }
                        if after.is_allowed() {
                            after_side = Some(side(
                                &crate::catalog::v1::enforcement::grade(
                                    table,
                                    snapshot,
                                    &after.obligations,
                                )
                                .await,
                            ));
                        }
                    }
                }
                changes.push(Change {
                    principal: subject.clone(),
                    resource: display.clone(),
                    action: action_name(&action),
                    change,
                    before: before_side,
                    after: after_side,
                });
            }
        }
    }

    changes.sort_by(|a, b| {
        (&a.principal, &a.resource, a.action).cmp(&(&b.principal, &b.resource, b.action))
    });

    Ok(AxumJson(ImpactResponse {
        checked: Checked {
            principals: subjects.into_iter().map(|(s, _)| s).collect(),
            tables: checked_tables,
            evaluations,
            truncated: checked_tables < tables.len(),
            unchecked_tables: tables.len() - checked_tables,
        },
        changes,
        note: NOTE,
    }))
}

/// How many whole tables fit in `max` evaluations once the policy set's own
/// rows are counted. A table is checked completely or not at all, so a partial
/// answer never shows half a table's consequences.
fn tables_within_bound(subjects: usize, tables: usize, max: usize) -> usize {
    let per_table = subjects * TABLE_ACTIONS.len();
    let budget = max.saturating_sub(subjects * POLICY_ACTIONS.len());
    tables.min(budget / per_table.max(1))
}

fn merge(into: &mut NamedPrincipals, from: NamedPrincipals) {
    into.users.extend(from.users);
    into.api_keys.extend(from.api_keys);
    into.groups.extend(from.groups);
}

/// The people to check, each built in the asker's tenant.
fn subjects(named: &NamedPrincipals, tenant: &str) -> Vec<(Subject, Principal)> {
    let mut out = Vec::new();
    for id in &named.api_keys {
        out.push((
            Subject {
                kind: "api_key",
                id: id.clone(),
                roles: Vec::new(),
                tenant: tenant.to_string(),
            },
            PrincipalBuilder::new(id, id, PrincipalType::ApiKey, tenant, AuthMethod::ApiKey)
                .build(),
        ));
    }
    for id in &named.users {
        out.push((
            Subject {
                kind: "user",
                id: id.clone(),
                roles: Vec::new(),
                tenant: tenant.to_string(),
            },
            PrincipalBuilder::new(id, id, PrincipalType::User, tenant, AuthMethod::Bearer).build(),
        ));
    }
    for group in &named.groups {
        let id = format!("member of {group}");
        out.push((
            Subject {
                kind: "group",
                id: id.clone(),
                roles: vec![group.clone()],
                tenant: tenant.to_string(),
            },
            PrincipalBuilder::new(&id, &id, PrincipalType::User, tenant, AuthMethod::Bearer)
                .with_role(group)
                .build(),
        ));
    }
    out.push((
        Subject {
            kind: "anyone",
            id: "anyone".to_string(),
            roles: Vec::new(),
            tenant: tenant.to_string(),
        },
        PrincipalBuilder::new(
            "anyone",
            "anyone",
            PrincipalType::User,
            tenant,
            AuthMethod::Bearer,
        )
        .build(),
    ));
    out
}

/// Every table the asker may read, with its namespace's owner. Asked with
/// `permits`, which records nothing: the asker's own `Read` on the policy set
/// is the recorded decision, and a row per table would bury it.
async fn readable_tables(
    state: &AppState,
    asker: &Principal,
) -> Result<Vec<(iceberg::NamespaceIdent, String, String)>> {
    let mut out = Vec::new();
    let mut queue: Vec<Option<iceberg::NamespaceIdent>> = vec![None];
    let mut seen = BTreeSet::new();
    while let Some(parent) = queue.pop() {
        if seen.len() >= MAX_NAMESPACES {
            break;
        }
        let mut request = PageRequest::default();
        loop {
            let page = state
                .catalog
                .list_namespaces(parent.as_ref(), &request)
                .await?;
            for entry in &page.entries {
                if seen.insert(entry.item.clone()) {
                    queue.push(Some(entry.item.clone()));
                }
            }
            match page.next {
                Some(next) => request = PageRequest::after(next, request.limit),
                None => break,
            }
        }
        let Some(namespace) = parent else { continue };
        let Some(owner) = guard::resolve_owner(state, &namespace).await? else {
            continue;
        };
        let mut request = PageRequest::default();
        loop {
            let page = state.catalog.list_tables(&namespace, &request).await?;
            for entry in page.entries {
                let name = entry.item.name().to_string();
                let context = AuthzContext::new(
                    asker.clone(),
                    Resource::table(&owner, namespace.to_vec(), &name),
                    Action::Read,
                );
                if state.authorizer.permits(&context).await {
                    out.push((namespace.clone(), name, owner.clone()));
                }
            }
            match page.next {
                Some(next) => request = PageRequest::after(next, request.limit),
                None => break,
            }
        }
    }
    out.sort();
    Ok(out)
}

async fn compare(
    before: &dyn Authorizer,
    after: &CedarAuthorizer,
    context: &AuthzContext,
) -> Option<&'static str> {
    match (
        before.decide(context).await.is_allowed(),
        Authorizer::decide(after, context).await.is_allowed(),
    ) {
        (false, true) => Some("gains"),
        (true, false) => Some("loses"),
        _ => None,
    }
}

fn side(grade: &Enforcement) -> Side {
    Side {
        grade: grade.grade(),
        header: grade.header_value(),
    }
}

fn action_name(action: &Action) -> &'static str {
    action.cedar_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound cuts whole tables, and never exceeds the evaluations it
    /// promises.
    #[test]
    fn a_bound_cuts_and_says_so() {
        let (subjects, tables) = (10, 10_000);
        let checked = tables_within_bound(subjects, tables, MAX_EVALUATIONS);
        assert!(checked < tables, "a large catalog is cut");
        let evaluations =
            subjects * POLICY_ACTIONS.len() + checked * subjects * TABLE_ACTIONS.len();
        assert!(evaluations <= MAX_EVALUATIONS, "{evaluations}");
        assert!(
            evaluations + subjects * TABLE_ACTIONS.len() > MAX_EVALUATIONS,
            "and it uses the bound rather than stopping early"
        );
        assert_eq!(
            tables_within_bound(3, 40, MAX_EVALUATIONS),
            40,
            "a small catalog is whole"
        );
    }
}

// ============================================================================
// The same loop, read by table
// ============================================================================

/// One enumerated principal's access to one table.
#[derive(Debug, Serialize)]
pub struct AccessRow {
    pub principal: Subject,
    /// `everything`, `filtered`, `masked`, `filtered-and-masked`, or `nothing`.
    pub access: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<Side>,
    #[serde(rename = "matched-policies")]
    pub matched_policies: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AccessResponse {
    pub table: String,
    pub rows: Vec<AccessRow>,
    pub note: &'static str,
}

/// `GET /management/v1/namespaces/{namespace}/tables/{table}/access`
///
/// Who of the principals the rules name may read this table, and in what form
/// — the question a compliance reviewer asks of one table. Same permissions as
/// the what-if: `Read` on the policy set and on the table.
///
/// # Errors
///
/// As [`super::explain::explain`].
pub async fn access(
    State(state): State<AppState>,
    AuthenticatedPrincipal(asker): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    crate::catalog::v1::extract::TablePath(table): crate::catalog::v1::extract::TablePath,
) -> Result<AxumJson<AccessResponse>> {
    let admin = state.policy_admin.as_ref().ok_or_else(|| {
        AppError::NotSupported("Policy administration is not available here.".to_string())
    })?;
    guard::authorize_new(
        &state,
        &asker,
        &request,
        Resource::policy_set(asker.tenant_id()),
        Action::Read,
    )
    .await?;
    let name = table.name().to_string();
    let authorized = guard::authorize(
        &state,
        &asker,
        &request,
        table.namespace(),
        guard::Target::Table(&name),
        Action::Read,
    )
    .await?;

    let source = match admin.store.get(admin.authorizer.loaded_sequence()).await? {
        Some(revision) => revision.source,
        None => admin
            .store
            .current()
            .await?
            .map(|r| r.source)
            .unwrap_or_default(),
    };
    let named = CedarAuthorizer::new(&source)
        .map(|a| a.named_principals())
        .unwrap_or_default();
    let loaded = state.catalog.load_table(&table).await?;
    let snapshot = loaded.metadata().current_snapshot();

    let mut rows = Vec::new();
    for (subject, principal) in subjects(&named, asker.tenant_id()) {
        let outcome = authorized.what_if(&state, principal).await;
        let (access, grade) = if !outcome.is_allowed() {
            ("nothing", None)
        } else {
            let filtered = !outcome.obligations.row_filters.is_empty();
            let masked = !outcome.obligations.column_masks.is_empty();
            let access = match (filtered, masked) {
                (false, false) => "everything",
                (true, false) => "filtered",
                (false, true) => "masked",
                (true, true) => "filtered-and-masked",
            };
            let grade =
                crate::catalog::v1::enforcement::grade(&loaded, snapshot, &outcome.obligations)
                    .await;
            (access, Some(side(&grade)))
        };
        rows.push(AccessRow {
            principal: subject,
            access,
            grade,
            matched_policies: outcome.matched_policies,
        });
    }

    Ok(AxumJson(AccessResponse {
        table: table.to_string(),
        rows,
        note: "For the principals the rules in force name; not a proof for anyone else.",
    }))
}
