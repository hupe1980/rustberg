//! `GET /management/v1/namespaces/{namespace}/tables/{table}/explain`
//!
//! What another principal would be granted on a table, before they ever ask:
//! the decision, the policies that made it, the restrictions `loadTable` would
//! publish, how strongly they hold, and what would make them hold against any
//! engine.
//!
//! # Who may ask, and what that reveals
//!
//! The asker is authorized twice: `Read` on the policy set — somebody who may
//! read every rule learns nothing from seeing which ones match — and `Read` on
//! the table, through the same guard `loadTable` uses, so a table the asker may
//! not see answers exactly as loading it would. The subject is always in the
//! asker's own tenant; a what-if never crosses one.
//!
//! # What it cannot know
//!
//! A real request carries a source address; this one does not, and is evaluated
//! at the current UTC hour. A policy conditioned on either is answered for that
//! context, and the response says so.

use axum::Json as AxumJson;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::{Action, Resource};
use crate::auth::{
    AuthMethod, AuthenticatedPrincipal, PrincipalBuilder, PrincipalType, RequestFacts,
};
use crate::catalog::v1::extract::TablePath;
use crate::catalog::v1::guard::{self, Target};
use crate::catalog::v1::restrictions::ReadRestrictions;
use crate::error::{AppError, Result};

/// Who the what-if is about.
#[derive(Debug, Deserialize)]
pub struct ExplainQuery {
    /// The principal's id — a token subject, or an API key's configured name.
    pub principal: String,
    /// `user` (default) or `api_key`. The two are different principals.
    #[serde(default)]
    pub kind: Option<String>,
    /// Comma-separated roles, which become Cedar groups.
    #[serde(default)]
    pub roles: Option<String>,
}

/// The answer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainResponse {
    pub principal: Subject,
    /// `allow` or `deny`.
    pub decision: &'static str,
    /// On allow, the permits that matched; on deny, the forbids that matched —
    /// empty means nothing permitted it and it failed closed.
    pub matched_policies: Vec<String>,
    /// Exactly what `loadTable` would publish to this principal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_restrictions: Option<ReadRestrictions>,
    /// Set when the principal is permitted but `loadTable` would still refuse —
    /// a mask naming a column the table renamed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<Grade>,
    pub context: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_set_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Subject {
    pub id: String,
    pub kind: &'static str,
    pub tenant: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Grade {
    pub grade: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    pub masked: bool,
    /// The `Rustberg-Enforcement` header the principal would receive.
    pub header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

const CONTEXT: &str = "Evaluated at the current UTC hour with no source address.";

/// `GET /management/v1/namespaces/{namespace}/tables/{table}/explain`
///
/// # Errors
///
/// `403` without `Read` on the policy set; the table's own `404`/`403` when the
/// asker may not read it; `400` for an unknown `kind`.
pub async fn explain(
    State(state): State<AppState>,
    AuthenticatedPrincipal(asker): AuthenticatedPrincipal,
    RequestFacts(request): RequestFacts,
    TablePath(table): TablePath,
    Query(query): Query<ExplainQuery>,
) -> Result<AxumJson<ExplainResponse>> {
    guard::authorize_new(
        &state,
        &asker,
        &request,
        Resource::policy_set(asker.tenant_id()),
        Action::Read,
    )
    .await?;

    let namespace = table.namespace().clone();
    let name = table.name().to_string();
    let authorized = guard::authorize(
        &state,
        &asker,
        &request,
        &namespace,
        Target::Table(&name),
        Action::Read,
    )
    .await?;

    let (kind, principal_type, method) = match query.kind.as_deref().unwrap_or("user") {
        "user" => ("user", PrincipalType::User, AuthMethod::Bearer),
        "api_key" => ("api_key", PrincipalType::ApiKey, AuthMethod::ApiKey),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown principal kind '{other}': use 'user' or 'api_key'."
            )));
        }
    };
    let id = query.principal.trim().to_string();
    if id.is_empty() {
        return Err(AppError::BadRequest(
            "Name the principal to explain with ?principal=.".to_string(),
        ));
    }
    let roles: Vec<String> = query
        .roles
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect();

    let subject = PrincipalBuilder::new(&id, &id, principal_type, asker.tenant_id(), method)
        .with_roles(roles.clone())
        .build();
    let outcome = authorized.what_if(&state, subject).await;

    let mut response = ExplainResponse {
        principal: Subject {
            id,
            kind,
            tenant: asker.tenant_id().to_string(),
            roles,
        },
        decision: if outcome.is_allowed() {
            "allow"
        } else {
            "deny"
        },
        matched_policies: outcome.matched_policies.clone(),
        read_restrictions: None,
        refused: None,
        enforcement: None,
        context: CONTEXT,
        policy_set_version: state.authorizer.policy_set_version(),
    };

    if !outcome.is_allowed() {
        return Ok(AxumJson(response));
    }

    let loaded = state.catalog.load_table(&table).await?;
    match crate::catalog::v1::restrictions::for_table(loaded.metadata(), &outcome.obligations) {
        Ok(restrictions) => response.read_restrictions = restrictions,
        Err(error) => {
            response.refused = Some(error.to_string());
            return Ok(AxumJson(response));
        }
    }

    let grade = crate::catalog::v1::enforcement::grade(
        &loaded,
        loaded.metadata().current_snapshot(),
        &outcome.obligations,
    )
    .await;
    let (columns, masked) = match &grade {
        crate::auth::filter_alignment::Enforcement::Cooperative { columns, masked } => {
            (columns.iter().cloned().collect(), *masked)
        }
        _ => (Vec::new(), false),
    };
    response.enforcement = Some(Grade {
        grade: grade.grade(),
        columns,
        masked,
        header: grade.header_value(),
        remedy: grade.remedy(&table.to_string()),
    });

    Ok(AxumJson(response))
}
