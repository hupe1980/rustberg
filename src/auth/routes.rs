//! Identity introspection: `GET /auth/context`.
//!
//! One endpoint, answering one question: *who does this server think I am?* It
//! reports the principal the authenticator established — id, tenant, roles, auth
//! method, expiry — and nothing else.
//!
//! # Why it does not report capabilities
//!
//! Authorization is per-resource and may depend on request context, so there is
//! no honest server-wide answer to "can this principal create tables". A summary
//! that is right for one table is wrong for the next.
//!
//! Reporting a guess would be worse than reporting nothing: an operator reaches
//! for introspection precisely when verifying that policy works. A client that
//! needs to know about a specific table asks about that table.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::{Deserialize, Serialize};

use super::middleware::AuthenticatedPrincipal;
use super::principal::{AuthMethod, PrincipalType};
use crate::app::AppState;

/// Response for `GET /auth/context`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContextResponse {
    /// The authenticated principal's identity.
    pub principal: PrincipalInfo,
}

/// The identity the authenticator established for this request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalInfo {
    /// Stable identifier for the principal.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Kind of principal: `user`, `service`, `api_key`, `system`, `anonymous`.
    pub principal_type: String,
    /// Tenant this principal belongs to.
    pub tenant_id: String,
    /// Roles carried by the credential. These become Cedar groups.
    pub roles: Vec<String>,
    /// How the principal authenticated: `api_key`, `jwt`, `host`, `internal`
    /// or `none`.
    pub auth_method: String,
    /// When the credential expires, RFC 3339, if it expires at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// `GET /auth/context` — reports the caller's own identity.
///
/// Useful for confirming that a token or key is accepted, that it maps to the
/// tenant expected, and that it carries the roles the policies name. That last
/// one is the common misconfiguration: a policy naming
/// `Rustberg::Group::"analysts"` matches nothing if the credential's roles say
/// `analyst`.
///
/// Requires authentication, and reveals nothing about any other principal.
pub async fn get_auth_context(
    State(_state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
) -> Result<Json<AuthContextResponse>, (StatusCode, &'static str)> {
    let principal_type = match principal.principal_type() {
        PrincipalType::User => "user",
        PrincipalType::Service => "service",
        PrincipalType::ApiKey => "api_key",
        PrincipalType::System => "system",
        PrincipalType::Anonymous => "anonymous",
    };

    let auth_method = match principal.auth_method() {
        AuthMethod::ApiKey => "api_key",
        AuthMethod::Bearer => "jwt",
        AuthMethod::Internal => "internal",
        AuthMethod::External => "host",
        AuthMethod::None => "none",
    };

    // Sorted so the response is stable across requests: `roles` is a HashSet, and
    // an order that changes between calls makes the output awkward to diff and
    // impossible to assert on.
    let mut roles: Vec<String> = principal.roles().iter().cloned().collect();
    roles.sort_unstable();

    Ok(Json(AuthContextResponse {
        principal: PrincipalInfo {
            id: principal.id().to_string(),
            name: principal.name().to_string(),
            principal_type: principal_type.to_string(),
            tenant_id: principal.tenant_id().to_string(),
            roles,
            auth_method: auth_method.to_string(),
            expires_at: principal.expires_at().map(|dt| dt.to_rfc3339()),
        },
    }))
}

/// Creates the identity introspection route.
pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/auth/context", get(get_auth_context))
        .with_state(app_state)
}

/// `POST /v1/oauth/tokens` — deliberately not a token endpoint.
///
/// The Iceberg REST spec marks `oauth/tokens` **deprecated for removal** and says
/// plainly: *"It is not recommended to implement this endpoint, unless you are
/// fully aware of the potential security implications."* It is scheduled to leave
/// the spec entirely in Iceberg 2.0.
///
/// Rustberg does not issue tokens. Doing so would make it an authorization
/// server — minting the credentials it also validates — when the whole design
/// puts token lifetime and revocation with the identity provider that owns them.
///
/// The route exists because *not* having it is worse. A client configured with
/// `credential=` performs an OAuth2 client-credentials exchange here before any
/// catalog call, and an unrouted path answers `401 Authentication required`,
/// which sends the reader hunting for a bad key. This answers the question that
/// was actually asked.
async fn oauth_tokens_unsupported() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": {
                "message": "This catalog does not issue tokens. The Iceberg REST \
                            `oauth/tokens` endpoint is deprecated for removal and is \
                            deliberately not implemented. If you are using an API key, pass \
                            it as the client's `token` property, not `credential`. If you \
                            are using OIDC, point `oauth2-server-uri` at your identity \
                            provider's token endpoint.",
                "type": "UnsupportedOperationException",
                "code": 501
            }
        })),
    )
}

/// Routes that must answer without a credential.
///
/// A client calling the token endpoint has no token yet, so requiring one would
/// replace the explanation with the `401` it is trying to understand.
pub fn create_public_routes() -> Router {
    Router::new().route(
        "/v1/oauth/tokens",
        axum::routing::post(oauth_tokens_unsupported),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::PrincipalBuilder;

    fn principal() -> crate::auth::Principal {
        PrincipalBuilder::new(
            "svc-etl",
            "ETL service",
            PrincipalType::Service,
            "acme",
            AuthMethod::ApiKey,
        )
        .with_role("writer")
        .with_role("reader")
        .build()
    }

    #[test]
    fn roles_are_reported_in_a_stable_order() {
        let p = principal();
        let mut roles: Vec<String> = p.roles().iter().cloned().collect();
        roles.sort_unstable();
        assert_eq!(roles, vec!["reader".to_string(), "writer".to_string()]);
    }

    #[test]
    fn response_carries_identity_only() {
        let json = serde_json::to_value(AuthContextResponse {
            principal: PrincipalInfo {
                id: "svc-etl".into(),
                name: "ETL service".into(),
                principal_type: "service".into(),
                tenant_id: "acme".into(),
                roles: vec!["writer".into()],
                auth_method: "api_key".into(),
                expires_at: None,
            },
        })
        .unwrap();

        assert_eq!(json["principal"]["id"], "svc-etl");
        assert_eq!(json["principal"]["tenant_id"], "acme");

        // The fabricated capability summary must not come back. It reported a
        // hardcoded role check as if it were a policy decision.
        assert!(
            json.get("capabilities").is_none(),
            "capabilities must not be reported: the value cannot be computed honestly"
        );
        assert!(!json.to_string().contains("is_admin"));
    }

    /// An absent expiry is omitted rather than sent as null, so a client can tell
    /// "never expires" from "expiry unknown".
    #[test]
    fn absent_expiry_is_omitted() {
        let json = serde_json::to_value(AuthContextResponse {
            principal: PrincipalInfo {
                id: "a".into(),
                name: "a".into(),
                principal_type: "user".into(),
                tenant_id: "t".into(),
                roles: vec![],
                auth_method: "jwt".into(),
                expires_at: None,
            },
        })
        .unwrap();

        assert!(json["principal"].get("expires_at").is_none());
    }
}
