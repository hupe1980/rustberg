use axum::{
    extract::{Query, State},
    response::Json as AxumJson,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::app::AppState;

/// Endpoints this server implements, in the form the spec requires:
/// `<HTTP verb> <resource path from the OpenAPI spec>`.
///
/// Clients feature-detect from this list, so the paths must match the spec
/// exactly — including the `{prefix}` segment. Non-spec routes (health, metrics)
/// are deliberately absent: this list describes the catalog API, and advertising
/// paths a client cannot interpret only invites confusion.
/// Endpoints that only exist when a capability is present.
///
/// Advertising is the **intersection** across mounts, not the union: `endpoints`
/// is one list describing one catalog, a client feature-detects from it once,
/// and an entry that fails on some namespaces is worse than an absent one. The
/// operation is still reachable on the mounts that support it — what the
/// intersection governs is only what is promised.
fn endpoints_for(capabilities: &crate::catalog::Capabilities, signing: bool) -> Vec<String> {
    let mut endpoints: Vec<String> = SUPPORTED_ENDPOINTS.iter().map(|s| s.to_string()).collect();

    if signing {
        endpoints.push(SIGN_ENDPOINT.to_string());
    }

    if !capabilities.write {
        endpoints.retain(|e| !is_mutating(e));
    }
    if !capabilities.views {
        endpoints.retain(|e| !e.contains("/views") && !e.contains("register-view"));
    }
    if !capabilities.multi_table_commit {
        endpoints.retain(|e| !e.ends_with("/transactions/commit"));
    }
    if !capabilities.register {
        endpoints.retain(|e| !e.ends_with("/register") && !e.ends_with("register-view"));
    }
    if !capabilities.scan_planning {
        endpoints.retain(|e| !e.contains("/plan"));
    }

    endpoints
}

/// Whether an endpoint changes catalog state.
///
fn is_mutating(endpoint: &str) -> bool {
    // Two `POST`s and one `DELETE` change nothing in the catalog: reporting scan
    // telemetry, planning a scan, and cancelling a plan. All three work on a
    // read-only mount, so classifying by verb would under-advertise them — an
    // advertisement is a lie when it under-reports as much as when it
    // over-reports.
    if endpoint.ends_with("/metrics") || endpoint.contains("/plan") {
        return false;
    }
    endpoint.starts_with("POST ") || endpoint.starts_with("DELETE ")
}

/// Advertised only where remote signing is configured. Unlike the capability
/// gates below this is a property of the deployment rather than of a mount, so
/// it is added rather than removed.
const SIGN_ENDPOINT: &str = "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/sign";

const SUPPORTED_ENDPOINTS: &[&str] = &[
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}",
    "HEAD /v1/{prefix}/namespaces/{namespace}",
    "DELETE /v1/{prefix}/namespaces/{namespace}",
    "POST /v1/{prefix}/namespaces/{namespace}/properties",
    "GET /v1/{prefix}/namespaces/{namespace}/tables",
    "POST /v1/{prefix}/namespaces/{namespace}/tables",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}/credentials",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan/{plan-id}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan/{plan-id}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/metrics",
    "POST /v1/{prefix}/namespaces/{namespace}/register",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/unregister",
    "POST /v1/{prefix}/tables/rename",
    "POST /v1/{prefix}/transactions/commit",
    "GET /v1/{prefix}/namespaces/{namespace}/views",
    "POST /v1/{prefix}/namespaces/{namespace}/views",
    "GET /v1/{prefix}/namespaces/{namespace}/views/{view}",
    "POST /v1/{prefix}/namespaces/{namespace}/views/{view}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/views/{view}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/views/{view}",
    "POST /v1/{prefix}/views/rename",
    "POST /v1/{prefix}/namespaces/{namespace}/register-view",
];

/// Formats a duration as the ISO-8601 form the spec's `idempotency-key-lifetime`
/// field takes.
///
/// Derived from the live cache TTL rather than written down as a constant. It
/// was a constant `"PT24H"`, which was true only for the default: a deployment
/// that shortened the TTL still advertised twenty-four hours, and a client
/// trusting that advertisement would replay a key the cache had already
/// dropped — the retry then executing a second time, which is the one thing an
/// idempotency key exists to prevent.
///
/// Whole hours, minutes and seconds are emitted separately so the common values
/// read naturally (`PT24H`, not `PT86400S`). Sub-second precision is dropped:
/// the field describes a reuse window measured in hours, and a fractional
/// second in it would be noise.
fn iso8601_duration(ttl: std::time::Duration) -> String {
    let total = ttl.as_secs();
    if total == 0 {
        return "PT0S".to_string();
    }

    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    let mut out = String::from("PT");
    if hours > 0 {
        out.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 {
        out.push_str(&format!("{seconds}S"));
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct ConfigQuery {
    /// Selects a warehouse. Rustberg serves a single warehouse, so a request
    /// naming a different one is rejected rather than silently served.
    pub warehouse: Option<String>,
}

/// Catalog configuration, per the Iceberg REST spec.
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    /// Applied *after* client configuration, so these win.
    pub overrides: HashMap<String, String>,
    /// Applied *before* client configuration, so a client may override these.
    pub defaults: HashMap<String, String>,
    /// Endpoints this server supports.
    pub endpoints: Vec<String>,
    /// Reuse window for `Idempotency-Key`.
    #[serde(rename = "idempotency-key-lifetime")]
    pub idempotency_key_lifetime: String,
}

/// `GET /v1/config`
///
/// The first call a client makes. Its `endpoints` list is how clients discover
/// which operations exist, so it must describe this server truthfully.
pub async fn get_config(
    State(state): State<AppState>,
    Query(query): Query<ConfigQuery>,
) -> crate::error::Result<AxumJson<ConfigResponse>> {
    // A client asking for a warehouse this server does not serve is told so.
    // Echoing the requested value back as an override would report acceptance
    // while every table was in fact created somewhere else.
    if let Some(requested) = query.warehouse.as_deref()
        && requested != state.default_warehouse.advertised()
    {
        return Err(crate::error::AppError::BadRequest(format!(
            "Unknown warehouse '{requested}'. This server serves exactly one warehouse, \
                 '{}'. Either set the client's `warehouse` to that value, or leave it unset \
                 and take it from `overrides.warehouse` in this response.",
            state.default_warehouse.advertised()
        )));
    }

    let mut overrides = HashMap::new();
    // This server's own warehouse, deliberately — not `warehouse_for`. The
    // override names the catalog a client is talking to, and there is no
    // namespace in scope to resolve a mount's warehouse from. A federated
    // deployment's mounts each have their own; `overrides.warehouse` is the
    // default, not a claim that everything lives there.
    overrides.insert(
        "warehouse".to_string(),
        state.default_warehouse.advertised().to_string(),
    );

    // Where to obtain a token, when the deployment uses OIDC. The spec's
    // recommended replacement for the deprecated `oauth/tokens` endpoint, which
    // Rustberg deliberately does not implement.
    if let Some(uri) = state.oauth2_server_uri.as_deref() {
        overrides.insert("oauth2-server-uri".to_string(), uri.to_string());
    }

    Ok(AxumJson(ConfigResponse {
        overrides,
        // No defaults are sent. The spec's illustrative `clients: "4"` means
        // nothing to any client, and echoing it would be noise.
        defaults: HashMap::new(),
        endpoints: endpoints_for(&state.capabilities, state.signing.enabled),
        idempotency_key_lifetime: iso8601_duration(state.idempotency_cache.ttl()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_query_parses_warehouse() {
        let q: ConfigQuery = serde_json::from_str(r#"{"warehouse": "s3://b/wh"}"#).unwrap();
        assert_eq!(q.warehouse.as_deref(), Some("s3://b/wh"));

        let q: ConfigQuery = serde_json::from_str("{}").unwrap();
        assert!(q.warehouse.is_none());
    }

    fn response() -> ConfigResponse {
        ConfigResponse {
            overrides: HashMap::from([("warehouse".to_string(), "s3://b/wh".to_string())]),
            defaults: HashMap::new(),
            endpoints: SUPPORTED_ENDPOINTS.iter().map(|s| s.to_string()).collect(),
            idempotency_key_lifetime: iso8601_duration(crate::catalog::DEFAULT_TTL),
        }
    }

    #[test]
    fn serializes_spec_shape() {
        let json = serde_json::to_value(response()).unwrap();
        assert_eq!(json["overrides"]["warehouse"], "s3://b/wh");
        assert_eq!(json["idempotency-key-lifetime"], "PT24H");
        assert!(json["endpoints"].as_array().unwrap().len() > 20);
    }

    /// The spec's illustrative `clients: "4"` means nothing to any client, so
    /// `defaults` stays empty.
    #[test]
    fn sends_no_meaningless_defaults() {
        let json = serde_json::to_value(response()).unwrap();
        assert!(json["defaults"].as_object().unwrap().is_empty());
        assert!(!json.to_string().contains("clients"));
    }

    /// Signing is advertised only where it is configured, because an endpoint a
    /// client feature-detects and then gets `501` from is worse than an absent
    /// one.
    #[test]
    fn signing_is_advertised_only_when_configured() {
        let off = endpoints_for(&crate::catalog::Capabilities::full(), false);
        assert!(!off.iter().any(|e| e.ends_with("/sign")));

        let on = endpoints_for(&crate::catalog::Capabilities::full(), true);
        assert!(on.iter().any(|e| e.ends_with("/sign")));
    }

    /// Clients feature-detect from this list, so every entry must be a real
    /// spec path — which means carrying the `{prefix}` segment.
    #[test]
    fn every_endpoint_is_spec_shaped() {
        for ep in SUPPORTED_ENDPOINTS
            .iter()
            .chain(std::iter::once(&SIGN_ENDPOINT))
        {
            let (verb, path) = ep.split_once(' ').expect("`<VERB> <path>`");
            assert!(
                ["GET", "POST", "DELETE", "HEAD", "PUT"].contains(&verb),
                "bad verb in {ep}"
            );
            assert!(
                path.starts_with("/v1/{prefix}/"),
                "endpoint must be a spec path with {{prefix}}: {ep}"
            );
        }
    }

    /// The default TTL must still read as it always did.
    #[test]
    fn the_default_ttl_formats_as_pt24h() {
        assert_eq!(iso8601_duration(crate::catalog::DEFAULT_TTL), "PT24H");
    }

    /// A constant here would advertise twenty-four hours to a deployment that
    /// shortened the TTL, and the client would replay a key already dropped.
    #[test]
    fn a_shortened_ttl_is_advertised_as_shortened() {
        assert_eq!(
            iso8601_duration(std::time::Duration::from_secs(3600)),
            "PT1H"
        );
        assert_eq!(
            iso8601_duration(std::time::Duration::from_secs(300)),
            "PT5M"
        );
        assert_eq!(
            iso8601_duration(std::time::Duration::from_secs(90)),
            "PT1M30S"
        );
    }

    #[test]
    fn a_mixed_duration_names_every_component() {
        // 25h 1m 5s
        assert_eq!(
            iso8601_duration(std::time::Duration::from_secs(90_065)),
            "PT25H1M5S"
        );
    }

    #[test]
    fn a_zero_ttl_is_still_well_formed() {
        assert_eq!(iso8601_duration(std::time::Duration::ZERO), "PT0S");
    }

    /// Sub-second precision is noise in a reuse window measured in hours.
    #[test]
    fn sub_second_precision_is_dropped() {
        assert_eq!(
            iso8601_duration(std::time::Duration::from_millis(1500)),
            "PT1S"
        );
    }

    /// With no mounts, or with mounts that all support everything, the full
    /// list is advertised.
    #[test]
    fn full_capabilities_advertise_every_endpoint() {
        let endpoints = endpoints_for(&crate::catalog::Capabilities::full(), false);
        assert_eq!(endpoints.len(), SUPPORTED_ENDPOINTS.len());
    }

    /// One read-only mount removes every mutating endpoint from what the
    /// catalog promises, because the list cannot say "except over there".
    #[test]
    fn a_read_only_catalog_advertises_no_mutations() {
        let endpoints = endpoints_for(&crate::catalog::Capabilities::read_only(), false);

        assert!(!endpoints.is_empty(), "reads are still advertised");
        for endpoint in &endpoints {
            assert!(
                endpoint.starts_with("GET ")
                    || endpoint.starts_with("HEAD ")
                    || endpoint.ends_with("/metrics"),
                "a read-only catalog must advertise no mutation: {endpoint}"
            );
        }
    }

    /// Telemetry reporting writes nothing to the catalog, so a read-only mount
    /// serves it. Dropping it because the verb is `POST` under-advertises an
    /// endpoint that works everywhere, which is a lie in the other direction.
    #[test]
    fn a_read_only_catalog_still_advertises_metrics_reporting() {
        let endpoints = endpoints_for(&crate::catalog::Capabilities::read_only(), false);
        assert!(endpoints.iter().any(|e| e.ends_with("/metrics")));
    }

    #[test]
    fn losing_views_removes_only_view_endpoints() {
        let capabilities = crate::catalog::Capabilities {
            views: false,
            ..crate::catalog::Capabilities::full()
        };
        let endpoints = endpoints_for(&capabilities, false);

        assert!(endpoints.iter().all(|e| !e.contains("/views")));
        assert!(
            endpoints
                .iter()
                .any(|e| e.contains("/tables") && e.starts_with("POST ")),
            "table writes are unaffected"
        );
    }

    #[test]
    fn losing_multi_table_commit_removes_the_transaction_endpoint() {
        let capabilities = crate::catalog::Capabilities {
            multi_table_commit: false,
            ..crate::catalog::Capabilities::full()
        };
        let endpoints = endpoints_for(&capabilities, false);
        assert!(
            endpoints
                .iter()
                .all(|e| !e.ends_with("/transactions/commit"))
        );
        assert!(endpoints.iter().any(|e| e.contains("/tables")));
    }

    #[test]
    fn endpoints_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for ep in SUPPORTED_ENDPOINTS {
            assert!(seen.insert(*ep), "duplicate endpoint: {ep}");
        }
    }
}
