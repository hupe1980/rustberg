use axum::{
    extract::{Query, State},
    response::Json as AxumJson,
};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

#[derive(Debug, Deserialize)]
pub struct ConfigQuery {
    pub warehouse: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Overrides {
    pub warehouse: String,
}

#[derive(Debug, Serialize)]
pub struct Defaults {
    pub clients: String,
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub overrides: Overrides,
    pub defaults: Defaults,
    pub endpoints: Vec<String>,
}

pub async fn get_config(
    State(state): State<AppState>,
    Query(query): Query<ConfigQuery>,
) -> AxumJson<ConfigResponse> {
    // Check if the `warehouse` query parameter is provided
    let warehouse_uri = query
        .warehouse
        .or(Some(state.warehouse_location)) // Use the provided warehouse or fallback to catalog's warehouse
        .unwrap_or_else(|| "file:///default-warehouse/".to_string()); // Default value

    AxumJson(ConfigResponse {
        overrides: Overrides {
            warehouse: warehouse_uri,
        },
        defaults: Defaults {
            clients: "4".to_string(),
        },
        endpoints: vec![
            // Config
            "GET /v1/config".to_string(),
            // Search
            "GET /v1/search".to_string(),
            // Namespace routes
            "GET /v1/namespaces".to_string(),
            "POST /v1/namespaces".to_string(),
            "GET /v1/namespaces/{namespace}".to_string(),
            "HEAD /v1/namespaces/{namespace}".to_string(),
            "DELETE /v1/namespaces/{namespace}".to_string(),
            "POST /v1/namespaces/{namespace}/properties".to_string(),
            // Table routes
            "GET /v1/namespaces/{namespace}/tables".to_string(),
            "POST /v1/namespaces/{namespace}/tables".to_string(),
            "POST /v1/namespaces/{namespace}/register".to_string(),
            "GET /v1/namespaces/{namespace}/tables/{table}".to_string(),
            "POST /v1/namespaces/{namespace}/tables/{table}".to_string(),
            "HEAD /v1/namespaces/{namespace}/tables/{table}".to_string(),
            "DELETE /v1/namespaces/{namespace}/tables/{table}".to_string(),
            "GET /v1/namespaces/{namespace}/tables/{table}/credentials".to_string(),
            "POST /v1/namespaces/{namespace}/tables/{table}/metrics".to_string(),
            "POST /v1/tables/rename".to_string(),
            // View routes
            "GET /v1/namespaces/{namespace}/views".to_string(),
            "POST /v1/namespaces/{namespace}/views".to_string(),
            "GET /v1/namespaces/{namespace}/views/{view}".to_string(),
            "POST /v1/namespaces/{namespace}/views/{view}".to_string(),
            "HEAD /v1/namespaces/{namespace}/views/{view}".to_string(),
            "DELETE /v1/namespaces/{namespace}/views/{view}".to_string(),
            "POST /v1/views/rename".to_string(),
            // Transaction routes
            "POST /v1/transactions/commit".to_string(),
            // Auth routes
            "GET /v1/auth/context".to_string(),
            // Observability routes
            "GET /health".to_string(),
            "GET /ready".to_string(),
            "GET /metrics".to_string(),
        ],
    })
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ConfigQuery Tests
    // ========================================================================

    #[test]
    fn test_config_query_empty() {
        let json = "{}";
        let query: ConfigQuery = serde_json::from_str(json).unwrap();
        assert!(query.warehouse.is_none());
    }

    #[test]
    fn test_config_query_with_warehouse() {
        let json = r#"{"warehouse": "s3://my-bucket/warehouse"}"#;
        let query: ConfigQuery = serde_json::from_str(json).unwrap();
        assert_eq!(
            query.warehouse,
            Some("s3://my-bucket/warehouse".to_string())
        );
    }

    // ========================================================================
    // Overrides Tests
    // ========================================================================

    #[test]
    fn test_overrides_serialization() {
        let overrides = Overrides {
            warehouse: "s3://bucket/path".to_string(),
        };
        let json = serde_json::to_value(&overrides).unwrap();
        assert_eq!(json["warehouse"], "s3://bucket/path");
    }

    // ========================================================================
    // Defaults Tests
    // ========================================================================

    #[test]
    fn test_defaults_serialization() {
        let defaults = Defaults {
            clients: "8".to_string(),
        };
        let json = serde_json::to_value(&defaults).unwrap();
        assert_eq!(json["clients"], "8");
    }

    // ========================================================================
    // ConfigResponse Tests
    // ========================================================================

    #[test]
    fn test_config_response_serialization() {
        let response = ConfigResponse {
            overrides: Overrides {
                warehouse: "/tmp/warehouse".to_string(),
            },
            defaults: Defaults {
                clients: "4".to_string(),
            },
            endpoints: vec![
                "GET /v1/namespaces".to_string(),
                "POST /v1/namespaces".to_string(),
            ],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["overrides"]["warehouse"], "/tmp/warehouse");
        assert_eq!(json["defaults"]["clients"], "4");
        assert_eq!(json["endpoints"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_config_response_full_endpoints() {
        // Verify the full endpoint list covers the expected categories
        let response = ConfigResponse {
            overrides: Overrides {
                warehouse: "test".to_string(),
            },
            defaults: Defaults {
                clients: "4".to_string(),
            },
            endpoints: vec![
                "GET /v1/config".to_string(),
                "GET /v1/search".to_string(),
                "GET /v1/namespaces".to_string(),
                "POST /v1/namespaces".to_string(),
                "GET /v1/namespaces/{namespace}".to_string(),
                "HEAD /v1/namespaces/{namespace}".to_string(),
                "DELETE /v1/namespaces/{namespace}".to_string(),
                "POST /v1/namespaces/{namespace}/properties".to_string(),
                "GET /v1/namespaces/{namespace}/tables".to_string(),
                "POST /v1/namespaces/{namespace}/tables".to_string(),
                "POST /v1/namespaces/{namespace}/register".to_string(),
                "GET /v1/namespaces/{namespace}/tables/{table}".to_string(),
                "POST /v1/namespaces/{namespace}/tables/{table}".to_string(),
                "HEAD /v1/namespaces/{namespace}/tables/{table}".to_string(),
                "DELETE /v1/namespaces/{namespace}/tables/{table}".to_string(),
                "GET /v1/namespaces/{namespace}/tables/{table}/credentials".to_string(),
                "POST /v1/namespaces/{namespace}/tables/{table}/metrics".to_string(),
                "POST /v1/tables/rename".to_string(),
                "GET /v1/namespaces/{namespace}/views".to_string(),
                "POST /v1/namespaces/{namespace}/views".to_string(),
                "GET /v1/namespaces/{namespace}/views/{view}".to_string(),
                "POST /v1/namespaces/{namespace}/views/{view}".to_string(),
                "HEAD /v1/namespaces/{namespace}/views/{view}".to_string(),
                "DELETE /v1/namespaces/{namespace}/views/{view}".to_string(),
                "POST /v1/views/rename".to_string(),
                "POST /v1/transactions/commit".to_string(),
                "GET /v1/auth/context".to_string(),
                "GET /health".to_string(),
                "GET /ready".to_string(),
                "GET /metrics".to_string(),
            ],
        };
        let json = serde_json::to_value(&response).unwrap();
        let endpoints = json["endpoints"].as_array().unwrap();

        // Verify completeness: config, search, 6 namespace, 10 table, 7 view, 1 transaction, 1 auth, 3 observability = 30
        assert_eq!(endpoints.len(), 30);

        // Spot-check a few key endpoints
        let strs: Vec<&str> = endpoints.iter().map(|e| e.as_str().unwrap()).collect();
        assert!(strs.contains(&"GET /v1/config"));
        assert!(strs.contains(&"GET /v1/search"));
        assert!(strs.contains(&"POST /v1/transactions/commit"));
        assert!(strs.contains(&"GET /v1/auth/context"));
        assert!(strs.contains(&"POST /v1/views/rename"));
        assert!(strs.contains(&"GET /health"));
    }

    #[test]
    fn test_config_response_endpoints_format() {
        let response = ConfigResponse {
            overrides: Overrides {
                warehouse: "test".to_string(),
            },
            defaults: Defaults {
                clients: "4".to_string(),
            },
            endpoints: vec![
                "GET /v1/namespaces".to_string(),
                "HEAD /v1/namespaces/{namespace}".to_string(),
            ],
        };
        let json = serde_json::to_value(&response).unwrap();
        let endpoints = json["endpoints"].as_array().unwrap();
        // Verify endpoints have correct format (METHOD path)
        assert!(endpoints[0].as_str().unwrap().starts_with("GET "));
        assert!(endpoints[1].as_str().unwrap().starts_with("HEAD "));
    }
}
