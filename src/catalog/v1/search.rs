//! Search endpoint for discovering catalog content.
//!
//! Provides a unified search interface for finding tables and namespaces
//! across the catalog. This is particularly useful for:
//! - CLI tools discovering available data
//! - Web UIs presenting searchable catalogs
//! - Data governance and discovery workflows
//!
//! # Authorization
//!
//! Search results are filtered based on the authenticated principal's
//! permissions. Users only see objects they have at least `Read` access to.
//!
//! # Example Request
//!
//! ```text
//! GET /v1/search?query=sales&type=table&limit=20
//! ```

use axum::{
    extract::{Query, State},
    response::Json as AxumJson,
};
use iceberg::NamespaceIdent;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::{Action, AuthenticatedPrincipal, AuthzContext, Resource};
use crate::error::Result;

/// Reserved property key for storing namespace owner's tenant ID.
const TENANT_ID_PROPERTY: &str = "_tenant_id";

// ============================================================================
// Search Query Parameters
// ============================================================================

/// Query parameters for search requests.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
    /// Search query string. Matches against names using substring/prefix matching.
    /// If empty, returns all accessible objects (subject to limit).
    #[serde(default)]
    pub query: String,

    /// Filter by object type: "table", "namespace", or "all" (default).
    #[serde(default = "default_object_type")]
    pub object_type: SearchObjectType,

    /// Limit results for tables within each namespace during enumeration.
    /// Default: 100. Max: 1000.
    #[serde(default = "default_limit")]
    pub limit: usize,

    /// Include tables from child namespaces (recursive search).
    /// Default: true.
    #[serde(default = "default_recursive")]
    pub recursive: bool,

    /// Filter to specific namespace (optional).
    /// If provided, only search within this namespace.
    pub namespace: Option<String>,
}

fn default_object_type() -> SearchObjectType {
    SearchObjectType::All
}

fn default_limit() -> usize {
    100
}

fn default_recursive() -> bool {
    true
}

/// Type of object to search for.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SearchObjectType {
    /// Search tables only.
    Table,
    /// Search namespaces only.
    Namespace,
    /// Search all object types (default).
    #[default]
    All,
}

// ============================================================================
// Search Response Types
// ============================================================================

/// Response containing search results.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    /// Search results.
    pub results: Vec<SearchResult>,
    /// Total count of results (before limit applied).
    pub total_count: usize,
    /// Whether more results exist beyond the limit.
    pub has_more: bool,
}

/// A single search result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    /// Type of the object.
    pub object_type: SearchObjectType,
    /// Fully qualified name (namespace.table or namespace).
    pub qualified_name: String,
    /// Object name (last component).
    pub name: String,
    /// Namespace containing this object (empty for root namespaces).
    pub namespace: Vec<String>,
    /// Brief description from properties (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Last modification time (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ============================================================================
// Search Context and Collector
// ============================================================================

/// Context for search operations.
struct SearchContext<'a> {
    state: &'a AppState,
    tenant_id: &'a str,
    search_term: &'a str,
    recursive: bool,
}

/// Collector for search results with limit tracking.
struct SearchCollector {
    results: Vec<SearchResult>,
    total_count: usize,
    limit: usize,
}

impl SearchCollector {
    fn new(limit: usize) -> Self {
        Self {
            results: Vec::new(),
            total_count: 0,
            limit,
        }
    }

    fn add(&mut self, result: SearchResult) {
        self.total_count += 1;
        if self.results.len() < self.limit {
            self.results.push(result);
        }
    }

    fn remaining_capacity(&self) -> usize {
        self.limit.saturating_sub(self.results.len())
    }
}

// ============================================================================
// Search Endpoint Handler
// ============================================================================

/// Search for tables and namespaces in the catalog.
///
/// # Authorization
///
/// Requires `List` permission on the catalog. Results are filtered to only
/// include objects the principal has `Read` access to.
///
/// # Query Parameters
///
/// - `query`: Search string (substring match on names)
/// - `objectType`: Filter by type ("table", "namespace", "all")
/// - `limit`: Maximum results (default 100, max 1000)
/// - `recursive`: Search child namespaces (default true)
/// - `namespace`: Filter to specific namespace
///
/// # Response
///
/// Returns a list of matching objects with metadata.
pub async fn search(
    State(state): State<AppState>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Query(query): Query<SearchQuery>,
) -> Result<AxumJson<SearchResponse>> {
    // Validate and clamp limit
    let limit = query.limit.clamp(1, 1000);

    // Authorize catalog list access
    let tenant_id = principal.tenant_id().to_string();
    let resource = Resource::catalog(&tenant_id);
    let ctx = AuthzContext::new(principal.clone(), resource, Action::List);
    state.authorizer.check(&ctx).await?;

    // Normalize search query (case-insensitive)
    let search_term = query.query.to_lowercase();

    let mut collector = SearchCollector::new(limit);

    // Determine which namespaces to search
    let namespaces_to_search = if let Some(ref ns_filter) = query.namespace {
        // Search only the specified namespace
        vec![NamespaceIdent::from_strs(
            ns_filter.split('.').collect::<Vec<_>>(),
        )
        .map_err(|e| crate::error::AppError::BadRequest(e.to_string()))?]
    } else {
        // Get all root namespaces
        state.catalog.list_namespaces(None).await?
    };

    let search_ctx = SearchContext {
        state: &state,
        tenant_id: &tenant_id,
        search_term: &search_term,
        recursive: query.recursive,
    };

    // Search namespaces
    if matches!(
        query.object_type,
        SearchObjectType::Namespace | SearchObjectType::All
    ) {
        search_namespaces(&search_ctx, &namespaces_to_search, &mut collector).await;
    }

    // Search tables
    if matches!(
        query.object_type,
        SearchObjectType::Table | SearchObjectType::All
    ) {
        search_tables(&search_ctx, &namespaces_to_search, &mut collector).await;
    }

    // Sort results by qualified name for consistency
    collector.results.sort_by(|a, b| a.qualified_name.cmp(&b.qualified_name));

    let has_more = collector.total_count > limit;
    let final_results: Vec<_> = collector.results.into_iter().take(limit).collect();

    Ok(AxumJson(SearchResponse {
        results: final_results,
        total_count: collector.total_count,
        has_more,
    }))
}

// ============================================================================
// Search Implementation Functions
// ============================================================================

/// Search namespaces matching the query.
async fn search_namespaces(
    ctx: &SearchContext<'_>,
    namespaces: &[NamespaceIdent],
    collector: &mut SearchCollector,
) {
    for namespace in namespaces {
        // Check tenant ownership
        if !is_namespace_accessible(ctx.state, namespace, ctx.tenant_id).await {
            continue;
        }

        let ns_parts = namespace.clone().inner();
        let ns_name = ns_parts.last().map(|s| s.as_str()).unwrap_or("");
        let qualified_name = ns_parts.join(".");

        // Check if namespace matches search term
        let matches = ctx.search_term.is_empty()
            || ns_name.to_lowercase().contains(ctx.search_term)
            || qualified_name.to_lowercase().contains(ctx.search_term);

        if matches {
            // Get description from properties
            let description = ctx
                .state
                .catalog
                .get_namespace(namespace)
                .await
                .ok()
                .and_then(|ns| ns.properties().get("description").cloned());

            collector.add(SearchResult {
                object_type: SearchObjectType::Namespace,
                qualified_name: qualified_name.clone(),
                name: ns_name.to_string(),
                namespace: if ns_parts.len() > 1 {
                    ns_parts[..ns_parts.len() - 1].to_vec()
                } else {
                    vec![]
                },
                description,
                updated_at: None,
            });
        }

        // Recursively search child namespaces
        if ctx.recursive && collector.remaining_capacity() > 0 {
            if let Ok(children) = ctx.state.catalog.list_namespaces(Some(namespace)).await {
                Box::pin(search_namespaces(ctx, &children, collector)).await;
            }
        }
    }
}

/// Search tables matching the query.
async fn search_tables(
    ctx: &SearchContext<'_>,
    namespaces: &[NamespaceIdent],
    collector: &mut SearchCollector,
) {
    for namespace in namespaces {
        // Check tenant ownership
        if !is_namespace_accessible(ctx.state, namespace, ctx.tenant_id).await {
            continue;
        }

        // List tables in this namespace
        if let Ok(tables) = ctx.state.catalog.list_tables(namespace).await {
            for table_ident in tables {
                let table_name = table_ident.name();
                let ns_parts = table_ident.namespace().clone().inner();
                let qualified_name = format!("{}.{}", ns_parts.join("."), table_name);

                // Check if table matches search term
                let matches = ctx.search_term.is_empty()
                    || table_name.to_lowercase().contains(ctx.search_term)
                    || qualified_name.to_lowercase().contains(ctx.search_term);

                if matches {
                    // Optionally load table metadata for description
                    let (description, updated_at) =
                        get_table_metadata(ctx.state, &table_ident).await;

                    collector.add(SearchResult {
                        object_type: SearchObjectType::Table,
                        qualified_name,
                        name: table_name.to_string(),
                        namespace: ns_parts.clone(),
                        description,
                        updated_at,
                    });
                }
            }
        }

        // Recursively search child namespaces
        if ctx.recursive && collector.remaining_capacity() > 0 {
            if let Ok(children) = ctx.state.catalog.list_namespaces(Some(namespace)).await {
                Box::pin(search_tables(ctx, &children, collector)).await;
            }
        }
    }
}

/// Check if a namespace is accessible to the given tenant.
async fn is_namespace_accessible(
    state: &AppState,
    namespace: &NamespaceIdent,
    tenant_id: &str,
) -> bool {
    match state.catalog.get_namespace(namespace).await {
        Ok(ns) => {
            let owner = ns.properties().get(TENANT_ID_PROPERTY).map(|s| s.as_str());
            // Include if: no owner set (legacy) OR owner matches tenant
            owner.is_none() || owner == Some(tenant_id)
        }
        Err(_) => false,
    }
}

/// Get table description and updated timestamp from metadata.
async fn get_table_metadata(
    state: &AppState,
    table_ident: &iceberg::TableIdent,
) -> (Option<String>, Option<String>) {
    // Only fetch if we want rich metadata
    // For performance, we might skip this in large catalogs
    match state.catalog.load_table(table_ident).await {
        Ok(table) => {
            let metadata = table.metadata();

            // Extract description from properties
            let description = metadata.properties().get("comment").cloned();

            // Get last updated timestamp
            let updated_at = metadata.current_snapshot().map(|snap| {
                // Convert snapshot timestamp (millis) to ISO 8601
                chrono::DateTime::from_timestamp_millis(snap.timestamp_ms())
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| format!("{}ms", snap.timestamp_ms()))
            });

            (description, updated_at)
        }
        Err(_) => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_query_defaults() {
        let query: SearchQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.query, "");
        assert_eq!(query.object_type, SearchObjectType::All);
        assert_eq!(query.limit, 100);
        assert!(query.recursive);
        assert!(query.namespace.is_none());
    }

    #[test]
    fn test_search_query_with_params() {
        let query: SearchQuery = serde_json::from_str(
            r#"{
                "query": "sales",
                "objectType": "table",
                "limit": 50,
                "recursive": false,
                "namespace": "production"
            }"#,
        )
        .unwrap();

        assert_eq!(query.query, "sales");
        assert_eq!(query.object_type, SearchObjectType::Table);
        assert_eq!(query.limit, 50);
        assert!(!query.recursive);
        assert_eq!(query.namespace.as_deref(), Some("production"));
    }

    #[test]
    fn test_search_result_serialization() {
        let result = SearchResult {
            object_type: SearchObjectType::Table,
            qualified_name: "production.sales.orders".to_string(),
            name: "orders".to_string(),
            namespace: vec!["production".to_string(), "sales".to_string()],
            description: Some("Order transactions".to_string()),
            updated_at: Some("2025-01-24T10:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"objectType\":\"table\""));
        assert!(json.contains("\"qualifiedName\":\"production.sales.orders\""));
    }

    #[test]
    fn test_search_response_structure() {
        let response = SearchResponse {
            results: vec![SearchResult {
                object_type: SearchObjectType::Namespace,
                qualified_name: "production".to_string(),
                name: "production".to_string(),
                namespace: vec![],
                description: None,
                updated_at: None,
            }],
            total_count: 1,
            has_more: false,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["totalCount"], 1);
        assert_eq!(json["hasMore"], false);
        assert_eq!(json["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_search_collector() {
        let mut collector = SearchCollector::new(2);

        assert_eq!(collector.remaining_capacity(), 2);

        collector.add(SearchResult {
            object_type: SearchObjectType::Table,
            qualified_name: "test.table1".to_string(),
            name: "table1".to_string(),
            namespace: vec!["test".to_string()],
            description: None,
            updated_at: None,
        });

        assert_eq!(collector.total_count, 1);
        assert_eq!(collector.results.len(), 1);
        assert_eq!(collector.remaining_capacity(), 1);

        collector.add(SearchResult {
            object_type: SearchObjectType::Table,
            qualified_name: "test.table2".to_string(),
            name: "table2".to_string(),
            namespace: vec!["test".to_string()],
            description: None,
            updated_at: None,
        });

        assert_eq!(collector.total_count, 2);
        assert_eq!(collector.results.len(), 2);
        assert_eq!(collector.remaining_capacity(), 0);

        // Adding more should increment count but not results
        collector.add(SearchResult {
            object_type: SearchObjectType::Table,
            qualified_name: "test.table3".to_string(),
            name: "table3".to_string(),
            namespace: vec!["test".to_string()],
            description: None,
            updated_at: None,
        });

        assert_eq!(collector.total_count, 3);
        assert_eq!(collector.results.len(), 2); // Still at limit
    }
}
