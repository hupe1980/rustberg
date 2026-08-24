//! Route definitions for Iceberg REST Catalog v1 API.

use axum::{
    Router,
    routing::{delete, get, head, post},
};

use super::namespace::{
    create_namespace, delete_namespace, get_namespace, list_namespaces, namespace_exists,
    update_namespace_properties,
};
use super::plan::{cancel_planning, fetch_planning_result, fetch_scan_tasks, plan_table_scan};
use super::sign::sign_request;
use super::table::{
    commit_table, commit_transaction, create_table, drop_table, list_tables, load_table,
    load_table_credentials, register_table, rename_table, report_metrics, table_exists,
    unregister_table,
};
use super::view::{
    commit_view, create_view, drop_view, list_views, load_view, register_view, rename_view,
    view_exists,
};
use crate::app::AppState;

/// Creates the v1 API routes.
pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        // ====================================================================
        // Namespace routes
        // ====================================================================
        .route("/namespaces", get(list_namespaces))
        .route("/namespaces", post(create_namespace))
        .route("/namespaces/{namespace}", get(get_namespace))
        .route("/namespaces/{namespace}", head(namespace_exists))
        .route("/namespaces/{namespace}", delete(delete_namespace))
        .route(
            "/namespaces/{namespace}/properties",
            post(update_namespace_properties),
        )
        // ====================================================================
        // Table routes
        // ====================================================================
        .route("/namespaces/{namespace}/tables", get(list_tables))
        .route("/namespaces/{namespace}/tables", post(create_table))
        // Register existing table (from external metadata location)
        .route("/namespaces/{namespace}/register", post(register_table))
        // Release the catalog's pointer without touching the files, so another
        // catalog can adopt the table. Distinct from DELETE, which is one query
        // parameter away from purging the data.
        .route(
            "/namespaces/{namespace}/tables/{table}/unregister",
            post(unregister_table),
        )
        // Note: GET and POST on same path handled by different methods
        // GET = load_table, POST = commit_table (update)
        .route(
            "/namespaces/{namespace}/tables/{table}",
            get(load_table).post(commit_table),
        )
        .route("/namespaces/{namespace}/tables/{table}", head(table_exists))
        .route("/namespaces/{namespace}/tables/{table}", delete(drop_table))
        // Credentials endpoint for vending storage access credentials
        .route(
            "/namespaces/{namespace}/tables/{table}/credentials",
            get(load_table_credentials),
        )
        // Server-side scan planning. Answered inline, so the plan-id the
        // response carries names a plan that is already finished — the two
        // follow-ups exist so a client that calls them gets a defined answer
        // rather than a router 404.
        .route(
            "/namespaces/{namespace}/tables/{table}/plan",
            post(plan_table_scan),
        )
        .route(
            "/namespaces/{namespace}/tables/{table}/plan/{plan_id}",
            get(fetch_planning_result).delete(cancel_planning),
        )
        // `fetchScanTasks`. Never reached by a client following this server's
        // own responses — it issues no `plan-task` to exchange — but routed so
        // that one which calls it gets the spec's `NoSuchPlanTaskException`
        // rather than a router 404 with no Iceberg error body.
        .route(
            "/namespaces/{namespace}/tables/{table}/tasks",
            post(fetch_scan_tasks),
        )
        // Remote signing: the engine holds no credential, and each object
        // request is authorized and signed individually.
        .route(
            "/namespaces/{namespace}/tables/{table}/sign",
            post(sign_request),
        )
        // Metrics reporting endpoint for client telemetry
        .route(
            "/namespaces/{namespace}/tables/{table}/metrics",
            post(report_metrics),
        )
        .route("/tables/rename", post(rename_table))
        // ====================================================================
        // View routes
        // ====================================================================
        .route("/namespaces/{namespace}/views", get(list_views))
        .route("/namespaces/{namespace}/views", post(create_view))
        // Register existing view (from external metadata location)
        .route("/namespaces/{namespace}/register-view", post(register_view))
        // GET = load_view, POST = commit_view (update)
        .route(
            "/namespaces/{namespace}/views/{view}",
            get(load_view).post(commit_view),
        )
        .route("/namespaces/{namespace}/views/{view}", head(view_exists))
        .route("/namespaces/{namespace}/views/{view}", delete(drop_view))
        .route("/views/rename", post(rename_view))
        // ====================================================================
        // Transaction routes
        // ====================================================================
        .route("/transactions/commit", post(commit_transaction))
        .with_state(app_state)
}
