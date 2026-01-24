//! Audit logging for security-relevant events.
//!
//! This module provides structured audit logging for authentication,
//! authorization, and data access events. Audit logs are essential for:
//!
//! - Security monitoring and incident response
//! - Compliance requirements (SOC 2, GDPR, HIPAA)
//! - Forensic analysis
//!
//! # Event Types
//!
//! The audit system captures several categories of events:
//!
//! - **Authentication**: Login attempts, API key usage, token validation
//! - **Authorization**: Permission checks, access denials
//! - **Data Access**: Namespace/table operations (create, read, update, delete)
//! - **Admin Operations**: API key management, configuration changes
//!
//! # Output Format
//!
//! Audit events are emitted as structured JSON logs compatible with:
//! - Splunk
//! - Elasticsearch/OpenSearch
//! - AWS CloudWatch
//! - Google Cloud Logging
//! - Azure Monitor
//!
//! # Example
//!
//! ```
//! use rustberg::auth::audit::{AuditEvent, AuditOutcome, AuditAction};
//!
//! // Log an authentication event
//! AuditEvent::authentication(AuditAction::ApiKeyAuth)
//!     .with_principal_id("user-123")
//!     .with_client_ip("192.168.1.1")
//!     .with_outcome(AuditOutcome::Success)
//!     .with_detail("api_key", "rb_xxx...xxx")
//!     .emit();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

// ============================================================================
// Audit Event Types
// ============================================================================

/// Category of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Authentication events (login, API key validation).
    Authentication,
    /// Authorization events (permission checks).
    Authorization,
    /// Data access events (CRUD operations).
    DataAccess,
    /// Administrative operations.
    Admin,
    /// System events (startup, shutdown, errors).
    System,
}

/// Specific action within an audit category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication actions
    /// API key authentication attempt.
    ApiKeyAuth,
    /// OAuth token validation.
    TokenAuth,
    /// Session creation.
    SessionCreate,
    /// Session termination.
    SessionDestroy,

    // Authorization actions
    /// Permission check.
    PermissionCheck,
    /// Access denied.
    AccessDenied,

    // Data access actions
    /// Namespace created.
    NamespaceCreate,
    /// Namespace read/listed.
    NamespaceRead,
    /// Namespace updated.
    NamespaceUpdate,
    /// Namespace deleted.
    NamespaceDelete,
    /// Table created.
    TableCreate,
    /// Table read/loaded.
    TableRead,
    /// Table updated/committed.
    TableUpdate,
    /// Table deleted.
    TableDelete,
    /// Table renamed.
    TableRename,

    // Admin actions
    /// API key created.
    ApiKeyCreate,
    /// API key revoked.
    ApiKeyRevoke,
    /// API key disabled.
    ApiKeyDisable,
    /// Configuration changed.
    ConfigChange,

    // System actions
    /// Service started.
    ServiceStart,
    /// Service stopped.
    ServiceStop,
    /// Rate limit triggered.
    RateLimitTriggered,
    /// Security alert.
    SecurityAlert,
}

/// Outcome of the audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Action succeeded.
    Success,
    /// Action failed due to error.
    Failure,
    /// Action was denied (authz failure).
    Denied,
    /// Action was rate limited.
    RateLimited,
    /// Action is pending (for async operations).
    Pending,
}

/// Severity level of the audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Informational event.
    Info,
    /// Warning event.
    Warning,
    /// Error event.
    Error,
    /// Critical security event.
    Critical,
}

// ============================================================================
// Audit Event
// ============================================================================

/// A structured audit event.
///
/// This is the main type for recording audit events. Use the builder pattern
/// to construct events with the appropriate fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    #[serde(rename = "event_id")]
    pub id: String,

    /// Timestamp in milliseconds since Unix epoch.
    #[serde(rename = "timestamp_ms")]
    pub timestamp: u64,

    /// ISO 8601 formatted timestamp.
    #[serde(rename = "timestamp")]
    pub timestamp_iso: String,

    /// Event category.
    pub category: AuditCategory,

    /// Specific action.
    pub action: AuditAction,

    /// Outcome of the action.
    pub outcome: AuditOutcome,

    /// Severity level.
    pub severity: AuditSeverity,

    /// Principal/user identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,

    /// Tenant identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Client IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    /// Request ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Resource type (namespace, table, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,

    /// Resource identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,

    /// Additional details.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,

    /// Error message if outcome is failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event with the specified category and action.
    pub fn new(category: AuditCategory, action: AuditAction) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let timestamp_ms = now.as_millis() as u64;

        // Generate ISO 8601 timestamp
        let datetime = chrono::DateTime::from_timestamp_millis(timestamp_ms as i64)
            .unwrap_or_else(chrono::Utc::now);
        let timestamp_iso = datetime.to_rfc3339();

        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: timestamp_ms,
            timestamp_iso,
            category,
            action,
            outcome: AuditOutcome::Success,
            severity: AuditSeverity::Info,
            principal_id: None,
            tenant_id: None,
            client_ip: None,
            request_id: None,
            resource_type: None,
            resource_id: None,
            details: HashMap::new(),
            error: None,
        }
    }

    // ========================================================================
    // Builder Methods
    // ========================================================================

    /// Creates an authentication audit event.
    pub fn authentication(action: AuditAction) -> Self {
        Self::new(AuditCategory::Authentication, action)
    }

    /// Creates an authorization audit event.
    pub fn authorization(action: AuditAction) -> Self {
        Self::new(AuditCategory::Authorization, action)
    }

    /// Creates a data access audit event.
    pub fn data_access(action: AuditAction) -> Self {
        Self::new(AuditCategory::DataAccess, action)
    }

    /// Creates an admin audit event.
    pub fn admin(action: AuditAction) -> Self {
        Self::new(AuditCategory::Admin, action)
    }

    /// Creates a system audit event.
    pub fn system(action: AuditAction) -> Self {
        Self::new(AuditCategory::System, action)
    }

    /// Sets the outcome.
    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        // Auto-adjust severity based on outcome
        if matches!(outcome, AuditOutcome::Denied | AuditOutcome::RateLimited) {
            self.severity = AuditSeverity::Warning;
        }
        if matches!(outcome, AuditOutcome::Failure) && self.severity == AuditSeverity::Info {
            self.severity = AuditSeverity::Error;
        }
        self
    }

    /// Sets the severity level.
    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the principal ID.
    pub fn with_principal_id<S: Into<String>>(mut self, id: S) -> Self {
        self.principal_id = Some(id.into());
        self
    }

    /// Sets the tenant ID.
    pub fn with_tenant_id<S: Into<String>>(mut self, id: S) -> Self {
        self.tenant_id = Some(id.into());
        self
    }

    /// Sets the client IP.
    pub fn with_client_ip<S: Into<String>>(mut self, ip: S) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Sets the client IP from an IpAddr.
    pub fn with_client_ip_addr(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip.to_string());
        self
    }

    /// Sets the request ID for correlation.
    pub fn with_request_id<S: Into<String>>(mut self, id: S) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Sets the resource type and ID.
    pub fn with_resource<S1: Into<String>, S2: Into<String>>(
        mut self,
        resource_type: S1,
        resource_id: S2,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Sets the namespace resource.
    pub fn with_namespace<S: Into<String>>(self, namespace: S) -> Self {
        self.with_resource("namespace", namespace)
    }

    /// Sets the table resource.
    pub fn with_table<S1: Into<String>, S2: Into<String>>(
        self,
        namespace: S1,
        table: S2,
    ) -> Self {
        let resource_id = format!("{}.{}", namespace.into(), table.into());
        self.with_resource("table", resource_id)
    }

    /// Adds a detail key-value pair.
    pub fn with_detail<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Sets the error message.
    pub fn with_error<S: Into<String>>(mut self, error: S) -> Self {
        self.error = Some(error.into());
        if self.severity == AuditSeverity::Info {
            self.severity = AuditSeverity::Error;
        }
        self
    }

    // ========================================================================
    // Emission Methods
    // ========================================================================

    /// Emits the audit event to the logging system.
    ///
    /// The event is serialized as JSON and logged at the appropriate level.
    pub fn emit(self) {
        let json = serde_json::to_string(&self).unwrap_or_else(|e| {
            format!("{{\"error\": \"failed to serialize audit event: {}\"}}", e)
        });

        // Log at appropriate level based on severity
        match self.severity {
            AuditSeverity::Info => {
                info!(
                    target: "audit",
                    category = ?self.category,
                    action = ?self.action,
                    outcome = ?self.outcome,
                    "{}",
                    json
                );
            }
            AuditSeverity::Warning | AuditSeverity::Error | AuditSeverity::Critical => {
                warn!(
                    target: "audit",
                    category = ?self.category,
                    action = ?self.action,
                    outcome = ?self.outcome,
                    severity = ?self.severity,
                    "{}",
                    json
                );
            }
        }
    }

    /// Converts the event to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Converts the event to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Logs an authentication success event.
pub fn log_auth_success(
    principal_id: &str,
    tenant_id: &str,
    client_ip: Option<&str>,
    method: &str,
) {
    let mut event = AuditEvent::authentication(AuditAction::ApiKeyAuth)
        .with_principal_id(principal_id)
        .with_tenant_id(tenant_id)
        .with_outcome(AuditOutcome::Success)
        .with_detail("method", method);

    if let Some(ip) = client_ip {
        event = event.with_client_ip(ip);
    }

    event.emit();
}

/// Logs an authentication failure event.
pub fn log_auth_failure(client_ip: Option<&str>, reason: &str) {
    let mut event = AuditEvent::authentication(AuditAction::ApiKeyAuth)
        .with_outcome(AuditOutcome::Failure)
        .with_severity(AuditSeverity::Warning)
        .with_error(reason);

    if let Some(ip) = client_ip {
        event = event.with_client_ip(ip);
    }

    event.emit();
}

/// Logs an authorization denial event.
pub fn log_authz_denied(
    principal_id: &str,
    tenant_id: &str,
    resource_type: &str,
    resource_id: &str,
    action: &str,
) {
    AuditEvent::authorization(AuditAction::AccessDenied)
        .with_principal_id(principal_id)
        .with_tenant_id(tenant_id)
        .with_resource(resource_type, resource_id)
        .with_outcome(AuditOutcome::Denied)
        .with_detail("requested_action", action)
        .emit();
}

/// Logs a rate limit triggered event.
pub fn log_rate_limit(client_ip: &str, tenant_id: Option<&str>, limit_type: &str) {
    let mut event = AuditEvent::system(AuditAction::RateLimitTriggered)
        .with_client_ip(client_ip)
        .with_outcome(AuditOutcome::RateLimited)
        .with_severity(AuditSeverity::Warning)
        .with_detail("limit_type", limit_type);

    if let Some(tid) = tenant_id {
        event = event.with_tenant_id(tid);
    }

    event.emit();
}

/// Logs a namespace operation.
pub fn log_namespace_operation(
    action: AuditAction,
    principal_id: &str,
    tenant_id: &str,
    namespace: &str,
    outcome: AuditOutcome,
) {
    AuditEvent::data_access(action)
        .with_principal_id(principal_id)
        .with_tenant_id(tenant_id)
        .with_namespace(namespace)
        .with_outcome(outcome)
        .emit();
}

/// Logs a table operation.
pub fn log_table_operation(
    action: AuditAction,
    principal_id: &str,
    tenant_id: &str,
    namespace: &str,
    table: &str,
    outcome: AuditOutcome,
) {
    AuditEvent::data_access(action)
        .with_principal_id(principal_id)
        .with_tenant_id(tenant_id)
        .with_table(namespace, table)
        .with_outcome(outcome)
        .emit();
}

/// Logs an API key management operation.
pub fn log_api_key_operation(
    action: AuditAction,
    admin_principal_id: &str,
    admin_tenant_id: &str,
    target_key_id: &str,
    target_tenant_id: &str,
) {
    AuditEvent::admin(action)
        .with_principal_id(admin_principal_id)
        .with_tenant_id(admin_tenant_id)
        .with_resource("api_key", target_key_id)
        .with_detail("target_tenant_id", target_tenant_id)
        .with_outcome(AuditOutcome::Success)
        .emit();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(AuditCategory::Authentication, AuditAction::ApiKeyAuth);

        assert!(!event.id.is_empty());
        assert!(event.timestamp > 0);
        assert_eq!(event.category, AuditCategory::Authentication);
        assert_eq!(event.action, AuditAction::ApiKeyAuth);
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(event.severity, AuditSeverity::Info);
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::authentication(AuditAction::ApiKeyAuth)
            .with_principal_id("user-123")
            .with_tenant_id("tenant-456")
            .with_client_ip("192.168.1.1")
            .with_request_id("req-789")
            .with_outcome(AuditOutcome::Success)
            .with_detail("api_key_prefix", "rb_");

        assert_eq!(event.principal_id, Some("user-123".to_string()));
        assert_eq!(event.tenant_id, Some("tenant-456".to_string()));
        assert_eq!(event.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(event.request_id, Some("req-789".to_string()));
        assert_eq!(event.details.get("api_key_prefix"), Some(&"rb_".to_string()));
    }

    #[test]
    fn test_audit_event_with_resource() {
        let event = AuditEvent::data_access(AuditAction::TableCreate)
            .with_table("my_namespace", "my_table");

        assert_eq!(event.resource_type, Some("table".to_string()));
        assert_eq!(
            event.resource_id,
            Some("my_namespace.my_table".to_string())
        );
    }

    #[test]
    fn test_audit_event_json_serialization() {
        let event = AuditEvent::authentication(AuditAction::ApiKeyAuth)
            .with_principal_id("user-123")
            .with_outcome(AuditOutcome::Success);

        let json = event.to_json().unwrap();
        assert!(json.contains("\"category\":\"authentication\""));
        assert!(json.contains("\"action\":\"api_key_auth\""));
        assert!(json.contains("\"principal_id\":\"user-123\""));
    }

    #[test]
    fn test_audit_outcome_affects_severity() {
        let denied = AuditEvent::authorization(AuditAction::AccessDenied)
            .with_outcome(AuditOutcome::Denied);
        assert_eq!(denied.severity, AuditSeverity::Warning);

        let failure = AuditEvent::authentication(AuditAction::ApiKeyAuth)
            .with_outcome(AuditOutcome::Failure);
        assert_eq!(failure.severity, AuditSeverity::Error);
    }

    #[test]
    fn test_audit_event_with_error() {
        let event = AuditEvent::authentication(AuditAction::ApiKeyAuth)
            .with_outcome(AuditOutcome::Failure)
            .with_error("Invalid API key format");

        assert_eq!(event.error, Some("Invalid API key format".to_string()));
        assert_eq!(event.severity, AuditSeverity::Error);
    }

    #[test]
    fn test_audit_categories() {
        // Test each category creation shorthand
        let auth = AuditEvent::authentication(AuditAction::ApiKeyAuth);
        assert_eq!(auth.category, AuditCategory::Authentication);

        let authz = AuditEvent::authorization(AuditAction::PermissionCheck);
        assert_eq!(authz.category, AuditCategory::Authorization);

        let data = AuditEvent::data_access(AuditAction::TableCreate);
        assert_eq!(data.category, AuditCategory::DataAccess);

        let admin = AuditEvent::admin(AuditAction::ApiKeyCreate);
        assert_eq!(admin.category, AuditCategory::Admin);

        let system = AuditEvent::system(AuditAction::ServiceStart);
        assert_eq!(system.category, AuditCategory::System);
    }

    #[test]
    fn test_audit_event_timestamp_format() {
        let event = AuditEvent::new(AuditCategory::System, AuditAction::ServiceStart);

        // Check ISO format contains expected components
        assert!(event.timestamp_iso.contains("T"));
        assert!(
            event.timestamp_iso.contains("Z") || event.timestamp_iso.contains("+")
        );

        // Timestamp should be reasonable (after year 2020)
        assert!(event.timestamp > 1577836800000); // Jan 1, 2020
    }
}
