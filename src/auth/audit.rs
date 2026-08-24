//! The record one security-relevant event produces.
//!
//! This module defines the *shape* of a record. Where records go, and what
//! happens when they cannot get there, is [`audit_sink`](super::audit_sink).
//!
//! # Every record goes to the sink
//!
//! A record is written through [`Auditor`](super::Auditor) or it does not
//! exist. Nothing here emits one on its own, and in particular nothing emits one
//! through `tracing`: a macro returns `()`, so a record written that way cannot
//! report that it was lost, and records on stderr are missing from the file a
//! deployment configured.
//!
//! # What is recorded
//!
//! Five things, one per [`AuditAction`]. The list is closed: a variant nothing
//! emits is a claim about the trail that reading the trail disproves.
//!
//! | Action | Emitted by | Fails the request if unrecordable |
//! |---|---|---|
//! | [`Authenticate`](AuditAction::Authenticate) | the auth middleware | no |
//! | [`Decision`](AuditAction::Decision) | [`guard`](crate::catalog::v1::guard) | for a permitted mutation |
//! | [`VendCredentials`](AuditAction::VendCredentials) | `loadTable`, `/credentials` | when a write credential was granted |
//! | [`SignRequest`](AuditAction::SignRequest) | `/sign` | when a write signature was minted |
//! | [`RateLimit`](AuditAction::RateLimit) | the auth middleware | no |
//!
//! Every "yes" in that column is a grant that happened. Handing an engine a
//! credential that can `PutObject`, or signing a `DeleteObjects`, changes what
//! the world can do with the warehouse, so losing the record and keeping the
//! grant is the same trade as losing a commit record and keeping the commit.
//!
//! # Example
//!
//! ```
//! use rustberg::auth::{AuditEvent, Auditor};
//!
//! let auditor = Auditor::disabled();
//! auditor.record_lossy(
//!     &AuditEvent::authentication("api_key", true).with_principal_id("svc-etl"),
//! );
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ============================================================================
// Audit Event Types
// ============================================================================

/// Which subsystem produced a record.
///
/// Coarse on purpose: it exists so a pipeline can route or retain the four
/// streams differently, not to classify events finely. [`AuditAction`] is the
/// field that says what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// A caller presented a credential.
    Authentication,
    /// A policy decision was made about a resource.
    Authorization,
    /// Access to the object store was handed out, or withheld.
    StorageAccess,
    /// Something the server did that was not a request.
    System,
}

/// What happened.
///
/// One variant per event this server actually emits. See the module docs for
/// why the list is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A credential was presented and accepted, or rejected.
    Authenticate,
    /// A policy decision was made. [`AuditEvent::operation`] names the action.
    Decision,
    /// A storage credential was vended, withheld, or could not be obtained.
    VendCredentials,
    /// A storage request was signed, or refused.
    SignRequest,
    /// A request was refused by a rate limit.
    RateLimit,
}

/// How the audited event turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// It was permitted, and it worked.
    Success,
    /// Policy permitted it, and it failed anyway — a credential exchange that
    /// the cloud provider refused, for instance. Distinct from `Denied`,
    /// because one is a policy question and the other is an outage.
    Failure,
    /// Policy refused it.
    Denied,
    /// A rate limit refused it.
    RateLimited,
}

/// How loudly a record should read.
///
/// Derived from the outcome rather than chosen, so two records describing the
/// same kind of event never disagree about how serious it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Something permitted happened.
    Info,
    /// Something was refused.
    Warning,
    /// Something broke.
    Error,
}

impl AuditSeverity {
    /// The severity an outcome implies.
    const fn of(outcome: AuditOutcome) -> Self {
        match outcome {
            AuditOutcome::Success => Self::Info,
            AuditOutcome::Denied | AuditOutcome::RateLimited => Self::Warning,
            AuditOutcome::Failure => Self::Error,
        }
    }
}

// ============================================================================
// Audit Event
// ============================================================================

/// One line of the audit trail.
///
/// Serialises to a single JSON object; the sink writes one per line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier. UUIDv7, so records sort by time.
    #[serde(rename = "event_id")]
    pub id: String,

    /// Timestamp in milliseconds since the Unix epoch.
    #[serde(rename = "timestamp_ms")]
    pub timestamp: u64,

    /// The same instant, RFC 3339.
    #[serde(rename = "timestamp")]
    pub timestamp_iso: String,

    /// Which subsystem produced this.
    pub category: AuditCategory,

    /// What happened.
    pub action: AuditAction,

    /// How it turned out.
    pub outcome: AuditOutcome,

    /// How loudly it reads.
    pub severity: AuditSeverity,

    /// What was being done, in the vocabulary of the subsystem that recorded it.
    ///
    /// The Cedar action on a decision (`Read`, `Update`, …), whether a vended
    /// credential could write, whether a signed request read or wrote. A
    /// first-class field rather than a `details` entry, because it is half of
    /// what every query against this trail filters on — the other half being
    /// [`resource_id`](Self::resource_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,

    /// Principal the request authenticated as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,

    /// Tenant the principal belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Address the request came from, as resolved by [`crate::remote_ip`].
    ///
    /// Absent when it could not be resolved, which is not the same as absent
    /// because nobody looked: a hop that cannot be read makes the address
    /// unknown, and inventing one would put a fiction in the trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    /// The `X-Request-Id` echoed to the client, so a record joins to an
    /// application log line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// What kind of thing was acted on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,

    /// Which one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,

    /// Policies that produced this decision.
    ///
    /// A first-class field rather than a `details` entry, because it is the one
    /// an operator greps for: "which rule allowed this?" is the question an
    /// audit trail exists to answer, and free-form details are neither stable
    /// nor documented.
    ///
    /// On a permit these are the permits that matched. On a denial they are the
    /// forbids that matched — and **empty on a denial means deny-by-default**:
    /// nothing forbade the request and nothing permitted it. That is a
    /// different situation to debug from an explicit `forbid`, so the record
    /// makes it visible rather than collapsing both into "denied".
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matched_policies: Vec<String>,

    /// Identifier of the policy set in force when this decision was made.
    ///
    /// Content-derived, so two records sharing it were evaluated against
    /// byte-identical rules — including across replicas. A record whose version
    /// differs from today's was decided under policies that have since changed,
    /// which is exactly what makes an old decision reproducible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_set_version: Option<String>,

    /// Anything else the recording site wanted to carry.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub details: HashMap<String, String>,

    /// Why it failed, when the outcome is not a policy decision.
    ///
    /// Never a provider's own message: those name roles, endpoints and account
    /// identifiers. The recording site logs the detail where reading it needs
    /// access to the host, and puts a sentence here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditEvent {
    /// The empty record for one category and action.
    fn new(category: AuditCategory, action: AuditAction, outcome: AuditOutcome) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp_ms = now.as_millis() as u64;
        let timestamp_iso = chrono::DateTime::from_timestamp_millis(timestamp_ms as i64)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        Self {
            id: Uuid::now_v7().to_string(),
            timestamp: timestamp_ms,
            timestamp_iso,
            category,
            action,
            outcome,
            severity: AuditSeverity::of(outcome),
            operation: None,
            principal_id: None,
            tenant_id: None,
            client_ip: None,
            request_id: None,
            resource_type: None,
            resource_id: None,
            matched_policies: Vec::new(),
            policy_set_version: None,
            details: HashMap::new(),
            error: None,
        }
    }

    // ========================================================================
    // The five events
    // ========================================================================

    /// A caller presented a credential.
    ///
    /// `method` is how it was presented — `api_key`, `jwt`, `anonymous`, `host`.
    /// A rejection carries no principal: nothing was established.
    pub fn authentication(method: &str, accepted: bool) -> Self {
        let outcome = if accepted {
            AuditOutcome::Success
        } else {
            AuditOutcome::Denied
        };
        Self::new(
            AuditCategory::Authentication,
            AuditAction::Authenticate,
            outcome,
        )
        .with_operation(method)
    }

    /// An authorization decision.
    ///
    /// Both outcomes are recorded. A trail of denials alone answers "who was
    /// turned away" but not "who read this table", which is where an
    /// investigation actually starts.
    pub fn decision(operation: &str, resource_type: &str, resource: &str, allowed: bool) -> Self {
        let outcome = if allowed {
            AuditOutcome::Success
        } else {
            AuditOutcome::Denied
        };
        Self::new(AuditCategory::Authorization, AuditAction::Decision, outcome)
            .with_operation(operation)
            .with_resource(resource_type, resource)
    }

    /// A storage credential was vended, withheld, or could not be obtained.
    ///
    /// `access` is what the caller actually walked away with — `read`,
    /// `read-write`, or `none` — and it is the field that makes this record
    /// worth keeping: the authorization record above it says the caller could
    /// `Read` the table, and only this one says whether the credential it
    /// received could also overwrite it. `none` is not the same as `read`: a
    /// withheld credential never had a width decided for it.
    pub fn credential_vend(access: &str, table: &str, outcome: AuditOutcome) -> Self {
        Self::new(
            AuditCategory::StorageAccess,
            AuditAction::VendCredentials,
            outcome,
        )
        .with_operation(access)
        .with_resource("table", table)
    }

    /// A storage request was signed, or refused.
    ///
    /// `operation` is `read` or `write`. The locations the request addressed go
    /// in `details`, because a `DeleteObjects` names up to a thousand of them
    /// and the record has to stay one line.
    pub fn request_sign(operation: &str, table: &str, allowed: bool) -> Self {
        let outcome = if allowed {
            AuditOutcome::Success
        } else {
            AuditOutcome::Denied
        };
        Self::new(
            AuditCategory::StorageAccess,
            AuditAction::SignRequest,
            outcome,
        )
        .with_operation(operation)
        .with_resource("table", table)
    }

    /// A request was refused by a rate limit.
    ///
    /// `scope` is `ip` or `tenant` — which bucket ran out, since the two mean
    /// different things about who is responsible.
    pub fn rate_limit(scope: &str) -> Self {
        Self::new(
            AuditCategory::System,
            AuditAction::RateLimit,
            AuditOutcome::RateLimited,
        )
        .with_operation(scope)
    }

    // ========================================================================
    // Builders
    // ========================================================================

    /// Sets what was being done.
    fn with_operation<S: Into<String>>(mut self, operation: S) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Sets the principal.
    #[must_use]
    pub fn with_principal_id<S: Into<String>>(mut self, id: S) -> Self {
        self.principal_id = Some(id.into());
        self
    }

    /// Sets the tenant.
    #[must_use]
    pub fn with_tenant_id<S: Into<String>>(mut self, id: S) -> Self {
        self.tenant_id = Some(id.into());
        self
    }

    /// Sets the caller's address.
    #[must_use]
    pub fn with_client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip.to_string());
        self
    }

    /// Sets the caller's address, when there is one.
    ///
    /// The `Option`-taking form exists because every call site has one: the
    /// address is genuinely unknown for an in-process caller and for a
    /// forwarding chain that could not be read, and `if let` at each site was
    /// where records went missing.
    #[must_use]
    pub fn with_optional_client_ip(self, ip: Option<IpAddr>) -> Self {
        match ip {
            Some(ip) => self.with_client_ip(ip),
            None => self,
        }
    }

    /// Sets the request id.
    #[must_use]
    pub fn with_request_id<S: Into<String>>(mut self, id: S) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Sets the request id, when there is one.
    #[must_use]
    pub fn with_optional_request_id(self, id: Option<&str>) -> Self {
        match id {
            Some(id) => self.with_request_id(id),
            None => self,
        }
    }

    /// Sets what was acted on.
    #[must_use]
    pub fn with_resource<S1: Into<String>, S2: Into<String>>(
        mut self,
        resource_type: S1,
        resource_id: S2,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Records which rules decided, and which policy set they came from.
    #[must_use]
    pub fn with_policy_provenance(
        mut self,
        matched: &[String],
        policy_set_version: Option<String>,
    ) -> Self {
        self.matched_policies = matched.to_vec();
        self.policy_set_version = policy_set_version;
        self
    }

    /// Adds one detail.
    #[must_use]
    pub fn with_detail<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Records why something failed, and marks the outcome as a failure rather
    /// than a denial.
    #[must_use]
    pub fn with_error<S: Into<String>>(mut self, error: S) -> Self {
        self.error = Some(error.into());
        self.outcome = AuditOutcome::Failure;
        self.severity = AuditSeverity::of(AuditOutcome::Failure);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_accepted_credential_is_a_success() {
        let event = AuditEvent::authentication("api_key", true).with_principal_id("svc-etl");

        assert_eq!(event.category, AuditCategory::Authentication);
        assert_eq!(event.action, AuditAction::Authenticate);
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(event.severity, AuditSeverity::Info);
        assert_eq!(event.operation.as_deref(), Some("api_key"));
    }

    /// A rejection is a warning, not an info line: it is the thing somebody
    /// watching this stream is watching for.
    #[test]
    fn a_rejected_credential_is_a_warning() {
        let event = AuditEvent::authentication("jwt", false);
        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert_eq!(event.severity, AuditSeverity::Warning);
        assert!(event.principal_id.is_none(), "nothing was established");
    }

    /// The Cedar action is a field, not a `details` entry: `action` names the
    /// kind of event, and free-form details are neither stable nor documented.
    #[test]
    fn a_decision_names_its_action_in_a_field() {
        let event = AuditEvent::decision("Update", "table", "acme/web/events", true);

        assert_eq!(event.action, AuditAction::Decision);
        assert_eq!(event.operation.as_deref(), Some("Update"));
        assert_eq!(event.resource_id.as_deref(), Some("acme/web/events"));
        assert!(event.details.is_empty());
    }

    /// The point of the vending record: the decision above it says `Read` was
    /// permitted, and only this says the credential could also write.
    #[test]
    fn a_vending_record_says_whether_the_credential_could_write() {
        let event =
            AuditEvent::credential_vend("read-write", "acme/web/events", AuditOutcome::Success);

        assert_eq!(event.category, AuditCategory::StorageAccess);
        assert_eq!(event.operation.as_deref(), Some("read-write"));
    }

    #[test]
    fn a_refused_signature_is_denied_and_a_broken_exchange_is_a_failure() {
        let refused = AuditEvent::request_sign("write", "acme/web/events", false);
        assert_eq!(refused.outcome, AuditOutcome::Denied);
        assert_eq!(refused.severity, AuditSeverity::Warning);

        let broken = AuditEvent::credential_vend("read", "t", AuditOutcome::Success)
            .with_error("the credential exchange failed");
        assert_eq!(broken.outcome, AuditOutcome::Failure);
        assert_eq!(broken.severity, AuditSeverity::Error);
    }

    #[test]
    fn optional_fields_are_omitted_rather_than_null() {
        let event = AuditEvent::rate_limit("ip");
        let json: serde_json::Value = serde_json::to_value(&event).unwrap();

        assert_eq!(json["action"], "rate_limit");
        assert_eq!(json["operation"], "ip");
        assert!(json.get("principal_id").is_none());
        assert!(json.get("details").is_none());
    }

    /// An unresolved address is absent, never a placeholder: the trail must not
    /// claim a request came from somewhere it might not have.
    #[test]
    fn an_unknown_address_leaves_the_field_out() {
        let event = AuditEvent::authentication("api_key", false).with_optional_client_ip(None);
        assert!(event.client_ip.is_none());

        let known = AuditEvent::authentication("api_key", true)
            .with_optional_client_ip(Some("10.0.0.5".parse().unwrap()));
        assert_eq!(known.client_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn records_sort_by_time_through_their_ids() {
        let first = AuditEvent::rate_limit("ip");
        let second = AuditEvent::rate_limit("ip");
        assert!(first.id < second.id, "UUIDv7 ids must be ordered");
    }
}
