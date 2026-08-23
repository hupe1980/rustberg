//! Where policy lives, and how a change to it becomes visible.
//!
//! # Why policy is stored rather than only read from a file
//!
//! A policy file is read once at startup, so changing policy means restarting
//! every replica — and until the last one restarts, the cluster is enforcing two
//! different rule sets with no way to tell which decided what. For a governance
//! product that is the wrong failure mode: policy is the thing that changes most
//! often and matters most when it does.
//!
//! So the policy set is a **versioned, append-only log** in the same backend the
//! catalog uses. Writing a new revision does not edit the old one, which is what
//! makes an audit record from last month reproducible: its `policy_set_version`
//! still names something that exists.
//!
//! # Sequence and version are different things
//!
//! - `sequence` is monotonic and identifies *when*: revision 7 came after 6.
//! - `version` is a content hash and identifies *what*: two revisions with the
//!   same version enforce byte-identical rules.
//!
//! Both are needed, and neither substitutes for the other. Rolling back to an
//! earlier revision appends a *new* sequence carrying an *old* version — the log
//! records that a rollback happened, while the version correctly says the rules
//! are the ones from before. A single counter could not express that, and a
//! content hash alone could not order it.
//!
//! # A file seeds; the store decides
//!
//! `policy_file` seeds an **empty** store and is then no longer authoritative.
//! The alternative — file wins on every start — would silently discard every
//! change made through the API the moment a pod restarted, which is a data-loss
//! bug wearing a configuration hat. Startup logs loudly when the two diverge.

use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// One revision of the policy set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRevision {
    /// Monotonic position in the log. Higher is newer.
    pub sequence: u64,
    /// Content hash of `source`; equal versions mean identical rules.
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
}

impl PolicyRevision {
    /// The revision without its policy text.
    pub fn summary(&self) -> PolicyRevisionSummary {
        PolicyRevisionSummary {
            sequence: self.sequence,
            version: self.version.clone(),
            author: self.author.clone(),
            created_at_ms: self.created_at_ms,
            note: self.note.clone(),
            source_bytes: self.source.len(),
        }
    }
}

/// A revision's metadata, without the policy text.
///
/// History listings use this: a policy set can be large, and an operator
/// scanning "what changed and who did it" does not want every revision's full
/// text in one response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRevisionSummary {
    /// Monotonic position in the log.
    pub sequence: u64,
    /// Content hash of the revision's source.
    pub version: String,
    /// Principal that wrote it.
    pub author: String,
    /// When it was written, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Why it was written, when the author said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Size of the policy text, so a listing conveys scale without the text.
    pub source_bytes: usize,
}

/// The append-only log of policy revisions.
///
/// Implemented by the same backends that hold the catalog, so a deployment has
/// one place to back up and one place to make durable.
#[async_trait]
pub trait PolicyStore: Debug + Send + Sync {
    /// The newest revision, or `None` when policy has never been written.
    async fn current(&self) -> Result<Option<PolicyRevision>>;

    /// Appends `source` as a new revision and returns it.
    ///
    /// Always appends, even when the content is unchanged from the current
    /// revision: the log records *that someone made a change*, and swallowing a
    /// no-op write would erase the fact that an operator touched policy at all.
    async fn append(
        &self,
        source: &str,
        author: &str,
        note: Option<&str>,
    ) -> Result<PolicyRevision>;

    /// Revisions newest-first, at most `limit` of them.
    async fn history(&self, limit: usize) -> Result<Vec<PolicyRevisionSummary>>;

    /// One revision by sequence, or `None` when there is no such revision.
    async fn get(&self, sequence: u64) -> Result<Option<PolicyRevision>>;
}

/// A stable identifier for policy text.
///
/// Shared by the store and the authorizer so a revision's recorded version and
/// the version stamped on an audit record are the same string by construction,
/// rather than by two functions agreeing.
pub fn version_of(source: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(source.as_bytes());
    digest
        .iter()
        .take(8)
        .fold(String::with_capacity(16), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_stable_for_identical_text() {
        assert_eq!(
            version_of("permit(principal, action, resource);"),
            version_of("permit(principal, action, resource);")
        );
    }

    #[test]
    fn different_text_gets_a_different_version() {
        assert_ne!(
            version_of("permit(principal, action, resource);"),
            version_of("forbid(principal, action, resource);")
        );
    }

    #[test]
    fn the_version_is_a_short_hex_digest() {
        let v = version_of("anything");
        assert_eq!(v.len(), 16);
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// A listing must convey scale without carrying every revision's full text.
    #[test]
    fn a_summary_drops_the_source_but_keeps_its_size() {
        let revision = PolicyRevision {
            sequence: 3,
            version: version_of("permit(principal, action, resource);"),
            source: "permit(principal, action, resource);".to_string(),
            author: "alice".to_string(),
            created_at_ms: 1_700_000_000_000,
            note: Some("open it up".to_string()),
        };

        let summary = revision.summary();
        assert_eq!(summary.sequence, 3);
        assert_eq!(summary.version, revision.version);
        assert_eq!(summary.source_bytes, revision.source.len());
        assert_eq!(summary.note.as_deref(), Some("open it up"));

        let json = serde_json::to_string(&summary).unwrap();
        assert!(
            !json.contains("permit("),
            "a summary must not carry the policy text: {json}"
        );
    }
}
