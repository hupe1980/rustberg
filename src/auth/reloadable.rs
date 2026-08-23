//! An authorizer whose policy set can change while requests are in flight.
//!
//! # The property that has to hold
//!
//! A decision is always evaluated against **one coherent policy set**, never a
//! half-applied change. That rules out mutating a `PolicySet` in place: a
//! request arriving mid-edit would be decided against a set that never existed
//! as a whole, and no audit record could describe what it was.
//!
//! So a change builds a *complete* new [`CedarAuthorizer`] — parsed, typechecked
//! and versioned — and swaps the pointer. A request holds an `Arc` to whichever
//! set was current when it started and finishes against that one. There is no
//! window, no lock held across evaluation, and no torn state.
//!
//! # Why the lock is not held during evaluation
//!
//! The read path clones an `Arc` under a very short read lock and releases it
//! before evaluating. Cedar evaluation is microseconds but it is not free, and
//! holding a lock across it would make every request contend with every other on
//! a structure that changes perhaps twice a year.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use super::authz::{Authorizer, AuthzContext, AuthzOutcome};
use super::cedar::CedarAuthorizer;

/// A [`CedarAuthorizer`] that can be replaced atomically.
#[derive(Debug)]
pub struct ReloadableAuthorizer {
    current: RwLock<Arc<CedarAuthorizer>>,
    /// Sequence of the revision currently loaded, for deciding whether a
    /// polled revision is actually newer.
    sequence: RwLock<u64>,
}

impl ReloadableAuthorizer {
    /// Wraps `authorizer` as the initially loaded policy set.
    ///
    /// `sequence` is the revision it came from; `0` means "not from the store",
    /// which is the case when policy was seeded from a file or the built-in
    /// defaults.
    pub fn new(authorizer: CedarAuthorizer, sequence: u64) -> Self {
        Self {
            current: RwLock::new(Arc::new(authorizer)),
            sequence: RwLock::new(sequence),
        }
    }

    /// The policy set in force right now.
    pub fn snapshot(&self) -> Arc<CedarAuthorizer> {
        self.current.read().clone()
    }

    /// The revision sequence currently loaded.
    pub fn loaded_sequence(&self) -> u64 {
        *self.sequence.read()
    }

    /// Replaces the policy set, atomically.
    ///
    /// Requests already evaluating continue against the set they started with;
    /// requests arriving after this returns see the new one. Nothing observes a
    /// mixture.
    pub fn swap(&self, authorizer: CedarAuthorizer, sequence: u64) {
        // Both writes happen under their own short lock. They are not one
        // atomic unit, and do not need to be: `sequence` is only read to decide
        // whether polling should reload, and a poller that briefly sees the old
        // sequence merely reloads an identical set on its next tick.
        *self.current.write() = Arc::new(authorizer);
        *self.sequence.write() = sequence;
    }
}

#[async_trait]
impl Authorizer for ReloadableAuthorizer {
    async fn decide(&self, ctx: &AuthzContext) -> AuthzOutcome {
        // The `Arc` is cloned out before evaluating, so the lock is not held
        // across the decision.
        let current = self.snapshot();
        current.decide(ctx).await
    }

    fn policy_set_version(&self) -> Option<String> {
        self.snapshot().policy_set_version()
    }
}

/// How often a replica checks the store for a newer policy revision.
///
/// Policy changes are rare and urgent: rare enough that a poll every few
/// seconds costs nothing, urgent enough that minutes of divergence between
/// replicas is not acceptable — during that window the cluster enforces two
/// different rule sets, and a revocation is only as fast as the slowest pod.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// A running poller, stopped when this is dropped.
///
/// The handle has to be *held*, not discarded. A spawned task keeps its own
/// `Arc`s alive, so a dropped-and-forgotten poller outlives the application it
/// was polling for and goes on querying the database every few seconds until
/// the process exits. In a test suite that builds many applications, or a
/// library embedding several, that is an unbounded accumulation of background
/// work nothing can reach to stop.
#[derive(Debug)]
pub struct PolicyPoller {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for PolicyPoller {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Keeps `authorizer` in step with `store`, forever.
///
/// # Why replicas poll rather than being told
///
/// The alternative is the writing replica notifying the others, which needs
/// either a message bus this project does not require or replicas knowing about
/// each other. Polling a row they already have a connection to needs neither,
/// and it converges after a restart, a network partition, or a replica that
/// joined after the change — none of which a notification would survive.
///
/// A replica that cannot reach the store keeps serving the policy set it has.
/// The alternative — failing closed on a transient database blip — would turn a
/// read-only outage into a total one, and the policy set in hand was valid.
///
/// The returned [`PolicyPoller`] must be kept for as long as the polling should
/// continue; dropping it stops the task.
pub fn spawn_policy_poller(
    store: Arc<dyn super::policy_store::PolicyStore>,
    authorizer: Arc<ReloadableAuthorizer>,
    interval: std::time::Duration,
) -> PolicyPoller {
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it, since the caller has just
        // loaded the current revision.
        ticker.tick().await;

        loop {
            ticker.tick().await;

            let current = match store.current().await {
                Ok(Some(revision)) => revision,
                // Nothing stored yet, or the store is briefly unreachable.
                // Keep serving what we have.
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Could not read the policy store; continuing with the loaded policy set"
                    );
                    continue;
                }
            };

            if current.sequence <= authorizer.loaded_sequence() {
                continue;
            }

            match CedarAuthorizer::new(&current.source) {
                Ok(next) => {
                    let previous = authorizer.loaded_sequence();
                    authorizer.swap(next, current.sequence);
                    tracing::info!(
                        from_sequence = previous,
                        to_sequence = current.sequence,
                        version = %current.version,
                        "Policy set reloaded from the store"
                    );
                }
                // A stored revision that will not compile cannot be installed,
                // and the set in hand is still valid — so this keeps serving it
                // and says so, rather than failing closed on every request.
                Err(e) => tracing::error!(
                    sequence = current.sequence,
                    error = %e,
                    "Stored policy revision is not usable; keeping the loaded policy set"
                ),
            }
        }
    });

    PolicyPoller { handle }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authz::{Action, Resource};
    use crate::auth::principal::{AuthMethod, PrincipalBuilder, PrincipalType};

    const ADMIN_ONLY: &str = r#"
        permit(principal in Rustberg::Group::"admin", action, resource)
          when { resource.tenant == principal.tenant };
    "#;

    const NOBODY: &str = "";

    fn admin_ctx() -> AuthzContext {
        let principal = PrincipalBuilder::new(
            "u1",
            "Admin",
            PrincipalType::User,
            "acme",
            AuthMethod::ApiKey,
        )
        .with_role("admin")
        .build();
        AuthzContext::new(
            principal,
            Resource::namespace("acme", ["analytics"]),
            Action::Read,
        )
    }

    #[tokio::test]
    async fn it_decides_with_the_loaded_policy_set() {
        let authz = ReloadableAuthorizer::new(CedarAuthorizer::new(ADMIN_ONLY).unwrap(), 1);
        assert!(authz.decide(&admin_ctx()).await.is_allowed());
    }

    /// The point of the type: a change takes effect without a restart.
    #[tokio::test]
    async fn a_swap_changes_the_decision() {
        let authz = ReloadableAuthorizer::new(CedarAuthorizer::new(ADMIN_ONLY).unwrap(), 1);
        assert!(authz.decide(&admin_ctx()).await.is_allowed());

        authz.swap(CedarAuthorizer::new(NOBODY).unwrap(), 2);

        let outcome = authz.decide(&admin_ctx()).await;
        assert!(!outcome.is_allowed(), "the new policy set permits nothing");
        assert!(
            outcome.is_default_deny(),
            "an empty policy set denies by default rather than by rule"
        );
    }

    /// Audit records must name the set that decided, so the version has to move
    /// with the swap.
    #[tokio::test]
    async fn the_version_follows_the_swap() {
        let authz = ReloadableAuthorizer::new(CedarAuthorizer::new(ADMIN_ONLY).unwrap(), 1);
        let before = authz.policy_set_version();

        authz.swap(CedarAuthorizer::new(NOBODY).unwrap(), 2);
        let after = authz.policy_set_version();

        assert!(before.is_some() && after.is_some());
        assert_ne!(
            before, after,
            "a different policy set is a different version"
        );
    }

    /// A forgotten poller would outlive its application and keep querying the
    /// database until the process exits.
    #[tokio::test]
    async fn dropping_the_poller_stops_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Counts how many times the store is polled.
        #[derive(Debug)]
        struct Counting(Arc<AtomicUsize>);

        #[async_trait]
        impl crate::auth::policy_store::PolicyStore for Counting {
            async fn current(
                &self,
            ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>>
            {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            async fn append(
                &self,
                _: &str,
                _: &str,
                _: Option<&str>,
            ) -> crate::error::Result<crate::auth::policy_store::PolicyRevision> {
                unreachable!("the poller only reads")
            }
            async fn history(
                &self,
                _: usize,
            ) -> crate::error::Result<Vec<crate::auth::policy_store::PolicyRevisionSummary>>
            {
                Ok(Vec::new())
            }
            async fn get(
                &self,
                _: u64,
            ) -> crate::error::Result<Option<crate::auth::policy_store::PolicyRevision>>
            {
                Ok(None)
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(Counting(polls.clone()));
        let authorizer = Arc::new(ReloadableAuthorizer::new(
            CedarAuthorizer::new(ADMIN_ONLY).unwrap(),
            1,
        ));

        let poller = spawn_policy_poller(store, authorizer, std::time::Duration::from_millis(10));

        // Let it run.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let while_running = polls.load(Ordering::SeqCst);
        assert!(while_running > 0, "the poller should have polled");

        drop(poller);

        // Whatever poll was in flight may still land; nothing after that should.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let after_drop = polls.load(Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        assert_eq!(
            polls.load(Ordering::SeqCst),
            after_drop,
            "a dropped poller must stop; it polled {while_running} times while alive \
             and kept going after being dropped"
        );
    }

    #[tokio::test]
    async fn the_loaded_sequence_follows_the_swap() {
        let authz = ReloadableAuthorizer::new(CedarAuthorizer::new(ADMIN_ONLY).unwrap(), 7);
        assert_eq!(authz.loaded_sequence(), 7);

        authz.swap(CedarAuthorizer::new(NOBODY).unwrap(), 8);
        assert_eq!(authz.loaded_sequence(), 8);
    }

    /// A snapshot taken before a swap keeps deciding against what it captured,
    /// which is what makes an in-flight request coherent.
    #[tokio::test]
    async fn a_snapshot_is_unaffected_by_a_later_swap() {
        let authz = ReloadableAuthorizer::new(CedarAuthorizer::new(ADMIN_ONLY).unwrap(), 1);
        let held = authz.snapshot();

        authz.swap(CedarAuthorizer::new(NOBODY).unwrap(), 2);

        assert!(
            held.decide(&admin_ctx()).await.is_allowed(),
            "a request that started before the swap finishes against the set it started with"
        );
        assert!(!authz.decide(&admin_ctx()).await.is_allowed());
    }
}
