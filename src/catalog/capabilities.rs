//! What a backend can actually do, and how that is reported.
//!
//! # Why capabilities are explicit
//!
//! Backends differ. An embedded redb catalog commits atomically across tables; a
//! federated mount over somebody else's REST catalog cannot commit at all,
//! because [`iceberg::Catalog`] is a *client* trait whose only commit method
//! takes a type that cannot be constructed downstream (see
//! [`store`](super::store)).
//!
//! A server that hides that difference has two options and both are bad: refuse
//! with a status that blames the caller, or accept and silently do less than was
//! asked. So every backend states what it supports, `GET /v1/config` publishes
//! the **intersection** across mounts, and an unsupported operation is refused
//! with `501` naming the mount — which is the honest answer, and one a client
//! can act on.
//!
//! # Why the intersection rather than the union
//!
//! `endpoints` in the config response is a single list describing one catalog.
//! Publishing the union would advertise an operation that fails on some
//! namespaces, which is worse than not advertising it: a client feature-detects
//! once at startup and then assumes. The intersection is the set of operations
//! that work *everywhere in this catalog*, which is the only promise a single
//! list can honestly make.
//!
//! Capabilities a mount lacks are still *reachable* on the mounts that have them
//! — the refusal is per-request, not per-server. What the intersection governs is
//! only what is advertised.

use serde::{Deserialize, Serialize};

/// What one backend supports.
///
/// Every field is a thing a caller can attempt, so a `false` always corresponds
/// to a request that gets refused rather than to an internal detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Creating, committing to, renaming and dropping tables.
    pub write: bool,
    /// Views at all: listing, loading, creating.
    pub views: bool,
    /// Committing several tables in one atomic transaction.
    pub multi_table_commit: bool,
    /// Adopting metadata that already exists in storage.
    pub register: bool,
    /// Building a table's first metadata without creating the table.
    pub stage_create: bool,
    /// Removing the files a dropped table referenced.
    pub purge: bool,
    /// Planning a scan server-side.
    ///
    /// Planning reads the snapshot's manifests through Rustberg's own `FileIO`,
    /// so it needs storage Rustberg can reach. A mount over somebody else's
    /// catalog stores nothing here, and its warehouse is not one this server
    /// holds credentials for — so it says so rather than failing on the first
    /// manifest read.
    pub scan_planning: bool,
}

impl Capabilities {
    /// Everything a native Rustberg catalog does.
    pub const fn full() -> Self {
        Self {
            write: true,
            views: true,
            multi_table_commit: true,
            register: true,
            stage_create: true,
            purge: true,
            scan_planning: true,
        }
    }

    /// Everything readable, nothing that changes anything.
    ///
    /// `views` stays **true**: reading a view is a read. Mutating one is gated
    /// by `write` separately, so a read-only mount serves `loadView` and refuses
    /// `createView` — which is what "read-only" means everywhere else and what
    /// an operator setting the flag expects.
    ///
    /// A backend with no view support at all is a different statement, spelled
    /// by clearing `views` explicitly. Conflating the two made a read-only mount
    /// silently pretend its views did not exist.
    pub const fn read_only() -> Self {
        Self {
            write: false,
            views: true,
            multi_table_commit: false,
            register: false,
            stage_create: false,
            purge: false,
            // Not a consequence of read-only: this preset describes a mount
            // over somebody else's catalog, whose manifests are in storage this
            // server does not manage.
            scan_planning: false,
        }
    }

    /// The same, with no view support at all.
    ///
    /// For a backend whose protocol has no views — not one that merely refuses
    /// to change them.
    pub const fn read_only_without_views() -> Self {
        Self {
            views: false,
            ..Self::read_only()
        }
    }

    /// The capabilities present in **both**.
    ///
    /// Used to fold many mounts into the single list `GET /v1/config` publishes.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            write: self.write && other.write,
            views: self.views && other.views,
            multi_table_commit: self.multi_table_commit && other.multi_table_commit,
            register: self.register && other.register,
            stage_create: self.stage_create && other.stage_create,
            purge: self.purge && other.purge,
            scan_planning: self.scan_planning && other.scan_planning,
        }
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::full()
    }
}

/// One thing a caller can attempt, for naming it in a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Any table mutation.
    Write,
    /// Anything view-shaped.
    Views,
    /// A multi-table transaction.
    MultiTableCommit,
    /// Adopting existing metadata.
    Register,
    /// Staged table creation.
    StageCreate,
    /// Dropping a table and its files.
    Purge,
    /// Server-side scan planning.
    ScanPlanning,
}

impl Capability {
    /// Whether `capabilities` includes this one.
    pub const fn present_in(self, capabilities: &Capabilities) -> bool {
        match self {
            Capability::Write => capabilities.write,
            Capability::Views => capabilities.views,
            Capability::MultiTableCommit => capabilities.multi_table_commit,
            Capability::Register => capabilities.register,
            Capability::StageCreate => capabilities.stage_create,
            Capability::Purge => capabilities.purge,
            Capability::ScanPlanning => capabilities.scan_planning,
        }
    }

    /// How the capability reads in a refusal message.
    pub const fn describe(self) -> &'static str {
        match self {
            Capability::Write => "writing",
            Capability::Views => "views",
            Capability::MultiTableCommit => "multi-table transactions",
            Capability::Register => "registering existing tables",
            Capability::StageCreate => "staged table creation",
            Capability::Purge => "purging table data",
            Capability::ScanPlanning => "server-side scan planning",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_native_catalog_supports_everything() {
        let full = Capabilities::full();
        for capability in [
            Capability::Write,
            Capability::Views,
            Capability::MultiTableCommit,
            Capability::Register,
            Capability::StageCreate,
            Capability::Purge,
            Capability::ScanPlanning,
        ] {
            assert!(
                capability.present_in(&full),
                "{capability} should be supported"
            );
        }
    }

    #[test]
    fn a_read_only_mount_supports_nothing_mutating() {
        let read_only = Capabilities::read_only();
        assert!(!read_only.write);
        assert!(!read_only.multi_table_commit);
        assert!(!read_only.register);
        assert!(!read_only.stage_create);
        assert!(!read_only.purge);
    }

    /// A mount over somebody else's catalog has manifests in storage this
    /// server does not manage, so it cannot plan a scan over them.
    #[test]
    fn a_remote_mount_cannot_plan_a_scan() {
        assert!(!Capabilities::read_only().scan_planning);
        assert!(Capabilities::full().scan_planning);
    }

    /// Reading a view is a read. Gating it behind `write` conflated "will not
    /// change your views" with "has no views", and made a read-only mount
    /// silently pretend its views did not exist.
    #[test]
    fn a_read_only_mount_can_still_read_views() {
        assert!(Capabilities::read_only().views);
    }

    /// "No views in the protocol" is a different statement, and spelled
    /// differently.
    #[test]
    fn a_backend_without_views_says_so_explicitly() {
        let none = Capabilities::read_only_without_views();
        assert!(!none.views);
        assert!(!none.write);
    }

    /// The rule the config response depends on: one mount lacking a capability
    /// removes it from what the catalog as a whole advertises.
    #[test]
    fn intersection_is_limited_by_the_weakest_mount() {
        let mixed = Capabilities::full().intersect(Capabilities::read_only());
        assert_eq!(mixed, Capabilities::read_only());
    }

    #[test]
    fn intersecting_identical_capabilities_changes_nothing() {
        assert_eq!(
            Capabilities::full().intersect(Capabilities::full()),
            Capabilities::full()
        );
    }

    /// Intersection must not depend on the order mounts happen to be listed in.
    #[test]
    fn intersection_is_commutative() {
        let a = Capabilities {
            write: true,
            views: false,
            multi_table_commit: true,
            register: false,
            stage_create: true,
            purge: false,
            scan_planning: true,
        };
        let b = Capabilities::full();
        assert_eq!(a.intersect(b), b.intersect(a));
    }

    #[test]
    fn every_capability_has_a_readable_name() {
        assert_eq!(Capability::Write.to_string(), "writing");
        assert_eq!(
            Capability::MultiTableCommit.to_string(),
            "multi-table transactions"
        );
    }
}
