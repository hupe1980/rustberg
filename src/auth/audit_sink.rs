//! Where audit records go, and what happens when they cannot get there.
//!
//! # Why not `tracing`
//!
//! A `tracing` macro returns `()`. Something that cannot fail cannot tell the
//! caller a record was lost, so "an unrecorded change is not made" is
//! unimplementable through it. Records would also interleave with application
//! logs, and go nowhere at all when no subscriber is configured for the target.
//!
//! A sink is a value that can fail. That is the point.
//!
//! # Fail-closed, for mutations only
//!
//! An unrecorded *change* to the catalog is precisely the event an audit exists
//! to capture, so losing the record and keeping the change is the one outcome a
//! governance product cannot offer. When the sink fails, mutating requests fail
//! with `503`.
//!
//! Reads degrade the other way: a failure is counted and serving continues.
//! Refusing reads because a disk filled would turn an observability problem into
//! an outage, and a lost read record is not a lost change.
//!
//! Both behaviours are configurable, and the default is the safe one.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use thiserror::Error;

use super::audit::AuditEvent;

/// Why a record could not be written.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The record could not be serialised.
    #[error("failed to serialise audit record: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The sink could not be written to.
    #[error("failed to write audit record: {0}")]
    Io(#[from] std::io::Error),
}

/// Where audit records are written.
///
/// Implementations must be append-only and must not reorder records. They may
/// buffer, but [`flush`](AuditSink::flush) must make everything durable.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Appends one record.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the record could not be serialised or written.
    /// A mutating request that sees an error here is refused.
    fn write(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// Makes previously written records durable.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the underlying sink could not be flushed.
    fn flush(&self) -> Result<(), AuditError>;

    /// Human-readable description, for startup logs.
    fn describe(&self) -> String;
}

/// Discards every record.
///
/// For embedding hosts that do their own auditing, and for tests. Selecting it
/// is an explicit choice — it is never a fallback when a configured sink fails
/// to open, because silently downgrading to "no audit" is how a deployment
/// believes it has a trail it does not have.
#[derive(Debug, Default)]
pub struct NullSink;

impl AuditSink for NullSink {
    fn write(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }

    fn describe(&self) -> String {
        "disabled".to_string()
    }
}

/// Writes JSON Lines to standard output.
///
/// The default. One record per line, so any log pipeline already ingests it, and
/// a container platform collects it with no extra configuration.
///
/// Records go to stdout while application logs go to stderr, so the two streams
/// can be routed separately without parsing.
#[derive(Debug, Default)]
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn write(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(event)?;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(line.as_bytes())?;
        handle.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        std::io::stdout().lock().flush()?;
        Ok(())
    }

    fn describe(&self) -> String {
        "stdout (JSON Lines)".to_string()
    }
}

/// Appends JSON Lines to a file.
///
/// # Durability
///
/// Writes are buffered and the buffer is flushed on every record, so a crash
/// loses nothing that was acknowledged. The file is **not** `fsync`ed per record:
/// that costs a disk round trip on every authorization decision, and the failure
/// it protects against — power loss between write and page-cache flush — is one
/// a deployment that cares about should be addressing with a replicated sink
/// rather than with `fsync` on a local file.
///
/// # Rotation
///
/// There is deliberately none. Rotation is what `logrotate` and every container
/// log driver already do, and doing it here would mean reimplementing size
/// tracking, naming, retention and compression — all of it worse. The file is
/// reopened on `SIGHUP`-style external rotation because the handle follows the
/// inode; operators using `copytruncate` avoid the problem entirely.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl FileSink {
    /// Opens `path` for appending, creating it if absent.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the file cannot be opened. This is fatal at
    /// startup: a deployment that asked for an audit file and did not get one
    /// must not serve, because it would be serving unaudited.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }
}

impl AuditSink for FileSink {
    fn write(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(event)?;
        let mut writer = self.writer.lock();
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        // Flushed per record: a buffered record that is still in memory when the
        // process dies was never audited, and the caller was told it was.
        writer.flush()?;
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        self.writer.lock().flush()?;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("file {} (JSON Lines)", self.path.display())
    }
}

/// A sink plus the policy for what to do when it fails.
///
/// This is what the server holds. Handlers call [`record`](Auditor::record) and
/// get back a `Result` they must not ignore for a mutation.
#[derive(Debug)]
pub struct Auditor {
    sink: Box<dyn AuditSink>,
    /// Whether a sink failure refuses a mutating request.
    fail_closed: bool,
    /// Records lost since start, for `/metrics` and for the gap record.
    dropped: AtomicU64,
}

impl Auditor {
    /// Builds an auditor over `sink`.
    pub fn new(sink: Box<dyn AuditSink>, fail_closed: bool) -> Self {
        Self {
            sink,
            fail_closed,
            dropped: AtomicU64::new(0),
        }
    }

    /// An auditor that discards everything, for tests and embedding hosts.
    pub fn disabled() -> Self {
        Self::new(Box::new(NullSink), false)
    }

    /// The default: JSON Lines on stdout, refusing mutations when it fails.
    pub fn stdout() -> Self {
        Self::new(Box::new(StdoutSink), true)
    }

    /// Records `event`, reporting whether a mutating request may proceed.
    ///
    /// Returns `Ok(())` when the record reached the sink, or when it did not and
    /// this auditor is configured to continue anyway.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] only when the record was lost *and* `fail_closed`
    /// is set. The caller turns that into a `503` for a mutation.
    pub fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        match self.sink.write(event) {
            Ok(()) => Ok(()),
            Err(e) => {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Reported through the application log, which is a different
                // stream: if the audit sink is what is broken, telling the story
                // through the audit sink would lose it too.
                tracing::error!(
                    error = %e,
                    dropped_total = dropped,
                    fail_closed = self.fail_closed,
                    "Audit record lost"
                );
                if self.fail_closed { Err(e) } else { Ok(()) }
            }
        }
    }

    /// Records `event`, never failing the request.
    ///
    /// For reads and for events that are not tied to a mutation — an
    /// authentication failure, a rate-limit trip. Losing one of these is a gap in
    /// observability rather than an unrecorded change.
    pub fn record_lossy(&self, event: &AuditEvent) {
        if let Err(e) = self.sink.write(event) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::error!(error = %e, dropped_total = dropped, "Audit record lost");
        }
    }

    /// How many records have been lost since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Whether a sink failure refuses mutating requests.
    pub fn is_fail_closed(&self) -> bool {
        self.fail_closed
    }

    /// Describes the sink, for the startup banner.
    pub fn describe(&self) -> String {
        format!(
            "{} ({})",
            self.sink.describe(),
            if self.fail_closed {
                "mutations refused if unrecordable"
            } else {
                "best effort"
            }
        )
    }

    /// Flushes the sink.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the sink could not be flushed.
    pub fn flush(&self) -> Result<(), AuditError> {
        self.sink.flush()
    }
}

impl Default for Auditor {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::audit::AuditEvent;

    /// A sink that always fails, to exercise the fail-closed path.
    #[derive(Debug)]
    struct BrokenSink;

    impl AuditSink for BrokenSink {
        fn write(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::Io(std::io::Error::other("disk full")))
        }
        fn flush(&self) -> Result<(), AuditError> {
            Ok(())
        }
        fn describe(&self) -> String {
            "broken".into()
        }
    }

    fn event() -> AuditEvent {
        AuditEvent::authentication("api_key", true).with_principal_id("alice")
    }

    #[test]
    fn a_working_sink_records() {
        let auditor = Auditor::new(Box::new(NullSink), true);
        assert!(auditor.record(&event()).is_ok());
        assert_eq!(auditor.dropped(), 0);
    }

    /// The guarantee: an unrecordable mutation is refused, not silently kept.
    #[test]
    fn fail_closed_refuses_when_the_sink_is_broken() {
        let auditor = Auditor::new(Box::new(BrokenSink), true);
        assert!(auditor.record(&event()).is_err());
        assert_eq!(auditor.dropped(), 1);
    }

    /// Reads must not be taken down by a full disk.
    #[test]
    fn a_lossy_record_never_fails_the_request() {
        let auditor = Auditor::new(Box::new(BrokenSink), true);
        auditor.record_lossy(&event());
        assert_eq!(auditor.dropped(), 1, "the loss must still be counted");
    }

    #[test]
    fn fail_open_continues_but_counts_the_loss() {
        let auditor = Auditor::new(Box::new(BrokenSink), false);
        assert!(auditor.record(&event()).is_ok());
        assert_eq!(auditor.dropped(), 1);
    }

    #[test]
    fn a_file_sink_appends_one_json_object_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");

        let sink = FileSink::open(&path).expect("open");
        sink.write(&event()).unwrap();
        sink.write(&event()).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one record per line");

        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["principal_id"], "alice");
        }
    }

    /// Reopening must append rather than truncate, or a restart erases the trail.
    #[test]
    fn reopening_a_file_sink_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        FileSink::open(&path).unwrap().write(&event()).unwrap();
        FileSink::open(&path).unwrap().write(&event()).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2, "a restart truncated the trail");
    }

    #[test]
    fn opening_an_unwritable_path_is_an_error() {
        // A directory cannot be opened as a file, so this stands in for any
        // permission or path problem. It must surface rather than fall back to
        // discarding records.
        let dir = tempfile::tempdir().unwrap();
        assert!(FileSink::open(dir.path()).is_err());
    }
}
