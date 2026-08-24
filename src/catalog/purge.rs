//! Deleting the files a dropped table referenced, and nothing else.
//!
//! # Why this is not `iceberg::drop_table_data`
//!
//! Upstream's helper walks the metadata, collects every path it finds and
//! deletes all of them. That is right for a *client*, which deletes its own
//! table with its own credentials.
//!
//! A catalog deletes with the **server's** storage role, on behalf of a caller,
//! using paths the caller wrote. Two of those come straight off a commit — a
//! manifest list, a Puffin file — and [`location::LocationBound::ensure_commit`]
//! confines them. The one it cannot confine is the **contents of a manifest**:
//! checking what an engine's Avro file lists would mean reading every manifest on
//! every commit, putting the catalog in the data path on the write side.
//!
//! So the check moves to where it is cheap and exact. A purge already reads the
//! manifests; filtering costs a string comparison per path. A caller that names
//! another tenant's data file in its own manifest gets an orphan, not a
//! deletion.
//!
//! # "The table's own" is its `location`, and nothing else
//!
//! Not the warehouse — that is where the other tenants are, so it is what the
//! server's role already reaches and no bound at all.
//!
//! And deliberately not `write.data.path` or `write.metadata.path`. A property is
//! client-supplied like every other input: a table naming `s3://wh/other-tenant/`
//! as its data path moves this hole one field along. Confining them to the
//! warehouse does not help, for the reason above; confining them to the table's
//! location makes them redundant.
//!
//! # Skipping is the safe direction
//!
//! A path outside the table's location is **not deleted**, and is counted in a
//! warning. That leaves an orphaned file, which costs storage and can be found.
//! The other way deletes a file this table never owned, which cannot be undone.
//! A deployment that separates data from metadata pays for it here, loudly.
//!
//! # A file that cannot be read gets the same answer, for the same reason
//!
//! A manifest list or a manifest this purge cannot open is one whose data files
//! it cannot enumerate — and the answer to "a file I cannot account for" is
//! already *leave it and say so*. Failing the whole purge instead is worse than
//! it looks. The metadata naming the files to delete is reachable only through
//! the registry entry being removed, so the entry goes first and the walk
//! follows; aborting the walk therefore answers `500` for a drop that already
//! happened, and the client that retries is told the table does not exist. The
//! ordinary way to reach it is a snapshot whose files somebody expired out of
//! band, which is not this server's failure at all.
//!
//! [`location::LocationBound::ensure_commit`]: crate::location::LocationBound::ensure_commit

use std::collections::HashSet;

use futures::{StreamExt, stream};
use iceberg::table::Table;
use iceberg::{Error, ErrorKind, Result};

/// Table properties that may name a prefix outside the table's own location.
///
/// Read only to *warn* about them — see the module docs for why they are not
/// treated as storage the table owns.
const WRITE_PATH_PROPERTIES: [&str; 2] = ["write.data.path", "write.metadata.path"];

/// How many manifests are read at once while collecting the data files a purge
/// covers.
///
/// Matches upstream's delete concurrency, for the same reason it chose that
/// number: an object store answers these in parallel, and a serial loop over a
/// large table is the slowest part of a drop. The deletes themselves are handed
/// to `FileIO::delete_stream`, which does its own batching.
const MANIFEST_READ_CONCURRENCY: usize = 10;

/// Deletes the files `table` references, confined to the table's own location.
///
/// # Errors
///
/// Whatever the storage layer returned. A file that is simply absent is not an
/// error — a purge races nothing, but it does follow a drop that may itself have
/// followed a partial one.
pub async fn purge_table_data(table: &Table) -> Result<()> {
    let metadata = table.metadata_ref();
    let root = metadata.location().to_string();
    warn_about_write_paths(table);

    let mut manifest_lists: HashSet<String> = HashSet::new();
    let mut manifests: HashSet<String> = HashSet::new();

    // Every snapshot, not only the current one: a purge is the end of the
    // table, so the files an expired snapshot still references are the table's
    // to remove.
    // Bounded, like the manifest reads below: unbounded would open one
    // object-store request per snapshot at once, and a table keeps every
    // snapshot until somebody expires it.
    // Cloned into owned handles (a `SnapshotRef` is an `Arc`) before the stream,
    // so each task owns its snapshot rather than borrowing the iterator's item
    // for a lifetime the combinator cannot name.
    let snapshots: Vec<iceberg::spec::SnapshotRef> = metadata.snapshots().cloned().collect();

    let loaded: Vec<(String, Option<_>)> = stream::iter(snapshots)
        .map(|snapshot| async move {
            let location = snapshot.manifest_list().to_string();
            match table.manifest_list_reader(&snapshot).load().await {
                Ok(list) => (location, Some(list)),
                // Best-effort, per the module docs: the files this list names
                // are left as orphans rather than the whole purge failing after
                // the table has already been dropped.
                Err(e) => {
                    tracing::warn!(
                        table = %table.identifier(),
                        manifest_list = %location,
                        error = %e,
                        "Could not read a manifest list while purging; the files it names \
                         are left in place"
                    );
                    (location, None)
                }
            }
        })
        .buffer_unordered(MANIFEST_READ_CONCURRENCY)
        .collect()
        .await;

    // A list still gets deleted when it was its *contents* that could not be
    // read: an unreadable manifest list is not a file this table stops owning.
    let mut unreadable = 0usize;
    for (list_location, list) in loaded {
        if !list_location.is_empty() {
            manifest_lists.insert(list_location);
        }
        match list {
            Some(list) => {
                for manifest in list.entries() {
                    manifests.insert(manifest.manifest_path.clone());
                }
            }
            None => unreadable += 1,
        }
    }

    // Data files come out of the manifests, and are the only paths here this
    // catalog never wrote itself.
    //
    // `gc.enabled` is the table's own statement that its data files are not
    // shared with another table. Upstream honours it and so does this: a
    // deployment that points two tables at one set of files has said so, and a
    // purge must not act on the assumption it did not.
    let mut skipped = 0usize;
    if metadata.table_properties()?.gc_enabled {
        let (data_files, unreadable_manifests) = read_data_file_paths(table, &manifests).await;
        unreadable += unreadable_manifests;
        skipped += delete_confined(table, &root, data_files).await?;
    }

    skipped += delete_confined(table, &root, manifests).await?;
    skipped += delete_confined(table, &root, manifest_lists).await?;
    skipped += delete_confined(
        table,
        &root,
        metadata
            .metadata_log()
            .iter()
            .map(|entry| entry.metadata_file.clone()),
    )
    .await?;
    skipped += delete_confined(
        table,
        &root,
        metadata
            .statistics_iter()
            .map(|stats| stats.statistics_path.clone()),
    )
    .await?;
    skipped += delete_confined(
        table,
        &root,
        metadata
            .partition_statistics_iter()
            .map(|stats| stats.statistics_path.clone()),
    )
    .await?;

    // The pointer this catalog wrote, last, so a failure above leaves the table
    // still readable rather than dangling.
    if let Some(location) = table.metadata_location() {
        skipped += delete_confined(table, &root, [location.to_string()]).await?;
    }

    if unreadable > 0 {
        tracing::warn!(
            table = %table.identifier(),
            unreadable,
            location = %root,
            "A purge could not read every manifest this table referenced, so the data \
             files those manifests name were not deleted. They are orphans now. The \
             ordinary cause is a snapshot whose files were expired outside this catalog; \
             if this names every manifest, check the catalog's read access to its own \
             warehouse."
        );
    }

    if skipped > 0 {
        // Warned rather than failed. The drop already happened — the caller
        // asked for it and was permitted — and refusing now would leave the
        // catalog entry gone and the purge half done with nothing to retry.
        tracing::warn!(
            table = %table.identifier(),
            skipped,
            location = %root,
            "A purge skipped files outside the table's own storage. They were \
             referenced by this table's metadata but do not live under it, so \
             deleting them could destroy another table's data. They are orphans \
             now and can be removed by hand."
        );
    }

    Ok(())
}

/// Names the write-path properties this table declares outside its own location.
///
/// They are not honoured (see the module docs), so the files under them survive
/// the purge. Said once, at the moment it becomes true, because "the purge left
/// data behind" and "this table writes its data somewhere else" are the same
/// fact and an operator reading only the first cannot get to the second.
fn warn_about_write_paths(table: &Table) {
    let metadata = table.metadata();
    let location = metadata.location();

    for property in WRITE_PATH_PROPERTIES {
        if let Some(declared) = metadata.properties().get(property)
            && !crate::location::is_within(location, declared)
        {
            tracing::warn!(
                table = %table.identifier(),
                property,
                declared,
                location,
                "This table writes files outside its own location, and a purge \
                 deletes only what is under that location. The files under the \
                 declared path are not removed — a catalog cannot tell that \
                 prefix apart from another table's."
            );
        }
    }
}

/// Deletes each path that is inside `root`, returning how many were not.
async fn delete_confined(
    table: &Table,
    root: &str,
    paths: impl IntoIterator<Item = String>,
) -> Result<usize> {
    let (owned, skipped): (Vec<String>, Vec<String>) = paths
        .into_iter()
        .partition(|path| crate::location::is_within(root, path));

    for path in &skipped {
        tracing::warn!(
            table = %table.identifier(),
            path,
            "Not deleting a file this table references but does not own"
        );
    }

    if !owned.is_empty() {
        table
            .file_io()
            .delete_stream(stream::iter(owned))
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "Failed to delete a table's files").with_source(e)
            })?;
    }

    Ok(skipped.len())
}

/// Every data-file path the manifests name, and how many manifests could not be
/// read.
///
/// Read here rather than streamed straight into the delete, because the
/// containment filter has to see each path before anything is removed.
///
/// Infallible by design. One unreadable manifest means the data files *it* names
/// are not enumerated; it does not mean the other manifests' files should be
/// kept, and it must not fail a drop that has already happened — see the module
/// docs.
async fn read_data_file_paths(table: &Table, manifests: &HashSet<String>) -> (Vec<String>, usize) {
    let io = table.file_io();

    let per_manifest: Vec<std::result::Result<Vec<String>, (String, Error)>> =
        stream::iter(manifests.iter().cloned())
            .map(|path| async move {
                let read = async {
                    let bytes = io.new_input(&path)?.read().await?;
                    let manifest = iceberg::spec::Manifest::parse_avro(&bytes)?;
                    Ok::<_, Error>(
                        manifest
                            .entries()
                            .iter()
                            .map(|entry| entry.data_file().file_path().to_string())
                            .collect::<Vec<String>>(),
                    )
                };
                read.await.map_err(|e| (path, e))
            })
            .buffer_unordered(MANIFEST_READ_CONCURRENCY)
            .collect()
            .await;

    let mut paths = Vec::new();
    let mut unreadable = 0usize;
    for outcome in per_manifest {
        match outcome {
            Ok(files) => paths.extend(files),
            Err((path, e)) => {
                unreadable += 1;
                tracing::warn!(
                    table = %table.identifier(),
                    manifest = %path,
                    error = %e,
                    "Could not read a manifest while purging; the data files it names are \
                     left in place"
                );
            }
        }
    }

    (paths, unreadable)
}
