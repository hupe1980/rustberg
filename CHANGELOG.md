# Changelog

All notable changes to Rustberg are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, a minor bump may carry breaking changes.

## [0.2.0] - 2026-09-13

Governance release. Rustberg now speaks the Iceberg REST spec's **Read
Restrictions** extension, and a restricted table is delegated at file
granularity instead of being refused delegation outright.

### Added

- **`read-restrictions` on `loadTable`.** A table whose matching permits carry
  `@row_filter` or `@column_mask` returns the spec's `required-row-filter` and
  `required-column-projections`, with columns addressed by field id. It never
  relaxes what is withheld: such a table still receives no storage credential and
  no signer block.
- **`scan-planning-mode: server`** in `config` for a restricted table, which the
  spec defines as requiring the client to plan through `planTableScan`. A client
  that obeys never reads the excluded files' manifests.
- **Pre-signed URLs in scan plans.** For a restricted table, each planned file is
  returned as a pre-signed S3 URL rather than a bare path, scoped to exactly the
  files the policy filter selected. The lifetime is
  `credentials.signing.presign_ttl_seconds` (default `900`).
- **`credentials.signing.presign_ttl_seconds`** configuration key.
- **`RequestSigner::presign_get`**, for read-only query-string signing.

### Changed

- **Column masks resolve to field ids** rather than being compared as names, and
  a mask on a struct now withholds the fields beneath it.
- **A mask that no longer resolves is decided by the table's schema history.** A
  name the table once had and no longer does is refused with `403` — it was
  renamed or dropped, and the mask would otherwise withhold nothing. A name the
  table never had is skipped, so a tenant-wide mask does not break every table it
  does not fit.
- **A policy row filter that cannot be expressed for a table publishes `false`**
  rather than being omitted, so a conforming reader returns no rows instead of
  treating the table as unrestricted.
- **`ETag` on `loadTable` now covers which restrictions apply**, not merely
  whether any do. Two callers restricted differently no longer share a validator.
- **`#![forbid(unsafe_code)]`** is now also applied to the binary crate. It
  previously covered the library only.

### Fixed

- **Masked columns leaked through scan plans after a rename.** A `@column_mask`
  matched by name stopped matching when the column was renamed, so the column's
  statistics — and, for a partition column, its values — were served, while the
  same policy still refused a storage credential for the table.
- **Filters using `IdReference` were silently widened to `AlwaysTrue`.** The
  Iceberg spec deprecated the `term`/`value` predicate form in favour of
  `left`/`right` and `child` with references that may carry a field id. Rustberg
  read the shapes but not the id, so every filter written the preferred way lost
  all partition pruning and returned the whole snapshot. In a policy `@row_filter`
  the same gap rejected the id form at load.
- **A mask on a map key** is now refused. The spec forbids projecting a map key,
  because doing so can collapse or null distinct keys.

### Removed

- `is_masked` and `all_partition_source_columns`, whose callers no longer exist.

### Licence

- Relicensed from **Apache-2.0** to **Apache-2.0 OR MIT**, at the user's option.
  `LICENSE` is replaced by `LICENSE-APACHE` and `LICENSE-MIT`.

## [0.1.1] - 2026-09-09

### Changed

- Moved off the yanked `chacha20` 0.10.1.

### Fixed

- Authority-less `file://` URLs are recognised in location containment.

## [0.1.0]

Initial release.
