# Changelog

All notable changes to Rustberg are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, a minor bump may carry breaking changes.

## [0.3.0] - 2026-09-18

Correctness release, from an audit of the enforcement paths. Three defects, all
in the direction that grants or discloses more than policy intended, plus two
controls that make a claim check itself.

### Fixed

- **A signed request could address an object outside the table it was authorized
  for.** Containment dropped empty path segments before comparing, so
  `https://bucket.s3…//wh/db/t/x` was checked as the key `wh/db/t/x` — inside the
  table — while the signature covered `/wh/db/t/x`, which no table contains. An
  object-store key is an opaque byte string and a doubled slash is part of it, so
  empty segments are now preserved for every scheme but `file`, where POSIX
  really does collapse them. This restores the rule the signer is built on: the
  string checked, the string signed and the string handed back are one string.
- **`planTableScan` refused a table whose `loadTable` had told the client to plan
  server-side.** A `@row_filter` naming a column the table does not have — the
  ordinary shape of a tenant-wide permit — was published as the constant `false`
  on `loadTable` and answered `403` by the planner. Such a branch now selects no
  files, which is what the wire already said. The published restriction, the
  scan task's `residual-filter` and the predicate the plan prunes by all come
  from one function, so they cannot disagree again.
- **A masked column could be dropped from `read-restrictions`.** Which field
  encloses which was inferred by splitting the dotted name Iceberg renders
  nesting with, and a top-level column legitimately called `user.ssn` was treated
  as a child of a struct called `user`. A policy masking both published a
  projection for `user` alone, so the column it named by hand came back unmasked.
  Ancestry now comes from the schema's own structure.

### Added

- **`referenced-by` is honoured on every load.** The spec's view-chain parameter —
  the views a table or view was reached through, outermost first — is parsed and
  recorded in the audit record as `referenced_by`, so the trail can answer *how
  did this request say it got here* and not only *what did it touch*.

  It is a caller's claim and grants nothing: every load is still authorized
  against the caller alone, and the chain is recorded, never consulted. The raw
  parameter is split on commas **before** it is percent-decoded, because a view
  name containing a comma arrives as `%2C` and decoding first turns one view into
  two. A chain that cannot be read is dropped rather than refused, and an absent
  one leaves the field off the record entirely.

- **A daily check that upstream specifications have not moved.** The Iceberg REST
  OpenAPI document carries no version, lives on a branch and produces no release
  event, so six fields have landed in it without anything firing. The four
  documents every conformance claim is read from are now pinned by digest in
  `.github/spec-pins.toml`, re-fetched by a scheduled `spec-drift` job, and a move
  fails the build. `just spec-check` asks the same question by hand;
  `just spec-pins` re-stamps after the change has been read.

  It pins digests rather than committing the documents because the retrieved
  corpus is gitignored, so a CI checkout has nothing to diff against. Rendered
  HTML pages are deliberately excluded: they re-render on every site build, and a
  check that cries wolf is one nobody reads.

### Security

- **`rustls` 0.23.43 → 0.23.45**, for
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285): TLS 1.3
  handshake messages were accepted across encryption-level boundaries. The
  transcript stays authenticated, so a handshake could not be altered or
  completed by a network attacker; the effect is that a peer could send in
  plaintext what should have been encrypted.

### Changed

- **Breaking (wire):** a scan task's `residual-filter` now spells its policy half
  with `left`/`right` and an `IdReference`, rather than the deprecated
  `term`/`value` form. It is the same predicate and the same form the table's
  `read-restrictions` already carried — both are built by one function now, so
  they cannot disagree — but a client that pattern-matched on `term` will not
  recognise it.
- **Breaking:** a location containing an empty path segment is now refused rather
  than silently normalised. `s3://bucket//wh` and `s3://bucket/wh` are different
  prefixes. A trailing slash on a warehouse remains notational, and `file://`
  paths are unaffected.
- `rustberg policy verify` is **not** added, but the reasoning that said policy
  overlap analysis was impossible has been corrected: it is decidable for Cedar,
  and needs an SMT solver this binary deliberately does not carry.

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
