//! Where the catalog writes a table's or a view's next metadata file.
//!
//! Always `<location>/metadata/<version>-<uuid>[.gz].metadata.json`, where
//! `<location>` is the location of the metadata being written.
//!
//! # Why `write.metadata.path` is not followed
//!
//! Iceberg's own location helper honours that table property, and it is an
//! ordinary property: any caller allowed to update the table may set it. The
//! file is written with this server's storage role, so following it would let a
//! property update write wherever that role reaches — outside the table, the
//! tenant or the warehouse. Engines keep the property's meaning for the files
//! they write with their own credentials; only the catalog's own write ignores
//! it, and it is never refused, rewritten or stripped.

use std::str::FromStr;

use iceberg::spec::TableMetadata;
use iceberg::{MetadataLocation, Result};

/// The first metadata file of a new table.
pub(crate) fn first_table(metadata: &TableMetadata) -> Result<MetadataLocation> {
    table_file(metadata, 0)
}

/// The metadata file that follows `current` for this table.
pub(crate) fn next_table(current: &str, metadata: &TableMetadata) -> Result<MetadataLocation> {
    table_file(metadata, version_after(current))
}

/// The first metadata file of a new view. View metadata carries no
/// compression setting.
pub(crate) fn first_view(location: &str) -> String {
    path(location, 0, "")
}

/// The metadata file that follows `current` for a view at `location`.
pub(crate) fn next_view(current: &str, location: &str) -> String {
    path(location, version_after(current), "")
}

/// The codec comes from the metadata because `TableMetadata::write_to` refuses
/// a location whose codec disagrees with the table's property.
fn table_file(metadata: &TableMetadata, version: i32) -> Result<MetadataLocation> {
    let suffix = metadata.metadata_compression_codec()?.suffix()?;
    MetadataLocation::from_str(&path(metadata.location(), version, suffix))
}

fn path(location: &str, version: i32, suffix: &str) -> String {
    format!(
        "{location}/metadata/{version:05}-{}{suffix}.metadata.json",
        uuid::Uuid::new_v4()
    )
}

/// One past the version `current` is named with, or `1` when it does not follow
/// the `<version>-<uuid>.metadata.json` convention — a registered table may
/// point at any file, and the next commit then starts a fresh sequence rather
/// than failing.
fn version_after(current: &str) -> i32 {
    if MetadataLocation::from_str(current).is_err() {
        return 1;
    }
    current
        .rsplit('/')
        .next()
        .and_then(|name| name.split_once('-'))
        .and_then(|(version, _)| version.parse::<i32>().ok())
        .map_or(1, |version| version + 1)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use iceberg::TableCreation;
    use iceberg::spec::{NestedField, PrimitiveType, Schema, TableMetadataBuilder, Type};

    use super::*;

    const LOCATION: &str = "s3://bucket/wh/db/t";

    fn metadata(properties: &[(&str, &str)]) -> TableMetadata {
        let schema = Schema::builder()
            .with_fields(vec![
                NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            ])
            .build()
            .unwrap();
        let properties: HashMap<String, String> = properties
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let creation = TableCreation::builder()
            .name("t".to_string())
            .location(LOCATION.to_string())
            .schema(schema)
            .properties(properties)
            .build();
        TableMetadataBuilder::from_table_creation(creation)
            .unwrap()
            .build()
            .unwrap()
            .metadata
    }

    fn in_metadata_dir(location: &str, version: &str) -> bool {
        location.starts_with(&format!("{LOCATION}/metadata/{version}-"))
    }

    #[test]
    fn metadata_version_advances_across_commits() {
        let metadata = metadata(&[]);
        let mut current = format!(
            "{LOCATION}/metadata/00003-{}.metadata.json",
            uuid::Uuid::new_v4()
        );
        for expected in ["00004", "00005", "00006"] {
            let next = next_table(&current, &metadata).unwrap().to_string();
            assert!(in_metadata_dir(&next, expected), "got {next}");
            current = next;
        }
    }

    #[test]
    fn a_current_file_off_the_convention_restarts_the_sequence() {
        let next = next_table("s3://lake/old/table.json", &metadata(&[]))
            .unwrap()
            .to_string();
        assert!(in_metadata_dir(&next, "00001"), "got {next}");
    }

    #[test]
    fn write_metadata_path_never_moves_the_catalogs_write() {
        for value in [
            "s3://other-bucket/elsewhere",
            "s3://bucket/wh/db/other_table/metadata",
            "s3://bucket/wh/db/t/custom",
            "",
        ] {
            let metadata = metadata(&[("write.metadata.path", value)]);
            let first = first_table(&metadata)
                .unwrap_or_else(|e| panic!("{value:?} must not fail a create: {e}"))
                .to_string();
            assert!(in_metadata_dir(&first, "00000"), "{value:?}: got {first}");
            let next = next_table(&first, &metadata)
                .unwrap_or_else(|e| panic!("{value:?} must not fail a commit: {e}"))
                .to_string();
            assert!(in_metadata_dir(&next, "00001"), "{value:?}: got {next}");
        }
    }

    #[test]
    fn the_compression_codec_still_follows_the_table() {
        let metadata = metadata(&[("write.metadata.compression-codec", "gzip")]);
        let first = first_table(&metadata).unwrap();
        assert!(
            first.to_string().ends_with(".gz.metadata.json"),
            "got {first}"
        );
    }

    #[test]
    fn a_view_follows_the_same_rule() {
        let first = first_view(LOCATION);
        assert!(in_metadata_dir(&first, "00000"), "got {first}");
        let next = next_view(&first, LOCATION);
        assert!(in_metadata_dir(&next, "00001"), "got {next}");
    }
}
