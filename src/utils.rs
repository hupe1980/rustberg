/// Returns a unique, unused path suitable as a default warehouse location.
///
/// The directory is **not** created here — whoever opens the warehouse creates
/// it. Note that `TempDir` is unsuitable: its guard deletes the directory when it
/// drops, which would be before the caller ever opens the path.
///
/// Used when no warehouse is configured, which means development and tests: a
/// server started with no configuration should run, not fail.
pub fn temp_path() -> String {
    let path = std::env::temp_dir().join(format!("rustberg-{}", uuid::Uuid::new_v4()));

    // A bare `C:\...` has its drive letter read as a URL scheme by the storage
    // layer, so this is handed back as a URL on Windows. Built by the one rule
    // that knows where the third slash goes; `location::path_from_url` is its
    // inverse.
    #[cfg(windows)]
    {
        crate::location::url_from_path(&path)
    }

    #[cfg(not(windows))]
    {
        path.display().to_string()
    }
}

/// Line endings as the documentation gates read them.
///
/// Every gate that checks the documentation against the code scans text for
/// structure — a blank line ending a table, the closing brace of a `match`, a
/// fenced block. Git checks out with CRLF on Windows by default, so a scanner
/// looking for `"\n\n"` finds nothing and the gate fails on one platform while
/// passing on the others. The gates are about the *content*, so line endings are
/// normalised on the way in rather than pinned in the working tree, and the
/// checks hold however the file arrived.
///
/// Needed for `include_str!` as much as for a read: it embeds the bytes on disk
/// at compile time, so a CRLF checkout compiles CRLF into the binary.
#[cfg(test)]
#[must_use]
pub(crate) fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Reads a file this repository ships, with line endings normalised.
///
/// See [`normalize_newlines`].
#[cfg(test)]
pub(crate) fn read_repo_text(path: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    std::fs::read_to_string(path).map(|text| normalize_newlines(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_unique() {
        assert_ne!(temp_path(), temp_path());
    }

    /// The path must not already exist — it is a location to create, not a
    /// directory that was created and then deleted.
    #[test]
    fn path_does_not_exist_yet() {
        let p = temp_path();
        let raw = p.strip_prefix("file:///").unwrap_or(&p);
        assert!(!std::path::Path::new(raw).exists());
    }

    #[test]
    fn path_is_usable_as_a_directory() {
        let p = temp_path();
        let raw = p.strip_prefix("file:///").unwrap_or(&p);
        std::fs::create_dir_all(raw).expect("path must be creatable");
        assert!(std::path::Path::new(raw).is_dir());
        let _ = std::fs::remove_dir_all(raw);
    }
}
