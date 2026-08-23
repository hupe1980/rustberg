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

    // On Windows a bare `C:\...` path has its drive letter read as a URL scheme
    // by the storage layer, so hand back a file:// URL there.
    #[cfg(windows)]
    {
        format!("file:///{}", path.display().to_string().replace('\\', "/"))
    }

    #[cfg(not(windows))]
    {
        path.display().to_string()
    }
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
