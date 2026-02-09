use tempfile::TempDir;

/// Creates a temporary directory path suitable for use as a warehouse location.
///
/// On Windows, this returns a `file://` URL to avoid the drive letter being
/// interpreted as a URL scheme by iceberg's file I/O layer.
///
/// # Panics
///
/// Panics if the system's temporary directory cannot be created or contains
/// non-UTF-8 characters. This is called at startup and test time only.
pub fn temp_path() -> String {
    let temp_dir = TempDir::new().expect("Failed to create temporary directory for warehouse");
    let path = temp_dir.path();

    // On Windows, convert to file:// URL to avoid drive letter being treated as scheme
    #[cfg(windows)]
    {
        // Convert Windows path to file:// URL format
        // C:\path\to\dir -> file:///C:/path/to/dir
        let path_str = path
            .to_str()
            .expect("Temporary directory path contains non-UTF-8 characters");
        format!("file:///{}", path_str.replace('\\', "/"))
    }

    #[cfg(not(windows))]
    {
        path.to_str()
            .expect("Temporary directory path contains non-UTF-8 characters")
            .to_string()
    }
}
