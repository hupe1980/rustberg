use tempfile::TempDir;

pub fn temp_path() -> String {
    let temp_dir = TempDir::new().unwrap();
    temp_dir.path().to_str().unwrap().to_string()
}
