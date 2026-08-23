//! Input validation utilities.
//!
//! This module provides validation functions to protect against malicious
//! or malformed input that could cause DoS or other security issues.
//!
//! # Security Considerations
//!
//! The validation functions protect against:
//! - **DoS via oversized inputs**: Length limits on names and properties
//! - **Path traversal attacks**: Blocks `..` and absolute paths
//! - **Null byte injection**: Rejects embedded null characters
//! - **Control character injection**: Rejects non-printable characters
//! - **Reserved name attacks**: Blocks Windows reserved names (CON, PRN, etc.)
//! - **Hidden file creation**: Blocks names starting with `.`

use crate::error::{AppError, Result};

/// Maximum length for a namespace or table name segment.
pub const MAX_NAME_LENGTH: usize = 255;

/// Maximum depth for hierarchical namespaces.
pub const MAX_NAMESPACE_DEPTH: usize = 10;

/// Maximum number of properties that can be set on a namespace or table.
pub const MAX_PROPERTIES_COUNT: usize = 100;

/// Maximum length for a property key.
pub const MAX_PROPERTY_KEY_LENGTH: usize = 255;

/// Maximum length for a property value.
pub const MAX_PROPERTY_VALUE_LENGTH: usize = 4096;

/// Windows reserved device names that are forbidden regardless of extension.
/// These could cause issues when metadata is stored on Windows filesystems.
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Characters allowed in namespace/table names (alphanumeric, underscore, hyphen).
fn is_valid_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Checks if a name is a Windows reserved device name.
fn is_windows_reserved(name: &str) -> bool {
    // Check without extension (CON.txt is also reserved)
    let base_name = name.split('.').next().unwrap_or(name);
    WINDOWS_RESERVED_NAMES
        .iter()
        .any(|&reserved| base_name.eq_ignore_ascii_case(reserved))
}

/// Validates a single name segment (namespace level or table name).
///
/// # Security
///
/// This function protects against:
/// - Empty names
/// - Oversized names (DoS)
/// - Path traversal (`..`)
/// - Null byte injection
/// - Control characters
/// - Hidden files (`.` prefix)
/// - Windows reserved names
///
/// # Errors
///
/// Returns an error if the name fails any security check.
pub fn validate_name(name: &str, context: &str) -> Result<()> {
    // Check for null bytes (could be used to truncate strings in C-based systems)
    if name.contains('\0') {
        return Err(AppError::BadRequest(format!(
            "{context} contains null byte"
        )));
    }

    // Check for control characters (could cause log injection or display issues)
    if name.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "{context} contains control characters"
        )));
    }

    if name.is_empty() {
        return Err(AppError::BadRequest(format!("{context} cannot be empty")));
    }

    if name.len() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "{context} exceeds maximum length of {MAX_NAME_LENGTH} characters"
        )));
    }

    // Path traversal check
    if name == ".." || name.contains("../") || name.contains("..\\") {
        return Err(AppError::BadRequest(format!(
            "{context} contains path traversal pattern"
        )));
    }

    if name.starts_with('.') {
        return Err(AppError::BadRequest(format!(
            "{context} cannot start with a dot"
        )));
    }

    // Check for Windows reserved names (cross-platform compatibility)
    if is_windows_reserved(name) {
        return Err(AppError::BadRequest(format!(
            "{context} uses a reserved name that is not allowed"
        )));
    }

    if let Some(invalid_char) = name.chars().find(|&c| !is_valid_name_char(c)) {
        return Err(AppError::BadRequest(format!(
            "{context} contains invalid character: '{invalid_char}'"
        )));
    }

    Ok(())
}

/// Validates a namespace identifier (list of name segments).
///
/// # Errors
///
/// Returns an error if:
/// - Namespace is empty
/// - Namespace exceeds maximum depth
/// - Any segment fails validation
pub fn validate_namespace(namespace: &[String]) -> Result<()> {
    if namespace.is_empty() {
        return Err(AppError::BadRequest(
            "Namespace cannot be empty".to_string(),
        ));
    }

    if namespace.len() > MAX_NAMESPACE_DEPTH {
        return Err(AppError::BadRequest(format!(
            "Namespace exceeds maximum depth of {MAX_NAMESPACE_DEPTH} levels"
        )));
    }

    for (i, segment) in namespace.iter().enumerate() {
        validate_name(segment, &format!("Namespace segment {}", i + 1))?;
    }

    Ok(())
}

/// Validates a table name.
pub fn validate_table_name(name: &str) -> Result<()> {
    validate_name(name, "Table name")
}

/// Validates a properties map.
///
/// # Errors
///
/// Returns an error if:
/// - Too many properties
/// - Any key exceeds maximum length
/// - Any value exceeds maximum length
pub fn validate_properties(properties: &std::collections::HashMap<String, String>) -> Result<()> {
    if properties.len() > MAX_PROPERTIES_COUNT {
        return Err(AppError::BadRequest(format!(
            "Too many properties (max: {MAX_PROPERTIES_COUNT})"
        )));
    }

    for (key, value) in properties {
        if key.len() > MAX_PROPERTY_KEY_LENGTH {
            return Err(AppError::BadRequest(format!(
                "Property key '{key}' exceeds maximum length of {MAX_PROPERTY_KEY_LENGTH}"
            )));
        }
        if value.len() > MAX_PROPERTY_VALUE_LENGTH {
            return Err(AppError::BadRequest(format!(
                "Property value for key '{key}' exceeds maximum length of {MAX_PROPERTY_VALUE_LENGTH}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("my_namespace", "test").is_ok());
        assert!(validate_name("my-namespace", "test").is_ok());
        assert!(validate_name("MyNamespace123", "test").is_ok());
        assert!(validate_name("a.b.c", "test").is_ok());
    }

    #[test]
    fn test_validate_name_empty() {
        let result = validate_name("", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(300);
        let result = validate_name(&long_name, "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_name_invalid_chars() {
        let result = validate_name("my namespace", "Namespace");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid character")
        );

        let result = validate_name("my/namespace", "Namespace");
        assert!(result.is_err());

        let result = validate_name("my@namespace", "Namespace");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_name_starts_with_dot() {
        let result = validate_name(".hidden", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start with a dot"));
    }

    #[test]
    fn test_validate_name_null_byte() {
        let result = validate_name("my\0namespace", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null byte"));
    }

    #[test]
    fn test_validate_name_control_char() {
        let result = validate_name("my\nnamespace", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));

        let result = validate_name("my\tnamespace", "Namespace");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_name_path_traversal() {
        let result = validate_name("..", "Namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));

        let result = validate_name("../etc/passwd", "Namespace");
        assert!(result.is_err());

        let result = validate_name("..\\windows\\system32", "Namespace");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_name_windows_reserved() {
        // These should all be rejected for cross-platform safety
        assert!(validate_name("CON", "Name").is_err());
        assert!(validate_name("con", "Name").is_err()); // Case insensitive
        assert!(validate_name("PRN", "Name").is_err());
        assert!(validate_name("AUX", "Name").is_err());
        assert!(validate_name("NUL", "Name").is_err());
        assert!(validate_name("COM1", "Name").is_err());
        assert!(validate_name("LPT1", "Name").is_err());

        // These should be OK (not reserved)
        assert!(validate_name("CONSOLE", "Name").is_ok());
        assert!(validate_name("mycon", "Name").is_ok());
        assert!(validate_name("com10", "Name").is_ok());
    }

    #[test]
    fn test_validate_namespace_valid() {
        assert!(validate_namespace(&["db".to_string()]).is_ok());
        assert!(validate_namespace(&["db".to_string(), "schema".to_string()]).is_ok());
    }

    #[test]
    fn test_validate_namespace_empty() {
        let result = validate_namespace(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_namespace_too_deep() {
        let deep: Vec<String> = (0..15).map(|i| format!("level{i}")).collect();
        let result = validate_namespace(&deep);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum depth"));
    }

    #[test]
    fn test_validate_properties_valid() {
        let mut props = HashMap::new();
        props.insert("key1".to_string(), "value1".to_string());
        props.insert("key2".to_string(), "value2".to_string());
        assert!(validate_properties(&props).is_ok());
    }

    #[test]
    fn test_validate_properties_too_many() {
        let props: HashMap<String, String> = (0..150)
            .map(|i| (format!("key{i}"), format!("value{i}")))
            .collect();
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many"));
    }

    #[test]
    fn test_validate_properties_key_too_long() {
        let mut props = HashMap::new();
        let long_key = "k".repeat(300);
        props.insert(long_key, "value".to_string());
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn test_validate_properties_value_too_long() {
        let mut props = HashMap::new();
        let long_value = "v".repeat(5000);
        props.insert("key".to_string(), long_value);
        let result = validate_properties(&props);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("value"));
    }
}
