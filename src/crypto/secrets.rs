//! Secure secret handling with automatic memory clearing.
//!
//! This module provides wrappers for sensitive data that:
//! - Automatically zeros memory when dropped (zeroize)
//! - Prevents accidental logging/printing (Debug redaction)
//! - Provides type safety for different secret types

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret byte array that is automatically zeroed when dropped.
///
/// This wrapper ensures that sensitive data like encryption keys,
/// API key hashes, and credentials are securely cleared from memory
/// when no longer needed.
///
/// # Security Properties
/// - **Zeroize on Drop**: Memory is overwritten with zeros when dropped
/// - **Debug Redaction**: Never prints actual secret contents
/// - **Clone Safety**: Clone also creates a zeroizable copy
///
/// # Example
/// ```
/// use rustberg::crypto::secrets::SecretBytes;
///
/// let key = SecretBytes::new(vec![0u8; 32]);
/// assert_eq!(key.expose().len(), 32);
/// // Key is automatically zeroed when `key` goes out of scope
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Creates a new secret from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Creates a new secret from a slice (copies data).
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Exposes the secret bytes for use.
    ///
    /// **WARNING**: Only call this when you actually need the secret.
    /// The exposed reference should not be stored or logged.
    #[inline]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the length of the secret.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED, {} bytes])", self.inner.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SECRET]")
    }
}

/// A secret string that is automatically zeroed when dropped.
///
/// Use this for passwords, tokens, and other string secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Creates a new secret string.
    pub fn new(data: String) -> Self {
        Self { inner: data }
    }

    /// Exposes the secret string for use.
    ///
    /// **WARNING**: Only call this when you actually need the secret.
    #[inline]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Returns the length of the secret string.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the secret string is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED, {} chars])", self.inner.len())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SECRET]")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// A fixed-size secret array that is automatically zeroed when dropped.
///
/// Use this for encryption keys and other fixed-size secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    /// Creates a new secret key from an array.
    pub fn new(data: [u8; N]) -> Self {
        Self { inner: data }
    }

    /// Exposes the secret key for use.
    ///
    /// **WARNING**: Only call this when you actually need the key.
    #[inline]
    pub fn expose(&self) -> &[u8; N] {
        &self.inner
    }
}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{}>([REDACTED])", N)
    }
}

impl<const N: usize> fmt::Display for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED KEY]")
    }
}

/// Type alias for a 256-bit (32-byte) encryption key.
pub type EncryptionKey = SecretKey<32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_debug_redacted() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4, 5]);
        let debug = format!("{:?}", secret);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1"));
    }

    #[test]
    fn test_secret_string_debug_redacted() {
        let secret = SecretString::new("password123".to_string());
        let debug = format!("{:?}", secret);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("password"));
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let secret = EncryptionKey::new([0u8; 32]);
        let debug = format!("{:?}", secret);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_secret_bytes_expose() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretBytes::new(data.clone());
        assert_eq!(secret.expose(), &data[..]);
    }

    #[test]
    fn test_secret_string_expose() {
        let secret = SecretString::new("password".to_string());
        assert_eq!(secret.expose(), "password");
    }

    #[test]
    fn test_secret_key_expose() {
        let key = [42u8; 32];
        let secret = EncryptionKey::new(key);
        assert_eq!(secret.expose(), &key);
    }

    #[test]
    fn test_secret_bytes_clone() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        let cloned = secret.clone();
        assert_eq!(secret.expose(), cloned.expose());
    }

    #[test]
    fn test_secret_string_from_str() {
        let secret: SecretString = "test".into();
        assert_eq!(secret.expose(), "test");
    }

    #[test]
    fn test_secret_bytes_len() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secret_string_len() {
        let secret = SecretString::new("hello".to_string());
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_empty_secrets() {
        let bytes = SecretBytes::new(vec![]);
        assert!(bytes.is_empty());

        let string = SecretString::new(String::new());
        assert!(string.is_empty());
    }
}
