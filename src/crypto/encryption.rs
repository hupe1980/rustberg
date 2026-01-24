//! Encryption provider for data-at-rest.
//!
//! Provides AES-256-GCM encryption for sensitive data (API keys, metadata).
//! Uses authenticated encryption to prevent tampering.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use std::sync::Arc;
use thiserror::Error;

/// Nonce size for AES-GCM (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;

/// Errors that can occur during encryption/decryption
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid key length: expected 32 bytes")]
    InvalidKeyLength,
    
    #[error("Invalid ciphertext format")]
    InvalidFormat,
}

pub type Result<T> = std::result::Result<T, EncryptionError>;

/// Trait for encryption providers.
///
/// Implementors provide authenticated encryption for data-at-rest.
pub trait EncryptionProvider: Send + Sync {
    /// Encrypts plaintext data.
    ///
    /// Returns ciphertext with embedded nonce (nonce || ciphertext || tag).
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypts ciphertext data.
    ///
    /// Expects format: nonce || ciphertext || tag
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Returns whether encryption is actually enabled.
    fn is_enabled(&self) -> bool;
}

// ============================================================================
// AES-256-GCM Provider
// ============================================================================

/// AES-256-GCM encryption provider.
///
/// Uses authenticated encryption with associated data (AEAD).
/// - Key: 256-bit (32 bytes)
/// - Nonce: 96-bit (12 bytes, random per message)
/// - Authentication: GMAC tag (128-bit)
///
/// **Security Properties**:
/// - Confidentiality: AES-256
/// - Authenticity: GMAC prevents tampering
/// - Nonce uniqueness: Random nonce per encryption
pub struct Aes256GcmProvider {
    cipher: Aes256Gcm,
}

impl Aes256GcmProvider {
    /// Creates a new provider with the given 256-bit key.
    ///
    /// # Errors
    /// Returns `InvalidKeyLength` if key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }
        
        let key_array = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key_array);
        
        Ok(Self { cipher })
    }
    
    /// Generates a new random 256-bit key.
    ///
    /// **WARNING**: Caller must securely store this key!
    /// Loss of key = permanent data loss.
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}

impl EncryptionProvider for Aes256GcmProvider {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
        
        // Format: nonce || ciphertext (ciphertext includes auth tag)
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Minimum size: nonce + tag (12 + 16 = 28 bytes)
        if ciphertext.len() < NONCE_SIZE + 16 {
            return Err(EncryptionError::InvalidFormat);
        }
        
        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted_data) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let plaintext = self.cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;
        
        Ok(plaintext)
    }
    
    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// Noop Provider (for testing/disabled encryption)
// ============================================================================

/// No-op encryption provider that passes data through unchanged.
///
/// **WARNING**: Only for testing or when encryption is explicitly disabled!
pub struct NoopEncryptionProvider;

impl EncryptionProvider for NoopEncryptionProvider {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
    
    fn is_enabled(&self) -> bool {
        false
    }
}

/// Type alias for thread-safe encryption provider.
pub type SharedEncryptionProvider = Arc<dyn EncryptionProvider>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aes256_encrypt_decrypt() {
        let key = Aes256GcmProvider::generate_key();
        let provider = Aes256GcmProvider::new(&key).unwrap();
        
        let plaintext = b"sensitive API key data";
        let ciphertext = provider.encrypt(plaintext).unwrap();
        
        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[NONCE_SIZE..], plaintext);
        
        // Decryption should recover original
        let decrypted = provider.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_aes256_random_nonces() {
        let key = Aes256GcmProvider::generate_key();
        let provider = Aes256GcmProvider::new(&key).unwrap();
        
        let plaintext = b"test data";
        
        // Encrypt twice, should get different ciphertexts (different nonces)
        let ct1 = provider.encrypt(plaintext).unwrap();
        let ct2 = provider.encrypt(plaintext).unwrap();
        
        assert_ne!(ct1, ct2, "Ciphertexts should differ due to random nonces");
        
        // Both should decrypt correctly
        assert_eq!(provider.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(provider.decrypt(&ct2).unwrap(), plaintext);
    }
    
    #[test]
    fn test_aes256_invalid_key_length() {
        let short_key = [0u8; 16];
        assert!(Aes256GcmProvider::new(&short_key).is_err());
        
        let long_key = [0u8; 64];
        assert!(Aes256GcmProvider::new(&long_key).is_err());
    }
    
    #[test]
    fn test_aes256_tampered_ciphertext() {
        let key = Aes256GcmProvider::generate_key();
        let provider = Aes256GcmProvider::new(&key).unwrap();
        
        let plaintext = b"important data";
        let mut ciphertext = provider.encrypt(plaintext).unwrap();
        
        // Tamper with ciphertext (flip a bit)
        ciphertext[NONCE_SIZE] ^= 0x01;
        
        // Decryption should fail due to authentication tag mismatch
        assert!(provider.decrypt(&ciphertext).is_err());
    }
    
    #[test]
    fn test_aes256_invalid_format() {
        let key = Aes256GcmProvider::generate_key();
        let provider = Aes256GcmProvider::new(&key).unwrap();
        
        // Too short (less than nonce + tag)
        let short_data = [0u8; 10];
        assert!(provider.decrypt(&short_data).is_err());
    }
    
    #[test]
    fn test_noop_provider() {
        let provider = NoopEncryptionProvider;
        let plaintext = b"test data";
        
        let ciphertext = provider.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext, plaintext, "Noop should not encrypt");
        
        let decrypted = provider.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        
        assert!(!provider.is_enabled());
    }
}
