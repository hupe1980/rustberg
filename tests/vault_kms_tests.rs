//! Integration tests for Vault KMS provider using testcontainers.
//!
//! These tests require Docker to be running.

#![cfg(feature = "vault-kms")]

use std::time::Duration;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::hashicorp_vault::HashicorpVault;
use tokio::time::sleep;

/// Test the VaultKmsProvider with a real Vault instance.
///
/// This test:
/// 1. Starts a Vault container in dev mode
/// 2. Enables the Transit secrets engine  
/// 3. Creates a key for encryption
/// 4. Tests data key generation, encryption, and decryption
#[tokio::test]
async fn test_vault_kms_provider_basic_operations() {
    use rustberg::crypto::kms::{KeyManagementService, VaultKmsProvider};

    // Start Vault container in dev mode with root token
    let vault: ContainerAsync<HashicorpVault> = HashicorpVault::default()
        .start()
        .await
        .expect("Failed to start Vault container");

    // Get the connection details
    let host_port = vault.get_host_port_ipv4(8200).await.unwrap();
    let vault_addr = format!("http://127.0.0.1:{}", host_port);
    let root_token = "myroot"; // Default dev mode token from testcontainers-modules

    // Wait for Vault to be ready
    sleep(Duration::from_secs(2)).await;

    // Setup Vault: Enable transit engine and create a key
    let client = reqwest::Client::new();

    // Enable transit secrets engine
    let enable_response = client
        .post(format!("{}/v1/sys/mounts/transit", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({
            "type": "transit"
        }))
        .send()
        .await
        .expect("Failed to enable transit engine");

    assert!(
        enable_response.status().is_success() || enable_response.status().as_u16() == 400,
        "Failed to enable transit: {:?}",
        enable_response.text().await
    );

    // Create a transit key for encryption
    let key_response = client
        .post(format!("{}/v1/transit/keys/rustberg-test-key", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({
            "type": "aes256-gcm96"
        }))
        .send()
        .await
        .expect("Failed to create transit key");

    assert!(
        key_response.status().is_success() || key_response.status().as_u16() == 204,
        "Failed to create key: {:?}",
        key_response.text().await
    );

    // Now test the VaultKmsProvider
    let provider = VaultKmsProvider::new(
        &vault_addr,
        "transit",
        "rustberg-test-key",
        root_token.to_string(),
    )
    .await
    .expect("Failed to create VaultKmsProvider");

    // Test health check
    provider.health_check().await.expect("Health check failed");

    // Test data key generation
    let dek = provider
        .generate_data_key("rustberg-test-key")
        .await
        .expect("Failed to generate data key");

    assert_eq!(dek.plaintext.expose().len(), 32, "DEK should be 32 bytes (256 bits)");
    assert!(!dek.ciphertext.is_empty(), "Encrypted DEK should not be empty");
    assert!(dek.version >= 1, "Version should be at least 1");

    // Test decryption of the wrapped key
    let decrypted = provider
        .decrypt_data_key("rustberg-test-key", &dek.ciphertext)
        .await
        .expect("Failed to decrypt data key");

    assert_eq!(
        decrypted.expose(),
        dek.plaintext.expose(),
        "Decrypted key should match original"
    );

    // Test encryption of arbitrary data
    let test_plaintext = b"test-data-for-encryption";
    let encrypted = provider
        .encrypt_data_key("rustberg-test-key", test_plaintext)
        .await
        .expect("Failed to encrypt data");

    assert!(!encrypted.is_empty(), "Encrypted data should not be empty");

    // Test decryption of the encrypted data
    let decrypted_data = provider
        .decrypt_data_key("rustberg-test-key", &encrypted)
        .await
        .expect("Failed to decrypt data");

    assert_eq!(
        decrypted_data.expose(),
        test_plaintext,
        "Decrypted data should match original"
    );

    // Test current version
    let version = provider
        .current_version("rustberg-test-key")
        .await
        .expect("Failed to get current version");

    assert!(version >= 1, "Version should be at least 1");

    println!("✅ All Vault KMS provider tests passed!");
}

/// Test key rotation in Vault.
#[tokio::test]
async fn test_vault_kms_key_rotation() {
    use rustberg::crypto::kms::{KeyManagementService, VaultKmsProvider};

    // Start Vault container
    let vault: ContainerAsync<HashicorpVault> = HashicorpVault::default()
        .start()
        .await
        .expect("Failed to start Vault container");

    let host_port = vault.get_host_port_ipv4(8200).await.unwrap();
    let vault_addr = format!("http://127.0.0.1:{}", host_port);
    let root_token = "myroot";

    sleep(Duration::from_secs(2)).await;

    // Setup Vault
    let client = reqwest::Client::new();

    client
        .post(format!("{}/v1/sys/mounts/transit", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({"type": "transit"}))
        .send()
        .await
        .expect("Failed to enable transit");

    client
        .post(format!("{}/v1/transit/keys/rotation-test-key", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({"type": "aes256-gcm96"}))
        .send()
        .await
        .expect("Failed to create key");

    // Create provider
    let provider = VaultKmsProvider::new(
        &vault_addr,
        "transit",
        "rotation-test-key",
        root_token.to_string(),
    )
    .await
    .expect("Failed to create provider");

    // Get initial version
    let initial_version = provider
        .current_version("rotation-test-key")
        .await
        .expect("Failed to get version");

    // Encrypt some data with current key
    let test_data = b"data-before-rotation";
    let encrypted_before = provider
        .encrypt_data_key("rotation-test-key", test_data)
        .await
        .expect("Failed to encrypt");

    // Rotate the key
    let new_version = provider
        .rotate_master_key("rotation-test-key")
        .await
        .expect("Failed to rotate key");

    assert!(
        new_version > initial_version,
        "New version should be greater than initial"
    );

    // Verify we can still decrypt data encrypted with old key version
    let decrypted = provider
        .decrypt_data_key("rotation-test-key", &encrypted_before)
        .await
        .expect("Failed to decrypt after rotation");

    assert_eq!(
        decrypted.expose(),
        test_data,
        "Should still decrypt data from old key version"
    );

    // New encryptions should use the new key version
    let encrypted_after = provider
        .encrypt_data_key("rotation-test-key", test_data)
        .await
        .expect("Failed to encrypt after rotation");

    // The ciphertext format includes version: vault:v2:...
    let ciphertext_str = String::from_utf8_lossy(&encrypted_after);
    assert!(
        ciphertext_str.contains(&format!(":v{}:", new_version)),
        "New encryption should use new key version"
    );

    println!("✅ Vault KMS key rotation tests passed!");
}

/// Test error handling when Vault is unavailable.
#[tokio::test]
async fn test_vault_kms_connection_error() {
    use rustberg::crypto::kms::VaultKmsProvider;

    // Try to connect to a non-existent Vault
    let result = VaultKmsProvider::new(
        "http://127.0.0.1:19999", // Non-existent port
        "transit",
        "test-key",
        "fake-token".to_string(),
    )
    .await;

    assert!(result.is_err(), "Should fail to connect to non-existent Vault");
    
    let err = result.unwrap_err();
    println!("Expected error: {}", err);
}

/// Test concurrent operations.
#[tokio::test]
async fn test_vault_kms_concurrent_operations() {
    use rustberg::crypto::kms::{KeyManagementService, VaultKmsProvider};
    use std::sync::Arc;

    // Start Vault container
    let vault: ContainerAsync<HashicorpVault> = HashicorpVault::default()
        .start()
        .await
        .expect("Failed to start Vault container");

    let host_port = vault.get_host_port_ipv4(8200).await.unwrap();
    let vault_addr = format!("http://127.0.0.1:{}", host_port);
    let root_token = "myroot";

    sleep(Duration::from_secs(2)).await;

    // Setup Vault
    let client = reqwest::Client::new();

    client
        .post(format!("{}/v1/sys/mounts/transit", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({"type": "transit"}))
        .send()
        .await
        .expect("Failed to enable transit");

    client
        .post(format!("{}/v1/transit/keys/concurrent-test-key", vault_addr))
        .header("X-Vault-Token", root_token)
        .json(&serde_json::json!({"type": "aes256-gcm96"}))
        .send()
        .await
        .expect("Failed to create key");

    // Create provider
    let provider = Arc::new(
        VaultKmsProvider::new(
            &vault_addr,
            "transit",
            "concurrent-test-key",
            root_token.to_string(),
        )
        .await
        .expect("Failed to create provider"),
    );

    // Run many concurrent operations
    let mut handles = Vec::new();
    for i in 0..10 {
        let provider = Arc::clone(&provider);
        let handle = tokio::spawn(async move {
            let data = format!("concurrent-data-{}", i);
            
            // Generate a data key
            let dek = provider
                .generate_data_key("concurrent-test-key")
                .await
                .expect("Failed to generate data key");

            // Encrypt
            let encrypted = provider
                .encrypt_data_key("concurrent-test-key", data.as_bytes())
                .await
                .expect("Failed to encrypt");

            // Decrypt
            let decrypted = provider
                .decrypt_data_key("concurrent-test-key", &encrypted)
                .await
                .expect("Failed to decrypt");

            assert_eq!(decrypted.expose(), data.as_bytes());
            assert_eq!(dek.plaintext.expose().len(), 32);

            i
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    let results: Vec<_> = futures::future::join_all(handles).await;
    for result in results {
        result.expect("Task failed");
    }

    println!("✅ Vault KMS concurrent operations tests passed!");
}
