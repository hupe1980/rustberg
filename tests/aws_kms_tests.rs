//! Integration tests for AWS KMS provider using LocalStack testcontainers.
//!
//! These tests require Docker to be running.

#![cfg(feature = "aws-kms")]

use std::time::Duration;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::localstack::LocalStack;
use tokio::time::sleep;

/// Test the AwsKmsProvider with LocalStack.
///
/// This test:
/// 1. Starts a LocalStack container with KMS service
/// 2. Creates a symmetric KMS key
/// 3. Tests data key generation, encryption, and decryption
#[tokio::test]
async fn test_aws_kms_provider_basic_operations() {
    use rustberg::crypto::kms::{AwsKmsProvider, KeyManagementService};

    // Start LocalStack container
    let localstack: ContainerAsync<LocalStack> = LocalStack::default()
        .start()
        .await
        .expect("Failed to start LocalStack container");

    // Get the connection details
    let host_port = localstack.get_host_port_ipv4(4566).await.unwrap();
    let endpoint_url = format!("http://127.0.0.1:{}", host_port);

    // Wait for LocalStack to be ready
    sleep(Duration::from_secs(3)).await;

    // Create a KMS key using AWS CLI equivalent via HTTP
    let client = reqwest::Client::new();

    // Create key via LocalStack KMS API
    let create_key_response = client
        .post(format!("{}/", endpoint_url))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "TrentService.CreateKey")
        .body(r#"{"Description": "Test key for Rustberg", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"}"#)
        .send()
        .await
        .expect("Failed to create KMS key");

    assert!(
        create_key_response.status().is_success(),
        "Failed to create KMS key: {:?}",
        create_key_response.text().await
    );

    let key_response: serde_json::Value = client
        .post(format!("{}/", endpoint_url))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "TrentService.CreateKey")
        .body(r#"{"Description": "Test key for Rustberg", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"}"#)
        .send()
        .await
        .expect("Failed to create KMS key")
        .json()
        .await
        .expect("Failed to parse key response");

    let key_id = key_response["KeyMetadata"]["KeyId"]
        .as_str()
        .expect("No KeyId in response");

    println!("Created KMS key: {}", key_id);

    // Set AWS credentials for LocalStack (dummy credentials work)
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");

    // Create the AWS KMS provider with LocalStack endpoint
    let provider = AwsKmsProvider::new("us-east-1", key_id, Some(endpoint_url.clone()))
        .await
        .expect("Failed to create AwsKmsProvider");

    // Test health check
    provider.health_check().await.expect("Health check failed");

    // Test data key generation
    let dek = provider
        .generate_data_key(key_id)
        .await
        .expect("Failed to generate data key");

    assert_eq!(
        dek.plaintext.expose().len(),
        32,
        "DEK should be 32 bytes (256 bits)"
    );
    assert!(
        !dek.ciphertext.is_empty(),
        "Encrypted DEK should not be empty"
    );
    assert!(dek.version >= 1, "Version should be at least 1");

    // Test decryption of the wrapped key
    let decrypted = provider
        .decrypt_data_key(key_id, &dek.ciphertext)
        .await
        .expect("Failed to decrypt data key");

    assert_eq!(
        decrypted.expose(),
        dek.plaintext.expose(),
        "Decrypted key should match original"
    );

    // Test encryption of arbitrary data
    let test_plaintext = b"test-data-for-encryption-aws";
    let encrypted = provider
        .encrypt_data_key(key_id, test_plaintext)
        .await
        .expect("Failed to encrypt data");

    assert!(!encrypted.is_empty(), "Encrypted data should not be empty");

    // Test decryption of the encrypted data
    let decrypted_data = provider
        .decrypt_data_key(key_id, &encrypted)
        .await
        .expect("Failed to decrypt data");

    assert_eq!(
        decrypted_data.expose(),
        test_plaintext,
        "Decrypted data should match original"
    );

    // Cleanup env vars
    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("AWS_DEFAULT_REGION");

    println!("✅ All AWS KMS provider tests passed!");
}

/// Test the envelope encryption flow with AWS KMS.
#[tokio::test]
async fn test_aws_kms_envelope_encryption() {
    use rustberg::crypto::kms::{AwsKmsProvider, EncryptedEnvelope};

    // Start LocalStack container
    let localstack: ContainerAsync<LocalStack> = LocalStack::default()
        .start()
        .await
        .expect("Failed to start LocalStack container");

    let host_port = localstack.get_host_port_ipv4(4566).await.unwrap();
    let endpoint_url = format!("http://127.0.0.1:{}", host_port);

    sleep(Duration::from_secs(3)).await;

    // Create a KMS key
    let client = reqwest::Client::new();
    let key_response: serde_json::Value = client
        .post(format!("{}/", endpoint_url))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "TrentService.CreateKey")
        .body(r#"{"Description": "Envelope test key", "KeyUsage": "ENCRYPT_DECRYPT"}"#)
        .send()
        .await
        .expect("Failed to create KMS key")
        .json()
        .await
        .expect("Failed to parse key response");

    let key_id = key_response["KeyMetadata"]["KeyId"]
        .as_str()
        .expect("No KeyId in response");

    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");

    let provider = AwsKmsProvider::new("us-east-1", key_id, Some(endpoint_url))
        .await
        .expect("Failed to create AwsKmsProvider");

    // Test envelope encryption
    let plaintext = b"Sensitive table metadata that needs encryption";

    let envelope = EncryptedEnvelope::encrypt(&provider, key_id, plaintext)
        .await
        .expect("Failed to encrypt envelope");

    assert!(!envelope.ciphertext.is_empty());
    assert!(!envelope.wrapped_dek.is_empty());

    // Decrypt and verify
    let decrypted = envelope
        .decrypt(&provider)
        .await
        .expect("Failed to decrypt envelope");
    assert_eq!(decrypted, plaintext);

    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("AWS_DEFAULT_REGION");

    println!("✅ AWS KMS envelope encryption test passed!");
}

/// Test error handling when AWS KMS key doesn't exist.
#[tokio::test]
async fn test_aws_kms_key_not_found() {
    use rustberg::crypto::kms::{AwsKmsProvider, KeyManagementService};

    // Start LocalStack container
    let localstack: ContainerAsync<LocalStack> = LocalStack::default()
        .start()
        .await
        .expect("Failed to start LocalStack container");

    let host_port = localstack
        .get_host_port_ipv4(4566)
        .await
        .expect("Failed to get LocalStack port");
    let endpoint_url = format!("http://127.0.0.1:{}", host_port);

    sleep(Duration::from_secs(3)).await;

    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");

    // Create provider with a non-existent key
    let result =
        AwsKmsProvider::new("us-east-1", "non-existent-key-12345", Some(endpoint_url)).await;

    // Provider creation might succeed but operations should fail
    if let Ok(provider) = result {
        let gen_result = provider.generate_data_key("non-existent-key-12345").await;
        assert!(gen_result.is_err(), "Should fail with non-existent key");
    }

    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("AWS_DEFAULT_REGION");

    println!("✅ AWS KMS error handling test passed!");
}

/// Test concurrent operations with AWS KMS.
#[tokio::test]
async fn test_aws_kms_concurrent_operations() {
    use rustberg::crypto::kms::{AwsKmsProvider, KeyManagementService};
    use std::sync::Arc;

    // Start LocalStack container
    let localstack: ContainerAsync<LocalStack> = LocalStack::default()
        .start()
        .await
        .expect("Failed to start LocalStack container");

    let host_port = localstack.get_host_port_ipv4(4566).await.unwrap();
    let endpoint_url = format!("http://127.0.0.1:{}", host_port);

    sleep(Duration::from_secs(3)).await;

    // Create a KMS key
    let client = reqwest::Client::new();
    let key_response: serde_json::Value = client
        .post(format!("{}/", endpoint_url))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "TrentService.CreateKey")
        .body(r#"{"Description": "Concurrent test key", "KeyUsage": "ENCRYPT_DECRYPT"}"#)
        .send()
        .await
        .expect("Failed to create KMS key")
        .json()
        .await
        .expect("Failed to parse key response");

    let key_id = key_response["KeyMetadata"]["KeyId"]
        .as_str()
        .expect("No KeyId in response")
        .to_string();

    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");

    let provider = Arc::new(
        AwsKmsProvider::new("us-east-1", &key_id, Some(endpoint_url))
            .await
            .expect("Failed to create AwsKmsProvider"),
    );

    // Run 10 concurrent operations
    let mut handles = vec![];
    for i in 0..10 {
        let provider = provider.clone();
        let key_id = key_id.clone();
        handles.push(tokio::spawn(async move {
            let dek = provider
                .generate_data_key(&key_id)
                .await
                .expect(&format!("Failed to generate DEK {}", i));

            let decrypted = provider
                .decrypt_data_key(&key_id, &dek.ciphertext)
                .await
                .expect(&format!("Failed to decrypt DEK {}", i));

            assert_eq!(decrypted.expose(), dek.plaintext.expose());
            i
        }));
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.expect("Task panicked");
    }

    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("AWS_DEFAULT_REGION");

    println!("✅ AWS KMS concurrent operations test passed!");
}
