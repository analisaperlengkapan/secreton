//! Comprehensive cryptographic function tests
//!
//! Tests all cryptographic operations including encryption, decryption,
//! key generation, hashing, signing, and verification.

use anyhow::Result;

use secreton_crypto::{
    AlgorithmId, CryptoError, SecurityParams,
    encryption::{Aes256GcmCipher, ChaCha20Poly1305Cipher, SymmetricCipher},
    generate_random_bytes,
    hashing::{Blake3Hash, HashFunction, Sha3_256Hash, Sha256Hash},
    key_derivation::{derive_key_argon2id, derive_key_pbkdf2},
};

#[cfg(test)]
mod crypto_comprehensive_tests {
    use super::*;

    #[tokio::test]
    async fn test_symmetric_encryption_comprehensive() -> Result<()> {
        // Test AES-256-GCM
        let aes_cipher = Aes256GcmCipher;

        // Test all supported symmetric encryption algorithms
        let algorithms = vec![
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
        ];

        let large_data = "x".repeat(10000);
        let test_data = vec![
            "Short message",
            "This is a longer message with more content to encrypt and test thoroughly",
            "Special chars: àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ",
            &large_data, // Large data
        ];

        for algorithm in algorithms {
            for data in &test_data {
                // Generate a random key
                let key = generate_random_bytes(32)?;

                // Encrypt
                let encrypted = match algorithm {
                    EncryptionAlgorithm::Aes256Gcm => aes_cipher.encrypt(data.as_bytes(), &key)?,
                    EncryptionAlgorithm::ChaCha20Poly1305 => {
                        let chacha_cipher = ChaCha20Poly1305Cipher;
                        chacha_cipher.encrypt(data.as_bytes(), &key)?
                    }
                };

                // Verify encryption produced different output
                assert_ne!(encrypted.ciphertext, data.as_bytes());

                // Decrypt
                let decrypted = match algorithm {
                    EncryptionAlgorithm::Aes256Gcm => aes_cipher.decrypt(&encrypted, &key)?,
                    EncryptionAlgorithm::ChaCha20Poly1305 => {
                        let chacha_cipher = ChaCha20Poly1305Cipher;
                        chacha_cipher.decrypt(&encrypted, &key)?
                    }
                };

                // Verify decrypted data matches original
                assert_eq!(decrypted, data.as_bytes());
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_hashing_algorithms_comprehensive() -> Result<()> {
        let large_data = "x".repeat(10000);
        let test_data = vec![
            "Short message",
            "This is a longer message with more content to hash and test thoroughly",
            "Special chars: àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ",
            &large_data, // Large data
        ];

        // Test SHA-256
        let sha256 = Sha256Hash;
        for data in &test_data {
            let hash1 = sha256.hash(data.as_bytes())?;
            let hash2 = sha256.hash(data.as_bytes())?;
            assert_eq!(hash1, hash2, "Hash should be deterministic");
            assert_eq!(hash1.len(), 32, "SHA-256 should produce 32 bytes");
        }

        // Test SHA3-256
        let sha3 = Sha3_256Hash;
        for data in &test_data {
            let hash1 = sha3.hash(data.as_bytes())?;
            let hash2 = sha3.hash(data.as_bytes())?;
            assert_eq!(hash1, hash2, "Hash should be deterministic");
            assert_eq!(hash1.len(), 32, "SHA3-256 should produce 32 bytes");
        }

        // Test BLAKE3
        let blake3 = Blake3Hash;
        for data in &test_data {
            let hash1 = blake3.hash(data.as_bytes())?;
            let hash2 = blake3.hash(data.as_bytes())?;
            assert_eq!(hash1, hash2, "Hash should be deterministic");
            assert_eq!(hash1.len(), 32, "BLAKE3 should produce 32 bytes");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_key_derivation_functions() -> Result<()> {
        let password = hex::encode(generate_random_bytes(16)?);

        // Test PBKDF2
        let salt = generate_random_bytes(16)?;
        let derived_key = derive_key_pbkdf2(password.as_bytes(), &salt, 10000, 32)?;
        assert_eq!(derived_key.len(), 32);

        // Verify the same derivation produces the same result
        let derived_key2 = derive_key_pbkdf2(password.as_bytes(), &salt, 10000, 32)?;
        assert_eq!(derived_key, derived_key2);

        // Different salt should produce different result
        let salt2 = generate_random_bytes(16)?;
        let derived_key3 = derive_key_pbkdf2(password.as_bytes(), &salt2, 10000, 32)?;
        assert_ne!(derived_key, derived_key3);

        // Test Argon2
        let argon_key = derive_key_argon2id(password.as_bytes(), &salt, 65536, 3, 1, 32)?;
        assert_eq!(argon_key.len(), 32);

        Ok(())
    }

    #[tokio::test]
    async fn test_random_generation() -> Result<()> {
        // Test random byte generation
        let random1 = generate_random_bytes(32)?;
        let random2 = generate_random_bytes(32)?;
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2, "Random bytes should be different");

        // Test different sizes
        let sizes = vec![16, 32, 64, 128];
        for size in sizes {
            let random = generate_random_bytes(size)?;
            assert_eq!(random.len(), size);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_security_parameters() -> Result<()> {
        // Test default security parameters
        let params = SecurityParams {
            algorithm: AlgorithmId::Aes256Gcm,
            key_size: 32,
            iterations: Some(10000),
            salt_size: Some(16),
        };

        assert_eq!(params.algorithm, AlgorithmId::Aes256Gcm);
        assert_eq!(params.key_size, 32);

        Ok(())
    }

    #[tokio::test]
    async fn test_error_handling() -> Result<()> {
        let aes_cipher = Aes256GcmCipher;

        // Test with wrong key size
        let short_key = generate_random_bytes(16)?; // Should be 32
        let result = aes_cipher.encrypt(b"test", &short_key);
        assert!(result.is_err());

        // Test with empty data
        let key = generate_random_bytes(32)?;
        let empty_data_result = aes_cipher.encrypt(b"", &key);
        assert!(empty_data_result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_algorithm_identifiers() -> Result<()> {
        let algorithms = vec![
            AlgorithmId::Aes256Gcm,
            AlgorithmId::ChaCha20Poly1305,
            AlgorithmId::Sha256,
            AlgorithmId::Sha3_256,
            AlgorithmId::Blake3,
            AlgorithmId::Pbkdf2,
            AlgorithmId::Argon2id,
        ];

        for algorithm in algorithms {
            let display = format!("{}", algorithm);
            assert!(!display.is_empty());
            assert!(
                display.contains("AES")
                    || display.contains("ChaCha")
                    || display.contains("SHA")
                    || display.contains("BLAKE")
                    || display.contains("PBKDF2")
                    || display.contains("Argon2")
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_crypto_operations() -> Result<()> {
        let mut handles = Vec::new();

        // Test concurrent encryption operations
        for i in 0..10 {
            let handle = tokio::spawn(async move {
                let aes_cipher = Aes256GcmCipher;
                let key = generate_random_bytes(32)?;
                let data = format!("Concurrent test data {}", i);
                let encrypted = aes_cipher.encrypt(data.as_bytes(), &key)?;
                let decrypted = aes_cipher.decrypt(&encrypted, &key)?;
                assert_eq!(decrypted, data.as_bytes());
                Ok::<_, CryptoError>(())
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await??;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_large_data_handling() -> Result<()> {
        let aes_cipher = Aes256GcmCipher;
        let key = generate_random_bytes(32)?;

        // Test with 1MB of data
        let large_data = vec![42u8; 1024 * 1024];

        let encrypted = aes_cipher.encrypt(&large_data, &key)?;
        assert!(!encrypted.ciphertext.is_empty());
        assert_ne!(encrypted.ciphertext, large_data);

        let decrypted = aes_cipher.decrypt(&encrypted, &key)?;
        assert_eq!(decrypted.len(), large_data.len());
        assert_eq!(decrypted, large_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_unicode_data_handling() -> Result<()> {
        let aes_cipher = Aes256GcmCipher;
        let key = generate_random_bytes(32)?;

        let unicode_data = "测试数据🔑 with special chars: àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ";

        let encrypted = aes_cipher.encrypt(unicode_data.as_bytes(), &key)?;
        let decrypted = aes_cipher.decrypt(&encrypted, &key)?;
        assert_eq!(std::str::from_utf8(&decrypted)?, unicode_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_key_sizes_and_validation() -> Result<()> {
        let aes_cipher = Aes256GcmCipher;

        // Test valid key sizes
        let valid_keys = vec![16, 24, 32]; // AES supports these
        for size in valid_keys {
            let key = generate_random_bytes(size)?;
            let result = aes_cipher.encrypt(b"test", &key);
            // Should work for AES-256-GCM (32 bytes)
            if size == 32 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_deterministic_operations() -> Result<()> {
        let aes_cipher = Aes256GcmCipher;
        let key = generate_random_bytes(32)?;
        let data = b"Deterministic test data";

        // Multiple encryptions should produce different ciphertexts (due to random nonce)
        let encrypted1 = aes_cipher.encrypt(data, &key)?;
        let encrypted2 = aes_cipher.encrypt(data, &key)?;
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // But decryption should always work
        let decrypted1 = aes_cipher.decrypt(&encrypted1, &key)?;
        let decrypted2 = aes_cipher.decrypt(&encrypted2, &key)?;
        assert_eq!(decrypted1, data);
        assert_eq!(decrypted2, data);

        Ok(())
    }
}

// Helper enum for testing
#[derive(Debug, Clone, Copy)]
enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}
