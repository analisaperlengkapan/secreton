//! Symmetric encryption implementations

use crate::{AlgorithmId, CryptoError, CryptoResult};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A fresh 12-byte AEAD nonce.
///
/// Returns the array rather than a `Vec`, so the caller has nothing left to unwrap. The
/// previous shape asked for 12 random bytes and then re-derived the length with a fallible
/// conversion it discharged with `unwrap`.
fn random_nonce() -> CryptoResult<[u8; 12]> {
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(nonce)
}

/// Read a stored nonce, rejecting one that is not 12 bytes.
///
/// The nonce comes off disk with the ciphertext, so its length is not something this
/// process controls. Length check and conversion are one expression: separating them let a
/// future edit remove the guard while leaving the `unwrap` that depended on it.
fn nonce_from(bytes: &[u8]) -> CryptoResult<[u8; 12]> {
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub algorithm: AlgorithmId,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Option<Vec<u8>>,
}

/// Symmetric encryption trait
pub trait SymmetricCipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> CryptoResult<EncryptedData>;
    fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> CryptoResult<Vec<u8>>;
}

/// AES-256-GCM implementation
pub struct Aes256GcmCipher;

impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> CryptoResult<EncryptedData> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        })?;

        let nonce_array = random_nonce()?;
        let nonce = Nonce::from(nonce_array);
        let nonce_bytes = nonce_array.to_vec();

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
        })?;

        Ok(EncryptedData {
            algorithm: AlgorithmId::Aes256Gcm,
            nonce: nonce_bytes,
            ciphertext,
            tag: None, // Tag is included in ciphertext for GCM
        })
    }

    fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: key.len(),
        })?;
        let nonce = Nonce::from(nonce_from(&encrypted.nonce)?);

        cipher
            .decrypt(&nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(format!("AES-GCM decryption failed: {}", e)))
    }
}

/// ChaCha20-Poly1305 implementation
pub struct ChaCha20Poly1305Cipher;

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> CryptoResult<EncryptedData> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            })?;

        let nonce_array = random_nonce()?;
        let nonce = Nonce::from(nonce_array);
        let nonce_bytes = nonce_array.to_vec();

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {}", e))
        })?;

        Ok(EncryptedData {
            algorithm: AlgorithmId::ChaCha20Poly1305,
            nonce: nonce_bytes,
            ciphertext,
            tag: None, // Tag is included in ciphertext for Poly1305
        })
    }

    fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        if encrypted.nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength);
        }

        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            })?;
        let nonce = Nonce::from(nonce_from(&encrypted.nonce)?);

        cipher
            .decrypt(&nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| {
                CryptoError::DecryptionFailed(format!("ChaCha20-Poly1305 decryption failed: {}", e))
            })
    }
}

/// Unified encryption interface
pub struct CryptoEngine;

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn encrypt(
        &self,
        algorithm: AlgorithmId,
        plaintext: &[u8],
        key: &[u8],
    ) -> CryptoResult<EncryptedData> {
        match algorithm {
            AlgorithmId::Aes256Gcm => {
                let cipher = Aes256GcmCipher;
                cipher.encrypt(plaintext, key)
            }
            AlgorithmId::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305Cipher;
                cipher.encrypt(plaintext, key)
            }
            _ => Err(CryptoError::EncryptionFailed(format!(
                "Unsupported encryption algorithm: {}",
                algorithm
            ))),
        }
    }

    pub fn decrypt(&self, encrypted: &EncryptedData, key: &[u8]) -> CryptoResult<Vec<u8>> {
        match encrypted.algorithm {
            AlgorithmId::Aes256Gcm => {
                let cipher = Aes256GcmCipher;
                cipher.decrypt(encrypted, key)
            }
            AlgorithmId::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305Cipher;
                cipher.decrypt(encrypted, key)
            }
            _ => Err(CryptoError::DecryptionFailed(format!(
                "Unsupported decryption algorithm: {}",
                encrypted.algorithm
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key;

    #[test]
    fn test_aes256gcm_encryption_roundtrip() {
        let engine = CryptoEngine::new();
        let key = generate_key(AlgorithmId::Aes256Gcm).unwrap();
        let plaintext = b"Hello, Secreton Security System!";

        let encrypted = engine
            .encrypt(AlgorithmId::Aes256Gcm, plaintext, &key)
            .unwrap();
        let decrypted = engine.decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(encrypted.algorithm, AlgorithmId::Aes256Gcm);
        assert_eq!(encrypted.nonce.len(), 12);
    }

    #[test]
    fn test_chacha20poly1305_encryption_roundtrip() {
        let engine = CryptoEngine::new();
        let key = generate_key(AlgorithmId::ChaCha20Poly1305).unwrap();
        let plaintext = b"ChaCha20-Poly1305 test message";

        let encrypted = engine
            .encrypt(AlgorithmId::ChaCha20Poly1305, plaintext, &key)
            .unwrap();
        let decrypted = engine.decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(encrypted.algorithm, AlgorithmId::ChaCha20Poly1305);
        assert_eq!(encrypted.nonce.len(), 12);
    }

    #[test]
    fn test_wrong_key_length() {
        let engine = CryptoEngine::new();
        let short_key = crate::generate_random_bytes(16).unwrap(); // Too short
        let plaintext = b"test";

        let result = engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, &short_key);
        assert!(result.is_err());

        match result.unwrap_err() {
            CryptoError::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }
}
