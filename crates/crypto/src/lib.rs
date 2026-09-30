//! Secreton Cryptographic Library
//!
//! High-performance, secure cryptographic primitives and protocols
//! with comprehensive RustCrypto integration and transit engine support.

use pkcs8::EncodePrivateKey;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod cryptography;
pub mod encryption;
pub mod error;
pub mod hashing;
pub mod key_derivation;
pub mod key_manager;
pub mod shamir;
pub mod signing;
pub mod transit;
pub mod wrapping;

pub use cryptography::*;
pub use encryption::*;
pub use error::*;
pub use key_derivation::{DerivedKey, KdfParams, derive_key};
pub use key_manager::*;
pub use shamir::*;
pub use signing::*;
pub use transit::TransitEngine;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmId {
    // Symmetric encryption
    Aes256Gcm,
    ChaCha20Poly1305,

    // Asymmetric signing.
    //
    // RSA is deliberately absent: the `rsa` crate carries an unfixed timing
    // side-channel advisory (RUSTSEC-2023-0071, "Marvin"), and Ed25519 or the
    // NIST curves cover every use this codebase has.
    EcdsaP256,
    EcdsaP384,
    Ed25519,

    // Hash functions
    Sha256,
    Sha3_256,
    Blake3,

    // Key derivation
    Pbkdf2,
    Argon2id,
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            AlgorithmId::Aes256Gcm => "AES-256-GCM",
            AlgorithmId::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AlgorithmId::EcdsaP256 => "ECDSA-P256",
            AlgorithmId::EcdsaP384 => "ECDSA-P384",
            AlgorithmId::Ed25519 => "Ed25519",
            AlgorithmId::Sha256 => "SHA-256",
            AlgorithmId::Sha3_256 => "SHA3-256",
            AlgorithmId::Blake3 => "BLAKE3",
            AlgorithmId::Pbkdf2 => "PBKDF2",
            AlgorithmId::Argon2id => "Argon2id",
        };
        write!(f, "{}", name)
    }
}

/// Security parameters for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    pub algorithm: AlgorithmId,
    pub key_size: usize,
    pub iterations: Option<u32>,
    pub salt_size: Option<usize>,
}

impl SecurityParams {
    /// Create security parameters for a given algorithm
    pub fn new(algorithm: AlgorithmId) -> Self {
        let (key_size, iterations, salt_size) = match algorithm {
            AlgorithmId::Aes256Gcm => (32, None, Some(12)),
            AlgorithmId::ChaCha20Poly1305 => (32, None, Some(12)),
            AlgorithmId::EcdsaP256 => (32, None, None),
            AlgorithmId::EcdsaP384 => (48, None, None),
            AlgorithmId::Ed25519 => (32, None, None),
            AlgorithmId::Sha256 => (32, None, None),
            AlgorithmId::Sha3_256 => (32, None, None),
            AlgorithmId::Blake3 => (32, None, None),
            AlgorithmId::Pbkdf2 => (32, Some(100_000), Some(16)),
            AlgorithmId::Argon2id => (32, Some(3), Some(16)),
        };

        Self {
            algorithm,
            key_size,
            iterations,
            salt_size,
        }
    }

    /// Check if parameters are secure for production use
    pub fn is_secure(&self) -> bool {
        match self.algorithm {
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => self.key_size >= 32,
            AlgorithmId::EcdsaP256 => self.key_size >= 32,
            AlgorithmId::EcdsaP384 => self.key_size >= 48,
            AlgorithmId::Ed25519 => self.key_size >= 32,
            AlgorithmId::Pbkdf2 => self.iterations.unwrap_or(0) >= 100_000 && self.key_size >= 32,
            AlgorithmId::Argon2id => self.iterations.unwrap_or(0) >= 3 && self.key_size >= 32,
            _ => true,
        }
    }
}

/// Generate cryptographically secure random bytes
///
/// The buffer is filled through `getrandom` rather than `rand`, so the freshly
/// allocated (and therefore all-zero) buffer is recognisably *input* to an entropy
/// source instead of a constant that happens to look like key material.
pub fn generate_random_bytes(len: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(bytes)
}

/// Generate a random key for the specified algorithm
pub fn generate_key(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);

    match algorithm {
        AlgorithmId::EcdsaP256 => {
            use p256::elliptic_curve::Generate;
            let secret_key = p256::SecretKey::generate();
            let doc = secret_key.to_pkcs8_der().map_err(|e| {
                CryptoError::KeyGenerationFailed(format!(
                    "ECDSA P-256 PKCS8 encoding failed: {}",
                    e
                ))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        AlgorithmId::EcdsaP384 => {
            use p384::elliptic_curve::Generate;
            let secret_key = p384::SecretKey::generate();
            let doc = secret_key.to_pkcs8_der().map_err(|e| {
                CryptoError::KeyGenerationFailed(format!(
                    "ECDSA P-384 PKCS8 encoding failed: {}",
                    e
                ))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        AlgorithmId::Ed25519 => {
            // The 32-byte seed *is* the Ed25519 private key; `SigningKey::from_bytes`
            // in `signing.rs` consumes exactly this representation.
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| CryptoError::RandomGenerationFailed)?;
            Ok(seed.to_vec())
        }
        _ => generate_random_bytes(params.key_size),
    }
}

/// Generate a random nonce/IV for the specified algorithm
pub fn generate_nonce(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);
    if let Some(nonce_size) = params.salt_size {
        generate_random_bytes(nonce_size)
    } else {
        Err(CryptoError::InvalidNonceLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_params_for_symmetric_algorithms() {
        let aes_params = SecurityParams::new(AlgorithmId::Aes256Gcm);
        assert_eq!(aes_params.key_size, 32);
        assert_eq!(aes_params.iterations, None);
        assert_eq!(aes_params.salt_size, Some(12));
        assert!(aes_params.is_secure());

        let chacha_params = SecurityParams::new(AlgorithmId::ChaCha20Poly1305);
        assert_eq!(chacha_params.key_size, 32);
        assert!(chacha_params.is_secure());
    }

    #[test]
    fn test_security_params_for_kdf_algorithms() {
        let pbkdf2_params = SecurityParams::new(AlgorithmId::Pbkdf2);
        assert_eq!(pbkdf2_params.iterations, Some(100_000));
        assert!(pbkdf2_params.is_secure());

        let mut unsafe_pbkdf2 = pbkdf2_params.clone();
        unsafe_pbkdf2.iterations = Some(10_000);
        assert!(!unsafe_pbkdf2.is_secure());

        let argon_params = SecurityParams::new(AlgorithmId::Argon2id);
        assert_eq!(argon_params.iterations, Some(3));
        assert!(argon_params.is_secure());

        let mut unsafe_argon = argon_params.clone();
        unsafe_argon.iterations = Some(1);
        assert!(!unsafe_argon.is_secure());
    }

    #[test]
    fn test_generate_key_lengths_match_algorithm_requirements() {
        let aes_key = generate_key(AlgorithmId::Aes256Gcm).expect("AES key generation failed");
        assert_eq!(aes_key.len(), 32);

        let argon_key = generate_key(AlgorithmId::Argon2id).expect("Argon2 key generation failed");
        assert_eq!(argon_key.len(), 32);
    }

    #[test]
    fn test_generate_nonce_respects_algorithm_requirements() {
        let aes_nonce = generate_nonce(AlgorithmId::Aes256Gcm).expect("nonce generation failed");
        assert_eq!(aes_nonce.len(), 12);

        let err =
            generate_nonce(AlgorithmId::Sha256).expect_err("expected nonce generation to fail");
        assert_eq!(err, CryptoError::InvalidNonceLength);
    }

    #[test]
    fn test_generate_random_bytes_produces_requested_length() {
        let bytes = generate_random_bytes(64).expect("random generation failed");
        assert_eq!(bytes.len(), 64);
    }
}
