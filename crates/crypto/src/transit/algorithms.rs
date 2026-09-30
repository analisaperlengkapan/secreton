//! Cryptographic algorithms implementation using RustCrypto
//!
//! This module provides implementations of various cryptographic algorithms
//! using the RustCrypto ecosystem, with a focus on modern, secure algorithms
//! like Ed25519 for signatures and ChaCha20-Poly1305 for encryption.

use crate::error::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export commonly used algorithms
pub use aes_gcm::{Aes128Gcm, Aes256Gcm};
pub use blake3::Hasher as Blake3Hasher;
pub use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
pub use sha2::{Digest, Sha256, Sha384, Sha512};
pub use sha3::{Sha3_256, Sha3_384, Sha3_512};

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256
    #[serde(alias = "sha256", alias = "SHA-256")]
    Sha256,
    /// SHA-384  
    #[serde(alias = "sha384", alias = "SHA-384")]
    Sha384,
    /// SHA-512
    #[serde(alias = "sha512", alias = "SHA-512")]
    Sha512,
    /// SHA3-256
    #[serde(alias = "sha3-256", alias = "SHA3-256")]
    Sha3_256,
    /// SHA3-384
    #[serde(alias = "sha3-384", alias = "SHA3-384")]
    Sha3_384,
    /// SHA3-512
    #[serde(alias = "sha3-512", alias = "SHA3-512")]
    Sha3_512,
    /// BLAKE3
    #[serde(alias = "blake3", alias = "BLAKE3")]
    Blake3,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha384 => write!(f, "sha384"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
            HashAlgorithm::Sha3_256 => write!(f, "sha3-256"),
            HashAlgorithm::Sha3_384 => write!(f, "sha3-384"),
            HashAlgorithm::Sha3_512 => write!(f, "sha3-512"),
            HashAlgorithm::Blake3 => write!(f, "blake3"),
        }
    }
}

/// Supported key derivation functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
    /// PBKDF2 with SHA-512
    Pbkdf2Sha512,
    /// Argon2id
    Argon2id,
    /// scrypt
    Scrypt,
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
}

impl fmt::Display for KdfAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfAlgorithm::Pbkdf2Sha256 => write!(f, "pbkdf2-sha256"),
            KdfAlgorithm::Pbkdf2Sha512 => write!(f, "pbkdf2-sha512"),
            KdfAlgorithm::Argon2id => write!(f, "argon2id"),
            KdfAlgorithm::Scrypt => write!(f, "scrypt"),
            KdfAlgorithm::HkdfSha256 => write!(f, "hkdf-sha256"),
            KdfAlgorithm::HkdfSha512 => write!(f, "hkdf-sha512"),
        }
    }
}

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 with SHA-512 (recommended)
    #[serde(alias = "ed25519")]
    Ed25519,
    /// ECDSA with P-256 and SHA-256
    #[serde(alias = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA with secp256k1 and SHA-256
    #[serde(alias = "ecdsa-secp256k1")]
    EcdsaSecp256k1,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::Ed25519 => write!(f, "ed25519"),
            SignatureAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256-sha256"),
            SignatureAlgorithm::EcdsaSecp256k1 => write!(f, "ecdsa-secp256k1-sha256"),
        }
    }
}

/// Hash data using the specified algorithm
pub fn hash_data(algorithm: HashAlgorithm, data: &[u8]) -> CryptoResult<Vec<u8>> {
    let digest = match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_384 => {
            let mut hasher = Sha3_384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
    };

    Ok(digest)
}

/// Derive key using the specified KDF algorithm
pub fn derive_key(
    algorithm: KdfAlgorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> CryptoResult<Vec<u8>> {
    match algorithm {
        KdfAlgorithm::Pbkdf2Sha256 => {
            use pbkdf2::pbkdf2_hmac;
            let mut key = vec![0u8; length];
            pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
            Ok(key)
        }
        KdfAlgorithm::Pbkdf2Sha512 => {
            use pbkdf2::pbkdf2_hmac;
            let mut key = vec![0u8; length];
            pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key);
            Ok(key)
        }
        KdfAlgorithm::Argon2id => {
            use argon2::{Algorithm, Argon2, Params, Version};
            let params = Params::new(
                65536, // memory cost (64 MB)
                iterations,
                1, // parallelism
                Some(length),
            )
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = vec![0u8; length];
            argon2
                .hash_password_into(password, salt, &mut key)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            Ok(key)
        }
        KdfAlgorithm::Scrypt => {
            use scrypt::{Params, scrypt};
            // log_n 14 (2^14 = 16384), r 8, p 1. The output length is taken from
            // the `key` buffer, not from `Params`.
            let params = Params::new(14, 8, 1)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

            let mut key = vec![0u8; length];
            scrypt(password, salt, &params, &mut key)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            Ok(key)
        }
        KdfAlgorithm::HkdfSha256 => {
            use hkdf::Hkdf;
            let hk = Hkdf::<Sha256>::new(Some(salt), password);
            let mut key = vec![0u8; length];
            hk.expand(&[], &mut key)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            Ok(key)
        }
        KdfAlgorithm::HkdfSha512 => {
            use hkdf::Hkdf;
            let hk = Hkdf::<Sha512>::new(Some(salt), password);
            let mut key = vec![0u8; length];
            hk.expand(&[], &mut key)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            Ok(key)
        }
    }
}

/// Generate cryptographically secure random bytes
pub fn generate_random(length: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    Ok(bytes)
}

/// Generate cryptographically secure random salt
pub fn generate_salt(length: usize) -> CryptoResult<Vec<u8>> {
    generate_random(length)
}

/// Constant-time comparison for cryptographic operations
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Secure random number generator trait
pub trait SecureRandom {
    fn fill_bytes(&mut self, dest: &mut [u8]);
    fn next_u32(&mut self) -> u32;
    fn next_u64(&mut self) -> u64;
}

impl SecureRandom for rand::rngs::ThreadRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::RngCore::fill_bytes(self, dest)
    }

    fn next_u32(&mut self) -> u32 {
        rand::RngCore::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand::RngCore::next_u64(self)
    }
}

/// Algorithm registry for dynamic algorithm selection
#[derive(Debug, Default)]
pub struct AlgorithmRegistry {
    supported_ciphers: Vec<String>,
    supported_hashes: Vec<HashAlgorithm>,
    supported_kdfs: Vec<KdfAlgorithm>,
    supported_signatures: Vec<SignatureAlgorithm>,
}

impl AlgorithmRegistry {
    /// Create new algorithm registry with default supported algorithms
    pub fn new() -> Self {
        Self {
            supported_ciphers: vec![
                "xchacha20-poly1305".to_string(),
                "chacha20-poly1305".to_string(),
                "aes-256-gcm".to_string(),
            ],
            supported_hashes: vec![
                HashAlgorithm::Blake3,
                HashAlgorithm::Sha3_512,
                HashAlgorithm::Sha3_384,
                HashAlgorithm::Sha3_256,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha256,
            ],
            supported_kdfs: vec![
                KdfAlgorithm::Argon2id,
                KdfAlgorithm::Scrypt,
                KdfAlgorithm::Pbkdf2Sha512,
                KdfAlgorithm::Pbkdf2Sha256,
                KdfAlgorithm::HkdfSha256,
                KdfAlgorithm::HkdfSha512,
            ],
            supported_signatures: vec![
                SignatureAlgorithm::Ed25519,
                SignatureAlgorithm::EcdsaP256,
                SignatureAlgorithm::EcdsaSecp256k1,
            ],
        }
    }

    /// Check if cipher is supported
    pub fn supports_cipher(&self, cipher: &str) -> bool {
        self.supported_ciphers.contains(&cipher.to_lowercase())
    }

    /// Check if hash algorithm is supported
    pub fn supports_hash(&self, hash: HashAlgorithm) -> bool {
        self.supported_hashes.contains(&hash)
    }

    /// Check if KDF algorithm is supported
    pub fn supports_kdf(&self, kdf: KdfAlgorithm) -> bool {
        self.supported_kdfs.contains(&kdf)
    }

    /// Check if signature algorithm is supported
    pub fn supports_signature(&self, signature: SignatureAlgorithm) -> bool {
        self.supported_signatures.contains(&signature)
    }

    /// Get all supported algorithms
    pub fn supported_algorithms(&self) -> AlgorithmSupport {
        AlgorithmSupport {
            ciphers: self.supported_ciphers.clone(),
            hashes: self.supported_hashes.clone(),
            kdfs: self.supported_kdfs.clone(),
            signatures: self.supported_signatures.clone(),
        }
    }
}

/// Supported algorithms information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSupport {
    pub ciphers: Vec<String>,
    pub hashes: Vec<HashAlgorithm>,
    pub kdfs: Vec<KdfAlgorithm>,
    pub signatures: Vec<SignatureAlgorithm>,
}

/// Cryptographic parameters for algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoParams {
    /// Salt for key derivation (if applicable)
    pub salt: Option<Vec<u8>>,
    /// Iteration count for KDF
    pub iterations: Option<u32>,
    /// Key length in bytes
    pub key_length: Option<usize>,
    /// Additional authenticated data (for AEAD)
    pub aad: Option<Vec<u8>>,
    /// Nonce/IV (if applicable)
    pub nonce: Option<Vec<u8>>,
}

impl Default for CryptoParams {
    fn default() -> Self {
        Self {
            salt: None,
            iterations: Some(100_000), // Default PBKDF2 iterations
            key_length: Some(32),      // Default to 256-bit keys
            aad: None,
            nonce: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithms() {
        let data = b"test data";

        // Test all hash algorithms
        for &algorithm in &[
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Blake3,
        ] {
            let digest = hash_data(algorithm, data).unwrap();
            assert!(!digest.is_empty());

            // Hash should be deterministic
            let digest2 = hash_data(algorithm, data).unwrap();
            assert_eq!(digest, digest2);
        }
    }

    #[test]
    fn test_kdf_algorithms() {
        let password = hex::encode(crate::generate_random_bytes(16).unwrap());
        let salt = crate::generate_random_bytes(16).unwrap();

        for &algorithm in &[
            KdfAlgorithm::Pbkdf2Sha256,
            KdfAlgorithm::Pbkdf2Sha512,
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha512,
        ] {
            let key = derive_key(algorithm, password.as_bytes(), &salt, 1000, 32).unwrap();
            assert_eq!(key.len(), 32);

            // KDF should be deterministic
            let key2 = derive_key(algorithm, password.as_bytes(), &salt, 1000, 32).unwrap();
            assert_eq!(key, key2);
        }
    }

    #[test]
    fn test_random_generation() {
        let random1 = generate_random(32).unwrap();
        let random2 = generate_random(32).unwrap();

        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2); // Should be different
    }

    #[test]
    fn test_algorithm_registry() {
        let registry = AlgorithmRegistry::new();

        assert!(registry.supports_cipher("aes-256-gcm"));
        assert!(registry.supports_hash(HashAlgorithm::Sha256));
        assert!(registry.supports_kdf(KdfAlgorithm::Pbkdf2Sha256));

        assert!(!registry.supports_cipher("unknown-cipher"));
    }
}
