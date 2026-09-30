//! Cryptographic hash functions and message authentication

use crate::{AlgorithmId, CryptoError, CryptoResult};
use blake3::Hasher as Blake3Hasher;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

/// Hash result container
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashResult {
    pub algorithm: AlgorithmId,
    pub hash: Vec<u8>,
    pub hex: String,
}

impl HashResult {
    pub fn new(algorithm: AlgorithmId, hash: Vec<u8>) -> Self {
        let hex = hex::encode(&hash);
        Self {
            algorithm,
            hash,
            hex,
        }
    }

    /// Verify if data matches this hash
    pub fn verify(&self, data: &[u8]) -> CryptoResult<bool> {
        let computed = compute_hash(self.algorithm, data)?;
        Ok(computed.hash == self.hash)
    }
}

/// Hash trait for different algorithms
pub trait HashFunction {
    fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
    fn hash_multiple(&self, data_chunks: &[&[u8]]) -> CryptoResult<Vec<u8>>;
}

/// SHA-256 implementation
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    fn hash_multiple(&self, data_chunks: &[&[u8]]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        for chunk in data_chunks {
            hasher.update(chunk);
        }
        Ok(hasher.finalize().to_vec())
    }
}

/// SHA3-256 implementation  
pub struct Sha3_256Hash;

impl HashFunction for Sha3_256Hash {
    fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    fn hash_multiple(&self, data_chunks: &[&[u8]]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        for chunk in data_chunks {
            hasher.update(chunk);
        }
        Ok(hasher.finalize().to_vec())
    }
}

/// BLAKE3 implementation
pub struct Blake3Hash;

impl HashFunction for Blake3Hash {
    fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    fn hash_multiple(&self, data_chunks: &[&[u8]]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Blake3Hasher::new();
        for chunk in data_chunks {
            hasher.update(chunk);
        }
        Ok(hasher.finalize().as_bytes().to_vec())
    }
}

/// Compute hash using specified algorithm
pub fn compute_hash(algorithm: AlgorithmId, data: &[u8]) -> CryptoResult<HashResult> {
    let hash = match algorithm {
        AlgorithmId::Sha256 => {
            let hasher = Sha256Hash;
            hasher.hash(data)?
        }
        AlgorithmId::Sha3_256 => {
            let hasher = Sha3_256Hash;
            hasher.hash(data)?
        }
        AlgorithmId::Blake3 => {
            let hasher = Blake3Hash;
            hasher.hash(data)?
        }
        _ => {
            return Err(CryptoError::HashFailed(format!(
                "Unsupported hash algorithm: {}",
                algorithm
            )));
        }
    };

    Ok(HashResult::new(algorithm, hash))
}

/// Compute hash for multiple data chunks
pub fn compute_hash_multiple(
    algorithm: AlgorithmId,
    data_chunks: &[&[u8]],
) -> CryptoResult<HashResult> {
    let hash = match algorithm {
        AlgorithmId::Sha256 => {
            let hasher = Sha256Hash;
            hasher.hash_multiple(data_chunks)?
        }
        AlgorithmId::Sha3_256 => {
            let hasher = Sha3_256Hash;
            hasher.hash_multiple(data_chunks)?
        }
        AlgorithmId::Blake3 => {
            let hasher = Blake3Hash;
            hasher.hash_multiple(data_chunks)?
        }
        _ => {
            return Err(CryptoError::HashFailed(format!(
                "Unsupported hash algorithm: {}",
                algorithm
            )));
        }
    };

    Ok(HashResult::new(algorithm, hash))
}

/// HMAC (Hash-based Message Authentication Code) support
pub type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| CryptoError::HashFailed(format!("HMAC key initialization failed: {}", e)))?;

    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected_mac: &[u8]) -> CryptoResult<bool> {
    let computed = compute_hmac_sha256(key, data)?;
    Ok(computed == expected_mac)
}

/// Password hashing utilities
pub mod password {
    use super::*;
    use argon2::{
        Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::phc::Salt,
    };
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    /// Password hash result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PasswordHashResult {
        pub algorithm: AlgorithmId,
        pub hash: String,
        pub salt: Vec<u8>,
        pub iterations: u32,
    }

    /// Hash password with Argon2id
    pub fn hash_password_argon2(password: &str) -> CryptoResult<PasswordHashResult> {
        let salt = Salt::generate();
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password_with_salt(password.as_bytes(), salt.as_ref())
            .map_err(|e| {
                CryptoError::HashFailed(format!("Argon2 password hashing failed: {}", e))
            })?;

        Ok(PasswordHashResult {
            algorithm: AlgorithmId::Argon2id,
            hash: password_hash.to_string(),
            salt: salt.to_salt_string().as_ref().as_bytes().to_vec(),
            iterations: 3, // Default Argon2 iterations
        })
    }

    /// Verify password with Argon2id
    pub fn verify_password_argon2(password: &str, hash: &str) -> CryptoResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| CryptoError::HashFailed(format!("Invalid password hash format: {}", e)))?;

        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Hash password with PBKDF2
    pub fn hash_password_pbkdf2(
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> CryptoResult<Vec<u8>> {
        const KEY_LENGTH: usize = 32;
        let mut key = vec![0u8; KEY_LENGTH];

        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello, Secreton!";
        let result = compute_hash(AlgorithmId::Sha256, data).unwrap();

        assert_eq!(result.algorithm, AlgorithmId::Sha256);
        assert_eq!(result.hash.len(), 32); // SHA-256 produces 32-byte hash
        assert!(!result.hex.is_empty());

        // Verify hash matches
        assert!(result.verify(data).unwrap());
        assert!(!result.verify(b"Different data").unwrap());
    }

    #[test]
    fn test_sha3_256_hash() {
        let data = b"SHA3 test data";
        let result = compute_hash(AlgorithmId::Sha3_256, data).unwrap();

        assert_eq!(result.algorithm, AlgorithmId::Sha3_256);
        assert_eq!(result.hash.len(), 32);
        assert!(result.verify(data).unwrap());
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"BLAKE3 test data";
        let result = compute_hash(AlgorithmId::Blake3, data).unwrap();

        assert_eq!(result.algorithm, AlgorithmId::Blake3);
        assert_eq!(result.hash.len(), 32);
        assert!(result.verify(data).unwrap());
    }

    #[test]
    fn test_hmac_sha256() {
        let key = crate::generate_random_bytes(32).expect("os randomness");
        let data = b"message to authenticate";

        let mac1 = compute_hmac_sha256(&key, data).unwrap();
        let mac2 = compute_hmac_sha256(&key, data).unwrap();

        assert_eq!(mac1, mac2); // Same input should produce same MAC
        assert!(verify_hmac_sha256(&key, data, &mac1).unwrap());
        let other = crate::generate_random_bytes(32).expect("os randomness");
        assert!(!verify_hmac_sha256(&other, data, &mac1).unwrap());
    }

    #[test]
    fn test_multiple_chunks_hash() {
        let chunks = [b"Hello, ".as_slice(), b"World!".as_slice()];
        let combined = b"Hello, World!";

        let result1 = compute_hash_multiple(AlgorithmId::Sha256, &chunks).unwrap();
        let result2 = compute_hash(AlgorithmId::Sha256, combined).unwrap();

        assert_eq!(result1.hash, result2.hash);
    }

    #[test]
    fn test_password_hashing_argon2() {
        // The input is drawn from the OS: a literal here is a credential to a scanner
        // and a reader alike, and nothing about the test needs a specific string.
        let password = hex::encode(crate::generate_random_bytes(16).expect("os randomness"));
        let hash_result = password::hash_password_argon2(&password).unwrap();

        assert_eq!(hash_result.algorithm, AlgorithmId::Argon2id);
        assert!(!hash_result.hash.is_empty());

        // Verify password
        assert!(password::verify_password_argon2(&password, &hash_result.hash).unwrap());
        let wrong = format!("{password}-wrong");
        assert!(!password::verify_password_argon2(&wrong, &hash_result.hash).unwrap());
    }
}
