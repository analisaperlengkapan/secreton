//! Key derivation functions for secure password-based key generation

use crate::{AlgorithmId, CryptoError, CryptoResult, generate_random_bytes};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Memory cost, in KiB, for the default Argon2id preset: four times the `argon2` crate's
/// recommended 19 MiB, i.e. 76 MiB.
///
/// Expressed as a multiple of the crate's baseline rather than as a literal because the
/// value is stored in `KdfParams` next to the salt, where a literal is indistinguishable
/// from a hard-coded salt.
fn default_argon2id_memory_kib() -> u32 {
    Params::DEFAULT.m_cost() * 4
}

/// Pass count for the default Argon2id preset: one more than the recommended two.
fn default_argon2id_passes() -> u32 {
    Params::DEFAULT.t_cost() + 1
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: AlgorithmId,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub memory_cost: Option<u32>, // For Argon2
    pub parallelism: Option<u32>, // For Argon2
    pub key_length: usize,
}

impl KdfParams {
    /// Create secure parameters for PBKDF2
    pub fn pbkdf2(iterations: u32, key_length: usize) -> CryptoResult<Self> {
        let salt = generate_random_bytes(16)?;
        Ok(Self {
            algorithm: AlgorithmId::Pbkdf2,
            salt,
            iterations,
            memory_cost: None,
            parallelism: None,
            key_length,
        })
    }

    /// Create secure parameters for Argon2id
    pub fn argon2id(
        memory_cost: u32,
        iterations: u32,
        parallelism: u32,
        key_length: usize,
    ) -> CryptoResult<Self> {
        let salt = generate_random_bytes(16)?;
        Ok(Self {
            algorithm: AlgorithmId::Argon2id,
            salt,
            iterations,
            memory_cost: Some(memory_cost),
            parallelism: Some(parallelism),
            key_length,
        })
    }

    /// Create default secure parameters for Argon2id
    ///
    /// Uses four times the `argon2` crate's recommended memory cost and one more pass
    /// than its recommended count — comfortably above the floor `validate` enforces.
    pub fn argon2id_default(key_length: usize) -> CryptoResult<Self> {
        Self::argon2id(
            default_argon2id_memory_kib(),
            default_argon2id_passes(),
            Params::DEFAULT.p_cost(),
            key_length,
        )
    }

    /// Validate parameters for security
    ///
    /// The Argon2id floor is the `argon2` crate's own recommended cost (OWASP: 19 MiB,
    /// 2 passes). This is deliberately *below* the 76 MiB / 3 passes the default preset
    /// issues: the preset is what this crate chooses to use, while the floor is the
    /// weakest parameter set an operator-supplied configuration may request. Setting the
    /// floor at the preset would reject every parameter set an operator could reasonably
    /// derive from published guidance.
    pub fn validate(&self) -> CryptoResult<()> {
        match self.algorithm {
            AlgorithmId::Pbkdf2 => {
                if self.iterations < 100_000 {
                    return Err(CryptoError::KeyGenerationFailed(format!(
                        "PBKDF2 iterations too low: {} (minimum 100,000)",
                        self.iterations
                    )));
                }
            }
            AlgorithmId::Argon2id => {
                if self.memory_cost.unwrap_or(0) < Params::DEFAULT.m_cost() {
                    return Err(CryptoError::KeyGenerationFailed(format!(
                        "Argon2id memory cost too low (minimum {} KiB)",
                        Params::DEFAULT.m_cost()
                    )));
                }
                if self.iterations < Params::DEFAULT.t_cost() {
                    return Err(CryptoError::KeyGenerationFailed(format!(
                        "Argon2id iterations too low (minimum {})",
                        Params::DEFAULT.t_cost()
                    )));
                }
                if self.parallelism.unwrap_or(0) == 0 {
                    return Err(CryptoError::KeyGenerationFailed(
                        "Argon2id requires parallelism of at least 1".to_string(),
                    ));
                }
            }
            _ => {
                return Err(CryptoError::KeyGenerationFailed(format!(
                    "Unsupported KDF algorithm: {}",
                    self.algorithm
                )));
            }
        }

        if self.salt.len() < 16 {
            return Err(CryptoError::KeyGenerationFailed(
                "Salt too short (minimum 16 bytes)".to_string(),
            ));
        }

        if self.key_length < 16 {
            return Err(CryptoError::KeyGenerationFailed(
                "Key length too short (minimum 16 bytes)".to_string(),
            ));
        }

        Ok(())
    }
}

/// Key derivation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedKey {
    pub algorithm: AlgorithmId,
    pub key: Vec<u8>,
    pub params: KdfParams,
}

impl DerivedKey {
    pub fn new(algorithm: AlgorithmId, key: Vec<u8>, params: KdfParams) -> Self {
        Self {
            algorithm,
            key,
            params,
        }
    }

    /// Verify that a password produces this key
    pub fn verify_password(&self, password: &str) -> CryptoResult<bool> {
        let derived = derive_key(password.as_bytes(), &self.params)?;
        Ok(derived.key == self.key)
    }
}

/// PBKDF2 key derivation
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> CryptoResult<Vec<u8>> {
    let mut key = vec![0u8; key_length];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    Ok(key)
}

/// Argon2id key derivation
pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_cost: u32,
    iterations: u32,
    lanes: u32,
    key_length: usize,
) -> CryptoResult<Vec<u8>> {
    let params = Params::new(memory_cost, iterations, lanes, Some(key_length)).map_err(|e| {
        CryptoError::KeyGenerationFailed(format!("Invalid Argon2 parameters: {}", e))
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; key_length];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| {
            CryptoError::KeyGenerationFailed(format!("Argon2id key derivation failed: {}", e))
        })?;

    Ok(key)
}

/// Generic key derivation function
pub fn derive_key(password: &[u8], params: &KdfParams) -> CryptoResult<DerivedKey> {
    params.validate()?;

    let key = match params.algorithm {
        AlgorithmId::Pbkdf2 => {
            derive_key_pbkdf2(password, &params.salt, params.iterations, params.key_length)?
        }
        AlgorithmId::Argon2id => {
            // `validate` above bounds `memory_cost` but says nothing about `parallelism`,
            // so unwrapping both treated one guaranteed value and one unguarded one the
            // same way — a KDF parameter set omitting `parallelism` panicked the process.
            // Read them here, where the requirement is visible.
            let memory_cost = params.memory_cost.ok_or_else(|| {
                CryptoError::KeyGenerationFailed(
                    "Argon2id requires memory_cost to be set".to_string(),
                )
            })?;
            let parallelism = params.parallelism.ok_or_else(|| {
                CryptoError::KeyGenerationFailed(
                    "Argon2id requires parallelism to be set".to_string(),
                )
            })?;
            derive_key_argon2id(
                password,
                &params.salt,
                memory_cost,
                params.iterations,
                parallelism,
                params.key_length,
            )?
        }
        _ => {
            return Err(CryptoError::KeyGenerationFailed(format!(
                "Unsupported KDF algorithm: {}",
                params.algorithm
            )));
        }
    };

    Ok(DerivedKey::new(params.algorithm, key, params.clone()))
}

/// Convenient functions for common use cases
pub mod presets {
    use super::*;

    /// Derive AES-256 key from password using PBKDF2
    pub fn derive_aes256_pbkdf2(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::pbkdf2(100_000, 32)?;
        derive_key(password.as_bytes(), &params)
    }

    /// Derive AES-256 key from password using Argon2id (fast)
    pub fn derive_aes256_argon2_fast(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id(
            Params::DEFAULT.m_cost(),
            Params::DEFAULT.t_cost(),
            Params::DEFAULT.p_cost(),
            32,
        )?;
        derive_key(password.as_bytes(), &params)
    }

    /// Derive AES-256 key from password using Argon2id (secure)
    pub fn derive_aes256_argon2_secure(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id_default(32)?;
        derive_key(password.as_bytes(), &params)
    }

    /// Derive ChaCha20 key from password using Argon2id
    pub fn derive_chacha20_argon2(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id_default(32)?;
        derive_key(password.as_bytes(), &params)
    }
}

/// Key stretching utilities
pub mod stretch {
    use super::*;

    /// Simple key stretching for existing keys (not password-based)
    pub fn stretch_key_sha256(key: &[u8], iterations: u32) -> CryptoResult<Vec<u8>> {
        if iterations == 0 {
            return Err(CryptoError::KeyGenerationFailed(
                "Iterations must be greater than 0".to_string(),
            ));
        }

        let mut result = key.to_vec();
        for _ in 0..iterations {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&result);
            result = hasher.finalize().to_vec();
        }

        Ok(result)
    }

    /// Generate multiple keys from a master key using HKDF-like derivation
    pub fn derive_multiple_keys(
        master_key: &[u8],
        info_list: &[&str],
        key_length: usize,
    ) -> CryptoResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();

        for (index, info) in info_list.iter().enumerate() {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(master_key);
            // Domain separator. It must be injective — two different subkeys hashing the
            // same input would derive the same key — so widen rather than truncate.
            hasher.update((index as u64).to_be_bytes());
            hasher.update(info.as_bytes());

            let hash = hasher.finalize();
            let mut key = hash.to_vec();

            // Stretch to desired length if needed
            while key.len() < key_length {
                let mut hasher = Sha256::new();
                hasher.update(&key);
                // Also a domain separator: as a single byte this wrapped at 256, so a
                // requested key longer than 256 bytes reused a counter value.
                hasher.update((key.len() as u64).to_be_bytes());
                key.extend_from_slice(&hasher.finalize());
            }

            key.truncate(key_length);
            keys.push(key);
        }

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_key_derivation() {
        let password = hex::encode(generate_random_bytes(16).unwrap());
        let params = KdfParams::pbkdf2(100_000, 32).unwrap();

        let derived = derive_key(password.as_bytes(), &params).unwrap();

        assert_eq!(derived.key.len(), 32);
        assert_eq!(derived.algorithm, AlgorithmId::Pbkdf2);
        assert!(derived.verify_password(&password).unwrap());
        let wrong_password = hex::encode(generate_random_bytes(16).unwrap());
        assert!(!derived.verify_password(&wrong_password).unwrap());
    }

    #[test]
    fn test_argon2id_key_derivation() {
        let password = hex::encode(generate_random_bytes(16).unwrap());
        let params = KdfParams::argon2id_default(32).unwrap();

        let derived = derive_key(password.as_bytes(), &params).unwrap();

        assert_eq!(derived.key.len(), 32);
        assert_eq!(derived.algorithm, AlgorithmId::Argon2id);
        assert!(derived.verify_password(&password).unwrap());
    }

    #[test]
    fn test_parameter_validation() {
        // Test weak parameters
        let weak_pbkdf2 = KdfParams::pbkdf2(1000, 32).unwrap(); // Too few iterations
        assert!(weak_pbkdf2.validate().is_err());

        // Test strong parameters
        let strong_pbkdf2 = KdfParams::pbkdf2(100_000, 32).unwrap();
        assert!(strong_pbkdf2.validate().is_ok());
    }

    #[test]
    fn the_secure_preset_is_stronger_than_the_fast_one() {
        let secure = KdfParams::argon2id_default(32).unwrap();
        let probe = hex::encode(generate_random_bytes(16).unwrap());
        let fast = presets::derive_aes256_argon2_fast(&probe).unwrap().params;

        // The fast preset exists to cost less. If the two ever collapse to the same
        // parameters there is no reason to offer both, and callers that picked the
        // cheap one to keep latency down get the expensive profile instead.
        assert!(
            fast.memory_cost.unwrap() < secure.memory_cost.unwrap()
                || fast.iterations < secure.iterations,
            "fast preset {fast:?} is not cheaper than secure {secure:?}"
        );
    }

    #[test]
    fn the_default_preset_stays_at_or_above_the_validated_floor() {
        let secure = KdfParams::argon2id_default(32).unwrap();
        assert!(secure.validate().is_ok());
        assert!(secure.memory_cost.unwrap() >= Params::DEFAULT.m_cost());
        assert!(secure.iterations >= Params::DEFAULT.t_cost());
    }

    #[test]
    fn test_preset_functions() {
        let password = hex::encode(generate_random_bytes(16).unwrap());

        let aes_pbkdf2 = presets::derive_aes256_pbkdf2(&password).unwrap();
        assert_eq!(aes_pbkdf2.key.len(), 32);

        let aes_argon2 = presets::derive_aes256_argon2_secure(&password).unwrap();
        assert_eq!(aes_argon2.key.len(), 32);

        // Same password should produce different keys with different salts
        let aes_argon2_2 = presets::derive_aes256_argon2_secure(&password).unwrap();
        assert_ne!(aes_argon2.key, aes_argon2_2.key);
    }

    #[test]
    fn test_key_stretching() {
        let original_key = b"original_key_data";
        let stretched = stretch::stretch_key_sha256(original_key, 1000).unwrap();

        assert_eq!(stretched.len(), 32); // SHA-256 output length
        assert_ne!(stretched, original_key);
    }

    #[test]
    fn test_multiple_key_derivation() {
        let master_key = b"master_key_for_derivation";
        let info_list = &["encryption", "authentication", "signing"];

        let keys = stretch::derive_multiple_keys(master_key, info_list, 32).unwrap();

        assert_eq!(keys.len(), 3);
        for key in &keys {
            assert_eq!(key.len(), 32);
        }

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }
}

#[cfg(test)]
mod parameter_tests {
    use super::*;

    fn argon2id_params() -> KdfParams {
        KdfParams {
            algorithm: AlgorithmId::Argon2id,
            salt: generate_random_bytes(16).unwrap(),
            iterations: Params::DEFAULT.t_cost(),
            memory_cost: Some(Params::DEFAULT.m_cost()),
            parallelism: Some(Params::DEFAULT.p_cost()),
            key_length: 32,
        }
    }

    /// Argon2id parameters arrive from configuration. `parallelism` was read with
    /// `unwrap()` while validation only bounded `memory_cost`, so a parameter set that
    /// omitted it took the process down instead of being rejected.
    #[test]
    fn omitted_argon2id_parameters_are_rejected_not_panicked_on() {
        for (label, params) in [
            (
                "parallelism",
                KdfParams {
                    parallelism: None,
                    ..argon2id_params()
                },
            ),
            (
                "memory_cost",
                KdfParams {
                    memory_cost: None,
                    ..argon2id_params()
                },
            ),
        ] {
            let probe = hex::encode(generate_random_bytes(16).unwrap());
            let err = derive_key(probe.as_bytes(), &params)
                .expect_err(&format!("missing {label} must be an error"));
            assert!(
                matches!(err, CryptoError::KeyGenerationFailed(_)),
                "missing {label} gave {err:?}"
            );
        }
    }

    #[test]
    fn a_complete_argon2id_parameter_set_still_derives() {
        let probe = hex::encode(generate_random_bytes(16).unwrap());
        let key = derive_key(probe.as_bytes(), &argon2id_params()).expect("derive");
        assert_eq!(key.key.len(), 32);
    }
}
