//! Transit keys implementation with RustCrypto integration

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Key},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, XChaCha20Poly1305};
// CLEANUP: Removed unused imports
// use digest::Digest; // Not used
use ed25519_dalek::{
    Signature as Ed25519Signature,
    SigningKey as Ed25519SigningKey,
    // VerifyingKey as Ed25519VerifyingKey, // Not used
};
use hkdf::Hkdf;
use k256::{
    SecretKey as K256SecretKey, // Re-enable: used in KeyMaterial enum
    ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey},
};
use p256::{
    SecretKey as P256SecretKey, // Re-enable: used in KeyMaterial enum
    ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey},
};
use sha2::Sha256;
// use sha2::{Sha384, Sha512}; // Not used
// use sha3::{Sha3_256, Sha3_512}; // Not used
use signature::Signer;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use crate::error::{CryptoError, CryptoResult};
use crate::transit::algorithms::SignatureAlgorithm;
use chrono::{DateTime, Utc};
// use rand::Rng; // Not used
use rand::RngCore;
// use rand::CryptoRng; // Not used
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// CLEANUP: Zeroize imports not used in this scope
// use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported key types for the transit engine
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// AES-256-GCM symmetric encryption
    #[serde(alias = "aes256-gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption
    #[serde(alias = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 symmetric encryption (extended nonce)
    #[serde(alias = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    /// Ed25519 key for signing
    #[serde(alias = "ed25519")]
    Ed25519,
    /// ECDSA key using P-256 curve
    #[serde(alias = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA key using secp256k1 curve
    #[serde(alias = "ecdsa-secp256k1")]
    EcdsaSecp256k1,
    /// X25519 key for key exchange
    #[serde(alias = "x25519")]
    X25519,
    /// RSA key for signing/encryption
    Rsa(u32),
}

/// Key derivation options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyOptions {
    /// Whether key can be exported (default: false)
    pub exportable: bool,
    /// Key usage constraints
    pub usage: Vec<KeyUsage>,
    /// Minimum key version for decryption (default: 1)
    pub min_decryption_version: u32,
    /// Whether to allow plaintext backup (default: false)
    pub allow_plaintext_backup: bool,
    /// Key derivation context if applicable
    pub context: Option<Vec<u8>>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Default for KeyOptions {
    fn default() -> Self {
        Self {
            exportable: false,
            usage: vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
            min_decryption_version: 1,
            allow_plaintext_backup: false,
            context: None,
            metadata: HashMap::new(),
        }
    }
}

/// Key usage constraints
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Derive,
}

/// Transit key with versioning and RustCrypto backends
#[derive(Debug)]
pub struct TransitKey {
    /// Key name
    name: String,
    /// Key type
    key_type: KeyType,
    /// Key options
    options: KeyOptions,
    /// Key versions (version -> key material)
    versions: HashMap<u32, KeyVersion>,
    /// Latest version number
    latest_version: u32,
    /// Creation time
    created_at: DateTime<Utc>,
    /// Last rotation time
    last_rotated_at: Option<DateTime<Utc>>,
}

/// Individual key version with cryptographic material
#[derive(Debug)]
struct KeyVersion {
    /// Key material (zeroized on drop)
    material: KeyMaterial,
}

/// Cryptographic key material (zeroized on drop)
#[derive(Debug)]
enum KeyMaterial {
    /// AES-256-GCM key
    Aes256Gcm(Box<[u8; 32]>),
    /// ChaCha20-Poly1305 key
    ChaCha20Poly1305(Box<[u8; 32]>),
    /// XChaCha20-Poly1305 key
    XChaCha20Poly1305(Box<[u8; 32]>),
    /// ECDSA P-256 private key
    EcdsaP256(Box<P256SecretKey>),
    /// ECDSA secp256k1 private key
    EcdsaSecp256k1(Box<K256SecretKey>),
    /// Ed25519 private key
    Ed25519(Box<Ed25519SigningKey>),
    /// X25519 private key for key exchange and encryption
    X25519(Box<[u8; 32]>),
}

impl TransitKey {
    /// Create a new transit key
    pub fn new(name: String, key_type: KeyType, options: KeyOptions) -> CryptoResult<Self> {
        let version = KeyVersion::new(1, &key_type)?;
        let mut versions = HashMap::new();
        versions.insert(1, version);

        Ok(Self {
            name,
            key_type,
            options,
            versions,
            latest_version: 1,
            created_at: Utc::now(),
            last_rotated_at: None,
        })
    }

    /// Rotate key (create new version)
    pub fn rotate(&mut self) -> CryptoResult<u32> {
        let new_version = self.latest_version + 1;
        let version = KeyVersion::new(new_version, &self.key_type)?;

        self.versions.insert(new_version, version);
        self.latest_version = new_version;
        self.last_rotated_at = Some(Utc::now());

        Ok(new_version)
    }

    /// Get key information
    pub fn info(&self) -> KeyInfo {
        KeyInfo {
            name: self.name.clone(),
            key_type: self.key_type.clone(),
            latest_version: self.latest_version,
            min_decryption_version: self.options.min_decryption_version,
            created_at: self.created_at,
            last_rotated_at: self.last_rotated_at,
            versions: self.versions.keys().copied().collect(),
            usage: self.options.usage.clone(),
            exportable: self.options.exportable,
        }
    }

    /// Encrypt data
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: Option<&[u8]>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let version = key_version.unwrap_or(self.latest_version);
        let key_version = self
            .versions
            .get(&version)
            .ok_or(CryptoError::KeyVersionNotFound(version))?;

        // Check if encrypt usage is allowed
        if !self.options.usage.contains(&KeyUsage::Encrypt) {
            return Err(CryptoError::InvalidUsage(
                "Encryption not allowed for this key".to_string(),
            ));
        }

        let ciphertext = match &key_version.material {
            KeyMaterial::Aes256Gcm(key_bytes) => {
                let key = Key::<Aes256Gcm>::from(**key_bytes);
                let cipher = Aes256Gcm::new(&key);

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                // `nonce_bytes` is already `[u8; 12]`; the round trip through a slice
                // only created a fallible conversion to unwrap.
                let nonce = ChaChaNonce::from(nonce_bytes);

                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }

                let encrypted = cipher
                    .encrypt(&nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                // Format: version:nonce:ciphertext
                let mut result = format!("v{}:", version);
                result.push_str(&BASE64.encode(nonce_bytes));
                result.push(':');
                result.push_str(&BASE64.encode(&encrypted));
                result
            }

            KeyMaterial::ChaCha20Poly1305(key_bytes) => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).map_err(|_| {
                        CryptoError::InvalidKeyLength {
                            expected: 32,
                            actual: key_bytes.len(),
                        }
                    })?;

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                // `nonce_bytes` is already `[u8; 12]`; the round trip through a slice
                // only created a fallible conversion to unwrap.
                let nonce = ChaChaNonce::from(nonce_bytes);

                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }

                let encrypted = cipher
                    .encrypt(&nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                let mut result = format!("v{}:", version);
                result.push_str(&BASE64.encode(nonce_bytes));
                result.push(':');
                result.push_str(&BASE64.encode(&encrypted));
                result
            }

            KeyMaterial::XChaCha20Poly1305(key_bytes) => {
                let cipher =
                    XChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).map_err(|_| {
                        CryptoError::InvalidKeyLength {
                            expected: 32,
                            actual: key_bytes.len(),
                        }
                    })?;

                let mut nonce_bytes = [0u8; 24]; // XChaCha20 uses 192-bit nonce
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }

                let encrypted = cipher
                    .encrypt(&nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                let mut result = format!("v{}:", version);
                result.push_str(&BASE64.encode(nonce_bytes));
                result.push(':');
                result.push_str(&BASE64.encode(&encrypted));
                result
            }

            KeyMaterial::X25519(private_key_bytes) => {
                // X25519 encryption using ECIES-like approach
                // Generate ephemeral key pair for this encryption
                let mut ephemeral_scalar = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut ephemeral_scalar);

                // Compute ephemeral public key
                let ephemeral_public = x25519(ephemeral_scalar, X25519_BASEPOINT_BYTES);

                // Compute shared secret using our private key and ephemeral public key
                let shared_secret = x25519(**private_key_bytes, ephemeral_public);

                // Derive AES key from shared secret using HKDF, salted with the
                // ephemeral public key. The salt is transmitted in the ciphertext, and
                // using it replaces the constant, empty HKDF salt this path used before.
                let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&ephemeral_public), &shared_secret);
                // `expand` overwrites every byte of the destination, so the buffer needs
                // no initial value — and drawing one from the OS would only add a
                // failure path to every encryption.
                let mut aes_key = Key::<Aes256Gcm>::default();
                hkdf.expand(b"secreton-x25519-aes", aes_key.as_mut())
                    .map_err(|_| {
                        CryptoError::KeyDerivationFailed("HKDF expansion failed".to_string())
                    })?;

                // Encrypt with AES-GCM
                let cipher = Aes256Gcm::new(&aes_key);

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = ChaChaNonce::from(nonce_bytes);

                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }

                let encrypted = cipher
                    .encrypt(&nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                // Format: v<version>:<ephemeral_public_key>:<nonce>:<ciphertext>
                //
                // The `x25519:v1` segment is a derivation marker. The key version names
                // the transit key material, not the ciphertext derivation scheme, so it
                // cannot distinguish the salted derivation below from the unsalted one
                // that earlier releases used. `decrypt` reads the marker to pick the
                // matching derivation, which keeps ciphertext issued before the salt was
                // introduced decryptable.
                let mut result = format!("v{}:x25519:v1:", version);
                result.push_str(&BASE64.encode(ephemeral_public));
                result.push(':');
                result.push_str(&BASE64.encode(nonce_bytes));
                result.push(':');
                result.push_str(&BASE64.encode(&encrypted));
                result
            }

            _ => {
                return Err(CryptoError::InvalidUsage(
                    "Key type does not support encryption".to_string(),
                ));
            }
        };

        Ok(ciphertext)
    }

    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &str, context: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        // Parse format: v<version>:<nonce>:<ciphertext> or v<version>:<ciphertext>.
        // X25519 records additionally carry an ephemeral key and a derivation marker;
        // see the `KeyMaterial::X25519` arm below.
        let parts: Vec<&str> = ciphertext.split(':').collect();
        if parts.len() < 2 {
            return Err(CryptoError::InvalidCiphertext("Invalid format".to_string()));
        }

        // Extract version
        let version_str = parts[0]
            .strip_prefix('v')
            .ok_or_else(|| CryptoError::InvalidCiphertext("Missing version prefix".to_string()))?;
        let version: u32 = version_str
            .parse()
            .map_err(|_| CryptoError::InvalidCiphertext("Invalid version".to_string()))?;

        // Check minimum decryption version
        if version < self.options.min_decryption_version {
            return Err(CryptoError::InvalidUsage(
                "Key version too old for decryption".to_string(),
            ));
        }

        let key_version = self
            .versions
            .get(&version)
            .ok_or(CryptoError::KeyVersionNotFound(version))?;

        // Check if decrypt usage is allowed
        if !self.options.usage.contains(&KeyUsage::Decrypt) {
            return Err(CryptoError::InvalidUsage(
                "Decryption not allowed for this key".to_string(),
            ));
        }

        let plaintext = match &key_version.material {
            KeyMaterial::Aes256Gcm(key_bytes) => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext(
                        "Invalid AES-GCM format".to_string(),
                    ));
                }

                let key = Key::<Aes256Gcm>::from(**key_bytes);
                let cipher = Aes256Gcm::new(&key);

                let nonce_bytes = BASE64.decode(parts[1]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string())
                })?;
                let nonce_array: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidCiphertext(
                        "Invalid nonce length (expected 12 bytes)".to_string(),
                    )
                })?;
                let nonce = ChaChaNonce::from(nonce_array);

                let encrypted_bytes = BASE64.decode(parts[2]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string())
                })?;

                let mut decrypted = cipher
                    .decrypt(&nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                // Remove context if present
                if let Some(ctx) = context
                    && decrypted.len() >= ctx.len()
                    && decrypted.ends_with(ctx)
                {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }

                decrypted
            }

            KeyMaterial::ChaCha20Poly1305(key_bytes) => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext(
                        "Invalid ChaCha20Poly1305 format".to_string(),
                    ));
                }

                let cipher =
                    ChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).map_err(|_| {
                        CryptoError::InvalidKeyLength {
                            expected: 32,
                            actual: key_bytes.len(),
                        }
                    })?;

                let nonce_bytes = BASE64.decode(parts[1]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string())
                })?;
                let nonce_array: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidCiphertext(
                        "Invalid nonce length (expected 12 bytes)".to_string(),
                    )
                })?;
                let nonce = ChaChaNonce::from(nonce_array);

                let encrypted_bytes = BASE64.decode(parts[2]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string())
                })?;

                let mut decrypted = cipher
                    .decrypt(&nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                // Remove context if present
                if let Some(ctx) = context
                    && decrypted.len() >= ctx.len()
                    && decrypted.ends_with(ctx)
                {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }

                decrypted
            }

            KeyMaterial::XChaCha20Poly1305(key_bytes) => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext(
                        "Invalid XChaCha20Poly1305 format".to_string(),
                    ));
                }

                let cipher =
                    XChaCha20Poly1305::new_from_slice(key_bytes.as_slice()).map_err(|_| {
                        CryptoError::InvalidKeyLength {
                            expected: 32,
                            actual: key_bytes.len(),
                        }
                    })?;

                let nonce_bytes = BASE64.decode(parts[1]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string())
                })?;

                let nonce_array: [u8; 24] = nonce_bytes.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidCiphertext(
                        "Invalid nonce length (expected 24 bytes)".to_string(),
                    )
                })?;
                let nonce = chacha20poly1305::XNonce::from(nonce_array);

                let encrypted_bytes = BASE64.decode(parts[2]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string())
                })?;

                let mut decrypted = cipher
                    .decrypt(&nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                // Remove context if present
                if let Some(ctx) = context
                    && decrypted.len() >= ctx.len()
                    && decrypted.ends_with(ctx)
                {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }

                decrypted
            }

            KeyMaterial::X25519(private_key_bytes) => {
                // Two layouts are accepted:
                //
                //   v<version>:x25519:v1:<ephemeral>:<nonce>:<ciphertext>   (salted)
                //   v<version>:<ephemeral>:<nonce>:<ciphertext>             (legacy, unsalted)
                //
                // The `x25519` marker's presence is what separates them. It is never a
                // valid base64 ephemeral key (base64 never emits ':'), so a legacy record
                // can never be misread as a marked one. When the marker is absent the
                // derivation must be the legacy unsalted one, or ciphertext issued before
                // the salt was introduced stops authenticating.
                let (salted, parts) = if parts.get(1) == Some(&"x25519") {
                    let derivation = parts.get(2).copied().unwrap_or("");
                    if derivation != "v1" {
                        return Err(CryptoError::InvalidCiphertext(format!(
                            "Unknown X25519 derivation version '{derivation}'"
                        )));
                    }
                    (true, &parts[3..])
                } else {
                    (false, &parts[1..])
                };

                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext(
                        "Invalid X25519 format".to_string(),
                    ));
                }

                // Decode ephemeral public key
                let ephemeral_public_bytes = BASE64.decode(parts[0]).map_err(|_| {
                    CryptoError::InvalidCiphertext(
                        "Invalid ephemeral public key encoding".to_string(),
                    )
                })?;
                let ephemeral_public: [u8; 32] =
                    ephemeral_public_bytes.as_slice().try_into().map_err(|_| {
                        CryptoError::InvalidCiphertext(
                            "Invalid ephemeral public key length".to_string(),
                        )
                    })?;

                // Decode nonce
                let nonce_bytes = BASE64.decode(parts[1]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string())
                })?;
                let nonce_array: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidCiphertext(
                        "Invalid nonce length (expected 12 bytes)".to_string(),
                    )
                })?;
                let nonce = ChaChaNonce::from(nonce_array);

                // Decode ciphertext
                let encrypted_bytes = BASE64.decode(parts[2]).map_err(|_| {
                    CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string())
                })?;

                // Compute shared secret using our private key and ephemeral public key
                let shared_secret = x25519(**private_key_bytes, ephemeral_public);

                // Derive AES key from shared secret. A marked record was salted with the
                // ephemeral public key by the encryptor; a legacy record used no salt.
                let mut aes_key = Key::<Aes256Gcm>::default();
                let salt: Option<&[u8]> = if salted {
                    Some(ephemeral_public.as_slice())
                } else {
                    None
                };
                hkdf::Hkdf::<sha2::Sha256>::new(salt, &shared_secret)
                    .expand(b"secreton-x25519-aes", aes_key.as_mut())
                    .map_err(|_| {
                        CryptoError::KeyDerivationFailed("HKDF expansion failed".to_string())
                    })?;

                // Decrypt with AES-GCM
                let cipher = Aes256Gcm::new(&aes_key);

                let mut decrypted = cipher
                    .decrypt(&nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                // Remove context if present
                if let Some(ctx) = context
                    && decrypted.len() >= ctx.len()
                    && decrypted.ends_with(ctx)
                {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }

                decrypted
            }

            _ => {
                return Err(CryptoError::InvalidUsage(
                    "Key type does not support decryption".to_string(),
                ));
            }
        };

        Ok(plaintext)
    }

    /// Sign data using specified algorithm (validates compatibility with key type)
    pub fn sign(
        &self,
        data: &[u8],
        algorithm: Option<SignatureAlgorithm>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let version = key_version.unwrap_or(self.latest_version);
        let key_version = self
            .versions
            .get(&version)
            .ok_or(CryptoError::KeyVersionNotFound(version))?;

        // Check if sign usage is allowed
        if !self.options.usage.contains(&KeyUsage::Sign) {
            return Err(CryptoError::InvalidUsage(
                "Signing not allowed for this key".to_string(),
            ));
        }

        let signature = match &key_version.material {
            KeyMaterial::EcdsaP256(private_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::EcdsaP256
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let signing_key = P256SigningKey::from(private_key.as_ref());
                let signature: p256::ecdsa::Signature = signing_key.sign(data);
                BASE64.encode(signature.to_der())
            }

            KeyMaterial::EcdsaSecp256k1(private_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::EcdsaSecp256k1
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let signing_key = K256SigningKey::from(private_key.as_ref());
                let signature: k256::ecdsa::Signature = signing_key.sign(data);
                BASE64.encode(signature.to_der())
            }

            KeyMaterial::Ed25519(signing_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::Ed25519
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let signature = signing_key.sign(data);
                BASE64.encode(signature.to_bytes())
            }

            KeyMaterial::X25519(_private_key) => {
                // X25519 doesn't support signing - use Ed25519 for signing
                return Err(CryptoError::InvalidUsage(
                    "X25519 key type does not support signing".to_string(),
                ));
            }

            _ => {
                return Err(CryptoError::InvalidUsage(
                    "Key type does not support signing".to_string(),
                ));
            }
        };

        Ok(format!("v{}:{}", version, signature))
    }

    /// Verify signature
    pub fn verify(
        &self,
        data: &[u8],
        signature_str: &str,
        algorithm: Option<SignatureAlgorithm>,
    ) -> CryptoResult<bool> {
        // Parse format: v<version>:<signature>
        let parts: Vec<&str> = signature_str.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidSignature("Invalid format".to_string()));
        }

        // Extract version
        let version_str = parts[0]
            .strip_prefix('v')
            .ok_or_else(|| CryptoError::InvalidSignature("Missing version prefix".to_string()))?;
        let version: u32 = version_str
            .parse()
            .map_err(|_| CryptoError::InvalidSignature("Invalid version".to_string()))?;

        let key_version = self
            .versions
            .get(&version)
            .ok_or(CryptoError::KeyVersionNotFound(version))?;

        // Check if verify usage is allowed
        if !self.options.usage.contains(&KeyUsage::Verify) {
            return Err(CryptoError::InvalidUsage(
                "Verification not allowed for this key".to_string(),
            ));
        }

        let signature_bytes = BASE64
            .decode(parts[1])
            .map_err(|_| CryptoError::InvalidSignature("Invalid signature encoding".to_string()))?;

        let is_valid = match &key_version.material {
            KeyMaterial::EcdsaP256(private_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::EcdsaP256
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let public_key = private_key.public_key();
                let verifying_key = P256VerifyingKey::from(&public_key);
                if let Ok(signature) = p256::ecdsa::Signature::from_der(&signature_bytes) {
                    signature::Verifier::verify(&verifying_key, data, &signature).is_ok()
                } else {
                    false
                }
            }

            KeyMaterial::EcdsaSecp256k1(private_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::EcdsaSecp256k1
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let public_key = private_key.public_key();
                let verifying_key = K256VerifyingKey::from(&public_key);
                if let Ok(signature) = k256::ecdsa::Signature::from_der(&signature_bytes) {
                    signature::Verifier::verify(&verifying_key, data, &signature).is_ok()
                } else {
                    false
                }
            }

            KeyMaterial::Ed25519(signing_key) => {
                // Validate algorithm compatibility if specified
                if let Some(alg) = algorithm
                    && alg != SignatureAlgorithm::Ed25519
                {
                    return Err(CryptoError::InvalidUsage(
                        "Algorithm does not match key type".to_string(),
                    ));
                }
                let verifying_key = signing_key.verifying_key();
                if let Ok(sig_bytes) = TryInto::<[u8; 64]>::try_into(signature_bytes) {
                    let signature = Ed25519Signature::from_bytes(&sig_bytes);
                    verifying_key.verify_strict(data, &signature).is_ok()
                } else {
                    false
                }
            }

            KeyMaterial::X25519(_private_key) => {
                // X25519 doesn't support signature verification - use Ed25519 for signing
                return Err(CryptoError::InvalidUsage(
                    "X25519 key type does not support signature verification".to_string(),
                ));
            }

            _ => {
                return Err(CryptoError::InvalidUsage(
                    "Key type does not support verification".to_string(),
                ));
            }
        };

        Ok(is_valid)
    }

    /// Derive key using HKDF
    pub fn derive_key(&self, context: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if !self.options.usage.contains(&KeyUsage::Derive) {
            return Err(CryptoError::InvalidUsage(
                "Key derivation not allowed for this key".to_string(),
            ));
        }

        let key_version = self
            .versions
            .get(&self.latest_version)
            .ok_or(CryptoError::KeyVersionNotFound(self.latest_version))?;

        let derived_key = match &key_version.material {
            KeyMaterial::Aes256Gcm(key_bytes) => {
                let hk = Hkdf::<Sha256>::new(Some(&[]), key_bytes.as_slice());
                let mut okm = vec![0u8; length];
                hk.expand(context, &mut okm)
                    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
                okm
            }
            KeyMaterial::ChaCha20Poly1305(key_bytes) => {
                let hk = Hkdf::<Sha256>::new(Some(&[]), key_bytes.as_slice());
                let mut okm = vec![0u8; length];
                hk.expand(context, &mut okm)
                    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
                okm
            }
            _ => {
                return Err(CryptoError::InvalidUsage(
                    "Key type does not support derivation".to_string(),
                ));
            }
        };

        Ok(derived_key)
    }
}

impl KeyVersion {
    /// Create new key version with random key material
    fn new(_version: u32, key_type: &KeyType) -> CryptoResult<Self> {
        let material = match key_type {
            KeyType::Aes256Gcm => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::Aes256Gcm(key_bytes)
            }

            KeyType::ChaCha20Poly1305 => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::ChaCha20Poly1305(key_bytes)
            }

            KeyType::XChaCha20Poly1305 => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::XChaCha20Poly1305(key_bytes)
            }

            KeyType::EcdsaP256 => {
                use p256::elliptic_curve::Generate;
                let secret_key = P256SecretKey::generate();
                KeyMaterial::EcdsaP256(Box::new(secret_key))
            }

            KeyType::EcdsaSecp256k1 => {
                use k256::elliptic_curve::Generate;
                let secret_key = K256SecretKey::generate();
                KeyMaterial::EcdsaSecp256k1(Box::new(secret_key))
            }

            KeyType::Ed25519 => {
                let signing_key = Ed25519SigningKey::from_bytes(&rand::random::<[u8; 32]>());
                KeyMaterial::Ed25519(Box::new(signing_key))
            }

            KeyType::X25519 => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::X25519(key_bytes)
            }

            KeyType::Rsa(_size) => {
                // Generate X25519 key for asymmetric encryption
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::X25519(key_bytes)
            }
        };

        Ok(Self { material })
    }
}

/// Key information for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub name: String,
    pub key_type: KeyType,
    pub latest_version: u32,
    pub min_decryption_version: u32,
    pub created_at: DateTime<Utc>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub versions: Vec<u32>,
    pub usage: Vec<KeyUsage>,
    pub exportable: bool,
}

#[cfg(test)]
mod x25519_ciphertext_tests {
    use super::*;

    /// Encrypt exactly the way releases did before the HKDF salt was introduced: an
    /// unsalted derivation and a `v<version>:<ephemeral>:<nonce>:<ciphertext>` layout
    /// with no derivation marker. The output is the shape a persisted record has.
    fn legacy_ciphertext(private_key: &[u8; 32], plaintext: &[u8], version: u32) -> String {
        let mut ephemeral_scalar = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_scalar);
        let ephemeral_public = x25519(ephemeral_scalar, X25519_BASEPOINT_BYTES);
        let shared_secret = x25519(*private_key, ephemeral_public);

        let mut aes_key = Key::<Aes256Gcm>::default();
        hkdf::Hkdf::<Sha256>::new(None, &shared_secret)
            .expand(b"secreton-x25519-aes", aes_key.as_mut())
            .expect("legacy HKDF expansion");
        let cipher = Aes256Gcm::new(&aes_key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = ChaChaNonce::from(nonce_bytes);
        let encrypted = cipher.encrypt(&nonce, plaintext).expect("legacy encrypt");

        format!(
            "v{}:{}:{}:{}",
            version,
            BASE64.encode(ephemeral_public),
            BASE64.encode(nonce_bytes),
            BASE64.encode(&encrypted)
        )
    }

    fn x25519_key() -> TransitKey {
        TransitKey::new("x".to_string(), KeyType::X25519, KeyOptions::default()).expect("new key")
    }

    fn private_bytes(key: &TransitKey) -> &[u8; 32] {
        match &key.versions[&1].material {
            KeyMaterial::X25519(bytes) => bytes,
            other => panic!("expected an X25519 key, got {other:?}"),
        }
    }

    #[test]
    fn ciphertext_issued_before_the_salt_was_added_still_decrypts() {
        let key = x25519_key();
        let plaintext = b"persisted before the derivation changed";
        let legacy = legacy_ciphertext(private_bytes(&key), plaintext, 1);

        let recovered = key
            .decrypt(&legacy, None)
            .expect("legacy ciphertext must still authenticate");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn new_encryptions_carry_a_derivation_marker_and_round_trip() {
        let key = x25519_key();
        let ciphertext = key
            .encrypt(b"fresh plaintext", None, None)
            .expect("encrypt");

        assert!(
            ciphertext.starts_with("v1:x25519:v1:"),
            "expected the salted derivation marker, got {ciphertext}"
        );
        assert_eq!(
            key.decrypt(&ciphertext, None).expect("decrypt"),
            b"fresh plaintext"
        );
    }

    #[test]
    fn an_unknown_derivation_version_is_rejected() {
        let key = x25519_key();
        let ciphertext = key
            .encrypt(b"fresh plaintext", None, None)
            .expect("encrypt");
        let tampered = ciphertext.replacen("x25519:v1:", "x25519:v9:", 1);

        assert!(
            key.decrypt(&tampered, None).is_err(),
            "a derivation version this build does not implement must not be guessed at"
        );
    }
}
