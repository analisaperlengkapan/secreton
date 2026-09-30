//! PKI engine implementation

use super::error::PkiError;
use super::model::{
    CertificateRequest, CertificateResponse, PkiConfig, RevocationReason, SshKeyRequest,
    SshKeyResponse,
};
use chrono::{DateTime, Duration, Utc};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, SanType};
use ssh_key::{Algorithm, PrivateKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x509_cert::Certificate;
use x509_cert::der::EncodePem;
use x509_cert::der::pem::LineEnding;

/// Revoked certificate entry
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_time: DateTime<Utc>,
    pub reason: RevocationReason,
}

/// PKI secret engine for certificate management
pub struct PkiEngine {
    config: PkiConfig,
    /// Certificate revocation list (serial_number -> revocation info)
    revoked_certificates: Arc<RwLock<HashMap<String, RevokedCertificate>>>,
    /// Issued certificates (serial_number -> certificate details)
    issued_certificates: Arc<RwLock<HashMap<String, IssuedCertificate>>>,
}

/// Lightweight certificate metadata extracted from a PEM certificate.
#[derive(Debug, Clone)]
pub struct CertificateMetadata {
    pub serial_number: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Issued certificate record
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub serial_number: String,
    pub common_name: String,
    pub certificate_pem: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PkiEngine {
    pub fn new(config: PkiConfig) -> Self {
        Self {
            config,
            revoked_certificates: Arc::new(RwLock::new(HashMap::new())),
            issued_certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if CA is configured
    pub fn has_ca_configured(&self) -> bool {
        self.config.ca_cert.is_some() && self.config.ca_key.is_some()
    }

    /// Generate a certificate from a request
    pub async fn generate_certificate(
        &self,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse, PkiError> {
        // Create certificate parameters
        let mut params = CertificateParams::new(vec![request.common_name.clone()])
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        if let Some(org) = &request.organization {
            dn.push(DnType::OrganizationName, org);
        }
        if let Some(ou) = &request.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        if let Some(country) = &request.country {
            dn.push(DnType::CountryName, country);
        }
        if let Some(state) = &request.state {
            dn.push(DnType::StateOrProvinceName, state);
        }
        if let Some(locality) = &request.locality {
            dn.push(DnType::LocalityName, locality);
        }
        params.distinguished_name = dn;

        // Set validity period
        let ttl = request.ttl.unwrap_or(self.config.default_lease_ttl);
        let not_before_chrono = Utc::now();
        let not_after_chrono = not_before_chrono + Duration::seconds(ttl);

        // rcgen uses time crate internally, convert from chrono
        params.not_before = ::time::OffsetDateTime::from_unix_timestamp(
            not_before_chrono.timestamp(),
        )
        .map_err(|e| PkiError::CertificateGeneration(format!("Invalid timestamp: {}", e)))?;
        params.not_after = ::time::OffsetDateTime::from_unix_timestamp(
            not_after_chrono.timestamp(),
        )
        .map_err(|e| PkiError::CertificateGeneration(format!("Invalid timestamp: {}", e)))?;

        // Add subject alternative names
        for dns_name in &request.alt_names {
            let ia5 = Ia5String::try_from(dns_name.as_str())
                .map_err(|_| PkiError::CertificateGeneration("Invalid DNS name".to_string()))?;
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }
        for ip in &request.ip_addresses {
            if let Ok(ip_addr) = ip.parse() {
                params.subject_alt_names.push(SanType::IpAddress(ip_addr));
            }
        }
        for email in &request.email_addresses {
            let ia5 = Ia5String::try_from(email.as_str()).map_err(|_| {
                PkiError::CertificateGeneration("Invalid email address".to_string())
            })?;
            params.subject_alt_names.push(SanType::Rfc822Name(ia5));
        }

        // Generate certificate and key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Use a consistent serial number
        // Generate it ourselves so we can return it correctly in the response
        let serial_number_u64 = rand::random::<u64>();
        let serial_number = format!("{:x}", serial_number_u64);
        params.serial_number = Some(serial_number_u64.into());

        // Determine signing method (Self-signed or CA-signed)
        let cert = if let (Some(ca_cert_pem), Some(ca_key_pem)) =
            (&self.config.ca_cert, &self.config.ca_key)
        {
            // Load CA KeyPair
            let ca_key_pair = rcgen::KeyPair::from_pem(ca_key_pem).map_err(|e| {
                PkiError::CertificateGeneration(format!("Failed to load CA key: {}", e))
            })?;

            // The issuer's distinguished name, key identifier and key usages are read
            // from the CA certificate itself, so the child's Issuer field matches the
            // CA's Subject rather than the child's own subject.
            let ca_issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair).map_err(|e| {
                PkiError::CertificateParsing(format!("Failed to parse CA certificate: {}", e))
            })?;

            // Sign the child certificate with the CA key, using the CA as the issuer.
            params.signed_by(&key_pair, &ca_issuer).map_err(|e| {
                PkiError::CertificateGeneration(format!("Failed to sign certificate: {}", e))
            })?
        } else {
            return Err(PkiError::InvalidCaConfiguration(
                "CA not configured. Cannot issue certificates.".to_string(),
            ));
        };

        // Convert to PEM format
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Store issued certificate for tracking
        let issued_cert = IssuedCertificate {
            serial_number: serial_number.clone(),
            common_name: request.common_name.clone(),
            certificate_pem: cert_pem.clone(),
            issued_at: not_before_chrono,
            expires_at: not_after_chrono,
        };
        self.issued_certificates
            .write()
            .await
            .insert(serial_number.clone(), issued_cert);

        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            serial_number,
            issuing_ca: self.config.ca_cert.clone().unwrap_or_default(),
            ca_chain: vec![], // Would include CA chain in full implementation
            expiration: not_after_chrono,
            revocation_time: None,
        })
    }

    /// Generate SSH keys
    pub async fn generate_ssh_key(
        &self,
        request: &SshKeyRequest,
    ) -> Result<SshKeyResponse, PkiError> {
        // Determine algorithm based on request
        let algorithm = match &request.key_type {
            super::model::SshKeyType::Rsa => Algorithm::Rsa { hash: None },
            super::model::SshKeyType::Ed25519 => Algorithm::Ed25519,
            super::model::SshKeyType::Ecdsa => Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        };

        // Generate private key
        let private_key = PrivateKey::random(&mut rand::thread_rng(), algorithm).map_err(|e| {
            PkiError::SshKeyGeneration(format!("Failed to generate private key: {}", e))
        })?;

        // Serialize to OpenSSH format
        let private_key_pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| {
                PkiError::SshKeyGeneration(format!("Failed to serialize private key: {}", e))
            })?;

        // Generate public key
        let public_key = private_key.public_key();
        let public_key_openssh = public_key.to_openssh().map_err(|e| {
            PkiError::SshKeyGeneration(format!("Failed to serialize public key: {}", e))
        })?;

        // Calculate expiration
        let ttl = request.ttl.unwrap_or(self.config.default_lease_ttl);
        let expiration = Utc::now() + Duration::seconds(ttl);

        Ok(SshKeyResponse {
            private_key: private_key_pem.to_string(),
            public_key: public_key_openssh.to_string(),
            certificate: None, // Not implemented yet
            key_type: request.key_type.clone(),
            expiration: Some(expiration),
        })
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        request: &super::model::RevocationRequest,
    ) -> Result<(), PkiError> {
        // Check if the certificate exists
        let issued_certs = self.issued_certificates.read().await;
        if !issued_certs.contains_key(&request.serial_number) {
            return Err(PkiError::CertificateNotFound(request.serial_number.clone()));
        }
        drop(issued_certs);

        // Check if already revoked
        let revoked = self.revoked_certificates.read().await;
        if revoked.contains_key(&request.serial_number) {
            return Err(PkiError::CertificateRevocation(format!(
                "Certificate {} is already revoked",
                request.serial_number
            )));
        }
        drop(revoked);

        // Add to revocation list
        let revoked_cert = RevokedCertificate {
            serial_number: request.serial_number.clone(),
            revocation_time: Utc::now(),
            reason: request.reason.clone(),
        };

        self.revoked_certificates
            .write()
            .await
            .insert(request.serial_number.clone(), revoked_cert);

        tracing::info!(
            "Certificate {} revoked with reason: {:?}",
            request.serial_number,
            request.reason
        );

        Ok(())
    }

    /// Check if a certificate is revoked
    pub async fn is_certificate_revoked(&self, serial_number: &str) -> bool {
        self.revoked_certificates
            .read()
            .await
            .contains_key(serial_number)
    }

    /// Get certificate revocation information
    pub async fn get_revocation_info(&self, serial_number: &str) -> Option<RevokedCertificate> {
        self.revoked_certificates
            .read()
            .await
            .get(serial_number)
            .cloned()
    }

    /// Generate a Certificate Revocation List (CRL)
    pub async fn generate_crl(&self) -> Result<super::model::CrlResponse, PkiError> {
        let revoked = self.revoked_certificates.read().await;
        let now = Utc::now();
        let next_update = now + Duration::hours(24); // CRL valid for 24 hours

        // Build CRL data (simplified PEM representation)
        let mut crl_data = String::new();
        crl_data.push_str("-----BEGIN X509 CRL-----\n");
        crl_data.push_str(&format!("# CRL Generated: {}\n", now.to_rfc3339()));
        crl_data.push_str(&format!("# Next Update: {}\n", next_update.to_rfc3339()));
        crl_data.push_str(&format!(
            "# Total Revoked Certificates: {}\n",
            revoked.len()
        ));

        for (serial, info) in revoked.iter() {
            crl_data.push_str(&format!(
                "# Serial: {} | Revoked: {} | Reason: {:?}\n",
                serial,
                info.revocation_time.to_rfc3339(),
                info.reason
            ));
        }

        crl_data.push_str("-----END X509 CRL-----\n");

        Ok(super::model::CrlResponse {
            crl: crl_data,
            last_update: now,
            next_update,
        })
    }

    /// List all revoked certificates
    pub async fn list_revoked_certificates(&self) -> Vec<RevokedCertificate> {
        self.revoked_certificates
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// List all issued certificates
    pub async fn list_issued_certificates(&self) -> Vec<IssuedCertificate> {
        self.issued_certificates
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Get CA information
    pub async fn get_ca_info(&self) -> Result<super::model::CaInfo, PkiError> {
        if let Some(ca_cert_pem) = &self.config.ca_cert {
            return self.parse_ca_cert(ca_cert_pem);
        }

        // For now, generate a default self-signed CA
        self.generate_default_ca_info().await
    }

    /// Parse CA certificate from PEM
    fn parse_ca_cert(&self, pem: &str) -> Result<super::model::CaInfo, PkiError> {
        use super::model::CaInfo;

        // Parse PEM to Certificate
        let cert = Certificate::load_pem_chain(pem.as_bytes())
            .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse PEM: {}", e)))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                PkiError::CertificateParsing("PEM contained no certificate".to_string())
            })?;

        // Extract public key info
        let tbs = cert.tbs_certificate();
        let spki = tbs.subject_public_key_info();
        let algorithm_oid = spki.algorithm.oid.to_string();

        let key_type = match algorithm_oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            oid if oid.starts_with("1.2.840.10045") => "ECDSA".to_string(),
            oid if oid.starts_with("1.3.101") => "EdDSA".to_string(),
            _ => format!("Unknown ({})", algorithm_oid),
        };

        // Extract validity
        let validity = tbs.validity();
        let valid_from = validity.not_before.to_unix_duration().as_secs() as i64;
        let valid_until = validity.not_after.to_unix_duration().as_secs() as i64;

        // Extract Subject and Issuer
        let subject = Self::extract_dn(tbs.subject());
        let issuer = Self::extract_dn(tbs.issuer());

        // Extract public key PEM
        let public_key_pem = spki.to_pem(LineEnding::LF).map_err(|e| {
            PkiError::CertificateParsing(format!("Failed to encode public key: {}", e))
        })?;

        // Calculate key bits based on algorithm
        let key_bits = match key_type.as_str() {
            "RSA" => {
                // RSA issuance was removed along with the `rsa` crate
                // (RUSTSEC-2023-0071), so this CA never minted the certificate being
                // inspected. Approximate the modulus size from the DER length of the
                // SubjectPublicKey rather than adding a `pkcs1` dependency purely to
                // introspect a key we cannot issue. `0` means "unknown", as elsewhere
                // in this match.
                let der_len = spki.subject_public_key.raw_bytes().len();
                match der_len {
                    0 => 0,
                    // A PKCS#1 RSAPublicKey wraps the modulus in ~9 bytes of DER.
                    n => ((n.saturating_sub(9)) / 2) * 8,
                }
            }
            "ECDSA" => {
                // Check curve from parameters
                // For now, simple mapping if possible, else 0
                if let Some(params) = &spki.algorithm.parameters {
                    if let Ok(oid) = params.decode_as::<x509_cert::der::asn1::ObjectIdentifier>() {
                        match oid.to_string().as_str() {
                            "1.2.840.10045.3.1.7" => 256, // P-256
                            "1.3.132.0.34" => 384,        // P-384
                            "1.3.132.0.35" => 521,        // P-521
                            _ => 0,
                        }
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            _ => 0,
        };

        Ok(CaInfo {
            certificate: pem.to_string(),
            public_key: public_key_pem,
            key_type,
            key_bits,
            signature_algorithm: cert.signature_algorithm().oid.to_string(),
            subject,
            issuer,
            valid_from: chrono::DateTime::from_timestamp(valid_from, 0).ok_or_else(|| {
                PkiError::CertificateParsing("Invalid valid_from timestamp".to_string())
            })?,
            valid_until: chrono::DateTime::from_timestamp(valid_until, 0).ok_or_else(|| {
                PkiError::CertificateParsing("Invalid valid_until timestamp".to_string())
            })?,
        })
    }

    /// Generate a new Root CA certificate
    pub async fn generate_root_ca(
        &self,
        common_name: &str,
        organization: &str,
    ) -> Result<(String, String), PkiError> {
        // Create CA parameters
        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Set CA distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, organization);
        dn.push(DnType::OrganizationalUnitName, "Certificate Authority");
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Set as CA certificate
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set key usage for CA
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        // Set validity (10 years)
        let not_before = ::time::OffsetDateTime::now_utc();
        let not_after = not_before + ::time::Duration::days(3650);
        params.not_before = not_before;
        params.not_after = not_after;

        // Generate key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Generate self-signed CA certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    /// Parse a certificate PEM and return lightweight metadata (serial number
    /// and expiration).  This is a public helper so that callers (e.g. the
    /// persistent service layer) can extract real values from a generated cert
    /// without duplicating the DER parsing logic.
    pub fn parse_ca_cert_from_pem(&self, pem: &str) -> Result<CertificateMetadata, PkiError> {
        // Parse PEM to Certificate
        let cert = Certificate::load_pem_chain(pem.as_bytes())
            .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse PEM: {}", e)))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                PkiError::CertificateParsing("PEM contained no certificate".to_string())
            })?;

        // Serial number as hex string
        let serial_number = hex::encode(cert.tbs_certificate().serial_number().as_bytes());

        // Validity
        let validity = cert.tbs_certificate().validity();
        let valid_from_secs = validity.not_before.to_unix_duration().as_secs() as i64;
        let valid_until_secs = validity.not_after.to_unix_duration().as_secs() as i64;

        let valid_from = chrono::DateTime::from_timestamp(valid_from_secs, 0).ok_or_else(|| {
            PkiError::CertificateParsing("Invalid valid_from timestamp".to_string())
        })?;
        let valid_until =
            chrono::DateTime::from_timestamp(valid_until_secs, 0).ok_or_else(|| {
                PkiError::CertificateParsing("Invalid valid_until timestamp".to_string())
            })?;

        Ok(CertificateMetadata {
            serial_number,
            valid_from,
            valid_until,
        })
    }

    /// Generate default CA info for development/testing
    async fn generate_default_ca_info(&self) -> Result<super::model::CaInfo, PkiError> {
        // reuse the new generate_root_ca logic but return CaInfo
        let (cert_pem, _key_pem) = self
            .generate_root_ca("Secreton CA", "Secreton Security")
            .await?;
        self.parse_ca_cert(&cert_pem)
    }

    /// Extract DN from a certificate Name
    fn extract_dn(name: &x509_cert::name::Name) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for rdn in name.as_ref().iter() {
            for attr in rdn.iter() {
                let oid_string = attr.oid.to_string();
                let key = match oid_string.as_str() {
                    "2.5.4.3" => "common_name",
                    "2.5.4.10" => "organization",
                    "2.5.4.11" => "organizational_unit",
                    "2.5.4.6" => "country",
                    "2.5.4.8" => "state",
                    "2.5.4.7" => "locality",
                    _ => &oid_string,
                };
                if let Ok(s) = attr.value.decode_as::<String>() {
                    map.insert(key.to_string(), s);
                }
            }
        }
        map
    }
}
