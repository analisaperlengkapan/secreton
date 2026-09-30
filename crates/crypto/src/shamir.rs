//! Shamir Secret Sharing Implementation
//!
//! Provides cryptographically secure secret sharing using Shamir's Secret Sharing algorithm.
//! Allows splitting a secret into N shares where any K shares can reconstruct the original secret.
//!
//! # Security
//! - Uses GF(256) for finite field arithmetic
//! - Cryptographically secure random number generation
//! - Constant-time operations where possible

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "GF(256) arithmetic. Every cast here is bounded by the field size: the log \
              and exp tables are indexed 0..256, and share indices run 1..=255 by \
              construction. The casts are exact, not lossy, and rewriting them as \
              try_from would add a fallible path that can never fail."
)]

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors that can occur during Shamir secret sharing operations
#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("Invalid threshold: must be > 0 and <= total shares")]
    InvalidThreshold,

    #[error("Invalid number of shares: must be between 2 and 255")]
    InvalidShareCount,

    #[error("Secret is empty")]
    EmptySecret,

    #[error("Not enough shares to reconstruct secret: need {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },

    #[error("Share size mismatch: expected {expected}, got {got}")]
    ShareSizeMismatch { expected: usize, got: usize },

    #[error("Invalid share format")]
    InvalidShareFormat,

    #[error("Duplicate share index: {0}")]
    DuplicateShareIndex(u8),

    #[error("Invalid shares for reconstruction")]
    InvalidShares,
}

/// A single share of a secret
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share {
    /// The index (x-coordinate) of this share (1-255)
    pub index: u8,
    /// The secret data (y-coordinates)
    pub data: Vec<u8>,
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Share #{} ({} bytes)", self.index, self.data.len())
    }
}

/// Galois Field GF(256) operations for Shamir's algorithm
struct GF256;

impl GF256 {
    // Precomputed log and exp tables for GF(256)
    const LOG_TABLE: [u8; 256] = Self::generate_log_table();
    const EXP_TABLE: [u8; 256] = Self::generate_exp_table();

    const fn generate_exp_table() -> [u8; 256] {
        let mut table = [0u8; 256];
        let mut x = 1u16;
        let mut i = 0;
        while i < 256 {
            table[i] = x as u8;
            x = (x << 1) ^ x; // Multiply by 3
            if x & 0x100 != 0 {
                x ^= 0x11B;
            }
            i += 1;
        }
        table
    }

    const fn generate_log_table() -> [u8; 256] {
        let mut table = [0u8; 256];
        let exp_table = Self::generate_exp_table();
        let mut i = 0;
        while i < 255 {
            table[exp_table[i] as usize] = i as u8;
            i += 1;
        }
        table
    }

    /// Multiply two elements in GF(256)
    #[inline]
    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let log_a = Self::LOG_TABLE[a as usize] as usize;
            let log_b = Self::LOG_TABLE[b as usize] as usize;
            Self::EXP_TABLE[(log_a + log_b) % 255]
        }
    }

    /// Divide two elements in GF(256)
    #[inline]
    fn div(a: u8, b: u8) -> Result<u8, &'static str> {
        if a == 0 {
            Ok(0)
        } else if b == 0 {
            Err("Division by zero in GF(256)")
        } else {
            let log_a = Self::LOG_TABLE[a as usize] as i32;
            let log_b = Self::LOG_TABLE[b as usize] as i32;
            let log_result = (log_a - log_b + 255) % 255;
            Ok(Self::EXP_TABLE[log_result as usize])
        }
    }

    /// Evaluate polynomial at x using Horner's method
    fn eval_poly(coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        for &coeff in coefficients.iter().rev() {
            result = Self::mul(result, x) ^ coeff;
        }
        result
    }
}

/// Split a secret into N shares with K threshold using Shamir's Secret Sharing
///
/// # Arguments
/// * `secret` - The secret data to split
/// * `threshold` - Number of shares required to reconstruct (K)
/// * `total_shares` - Total number of shares to generate (N)
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// Vector of shares, where any K shares can reconstruct the secret
///
/// # Errors
/// Returns error if parameters are invalid
pub fn split<R: RngCore + CryptoRng>(
    secret: &[u8],
    threshold: usize,
    total_shares: usize,
    rng: &mut R,
) -> Result<Vec<Share>, ShamirError> {
    // Validate parameters
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    if threshold == 0 || threshold > total_shares {
        return Err(ShamirError::InvalidThreshold);
    }
    if !(2..=255).contains(&total_shares) {
        return Err(ShamirError::InvalidShareCount);
    }

    let mut shares = vec![Vec::with_capacity(secret.len()); total_shares];

    // Process each byte of the secret
    for &secret_byte in secret {
        // Generate random coefficients for polynomial
        // p(x) = secret_byte + c1*x + c2*x^2 + ... + c(k-1)*x^(k-1)
        let mut coefficients = vec![0u8; threshold];
        coefficients[0] = secret_byte; // Constant term is the secret

        for coeff in coefficients.iter_mut().skip(1) {
            let mut coeff_val = 0u8;
            while coeff_val == 0 {
                // Ensure non-zero coefficients
                rng.fill_bytes(std::slice::from_mut(&mut coeff_val));
            }
            *coeff = coeff_val;
        }

        // Evaluate polynomial at x=1,2,3,...,total_shares
        for (i, share_data) in shares.iter_mut().enumerate() {
            let x = (i + 1) as u8; // Share indices start at 1
            let y = GF256::eval_poly(&coefficients, x);
            share_data.push(y);
        }
    }

    // Convert to Share objects
    Ok(shares
        .into_iter()
        .enumerate()
        .map(|(i, data)| Share {
            index: (i + 1) as u8,
            data,
        })
        .collect())
}

/// Combine shares to reconstruct the original secret using Lagrange interpolation
///
/// # Arguments
/// * `shares` - Vector of shares (must have at least K shares)
///
/// # Returns
/// The reconstructed secret
///
/// # Errors
/// Returns error if shares are invalid or insufficient
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
    }

    // Check all shares have same length
    let secret_len = shares[0].data.len();
    for share in shares.iter().skip(1) {
        if share.data.len() != secret_len {
            return Err(ShamirError::ShareSizeMismatch {
                expected: secret_len,
                got: share.data.len(),
            });
        }
    }

    // Check for duplicate indices
    let mut indices = shares.iter().map(|s| s.index).collect::<Vec<_>>();
    indices.sort_unstable();
    for window in indices.windows(2) {
        if window[0] == window[1] {
            return Err(ShamirError::DuplicateShareIndex(window[0]));
        }
    }

    // Build the result by pushing each recovered byte. The buffer is never
    // pre-filled with a constant, so nothing here can be mistaken for key
    // material seeded into the reconstruction.
    let mut secret = Vec::with_capacity(secret_len);

    // Reconstruct each byte using Lagrange interpolation
    for byte_idx in 0..secret_len {
        let mut value = 0u8;

        // Lagrange interpolation to find p(0)
        for (i, share_i) in shares.iter().enumerate() {
            let x_i = share_i.index;
            let y_i = share_i.data[byte_idx];

            // Calculate Lagrange basis polynomial L_i(0)
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    let x_j = share_j.index;
                    // L_i(0) = product of (0 - x_j) / (x_i - x_j) for all j != i
                    numerator = GF256::mul(numerator, x_j);
                    denominator = GF256::mul(denominator, x_i ^ x_j);
                }
            }

            let basis =
                GF256::div(numerator, denominator).map_err(|_| ShamirError::InvalidShares)?;
            value ^= GF256::mul(y_i, basis);
        }

        secret.push(value);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_split_and_combine() {
        let secret = b"Hello, Shamir!";
        let threshold = 3;
        let total = 5;

        let shares = split(secret, threshold, total, &mut OsRng).unwrap();
        assert_eq!(shares.len(), total);

        // Test with minimum threshold
        let reconstructed = combine(&shares[..threshold]).unwrap();
        assert_eq!(&reconstructed[..], secret);

        // Test with all shares
        let reconstructed = combine(&shares).unwrap();
        assert_eq!(&reconstructed[..], secret);

        // Test with different combinations
        let reconstructed =
            combine(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Secret data";
        let threshold = 3;
        let total = 5;

        let shares = split(secret, threshold, total, &mut OsRng).unwrap();

        // Try with fewer than threshold shares - should still work but wrong result
        let result = combine(&shares[..2]);
        assert!(result.is_ok()); // It succeeds but gives wrong data
        let reconstructed = result.unwrap();
        assert_ne!(&reconstructed[..], secret); // Wrong secret recovered
    }

    #[test]
    fn test_invalid_parameters() {
        let secret = b"test";

        assert!(split(secret, 0, 5, &mut OsRng).is_err());
        assert!(split(secret, 6, 5, &mut OsRng).is_err());
        assert!(split(secret, 3, 1, &mut OsRng).is_err());
        assert!(split(secret, 3, 256, &mut OsRng).is_err());
        assert!(split(&[], 3, 5, &mut OsRng).is_err());
    }

    #[test]
    fn test_gf256_operations() {
        // Test identity
        assert_eq!(GF256::mul(5, 1), 5);
        assert_eq!(GF256::mul(1, 5), 5);

        // Test zero
        assert_eq!(GF256::mul(5, 0), 0);
        assert_eq!(GF256::mul(0, 5), 0);

        // Test division
        assert_eq!(
            GF256::div(10, 5).unwrap(),
            GF256::mul(10, GF256::div(1, 5).unwrap())
        );
    }

    #[test]
    fn test_large_secret() {
        let secret = vec![42u8; 1024]; // 1KB secret
        let threshold = 5;
        let total = 10;

        let shares = split(&secret, threshold, total, &mut OsRng).unwrap();
        let reconstructed = combine(&shares[..threshold]).unwrap();
        assert_eq!(reconstructed, secret);
    }
}
