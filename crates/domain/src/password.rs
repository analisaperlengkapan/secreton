//! Password policy and generation.

use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::{Result, SecretonError};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Special characters a [`PasswordPolicy`] accepts when it does not name its own set.
///
/// Public because [`PasswordPolicy::allowed_special_chars`] documents itself in terms of
/// it: a caller deciding whether to override the default has to be able to see what the
/// default is.
pub const DEFAULT_SPECIAL: &str = "!@#$%^&*";

/// Rules a password must satisfy, used both to validate user input and to drive generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: Option<usize>,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    /// Special characters permitted. `None` means [`DEFAULT_SPECIAL`].
    pub allowed_special_chars: Option<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 16,
            max_length: Some(128),
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            allowed_special_chars: None,
        }
    }
}

impl PasswordPolicy {
    fn special_chars(&self) -> &str {
        self.allowed_special_chars
            .as_deref()
            .unwrap_or(DEFAULT_SPECIAL)
    }

    /// Number of distinct character classes this policy demands at least one of.
    fn required_classes(&self) -> usize {
        usize::from(self.require_lowercase)
            + usize::from(self.require_uppercase)
            + usize::from(self.require_digit)
            + usize::from(self.require_special)
    }

    /// Reject policies that cannot be satisfied, so generation never has to.
    pub fn validate(&self) -> Result<()> {
        if self.min_length == 0 {
            return Err(SecretonError::Validation {
                message: "minimum password length cannot be zero".into(),
            });
        }
        if self.require_special && self.special_chars().is_empty() {
            return Err(SecretonError::Validation {
                message: "special characters are required but the allowed set is empty".into(),
            });
        }
        if let Some(max) = self.max_length {
            if max < self.min_length {
                return Err(SecretonError::Validation {
                    message: format!(
                        "maximum length {max} is below minimum length {}",
                        self.min_length
                    ),
                });
            }
            // A policy demanding more character classes than it allows characters is
            // unsatisfiable; catching it here means `generate` can never fail to comply.
            if max < self.required_classes() {
                return Err(SecretonError::Validation {
                    message: format!(
                        "maximum length {max} cannot hold the {} required character classes",
                        self.required_classes()
                    ),
                });
            }
        }
        Ok(())
    }

    /// Check an existing password against this policy.
    pub fn check(&self, password: &str) -> Result<()> {
        let len = password.chars().count();
        if len < self.min_length {
            return Err(SecretonError::Validation {
                message: format!("password must be at least {} characters", self.min_length),
            });
        }
        if let Some(max) = self.max_length
            && len > max
        {
            return Err(SecretonError::Validation {
                message: format!("password must be at most {max} characters"),
            });
        }

        let specials = self.special_chars();
        let mut missing = Vec::new();
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            missing.push("a lowercase letter");
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            missing.push("an uppercase letter");
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            missing.push("a digit");
        }
        if self.require_special && !password.chars().any(|c| specials.contains(c)) {
            missing.push("a special character");
        }
        if !missing.is_empty() {
            return Err(SecretonError::Validation {
                message: format!("password must contain {}", missing.join(", ")),
            });
        }
        Ok(())
    }

    /// Generate a password that satisfies this policy.
    ///
    /// One character is drawn from each required class first so compliance is guaranteed by
    /// construction, the remainder is drawn from the union, and the result is shuffled so the
    /// required characters are not left in a predictable prefix.
    pub fn generate(&self) -> Result<String> {
        self.validate()?;

        let specials = self.special_chars().to_string();
        let mut rng = rand::thread_rng();
        let mut chars: Vec<char> = Vec::new();

        if self.require_lowercase {
            chars.push(pick(&mut rng, LOWER.iter().map(|&b| b as char)));
        }
        if self.require_uppercase {
            chars.push(pick(&mut rng, UPPER.iter().map(|&b| b as char)));
        }
        if self.require_digit {
            chars.push(pick(&mut rng, DIGITS.iter().map(|&b| b as char)));
        }
        if self.require_special {
            chars.push(pick(&mut rng, specials.chars()));
        }

        let mut pool: Vec<char> = LOWER
            .iter()
            .chain(UPPER)
            .chain(DIGITS)
            .map(|&b| b as char)
            .collect();
        if self.require_special {
            pool.extend(specials.chars());
        }

        let target = self.min_length.max(chars.len());
        while chars.len() < target {
            chars.push(pool[rng.gen_range(0..pool.len())]);
        }

        chars.shuffle(&mut rng);
        Ok(chars.into_iter().collect())
    }
}

fn pick<R: Rng, I: Iterator<Item = char>>(rng: &mut R, iter: I) -> char {
    let candidates: Vec<char> = iter.collect();
    candidates[rng.gen_range(0..candidates.len())]
}

/// Generate a password of `length` from the default alphabet, ignoring policy.
pub fn generate_password(length: usize) -> String {
    let policy = PasswordPolicy {
        min_length: length,
        max_length: None,
        ..Default::default()
    };
    policy
        .generate()
        .expect("the default policy with an unbounded maximum is always satisfiable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_always_satisfy_their_policy() {
        let policy = PasswordPolicy::default();
        for _ in 0..200 {
            let pw = policy.generate().unwrap();
            policy
                .check(&pw)
                .expect("generated password must pass check");
            assert_eq!(pw.chars().count(), policy.min_length);
        }
    }

    #[test]
    fn required_characters_are_not_left_in_a_predictable_prefix() {
        // Before shuffling, index 0 was always lowercase. Over many samples at least one
        // password must start with something else.
        let policy = PasswordPolicy::default();
        let varied = (0..200)
            .map(|_| policy.generate().unwrap())
            .any(|pw| !pw.chars().next().unwrap().is_ascii_lowercase());
        assert!(
            varied,
            "first character never varied — shuffle is not applied"
        );
    }

    #[test]
    fn unsatisfiable_policies_are_rejected_rather_than_silently_violated() {
        let too_short = PasswordPolicy {
            min_length: 2,
            max_length: Some(2),
            ..Default::default()
        };
        // Four classes required but only two characters allowed.
        assert!(too_short.validate().is_err());
        assert!(too_short.generate().is_err());

        let inverted = PasswordPolicy {
            min_length: 20,
            max_length: Some(10),
            ..Default::default()
        };
        assert!(inverted.validate().is_err());

        let no_specials = PasswordPolicy {
            require_special: true,
            allowed_special_chars: Some(String::new()),
            ..Default::default()
        };
        assert!(no_specials.validate().is_err());
    }

    #[test]
    fn check_reports_what_is_missing() {
        let policy = PasswordPolicy::default();
        // Lowercase letters only, so the report has something to say. Drawn from the
        // generator rather than a literal so no fixed credential lives in the source.
        let candidate: String = generate_password(40)
            .chars()
            .filter(char::is_ascii_alphabetic)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        let err = policy.check(&candidate).unwrap_err().to_string();
        assert!(err.contains("uppercase"), "unexpected message: {err}");
        assert!(err.contains("digit"), "unexpected message: {err}");
    }

    #[test]
    fn check_rejects_passwords_below_and_above_the_bounds() {
        let policy = PasswordPolicy {
            min_length: 8,
            max_length: Some(12),
            ..Default::default()
        };
        let within = policy.generate().unwrap();
        assert!(policy.check(&within).is_ok());

        let too_short = PasswordPolicy {
            min_length: 4,
            max_length: None,
            ..Default::default()
        }
        .generate()
        .unwrap();
        assert!(policy.check(&too_short).is_err());

        let too_long = PasswordPolicy {
            min_length: 20,
            max_length: None,
            ..Default::default()
        }
        .generate()
        .unwrap();
        assert!(policy.check(&too_long).is_err());
    }
}
