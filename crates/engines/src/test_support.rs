//! Helpers shared by the unit tests in this crate. Only compiled under `cfg(test)`.

#![allow(
    clippy::disallowed_methods,
    reason = "The rule stops runtime configuration reaching the process through the \
              environment. This module exists to set and clear environment variables for \
              tests that exercise configuration loading, which is the one place doing so \
              is the subject rather than a shortcut."
)]

use std::sync::{Mutex, MutexGuard, OnceLock};

const TEST_ROOT_KEY: &str = "test_root_key_must_be_32_bytes_long!!";

/// Serialises every test that reads or writes `SECRETON_ROOT_KEY`.
///
/// The crypto and seal services take the root key from the process environment, and all
/// `#[tokio::test]` cases in a binary share one process. Some tests need the key present
/// (unsealed) and others need it absent (sealed), so without a lock they race: whichever
/// runs second observes the other's environment. That is a real flakiness source, not a
/// lint technicality — `std::env::set_var` is `unsafe` in edition 2024 for exactly this
/// reason.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Guard held for the duration of a test that depends on the root-key environment.
///
/// Dropping it releases the lock; it does not restore the previous value, because every
/// test that cares sets the state it needs on entry.
#[must_use = "the environment is only serialised while the guard is alive"]
pub(crate) struct RootKeyEnv(
    #[allow(dead_code, reason = "held for its Drop")] MutexGuard<'static, ()>,
);

/// Make the root key present, so services start unsealed.
pub(crate) fn with_root_key() -> RootKeyEnv {
    let guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: the mutex guarantees no other test thread is reading or writing the
    // environment while this runs.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("SECRETON_ROOT_KEY", TEST_ROOT_KEY);
    }
    RootKeyEnv(guard)
}

/// Make the root key absent, so services start sealed.
pub(crate) fn without_root_key() -> RootKeyEnv {
    let guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: as above — the mutex serialises all access to this variable.
    #[allow(unsafe_code)]
    unsafe {
        std::env::remove_var("SECRETON_ROOT_KEY");
    }
    RootKeyEnv(guard)
}

/// A random, valid-looking password for a test account.
///
/// Tests that exercise a password path need a value a real verifier would accept. Writing
/// one as a literal makes the source read — to a person and to a scanner — like a committed
/// credential, and models production wrongly: an operator, not the repository, chooses the
/// password. A fresh value per call keeps no fixed secret in the tree and no generated value
/// is ever logged, asserted on, or embedded in an error.
pub(crate) fn generated_password() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
