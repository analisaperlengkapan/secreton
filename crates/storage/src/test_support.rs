//! Test-only rendezvous points for forcing a concurrent write into a backend's
//! read-to-write window.
//!
//! Several backends choose a record's identity (or its destination file) from a read that
//! happens before the atomic step that publishes the write. Forcing a concurrent replacement
//! into that window is the only way to prove the window is actually closed: a test that
//! merely races two tasks may never interleave them. These are `#[cfg(test)]`-gated and
//! compile out of every non-test build, so nothing here can run in production.

use std::sync::atomic::{AtomicBool, Ordering};

/// A one-shot park point. The first caller to take it signals `reached` and waits for
/// `resume`; every later caller runs straight through, so a retry after the test's forced
/// interleaving does not deadlock waiting for a rendezvous that already happened.
#[derive(Debug)]
pub(crate) struct WritePause {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    taken: AtomicBool,
}

impl WritePause {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            taken: AtomicBool::new(false),
        }
    }

    /// Signal that a write has reached the park point and wait to be released.
    pub(crate) async fn park(&self) {
        if !self.taken.swap(true, Ordering::SeqCst) {
            self.reached.notify_one();
            self.resume.notified().await;
        }
    }

    /// Await the first arrival at the park point.
    pub(crate) async fn wait_reached(&self) {
        self.reached.notified().await;
    }

    /// Release a parked writer.
    pub(crate) fn release(&self) {
        self.resume.notify_one();
    }
}

impl Default for WritePause {
    fn default() -> Self {
        Self::new()
    }
}
