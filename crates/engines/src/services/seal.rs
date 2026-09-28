use crate::services::crypto::CryptoService;
use anyhow::{Result, anyhow};
use chrono::Utc;
use secreton_crypto::shamir::{self, Share};
use secreton_crypto::{AlgorithmId, EncryptedData};
use secreton_storage::{EncryptionMetadata, Expect, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Seal/Unseal Service
/// Manages the initialization and sealing status of the vault.
pub struct SealService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    // Set after construction (`Services::new` builds auth after seal) and used by
    // `unseal` to record the session that binds the root token it mints.
    auth: std::sync::OnceLock<Arc<crate::services::auth::AuthenticationService>>,
    // Set after construction, like `auth`. Unsealing is the one operation whose success
    // and failure both matter to a reviewer after the fact.
    audit: std::sync::OnceLock<Arc<crate::services::audit::AuditLogger>>,

    // In-memory buffer for unseal shares
    // (share_index, share_data)
    unseal_buffer: Arc<RwLock<Vec<Share>>>,

    // Serialises initialization within this process.
    //
    // Two concurrent `init` calls each pass the `is_initialized` guard before either has
    // written anything, and then interleave: one call's stale-state cleanup deletes the
    // other's artifacts, or both commit and one caller walks away with shares that do not
    // open the root key that ended up stored. The lock covers the whole sequence —
    // cleanup, the guard, staging, initialization, commit and marker removal — not just
    // the guard, because every one of those steps is what the other call races against.
    //
    // This is an async mutex and is never held across a blocking call. It protects one
    // process only; see `initialize` for the cross-process boundary.
    init_lock: tokio::sync::Mutex<()>,

    // True once the barrier has been opened but before the root credential that grants
    // access to it has been issued. Without this the two events are indistinguishable
    // from outside, and a failure between them leaves a vault that is open and
    // unreachable with no way to ask for the credential again.
    //
    // The retry it authorises is *not* shareless. Whoever asks for the owed credential
    // must still prove they hold a share that belongs to this vault, because the
    // credential is the root token: minting it from the flag alone would hand the most
    // privileged token in the system to an unauthenticated caller of the public
    // `sys/unseal` route. See `bootstrap_share_proof`.
    //
    // In-process only. The proof is bound to the specific shares the barrier was opened
    // with, and a restart discards both the in-memory root key and the proof, so after a
    // restart the vault must be unsealed again with its shares.
    bootstrap_pending: Arc<AtomicBool>,

    // The proof that a retry of a pending bootstrap credential may use, set when an unseal
    // successfully reconstructs the master key.
    //
    // It records a keyed digest of each share that opened the barrier, never the share or
    // the master key itself. A retry must present a share whose digest matches, so it
    // proves knowledge of a share that belongs to this vault without the value being usable
    // to decrypt anything. A caller with no share, or the wrong share, produces a different
    // digest and is refused.
    bootstrap_share_proof: Arc<RwLock<Option<BootstrapShareProof>>>,

    // Test-only fault injection: when set, the next bootstrap credential issuance fails
    // and the flag clears. This exists because the failure it injects is a transient one
    // (storage or token-service trouble) that cannot otherwise be triggered from a test
    // without weakening a real code path.
    #[cfg(test)]
    fail_next_bootstrap: Arc<AtomicBool>,

    // Serialises the barrier transition (`seal`) against bootstrap credential issuance.
    //
    // The two are not independent. `issue_bootstrap_credential_with` awaits storage and the
    // token service while it mints the root credential, and `seal` clears the in-memory root
    // key and the pending-bootstrap state. Without a lock the issuance could be in flight
    // when a seal lands, and the unseal request would then return a live root token for a
    // vault the operator had just sealed — a credential minted against a barrier that no
    // longer exists. Holding this across both makes them mutually exclusive: an issuance
    // either completes before the seal, or, if the seal won, the issuance re-checks the
    // barrier after acquiring the lock and refuses rather than minting.
    //
    // An async mutex, and the only two holders are `seal` and
    // `issue_bootstrap_credential_with`, both of which take it before touching the barrier
    // or the crypto key, so the lock order is consistent and there is no deadlock.
    credential_lock: tokio::sync::Mutex<()>,

    // Test-only override of [`INIT_LEASE_TTL_SECS`], so a test can exercise the lease
    // expiry and renewal path in milliseconds rather than the five minutes production
    // uses. `None` means the production constant.
    #[cfg(test)]
    lease_ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub keys: Vec<String>,        // Hex encoded shares
    pub keys_base64: Vec<String>, // Base64 encoded shares
    // Root token removed for security
    pub root_totp_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub sealed: bool,
    pub t: usize,
    pub n: usize,
    pub progress: usize,
    pub root_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InitConfig {
    shares: u8,
    threshold: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRootKey {
    data: EncryptedData,
}

const INIT_PATH: &str = "sys/init";
const ROOT_KEY_PATH: &str = "sys/root_key_enc";

/// The proof a retry of a pending bootstrap credential must satisfy.
///
/// [`SealService::unseal`] sets this the moment it reconstructs the master key, from the
/// shares that did so. A retry must present a share whose digest matches one of these, so
/// it proves knowledge of a share that belongs to *this* vault before the root token is
/// minted. A caller with no share, or the wrong share, cannot satisfy it.
///
/// Only digests are retained — an HMAC-SHA-256 under a random per-process key over the
/// share's index and bytes — so nothing here is reversible into a share or into the master
/// key. The key is random per instance and never persisted or logged, and is zeroized on
/// drop, so the digests are meaningless to anyone who does not hold the running process's
/// memory.
struct BootstrapShareProof {
    key: zeroize::Zeroizing<[u8; 32]>,
    digests: Vec<[u8; 32]>,
}

impl BootstrapShareProof {
    /// Digest the shares that opened the barrier, under a fresh random key.
    fn from_shares(shares: &[Share]) -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let key = zeroize::Zeroizing::new(key);
        let digests = shares
            .iter()
            .map(|share| Self::digest(&key, share))
            .collect();
        Self { key, digests }
    }

    fn digest(key: &[u8; 32], share: &Share) -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
        mac.update(&[share.index]);
        // `usize` widens to `u64` on every supported target, so this cannot truncate.
        mac.update(&(share.data.len() as u64).to_be_bytes());
        mac.update(&share.data);
        mac.finalize().into_bytes().into()
    }

    /// Whether `share` is one of the shares that opened the barrier.
    ///
    /// Compares against every stored digest without short-circuiting, so the time taken
    /// does not reveal how many — if any — of a probe's shares are known.
    fn accepts(&self, share: &Share) -> bool {
        let candidate = Self::digest(&self.key, share);
        let mut matched = false;
        for digest in &self.digests {
            let mut diff = 0u8;
            for (a, b) in candidate.iter().zip(digest.iter()) {
                diff |= a ^ b;
            }
            matched |= diff == 0;
        }
        matched
    }
}

/// The cross-process initialization lease.
///
/// The in-process `init_lock` cannot protect a backend two replicas share: each replica
/// holds its own mutex, so both pass the `is_initialized` guard during the same window and
/// interleave their writes. This record is the authority that does hold across processes,
/// and it works wherever the backend can perform an atomic
/// [`StorageBackend::compare_and_set`]: acquiring it is insert-if-absent, so exactly one
/// caller can hold it, and it carries an owner token and an expiry so a dead holder can be
/// replaced without guessing.
///
/// It never holds key or share material — only the attempt token and a timestamp.
const INIT_LEASE_PATH: &str = "sys/init_lease";

/// How long a lease is valid before another attempt may replace it.
///
/// Generous enough for a slow Shamir split and TOTP enrollment on a loaded machine, short
/// enough that a replica that died mid-initialization does not block recovery indefinitely.
/// A *live* attempt never relies on this window: it renews the lease while it runs (see
/// [`InitLeaseGuard`]), so the expiry only ever lets a genuinely dead holder be replaced.
const INIT_LEASE_TTL_SECS: u64 = 300;

/// Divisor applied to the TTL to get the renewal interval.
///
/// The holder renews every `ttl / this`, so a single missed renewal does not yet let the
/// lease expire — there are two more opportunities before the deadline — while a holder
/// whose renewal path is genuinely broken is fenced well before a replacement can take over.
const INIT_LEASE_RENEW_DIVISOR: u64 = 3;

/// What an attempt records at [`INIT_LEASE_PATH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitLease {
    /// The attempt that holds the lease. Opaque and random; an identifier, not a secret.
    owner: String,
    /// Unix seconds after which the lease may be replaced by another attempt.
    expires_at: i64,
}

impl InitLease {
    fn is_expired(&self, now: i64) -> bool {
        self.expires_at <= now
    }
}

/// Build the lease record for `owner`, expiring `ttl_secs` from now.
///
/// A free function so the acquisition path and the renewal task write byte-identical
/// records; the record is an ordinary [`SecretEntry`] carrying the owner token in its
/// metadata, which is what the ownership-conditional replace matches on.
fn lease_entry(owner: &str, ttl_secs: u64) -> SecretEntry {
    SecretEntry::new(
        INIT_LEASE_PATH.to_string(),
        serde_json::to_vec(&InitLease {
            owner: owner.to_string(),
            expires_at: Utc::now().timestamp() + ttl_secs as i64,
        })
        .unwrap_or_default(),
        EncryptionMetadata::default(),
        SecurityLevel::Internal,
        Uuid::nil(),
    )
    .owned_by(owner)
}

/// A held initialization lease: the owner token, the fence every durable write consults,
/// and — on a backend that arbitrates between processes — the task that renews it.
///
/// A fixed expiry alone is not enough. If an attempt runs longer than its TTL, a second
/// replica may legitimately take the lease over while the first is still writing; the first
/// then keeps overwriting the second's artifacts and can hand its caller shares that do not
/// open the root key that ends up stored. Renewal redraws the window, but renewal alone is
/// not the guarantee: renewal is a background task, so a renewal that fails is only noticed
/// on the *next* write's [`Self::check`], and an attempt can be fenced the instant after a
/// check passes. The guarantee is [`Self::fence`], which makes every durable write
/// conditional in the shared backend on this record still carrying this token — so a write
/// either lands while the attempt demonstrably holds the lease, or it does not land at all.
/// Loss is always fail-closed: an attempt that cannot prove it still holds the lease stops
/// rather than racing.
struct InitLeaseGuard {
    owner: String,
    /// Set once this attempt has lost the lease — taken over, or a renewal failed.
    ///
    /// This is a *hint*, never the guarantee: it is set asynchronously by the renewal task,
    /// so it can lag the durable truth. [`Self::check`] uses it to fail fast and to stop the
    /// sequence early, but no write is ever authorised by its absence — that is
    /// [`Self::fence`]'s job.
    lost: Arc<AtomicBool>,
    /// Renewal task. `None` on a single-process backend, where no lease record exists.
    renewal: Option<tokio::task::JoinHandle<()>>,
    /// Whether a lease record actually exists and must be released.
    holds_record: bool,
}

impl InitLeaseGuard {
    fn owner(&self) -> &str {
        &self.owner
    }

    /// Fail closed if this attempt believes it no longer holds the lease.
    ///
    /// A cheap early-out over the in-process loss flag, called before each durable write so
    /// an attempt that already knows it is fenced stops promptly. It is deliberately **not**
    /// the guarantee: the flag is set by the renewal task and can lag a takeover, and the
    /// two are separated by an arbitrary window in which the attempt would still see
    /// "not lost". Nothing may be authorised by this call returning `Ok`. That is
    /// [`Self::fence`]'s job, and it is why every durable write of the sequence is fenced.
    fn check(&self) -> Result<()> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(anyhow!(
                "this initialization no longer holds its lease — another attempt took it \
                 over or renewal failed — so it must not write or commit"
            ));
        }
        Ok(())
    }

    /// The fence every durable write of this attempt must go through.
    ///
    /// Names the lease record and this attempt's token, so the backend can make the write
    /// conditional on the record still being present and still carrying the token — as one
    /// indivisible step. An attempt that has lost the lease cannot use this to write, and
    /// there is no way to obtain a value that would let it: the token is this attempt's, and
    /// a takeover replaces the record's token, which is exactly what the backend compares.
    ///
    /// On a single-process backend no lease record exists. There is no peer to take anything
    /// over, so the in-process lock and [`Self::check`] are the whole guarantee and the fence
    /// degrades to them; the returned option is `None` there. It is `Some` whenever a record
    /// backs the lease, which is every backend that can be shared between replicas.
    fn fence(&self) -> Option<secreton_storage::StorageFence<'_>> {
        if !self.holds_record {
            return None;
        }
        Some(secreton_storage::StorageFence::new(
            INIT_LEASE_PATH,
            &self.owner,
        ))
    }

    /// Stop the renewal task. Idempotent, and called on every return path of `init`.
    fn stop_renewal(&mut self) {
        if let Some(task) = self.renewal.take() {
            task.abort();
        }
    }
}

/// Marker written first by `init` and removed only once every initialization artifact
/// is stored. Its presence means an earlier `init` did not finish — whether it returned
/// an error or the process died mid-way — and the next attempt must discard the partial
/// state before starting.
///
/// Initialization cannot be one storage transaction: the root account and its TOTP
/// enrollment are written by the auth and MFA services through their own storage calls,
/// and the file backend has no transactions at all. A staging marker is what makes the
/// sequence recoverable regardless of backend, without ever persisting share, root-key
/// or credential material.
const INIT_STAGING_PATH: &str = "sys/init_staging";

/// Identity of the account `init` created for root, stored beside the init config.
///
/// The init request carries a `root_username`, so hard-coding `"root"` when issuing the
/// unseal credential loses it for every deployment that chose another name: the vault
/// opens and then fails to find the account, which is a vault nobody can reach. The
/// identity is recorded here instead of assumed, and carries the account's id so the
/// lookup does not depend on the username being spelled the same way twice.
const ROOT_IDENTITY_PATH: &str = "sys/root_identity";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RootIdentity {
    id: String,
    username: String,
}

/// What an in-progress `init` records at [`INIT_STAGING_PATH`], so a later attempt can
/// either finish or roll it back.
///
/// Names the account it was about to create and, once known, that account's id — the id
/// is what locates the TOTP enrollment without decrypting anything. It deliberately holds
/// no share, token, password or key: recovery must not require storing any of those.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitStaging {
    root_username: String,
    /// Set once the root account exists, so cleanup can find its TOTP enrollment by path.
    root_entity_id: Option<String>,
    /// Whether *this* attempt created the root account at `root_username`.
    ///
    /// Registration is an insert-if-absent, so a rejected write — the username is already
    /// taken — leaves this attempt owning nothing at that path, and the record there belongs
    /// to a pre-existing account that cleanup must never delete. Only the writer knows which
    /// case it is; a cleanup that guessed from the username would delete an ordinary account,
    /// and one that skipped the removal whenever the account survived would strand the marker
    /// and make every later initialization fail on recovery.
    ///
    /// `None` is a marker written before this field existed, where the attempt recorded a
    /// `root_entity_id` only after the account was created — so an absent field means the
    /// account was this attempt's, and cleanup should treat it as such rather than strand a
    /// legacy partial attempt's record.
    #[serde(default)]
    root_account_created: Option<bool>,
    /// Set once every durable artifact is stored and the marker is the only thing left.
    ///
    /// Its purpose is to stop a retry from destroying a vault that actually committed:
    /// if the process died between the commit and removing the marker, the artifacts are
    /// all present and correct, and cleanup must verify them rather than delete them.
    #[serde(default)]
    committed: bool,
    /// The `init` attempt that owns this partial state, so rollback only ever removes
    /// what that attempt wrote. Defaulted for markers written before this existed, which
    /// then fail closed into the unowned path rather than being attributed to whoever
    /// retries next.
    #[serde(default)]
    owner: Option<String>,
}

/// The username a vault initialised before [`ROOT_IDENTITY_PATH`] existed always used.
///
/// This is a compatibility constant, not an authentication boundary. It is only ever used
/// to *look up a real account* during legacy recovery, and only after confirming that
/// account exists; the persisted [`RootIdentity`] supersedes it from then on.
const LEGACY_ROOT_USERNAME: &str = "root";

impl SealService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        Self {
            storage,
            crypto,
            auth: std::sync::OnceLock::new(),
            audit: std::sync::OnceLock::new(),
            unseal_buffer: Arc::new(RwLock::new(Vec::new())),
            init_lock: tokio::sync::Mutex::new(()),
            bootstrap_pending: Arc::new(AtomicBool::new(false)),
            bootstrap_share_proof: Arc::new(RwLock::new(None)),
            credential_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            fail_next_bootstrap: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            lease_ttl_secs: None,
        }
    }

    /// Hand the seal service the auth service it needs to open the root session.
    ///
    /// Assigned here rather than passed to `new` because `Services::new` constructs seal
    /// before auth; a `OnceLock` keeps that ordering honest without an `Option` that every
    /// caller has to handle. Called once at startup.
    pub fn with_auth(
        self: Arc<Self>,
        auth: Arc<crate::services::auth::AuthenticationService>,
    ) -> Arc<Self> {
        let _ = self.auth.set(auth);
        self
    }

    /// Hand the seal service the audit logger, for the same reason as [`Self::with_auth`].
    pub fn with_audit(
        self: Arc<Self>,
        audit: Arc<crate::services::audit::AuditLogger>,
    ) -> Arc<Self> {
        let _ = self.audit.set(audit);
        self
    }

    /// Whether an unseal has opened the barrier but its bootstrap credential has not been
    /// issued yet — the state from which a retried unseal can recover the credential with
    /// one of the shares that opened it, rather than the full threshold again.
    ///
    /// The retry is in-process: it holds only while the barrier is still open in this
    /// process. After a restart the root key is gone and the shares are required again.
    pub fn bootstrap_is_pending(&self) -> bool {
        self.bootstrap_pending.load(Ordering::SeqCst)
    }

    /// Check if the system is initialized
    ///
    /// The staging marker is the authority on "not finished": the init config is written
    /// before the root identity, so a crash or a cleanup that could not remove every
    /// artifact would otherwise leave a partial initialization looking permanent, and the
    /// [guard in `init`](Self::init) would refuse the retry that is meant to fix it. A
    /// marker for a *partial* attempt means the vault is treated as uninitialised
    /// regardless of what else is on disk. A marker for a *committed* attempt — every
    /// artifact written, only the marker removal failed — is treated as initialised, so a
    /// retry cannot destroy a working vault.
    pub async fn is_initialized(&self) -> bool {
        if let Ok(Some(entry)) = self.storage.get_by_path(INIT_STAGING_PATH).await {
            // A marker recording a committed initialization means every artifact was
            // written and only the marker's removal failed; the vault is initialised.
            // Only a marker for a genuinely partial attempt makes it uninitialised.
            let committed = serde_json::from_slice::<InitStaging>(&entry.encrypted_data)
                .map(|staging| staging.committed)
                .unwrap_or(false);
            if !committed {
                return false;
            }
        }
        self.storage
            .get_by_path(INIT_PATH)
            .await
            .unwrap_or(None)
            .is_some()
    }

    /// Check if the system is sealed
    pub async fn is_sealed(&self) -> bool {
        !self.crypto.is_unsealed().await
    }

    /// Get current seal status
    pub async fn get_status(&self) -> Result<UnsealResponse> {
        let sealed = self.is_sealed().await;

        let (t, n) = if let Ok(Some(entry)) = self.storage.get_by_path(INIT_PATH).await {
            let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)
                .map_err(|_| anyhow!("Failed to parse init config"))?;
            (config.threshold as usize, config.shares as usize)
        } else {
            (0, 0)
        };

        let progress = self.unseal_buffer.read().await.len();

        Ok(UnsealResponse {
            sealed,
            t,
            n,
            progress,
            root_token: None,
        })
    }

    /// Initialize the vault
    /// Generates Master Key, Splits it, Encrypts Root Key.
    /// Also creates the initial Root User with MFA enabled.
    ///
    /// Refactored per comment 3822469315:
    /// - Root has NO password.
    /// - Root auth is only via Unseal (SSS).
    /// - Root manages Admins.
    ///
    /// Initialization is staged so it is recoverable: a failure anywhere after the first
    /// write leaves the vault re-initialisable rather than permanently unusable. The
    /// failure that matters is the one after the init config is stored but before the
    /// shares reach the operator — the vault is not open, the shares are gone, and without
    /// staging the init config would refuse every retry.
    pub async fn init(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
    ) -> Result<InitResponse> {
        // Hold the initialization lock for the whole sequence below — stale-state
        // recovery, the initialized guard, staging, the writes, commit and marker
        // removal. Locking only the guard would still let two calls interleave across the
        // writes and delete or overwrite each other's artifacts.
        //
        // This protects one process. The lease taken next is what extends the same
        // guarantee to every other replica sharing this backend.
        let _init_guard = self.init_lock.lock().await;

        // Take the cross-process lease before touching durable state, and never proceed
        // without it. A backend that cannot arbitrate between processes returns
        // `Unsupported` here rather than a lock that only appears to lock, and the caller
        // fails closed: initializing on such a backend from two replicas is not something
        // this can make safe, so it refuses instead of proceeding unsafely.
        //
        // The guard renews the lease while the attempt runs and fences every write against
        // it, so an attempt that outlives its TTL is stopped rather than allowed to
        // interleave with the replica that legitimately took the lease over.
        let mut lease = self.acquire_init_lease().await?;

        let result = self
            .init_under_lease(shares, threshold, root_username, auth, mfa, &lease)
            .await;

        // Stop renewal on every path before releasing: a renewal that fired after the
        // release would recreate the lease record from an attempt that has already finished.
        lease.stop_renewal();

        // The lease is released on every path — success, failure and early return — but
        // only if this attempt still owns it. A lease that expired and was legitimately
        // taken over by another attempt must not be deleted by its former holder, which is
        // what the ownership check inside `release_init_lease` enforces.
        self.release_init_lease(&lease).await;

        result
    }

    /// The body of [`Self::init`] with the lease already held.
    async fn init_under_lease(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
        lease: &InitLeaseGuard,
    ) -> Result<InitResponse> {
        // Recovery and the guard run under the lock, against a state neither call can
        // change from now on. `recover_partial_initialization` removes a partial attempt
        // before the initialized check, so a mid-initialisation vault can be retried; it
        // must run first or the init config a partial attempt wrote would be read as a
        // finished initialization.
        self.recover_partial_initialization().await?;

        // A vault that already finished initialising must not be overwritten: the root key
        // in `ROOT_KEY_PATH` is the only thing the existing shares can decrypt.
        if self.is_initialized().await {
            return Err(anyhow!("System already initialized"));
        }

        if threshold > shares {
            return Err(anyhow!("Threshold cannot be greater than shares"));
        }
        if threshold < 2 {
            return Err(anyhow!("Threshold must be at least 2"));
        }

        let outcome = self
            .initialize(shares, threshold, root_username, auth, mfa, lease)
            .await;

        match outcome {
            Ok(response) => Ok(response),
            Err(e) => {
                // The caller gets the original error, but not before the partial state is
                // removed so the next attempt starts clean. The lock is still held, so no
                // concurrent attempt on this instance is observing the state being rolled back.
                //
                // The cleanup runs only while this attempt still durably holds its lease. A
                // taken-over attempt must not roll anything back: the artifacts now in
                // storage belong to the attempt that took the lease over, and the staging
                // marker it would read names *that* attempt — so an unguarded cleanup would
                // delete the winner's root key, account and identity on the way to reporting a
                // failure. That is the opposite of the invariant the lease exists to provide:
                // a losing attempt must change nothing of the winner's.
                if self.lease_still_held(lease).await {
                    self.discard_partial_initialization().await;
                } else {
                    tracing::warn!(
                        "Not rolling back a failed initialization: it no longer holds its \
                         lease, so the durable state belongs to the attempt that took over."
                    );
                }
                Err(e)
            }
        }
    }

    /// Whether this attempt still durably holds the lease record it acquired.
    ///
    /// A read of the shared record, not the in-process loss flag: the flag is set
    /// asynchronously by the renewal task and can lag a takeover, so it cannot decide whether
    /// it is safe to delete state. On a single-process backend there is no record and no peer,
    /// so the in-process view is the whole truth and this reports `true`.
    async fn lease_still_held(&self, lease: &InitLeaseGuard) -> bool {
        if !lease.holds_record {
            return true;
        }
        match self.storage.get_by_path(INIT_LEASE_PATH).await {
            Ok(Some(record)) => record.has_owner(lease.owner()),
            _ => false,
        }
    }

    /// Acquire the cross-process initialization lease and return a guard holding it.
    ///
    /// The acquire is an insert-if-absent on the lease path, which only one caller can win.
    /// A lease that is already present but expired is replaced with an owner-conditional
    /// write, so a replica that died mid-initialization does not block recovery forever and
    /// does not have its live lease stolen by a replica that merely read a stale expiry.
    ///
    /// On a backend that arbitrates between processes the returned guard also starts a
    /// renewal task, so a live attempt keeps its lease for as long as it runs and only a
    /// genuinely dead holder's lease is ever replaceable.
    ///
    /// A backend that cannot arbitrate between processes is a hard error: proceeding would
    /// reintroduce exactly the race the lease exists to close.
    async fn acquire_init_lease(&self) -> Result<InitLeaseGuard> {
        use secreton_storage::Coordination;

        let owner = Uuid::new_v4().to_string();
        let ttl_secs = self.lease_ttl();

        if self.storage.coordination() == Coordination::SingleProcess {
            // A process-local backend cannot be shared between replicas at all — each one
            // is a separate map — so the in-process lock already covers every caller that
            // can reach this backend. There is nothing to take a lease against, and
            // pretending otherwise would be the fake lock this refuses.
            tracing::debug!(
                "Initialization on a single-process backend: the in-process lock is the \
                 complete guarantee, as no second replica can share this storage."
            );
            return Ok(InitLeaseGuard {
                owner,
                lost: Arc::new(AtomicBool::new(false)),
                renewal: None,
                holds_record: false,
            });
        }

        // First attempt: nobody holds it.
        let acquired = self
            .storage
            .compare_and_set(&lease_entry(&owner, ttl_secs), Expect::Absent)
            .await
            .map_err(|e| anyhow!("Failed to acquire the initialization lease: {e}"))?;
        if !acquired {
            // Someone holds it. Replace it only if it has genuinely expired, and only via an
            // ownership-conditional write against the token that is genuinely there — reading
            // the record and then writing it unconditionally would race a live holder.
            let existing = self
                .storage
                .get_by_path(INIT_LEASE_PATH)
                .await
                .map_err(|e| anyhow!("Failed to read the initialization lease: {e}"))?
                .ok_or_else(|| {
                    anyhow!("the initialization lease vanished between acquiring and reading it")
                })?;

            let held: InitLease = serde_json::from_slice(&existing.encrypted_data)
                .map_err(|e| anyhow!("corrupt initialization lease record: {e}"))?;

            if !held.is_expired(Utc::now().timestamp()) {
                return Err(anyhow!(
                    "another initialization is in progress on this backend; retry once it \
                     completes or its lease expires"
                ));
            }

            let taken_over = self
                .storage
                .compare_and_set(&lease_entry(&owner, ttl_secs), Expect::Owner(&held.owner))
                .await
                .map_err(|e| {
                    anyhow!("Failed to take over the expired initialization lease: {e}")
                })?;
            if !taken_over {
                return Err(anyhow!(
                    "another initialization took over the expired lease first; retry"
                ));
            }

            tracing::warn!(
                "Took over an expired initialization lease. The previous holder may have died \
                 mid-initialization; its partial state is discarded before this attempt writes."
            );
        }

        let guard = InitLeaseGuard {
            owner,
            lost: Arc::new(AtomicBool::new(false)),
            renewal: None,
            holds_record: true,
        };
        let renewal = self.spawn_lease_renewal(&guard, ttl_secs);
        Ok(InitLeaseGuard {
            renewal: Some(renewal),
            ..guard
        })
    }

    /// The lease TTL in force: the production constant, or the test override.
    fn lease_ttl(&self) -> u64 {
        #[cfg(test)]
        if let Some(ttl) = self.lease_ttl_secs {
            return ttl;
        }
        INIT_LEASE_TTL_SECS
    }

    /// Test-only: shorten the initialization lease so a test can exercise expiry and
    /// renewal in seconds rather than the production five minutes.
    #[cfg(test)]
    fn with_lease_ttl(mut self, secs: u64) -> Self {
        self.lease_ttl_secs = Some(secs);
        self
    }

    /// Renew the held lease at a fraction of its TTL until the task is aborted.
    ///
    /// Renewal is an ownership-conditional replace: if the record is gone or carries
    /// another token, this attempt has lost the lease and the shared `lost` flag is set, so
    /// every subsequent write and the commit fail closed. A renewal that *errors* is treated
    /// the same way rather than retried indefinitely — an attempt that cannot prove it holds
    /// the lease must not keep writing as though it did.
    fn spawn_lease_renewal(
        &self,
        guard: &InitLeaseGuard,
        ttl_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let storage = self.storage.clone();
        let owner = guard.owner.clone();
        let lost = guard.lost.clone();
        let interval = std::time::Duration::from_secs((ttl_secs / INIT_LEASE_RENEW_DIVISOR).max(1));

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick of a `tokio::time::interval` fires immediately; consume it so
            // renewal starts one interval from now, after the acquisition has settled.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if lost.load(Ordering::SeqCst) {
                    return;
                }
                // A lease that has already lapsed must not be revived by extending it. A
                // renewal that lands after the record's own expiry but before a takeover
                // would replace the dead record with a live one, and the expired attempt
                // would keep initializing — exactly the overlap the lease exists to prevent,
                // and a window in which a second replica that read the expiry notices the
                // extension too late. Fail closed instead: the attempt's renewed window has
                // already been exceeded, so it cannot prove it holds a live lease.
                let expired = match storage.get_by_path(INIT_LEASE_PATH).await {
                    Ok(Some(record)) => {
                        match serde_json::from_slice::<InitLease>(&record.encrypted_data) {
                            Ok(held) => held.is_expired(Utc::now().timestamp()),
                            // A record we cannot parse cannot confirm a live lease.
                            Err(_) => true,
                        }
                    }
                    // Vanished, or unreadable: either way this attempt cannot confirm it
                    // still holds a live lease.
                    Ok(None) | Err(_) => true,
                };
                if expired {
                    tracing::error!(
                        "Initialization lease renewal found the lease already expired; \
                         fencing this initialization so it cannot revive a lapsed lease."
                    );
                    lost.store(true, Ordering::SeqCst);
                    return;
                }
                match storage
                    .compare_and_set(&lease_entry(&owner, ttl_secs), Expect::Owner(&owner))
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::error!(
                            "Initialization lease renewal found the lease absent or owned by \
                             another attempt; fencing this initialization so it cannot write \
                             or commit."
                        );
                        lost.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        tracing::error!(
                            "Initialization lease renewal failed: {e}; fencing this \
                             initialization so it cannot write or commit."
                        );
                        lost.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            }
        })
    }

    /// Release the lease, but only while this attempt still owns it.
    ///
    /// A former holder whose lease expired and was taken over must not delete the new
    /// holder's lease: that would reopen the window for a third caller while the second is
    /// still initializing. `delete_owned` is conditional for exactly this reason.
    async fn release_init_lease(&self, guard: &InitLeaseGuard) {
        if !guard.holds_record {
            // Single-process or otherwise incapable backend: there is no lease to release,
            // and `acquire_init_lease` did not create one.
            return;
        }
        match self
            .storage
            .delete_owned(INIT_LEASE_PATH, guard.owner())
            .await
        {
            Ok(_) => {}
            Err(secreton_storage::StorageError::Unsupported { .. }) => {
                // The backend reported cross-process coordination but cannot delete
                // conditionally; there is nothing this attempt can safely do here.
            }
            Err(e) => {
                tracing::error!("Failed to release the initialization lease: {e}");
            }
        }
    }

    /// The write sequence for a fresh initialization. Writes a staging marker first and
    /// removes it last, so its presence after this returns is the signal that the vault is
    /// mid-initialisation and must be rolled back before any retry.
    async fn initialize(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
        lease: &InitLeaseGuard,
    ) -> Result<InitResponse> {
        let lease_token = lease.owner();

        // 1. Generate Master Key (32 bytes)
        let master_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 2. Generate Root Key (32 bytes) - The key used by CryptoService
        let root_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 3. Encrypt Root Key with Master Key
        // We use CryptoService's low-level encrypt which doesn't require unsealing
        let encrypted_root = self.crypto.encrypt(&master_key, &root_key, None)?;

        // 4. Split Master Key
        let mut rng = rand::rngs::OsRng;
        let splits = shamir::split(&master_key, threshold as usize, shares as usize, &mut rng)
            .map_err(|e| anyhow!("Shamir split failed: {}", e))?;

        // 5. Staging marker, before any durable artifact of this initialization.
        //
        // Every durable write from here is fenced on the lease: an attempt that has been
        // taken over, or whose renewal failed, must not publish an artifact. `store_artifact`
        // makes each write conditional on the lease record in the shared backend, so a stale
        // attempt cannot publish even in the window between a `check` and the write that
        // follows it.
        self.write_staging(
            &InitStaging {
                root_username: root_username.to_string(),
                root_entity_id: None,
                root_account_created: Some(false),
                committed: false,
                owner: Some(lease_token.to_string()),
            },
            lease,
        )
        .await?;

        // 6. Store Init Config
        let config = InitConfig { shares, threshold };
        let config_bytes = serde_json::to_vec(&config)?;

        self.store_artifact(
            SecretEntry::new(
                INIT_PATH.to_string(),
                config_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            )
            .owned_by(lease_token),
            lease,
        )
        .await
        .map_err(|e| anyhow!("Failed to store init config: {}", e))?;

        // 7. Store Encrypted Root Key
        //
        // This is the write the finding names. On Redis the former unconditional `store` set
        // `secreton:path:sys/root_key` to this attempt's id, so a holder that had already lost
        // the lease still repointed the mapping the winning attempt had installed — the
        // winner's returned shares then did not open the root key the path resolved to. The
        // fenced write replaces this atomically while, and only while, the lease is still
        // this attempt's, so a lost lease means the write does not happen at all.
        let enc_root_bytes = serde_json::to_vec(&EncryptedRootKey {
            data: encrypted_root,
        })?;
        self.store_artifact(
            SecretEntry::new(
                ROOT_KEY_PATH.to_string(),
                enc_root_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::TopSecret,
                Uuid::nil(),
            )
            .owned_by(lease_token),
            lease,
        )
        .await
        .map_err(|e| anyhow!("Failed to store root key: {}", e))?;

        // 8. Format Response
        //
        // Serialise once and encode the same bytes twice. Each share was previously
        // serialised separately per encoding, with the failure discharged by `unwrap` — in
        // the one path where a panic is least recoverable, since the root key is already
        // stored by this point and a caller that never receives its unseal keys is left
        // with a vault nobody can open.
        let encoded: Vec<Vec<u8>> = splits
            .iter()
            .map(|s| {
                serde_json::to_vec(s)
                    .map_err(|e| anyhow!("Failed to serialise an unseal share: {}", e))
            })
            .collect::<Result<_>>()?;

        let keys_hex: Vec<String> = encoded.iter().map(hex::encode).collect();
        let keys_base64: Vec<String> = encoded
            .iter()
            .map(|bytes| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes))
            .collect();

        // 9. Create Root User and Enable MFA
        // We must temporarily enable the root key so Auth service can encrypt user data
        self.crypto.set_root_key(root_key.clone()).await?;

        // The root account is created as a non-password-authenticatable identity: no
        // generated password, no stored hash, and `password_login_disabled` persisted on
        // the record. The previous implementation registered it as an ordinary user with a
        // random password and relied on a literal `"root"` username check to keep it out of
        // the password path — which stopped covering it the moment init accepted a custom
        // `root_username`.
        //
        // Create the account, record its id in staging, then enroll TOTP. The order is the
        // fix: `write_staging` persists the account id *before* the enrollment exists, so
        // any failure at or after enrollment leaves a marker that names the account whose
        // TOTP record must be removed. The previous order enrolled first and recorded the
        // id second, so a failure on that second staging write returned an error, cleanup
        // read a marker with `root_entity_id: None`, deleted the account by username but
        // could not locate its enrollment — which stayed behind as an orphan.
        let result: Result<(secreton_auth::mfa::TotpEnrollment, RootIdentity), anyhow::Error> =
            async {
                let root_user = auth
                    .register_bootstrap_root_owned(
                        root_username,
                        Some("root@system.local".to_string()),
                        vec!["root".to_string(), "admin".to_string()],
                        vec!["*".to_string()],
                        Some(lease_token),
                        lease.fence(),
                    )
                    .await
                    .map_err(|e| anyhow!("Failed to create root user: {}", e))?;

                let identity = RootIdentity {
                    id: root_user.id.clone(),
                    username: root_user.username.clone(),
                };

                self.write_staging(
                    &InitStaging {
                        root_username: identity.username.clone(),
                        root_entity_id: Some(identity.id.clone()),
                        root_account_created: Some(true),
                        committed: false,
                        owner: Some(lease_token.to_string()),
                    },
                    lease,
                )
                .await?;

                // Enable TOTP for Root
                // IMPORTANT: Must be done BEFORE clearing the root key because PersistentTotpService encrypts the secret!
                //
                // The enrollment carries this attempt's lease token and is written through the
                // fence, so (a) the cleanup below can remove it with the ownership-conditional
                // delete it uses for every other artifact of this attempt, and (b) an attempt
                // that has lost the lease cannot create the enrollment at all. The token
                // alone would only make the record removable afterwards; the fence is what
                // stops the stale write, and a stale write here is an orphaned second factor
                // for a privileged account.
                let user_uuid = Uuid::parse_str(&root_user.id).unwrap_or_default();
                let totp_config = mfa
                    .enable_totp_owned(
                        user_uuid,
                        root_user.username.clone(),
                        Some(lease_token),
                        lease.fence(),
                    )
                    .await
                    .map_err(|e| anyhow!("Failed to enable TOTP for root user: {}", e))?;

                Ok((totp_config, identity))
            }
            .await;

        // The generated root key is no longer needed once the account records are
        // encrypted, and must not survive this call either way. Clear it before examining
        // the result so no early return can skip it.
        self.crypto.clear_root_key().await;
        let (totp_config, root_identity) = result?;

        // Persist the created root identity. Reading it back needs no key of its own — it
        // names an account, it does not authenticate one.
        let bytes = serde_json::to_vec(&root_identity)?;
        self.store_artifact(
            SecretEntry::new(
                ROOT_IDENTITY_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            )
            .owned_by(lease_token),
            lease,
        )
        .await
        .map_err(|e| anyhow!("Failed to store root identity: {}", e))?;

        // 10. Commit. Every durable artifact is now stored, so mark the staging entry as
        // committed *before* removing it. If the process dies between the two, the marker
        // still says the vault finished — and recovery must verify and keep it rather than
        // delete a working vault.
        //
        // The commit is fenced like every write before it: an attempt that lost its lease
        // must not publish a committed marker, and must not hand its caller shares it can no
        // longer vouch for. Refusing here is what makes the property "the winning attempt's
        // shares open the stored root key" hold rather than "whichever attempt wrote last".
        self.write_staging(
            &InitStaging {
                root_username: root_identity.username.clone(),
                root_entity_id: Some(root_identity.id.clone()),
                root_account_created: Some(true),
                committed: true,
                owner: Some(lease_token.to_string()),
            },
            lease,
        )
        .await?;

        // Removing the marker is the last step and the only one whose failure does not
        // invalidate the result: the vault is committed, the shares are in the response
        // below, and a later recovery recognises a committed marker and clears it. Failing
        // the whole call here would withhold the shares from the operator while leaving the
        // vault initialised — the one combination nobody can recover from.
        if !self
            .remove_required(INIT_STAGING_PATH, Some(lease_token))
            .await
        {
            tracing::warn!(
                "Initialization committed but its staging marker could not be removed; \
                 recovery will verify and clear it on the next attempt."
            );
        }

        tracing::info!(
            root_username = %root_identity.username,
            "Root account created. The unseal response carries its token; no password login exists."
        );

        Ok(InitResponse {
            keys: keys_hex,
            keys_base64,
            root_totp_uri: totp_config.url,
            // Secret removed for security
        })
    }

    /// Write one initialization artifact through the lease fence.
    ///
    /// Every durable artifact of the initialization sequence — init config, encrypted root
    /// key, root account, TOTP enrollment, root identity — goes through here. The fence makes
    /// the write conditional, *in the shared backend and in the same indivisible step*, on
    /// the lease record still carrying this attempt's token. That is what closes the window
    /// [`InitLeaseGuard::check`] cannot: a check is a snapshot, and an attempt can be fenced
    /// the instant after it passes, so a write authorised only by a preceding check is a
    /// write a taken-over attempt can still perform.
    ///
    /// Fails closed. A backend that reports cross-process coordination but cannot evaluate
    /// the fence returns `Unsupported`, which is propagated as an error rather than falling
    /// back to an unconditional `store` — the fallback would silently reintroduce the race
    /// on exactly the backend that needs the fence. `Ok(false)` means the lease is gone: the
    /// attempt must fail, not retry or write anyway.
    ///
    /// On a single-process backend no lease record exists and no peer can take one over, so
    /// the in-process lock and [`InitLeaseGuard::check`] are the whole guarantee and the
    /// write is a plain `store`.
    async fn store_artifact(&self, entry: SecretEntry, lease: &InitLeaseGuard) -> Result<()> {
        lease.check()?;
        match lease.fence() {
            Some(fence) => {
                let written = self
                    .storage
                    .store_fenced(&entry, fence)
                    .await
                    .map_err(|e| anyhow!("Failed to store initialization artifact: {}", e))?;
                if !written {
                    return Err(anyhow!(
                        "this initialization no longer holds its lease, so it must not write \
                         '{}'",
                        entry.path
                    ));
                }
            }
            None => {
                // `upsert`, not `store`: the staging marker is written up to three times by
                // one attempt, and a plain insert's behaviour on the repeat is not portable —
                // a relational backend with `UNIQUE(path)` refuses it. `upsert` is an
                // update-or-insert, so it carries the repeat. On a single-process backend no
                // peer exists, so the in-process lock plus `check` is the whole guarantee and
                // there is nothing to fence against.
                self.storage
                    .upsert(&entry)
                    .await
                    .map_err(|e| anyhow!("Failed to store initialization artifact: {}", e))?;
            }
        }
        Ok(())
    }

    /// Record initialization progress under [`INIT_STAGING_PATH`].
    ///
    /// Uses a fenced replacement rather than a bare insert: initialization writes this path up
    /// to three times, and a bare `store` is an insert whose behaviour on a repeat write is
    /// not portable — PostgreSQL refuses the second insert on its `UNIQUE(path)` constraint
    /// while the in-memory backend accepts it, so initialization failed on PostgreSQL and
    /// passed in every test that used memory.
    ///
    /// The write is conditional on the *lease*, not on the marker. Conditioning on the
    /// marker's own owner would authorise this attempt to insert a fresh marker whenever the
    /// previous one had been cleared — which is exactly the state a takeover leaves behind.
    /// An attempt that resumed after a winning attempt committed and cleared the marker would
    /// then write its own uncommitted marker over a working vault, and a later recovery would
    /// read it and discard that vault. Fencing on the lease makes the commit
    /// ("only an attempt still holding the lease may publish") true for the marker too.
    async fn write_staging(&self, staging: &InitStaging, lease: &InitLeaseGuard) -> Result<()> {
        let bytes = serde_json::to_vec(staging)?;
        let entry = SecretEntry::new(
            INIT_STAGING_PATH.to_string(),
            bytes,
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .owned_by(lease.owner());

        self.store_artifact(entry, lease).await
    }

    /// Bring a vault that an interrupted `init` left behind to a state a retry can start
    /// from, and fail loudly rather than guess.
    ///
    /// Three cases, distinguished by evidence rather than by assumption:
    ///
    /// - No marker: nothing to recover, including a vault that finished normally.
    /// - Marker with `committed`: every artifact was written and only the marker removal
    ///   failed. It is verified and kept, never deleted — deleting a working vault would
    ///   destroy the only root key its shares can open. If an artifact is missing, that is
    ///   an inconsistency to report, not to paper over.
    /// - Marker without `committed`: a genuine partial attempt, discarded.
    ///
    /// A marker that cannot be read or parsed is an error: it is not the same as "no
    /// marker", and treating it as such would run an initialization against files whose
    /// ownership is unknown.
    async fn recover_partial_initialization(&self) -> Result<()> {
        let Some(staging) = self.read_staging().await? else {
            return Ok(());
        };

        if staging.committed {
            // The attempt finished; only the marker's removal did not. Keep the vault and
            // make it whole again by clearing the marker, which is the single remaining
            // step of a committed initialization.
            if !self.committed_artifacts_present().await? {
                return Err(anyhow!(
                    "the initialization staging marker records a committed vault, but its \
                     artifacts are incomplete; refusing to overwrite a vault that may still \
                     be openable by its shares"
                ));
            }
            // `delete_by_path`'s `Ok(false)` only means "no record was there"; a backend
            // that failed to remove a record it did have reports the same value, so the
            // removal is verified rather than trusted.
            if !self
                .remove_required(INIT_STAGING_PATH, staging.owner.as_deref())
                .await
            {
                return Err(anyhow!(
                    "the committed initialization staging marker could not be removed; \
                     retry once storage is healthy"
                ));
            }
            tracing::info!(
                "Completed a previously committed initialization whose staging marker \
                 removal had failed."
            );
            return Ok(());
        }

        // A partial attempt. Cleanup is only successful if the marker is gone; otherwise
        // starting a new initialization on top of stale artifacts is exactly the state
        // this is meant to prevent. Report it and let the operator retry.
        if !self.discard_partial_initialization_summary().await {
            return Err(anyhow!(
                "an incomplete initialization could not be fully cleaned up; retry once \
                 storage is healthy, or the vault may remain uninitialisable"
            ));
        }
        Ok(())
    }

    /// Read and parse the staging marker.
    ///
    /// `Ok(None)` means absent. An unreadable or unparseable marker is an error: a corrupt
    /// record must not be indistinguishable from a record that is not there, or recovery
    /// would proceed against unknown state.
    async fn read_staging(&self) -> Result<Option<InitStaging>> {
        let entry = self
            .storage
            .get_by_path(INIT_STAGING_PATH)
            .await
            .map_err(|e| anyhow!("Failed to read the initialization staging marker: {e}"))?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let staging = serde_json::from_slice::<InitStaging>(&entry.encrypted_data)
            .map_err(|e| anyhow!("Invalid initialization staging marker: {e}"))?;
        Ok(Some(staging))
    }

    /// Whether a committed initialization's artifacts are all present.
    async fn committed_artifacts_present(&self) -> Result<bool> {
        for path in [INIT_PATH, ROOT_KEY_PATH, ROOT_IDENTITY_PATH] {
            let present = self
                .storage
                .get_by_path(path)
                .await
                .map_err(|e| anyhow!("Failed to verify '{path}' during recovery: {e}"))?
                .is_some();
            if !present {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Remove whatever a partial `init` wrote, marker last.
    ///
    /// Acts only when the staging marker is present: a vault that is not mid-initialisation
    /// must not have its records touched. Every mandatory removal is attempted, and the
    /// marker is removed only if all of them succeeded. A removal that fails leaves the
    /// marker in place so the next `init` retries the cleanup rather than believing the
    /// stale state is gone — which is how a vault becomes permanently uninitialisable.
    ///
    /// Nothing here stores or logs share, token, password or key material: the marker names
    /// the account, and the account's own records are located by path.
    async fn discard_partial_initialization(&self) {
        let _ = self.discard_partial_initialization_summary().await;
    }

    /// The body of [`Self::discard_partial_initialization`], returning whether the marker
    /// was actually removed so the recovery path can report the difference.
    async fn discard_partial_initialization_summary(&self) -> bool {
        let staging = match self.read_staging().await {
            Ok(Some(staging)) => Some(staging),
            // No marker: nothing to do.
            Ok(None) => return true,
            Err(e) => {
                // Cannot read the marker, so cannot locate the account it names. The durable
                // artifacts can still be removed, but the marker must stay so a later
                // attempt with working storage can find the account. Never report success.
                tracing::error!("{e}");
                None
            }
        };

        let mut all_removed = staging.is_some();

        // A committed marker means every artifact was written and the vault is good. Only
        // the marker removal is outstanding; deleting the artifacts would destroy a
        // working vault. This is reachable from the `init` error path if step 10's marker
        // removal failed after the commit was recorded.
        if let Some(staging) = &staging
            && staging.committed
        {
            self.crypto.clear_root_key().await;
            return self
                .remove_required(INIT_STAGING_PATH, staging.owner.as_deref())
                .await;
        }

        // A partial attempt. Only the artifacts it owns may be removed; anything written by
        // another attempt (a marker whose owner is different, or a path with no owner token
        // authored by this repository before tokens existed) is left alone. Cleanup is
        // scoped by ownership precisely so a stale cleanup cannot delete a newer attempt's
        // work.
        if let Some(staging) = &staging {
            if let Some(entity_id) = &staging.root_entity_id {
                let totp_path = format!(
                    "{}{}",
                    crate::services::mfa_persistence::TOTP_PREFIX,
                    entity_id
                );
                all_removed &= self
                    .remove_required(&totp_path, staging.owner.as_deref())
                    .await;
            }
            // Only remove the user record when this attempt actually created it. A duplicate
            // root username was refused by the insert-if-absent leaving the pre-existing
            // account in place, and this attempt owns nothing there — removing it by name
            // would delete an ordinary account. The marker still names the username so a
            // retry can tell what happened; it just does not authorise the deletion. An
            // absent field is a legacy marker and means the account was this attempt's.
            if staging.root_account_created.unwrap_or(true) {
                let user_path = format!(
                    "{}{}",
                    crate::services::auth::USER_STORAGE_PREFIX,
                    staging.root_username
                );
                all_removed &= self
                    .remove_required(&user_path, staging.owner.as_deref())
                    .await;
            }
        }

        let owner = staging.as_ref().and_then(|s| s.owner.as_deref());
        for path in [ROOT_IDENTITY_PATH, ROOT_KEY_PATH, INIT_PATH] {
            all_removed &= self.remove_required(path, owner).await;
        }

        // The marker goes last, and only once every artifact is gone. If anything above
        // failed, leaving it is exactly what lets the next attempt retry the cleanup.
        if all_removed {
            all_removed = self.remove_required(INIT_STAGING_PATH, owner).await;
        } else {
            tracing::error!(
                "Not removing the initialization staging marker: an artifact could not be \
                 removed, so the partial state is still present and the next attempt must \
                 retry this cleanup."
            );
        }

        // The generated root key was installed only to encrypt the account records that
        // were just removed; a completed initialization would not leave it in place.
        self.crypto.clear_root_key().await;
        all_removed
    }

    /// Delete a path and only report success once the path is verifiably gone.
    ///
    /// `Ok(false)` from a backend means "no record was there to delete", which is success
    /// for an idempotent cleanup — but it must never be *trusted* without a read-back,
    /// because a backend whose delete silently did nothing would report the same value as
    /// one with nothing to do. Every removal is therefore followed by a read: the path must
    /// be absent, or the removal is a failure and the marker stays so a retry can finish.
    ///
    /// When `owner` is `Some`, a record that exists but carries a different owner token is
    /// left in place and reported as success — it belongs to an attempt that is not this
    /// one. That is what stops a stale cleanup from deleting a newer attempt's artifacts.
    ///
    /// When `owner` is `None` — a legacy marker with no token, or the crash path before this
    /// attempt recorded one — a record that carries *any* owner token is left in place on a
    /// backend that arbitrates between processes. An unowned cleanup is the one with the
    /// least right to delete: it cannot name whose record it is looking at, so on a shared
    /// backend it must not be allowed to remove a record that some attempt has claimed. The
    /// fallback to an unconditional delete is for a record that genuinely has no owner, not
    /// for one whose owner this call simply does not know.
    async fn remove_required(&self, path: &str, owner: Option<&str>) -> bool {
        // Ownership-scoped removal where a token is known and the backend can express it.
        // A single-process backend has no peers, so ownership is moot and a plain delete is
        // the whole operation.
        let scoped = owner.is_some()
            && self.storage.coordination() != secreton_storage::Coordination::SingleProcess;

        if let Some(owner) = owner.filter(|_| scoped) {
            match self.storage.delete_owned(path, owner).await {
                Ok(true) => {}
                Ok(false) => {
                    // Either the path is already gone, or the record belongs to another
                    // owner. Both are "leave it alone"; the read-back below distinguishes
                    // them from a delete that silently failed.
                }
                Err(secreton_storage::StorageError::Unsupported { .. }) => {
                    // The backend claims `CrossProcess` but cannot delete conditionally.
                    // That is a contradiction in the backend, and falling back to an
                    // unconditional delete here would be worse than the missing capability:
                    // the caller asked to remove only a record it still owns and would then
                    // remove whatever is there, including a newer attempt's artifact. Fail
                    // closed, keep the staging marker, and let a later retry — or an operator
                    // with a working backend — finish the cleanup.
                    tracing::error!(
                        "Refusing to delete '{}' during cleanup: the backend reports \
                         cross-process coordination but `delete_owned` is unsupported, so \
                         the removal cannot be scoped to this attempt's owner. The staging \
                         marker is kept so the cleanup can be retried.",
                        path
                    );
                    return false;
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to remove '{}' during cleanup of an incomplete \
                         initialization: {}",
                        path,
                        e
                    );
                    return false;
                }
            }
        } else if self.storage.coordination() != secreton_storage::Coordination::SingleProcess {
            // Unowned removal on a shared backend. Refuse to remove a claimed record: this
            // call cannot say whose it is, and deleting it would destroy the only root key a
            // newer attempt's shares can open. A record with no owner token at all — the
            // legacy shape — is still fair game, and the read-back below verifies the rest.
            match self.storage.get_by_path(path).await {
                Ok(Some(record)) if record.owner_token().is_some() => {
                    tracing::warn!(
                        "Refusing to remove '{}' during an unowned cleanup: the record is \
                         owned by an attempt this cleanup cannot identify.",
                        path
                    );
                    return true;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Could not read '{}' before an unowned cleanup: {}", path, e);
                    return false;
                }
            }
            if !self.delete_unconditionally(path).await {
                return false;
            }
        } else if !self.delete_unconditionally(path).await {
            return false;
        }

        // Read back. The record must be gone, or belong to someone other than this
        // attempt; anything else means the delete did not take effect and the caller must
        // not continue as though it had.
        //
        // The second arm is the bootstrap-root duplicate case. The root account is created
        // by an insert-if-absent that stamps this attempt's token, so a rejected write — a
        // username that already exists — leaves an account this attempt never created, and
        // an ordinary account carries no owner token at all. Treating that surviving
        // token-less record as a failed removal stranded the staging marker, and every later
        // initialization, even with a different username, then failed while recovering the
        // marker. Only this attempt's own artifacts are stamped, so a token-less record is
        // never this attempt's and leaving it is correct.
        match self.storage.get_by_path(path).await {
            Ok(None) => true,
            Ok(Some(record)) => match (owner, record.owner_token()) {
                (Some(owner), Some(record_owner)) if record_owner != owner => true,
                (Some(_), None) => true,
                _ => {
                    tracing::error!(
                        "Delete of '{}' during cleanup reported success but the record is \
                         still present; keeping the staging marker so a retry can finish \
                         the cleanup.",
                        path
                    );
                    false
                }
            },
            Err(e) => {
                tracing::error!(
                    "Could not verify removal of '{}' during cleanup: {}",
                    path,
                    e
                );
                false
            }
        }
    }

    /// Delete without an ownership precondition, treating absence as success.
    async fn delete_unconditionally(&self, path: &str) -> bool {
        match self.storage.delete_by_path(path).await {
            Ok(_) => true,
            Err(e) => {
                tracing::error!(
                    "Failed to remove '{}' while cleaning up an incomplete initialization: {}",
                    path,
                    e
                );
                false
            }
        }
    }

    /// Give a legacy vault the root identity it was initialised without.
    ///
    /// Vaults created before [`ROOT_IDENTITY_PATH`] existed have no record naming their
    /// root account, so an unseal opens the barrier and then cannot mint the bootstrap
    /// credential — the vault is open and unreachable, and a retry repeats the same
    /// failure. This repairs that state from evidence, never from a guess:
    ///
    /// - The account must actually exist in storage, read back and deserialized.
    /// - It must already be privileged (`admin`/`root`), so a stray unprivileged account
    ///   named `root` is never elevated into the bootstrap identity.
    /// - Only then is it persisted as the identity, and marked non-password-authenticatable
    ///   to match what a fresh `init` would have written, so the legacy account cannot
    ///   password-login either.
    ///
    /// Called by `unseal` when no identity is recorded, so recovery needs no new endpoint
    /// and no reinitialisation. It is idempotent: once the identity exists it returns
    /// immediately, and it returns the identity it recorded so the caller does not have to
    /// re-read it.
    ///
    /// If no such account exists the error stands — inventing an identity for an account
    /// that is not there would mint a credential for an account that cannot be loaded.
    async fn repair_legacy_root_identity(
        &self,
        auth: &crate::services::auth::AuthenticationService,
    ) -> Result<RootIdentity> {
        // Distinguish "no record" from "record I cannot read". Reading through the
        // storage trait first means a corrupt identity or a storage error is reported as
        // itself and never falls through to adopting an account by name: a damaged record
        // must not silently become a different root.
        let existing = self
            .storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .map_err(|e| anyhow!("Failed to read the root identity: {e}"))?;
        if let Some(entry) = existing {
            return serde_json::from_slice(&entry.encrypted_data)
                .map_err(|e| anyhow!("corrupt root identity record: {e}"));
        }

        let Some(user) = auth
            .find_user_by_username(LEGACY_ROOT_USERNAME)
            .await
            .map_err(|e| anyhow!("Failed to read the legacy root account: {e}"))?
        else {
            return Err(anyhow!(
                "no root identity is recorded for this vault, and no legacy '{LEGACY_ROOT_USERNAME}' \
                 account exists to adopt; the vault cannot be given a bootstrap credential"
            ));
        };

        if !user.is_admin() {
            return Err(anyhow!(
                "no root identity is recorded for this vault, and the account named \
                 '{LEGACY_ROOT_USERNAME}' is not privileged; refusing to adopt it as the \
                 bootstrap root"
            ));
        }

        // Persist the boundary a fresh init now writes directly, then record the identity.
        // A failure to mark the account is fatal here: continuing would leave a
        // password-authenticatable root, which is the defect this whole path exists to fix.
        auth.mark_password_login_disabled(&user.username)
            .await
            .map_err(|e| {
                anyhow!("Failed to disable password login for the legacy root account: {e}")
            })?;

        let identity = RootIdentity {
            id: user.id.clone(),
            username: user.username.clone(),
        };
        let bytes = serde_json::to_vec(&identity)?;
        // `upsert`: this repair path is documented as idempotent, and two unseals can race
        // to repair the same vault. A concurrent second write must not hit the backend's
        // `UNIQUE(path)` constraint, which `store` would.
        self.storage
            .upsert(&SecretEntry::new(
                ROOT_IDENTITY_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to persist the legacy root identity: {e}"))?;

        tracing::info!(
            root_username = %identity.username,
            "Recovered the root identity for a vault initialised before it was persisted."
        );
        Ok(identity)
    }

    /// Submit a share to unseal.
    ///
    /// The share is required on every path, including a retry of a pending bootstrap
    /// credential: the credential is the root token, so issuing it must be earned by
    /// producing key material that belongs to this vault, not by the presence of an
    /// in-memory flag.
    pub async fn unseal(&self, share_str: &str) -> Result<UnsealResponse> {
        if !self.is_initialized().await {
            return Err(anyhow!("System not initialized"));
        }

        let share = Self::decode_share(share_str)?;

        if !self.is_sealed().await {
            // The barrier is already open. Normally that means there is nothing to do and
            // the status is all the caller needs. But if a previous unseal opened the
            // barrier and then failed to issue the root credential, this call is the
            // retry: the root identity was persisted at init, so the credential can be
            // minted without reinitialising or resurrecting the master key. Answering with
            // an empty token here is what left the vault open and unreachable.
            //
            // The retry still demands the share. Accepting the flag alone would make
            // `sys/unseal` — a public route by construction, since it must work while
            // sealed — mint the most privileged token in the system for any anonymous
            // caller that happened to hit the window.
            if self.bootstrap_is_pending() {
                return self.issue_bootstrap_credential_for(&share).await;
            }
            return self.get_status().await;
        }

        let mut buffer = self.unseal_buffer.write().await;

        // Add if not exists
        if !buffer.iter().any(|s| s.index == share.index) {
            buffer.push(share.clone());
        }

        // Check threshold
        let (threshold, shares_total) = {
            let entry = self
                .storage
                .get_by_path(INIT_PATH)
                .await
                .map_err(|e| anyhow!("Storage error: {}", e))?
                .ok_or(anyhow!("Init config missing"))?;
            let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)?;
            (config.threshold as usize, config.shares as usize)
        };

        if buffer.len() < threshold {
            drop(buffer);
            return self.get_status().await;
        }

        // Threshold reached. The buffer's contents are about to be either consumed into a
        // proof (success) or discarded (failure), and in both cases must not linger in
        // memory. Rotate them out of the shared buffer now so no early return below can
        // skip the cleanup.
        tracing::info!("Threshold reached. Attempting to unseal...");
        let submitted: Vec<Share> = std::mem::take(&mut *buffer);
        drop(buffer);

        // Reconstruct Master Key. A failure here means at least one share is wrong; the
        // buffer must be emptied rather than left full, or the same share index could never
        // be corrected — the correct share would find its index occupied and be ignored,
        // and every later attempt would reuse the bad combination.
        let master_key = match shamir::combine(&submitted) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Failed to combine shares: {}", e);
                Self::discard_shares(submitted);
                self.audit_unseal(
                    LEGACY_ROOT_USERNAME,
                    false,
                    "unseal",
                    "share reconstruction failed; shares discarded, retry with valid shares",
                )
                .await;
                return Err(anyhow!("Failed to reconstruct key: {}", e));
            }
        };

        // Get Encrypted Root Key
        let entry = self
            .storage
            .get_by_path(ROOT_KEY_PATH)
            .await
            .map_err(|e| anyhow!("Storage error: {}", e))?
            .ok_or(anyhow!("Root key missing"))?;

        let enc_root: EncryptedRootKey = serde_json::from_slice(&entry.encrypted_data)
            .map_err(|_| anyhow!("Invalid root key data"))?;

        // Decrypt Root Key
        match self.crypto.decrypt_with_key(&master_key, &enc_root.data) {
            Ok(root_key) => {
                // SUCCESS!
                self.crypto.set_root_key(root_key).await?;
                tracing::info!("Vault unsealed successfully.");

                // Record what a retry must prove before the shares are discarded: a digest
                // of each share that actually opened the barrier. The credential is minted
                // later, and if that fails the caller retries by re-presenting a share, not
                // by presenting nothing.
                *self.bootstrap_share_proof.write().await =
                    Some(BootstrapShareProof::from_shares(&submitted));
                Self::discard_shares(submitted);

                self.issue_bootstrap_credential_with(threshold, shares_total)
                    .await
            }
            Err(e) => {
                tracing::error!(
                    "Failed to decrypt root key with reconstructed master key. Wrong shares?"
                );
                Self::discard_shares(submitted);
                self.audit_unseal(
                    LEGACY_ROOT_USERNAME,
                    false,
                    "unseal",
                    "root key did not decrypt with the submitted shares; shares discarded",
                )
                .await;
                Err(anyhow!(
                    "Failed to decrypt root key. Invalid shares? Error: {}",
                    e
                ))
            }
        }
    }

    /// Decode a share from its wire form: hex or base64 of the serialised [`Share`].
    fn decode_share(share_str: &str) -> Result<Share> {
        // Try decoding hex first, then base64
        let share_bytes = if let Ok(b) = hex::decode(share_str) {
            b
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, share_str)
                .map_err(|_| anyhow!("Invalid share format (expected hex or base64)"))?
        };
        serde_json::from_slice(&share_bytes).map_err(|_| anyhow!("Invalid share structure"))
    }

    /// Zeroize and drop a set of shares that has done its job or proved wrong.
    fn discard_shares(mut shares: Vec<Share>) {
        use zeroize::Zeroize;
        for share in &mut shares {
            share.data.zeroize();
        }
    }

    /// The retry path for a pending bootstrap credential. The caller must present a share
    /// that opened this vault's barrier; the flag alone is not enough.
    ///
    /// A refusal is audited, because `sys/unseal` is public and an unauthenticated attempt
    /// to obtain the root token is exactly the event a reviewer needs after the fact.
    async fn issue_bootstrap_credential_for(&self, share: &Share) -> Result<UnsealResponse> {
        // Error message deliberately says only that the barrier is open: an anonymous
        // caller must not learn whether their share matched, only that they received no
        // credential. The audit record carries the detail.
        let refused = "Vault is already unsealed; no credential is owed. To rotate the root credential, seal and unseal again.";
        let proof = self.bootstrap_share_proof.read().await;
        let accepted = proof.as_ref().is_some_and(|p| p.accepts(share));
        drop(proof);
        if !accepted {
            self.audit_unseal(
                LEGACY_ROOT_USERNAME,
                false,
                "unseal",
                "rejected a pending-bootstrap retry that did not present a share of this vault",
            )
            .await;
            return Err(anyhow!(refused));
        }
        let (threshold, shares_total) = self.init_shape().await;
        self.issue_bootstrap_credential_with(threshold, shares_total)
            .await
    }

    /// Mint the root token and record the session it is bound to.
    ///
    /// Failure here leaves the barrier open with [`Self::bootstrap_is_pending`] set, which
    /// is the recoverable state: a later unseal call reaches
    /// [`Self::issue_bootstrap_credential_for`], whose caller must re-present a share of
    /// this vault, and mints the credential without reinitialising the vault or
    /// re-presenting the full threshold.
    async fn issue_bootstrap_credential_with(
        &self,
        threshold: usize,
        shares_total: usize,
    ) -> Result<UnsealResponse> {
        // Hold the barrier transition out for the whole issuance. `seal` takes the same
        // lock, so a seal cannot clear the root key while this awaits the token service and
        // then let a root token for a sealed vault reach the caller.
        let _guard = self.credential_lock.lock().await;

        // Re-check the barrier under the lock. The caller (or `unseal`) observed an open
        // barrier before reaching here, but `seal` may have won the lock in between and
        // cleared the root key; minting now would hand back a credential for a vault that
        // is closed. Refusing is the only consistent answer, and it is audited because an
        // operator who sealed a vault wants to see why the unseal returned nothing.
        if self.is_sealed().await {
            self.audit_unseal(
                LEGACY_ROOT_USERNAME,
                false,
                "unseal",
                "credential issuance refused: the vault was sealed before the credential \
                 could be minted",
            )
            .await;
            return Err(anyhow!(
                "Vault was sealed before the root credential could be issued; unseal \
                 again with its shares."
            ));
        }

        self.bootstrap_pending.store(true, Ordering::SeqCst);

        // The identity the audit record names is the one `init` recorded, not a literal:
        // a deployment with a custom root username must not have its audit trail claim
        // the actor was "root". When no identity is recorded this is a legacy vault, and
        // resolving it here is what lets the repair happen before the credential is minted
        // rather than failing and being retried forever.
        let actor = match self.auth.get().map(|auth| auth.as_ref()) {
            Some(auth) => match self.repair_legacy_root_identity(auth).await {
                Ok(identity) => identity.username,
                Err(_) => "unresolved-root".to_string(),
            },
            None => "unresolved-root".to_string(),
        };

        match self.mint_root_credential().await {
            Ok(root_token) => {
                self.bootstrap_pending.store(false, Ordering::SeqCst);
                self.audit_unseal(&actor, true, "unseal", "bootstrap credential issued")
                    .await;
                Ok(UnsealResponse {
                    sealed: false,
                    t: threshold,
                    n: shares_total,
                    progress: 0,
                    root_token: Some(root_token),
                })
            }
            Err(e) => {
                // The vault stays open — closing the barrier here would discard the
                // reconstruction the shares just paid for, and the next restart has the
                // same shares available anyway. The state is reported through
                // `bootstrap_is_pending` so the failure is recoverable rather than final.
                //
                // The detail goes to the log and to the audit record, not to the response.
                // This path is reached on a storage or crypto fault, and its error text can
                // carry a backend message ("postgres://…", a file path, a driver string).
                // `sys/unseal` is a public route, so the caller gets the same generic
                // string every other 500 does; the operator correlates it through the log
                // line below. The audit record is internal, so it keeps the real reason.
                tracing::error!(
                    error = %e,
                    "root credential issuance failed after the barrier opened; the vault \
                     stays open and a share-backed unseal retry can recover the credential"
                );
                self.audit_unseal(
                    &actor,
                    false,
                    "unseal",
                    &format!("credential issuance failed: {e}"),
                )
                .await;
                Err(anyhow!(
                    "Vault is unsealed but the root credential could not be issued. \
                     Retry unseal while this process is still running, presenting one of \
                     the shares that opened the vault; the barrier stays open in memory, \
                     so the full threshold is not needed again. A restart discards the \
                     in-memory root key, so after one the vault must be unsealed again \
                     with its shares."
                ))
            }
        }
    }
    /// Look up the root account the way `init` recorded it.
    async fn mint_root_credential(&self) -> Result<String> {
        #[cfg(test)]
        if self.fail_next_bootstrap.swap(false, Ordering::SeqCst) {
            // The marker is deliberately internal-looking so the test below can assert it
            // does not reach the public error: a real storage fault here carries a backend
            // message, and this is the shape of one.
            return Err(anyhow!(
                "injected bootstrap credential failure: \
                 postgres://secreton:hunter2@db.internal:5432 connection refused"
            ));
        }

        let auth = self.auth.get().ok_or_else(|| {
            anyhow!("seal service has no auth service; root login cannot be issued")
        })?;

        // Resolve the root account, repairing a legacy vault that never recorded its
        // identity. Doing it here, rather than only for the audit label, means the
        // credential is minted for the account the vault actually owns.
        let identity = self.repair_legacy_root_identity(auth).await?;
        let root_user = auth
            .find_user_by_username(&identity.username)
            .await
            .map_err(|e| anyhow!("Failed to load root user: {}", e))?
            .ok_or_else(|| {
                anyhow!(
                    "the root account '{}' recorded at init is missing; cannot issue a root token",
                    identity.username
                )
            })?;

        // Hand back a usable root credential, not just a signed string.
        //
        // The previous version encoded a JWT here directly and returned it. That token
        // carried a `jti`, but nothing ever wrote the matching session record, and
        // `validate_token` rejects any token whose `jti` has no session — so *every* call
        // made with the token unseal just returned was refused with "token rejected".
        // Unsealing wiped the shares buffer, so there was no way to get another one. The
        // vault was open and unreachable.
        //
        // The TTL is the bootstrap TTL, not the interactive session timeout: the session
        // policy can be raised to a day, and this credential should not inherit that.
        auth.issue_session_token(
            &root_user,
            "unseal".to_string(),
            "seal-service".to_string(),
            crate::services::auth::BOOTSTRAP_TOKEN_TTL_SECS,
        )
        .await
        .map_err(|e| anyhow!("Failed to issue root token: {}", e))
    }

    /// The `(threshold, shares)` shape recorded at init, for a status response that must
    /// reflect it.
    async fn init_shape(&self) -> (usize, usize) {
        match self.storage.get_by_path(INIT_PATH).await {
            Ok(Some(entry)) => match serde_json::from_slice::<InitConfig>(&entry.encrypted_data) {
                Ok(config) => (config.threshold as usize, config.shares as usize),
                Err(_) => (0, 0),
            },
            _ => (0, 0),
        }
    }

    async fn audit_unseal(&self, actor: &str, success: bool, operation: &str, detail: &str) {
        if let Some(audit) = self.audit.get() {
            audit
                .log_event(crate::services::audit::SecurityEventType::SealOperation {
                    operation: format!("{operation} ({detail})"),
                    user: actor.to_string(),
                    success,
                })
                .await;
        }
    }

    /// Seal the vault
    pub async fn seal(&self) {
        // Serialise against bootstrap credential issuance: a seal that landed while an
        // issuance was awaiting the token service would leave the caller holding a root
        // token for a barrier this call just closed. Taking the lock makes the two
        // mutually exclusive; an issuance that lost the race re-checks and refuses.
        let _guard = self.credential_lock.lock().await;
        self.crypto.clear_root_key().await;
        self.unseal_buffer.write().await.clear();
        // Sealing discards the root key, so a credential that was never issued cannot be
        // issued from this state either. Clearing the flag and the share proof keeps the
        // two in step: after a seal, an unseal must go through the shares again.
        self.bootstrap_pending.store(false, Ordering::SeqCst);
        *self.bootstrap_share_proof.write().await = None;
        tracing::info!("Vault sealed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::performance::SecretPerformanceOptimizer;
    use crate::services::admin::AdminService;
    use crate::services::audit::AuditLogger;
    use crate::services::auth::{AuthenticationService, BOOTSTRAP_TOKEN_TTL_SECS};
    use crate::services::mfa_persistence::PersistentTotpService;
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    };
    use secreton_storage::StorageResult;
    use secreton_storage::backends::MemoryBackend;

    /// A sealed vault with the auth, MFA, audit and admin services wired the way
    /// `Services::new` wires them. Shared by every test here so none of them drifts into
    /// testing a partially connected service graph.
    struct Vault {
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        auth: Arc<AuthenticationService>,
        mfa: Arc<CombinedMfaService>,
        seal: Arc<SealService>,
        admin: Arc<AdminService>,
        audit: Arc<AuditLogger>,
    }

    async fn sealed_vault() -> Vault {
        let storage = Arc::new(MemoryBackend::new());
        sealed_vault_with_storage(storage).await
    }

    /// The same graph as [`sealed_vault`], over a caller-supplied backend so a test can
    /// inject storage faults without a second service wiring.
    async fn sealed_vault_with_storage(storage: Arc<dyn StorageBackend + Send + Sync>) -> Vault {
        sealed_vault_with_storage_and_lease_ttl(storage, None).await
    }

    /// The same graph, with the initialization lease shortened so a test can exercise
    /// expiry and renewal without waiting the production five minutes.
    async fn sealed_vault_with_storage_and_lease_ttl(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        lease_ttl_secs: Option<u64>,
    ) -> Vault {
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test-secret-1234567890".to_string());

        let persistent_totp = Arc::new(PersistentTotpService::new(
            storage.clone(),
            crypto.clone(),
            "secreton-test".to_string(),
        ));
        let mfa = Arc::new(CombinedMfaService::new(
            persistent_totp,
            Arc::new(InMemorySmsService::new(SmsConfig::default())),
            Arc::new(InMemoryEmailService::new(EmailConfig::default())),
            Arc::new(InMemoryHardwareService::new()),
            Arc::new(DefaultPushService::new_mock()),
            Arc::new(DefaultWebAuthnService::new_default()),
            Arc::new(DefaultRecoveryCodeService::new()),
        ));

        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto.clone(), &config)
                .await
                .unwrap()
                .with_mfa(mfa.clone()),
        );

        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 100, true)
                .await
                .expect("audit logger"),
        );
        let seal = SealService::new(storage.clone(), crypto.clone());
        let seal = match lease_ttl_secs {
            Some(ttl) => seal.with_lease_ttl(ttl),
            None => seal,
        };
        let seal = Arc::new(seal)
            .with_auth(Arc::clone(&auth))
            .with_audit(audit.clone());

        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let admin = Arc::new(
            AdminService::new(storage.clone(), auth.clone(), performance, audit.clone())
                .await
                .expect("admin service")
                .with_crypto(crypto.clone()),
        );

        Vault {
            storage,
            crypto,
            auth,
            mfa,
            seal,
            admin,
            audit,
        }
    }

    /// The JWT payload, read without verification — the tests here are asserting what was
    /// *issued*, and the signature is exercised by the token service's own tests.
    fn claims_of(token: &str) -> serde_json::Value {
        use base64::Engine;
        let payload = token.split('.').nth(1).expect("a JWT has three segments");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload is base64url");
        serde_json::from_slice(&bytes).expect("payload is JSON")
    }

    #[tokio::test]
    async fn a_duplicate_root_username_does_not_strand_the_staging_marker() {
        // Regression: `init` writes the staging marker before it registers the root account.
        // A username already in storage makes that registration fail as a duplicate, and the
        // attempt owns nothing at the user path. Cleanup then could not remove the
        // pre-existing account and treated its survival as its own failure, so it kept the
        // marker — and every later `init`, even with a different username, failed while
        // recovering that marker. The pre-existing account must also survive: it is not this
        // attempt's to delete.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const OCCUPIED: &str = "vault-operator";
        // An ordinary account: a record at the user path with no owner token. Written
        // directly so the test does not need an active crypto key (registration encrypts),
        // which is orthogonal to what this regression is about.
        vault
            .storage
            .store(&SecretEntry::new(
                format!("users/{OCCUPIED}"),
                b"ordinary-account".to_vec(),
                EncryptionMetadata::default(),
                SecurityLevel::Secret,
                Uuid::new_v4(),
            ))
            .await
            .expect("pre-existing ordinary account");

        let first = vault
            .seal
            .init(3, 2, OCCUPIED, &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "initializing with an occupied username must be refused"
        );

        // The next attempt, with a different name, must get past recovery and succeed.
        let second = vault
            .seal
            .init(3, 2, "new-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry with a fresh username must not be blocked by the failed attempt");

        assert_eq!(second.keys.len(), 3, "the retry must return its shares");
        assert!(
            vault
                .storage
                .get_by_path("sys/init_staging")
                .await
                .expect("read marker")
                .is_none(),
            "a committed initialization must clear its staging marker"
        );

        // The ordinary account the failed attempt collided with is untouched.
        let surviving = vault
            .storage
            .get_by_path(&format!("users/{OCCUPIED}"))
            .await
            .expect("read occupied account");
        assert!(
            surviving.is_some(),
            "cleanup must not delete an account this attempt never created"
        );
    }

    #[tokio::test]
    async fn unsealing_with_a_custom_root_username_returns_the_root_credential() {
        // Regression: `unseal` looked up the literal username "root" while `init` accepted
        // any name, so a deployment that chose another name opened the vault and then could
        // not find the account — no credential, and no shares left to ask with.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "vault-operator";
        let init = vault
            .seal
            .init(3, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        let partial = vault.seal.unseal(&init.keys[0]).await.expect("share one");
        assert!(partial.sealed);
        assert_eq!(partial.progress, 1);
        assert!(partial.root_token.is_none(), "no token before threshold");

        let complete = vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert!(!complete.sealed);
        assert_eq!(complete.t, 2);
        assert_eq!(complete.n, 3);

        let token = complete
            .root_token
            .expect("the threshold unseal must hand back a root credential");
        let claims = claims_of(&token);
        assert_eq!(
            claims["username"], ROOT_USERNAME,
            "the token must name the account init created, not a hard-coded 'root'"
        );
    }

    #[tokio::test]
    async fn the_bootstrap_credential_is_access_only() {
        // Security regression: `issue_session_token` minted a full token *pair* and stored
        // the refresh half on the bootstrap session. A refresh token outlives the
        // one-hour bootstrap TTL by design, so the most privileged credential in the
        // system could be rotated indefinitely — the TTL the whole design rests on would
        // be decorative.
        //
        // The property: the session record behind the bootstrap token carries no refresh
        // token, so there is nothing to exchange and `refresh_token()` cannot extend it.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(2, 2, "access-only-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        // The session is located by the token's own `jti`, the same way `validate_token`
        // does, so this reads the exact record the credential is bound to.
        let jti = claims_of(&token)["jti"]
            .as_str()
            .expect("the access token carries a jti")
            .to_string();
        let path = format!("sys/auth/sessions/{jti}");
        let entry = vault
            .storage
            .get_by_path(&path)
            .await
            .expect("storage")
            .expect("the bootstrap session record must exist");
        let plaintext = vault
            .crypto
            .decrypt(&entry.encrypted_data)
            .await
            .expect("decrypt the session record");
        let session: serde_json::Value =
            serde_json::from_slice(&plaintext).expect("the session record is JSON");
        assert!(
            session["refresh_token"].is_null(),
            "a bootstrap session must be access-only, but the session record carries a \
             refresh token"
        );

        // And the credential itself cannot be exchanged. `refresh_token` rejects it because
        // no matching refresh token was ever issued.
        assert!(
            vault
                .auth
                .refresh_token(&token, "192.0.2.1".to_string(), "test".to_string())
                .await
                .is_err(),
            "the bootstrap access token must not be exchangeable for a refreshed credential"
        );
    }

    #[tokio::test]
    async fn the_unseal_token_validates_and_reaches_administrative_operations() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "operations-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        // The token survives validation, which requires the session record it was issued
        // with. A signed string with no session is refused by `validate_token`, and that
        // was the original unreachable-vault failure.
        let user = vault
            .auth
            .validate_token(&token)
            .await
            .expect("the unseal token must validate");
        assert_eq!(user.username, ROOT_USERNAME);
        assert!(user.roles.contains(&"root".to_string()), "{:?}", user.roles);
        assert!(
            user.roles.contains(&"admin".to_string()),
            "{:?}",
            user.roles
        );
        assert_eq!(user.policies, vec!["default".to_string()]);
        assert!(user.is_admin(), "the bootstrap identity must be privileged");

        // The session record the validator checked really exists, under the token's jti.
        let claims = claims_of(&token);
        let jti = claims["jti"].as_str().expect("jti");
        assert!(
            vault
                .storage
                .exists(&format!("sys/auth/sessions/{jti}"))
                .await
                .expect("storage"),
            "the token's session record must be persisted"
        );

        // And it can actually do administrative work, not merely pass a role check.
        let looked_up = vault
            .admin
            .get_user(ROOT_USERNAME)
            .await
            .expect("an admin operation the root token authorises");
        assert_eq!(looked_up.username, ROOT_USERNAME);
    }

    #[tokio::test]
    async fn the_unseal_audit_event_names_the_recorded_root_identity() {
        // The audit trail used to hard-code the actor as "root", so a deployment with a
        // custom root username had its most privileged event attributed to a name that
        // does not exist in its user table.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "audit-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");

        let events = vault
            .audit
            .get_entries(crate::services::audit::AuditFilters::default())
            .await
            .expect("audit entries");
        assert!(
            events.iter().any(|e| e.original_user == ROOT_USERNAME),
            "the seal audit event must name the account init created: {:?}",
            events.iter().map(|e| &e.original_user).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_failed_bootstrap_credential_is_recoverable_only_with_a_share_that_opened_the_vault()
    {
        // Two regressions, one property. If `issue_session_token` failed after the barrier
        // opened and the shares were cleared, the vault was open and unreachable with no
        // retry path. The first fix let any caller retry with no share at all — which
        // turned the public `sys/unseal` route into a way to mint the root token from the
        // mere presence of the in-memory flag. The retry must both exist and require a
        // share that belongs to this vault.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "recovery-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        // Force the next credential issuance to fail, once.
        vault.seal.fail_next_bootstrap.store(true, Ordering::SeqCst);

        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let failed = vault.seal.unseal(&init.keys[1]).await;
        assert!(
            failed.is_err(),
            "the injected failure must surface to the caller"
        );

        // The barrier is open — the shares did their job — and the service records that a
        // credential is still owed. Neither is a state the caller has to guess at.
        assert!(!vault.seal.is_sealed().await);
        assert!(vault.seal.bootstrap_is_pending());

        // A retry must prove it holds a share of this vault. A caller with none is refused
        // and receives no credential; the request names nothing about whether the barrier
        // is open beyond a generic refusal.
        let without_a_share = vault.seal.unseal("not-a-share").await;
        assert!(
            without_a_share.is_err(),
            "a pending retry with no valid share must not receive a credential"
        );
        assert!(
            vault.seal.bootstrap_is_pending(),
            "a refused retry must leave the credential still owed"
        );

        // A wrong-but-well-formed share is refused too: the proof is over the shares that
        // opened this vault, not over the ability to serialise a share. This share is from
        // a *different* vault, so it is real and well-formed but cannot open this barrier.
        let other_vault = sealed_vault().await;
        let other_init = other_vault
            .seal
            .init(2, 2, "other-root", &other_vault.auth, &other_vault.mfa)
            .await
            .expect("second vault init");
        assert!(
            vault.seal.unseal(&other_init.keys[0]).await.is_err(),
            "a share from a different vault must not satisfy the retry"
        );

        // Retry by re-presenting one of the shares that opened the barrier — not the full
        // threshold again.
        let retried = vault
            .seal
            .unseal(&init.keys[0])
            .await
            .expect("a retry with a share that opened the vault must recover the credential");
        let token = retried.root_token.expect("root credential on retry");
        let user = vault
            .auth
            .validate_token(&token)
            .await
            .expect("the retried token must validate");
        assert_eq!(user.username, ROOT_USERNAME);
        assert!(user.is_admin());
        assert!(
            !vault.seal.bootstrap_is_pending(),
            "the pending flag clears once the credential is issued"
        );

        // Fault injection is single-shot, so the vault is healthy: a further call while
        // the barrier is open, with a valid share, returns plain status and mints nothing.
        let afterwards = vault
            .seal
            .unseal(&init.keys[0])
            .await
            .expect("the vault keeps operating");
        assert!(!afterwards.sealed);
        assert!(
            afterwards.root_token.is_none(),
            "a settled vault issues no second credential"
        );
    }

    #[tokio::test]
    async fn a_failed_issuance_error_reaches_the_caller_without_internal_detail() {
        // Regression: the failure branch of `issue_bootstrap_credential_with` formatted the
        // underlying anyhow error into the returned message, and `sys/unseal` is a public
        // route — it has to work while sealed — so the caller received the storage
        // backend's raw text. Connection strings and hostnames were reaching an
        // unauthenticated response body, the one place the repository's rule says they
        // must not. The detail belongs in the log and the audit record; the caller gets the
        // actionable, generic instruction.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(2, 2, "leak-check-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.fail_next_bootstrap.store(true, Ordering::SeqCst);

        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let err = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect_err("the injected issuance failure must surface");

        let rendered = format!("{err:#}");
        // The markers are named by index: a panic message that interpolated one would put
        // it in a log, which is the very thing the assertion proves did not happen. The
        // rendered body is deliberately not printed either, for the same reason.
        let forbidden = ["hunter2", "db.internal", "postgres://"];
        for (index, marker) in forbidden.iter().enumerate() {
            assert!(
                !rendered.contains(marker),
                "the public unseal error leaked the marker at index {index}"
            );
        }
        // It still has to be actionable: the operator must be told the vault is open and
        // how to recover the credential.
        assert!(
            rendered.contains("Retry unseal"),
            "the error must still tell the operator how to recover"
        );
    }

    #[tokio::test]
    async fn the_bootstrap_token_is_not_mfa_pending_and_this_is_deliberate() {
        // Devin Review flagged the bootstrap credential as bypassing MFA: the root account
        // has a TOTP enrollment, yet the token `unseal` returns reaches administrative
        // operations without a code. That is true, and it is the intended design, not an
        // oversight — pinning it here so the reasoning is recorded next to the code rather
        // than only in a review thread.
        //
        // Root has no password login at all (`password_login_disabled` is persisted on the
        // record). The only way to obtain a root credential is to reconstruct the root key
        // from a threshold of Shamir shares — key material physically held by the operator.
        // That is a *stronger* factor than a TOTP code, which is generated from a secret the
        // server itself stores; demanding the TOTP here would gate a share-proof behind a
        // server-side secret without adding assurance. Gating the token behind the TOTP
        // would also strand an operator whose TOTP device is lost with a vault they can
        // open but cannot administer — the exact unreachable-vault failure this branch
        // already fixed.
        //
        // The property that makes the decision safe is that the credential carries no
        // `mfa_required` claim, so `enforce_mfa_pending` never restricts it: it is a full
        // root token by construction, and it is the share proof, not an MFA code, that the
        // design relies on. The TOTP enrollment still exists and `root_totp_uri` is
        // returned from `init` so the operator can attach an authenticator; it is simply not
        // the factor that mints the bootstrap credential.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "mfa-design-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");
        assert!(
            !init.root_totp_uri.is_empty(),
            "init must still hand back a TOTP enrolment URI for the operator"
        );
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        let claims = claims_of(&token);
        assert_eq!(
            claims["mfa_required"], false,
            "the bootstrap credential is whole by design; it must not be an mfa_pending token"
        );

        let user = vault
            .auth
            .validate_token(&token)
            .await
            .expect("the bootstrap token validates");
        assert!(
            !user
                .metadata
                .get("mfa_pending")
                .map(|v| v == "true")
                .unwrap_or(false),
            "the middleware must not restrict the share-proof credential to MFA endpoints"
        );
        assert!(user.is_admin(), "the credential reaches administrative ops");
    }

    #[tokio::test]
    async fn the_bootstrap_token_lives_for_the_bootstrap_ttl_not_the_session_policy() {
        // Regression: `issue_session_token` read the effective session timeout, which an
        // operator can raise to 24 hours, so the most privileged credential in the system
        // silently inherited that lifetime.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        // Raise the interactive session policy to the maximum the admin service allows.
        vault
            .storage
            .store(
                &SecretEntry::new(
                    "system/config".to_string(),
                    Vec::new(),
                    EncryptionMetadata::default(),
                    SecurityLevel::Internal,
                    Uuid::nil(),
                )
                .add_metadata(
                    "config_data".to_string(),
                    serde_json::json!({ "session_timeout": 86_400u64 }).to_string(),
                ),
            )
            .await
            .expect("store session policy");

        let init = vault
            .seal
            .init(2, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        let claims = claims_of(&token);
        let issued = claims["iat"].as_u64().expect("iat");
        let expires = claims["exp"].as_u64().expect("exp");
        assert_eq!(
            expires - issued,
            BOOTSTRAP_TOKEN_TTL_SECS,
            "the bootstrap credential must not follow the interactive session policy"
        );
        assert_ne!(
            expires - issued,
            86_400,
            "the credential inherited the 24-hour session timeout"
        );
    }

    #[tokio::test]
    async fn bootstrap_recovery_does_not_survive_a_restart() {
        // The retry documented for a failed credential issuance is deliberately
        // in-process. This pins that boundary: a fresh service graph over the same storage
        // has no pending state and a sealed barrier, so it cannot mint a credential
        // without the shares — and does not pretend it could.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "restart-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        vault.seal.fail_next_bootstrap.store(true, Ordering::SeqCst);
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        assert!(vault.seal.unseal(&init.keys[1]).await.is_err());
        assert!(vault.seal.bootstrap_is_pending());

        // Restart: same durable storage, brand-new in-memory services.
        let restarted = sealed_vault_with_storage(vault.storage.clone()).await;
        assert!(
            !restarted.seal.bootstrap_is_pending(),
            "the pending state is in memory and does not survive a restart"
        );
        assert!(
            restarted.seal.is_sealed().await,
            "a restart drops the in-memory root key, so the barrier is sealed"
        );

        // The barrier is sealed and no credential is owed, so a call without shares is
        // refused rather than answered with a credential the process cannot back.
        let without_shares = restarted.seal.unseal("a string that is not a share").await;
        assert!(
            without_shares.is_err(),
            "a restarted vault must not recover a credential without its shares"
        );

        // And with the shares it unseals exactly as it did the first time.
        restarted
            .seal
            .unseal(&init.keys[0])
            .await
            .expect("share one");
        let complete = restarted
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two");
        let token = complete
            .root_token
            .expect("root credential after re-unseal");
        let claims = claims_of(&token);
        assert_eq!(claims["username"], ROOT_USERNAME);
    }

    #[tokio::test]
    async fn sealing_again_clears_the_pending_bootstrap_and_requires_the_shares() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(3, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert!(!vault.seal.is_sealed().await);

        // Crypto works while unsealed.
        assert!(vault.crypto.encrypt_data(b"test").await.is_ok());

        vault.seal.seal().await;
        assert!(vault.seal.is_sealed().await);
        assert!(
            !vault.seal.bootstrap_is_pending(),
            "a sealed vault owes no credential"
        );
        assert!(vault.crypto.encrypt_data(b"test").await.is_err());
    }

    #[tokio::test]
    async fn a_failed_reconstruction_clears_the_buffer_so_correct_shares_can_be_submitted() {
        // Regression: when `shamir::combine` or the root-key decryption failed, the share
        // buffer was left exactly as it was. A wrong share whose index happened to match a
        // correct one could then never be replaced — the correct share found its index
        // occupied and was ignored — so the vault stayed permanently unopenable without a
        // restart, even though the operator was holding the right shares.
        //
        // The property: a wrong share that reaches the threshold is discarded, and the
        // correct shares unseal the vault immediately afterwards, in the same process.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(3, 2, "retry-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");

        // A well-formed share from a different vault: it decodes and contributes to a
        // combination, but cannot open this vault's root key.
        let foreign_vault = sealed_vault().await;
        let foreign = foreign_vault
            .seal
            .init(
                3,
                2,
                "foreign-root",
                &foreign_vault.auth,
                &foreign_vault.mfa,
            )
            .await
            .expect("foreign init");

        vault
            .seal
            .unseal(&foreign.keys[0])
            .await
            .expect("the foreign share is well-formed");
        let failed = vault.seal.unseal(&init.keys[1]).await;
        assert!(
            failed.is_err(),
            "two shares that do not open this vault must fail, not unseal it"
        );
        assert!(
            vault.seal.is_sealed().await,
            "a failed reconstruction must leave the barrier sealed"
        );

        // The buffer must have been emptied by the failure, or the share with this index
        // could not be replaced. Submit the two correct shares and expect success.
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let complete = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("the correct shares must unseal the vault without a restart");
        assert!(!complete.sealed);
        assert!(
            complete.root_token.is_some(),
            "a successful unseal must hand back the root credential"
        );
    }

    #[tokio::test]
    async fn a_rejected_share_combination_is_audited() {
        // The failure path discards key material, so it must be recorded; a reviewer
        // reading the audit log needs to know that a threshold of shares was presented and
        // rejected.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(2, 2, "audit-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        let foreign_vault = sealed_vault().await;
        let foreign = foreign_vault
            .seal
            .init(
                2,
                2,
                "audit-foreign",
                &foreign_vault.auth,
                &foreign_vault.mfa,
            )
            .await
            .expect("foreign init");

        vault
            .seal
            .unseal(&foreign.keys[0])
            .await
            .expect("share one");
        assert!(vault.seal.unseal(&init.keys[1]).await.is_err());

        let events = vault
            .audit
            .get_entries(crate::services::audit::AuditFilters::default())
            .await
            .expect("audit entries");
        assert!(
            events.iter().any(|e| !e.entry.success),
            "a rejected share combination must produce a failed seal audit event: {:?}",
            events
                .iter()
                .map(|e| (&e.original_user, e.entry.success))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn an_initialised_vault_cannot_be_initialised_again() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        vault
            .seal
            .init(3, 2, "first-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        let again = vault
            .seal
            .init(3, 2, "second-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            again.is_err(),
            "re-initialising would discard the existing root key"
        );
    }

    #[tokio::test]
    async fn unseal_before_init_reports_uninitialised_rather_than_decrypting() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        assert!(!vault.seal.is_initialized().await);
        let result = vault.seal.unseal("00").await;
        assert!(result.is_err());
    }

    /// A backend that refuses one write and passes everything else through.
    ///
    /// `fail_stores_for` names the exact path whose *next* store returns an error. The
    /// fault is transient and narrow on purpose: it reproduces the failure an operator
    /// cannot retry by hand — a storage hiccup at one step of initialization — without
    /// breaking any other part of the service graph.
    #[derive(Debug)]
    struct OneShotStoreFailure {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl OneShotStoreFailure {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for OneShotStoreFailure {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            if entry.path == self.path
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot store failure".to_string(),
                });
            }
            self.inner.store(entry).await
        }
        /// The root account is created with `compare_and_set(Absent)`; forwarding keeps the
        /// atomic contract the wrapper exists to model around.
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        /// The write the real path takes on a single-process backend, so the fault lands on
        /// the same artifact regardless of which method carries it.
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            if entry.path == self.path
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot store failure".to_string(),
                });
            }
            self.inner.upsert(entry).await
        }

        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    /// A backend that blocks the first write to one path until the test releases it.
    ///
    /// A `tokio::join!` of two `init` calls is not deterministic: each call may run to
    /// completion before the other starts, so the test passes whether or not the sequence
    /// is guarded. This backend forces the interleaving. `init` writes the staging marker
    /// before any other durable artifact, so pausing there parks the first call inside its
    /// write sequence — after it has passed the `is_initialized` guard and before it has
    /// committed anything — while the test starts a second call. If the sequence is
    /// unguarded, the second call observes the same uninitialised state and interleaves.
    #[derive(Debug)]
    struct PausingStore {
        inner: MemoryBackend,
        pause_on: String,
        reached: tokio::sync::Notify,
        resume: tokio::sync::Notify,
        started: std::sync::atomic::AtomicUsize,
    }

    impl PausingStore {
        fn pausing_on(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                pause_on: path.to_string(),
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                started: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        /// Park the first write to the watched path. `store`, `upsert` and `store_fenced`
        /// all route through here, because which of them carries a given write depends on the
        /// backend's coordination class and the caller should not have to know.
        async fn maybe_pause(&self, path: &str) {
            if path == self.pause_on
                && self
                    .started
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
            {
                self.reached.notify_one();
                self.resume.notified().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for PausingStore {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
            self.inner.store(entry).await
        }
        /// The single-process root-account write goes through `compare_and_set(Absent)`; the
        /// pause must apply here too, so the concurrent-init test parks the first writer in
        /// the same window it always did.
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.maybe_pause(&entry.path).await;
            self.inner.compare_and_set(entry, expect).await
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: secreton_storage::StorageFence<'_>,
        ) -> StorageResult<bool> {
            self.maybe_pause(&entry.path).await;
            self.inner.store_fenced(entry, fence).await
        }

        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    /// A backend that models a well-behaved relational store: a second insert at the same
    /// path is a constraint violation, unlike the in-memory backend, which silently
    /// overwrites. This is the property the memory-only test suite never exercised, and
    /// `write_staging` relied on the overwrite.
    #[derive(Debug)]
    struct UniquePathStore {
        inner: MemoryBackend,
    }

    #[async_trait::async_trait]
    impl StorageBackend for UniquePathStore {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            if self.inner.get_by_path(&entry.path).await?.is_some() {
                return Err(secreton_storage::StorageError::ConstraintViolation {
                    constraint: "UNIQUE(path)".to_string(),
                    message: "a second entry already exists at this path".to_string(),
                });
            }
            self.inner.store(entry).await
        }
        /// Forward the atomic path to the inner memory backend. Without this the default
        /// `Unsupported` is returned and initialization — which creates the root account
        /// with `compare_and_set(Absent)` — cannot run at all. The wrapper's `UNIQUE(path)`
        /// model is about unconditional `store`, and the insert-if-absent path is exactly
        /// the constraint-respecting one, so forwarding is faithful.
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn initialization_writes_its_progress_to_a_unique_path_store() {
        // Regression (severe): `write_staging` used `store` for a path it writes up to
        // three times. Memory accepts the second insert; a relational backend with a
        // `UNIQUE(path)` constraint refuses it, so initialization failed on PostgreSQL
        // while every existing test, which used memory, passed. The injected backend
        // reproduces the constraint without needing a live PostgreSQL in the unit suite.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(UniquePathStore {
            inner: MemoryBackend::new(),
        });
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let init = vault
            .seal
            .init(3, 2, "unique-path-root", &vault.auth, &vault.mfa)
            .await
            .expect("initialization must not depend on store-overwrites-a-path");

        // The vault is genuinely usable, not merely error-free.
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "unique-path-root"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a completed init must not leave its staging marker behind"
        );
    }

    #[tokio::test]
    async fn cleanup_keeps_the_marker_when_an_artifact_delete_fails() {
        // Regression: `discard_partial_initialization` logged a delete failure and then
        // removed the marker anyway. The next attempt therefore saw no marker, skipped
        // cleanup, and the stale init config made it look initialised — a vault that could
        // never be initialised again.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(OneShotDeleteFailure::arming(INIT_PATH));
        let vault = sealed_vault_with_storage(storage.clone()).await;

        // Simulate a crashed init that left the config and the marker behind.
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        store_partial_init(&storage_dyn, "delete-failure-root", None).await;

        let first = vault
            .seal
            .init(3, 2, "delete-failure-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "cleanup that could not remove an artifact must fail the init, not proceed"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the marker must survive so the next attempt retries the cleanup"
        );

        // The delete fault is one-shot; the retry cleans everything and initialises.
        let second = vault
            .seal
            .init(3, 2, "delete-failure-root", &vault.auth, &vault.mfa)
            .await
            .expect("the retry must clear the stale state and initialise");
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "delete-failure-root"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the successful retry must clear the marker"
        );
    }

    #[tokio::test]
    async fn concurrent_initializations_admit_exactly_one_winner() {
        // Regression (severe): two `init` calls both passed the `is_initialized` guard
        // before either had written anything, then interleaved — one call's cleanup deleted
        // the other's artifacts, or both committed and one caller received shares that did
        // not open the stored root key. The lock serialises the whole sequence, so exactly
        // one call succeeds and the shares it returns open the vault.
        //
        // The overlap is forced rather than hoped for: the first call is parked inside
        // `write_staging` (past the guard, before anything is committed) while the second
        // call runs to completion. Without the lock the second call sees an uninitialised
        // vault and both proceed. With the lock the second call blocks until the first
        // finishes and is then refused by the guard.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(PausingStore::pausing_on(INIT_STAGING_PATH));
        let vault = Arc::new(sealed_vault_with_storage(storage.clone()).await);

        let first = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "racer-a", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Wait until the first call is inside its staging write, then start the second.
        storage.reached.notified().await;
        let second = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "racer-b", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Give the second call every chance to reach the guard before releasing the first.
        tokio::task::yield_now().await;
        storage.resume.notify_one();

        let first = first.await.expect("first task");
        let second = second.await.expect("second task");

        let successes: Vec<_> = [&first, &second]
            .into_iter()
            .filter(|r| r.is_ok())
            .collect();
        assert_eq!(
            successes.len(),
            1,
            "exactly one concurrent initialization must succeed; got {:?}",
            [&first, &second].map(|r| r.as_ref().map(|_| ()).map_err(|e| e.to_string()))
        );

        let winner = successes[0];
        let keys = &winner.as_ref().expect("checked").keys;

        // The winning call's shares open the vault the winner initialised, and the
        // credential names the winner's account — not the loser's.
        vault.seal.unseal(&keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&keys[1]).await.expect("share two");
        let winner_name = if first.is_ok() { "racer-a" } else { "racer-b" };
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            winner_name,
            "the shares returned by the winner must open the vault the winner initialised"
        );

        // Final state is consistent: initialised, no marker, and the recorded root identity
        // is the winner's.
        assert!(vault.seal.is_initialized().await);
        assert!(
            vault
                .storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the winner must not leave a staging marker"
        );
        let identity: RootIdentity = serde_json::from_slice(
            &vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .expect("root identity")
                .encrypted_data,
        )
        .expect("root identity parses");
        assert_eq!(identity.username, winner_name);
    }

    #[tokio::test]
    async fn a_legacy_vault_without_a_root_identity_issues_a_working_credential() {
        // Regression (severe): a vault initialised before the root identity was persisted
        // had no `sys/root_identity` record, so unseal opened the barrier and then could
        // not mint a credential, and every retry failed the same way. The repair adopts the
        // real, privileged `root` account and persists the identity. This builds exactly
        // that legacy state: an initialised vault (its root account named `root`) with the
        // identity record removed, which is what a pre-identity vault looks like.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(2, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        // Remove what a pre-identity vault would not have; keep the rest of the state.
        vault
            .storage
            .delete_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage");
        assert!(
            vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the legacy state under test must have no root identity"
        );

        assert!(
            vault
                .seal
                .unseal(&init.keys[0])
                .await
                .expect("share one")
                .sealed,
            "one share of two must not open the vault"
        );
        let complete = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("the legacy vault must unseal");
        let token = complete
            .root_token
            .expect("a legacy vault must recover a root credential");

        // The credential is real: it validates and does administrative work.
        let user = vault.auth.validate_token(&token).await.expect("validates");
        assert_eq!(user.username, "root");
        assert!(user.is_admin());
        vault
            .admin
            .get_user("root")
            .await
            .expect("an admin operation the recovered credential authorises");

        // The identity is now persisted, so the repair does not run again, and the legacy
        // account was made non-password-authenticatable.
        assert!(
            vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .is_some(),
            "recovery must persist the identity so later requests do not depend on the fallback"
        );
        assert!(
            !vault
                .auth
                .verify_password("root", &crate::test_support::generated_password())
                .await
                .expect("verify"),
            "the adopted root account must not be password-authenticatable"
        );
    }

    #[tokio::test]
    async fn a_corrupt_root_identity_is_not_treated_as_a_legacy_vault() {
        // A damaged `sys/root_identity` record must be reported as corrupt, not silently
        // repaired by adopting a `root` account: that would let a damaged record become a
        // different root. The repair only proceeds from a record that is genuinely absent.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        // Initialise a vault, then create a decoy `root` account through the same storage
        // while the barrier is open, so the test needs no second init.
        let init = vault
            .seal
            .init(2, 2, "corrupt-identity-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");

        let decoy_password = crate::test_support::generated_password();
        let decoy = vault
            .auth
            .register_user(
                "root",
                &decoy_password,
                Some("root@system.local".to_string()),
                vec!["root".to_string(), "admin".to_string()],
                vec!["*".to_string()],
            )
            .await
            .expect("a decoy root account that must not be adopted");
        assert!(decoy.is_admin());

        // Corrupt the identity record in place.
        let entry = vault
            .storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage")
            .expect("identity");
        let mut corrupted = entry;
        corrupted.encrypted_data = b"not json".to_vec();
        vault.storage.update(&corrupted).await.expect("update");

        // Seal, then unseal again so the credential is reissued from the now-corrupt
        // identity.
        vault.seal.seal().await;
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let result = vault.seal.unseal(&init.keys[1]).await;

        assert!(
            result.is_err(),
            "a corrupt identity must fail rather than adopt a different root account"
        );
        // The decoy was not adopted: its password still works because it was never turned
        // into the bootstrap root.
        assert!(
            vault
                .auth
                .verify_password("root", &decoy_password)
                .await
                .expect("verify"),
            "no repair may run against a corrupt identity"
        );
    }

    #[tokio::test]
    async fn init_refuses_to_start_when_a_partial_state_cannot_be_cleaned() {
        // A storage failure reading or deleting the marker must not be mistaken for "no
        // marker": proceeding would initialize on top of state whose ownership is unknown.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(FailingReadPath::arming(INIT_STAGING_PATH));
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        store_partial_init(&storage_dyn, "unreadable-marker-root", None).await;

        let result = vault
            .seal
            .init(3, 2, "unreadable-marker-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            result.is_err(),
            "an unreadable staging marker must stop init, not be read as absent"
        );
        assert!(
            !vault.seal.is_initialized().await,
            "the vault must not be left advertising an initialised state"
        );
    }

    /// Write the state a crashed `init` would leave: an init config, and optionally a
    /// staging marker naming the root account it was about to create.
    async fn store_partial_init(
        storage: &Arc<dyn StorageBackend + Send + Sync>,
        root_username: &str,
        root_entity_id: Option<String>,
    ) {
        let config = serde_json::to_vec(&InitConfig {
            shares: 3,
            threshold: 2,
        })
        .expect("serialise init config");
        storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .expect("store a partial init config");
        let staging = serde_json::to_vec(&InitStaging {
            root_username: root_username.to_string(),
            root_entity_id,
            root_account_created: None,
            committed: false,
            owner: None,
        })
        .expect("serialise staging");
        storage
            .store(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                staging,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .expect("store a staging marker");
    }

    /// A backend that fails the *next* delete of one path, and passes everything else
    /// through. One-shot so a test can prove that a retry after the fault succeeds.
    #[derive(Debug)]
    struct OneShotDeleteFailure {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl OneShotDeleteFailure {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for OneShotDeleteFailure {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            if path == self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot delete failure".to_string(),
                });
            }
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    /// A backend whose read of one path fails, to prove a storage failure is not read as
    /// "path absent".
    #[derive(Debug)]
    struct FailingReadPath {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl FailingReadPath {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for FailingReadPath {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            if path == self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot read failure".to_string(),
                });
            }
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    /// Fails the *next* staging-marker upsert that happens while a TOTP enrollment is
    /// already present, then passes every later write through.
    ///
    /// That condition — "the marker is being updated after the enrollment was created" — is
    /// exactly the window the orphan bug lived in: if the marker written before the
    /// enrollment did not already name the account, cleanup could not find the enrollment to
    /// remove. Keying the fault to the enrollment's presence, rather than to the Nth staging
    /// write, keeps the test meaningful across a reordering of the writes.
    #[derive(Debug)]
    struct FailStagingWhileTotpExists {
        inner: MemoryBackend,
        armed: std::sync::atomic::AtomicBool,
        fired: std::sync::atomic::AtomicBool,
    }

    impl FailStagingWhileTotpExists {
        fn new() -> Self {
            Self {
                inner: MemoryBackend::new(),
                armed: std::sync::atomic::AtomicBool::new(true),
                fired: std::sync::atomic::AtomicBool::new(false),
            }
        }

        async fn totp_exists(&self) -> bool {
            !self
                .inner
                .list(
                    &secreton_storage::QueryParams::new().with_path_prefix(
                        crate::services::mfa_persistence::TOTP_PREFIX.to_string(),
                    ),
                )
                .await
                .expect("list")
                .is_empty()
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for FailStagingWhileTotpExists {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            // `totp_exists` is checked before the armed flag is consumed: the first staging
            // write happens before the enrollment exists and must not spend the one fault.
            if entry.path == INIT_STAGING_PATH
                && self.totp_exists().await
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected staging update failure after TOTP enrollment".to_string(),
                });
            }
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn a_failed_staging_update_after_totp_creation_does_not_orphan_the_enrollment() {
        // Regression: `init` enrolled TOTP *before* recording the account id in the staging
        // marker, so a staging-write failure in that window returned an error while the
        // marker still said `root_entity_id: None`. Cleanup could delete the account by
        // username but had no id to locate the enrollment by, so the TOTP record survived
        // the failed initialization — an orphaned second-factor enrollment for a privileged
        // account that `init` believed it had rolled back. The fix records the id in staging
        // *before* enrolling, so cleanup can always find what it created.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(FailStagingWhileTotpExists::new());
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let first = vault
            .seal
            .init(3, 2, "orphan-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "the injected staging failure after TOTP creation must fail `init`"
        );
        assert!(
            storage.fired.load(std::sync::atomic::Ordering::SeqCst),
            "the fault must actually have fired, or this test proves nothing"
        );
        assert!(
            first.unwrap_err().to_string().contains("injected"),
            "the caller must receive the injected failure"
        );
        assert!(
            !vault.seal.is_initialized().await,
            "a rolled-back init must not advertise an initialised vault"
        );

        // Every artifact of the failed attempt is gone: the TOTP enrollment, the account,
        // the root identity, the root key, the init config and the staging marker.
        assert!(
            !storage.totp_exists().await,
            "the TOTP enrollment created before the failure must not be orphaned"
        );
        assert!(
            !storage
                .exists(&format!(
                    "{}{}",
                    crate::services::auth::USER_STORAGE_PREFIX,
                    "orphan-root"
                ))
                .await
                .expect("exists"),
            "the root account created before the failure must be removed"
        );
        assert!(
            storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the root identity must not survive a rolled-back init"
        );
        assert!(
            storage
                .get_by_path(INIT_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the init config must not survive a rolled-back init"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the staging marker must be removed once cleanup succeeds"
        );
        assert!(
            vault.seal.is_sealed().await,
            "cleanup must clear the root key it installed for the account writes"
        );

        // And the vault is re-initialisable: the retry creates a clean enrollment and the
        // shares it hands back open the vault and issue a credential for the named account.
        let second = vault
            .seal
            .init(3, 2, "orphan-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry after a rolled-back init must succeed");
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "orphan-root"
        );
        let totp_entries = storage
            .inner
            .list(
                &secreton_storage::QueryParams::new()
                    .with_path_prefix(crate::services::mfa_persistence::TOTP_PREFIX.to_string()),
            )
            .await
            .expect("list");
        assert_eq!(
            totp_entries.len(),
            1,
            "the successful retry must leave exactly one TOTP enrollment, not the orphan plus a new one"
        );
    }

    #[tokio::test]
    async fn a_failed_root_identity_write_leaves_the_vault_reinitialisable() {
        // Regression (severe): `init` stored the init config before the root identity, so a
        // failure writing the identity returned an error *after* the vault looked
        // initialised. No shares reached the operator, `init` refused to run again, and a
        // restart discarded the in-memory root key — a new vault nobody could ever unseal.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(OneShotStoreFailure::arming(ROOT_IDENTITY_PATH));
        let vault = sealed_vault_with_storage(storage).await;

        // 1. The first init fails, and does not hand back any shares.
        let first = vault
            .seal
            .init(3, 2, "recovered-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "the injected identity-write failure must surface as an init error"
        );

        // 2. The vault is not left in an initialised state, even though the init config
        // was written before the failure.
        assert!(
            !vault.seal.is_initialized().await,
            "a failed init must not advertise an initialised vault"
        );

        // 3. The next init succeeds with no restart and no manual cleanup.
        let second = vault
            .seal
            .init(3, 2, "recovered-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry must be able to initialise the vault");

        // 4. Its shares open the vault and yield a credential for the account it named.
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        let token = complete
            .root_token
            .expect("a recovered initialization must issue a bootstrap credential");
        let claims = claims_of(&token);
        assert_eq!(
            claims["username"], "recovered-root",
            "the credential must name the account the successful init created"
        );

        // 5. The stale artifacts from the failed attempt are gone, so the second
        // initialization is the only one recorded.
        assert!(
            vault
                .storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a completed init must not leave its staging marker behind"
        );
    }

    #[tokio::test]
    async fn a_leftover_staging_marker_makes_the_vault_look_uninitialised_and_recover() {
        // The crash case: a process dies between writing the init config and completing
        // initialization, so no cleanup runs and both the config and the marker are on
        // disk. The config alone would read as "initialized" and refuse the retry; the
        // marker is what says the work is unfinished, so the retry must be allowed.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let config = serde_json::to_vec(&InitConfig {
            shares: 3,
            threshold: 2,
        })
        .expect("serialise init config");
        storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .expect("store a partial init config");
        let staging = serde_json::to_vec(&InitStaging {
            root_username: "crashed-root".to_string(),
            root_entity_id: None,
            root_account_created: None,
            committed: false,
            owner: None,
        })
        .expect("serialise staging");
        storage
            .store(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                staging,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .expect("store a staging marker");

        assert!(
            !vault.seal.is_initialized().await,
            "a staging marker must override a partial init config"
        );

        // The retry rolls the partial state back and initialises for real, so the shares
        // it hands back are the ones that open this vault.
        let response = vault
            .seal
            .init(3, 2, "crash-recovered-root", &vault.auth, &vault.mfa)
            .await
            .expect("a leftover staging marker must not block a retry");
        vault
            .seal
            .unseal(&response.keys[0])
            .await
            .expect("share one");
        let complete = vault
            .seal
            .unseal(&response.keys[1])
            .await
            .expect("share two");
        let token = complete
            .root_token
            .expect("the recovered initialization must issue a bootstrap credential");
        assert_eq!(claims_of(&token)["username"], "crash-recovered-root");
    }

    /// A backend whose `delete_by_path` reports `Ok(false)` — "nothing was there" — while
    /// leaving the record in place, and whose `delete_owned` is unsupported.
    ///
    /// This is the exact shape the old `remove_required` trusted: it read `Ok(_)` as
    /// success, so a backend that silently declined to delete looked identical to one with
    /// nothing to delete, and cleanup removed the marker over a still-present artifact.
    /// It is one-shot so the test can then prove the retry succeeds.
    #[derive(Debug)]
    struct SilentDeleteFailure {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
        fired: std::sync::atomic::AtomicBool,
    }

    impl SilentDeleteFailure {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
                fired: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for SilentDeleteFailure {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            if path == self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
                // Claims nothing was there, while the record stays. The whole point.
                return Ok(false);
            }
            self.inner.delete_by_path(path).await
        }
        async fn delete_owned(&self, _path: &str, _token: &str) -> StorageResult<bool> {
            // No conditional delete capability, so cleanup must fall back to the
            // unconditional path — and still verify it with a read-back.
            Err(secreton_storage::StorageError::Unsupported {
                operation: "delete_owned".to_string(),
                backend: "silent-delete-failure".to_string(),
            })
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn a_delete_that_reports_false_while_keeping_the_record_keeps_the_marker() {
        // Regression: `remove_required` treated any `Ok(_)` from `delete_by_path` as
        // success, including `Ok(false)`. A backend that reports "nothing was there" while
        // keeping the record — which is exactly what the Redis backend answered for every
        // path-keyed delete before this was fixed — let cleanup delete the staging marker
        // over an artifact that was still present. The next attempt then saw no marker,
        // skipped cleanup, and read the leftover init config as a finished initialization.
        //
        // The property: a removal that does not actually remove is a failure, the marker
        // survives, and the retry does not start on top of stale state.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(SilentDeleteFailure::arming(INIT_PATH));
        let vault = sealed_vault_with_storage(storage.clone()).await;

        // A crashed init left the config and the marker behind.
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        store_partial_init(&storage_dyn, "silent-delete-root", None).await;

        let first = vault
            .seal
            .init(3, 2, "silent-delete-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            storage.fired.load(std::sync::atomic::Ordering::SeqCst),
            "the silent-delete fault must actually have fired, or this test proves nothing"
        );
        assert!(
            first.is_err(),
            "cleanup must not report success when the artifact is still present"
        );
        assert!(
            storage
                .get_by_path(INIT_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the artifact the delete did not remove must still be there"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the marker must survive so the next attempt retries the cleanup"
        );

        // The fault is one-shot; the retry removes the artifact for real and initialises.
        let second = vault
            .seal
            .init(3, 2, "silent-delete-root", &vault.auth, &vault.mfa)
            .await
            .expect("the retry must clear the stale state and initialise");
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "silent-delete-root"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a successful retry must not leave its staging marker behind"
        );
    }

    /// A cross-process backend that cannot perform an ownership-scoped delete.
    ///
    /// A backend is not allowed to report `Coordination::CrossProcess` and then refuse
    /// `delete_owned`, but a wrapper can: the capability is proxied, and a misconfigured
    /// deployment must fail closed rather than degrade into a delete that removes whatever
    /// happens to be at the path.
    #[derive(Debug)]
    struct CrossProcessWithoutScopedDelete {
        inner: Arc<MemoryBackend>,
    }

    impl CrossProcessWithoutScopedDelete {
        fn new() -> Self {
            Self {
                inner: Arc::new(MemoryBackend::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for CrossProcessWithoutScopedDelete {
        fn coordination(&self) -> secreton_storage::Coordination {
            secreton_storage::Coordination::CrossProcess
        }
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn delete_owned(&self, _path: &str, _token: &str) -> StorageResult<bool> {
            Err(secreton_storage::StorageError::Unsupported {
                operation: "delete_owned".to_string(),
                backend: "cross-process-without-scoped-delete".to_string(),
            })
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: secreton_storage::StorageFence<'_>,
        ) -> StorageResult<bool> {
            self.inner.store_fenced(entry, fence).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn an_unsupported_scoped_delete_does_not_fall_back_to_an_unconditional_one() {
        // Regression: on a backend that reports `Coordination::CrossProcess` but answers
        // `Unsupported` for `delete_owned`, cleanup fell back to `delete_unconditionally`.
        // That removes whatever is at the path — including an artifact another attempt
        // owns — which is the one thing the ownership scoping exists to prevent.
        //
        // The property: the foreign record survives, the staging marker survives so the
        // cleanup can be retried, and `init` reports the failure instead of proceeding.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(CrossProcessWithoutScopedDelete::new());
        let vault = sealed_vault_with_storage(storage.clone()).await;

        // A crashed attempt left a partial init. The root key it wrote belongs to a
        // *different* owner than the staging attempt that will try to clean up.
        let config = serde_json::to_vec(&InitConfig {
            shares: 3,
            threshold: 2,
        })
        .expect("serialise init config");
        storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .expect("store the partial init config");
        storage
            .store(
                &SecretEntry::new(
                    ROOT_KEY_PATH.to_string(),
                    b"another attempts key".to_vec(),
                    EncryptionMetadata::default(),
                    SecurityLevel::Secret,
                    Uuid::nil(),
                )
                .owned_by("another-attempt"),
            )
            .await
            .expect("store a foreign root key");
        let staging = serde_json::to_vec(&InitStaging {
            root_username: "cleanup-root".to_string(),
            root_entity_id: None,
            root_account_created: None,
            committed: false,
            owner: Some("this-attempt".to_string()),
        })
        .expect("serialise staging");
        storage
            .store(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                staging,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .expect("store the staging marker");

        let outcome = vault
            .seal
            .init(3, 2, "cleanup-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            outcome.is_err(),
            "cleanup must report failure when it cannot scope the delete"
        );
        assert!(
            storage
                .get_by_path(ROOT_KEY_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the record owned by another attempt must not be removed by an unscoped delete"
        );
        assert_eq!(
            storage
                .get_by_path(ROOT_KEY_PATH)
                .await
                .expect("storage")
                .and_then(|e| e.owner_token().map(str::to_string))
                .as_deref(),
            Some("another-attempt"),
            "the foreign owner token must be intact"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the staging marker must be kept so the cleanup can be retried"
        );
    }

    /// One in-memory store shared by two `SealService` instances, presented as a
    /// cross-process backend.
    ///
    /// `MemoryBackend` reports `Coordination::SingleProcess` because two instances are two
    /// separate maps — so two `SealService`s over one `MemoryBackend` would be modelling a
    /// shared backend while the service correctly decides it is not shareable. This double
    /// wraps *one* map in an `Arc` and reports `Coordination::CrossProcess`, so the two
    /// services really do contend over the same records and the lease path is exercised.
    /// `compare_and_set` and `delete_owned` delegate to the inner map, which performs them
    /// under its own lock — atomic, which is what the backend contract requires.
    ///
    /// It also parks the first write to a watched path so a test can force the overlap
    /// deterministically rather than by timing.
    #[derive(Debug)]
    struct SharedCrossProcessBackend {
        inner: Arc<MemoryBackend>,
        pause_on: String,
        reached: tokio::sync::Notify,
        resume: tokio::sync::Notify,
        started: std::sync::atomic::AtomicUsize,
        /// When set, an owner-conditional replace of the lease record fails, as a storage
        /// fault during renewal would. Presents the renewal-failure path deterministically.
        fail_lease_renewal: std::sync::atomic::AtomicBool,
        /// Set the moment a renewal was refused, so a test can wait for the fence instead
        /// of sleeping a fixed interval.
        renewal_failed: tokio::sync::Notify,
        /// When set, the next staging write that happens *after* a TOTP enrollment exists
        /// fails once, injecting a storage fault in the window finding #1 is about.
        fail_staging_after_totp: std::sync::atomic::AtomicBool,
        staging_fault_fired: std::sync::atomic::AtomicBool,
        /// When set, a read of the lease record reports it as already expired, so a test can
        /// drive the renewal's lapsed-lease fail-closed path deterministically.
        expire_lease_on_read: std::sync::atomic::AtomicBool,
        /// Notified after each read of the lease record, so a test can wait for a renewal's
        /// expiry check instead of sleeping a fixed interval.
        lease_read: tokio::sync::Notify,
    }

    impl SharedCrossProcessBackend {
        fn new(pause_on: &str) -> Self {
            Self {
                inner: Arc::new(MemoryBackend::new()),
                pause_on: pause_on.to_string(),
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                started: std::sync::atomic::AtomicUsize::new(0),
                fail_lease_renewal: std::sync::atomic::AtomicBool::new(false),
                renewal_failed: tokio::sync::Notify::new(),
                fail_staging_after_totp: std::sync::atomic::AtomicBool::new(false),
                staging_fault_fired: std::sync::atomic::AtomicBool::new(false),
                expire_lease_on_read: std::sync::atomic::AtomicBool::new(false),
                lease_read: tokio::sync::Notify::new(),
            }
        }

        async fn totp_exists(&self) -> bool {
            !self
                .inner
                .list(
                    &secreton_storage::QueryParams::new().with_path_prefix(
                        crate::services::mfa_persistence::TOTP_PREFIX.to_string(),
                    ),
                )
                .await
                .expect("list")
                .is_empty()
        }

        async fn maybe_pause(&self, path: &str) {
            if path == self.pause_on
                && self
                    .started
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
            {
                self.reached.notify_one();
                self.resume.notified().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for SharedCrossProcessBackend {
        fn coordination(&self) -> secreton_storage::Coordination {
            secreton_storage::Coordination::CrossProcess
        }
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            let mut found = self.inner.get_by_path(path).await?;
            if path == INIT_LEASE_PATH {
                self.lease_read.notify_one();
                if self
                    .expire_lease_on_read
                    .load(std::sync::atomic::Ordering::SeqCst)
                    && let Some(record) = found.as_mut()
                {
                    // Rewrite the body so the lease names an already-elapsed deadline, but
                    // leave the record present. A renewal that checks the expiry must see it
                    // lapsed and fence; a checkout of the record alone must not.
                    if let Ok(mut held) =
                        serde_json::from_slice::<InitLease>(&record.encrypted_data)
                    {
                        held.expires_at = Utc::now().timestamp() - 1;
                        record.encrypted_data = serde_json::to_vec(&held).unwrap_or_default();
                    }
                }
            }
            Ok(found)
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: Expect<'_>,
        ) -> StorageResult<bool> {
            // A renewal — an owner-conditional replace of the lease record — is the one
            // operation the fault targets, so acquisition (insert-if-absent) still succeeds
            // and only the attempt's continued holding of the lease is broken.
            if entry.path == INIT_LEASE_PATH
                && matches!(expect, Expect::Owner(_))
                && self
                    .fail_lease_renewal
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                self.renewal_failed.notify_one();
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected lease renewal failure".to_string(),
                });
            }
            // A one-shot staging fault, but only once the enrollment exists, so the failure
            // lands in the window where the account and its second factor are already stored
            // and cleanup must remove them.
            if entry.path == INIT_STAGING_PATH
                && self
                    .fail_staging_after_totp
                    .load(std::sync::atomic::Ordering::SeqCst)
                && self.totp_exists().await
                && self
                    .fail_staging_after_totp
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.staging_fault_fired
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected staging failure after TOTP enrollment".to_string(),
                });
            }
            self.maybe_pause(&entry.path).await;
            self.inner.compare_and_set(entry, expect).await
        }
        /// The staging write and every artifact now take this path on a cross-process
        /// backend, so both the park hook and the staging fault live here. This is also the
        /// operation the finding is about: it is what makes a write conditional on the lease
        /// in the same step, closing the window between a `check` and the write it follows.
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: secreton_storage::StorageFence<'_>,
        ) -> StorageResult<bool> {
            if entry.path == INIT_STAGING_PATH
                && self
                    .fail_staging_after_totp
                    .load(std::sync::atomic::Ordering::SeqCst)
                && self.totp_exists().await
                && self
                    .fail_staging_after_totp
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.staging_fault_fired
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected staging failure after TOTP enrollment".to_string(),
                });
            }
            self.maybe_pause(&entry.path).await;
            self.inner.store_fenced(entry, fence).await
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            self.inner.delete_owned(path, token).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn two_service_instances_sharing_a_backend_admit_exactly_one_winner() {
        // Regression (severe, cross-process): `init_lock` is a mutex inside one process.
        // Two replicas sharing a backend each hold their own, so neither is excluded by the
        // other, both pass the `is_initialized` guard, and they interleave their staging,
        // recovery and commit — one caller receiving shares that do not open the root key
        // that ended up stored. The lease at `INIT_LEASE_PATH` is the cross-process
        // authority: this test uses two *separate* `SealService` instances over one shared
        // backend, each with its own `init_lock`, so only the lease can serialise them.
        //
        // The overlap is forced: instance A is parked inside its first staging write — past
        // the guard, holding the lease — while instance B runs to completion. B must be
        // refused rather than interleaved, must not remove A's artifacts, and A's shares
        // must open the root key that is actually stored.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(SharedCrossProcessBackend::new(INIT_PATH));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();

        // Two independent service graphs over the same records, as two replicas would be.
        let replica_a = Arc::new(sealed_vault_with_storage(storage_dyn.clone()).await);
        let replica_b = Arc::new(sealed_vault_with_storage(storage_dyn.clone()).await);

        let first = {
            let replica_a = replica_a.clone();
            tokio::spawn(async move {
                replica_a
                    .seal
                    .init(3, 2, "winner-root", &replica_a.auth, &replica_a.mfa)
                    .await
            })
        };

        // A is inside its staging write, holding the cross-process lease. B must not win.
        storage.reached.notified().await;
        let loser = replica_b
            .seal
            .init(3, 2, "loser-root", &replica_b.auth, &replica_b.mfa)
            .await;
        assert!(
            loser.is_err(),
            "the second replica must be refused while the first holds the lease, not \
             initialise in parallel"
        );

        // B did not remove what A had already written.
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the loser must not delete the winner's staging marker"
        );

        // Let A finish; it is the single winner.
        storage.resume.notify_one();
        let winner = first
            .await
            .expect("the winner task must not panic")
            .expect("the lease holder must complete its initialization");

        // Exactly one winner: the vault is initialized once, names the winner's account,
        // and carries no staging marker.
        assert!(replica_a.seal.is_initialized().await);
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the winner must not leave a staging marker"
        );
        let identity: RootIdentity = serde_json::from_slice(
            &storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .expect("the winner must have persisted a root identity")
                .encrypted_data,
        )
        .expect("root identity parses");
        assert_eq!(
            identity.username, "winner-root",
            "the stored root identity must be the winner's, not the loser's"
        );

        // The winner's shares open the stored root key: unseal mints a credential naming
        // the account the winner created. This is the property a cross-replica race
        // destroys — shares handed out that do not open the key that ended up stored.
        let complete = {
            let replica_a = replica_a.clone();
            let key = winner.keys[0].clone();
            let key2 = winner.keys[1].clone();
            async move {
                replica_a.seal.unseal(&key).await.expect("share one");
                replica_a
                    .seal
                    .unseal(&key2)
                    .await
                    .expect("the winner's shares must open the stored root key")
            }
        }
        .await;
        let token = complete
            .root_token
            .expect("the winner's vault must issue a bootstrap credential");
        assert_eq!(claims_of(&token)["username"], "winner-root");

        // The lease was released, so a later attempt is not blocked by a stale record.
        assert!(
            storage
                .get_by_path(INIT_LEASE_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a completed initialization must release its lease"
        );
    }

    /// Every durable artifact of an initialization, by path, as a list a test can assert on.
    async fn initialization_artifact_paths(
        storage: &Arc<dyn StorageBackend + Send + Sync>,
        root_username: &str,
    ) -> Vec<String> {
        let mut present = Vec::new();
        for path in [
            INIT_PATH,
            ROOT_KEY_PATH,
            ROOT_IDENTITY_PATH,
            INIT_STAGING_PATH,
            INIT_LEASE_PATH,
        ] {
            if storage.get_by_path(path).await.expect("storage").is_some() {
                present.push(path.to_string());
            }
        }
        let user_path = format!(
            "{}{}",
            crate::services::auth::USER_STORAGE_PREFIX,
            root_username
        );
        if storage
            .get_by_path(&user_path)
            .await
            .expect("storage")
            .is_some()
        {
            present.push(user_path);
        }
        let enrollments = storage
            .list(
                &secreton_storage::QueryParams::new()
                    .with_path_prefix(crate::services::mfa_persistence::TOTP_PREFIX.to_string()),
            )
            .await
            .expect("list");
        present.extend(enrollments.into_iter().map(|e| e.path));
        present
    }

    #[tokio::test]
    async fn a_failed_cross_process_init_removes_every_owned_artifact_and_allows_a_retry() {
        // Regression (severe): on a backend shared between processes, cleanup removes an
        // attempt's artifacts with `delete_owned`, which only deletes a record that carries
        // that attempt's lease token. The root account and its TOTP enrollment were written
        // *without* a token, so a failed initialization's cleanup could not remove them: the
        // read-back saw an unowned record, reported the removal as a failure, and left the
        // staging marker behind. Every retry then ran the same failing cleanup and the vault
        // was permanently uninitialisable — after `init` had already reported an error, so
        // the operator had no reason to expect a stuck vault.
        //
        // The fixed property: a failed attempt's account and enrollment carry the attempt's
        // token and are removed, the marker is removed only once they are gone, and a retry
        // succeeds with exactly one enrollment.
        let _env = crate::test_support::without_root_key();
        // A pause path that is never written: this test needs the cross-process
        // coordination and the ownership token, not the parking behaviour.
        let storage = Arc::new(SharedCrossProcessBackend::new("never/written"));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        let vault = Arc::new(sealed_vault_with_storage(storage_dyn.clone()).await);

        // Fail the commit-time staging write, which is the first one after the enrollment
        // exists — the window where the account and second factor are already stored.
        storage
            .fail_staging_after_totp
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let first = vault
            .seal
            .init(3, 2, "cross-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "the injected staging failure must fail `init`: {:?}",
            first.as_ref().err().map(|e| e.to_string())
        );
        assert!(
            storage
                .staging_fault_fired
                .load(std::sync::atomic::Ordering::SeqCst),
            "the fault must actually have fired, or this test proves nothing"
        );

        // Every artifact the failed attempt created is gone — including the account and the
        // TOTP enrollment, which only the ownership token made removable.
        let leftovers = initialization_artifact_paths(&storage_dyn, "cross-root").await;
        assert!(
            leftovers.is_empty(),
            "a rolled-back cross-process init must leave no artifact behind, found: {leftovers:?}"
        );
        assert!(
            !vault.seal.is_initialized().await,
            "a rolled-back init must not advertise an initialised vault"
        );

        // A retry starts from clean state and succeeds, with exactly one enrollment.
        let second = vault
            .seal
            .init(3, 2, "cross-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry after a fully rolled-back attempt must initialise");

        let enrollments = storage
            .list(
                &secreton_storage::QueryParams::new()
                    .with_path_prefix(crate::services::mfa_persistence::TOTP_PREFIX.to_string()),
            )
            .await
            .expect("list");
        assert_eq!(
            enrollments.len(),
            1,
            "the retry must produce exactly one TOTP enrollment, not one per attempt"
        );

        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "cross-root"
        );
    }

    /// The failure mode the finding names, made deterministic.
    ///
    /// Instance A is parked inside its write of [`ROOT_KEY_PATH`] — staged, past the
    /// `is_initialized` guard, having just passed the `check` that precedes that write — while
    /// its lease is expired and taken over. Instance B then takes the lease, discards A's
    /// partial state and completes an initialization of its own. When A is resumed it must
    /// fail closed: it may not publish a root key, and it may not roll back what is now B's.
    ///
    /// The takeover is *forced*, not raced. When A writes the locked root key this backend
    /// (a) replaces the lease record with one already in the past, so B's acquisition sees a
    /// genuinely expired lease and takes it over legitimately, and (b) refuses A's renewals
    /// from then on, so A's own background task cannot redraw its expiry before B arrives.
    /// No test here sleeps, and none depends on the scheduler interleaving two tasks.
    #[derive(Debug)]
    struct LeaseTakeoverBackend {
        inner: Arc<MemoryBackend>,
        /// Path whose first write parks the holder and triggers the forced expiry.
        pause_on: String,
        reached: tokio::sync::Notify,
        resume: tokio::sync::Notify,
        started: std::sync::atomic::AtomicUsize,
        /// Set once the lease has been forcibly expired and the holder must not renew.
        expiry_forced: std::sync::atomic::AtomicBool,
    }

    impl LeaseTakeoverBackend {
        fn new(pause_on: &str) -> Self {
            Self {
                inner: Arc::new(MemoryBackend::new()),
                pause_on: pause_on.to_string(),
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                started: std::sync::atomic::AtomicUsize::new(0),
                expiry_forced: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// Expire the lease record in place, keeping the same owner token.
        ///
        /// The token is preserved so that nothing but the expiry changes: A's fence would
        /// still match if the write were merely conditional on the token, which is the point
        /// — the guarantee must come from B having replaced the record, and the expiry is what
        /// lets B do that legitimately. It also keeps this helper from standing in for the
        /// takeover itself.
        async fn force_expiry(&self) {
            let current = self
                .inner
                .get_by_path(INIT_LEASE_PATH)
                .await
                .expect("storage")
                .expect("the holder must have a lease record to expire");
            let owner = current
                .owner_token()
                .expect("the lease record carries its owner token")
                .to_string();
            let expired = SecretEntry::new(
                INIT_LEASE_PATH.to_string(),
                serde_json::to_vec(&InitLease {
                    owner: owner.clone(),
                    expires_at: Utc::now().timestamp() - 1,
                })
                .expect("serialise expired lease"),
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            )
            .owned_by(&owner);
            self.inner
                .upsert(&expired)
                .await
                .expect("expire the lease record");
            self.expiry_forced
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for LeaseTakeoverBackend {
        fn coordination(&self) -> secreton_storage::Coordination {
            secreton_storage::Coordination::CrossProcess
        }
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            self.inner.delete_owned(path, token).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: Expect<'_>,
        ) -> StorageResult<bool> {
            // Once the forced expiry is armed, refuse *the holder's own renewal* — an
            // ownership-conditional replace that keeps the same token — so the expiry stays
            // genuinely past for B. A takeover uses a different token, so it is allowed
            // through; blocking that too would prevent B from ever taking over and would make
            // this backend model "expired leases are unusable" instead of "expired leases are
            // takeable", which is not the situation under test.
            if entry.path == INIT_LEASE_PATH
                && matches!(expect, Expect::Owner(_))
                && self.expiry_forced.load(std::sync::atomic::Ordering::SeqCst)
            {
                let existing = self.inner.get_by_path(INIT_LEASE_PATH).await?;
                if existing
                    .as_ref()
                    .is_some_and(|record| record.owner_token() == entry.owner_token())
                {
                    return Ok(false);
                }
            }
            self.inner.compare_and_set(entry, expect).await
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: secreton_storage::StorageFence<'_>,
        ) -> StorageResult<bool> {
            // Park the holder inside its first write of the watched path — for this test the
            // encrypted root key, the artifact the finding names. The park is *before* the
            // fence is evaluated, so the holder is released with its fence already stale.
            if entry.path == self.pause_on
                && self
                    .started
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
            {
                self.force_expiry().await;
                self.reached.notify_one();
                self.resume.notified().await;
            }
            self.inner.store_fenced(entry, fence).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn an_attempt_that_lost_its_lease_cannot_overwrite_the_winner() {
        // Regression (severe, cross-process): the write of the encrypted root key was a plain
        // `store` authorised only by a preceding `lease.check()`. That check reads an
        // in-process flag, so a holder whose lease had expired and been taken over could still
        // write afterwards — and on Redis the write repointed the path mapping, so the winning
        // attempt's returned shares no longer opened the root key the path resolved to. The
        // fix makes the write itself conditional on the lease *in the shared backend*.
        //
        // The sequence is forced, not raced: A parks inside the root-key write having already
        // passed its check; its lease is expired; B legitimately takes over and completes;
        // only then is A resumed. A must fail, and B's state must be untouched.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(LeaseTakeoverBackend::new(ROOT_KEY_PATH));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();

        let replica_a = Arc::new(sealed_vault_with_storage(storage_dyn.clone()).await);
        let replica_b = Arc::new(sealed_vault_with_storage(storage_dyn.clone()).await);

        // A runs until it is parked inside its root-key write.
        let attempt_a = {
            let replica_a = replica_a.clone();
            tokio::spawn(async move {
                replica_a
                    .seal
                    .init(3, 2, "stale-root", &replica_a.auth, &replica_a.mfa)
                    .await
            })
        };
        storage.reached.notified().await;

        // B takes the expired lease over and initialises. Its shares are the ones that must
        // open the final vault — asserted once, after A has resumed, because `unseal` is
        // single-shot and consumes the shares buffer.
        let winner = replica_b
            .seal
            .init(3, 2, "winner-root", &replica_b.auth, &replica_b.mfa)
            .await
            .expect("the second replica must be able to take over an expired lease");

        // Capture B's durable state before A resumes, so the assertions name exactly what
        // must not change.
        let root_key_before = storage
            .get_by_path(ROOT_KEY_PATH)
            .await
            .expect("storage")
            .expect("the winner stored a root key");
        let identity_before = storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage")
            .expect("the winner stored a root identity");

        // Now let A continue. It must fail closed.
        storage.resume.notify_one();
        let lost = attempt_a
            .await
            .expect("the stale attempt task must not panic");
        assert!(
            lost.is_err(),
            "an attempt that lost its lease must not succeed, even though it passed its own \
             check before writing"
        );

        // A changed nothing of B's. This is the whole invariant: a losing attempt must not be
        // able to alter the artifacts of the attempt that took over.
        let root_key_after = storage
            .get_by_path(ROOT_KEY_PATH)
            .await
            .expect("storage")
            .expect("the winner's root key must still be present");
        let identity_after = storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage")
            .expect("the winner's root identity must still be present");
        assert_eq!(
            root_key_after.id, root_key_before.id,
            "a stale attempt must not replace the winner's root key"
        );
        assert_eq!(
            root_key_after.encrypted_data, root_key_before.encrypted_data,
            "a stale attempt must not overwrite the winner's encrypted root key"
        );
        assert_eq!(
            identity_after.encrypted_data, identity_before.encrypted_data,
            "a stale attempt must not overwrite the winner's root identity"
        );

        // The winner's shares still open the final root key. This is the property the finding
        // says is violated, asserted directly rather than inferred from the records.
        replica_b
            .seal
            .unseal(&winner.keys[0])
            .await
            .expect("share one after the stale attempt resumed");
        let complete = replica_b
            .seal
            .unseal(&winner.keys[1])
            .await
            .expect("share two after the stale attempt resumed");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "winner-root",
            "the winner's shares must still open the vault after the stale attempt resumed"
        );

        // No artifact of A's own attempt survived. The paths above are B's: `sys/init`,
        // `sys/root_key_enc` and `sys/root_identity` are single-instance locations that the
        // winner legitimately owns, and the TOTP record belongs to the winner's identity
        // (asserted by the identity comparison above). What must be gone is anything named
        // for A's attempt specifically — its account — and the marker itself.
        assert!(
            storage
                .get_by_path(&format!(
                    "{}{}",
                    crate::services::auth::USER_STORAGE_PREFIX,
                    "stale-root"
                ))
                .await
                .expect("storage")
                .is_none(),
            "the stale attempt's account must not survive the winner's takeover"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the winner must not be left with a staging marker"
        );

        // A's shares cannot become shares for the final state: `init` failed, so it handed
        // back no shares at all. The assertion below is the whole of that property — there is
        // no share value to test against the winner's vault, because the fenced attempt
        // produced none. (A version of this test that read shares out of a failed `init`
        // would be asserting on a value the production type does not expose.)
        assert!(
            lost.as_ref().err().is_some(),
            "an attempt that lost its lease must not return an initialization response"
        );
    }

    #[tokio::test]
    async fn a_renewal_failure_fences_the_attempt_so_it_cannot_commit() {
        // Regression (severe): the lease had a fixed expiry and no renewal, so an attempt
        // that outlived its TTL could keep writing after a second replica legitimately took
        // the lease over — and could return shares that do not open the root key that ended
        // up stored. The fix renews the lease while the attempt runs and fences every write
        // and the commit against it, so an attempt that cannot prove it still holds the lease
        // stops instead of racing.
        //
        // This forces the fence deterministically: renewal is failed via the backend while
        // the attempt is parked mid-sequence. The attempt must fail closed rather than commit
        // under a lease it no longer holds.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(SharedCrossProcessBackend::new(INIT_PATH));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        // A one-second TTL makes the renewal interval one second, so the real renewal task
        // runs during the parked window rather than after the test has finished.
        let vault =
            Arc::new(sealed_vault_with_storage_and_lease_ttl(storage_dyn.clone(), Some(3)).await);

        storage
            .fail_lease_renewal
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let attempt = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "fenced-root", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Parked inside the root-key write, past staging and the init config.
        storage.reached.notified().await;
        // Wait for a renewal to be refused, which sets the fence.
        storage.renewal_failed.notified().await;
        storage.resume.notify_one();

        let outcome = attempt.await.expect("the attempt task must not panic");
        assert!(
            outcome.is_err(),
            "an attempt whose lease renewal failed must fail closed, not commit"
        );

        // Nothing committed, and the vault is not advertised as initialised.
        assert!(
            !vault.seal.is_initialized().await,
            "a fenced attempt must not leave an initialised vault"
        );
        let leftovers = initialization_artifact_paths(&storage_dyn, "fenced-root").await;
        assert!(
            leftovers.is_empty(),
            "a fenced attempt must roll its artifacts back, found: {leftovers:?}"
        );

        // With renewal healthy again, a retry initialises and its shares open the key.
        storage
            .fail_lease_renewal
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let retry = vault
            .seal
            .init(3, 2, "fenced-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry after a fenced attempt must initialise");
        vault.seal.unseal(&retry.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&retry.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "fenced-root"
        );
    }

    #[tokio::test]
    async fn a_renewal_that_finds_the_lease_expired_fails_closed_instead_of_reviving_it() {
        // Regression: renewal was an unconditional owner-conditional replace. If the lease
        // had already lapsed and a renewal landed before any takeover, the expired record
        // was simply overwritten with a fresh deadline — reviving a lease the attempt had
        // already lost the right to hold, and letting an expired attempt keep initializing.
        // The fix fences such a renewal: a lapsed lease cannot be extended.
        //
        // This forces the lapsed state deterministically through the backend's read hook,
        // which reports the lease record with an elapsed deadline while leaving it present.
        // The attempt is parked past staging, so the renewal runs mid-sequence. Without the
        // fence, the owner-conditional replace would succeed against the (still-owned)
        // record and the attempt would commit; with it, the renewal fences and the attempt
        // fails closed.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(SharedCrossProcessBackend::new(INIT_PATH));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        let vault =
            Arc::new(sealed_vault_with_storage_and_lease_ttl(storage_dyn.clone(), Some(3)).await);

        storage
            .expire_lease_on_read
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let attempt = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "lapsed-root", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Parked inside the root-key write, past staging and the init config, holding the
        // lease. Wait for the renewal to read the lease and observe it lapsed. The renewal
        // sets the loss flag synchronously right after that read, so a short settle is
        // enough for the fence to be in place before the attempt is resumed.
        storage.reached.notified().await;
        storage.lease_read.notified().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        storage.resume.notify_one();

        let outcome = attempt.await.expect("the attempt task must not panic");
        assert!(
            outcome.is_err(),
            "a renewal that finds the lease already expired must fence the attempt, not \
             revive the lapsed lease and let it commit"
        );
        assert!(
            !vault.seal.is_initialized().await,
            "a fenced attempt must not leave an initialised vault"
        );

        // The lapsed lease is genuinely gone: with the read hook cleared, a retry takes over
        // and initialises.
        storage
            .expire_lease_on_read
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let retry = vault
            .seal
            .init(3, 2, "lapsed-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry after a lapsed attempt must be able to take over");
        vault.seal.unseal(&retry.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&retry.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "lapsed-root"
        );
    }

    #[tokio::test]
    async fn a_live_attempt_holds_its_lease_past_the_ttl_and_is_not_taken_over() {
        // The counterpart to the fence: renewal must actually extend a live attempt's lease.
        // Without renewal an attempt that runs longer than its TTL has its lease legitimately
        // taken over by a second replica, which is exactly the overlap the lease exists to
        // prevent. This parks an attempt past its TTL and shows a second replica is still
        // refused — falsified by removing the renewal task, after which the second replica
        // takes over the expired lease.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(SharedCrossProcessBackend::new(INIT_PATH));
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();

        let replica_a =
            Arc::new(sealed_vault_with_storage_and_lease_ttl(storage_dyn.clone(), Some(3)).await);
        let replica_b =
            Arc::new(sealed_vault_with_storage_and_lease_ttl(storage_dyn.clone(), Some(3)).await);

        let first = {
            let replica_a = replica_a.clone();
            tokio::spawn(async move {
                replica_a
                    .seal
                    .init(3, 2, "renewed-root", &replica_a.auth, &replica_a.mfa)
                    .await
            })
        };

        storage.reached.notified().await;
        // Hold the attempt past its one-second TTL, several renewal intervals.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let loser = replica_b
            .seal
            .init(3, 2, "usurper-root", &replica_b.auth, &replica_b.mfa)
            .await;
        assert!(
            loser.is_err(),
            "a live attempt that renewed its lease must not be taken over after its original \
             TTL elapses"
        );

        storage.resume.notify_one();
        let winner = first
            .await
            .expect("the winner task must not panic")
            .expect("the renewed attempt must complete");
        replica_a
            .seal
            .unseal(&winner.keys[0])
            .await
            .expect("share one");
        let complete = replica_a
            .seal
            .unseal(&winner.keys[1])
            .await
            .expect("the winner's shares must open the stored root key");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "renewed-root"
        );
    }
}
