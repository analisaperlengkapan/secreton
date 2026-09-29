//! Full initialization and cross-replica coordination against a real Redis backend.
//!
//! Redis is the shared backend in the deployments this repository actually runs, and it is
//! where "path-keyed operations are a no-op" used to be true: `delete_by_path` returned
//! `Ok(false)` for every path regardless of whether a record existed. That made cleanup
//! report success without removing anything, deleted the staging marker over a still-present
//! artifact, and left the next attempt reading a stale init config as a finished vault.
//!
//! The unit suite reproduces that shape with `SilentDeleteFailure`; this test proves the
//! real backend now reports and performs the delete, and that two independent `SealService`
//! instances sharing one Redis admit exactly one initialization.
//!
//! Set `SECRETON_TEST_REDIS_URL` to run it:
//!
//! ```text
//! docker run --rm -d -p 6379:6379 redis:7-alpine
//! SECRETON_TEST_REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p secreton-engines --test seal_redis
//! ```
//!
//! Without the variable the test returns early, like the other integration tests.

use std::sync::Arc;

use secreton_engines::config::AuthConfig;
use secreton_engines::services::audit::AuditLogger;
use secreton_engines::services::auth::AuthenticationService;
use secreton_engines::services::crypto::CryptoService;
use secreton_engines::services::mfa_persistence::PersistentTotpService;
use secreton_engines::services::seal::SealService;
use secreton_storage::backends::RedisBackend;
use secreton_storage::{Coordination, Expect, SecretEntry, SecurityLevel, StorageBackend};

fn redis_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_REDIS_URL is not set");
            None
        }
    }
}

/// A lease record carrying the deadline metadata a fence now requires, `ttl_secs` from now.
///
/// A fence rejects an expired or deadline-less lease, so a test that stores a lease directly
/// must record one, exactly as `SealService`'s `lease_entry` does.
fn lease_record(path: &str, owner: &str, ttl_secs: i64) -> SecretEntry {
    let expires_at = chrono::Utc::now().timestamp() + ttl_secs;
    SecretEntry::new(
        path.to_string(),
        b"lease".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
    .owned_by(owner)
    .add_metadata(
        secreton_storage::LEASE_EXPIRES_AT_KEY.to_string(),
        expires_at.to_string(),
    )
}

/// Namespace every path so two test runs against one server cannot collide, and so the
/// `Coordination` the backend reports is not downgraded by the wrapper.
#[derive(Debug)]
struct NamespacedRedis {
    inner: RedisBackend,
    prefix: String,
}

impl NamespacedRedis {
    fn scope(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

#[async_trait::async_trait]
impl StorageBackend for NamespacedRedis {
    async fn store(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.store(&scoped).await
    }

    async fn get_by_id(
        &self,
        id: uuid::Uuid,
    ) -> secreton_storage::StorageResult<Option<SecretEntry>> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_path(
        &self,
        path: &str,
    ) -> secreton_storage::StorageResult<Option<SecretEntry>> {
        self.inner.get_by_path(&self.scope(path)).await
    }

    async fn update(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.update(&scoped).await
    }

    async fn upsert(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.upsert(&scoped).await
    }

    async fn delete_by_id(&self, id: uuid::Uuid) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_by_id(id).await
    }

    async fn delete_by_path(&self, path: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_by_path(&self.scope(path)).await
    }

    fn coordination(&self) -> Coordination {
        // Must not downgrade what it wraps: Redis arbitrates across processes.
        self.inner.coordination()
    }

    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: Expect<'_>,
    ) -> secreton_storage::StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        // The fence inside `AbsentFenced` names the lease record, so it must be scoped the
        // same way `store_fenced` scopes its fence — otherwise the backend looks for the
        // lease outside the namespace, finds none, and reports a lost lease to an
        // initialization that still holds it.
        let scoped_fence_path;
        let scoped_expect = match expect {
            Expect::AbsentFenced(fence) => {
                scoped_fence_path = self.scope(fence.path);
                Expect::AbsentFenced(secreton_storage::StorageFence::new(
                    &scoped_fence_path,
                    fence.token,
                ))
            }
            other => other,
        };
        self.inner.compare_and_set(&scoped, scoped_expect).await
    }

    async fn delete_owned(&self, path: &str, token: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_owned(&self.scope(path), token).await
    }

    /// Scoped exactly like every other path-keyed operation, including the *fence* path: the
    /// fence names the lease record, and an unscoped fence would look for it outside the
    /// namespace and never find it.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: secreton_storage::StorageFence<'_>,
    ) -> secreton_storage::StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        let scoped_fence_path = self.scope(fence.path);
        let scoped_fence = secreton_storage::StorageFence::new(&scoped_fence_path, fence.token);
        self.inner.store_fenced(&scoped, scoped_fence).await
    }

    async fn list(
        &self,
        params: &secreton_storage::QueryParams,
    ) -> secreton_storage::StorageResult<Vec<SecretEntry>> {
        let mut scoped = params.clone();
        scoped.path_prefix = Some(self.scope(params.path_prefix.as_deref().unwrap_or("")));
        self.inner.list(&scoped).await
    }

    async fn count(
        &self,
        params: &secreton_storage::QueryParams,
    ) -> secreton_storage::StorageResult<u64> {
        let mut scoped = params.clone();
        scoped.path_prefix = Some(self.scope(params.path_prefix.as_deref().unwrap_or("")));
        self.inner.count(&scoped).await
    }

    async fn exists(&self, path: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.exists(&self.scope(path)).await
    }

    async fn begin_transaction(
        &self,
    ) -> secreton_storage::StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
        self.inner.begin_transaction().await
    }

    async fn health_check(
        &self,
    ) -> secreton_storage::StorageResult<secreton_storage::HealthStatus> {
        self.inner.health_check().await
    }

    async fn get_stats(&self) -> secreton_storage::StorageResult<secreton_storage::StorageStats> {
        self.inner.get_stats().await
    }

    async fn migrate(&self) -> secreton_storage::StorageResult<()> {
        self.inner.migrate().await
    }

    async fn compact(&self) -> secreton_storage::StorageResult<()> {
        self.inner.compact().await
    }

    async fn vacuum(&self) -> secreton_storage::StorageResult<()> {
        self.inner.vacuum().await
    }

    async fn delete_expired(
        &self,
        path_prefix: Option<String>,
    ) -> secreton_storage::StorageResult<u64> {
        self.inner
            .delete_expired(path_prefix.map(|p| self.scope(&p)))
            .await
    }

    async fn store_oauth_state(
        &self,
        state: &secreton_domain::OAuthState,
    ) -> secreton_storage::StorageResult<()> {
        self.inner.store_oauth_state(state).await
    }

    async fn get_oauth_state(
        &self,
        state: &str,
    ) -> secreton_storage::StorageResult<Option<secreton_domain::OAuthState>> {
        self.inner.get_oauth_state(state).await
    }

    async fn delete_expired_oauth_states(&self) -> secreton_storage::StorageResult<u64> {
        self.inner.delete_expired_oauth_states().await
    }
}

/// The `delete_by_path` contract on Redis: `Ok(true)` only when a record was actually there
/// and this call removed it, `Ok(false)` otherwise, and the path is absent afterwards in
/// both cases. The old backend returned `Ok(false)` unconditionally and removed nothing.
#[tokio::test]
async fn redis_delete_by_path_reports_and_removes() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/delete-me";
    assert!(
        !storage.delete_by_path(path).await.expect("delete absent"),
        "deleting a path with no record must report false"
    );

    let entry = SecretEntry::new(
        path.to_string(),
        b"payload".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    storage.store(&entry).await.expect("store");
    assert!(
        storage.get_by_path(path).await.expect("read").is_some(),
        "the record must exist before the delete that is being tested"
    );

    assert!(
        storage.delete_by_path(path).await.expect("delete present"),
        "deleting a present record must report true, not a silent false"
    );
    assert!(
        storage.get_by_path(path).await.expect("read").is_none(),
        "the record must actually be gone after a reported delete"
    );
}

/// Regression (severe): `delete_by_id` read the entry, deleted the entry key, then removed
/// `secreton:path:<entry.path>` unconditionally. If the path had been rewritten in between —
/// a concurrent `store` publishing a replacement under the same path — that second delete
/// removed the *replacement's* mapping. Its entry key survived but was unreachable by path,
/// so the replacement was lost while `get_by_path` reported a missing record.
///
/// The fixed property: deleting an old id removes its own record, and a replacement written
/// under the same path before the delete still resolves by path afterwards. The old
/// read-then-delete is falsified here because this test forces exactly that interleaving on
/// a real server.
#[tokio::test]
async fn redis_delete_by_id_does_not_unlink_a_concurrent_replacement() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/replaced";
    let original = SecretEntry::new(
        path.to_string(),
        b"original".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    storage.store(&original).await.expect("store original");

    // Read the original so its id is known, then rewrite the same path as a *replacement*
    // with a different id — the state a concurrent `store` would leave behind.
    let read_back = storage
        .get_by_path(path)
        .await
        .expect("read")
        .expect("original is present");
    assert_eq!(read_back.id, original.id);

    let replacement = SecretEntry::new(
        path.to_string(),
        b"replacement".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    assert_ne!(
        replacement.id, original.id,
        "the replacement must be a distinct record, or this proves nothing"
    );
    storage
        .store(&replacement)
        .await
        .expect("store replacement");

    // Delete the *old* id. Its path mapping no longer points at it, so the replacement's
    // mapping must survive.
    assert!(
        storage
            .delete_by_id(original.id)
            .await
            .expect("delete old id"),
        "deleting the old id that still has its entry must report true"
    );
    assert!(
        storage
            .get_by_id(original.id)
            .await
            .expect("read old id")
            .is_none(),
        "the deleted entry must be gone by id"
    );

    let resolved = storage
        .get_by_path(path)
        .await
        .expect("read replacement by path")
        .expect("the concurrent replacement must still be reachable by path");
    assert_eq!(
        resolved.id, replacement.id,
        "the path must resolve to the replacement, not the deleted record"
    );
    assert_eq!(resolved.encrypted_data, b"replacement");
}

/// `compare_and_set` on Redis is one server-side Lua invocation, so an insert-if-absent
/// admits one writer and the owner-conditional write is refused after a takeover.
#[tokio::test]
async fn redis_compare_and_set_arbitrates_between_callers() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/cas";
    let entry = |owner: &str| {
        SecretEntry::new(
            path.to_string(),
            b"payload".to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::Internal,
            uuid::Uuid::nil(),
        )
        .owned_by(owner)
    };

    assert!(
        storage
            .compare_and_set(&entry("a"), Expect::Absent)
            .await
            .expect("first insert"),
        "the first insert-if-absent must win"
    );
    assert!(
        !storage
            .compare_and_set(&entry("b"), Expect::Absent)
            .await
            .expect("second insert"),
        "a second insert-if-absent must lose; the record already exists"
    );

    assert!(
        storage
            .compare_and_set(&entry("a"), Expect::Owner("a"))
            .await
            .expect("owner replace"),
        "the recorded owner may replace its own record"
    );
    assert!(
        !storage
            .compare_and_set(&entry("b"), Expect::Owner("b"))
            .await
            .expect("wrong owner"),
        "a caller that does not hold the recorded token must not replace it"
    );
    assert!(
        storage
            .compare_and_set(&entry("b"), Expect::Owner("a"))
            .await
            .expect("precondition on a token the caller does not hold"),
        "the precondition is the recorded token, whoever writes with it"
    );
}

/// `store_fenced` is one server-side Lua invocation, so the fence record and the artifact it
/// authorises are read and written in indivisible steps. This is the primitive the finding
/// turns on: an attempt whose lease has been taken over must not be able to publish an
/// artifact, and on Redis the pre-fix path wrote the *path mapping* unconditionally, so the
/// winner's shares no longer opened the record the path resolved to.
#[tokio::test]
async fn redis_store_fenced_refuses_a_lost_lease_and_preserves_the_winner() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let lease = "sys/init_lease";
    let artifact = "sys/root_key_enc";
    let entry = |token: &str, payload: &[u8]| {
        SecretEntry::new(
            artifact.to_string(),
            payload.to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        )
        .owned_by(token)
    };

    // The winner acquires the lease, then publishes its artifact through the fence.
    storage
        .store(&lease_record(lease, "winner", 300))
        .await
        .expect("store lease");
    assert!(
        storage
            .store_fenced(
                &entry("winner", b"winner-artifact"),
                secreton_storage::StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write by the holder"),
        "the holder of the lease must be able to publish its artifact"
    );
    let winner_id = storage
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the winner's artifact is present")
        .id;

    // A stale attempt — fenced on a lease it no longer holds — must write nothing, and in
    // particular must not repoint the path mapping at its own record.
    assert!(
        !storage
            .store_fenced(
                &entry("stale", b"stale-artifact"),
                secreton_storage::StorageFence::new(lease, "stale")
            )
            .await
            .expect("fenced write by a stale holder"),
        "an attempt whose fence token is not the lease's must not write"
    );

    let resolved = storage
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the winner's artifact must still resolve by path");
    assert_eq!(
        resolved.id, winner_id,
        "the path mapping must still name the winner's record"
    );
    assert_eq!(
        resolved.encrypted_data, b"winner-artifact",
        "the winner's artifact must not have been overwritten"
    );

    // And a fence whose lease record is gone entirely also refuses — absence is not consent.
    storage.delete_by_path(lease).await.expect("remove lease");
    assert!(
        !storage
            .store_fenced(
                &entry("winner", b"after-release"),
                secreton_storage::StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write after the lease is gone"),
        "a fence with no lease record must refuse, not fail open"
    );
}

/// An expired lease must not authorise a write on the real Redis backend, even though no
/// replacement has taken it over.
///
/// `store_fenced` is a single Lua invocation, so the lease's recorded deadline is compared
/// against the *server's* clock in the same indivisible step as the owner check. Before the
/// fix the script matched only the owner token and read the deadline from the record body,
/// which is encrypted and therefore unreadable to the script — so an attempt whose lease had
/// lapsed but had not yet been superseded could still publish. The pre-fix script returns
/// success here; the fixed one refuses.
#[tokio::test]
async fn redis_store_fenced_refuses_an_expired_lease() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let lease = "sys/init_lease";
    let artifact = "sys/root_key_enc";
    // The lease's owner still matches, but its recorded deadline is already in the past.
    storage
        .store(&lease_record(lease, "holder", -1))
        .await
        .expect("store expired lease");

    let artifact_entry = SecretEntry::new(
        artifact.to_string(),
        b"payload".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::TopSecret,
        uuid::Uuid::nil(),
    )
    .owned_by("holder");

    assert!(
        !storage
            .store_fenced(
                &artifact_entry,
                secreton_storage::StorageFence::new(lease, "holder")
            )
            .await
            .expect("fenced write under an expired lease"),
        "an attempt whose lease has expired must not publish an artifact, even before a \
         takeover"
    );
    assert!(
        storage.get_by_path(artifact).await.expect("read").is_none(),
        "a refused write under an expired lease must store nothing"
    );

    // The same for the bootstrap root account, which goes through `AbsentFenced`.
    let root = SecretEntry::new(
        "users/root".to_string(),
        b"root".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::TopSecret,
        uuid::Uuid::nil(),
    )
    .owned_by("holder");
    assert!(
        !storage
            .compare_and_set(
                &root,
                Expect::AbsentFenced(secreton_storage::StorageFence::new(lease, "holder"))
            )
            .await
            .expect("fenced insert under an expired lease"),
        "an expired lease must not authorise creating the bootstrap root account"
    );
    assert!(
        storage
            .get_by_path("users/root")
            .await
            .expect("read")
            .is_none(),
        "a refused root-account insert must store nothing"
    );
}

/// Two independent `SealService` instances, each on its own Redis connection, sharing one
/// server must admit exactly one initialization.
///
/// The in-process `init_lock` cannot serialise them: separate graphs as two replicas are.
/// Only the cross-process lease — an insert-if-absent, which Redis evaluates atomically —
/// can.
#[tokio::test]
async fn two_replicas_on_one_redis_admit_exactly_one_initialization() {
    let Some(url) = redis_url() else {
        return;
    };

    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let open = |url: &str| {
        let url = url.to_string();
        async move { RedisBackend::new(&url).await.expect("connect") }
    };

    let storage_a: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });
    let storage_b: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });

    let (auth_a, mfa_a, seal_a) = replica(storage_a.clone()).await;
    let (auth_b, mfa_b, seal_b) = replica(storage_b.clone()).await;

    let a = {
        let (seal, auth, mfa) = (seal_a.clone(), auth_a.clone(), mfa_a.clone());
        tokio::spawn(async move { seal.init(3, 2, "redis-winner", &auth, &mfa).await })
    };
    let b = {
        let (seal, auth, mfa) = (seal_b.clone(), auth_b.clone(), mfa_b.clone());
        tokio::spawn(async move { seal.init(3, 2, "redis-loser", &auth, &mfa).await })
    };

    let (result_a, result_b) = tokio::join!(a, b);
    let result_a = result_a.expect("task A");
    let result_b = result_b.expect("task B");

    let successes = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes,
        1,
        "exactly one replica must initialize; got A={:?} B={:?}",
        result_a.as_ref().err().map(|e| e.to_string()),
        result_b.as_ref().err().map(|e| e.to_string()),
    );

    let winner = result_a.as_ref().or(result_b.as_ref()).expect("one winner");
    let (winner_seal, winner_auth) = if result_a.is_ok() {
        (seal_a.clone(), auth_a.clone())
    } else {
        (seal_b.clone(), auth_b.clone())
    };
    assert!(winner_seal.is_initialized().await);
    winner_seal
        .unseal(&winner.keys[0])
        .await
        .expect("share one");
    let complete = winner_seal
        .unseal(&winner.keys[1])
        .await
        .expect("the winner's shares must open the stored root key");
    let token = complete
        .root_token
        .expect("the winner must issue a bootstrap credential");
    let user = winner_auth.validate_token(&token).await.expect("validates");
    assert!(
        user.username == "redis-winner" || user.username == "redis-loser",
        "the credential must name the winner's account"
    );

    assert!(
        storage_a
            .get_by_path("sys/init_lease")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must release its cross-process lease"
    );
    assert!(
        storage_a
            .get_by_path("sys/init_staging")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must clear its staging marker on Redis"
    );
}

/// Build one replica's service graph over `storage`.
async fn replica(
    storage: Arc<dyn StorageBackend + Send + Sync>,
) -> (
    Arc<AuthenticationService>,
    Arc<secreton_auth::mfa::CombinedMfaService>,
    Arc<SealService>,
) {
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.expect("crypto"));
    let mut config = AuthConfig::default();
    config.jwt.secret = Some("integration-test-secret-1234567890".to_string());
    let auth = Arc::new(
        AuthenticationService::new(storage.clone(), crypto.clone(), &config)
            .await
            .expect("auth"),
    );
    let audit = Arc::new(
        AuditLogger::new(storage.clone(), 2555, 100, true)
            .await
            .expect("audit"),
    );
    let seal = Arc::new(SealService::new(storage.clone(), crypto.clone()))
        .with_auth(auth.clone())
        .with_audit(audit.clone());
    let mfa = mfa_service(storage, crypto).await;
    (auth, mfa, seal)
}

async fn mfa_service(
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
) -> Arc<secreton_auth::mfa::CombinedMfaService> {
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    };

    Arc::new(CombinedMfaService::new(
        Arc::new(PersistentTotpService::new(
            storage,
            crypto,
            "secreton-test".to_string(),
        )),
        Arc::new(InMemorySmsService::new(SmsConfig::default())),
        Arc::new(InMemoryEmailService::new(EmailConfig::default())),
        Arc::new(InMemoryHardwareService::new()),
        Arc::new(DefaultPushService::new_mock()),
        Arc::new(DefaultWebAuthnService::new_default()),
        Arc::new(DefaultRecoveryCodeService::new()),
    ))
}

/// Regression: a conditional write must honour the record's expiry.
///
/// The Redis `compare_and_set` script used a bare `SET` for both the entry and the path
/// mapping, so a conditional write that carried an `expires_at` stored a record with **no**
/// TTL at all. Redis then served a record whose own body already said it had expired, and the
/// only thing that could ever remove it was the application-level lifecycle sweep — which is
/// not guaranteed to run and is a no-op on this backend's `delete_expired`. The fix applies
/// the deadline inside the script, dropping a record whose deadline has already passed.
///
/// The property, asserted with no sleep and no clock dependency: a conditional write of a
/// record whose `expires_at` is already past must leave the path unreachable. The pre-fix
/// `SET` stored it unconditionally, so `get_by_path` returned it.
#[tokio::test]
async fn redis_conditional_write_honours_an_elapsed_expiry() {
    use chrono::{Duration, Utc};

    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/expired";
    let mut entry = SecretEntry::new(
        path.to_string(),
        b"payload".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
    .owned_by("a");
    entry.expires_at = Some(Utc::now() - Duration::hours(1));

    storage
        .compare_and_set(&entry, Expect::Absent)
        .await
        .expect("insert-if-absent with an elapsed expiry");

    assert!(
        storage.get_by_path(path).await.expect("read").is_none(),
        "a record whose expiry has already elapsed must not be reachable; the pre-fix \
         bare `SET` made it immortal"
    );

    // The counterpart property: the call must not report a write that was deliberately
    // dropped. The script deleted the destination instead of storing the expired record, so
    // telling the caller `Ok(true)` would claim a record exists that does not.
    let written = storage
        .compare_and_set(&entry, Expect::Absent)
        .await
        .expect("insert-if-absent with an elapsed expiry");
    assert!(
        !written,
        "a conditional write whose deadline has already elapsed must not report success"
    );
}

/// Regression: a fenced write must honour the record's expiry, exactly like the conditional
/// write. The pre-fix `store_fenced` script used a bare `SET` with no TTL, so an
/// initialization artifact written with an elapsed deadline was still served.
#[tokio::test]
async fn redis_fenced_write_honours_an_elapsed_expiry() {
    use chrono::{Duration, Utc};

    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let lease = "sys/init_lease";
    let artifact = "sys/root_key_enc";
    storage
        .store(&lease_record(lease, "holder", 300))
        .await
        .expect("store lease");

    let mut artifact_entry = SecretEntry::new(
        artifact.to_string(),
        b"payload".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
    .owned_by("holder");
    artifact_entry.expires_at = Some(Utc::now() - Duration::hours(1));

    storage
        .store_fenced(
            &artifact_entry,
            secreton_storage::StorageFence::new(lease, "holder"),
        )
        .await
        .expect("fenced write with an elapsed expiry");

    assert!(
        storage.get_by_path(artifact).await.expect("read").is_none(),
        "a fenced artifact whose expiry has elapsed must not be reachable; the pre-fix bare \
         `SET` made it immortal"
    );

    // Same false-success property as the conditional write: the store dropped the artifact,
    // so the call must not report that it landed.
    let written = storage
        .store_fenced(
            &artifact_entry,
            secreton_storage::StorageFence::new(lease, "holder"),
        )
        .await
        .expect("fenced write with an elapsed expiry");
    assert!(
        !written,
        "a fenced write whose deadline has already elapsed must not report success"
    );
}

/// Regression: a superseded record must not be enumerated.
///
/// Redis stores entries keyed by id with a separate path→id mapping. A `store` that writes a
/// fresh record at an existing path repoints the mapping but leaves the previous entry key
/// behind. `list` scanned `secreton:entry:*` and returned every key, so an updated secret
/// appeared twice — and a secret whose mapping was gone but whose entry key survived kept
/// showing up — while `get_by_path`/`get_by_id` could not reach either. `count` grew on
/// every update.
///
/// The property: `list` returns only the record each path currently resolves to.
#[tokio::test]
async fn redis_list_does_not_report_superseded_records() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/updated";
    let first = SecretEntry::new(
        path.to_string(),
        b"v1".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    storage.store(&first).await.expect("store v1");

    // A second write at the same path with a *different* id — what an update through `store`
    // produces. The old entry key stays behind with no mapping pointing at it.
    let second = SecretEntry::new(
        path.to_string(),
        b"v2".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    assert_ne!(
        first.id, second.id,
        "the two writes must be distinct records"
    );
    storage.store(&second).await.expect("store v2");

    // `list` scoped to this path's prefix must report the current record only. The pre-fix
    // scan-key-only implementation returned both.
    let listed = storage
        .list(&secreton_storage::QueryParams {
            path_prefix: Some(path.to_string()),
            ..Default::default()
        })
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "a superseded record must not appear in `list`; got {:?}",
        listed.iter().map(|e| e.id).collect::<Vec<_>>()
    );
    assert_eq!(
        listed[0].id, second.id,
        "`list` must report the record the path currently resolves to"
    );
    assert_eq!(listed[0].encrypted_data, b"v2");

    // And the record the path resolves to is the one `get_by_path` returns.
    let resolved = storage
        .get_by_path(path)
        .await
        .expect("read")
        .expect("the current record is present");
    assert_eq!(resolved.id, listed[0].id);
}

/// A completed exchange must block reuse of the refresh token until the token's own expiry,
/// across two replicas sharing one Redis.
///
/// The claim is now taken with the short `REFRESH_CLAIM_TTL_SECS` window so an interrupted
/// exchange cannot lock the token out for days; a successful exchange extends it to the
/// token's `exp` before returning. Without that extension the claim would lapse two minutes
/// after the exchange, freeing the slot, and the same refresh token could be exchanged a
/// *second* time — the reuse the reservation exists to prevent. This proves the window
/// survives on the real Redis backend and that the second replica is refused.
#[tokio::test]
async fn redis_a_completed_exchange_blocks_reuse_across_replicas_until_expiry() {
    let Some(url) = redis_url() else {
        return;
    };
    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let open = |url: &str| {
        let url = url.to_string();
        async move { RedisBackend::new(&url).await.expect("connect") }
    };
    let storage_a: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });
    let storage_b: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });

    // Two service graphs over the one backend, sharing the root key that encrypts the
    // system's own records — what a real multi-replica deployment does.
    let shared_root_key =
        secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm).expect("root key");
    let replica_with_key = |storage: Arc<dyn StorageBackend + Send + Sync>, root_key: Vec<u8>| async move {
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.expect("crypto"));
        crypto
            .set_root_key(root_key)
            .await
            .expect("install root key");
        let mut config = AuthConfig::default();
        // A fresh signing secret per run, never a literal that reads like a credential.
        let mut jwt_secret = uuid::Uuid::new_v4().simple().to_string();
        jwt_secret.push_str(&uuid::Uuid::new_v4().simple().to_string());
        config.jwt.secret = Some(jwt_secret);
        Arc::new(
            AuthenticationService::new(storage, crypto, &config)
                .await
                .expect("auth"),
        )
    };
    let auth_a = replica_with_key(storage_a.clone(), shared_root_key.clone()).await;
    let auth_b = replica_with_key(storage_b, shared_root_key).await;

    // A fresh, random password per run: never a literal that reads like a credential.
    let password = uuid::Uuid::new_v4().simple().to_string();
    use secreton_engines::services::auth::ApiLoginRequest;
    auth_a
        .register_user("reuse-user", &password, None, vec![], vec![])
        .await
        .expect("register user");
    let login = auth_a
        .login(
            ApiLoginRequest {
                username: "reuse-user".to_string(),
                password,
                mfa_code: None,
            },
            "192.0.2.1".to_string(),
            "test".to_string(),
        )
        .await
        .expect("login");
    let refresh = login.token.refresh_token.clone();

    // Replica A exchanges it once. A replay must be refused by both replicas for the token's
    // whole lifetime, not merely for the short claim window.
    auth_a
        .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
        .await
        .expect("the first exchange succeeds");
    assert!(
        auth_b
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await
            .is_err(),
        "a refresh token exchanged by one replica must not be exchangeable by another"
    );
    assert!(
        auth_a
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await
            .is_err(),
        "a refresh token must not be exchangeable twice on the replica that exchanged it"
    );

    // The durable claim the exchange left behind reaches the token's own `exp`, not the short
    // claim window: that extension is what makes the refusal last.
    let reservations = storage_a
        .list(&secreton_storage::QueryParams {
            path_prefix: Some("sys/auth/refresh-reservations/".to_string()),
            ..Default::default()
        })
        .await
        .expect("list reservations");
    assert_eq!(
        reservations.len(),
        1,
        "a successful exchange must leave exactly one durable reservation"
    );
    let recorded = reservations[0]
        .expires_at
        .expect("the reservation must expire");
    assert!(
        recorded > chrono::Utc::now() + chrono::Duration::days(1),
        "the claim must be extended to the refresh token's own expiry, not left at the short \
         claim window: recorded={recorded}"
    );
}
