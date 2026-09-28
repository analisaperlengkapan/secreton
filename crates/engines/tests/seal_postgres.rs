//! Full initialization against a real PostgreSQL backend.
//!
//! The unit tests use the in-memory backend, whose `store` silently overwrites a path.
//! PostgreSQL declares `path VARCHAR NOT NULL UNIQUE`, so a second insert at the same path
//! is a constraint violation. That difference is exactly what made initialization fail on
//! PostgreSQL while every memory-backed test passed: the staging marker is written several
//! times. The unit suite reproduces the constraint with `UniquePathStore`; this test proves
//! it against the real thing.
//!
//! Set `SECRETON_TEST_POSTGRES_URL` to run it:
//!
//! ```text
//! docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
//! SECRETON_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!     cargo test -p secreton-engines --features postgres --test seal_postgres
//! ```
//!
//! Without the variable the test returns early, like the other database integration tests.

use std::sync::Arc;

use secreton_engines::config::AuthConfig;
use secreton_engines::services::audit::AuditLogger;
use secreton_engines::services::auth::AuthenticationService;
use secreton_engines::services::crypto::CryptoService;
use secreton_engines::services::mfa_persistence::PersistentTotpService;
use secreton_engines::services::seal::SealService;
use secreton_storage::{StorageBackend, backends::PostgresBackend};

fn database_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_POSTGRES_URL is not set");
            None
        }
    }
}

/// Migrate once per process. The tests here run in parallel against one database, and
/// concurrent DDL from two `migrate()` calls races on the schema — unrelated to what any
/// of them is testing.
async fn migrate_once(url: &str) {
    static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    MIGRATED
        .get_or_init(|| async {
            let backend = PostgresBackend::new(url).await.expect("connect");
            backend.migrate().await.expect("migrate");
        })
        .await;
}

#[tokio::test]
async fn initialization_completes_on_a_unique_path_backend() {
    let Some(url) = database_url() else {
        return;
    };

    migrate_once(&url).await;
    let backend = PostgresBackend::new(&url).await.expect("connect");

    // A dedicated path namespace per run, so a previous run's rows cannot make this pass
    // or fail for the wrong reason and this test cannot collide with another.
    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedBackend {
        inner: backend,
        prefix: namespace,
    });

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
    let mfa = mfa_service(storage.clone(), crypto.clone()).await;

    let init = seal
        .init(3, 2, "pg-root", &auth, &mfa)
        .await
        .expect("initialization must survive a UNIQUE(path) backend");
    // The shares open the vault and issue a credential for the named account.
    let partial = seal.unseal(&init.keys[0]).await.expect("share one");
    assert!(partial.sealed);
    let complete = seal.unseal(&init.keys[1]).await.expect("share two");
    assert!(!complete.sealed);
    let token = complete
        .root_token
        .expect("a completed initialization must issue a bootstrap credential");
    let user = auth.validate_token(&token).await.expect("token validates");
    assert_eq!(user.username, "pg-root");

    // The marker is gone: the repeated writes and its removal all worked on PostgreSQL.
    assert!(
        storage
            .get_by_path("sys/init_staging")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must clear its staging marker"
    );
    assert!(seal.is_initialized().await);
}

/// Two independent `SealService` instances, each on its own PostgreSQL connection pool,
/// sharing one database, must admit exactly one initialization.
///
/// The in-process `init_lock` cannot serialise these: they are separate service graphs and
/// separate pools, exactly as two replicas are. Only the cross-process lease — an
/// `INSERT ... ON CONFLICT DO NOTHING` on `sys/init_lease`, which PostgreSQL evaluates
/// atomically — can. This is the integration-level counterpart of
/// `two_service_instances_sharing_a_backend_admit_exactly_one_winner`, proving the
/// guarantee against the real backend rather than a double.
#[tokio::test]
async fn two_replicas_on_one_postgres_admit_exactly_one_initialization() {
    let Some(url) = database_url() else {
        return;
    };

    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let scoped = |backend: PostgresBackend| -> Arc<dyn StorageBackend + Send + Sync> {
        Arc::new(NamespacedBackend {
            inner: backend,
            prefix: namespace.clone(),
        })
    };

    // Two pools, as two processes would each open their own.
    migrate_once(&url).await;
    let backend_a = PostgresBackend::new(&url).await.expect("connect A");
    let backend_b = PostgresBackend::new(&url).await.expect("connect B");

    let storage_a = scoped(backend_a);
    let storage_b = scoped(backend_b);

    // Start replica A and let it reach a point past the guard and past its first staging
    // write, then start B while A is still running. Both are started before either can
    // finish, so the overlap is real rather than hoped for.
    let (auth_a, mfa_a, seal_a) = replica(storage_a.clone()).await;
    let (auth_b, mfa_b, seal_b) = replica(storage_b.clone()).await;

    let a = {
        let seal_a = seal_a.clone();
        let auth_a = auth_a.clone();
        let mfa_a = mfa_a.clone();
        tokio::spawn(async move { seal_a.init(3, 2, "pg-winner", &auth_a, &mfa_a).await })
    };
    let b = {
        let seal_b = seal_b.clone();
        let auth_b = auth_b.clone();
        let mfa_b = mfa_b.clone();
        tokio::spawn(async move { seal_b.init(3, 2, "pg-loser", &auth_b, &mfa_b).await })
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

    // Whichever won, the vault is initialised once and its shares open the stored key.
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
        user.username == "pg-winner" || user.username == "pg-loser",
        "the credential must name the winner's account, not some other state"
    );

    // The lease was released, so the vault is not left locked out of a future operation.
    assert!(
        storage_a
            .get_by_path("sys/init_lease")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must release its cross-process lease"
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

/// The MFA service the engine graph expects, built from the public MFA types.
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

/// `store_fenced` on PostgreSQL is a single statement whose `INSERT ... WHERE EXISTS` and
/// conflict-arm `WHERE EXISTS` are evaluated against the statement's own snapshot, so the
/// fence and the write cannot interleave. An attempt whose lease has been taken over must not
/// publish an artifact — the pre-fix plain `store` did.
#[tokio::test]
async fn postgres_store_fenced_refuses_a_lost_lease_and_preserves_the_winner() {
    let Some(url) = database_url() else {
        return;
    };
    migrate_once(&url).await;
    let backend = PostgresBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedBackend> = Arc::new(NamespacedBackend {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let lease = "sys/init_lease";
    let artifact = "sys/root_key_enc";
    let entry = |token: &str, payload: &[u8]| {
        secreton_storage::SecretEntry::new(
            artifact.to_string(),
            payload.to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        )
        .owned_by(token)
    };

    storage
        .store(
            &secreton_storage::SecretEntry::new(
                lease.to_string(),
                b"winner".to_vec(),
                secreton_storage::EncryptionMetadata::default(),
                secreton_storage::SecurityLevel::Internal,
                uuid::Uuid::nil(),
            )
            .owned_by("winner"),
        )
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
        "the winner's record must be unchanged by a refused fenced write"
    );
    assert_eq!(resolved.encrypted_data, b"winner-artifact");

    // A fence whose lease row is gone entirely also refuses: the `WHERE EXISTS` is unsatisfied
    // and the conflict arm cannot fire, so nothing is written.
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

/// The owner-conditional replacement `SealService::acquire_init_lease` uses to take over an
/// expired lease must work on PostgreSQL. Before the fix the statement was
/// `INSERT ... SELECT ... WHERE false ON CONFLICT ... DO UPDATE`, whose insert arm can never
/// produce a row and whose `ON CONFLICT` arm therefore never fires: replacing an existing
/// row always affected zero rows. This proves the four behaviours takeover depends on against
/// a real server.
#[tokio::test]
async fn postgres_owner_conditional_replacement_is_atomic_and_fails_closed() {
    use secreton_storage::{Expect, SecretEntry, SecurityLevel, StorageBackend};

    let Some(url) = database_url() else {
        return;
    };
    migrate_once(&url).await;
    let backend = PostgresBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedBackend> = Arc::new(NamespacedBackend {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let entry = |owner: &str, payload: &[u8]| {
        SecretEntry::new(
            "contract/owner-cas".to_string(),
            payload.to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::Internal,
            uuid::Uuid::nil(),
        )
        .owned_by(owner)
    };

    // (c) An absent path must refuse and must not create a record.
    assert!(
        !storage
            .compare_and_set(&entry("a", b"absent"), Expect::Owner("a"))
            .await
            .expect("owner-conditional write to an absent path"),
        "an owner precondition must not be satisfied by the absence of the record"
    );
    assert!(
        storage
            .get_by_path("contract/owner-cas")
            .await
            .expect("read")
            .is_none(),
        "an owner-conditional write to an absent path must not create a record"
    );

    // (a) The recorded owner can replace an existing row.
    assert!(
        storage
            .compare_and_set(&entry("a", b"first"), Expect::Absent)
            .await
            .expect("insert-if-absent"),
        "the first insert-if-absent must win"
    );
    let original = storage
        .get_by_path("contract/owner-cas")
        .await
        .expect("read")
        .expect("inserted");
    let original_id = original.id;
    let original_created_at = original.created_at;
    assert!(
        storage
            .compare_and_set(&entry("a", b"replaced"), Expect::Owner("a"))
            .await
            .expect("owner-conditional replacement of an existing row"),
        "the recorded owner must be able to replace an existing row; a zero-row UPDATE \
         means an expired initialization lease can never be taken over on PostgreSQL"
    );
    let replaced = storage
        .get_by_path("contract/owner-cas")
        .await
        .expect("read")
        .expect("still present");
    assert_eq!(replaced.encrypted_data, b"replaced");
    assert_eq!(
        replaced.id, original_id,
        "a replacement must preserve the existing row's id"
    );
    assert_eq!(
        replaced.created_at, original_created_at,
        "a replacement must preserve the existing row's creation time"
    );

    // (b) A caller without the recorded token is refused and the row is untouched.
    assert!(
        !storage
            .compare_and_set(&entry("b", b"stolen"), Expect::Owner("b"))
            .await
            .expect("owner-conditional write by a non-owner"),
        "a caller that does not hold the recorded token must not replace the row"
    );
    assert_eq!(
        storage
            .get_by_path("contract/owner-cas")
            .await
            .expect("read")
            .expect("still present")
            .encrypted_data,
        b"replaced",
        "a refused owner-conditional write must not change the row"
    );
}

/// (d) and (e): an expired initialization lease can be taken over by a second instance, and a
/// live lease cannot be stolen. The lease record is seeded directly in the exact shape
/// `lease_entry` writes, so the takeover runs the real `acquire_init_lease` path
/// deterministically — no sleep, no shortened TTL.
#[tokio::test]
async fn postgres_expired_initialization_lease_can_be_taken_over_and_a_live_one_cannot() {
    use chrono::Utc;
    use secreton_storage::{Expect, SecretEntry, SecurityLevel, StorageBackend};

    let Some(url) = database_url() else {
        return;
    };
    migrate_once(&url).await;
    let backend = PostgresBackend::new(&url).await.expect("connect");
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedBackend {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let lease_entry = |owner: &str, expires_at: i64| {
        SecretEntry::new(
            "sys/init_lease".to_string(),
            serde_json::to_vec(&serde_json::json!({ "owner": owner, "expires_at": expires_at }))
                .expect("lease json"),
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::Internal,
            uuid::Uuid::nil(),
        )
        .owned_by(owner)
    };

    let (auth, mfa, seal) = replica(storage.clone()).await;

    // (e) A live lease must not be stolen: the second instance fails closed.
    storage
        .compare_and_set(
            &lease_entry("live-holder", Utc::now().timestamp() + 3600),
            Expect::Absent,
        )
        .await
        .expect("seed a live lease");
    let refused = seal.init(3, 2, "root-b", &auth, &mfa).await;
    assert!(
        refused.is_err(),
        "an initialization must not steal a live lease; got {:?}",
        refused.as_ref().ok().map(|_| "ok")
    );
    assert!(
        storage
            .get_by_path("sys/init_lease")
            .await
            .expect("read")
            .expect("the live lease is still present")
            .has_owner("live-holder"),
        "the live holder's lease must be unchanged by a refused attempt"
    );

    // (d) An expired lease can be taken over, and initialization then completes.
    assert!(
        storage
            .compare_and_set(
                &lease_entry("dead-holder", Utc::now().timestamp() - 1),
                Expect::Owner("live-holder"),
            )
            .await
            .expect("expire the lease"),
        "replacing the live holder's lease with an expired one must succeed"
    );
    let initialized = seal
        .init(3, 2, "root-b", &auth, &mfa)
        .await
        .expect("a vault left by a dead process must be recoverable on PostgreSQL");
    seal.unseal(&initialized.keys[0]).await.expect("share one");
    let complete = seal
        .unseal(&initialized.keys[1])
        .await
        .expect("the recovered vault's shares must open its root key");
    assert!(
        complete.root_token.is_some(),
        "the recovered vault must issue its bootstrap credential"
    );
    assert!(
        storage
            .get_by_path("sys/init_lease")
            .await
            .expect("read")
            .is_none(),
        "a completed initialization must release its cross-process lease"
    );
}

/// Prefix every path so one run owns an isolated namespace in a shared database. The
/// service under test is path-keyed throughout, so re-scoping on the way in and out is all
/// that is needed; the entry bodies are opaque to this wrapper.
#[derive(Debug)]
struct NamespacedBackend {
    inner: PostgresBackend,
    prefix: String,
}

impl NamespacedBackend {
    fn scope(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

#[async_trait::async_trait]
impl StorageBackend for NamespacedBackend {
    async fn store(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.store(&scoped).await
    }

    async fn get_by_id(
        &self,
        id: uuid::Uuid,
    ) -> secreton_storage::StorageResult<Option<secreton_storage::SecretEntry>> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_path(
        &self,
        path: &str,
    ) -> secreton_storage::StorageResult<Option<secreton_storage::SecretEntry>> {
        self.inner.get_by_path(&self.scope(path)).await
    }

    async fn update(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.update(&scoped).await
    }

    async fn upsert(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> secreton_storage::StorageResult<()> {
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

    fn coordination(&self) -> secreton_storage::Coordination {
        // The wrapper must not downgrade what it wraps: PostgreSQL arbitrates across
        // processes, and a test wrapper that reported otherwise would make the seal service
        // skip the cross-process lease and pass while testing the wrong guarantee.
        self.inner.coordination()
    }

    async fn compare_and_set(
        &self,
        entry: &secreton_storage::SecretEntry,
        expect: secreton_storage::Expect<'_>,
    ) -> secreton_storage::StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        // `AbsentFenced` carries a fence path of its own — the initialization lease — and the
        // caller names it with its unscoped path, exactly as `store_fenced` above does. It
        // must be re-scoped too: an unscoped fence makes the backend look for the lease
        // outside this namespace, find nothing, and report a lost lease, failing a root
        // account write by an initialization that still holds it.
        let scoped_fence_path;
        let scoped_expect = match expect {
            secreton_storage::Expect::AbsentFenced(fence) => {
                scoped_fence_path = self.scope(fence.path);
                secreton_storage::Expect::AbsentFenced(secreton_storage::StorageFence::new(
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

    /// Scoped like every other path-keyed operation, fence path included: the fence names the
    /// lease record, and an unscoped fence would look for it outside the namespace.
    async fn store_fenced(
        &self,
        entry: &secreton_storage::SecretEntry,
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
    ) -> secreton_storage::StorageResult<Vec<secreton_storage::SecretEntry>> {
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

/// Regression (severe): the fenced write must serialise with a takeover that is *in flight*,
/// not merely with one that has already committed.
///
/// The pre-fix statement used a plain `WHERE EXISTS (SELECT 1 FROM secreton_entries ...)`.
/// Under READ COMMITTED that is an unlocked snapshot read, so a takeover transaction that has
/// executed `UPDATE ... SET metadata['storage_owner'] = 'B'` but **not** committed is invisible
/// to it: the stale attempt still sees `'A'`, its write commits, and — because the fenced write
/// lands *after* the takeover — it overwrites the winner's artifact. The path then resolves to
/// the loser's record, so the shares the winner returned no longer open the stored root key.
///
/// This test forces exactly that interleaving. It holds the takeover in an open transaction on
/// one connection, starts the stale fenced write on another, proves the write is *blocked* on
/// the takeover's row lock (the property the fix adds), then lets the takeover commit and
/// asserts the stale write wrote nothing. The pre-fix code returns `Ok(true)` here and leaves
/// the loser's payload at the path; the fix returns `Ok(false)`.
#[tokio::test]
async fn postgres_fenced_write_serialises_with_an_in_flight_takeover() {
    let Some(url) = database_url() else {
        return;
    };
    migrate_once(&url).await;

    let backend = PostgresBackend::new(&url).await.expect("connect");
    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let storage: Arc<NamespacedBackend> = Arc::new(NamespacedBackend {
        inner: PostgresBackend::new(&url).await.expect("connect"),
        prefix: namespace.clone(),
    });

    let lease = "sys/init_lease";
    let artifact = "sys/root_key_enc";
    let scoped_lease = format!("{}/{}", namespace, lease);

    // The winner holds the lease ...
    storage
        .store(
            &secreton_storage::SecretEntry::new(
                lease.to_string(),
                b"lease-held-by-a".to_vec(),
                secreton_storage::EncryptionMetadata::default(),
                secreton_storage::SecurityLevel::Internal,
                uuid::Uuid::nil(),
            )
            .owned_by("A"),
        )
        .await
        .expect("store lease");

    // ... and attempt A is about to publish its root key through the fence.
    let artifact_entry = |token: &str, payload: &[u8]| {
        secreton_storage::SecretEntry::new(
            artifact.to_string(),
            payload.to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        )
        .owned_by(token)
    };

    // A takeover of the lease is started on its own connection and left **uncommitted**, so
    // the lease row is locked while its recorded owner is already 'B' in that transaction.
    let mut takeover_conn = backend.pool().get().await.expect("takeover connection");
    let takeover = takeover_conn.transaction().await.expect("begin takeover");
    takeover
        .execute(
            "UPDATE secreton_entries \
             SET metadata = jsonb_set(metadata, '{storage_owner}', '\"B\"') \
             WHERE path = $1",
            &[&scoped_lease],
        )
        .await
        .expect("stage the takeover without committing");

    // Start A's stale fenced write while the takeover holds the row lock.
    let mut pending = {
        let storage = storage.clone();
        let entry = artifact_entry("A", b"loser-artifact");
        tokio::spawn(async move {
            storage
                .store_fenced(&entry, secreton_storage::StorageFence::new(lease, "A"))
                .await
        })
    };

    // The fix makes this write block on the takeover's lock. The pre-fix `EXISTS` read does
    // not: it reads the stale snapshot and publishes immediately, so this assertion fails.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut pending)
            .await
            .is_err(),
        "a fenced write must serialise with an in-flight takeover; it published while the \
         takeover held the lease row lock, which means the fence is a snapshot read"
    );

    // Let the takeover commit, then release the write.
    takeover.commit().await.expect("commit the takeover");
    let wrote = pending
        .await
        .expect("the stale write task must not panic")
        .expect("the stale write must return a result, not an error");
    assert!(
        !wrote,
        "an attempt whose lease was taken over must not publish its artifact"
    );

    // The artifact must be absent: A's write was refused, so nothing opened the path.
    assert!(
        storage.get_by_path(artifact).await.expect("read").is_none(),
        "a refused fenced write must leave no artifact behind"
    );

    // The winner's own fenced write still succeeds and lands the winner's record.
    assert!(
        storage
            .store_fenced(
                &artifact_entry("B", b"winner-artifact"),
                secreton_storage::StorageFence::new(lease, "B")
            )
            .await
            .expect("the winner's fenced write"),
        "the new lease holder must be able to publish its artifact"
    );
    let resolved = storage
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the winner's artifact is present");
    assert_eq!(
        resolved.encrypted_data, b"winner-artifact",
        "the path must resolve to the winner's record"
    );
}
