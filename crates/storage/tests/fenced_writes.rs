//! The `store_fenced` contract every backend must honour.
//!
//! `check()`-then-write is not a guarantee: an attempt can be fenced the instant after it
//! reads its own lease, so a write authorised only by a preceding check can still land after
//! a takeover. `store_fenced` moves the precondition into the write itself, and these tests
//! pin the three behaviours a correct backend must have:
//!
//! - a write whose fence token matches the lease record succeeds;
//! - a write whose fence token does not match writes nothing and leaves the existing record
//!   exactly as it was — this is the overwrite the finding is about;
//! - a write whose fence record is absent writes nothing, rather than failing open.
//!
//! Memory, file and the cache wrapper are exercised here with no external service. Redis and
//! PostgreSQL have their own tests that connect to a real server (`seal_redis.rs`,
//! `seal_postgres.rs` in `secreton-engines`); Raft is asserted to refuse, because a
//! process-local state machine cannot arbitrate between replicas and a fence it cannot
//! enforce must not be faked.

use std::sync::Arc;
use std::time::Duration;

use secreton_storage::cache::CachedStorage;
use secreton_storage::{
    EncryptionMetadata, Expect, FileBackend, MemoryBackend, SecretEntry, SecurityLevel,
    StorageBackend, StorageFence, StorageResult,
};

fn entry(path: &str, owner: &str, payload: &[u8]) -> SecretEntry {
    SecretEntry::new(
        path.to_string(),
        payload.to_vec(),
        EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
    .owned_by(owner)
}

async fn assert_fenced_contract(backend: &(dyn StorageBackend + Send + Sync), lease: &str) {
    let artifact = "artifact/root_key";

    // The holder of the lease acquires it, then publishes its artifact through the fence.
    backend
        .store(&entry(lease, "winner", b"lease"))
        .await
        .expect("store lease record");
    assert!(
        backend
            .store_fenced(
                &entry(artifact, "winner", b"winner-artifact"),
                StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write by the current holder"),
        "the holder of the lease must be able to publish its artifact"
    );
    let winner_id = backend
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the artifact is present")
        .id;

    // A stale attempt — its fence token no longer matches the lease — must write nothing.
    assert!(
        !backend
            .store_fenced(
                &entry(artifact, "stale", b"stale-artifact"),
                StorageFence::new(lease, "stale")
            )
            .await
            .expect("fenced write by a stale holder"),
        "an attempt whose fence token is not the lease's must not write"
    );

    let resolved = backend
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the winner's artifact must still be present");
    assert_eq!(
        resolved.id, winner_id,
        "a refused fenced write must not replace the winner's record"
    );
    assert_eq!(
        resolved.encrypted_data, b"winner-artifact",
        "a refused fenced write must not overwrite the winner's payload"
    );

    // A fence whose record has been released must refuse too: absence is not consent.
    backend
        .delete_by_path(lease)
        .await
        .expect("release the lease");
    assert!(
        !backend
            .store_fenced(
                &entry(artifact, "winner", b"after-release"),
                StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write after the lease is released"),
        "a fence with no lease record must refuse, not fail open"
    );
    assert_eq!(
        backend
            .get_by_path(artifact)
            .await
            .expect("read")
            .expect("the artifact survives")
            .encrypted_data,
        b"winner-artifact",
        "the artifact must be untouched after a refused post-release write"
    );
}

/// The `compare_and_set(.., Expect::AbsentFenced(_))` contract every backend must honour.
///
/// Creating the bootstrap root identity needs both an insert-if-absent and a still-held
/// lease, as one indivisible step: a plain `Absent` would let a concurrently registered
/// user be replaced, and a plain `store_fenced` would overwrite one. The two failure modes
/// must also stay distinguishable — an occupied path is a duplicate, while a lost lease is
/// `Ok(false)` — because the caller reports them as different errors.
async fn assert_absent_fenced_contract(backend: &(dyn StorageBackend + Send + Sync), lease: &str) {
    let artifact = "users/root";

    backend
        .store(&entry(lease, "winner", b"lease"))
        .await
        .expect("store lease record");

    // While the path is free and the lease held, the write lands.
    assert!(
        backend
            .compare_and_set(
                &entry(artifact, "winner", b"root"),
                Expect::AbsentFenced(StorageFence::new(lease, "winner"))
            )
            .await
            .expect("fenced insert by the lease holder"),
        "a free path plus a held lease must accept the insert"
    );

    // Now the path is occupied: the result must be a duplicate, not a lost-lease `false`,
    // and the existing record must be untouched.
    let occupied = backend
        .compare_and_set(
            &entry(artifact, "winner", b"replacement"),
            Expect::AbsentFenced(StorageFence::new(lease, "winner")),
        )
        .await;
    assert!(
        matches!(occupied, Err(ref e) if e.is_precondition_failure()),
        "an occupied path must be reported as a precondition failure, got {occupied:?}"
    );
    assert_eq!(
        backend
            .get_by_path(artifact)
            .await
            .expect("read")
            .expect("the root record survives")
            .encrypted_data,
        b"root",
        "a refused insert-if-absent must not replace the existing record"
    );

    // A stale attempt at a free path is `false` (lost lease), never a duplicate — the two
    // outcomes must not be conflated.
    let stale = backend
        .compare_and_set(
            &entry("users/other", "stale", b"stale"),
            Expect::AbsentFenced(StorageFence::new(lease, "stale")),
        )
        .await
        .expect("fenced insert by a stale holder");
    assert!(
        !stale,
        "a stale lease on a free path must be refused, not treated as a duplicate"
    );
    assert!(
        backend
            .get_by_path("users/other")
            .await
            .expect("read")
            .is_none(),
        "a refused stale insert must write nothing"
    );
}

#[tokio::test]
async fn memory_backend_honours_the_fence() {
    let backend = MemoryBackend::new();
    assert_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn memory_backend_honours_absent_fenced() {
    let backend = MemoryBackend::new();
    assert_absent_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn file_backend_honours_absent_fenced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    assert_absent_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn cache_wrapper_preserves_the_absent_fenced_contract() {
    use secreton_storage::cache::InMemoryCache;

    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(CachedStorage::new(
        MemoryBackend::new(),
        InMemoryCache::new(),
        Duration::from_secs(60),
    ));
    assert_absent_fenced_contract(storage.as_ref(), "sys/init_lease").await;
}

#[tokio::test]
async fn file_backend_honours_the_fence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    assert_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn cache_wrapper_preserves_the_fence_contract() {
    use secreton_storage::cache::InMemoryCache;

    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(CachedStorage::new(
        MemoryBackend::new(),
        InMemoryCache::new(),
        Duration::from_secs(60),
    ));
    assert_fenced_contract(storage.as_ref(), "sys/init_lease").await;
}

/// The owner-conditional `compare_and_set` contract every backend must honour.
///
/// `SealService::acquire_init_lease` takes over an *expired* initialization lease with
/// `compare_and_set(.., Expect::Owner(token))`. If a backend reports the precondition failed
/// when it actually held, a vault left behind by a dead process can never be recovered. This
/// pins the four behaviours the takeover depends on, and is run against every backend that
/// claims cross-process coordination — the PostgreSQL variant lives in `seal_postgres.rs`
/// because it needs a real server.
async fn assert_owner_compare_and_set_contract(backend: &(dyn StorageBackend + Send + Sync)) {
    let path = "contract/owner-cas";

    // Absent: owner-conditional insert must fail closed, not create the row.
    assert!(
        !backend
            .compare_and_set(&entry(path, "a", b"absent"), Expect::Owner("a"))
            .await
            .expect("owner-conditional write to an absent path"),
        "an owner precondition must not be satisfied by the absence of the record"
    );
    assert!(
        backend.get_by_path(path).await.expect("read").is_none(),
        "an owner-conditional write to an absent path must not create a record"
    );

    // Present and owned by "a": replacement must succeed.
    assert!(
        backend
            .compare_and_set(&entry(path, "a", b"first"), Expect::Absent)
            .await
            .expect("insert-if-absent"),
        "the first insert-if-absent must win"
    );
    let original_id = backend
        .get_by_path(path)
        .await
        .expect("read")
        .expect("inserted")
        .id;

    assert!(
        backend
            .compare_and_set(&entry(path, "a", b"replaced"), Expect::Owner("a"))
            .await
            .expect("owner-conditional replacement of an existing row"),
        "the recorded owner must be able to replace the record"
    );
    let replaced = backend
        .get_by_path(path)
        .await
        .expect("read")
        .expect("still present");
    assert_eq!(
        replaced.encrypted_data, b"replaced",
        "the replacement payload must be stored"
    );
    assert_eq!(
        replaced.id, original_id,
        "a replacement must keep the existing record's id"
    );

    // Present but owned by someone else: must refuse and change nothing.
    assert!(
        !backend
            .compare_and_set(&entry(path, "b", b"stolen"), Expect::Owner("b"))
            .await
            .expect("owner-conditional write by a non-owner"),
        "a caller that does not hold the recorded token must not replace the record"
    );
    let untouched = backend
        .get_by_path(path)
        .await
        .expect("read")
        .expect("still present");
    assert_eq!(
        untouched.encrypted_data, b"replaced",
        "a refused owner-conditional write must not change the payload"
    );
}

#[tokio::test]
async fn memory_backend_honours_owner_conditional_replacement() {
    assert_owner_compare_and_set_contract(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn file_backend_honours_owner_conditional_replacement() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    assert_owner_compare_and_set_contract(&backend).await;
}

#[tokio::test]
async fn cache_wrapper_preserves_owner_conditional_replacement() {
    use secreton_storage::cache::InMemoryCache;

    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(CachedStorage::new(
        MemoryBackend::new(),
        InMemoryCache::new(),
        Duration::from_secs(60),
    ));
    assert_owner_compare_and_set_contract(storage.as_ref()).await;
}

/// Raft's state machine is a process-local map no second replica observes, so it must refuse a
/// fence rather than evaluate it against its own memory and report a success it cannot
/// guarantee. A backend that returned `Ok(true)` here would hand the seal service a lock that
/// does not lock.
#[cfg(feature = "raft")]
#[tokio::test]
async fn raft_refuses_a_fence_it_cannot_enforce() {
    use secreton_storage::Coordination;
    use secreton_storage::backends::{RaftConfig, RaftStorageBackend};

    let dir = tempfile::tempdir().expect("temp dir");
    let backend = RaftStorageBackend::new(RaftConfig {
        data_dir: dir.path().to_path_buf(),
        ..RaftConfig::default()
    })
    .await
    .expect("raft backend");

    assert_eq!(
        backend.coordination(),
        Coordination::SingleProcess,
        "a single-node in-memory state machine cannot arbitrate between processes"
    );
    let outcome: StorageResult<bool> = backend
        .store_fenced(
            &entry("artifact/root_key", "winner", b"payload"),
            StorageFence::new("sys/init_lease", "winner"),
        )
        .await;
    assert!(
        outcome.is_err(),
        "a backend that cannot enforce a fence must refuse, not fake one"
    );
}
