//! A path must enumerate to the single record a read resolves to.
//!
//! `store` is last-writer-wins by id, so a rewrite that carries a fresh id for an existing
//! path leaves the previous record behind — a second entry key on Redis, a second `.json`
//! file in the file backend. Enumerating by stored key reported both, so a rewritten secret
//! appeared twice, a `count` grew on every update, and the extra row named an id that
//! `get_by_id` could not reach. A backend that keeps a secondary record must hide it from
//! enumeration.
//!
//! The two backends then diverge on the superseded id, and each is asserted to its own
//! contract. The file backend keys by id, so the superseded record keeps its file and stays
//! readable by its own id. The memory backend is keyed by path: the replacement took the
//! path's only slot, so the memory backend and its cache wrapper must report the superseded
//! id as gone — resolving it through the still-mapped path to the *replacement* was the bug.
use std::sync::Arc;

use secreton_storage::cache::{CachedStorage, InMemoryCache};
use secreton_storage::{
    EncryptionMetadata, Expect, FileBackend, MemoryBackend, QueryParams, SecretEntry,
    SecurityLevel, StorageBackend,
};

fn entry(path: &str, payload: &[u8]) -> SecretEntry {
    SecretEntry::new(
        path.to_string(),
        payload.to_vec(),
        EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
}

/// Write `payload` at `path`, replacing whatever was there with a *fresh* record identity —
/// the shape a caller that does not preserve the id produces.
async fn write_fresh(
    backend: &(dyn StorageBackend + Send + Sync),
    path: &str,
    payload: &[u8],
) -> uuid::Uuid {
    let e = entry(path, payload);
    backend.store(&e).await.expect("store");
    e.id
}

/// How a backend keys a superseded record, once a fresh id has replaced it at `path`.
///
/// This is the one place the backends legitimately differ. The file backend stores one file
/// per id, so the record it superseded keeps its own file and is still readable by its id.
/// The memory backend is keyed by path: the replacement took the path's single slot, so the
/// superseded id names nothing at all — and it must report exactly that, rather than
/// resolving through the still-mapped path to the *replacement* record.
#[derive(Clone, Copy)]
enum SupersededId {
    /// `get_by_id(old_id)` is a cache/backend miss.
    Retired,
    /// `get_by_id(old_id)` still yields the original record, under its own id.
    Retained,
}

async fn assert_path_enumerates_once(
    backend: &(dyn StorageBackend + Send + Sync),
    superseded: SupersededId,
) {
    let path = "kv/rewritten";
    let old_id = write_fresh(backend, path, b"v1").await;
    let new_id = write_fresh(backend, path, b"v2").await;
    assert_ne!(old_id, new_id, "the two writes must be distinct records");

    let listed = backend
        .list(&QueryParams {
            path_prefix: Some(path.to_string()),
            ..Default::default()
        })
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "a path must enumerate once; the superseded record is still stored but must not \
         appear. Got ids {:?}",
        listed.iter().map(|e| e.id).collect::<Vec<_>>()
    );
    assert_eq!(
        listed[0].encrypted_data, b"v2",
        "the enumerated record must be the one the path resolves to"
    );

    // `count` shares the enumeration, so it must agree with `list`.
    let counted = backend
        .count(&QueryParams {
            path_prefix: Some(path.to_string()),
            ..Default::default()
        })
        .await
        .expect("count");
    assert_eq!(counted, 1, "`count` must not include a superseded record");

    // And a read by path agrees with the enumeration.
    let resolved = backend
        .get_by_path(path)
        .await
        .expect("read")
        .expect("the current record is present");
    assert_eq!(resolved.id, listed[0].id);

    // The point of the find: a read by the superseded id must never hand back the record that
    // replaced it. That is the bug the memory backend had — its `id_index` still mapped the
    // old id to the path, which the replacement now occupied.
    let old = backend.get_by_id(old_id).await.expect("read old id");
    assert!(
        old.as_ref().is_none_or(|e| e.id == old_id),
        "`get_by_id(old_id)` must never resolve through the path to the replacement record"
    );
    match superseded {
        SupersededId::Retired => assert!(
            old.is_none(),
            "the superseded id must be retired, but a record was returned"
        ),
        SupersededId::Retained => assert!(
            old.is_some(),
            "the superseded record is stored under its own id and must remain readable"
        ),
    }
}

#[tokio::test]
async fn file_backend_enumerates_a_rewritten_path_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    assert_path_enumerates_once(&backend, SupersededId::Retained).await;
}

#[tokio::test]
async fn memory_backend_enumerates_a_rewritten_path_once() {
    let backend = MemoryBackend::new();
    assert_path_enumerates_once(&backend, SupersededId::Retired).await;
}

#[tokio::test]
async fn cache_wrapper_enumerates_a_rewritten_path_once() {
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(CachedStorage::new(
        MemoryBackend::new(),
        InMemoryCache::new(),
        std::time::Duration::from_secs(60),
    ));
    assert_path_enumerates_once(storage.as_ref(), SupersededId::Retired).await;
}

/// `compare_and_set` replaces a record in place, so a conditional rewrite must not leave a
/// second record behind. This is the shape the initialization lease and the staging marker
/// are written in, so a backend that leaked here would grow a duplicate on every renewal.
#[tokio::test]
async fn file_backend_conditional_rewrite_leaves_one_record() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    let path = "kv/conditional";
    assert!(
        backend
            .compare_and_set(&entry(path, b"v1").owned_by("a"), Expect::Absent)
            .await
            .expect("insert"),
        "the insert-if-absent must win"
    );
    assert!(
        backend
            .compare_and_set(&entry(path, b"v2").owned_by("a"), Expect::Owner("a"))
            .await
            .expect("replace"),
        "the recorded owner may replace"
    );

    let listed = backend
        .list(&QueryParams {
            path_prefix: Some(path.to_string()),
            ..Default::default()
        })
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "a conditional replace must not accumulate records"
    );
    assert_eq!(
        backend
            .get_by_path(path)
            .await
            .expect("read")
            .expect("present")
            .encrypted_data,
        b"v2"
    );
}
