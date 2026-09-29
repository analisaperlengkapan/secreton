//! `count` must report the size of the page `list` returns, not the unpaginated total.
//!
//! Memory, file and Redis all define `count` as `list(params).len()`, but PostgreSQL's
//! `count` built its own `SELECT COUNT(*)` and dropped `limit`/`offset`. A caller that sized
//! its work from `count` (the lifecycle sweep, session churn checks) therefore got a total it
//! never received from `list` — the same query returning a different answer depending only on
//! the backend a deployment chose. This test pins the contract on every backend that can run
//! without an external service, and on PostgreSQL when `SECRETON_TEST_POSTGRES_URL` is set.
//!
//! Set the variable to include the PostgreSQL assertion:
//!
//! ```text
//! docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
//! SECRETON_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!     cargo test -p secreton-storage --test count_pagination
//! ```
//!
//! Without it the PostgreSQL arm returns early, like the other database integration tests.
use secreton_storage::{
    EncryptionMetadata, QueryParams, SecretEntry, SecurityLevel, StorageBackend,
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

/// An entry carrying a single metadata pair, so a `metadata_filters` query can select it.
fn entry_with_metadata(path: &str, payload: &[u8], key: &str, value: &str) -> SecretEntry {
    let mut entry = entry(path, payload);
    entry.metadata.insert(key.to_string(), value.to_string());
    entry
}

fn postgres_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping postgres arm: SECRETON_TEST_POSTGRES_URL is not set");
            None
        }
    }
}

/// Assert the pagination contract on one backend: for a set of `limit`/`offset` windows,
/// `count` equals the number of records `list` actually returns.
async fn assert_count_matches_the_page(
    backend: &(dyn StorageBackend + Send + Sync),
    namespace: &str,
) {
    for i in 0..7u8 {
        let path = format!("{namespace}/item/{i}");
        backend.store(&entry(&path, &[i])).await.expect("seed");
    }

    let scoped = |limit: Option<u32>, offset: Option<u32>| QueryParams {
        path_prefix: Some(namespace.to_string()),
        limit,
        offset,
        ..QueryParams::default()
    };

    // The unpaginated count is the full set, and every windowed count equals its page size.
    let cases = [
        (None, None),
        (Some(3), None),
        (Some(3), Some(2)),
        (Some(2), Some(6)),
        (Some(10), Some(6)),
        (None, Some(3)),
    ];
    for (limit, offset) in cases {
        let params = scoped(limit, offset);
        let listed = backend.list(&params).await.expect("list");
        let counted = backend.count(&params).await.expect("count");
        assert_eq!(
            counted,
            listed.len() as u64,
            "count must equal the page list returns for limit={limit:?} offset={offset:?}"
        );
    }
}

#[tokio::test]
async fn memory_count_matches_the_paginated_page() {
    let backend = secreton_storage::MemoryBackend::new();
    let namespace = format!("count-pagination/memory/{}", uuid::Uuid::new_v4());
    assert_count_matches_the_page(&backend, &namespace).await;
}

#[tokio::test]
async fn file_count_matches_the_paginated_page() {
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 temp path"))
        .expect("file backend");
    let namespace = format!("count-pagination/file/{}", uuid::Uuid::new_v4());
    assert_count_matches_the_page(&backend, &namespace).await;
}

#[tokio::test]
async fn postgres_count_matches_the_paginated_page() {
    let Some(url) = postgres_url() else {
        return;
    };
    let backend = secreton_storage::backends::PostgresBackend::new(&url)
        .await
        .expect("connect");
    backend.migrate().await.expect("migrate");
    let namespace = format!("count-pagination/pg/{}", uuid::Uuid::new_v4());
    assert_count_matches_the_page(&backend, &namespace).await;
}

#[tokio::test]
async fn postgres_count_with_metadata_filter_and_pagination_matches_the_page() {
    let Some(url) = postgres_url() else {
        return;
    };
    let backend = secreton_storage::backends::PostgresBackend::new(&url)
        .await
        .expect("connect");
    backend.migrate().await.expect("migrate");
    let namespace = format!("count-pagination/pg-meta/{}", uuid::Uuid::new_v4());
    assert_metadata_count_matches_the_page(&backend, &namespace).await;
}

/// The same pagination contract, but with a metadata filter present.
///
/// A metadata predicate binds a JSONB value; `count` builds numbered placeholders and must
/// advance past that binding before it emits `LIMIT $n` / `OFFSET $n`. When it did not, the
/// limit reused the JSONB placeholder and PostgreSQL rejected the query with a "could not
/// determine data type" / bind-count error — so a filtered, paginated count failed outright
/// instead of returning the page size. `list` already advanced the counter; this pins the two
/// backends to the same answer under a filter.
async fn assert_metadata_count_matches_the_page(
    backend: &(dyn StorageBackend + Send + Sync),
    namespace: &str,
) {
    // Five rows share the filter, and three more are outside it. The filter must narrow the
    // page before `limit`/`offset` apply, exactly as `list` does.
    for i in 0..5u8 {
        let path = format!("{namespace}/in/{i}");
        backend
            .store(&entry_with_metadata(&path, &[i], "team", "ops"))
            .await
            .expect("seed matching entry");
    }
    for i in 0..3u8 {
        let path = format!("{namespace}/out/{i}");
        backend
            .store(&entry_with_metadata(&path, &[i], "team", "infra"))
            .await
            .expect("seed non-matching entry");
    }

    let mut filters = std::collections::HashMap::new();
    filters.insert("team".to_string(), "ops".to_string());

    let scoped = |limit: Option<u32>, offset: Option<u32>| QueryParams {
        path_prefix: Some(namespace.to_string()),
        metadata_filters: filters.clone(),
        limit,
        offset,
        ..QueryParams::default()
    };

    for (limit, offset) in [
        (None, None),
        (Some(3), None),
        (Some(3), Some(2)),
        (Some(2), Some(4)),
        (Some(10), Some(4)),
        (None, Some(2)),
    ] {
        let params = scoped(limit, offset);
        let listed = backend.list(&params).await.expect("list");
        let counted = backend.count(&params).await.expect("count");
        assert_eq!(
            counted,
            listed.len() as u64,
            "a metadata-filtered count must equal the page list returns for \
             limit={limit:?} offset={offset:?}"
        );
    }
}
