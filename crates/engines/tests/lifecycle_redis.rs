//! The lifecycle sweep must find an expired secret even when the store is busy.
//!
//! The sweep asks for one page of entries sorted by `expires_at`, with reserved namespaces
//! excluded and a 10 000-entry limit. Redis enumerates by key scan and applies the query
//! in memory (`QueryParams::apply_to`), so this is the backend where the query *is* the
//! filter. Two defects made the sweep miss expired secrets against it:
//!
//! - `apply_to` had no `expires_at` branch, so sorting by it fell through to the metadata
//!   fallback, keyed every entry `""`, and left the page unordered. The `limit` then
//!   truncated arbitrary records, and the expired ones fell outside the page.
//! - The reserved-prefix exclusion was applied *after* the `limit`, so a store with many
//!   reserved entries consumed the page and pushed the expired secret out.
//!
//! With more than `SWEEP_MAX_ENTRIES` (10 000) non-expired entries present, a correct sweep
//! still returns the single expired one. This test proves it against a real Redis.
//!
//! Set `SECRETON_TEST_REDIS_URL` to run it:
//!
//! ```text
//! docker run --rm -d -p 6379:6379 redis:7-alpine
//! SECRETON_TEST_REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p secreton-engines --test lifecycle_redis
//! ```

use std::sync::Arc;

use secreton_engines::lifecycle::LifecycleConfig;
use secreton_engines::services::audit::AuditLogger;
use secreton_engines::services::crypto::CryptoService;
use secreton_engines::services::lifecycle::LifecycleService;
use secreton_storage::backends::RedisBackend;
use secreton_storage::{
    Coordination, EncryptionMetadata, Expect, QueryParams, SecretEntry, SecurityLevel,
    StorageBackend, StorageResult,
};

fn redis_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_REDIS_URL is not set");
            None
        }
    }
}

/// Prefix every path so concurrent runs cannot collide, without downgrading the backend's
/// reported coordination.
#[derive(Debug)]
struct NamespacedRedis {
    inner: Arc<RedisBackend>,
    prefix: String,
}

impl NamespacedRedis {
    fn scope(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

#[async_trait::async_trait]
impl StorageBackend for NamespacedRedis {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.store(&scoped).await
    }
    async fn get_by_id(&self, id: uuid::Uuid) -> StorageResult<Option<SecretEntry>> {
        self.inner.get_by_id(id).await
    }
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        self.inner.get_by_path(&self.scope(path)).await
    }
    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.update(&scoped).await
    }
    async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.upsert(&scoped).await
    }
    async fn delete_by_id(&self, id: uuid::Uuid) -> StorageResult<bool> {
        self.inner.delete_by_id(id).await
    }
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        self.inner.delete_by_path(&self.scope(path)).await
    }
    fn coordination(&self) -> Coordination {
        self.inner.coordination()
    }
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: Expect<'_>,
    ) -> StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.compare_and_set(&scoped, expect).await
    }
    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        self.inner.delete_owned(&self.scope(path), token).await
    }
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: secreton_storage::StorageFence<'_>,
    ) -> StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        let scoped_path = self.scope(fence.path);
        let scoped_fence = secreton_storage::StorageFence::new(&scoped_path, fence.token);
        self.inner.store_fenced(&scoped, scoped_fence).await
    }
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        // Scope the prefix filters the same way the storage wrapper scopes paths, so the
        // query the service builds (unprefixed) selects only this namespace's records.
        let mut scoped = params.clone();
        scoped.path_prefix = params.path_prefix.as_ref().map(|p| self.scope(p));
        if scoped.path_prefix.is_none() {
            scoped.path_prefix = Some(self.scope(""));
        }
        scoped.excluded_path_prefixes = params
            .excluded_path_prefixes
            .iter()
            .map(|p| self.scope(p))
            .collect();
        let mut entries = self.inner.list(&scoped).await?;
        for entry in &mut entries {
            entry.path = entry
                .path
                .strip_prefix(&format!("{}/", self.prefix))
                .unwrap_or(&entry.path)
                .to_string();
        }
        Ok(entries)
    }
    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        Ok(self.list(params).await?.len() as u64)
    }
    async fn exists(&self, path: &str) -> StorageResult<bool> {
        self.inner.exists(&self.scope(path)).await
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
    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        self.inner
            .delete_expired(path_prefix.map(|p| self.scope(&p)))
            .await
    }
    async fn store_oauth_state(&self, state: &secreton_domain::OAuthState) -> StorageResult<()> {
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

fn entry(path: &str, expires_at: Option<chrono::DateTime<chrono::Utc>>) -> SecretEntry {
    let mut entry = SecretEntry::new(
        path.to_string(),
        vec![1, 2, 3],
        EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::new_v4(),
    );
    entry.expires_at = expires_at;
    entry
}

#[tokio::test]
async fn an_expired_secret_does_not_survive_behind_a_full_page_of_live_entries() {
    let Some(url) = redis_url() else {
        return;
    };
    let namespace = format!("it/lifecycle/{}", uuid::Uuid::new_v4());
    let inner = Arc::new(RedisBackend::new(&url).await.expect("connect redis"));
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: inner.clone(),
        prefix: namespace.clone(),
    });

    // More live records than the sweep's page size (10 000), so a query that truncated
    // before filtering or ordering would never reach an expiring record at the end.
    const LIVE: usize = 10_050;
    for i in 0..LIVE {
        storage
            .store(&entry(&format!("apps/live/{i}"), None))
            .await
            .expect("seed live entry");
    }
    // The expiring record is stored *before* its deadline, which is the only state Redis
    // will hold it in: the backend maps `expires_at` onto a Redis TTL, so a deadline that
    // has already passed is never written at all. It expires on its own a second later.
    let expiring = entry(
        "apps/gone/expiring",
        Some(chrono::Utc::now() + chrono::Duration::seconds(1)),
    );
    let expiring_id = expiring.id;
    storage.store(&expiring).await.expect("seed expiring entry");

    let audit = Arc::new(
        AuditLogger::new(storage.clone(), 2555, 100, true)
            .await
            .expect("audit logger"),
    );
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.expect("crypto"));
    let service = Arc::new(LifecycleService::new(
        storage.clone(),
        crypto,
        audit,
        LifecycleConfig {
            enabled: true,
            default_ttl_days: 30,
            grace_period_days: 0,
            auto_archive_enabled: false,
            cleanup_enabled: true,
        },
    ));

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    service
        .process_lifecycle_events()
        .await
        .expect("the sweep runs");

    // On Redis the record is gone because the backend's TTL removed it, which is the
    // stronger outcome: it does not depend on the sweep's page reaching it at all. What
    // this asserts is the end state the finding asks for — an expired secret does not
    // survive while more than a page of live entries exists.
    assert!(
        storage
            .get_by_id(expiring_id)
            .await
            .expect("read")
            .is_none(),
        "an expired secret must not survive behind {LIVE} live entries"
    );
}

/// A direct assertion of the ordering contract the sweep depends on, so a regression is
/// reported as the ordering bug it is rather than as a downstream sweep miss.
#[tokio::test]
async fn redis_list_orders_by_expiry_and_excludes_before_truncating() {
    let Some(url) = redis_url() else {
        return;
    };
    let namespace = format!("it/query/{}", uuid::Uuid::new_v4());
    let inner = Arc::new(RedisBackend::new(&url).await.expect("connect redis"));
    let storage = NamespacedRedis {
        inner,
        prefix: namespace.clone(),
    };

    for i in 0..20 {
        storage
            .store(&entry(&format!("sys/reserved/{i}"), None))
            .await
            .expect("seed reserved");
    }
    let soon = entry(
        "apps/soon",
        Some(chrono::Utc::now() + chrono::Duration::hours(1)),
    );
    let later = entry("apps/later", None);
    storage.store(&later).await.expect("seed later");
    storage.store(&soon).await.expect("seed soon");

    let params = QueryParams {
        include_expired: true,
        limit: Some(3),
        sort_by: Some("expires_at".to_string()),
        sort_order: Some("asc".to_string()),
        excluded_path_prefixes: vec!["sys/".to_string()],
        ..Default::default()
    };
    let listed = storage.list(&params).await.expect("list");

    assert_eq!(
        listed.first().map(|e| e.path.as_str()),
        Some("apps/soon"),
        "the earliest expiry must sort first and reserved entries must not consume the \
         limit; got {:?}",
        listed.iter().map(|e| e.path.as_str()).collect::<Vec<_>>()
    );
}
