//! Cache abstraction for storage layer

use crate::{SecretEntry, StorageResult};
use async_trait::async_trait;
use secreton_domain::OAuthState;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Cache backend trait
#[async_trait]
pub trait CacheBackend: std::fmt::Debug + Send + Sync {
    /// Get an entry from cache
    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Set an entry in cache
    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> StorageResult<()>;

    /// Delete an entry from cache
    async fn delete(&self, key: &str) -> StorageResult<bool>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> StorageResult<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> StorageResult<()>;

    /// Get cache statistics
    async fn stats(&self) -> StorageResult<CacheStats>;
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_rate: f64,
    pub entry_count: u64,
    pub memory_usage_bytes: u64,
    pub eviction_count: u64,
}

/// In-memory cache implementation for development/testing
#[derive(Debug)]
pub struct InMemoryCache {
    // `parking_lot` rather than `std`: a std lock poisons when a holder panics, and every
    // call site discharged that with `unwrap()` — so one panic anywhere turned a *cache*
    // into a process-wide outage. parking_lot does not poison, which is the right
    // semantics here: stale cache state is recoverable, a dead server is not.
    data: parking_lot::RwLock<std::collections::HashMap<String, CacheEntry>>,
    stats: parking_lot::RwLock<CacheStats>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    expires_at: Option<std::time::Instant>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            data: parking_lot::RwLock::new(std::collections::HashMap::new()),
            stats: parking_lot::RwLock::new(CacheStats {
                hit_count: 0,
                miss_count: 0,
                hit_rate: 0.0,
                entry_count: 0,
                memory_usage_bytes: 0,
                eviction_count: 0,
            }),
        }
    }

    fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        let mut data = self.data.write();
        let mut stats = self.stats.write();

        let original_count = data.len();
        data.retain(|_, entry| entry.expires_at.is_none_or(|expires| expires > now));

        let evicted_count = original_count - data.len();
        stats.eviction_count += evicted_count as u64;
        stats.entry_count = data.len() as u64;
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for InMemoryCache {
    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.cleanup_expired();

        let data = self.data.read();
        let mut stats = self.stats.write();

        match data.get(key) {
            Some(entry) => {
                if let Some(expires_at) = entry.expires_at
                    && std::time::Instant::now() > expires_at
                {
                    stats.miss_count += 1;
                    return Ok(None);
                }

                stats.hit_count += 1;
                Ok(Some(entry.data.clone()))
            }
            None => {
                stats.miss_count += 1;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> StorageResult<()> {
        let expires_at = ttl.map(|duration| std::time::Instant::now() + duration);

        let mut data = self.data.write();
        let mut stats = self.stats.write();

        let entry = CacheEntry {
            data: value.clone(),
            expires_at,
        };

        let memory_delta = if let Some(old_entry) = data.get(key) {
            value.len() as i64 - old_entry.data.len() as i64
        } else {
            value.len() as i64 + key.len() as i64
        };

        data.insert(key.to_string(), entry);
        stats.entry_count = data.len() as u64;
        stats.memory_usage_bytes = i64::try_from(stats.memory_usage_bytes)
            .unwrap_or(i64::MAX)
            .saturating_add(memory_delta)
            .try_into()
            .unwrap_or(0);

        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<bool> {
        let mut data = self.data.write();
        let mut stats = self.stats.write();

        if let Some(entry) = data.remove(key) {
            stats.entry_count = data.len() as u64;
            stats.memory_usage_bytes = stats
                .memory_usage_bytes
                .saturating_sub(entry.data.len() as u64 + key.len() as u64);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let result = self.get(key).await?;
        Ok(result.is_some())
    }

    async fn clear(&self) -> StorageResult<()> {
        let mut data = self.data.write();
        let mut stats = self.stats.write();

        data.clear();
        stats.entry_count = 0;
        stats.memory_usage_bytes = 0;

        Ok(())
    }

    async fn stats(&self) -> StorageResult<CacheStats> {
        self.cleanup_expired();

        let mut stats = self.stats.write();
        let total_requests = stats.hit_count + stats.miss_count;
        stats.hit_rate = if total_requests > 0 {
            stats.hit_count as f64 / total_requests as f64
        } else {
            0.0
        };

        Ok(stats.clone())
    }
}

/// Cached storage wrapper that adds caching to any storage backend
#[derive(Debug)]
pub struct CachedStorage<S: crate::StorageBackend, C: CacheBackend> {
    storage: S,
    cache: C,
    default_ttl: Duration,
}

impl<S, C> CachedStorage<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    pub fn new(storage: S, cache: C, default_ttl: Duration) -> Self {
        Self {
            storage,
            cache,
            default_ttl,
        }
    }

    fn cache_key_for_id(id: Uuid) -> String {
        format!("entry:id:{}", id)
    }

    fn cache_key_for_path(path: &str) -> String {
        format!("entry:path:{}", path)
    }

    /// Refresh both cache keys for an entry, through the same keys `store` populates.
    async fn cache_entry(&self, entry: &SecretEntry) {
        let serialized = postcard::to_stdvec(entry).unwrap_or_default();
        let _ = self
            .cache
            .set(
                &Self::cache_key_for_id(entry.id),
                serialized.clone(),
                Some(self.default_ttl),
            )
            .await;
        let _ = self
            .cache
            .set(
                &Self::cache_key_for_path(&entry.path),
                serialized,
                Some(self.default_ttl),
            )
            .await;
    }

    /// Align the cache with the record a conditional write left at `path`.
    ///
    /// The cache keys a record under both its id and its path. A conditional write is a
    /// replacement and the shipped backends preserve the record's existing id, but the
    /// wrapper must not rely on that: if the write ends up under a different id than the
    /// path previously named, the old `entry:id:<old>` key still holds the superseded
    /// record, and `get_by_id(old_id)` would serve it from cache rather than report the
    /// record gone. Cache the canonical record and retire any id the path no longer names.
    async fn cache_after_conditional_write(
        &self,
        path: &str,
        previous: Option<&SecretEntry>,
        canonical: Option<SecretEntry>,
    ) {
        match canonical {
            Some(canonical) => {
                self.cache_entry(&canonical).await;
                if let Some(previous) = previous
                    && previous.id != canonical.id
                {
                    let _ = self
                        .cache
                        .delete(&Self::cache_key_for_id(previous.id))
                        .await;
                }
            }
            None => {
                let _ = self.cache.delete(&Self::cache_key_for_path(path)).await;
                if let Some(previous) = previous {
                    let _ = self
                        .cache
                        .delete(&Self::cache_key_for_id(previous.id))
                        .await;
                }
            }
        }
    }

    /// Retire the cached keys a conditional write's canonical readback would have refreshed.
    ///
    /// A conditional write has already committed at this point — the caller's error is only
    /// that the immediate readback failed, not that the write did not land. If the cache is
    /// left untouched, the pre-write record survives under the path key and later reads serve
    /// it until the TTL expires, reporting a value the backend no longer holds. Invalidating
    /// both keys here converts that silent staleness into a cache miss that the next read
    /// repairs from the backend.
    async fn invalidate_after_failed_readback(&self, path: &str, previous: Option<&SecretEntry>) {
        let _ = self.cache.delete(&Self::cache_key_for_path(path)).await;
        if let Some(previous) = previous {
            let _ = self
                .cache
                .delete(&Self::cache_key_for_id(previous.id))
                .await;
        }
    }
}

#[async_trait]
impl<S, C> crate::StorageBackend for CachedStorage<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        // Read what the path named before the write, so a `store` that replaces the record
        // under a different id can retire the superseded id from the cache. Without this the
        // `entry:id:<old>` key survives the write, and `get_by_id(old_id)` keeps answering
        // from cache with a record the backend no longer has.
        let previous = self.storage.get_by_path(&entry.path).await.ok().flatten();
        let result = self.storage.store(entry).await;

        if result.is_ok() {
            // Cache the entry on successful store
            let serialized = postcard::to_stdvec(entry).unwrap_or_default();
            let _ = self
                .cache
                .set(
                    &Self::cache_key_for_id(entry.id),
                    serialized.clone(),
                    Some(self.default_ttl),
                )
                .await;
            let _ = self
                .cache
                .set(
                    &Self::cache_key_for_path(&entry.path),
                    serialized,
                    Some(self.default_ttl),
                )
                .await;
            if let Some(previous) = previous
                && previous.id != entry.id
            {
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_id(previous.id))
                    .await;
            }
        }

        result
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let cache_key = Self::cache_key_for_id(id);

        // Try cache first
        if let Ok(Some(cached_data)) = self.cache.get(&cache_key).await
            && let Ok(entry) = postcard::from_bytes::<SecretEntry>(&cached_data)
        {
            return Ok(Some(entry));
        }

        // Fall back to storage
        let entry = self.storage.get_by_id(id).await?;

        // Cache the result if found
        if let Some(ref entry) = entry
            && let Ok(serialized) = postcard::to_stdvec(entry)
        {
            let _ = self
                .cache
                .set(&cache_key, serialized, Some(self.default_ttl))
                .await;
        }

        Ok(entry)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let cache_key = Self::cache_key_for_path(path);

        // Try cache first
        if let Ok(Some(cached_data)) = self.cache.get(&cache_key).await
            && let Ok(entry) = postcard::from_bytes::<SecretEntry>(&cached_data)
        {
            return Ok(Some(entry));
        }

        // Fall back to storage
        let entry = self.storage.get_by_path(path).await?;

        // Cache the result if found
        if let Some(ref entry) = entry
            && let Ok(serialized) = postcard::to_stdvec(entry)
        {
            let _ = self
                .cache
                .set(&cache_key, serialized, Some(self.default_ttl))
                .await;
        }

        Ok(entry)
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let result = self.storage.update(entry).await;

        if result.is_ok() {
            // Update cache
            if let Ok(serialized) = postcard::to_stdvec(entry) {
                let _ = self
                    .cache
                    .set(
                        &Self::cache_key_for_id(entry.id),
                        serialized.clone(),
                        Some(self.default_ttl),
                    )
                    .await;
                let _ = self
                    .cache
                    .set(
                        &Self::cache_key_for_path(&entry.path),
                        serialized,
                        Some(self.default_ttl),
                    )
                    .await;
            }
        }

        result
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        // Get the entry first to find the path for cache invalidation
        let entry = self.storage.get_by_id(id).await?;

        let result = self.storage.delete_by_id(id).await?;

        if result {
            // Invalidate cache
            let _ = self.cache.delete(&Self::cache_key_for_id(id)).await;
            if let Some(entry) = entry {
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_path(&entry.path))
                    .await;
            }
        }

        Ok(result)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // Get the entry first to find the ID for cache invalidation
        let entry = self.storage.get_by_path(path).await?;

        let result = self.storage.delete_by_path(path).await?;

        if result {
            // Invalidate cache
            let _ = self.cache.delete(&Self::cache_key_for_path(path)).await;
            if let Some(entry) = entry {
                let _ = self.cache.delete(&Self::cache_key_for_id(entry.id)).await;
            }
        }

        Ok(result)
    }

    fn coordination(&self) -> crate::Coordination {
        // A cache in front of a backend changes nothing about who arbitrates: the
        // underlying store does, and this wrapper must not claim more than it has.
        self.storage.coordination()
    }

    /// Delegated to the inner backend, which owns the arbitration.
    ///
    /// The cache is updated only after the conditional write reports success, and a
    /// precondition that did not hold is reported as `Ok(false)` without touching it: a
    /// lost race must not leave a cached copy of a write that never happened.
    ///
    /// On success the record is *re-read* from the backend and that canonical record is
    /// cached, never the caller's input. A compare-and-set is a replacement of a record
    /// that already exists at the path, and the backends normalize what they write: the
    /// existing `id` and `created_at` are preserved (see `Expect` and each backend's
    /// `compare_and_set`). Caching the input would therefore hand a later read a record
    /// whose identity and creation time differ from what storage holds — a divergence that
    /// lasts until the entry expires from the cache. Re-reading costs one backend read per
    /// successful conditional write and cannot drift.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        // Read the record the path names *before* the write so its id can be retired from
        // the cache if the write lands under a different one. Best-effort: a failed read
        // just means the stale-id cleanup below has nothing to work from.
        let previous = self.storage.get_by_path(&entry.path).await.ok().flatten();
        let written = self.storage.compare_and_set(entry, expect).await?;
        if written {
            // Read back the canonical record. If the read fails or the record is
            // unexpectedly absent, do not cache the input: a stale or wrong cached identity
            // is worse than a cache miss, which the next read repairs.
            let canonical = match self.storage.get_by_path(&entry.path).await {
                Ok(canonical) => canonical,
                Err(e) => {
                    // The write landed; only the readback failed. Retire the keys it would
                    // have refreshed so a later read cannot serve the pre-write record, then
                    // report the readback failure without pretending the write did not happen.
                    self.invalidate_after_failed_readback(&entry.path, previous.as_ref())
                        .await;
                    return Err(e);
                }
            };
            self.cache_after_conditional_write(&entry.path, previous.as_ref(), canonical)
                .await;
        } else {
            // The inner write did not happen, but a stale positive cache entry for this
            // path would make a subsequent read report a record the backend may not have.
            let _ = self
                .cache
                .delete(&Self::cache_key_for_path(&entry.path))
                .await;
        }
        Ok(written)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let entry = self.storage.get_by_path(path).await?;
        let deleted = self.storage.delete_owned(path, token).await?;
        if deleted {
            let _ = self.cache.delete(&Self::cache_key_for_path(path)).await;
            if let Some(entry) = entry {
                let _ = self.cache.delete(&Self::cache_key_for_id(entry.id)).await;
            }
        }
        Ok(deleted)
    }

    /// Delegated to the inner backend, which owns the arbitration — a cache in front of a
    /// store changes nothing about who fences.
    ///
    /// As with [`crate::StorageBackend::compare_and_set`], the cache is only touched once
    /// the conditional write reports success, and the canonical record is re-read from the
    /// backend rather than taken from the caller's input: a fenced write is a replacement, and
    /// the backends preserve the existing `id` and `created_at`, so caching the input would
    /// hand later reads a record whose identity disagrees with storage. A fence that did not
    /// hold is a `Ok(false)` and must leave nothing behind that suggests a write happened.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: crate::StorageFence<'_>,
    ) -> StorageResult<bool> {
        let previous = self.storage.get_by_path(&entry.path).await.ok().flatten();
        let written = self.storage.store_fenced(entry, fence).await?;
        if written {
            let canonical = match self.storage.get_by_path(&entry.path).await {
                Ok(canonical) => canonical,
                Err(e) => {
                    // Same contract as `compare_and_set`: the write committed, only the
                    // readback failed. Invalidate the cached keys so no later read reports
                    // the superseded record, and surface the readback error unchanged.
                    self.invalidate_after_failed_readback(&entry.path, previous.as_ref())
                        .await;
                    return Err(e);
                }
            };
            self.cache_after_conditional_write(&entry.path, previous.as_ref(), canonical)
                .await;
        } else {
            let _ = self
                .cache
                .delete(&Self::cache_key_for_path(&entry.path))
                .await;
        }
        Ok(written)
    }

    // For operations that return multiple entries, we don't cache them as they can be large
    // and the cache keys would be complex to manage
    async fn list(&self, params: &crate::QueryParams) -> StorageResult<Vec<SecretEntry>> {
        self.storage.list(params).await
    }

    async fn count(&self, params: &crate::QueryParams) -> StorageResult<u64> {
        self.storage.count(params).await
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        // Check cache first
        if self
            .cache
            .exists(&Self::cache_key_for_path(path))
            .await
            .unwrap_or(false)
        {
            return Ok(true);
        }

        self.storage.exists(path).await
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
        self.storage.begin_transaction().await
    }

    async fn health_check(&self) -> StorageResult<crate::HealthStatus> {
        self.storage.health_check().await
    }

    async fn get_stats(&self) -> StorageResult<crate::StorageStats> {
        self.storage.get_stats().await
    }

    async fn migrate(&self) -> StorageResult<()> {
        self.storage.migrate().await
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        self.storage.store_oauth_state(state).await
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        self.storage.get_oauth_state(state).await
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        self.storage.delete_expired_oauth_states().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_in_memory_cache_set_get_and_stats() {
        let cache = InMemoryCache::new();
        let key = "secreton:test";

        // Miss before value set
        assert!(cache.get(key).await.unwrap().is_none());

        cache
            .set(key, b"encrypted-data".to_vec(), None)
            .await
            .unwrap();

        let cached = cache.get(key).await.unwrap();
        assert_eq!(cached, Some(b"encrypted-data".to_vec()));

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.entry_count, 1);
        assert!(stats.hit_rate > 0.0);
    }

    #[tokio::test]
    async fn test_in_memory_cache_expiration() {
        let cache = InMemoryCache::new();
        let key = "secreton:expiring";

        cache
            .set(key, b"temp".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();

        assert!(cache.get(key).await.unwrap().is_some());

        sleep(Duration::from_millis(60)).await;

        assert!(cache.get(key).await.unwrap().is_none());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.entry_count, 0);
        assert!(stats.eviction_count >= 1);
    }

    #[tokio::test]
    async fn test_in_memory_cache_exists_and_clear() {
        let cache = InMemoryCache::new();
        let key = "secreton:clear";

        cache.set(key, b"value".to_vec(), None).await.unwrap();
        assert!(cache.exists(key).await.unwrap());

        cache.clear().await.unwrap();
        assert!(!cache.exists(key).await.unwrap());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.memory_usage_bytes, 0);
    }
}

#[cfg(test)]
mod round_trip_tests {
    use super::*;
    use crate::{EncryptionMetadata, SecurityLevel};

    fn sample_entry() -> SecretEntry {
        let mut entry = SecretEntry::new(
            "kv/app/db-password".to_string(),
            // Ciphertext: arbitrary bytes, including zero and 0xFF, which a text encoding
            // would have to escape and a length-prefixed one must round-trip exactly.
            vec![0u8, 1, 2, 250, 255, 0, 128],
            EncryptionMetadata {
                algorithm: "AES-256-GCM".to_string(),
                key_id: "key-1".to_string(),
                iv: vec![9u8; 12],
                ..Default::default()
            },
            SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        );
        entry
            .metadata
            .insert("owner".to_string(), "platform-team".to_string());
        entry.tags.push("production".to_string());
        entry.version = 7;
        entry.expires_at = Some(chrono::Utc::now() + chrono::Duration::hours(2));
        entry
    }

    /// The cache stores entries as bytes, so the encoder is load-bearing: a serializer
    /// that silently drops or reorders a field would hand back a *different secret* than
    /// the one stored. Nothing tested this — the existing cache tests exercise the
    /// backend's set/get, not the layer that encodes an entry into it.
    #[test]
    fn an_entry_survives_the_cache_encoding_unchanged() {
        let original = sample_entry();

        let encoded = postcard::to_stdvec(&original).expect("encode");
        let decoded: SecretEntry = postcard::from_bytes(&encoded).expect("decode");

        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.path, original.path);
        assert_eq!(
            decoded.encrypted_data, original.encrypted_data,
            "ciphertext did not survive the round trip"
        );
        assert_eq!(decoded.metadata, original.metadata);
        assert_eq!(decoded.tags, original.tags);
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.owner_id, original.owner_id);
        assert_eq!(decoded.expires_at, original.expires_at);
    }

    /// An empty ciphertext is a legitimate value (an empty secret) and a common edge for
    /// length-prefixed encodings.
    #[test]
    fn an_entry_with_no_ciphertext_round_trips() {
        let mut entry = sample_entry();
        entry.encrypted_data.clear();
        entry.metadata.clear();
        entry.tags.clear();
        entry.expires_at = None;

        let encoded = postcard::to_stdvec(&entry).expect("encode");
        let decoded: SecretEntry = postcard::from_bytes(&encoded).expect("decode");

        assert!(decoded.encrypted_data.is_empty());
        assert_eq!(decoded.expires_at, None);
        assert_eq!(decoded.path, entry.path);
    }

    /// Truncated or foreign bytes must be rejected, not decoded into a partial entry —
    /// the read paths treat a successful decode as a cache hit and return it to the caller.
    #[test]
    fn corrupt_cache_bytes_are_rejected() {
        let encoded = postcard::to_stdvec(&sample_entry()).expect("encode");

        assert!(
            postcard::from_bytes::<SecretEntry>(&encoded[..encoded.len() / 2]).is_err(),
            "a truncated entry decoded successfully"
        );
        assert!(
            postcard::from_bytes::<SecretEntry>(b"not an entry at all").is_err(),
            "arbitrary bytes decoded as an entry"
        );
    }

    #[tokio::test]
    async fn a_cached_read_after_a_compare_and_set_matches_the_backend() {
        // Regression: after a successful compare-and-set the cache stored the *caller's*
        // input. A conditional write replaces an existing record, and the backends normalize
        // the replacement by keeping the existing `id` and `created_at`, so the cached copy
        // diverged from storage — a later cached read reported an identity and creation time
        // the backend never held, until the entry expired from the cache. The fix reads the
        // canonical record back and caches that.
        //
        // The property: a cached read after a conditional write returns exactly what a direct
        // backend read returns.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/cas/target";

        // Seed, then warm the cache so the conditional write is exercised against a cached
        // record rather than a cold path.
        let seeded = sample_entry_with_path(path, b"v1");
        crate::StorageBackend::store(&cached, &seeded)
            .await
            .expect("seed");
        let _ = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("warm the cache");

        // A replacement carries a fresh id and creation time. The backend discards both and
        // keeps the seeded record's; the cache must reflect that, not the input.
        let mut replacement = sample_entry_with_path(path, b"v2");
        assert_ne!(
            replacement.id, seeded.id,
            "the input must differ from the stored record, or this proves nothing"
        );
        replacement.created_at = seeded.created_at + chrono::Duration::hours(1);

        let wrote =
            crate::StorageBackend::compare_and_set(&cached, &replacement, crate::Expect::Any)
                .await
                .expect("conditional write");
        assert!(
            wrote,
            "the unconditional precondition must let the write through"
        );

        let cached_read = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("cached read")
            .expect("present");
        let direct_read = crate::StorageBackend::get_by_path(&backend, path)
            .await
            .expect("direct read")
            .expect("present");

        assert_eq!(
            cached_read.id, direct_read.id,
            "the cached record's id must match storage after a conditional write"
        );
        assert_eq!(
            cached_read.created_at, direct_read.created_at,
            "the cached record's creation time must match storage"
        );
        assert_eq!(
            cached_read.id, seeded.id,
            "the normalized replacement must keep the seeded record's id"
        );
        assert_eq!(cached_read.encrypted_data, direct_read.encrypted_data);
        assert_eq!(cached_read.encrypted_data, b"v2");
    }

    fn sample_entry_with_path(path: &str, payload: &[u8]) -> SecretEntry {
        SecretEntry::new(
            path.to_string(),
            payload.to_vec(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        )
    }

    /// A backend whose conditional writes *do* change the record's id, to prove the cache
    /// retires the id the path no longer names. The shipped backends preserve the id, but the
    /// wrapper must not depend on that.
    #[derive(Debug)]
    struct RewritesIdBackend {
        inner: crate::backends::MemoryBackend,
    }

    #[async_trait::async_trait]
    impl crate::StorageBackend for RewritesIdBackend {
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
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: crate::Expect<'_>,
        ) -> StorageResult<bool> {
            // Deliberately *do not* normalize the id: write exactly the caller's record.
            //
            // `AbsentFenced` reports an occupied path as an error, not `Ok(false)`, so a
            // caller can tell "someone else already took this name" from "my lease is gone".
            // The check runs before the fence for the same reason as the memory backend.
            if let crate::Expect::AbsentFenced(_) = expect
                && self.inner.get_by_path(&entry.path).await?.is_some()
            {
                return Err(crate::StorageError::Duplicate {
                    resource_type: "SecretEntry".to_string(),
                    id: entry.path.clone(),
                });
            }
            let held = match expect {
                crate::Expect::Absent => self.inner.get_by_path(&entry.path).await?.is_none(),
                crate::Expect::AbsentFenced(fence) => self
                    .inner
                    .get_by_path(fence.path)
                    .await?
                    .is_some_and(|e| e.has_owner(fence.token)),
                crate::Expect::Owner(token) => self
                    .inner
                    .get_by_path(&entry.path)
                    .await?
                    .is_some_and(|e| e.has_owner(token)),
                crate::Expect::Any => true,
            };
            if !held {
                return Ok(false);
            }
            self.inner.delete_by_path(&entry.path).await?;
            self.inner.store(entry).await?;
            Ok(true)
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: crate::StorageFence<'_>,
        ) -> StorageResult<bool> {
            let holds = self
                .inner
                .get_by_path(fence.path)
                .await?
                .is_some_and(|e| e.has_owner(fence.token));
            if !holds {
                return Ok(false);
            }
            // Again, the caller's id is written as-is.
            self.inner.delete_by_path(&entry.path).await?;
            self.inner.store(entry).await?;
            Ok(true)
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            self.inner.delete_owned(path, token).await
        }
        async fn list(&self, params: &crate::QueryParams) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &crate::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<crate::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<crate::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
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

    /// A backend whose `compare_and_set` commits, then makes the *next* `get_by_path` fail,
    /// so the cache wrapper's canonical readback cannot complete. Reproduces a transient
    /// backend read fault immediately after a successful conditional write.
    #[derive(Debug)]
    struct ReadbackFailsAfterConditionalWriteBackend {
        inner: crate::backends::MemoryBackend,
        fail_next_get_by_path: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl crate::StorageBackend for ReadbackFailsAfterConditionalWriteBackend {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            if self
                .fail_next_get_by_path
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(crate::StorageError::BackendError {
                    backend: "test".to_string(),
                    message: "transient readback failure".to_string(),
                });
            }
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
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: crate::Expect<'_>,
        ) -> StorageResult<bool> {
            let written = self.inner.compare_and_set(entry, expect).await?;
            if written {
                self.fail_next_get_by_path
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(written)
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: crate::StorageFence<'_>,
        ) -> StorageResult<bool> {
            let written = self.inner.store_fenced(entry, fence).await?;
            if written {
                self.fail_next_get_by_path
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(written)
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            self.inner.delete_owned(path, token).await
        }
        async fn list(&self, params: &crate::QueryParams) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &crate::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<crate::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<crate::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
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
    async fn a_failed_readback_after_a_conditional_write_does_not_serve_the_stale_record() {
        // Regression: after `compare_and_set` succeeded but its canonical readback failed,
        // the wrapper returned early on the `?` and left the pre-write record cached under
        // the path key. A later `get_by_path` then served that superseded value from cache
        // rather than reporting the record the backend actually holds.
        //
        // The property: once the conditional write has committed, a cached read must never
        // return the pre-write record — the failed readback invalidates the key, so the next
        // read misses and re-reads the canonical record.
        let backend = ReadbackFailsAfterConditionalWriteBackend {
            inner: crate::backends::MemoryBackend::new(),
            fail_next_get_by_path: std::sync::atomic::AtomicBool::new(false),
        };
        let cached = CachedStorage::new(backend, InMemoryCache::new(), Duration::from_secs(300));
        let path = "kv/readback/target";

        let seeded = sample_entry_with_path(path, b"v1");
        crate::StorageBackend::store(&cached, &seeded)
            .await
            .expect("seed");
        // Warm the cache under the path so the stale entry exists to be served.
        assert_eq!(
            crate::StorageBackend::get_by_path(&cached, path)
                .await
                .expect("warm the cache")
                .expect("seeded")
                .encrypted_data,
            b"v1"
        );

        let replacement = sample_entry_with_path(path, b"v2");
        let result =
            crate::StorageBackend::compare_and_set(&cached, &replacement, crate::Expect::Any).await;
        assert!(
            result.is_err(),
            "the canonical readback failed, so the call must report an error"
        );

        let read = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("cached read")
            .expect("the committed record is present");
        assert_eq!(
            read.encrypted_data, b"v2",
            "the cache must not keep serving the pre-write record after a committed write"
        );
    }

    #[tokio::test]
    async fn a_conditional_write_that_changes_the_id_retires_the_old_cached_id() {
        // Regression: after a conditional write that landed under a new id, the cache kept
        // the superseded record under `entry:id:<old>`. `get_by_id(old_id)` then answered from
        // cache with a record that no longer exists in storage — a stale hit that survives
        // until the TTL expires.
        //
        // The property: a cached `get_by_id(old_id)` after a fenced write that replaced the id
        // returns None, matching the backend.
        let backend = RewritesIdBackend {
            inner: crate::backends::MemoryBackend::new(),
        };
        let cached = CachedStorage::new(backend, InMemoryCache::new(), Duration::from_secs(300));

        let lease = "lease/init";
        let owner = "owner-token";
        crate::StorageBackend::store(
            &cached,
            &sample_entry_with_path(lease, b"lease").owned_by(owner),
        )
        .await
        .expect("lease");

        let old = sample_entry_with_path("artifact/root", b"v1");
        let old_id = old.id;
        crate::StorageBackend::store(&cached, &old)
            .await
            .expect("seed");
        // Warm the cache under the old id so the stale entry exists to be missed.
        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("warm")
                .is_some()
        );

        let mut fresh = sample_entry_with_path("artifact/root", b"v2");
        fresh.id = Uuid::new_v4();
        assert_ne!(fresh.id, old_id);
        let wrote = crate::StorageBackend::store_fenced(
            &cached,
            &fresh,
            crate::StorageFence::new(lease, owner),
        )
        .await
        .expect("fenced write");
        assert!(wrote, "the fence must allow the write");

        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("cached read")
                .is_none(),
            "the superseded id must not be served from cache after a fenced write changed it"
        );
        assert!(
            crate::StorageBackend::get_by_id(&cached, fresh.id)
                .await
                .expect("cached read")
                .is_some(),
            "the new id must be readable"
        );
    }
}
