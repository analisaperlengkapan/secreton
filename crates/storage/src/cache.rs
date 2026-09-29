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

/// Cached storage wrapper that adds caching to any storage backend.
///
/// The inner backend and cache live behind `Arc` so a transaction opened by this wrapper can
/// hold a handle to both and reconcile the cache when it commits. `S` and `C` are cloneable
/// (`MemoryBackend` clones share state; cache handles clone their map), so an alternative
/// would be to clone them, but an `Arc` makes clear that the transaction and the wrapper
/// address the same store and the same cache.
#[derive(Debug)]
pub struct CachedStorage<S: crate::StorageBackend + 'static, C: CacheBackend + 'static> {
    storage: std::sync::Arc<S>,
    cache: std::sync::Arc<C>,
    default_ttl: Duration,
}

impl<S, C> CachedStorage<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    pub fn new(storage: S, cache: C, default_ttl: Duration) -> Self {
        Self {
            storage: std::sync::Arc::new(storage),
            cache: std::sync::Arc::new(cache),
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

/// A transaction that keeps the cache coherent with what the wrapped transaction commits.
///
/// [`CachedStorage::begin_transaction`] previously returned the inner transaction directly,
/// so a committed write or delete never touched the cache. A delete committed through a
/// transaction left the path and id keys holding the record, and `get_by_path`/`get_by_id`
/// kept serving a secret the backend had removed until its TTL expired — a deleted secret
/// still readable. A store committed through a transaction left the pre-transaction record
/// cached under the path key.
///
/// The wrapper exists because the cache wrapper's own surface (`store`/`delete_by_path`/…)
/// is bypassed entirely by a transaction: the caller drives the inner transaction, so the
/// reconciliation has to happen inside the commit. It records which paths and ids the
/// transaction touched, then, only after the inner commit has succeeded, re-reads each
/// touched path from the backend and caches the canonical record (or clears the key when
/// the record is gone). A staged write that has not committed is deliberately invisible,
/// because a rolled-back transaction must publish nothing.
#[derive(Debug)]
struct CachedTransaction<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    storage: std::sync::Arc<S>,
    cache: std::sync::Arc<C>,
    default_ttl: Duration,
    inner: Box<dyn crate::StorageTransaction>,
    /// Paths the transaction wrote or deleted from, plus the ids it wrote or removed.
    touched_paths: Vec<String>,
    touched_ids: Vec<Uuid>,
    /// The latest path each id was given by a staged write in this transaction. A delete
    /// resolves the id's path from here first: the committed record may still name the id's
    /// *previous* path, and reconciling only that path would leave the path the staged write
    /// installed cached after the delete.
    staged_paths: std::collections::HashMap<Uuid, String>,
}

impl<S, C> CachedTransaction<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    /// Note the id a stored path names *now*, before the staged write replaces it.
    ///
    /// A `store` at an occupied path replaces the record there, and the backends keep the
    /// path resolving to the new id. The displaced id is no longer reachable by path, but its
    /// id cache key survives unless it is retired, and `get_by_id(old_id)` keeps serving the
    /// superseded record from cache until its TTL expires. Recording it here puts it through
    /// the same commit-time reconciliation as an id the transaction itself removed: the id is
    /// kept only if the backend still has it.
    async fn record_displaced_id(&mut self, entry: &SecretEntry) {
        let previous = self.storage.get_by_path(&entry.path).await.ok().flatten();
        if let Some(previous) = previous
            && previous.id != entry.id
        {
            self.touched_ids.push(previous.id);
        }
    }

    /// Note the path an id currently names in the backend, before a staged write moves it.
    ///
    /// A `store` or `update` of an existing id at a *new* path is a relocation: the backend
    /// then resolves the id only at the new path, but the old path's cache key survives unless
    /// it is reconciled. Recording the source path here makes the commit clear it (the path is
    /// re-read from the backend and cached, or, absent, dropped) so a cached lookup at the
    /// former path cannot keep serving the relocated record until its TTL expires. The id's
    /// *current* path is read from the backend, not from the cache, so a relocation this
    /// wrapper did not observe is still caught.
    async fn record_relocated_path(&mut self, entry: &SecretEntry) {
        if let Ok(Some(previous)) = self.storage.get_by_id(entry.id).await
            && !previous.path.is_empty()
            && previous.path != entry.path
        {
            self.touched_paths.push(previous.path);
        }
    }
}

#[async_trait]
impl<S, C> crate::StorageTransaction for CachedTransaction<S, C>
where
    S: crate::StorageBackend + 'static,
    C: CacheBackend + 'static,
{
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.record_displaced_id(entry).await;
        self.record_relocated_path(entry).await;
        self.inner.store(entry).await?;
        self.staged_paths.insert(entry.id, entry.path.clone());
        self.touched_paths.push(entry.path.clone());
        self.touched_ids.push(entry.id);
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.record_displaced_id(entry).await;
        self.record_relocated_path(entry).await;
        self.inner.update(entry).await?;
        self.staged_paths.insert(entry.id, entry.path.clone());
        self.touched_paths.push(entry.path.clone());
        self.touched_ids.push(entry.id);
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        // Resolve every path this id can currently be reached through, *before* the delete:
        // after the commit the record is gone and the path cannot be recovered.
        //
        // The backend is the authority, not the cache's id key. That key can name a path an
        // earlier relocation moved the id away from — a write this wrapper did not observe,
        // or one whose readback failed — and reconciling only that path would leave the path
        // the record actually occupies cached after the delete, so `get_by_path` kept serving
        // the removed secret until its TTL expired. A write staged in this same transaction
        // is newer still: the backend has not seen it, so it names the id's previous path.
        let mut paths: Vec<String> = Vec::new();
        if let Some(staged) = self.staged_paths.get(&id) {
            paths.push(staged.clone());
        }
        if let Some(backend_path) = self
            .storage
            .get_by_id(id)
            .await
            .ok()
            .flatten()
            .map(|entry| entry.path)
            && !paths.contains(&backend_path)
        {
            paths.push(backend_path);
        }
        if paths.is_empty()
            && let Ok(Some(bytes)) = self
                .cache
                .get(&CachedStorage::<S, C>::cache_key_for_id(id))
                .await
            && let Ok(entry) = postcard::from_bytes::<SecretEntry>(&bytes)
            && !entry.path.is_empty()
        {
            paths.push(entry.path);
        }

        let removed = self.inner.delete(id).await?;
        self.touched_paths.extend(paths);
        self.touched_ids.push(id);
        Ok(removed)
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        let CachedTransaction {
            storage,
            cache,
            default_ttl,
            touched_paths,
            touched_ids,
            staged_paths: _,
            inner,
        } = *self;

        // The inner transaction publishes everything or nothing; the cache is reconciled
        // only once it has actually committed.
        inner.commit().await?;

        for path in &touched_paths {
            let key = CachedStorage::<S, C>::cache_key_for_path(path);
            match storage.get_by_path(path).await {
                Ok(Some(canonical)) => {
                    let serialized = postcard::to_stdvec(&canonical).unwrap_or_default();
                    let _ = cache
                        .set(
                            &CachedStorage::<S, C>::cache_key_for_id(canonical.id),
                            serialized.clone(),
                            Some(default_ttl),
                        )
                        .await;
                    let _ = cache.set(&key, serialized, Some(default_ttl)).await;
                }
                // Absent, or unreadable: clear the key so the next read misses and goes to
                // the backend rather than serving a record that may have been removed.
                Ok(None) | Err(_) => {
                    let _ = cache.delete(&key).await;
                }
            }
        }
        for id in &touched_ids {
            // Reconcile each touched id against the backend as the authority, rather than
            // assuming the path loop above refreshed it.
            //
            // The path loop refreshes an id key only when the *path* readback succeeds. If that
            // read fails after a committed update, the path key is cleared but the id key kept
            // the pre-write value, and `get_by_id` then served the stale record until its TTL
            // expired — a committed update invisible through half the API. A `get_by_id` that
            // succeeds must refresh the id key with the canonical record; an absent record or a
            // failed read must drop it, so the next read misses and goes to the backend.
            match storage.get_by_id(*id).await {
                Ok(Some(canonical)) => {
                    let serialized = postcard::to_stdvec(&canonical).unwrap_or_default();
                    let _ = cache
                        .set(
                            &CachedStorage::<S, C>::cache_key_for_id(*id),
                            serialized,
                            Some(default_ttl),
                        )
                        .await;
                }
                Ok(None) | Err(_) => {
                    let _ = cache
                        .delete(&CachedStorage::<S, C>::cache_key_for_id(*id))
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        // Nothing committed, so nothing was published to the cache; the inner transaction
        // discards its buffer.
        let CachedTransaction { inner, .. } = *self;
        inner.rollback().await
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
        // Read both identities the update can retire, before the write: the record this id
        // currently resolves to (an update may move it to a new path), and the record the
        // destination path currently names (an update may replace it with a different id).
        // Without this, a warmed id key survives `get_by_id` after the backend has retired
        // the id, and `get_by_id` keeps serving the retired secret until its TTL expires.
        let previous_by_id = self.storage.get_by_id(entry.id).await.ok().flatten();
        let previous_at_path = self.storage.get_by_path(&entry.path).await.ok().flatten();

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
            if let Some(previous) = &previous_by_id
                && previous.path != entry.path
            {
                // The id moved: the path it used to occupy must not keep resolving it.
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_path(&previous.path))
                    .await;
            }
            if let Some(previous) = &previous_at_path
                && previous.id != entry.id
            {
                // The destination path now names a different id: retire the superseded id
                // so a cached `get_by_id` cannot return the record the backend dropped.
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_id(previous.id))
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
            match self.storage.get_by_path(&entry.path).await {
                Ok(canonical) => {
                    self.cache_after_conditional_write(&entry.path, previous.as_ref(), canonical)
                        .await;
                }
                Err(_) => {
                    // The write landed; only the immediate readback failed. The cache is
                    // retired so a later read cannot serve the pre-write record, but the
                    // result stays `Ok(true)`: the conditional write committed, and reporting
                    // an error here would tell the caller a durable write failed. Registration
                    // would refuse an account that exists, and initialization would leave its
                    // lease held until expiry, both over a read that the next request repeats.
                    self.invalidate_after_failed_readback(&entry.path, previous.as_ref())
                        .await;
                }
            }
        } else {
            // The inner write did not happen. A stale positive cache entry for this path
            // would make a subsequent read report a record the backend may not have — and
            // the id key matters too: when several wrappers share storage, a replacement
            // this call *lost* to can have displaced the record the path named, so
            // `get_by_id` would otherwise keep serving the superseded entry until its TTL
            // expires. Retire both the path and the id it previously resolved to.
            let _ = self
                .cache
                .delete(&Self::cache_key_for_path(&entry.path))
                .await;
            if let Some(previous) = previous.as_ref() {
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_id(previous.id))
                    .await;
            }
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
            match self.storage.get_by_path(&entry.path).await {
                Ok(canonical) => {
                    self.cache_after_conditional_write(&entry.path, previous.as_ref(), canonical)
                        .await;
                }
                Err(_) => {
                    // Same contract as `compare_and_set`: the fenced write committed, only the
                    // readback failed. Retire the cached keys so no later read reports the
                    // superseded record, but keep the success result — the write is durable,
                    // and turning the readback failure into an error would report it as lost.
                    self.invalidate_after_failed_readback(&entry.path, previous.as_ref())
                        .await;
                }
            }
        } else {
            // The fence did not hold, so nothing was written. Clear both the path key and the
            // id the path previously resolved to: another writer that took the fence can have
            // replaced the record under a new id, and the old id key would otherwise keep
            // serving the displaced record through `get_by_id` until its TTL expires. This is
            // the same two-key retirement `compare_and_set` does on a lost race.
            let _ = self
                .cache
                .delete(&Self::cache_key_for_path(&entry.path))
                .await;
            if let Some(previous) = previous.as_ref() {
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_id(previous.id))
                    .await;
            }
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
        // Wrap the backend transaction so the cache is reconciled when it commits. Returning
        // the inner transaction directly is what let a committed delete leave a cached secret
        // readable.
        let inner = self.storage.begin_transaction().await?;
        Ok(Box::new(CachedTransaction {
            storage: std::sync::Arc::clone(&self.storage),
            cache: std::sync::Arc::clone(&self.cache),
            default_ttl: self.default_ttl,
            inner,
            touched_paths: Vec::new(),
            touched_ids: Vec::new(),
            staged_paths: std::collections::HashMap::new(),
        }))
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
        // The readback failure also must not turn the committed write into a reported error:
        // the caller would refuse an account that exists or hold an initialization lease it
        // had already released. So the call is `Ok(true)`.
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
            result.expect("the committed write must still be reported as success"),
            "the conditional write committed, so the readback failure must not turn it into a failure"
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
    async fn a_failed_readback_after_a_fenced_write_does_not_serve_the_stale_record() {
        // Regression: `store_fenced` had the same failure path as `compare_and_set` — a
        // committed fenced write whose canonical readback then failed returned early on `?`
        // and left the pre-write record cached under the path key, so a later read served a
        // value the backend no longer held. The readback failure must invalidate the key.
        let backend = ReadbackFailsAfterConditionalWriteBackend {
            inner: crate::backends::MemoryBackend::new(),
            fail_next_get_by_path: std::sync::atomic::AtomicBool::new(false),
        };
        let cached = CachedStorage::new(backend, InMemoryCache::new(), Duration::from_secs(300));

        let lease = "lease/init";
        let owner = "owner-token";
        crate::StorageBackend::store(
            &cached,
            &sample_entry_with_path(lease, b"lease")
                .owned_by(owner)
                .add_metadata(
                    crate::LEASE_EXPIRES_AT_KEY.to_string(),
                    (chrono::Utc::now().timestamp() + 300).to_string(),
                ),
        )
        .await
        .expect("lease");

        let path = "kv/fenced/target";
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
        let result = crate::StorageBackend::store_fenced(
            &cached,
            &replacement,
            crate::StorageFence::new(lease, owner),
        )
        .await;
        assert!(
            result.expect("the committed fenced write must still be reported as success"),
            "the fenced write committed, so the readback failure must not turn it into a failure"
        );

        let read = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("cached read")
            .expect("the committed record is present");
        assert_eq!(
            read.encrypted_data, b"v2",
            "the cache must not keep serving the pre-write record after a committed fenced write"
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
            &sample_entry_with_path(lease, b"lease")
                .owned_by(owner)
                .add_metadata(
                    crate::LEASE_EXPIRES_AT_KEY.to_string(),
                    (chrono::Utc::now().timestamp() + 300).to_string(),
                ),
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

    #[tokio::test]
    async fn a_transaction_commit_retires_the_cached_deleted_secret() {
        // Regression: `begin_transaction` returned the inner backend's transaction, so a
        // delete committed through it never touched the cache. The path and id keys kept the
        // record, and `get_by_path`/`get_by_id` served a secret the backend had removed until
        // the TTL expired — a deleted secret still readable.
        //
        // The property: after a transaction delete commits, neither a path nor an id read
        // returns the removed record.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/tx/delete-me";

        let entry = sample_entry_with_path(path, b"payload");
        let id = entry.id;
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        // Warm both keys, so a stale hit is what the test observes.
        assert!(
            crate::StorageBackend::get_by_path(&cached, path)
                .await
                .expect("warm path")
                .is_some()
        );
        assert!(
            crate::StorageBackend::get_by_id(&cached, id)
                .await
                .expect("warm id")
                .is_some()
        );

        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.delete(id).await.expect("stage delete");
        tx.commit().await.expect("commit");

        assert!(
            crate::StorageBackend::get_by_path(&cached, path)
                .await
                .expect("cached read")
                .is_none(),
            "a committed transaction delete must not leave the secret readable by path"
        );
        assert!(
            crate::StorageBackend::get_by_id(&cached, id)
                .await
                .expect("cached read")
                .is_none(),
            "a committed transaction delete must not leave the secret readable by id"
        );
        // The same must hold against the backend itself, so the cache is not masking a real
        // failure to delete.
        assert!(
            crate::StorageBackend::get_by_path(&backend, path)
                .await
                .expect("backend read")
                .is_none(),
            "the backend must have removed the record"
        );
    }

    #[tokio::test]
    async fn a_transaction_rollback_leaves_the_cache_alone() {
        // The mirror of the previous test: nothing was committed, so the cache must keep
        // serving the record that is still there. A rollback that invalidated the cache would
        // just be a spurious miss, but one that *replaced* a stale cached value with nothing
        // would hide a live record.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(backend, InMemoryCache::new(), Duration::from_secs(300));
        let path = "kv/tx/rolled-back";

        let entry = sample_entry_with_path(path, b"payload");
        let id = entry.id;
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        assert!(
            crate::StorageBackend::get_by_path(&cached, path)
                .await
                .expect("warm")
                .is_some()
        );

        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.delete(id).await.expect("stage delete");
        tx.rollback().await.expect("rollback");

        let read = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("cached read")
            .expect("a rolled-back transaction must leave the record readable");
        assert_eq!(read.id, id);
    }

    #[tokio::test]
    async fn a_transaction_store_refreshes_the_cached_path() {
        // Regression: a store committed through a transaction left the pre-transaction record
        // cached under the path key, so a later cached read served the superseded payload.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/tx/rewrite";

        let seeded = sample_entry_with_path(path, b"v1");
        crate::StorageBackend::store(&cached, &seeded)
            .await
            .expect("seed");
        assert_eq!(
            crate::StorageBackend::get_by_path(&cached, path)
                .await
                .expect("warm")
                .expect("seeded")
                .encrypted_data,
            b"v1"
        );

        // The transaction stages a replacement carrying a fresh id, as the backends keep the
        // existing id only for `compare_and_set`/`store_fenced`; a plain transaction store
        // writes the caller's record.
        let replacement = sample_entry_with_path(path, b"v2");
        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.store(&replacement).await.expect("stage store");
        tx.commit().await.expect("commit");

        let cached_read = crate::StorageBackend::get_by_path(&cached, path)
            .await
            .expect("cached read")
            .expect("present");
        let direct_read = crate::StorageBackend::get_by_path(&backend, path)
            .await
            .expect("direct read")
            .expect("present");
        assert_eq!(
            cached_read.encrypted_data, b"v2",
            "the cache must serve the committed transaction write, not the superseded record"
        );
        assert_eq!(
            cached_read.id, direct_read.id,
            "the cached identity must match what the backend holds after a transaction store"
        );
    }

    #[tokio::test]
    async fn a_transaction_store_retires_the_id_the_path_no_longer_names() {
        // Regression: a transaction store that replaced a path's record under a *new* id left
        // the old id's cache key holding the superseded record. `touched_ids` only carried the
        // replacement id, so the commit never reconciled the displaced id, and `get_by_id(old)`
        // kept answering from cache with a secret the backend no longer had — until its TTL
        // expired. The property: after the commit, the id the path no longer names is not
        // served by id from the cache.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/tx/replace";

        let old = sample_entry_with_path(path, b"v1");
        let old_id = old.id;
        crate::StorageBackend::store(&cached, &old)
            .await
            .expect("seed");
        // Warm the old id key, so a stale hit is what the test observes.
        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("warm id")
                .is_some()
        );

        let mut replacement = sample_entry_with_path(path, b"v2");
        replacement.id = Uuid::new_v4();
        assert_ne!(replacement.id, old_id);
        let new_id = replacement.id;

        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.store(&replacement).await.expect("stage store");
        tx.commit().await.expect("commit");

        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("cached read")
                .is_none(),
            "the id the path no longer names must not be served from cache after a transaction store"
        );
        assert!(
            crate::StorageBackend::get_by_id(&cached, new_id)
                .await
                .expect("cached read")
                .is_some(),
            "the replacement id must be readable"
        );
        assert!(
            crate::StorageBackend::get_by_id(&backend, old_id)
                .await
                .expect("backend read")
                .is_none(),
            "the backend must no longer hold the displaced record"
        );
    }

    #[tokio::test]
    async fn a_direct_update_retires_the_id_at_the_destination_path() {
        // Regression: `CachedStorage::update` refreshed the id and path keys of the record it
        // wrote but never retired the id the destination path used to name. An `update` that
        // replaces a path's record under a *new* id left the old id's cache key holding the
        // superseded record, and `get_by_id(old_id)` kept serving a secret the backend no
        // longer had until its TTL expired — a deleted secret still readable through the
        // wrapper. `store` already reconciled this; `update` did not.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/update/retire";

        let old = sample_entry_with_path(path, b"v1");
        let old_id = old.id;
        crate::StorageBackend::store(&cached, &old)
            .await
            .expect("seed");
        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("warm id")
                .is_some()
        );

        let mut replacement = sample_entry_with_path(path, b"v2");
        replacement.id = Uuid::new_v4();
        assert_ne!(replacement.id, old_id);
        crate::StorageBackend::update(&cached, &replacement)
            .await
            .expect("update");

        assert!(
            crate::StorageBackend::get_by_id(&cached, old_id)
                .await
                .expect("cached read")
                .is_none(),
            "the superseded id must not be served from cache after an update"
        );
        assert!(
            crate::StorageBackend::get_by_id(&backend, old_id)
                .await
                .expect("backend read")
                .is_none(),
            "the backend must no longer hold the superseded record"
        );
    }

    #[tokio::test]
    async fn an_update_that_relocates_an_id_clears_the_old_path_cache() {
        // The sibling of the transaction relocation test, for a direct `update`: moving an id
        // to a new path must clear the cached entry at the path it left, or that path keeps
        // answering with the relocated secret.
        let backend = RelocatingBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let old_path = "kv/update/relocate-old";
        let new_path = "kv/update/relocate-new";

        let entry = sample_entry_with_path(old_path, b"payload");
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        assert!(
            crate::StorageBackend::get_by_path(&cached, old_path)
                .await
                .expect("warm old path")
                .is_some()
        );

        let mut relocated = entry.clone();
        relocated.path = new_path.to_string();
        crate::StorageBackend::update(&cached, &relocated)
            .await
            .expect("update");

        assert!(
            crate::StorageBackend::get_by_path(&cached, new_path)
                .await
                .expect("cached read")
                .is_some(),
            "the relocated record must resolve at its new path"
        );
        assert!(
            crate::StorageBackend::get_by_path(&cached, old_path)
                .await
                .expect("cached read")
                .is_none(),
            "the former path must not keep serving the relocated record from cache"
        );
    }

    #[tokio::test]
    async fn a_transaction_delete_reconciles_the_backend_path_not_a_stale_cached_one() {
        // Regression: `CachedTransaction::delete` resolved the id's path from the cache's id
        // key, which can name a path the record no longer occupies — a relocation this
        // wrapper did not observe (another replica sharing the backend), or a cache entry
        // that outlived the record it described. It then reconciled only that path, leaving
        // the path the record actually occupies cached, so `get_by_path` kept serving the
        // deleted secret until its TTL expired. The property: the commit reconciles the path
        // the backend names, not a stale cached one.
        let backend = crate::backends::MemoryBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let old_path = "kv/tx/delete-stale-old";
        let new_path = "kv/tx/delete-stale-new";

        // Seed through the wrapper so the id key caches `old_path`.
        let entry = sample_entry_with_path(old_path, b"payload");
        let id = entry.id;
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        assert!(
            crate::StorageBackend::get_by_id(&cached, id)
                .await
                .expect("warm id")
                .is_some()
        );

        // Relocate the id in the backend without going through the wrapper, so the wrapper's
        // id key still names `old_path` while the record now names `new_path`.
        let relocated = SecretEntry {
            path: new_path.to_string(),
            ..entry.clone()
        };
        crate::StorageBackend::store(&backend, &relocated)
            .await
            .expect("relocate");
        // Warm the new path key, so a stale hit is what the test observes.
        assert!(
            crate::StorageBackend::get_by_path(&cached, new_path)
                .await
                .expect("warm")
                .is_some()
        );

        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.delete(id).await.expect("stage delete");
        tx.commit().await.expect("commit");

        assert!(
            crate::StorageBackend::get_by_path(&cached, new_path)
                .await
                .expect("cached read")
                .is_none(),
            "the path the backend names must be reconciled even when the cached id key is stale"
        );
        assert!(
            crate::StorageBackend::get_by_id(&cached, id)
                .await
                .expect("cached read")
                .is_none(),
            "the deleted id must not be readable"
        );
    }

    #[tokio::test]
    async fn a_transaction_relocation_clears_the_old_path_cache() {
        // Regression: `CachedTransaction` tracked only the destination path of a staged
        // `store`/`update`. On a backend that relocates an id — the record's `path` field
        // moves to the new path — a cached lookup at the *former* path kept returning the
        // relocated record until its TTL expired, even though the backend no longer names it
        // there. The property: after a commit that moves an id, the old path resolves to
        // nothing through the wrapper, matching the backend.
        //
        // `RelocatingBackend` makes the relocation explicit (`MemoryBackend` reconciles the
        // id index too, so the stale lookup would otherwise hit the backend and miss).
        let backend = RelocatingBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let old_path = "kv/tx/relocate-old";
        let new_path = "kv/tx/relocate-new";

        // Seed at the old path through the wrapper, then read it back so both the path key
        // (`old_path`) and the id key hold the record.
        let entry = sample_entry_with_path(old_path, b"payload");
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        assert!(
            crate::StorageBackend::get_by_path(&cached, old_path)
                .await
                .expect("warm old path")
                .is_some(),
            "the seed must be cached at the old path"
        );

        // Move the same id to a new path through a transaction.
        let mut relocated = entry.clone();
        relocated.path = new_path.to_string();
        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.store(&relocated).await.expect("stage store");
        tx.commit().await.expect("commit");

        assert!(
            crate::StorageBackend::get_by_path(&cached, new_path)
                .await
                .expect("cached read")
                .is_some(),
            "the relocated record must resolve at its new path"
        );
        assert!(
            crate::StorageBackend::get_by_path(&cached, old_path)
                .await
                .expect("cached read")
                .is_none(),
            "the former path must not keep serving the relocated record from cache"
        );
    }

    /// A backend that relocates an id: `store` of an existing id at a different path removes
    /// the record from the old path and leaves it reachable only at the new one, so a cached
    /// old-path key is the only way the former path could still answer. State is shared across
    /// clones (like `MemoryBackend`), so the wrapper and the test observe the same store.
    #[derive(Debug, Clone)]
    struct RelocatingBackend {
        data: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, SecretEntry>>>,
    }

    impl RelocatingBackend {
        fn new() -> Self {
            Self {
                data: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::StorageBackend for RelocatingBackend {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            let mut data = self.data.write().unwrap();
            // Drop any record of the same id under a different path, so the id resolves only
            // at the new path.
            data.retain(|_, record| record.id != entry.id || record.path == entry.path);
            data.insert(entry.path.clone(), entry.clone());
            Ok(())
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            let data = self.data.read().unwrap();
            Ok(data.values().find(|record| record.id == id).cloned())
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            let data = self.data.read().unwrap();
            Ok(data.get(path).cloned())
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.store(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.store(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            let mut data = self.data.write().unwrap();
            let before = data.len();
            data.retain(|_, record| record.id != id);
            Ok(data.len() < before)
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            let mut data = self.data.write().unwrap();
            Ok(data.remove(path).is_some())
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            _expect: crate::Expect<'_>,
        ) -> StorageResult<bool> {
            self.store(entry).await?;
            Ok(true)
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            _fence: crate::StorageFence<'_>,
        ) -> StorageResult<bool> {
            self.store(entry).await?;
            Ok(true)
        }
        async fn delete_owned(&self, path: &str, _token: &str) -> StorageResult<bool> {
            self.delete_by_path(path).await
        }
        async fn list(&self, params: &crate::QueryParams) -> StorageResult<Vec<SecretEntry>> {
            let data = self.data.read().unwrap();
            Ok(params.apply_to(data.values().cloned().collect()))
        }
        async fn count(&self, params: &crate::QueryParams) -> StorageResult<u64> {
            Ok(self.list(params).await?.len() as u64)
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            let data = self.data.read().unwrap();
            Ok(data.contains_key(path))
        }
        async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
            Ok(Box::new(RelocatingTransaction {
                backend: self.clone(),
                ops: Vec::new(),
            }))
        }
        async fn health_check(&self) -> StorageResult<crate::HealthStatus> {
            Ok(crate::HealthStatus {
                is_healthy: true,
                response_time_ms: 0.0,
                connections_active: 0,
                connections_idle: 0,
                last_error: None,
                uptime_seconds: 0,
            })
        }
        async fn get_stats(&self) -> StorageResult<crate::StorageStats> {
            let data = self.data.read().unwrap();
            Ok(crate::StorageStats {
                total_entries: data.len() as u64,
                total_size_bytes: 0,
                average_entry_size: 0.0,
                entries_by_security_level: std::collections::HashMap::new(),
                entries_created_today: 0,
                entries_updated_today: 0,
                expired_entries: 0,
            })
        }
        async fn migrate(&self) -> StorageResult<()> {
            Ok(())
        }
        async fn delete_expired(&self, _path_prefix: Option<String>) -> StorageResult<u64> {
            Ok(0)
        }
        async fn store_oauth_state(
            &self,
            _state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            Ok(())
        }
        async fn get_oauth_state(
            &self,
            _state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            Ok(None)
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            Ok(0)
        }
    }

    /// Buffered transaction for [`RelocatingBackend`]. `commit` applies the staged ops through
    /// the backend's relocating `store`, so a moved id is dropped from its former path.
    #[derive(Debug)]
    struct RelocatingTransaction {
        backend: RelocatingBackend,
        ops: Vec<(Uuid, SecretEntry)>,
    }

    #[async_trait::async_trait]
    impl crate::StorageTransaction for RelocatingTransaction {
        async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
            self.ops.push((entry.id, entry.clone()));
            Ok(())
        }
        async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
            self.ops.push((entry.id, entry.clone()));
            Ok(())
        }
        async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
            crate::StorageBackend::delete_by_id(&self.backend, id).await
        }
        async fn commit(self: Box<Self>) -> StorageResult<()> {
            for (_, entry) in &self.ops {
                crate::StorageBackend::store(&self.backend, entry).await?;
            }
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> StorageResult<()> {
            Ok(())
        }
    }

    /// A backend whose transaction commit succeeds, then makes the *next* `get_by_path` fail,
    /// so the cache wrapper's post-commit canonical path readback cannot complete.
    /// `MemoryBackend` leaves no stale path behind on its own, so this isolated the wrapper's
    /// id-key reconciliation.
    #[derive(Debug, Clone)]
    struct FailingPathReadbackBackend {
        inner: crate::backends::MemoryBackend,
        fail_next_get_by_path: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl FailingPathReadbackBackend {
        fn new() -> Self {
            Self {
                inner: crate::backends::MemoryBackend::new(),
                fail_next_get_by_path: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                    false,
                )),
            }
        }
    }

    #[derive(Debug)]
    struct FailingPathReadbackTransaction {
        inner: Box<dyn crate::StorageTransaction>,
        fail_next_get_by_path: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::StorageTransaction for FailingPathReadbackTransaction {
        async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete(id).await
        }
        async fn commit(self: Box<Self>) -> StorageResult<()> {
            let Self {
                inner,
                fail_next_get_by_path,
            } = *self;
            inner.commit().await?;
            // Arm the failure *after* the durable commit, so only the wrapper's post-commit
            // readback (which runs next) observes it.
            fail_next_get_by_path.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> StorageResult<()> {
            let Self { inner, .. } = *self;
            inner.rollback().await
        }
    }

    #[async_trait::async_trait]
    impl crate::StorageBackend for FailingPathReadbackBackend {
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
                    message: "transient post-commit readback failure".to_string(),
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
            self.inner.compare_and_set(entry, expect).await
        }
        async fn store_fenced(
            &self,
            entry: &SecretEntry,
            fence: crate::StorageFence<'_>,
        ) -> StorageResult<bool> {
            self.inner.store_fenced(entry, fence).await
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
            Ok(Box::new(FailingPathReadbackTransaction {
                inner: self.inner.begin_transaction().await?,
                fail_next_get_by_path: self.fail_next_get_by_path.clone(),
            }))
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
    async fn a_failed_path_readback_still_reconciles_the_touched_id() {
        // Regression: when `get_by_path` failed during commit reconciliation after a committed
        // `update`, the path loop cleared the path key but the id loop deleted the id key only
        // if the record was *absent*. The record exists with new data, so the stale pre-update
        // value stayed in the id cache and `get_by_id` served it until TTL — a committed update
        // invisible through one read path. The property: a touched id is reconciled with the
        // canonical `get_by_id` result, refreshed on success and invalidated on failure.
        let backend = FailingPathReadbackBackend::new();
        let cached = CachedStorage::new(
            backend.clone(),
            InMemoryCache::new(),
            Duration::from_secs(300),
        );
        let path = "kv/tx/readback-update";

        // Seed and warm both caches with `v1`.
        let mut entry = sample_entry_with_path(path, b"v1");
        let id = entry.id;
        crate::StorageBackend::store(&cached, &entry)
            .await
            .expect("seed");
        let warm = crate::StorageBackend::get_by_id(&cached, id)
            .await
            .expect("warm")
            .expect("present");
        assert_eq!(warm.encrypted_data, b"v1");

        // A transaction update commits `v2`, then the post-commit path readback fails. The
        // stale cached `v1` must not survive that failed readback.
        entry.encrypted_data = b"v2".to_vec();
        let mut tx = crate::StorageBackend::begin_transaction(&cached)
            .await
            .expect("begin");
        tx.update(&entry).await.expect("stage update");
        tx.commit().await.expect("commit");

        let served = crate::StorageBackend::get_by_id(&cached, id)
            .await
            .expect("cached read")
            .expect("the record must still exist");
        assert_eq!(
            served.encrypted_data, b"v2",
            "a committed update must not be masked by a stale cached id entry after a failed \
             path readback"
        );
    }
}
