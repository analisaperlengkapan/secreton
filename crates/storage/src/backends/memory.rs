//! In-memory storage backend.

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use secreton_domain::OAuthState;

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageFence,
    StorageResult, StorageStats, StorageTransaction,
};

/// In-memory storage backend.
///
/// Always compiled, with no external service required, so `cargo leptos serve`, the test
/// suite and a first-run demo all work with zero setup. State lives only for the lifetime
/// of the process — it is not a production backend.
#[derive(Debug, Clone)]
pub struct MemoryBackend {
    data: Arc<RwLock<HashMap<String, SecretEntry>>>,
    id_index: Arc<RwLock<HashMap<Uuid, String>>>,
    oauth_states: Arc<RwLock<HashMap<String, OAuthState>>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            id_index: Arc::new(RwLock::new(HashMap::new())),
            oauth_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Retire the path an id used to resolve to when a write relocates it.
///
/// `data` is keyed by path, so writing the same id at a new path otherwise leaves the
/// record under the old path: `get_by_id` follows the index to the new path, but the old
/// path still answers `get_by_path` and is enumerated by `list`, and `delete_by_id`
/// (which removes only the indexed path) then leaves the secret behind. Only a record
/// that still names `entry.id` is dropped — if another id has since taken the old path,
/// that replacement must survive. Call before the index is updated to the new path.
fn retire_moved_record(
    data: &mut HashMap<String, SecretEntry>,
    id_index: &HashMap<Uuid, String>,
    entry: &SecretEntry,
) {
    if let Some(previous_path) = id_index.get(&entry.id)
        && previous_path != &entry.path
        && data.get(previous_path).map(|record| record.id) == Some(entry.id)
    {
        data.remove(previous_path);
    }
}

#[async_trait]
impl StorageBackend for MemoryBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write();
        let mut id_index = self.id_index.write();

        // A `store` at a path that already holds a record is a replacement. The old id stops
        // being reachable through that path, so leaving its index entry behind would keep
        // `get_by_id(old_id)` resolving to the *replacement* record — the path is still
        // mapped, the id is not — and `delete_by_id(old_id)` would then delete the record
        // that replaced it. Drop the stale mapping in the same critical section.
        if let Some(old_id) = data.get(&entry.path).map(|old| old.id)
            && old_id != entry.id
        {
            id_index.remove(&old_id);
        }
        // The same id written at a new path is a relocation: drop the record it used to
        // occupy, or the old path keeps answering and `delete_by_id` cannot reach it.
        retire_moved_record(&mut data, &id_index, entry);
        id_index.insert(entry.id, entry.path.clone());
        data.insert(entry.path.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        // Lock order is `data` before `id_index`, everywhere in this file. The two locks
        // are not independent: a writer holds `data` while inserting into `id_index`, so a
        // reader that took `id_index` first could hold it while waiting for `data` and
        // deadlock against that writer. `parking_lot`'s guards block the thread rather than
        // yielding, so the cycle wedges the whole runtime instead of just this task.
        // Taking `data` first also makes the two maps read consistently: no writer can
        // commit a new `(path, id)` pair between the reads.
        let data = self.data.read();
        let id_index = self.id_index.read();
        match id_index.get(&id) {
            Some(path) => Ok(data.get(path).cloned()),
            None => Ok(None),
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let data = self.data.read();
        Ok(data.get(path).cloned())
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write();
        let Some(existing) = data.get(&entry.path).map(|existing| existing.id) else {
            return Err(StorageError::NotFound {
                resource_type: "SecretEntry".to_string(),
                id: entry.id.to_string(),
            });
        };
        let mut id_index = self.id_index.write();
        // Keep the index consistent with the record being written. `upsert` preserves the
        // id, so the common case changes nothing; a caller that did supply a different id
        // must not leave the old id resolving through this path to the new record, or
        // `get_by_id(old_id)` would report the wrong record and `delete_by_id(old_id)`
        // would remove it.
        if existing != entry.id {
            id_index.remove(&existing);
        }
        // An update that moves this id to a new path must retire the record under the old
        // path, exactly as `store` does: the index update alone leaves the stale record
        // readable by path and out of reach of `delete_by_id`.
        retire_moved_record(&mut data, &id_index, entry);
        id_index.insert(entry.id, entry.path.clone());
        data.insert(entry.path.clone(), entry.clone());
        Ok(())
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        // Both guards are taken in the file's global order (`data` then `id_index`) so the
        // lookup, the removal and the index update are one atomic step. Reading the index
        // first and releasing it would leave a window in which a concurrent writer commits
        // a new mapping for this id, and the removal would then act on a stale path.
        let mut data = self.data.write();
        let mut id_index = self.id_index.write();
        let Some(path) = id_index.get(&id).cloned() else {
            return Ok(false);
        };
        let present = data.remove(&path).is_some();
        // Drop the index entry either way: a mapping that points at no record sends the next
        // `get_by_id` to a missing path and reports the record as absent.
        id_index.remove(&id);
        Ok(present)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut data = self.data.write();
        if let Some(entry) = data.remove(path) {
            let mut id_index = self.id_index.write();
            id_index.remove(&entry.id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Atomic within this backend's own lock: the check and the write happen while the
    /// same `RwLock` write guard is held, so no other task on this instance can observe
    /// the path between them. Two `MemoryBackend`s are two separate maps, so this is
    /// in-process only by construction — which is all a process-local backend can offer.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        let mut data = self.data.write();
        let existing = data.get(&entry.path);

        // `AbsentFenced` reports an occupied path as an error, not `Ok(false)`, so a caller
        // can tell "someone else already took this name" from "my lease is gone" — both
        // must stop the write, but only the first is a duplicate. See `Expect`.
        if let crate::Expect::AbsentFenced(_) = expect
            && existing.is_some()
        {
            return Err(StorageError::Duplicate {
                resource_type: "SecretEntry".to_string(),
                id: entry.path.clone(),
            });
        }

        let holds = match expect {
            crate::Expect::Absent => existing.is_none(),
            // An expired lease is not a held lease: reject it here, under the same write
            // guard as the owner comparison, so a lapsed attempt cannot write before some
            // other attempt takes the record over.
            crate::Expect::AbsentFenced(fence) => data.get(fence.path).is_some_and(|held| {
                held.has_owner(fence.token)
                    && crate::lease_has_not_expired(held, Utc::now().timestamp())
            }),
            crate::Expect::Owner(token) => existing.is_some_and(|e| e.has_owner(token)),
            // Owner *and* deadline, evaluated under the same write guard as the replacement:
            // a renewal must not revive a lease that lapsed before this instant.
            crate::Expect::UnexpiredOwner(token) => existing.is_some_and(|e| {
                e.has_owner(token) && crate::lease_has_not_expired(e, Utc::now().timestamp())
            }),
            crate::Expect::Any => true,
        };
        if !holds {
            return Ok(false);
        }

        // A replacement keeps the existing record's id and creation time, matching
        // [`StorageBackend::upsert`]: the path is the identity that matters and callers
        // that go on to `update` are keyed by id on PostgreSQL.
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        let mut id_index = self.id_index.write();
        if let Some(old) = existing {
            let old_id = old.id;
            id_index.remove(&old_id);
        }
        // A conditional write that relocates the id must retire the record under its old
        // path, exactly as `store` does.
        retire_moved_record(&mut data, &id_index, &to_write);
        id_index.insert(to_write.id, to_write.path.clone());
        data.insert(to_write.path.clone(), to_write);
        Ok(true)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let mut data = self.data.write();
        let owned = data.get(path).is_some_and(|e| e.has_owner(token));
        if !owned {
            return Ok(false);
        }
        let entry = data.remove(path).expect("just checked present");
        self.id_index.write().remove(&entry.id);
        Ok(true)
    }

    /// Atomic within this backend's own lock, which is the whole guarantee a process-local
    /// map can offer. The fence record and the write are evaluated under the same write
    /// guard, so no task on this instance can observe the path between them and no caller
    /// whose fence token no longer matches can publish anything.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let mut data = self.data.write();
        if !data.get(fence.path).is_some_and(|e| {
            e.has_owner(fence.token) && crate::lease_has_not_expired(e, Utc::now().timestamp())
        }) {
            return Ok(false);
        }

        let existing = data.get(&entry.path).cloned();
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        let mut id_index = self.id_index.write();
        if let Some(old) = data.get(&entry.path) {
            id_index.remove(&old.id);
        }
        // A fenced write that relocates the id must retire the record under its old path,
        // exactly as `store` does.
        retire_moved_record(&mut data, &id_index, &to_write);
        id_index.insert(to_write.id, to_write.path.clone());
        data.insert(to_write.path.clone(), to_write);
        Ok(true)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let data = self.data.read();
        // Delegate the whole query contract to `QueryParams::apply_to` rather than
        // re-implementing a subset. The previous hand-rolled filter honoured only
        // `path_prefix`, `owner_id`, `include_expired` and `limit`, so `excluded_path_prefixes`,
        // `security_level`, tags, metadata filters, `sort_by`/`sort_order` and `offset` were
        // silently dropped. That is not merely an incomplete listing: the lifecycle sweep
        // passes `excluded_path_prefixes` for reserved namespaces *and* a `limit` while sorting
        // by `expires_at`, so with reserved entries counted and the ordering ignored the
        // `limit` truncated live records before the expired ones, and expired user secrets were
        // never swept.
        let entries: Vec<SecretEntry> = data.values().cloned().collect();
        Ok(params.apply_to(entries))
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let data = self.data.read();
        Ok(data.contains_key(path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(MemoryTransaction::new(self.clone())))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 3600,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let data = self.data.read();
        let total_entries = data.len() as u64;
        let total_size_bytes = data.values().map(|e| e.encrypted_data.len() as u64).sum();

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: HashMap::new(),
            entries_created_today: total_entries,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // Mock migration - nothing to do
        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn vacuum(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let now = Utc::now();
        let mut data = self.data.write();
        let mut id_index = self.id_index.write();
        let mut deleted_count = 0;

        // Collect keys to delete first to avoid borrowing issues
        let keys_to_delete: Vec<String> = data
            .iter()
            .filter(|(_, entry)| {
                let matches_prefix = if let Some(prefix) = &path_prefix {
                    entry.path.starts_with(prefix)
                } else {
                    true
                };

                let is_expired = if let Some(expires_at) = entry.expires_at {
                    expires_at < now
                } else {
                    false
                };

                matches_prefix && is_expired
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_delete {
            if let Some(entry) = data.remove(&key) {
                id_index.remove(&entry.id);
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        let mut states = self.oauth_states.write();
        states.insert(state.state.clone(), state.clone());
        Ok(())
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        let mut states = self.oauth_states.write();
        if let Some(oauth_state) = states.get(state)
            && oauth_state.expires_at < Utc::now()
        {
            states.remove(state);
            return Ok(None);
        }
        Ok(states.remove(state))
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        let mut states = self.oauth_states.write();
        let mut count = 0;
        states.retain(|_, state| {
            if state.expires_at < Utc::now() {
                count += 1;
                false
            } else {
                true
            }
        });
        Ok(count)
    }
}

/// Transaction over [`MemoryBackend`].
///
/// The previous implementation returned a transaction whose methods were all `Ok(())`
/// no-ops, so callers that wrote through `begin_transaction` silently lost every write
/// while being told it had succeeded. This buffers the operations and applies them on
/// `commit`, so a caller that commits sees its writes and a caller that rolls back
/// sees none of them.
#[derive(Debug)]
pub struct MemoryTransaction {
    backend: MemoryBackend,
    pending: Vec<PendingOp>,
}

#[derive(Debug)]
enum PendingOp {
    Store(Box<SecretEntry>),
    Update(Box<SecretEntry>),
    Delete(Uuid),
}

impl MemoryTransaction {
    fn new(backend: MemoryBackend) -> Self {
        Self {
            backend,
            pending: Vec::new(),
        }
    }
}

#[async_trait]
impl StorageTransaction for MemoryTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.pending.push(PendingOp::Store(Box::new(entry.clone())));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.pending
            .push(PendingOp::Update(Box::new(entry.clone())));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        self.pending.push(PendingOp::Delete(id));
        Ok(true)
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        // Take both write guards once and evaluate the *whole* operation list against a
        // scratch copy before publishing anything. The previous implementation applied each
        // operation through `backend.store`/`update`/`delete_by_id`, so a later operation
        // that failed — an `update` of a path that does not exist — left every earlier
        // write published while the commit reported an error, and concurrent readers could
        // observe that partial state. The transaction contract is that a failed commit
        // publishes nothing, and for an in-memory backend the only way to keep it is to
        // stage the result and swap it in once the list is known-good.
        let mut data = self.backend.data.write();
        let mut id_index = self.backend.id_index.write();

        let mut staged_data = data.clone();
        let mut staged_index = id_index.clone();

        for op in &self.pending {
            match op {
                PendingOp::Store(entry) => {
                    // A `store` replaces any record already at the path; retire the id it
                    // superseded so it no longer resolves, exactly as `store` does.
                    if let Some(old_id) = staged_data.get(&entry.path).map(|old| old.id)
                        && old_id != entry.id
                    {
                        staged_index.remove(&old_id);
                    }
                    // A relocation retires the id's former path, exactly as `store` does.
                    retire_moved_record(&mut staged_data, &staged_index, entry);
                    staged_index.insert(entry.id, entry.path.clone());
                    staged_data.insert(entry.path.clone(), entry.as_ref().clone());
                }
                PendingOp::Update(entry) => {
                    let Some(existing) = staged_data.get(&entry.path).map(|e| e.id) else {
                        return Err(StorageError::NotFound {
                            resource_type: "SecretEntry".to_string(),
                            id: entry.id.to_string(),
                        });
                    };
                    if existing != entry.id {
                        staged_index.remove(&existing);
                    }
                    // A relocation retires the id's former path, exactly as `update` does.
                    retire_moved_record(&mut staged_data, &staged_index, entry);
                    staged_index.insert(entry.id, entry.path.clone());
                    staged_data.insert(entry.path.clone(), entry.as_ref().clone());
                }
                PendingOp::Delete(id) => {
                    if let Some(path) = staged_index.remove(id) {
                        staged_data.remove(&path);
                    }
                }
            }
        }

        *data = staged_data;
        *id_index = staged_index;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        // Nothing was applied, so dropping the buffer is the rollback.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionMetadata, SecurityLevel};

    fn entry(path: &str) -> SecretEntry {
        SecretEntry::new(
            path.to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-1".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
    }

    #[tokio::test]
    async fn store_and_read_round_trip() {
        let backend = MemoryBackend::new();
        let e = entry("kv/app/db");
        backend.store(&e).await.unwrap();

        assert_eq!(
            backend.get_by_path("kv/app/db").await.unwrap().unwrap().id,
            e.id
        );
        assert_eq!(backend.get_by_id(e.id).await.unwrap().unwrap().path, e.path);
        assert!(backend.exists("kv/app/db").await.unwrap());
    }

    /// Regression: a rewrite under a fresh id must supersede the old one completely. If the
    /// stale id were left in the index, `get_by_id(old_id)` would resolve through the still
    /// mapped path to the *replacement* record, and `delete_by_id(old_id)` would delete the
    /// record that replaced it rather than reporting it absent.
    #[tokio::test]
    async fn a_rewrite_under_a_new_id_retires_the_old_id() {
        let backend = MemoryBackend::new();
        let mut first = entry("kv/app/rewritten");
        first.id = Uuid::new_v4();
        backend.store(&first).await.unwrap();

        let mut second = entry("kv/app/rewritten");
        second.id = Uuid::new_v4();
        backend.store(&second).await.unwrap();

        assert!(
            backend.get_by_id(first.id).await.unwrap().is_none(),
            "the superseded id must not resolve"
        );
        assert!(
            !backend.delete_by_id(first.id).await.unwrap(),
            "deleting the superseded id must report nothing removed, not remove its replacement"
        );
        let survivor = backend
            .get_by_id(second.id)
            .await
            .unwrap()
            .expect("the replacement must survive");
        assert_eq!(survivor.id, second.id);
    }

    /// Regression: storing the *same* id at a new path is a relocation. If the record under
    /// the old path were left behind, `get_by_path(old)` would keep serving it (and `list`
    /// would enumerate it) while `delete_by_id` removes only the indexed path — so the
    /// secret survives a delete and appears in two places.
    #[tokio::test]
    async fn storing_an_id_at_a_new_path_retires_its_old_path() {
        let backend = MemoryBackend::new();
        let mut moved = entry("kv/old");
        let id = moved.id;
        backend.store(&moved).await.unwrap();

        moved.path = "kv/new".to_string();
        backend.store(&moved).await.unwrap();

        assert_eq!(
            backend
                .get_by_id(id)
                .await
                .unwrap()
                .expect("the id must still resolve")
                .path,
            "kv/new"
        );
        assert!(
            backend.get_by_path("kv/old").await.unwrap().is_none(),
            "the old path must no longer resolve the moved record"
        );
        assert!(
            backend.delete_by_id(id).await.unwrap(),
            "delete_by_id must reach the relocated record"
        );
        assert!(
            backend.get_by_path("kv/new").await.unwrap().is_none(),
            "the relocated record must be gone after delete_by_id"
        );
    }

    /// The same relocation guard must hold for an `update`. `update` requires the destination
    /// path to exist, so a relocation here is an id updated onto a path another id occupies:
    /// the id's former path must be retired, and the displaced id must no longer resolve.
    #[tokio::test]
    async fn updating_an_id_to_a_new_path_retires_its_old_path_and_the_displaced_id() {
        let backend = MemoryBackend::new();
        let original = entry("kv/update/old");
        let id = original.id;
        backend.store(&original).await.unwrap();

        let displaced = entry("kv/update/new");
        let displaced_id = displaced.id;
        backend.store(&displaced).await.unwrap();

        let mut moved = original.clone();
        moved.path = "kv/update/new".to_string();
        backend.update(&moved).await.unwrap();

        assert!(
            backend
                .get_by_path("kv/update/old")
                .await
                .unwrap()
                .is_none(),
            "an update that relocates an id must retire the old path"
        );
        assert_eq!(
            backend
                .get_by_id(id)
                .await
                .unwrap()
                .expect("the id must still resolve")
                .path,
            "kv/update/new"
        );
        assert!(
            backend.get_by_id(displaced_id).await.unwrap().is_none(),
            "the displaced id must not resolve after the update replaced it"
        );
    }

    /// A conditional write can relocate an id too; the record under the former path must be
    /// retired rather than left behind.
    #[tokio::test]
    async fn a_conditional_write_that_relocates_an_id_retires_its_old_path() {
        let backend = MemoryBackend::new();
        let mut moved = entry("kv/cas/old");
        let id = moved.id;
        backend.store(&moved).await.unwrap();

        moved.path = "kv/cas/new".to_string();
        let wrote = backend
            .compare_and_set(&moved, crate::Expect::Any)
            .await
            .unwrap();
        assert!(wrote, "the conditional write must succeed");

        assert!(
            backend.get_by_path("kv/cas/old").await.unwrap().is_none(),
            "the old path must no longer resolve the moved record"
        );
        assert_eq!(
            backend.get_by_id(id).await.unwrap().unwrap().path,
            "kv/cas/new"
        );
    }

    #[tokio::test]
    async fn committed_transaction_writes_are_visible() {
        let backend = MemoryBackend::new();
        let e = entry("kv/tx/committed");

        let mut tx = backend.begin_transaction().await.unwrap();
        tx.store(&e).await.unwrap();
        tx.commit().await.unwrap();

        assert!(
            backend
                .get_by_path("kv/tx/committed")
                .await
                .unwrap()
                .is_some(),
            "a committed transaction must persist its writes"
        );
    }

    #[tokio::test]
    async fn rolled_back_transaction_writes_are_discarded() {
        let backend = MemoryBackend::new();
        let e = entry("kv/tx/rolled-back");

        let mut tx = backend.begin_transaction().await.unwrap();
        tx.store(&e).await.unwrap();
        tx.rollback().await.unwrap();

        assert!(
            backend
                .get_by_path("kv/tx/rolled-back")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_failed_transaction_commit_publishes_nothing() {
        // Regression: `commit` applied each buffered operation through the backend's own
        // `store`/`update`, so an operation that failed midway — here an `update` of a path
        // that does not exist — left every earlier operation published while the commit
        // reported an error. The transaction contract is all-or-nothing, so a failed commit
        // must leave the store exactly as it was.
        let backend = MemoryBackend::new();
        let stored = entry("kv/tx/staged");
        let missing = entry("kv/tx/never-existed");

        let mut tx = backend.begin_transaction().await.unwrap();
        tx.store(&stored).await.unwrap();
        // The second operation cannot succeed: nothing was ever stored at this path.
        tx.update(&missing).await.unwrap();

        let outcome = tx.commit().await;
        assert!(
            outcome.is_err(),
            "committing an update of a missing path must fail"
        );

        assert!(
            backend.get_by_path("kv/tx/staged").await.unwrap().is_none(),
            "a failed commit must not leave the earlier write published"
        );
        assert!(
            backend.get_by_id(stored.id).await.unwrap().is_none(),
            "a failed commit must not leave the earlier write reachable by id"
        );
    }

    #[tokio::test]
    async fn deleting_by_path_also_clears_the_id_index() {
        let backend = MemoryBackend::new();
        let e = entry("kv/app/gone");
        backend.store(&e).await.unwrap();

        assert!(backend.delete_by_path("kv/app/gone").await.unwrap());
        assert!(backend.get_by_id(e.id).await.unwrap().is_none());
        assert!(!backend.delete_by_path("kv/app/gone").await.unwrap());
    }

    #[tokio::test]
    async fn storing_a_new_id_at_an_existing_path_retires_the_old_id() {
        // Regression: `store` overwrote the path but left the previous id in `id_index`.
        // The stale mapping still pointed at the path, and the path now held the replacement,
        // so `get_by_id(old_id)` handed back the *replacement* record and
        // `delete_by_id(old_id)` deleted it — a caller holding the old handle could destroy
        // the record that superseded it.
        let backend = MemoryBackend::new();

        let old = entry("kv/app/current");
        backend.store(&old).await.unwrap();

        let replacement = entry("kv/app/current");
        assert_ne!(
            replacement.id, old.id,
            "ids must differ or this proves nothing"
        );
        backend.store(&replacement).await.unwrap();

        assert!(
            backend.get_by_id(old.id).await.unwrap().is_none(),
            "the superseded id must no longer resolve"
        );
        assert_eq!(
            backend.get_by_id(replacement.id).await.unwrap().unwrap().id,
            replacement.id
        );

        assert!(
            !backend.delete_by_id(old.id).await.unwrap(),
            "deleting by the superseded id must report nothing removed"
        );
        assert!(
            backend
                .get_by_path("kv/app/current")
                .await
                .unwrap()
                .is_some(),
            "the replacement record must survive a delete of the superseded id"
        );
    }

    #[tokio::test]
    async fn updating_with_a_new_id_keeps_the_index_consistent() {
        // Regression partner to the `store` case: `update` wrote the caller's record but
        // never touched `id_index`. A caller that supplied a different id left the old
        // mapping in place, so `get_by_id(old_id)` resolved through the path to the new
        // record and `delete_by_id(old_id)` removed it.
        let backend = MemoryBackend::new();

        let original = entry("kv/app/edit");
        backend.store(&original).await.unwrap();

        let mut edited = entry("kv/app/edit");
        edited.id = Uuid::new_v4();
        backend.update(&edited).await.unwrap();

        assert!(
            backend.get_by_id(original.id).await.unwrap().is_none(),
            "the retired id must not resolve to the edited record"
        );
        assert_eq!(
            backend.get_by_id(edited.id).await.unwrap().unwrap().id,
            edited.id
        );
        assert!(
            !backend.delete_by_id(original.id).await.unwrap(),
            "deleting by the retired id must remove nothing"
        );
        assert!(
            backend.get_by_path("kv/app/edit").await.unwrap().is_some(),
            "the edited record must survive"
        );
    }

    #[tokio::test]
    async fn reserved_entries_do_not_hide_an_expired_secret_from_the_lifecycle_query() {
        // Regression: `list` honoured only `path_prefix`, `owner_id`, `include_expired` and
        // `limit`. It ignored `excluded_path_prefixes` and the `expires_at` ordering, so with
        // enough reserved entries — which never expire and were counted against the limit —
        // an expired user secret never appeared in the sweep's page and was never deleted.
        use chrono::Duration;

        let backend = MemoryBackend::new();
        // More reserved entries than the limit: the old code truncated them into the page
        // and pushed the expired secret out.
        for i in 0..5 {
            let e = entry(&format!("sys/reserved/{i}"));
            backend.store(&e).await.unwrap();
        }
        let mut expired = entry("apps/expired");
        expired.expires_at = Some(Utc::now() - Duration::hours(1));
        backend.store(&expired).await.unwrap();

        let params = QueryParams {
            include_expired: true,
            limit: Some(2),
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            excluded_path_prefixes: vec!["sys/".to_string()],
            ..Default::default()
        };

        let listed = backend.list(&params).await.unwrap();
        assert!(
            listed.iter().any(|e| e.id == expired.id),
            "the expired secret must survive the limit once reserved entries are excluded; \
             got {:?}",
            listed.iter().map(|e| e.path.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn oauth_state_is_single_use_and_expires() {
        use chrono::Duration;

        let backend = MemoryBackend::new();
        let live = OAuthState {
            state: "live".into(),
            provider: "github".into(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        backend.store_oauth_state(&live).await.unwrap();

        assert!(backend.get_oauth_state("live").await.unwrap().is_some());
        assert!(
            backend.get_oauth_state("live").await.unwrap().is_none(),
            "an OAuth state must not be redeemable twice"
        );

        let stale = OAuthState {
            state: "stale".into(),
            provider: "github".into(),
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
        };
        backend.store_oauth_state(&stale).await.unwrap();
        assert!(backend.get_oauth_state("stale").await.unwrap().is_none());
    }

    /// Every operation that touches both maps must take `data` before `id_index`.
    ///
    /// `get_by_id` previously read `id_index` first and then `data`, while every writer holds
    /// `data` and then takes `id_index`. Two threads in that shape deadlock: the reader holds
    /// the index lock and waits for `data`, the writer holds `data` and waits for the index.
    /// `parking_lot` guards block the whole thread, so the runtime stalls rather than the task.
    ///
    /// The test does not race. It holds `data` itself, so a reader parked in `get_by_id` can
    /// only be blocked either before taking `id_index` (correct order) or after taking it (the
    /// inversion). It then probes whether `id_index` is held by someone else: under the
    /// inversion the reader holds it for as long as `data` is held, so the probe finds it
    /// locked; under the correct order the reader is parked on `data` and never touches the
    /// index, so the probe always succeeds. The reader runs on its own OS thread with its own
    /// runtime, so blocking it on a `parking_lot` guard cannot stall the probe.
    #[test]
    fn get_by_id_takes_data_before_id_index() {
        let backend = Arc::new(MemoryBackend::new());
        let seed = entry("kv/lock_order");
        let seed_id = seed.id;
        futures_executor_block_on(backend.store(&seed)).expect("seed the record");

        // Holding `data` pins any reader to its first lock: whichever lock `get_by_id` takes
        // first, this guard is what it blocks on next.
        let data_guard = backend.data.write();

        let reader_backend = backend.clone();
        let started = Arc::new(std::sync::Barrier::new(2));
        let reader_barrier = started.clone();
        let reader = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("reader runtime");
            // Signal readiness, then enter `get_by_id` and block on the held `data` guard.
            reader_barrier.wait();
            rt.block_on(reader_backend.get_by_id(seed_id))
        });

        // Wait until the reader is about to call `get_by_id`, then let it reach its first lock.
        started.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut inversion_detected = false;
        while std::time::Instant::now() < deadline {
            if backend.id_index.try_write().is_none() {
                inversion_detected = true;
                break;
            }
            std::thread::yield_now();
        }

        drop(data_guard);
        let _ = reader.join().expect("reader thread");

        assert!(
            !inversion_detected,
            "`get_by_id` must take `data` before `id_index`. A reader that held `id_index` \
             while waiting for `data` inverts the writers' order and deadlocks against them"
        );
    }

    /// Run a future to completion without depending on the ambient test runtime.
    fn futures_executor_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    /// A record at `path` owned by `token` whose recorded lease deadline is `expires_at`
    /// (Unix seconds).
    fn lease_entry_at(path: &str, token: &str, expires_at: i64) -> SecretEntry {
        SecretEntry::new(
            path.to_string(),
            b"lease".to_vec(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .owned_by(token)
        .add_metadata(
            crate::LEASE_EXPIRES_AT_KEY.to_string(),
            expires_at.to_string(),
        )
    }

    /// Regression: `Expect::Owner` alone let a renewal revive a lease that had already
    /// lapsed. The renewal read the record, saw it live, and then the record's deadline
    /// passed before the write; conditioning only on the token replaced it with a fresh
    /// deadline, and a replica that read the expiry in that window raced an attempt that
    /// still believed it held a live lease. `UnexpiredOwner` folds the deadline into the
    /// same atomic step, so the lapsed lease is not revived. Falsified by treating the new
    /// variant like `Owner`.
    #[tokio::test]
    async fn an_unexpired_owner_write_refuses_to_revive_a_lapsed_lease() {
        let backend = MemoryBackend::new();
        let path = "sys/init_lease";
        let lapsed_at = Utc::now().timestamp() - 1;
        let lapsed = lease_entry_at(path, "attempt-a", lapsed_at);
        backend.store(&lapsed).await.unwrap();

        let renewal = lease_entry_at(path, "attempt-a", Utc::now().timestamp() + 300);
        assert!(
            !backend
                .compare_and_set(&renewal, crate::Expect::UnexpiredOwner("attempt-a"))
                .await
                .unwrap(),
            "a renewal must not revive a lease whose deadline has already passed"
        );
        let expired_marker = lapsed_at.to_string();
        assert_eq!(
            backend
                .get_by_path(path)
                .await
                .unwrap()
                .unwrap()
                .metadata
                .get(crate::LEASE_EXPIRES_AT_KEY)
                .map(String::as_str),
            Some(expired_marker.as_str()),
            "the lapsed lease record must be left untouched, not rewritten with a fresh deadline"
        );

        // The positive control: a *live* owned lease is renewed, so the variant is not simply
        // refusing every write.
        let live = lease_entry_at(path, "attempt-b", Utc::now().timestamp() + 300);
        backend.store(&live).await.unwrap();
        assert!(
            backend
                .compare_and_set(
                    &lease_entry_at(path, "attempt-b", Utc::now().timestamp() + 600),
                    crate::Expect::UnexpiredOwner("attempt-b")
                )
                .await
                .unwrap(),
            "a live owned lease must be renewable"
        );
    }
}
