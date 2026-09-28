//! Modern Redis storage backend implementation using redis v0.1.0-alpha.1

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError,
    StorageFence, StorageResult, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use secreton_domain::OAuthState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// How many times a conditional write re-reads and retries when the path's identity moved
/// between its read and the atomic script. A benign single replacement is absorbed on the
/// first retry; the bound turns a path under pathological churn into an error rather than a
/// livelock.
const CONDITIONAL_WRITE_MAX_ATTEMPTS: usize = 5;

/// Build the record a replacement should write, preserving the identity and creation time
/// the path already had — matching the memory, file and PostgreSQL backends, which all keep
/// the existing `id` and `created_at` and overwrite the rest.
fn plan_replacement(existing: &Option<SecretEntry>, entry: &SecretEntry) -> SecretEntry {
    match existing {
        Some(old) => {
            let mut updated = entry.clone();
            updated.id = old.id;
            updated.created_at = old.created_at;
            updated
        }
        None => entry.clone(),
    }
}

/// Modern Redis storage backend with connection pooling
pub struct RedisBackend {
    manager: Arc<Mutex<ConnectionManager>>,
    #[cfg(test)]
    pause: Option<Arc<crate::test_support::WritePause>>,
}

/// Redis transaction implementation using pipelines
pub struct RedisTransaction {
    manager: Arc<Mutex<ConnectionManager>>,
    operations: Vec<RedisTransactionOp>,
    committed: bool,
}

#[derive(Debug, Clone)]
enum RedisTransactionOp {
    Store(SecretEntry),
    Update(SecretEntry),
    Delete(Uuid),
}

/// The key used in place of a path key for an entry that has no path.
///
/// Lua indexes `KEYS` positionally and Redis rejects an empty key name, so the "no path"
/// case needs a real, never-written key. A `GET` of it returns nil, which is exactly how
/// the script treats "this record has no mapping".
const NO_PATH_KEY: &str = "secreton:_no_path_";

/// The Lua script a transaction commit runs, once for the *whole* operation list.
///
/// A commit previously invoked one independent script per operation, holding this process's
/// manager mutex only around each call. Two defects followed. First, a later operation that
/// failed left the earlier scripts' writes published — Redis cannot roll back a script that
/// already returned — so the transaction contract ("a failed commit publishes nothing") was
/// broken. Running every operation inside one script makes the commit one atomic unit:
/// Redis executes a script without interleaving other commands, and no error path in this
/// script occurs after a write has been applied. Second, the superseded entry key was
/// resolved from a read in Rust before the script ran and then deleted unconditionally; a
/// concurrent writer that moved the path to a new id in that window had its record deleted
/// even though it belonged elsewhere. The script now resolves the mapping itself and removes
/// the superseded record only while that record still names this path.
///
/// The delete branch removes the mapping only while it still names the id being deleted, the
/// same guard `delete_by_id` uses.
///
/// KEYS: two per operation, in order — `[path_key, entry_key]`; `path_key` is
/// [`NO_PATH_KEY`] when the entry has no path.
/// ARGV: `[1]`=operation count, then five per operation:
/// `[mode]` (`write`|`delete`), `[entry json]`, `[id]`, `[absolute expiry or '']`,
/// `[path]` (`''` for none).
const TRANSACTION_SCRIPT: &str = r"
    local n = tonumber(ARGV[1])

    local function set_maybe_expiring(key, value, expires)
        if expires ~= '' then
            local ttl = tonumber(expires) - tonumber(redis.call('TIME')[1])
            if ttl <= 0 then
                redis.call('DEL', key)
                return
            end
            redis.call('SET', key, value)
            redis.call('PEXPIRE', key, ttl * 1000)
        else
            redis.call('SET', key, value)
        end
    end

    for i = 1, n do
        local base = 2 + (i - 1) * 5
        local mode = ARGV[base]
        local value = ARGV[base + 1]
        local id = ARGV[base + 2]
        local expires = ARGV[base + 3]
        local path = ARGV[base + 4]
        local path_key = KEYS[(i - 1) * 2 + 1]
        local entry_key = KEYS[(i - 1) * 2 + 2]

        if mode == 'write' then
            -- Resolve the superseded record here, not from a pre-read the caller did. The
            -- mapping must currently name a different id for this path, and that id's record
            -- must still name this path: a record moved to another path by a concurrent
            -- writer must not be deleted out from under that path.
            local mapping = redis.call('GET', path_key)
            if mapping and mapping ~= id then
                local superseded = redis.call('GET', 'secreton:entry:' .. mapping)
                if superseded then
                    local ok, decoded = pcall(cjson.decode, superseded)
                    if ok and type(decoded) == 'table' and decoded.path == path then
                        redis.call('DEL', 'secreton:entry:' .. mapping)
                    end
                end
            end
            set_maybe_expiring(entry_key, value, expires)
            -- Guard on the path string, not the key: a pathless entry's key is the sentinel
            -- and must never be written as though it were a mapping.
            if path ~= '' then
                set_maybe_expiring(path_key, id, expires)
            end
        else
            local mapping = redis.call('GET', path_key)
            local removed = redis.call('DEL', entry_key)
            if removed > 0 and mapping == id then
                redis.call('DEL', path_key)
            end
        end
    end
    return 1
";

impl RedisTransaction {
    pub fn new(manager: Arc<Mutex<ConnectionManager>>) -> Self {
        Self {
            manager,
            operations: Vec::new(),
            committed: false,
        }
    }

    /// The key to pass as a path key for an entry that has no path.
    fn path_key_for(path: &str) -> String {
        if path.is_empty() {
            NO_PATH_KEY.to_string()
        } else {
            format!("secreton:path:{}", path)
        }
    }
}

#[async_trait]
impl StorageTransaction for RedisTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(RedisTransactionOp::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // Build the script inputs *before* any write. Serialisation and path policy run
        // client-side, so a failure here happens with nothing published; the script itself
        // has no error path after a write, which is what makes the commit all-or-nothing.
        // The operation count, the key list and the argument list are assembled together so
        // the script's positional indexing cannot drift.
        let mut conn = self.manager.lock().await;

        let script = redis::Script::new(TRANSACTION_SCRIPT);
        // Exactly two keys per operation, in the order the script indexes them:
        // `[path_key, entry_key]`. The entry key is derived from the id here rather than in
        // the script so both key names are declared to Redis (Cluster would otherwise reject
        // the in-script `secreton:entry:<id>` access) and so the positional indexing is
        // assembled in one place.
        let mut keys: Vec<String> = Vec::with_capacity(self.operations.len() * 2);
        let mut args: Vec<String> = Vec::with_capacity(1 + self.operations.len() * 5);
        args.push(self.operations.len().to_string());

        for op in &self.operations {
            match op {
                RedisTransactionOp::Store(entry) | RedisTransactionOp::Update(entry) => {
                    let value = serde_json::to_string(entry).map_err(|e| {
                        StorageError::SerializationError {
                            message: e.to_string(),
                        }
                    })?;
                    // An already-expired write must not resurrect the path: the empty deadline
                    // makes the script's TTL branch see a non-positive ttl and delete both
                    // keys.
                    let expires = entry
                        .expires_at
                        .map(|at| at.timestamp().to_string())
                        .unwrap_or_default();
                    keys.push(Self::path_key_for(&entry.path));
                    keys.push(format!("secreton:entry:{}", entry.id));
                    args.push("write".to_string());
                    args.push(value);
                    args.push(entry.id.to_string());
                    args.push(expires);
                    args.push(entry.path.clone());
                }
                RedisTransactionOp::Delete(id) => {
                    // The mapping key cannot be derived from the id alone — Redis has no
                    // index from entry to path — so read the entry to learn its path. The
                    // read is safe to do before the script: the script only uses it as a
                    // hint and re-checks the mapping against the id before removing it.
                    let entry_key = format!("secreton:entry:{}", id);
                    let stored: Option<String> =
                        conn.get(&entry_key)
                            .await
                            .map_err(|e| StorageError::QueryFailed {
                                message: format!("Failed to read entry for transaction: {}", e),
                            })?;
                    let path = stored
                        .as_deref()
                        .and_then(|json| serde_json::from_str::<SecretEntry>(json).ok())
                        .map(|entry| entry.path)
                        .unwrap_or_default();
                    keys.push(Self::path_key_for(&path));
                    keys.push(entry_key);
                    args.push("delete".to_string());
                    args.push(String::new());
                    args.push(id.to_string());
                    args.push(String::new());
                    args.push(path);
                }
            }
        }

        // One script invocation for the whole list, so every write, mapping update and
        // superseded-record removal either all happen or none do. The previous per-operation
        // invocations left earlier writes published when a later one failed.
        for key in &keys {
            script.key(key);
        }
        script.arg(args[0].clone());
        for arg in &args[1..] {
            script.arg(arg);
        }
        script
            .invoke_async::<_, i64>(&mut *conn)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to execute transaction commit: {}", e),
            })?;

        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl RedisBackend {
    /// Create a new modern Redis backend with connection pooling
    pub async fn new(connection_url: &str) -> StorageResult<Self> {
        let client = Client::open(connection_url).map_err(|e| StorageError::ConnectionFailed {
            message: format!("Invalid Redis URL: {}", e),
        })?;

        let manager =
            ConnectionManager::new(client)
                .await
                .map_err(|e| StorageError::ConnectionFailed {
                    message: format!("Failed to create Redis connection manager: {}", e),
                })?;

        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
            #[cfg(test)]
            pause: None,
        })
    }

    /// Test-only: force this backend's conditional writes to park just before their script
    /// the first time one runs, so a test can replace the path's record in the window
    /// between the read and the write. Returns the rendezvous handle.
    #[cfg(test)]
    pub(crate) fn arm_compare_and_set_pause(&mut self) -> Arc<crate::test_support::WritePause> {
        let pause = Arc::new(crate::test_support::WritePause::new());
        self.pause = Some(pause.clone());
        pause
    }

    /// Test-only: the pause for the first attempt, taken once.
    #[cfg(test)]
    async fn take_pause(&self) {
        if let Some(pause) = &self.pause {
            pause.park().await;
        }
    }

    /// Insert-if-absent that is also fenced on a still-held lease, in one script.
    ///
    /// Both preconditions and the write run server-side as one atomic unit, which is what
    /// closes the registration race: a plain `exists` check on the caller's side and a later
    /// `store` are two steps, and a concurrent ordinary registration can pass the same check
    /// in between and have its account replaced. Here the path mapping is read (KEYS[1]) and
    /// the fence record is read (KEYS[2] -> entry) inside the same script that writes, so
    /// either the path is empty and the lease still names this attempt, or nothing is written.
    ///
    /// Returns `1` written, `0` lost lease, `2` path already occupied — the occupied result
    /// is mapped to [`StorageError::Duplicate`] by the caller so "someone else registered
    /// this name" is never confused with "this attempt's lease expired".
    ///
    /// KEYS[1]=entry path key, KEYS[2]=fence path key.
    /// ARGV[1]=entry value, ARGV[2]=entry id, ARGV[3]=absolute expiry second or '',
    /// ARGV[4]=fence owner token.
    async fn compare_and_set_absent_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let entry_path_key = if entry.path.is_empty() {
            String::new()
        } else {
            format!("secreton:path:{}", entry.path)
        };
        // A pathless entry has no mapping to contend over; that is a programming error for
        // this operation rather than something to silently treat as absent.
        if entry_path_key.is_empty() {
            return Err(StorageError::Unsupported {
                operation: "compare_and_set(AbsentFenced) on a pathless entry".to_string(),
                backend: "redis".to_string(),
            });
        }

        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;
        let fence_path_key = format!("secreton:path:{}", fence.path);
        let expires = entry
            .expires_at
            .map(|at| at.timestamp().to_string())
            .unwrap_or_default();

        let script = redis::Script::new(
            r"
            local expires = ARGV[3]

            local function write(key, value)
                if expires ~= '' then
                    local ttl = tonumber(expires) - tonumber(redis.call('TIME')[1])
                    if ttl <= 0 then
                        redis.call('DEL', key)
                        return
                    end
                    redis.call('SET', key, value)
                    redis.call('PEXPIRE', key, ttl * 1000)
                else
                    redis.call('SET', key, value)
                end
            end

            -- Occupancy first: a live record at the path means another registration won,
            -- which the caller must see as a duplicate rather than a lost lease.
            if redis.call('GET', KEYS[1]) then
                return 2
            end

            -- Then the fence: the lease record must still exist and carry this token.
            local fence_id = redis.call('GET', KEYS[2])
            if not fence_id then
                return 0
            end
            local fence_entry = redis.call('GET', 'secreton:entry:' .. fence_id)
            if not fence_entry then
                return 0
            end
            local ok, decoded = pcall(cjson.decode, fence_entry)
            if not ok or type(decoded) ~= 'table' or type(decoded.metadata) ~= 'table'
                or decoded.metadata['storage_owner'] ~= ARGV[4] then
                return 0
            end

            write('secreton:entry:' .. ARGV[2], ARGV[1])
            write(KEYS[1], ARGV[2])
            return 1
            ",
        );

        let outcome: i64 = {
            let mut conn = self.manager.lock().await;
            script
                .key(&entry_path_key)
                .key(&fence_path_key)
                .arg(&value)
                .arg(entry.id.to_string())
                .arg(&expires)
                .arg(fence.token)
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to fenced insert entry: {}", e),
                })?
        };

        match outcome {
            1 => Ok(true),
            0 => Ok(false),
            2 => Err(StorageError::Duplicate {
                resource_type: "SecretEntry".to_string(),
                id: entry.path.clone(),
            }),
            other => Err(StorageError::QueryFailed {
                message: format!("fenced insert returned an unexpected outcome: {other}"),
            }),
        }
    }
}

// `redis::aio::ConnectionManager` is not `Debug`, so these are written by hand rather
// than derived. They deliberately print no connection details.
impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedisBackend")
    }
}

impl std::fmt::Debug for RedisTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisTransaction")
            .field("pending_operations", &self.operations.len())
            .finish()
    }
}

#[async_trait]
impl StorageBackend for RedisBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let key = format!("secreton:entry:{}", entry.id);
        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let mut conn = self.manager.lock().await;

        if let Some(expires_at) = entry.expires_at {
            let ttl = (expires_at - Utc::now()).num_seconds();
            if ttl > 0 {
                conn.set_ex::<_, _, ()>(&key, value, u64::try_from(ttl).unwrap_or(0))
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store entry with TTL: {}", e),
                    })?;
            } else {
                // Already expired, ensure it is removed
                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete expired entry: {}", e),
                    })?;
            }
        } else {
            conn.set::<_, _, ()>(&key, value)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to store entry: {}", e),
                })?;
        }

        // Also store path mapping
        if !entry.path.is_empty() {
            let path_key = format!("secreton:path:{}", entry.path);

            if let Some(expires_at) = entry.expires_at {
                let ttl = (expires_at - Utc::now()).num_seconds();
                if ttl > 0 {
                    conn.set_ex::<_, _, ()>(
                        &path_key,
                        entry.id.to_string(),
                        u64::try_from(ttl).unwrap_or(0),
                    )
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store path mapping with TTL: {}", e),
                    })?;
                } else {
                    conn.del::<_, ()>(&path_key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to delete expired path mapping: {}", e),
                        })?;
                }
            } else {
                conn.set::<_, _, ()>(&path_key, entry.id.to_string())
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store path mapping: {}", e),
                    })?;
            }
        }

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:entry:{}", id);
        let mut conn = self.manager.lock().await;

        let value: Option<String> =
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get entry: {}", e),
                })?;

        match value {
            Some(json_str) => {
                let entry = serde_json::from_str(&json_str).map_err(|e| {
                    StorageError::SerializationError {
                        message: e.to_string(),
                    }
                })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:path:{}", path);

        // Resolve the id and release the connection before reading the entry: `get_by_id`
        // takes the same non-reentrant lock, so holding it across that call deadlocks.
        let entry_id: Option<String> = {
            let mut conn = self.manager.lock().await;
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get path mapping: {}", e),
                })?
        };

        match entry_id {
            Some(id_str) => {
                let id =
                    Uuid::parse_str(&id_str).map_err(|e| StorageError::SerializationError {
                        message: e.to_string(),
                    })?;
                self.get_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For updates, we use the same store logic
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let entry_key = format!("secreton:entry:{}", id);
        let mut conn = self.manager.lock().await;

        // One server-side script removes the entry and the path mapping that points at it,
        // and it removes the mapping only while the mapping still resolves to this id.
        //
        // The previous implementation read the entry, deleted the entry key, and then
        // unconditionally deleted `secreton:path:<entry.path>`. If the path had been
        // rewritten between the read and the delete — a concurrent `store` or
        // `compare_and_set` publishing a replacement — that second delete removed the
        // *replacement's* mapping. The replacement's entry key survived, but nothing could
        // reach it by path any more, so it was lost while `get_by_path` reported a missing
        // record. Comparing the mapping's current value against the id being deleted is what
        // keeps a replacement reachable.
        let script = redis::Script::new(
            r"
            local mapping = redis.call('GET', KEYS[1])
            local removed = redis.call('DEL', KEYS[2])
            if removed > 0 and mapping == ARGV[1] then
                redis.call('DEL', KEYS[1])
            end
            return removed
            ",
        );

        // The path key is derived from the entry itself, which is what the mapping names,
        // so it can be computed here without a read. A record whose path is empty has no
        // mapping.
        let path_key = {
            let stored: Option<String> =
                conn.get(&entry_key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to read entry before delete: {}", e),
                    })?;
            match stored.as_deref().and_then(|json| {
                serde_json::from_str::<SecretEntry>(json)
                    .ok()
                    .map(|entry| entry.path)
            }) {
                Some(path) if !path.is_empty() => format!("secreton:path:{}", path),
                _ => String::new(),
            }
        };

        let removed: i64 = if path_key.is_empty() {
            // No mapping to consider; delete the entry alone.
            let removed: u64 =
                conn.del(&entry_key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete entry: {}", e),
                    })?;
            removed as i64
        } else {
            script
                .key(&path_key)
                .key(&entry_key)
                .arg(id.to_string())
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete entry: {}", e),
                })?
        };

        Ok(removed > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // Resolve the path to an id under the connection lock, then delete by id, so the
        // path mapping and the entry are removed together and this reports whether a
        // record was actually there.
        match self.get_by_path(path).await? {
            Some(entry) => self.delete_by_id(entry.id).await,
            None => Ok(false),
        }
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let key = format!("secreton:path:{}", path);
        let mut conn = self.manager.lock().await;
        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to check existence: {}", e),
            })?;
        Ok(exists)
    }

    fn coordination(&self) -> Coordination {
        // Redis is the shared backend in the deployments this repository actually runs, so
        // its conditional operations are `SET ... NX` and `DEL` guarded by a Lua script:
        // each is a single server-side operation that every replica observes.
        Coordination::CrossProcess
    }

    /// Conditional write as a single server-side operation.
    ///
    /// Every precondition is evaluated against the *path* mapping, because the path is the
    /// identity the caller is fencing on. Checking an entry key derived from the caller's
    /// own id would find nothing for a fresh id and report success unconditionally — which
    /// is how an insert-if-absent turns into a lock that does not lock.
    ///
    /// The record body is never re-encoded inside the script: Lua's `cjson` renders an
    /// empty table as `{}`, so a round-trip turns an empty `tags` array into a map and the
    /// entry stops deserialising. The caller hands over a fully-formed value and the script
    /// only chooses to write it or not.
    ///
    /// A replacement preserves the identity the path already had, and the *expected* id is
    /// carried into the script as a second precondition: the script writes only while the
    /// path mapping still names that id. The id is chosen in Rust from a read that happens
    /// before the script runs, so without that check a path replaced in between would let
    /// this call publish a record whose id was chosen from a stale read — resurrecting an
    /// identity that is no longer current and deleting the live record under the current
    /// id. When the mapping has moved, the script writes nothing and signals the caller
    /// (return `2`), which re-reads and rebuilds so the payload always carries the identity
    /// that is current at the instant of the write. This is why the pre-read is a *hint*
    /// that the script verifies, not an authority it trusts.
    ///
    /// `outcome` is the script's return value: `1` written, `0` precondition failed, `2`
    /// identity moved since the read.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        // `AbsentFenced` combines insert-if-absent with a lease fence, and its two failure
        // modes must be distinguishable, so it runs its own single script.
        if let crate::Expect::AbsentFenced(fence) = expect {
            return self.compare_and_set_absent_fenced(entry, fence).await;
        }

        let path_key = format!("secreton:path:{}", entry.path);

        let expected_owner = match expect {
            crate::Expect::Owner(token) => Some(token.to_string()),
            _ => None,
        };

        // KEYS[1]=path key; ARGV[1]=value, ARGV[2]=mode ("absent" | "any" | "owner"),
        // ARGV[3]=owner token (owner mode only), ARGV[4]=the id the payload was built with,
        // ARGV[5]=the os.time() at which the record expires, or '' for no expiry.
        //
        // The TTL is applied inside the script so both the entry and the path mapping carry
        // the same absolute deadline. The previous script `SET` the value with no expiry, so a
        // conditional write silently made an expiring record immortal: the caller asked for a
        // deadline, the write dropped it, and Redis would then serve a record whose own body
        // still says `expires_at` has passed. `SETEX`/`PEXPIREAT` closes that. The deadline is
        // passed as an absolute Unix second so a retry after a "moved" signal cannot shorten
        // the TTL by the time already spent.
        let script = redis::Script::new(
            r"
            local mode = ARGV[2]
            local mapping = redis.call('GET', KEYS[1])
            local expected = ARGV[4]
            local expires = ARGV[5]

            local function write(key, value)
                if expires ~= '' then
                    local ttl = tonumber(expires) - tonumber(redis.call('TIME')[1])
                    if ttl <= 0 then
                        redis.call('DEL', key)
                        return
                    end
                    redis.call('SET', key, value)
                    redis.call('PEXPIRE', key, ttl * 1000)
                else
                    redis.call('SET', key, value)
                end
            end

            if mode == 'absent' then
                if mapping then
                    return 0
                end
                write('secreton:entry:' .. expected, ARGV[1])
                write(KEYS[1], expected)
                return 1
            end

            if not mapping then
                if mode == 'owner' then
                    return 0
                end
                write('secreton:entry:' .. expected, ARGV[1])
                write(KEYS[1], expected)
                return 1
            end

            -- The mapping names an id. If the payload was built for a different one, the
            -- path has been replaced since the read: a live record under the mapped id must
            -- not be overwritten with a stale identity. A *dangling* mapping (no record
            -- under the mapped id) is not a live record and may be repaired in place.
            if mapping ~= expected then
                if redis.call('GET', 'secreton:entry:' .. mapping) then
                    return 2
                end
            end

            if mode == 'owner' then
                local current = redis.call('GET', 'secreton:entry:' .. mapping)
                if not current then
                    return 0
                end
                local ok, decoded = pcall(cjson.decode, current)
                if not ok or type(decoded) ~= 'table' or type(decoded.metadata) ~= 'table'
                    or decoded.metadata['storage_owner'] ~= ARGV[3] then
                    return 0
                end
            end

            write('secreton:entry:' .. expected, ARGV[1])
            write(KEYS[1], expected)
            -- A replacement whose identity moved off the old id leaves that id's record
            -- behind; drop it so a superseded record cannot outlive the path that named it.
            if mapping ~= expected then
                redis.call('DEL', 'secreton:entry:' .. mapping)
            end
            return 1
            ",
        );

        let mode = match expect {
            crate::Expect::Absent => "absent",
            crate::Expect::Any => "any",
            crate::Expect::Owner(_) => "owner",
            // Dispatched above; restated so the match stays exhaustive.
            crate::Expect::AbsentFenced(_) => {
                return Err(StorageError::Unsupported {
                    operation: "compare_and_set".to_string(),
                    backend: "redis".to_string(),
                });
            }
        };

        for _ in 0..CONDITIONAL_WRITE_MAX_ATTEMPTS {
            // The identity and creation time the path currently has are what the replacement
            // must keep, exactly as the memory and file backends do.
            let existing = self.get_by_path(&entry.path).await?;
            let to_write = plan_replacement(&existing, entry);

            let value =
                serde_json::to_string(&to_write).map_err(|e| StorageError::SerializationError {
                    message: e.to_string(),
                })?;

            // A test can park here to force a replacement into the read-to-script window.
            #[cfg(test)]
            self.take_pause().await;

            // Absolute Unix-second deadline, so the entry and its mapping expire together and
            // a retry after a "moved" signal cannot shorten the TTL by the elapsed time.
            let expires_at = to_write
                .expires_at
                .map(|at| at.timestamp().to_string())
                .unwrap_or_default();

            let outcome: i64 = {
                let mut conn = self.manager.lock().await;
                script
                    .key(&path_key)
                    .arg(&value)
                    .arg(mode)
                    .arg(expected_owner.as_deref().unwrap_or_default())
                    .arg(to_write.id.to_string())
                    .arg(&expires_at)
                    .invoke_async(&mut *conn)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to compare-and-set entry: {}", e),
                    })?
            };

            match outcome {
                1 => return Ok(true),
                0 => return Ok(false),
                // The path's identity moved between the read and the script. Re-read and
                // rebuild so the payload matches the record that is current at the write.
                2 => continue,
                other => {
                    return Err(StorageError::QueryFailed {
                        message: format!("compare-and-set returned an unexpected outcome: {other}"),
                    });
                }
            }
        }

        Err(StorageError::QueryFailed {
            message: "the record at this path is being replaced too rapidly to \
                      conditionally write it"
                .to_string(),
        })
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let path_key = format!("secreton:path:{}", path);
        let mut conn = self.manager.lock().await;

        // KEYS[1]=path key; ARGV[1]=owner token. Resolves the id, verifies ownership, and
        // deletes both the entry and the mapping in one script.
        let script = redis::Script::new(
            r"
            local id = redis.call('GET', KEYS[1])
            if not id then
                return 0
            end
            local entry_key = 'secreton:entry:' .. id
            local current = redis.call('GET', entry_key)
            if not current then
                return 0
            end
            local ok, decoded = pcall(cjson.decode, current)
            if not ok or not decoded.metadata or decoded.metadata['storage_owner'] ~= ARGV[1] then
                return 0
            end
            redis.call('DEL', entry_key)
            redis.call('DEL', KEYS[1])
            return 1
            ",
        );

        let removed: i64 = script
            .key(&path_key)
            .arg(token)
            .invoke_async(&mut *conn)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete owned entry: {}", e),
            })?;

        Ok(removed == 1)
    }

    /// Fenced write as a single server-side script.
    ///
    /// The fence record and the artifact are two different keys, and Redis runs a Lua
    /// script as one atomic unit, so the `GET` of the fence and the two `SET`s of the write
    /// are indivisible: no other client can take the lease over between them. That is what
    /// the previous `store` could not do — it unconditionally repointed
    /// `secreton:path:<artifact>` at the writer's own id, so a holder that had lost the
    /// lease still overwrote the winning initialization's path mapping and made the
    /// winner's returned shares stop opening the stored root key.
    ///
    /// `KEYS[1]`=fence path key, `KEYS[2]`=artifact path key.
    /// `ARGV[1]`=fence token, `ARGV[2]`=artifact value, `ARGV[3]`=artifact write id,
    /// `ARGV[4]`=artifact absolute expiry (Unix seconds) or `''` for none.
    ///
    /// The expiry is applied in the script for the same reason the compare-and-set applies
    /// it there: a fenced write that `SET` the artifact with no deadline would silently make
    /// an expiring record immortal, and Redis would then serve a record whose body already
    /// says it expired.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let fence_path_key = format!("secreton:path:{}", fence.path);
        let artifact_path_key = format!("secreton:path:{}", entry.path);

        let script = redis::Script::new(
            r"
            local fence_id = redis.call('GET', KEYS[1])
            if not fence_id then
                return 0
            end
            local fence = redis.call('GET', 'secreton:entry:' .. fence_id)
            if not fence then
                return 0
            end
            local ok, decoded = pcall(cjson.decode, fence)
            if not ok or type(decoded) ~= 'table' or type(decoded.metadata) ~= 'table'
                or decoded.metadata['storage_owner'] ~= ARGV[1] then
                return 0
            end

            local expires = ARGV[4]
            local function write(key, value)
                if expires ~= '' then
                    local ttl = tonumber(expires) - tonumber(redis.call('TIME')[1])
                    if ttl <= 0 then
                        redis.call('DEL', key)
                        return
                    end
                    redis.call('SET', key, value)
                    redis.call('PEXPIRE', key, ttl * 1000)
                else
                    redis.call('SET', key, value)
                end
            end

            -- The value and the path mapping must name the same id, so the mapping never
            -- resolves to a record whose own id disagrees. A key left by the id this
            -- replaces is removed so the rewrite does not leak it.
            local existing_id = redis.call('GET', KEYS[2])
            if existing_id and existing_id ~= ARGV[3] then
                redis.call('DEL', 'secreton:entry:' .. existing_id)
            end
            write('secreton:entry:' .. ARGV[3], ARGV[2])
            write(KEYS[2], ARGV[3])
            return 1
            ",
        );

        let expires_at = entry
            .expires_at
            .map(|at| at.timestamp().to_string())
            .unwrap_or_default();

        let written: i64 = {
            let mut conn = self.manager.lock().await;
            script
                .key(&fence_path_key)
                .key(&artifact_path_key)
                .arg(fence.token)
                .arg(&value)
                .arg(entry.id.to_string())
                .arg(&expires_at)
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to fenced-store entry: {}", e),
                })?
        };

        Ok(written == 1)
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(RedisTransaction::new(self.manager.clone())))
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        // Redis holds entries keyed by id with a separate path index. Scanning keys is
        // the only way to enumerate them, and `SCAN` is the non-blocking cursor the
        // server provides for exactly this; `KEYS` would stall the whole server.
        let mut conn = self.manager.lock().await;
        let mut cursor: u64 = 0;
        let mut entries = Vec::new();

        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("secreton:entry:*")
                .arg("COUNT")
                .arg(100)
                .query_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to scan entries: {}", e),
                })?;

            for key in keys {
                let value: Option<String> =
                    conn.get(&key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to read entry during scan: {}", e),
                        })?;
                if let Some(json_str) = value
                    && let Ok(entry) = serde_json::from_str::<SecretEntry>(&json_str)
                {
                    entries.push(entry);
                }
            }

            cursor = next;
            if cursor == 0 {
                break;
            }
        }

        // An entry key is only reachable through the path mapping that names it, so an entry
        // whose path mapping now names a *different* id is superseded: a `store` that wrote a
        // fresh record at an existing path repoints the mapping but leaves the previous entry
        // key behind. Enumerating by key alone therefore reports records that `get_by_path`/
        // `get_by_id` can no longer reach — a deleted secret that `list` still shows, and a
        // `count` that grows on every update. Keep only the record each path currently
        // resolves to; entries with no path have no mapping and are kept as they are.
        let mut current = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.path.is_empty() {
                current.push(entry);
                continue;
            }
            let path_key = format!("secreton:path:{}", entry.path);
            let mapped: Option<String> =
                conn.get(&path_key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to read path mapping during scan: {}", e),
                    })?;
            if mapped.as_deref() == Some(entry.id.to_string().as_str()) {
                current.push(entry);
            }
        }

        Ok(params.apply_to(current))
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        Ok(self.list(params).await?.len() as u64)
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 0,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            total_entries: 0,
            total_size_bytes: 0,
            average_entry_size: 0.0,
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_expired(&self, _path_prefix: Option<String>) -> StorageResult<u64> {
        // Redis handles expiration automatically via TTL
        Ok(0)
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionMetadata, Expect, SecurityLevel, StorageBackend};

    fn redis_url() -> Option<String> {
        match std::env::var("SECRETON_TEST_REDIS_URL") {
            Ok(url) if !url.trim().is_empty() => Some(url),
            _ => {
                eprintln!("skipping: SECRETON_TEST_REDIS_URL is not set");
                None
            }
        }
    }

    fn entry_at(path: &str, payload: &[u8]) -> SecretEntry {
        SecretEntry::new(
            path.to_string(),
            payload.to_vec(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
    }

    /// Regression (severe): the conditional write chose the replacement's `id` from a read
    /// that happened *before* the atomic script, and the script trusted it — including a
    /// `DEL` of whatever id the path happened to name at script time. A path replaced in
    /// that window had its live record deleted and its identity overwritten by one taken
    /// from a stale read, so `get_by_path` resolved to a record other writers had already
    /// moved past.
    ///
    /// The interleaving is *forced*, not raced: the first conditional write is parked by
    /// `arm_compare_and_set_pause` after its read and before its script, a second backend
    /// replaces the path while it is parked, and only then is it released. The write must
    /// not publish its stale identity, must not delete the replacement's record, and must
    /// leave the key, the body id and the path mapping naming one consistent record.
    #[tokio::test]
    async fn a_replacement_racing_the_read_cannot_publish_a_stale_identity() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let path = format!("{namespace}/contract/raced");

        // The seed establishes the identity the racing write will read first.
        let mut writer_backend = RedisBackend::new(&url).await.expect("connect");
        let pause = writer_backend.arm_compare_and_set_pause();
        let writer_backend = Arc::new(writer_backend);

        let seeded = entry_at(&path, b"seeded");
        let seeded_id = seeded.id;
        writer_backend.store(&seeded).await.expect("seed");

        // Begin the conditional write and wait until it has read the seeded record and
        // parked, so the replacement below lands strictly inside the read-to-script window.
        let writer = {
            let backend = writer_backend.clone();
            let path = path.clone();
            tokio::spawn(async move {
                backend
                    .compare_and_set(&entry_at(&path, b"raced-payload"), Expect::Any)
                    .await
            })
        };
        pause.wait_reached().await;

        // A separate backend replaces the path with a new identity while the first write is
        // parked. This is the concurrent replacement the stale read must not clobber.
        let other = RedisBackend::new(&url).await.expect("connect");
        let winner = entry_at(&path, b"winner");
        let winner_id = winner.id;
        assert_ne!(
            winner_id, seeded_id,
            "the replacement must be a distinct record, or this proves nothing"
        );
        other.store(&winner).await.expect("concurrent replacement");

        // Release the parked write. It must detect that the path moved, re-read and rebuild,
        // so the record it publishes carries the *current* identity — never the stale one.
        pause.release();
        let outcome = writer.await.expect("task must not panic");
        assert!(
            outcome.expect("conditional write must succeed"),
            "an unconditional replacement must eventually succeed, retrying past the race"
        );

        // The live record must not have been deleted by the racing write.
        let winner_record = writer_backend
            .get_by_id(winner_id)
            .await
            .expect("read winner by id");
        assert!(
            winner_record.is_some(),
            "the path's live record must not be deleted by a write that read it stalely"
        );

        // The path must resolve to the current identity, not the one read before the race.
        let resolved = writer_backend
            .get_by_path(&path)
            .await
            .expect("read by path")
            .expect("the path must still resolve");
        assert_ne!(
            resolved.id, seeded_id,
            "the write must not republish the identity it read before the path moved"
        );
        assert_eq!(
            resolved.id, winner_id,
            "the replacement must keep the identity the path had at write time"
        );

        // No key/body id mismatch: the entry key, the body's own id and the path mapping
        // must all name the same record.
        let entry_key = format!("secreton:entry:{}", resolved.id);
        let body: SecretEntry = {
            let mut conn = writer_backend.manager.lock().await;
            let raw: String = conn.get(&entry_key).await.expect("raw entry body");
            serde_json::from_str(&raw).expect("entry body must deserialise")
        };
        assert_eq!(
            body.id, resolved.id,
            "the body's id must equal the id its key and the path mapping name"
        );
        let mapped: String = {
            let mut conn = writer_backend.manager.lock().await;
            conn.get(format!("secreton:path:{}", path))
                .await
                .expect("path mapping")
        };
        assert_eq!(
            mapped,
            resolved.id.to_string(),
            "the path mapping must name the record it resolves to"
        );

        // `get_by_path` and `get_by_id` must name the same record.
        let by_id = writer_backend
            .get_by_id(resolved.id)
            .await
            .expect("read by id")
            .expect("the resolved id must exist");
        assert_eq!(
            by_id.id, resolved.id,
            "get_by_path and get_by_id must agree on the record"
        );

        // A following delete must remain correct: it removes this record and leaves no
        // mapping behind that resolves to nothing (no orphan).
        assert!(
            writer_backend
                .delete_by_id(resolved.id)
                .await
                .expect("delete resolved id"),
            "the resolved record must be deletable"
        );
        assert!(
            writer_backend
                .get_by_path(&path)
                .await
                .expect("read after delete")
                .is_none(),
            "deleting the record must not leave a mapping that resolves to nothing"
        );
    }

    /// The owner-conditional `compare_and_set` contract against a real server, matching the
    /// PostgreSQL and in-process suites. `SealService::acquire_init_lease` takes over an
    /// expired lease through this operation; a backend that refused while it actually held
    /// would make a vault left by a dead process unrecoverable.
    #[tokio::test]
    async fn owner_conditional_replacement_is_atomic_and_fails_closed() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let path = format!("{namespace}/contract/owner-cas");
        let backend = RedisBackend::new(&url).await.expect("connect");

        // An owner precondition on an absent path must refuse and create nothing.
        assert!(
            !backend
                .compare_and_set(&entry_at(&path, b"absent"), Expect::Owner("a"))
                .await
                .expect("owner-conditional write to an absent path"),
            "an owner precondition must not be satisfied by the absence of the record"
        );
        assert!(
            backend.get_by_path(&path).await.expect("read").is_none(),
            "an owner-conditional write to an absent path must not create a record"
        );

        // The recorded owner can replace an existing record, preserving its identity.
        let seeded = entry_at(&path, b"first").owned_by("a");
        let seeded_id = seeded.id;
        assert!(
            backend
                .compare_and_set(&seeded, Expect::Absent)
                .await
                .expect("insert-if-absent")
        );
        assert!(
            backend
                .compare_and_set(
                    &entry_at(&path, b"replaced").owned_by("a"),
                    Expect::Owner("a")
                )
                .await
                .expect("owner-conditional replacement"),
            "the recorded owner must be able to replace an existing record"
        );
        let replaced = backend
            .get_by_path(&path)
            .await
            .expect("read")
            .expect("still present");
        assert_eq!(replaced.encrypted_data, b"replaced");
        assert_eq!(
            replaced.id, seeded_id,
            "a replacement must preserve the existing record's identity"
        );

        // A caller without the recorded token is refused and the record is untouched.
        assert!(
            !backend
                .compare_and_set(
                    &entry_at(&path, b"stolen").owned_by("b"),
                    Expect::Owner("b")
                )
                .await
                .expect("owner-conditional write by a non-owner"),
            "a caller that does not hold the recorded token must not replace the record"
        );
        assert_eq!(
            backend
                .get_by_path(&path)
                .await
                .expect("read")
                .expect("still present")
                .encrypted_data,
            b"replaced",
            "a refused owner-conditional write must not change the record"
        );

        backend.delete_by_id(seeded_id).await.expect("cleanup");
    }

    /// Regression: `RedisTransaction::commit` wrote only `secreton:entry:*`. The path
    /// mapping `secreton:path:*` — the only way `get_by_path`, `exists`, `list` and `count`
    /// reach a record — was never written by a transaction, so a committed store was
    /// invisible to every read that resolves by path, and a committed delete left a mapping
    /// pointing at a missing entry.
    #[tokio::test]
    async fn a_committed_transaction_writes_and_removes_the_path_mapping() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let path = format!("{namespace}/contract/transaction-mapping");
        let backend = RedisBackend::new(&url).await.expect("connect");

        // `list`/`count` are database-wide, and other tests may share this server, so scope
        // the enumeration assertions to this test's own namespace.
        let scoped = || QueryParams {
            path_prefix: Some(namespace.clone()),
            ..QueryParams::default()
        };

        // Store through a transaction, then commit.
        let stored = entry_at(&path, b"via-transaction");
        let stored_id = stored.id;
        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.store(&stored).await.expect("stage store");
        tx.commit().await.expect("commit");

        // Every path-resolving read must see it.
        let by_path = backend
            .get_by_path(&path)
            .await
            .expect("read by path")
            .expect("a committed transaction write must be reachable by path");
        assert_eq!(by_path.id, stored_id);
        assert!(
            backend.exists(&path).await.expect("exists"),
            "a committed transaction write must be reported by exists"
        );
        let listed = backend.list(&scoped()).await.expect("list");
        assert!(
            listed.iter().any(|e| e.id == stored_id),
            "a committed transaction write must appear in list"
        );
        assert_eq!(
            backend.count(&scoped()).await.expect("count"),
            1,
            "count must include the committed transaction write exactly once"
        );

        // A transaction delete must remove the mapping too, leaving nothing orphaned.
        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.delete(stored_id).await.expect("stage delete");
        tx.commit().await.expect("commit delete");

        assert!(
            backend
                .get_by_path(&path)
                .await
                .expect("read after delete")
                .is_none(),
            "a committed transaction delete must remove the path mapping"
        );
        let mapping: Option<String> = {
            let mut conn = backend.manager.lock().await;
            conn.get(format!("secreton:path:{}", path))
                .await
                .expect("read mapping")
        };
        assert!(
            mapping.is_none(),
            "a committed transaction delete must not leave an orphaned mapping"
        );
        assert_eq!(backend.count(&scoped()).await.expect("count"), 0);
    }

    /// A transaction that rewrites a path under a fresh id must supersede the previous
    /// record: repoint the mapping and drop the old entry key, so an enumeration does not
    /// report both and the old id does not resolve.
    #[tokio::test]
    async fn a_committed_transaction_rewrite_supersedes_the_previous_record() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let path = format!("{namespace}/contract/transaction-rewrite");
        let backend = RedisBackend::new(&url).await.expect("connect");

        let first = entry_at(&path, b"first");
        let first_id = first.id;
        backend.store(&first).await.expect("seed");

        let second = entry_at(&path, b"second");
        let second_id = second.id;
        assert_ne!(first_id, second_id);
        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.store(&second).await.expect("stage rewrite");
        tx.commit().await.expect("commit rewrite");

        let resolved = backend
            .get_by_path(&path)
            .await
            .expect("read by path")
            .expect("the rewrite must resolve");
        assert_eq!(
            resolved.id, second_id,
            "the path must resolve to the rewritten record"
        );
        assert!(
            backend.get_by_id(first_id).await.expect("by id").is_none(),
            "the superseded entry key must be dropped"
        );
        let scoped = QueryParams {
            path_prefix: Some(namespace.clone()),
            ..QueryParams::default()
        };
        assert_eq!(
            backend.count(&scoped).await.expect("count"),
            1,
            "the superseded record must not be counted as well"
        );
    }

    /// A single transaction that mixes operations must apply them as one unit: a store, a
    /// delete of a *different* record, and a rewrite that repoints a path. Each op is a
    /// separate script invocation, so the mapping state a later op reads must reflect what
    /// an earlier op in the same commit wrote — otherwise a rewrite deletes the wrong entry
    /// or a delete clears a mapping that has already moved on.
    #[tokio::test]
    async fn a_mixed_operation_transaction_applies_every_operation_exactly_once() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let backend = RedisBackend::new(&url).await.expect("connect");
        let scoped = || QueryParams {
            path_prefix: Some(namespace.clone()),
            ..QueryParams::default()
        };

        // Seed a record the transaction will delete, and one it will rewrite.
        let doomed_path = format!("{namespace}/mixed/doomed");
        let doomed = entry_at(&doomed_path, b"doomed");
        let doomed_id = doomed.id;
        backend.store(&doomed).await.expect("seed doomed");

        let rewritten_path = format!("{namespace}/mixed/rewritten");
        let original = entry_at(&rewritten_path, b"original");
        let original_id = original.id;
        backend.store(&original).await.expect("seed original");

        let replacement = entry_at(&rewritten_path, b"replacement");
        let replacement_id = replacement.id;
        assert_ne!(original_id, replacement_id);

        let fresh_path = format!("{namespace}/mixed/fresh");
        let fresh = entry_at(&fresh_path, b"fresh");
        let fresh_id = fresh.id;

        // One commit, three different operations.
        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.delete(doomed_id).await.expect("stage delete");
        tx.store(&replacement).await.expect("stage rewrite");
        tx.store(&fresh).await.expect("stage store");
        tx.commit().await.expect("commit mixed");

        // The delete removed exactly its record, mapping included.
        assert!(
            backend.get_by_id(doomed_id).await.expect("by id").is_none(),
            "the deleted entry key must be gone"
        );
        assert!(
            backend
                .get_by_path(&doomed_path)
                .await
                .expect("by path")
                .is_none(),
            "the deleted record's path mapping must be gone"
        );

        // The rewrite repointed the path and dropped the superseded key.
        let resolved = backend
            .get_by_path(&rewritten_path)
            .await
            .expect("by path")
            .expect("the rewrite must resolve");
        assert_eq!(resolved.id, replacement_id);
        assert!(
            backend
                .get_by_id(original_id)
                .await
                .expect("by id")
                .is_none(),
            "the superseded key must be dropped, not left for an enumeration"
        );

        // The fresh store is visible and counted.
        assert_eq!(
            backend
                .get_by_path(&fresh_path)
                .await
                .expect("by path")
                .expect("the store must resolve")
                .id,
            fresh_id
        );
        assert_eq!(
            backend.count(&scoped()).await.expect("count"),
            2,
            "only the replacement and the fresh store remain in this namespace"
        );
    }

    /// A rolled-back transaction must leave no trace, whatever mix of operations it staged.
    /// The staging is in-process, so a rollback must not have touched Redis at all — this
    /// pins that no operation is applied before commit.
    #[tokio::test]
    async fn a_rolled_back_mixed_transaction_leaves_no_trace() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let backend = RedisBackend::new(&url).await.expect("connect");

        let kept_path = format!("{namespace}/rollback/kept");
        let kept = entry_at(&kept_path, b"kept");
        let kept_id = kept.id;
        backend.store(&kept).await.expect("seed kept");

        let staged_path = format!("{namespace}/rollback/staged");
        let staged = entry_at(&staged_path, b"staged");
        let staged_id = staged.id;

        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.store(&staged).await.expect("stage store");
        tx.delete(kept_id).await.expect("stage delete");
        tx.rollback().await.expect("rollback");

        assert!(
            backend
                .get_by_path(&staged_path)
                .await
                .expect("by path")
                .is_none(),
            "a rolled-back store must not reach Redis"
        );
        assert!(
            backend.exists(&kept_path).await.expect("exists"),
            "a rolled-back delete must not remove the record"
        );
        assert_eq!(
            backend
                .get_by_path(&kept_path)
                .await
                .expect("by path")
                .expect("kept record")
                .id,
            kept_id
        );
        assert!(
            backend.get_by_id(staged_id).await.expect("by id").is_none(),
            "the staged entry key must never have been written"
        );
    }

    /// The last write to a path within one commit wins, and only the winner is reachable.
    /// A transaction may stage two rewrites of the same path; the mapping must end up
    /// pointing at the second, with neither the seed nor the intermediate record left for
    /// an enumeration to find.
    #[tokio::test]
    async fn the_last_write_to_a_path_in_one_transaction_wins() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let path = format!("{namespace}/ordering/winner");
        let backend = RedisBackend::new(&url).await.expect("connect");
        let scoped = QueryParams {
            path_prefix: Some(namespace.clone()),
            ..QueryParams::default()
        };

        let seed = entry_at(&path, b"seed");
        let seed_id = seed.id;
        backend.store(&seed).await.expect("seed");

        let first = entry_at(&path, b"first");
        let first_id = first.id;
        let second = entry_at(&path, b"second");
        let second_id = second.id;
        assert_ne!(seed_id, first_id);
        assert_ne!(first_id, second_id);

        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.store(&first).await.expect("stage first rewrite");
        tx.store(&second).await.expect("stage second rewrite");
        tx.commit().await.expect("commit");

        assert_eq!(
            backend
                .get_by_path(&path)
                .await
                .expect("by path")
                .expect("the path must resolve")
                .id,
            second_id,
            "the path must resolve to the last write in the commit"
        );
        for superseded in [seed_id, first_id] {
            assert!(
                backend
                    .get_by_id(superseded)
                    .await
                    .expect("by id")
                    .is_none(),
                "a superseded record must be dropped so it cannot surface in an enumeration"
            );
        }
        assert_eq!(
            backend.count(&scoped).await.expect("count"),
            1,
            "only the winning record may remain in this namespace"
        );
    }

    /// Deleting an id that does not exist is a no-op that reports success and leaves every
    /// live mapping untouched. A commit that errored, or that cleared a mapping it did not
    /// own, would make a caller's cleanup of an already-removed record destructive.
    #[tokio::test]
    async fn deleting_an_unknown_id_is_a_harmless_no_op() {
        let Some(url) = redis_url() else {
            return;
        };
        let namespace = format!("it/{}", Uuid::new_v4());
        let survivor_path = format!("{namespace}/noop/survivor");
        let survivor = entry_at(&survivor_path, b"survivor");
        let survivor_id = survivor.id;
        let backend = RedisBackend::new(&url).await.expect("connect");
        backend.store(&survivor).await.expect("seed");

        let mut tx = backend.begin_transaction().await.expect("begin");
        tx.delete(Uuid::new_v4())
            .await
            .expect("stage unknown delete");
        tx.commit()
            .await
            .expect("deleting an unknown id must not fail the commit");

        assert!(
            backend.exists(&survivor_path).await.expect("exists"),
            "an unrelated live record must be untouched"
        );
        assert_eq!(
            backend
                .get_by_path(&survivor_path)
                .await
                .expect("by path")
                .expect("survivor")
                .id,
            survivor_id
        );
    }
}
