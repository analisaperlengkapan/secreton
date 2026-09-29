//! File-based storage backend implementation using JSON serialization for persistence and directory scanning for queries.
//! This backend stores each SecretEntry as a separate JSON file in the configured storage directory,
//! enabling simple file-based storage with full CRUD operations, querying, and statistics collection.

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError,
    StorageFence, StorageResult, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use secreton_domain::OAuthState;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;

/// File-based storage backend using JSON serialization
#[derive(Debug)]
pub struct FileBackend {
    storage_path: PathBuf,
    /// Test-only: a park point inside the conditional write, so a test can force a
    /// concurrent replacement into the read-to-write window.
    #[cfg(test)]
    pause: Option<std::sync::Arc<crate::test_support::WritePause>>,
}

/// RAII guard for the file backend's cross-process advisory lock; released on drop.
///
/// Holding it is what makes [`StorageBackend::compare_and_set`] and
/// [`StorageBackend::delete_owned`] indivisible between separate processes sharing one
/// storage directory: the OS lock (`flock` on Unix, `LockFileEx` on Windows) excludes
/// every other holder, not merely other tasks in this process.
#[derive(Debug)]
struct FileLock {
    file: std::fs::File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl FileBackend {
    /// Create a new file-based backend
    pub fn new(storage_path: &str) -> StorageResult<Self> {
        let path = PathBuf::from(storage_path);

        // Create directory if it doesn't exist
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| StorageError::ConfigurationError {
                message: format!(
                    "Failed to create storage directory {}: {}",
                    path.display(),
                    e
                ),
            })?;
        }

        // Verify directory is writable
        let test_file = path.join(".write_test");
        fs::write(&test_file, b"test").map_err(|e| StorageError::ConfigurationError {
            message: format!(
                "Storage directory {} is not writable: {}",
                path.display(),
                e
            ),
        })?;
        let _ = fs::remove_file(&test_file);

        Ok(Self {
            storage_path: path,
            #[cfg(test)]
            pause: None,
        })
    }

    /// Test-only: force this backend's conditional writes to park just before they publish,
    /// so a test can replace the path's record in the window between the read and the write.
    #[cfg(test)]
    pub(crate) fn arm_compare_and_set_pause(
        &mut self,
    ) -> std::sync::Arc<crate::test_support::WritePause> {
        let pause = std::sync::Arc::new(crate::test_support::WritePause::new());
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

    /// Generate file path for a secreton entry by ID
    fn entry_path(&self, id: Uuid) -> PathBuf {
        self.storage_path.join(format!("{}.json", id))
    }

    /// Read and deserialize a secreton entry from file
    fn read_entry(&self, file_path: &Path) -> StorageResult<SecretEntry> {
        let content = fs::read_to_string(file_path).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!("Failed to read entry file {}: {}", file_path.display(), e),
        })?;

        serde_json::from_str(&content).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize entry: {}", e),
        })
    }

    /// Write an entry through a unique temporary file and a rename, so a reader never
    /// observes a half-written record and two concurrent writers never collide.
    ///
    /// A plain `fs::write` truncates the destination before writing; a crash or a
    /// concurrent scanner in that window sees an empty or partial file. `rename` within a
    /// directory is atomic, which is the property [`StorageBackend::compare_and_set`]
    /// needs to be a real compare-and-set rather than a compare-and-maybe-write.
    ///
    /// The temporary file is unique per call (`create_new`, so the kernel refuses a name
    /// that already exists) rather than derived only from the destination. `store` and
    /// `update` are not serialised by the advisory lock — a conditional write is, but a
    /// plain write is deliberately last-writer-wins — so two concurrent writes to the same
    /// id with a destination-derived temporary name would otherwise write the *same*
    /// temporary file and one would rename the other's bytes into place, or fail because
    /// the file had already been moved. A unique name makes each write's temporary file
    /// private to it, and the atomic rename publishes whichever finishes last. This is
    /// last-writer semantics, the same as the memory backend's plain `store`; it is not
    /// serialisation, which only `compare_and_set`/`store_fenced` (under the lock) claim.
    async fn write_entry_atomically(
        &self,
        file_path: &Path,
        entry: &SecretEntry,
    ) -> StorageResult<()> {
        let tmp = self.stage_entry(file_path, entry)?;

        // A test can park here — after its own temporary file exists, before the rename —
        // so a concurrent writer is forced into the window rather than hoped into it.
        #[cfg(test)]
        self.take_pause().await;

        self.publish_staged_entry(&tmp, file_path)
    }

    /// Serialize `entry` into a fresh, uniquely-named temporary file beside `file_path` and
    /// return its path. The temporary file is private to this call; a failure removes it.
    fn stage_entry(&self, file_path: &Path, entry: &SecretEntry) -> StorageResult<PathBuf> {
        let content =
            serde_json::to_string_pretty(entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        let mut tmp = self.temporary_path(file_path);
        let mut file = loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
            {
                Ok(file) => break file,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Overwhelmingly unlikely (a v4 UUID), but retry rather than reuse a
                    // name another writer owns.
                    tmp = self.temporary_path(file_path);
                }
                Err(e) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!(
                            "Failed to create temporary file {}: {}",
                            tmp.display(),
                            e
                        ),
                    });
                }
            }
        };

        if let Err(e) = std::io::Write::write_all(&mut file, content.as_bytes()) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to write temporary file {}: {}", tmp.display(), e),
            });
        }
        drop(file);
        Ok(tmp)
    }

    /// Atomically publish a staged temporary file over `file_path`. On failure the staged
    /// file is removed, so a failed write leaves no debris and — because the name is unique
    /// to the staging call — never removes another writer's temporary file.
    fn publish_staged_entry(&self, tmp: &Path, file_path: &Path) -> StorageResult<()> {
        if let Err(e) = fs::rename(tmp, file_path) {
            let _ = fs::remove_file(tmp);
            return Err(StorageError::BackendError {
                backend: "File".to_string(),
                message: format!(
                    "Failed to publish entry file {}: {}",
                    file_path.display(),
                    e
                ),
            });
        }
        Ok(())
    }

    /// A temporary path in the destination's directory, unique to this call.
    ///
    /// The `rename` must stay within one directory to be atomic, so the temporary file is a
    /// sibling of the destination. The name carries the destination's file name, a v4 UUID
    /// and this process's id, so it is unique across writers and processes; the extension is
    /// deliberately not `.json`, so a concurrent [`Self::scan_entries`] does not try to read
    /// a half-written temporary file as an entry.
    fn temporary_path(&self, file_path: &Path) -> PathBuf {
        let stem = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("entry");
        file_path.with_file_name(format!(
            ".{stem}.{}-{}.tmp",
            Uuid::new_v4(),
            std::process::id()
        ))
    }

    /// Path of the advisory lock that serialises this backend's conditional operations
    /// across processes sharing the same storage directory.
    fn lock_path(&self) -> PathBuf {
        self.storage_path.join(".secreton.lock")
    }

    /// Take the backend's exclusive advisory lock, waiting for it.
    ///
    /// The wait is a bounded non-blocking retry loop rather than a blocking `lock()`: the
    /// lock is held across the read and the write of a conditional operation, both of
    /// which are already synchronous `std::fs` calls in this backend, and blocking a
    /// Tokio worker for the whole wait would stall unrelated tasks. The lock is a real OS
    /// advisory lock (`flock` on Unix, `LockFileEx` on Windows), so it excludes other
    /// processes and other `FileBackend` instances in this process, not just tasks in it.
    fn acquire_lock(&self) -> StorageResult<FileLock> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())
            .map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to open storage lock file: {}", e),
            })?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(FileLock { file }),
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: "Timed out waiting for the storage lock".to_string(),
                    });
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!("Failed to acquire storage lock: {}", e),
                    });
                }
            }
        }
    }

    /// Scan directory and collect all entries
    fn scan_entries(&self) -> StorageResult<Vec<SecretEntry>> {
        let mut entries = Vec::new();

        let read_dir =
            fs::read_dir(&self.storage_path).map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to read storage directory: {}", e),
            })?;

        for entry in read_dir {
            let entry = entry.map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to read directory entry: {}", e),
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.read_entry(&path) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        // Log error but continue scanning
                        eprintln!("Failed to read entry {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Collapse records sharing a path down to the single one a read resolves to.
    ///
    /// Entries are files keyed by id, and `store` is last-writer-wins by id, so a write that
    /// carries a fresh id for an existing path leaves the previous record's file behind.
    /// An enumeration by file would report both — a rewritten secret shown twice, and a
    /// `count` that grows on every update — while a read resolves the path to exactly one.
    /// Both the read and the enumeration now order candidates by `(updated_at, id)` and take
    /// the first, so they cannot disagree on which record a path names. The tie-break on the
    /// id exists because two writes can carry the same timestamp; without it the choice would
    /// depend on directory order and the two operations could still pick differently. A record
    /// with no path has no mapped identity and is kept as it is.
    fn collapse_to_current_paths(&self, entries: Vec<SecretEntry>) -> Vec<SecretEntry> {
        use std::collections::HashMap;

        // The id each path resolves to, by the same ordering as `get_by_path`.
        let mut current: HashMap<String, (chrono::DateTime<chrono::Utc>, Uuid)> = HashMap::new();
        for entry in &entries {
            if entry.path.is_empty() {
                continue;
            }
            let candidate = (entry.updated_at, entry.id);
            let better = match current.get(&entry.path) {
                None => true,
                Some(held) => candidate > *held,
            };
            if better {
                current.insert(entry.path.clone(), candidate);
            }
        }

        entries
            .into_iter()
            .filter(|entry| {
                entry.path.is_empty()
                    || current
                        .get(&entry.path)
                        .is_some_and(|(_, id)| *id == entry.id)
            })
            .collect()
    }
}

#[async_trait]
impl StorageBackend for FileBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        // Deliberately not serialised by the advisory lock: `store` is last-writer-wins, and
        // a plain store racing a conditional one is already covered by the conditional
        // write's own contract (see `compare_and_set`). Taking the exclusive lock here would
        // put every ordinary write behind a cross-process lock it does not need.
        let file_path = self.entry_path(entry.id);
        self.write_entry_atomically(&file_path, entry).await
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let file_path = self.entry_path(id);
        if file_path.exists() {
            match self.read_entry(&file_path) {
                Ok(entry) => Ok(Some(entry)),
                Err(_) => Ok(None), // File exists but corrupted
            }
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        // A path can have more than one record on disk: `store` is keyed by id, so a rewrite
        // that carries a fresh id leaves the previous file behind. Resolve by `(updated_at,
        // id)`, the same ordering `list` collapses with, so a read and an enumeration always
        // name the same record and neither depends on directory order.
        let entries = self.scan_entries()?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.path == path)
            .max_by(|a, b| (a.updated_at, a.id).cmp(&(b.updated_at, b.id))))
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For file backend, update is same as store (overwrite) and, like `store`, is not
        // serialised by the advisory lock; the atomic rename still makes it whole.
        let file_path = self.entry_path(entry.id);
        self.write_entry_atomically(&file_path, entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let file_path = self.entry_path(id);
        if file_path.exists() {
            match fs::remove_file(&file_path) {
                Ok(_) => Ok(true),
                Err(e) => Err(StorageError::BackendError {
                    backend: "File".to_string(),
                    message: format!("Failed to delete entry file {}: {}", file_path.display(), e),
                }),
            }
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // The read that locates the files and the unlinks that remove them happen under the
        // backend's advisory lock, so a concurrent `compare_and_set` at the same path
        // cannot publish a new record between them and have this call delete it by id.
        //
        // Every record at the path is removed, not just the first. `store` is keyed by id,
        // so a rewrite carrying a fresh id leaves the previous file behind; `get_by_path`
        // resolves the newest of them. Deleting only one left a superseded file on disk
        // that still matched the path, and the next `get_by_path` — or `list`/`count` after
        // the rewrite was superseded — reported the "deleted" secret again. Removing all
        // candidates is what makes the delete stick.
        let _guard = self.acquire_lock()?;
        let entries = self.scan_entries()?;
        let mut removed_any = false;
        for entry in entries {
            if entry.path != path {
                continue;
            }
            let file_path = self.entry_path(entry.id);
            match fs::remove_file(&file_path) {
                Ok(()) => removed_any = true,
                // A file that another attempt already removed is not a failure: the path's
                // record is gone either way, and the loop must go on to the remaining
                // duplicates.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!(
                            "Failed to delete entry file {}: {}",
                            file_path.display(),
                            e
                        ),
                    });
                }
            }
        }
        Ok(removed_any)
    }

    fn coordination(&self) -> Coordination {
        // Several processes may point at one storage directory; the OS advisory lock is
        // what arbitrates between them.
        Coordination::CrossProcess
    }

    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        // The entire check-then-write runs while the advisory lock is held, so it is a
        // genuine compare-and-set for every other process sharing this directory.
        let _guard = self.acquire_lock()?;
        let existing = self.get_by_path(&entry.path).await?;

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
            // The fence read shares the advisory lock with the write, so this is a genuine
            // check-and-write, not the read-then-write `store_fenced`'s default refuses. An
            // expired lease is not a held lease: reject it here too, so a lapsed attempt
            // cannot write before some other attempt takes the record over.
            crate::Expect::AbsentFenced(fence) => {
                self.get_by_path(fence.path).await?.is_some_and(|held| {
                    held.has_owner(fence.token)
                        && crate::lease_has_not_expired(&held, Utc::now().timestamp())
                })
            }
            crate::Expect::Owner(token) => existing.as_ref().is_some_and(|e| e.has_owner(token)),
            // Owner *and* deadline, evaluated under the same advisory lock as the
            // replacement: a renewal must not revive a lease that lapsed before this instant.
            crate::Expect::UnexpiredOwner(token) => existing.as_ref().is_some_and(|e| {
                e.has_owner(token) && crate::lease_has_not_expired(e, Utc::now().timestamp())
            }),
            crate::Expect::Any => true,
        };
        if !holds {
            return Ok(false);
        }

        let to_write = match &existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        self.write_entry_atomically(&self.entry_path(to_write.id), &to_write)
            .await?;
        Ok(true)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        // Conditional on ownership *and* executed under the lock, so a record rewritten
        // by another attempt between a naive read and delete cannot be removed by this one.
        //
        // Every record at the path that carries `token` is removed, not only the newest one.
        // `store` is keyed by id, so an attempt that wrote the path under more than one id
        // left several files behind; `get_by_path` resolves the newest, and removing only
        // that one made the *previous* owned record visible again — `delete_owned` reported
        // success while a read of the path still resolved, to a record of the very attempt
        // the caller believed it had removed. A record carrying a different owner is
        // deliberately preserved: cleanup must never delete another attempt's artifact.
        let _guard = self.acquire_lock()?;
        let entries = self.scan_entries()?;
        let mut removed_any = false;
        for entry in entries {
            if entry.path != path || !entry.has_owner(token) {
                continue;
            }
            match fs::remove_file(self.entry_path(entry.id)) {
                Ok(()) => removed_any = true,
                // Already removed by someone else; the record is gone either way.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!("Failed to delete owned entry: {}", e),
                    });
                }
            }
        }
        Ok(removed_any)
    }

    /// The fence read and the write happen while the advisory lock is held, so the check
    /// and the publish cannot interleave with another process sharing this directory.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let _guard = self.acquire_lock()?;

        let holds = self.get_by_path(fence.path).await?.is_some_and(|held| {
            held.has_owner(fence.token)
                && crate::lease_has_not_expired(&held, Utc::now().timestamp())
        });
        if !holds {
            return Ok(false);
        }

        let existing = self.get_by_path(&entry.path).await?;
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        self.write_entry_atomically(&self.entry_path(to_write.id), &to_write)
            .await?;
        Ok(true)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        // Collapse first, so a path with a superseded record is counted and reported once,
        // then hand the surviving records to `QueryParams::apply_to`, which is the one
        // implementation of the query contract shared with the other backends. The previous
        // hand-rolled filter honoured only a subset of `params`: it ignored
        // `excluded_path_prefixes` and had no `expires_at` sort, so the lifecycle sweep —
        // which passes reserved prefixes to skip *and* a `limit` while sorting by
        // `expires_at` — truncated arbitrary records before reaching expired user secrets,
        // and those secrets were never swept. Applying the whole contract before pagination
        // is what makes `limit` keep the records closest to expiry.
        let entries = self.collapse_to_current_paths(self.scan_entries()?);
        Ok(params.apply_to(entries))
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        // Count exactly what `list` would return, including the path collapse: a superseded
        // record must not inflate the count any more than it may appear in a listing.
        let entries = self.collapse_to_current_paths(self.scan_entries()?);
        Ok(params.apply_to(entries).len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let entries = self.scan_entries()?;
        Ok(entries.iter().any(|entry| entry.path == path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
            message: "Transactions not supported in File backend".to_string(),
        })
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start_time = SystemTime::now();

        // Check if directory is readable and writable
        let is_healthy = match fs::read_dir(&self.storage_path) {
            Ok(_) => {
                // Try to write a test file
                let test_file = self.storage_path.join(".health_check");
                fs::write(&test_file, b"health_check").is_ok()
                    && fs::remove_file(&test_file).is_ok()
            }
            Err(_) => false,
        };

        let response_time_ms = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or_default()
            .as_millis() as f64;

        Ok(HealthStatus {
            is_healthy,
            response_time_ms,
            connections_active: 0, // File backend doesn't use connections
            connections_idle: 0,
            last_error: if is_healthy {
                None
            } else {
                Some("Directory not accessible".to_string())
            },
            uptime_seconds: 0, // Not tracked for file backend
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let entries = self.scan_entries()?;
        let total_entries = entries.len() as u64;
        let total_size_bytes = entries.iter().map(|e| e.encrypted_data.len() as u64).sum();

        let mut entries_by_security_level = HashMap::new();
        let mut entries_created_today = 0;
        let mut entries_updated_today = 0;
        let mut expired_entries = 0;

        let today = Utc::now().date_naive();

        for entry in &entries {
            // Count by security level
            *entries_by_security_level
                .entry(entry.security_level)
                .or_insert(0) += 1;

            // Count entries created today
            if entry.created_at.date_naive() == today {
                entries_created_today += 1;
            }

            // Count entries updated today
            if entry.updated_at.date_naive() == today {
                entries_updated_today += 1;
            }

            // Count expired entries
            if entry.is_expired() {
                expired_entries += 1;
            }
        }

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level,
            entries_created_today,
            entries_updated_today,
            expired_entries,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
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
    use crate::{EncryptionMetadata, SecurityLevel, StorageBackend};
    use std::sync::Arc;

    fn entry_at(id: Uuid, path: &str, payload: &[u8]) -> SecretEntry {
        let mut entry = SecretEntry::new(
            path.to_string(),
            payload.to_vec(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        );
        // The destination is chosen by id, so pin it; `SecretEntry::new`'s last argument is
        // the owner, not the id.
        entry.id = id;
        entry
    }

    /// Regression: the write staged into a temporary file named only after the destination
    /// (`<id>.json.tmp`), so two concurrent writes to the same destination used the *same*
    /// temporary path. One would rename the other's bytes into place, or the second rename
    /// would fail because the first had already moved the file away — either way a write
    /// either lost its own payload or failed.
    ///
    /// The interleaving is forced: the first write is parked after it has staged its
    /// temporary file and before the rename, the second write runs to completion in that
    /// window, and only then is the first released. Each write must publish its own payload
    /// with the atomic rename, and the second must not be able to observe or destroy the
    /// first's temporary file. The property is that a completed write's payload is readable
    /// and the destination always names one of the two written payloads, never a mixture.
    #[tokio::test]
    async fn concurrent_writes_to_one_destination_use_private_temporary_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = Uuid::new_v4();
        let path = "contract/one-destination";

        let mut first = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let pause = first.arm_compare_and_set_pause();
        let first = Arc::new(first);

        let first_entry = entry_at(id, path, b"first-payload");
        let first_write = {
            let backend = first.clone();
            let entry = first_entry.clone();
            tokio::spawn(async move { backend.store(&entry).await })
        };
        pause.wait_reached().await;

        // The second write completes entirely inside the first write's staging-to-rename
        // window, using the same destination id.
        let second = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let second_entry = entry_at(id, path, b"second-payload");
        second
            .store(&second_entry)
            .await
            .expect("the second concurrent write must succeed");

        // Releasing the first must not fail: its temporary file is its own, so the second
        // write could neither move nor remove it.
        pause.release();
        first_write
            .await
            .expect("task must not panic")
            .expect("the first concurrent write must succeed");

        // Exactly one record exists for the id, and it is one of the two payloads — not a
        // truncation, not a mixture, and not a failure caused by a shared temporary path.
        let resolved = first
            .get_by_id(id)
            .await
            .expect("read by id")
            .expect("the destination must exist");
        assert!(
            resolved.encrypted_data == b"first-payload"
                || resolved.encrypted_data == b"second-payload",
            "the destination must hold one writer's payload intact, got {:?}",
            String::from_utf8_lossy(&resolved.encrypted_data)
        );

        // No temporary file survives: each write either renamed its own or would have
        // removed it on failure, and neither could have leaked the other's.
        let leftovers = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "no temporary file may survive a completed write: {leftovers:?}"
        );
    }

    /// Regression: `delete_by_path` removed the *first* record its directory scan returned
    /// for the path, while `get_by_path` resolves the *newest* by `(updated_at, id)`. A
    /// rewrite under a fresh id therefore left the superseded file on disk, and after the
    /// delete the path still resolved — the "deleted" secret was readable again. The delete
    /// must remove every record at the path.
    #[tokio::test]
    async fn delete_by_path_removes_every_record_at_the_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let path = "contract/superseded";

        let id1 = Uuid::new_v4();
        let mut first = entry_at(id1, path, b"first");
        first.updated_at = chrono::Utc::now() - chrono::Duration::seconds(5);
        backend.store(&first).await.expect("store first");

        // A rewrite under a fresh id: both files now sit on disk for one path, and the
        // second is the one reads resolve to.
        let id2 = Uuid::new_v4();
        let second = entry_at(id2, path, b"second");
        backend.store(&second).await.expect("store second");

        assert!(
            backend
                .get_by_path(path)
                .await
                .expect("read before delete")
                .is_some(),
            "precondition: the path must resolve before the delete"
        );

        let removed = backend.delete_by_path(path).await.expect("delete by path");
        assert!(
            removed,
            "the path existed, so the delete must report removal"
        );

        assert!(
            backend
                .get_by_path(path)
                .await
                .expect("read after delete")
                .is_none(),
            "a deleted path must not resolve, even when a superseded duplicate was on disk"
        );
        assert_eq!(
            backend.count(&QueryParams::default()).await.expect("count"),
            0,
            "the superseded record must not survive the delete"
        );
        assert!(
            backend
                .list(&QueryParams::default())
                .await
                .expect("list")
                .is_empty(),
            "the superseded record must not appear in a listing"
        );
    }

    /// Regression: the lifecycle sweep asks storage to skip reserved namespaces
    /// (`excluded_path_prefixes`) and orders by `expires_at` *before* applying its
    /// 10,000-record cap. `FileBackend::list` honoured neither — its hand-rolled predicate
    /// ignored excluded prefixes and it had no `expires_at` sort — so the cap could be spent
    /// on `sys/` records before any expired user secret was reached, and those secrets were
    /// never swept. `list` now applies the whole `QueryParams` contract.
    ///
    /// The limit is deliberately larger than the number of non-reserved records, so a
    /// listing that does not exclude reserved paths *must* return a reserved record: the
    /// assertion cannot pass by luck.
    #[tokio::test]
    async fn the_lifecycle_query_excludes_reserved_records_before_its_limit_on_the_file_backend() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");

        let now = chrono::Utc::now();
        // Reserved records with deadlines nearest to expiry: a listing that lets them count
        // spends its whole limit on them, so the user secret is never reached.
        for i in 0..5 {
            let mut reserved = entry_at(Uuid::new_v4(), &format!("sys/keys/{i}"), b"reserved");
            reserved.expires_at = Some(now - chrono::Duration::seconds(60 - i));
            backend.store(&reserved).await.expect("store reserved");
        }
        let expired_id = Uuid::new_v4();
        let mut expired = entry_at(expired_id, "kv/app", b"expired");
        expired.expires_at = Some(now - chrono::Duration::seconds(1));
        backend
            .store(&expired)
            .await
            .expect("store expired user secret");

        // The sweep's query: expired entries included, earliest deadline first, reserved
        // namespaces excluded, capped. The cap exceeds the non-reserved count.
        let params = QueryParams {
            include_expired: true,
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            excluded_path_prefixes: vec!["sys/".to_string()],
            limit: Some(3),
            ..QueryParams::default()
        };
        let listed = backend.list(&params).await.expect("list");

        assert!(
            !listed.iter().any(|entry| entry.path.starts_with("sys/")),
            "reserved namespaces must be excluded before the limit is applied, got {:?}",
            listed.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
        assert!(
            listed.iter().any(|entry| entry.id == expired_id),
            "the expired user secret must survive the sweep's limited listing"
        );
        assert!(
            listed
                .windows(2)
                .all(|pair| pair[0].expires_at <= pair[1].expires_at),
            "the sweep orders by earliest expiry, so the listing must be sorted by it"
        );
    }

    /// Regression: `delete_owned` removed only the newest record the path resolved to, so a
    /// superseded owned record at the same path became readable again after the delete
    /// reported success. The property: after `delete_owned(path, token)` returns, no record
    /// of that attempt is readable at the path, and a record of another owner is untouched.
    #[tokio::test]
    async fn delete_owned_never_revives_a_superseded_owned_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let path = "sys/init_staging";

        // Two records at one path under the same owner, then a newer id. `get_by_path`
        // resolves the newest; the older file is superseded but still on disk.
        let id1 = Uuid::new_v4();
        let mut first = entry_at(id1, path, b"first").owned_by("attempt-a");
        first.updated_at = chrono::Utc::now() - chrono::Duration::seconds(5);
        backend.store(&first).await.expect("store first");

        let id2 = Uuid::new_v4();
        backend
            .store(&entry_at(id2, path, b"second").owned_by("attempt-a"))
            .await
            .expect("store second");

        // A different attempt's record must survive the cleanup.
        let other = "sys/init";
        backend
            .store(&entry_at(Uuid::new_v4(), other, b"other").owned_by("attempt-b"))
            .await
            .expect("store other owner");

        assert!(
            backend
                .delete_owned(path, "attempt-a")
                .await
                .expect("delete owned"),
            "the path held owned records, so the delete must report removal"
        );

        assert!(
            backend
                .get_by_path(path)
                .await
                .expect("read after delete")
                .is_none(),
            "deleting the owned path must not leave a superseded owned record readable"
        );
        assert!(
            backend.get_by_id(id1).await.expect("read id1").is_none(),
            "the superseded owned record must be gone"
        );
        assert!(
            backend.get_by_id(id2).await.expect("read id2").is_none(),
            "the newest owned record must be gone"
        );
        assert_eq!(
            backend
                .get_by_path(other)
                .await
                .expect("read other owner")
                .expect("the other attempt's record must remain")
                .owner_token(),
            Some("attempt-b"),
            "cleanup must not delete another attempt's artifact"
        );
    }

    /// Regression: `Expect::Owner` alone let a renewal revive a lease that had already
    /// lapsed — the check-then-write ran under the lock, but the deadline could pass between
    /// the caller's read and this call, and the token alone still matched. `UnexpiredOwner`
    /// folds the deadline into the same advisory-locked step, so the lapsed lease is not
    /// revived. Falsified by treating the new variant like `Owner`.
    #[tokio::test]
    async fn an_unexpired_owner_write_refuses_to_revive_a_lapsed_lease() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let path = "sys/init_lease";
        let lease = |token: &str, expires_at: i64| {
            entry_at(Uuid::new_v4(), path, b"lease")
                .owned_by(token)
                .add_metadata(
                    crate::LEASE_EXPIRES_AT_KEY.to_string(),
                    expires_at.to_string(),
                )
        };

        backend
            .store(&lease("attempt-a", Utc::now().timestamp() - 1))
            .await
            .expect("store lapsed lease");

        assert!(
            !backend
                .compare_and_set(
                    &lease("attempt-a", Utc::now().timestamp() + 300),
                    crate::Expect::UnexpiredOwner("attempt-a")
                )
                .await
                .expect("conditional renewal"),
            "a renewal must not revive a lease whose deadline has already passed"
        );

        // The positive control: a live owned lease is renewed.
        backend
            .store(&lease("attempt-b", Utc::now().timestamp() + 300))
            .await
            .expect("store live lease");
        assert!(
            backend
                .compare_and_set(
                    &lease("attempt-b", Utc::now().timestamp() + 600),
                    crate::Expect::UnexpiredOwner("attempt-b")
                )
                .await
                .expect("conditional renewal"),
            "a live owned lease must be renewable"
        );
    }
}
