//! PostgreSQL storage backend implementation using tokio-postgres

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, SecurityLevel, StorageBackend,
    StorageError, StorageFence, StorageResult, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime};
use futures::future::try_join_all;
use secreton_domain::OAuthState;
use std::sync::Arc;
use tokio_postgres::{NoTls, Row};
use uuid::Uuid;

/// PostgreSQL storage backend
#[derive(Debug)]
pub struct PostgresBackend {
    pool: Arc<Pool>,
}

impl PostgresBackend {
    /// Create a new PostgreSQL backend
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        let mut cfg = Config::new();
        cfg.url = Some(database_url.to_string());
        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).map_err(|e| {
            StorageError::ConnectionFailed {
                message: format!("Failed to create PostgreSQL pool: {}", e),
            }
        })?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Get the connection pool
    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            INSERT INTO secreton_entries 
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;

        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        client
            .execute(
                query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &entry.tags,
                    &(entry.version as i32),
                    &entry.owner_id,
                    &entry.created_at,
                    &entry.updated_at,
                    &entry.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store secreton entry: {}", e),
            })?;

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM secreton_entries 
            WHERE id = $1
        "#;

        let rows = client
            .query(query, &[&id])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to query secreton entry: {}", e),
            })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        let entry = self.row_to_secreton_entry(row)?;
        Ok(Some(entry))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM secreton_entries 
            WHERE path = $1
        "#;

        let rows = client
            .query(query, &[&path])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to query secreton entry: {}", e),
            })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        let entry = self.row_to_secreton_entry(row)?;
        Ok(Some(entry))
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut query = "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM secreton_entries WHERE 1=1".to_string();
        let mut bind_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_count = 1;

        if let Some(prefix) = &params.path_prefix {
            query.push_str(&format!(" AND path LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        if let Some(owner) = &params.owner_id {
            query.push_str(&format!(" AND owner_id = ${}", param_count));
            bind_params.push(Box::new(*owner));
            param_count += 1;
        }

        // Exclude reserved namespaces at the SQL layer so they don't consume
        // rows from `limit`. Without this, e.g. the lifecycle sweep on a
        // deployment with >SWEEP_MAX_ENTRIES expired audit entries (under
        // `sys/audit/`, sorted earliest by `expires_at ASC`) would have its
        // entire window filled with reserved entries and never reach a
        // user-owned secret. Each excluded prefix becomes its own bound
        // `path NOT LIKE $N` clause to keep this SQL-injection safe.
        for prefix in &params.excluded_path_prefixes {
            query.push_str(&format!(" AND path NOT LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        // Security-level, tag and metadata filters are part of the shared query contract
        // (`QueryParams::apply_to`, implemented by memory/file/Redis). They were previously
        // dropped here, so a caller that filtered on any of them got every row from
        // PostgreSQL and a filtered set from every other backend — the same query returning
        // different results depending only on which backend a deployment chose. Applied at
        // the SQL layer so they compose with `limit`/`offset` rather than truncating before
        // the filter.
        if let Some(min_level) = params.security_level {
            query.push_str(&format!(" AND security_level >= ${}", param_count));
            bind_params.push(Box::new(min_level as i32));
            param_count += 1;
        }

        // `apply_to` requires every requested tag to be present (subset semantics), which is
        // exactly what the array containment operator checks.
        if !params.tags.is_empty() {
            query.push_str(&format!(" AND tags @> ${}", param_count));
            bind_params.push(Box::new(params.tags.clone()));
            param_count += 1;
        }

        // Same subset semantics as `apply_to`: every key/value pair must match.
        if !params.metadata_filters.is_empty() {
            query.push_str(&format!(" AND metadata @> ${}::jsonb", param_count));
            bind_params.push(Box::new(serde_json::Value::Object(
                params
                    .metadata_filters
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
            )));
            param_count += 1;
        }

        // Filter out expired entries unless explicitly requested. This matches
        // the behavior of the InMemory and MySQL backends so that callers see
        // a consistent contract across storage implementations.
        if !params.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }

        // Resolve ORDER BY clause from `sort_by` / `sort_order`. We whitelist
        // both inputs to avoid SQL injection (these are concatenated into the
        // query string, not bound parameters). Default ordering is unchanged
        // (`created_at DESC`) so existing callers keep their previous behavior.
        //
        // For `expires_at ASC` we append `NULLS LAST` so that non-expiring
        // entries (NULL `expires_at`) sort to the end. This is what the
        // lifecycle sweep needs: it requests `expires_at ASC` to surface the
        // oldest-expired entries first, which would otherwise be hidden
        // behind the default newest-first ordering and missed by the
        // `SWEEP_MAX_ENTRIES` cap.
        //
        // `security_level` was missing from this whitelist, so a query that sorted by it
        // fell through to `created_at`. `QueryParams::apply_to` — the in-memory ordering
        // memory/file/Redis use — sorts by the numeric level, so the two backends returned
        // different records for the same page, offset and limit. It is exposed as an
        // integer here to match `SecurityLevel`'s own discriminants.
        let sort_column = match params.sort_by.as_deref() {
            Some("path") => "path",
            Some("created_at") => "created_at",
            Some("updated_at") => "updated_at",
            Some("expires_at") => "expires_at",
            Some("security_level") => "security_level",
            _ => "created_at",
        };
        let sort_dir = match params.sort_order.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("asc") => "ASC",
            _ => "DESC",
        };
        // Every ordering carries the id as a final tie-break in the same direction as the
        // primary key, exactly as `apply_to` does by ordering `(key, id)` and then reversing
        // the whole comparison for a descending sort. Without it two rows sharing a timestamp
        // or level are ordered by PostgreSQL's arbitrary scan order, which can differ between
        // queries and from the other backends, so pagination can repeat or skip a record.
        if sort_column == "expires_at" && sort_dir == "ASC" {
            query.push_str(" ORDER BY expires_at ASC NULLS LAST, id ASC");
        } else {
            query.push_str(&format!(
                " ORDER BY {column} {dir}, id {dir}",
                column = sort_column,
                dir = sort_dir
            ));
        }
        if let Some(limit) = params.limit {
            query.push_str(&format!(" LIMIT ${}", param_count));
            bind_params.push(Box::new(limit as i64));
            param_count += 1;
        }

        // `offset` was dropped here, so a caller paginating with it received page one on
        // PostgreSQL and the requested page on memory/file/Redis. Applied as a SQL `OFFSET`
        // after the `ORDER BY`, which is the same window `QueryParams::apply_to` computes.
        if let Some(offset) = params.offset
            && offset > 0
        {
            query.push_str(&format!(" OFFSET ${}", param_count));
            bind_params.push(Box::new(offset as i64));
        }

        let bind_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = bind_params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let rows =
            client
                .query(&query, &bind_refs)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to list secreton entries: {}", e),
                })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(self.row_to_secreton_entry(&row)?);
        }

        Ok(entries)
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            UPDATE secreton_entries 
            SET path = $2, encrypted_data = $3, encryption_metadata = $4, security_level = $5, 
                metadata = $6, tags = $7, version = $8, updated_at = $9, expires_at = $10
            WHERE id = $1
        "#;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;

        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        let rows_affected = client
            .execute(
                query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &entry.tags,
                    &(entry.version as i32),
                    &entry.updated_at,
                    &entry.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to update secreton entry: {}", e),
            })?;

        if rows_affected == 0 {
            return Err(StorageError::NotFound {
                resource_type: "SecretEntry".to_string(),
                id: entry.id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "DELETE FROM secreton_entries WHERE id = $1";

        let rows_affected =
            client
                .execute(query, &[&id])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete secreton entry: {}", e),
                })?;

        Ok(rows_affected > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "DELETE FROM secreton_entries WHERE path = $1";

        let rows_affected =
            client
                .execute(query, &[&path])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete secreton entry: {}", e),
                })?;

        Ok(rows_affected > 0)
    }

    fn coordination(&self) -> Coordination {
        // A shared PostgreSQL is exactly the case where an in-process mutex is not enough:
        // separate replicas each hold their own, so the row itself has to arbitrate. The
        // conditional statements below do that in the database.
        Coordination::CrossProcess
    }

    /// Conditional write as one statement, so the check and the write cannot interleave.
    ///
    /// `ON CONFLICT (path) DO NOTHING` is the insert-if-absent case. For the owner case,
    /// `DO UPDATE ... WHERE` makes the update itself conditional: PostgreSQL evaluates the
    /// `WHERE` against the row it is about to overwrite, inside the statement's own
    /// snapshot, so a record that changed between the caller's read and this write is not
    /// overwritten and `rows_affected` is 0. That is what makes this a compare-and-set
    /// rather than the read-then-write the trait's default `upsert` performs.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        // `AbsentFenced` is the conjunction of insert-if-absent and a still-held fence, and
        // its two failure modes must be told apart (occupied path vs. lost lease), so it is
        // its own statement pair rather than a variant of the single-statement cases below.
        if let crate::Expect::AbsentFenced(fence) = expect {
            return self.compare_and_set_absent_fenced(entry, fence).await;
        }

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;
        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        // `id` and `created_at` are never written on the update path: the existing row's
        // identity and creation time are preserved, matching `upsert`.
        let update_set = r#"
                encrypted_data = EXCLUDED.encrypted_data,
                encryption_metadata = EXCLUDED.encryption_metadata,
                security_level = EXCLUDED.security_level,
                metadata = EXCLUDED.metadata,
                tags = EXCLUDED.tags,
                version = EXCLUDED.version,
                owner_id = EXCLUDED.owner_id,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at"#;

        // The owner-conditional replacement is a single `UPDATE` whose precondition and
        // write are the same statement, so they cannot interleave: PostgreSQL evaluates the
        // `WHERE` against the row it is about to overwrite, inside the statement's own
        // snapshot, and a row whose recorded owner is no longer the expected token affects
        // zero rows. `id` and `created_at` are deliberately absent from the `SET`, so the
        // existing row's identity and creation time are preserved exactly as `upsert` and
        // the other backends preserve them. The parameters are contiguous ($1–$11) because
        // this statement does not share the insert's placeholder numbering.
        //
        // The previous form built `INSERT ... SELECT ... WHERE false ON CONFLICT ... DO
        // UPDATE`. The insert arm could never produce a row, and an `ON CONFLICT` clause
        // only fires when the insert actually conflicts, so the `DO UPDATE` arm was
        // unreachable: replacement of an *existing* row always affected zero rows and
        // reported failure. `SealService::acquire_init_lease` uses exactly this operation to
        // take over an expired initialization lease, so a vault left by a dead process could
        // never be recovered on PostgreSQL.
        let owner_update_set = r#"
                encrypted_data = $2,
                encryption_metadata = $3,
                security_level = $4,
                metadata = $5,
                tags = $6,
                version = $7,
                owner_id = $8,
                updated_at = $9,
                expires_at = $10"#;

        let insert_columns = "INSERT INTO secreton_entries \
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)";
        let insert_values = "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
        let base = format!("{insert_columns} {insert_values}");

        let security_level = entry.security_level as i32;
        let version = entry.version as i32;
        let token = match expect {
            crate::Expect::Owner(token) | crate::Expect::UnexpiredOwner(token) => token.to_string(),
            _ => String::new(),
        };

        let (query, params): (String, Vec<&(dyn tokio_postgres::types::ToSql + Sync)>) =
            match expect {
                crate::Expect::Absent => (
                    format!("{base} ON CONFLICT (path) DO NOTHING"),
                    vec![
                        &entry.id,
                        &entry.path,
                        &entry.encrypted_data,
                        &encryption_metadata_json,
                        &security_level,
                        &metadata_json,
                        &entry.tags,
                        &version,
                        &entry.owner_id,
                        &entry.created_at,
                        &entry.updated_at,
                        &entry.expires_at,
                    ],
                ),
                crate::Expect::Any => (
                    format!("{base} ON CONFLICT (path) DO UPDATE SET{update_set}"),
                    vec![
                        &entry.id,
                        &entry.path,
                        &entry.encrypted_data,
                        &encryption_metadata_json,
                        &security_level,
                        &metadata_json,
                        &entry.tags,
                        &version,
                        &entry.owner_id,
                        &entry.created_at,
                        &entry.updated_at,
                        &entry.expires_at,
                    ],
                ),
                crate::Expect::Owner(_) | crate::Expect::UnexpiredOwner(_) => (
                    // The owner key is a compile-time constant, not interpolated input.
                    // `UnexpiredOwner` folds the lease deadline into the same `WHERE`, so the
                    // renewal is a single statement whose precondition and write cannot
                    // interleave: a lease that lapsed before the statement executes matches no
                    // row and is never revived. The deadline is read from metadata against the
                    // database clock, and the regex guard keeps the `::bigint` cast from
                    // erroring on a malformed value rather than rejecting it.
                    format!(
                        "UPDATE secreton_entries SET{owner_update_set} \
                         WHERE path = $1 AND metadata->>'{owner}' = $11{deadline}",
                        owner = crate::OWNER_TOKEN_KEY,
                        deadline = match expect {
                            crate::Expect::UnexpiredOwner(_) => format!(
                                " AND metadata->>'{expires}' IS NOT NULL \
                                 AND (metadata->>'{expires}') ~ '^[0-9]+$' \
                                 AND (metadata->>'{expires}')::bigint \
                                     > EXTRACT(EPOCH FROM NOW())::bigint",
                                expires = crate::LEASE_EXPIRES_AT_KEY
                            ),
                            _ => String::new(),
                        }
                    ),
                    vec![
                        &entry.path,
                        &entry.encrypted_data,
                        &encryption_metadata_json,
                        &security_level,
                        &metadata_json,
                        &entry.tags,
                        &version,
                        &entry.owner_id,
                        &entry.updated_at,
                        &entry.expires_at,
                        &token,
                    ],
                ),
                // Dispatched to `compare_and_set_absent_fenced` above; the compiler cannot
                // see that through the `if let`, so restate the refusal here.
                crate::Expect::AbsentFenced(_) => {
                    return Err(StorageError::Unsupported {
                        operation: "compare_and_set".to_string(),
                        backend: "postgres".to_string(),
                    });
                }
            };

        let rows_affected =
            client
                .execute(&query, &params)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to compare-and-set secreton entry: {}", e),
                })?;

        Ok(rows_affected > 0)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = format!(
            "DELETE FROM secreton_entries WHERE path = $1 AND metadata->>'{}' = $2",
            crate::OWNER_TOKEN_KEY
        );

        let rows_affected = client
            .execute(&query, &[&path, &token])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete owned secreton entry: {}", e),
            })?;

        Ok(rows_affected > 0)
    }

    /// Fenced write as a single statement that **locks the lease row**.
    ///
    /// The insert is `SELECT ... FROM f`, where `f` is a CTE that selects the lease row only
    /// while it still carries the token, and `FOR SHARE` makes that select take a row lock.
    /// The conflict arm repeats the same locked CTE inside its own update condition. Because
    /// both the fence read and the artifact write are one statement, and the fence read holds
    /// a lock on the lease row for the statement's duration, a concurrent takeover cannot slip
    /// between them.
    ///
    /// A plain `WHERE EXISTS (SELECT ...)` is **not** enough here, and this is the defect this
    /// version fixes. `EXISTS` is an unlocked read of the statement's snapshot under READ
    /// COMMITTED, so it does not serialise with a takeover at all: a takeover transaction that
    /// has already executed `UPDATE ... SET storage_owner = 'B'` but not yet committed is
    /// invisible to the snapshot, the `EXISTS` still sees the old `'A'`, and the stale write
    /// commits — landing *after* the takeover and overwriting the winner's artifact. `FOR
    /// SHARE` closes that: it blocks on the takeover's row lock, and when the takeover commits
    /// the lock is re-evaluated against the row's new version, so a token that is no longer
    /// the lease's owner matches nothing and the write affects zero rows.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;
        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        let update_set = r#"
                encrypted_data = EXCLUDED.encrypted_data,
                encryption_metadata = EXCLUDED.encryption_metadata,
                security_level = EXCLUDED.security_level,
                metadata = EXCLUDED.metadata,
                tags = EXCLUDED.tags,
                version = EXCLUDED.version,
                owner_id = EXCLUDED.owner_id,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at"#;

        // $13 = fence path, $14 = fence owner token. The owner key is a compile-time
        // constant, never interpolated input. `FOR SHARE` on the fence CTE is the lock that
        // makes the fence and the write one indivisible step; it is evaluated for both the
        // insert arm and the conflict arm.
        //
        // The lease's own deadline is evaluated in the same locked CTE, against the
        // database's clock: an owner token that still matches is not enough if the lease
        // has lapsed, and a record with no readable deadline fails closed. The regex guard
        // keeps the `::bigint` cast from erroring on a malformed value rather than
        // rejecting it.
        let query = format!(
            "WITH fence AS ( \
                 SELECT 1 FROM secreton_entries \
                 WHERE path = $13 AND metadata->>'{owner}' = $14 \
                 AND metadata->>'lease_expires_at' IS NOT NULL \
                 AND (metadata->>'lease_expires_at') ~ '^[0-9]+$' \
                 AND (metadata->>'lease_expires_at')::bigint > EXTRACT(EPOCH FROM NOW())::bigint \
                 FOR SHARE \
             ), written AS ( \
                 INSERT INTO secreton_entries \
                 (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 FROM fence \
                 ON CONFLICT (path) DO UPDATE SET{update_set} \
                 WHERE EXISTS (SELECT 1 FROM fence) \
                 RETURNING 1 \
             ) \
             SELECT COUNT(*)::bigint FROM written",
            owner = crate::OWNER_TOKEN_KEY
        );

        let security_level = entry.security_level as i32;
        let version = entry.version as i32;

        let row = client
            .query_one(
                &query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &security_level,
                    &metadata_json,
                    &entry.tags,
                    &version,
                    &entry.owner_id,
                    &entry.created_at,
                    &entry.updated_at,
                    &entry.expires_at,
                    &fence.path,
                    &fence.token,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to fenced-store secreton entry: {}", e),
            })?;

        let written: i64 = row.get(0);
        Ok(written > 0)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        // The inner query selects a row per match; the outer `COUNT(*)` then counts the page
        // the LIMIT/OFFSET below produces. Starting from `COUNT(*)` and wrapping it would count
        // a single aggregate row instead.
        let mut query = "SELECT 1 FROM secreton_entries WHERE 1=1".to_string();
        let mut bind_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_count = 1;

        if let Some(prefix) = &params.path_prefix {
            query.push_str(&format!(" AND path LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        if let Some(owner) = &params.owner_id {
            query.push_str(&format!(" AND owner_id = ${}", param_count));
            bind_params.push(Box::new(*owner));
            param_count += 1;
        }

        // Mirror the filters applied in `list()` so that `count()` and
        // `list()` agree on which rows are visible for a given `QueryParams`.
        // Without this, callers like `get_active_session_count()` (which uses
        // the default `include_expired: false`) would see expired sessions
        // counted by `count()` but excluded by `list()` — a silent contract
        // violation between the two methods that other backends (e.g. MySQL,
        // whose `count()` delegates to `list().len()`) do not exhibit.
        for prefix in &params.excluded_path_prefixes {
            query.push_str(&format!(" AND path NOT LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        // The same security-level, tag and metadata filters `list()` now applies, so the two
        // agree on which rows a `QueryParams` selects.
        if let Some(min_level) = params.security_level {
            query.push_str(&format!(" AND security_level >= ${}", param_count));
            bind_params.push(Box::new(min_level as i32));
            param_count += 1;
        }

        if !params.tags.is_empty() {
            query.push_str(&format!(" AND tags @> ${}", param_count));
            bind_params.push(Box::new(params.tags.clone()));
            param_count += 1;
        }

        if !params.metadata_filters.is_empty() {
            query.push_str(&format!(" AND metadata @> ${}::jsonb", param_count));
            bind_params.push(Box::new(serde_json::Value::Object(
                params
                    .metadata_filters
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
            )));
            // Advance past the placeholder just bound, exactly as `list` does. Without this
            // `param_count` still names the JSONB predicate, so a following `LIMIT ${...}` or
            // a nonzero-offset `OFFSET ${...}` reuses `$1` for an integer while a second value
            // is appended: PostgreSQL sees the placeholder bound to two values and rejects the
            // whole query, so a filtered, paginated `count` failed instead of returning a size.
            param_count += 1;
        }

        if !params.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }

        // `count` counts what `list` would return, so pagination is part of the count. The
        // filtered, ordered page is built as a subquery and wrapped in `COUNT(*)`; memory, file
        // and Redis define `count` as `list(params).len()`, and a bare `SELECT COUNT(*) ... LIMIT`
        // would return the count of the *unpaginated* match set (the LIMIT applies to the single
        // aggregate row and is inert). The default ordering is the same `created_at DESC, id DESC`
        // `list` uses, so "the first N rows" is the same page in both methods.
        let mut page = query;
        page.push_str(" ORDER BY created_at DESC, id DESC");
        if let Some(limit) = params.limit {
            page.push_str(&format!(" LIMIT ${}", param_count));
            bind_params.push(Box::new(limit as i64));
            param_count += 1;
        }

        if let Some(offset) = params.offset
            && offset > 0
        {
            page.push_str(&format!(" OFFSET ${}", param_count));
            bind_params.push(Box::new(offset as i64));
        }

        let query = format!("SELECT COUNT(*) FROM ({}) AS page", page);

        let bind_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = bind_params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let rows =
            client
                .query(&query, &bind_refs)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to count secreton entries: {}", e),
                })?;

        let count: i64 = rows[0].get(0);
        Ok(u64::try_from(count).unwrap_or(0))
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "SELECT EXISTS(SELECT 1 FROM secreton_entries WHERE path = $1)";
        let rows = client
            .query(query, &[&path])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to check existence: {}", e),
            })?;

        let exists: bool = rows[0].get(0);
        Ok(exists)
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        client
            .query("SELECT 1", &[])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Health check failed: {}", e),
            })?;

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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let count_query = "SELECT COUNT(*) FROM secreton_entries";
        let size_query = "SELECT pg_total_relation_size('secreton_entries')";

        let count_rows =
            client
                .query(count_query, &[])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get entry count: {}", e),
                })?;

        let size_rows =
            client
                .query(size_query, &[])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get storage size: {}", e),
                })?;

        let total_entries: i64 = count_rows[0].get(0);
        let storage_size: i64 = size_rows[0].get(0);

        Ok(StorageStats {
            total_entries: u64::try_from(total_entries).unwrap_or(0),
            total_size_bytes: u64::try_from(storage_size).unwrap_or(0),
            average_entry_size: if total_entries > 0 {
                storage_size as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: std::collections::HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction + 'static>> {
        Ok(Box::new(PostgresTransaction::new(Arc::clone(&self.pool))))
    }

    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut query = "DELETE FROM secreton_entries WHERE expires_at < NOW()".to_string();
        let mut bind_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();

        if let Some(prefix) = path_prefix {
            query.push_str(" AND path LIKE $1");
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
        }

        let bind_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = bind_params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let rows_affected =
            client
                .execute(&query, &bind_refs)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete expired entries: {}", e),
                })?;

        Ok(rows_affected)
    }

    async fn migrate(&self) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let create_table_query = r#"
            CREATE TABLE IF NOT EXISTS secreton_entries (
                id UUID PRIMARY KEY,
                path VARCHAR NOT NULL UNIQUE,
                encrypted_data BYTEA NOT NULL,
                encryption_metadata JSONB NOT NULL,
                security_level INTEGER NOT NULL,
                metadata JSONB NOT NULL,
                tags TEXT[] NOT NULL,
                version INTEGER NOT NULL,
                owner_id UUID NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS idx_secreton_entries_path ON secreton_entries(path);
            CREATE INDEX IF NOT EXISTS idx_secreton_entries_owner ON secreton_entries(owner_id);
            CREATE INDEX IF NOT EXISTS idx_secreton_entries_security_level ON secreton_entries(security_level);

            CREATE TABLE IF NOT EXISTS oauth_state (
                state VARCHAR(255) PRIMARY KEY,
                provider VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_state_expires_at ON oauth_state(expires_at);
        "#;

        client
            .batch_execute(create_table_query)
            .await
            .map_err(|e| StorageError::MigrationError {
                message: format!("Failed to run migrations: {}", e),
            })?;

        Ok(())
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            INSERT INTO oauth_state (state, provider, created_at, expires_at)
            VALUES ($1, $2, $3, $4)
        "#;

        client
            .execute(
                query,
                &[
                    &state.state,
                    &state.provider,
                    &state.created_at,
                    &state.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store OAuth state: {}", e),
            })?;

        Ok(())
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            DELETE FROM oauth_state
            WHERE state = $1 AND expires_at > NOW()
            RETURNING state, provider, created_at, expires_at
        "#;

        let rows = client
            .query(query, &[&state])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to get OAuth state: {}", e),
            })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        let oauth_state = OAuthState {
            state: row.get("state"),
            provider: row.get("provider"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        };

        Ok(Some(oauth_state))
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "DELETE FROM oauth_state WHERE expires_at < NOW()";

        let rows_affected =
            client
                .execute(query, &[])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete expired OAuth states: {}", e),
                })?;

        Ok(rows_affected)
    }
}

impl PostgresBackend {
    /// Insert-if-absent that is also fenced on a still-held lease, in one transaction.
    ///
    /// The artifact insert and the fence read must be one indivisible step for the same
    /// reason [`StorageBackend::store_fenced`] is: a fence checked in a separate statement
    /// says nothing by the time the insert lands, so a stale initialization could still
    /// create a privileged identity. `SELECT ... FOR SHARE` locks the lease row, so a
    /// concurrent takeover blocks on it and the fence is re-evaluated against the row's
    /// committed version.
    ///
    /// The two preconditions are ordered deliberately. Occupancy is checked first, with
    /// `INSERT ... ON CONFLICT (path) DO NOTHING` followed by a conditional `UPDATE`: a
    /// plain prefetch of the path would race a concurrent registration that has not
    /// committed, whereas the conflict resolution evaluates against the latest row. If the
    /// path is occupied the statement affects no row and [`StorageError::Duplicate`] is
    /// returned, telling the caller "someone else owns this name". Only then is the fence
    /// consulted, and a lease that is gone is `Ok(false)` — a distinct outcome from the
    /// duplicate, so registration never reports a storage-level duplicate for a lost lease
    /// or vice versa.
    async fn compare_and_set_absent_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;
        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        let security_level = entry.security_level as i32;
        let version = entry.version as i32;

        let transaction = client
            .transaction()
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to begin fenced insert: {}", e),
            })?;

        // Occupancy is evaluated first, matching the memory and file backends. The caller
        // checks the registration precondition before the lease, so "someone else owns this
        // name" must be reported ahead of "your lease is gone"; evaluating the fence first
        // would report a lost lease (an internal error) for a path that is merely occupied.
        // `ON CONFLICT (path) DO NOTHING` affects one row when it inserts and no row when
        // the path already exists, so the statement's own row count is the occupancy test —
        // no separate race-prone prefetch is needed.
        let insert_query = "INSERT INTO secreton_entries \
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
            ON CONFLICT (path) DO NOTHING";
        let inserted = transaction
            .execute(
                insert_query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &security_level,
                    &metadata_json,
                    &entry.tags,
                    &version,
                    &entry.owner_id,
                    &entry.created_at,
                    &entry.updated_at,
                    &entry.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to insert fenced entry: {}", e),
            })?;

        if inserted == 0 {
            // A record already occupies the path; the insert did nothing. Roll back and
            // report the occupied path specifically, so the caller maps it to "already
            // exists" rather than treating it as a lost lease.
            let _ = transaction.rollback().await;
            return Err(StorageError::Duplicate {
                resource_type: "SecretEntry".to_string(),
                id: entry.path.clone(),
            });
        }

        // The fence lock is taken in the same transaction as the insert above. A takeover
        // that has run but not committed makes this statement block and then match nothing
        // once it does, so the artifact cannot land after a lease it no longer holds. If
        // the fence is gone the whole transaction is rolled back and the insert above is
        // discarded, so a stale attempt publishes nothing. The owner key is a compile-time
        // constant.
        //
        // The lease's own deadline is evaluated in the same locked statement against the
        // database's clock: a matching owner token is not enough if the lease has lapsed,
        // and a record with no readable deadline fails closed. The regex guard keeps the
        // `::bigint` cast from erroring on a malformed value.
        let fence_query = format!(
            "SELECT 1 FROM secreton_entries WHERE path = $1 AND metadata->>'{owner}' = $2 \
             AND metadata->>'lease_expires_at' IS NOT NULL \
             AND (metadata->>'lease_expires_at') ~ '^[0-9]+$' \
             AND (metadata->>'lease_expires_at')::bigint > EXTRACT(EPOCH FROM NOW())::bigint \
             FOR SHARE",
            owner = crate::OWNER_TOKEN_KEY
        );
        let fence_held = transaction
            .query_opt(&fence_query, &[&fence.path, &fence.token])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to evaluate fenced insert: {}", e),
            })?
            .is_some();
        if !fence_held {
            let _ = transaction.rollback().await;
            return Ok(false);
        }

        transaction
            .commit()
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to commit fenced insert: {}", e),
            })?;
        Ok(true)
    }

    fn row_to_secreton_entry(&self, row: &Row) -> StorageResult<SecretEntry> {
        let encryption_metadata_value: serde_json::Value = row.get("encryption_metadata");
        let encryption_metadata =
            serde_json::from_value(encryption_metadata_value).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to deserialize encryption metadata: {}", e),
                }
            })?;

        let metadata_value: serde_json::Value = row.get("metadata");
        let metadata = serde_json::from_value(metadata_value).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to deserialize metadata: {}", e),
            }
        })?;

        let security_level_int: i32 = row.get("security_level");
        let security_level = match security_level_int {
            0 => SecurityLevel::Public,
            1 => SecurityLevel::Internal,
            2 => SecurityLevel::Confidential,
            3 => SecurityLevel::Secret,
            4 => SecurityLevel::TopSecret,
            _ => SecurityLevel::Internal,
        };

        Ok(SecretEntry {
            id: row.get("id"),
            path: row.get("path"),
            encrypted_data: row.get("encrypted_data"),
            encryption_metadata,
            security_level,
            metadata,
            tags: row.get("tags"),
            version: u32::try_from(row.get::<_, i32>("version")).unwrap_or(0),
            owner_id: row.get("owner_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            expires_at: row.get("expires_at"),
        })
    }
}

/// PostgreSQL transaction implementation
#[derive(Debug)]
pub struct PostgresTransaction {
    pool: Arc<Pool>,
    operations: Vec<PostgresOperation>,
    committed: bool,
}

#[derive(Debug)]
enum PostgresOperation {
    Store(SecretEntry),
    Update(SecretEntry),
    Delete(Uuid),
}

impl PostgresTransaction {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            operations: Vec::new(),
            committed: false,
        }
    }

    async fn execute_operation(
        &self,
        transaction: &deadpool_postgres::Transaction<'_>,
        op: &PostgresOperation,
    ) -> StorageResult<()> {
        match op {
            PostgresOperation::Store(entry) => {
                let query = r#"
                    INSERT INTO secreton_entries
                    (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (id) DO UPDATE SET
                        path = EXCLUDED.path,
                        encrypted_data = EXCLUDED.encrypted_data,
                        encryption_metadata = EXCLUDED.encryption_metadata,
                        security_level = EXCLUDED.security_level,
                        metadata = EXCLUDED.metadata,
                        tags = EXCLUDED.tags,
                        version = EXCLUDED.version,
                        owner_id = EXCLUDED.owner_id,
                        updated_at = EXCLUDED.updated_at,
                        expires_at = EXCLUDED.expires_at
                "#;

                let metadata_json =
                    serde_json::to_value(&entry.metadata).unwrap_or(serde_json::Value::Null);
                let tags_json =
                    serde_json::to_value(&entry.tags).unwrap_or(serde_json::Value::Null);
                let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
                    .unwrap_or(serde_json::Value::Null);

                transaction
                    .execute(
                        query,
                        &[
                            &entry.id,
                            &entry.path,
                            &entry.encrypted_data,
                            &encryption_metadata_json,
                            &(entry.security_level as i32),
                            &metadata_json,
                            &tags_json,
                            &(entry.version as i32),
                            &entry.owner_id,
                            &entry.created_at.naive_utc(),
                            &entry.updated_at.naive_utc(),
                            &entry.expires_at.map(|dt| dt.naive_utc()),
                        ],
                    )
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store entry: {}", e),
                    })?;
            }
            PostgresOperation::Update(entry) => {
                let query = r#"
                    UPDATE secreton_entries SET
                        path = $2,
                        encrypted_data = $3,
                        encryption_metadata = $4,
                        security_level = $5,
                        metadata = $6,
                        tags = $7,
                        version = $8,
                        owner_id = $9,
                        updated_at = $10,
                        expires_at = $11
                    WHERE id = $1
                "#;

                let metadata_json =
                    serde_json::to_value(&entry.metadata).unwrap_or(serde_json::Value::Null);
                let tags_json =
                    serde_json::to_value(&entry.tags).unwrap_or(serde_json::Value::Null);
                let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
                    .unwrap_or(serde_json::Value::Null);

                transaction
                    .execute(
                        query,
                        &[
                            &entry.id,
                            &entry.path,
                            &entry.encrypted_data,
                            &encryption_metadata_json,
                            &(entry.security_level as i32),
                            &metadata_json,
                            &tags_json,
                            &(entry.version as i32),
                            &entry.owner_id,
                            &entry.updated_at.naive_utc(),
                            &entry.expires_at.map(|dt| dt.naive_utc()),
                        ],
                    )
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to update entry: {}", e),
                    })?;
            }
            PostgresOperation::Delete(id) => {
                let query = "DELETE FROM secreton_entries WHERE id = $1";
                transaction
                    .execute(query, &[id])
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete entry: {}", e),
                    })?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StorageTransaction for PostgresTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(PostgresOperation::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(PostgresOperation::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(PostgresOperation::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // Execute all operations in a database transaction
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection for transaction: {}", e),
            })?;

        let transaction =
            client
                .transaction()
                .await
                .map_err(|e| StorageError::TransactionFailed {
                    message: format!("Failed to begin transaction: {}", e),
                })?;

        let futures = self
            .operations
            .iter()
            .map(|op| self.execute_operation(&transaction, op));

        try_join_all(futures).await?;

        transaction
            .commit()
            .await
            .map_err(|e| StorageError::TransactionFailed {
                message: format!("Failed to commit transaction: {}", e),
            })?;

        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}
