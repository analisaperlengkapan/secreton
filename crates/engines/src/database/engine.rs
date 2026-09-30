//! Database secret engine for dynamic credential generation

use super::error::DatabaseError;
use super::model::{DatabaseConfig, DatabaseRole, DatabaseType};
#[cfg(feature = "postgres")]
use deadpool_postgres::{Manager, ManagerConfig, Pool as PgPool, RecyclingMethod};
#[cfg(feature = "mysql")]
use mysql_async::{Opts, Pool as MySqlPool};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use tokio::sync::Mutex;
#[cfg(feature = "postgres")]
use tokio_postgres::types::ToSql;
#[cfg(feature = "postgres")]
use tokio_postgres::{Config, NoTls};

/// Database secret engine for dynamic credentials
pub struct DatabaseEngine {
    config: DatabaseConfig,
    enabled: bool,
    roles: HashMap<String, DatabaseRole>,
    #[cfg(feature = "postgres")]
    pg_pool: Mutex<Option<PgPool>>,
    #[cfg(feature = "mysql")]
    mysql_pool: Mutex<Option<MySqlPool>>,
}

impl DatabaseEngine {
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
            #[cfg(feature = "postgres")]
            pg_pool: Mutex::new(None),
            #[cfg(feature = "mysql")]
            mysql_pool: Mutex::new(None),
        }
    }

    /// Generate database credentials for a role
    pub async fn generate_credentials(
        &self,
        role_name: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        if !self.enabled {
            return Err(DatabaseError::EngineDisabled);
        }

        // Get role configuration
        let role = self.roles.get(role_name).ok_or_else(|| {
            DatabaseError::RoleNotFound(format!("Role '{}' not found", role_name))
        })?;

        // Determine database type from connection URL
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        // Generate credentials based on database type
        match db_type {
            #[cfg(feature = "postgres")]
            DatabaseType::PostgreSQL => {
                self.generate_postgres_credentials(role_name, &role.sql, role.default_ttl)
                    .await
            }
            #[cfg(not(feature = "postgres"))]
            DatabaseType::PostgreSQL => Err(DatabaseError::InvalidConfiguration(
                "this build has no PostgreSQL driver; rebuild secreton-engines with the \
                 `postgres` feature to issue PostgreSQL credentials"
                    .to_string(),
            )),

            #[cfg(feature = "mysql")]
            DatabaseType::MySQL => {
                self.generate_mysql_credentials(
                    role_name,
                    &role.sql,
                    role.default_ttl,
                    &role.mysql_host,
                )
                .await
            }
            #[cfg(not(feature = "mysql"))]
            DatabaseType::MySQL => Err(DatabaseError::InvalidConfiguration(
                "this build has no MySQL driver; rebuild secreton-engines with the `mysql` \
                 feature to issue MySQL credentials"
                    .to_string(),
            )),
        }
    }

    /// Revoke database credentials
    pub async fn revoke_credentials(&self, principal: &str) -> Result<(), DatabaseError> {
        if !self.enabled {
            return Err(DatabaseError::EngineDisabled);
        }

        // Determine database type from connection URL
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        match db_type {
            #[cfg(feature = "postgres")]
            DatabaseType::PostgreSQL => self.revoke_postgres_with_retry(principal).await,
            #[cfg(not(feature = "postgres"))]
            DatabaseType::PostgreSQL => Err(DatabaseError::InvalidConfiguration(
                "this build has no PostgreSQL driver; rebuild secreton-engines with the \
                 `postgres` feature to issue PostgreSQL credentials"
                    .to_string(),
            )),

            #[cfg(feature = "mysql")]
            DatabaseType::MySQL => self.revoke_mysql_credentials(principal).await,
            #[cfg(not(feature = "mysql"))]
            DatabaseType::MySQL => Err(DatabaseError::InvalidConfiguration(
                "this build has no MySQL driver; rebuild secreton-engines with the `mysql` \
                 feature to issue MySQL credentials"
                    .to_string(),
            )),
        }
    }

    /// Get or create PostgreSQL connection pool
    #[cfg(feature = "postgres")]
    async fn get_pg_pool(&self) -> Result<PgPool, DatabaseError> {
        let mut lock = self.pg_pool.lock().await;
        if let Some(pool) = &*lock {
            return Ok(pool.clone());
        }

        // Parse connection URL
        let mut pg_config = Config::from_str(&self.config.connection_url).map_err(|e| {
            DatabaseError::InvalidConfiguration(format!("Invalid PostgreSQL connection URL: {}", e))
        })?;

        // Override with explicit config if present
        if let Some(username) = &self.config.username {
            pg_config.user(username);
        }
        if let Some(password) = &self.config.password {
            pg_config.password(password);
        }
        if let Some(dbname) = &self.config.database_name {
            pg_config.dbname(dbname);
        }
        if let Some(timeout) = self.config.connection_timeout {
            pg_config.connect_timeout(std::time::Duration::from_secs(timeout));
        }

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        // TODO: Implement TLS support (e.g. using rustls or native-tls)
        let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
        let pool = PgPool::builder(mgr)
            .max_size(self.config.max_open_connections.unwrap_or(10) as usize)
            .build()
            .map_err(|e| {
                DatabaseError::ConnectionFailed(format!("Failed to create PostgreSQL pool: {}", e))
            })?;

        *lock = Some(pool.clone());
        Ok(pool)
    }

    /// Get or create MySQL connection pool
    #[cfg(feature = "mysql")]
    async fn get_mysql_pool(&self) -> Result<MySqlPool, DatabaseError> {
        let mut lock = self.mysql_pool.lock().await;
        if let Some(pool) = &*lock {
            return Ok(pool.clone());
        }

        let mut opts = Opts::from_url(&self.config.connection_url).map_err(|e| {
            DatabaseError::InvalidConfiguration(format!("Invalid MySQL connection URL: {}", e))
        })?;

        // Manual overrides if provided in config
        if self.config.username.is_some()
            || self.config.password.is_some()
            || self.config.database_name.is_some()
        {
            let mut builder = mysql_async::OptsBuilder::from_opts(opts);
            if let Some(username) = &self.config.username {
                builder = builder.user(Some(username));
            }
            if let Some(password) = &self.config.password {
                builder = builder.pass(Some(password));
            }
            if let Some(dbname) = &self.config.database_name {
                builder = builder.db_name(Some(dbname));
            }
            // Apply pool limits
            if self.config.max_open_connections.is_some()
                || self.config.max_idle_connections.is_some()
            {
                let min = self.config.max_idle_connections.unwrap_or(5) as usize;
                let max = self.config.max_open_connections.unwrap_or(10) as usize;
                let constraints = mysql_async::PoolConstraints::new(min, max).ok_or_else(|| {
                    DatabaseError::InvalidConfiguration(
                        "Invalid pool constraints: min > max".to_string(),
                    )
                })?;
                builder = builder
                    .pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
            }

            opts = builder.into();
        } else if self.config.max_open_connections.is_some()
            || self.config.max_idle_connections.is_some()
        {
            // Even if no overrides, we might need to apply pool options to the base opts
            let mut builder = mysql_async::OptsBuilder::from_opts(opts);
            let min = self.config.max_idle_connections.unwrap_or(5) as usize;
            let max = self.config.max_open_connections.unwrap_or(10) as usize;
            let constraints = mysql_async::PoolConstraints::new(min, max).ok_or_else(|| {
                DatabaseError::InvalidConfiguration(
                    "Invalid pool constraints: min > max".to_string(),
                )
            })?;
            builder =
                builder.pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
            opts = builder.into();
        }

        let pool = MySqlPool::new(opts);
        *lock = Some(pool.clone());
        Ok(pool)
    }

    /// Revoke PostgreSQL credentials
    #[cfg(feature = "postgres")]
    async fn revoke_postgres_credentials(&self, principal: &str) -> Result<(), DatabaseError> {
        // Validate that the account name matches the format produced by
        // `issue_name()` (ASCII alphanumeric + underscore).  This is
        // a defense-in-depth measure consistent with `revoke_mysql_credentials`.
        // PostgreSQL identifier quoting (double-quote escaping) is more robust
        // than MySQL string-literal escaping, but we still reject unexpected
        // characters to maintain a strict security posture.
        Self::ensure_sql_safe(principal, "principal to revoke")?;

        let pool = self.get_pg_pool().await?;
        let client = pool.get().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get PostgreSQL connection: {e}"))
        })?;

        // In PostgreSQL, we must reassign owned objects and revoke all privileges
        // before dropping the user. Without this, DROP USER fails with
        // "role cannot be dropped because some objects depend on it" when the
        // role SQL used during credential generation contained GRANT statements.
        //
        // All three statements are wrapped in a transaction so that a failure
        // in any step rolls back the previous ones, preventing a partially
        // cleaned-up state (e.g. objects reassigned but user not dropped).
        let safe_principal = principal.replace('"', "\"\"");
        let reassign_sql = format!("REASSIGN OWNED BY \"{}\" TO CURRENT_USER", safe_principal);
        let drop_owned_sql = format!("DROP OWNED BY \"{}\"", safe_principal);
        let drop_user_sql = format!("DROP USER IF EXISTS \"{}\"", safe_principal);

        let params: &[&(dyn ToSql + Sync)] = &[];

        client.execute("BEGIN", params).await.map_err(|e| {
            DatabaseError::QueryFailed(format!(
                "Failed to begin transaction: {}",
                Self::describe_pg_error(&e)
            ))
        })?;

        let result = async {
            // Check whether the role exists before attempting REASSIGN/DROP OWNED.
            // Both commands raise an error when the target role is missing, which
            // would otherwise cause the transaction to abort and prevent the lease
            // record from being deleted — leaving the lease permanently stuck.
            // If the role is already gone (e.g. an operator removed it manually,
            // or VALID UNTIL elapsed and it was cleaned up), skip REASSIGN/DROP
            // OWNED and fall through to DROP USER IF EXISTS (a no-op).
            //
            // The existence check is performed INSIDE the transaction so that the
            // role cannot be concurrently dropped between the check and the
            // REASSIGN/DROP OWNED statements.  Running the check inside the
            // transaction serializes it with any concurrent DROP USER against
            // pg_authid, closing the TOCTOU window.
            let role_exists_row = client
                .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&principal])
                .await
                .map_err(|e| {
                    DatabaseError::QueryFailed(format!(
                        "Failed to check role existence: {}",
                        Self::describe_pg_error(&e)
                    ))
                })?;
            let role_exists = role_exists_row.is_some();

            if role_exists {
                client.execute(&reassign_sql, params).await.map_err(|e| {
                    DatabaseError::QueryFailed(format!(
                        "Failed to reassign owned objects: {}",
                        Self::describe_pg_error(&e)
                    ))
                })?;
                client.execute(&drop_owned_sql, params).await.map_err(|e| {
                    DatabaseError::QueryFailed(format!(
                        "Failed to drop owned objects: {}",
                        Self::describe_pg_error(&e)
                    ))
                })?;
            } else {
                tracing::info!(
                    "PostgreSQL role '{}' does not exist; skipping REASSIGN/DROP OWNED \
                     and treating revocation as a no-op",
                    principal
                );
            }
            client.execute(&drop_user_sql, params).await.map_err(|e| {
                DatabaseError::QueryFailed(format!(
                    "Failed to drop PostgreSQL user: {}",
                    Self::describe_pg_error(&e)
                ))
            })?;
            Ok::<(), DatabaseError>(())
        }
        .await;

        match result {
            Ok(()) => {
                client.execute("COMMIT", params).await.map_err(|e| {
                    DatabaseError::QueryFailed(format!(
                        "Failed to commit transaction: {}",
                        Self::describe_pg_error(&e)
                    ))
                })?;
                Ok(())
            }
            Err(e) => {
                // Best-effort rollback — if this fails the connection will be
                // returned to the pool in an aborted transaction state, which
                // deadpool-postgres handles via its recycling method.
                let _ = client.execute("ROLLBACK", params).await;
                Err(e)
            }
        }
    }

    /// Revoke, retrying the whole transaction on a transient catalog conflict.
    ///
    /// `REASSIGN OWNED` / `DROP OWNED` / `DROP USER` update shared catalog rows, so a
    /// revocation racing another revocation — or an issue for the same role — fails with
    /// `tuple concurrently updated`. Retrying individual statements is not an option:
    /// once one fails the transaction is aborted and every later statement errors too, so
    /// the retry has to restart from `BEGIN`.
    #[cfg(feature = "postgres")]
    async fn revoke_postgres_with_retry(&self, principal: &str) -> Result<(), DatabaseError> {
        let mut attempt = 0u32;
        loop {
            match self.revoke_postgres_credentials(principal).await {
                Ok(()) => return Ok(()),
                Err(e) if attempt < 4 && Self::is_transient_message(&e) => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(20 * u64::from(attempt)))
                        .await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Whether a `DatabaseError` describes a transient conflict.
    ///
    /// The typed `tokio_postgres::Error` has already been rendered to a string by the
    /// time it reaches here, so this matches on what `describe_pg_error` produced.
    #[cfg(feature = "postgres")]
    fn is_transient_message(e: &DatabaseError) -> bool {
        let text = e.to_string();
        text.contains("tuple concurrently updated")
            || text.contains("deadlock detected")
            || text.contains("could not serialize access")
    }

    /// Generate PostgreSQL credentials
    #[cfg(feature = "postgres")]
    async fn generate_postgres_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
        default_ttl: u64,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let issued_name = self.issue_name();
        let issued_credential = self.issue_credential();
        let expiration = Self::expiry_for(default_ttl)?;

        Self::ensure_sql_safe(&issued_name, "generated username")?;
        Self::ensure_sql_safe(&issued_credential, "generated password")?;

        // Get connection
        let pool = self.get_pg_pool().await?;
        let client = pool.get().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get PostgreSQL connection: {}", e))
        })?;

        // Create user
        let create_user_sql = format!(
            "CREATE USER \"{}\" WITH LOGIN PASSWORD '{}' VALID UNTIL '{}'",
            issued_name, issued_credential, expiration
        );

        let params: &[&(dyn ToSql + Sync)] = &[];
        client
            .execute(&create_user_sql, params)
            .await
            .map_err(|e| {
                DatabaseError::QueryFailed(format!(
                    "Failed to create user: {}",
                    Self::describe_pg_error(&e)
                ))
            })?;

        // Execute role SQL statements
        let statements =
            self.replace_placeholders(role_sql, &issued_name, &issued_credential, &expiration);

        // Execute each statement in the role definition
        // Note: This split is naive and does not handle semicolons within string literals.
        // Complex SQL should be avoided in role definitions or handled with a proper parser.
        for statement in statements.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }

            let mut attempt = 0;
            loop {
                match client.execute(stmt, params).await {
                    Ok(_) => break,
                    Err(e) if Self::is_transient_conflict(&e) && attempt < 4 => {
                        attempt += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(20 * attempt)).await;
                    }
                    Err(e) => {
                        // Best-effort cleanup: leaving the account behind without its
                        // grants would be worse than failing outright.
                        let _ = client
                            .execute(&format!("DROP USER IF EXISTS \"{}\"", issued_name), params)
                            .await;
                        return Err(DatabaseError::QueryFailed(format!(
                            "Failed to execute role statement '{}': {}",
                            stmt,
                            Self::describe_pg_error(&e)
                        )));
                    }
                }
            }
        }

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(issued_name));
        data.insert("password".to_string(), Value::String(issued_credential));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );
        data.insert("expiration".to_string(), Value::String(expiration));

        Ok(data)
    }

    /// Whether a PostgreSQL error is a transient serialisation conflict worth retrying.
    ///
    /// `GRANT ... ON DATABASE` updates a row in a shared catalog, so two callers issuing
    /// credentials for the same role at the same time collide with `XX000: tuple
    /// concurrently updated`. Nothing is wrong with either request — one simply has to go
    /// second. Without this, concurrent issuance for one role failed outright.
    #[cfg(feature = "postgres")]
    fn is_transient_conflict(e: &tokio_postgres::Error) -> bool {
        e.as_db_error().is_some_and(|db| {
            db.message().contains("tuple concurrently updated")
                || db.code() == &tokio_postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
                || db.code() == &tokio_postgres::error::SqlState::T_R_DEADLOCK_DETECTED
        })
    }

    /// Render a `tokio_postgres` error usefully.
    ///
    /// Its `Display` is the literal string "db error" — the SQLSTATE, the message and the
    /// server's hint all live in the `DbError` behind it. Reporting the bare Display left
    /// an operator debugging a role statement with nothing to go on.
    #[cfg(feature = "postgres")]
    fn describe_pg_error(e: &tokio_postgres::Error) -> String {
        match e.as_db_error() {
            Some(db) => {
                let mut out = format!("{}: {}", db.code().code(), db.message());
                if let Some(detail) = db.detail() {
                    out.push_str(&format!(" ({detail})"));
                }
                if let Some(hint) = db.hint() {
                    out.push_str(&format!(" [hint: {hint}]"));
                }
                out
            }
            None => e.to_string(),
        }
    }

    fn replace_placeholders(
        &self,
        sql: &str,
        principal: &str,
        credential: &str,
        expiration: &str,
    ) -> String {
        sql.replace("{{name}}", principal)
            .replace("{{password}}", credential)
            .replace("{{expiration}}", expiration)
    }

    /// Revoke MySQL credentials
    #[cfg(feature = "mysql")]
    async fn revoke_mysql_credentials(&self, principal: &str) -> Result<(), DatabaseError> {
        // Validate that the principal matches the format produced by
        // `issue_name()` (ASCII alphanumeric + underscore, prefixed
        // with "s_").  This is a defense-in-depth measure: if
        // `revoke_credentials` is ever called with a principal not generated
        // by `issue_name()` (e.g. from a manually-created lease),
        // we reject it rather than risk SQL injection through the string
        // interpolation below.  The escaping (`replace`) is kept as a
        // secondary safeguard but should never be exercised for valid
        // usernames.
        Self::ensure_sql_safe(principal, "principal to revoke")?;

        let pool = self.get_mysql_pool().await?;
        let mut conn = pool.get_conn().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get MySQL connection: {}", e))
        })?;

        // Drop the account on *every* host it exists for, not just `%`. Revocation is
        // asked for an account name, and a role can be configured with any host; a row left
        // behind under a different host is a credential that still works, which is the
        // one outcome revocation exists to prevent.
        use mysql_async::prelude::Queryable;
        let hosts: Vec<String> = conn
            .exec("SELECT Host FROM mysql.user WHERE User = ?", (principal,))
            .await
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to look up MySQL account: {e}"))
            })?;

        for host in &hosts {
            Self::ensure_host_safe(host)?;
        }

        let revoke_sql = hosts
            .iter()
            .map(|host| format!("DROP USER IF EXISTS '{issued_name}'@'{host}'"))
            .collect::<Vec<_>>()
            .join("; ");

        if revoke_sql.is_empty() {
            // Already gone — an operator removed it, or a previous revoke succeeded.
            return Ok(());
        }

        conn.query_drop(revoke_sql)
            .await
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to drop MySQL user: {}", e)))?;

        Ok(())
    }

    /// Generate MySQL credentials
    #[cfg(feature = "mysql")]
    async fn generate_mysql_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
        default_ttl: u64,
        host: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let issued_name = self.issue_name();
        let issued_credential = self.issue_credential();
        // MySQL doesn't strictly require valid until in CREATE USER, but we might want to handle expiration
        // by a scheduled job or event scheduler. For now, we just create the user.
        // If the role_sql contains expiration logic (e.g. event creation), it will be executed.
        let expiration = Self::expiry_for(default_ttl)?;

        Self::ensure_sql_safe(&issued_name, "generated username")?;
        Self::ensure_sql_safe(&issued_credential, "generated password")?;
        Self::ensure_host_safe(host)?;

        let pool = self.get_mysql_pool().await?;
        let mut conn = pool.get_conn().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get MySQL connection: {}", e))
        })?;

        // `%` as host, the usual choice for dynamic secrets. Interpolation is safe because
        // `ensure_sql_safe` above rejects anything outside [A-Za-z0-9_]; MySQL cannot
        // parameterise CREATE USER.
        let create_user_sql =
            format!("CREATE USER '{issued_name}'@'{host}' IDENTIFIED BY '{issued_credential}'");

        use mysql_async::prelude::Queryable;

        conn.query_drop(create_user_sql).await.map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to create MySQL user: {}", e))
        })?;

        // Execute role SQL statements
        let statements =
            self.replace_placeholders(role_sql, &issued_name, &issued_credential, &expiration);

        // Execute each statement
        // Note: This split is naive and does not handle semicolons within string literals.
        // Complex SQL should be avoided in role definitions or handled with a proper parser.
        for statement in statements.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }

            if let Err(e) = conn.query_drop(stmt).await {
                // Attempt cleanup
                let _ = conn
                    .query_drop(format!("DROP USER IF EXISTS '{issued_name}'@'{host}'"))
                    .await;
                return Err(DatabaseError::QueryFailed(format!(
                    "Failed to execute role statement '{}': {}",
                    stmt, e
                )));
            }
        }

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(issued_name));
        data.insert("password".to_string(), Value::String(issued_credential));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );
        data.insert("expiration".to_string(), Value::String(expiration));

        Ok(data)
    }

    /// Reject anything that is not ASCII alphanumeric or `_`.
    ///
    /// PostgreSQL cannot parameterise `CREATE USER ... PASSWORD`, so the username and
    /// password are interpolated into SQL text. The generators below produce only
    /// alphanumerics, which makes that safe — but "safe because of a comment three
    /// functions away" is how injection bugs are born. Every value that reaches SQL text
    /// passes through here first, so changing a charset breaks loudly instead of silently
    /// opening a hole.
    fn ensure_sql_safe(value: &str, what: &str) -> Result<(), DatabaseError> {
        if value.is_empty() {
            return Err(DatabaseError::InvalidConfiguration(format!(
                "refusing to build SQL with an empty {what}"
            )));
        }
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DatabaseError::InvalidConfiguration(format!(
                "refusing to build SQL: {what} contains characters outside [A-Za-z0-9_]"
            )));
        }
        Ok(())
    }

    /// Reject a MySQL host pattern that could break out of its quotes.
    ///
    /// Hosts legitimately contain `%`, `.`, `-` and `_` (`192.168.1.%`, `app.internal`),
    /// so `ensure_sql_safe` is too strict here — but the value still comes from role
    /// configuration and lands in SQL text, so it gets its own allowlist rather than none.
    #[cfg(feature = "mysql")]
    fn ensure_host_safe(host: &str) -> Result<(), DatabaseError> {
        if host.is_empty() {
            return Err(DatabaseError::InvalidConfiguration(
                "mysql_host must not be empty".to_string(),
            ));
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '%' | '.' | '-' | '_' | ':'))
        {
            return Err(DatabaseError::InvalidConfiguration(format!(
                "mysql_host {host:?} contains characters outside [A-Za-z0-9%.:_-]"
            )));
        }
        Ok(())
    }

    /// Generate a random username (prefixed with 's_' for safety)
    /// Uses Alphanumeric charset to ensure safety in SQL string literals without escaping.
    fn issue_name(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        format!("s_{}", suffix)
    }

    /// Expiry timestamp for a credential with `ttl_secs` of life left.
    ///
    /// A TTL large enough to overflow the calendar used to fall back to *now*, which
    /// silently issued a credential that had already expired — the caller got a working
    /// username and a database account it could not use.
    fn expiry_for(ttl_secs: u64) -> Result<String, DatabaseError> {
        let ttl = i64::try_from(ttl_secs).map_err(|_| {
            DatabaseError::InvalidConfiguration(format!("ttl of {ttl_secs}s is out of range"))
        })?;
        // `TimeDelta::seconds` panics out of range rather than returning None, so a TTL
        // read from configuration could take the process down. `try_seconds` is the
        // non-panicking form.
        chrono::TimeDelta::try_seconds(ttl)
            .and_then(|d| chrono::Utc::now().checked_add_signed(d))
            .map(|t| t.to_rfc3339())
            .ok_or_else(|| {
                DatabaseError::InvalidConfiguration(format!(
                    "ttl of {ttl_secs}s overflows the representable date range"
                ))
            })
    }

    /// Generate a random password
    /// Uses Alphanumeric charset to ensure safety in SQL string literals without escaping.
    /// This guarantees that passwords do not contain characters that could break SQL syntax or cause injection.
    fn issue_credential(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> Result<DatabaseType, DatabaseError> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://")
        {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else {
            Err(DatabaseError::UnsupportedDatabaseType(format!(
                "Unsupported database type in URL: {}",
                connection_url
            )))
        }
    }

    /// Add a database role
    pub fn add_role(&mut self, name: String, role: DatabaseRole) {
        self.roles.insert(name, role);
    }

    /// Remove a database role
    pub fn remove_role(&mut self, name: &str) {
        self.roles.remove(name);
    }

    /// List all roles
    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    /// Get the default TTL for a role, if the role exists.
    pub fn get_role_default_ttl(&self, name: &str) -> Option<u64> {
        self.roles.get(name).map(|r| r.default_ttl)
    }

    /// Enable the engine
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the engine
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if engine is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sanitize connection URL to remove credentials
    fn sanitize_connection_url(&self, url: &str) -> String {
        // Simple heuristic: if url contains @, replace user:pass section
        if let Some(at_pos) = url.rfind('@')
            && let Some(scheme_end) = url.find("://")
        {
            let prefix = &url[0..scheme_end + 3];
            let suffix = &url[at_pos + 1..];
            return format!("{}****:****@{}", prefix, suffix);
        }
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> DatabaseEngine {
        DatabaseEngine::new(DatabaseConfig::default())
    }

    #[test]
    fn placeholders_are_substituted() {
        let e = engine();
        let sql =
            "CREATE ROLE \"{{name}}\" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';";
        let issued_name = e.issue_name();
        let issued_credential = e.issue_credential();
        let result = e.replace_placeholders(
            sql,
            &issued_name,
            &issued_credential,
            "2025-01-01T00:00:00Z",
        );
        assert!(
            result.contains(&issued_name),
            "name placeholder was not substituted"
        );
        assert!(
            result.contains(&issued_credential),
            "password placeholder was not substituted"
        );
        assert!(result.contains("2025-01-01T00:00:00Z"));
        assert!(!result.contains("{{"), "a placeholder survived: {result}");
    }

    /// The generators are the only reason interpolating into SQL text is safe. If someone
    /// widens the charset — to add symbols to a password, say — this fails rather than
    /// quietly creating an injection point in `CREATE USER`.
    #[test]
    fn generated_credentials_never_leave_the_sql_safe_charset() {
        let e = engine();
        for _ in 0..1_000 {
            let issued_name = e.issue_name();
            let issued_credential = e.issue_credential();

            assert!(issued_name.starts_with("s_"), "username lost its prefix");
            assert_eq!(issued_name.len(), 18);
            assert_eq!(issued_credential.len(), 32);

            DatabaseEngine::ensure_sql_safe(&issued_name, "username")
                .expect("generated username must be SQL-safe");
            DatabaseEngine::ensure_sql_safe(&issued_credential, "password")
                .expect("generated password must be SQL-safe");
        }
    }

    #[test]
    fn credentials_are_not_reused_between_calls() {
        let e = engine();
        let first = e.issue_credential();
        let second = e.issue_credential();
        assert_ne!(first, second, "two calls returned the same password");
    }

    /// The host reaches SQL text from role configuration, so it gets an allowlist of its
    /// own — wider than the username's, because a host legitimately contains `%` and `.`,
    /// but not absent.
    #[cfg(feature = "mysql")]
    #[test]
    fn mysql_hosts_are_validated_without_being_over_restricted() {
        for ok in [
            "%",
            "localhost",
            "192.168.1.%",
            "app.internal",
            "db-01",
            "::1",
        ] {
            DatabaseEngine::ensure_host_safe(ok).unwrap_or_else(|e| {
                panic!("rejected a legitimate host {ok:?}: {e}");
            });
        }
        for bad in ["", "'; DROP USER x; --", "host'", "a b", "hostname\\"] {
            assert!(
                DatabaseEngine::ensure_host_safe(bad).is_err(),
                "accepted a host that would reach SQL text: {bad:?}"
            );
        }
    }

    #[test]
    fn sql_unsafe_values_are_refused() {
        for hostile in [
            "bob'; DROP TABLE users; --",
            "bob\"; DROP TABLE users; --",
            "bob--",
            "bob;",
            "bob bob",
            "bob\\",
            "böb",
            "",
        ] {
            assert!(
                DatabaseEngine::ensure_sql_safe(hostile, "test value").is_err(),
                "accepted a value that would reach SQL text: {hostile:?}"
            );
        }
        DatabaseEngine::ensure_sql_safe("s_aB3_9", "test value").expect("ordinary name");
    }

    /// An overflowing TTL used to fall back to `Utc::now()`, handing back a credential
    /// that had already expired while reporting success.
    #[test]
    fn an_overflowing_ttl_is_an_error_not_an_expired_credential() {
        assert!(DatabaseEngine::expiry_for(u64::MAX).is_err());
        assert!(DatabaseEngine::expiry_for(i64::MAX as u64).is_err());

        let ok = DatabaseEngine::expiry_for(3600).expect("an hour is representable");
        let parsed = chrono::DateTime::parse_from_rfc3339(&ok).expect("rfc3339");
        assert!(
            parsed > chrono::Utc::now(),
            "expiry must be in the future, got {ok}"
        );
    }

    #[test]
    fn only_databases_the_engine_can_provision_are_detected() {
        let e = engine();
        assert_eq!(
            e.detect_database_type("postgresql://h/db").unwrap(),
            DatabaseType::PostgreSQL
        );
        assert_eq!(
            e.detect_database_type("postgres://h/db").unwrap(),
            DatabaseType::PostgreSQL
        );
        assert_eq!(
            e.detect_database_type("mysql://h/db").unwrap(),
            DatabaseType::MySQL
        );

        // These used to route to code paths that invented a username and password and
        // returned them without creating any account. Detection must refuse them.
        for unsupported in [
            "mongodb://h/db",
            "redis://h",
            "sqlite://local.db",
            "http://h",
            "",
        ] {
            assert!(
                e.detect_database_type(unsupported).is_err(),
                "accepted a database it cannot provision: {unsupported:?}"
            );
        }
    }

    #[test]
    fn the_returned_connection_string_carries_no_password() {
        let e = engine();
        let sanitised =
            e.sanitize_connection_url("postgresql://admin:hunter2@db.internal:5432/app");
        assert!(
            !sanitised.contains("hunter2"),
            "password leaked: {sanitised}"
        );
        assert!(!sanitised.contains("admin"), "username leaked: {sanitised}");
        assert!(sanitised.contains("db.internal:5432/app"), "{sanitised}");

        // A password containing '@' must not defeat the split.
        let awkward = e.sanitize_connection_url("postgresql://admin:p@ss@db.internal/app");
        assert!(!awkward.contains("p@ss"), "password leaked: {awkward}");
        assert!(awkward.contains("db.internal/app"), "{awkward}");
    }

    #[tokio::test]
    async fn a_disabled_engine_issues_nothing() {
        // `new` leaves the engine disabled. Issuing from it would mean handing out a
        // credential for a database the operator has not configured.
        let e = engine();
        let err = e.generate_credentials("any-role").await.unwrap_err();
        assert!(matches!(err, DatabaseError::EngineDisabled), "{err:?}");
    }

    #[tokio::test]
    async fn an_unknown_role_is_refused_before_any_connection_is_made() {
        let mut e = engine();
        e.enabled = true;
        let err = e.generate_credentials("no-such-role").await.unwrap_err();
        assert!(matches!(err, DatabaseError::RoleNotFound(_)), "{err:?}");
    }
}
