//! Integration tests for the MySQL side of the dynamic-database-credentials engine.
//!
//! The PostgreSQL suite in `database_postgres.rs` explains why these exist: only a real
//! server can show that an issued credential corresponds to an account that exists, which
//! is the one thing a caller depends on. The MySQL path had never been executed at all —
//! it was gated on a cargo feature that was never declared, so no build ever compiled it.
//!
//! Set `SECRETON_TEST_MYSQL_URL` to run them, e.g.
//!
//! ```text
//! docker run --rm -d -p 3306:3306 -e MARIADB_ROOT_PASSWORD=rootpw mariadb:11
//! SECRETON_TEST_MYSQL_URL=mysql://root:rootpw@127.0.0.1:3306/secreton_test \
//!     cargo test -p secreton-engines --features mysql --test database_mysql
//! ```
//!
//! Without that variable each test returns early, so a fresh checkout needs no server.

#![cfg(feature = "mysql")]

use mysql_async::prelude::Queryable;
use secreton_engines::database::{DatabaseConfig, DatabaseEngine, DatabaseRole};

/// Remove the anonymous `''@'localhost'` rows a default MariaDB install creates.
///
/// MySQL matches the most specific host row first, so while those exist an account
/// created only as `@'%'` cannot authenticate from localhost — the anonymous entry wins
/// and denies. `mysql_secure_installation` removes them on any real deployment; doing it
/// here means the tests exercise the engine rather than that quirk.
async fn drop_anonymous_users(url: &str) {
    let pool = mysql_async::Pool::new(url);
    if let Ok(mut conn) = pool.get_conn().await {
        let _ = conn
            .query_drop("DELETE FROM mysql.user WHERE User = ''")
            .await;
        let _ = conn.query_drop("FLUSH PRIVILEGES").await;
    }
}

fn database_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_MYSQL_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_MYSQL_URL is not set");
            None
        }
    }
}

fn engine_for(url: &str) -> DatabaseEngine {
    let config = DatabaseConfig {
        connection_url: url.to_string(),
        ..Default::default()
    };
    let mut engine = DatabaseEngine::new(config);
    engine.enable();
    engine.add_role(
        "reader".to_string(),
        DatabaseRole {
            sql: "GRANT SELECT ON secreton_test.* TO '{{name}}'@'%';".to_string(),
            default_ttl: 3600,
            max_ttl: 86400,
            mysql_host: "%".to_string(),
        },
    );
    engine
}

/// Whether the issued name exists as an account on the server.
async fn user_exists(url: &str, issued_name: &str) -> bool {
    let pool = mysql_async::Pool::new(url);
    let mut conn = pool.get_conn().await.expect("connect");
    let rows: Vec<u8> = conn
        .exec("SELECT 1 FROM mysql.user WHERE User = ?", (issued_name,))
        .await
        .expect("query mysql.user");
    !rows.is_empty()
}

/// The privileges the issued credentials authenticate with, as `SHOW GRANTS` reports
/// them for the current user.
///
/// Connecting *as* the issued account rather than asking for its grants by name keeps
/// the issued name out of the SQL text, and proves the credential actually works as a
/// side effect.
async fn privileges_of_current_user(issued_url: &str) -> Vec<String> {
    let pool = mysql_async::Pool::new(issued_url);
    let mut conn = pool.get_conn().await.expect("connect as issued account");
    conn.query("SHOW GRANTS FOR CURRENT_USER()")
        .await
        .unwrap_or_default()
}

#[tokio::test]
async fn issued_credentials_correspond_to_a_real_account() {
    let Some(url) = database_url() else { return };
    drop_anonymous_users(&url).await;
    let engine = engine_for(&url);

    let creds = engine
        .generate_credentials("reader")
        .await
        .expect("issue credentials");

    let issued_name = creds["username"].as_str().expect("username").to_string();
    let issued_credential = creds["password"].as_str().expect("password").to_string();

    assert!(
        user_exists(&url, &issued_name).await,
        "the engine returned credentials that do not exist on the server"
    );

    // And they authenticate. This is what separates a provisioned account from a
    // fabricated one — the shape both MongoDB and Redis shipped with.
    let issued_url = url.replace(
        "root:rootpw@",
        &format!("{issued_name}:{issued_credential}@"),
    );
    let pool = mysql_async::Pool::new(issued_url.as_str());
    let conn = pool.get_conn().await;
    assert!(
        conn.is_ok(),
        "issued credentials did not authenticate: {:?}",
        conn.err()
    );

    engine
        .revoke_credentials(&issued_name)
        .await
        .expect("revoke should succeed");
}

#[tokio::test]
async fn the_role_statement_is_applied_to_the_new_account() {
    let Some(url) = database_url() else { return };
    let engine = engine_for(&url);

    let creds = engine
        .generate_credentials("reader")
        .await
        .expect("issue credentials");
    let issued_name = creds["username"].as_str().expect("username").to_string();
    let issued_credential = creds["password"].as_str().expect("password").to_string();

    // Creating the account is not enough: without the role SQL the caller gets a login
    // with no privileges, which fails at the first query rather than at issue time.
    let issued_url = url.replace(
        "root:rootpw@",
        &format!("{issued_name}:{issued_credential}@"),
    );
    let granted = privileges_of_current_user(&issued_url).await;
    assert!(
        granted.iter().any(|g| g.contains("SELECT")),
        "the role statement did not reach the account; the account held {granted:?}"
    );

    let _ = engine.revoke_credentials(&issued_name).await;
}

#[tokio::test]
async fn revocation_removes_the_account() {
    let Some(url) = database_url() else { return };
    let engine = engine_for(&url);

    let creds = engine
        .generate_credentials("reader")
        .await
        .expect("issue credentials");
    let issued_name = creds["username"].as_str().expect("username").to_string();
    assert!(
        user_exists(&url, &issued_name).await,
        "setup: user should exist"
    );

    engine
        .revoke_credentials(&issued_name)
        .await
        .expect("revoke");

    assert!(
        !user_exists(&url, &issued_name).await,
        "an account still exists after revocation; a revoked lease must not leave a \
         usable account behind"
    );
}

#[tokio::test]
async fn the_returned_connection_string_does_not_carry_the_admin_password() {
    let Some(url) = database_url() else { return };
    let engine = engine_for(&url);

    let creds = engine
        .generate_credentials("reader")
        .await
        .expect("issue credentials");
    let connection_string = creds["connection_string"].as_str().expect("string");

    assert!(
        !connection_string.contains("rootpw"),
        "the admin credential from the engine's own connection URL was handed to the \
         caller: {connection_string}"
    );

    let issued_name = creds["username"].as_str().expect("username");
    let _ = engine.revoke_credentials(issued_name).await;
}

#[tokio::test]
async fn concurrent_issuance_for_one_role_does_not_fail() {
    let Some(url) = database_url() else { return };
    let engine = std::sync::Arc::new(engine_for(&url));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let engine = engine.clone();
        handles.push(tokio::spawn(async move {
            engine.generate_credentials("reader").await
        }));
    }

    let mut issued_names = Vec::new();
    for handle in handles {
        let creds = handle
            .await
            .expect("task panicked")
            .expect("concurrent issuance must succeed");
        issued_names.push(creds["username"].as_str().expect("username").to_string());
    }

    let unique: std::collections::HashSet<_> = issued_names.iter().collect();
    assert_eq!(
        unique.len(),
        issued_names.len(),
        "two callers shared an account"
    );

    for issued_name in &issued_names {
        assert!(
            user_exists(&url, issued_name).await,
            "an issued account was not created"
        );
        let _ = engine.revoke_credentials(issued_name).await;
    }
}
