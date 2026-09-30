//! Integration tests for the dynamic-database-credentials engine.
//!
//! These talk to a real PostgreSQL. Unit tests can only show that the engine builds the
//! right SQL string — they cannot show that the account exists afterwards, which is the
//! only thing a caller actually cares about. This engine previously shipped with two
//! backends that returned a name and credential without creating any account at all,
//! and no test in the repository could have caught it.
//!
//! Set `SECRETON_TEST_POSTGRES_URL` to run them, e.g.
//!
//! ```text
//! docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
//! export SECRETON_TEST_POSTGRES_URL="postgres://postgres@localhost:5432/postgres"
//! cargo test -p secreton-engines --features postgres --test database_postgres
//! ```
//!
//! The URL above embeds no password; insert the container's `POSTGRES_PASSWORD` between
//! the role name and the `@` (or use a role that authenticates without one).
//!
//! Without that variable each test returns early. That is deliberate: `cargo test` on a
//! fresh checkout must not require Docker. CI sets the variable in the job that runs a
//! PostgreSQL service container.

#![cfg(feature = "postgres")]

use secreton_engines::database::{DatabaseConfig, DatabaseEngine, DatabaseRole};

/// The connection URL, or `None` when the suite should skip.
fn database_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_POSTGRES_URL is not set");
            None
        }
    }
}

/// The admin URL with its userinfo replaced by the issued account's.
///
/// The admin password is not a fixed string — CI and a local container use different
/// ones — so the URL is split on its structure rather than matched against a literal.
/// A literal substitution silently does nothing when the password differs, and the
/// assertion that follows then runs against the *admin* connection and passes for the
/// wrong reason.
fn with_issued_credentials(admin_url: &str, issued_name: &str, issued_credential: &str) -> String {
    let (scheme, rest) = admin_url
        .split_once("://")
        .expect("the admin URL has a scheme");
    let at = rest.rfind('@').expect("the admin URL carries userinfo");
    format!(
        "{scheme}://{issued_name}:{issued_credential}@{}",
        &rest[at + 1..]
    )
}

/// The userinfo embedded in a connection URL, if it carries any.
fn embedded_userinfo(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(&rest[..rest.find('@')?])
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
            sql: "GRANT CONNECT ON DATABASE postgres TO \"{{name}}\";".to_string(),
            default_ttl: 3600,
            max_ttl: 86400,
            // Ignored by the PostgreSQL path; PostgreSQL has no host in CREATE USER.
            mysql_host: "%".to_string(),
        },
    );
    engine
}

/// Whether the issued name exists as a role on the server.
async fn role_exists(url: &str, issued_name: &str) -> bool {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let rows = client
        .query("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&issued_name])
        .await
        .expect("query pg_roles");
    !rows.is_empty()
}

#[tokio::test]
async fn issued_credentials_correspond_to_a_real_account() {
    let Some(url) = database_url() else { return };
    let engine = engine_for(&url);

    let creds = engine
        .generate_credentials("reader")
        .await
        .expect("issue credentials");

    let issued_name = creds["username"].as_str().expect("username").to_string();
    let issued_credential = creds["password"].as_str().expect("password").to_string();

    // The point of the whole test: the account is on the server, not just in the response.
    assert!(
        role_exists(&url, &issued_name).await,
        "the engine returned credentials that do not exist on the server"
    );

    // And they actually authenticate.
    let issued_url = with_issued_credentials(&url, &issued_name, &issued_credential);
    let connected = tokio_postgres::connect(&issued_url, tokio_postgres::NoTls).await;
    assert!(
        connected.is_ok(),
        "issued credentials did not authenticate: {:?}",
        connected.err()
    );

    engine
        .revoke_credentials(&issued_name)
        .await
        .expect("revoke should succeed");
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
        role_exists(&url, &issued_name).await,
        "setup: role should exist"
    );

    engine
        .revoke_credentials(&issued_name)
        .await
        .expect("revoke");

    assert!(
        !role_exists(&url, &issued_name).await,
        "an issued account still exists after revocation; a revoked lease must not leave a \
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
    let admin_userinfo = embedded_userinfo(&url).expect("the admin URL carries userinfo");
    let connection_string = creds["connection_string"].as_str().expect("string");

    assert!(
        !connection_string.contains(admin_userinfo),
        "the admin credentials from the engine's own connection URL were handed to the \
         caller: {connection_string}"
    );

    let issued_name = creds["username"].as_str().expect("username");
    let _ = engine.revoke_credentials(issued_name).await;
}

#[tokio::test]
async fn two_issues_produce_two_distinct_accounts() {
    let Some(url) = database_url() else { return };
    let engine = engine_for(&url);

    let first = engine.generate_credentials("reader").await.expect("first");
    let second = engine.generate_credentials("reader").await.expect("second");

    let a = first["username"].as_str().expect("username");
    let b = second["username"].as_str().expect("username");
    assert_ne!(a, b, "two leases collided on one account");

    assert!(role_exists(&url, a).await);
    assert!(role_exists(&url, b).await);

    let _ = engine.revoke_credentials(a).await;
    let _ = engine.revoke_credentials(b).await;
}

/// Two callers asking for the same role at the same time.
///
/// `GRANT ... ON DATABASE` updates a shared catalog row, so concurrent issuance used to
/// fail with `XX000: tuple concurrently updated` — a transient conflict reported to the
/// caller as an outright failure. Nothing about either request is invalid; one just has
/// to go second.
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
            role_exists(&url, issued_name).await,
            "an issued account was not created"
        );
        let _ = engine.revoke_credentials(issued_name).await;
    }
}
