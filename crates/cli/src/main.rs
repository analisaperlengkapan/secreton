use anyhow::Result;
use base64::prelude::*;
use clap::{Parser, Subcommand};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

mod config;

use config::CliConfig;

#[derive(Parser)]
#[command(
    name = "secreton-cli",
    about = "Command line interface for Secreton system",
    version = env!("CARGO_PKG_VERSION"),
    author = "Secreton Team"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    config: Option<String>,

    #[arg(long, global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// System health and status commands
    Status,
    /// Configuration management
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
    /// Transit engine operations (encryption/decryption)
    Transit {
        #[command(subcommand)]
        cmd: TransitCommand,
    },
    /// KV secrets engine operations
    Secret {
        #[command(subcommand)]
        cmd: SecretCommand,
    },
    /// Operator commands (init, seal, unseal)
    Operator {
        #[command(subcommand)]
        cmd: OperatorCommand,
    },
    /// Login to the system
    Login {
        /// The token to use
        token: Option<String>,
    },
    /// Logout from the system
    Logout,
    /// User management commands
    User {
        #[command(subcommand)]
        cmd: UserCommand,
    },
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Initialize the system
    Init {
        #[arg(short, long, default_value = "5")]
        shares: u8,
        #[arg(short, long, default_value = "3")]
        threshold: u8,
    },
    /// Unseal the system
    Unseal {
        /// The unseal key/share
        key: Option<String>,
    },
    /// Seal the system
    Seal,
    /// Check seal status
    Status,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a new user
    Create {
        username: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        email: Option<String>,
        #[arg(short, long, value_delimiter = ',')]
        roles: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Apply a configuration file to the server
    Apply {
        /// Path to the configuration file (TOML)
        #[arg(short, long)]
        file: String,
    },
    /// Delete configuration from the server
    Delete,
}

#[derive(Subcommand)]
enum TransitCommand {
    /// Create a new encryption key
    CreateKey { name: String },
    /// List all encryption keys
    ListKeys,
    /// Encrypt data with a key
    Encrypt {
        key: String,
        #[arg(short, long)]
        data: Option<String>,
    },
    /// Decrypt data with a key
    Decrypt {
        key: String,
        #[arg(short, long)]
        data: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret
    Put {
        path: String,
        #[arg(short, long)]
        data: Vec<String>, // key=value format
    },
    /// Retrieve a secret
    Get { path: String },
    /// List all secret paths
    List,
    /// Delete a secret
    Delete { path: String },
}

/// Render a JSON field for display, or `unknown` when the server did not send it.
///
/// These were `unwrap()`, so a server response missing any expected field aborted the
/// CLI with a panic and a backtrace instead of printing what it did know.
fn field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .map_or_else(|| "unknown".to_string(), ToString::to_string)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let mut config = CliConfig::default();
    if let Some(config_path) = &cli.config {
        config = CliConfig::load_from_file(config_path)?;
    }

    // Override server URL if provided via command line
    if let Some(server_url) = &cli.server {
        config.server_url = server_url.clone();
    }

    // Load token from file if not in config
    if config.token.is_none()
        && let Some(path) = get_token_path()
        && path.exists()
        && let Ok(token) = tokio::fs::read_to_string(path).await
    {
        config.token = Some(token.trim().to_string());
    }

    // Override token from env var
    if let Ok(token) = std::env::var("SECRETON_TOKEN") {
        config.token = Some(token);
    }

    info!("Using server: {}", config.server_url);

    // Execute commands
    match cli.command {
        Commands::Status => status_command(&config).await,
        Commands::Config { cmd } => config_command(cmd, &config).await,
        Commands::Transit { cmd } => transit_command(cmd, &config).await,
        Commands::Secret { cmd } => secret_command(cmd, &config).await,
        Commands::Operator { cmd } => operator_command(cmd, &config).await,
        Commands::Login { token } => login_command(token).await,
        Commands::Logout => logout_command().await,
        Commands::User { cmd } => user_command(cmd, &config).await,
    }
}

fn get_token_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".secreton-token"))
}

fn create_client(config: &CliConfig) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = &config.token {
        let mut auth_val = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?;
        auth_val.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, auth_val);
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|e| e.into())
}

async fn config_command(cmd: ConfigCommand, config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    match cmd {
        ConfigCommand::Apply { file } => {
            let content = std::fs::read_to_string(&file)?;

            let toml_value: toml::Value = toml::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse TOML config: {}", e))?;

            let json_value: serde_json::Value = serde_json::to_value(toml_value)
                .map_err(|e| anyhow::anyhow!("Failed to convert config to JSON: {}", e))?;

            let url = format!("{}/api/v1/sys/config", config.server_url);
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&json_value)
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ Configuration applied successfully.");
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                println!("❌ Failed to apply configuration: {} - {}", status, text);
            }
        }
        ConfigCommand::Delete => {
            let url = format!("{}/api/v1/sys/config", config.server_url);
            let response = client.delete(&url).send().await?;

            if response.status().is_success() {
                println!("✅ Configuration deleted successfully.");
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                println!("❌ Failed to delete configuration: {} - {}", status, text);
            }
        }
    }
    Ok(())
}

async fn login_command(token: Option<String>) -> Result<()> {
    let token_to_save = if let Some(t) = token {
        t
    } else {
        use std::io::{self, Write};
        print!("Token (hidden): ");
        io::stdout().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        buffer.trim().to_string()
    };

    if let Some(path) = get_token_path() {
        tokio::fs::write(path, token_to_save).await?;
        println!("Success! Token saved to ~/.secreton-token");
    } else {
        println!("Error: Could not determine home directory to save token.");
    }

    Ok(())
}

async fn logout_command() -> Result<()> {
    if let Some(path) = get_token_path() {
        if path.exists() {
            tokio::fs::remove_file(path).await?;
            println!("Success! Token removed.");
        } else {
            println!("No active login found.");
        }
    } else {
        println!("Error: Could not determine home directory.");
    }
    Ok(())
}

async fn user_command(cmd: UserCommand, config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    match cmd {
        UserCommand::Create {
            username,
            password,
            email,
            roles,
        } => {
            let password_val = if let Some(p) = password {
                p
            } else {
                use std::io::{self, Write};
                print!("Password: ");
                io::stdout().flush()?;
                let mut buffer = String::new();
                io::stdin().read_line(&mut buffer)?;
                buffer.trim().to_string()
            };

            let roles_val = if roles.is_empty() {
                vec!["user".to_string()]
            } else {
                roles
            };

            let url = format!("{}/api/v1/auth/users", config.server_url);
            let response = client
                .post(&url)
                .json(&serde_json::json!({
                    "username": username,
                    "password": password_val,
                    "email": email,
                    "roles": roles_val
                }))
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ User created successfully.");
            } else {
                println!("❌ Failed to create user: {}", response.status());
                println!("   {}", response.text().await?);
            }
        }
    }
    Ok(())
}

async fn operator_command(cmd: OperatorCommand, config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    match cmd {
        OperatorCommand::Init { shares, threshold } => {
            let url = format!("{}/api/v1/sys/init", config.server_url);
            let response = client
                .post(&url)
                .json(&serde_json::json!({
                    "shares": shares,
                    "threshold": threshold
                }))
                .send()
                .await?;

            if response.status().is_success() {
                let body: serde_json::Value = response.json().await?;
                if let Some(data) = body.get("data") {
                    println!("Unseal Keys:");
                    if let Some(keys) = data.get("keys").and_then(|k| k.as_array()) {
                        for (i, key) in keys.iter().enumerate() {
                            println!("Key {}: {}", i + 1, key.as_str().unwrap_or(""));
                        }
                    }
                    println!(
                        "\nInitial Root Token: {}",
                        data.get("root_token")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                    );
                    println!("\nSecreton is initialized! The system is sealed.");
                    println!("You must provide the unseal keys to unseal the system.");
                }
            } else {
                let err_text = response.text().await?;
                println!("Error initializing: {}", err_text);
            }
        }
        OperatorCommand::Unseal { key } => {
            let key_str = if let Some(k) = key {
                k
            } else {
                use std::io::{self, Write};
                print!("Unseal Key: ");
                io::stdout().flush()?;
                let mut buffer = String::new();
                io::stdin().read_line(&mut buffer)?;
                buffer.trim().to_string()
            };

            let url = format!("{}/api/v1/sys/unseal", config.server_url);
            let response = client
                .post(&url)
                .json(&serde_json::json!({
                    "key": key_str
                }))
                .send()
                .await?;

            if response.status().is_success() {
                let body: serde_json::Value = response.json().await?;
                if let Some(data) = body.get("data") {
                    println!("Sealed: {}", field(data, "sealed"));
                    println!("Progress: {}/{}", field(data, "progress"), field(data, "t"));
                }
            } else {
                let err_text = response.text().await?;
                println!("Error unsealing: {}", err_text);
            }
        }
        OperatorCommand::Seal => {
            let url = format!("{}/api/v1/sys/seal", config.server_url);
            let response = client.post(&url).send().await?;
            if response.status().is_success() {
                println!("Success! System is now sealed.");
            } else {
                println!("Error sealing system: {}", response.status());
            }
        }
        OperatorCommand::Status => {
            let url = format!("{}/api/v1/sys/seal-status", config.server_url);
            let response = client.get(&url).send().await?;
            if response.status().is_success() {
                let body: serde_json::Value = response.json().await?;
                if let Some(data) = body.get("data") {
                    println!("Sealed: {}", field(data, "sealed"));
                    println!("Threshold: {}", field(data, "t"));
                    println!("Shares: {}", field(data, "n"));
                    println!("Progress: {}", field(data, "progress"));
                }
            } else {
                println!("Error getting status: {}", response.status());
            }
        }
    }
    Ok(())
}

async fn status_command(config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    // Check health
    let health_url = format!("{}/health", config.server_url);
    let health_response = client.get(&health_url).send().await?;

    if health_response.status().is_success() {
        let health: serde_json::Value = health_response.json().await?;
        println!("🟢 Secreton Status: HEALTHY");
        println!("   Server: {}", config.server_url);
        println!(
            "   Version: {}",
            health
                .get("version")
                .unwrap_or(&serde_json::Value::String("unknown".to_string()))
        );
        println!(
            "   Timestamp: {}",
            health
                .get("timestamp")
                .unwrap_or(&serde_json::Value::String("unknown".to_string()))
        );
    } else {
        println!("🔴 Secreton Status: UNHEALTHY");
        println!("   HTTP Status: {}", health_response.status());
    }

    Ok(())
}

async fn transit_command(cmd: TransitCommand, config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    match cmd {
        TransitCommand::CreateKey { name } => {
            let url = format!("{}/v1/transit/keys/{}", config.server_url, name);
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({}))
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ Created encryption key: {}", name);
            } else {
                println!("❌ Failed to create key: {}", response.status());
            }
        }
        TransitCommand::ListKeys => {
            let url = format!("{}/v1/transit/keys", config.server_url);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let keys: serde_json::Value = response.json().await?;
                println!("🔑 Available encryption keys:");
                if let Some(key_list) = keys.get("keys").and_then(|k| k.as_array()) {
                    for key in key_list {
                        if let Some(key_str) = key.as_str() {
                            println!("   • {}", key_str);
                        }
                    }
                } else {
                    println!("   No keys found");
                }
            } else {
                println!("❌ Failed to list keys: {}", response.status());
            }
        }
        TransitCommand::Encrypt { key, data } => {
            let plaintext = if let Some(d) = data {
                d
            } else {
                // Read from stdin if no data provided
                use std::io::Read;
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;
                buffer.trim().to_string()
            };

            // Base64 encode the plaintext
            let encoded_data = BASE64_STANDARD.encode(plaintext.as_bytes());

            let url = format!("{}/v1/transit/encrypt/{}", config.server_url, key);
            let payload = serde_json::json!({
                "plaintext": encoded_data
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(ciphertext) = result.get("ciphertext").and_then(|c| c.as_str()) {
                    println!("🔐 Encrypted data:");
                    println!("{}", ciphertext);
                }
            } else {
                println!("❌ Failed to encrypt: {}", response.status());
            }
        }
        TransitCommand::Decrypt { key, data } => {
            let ciphertext = if let Some(d) = data {
                d
            } else {
                use std::io::Read;
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;
                buffer.trim().to_string()
            };

            let url = format!("{}/v1/transit/decrypt/{}", config.server_url, key);
            let payload = serde_json::json!({
                "ciphertext": ciphertext
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(plaintext_b64) = result.get("plaintext").and_then(|p| p.as_str()) {
                    // Base64 decode the result
                    let decoded = BASE64_STANDARD.decode(plaintext_b64)?;
                    let plaintext = String::from_utf8(decoded)?;
                    println!("🔓 Decrypted data:");
                    println!("{}", plaintext);
                }
            } else {
                println!("❌ Failed to decrypt: {}", response.status());
            }
        }
    }

    Ok(())
}

async fn secret_command(cmd: SecretCommand, config: &CliConfig) -> Result<()> {
    let client = create_client(config)?;

    match cmd {
        SecretCommand::Put { path, data } => {
            // Parse key=value pairs
            let mut secret_data = serde_json::Map::new();
            for pair in data {
                if let Some((key, value)) = pair.split_once('=') {
                    secret_data.insert(
                        key.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                } else {
                    println!("❌ Invalid format '{}'. Use key=value format.", pair);
                    return Ok(());
                }
            }

            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let payload = serde_json::json!({
                "data": secret_data
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(version) = result.get("version").and_then(|v| v.as_u64()) {
                    println!("✅ Secret stored at path '{}' (version {})", path, version);
                } else {
                    println!("✅ Secret stored at path '{}'", path);
                }
            } else {
                println!("❌ Failed to store secret: {}", response.status());
            }
        }
        SecretCommand::Get { path } => {
            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(data) = result.get("data") {
                    println!("🔍 Secret at path '{}':", path);
                    println!("{}", serde_json::to_string_pretty(data)?);
                }
                if let Some(version) = result.get("version").and_then(|v| v.as_u64()) {
                    println!("Version: {}", version);
                }
            } else if response.status() == 404 {
                println!("❌ Secret not found at path '{}'", path);
            } else {
                println!("❌ Failed to retrieve secret: {}", response.status());
            }
        }
        SecretCommand::List => {
            let url = format!("{}/v1/secrets", config.server_url);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(secrets) = result.get("keys").and_then(|s| s.as_array()) {
                    println!("📋 Available secrets:");
                    for secret in secrets {
                        if let Some(path) = secret.as_str() {
                            println!("   • {}", path);
                        }
                    }
                } else {
                    println!("📋 No secrets found");
                }
            } else {
                println!("❌ Failed to list secrets: {}", response.status());
            }
        }
        SecretCommand::Delete { path } => {
            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let response = client.delete(&url).send().await?;

            if response.status().is_success() {
                println!("✅ Secret deleted at path '{}'", path);
            } else if response.status() == 404 {
                println!("❌ Secret not found at path '{}'", path);
            } else {
                println!("❌ Failed to delete secret: {}", response.status());
            }
        }
    }

    Ok(())
}
