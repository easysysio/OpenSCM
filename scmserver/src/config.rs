use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::error::Error;
use tracing::{info, warn, error};
use base64::{engine::general_purpose, Engine as _};
use cfg_if::cfg_if;

// load OS specific modules
cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        use std::io::Write;
        use std::path::PathBuf;
        use toml;
    } else if #[cfg(target_os = "windows")] {
        use winreg::enums::*;
        use winreg::RegKey;
    }
}

// --- Constants ---
cfg_if! {
    if #[cfg(target_os = "linux")] {
        const CONFIG_PATH: &str = "/etc/openscm/scmserver.config";
        const DB_PATH: &str = "/var/lib/openscm/scm.db";
        const PRIVATE_KEY_PATH: &str = "/etc/openscm/keys/scmserver.key";
        const PUBLIC_KEY_PATH: &str = "/etc/openscm/keys/scmserver.pub";
    } else if #[cfg(target_os = "freebsd")] {
        const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmserver.config";
        const DB_PATH: &str = "/var/db/openscm/scm.db";
        const PRIVATE_KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmserver.key";
        const PUBLIC_KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmserver.pub";
    } else if #[cfg(target_os = "windows")] {
        const CONFIG_PATH: &str = r"C:\ProgramData\OpenSCM\Server\scmserver.config";
        const DB_PATH: &str = r"C:\ProgramData\OpenSCM\Server\scm.db";
        const PRIVATE_KEY_PATH: &str = r"C:\ProgramData\OpenSCM\Server\keys\scmserver.key";
        const PUBLIC_KEY_PATH: &str = r"C:\ProgramData\OpenSCM\Server\keys\scmserver.pub";
    }  else if #[cfg(target_os = "macos")] {
        const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmserver.config";
        const DB_PATH: &str = "/var/db/openscm/scm.db";
        const PRIVATE_KEY_PATH: &str ="/usr/local/etc/openscm/keys/scmserver.key";
        const PUBLIC_KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmserver.pub";
    }
}

pub fn db_path() -> &'static str { DB_PATH }
pub fn private_key_path() -> &'static str { PRIVATE_KEY_PATH }
pub fn config_path() -> &'static str { CONFIG_PATH }

// --- Structs ---

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub key: KeyConfig,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub port: Option<String>,
    pub loglevel: Option<String>,
    /// Peers whose X-Forwarded-For / X-Real-IP headers are believed, as CIDR
    /// ranges or single addresses. Unset: loopback and private ranges
    /// (handlers::DEFAULT_TRUSTED_PROXIES). An empty list trusts nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_proxies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct DatabaseConfig {
    /// SQLite file path (used when db_type = "sqlite", the default).
    pub path: String,
    /// Backend selector: "sqlite" (default), "mysql", or "postgres".
    pub db_type: Option<String>,
    /// Full MySQL connection URL (used when db_type = "mysql").
    pub mysql_url: Option<String>,
    /// Full PostgreSQL connection URL (used when db_type = "postgres").
    pub postgres_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct KeyConfig {
    pub public_key: Option<String>,
    pub private_key: Option<String>,
}

// --- Default ---

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: Some("8000".to_string()),
                loglevel: Some("info".to_string()),
                trusted_proxies: None,
            },
            database: DatabaseConfig {
                path: DB_PATH.to_string(),
                db_type: None,
                mysql_url: None,
                postgres_url: None,
            },
            key: KeyConfig {
                public_key: Some(PUBLIC_KEY_PATH.to_string()),
                private_key: Some(PRIVATE_KEY_PATH.to_string()),
            },
        }
    }
}

// --- Key Generation ---

pub fn generate_keys_if_missing() -> Result<(), Box<dyn Error>> {
    let priv_path = Path::new(PRIVATE_KEY_PATH);
    let pub_path = Path::new(PUBLIC_KEY_PATH);

    if priv_path.exists() && pub_path.exists() {
        return Ok(());
    }

    if priv_path.exists() || pub_path.exists() {
        warn!("Incomplete key pair found. Regenerating for consistency.");
    } else {
        info!("Initializing OpenSCM server identity keys...");
    }


    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = VerifyingKey::from(&signing_key);

    let priv_encoded = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let pub_encoded = general_purpose::STANDARD.encode(verify_key.to_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).mode(0o600);
        let mut priv_file = options.open(priv_path)?;
        priv_file.write_all(priv_encoded.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(priv_path, &priv_encoded)?;
    }

    fs::write(pub_path, pub_encoded)?;
    info!("Server keys generated successfully.");
    Ok(())
}

// --- Validation ---

fn validate_and_setup_keys(config: &mut Config) -> Result<(), Box<dyn Error>> {
    if let Some(p) = &config.server.port {
        p.parse::<u16>().map_err(|_| {
            error!("Invalid port in config: '{}'.", p);
            format!("Invalid port: {}", p)
        })?;
    }

    // Force constants to ensure compliance
    config.database.path = DB_PATH.to_string();
    config.key.private_key = Some(PRIVATE_KEY_PATH.to_string());
    config.key.public_key = Some(PUBLIC_KEY_PATH.to_string());

    generate_keys_if_missing()?;
    Ok(())
}

// --- Config Implementation ---

impl Config {
    pub fn load() -> Result<Self, Box<dyn Error>> {
        cfg_if! {
            if #[cfg(target_os = "windows")] {
                info!("Loading configuration from Windows Registry...");
                Self::load_from_registry()
            } else {
                let path = PathBuf::from(CONFIG_PATH);
                info!("Loading configuration from {:?}...", path);
                if !path.exists() {
                    warn!("Config file not found. Bootstrapping defaults...");
                    let mut default_cfg = Self::default();
                    validate_and_setup_keys(&mut default_cfg)?;
                    default_cfg.save()?;
                    return Ok(default_cfg);
                }
                Self::load_from_toml(&path)
            }
        }
    }

    cfg_if! {
        if #[cfg(target_os = "windows")] {
            fn load_from_registry() -> Result<Self, Box<dyn Error>> {
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Server")?;

                let port     = key.get_value("Port").unwrap_or_else(|_| "8000".to_string());
                let loglevel = key.get_value("LogLevel").unwrap_or_else(|_| "info".to_string());

                // 1. Initialize using your Default to get all fields (database, key, etc.)
                let mut config = Config::default();
                config.server.port = Some(port);
                config.server.loglevel = Some(loglevel);
                // Optional, comma-separated; absent means the defaults.
                config.server.trusted_proxies = key.get_value::<String, _>("TrustedProxies").ok()
                    .map(|v| v.split(',').map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect());

                // 2. Check if we need to repair missing registry values
                let needs_repair = [
                    key.get_value::<String, _>("Port").is_err(),
                    key.get_value::<String, _>("LogLevel").is_err(),
                ].iter().any(|&missing| missing);

                if needs_repair {
                    warn!("Registry settings were missing. Performing self-repair...");
                    config.save()?;
                }
                
                validate_and_setup_keys(&mut config)?;
                Ok(config)
            }

            pub fn save(&self) -> Result<(), Box<dyn Error>> {
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Server")?;
                if let Some(p) = &self.server.port { key.set_value("Port", p)?; }
                if let Some(l) = &self.server.loglevel { key.set_value("LogLevel", l)?; }
                Ok(())
            }
        } else {
            pub fn save(&self) -> Result<(), Box<dyn Error>> {
                let path = PathBuf::from(CONFIG_PATH);
                let toml_string = toml::to_string_pretty(self)?;
                fs::write(path, toml_string)?;
                Ok(())
            }

            fn load_from_toml(path: &Path) -> Result<Self, Box<dyn Error>> {
                let contents = fs::read_to_string(path)?;
                let mut config: Config = toml::from_str(&contents)?;
                validate_and_setup_keys(&mut config)?;
                Ok(config)
            }
        }
    }
} 

