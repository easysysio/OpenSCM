use serde::{Deserialize, Serialize};
use std::error::Error;
use tracing::{info, warn, error};
use cfg_if::cfg_if;

// load OS specific modules
cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        use std::path::Path;
        use std::fs;
        use std::path::PathBuf;
    } else if #[cfg(target_os = "windows")] {
        use winreg::enums::*;
        use winreg::RegKey;
    }
}


// ============================================================
// CONSTANTS
// ============================================================

cfg_if! {
    if #[cfg(target_os = "linux")] {
        const CONFIG_PATH: &str = "/etc/openscm/scmclient.config";
        const KEY_PATH: &str = "/etc/openscm/keys/scmclient";
        const LOCK_PATH: &str = "/etc/openscm/scmclient.lock";
    } else if #[cfg(target_os = "freebsd")] {
        const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmclient.config";
        const KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmclient";
        const LOCK_PATH: &str = "/usr/local/etc/openscm/scmclient.lock";
    } else if #[cfg(target_os = "windows")] {
        const CONFIG_PATH: &str = r"C:\ProgramData\OpenSCM\Client\scmclient.config";
        const KEY_PATH: &str = r"C:\ProgramData\OpenSCM\Client\keys\scmclient";
        const LOCK_PATH: &str = r"C:\ProgramData\OpenSCM\Client\scmclient.lock";
    } else if #[cfg(target_os = "macos")] {
        const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmclient.config";
        const KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmclient";
        const LOCK_PATH: &str = "/usr/local/etc/openscm/scmclient.lock";
    }
}

pub fn key_path() -> &'static str { KEY_PATH }
pub fn config_path() -> &'static str { CONFIG_PATH }
// Single-instance advisory-lock file (same dir as the config, created by
// check_required_directories). See the lock guard in main().
pub fn lock_path() -> &'static str { LOCK_PATH }

// ============================================================
// REGISTRY SCHEMA (Windows)
// ============================================================
//
// Defines the canonical set of registry values.
// On every startup, values NOT in this list are deleted automatically.
// When adding a new setting: add it here + add it to normalize() below.
//
#[cfg(target_os = "windows")]
const CURRENT_REGISTRY_KEYS: &[&str] = &[
    "ServerURL",
    "Organization",
    "Heartbeat",
    "LogLevel",
    "CmdEnabled",
    "PsEnabled",
    "EnrollmentToken",
];

// ============================================================
// STRUCTS
// ============================================================

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub url: String,
    #[serde(alias = "tenant_id")]   // v0.2.2 and older used tenant_id
    pub organization: String,
    /// Optional golden enrollment token. When set, sent at first registration
    /// so the server auto-approves this system instead of leaving it pending.
    /// Approval bypass only — see docs/design/0.6.0-enrollment-tokens.md.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct ClientConfig {
    pub heartbeat:   Option<String>,
    pub loglevel:    Option<String>,
    pub cmd_enabled: Option<bool>,
    pub ps_enabled:  Option<bool>,
}


// ============================================================
// DEFAULT
// ============================================================

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                url:          "http://localhost:8000".to_string(),
                organization: "default".to_string(),
                enrollment_token: None,
            },
            client: ClientConfig {
                heartbeat:   Some("300".to_string()),
                loglevel:    Some("info".to_string()),
                cmd_enabled: Some(false),
                ps_enabled:  Some(false),
            },
        }
    }
}


// ============================================================
// NORMALIZE
// ============================================================
//
// Fills any absent optional fields with their defaults.
// Called on every load so the on-disk config is always up to date.
//
// When adding a new optional setting:
//   1. Add the field to ClientConfig above
//   2. Add its default to Config::default() above
//   3. Add one line here
//   4. Add the registry key name to CURRENT_REGISTRY_KEYS (Windows)
//   5. Add it to the NSIS installer WriteRegStr block
//
impl Config {
    // Fills any absent optional fields with their defaults. Returns a tuple of
    // (normalised_config, changed) so callers can skip rewriting the file when
    // the on-disk form already matches the in-memory form — avoiding pointless
    // disk writes (and mtime churn that confuses file-integrity monitors).
    fn normalize(mut self) -> (Self, bool) {
        let d = Config::default();
        let mut changed = false;
        if self.client.heartbeat.is_none()   { self.client.heartbeat   = d.client.heartbeat;   changed = true; }
        if self.client.loglevel.is_none()    { self.client.loglevel    = d.client.loglevel;    changed = true; }
        if self.client.cmd_enabled.is_none() { self.client.cmd_enabled = d.client.cmd_enabled; changed = true; }
        if self.client.ps_enabled.is_none()  { self.client.ps_enabled  = d.client.ps_enabled;  changed = true; }
        (self, changed)
    }
}


// ============================================================
// SAVE
// ============================================================

impl Config {
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        cfg_if! {
            if #[cfg(target_os = "windows")] {
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

                key.set_value("ServerURL",    &self.server.url)?;
                key.set_value("Organization", &self.server.organization)?;
                if let Some(tok) = &self.server.enrollment_token { key.set_value("EnrollmentToken", tok)?; }

                if let Some(hb)  = &self.client.heartbeat   { key.set_value("Heartbeat",  hb)?; }
                if let Some(ll)  = &self.client.loglevel     { key.set_value("LogLevel",   ll)?; }
                if let Some(cmd) =  self.client.cmd_enabled  { key.set_value("CmdEnabled", &cmd.to_string())?; }
                if let Some(ps)  =  self.client.ps_enabled   { key.set_value("PsEnabled",  &ps.to_string())?;  }

                Ok(())
            } else {
                let path = PathBuf::from(CONFIG_PATH);
                let toml_string = toml::to_string_pretty(self)?;
                fs::write(&path, toml_string)?;
                Ok(())
            }
        }
    }
}


// ============================================================
// PUBLIC ENTRY POINT
// ============================================================

pub fn get_config() -> Result<Config, Box<dyn Error>> {
    cfg_if! {
        if #[cfg(target_os = "windows")] {
            load_from_registry()
        } else {
            let path = PathBuf::from(CONFIG_PATH);

            if !path.exists() {
                warn!(
                    "Config file not found at '{}'. Bootstrapping defaults.",
                    CONFIG_PATH
                );
                bootstrap_default_config(&path)?;
            }

            load_from_toml(&path)
        }
    }
}


// ============================================================
// PRIVATE HELPERS
// ============================================================

#[cfg(target_os = "windows")]
fn load_from_registry() -> Result<Config, Box<dyn Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

    let read_val = |name: &str, default: &str| -> String {
        key.get_value::<String, _>(name)
            .unwrap_or_else(|_| default.to_string())
            .trim_matches(char::from(0))
            .trim()
            .to_string()
    };

    // Field migration: TenantId → Organization (v0.2.3)
    let organization = {
        let org = read_val("Organization", "");
        if org.is_empty() {
            let legacy = read_val("TenantId", "default");
            if legacy != "default" {
                warn!("Migrating registry: 'TenantId' → 'Organization'.");
            }
            legacy
        } else {
            org
        }
    };

    let url = read_val("ServerURL", "http://localhost:8000");
    if url.is_empty() {
        error!("Registry: ServerURL is empty. Please set a valid server URL.");
        return Err("ServerURL is required but empty in registry".into());
    }

    let enrollment_token = {
        let t = read_val("EnrollmentToken", "");
        if t.is_empty() { None } else { Some(t) }
    };

    let (config, changed) = Config {
        server: ServerConfig { url, organization, enrollment_token },
        client: ClientConfig {
            heartbeat:   Some(read_val("Heartbeat",  "300")),
            loglevel:    Some(read_val("LogLevel",   "info")),
            cmd_enabled: Some(read_val("CmdEnabled", "false") == "true"),
            ps_enabled:  Some(read_val("PsEnabled",  "false") == "true"),
        },
    }
    .normalize();

    // Save only when normalize filled in something missing.
    if changed {
        if let Err(e) = config.save() {
            warn!("Failed to update registry: {}.", e);
        }
    }

    // Delete any registry values outside the current schema (stale / renamed)
    let existing: Vec<String> = key
        .enum_values()
        .filter_map(|r| r.ok().map(|(name, _)| name))
        .collect();

    for name in &existing {
        if !CURRENT_REGISTRY_KEYS.contains(&name.as_str()) {
            match key.delete_value(name) {
                Ok(_)  => info!("Removed stale registry value: '{}'.", name),
                Err(e) => warn!("Could not remove stale registry value '{}': {}.", name, e),
            }
        }
    }

    Ok(config)
}


#[cfg(not(target_os = "windows"))]
fn bootstrap_default_config(path: &Path) -> Result<(), Box<dyn Error>> {
    let default_config = Config::default();
    let toml_string = toml::to_string_pretty(&default_config)?;
    fs::write(path, &toml_string)?;
    info!("Default configuration written to '{}'.", path.display());
    info!("Please edit the configuration file and set your server URL before running.");
    Ok(())
}


#[cfg(not(target_os = "windows"))]
fn load_from_toml(path: &Path) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;  // serde aliases handle field renames

    if config.server.url.trim().is_empty() {
        error!("Configuration error: 'server.url' is empty in '{}'.", path.display());
        return Err("server.url is required but empty in config file".into());
    }
    if config.server.organization.trim().is_empty() {
        error!("Configuration error: 'server.organization' is empty in '{}'.", path.display());
        return Err("server.organization is required but empty in config file".into());
    }

    let (config, changed) = config.normalize();

    // Save only when normalize filled in something missing (or to migrate a
    // legacy field rename — handled by serde aliases during deserialisation
    // and surfaced here by comparing the post-load text).
    if changed
        && let Err(e) = config.save()
    {
        warn!("Failed to update config file: {}.", e);
    }

    Ok(config)
}
