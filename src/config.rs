use crate::error::ZenvError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Project configuration — stored in `.zenv.toml` at the project root.
/// Safe to commit (contains no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub project_id: String,
    pub project_name: String,
    #[serde(default = "default_environment")]
    pub default_environment: String,
    #[serde(default)]
    pub dynamic_providers: Vec<DynamicProviderConfig>,
    #[serde(default)]
    pub sync_targets: Vec<SyncTargetConfig>,
    #[serde(default)]
    pub strip_patterns: Vec<String>,
}

fn default_environment() -> String {
    "development".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicProviderConfig {
    pub name: String,
    pub provider_type: String,
    #[serde(default)]
    pub config: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTargetConfig {
    pub name: String,
    pub target_type: String,
    #[serde(default)]
    pub config: std::collections::HashMap<String, String>,
}

/// Per-device configuration — stored at `~/.zenv/device.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub created_at: DateTime<Utc>,
}

impl ProjectConfig {
    pub fn new(name: &str) -> Self {
        Self {
            project_id: Uuid::new_v4().to_string(),
            project_name: name.to_string(),
            default_environment: "development".to_string(),
            dynamic_providers: Vec::new(),
            sync_targets: Vec::new(),
            strip_patterns: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, ZenvError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ZenvError::Config(format!("read .zenv.toml: {}", e)))?;
        toml::from_str(&content)
            .map_err(|e| ZenvError::Config(format!("parse .zenv.toml: {}", e)))
    }

    pub fn save(&self, path: &Path) -> Result<(), ZenvError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ZenvError::Serialization(format!("serialize config: {}", e)))?;
        std::fs::write(path, content)
            .map_err(|e| ZenvError::Config(format!("write .zenv.toml: {}", e)))
    }
}

impl DeviceConfig {
    pub fn new() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
        }
    }

    pub fn load_or_create() -> Result<Self, ZenvError> {
        let path = device_config_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| ZenvError::Config(format!("read device.toml: {}", e)))?;
            toml::from_str(&content)
                .map_err(|e| ZenvError::Config(format!("parse device.toml: {}", e)))
        } else {
            let config = Self::new();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<(), ZenvError> {
        let path = device_config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ZenvError::Config(format!("create ~/.zenv: {}", e)))?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| ZenvError::Serialization(format!("serialize device config: {}", e)))?;
        std::fs::write(&path, content)
            .map_err(|e| ZenvError::Config(format!("write device.toml: {}", e)))
    }
}

/// Walk up from cwd looking for `.zenv.toml`, like git does with `.git`.
pub fn find_project_root() -> Result<PathBuf, ZenvError> {
    let mut dir = std::env::current_dir().map_err(ZenvError::Io)?;
    loop {
        if dir.join(".zenv.toml").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(ZenvError::NotInitialized);
        }
    }
}

/// Return `~/.zenv/cache/`.
pub fn cache_dir() -> Result<PathBuf, ZenvError> {
    let home = dirs::home_dir()
        .ok_or_else(|| ZenvError::Config("cannot determine home directory".to_string()))?;
    Ok(home.join(".zenv").join("cache"))
}

/// Return `~/.zenv/device.toml`.
fn device_config_path() -> Result<PathBuf, ZenvError> {
    let home = dirs::home_dir()
        .ok_or_else(|| ZenvError::Config("cannot determine home directory".to_string()))?;
    Ok(home.join(".zenv").join("device.toml"))
}

/// Return `~/.zenv/`.
pub fn zenv_dir() -> Result<PathBuf, ZenvError> {
    let home = dirs::home_dir()
        .ok_or_else(|| ZenvError::Config("cannot determine home directory".to_string()))?;
    Ok(home.join(".zenv"))
}
