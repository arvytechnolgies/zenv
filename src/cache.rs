use crate::crypto;
use crate::error::ZenvError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: String,
    pub environment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_dynamic: bool,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretEntry {
    pub meta: SecretMeta,
    /// Per-secret encrypted value. AAD = "{project_id}:{name}"
    pub sealed_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheStore {
    pub version: u32,
    pub secrets: HashMap<String, SecretEntry>,
}

pub struct Cache {
    store: CacheStore,
    file_path: PathBuf,
    project_id: String,
    key: [u8; 32],
}

impl Cache {
    /// Open an existing cache or create a new empty one.
    /// The outer blob AAD is `project_id.as_bytes()`.
    pub fn open(cache_dir: &Path, project_id: &str, key: [u8; 32]) -> Result<Self, ZenvError> {
        let file_name = format!("{}.sealed", &project_id[..8.min(project_id.len())]);
        let file_path = cache_dir.join(file_name);

        let store = if file_path.exists() {
            let encoded = std::fs::read_to_string(&file_path)
                .map_err(|e| ZenvError::Cache(format!("read cache file: {}", e)))?;
            let plaintext = crypto::open(&key, encoded.trim(), project_id.as_bytes())?;
            let json_str = String::from_utf8(plaintext)
                .map_err(|e| ZenvError::Cache(format!("cache not valid UTF-8: {}", e)))?;
            serde_json::from_str(&json_str)
                .map_err(|e| ZenvError::Cache(format!("cache JSON parse: {}", e)))?
        } else {
            debug!("creating new cache for project {}", &project_id[..8]);
            CacheStore {
                version: 1,
                secrets: HashMap::new(),
            }
        };

        Ok(Self {
            store,
            file_path,
            project_id: project_id.to_string(),
            key,
        })
    }

    /// Encrypt and set a secret. Per-secret AAD = "{project_id}:{name}".
    pub fn set(
        &mut self,
        name: &str,
        value: &str,
        environment: &str,
    ) -> Result<bool, ZenvError> {
        let aad = format!("{}:{}", self.project_id, name);
        let sealed_value = crypto::seal(&self.key, value.as_bytes(), aad.as_bytes())?;

        let now = Utc::now();
        let existed = self.store.secrets.contains_key(name);

        let meta = if let Some(existing) = self.store.secrets.get(name) {
            SecretMeta {
                name: name.to_string(),
                environment: environment.to_string(),
                created_at: existing.meta.created_at,
                updated_at: now,
                is_dynamic: false,
                provider: None,
            }
        } else {
            SecretMeta {
                name: name.to_string(),
                environment: environment.to_string(),
                created_at: now,
                updated_at: now,
                is_dynamic: false,
                provider: None,
            }
        };

        self.store.secrets.insert(
            name.to_string(),
            SecretEntry { meta, sealed_value },
        );

        Ok(existed)
    }

    /// Get a decrypted secret value.
    pub fn get(&self, name: &str) -> Result<String, ZenvError> {
        let entry = self
            .store
            .secrets
            .get(name)
            .ok_or_else(|| ZenvError::SecretNotFound(name.to_string()))?;

        let aad = format!("{}:{}", self.project_id, name);
        let plaintext = crypto::open(&self.key, &entry.sealed_value, aad.as_bytes())?;
        String::from_utf8(plaintext)
            .map_err(|e| ZenvError::Cache(format!("secret not valid UTF-8: {}", e)))
    }

    /// Remove a secret from the store.
    pub fn remove(&mut self, name: &str) -> Result<(), ZenvError> {
        self.store
            .secrets
            .remove(name)
            .ok_or_else(|| ZenvError::SecretNotFound(name.to_string()))?;
        Ok(())
    }

    /// Get all secrets for a given environment (or "all").
    pub fn get_for_env(&self, environment: &str) -> Result<HashMap<String, String>, ZenvError> {
        let mut result = HashMap::new();
        for (name, entry) in &self.store.secrets {
            if entry.meta.environment == environment || entry.meta.environment == "all" {
                let aad = format!("{}:{}", self.project_id, name);
                let plaintext = crypto::open(&self.key, &entry.sealed_value, aad.as_bytes())?;
                let value = String::from_utf8(plaintext)
                    .map_err(|e| ZenvError::Cache(format!("secret not valid UTF-8: {}", e)))?;
                result.insert(name.clone(), value);
            }
        }
        Ok(result)
    }

    /// Return metadata for all secrets, sorted by name.
    pub fn list_meta(&self) -> Vec<&SecretMeta> {
        let mut metas: Vec<&SecretMeta> = self.store.secrets.values().map(|e| &e.meta).collect();
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        metas
    }

    /// Return metadata for all secrets matching an environment.
    pub fn list_meta_for_env(&self, environment: &str) -> Vec<&SecretMeta> {
        let mut metas: Vec<&SecretMeta> = self
            .store
            .secrets
            .values()
            .filter(|e| e.meta.environment == environment || e.meta.environment == "all")
            .map(|e| &e.meta)
            .collect();
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        metas
    }

    /// Number of stored secrets.
    pub fn count(&self) -> usize {
        self.store.secrets.len()
    }

    /// All secret names.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.store.secrets.keys().cloned().collect();
        names.sort();
        names
    }

    /// Check if a secret exists.
    pub fn contains(&self, name: &str) -> bool {
        self.store.secrets.contains_key(name)
    }

    /// Flush the cache to disk. Outer blob AAD = project_id.
    pub fn flush(&self) -> Result<(), ZenvError> {
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ZenvError::Cache(format!("create cache dir: {}", e)))?;
        }

        let json = serde_json::to_string(&self.store)
            .map_err(|e| ZenvError::Serialization(format!("cache serialize: {}", e)))?;

        let sealed = crypto::seal(&self.key, json.as_bytes(), self.project_id.as_bytes())?;
        std::fs::write(&self.file_path, &sealed)
            .map_err(|e| ZenvError::Cache(format!("write cache file: {}", e)))?;

        debug!("cache flushed to {:?}", self.file_path);
        Ok(())
    }
}
