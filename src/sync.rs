use crate::error::ZenvError;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use tracing::debug;

#[derive(Debug, Clone, PartialEq)]
pub enum DiffEntry {
    Add { key: String },
    Update { key: String },
    Remove { key: String },
    Unchanged { key: String },
}

impl DiffEntry {
    pub fn key(&self) -> &str {
        match self {
            DiffEntry::Add { key } => key,
            DiffEntry::Update { key } => key,
            DiffEntry::Remove { key } => key,
            DiffEntry::Unchanged { key } => key,
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            DiffEntry::Add { .. } => "+",
            DiffEntry::Update { .. } => "~",
            DiffEntry::Remove { .. } => "−",
            DiffEntry::Unchanged { .. } => "=",
        }
    }
}

/// Pure function: compute diff between local and remote secret sets.
/// Returns sorted entries.
pub fn compute_diff(
    local: &HashMap<String, String>,
    remote: &HashMap<String, String>,
) -> Vec<DiffEntry> {
    let all_keys: BTreeSet<&String> = local.keys().chain(remote.keys()).collect();
    let mut entries = Vec::new();

    for key in all_keys {
        match (local.get(key), remote.get(key)) {
            (Some(lv), Some(rv)) => {
                if lv == rv {
                    entries.push(DiffEntry::Unchanged {
                        key: key.to_string(),
                    });
                } else {
                    entries.push(DiffEntry::Update {
                        key: key.to_string(),
                    });
                }
            }
            (Some(_), None) => {
                entries.push(DiffEntry::Add {
                    key: key.to_string(),
                });
            }
            (None, Some(_)) => {
                entries.push(DiffEntry::Remove {
                    key: key.to_string(),
                });
            }
            (None, None) => unreachable!(),
        }
    }

    entries
}

#[derive(Debug, Serialize)]
struct VercelEnvBody {
    key: String,
    value: String,
    r#type: String,
    target: Vec<String>,
}

/// Push a secret to Vercel.
/// POST https://api.vercel.com/v9/projects/{id}/env
pub async fn push_to_vercel(
    api_token: &str,
    project_id: &str,
    key: &str,
    value: &str,
    environment: &str,
) -> Result<(), ZenvError> {
    debug!(
        "Vercel sync: project={}, key={}, env={}",
        project_id, key, environment
    );

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.vercel.com/v9/projects/{}/env",
        project_id
    );

    let body = VercelEnvBody {
        key: key.to_string(),
        value: value.to_string(),
        r#type: "encrypted".to_string(),
        target: vec![environment.to_string()],
    };

    let resp = client
        .post(&url)
        .bearer_auth(api_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| ZenvError::Sync(format!("Vercel API request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(ZenvError::Sync(format!(
            "Vercel API returned {}: {}",
            status, text
        )));
    }

    Ok(())
}

/// Push a secret to GitHub Actions.
///
/// Real flow:
/// 1. GET /repos/{owner}/{repo}/actions/secrets/public-key → { key_id, key }
/// 2. Encrypt value with libsodium sealed_box using the public key
/// 3. PUT /repos/{owner}/{repo}/actions/secrets/{name}
///    Body: { encrypted_value: base64(sealed_box), key_id }
pub async fn push_to_github(
    token: &str,
    owner: &str,
    repo: &str,
    name: &str,
    _value: &str,
) -> Result<(), ZenvError> {
    debug!(
        "GitHub Actions sync: {}/{}, secret={}",
        owner, repo, name
    );

    // Step 1: Get the repository public key
    let client = reqwest::Client::new();
    let _pk_url = format!(
        "https://api.github.com/repos/{}/{}/actions/secrets/public-key",
        owner, repo
    );

    // Step 2: Encrypt with libsodium sealed box (requires libsodium bindings)
    // let sealed = crypto_box::SealedBox::seal(value.as_bytes(), &public_key);

    // Step 3: PUT the encrypted secret
    let _secret_url = format!(
        "https://api.github.com/repos/{}/{}/actions/secrets/{}",
        owner, repo, name
    );

    // Stub: log that we'd push but don't have libsodium linked
    debug!(
        "GitHub Actions push requires libsodium sealed box encryption. \
         Configure credentials in .zenv.toml to enable. Token present: {}",
        !token.is_empty()
    );

    Err(ZenvError::Sync(
        "GitHub Actions sync requires libsodium — planned for v2".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_diff() {
        let local: HashMap<String, String> = [
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2-new".to_string()),
            ("C".to_string(), "3".to_string()),
        ]
        .into();
        let remote: HashMap<String, String> = [
            ("B".to_string(), "2-old".to_string()),
            ("D".to_string(), "4".to_string()),
        ]
        .into();
        let diff = compute_diff(&local, &remote);
        assert_eq!(diff.len(), 4);
        assert!(diff.iter().any(|e| matches!(e, DiffEntry::Add { key } if key == "A")));
        assert!(diff.iter().any(|e| matches!(e, DiffEntry::Add { key } if key == "C")));
        assert!(diff.iter().any(|e| matches!(e, DiffEntry::Update { key } if key == "B")));
        assert!(diff.iter().any(|e| matches!(e, DiffEntry::Remove { key } if key == "D")));
    }
}
