use crate::error::ZenvError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit master key. Zeroed on drop — never clone unnecessarily.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive a purpose-specific subkey via HKDF-SHA256.
    /// Info string: "zenv.v1.{purpose}" — domain separation ensures
    /// keys for storage, identity, and exchange are cryptographically
    /// independent even if one leaks.
    pub fn derive(&self, purpose: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let info = format!("zenv.v1.{}", purpose);
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm)
            .expect("HKDF expand should not fail for 32-byte output");
        okm
    }

    /// Derive a storage key scoped to a specific project.
    pub fn storage_key(&self, project_id: &str) -> [u8; 32] {
        self.derive(&format!("storage:{}", project_id))
    }

    /// Return the first 8 bytes of the raw key as a hex fingerprint.
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

/// Encrypt plaintext with ChaCha20-Poly1305.
/// Random 12-byte nonce from OsRng. AAD is bound into the AEAD tag.
/// Returns base64(nonce || ciphertext+tag).
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String, ZenvError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ZenvError::Crypto(format!("cipher init: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| ZenvError::Crypto(format!("seal failed: {}", e)))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// Decrypt a base64(nonce || ciphertext+tag) blob.
/// AAD must match what was used during seal().
pub fn open(key: &[u8; 32], encoded: &str, aad: &[u8]) -> Result<Vec<u8>, ZenvError> {
    let combined = BASE64
        .decode(encoded)
        .map_err(|e| ZenvError::Crypto(format!("base64 decode: {}", e)))?;

    if combined.len() < 12 {
        return Err(ZenvError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ZenvError::Crypto(format!("cipher init: {}", e)))?;

    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| ZenvError::Crypto(format!("open failed (wrong key or tampered): {}", e)))
}

/// Shannon entropy in bits per character.
/// Random base64 ≈ 5.5, English text ≈ 4.0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Three-signal heuristic to detect if a value looks like a secret.
/// Returns (is_secret, reason).
pub fn looks_like_secret(name: &str, value: &str) -> (bool, &'static str) {
    // Signal 1: Known vendor prefix match
    let vendor_prefixes = [
        "sk_live_",
        "sk_test_",
        "pk_live_",
        "pk_test_",
        "ghp_",
        "gho_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "AKIA",
        "SG.",
        "sk-",
        "eyJ",
        "-----BEGIN",
        "AIza",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxs-",
        "glpat-",
        "npm_",
        "pypi-",
        "op://",
        "vault:v1:",
        "AgA",
        "whsec_",
        "rk_live_",
        "rk_test_",
    ];
    for prefix in &vendor_prefixes {
        if value.starts_with(prefix) {
            return (true, "known vendor secret prefix");
        }
    }

    let entropy = shannon_entropy(value);

    // Signal 2: High entropy for long values
    if value.len() >= 24 && entropy > 4.5 {
        return (true, "high entropy (likely random credential)");
    }

    // Signal 3: Name contains secret keyword + moderate entropy + decent length
    let name_lower = name.to_lowercase();
    let secret_keywords = [
        "key",
        "secret",
        "token",
        "password",
        "credential",
        "passwd",
        "api_key",
        "apikey",
        "auth",
        "private",
    ];
    let has_keyword = secret_keywords.iter().any(|kw| name_lower.contains(kw));
    if has_keyword && entropy > 3.5 && value.len() >= 20 {
        return (true, "secret keyword in name + high entropy");
    }

    (false, "")
}

/// Load or create the master key. Priority:
/// 1. ZENV_MASTER_KEY env var (CI/CD mode, hex-encoded)
/// 2. OS keychain via keyring
/// 3. Generate new key, persist to keychain
pub fn load_or_create_master_key(device_id: &str) -> Result<MasterKey, ZenvError> {
    // 1. Check env var first (CI/CD escape hatch)
    if let Ok(hex_key) = std::env::var("ZENV_MASTER_KEY") {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| ZenvError::Crypto(format!("invalid ZENV_MASTER_KEY hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(ZenvError::Crypto(format!(
                "ZENV_MASTER_KEY must be 64 hex chars (32 bytes), got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(MasterKey::from_bytes(arr));
    }

    // 2. Try OS keychain
    let entry = keyring::Entry::new("zenv", device_id)
        .map_err(|e| ZenvError::Keychain(format!("keyring entry creation failed: {}", e)))?;

    match entry.get_password() {
        Ok(hex_key) => {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|e| ZenvError::Crypto(format!("corrupt keychain key: {}", e)))?;
            if bytes.len() != 32 {
                return Err(ZenvError::Crypto("corrupt keychain key length".into()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(MasterKey::from_bytes(arr))
        }
        Err(_) => {
            // 3. Generate new key
            let mut key_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key_bytes);
            let hex_key = hex::encode(key_bytes);
            entry
                .set_password(&hex_key)
                .map_err(|e| ZenvError::Keychain(format!("failed to store key: {}", e)))?;
            Ok(MasterKey::from_bytes(key_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello zenv";
        let aad = b"test-project";
        let sealed = seal(&key, plaintext, aad).unwrap();
        let opened = open(&key, &sealed, aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_open_wrong_aad_fails() {
        let key = [42u8; 32];
        let plaintext = b"secret";
        let sealed = seal(&key, plaintext, b"correct-aad").unwrap();
        assert!(open(&key, &sealed, b"wrong-aad").is_err());
    }

    #[test]
    fn test_shannon_entropy() {
        let e = shannon_entropy("aaaa");
        assert!(e < 0.01);
        let e = shannon_entropy("abcdefghijklmnopqrstuvwxyz");
        assert!(e > 4.0);
    }

    #[test]
    fn test_looks_like_secret() {
        assert!(looks_like_secret("key", "sk_live_abcdefghijklmnop").0);
        assert!(looks_like_secret("x", "ghp_1234567890abcdef").0);
        assert!(!looks_like_secret("name", "hello world").0);
    }

    #[test]
    fn test_hkdf_derive() {
        let mk = MasterKey::from_bytes([1u8; 32]);
        let k1 = mk.derive("storage:proj1");
        let k2 = mk.derive("storage:proj2");
        assert_ne!(k1, k2);
    }
}
