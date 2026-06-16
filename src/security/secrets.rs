use std::collections::HashMap;
use std::env;

use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use zeroize::Zeroize;

use crate::error::{AegisError, Result};
use crate::security::crypto::CryptoProvider;

const SECRET_ROTATION_DAYS: i64 = 90;
const MASTER_KEY_ENV_VAR: &str = "AEGIS_MASTER_KEY";
const MASTER_KEY_MIN_LENGTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: u32,
    pub created_at: i64,
}

impl Drop for EncryptedSecret {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

#[derive(Debug)]
struct SecretEntry {
    #[allow(dead_code)]
    name: String,
    encrypted: EncryptedSecret,
    loaded_at: i64,
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        self.encrypted.ciphertext.zeroize();
    }
}

#[allow(dead_code)]
fn generate_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex char at position {}: {}", i, e))
        })
        .collect()
}

fn read_master_key() -> Result<Vec<u8>> {
    let encoded = env::var(MASTER_KEY_ENV_VAR).map_err(|_| {
        AegisError::ConfigError(
            "AEGIS_MASTER_KEY environment variable not set. \
             Generate one with: openssl rand -hex 32"
                .into(),
        )
    })?;

    let key_bytes = decode_hex(&encoded).map_err(|e| {
        AegisError::ConfigError(format!("AEGIS_MASTER_KEY is not valid hex: {}", e))
    })?;

    if key_bytes.len() < MASTER_KEY_MIN_LENGTH {
        return Err(AegisError::ConfigError(format!(
            "AEGIS_MASTER_KEY must be at least {} bytes ({} hex chars), got {} bytes",
            MASTER_KEY_MIN_LENGTH,
            MASTER_KEY_MIN_LENGTH * 2,
            key_bytes.len()
        )));
    }

    Ok(key_bytes)
}

pub struct SecretManager {
    master_key: RwLock<Vec<u8>>,
    key_versions: RwLock<HashMap<u32, Vec<u8>>>,
    secrets: RwLock<HashMap<String, SecretEntry>>,
}

impl Drop for SecretManager {
    fn drop(&mut self) {
        let mut master = self.master_key.write();
        master.zeroize();

        let mut versions = self.key_versions.write();
        for (_ver, key) in versions.iter_mut() {
            key.zeroize();
        }
        versions.clear();

        let mut secrets = self.secrets.write();
        secrets.clear();
    }
}

impl SecretManager {
    pub fn new() -> Result<Self> {
        let master_key = read_master_key()?;

        let mut key_versions = HashMap::new();
        key_versions.insert(1u32, master_key.clone());

        info!(
            "SecretManager initialized with {} key versions",
            key_versions.len()
        );

        Ok(Self {
            master_key: RwLock::new(master_key),
            key_versions: RwLock::new(key_versions),
            secrets: RwLock::new(HashMap::new()),
        })
    }

    pub fn from_env_var(var_name: &str) -> Result<String> {
        env::var(var_name).map_err(|_| {
            AegisError::ConfigError(format!("Environment variable '{}' is not set", var_name))
        })
    }

    pub fn load_secret(&self, name: &str) -> Result<String> {
        let master = self.master_key.read();

        if let Ok(val) = env::var(name) {
            let encrypted = CryptoProvider::encrypt_secret_payload(&master, &val)?;

            let mut secrets = self.secrets.write();
            secrets.insert(
                name.to_string(),
                SecretEntry {
                    name: name.to_string(),
                    encrypted: encrypted.clone(),
                    loaded_at: chrono::Utc::now().timestamp(),
                },
            );

            debug!("Secret '{}' loaded from environment", name);
            return Ok(val);
        }

        let secrets = self.secrets.read();
        if let Some(entry) = secrets.get(name) {
            let key = self
                .key_versions
                .read()
                .get(&entry.encrypted.key_version)
                .cloned()
                .ok_or_else(|| AegisError::SecurityViolation {
                    reason: format!(
                        "Key version {} not found for secret '{}'",
                        entry.encrypted.key_version, name
                    ),
                })?;

            let decrypted = CryptoProvider::decrypt_secret_payload(&key, &entry.encrypted)?;
            return Ok(decrypted);
        }

        Err(AegisError::ConfigError(format!(
            "Secret '{}' not found in environment or secret store",
            name
        )))
    }

    pub fn encrypt_secret(&self, value: &str) -> Result<EncryptedSecret> {
        let master = self.master_key.read();
        CryptoProvider::encrypt_secret_payload(&master, value)
    }

    pub fn decrypt_secret(&self, encrypted: &EncryptedSecret) -> Result<String> {
        let key = self
            .key_versions
            .read()
            .get(&encrypted.key_version)
            .cloned()
            .ok_or_else(|| AegisError::SecurityViolation {
                reason: format!(
                    "Key version {} not available for decryption",
                    encrypted.key_version
                ),
            })?;

        CryptoProvider::decrypt_secret_payload(&key, encrypted)
    }

    pub fn rotate_secrets(&self) -> Result<()> {
        let new_version: u32;

        {
            let versions = self.key_versions.read();
            let max_version = versions.keys().max().copied().unwrap_or(0);
            new_version =
                max_version
                    .checked_add(1)
                    .ok_or_else(|| AegisError::SecurityViolation {
                        reason: "Key version overflow".into(),
                    })?;
        }

        let new_key: Vec<u8> = {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key.to_vec()
        };

        let mut master = self.master_key.write();
        *master = new_key.clone();
        drop(master);

        let mut versions = self.key_versions.write();
        versions.insert(new_version, new_key);

        let re_encrypt_count = {
            let mut secrets = self.secrets.write();
            let mut count = 0usize;

            for (_name, entry) in secrets.iter_mut() {
                let plain = CryptoProvider::decrypt_secret_payload(
                    &self
                        .key_versions
                        .read()
                        .get(&1)
                        .cloned()
                        .unwrap_or_default(),
                    &entry.encrypted,
                )
                .ok();

                if let Some(plaintext) = plain {
                    if let Ok(new_encrypted) =
                        CryptoProvider::encrypt_secret_payload(&self.master_key.read(), &plaintext)
                    {
                        entry.encrypted = new_encrypted;
                        entry.encrypted.key_version = new_version;
                        entry.loaded_at = chrono::Utc::now().timestamp();
                        count += 1;
                    }
                }
            }
            count
        };

        info!(
            "Secret rotation completed: new_version={}, re-encrypted_secrets={}",
            new_version, re_encrypt_count
        );

        Ok(())
    }

    pub fn needs_rotation(&self) -> bool {
        let secrets = self.secrets.read();
        if secrets.is_empty() {
            return false;
        }

        let now = chrono::Utc::now().timestamp();
        let rotation_seconds = SECRET_ROTATION_DAYS * 86400;

        secrets
            .values()
            .any(|entry| now - entry.loaded_at > rotation_seconds)
    }

    pub fn store_secret(&self, name: &str, value: &str) -> Result<()> {
        let master = self.master_key.read();
        let encrypted = CryptoProvider::encrypt_secret_payload(&master, value)?;

        let mut secrets = self.secrets.write();
        secrets.insert(
            name.to_string(),
            SecretEntry {
                name: name.to_string(),
                encrypted,
                loaded_at: chrono::Utc::now().timestamp(),
            },
        );

        debug!("Secret '{}' stored (encrypted)", name);
        Ok(())
    }

    pub fn remove_secret(&self, name: &str) -> Result<()> {
        let mut secrets = self.secrets.write();
        if let Some(entry) = secrets.remove(name) {
            drop(entry);
            debug!("Secret '{}' removed and zeroized", name);
            Ok(())
        } else {
            Err(AegisError::ConfigError(format!(
                "Secret '{}' not found",
                name
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_key() {
        let bytes = CryptoProvider::generate_random_bytes(32);
        let key: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        env::set_var(MASTER_KEY_ENV_VAR, key);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        setup_test_key();
        let manager = SecretManager::new().unwrap();
        let original = "database-password-12345!@#$%";

        let encrypted = manager.encrypt_secret(original).unwrap();
        let decrypted = manager.decrypt_secret(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_load_from_env() {
        setup_test_key();
        env::set_var("AEGIS_TEST_SECRET", "test-value-12345");
        let manager = SecretManager::new().unwrap();

        let value = manager.load_secret("AEGIS_TEST_SECRET").unwrap();
        assert_eq!(value, "test-value-12345");

        env::remove_var("AEGIS_TEST_SECRET");
    }

    #[test]
    fn test_store_and_retrieve() {
        setup_test_key();
        let manager = SecretManager::new().unwrap();
        let secret_value = "redis-password-abc123";

        manager
            .store_secret("REDIS_PASSWORD", secret_value)
            .unwrap();
        let retrieved = manager.load_secret("REDIS_PASSWORD").unwrap();

        assert_eq!(retrieved, secret_value);
    }

    #[test]
    fn test_needs_rotation_empty() {
        setup_test_key();
        let manager = SecretManager::new().unwrap();
        assert!(!manager.needs_rotation());
    }
}
