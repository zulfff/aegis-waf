use rand::{rngs::OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::hmac;

use crate::error::{AegisError, Result};
use crate::security::secrets::EncryptedSecret;

#[allow(dead_code)]
const NONCE_AND_TAG_LEN: usize = ring::aead::NONCE_LEN + ring::aead::MAX_TAG_LEN;
const AES256_KEY_LEN: usize = 32;

pub struct CryptoProvider;

impl CryptoProvider {
    pub fn encrypt_aes_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != AES256_KEY_LEN {
            return Err(AegisError::SecurityViolation {
                reason: format!(
                    "AES-256-GCM key must be {} bytes, got {}",
                    AES256_KEY_LEN,
                    key.len()
                ),
            });
        }
        if nonce.len() != ring::aead::NONCE_LEN {
            return Err(AegisError::SecurityViolation {
                reason: format!(
                    "AES-256-GCM nonce must be {} bytes, got {}",
                    ring::aead::NONCE_LEN,
                    nonce.len()
                ),
            });
        }

        let unbound_key =
            UnboundKey::new(&AES_256_GCM, key).map_err(|_| AegisError::SecurityViolation {
                reason: "Failed to create AES-256-GCM key".into(),
            })?;

        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce.try_into().map_err(|_| {
            AegisError::SecurityViolation {
                reason: "Nonce conversion failed".into(),
            }
        })?);

        let mut buffer = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| AegisError::SecurityViolation {
                reason: "AES-256-GCM encryption failed".into(),
            })?;

        Ok(buffer)
    }

    pub fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != AES256_KEY_LEN {
            return Err(AegisError::SecurityViolation {
                reason: format!(
                    "AES-256-GCM key must be {} bytes, got {}",
                    AES256_KEY_LEN,
                    key.len()
                ),
            });
        }
        if nonce.len() != ring::aead::NONCE_LEN {
            return Err(AegisError::SecurityViolation {
                reason: format!(
                    "AES-256-GCM nonce must be {} bytes, got {}",
                    ring::aead::NONCE_LEN,
                    nonce.len()
                ),
            });
        }

        let unbound_key =
            UnboundKey::new(&AES_256_GCM, key).map_err(|_| AegisError::SecurityViolation {
                reason: "Failed to create AES-256-GCM key".into(),
            })?;

        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce.try_into().map_err(|_| {
            AegisError::SecurityViolation {
                reason: "Nonce conversion failed".into(),
            }
        })?);

        let mut buffer = ciphertext.to_vec();
        let decrypted_len = {
            let result = less_safe_key
                .open_in_place(nonce, Aad::empty(), &mut buffer)
                .map_err(|_| AegisError::SecurityViolation {
                    reason: "AES-256-GCM decryption failed (authentication tag mismatch)".into(),
                })?;
            result.len()
        };

        buffer.truncate(decrypted_len);
        Ok(buffer)
    }

    pub fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&signing_key, data);
        tag.as_ref().to_vec()
    }

    pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&signing_key, data, tag).is_ok()
    }

    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    pub fn derive_key(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(ikm);
        let mut okm = vec![0u8; output_length];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .map_err(|_| AegisError::SecurityViolation {
                reason: "HKDF expand failed".into(),
            })?
            .fill(&mut okm)
            .map_err(|_| AegisError::SecurityViolation {
                reason: "HKDF fill failed".into(),
            })?;

        Ok(okm)
    }

    pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
        let d = digest(&SHA256, data);
        d.as_ref().to_vec()
    }

    pub fn encrypt_secret_payload(
        master_key: &[u8],
        secret_value: &str,
    ) -> Result<EncryptedSecret> {
        let nonce = Self::generate_random_bytes(ring::aead::NONCE_LEN);
        let plaintext = secret_value.as_bytes();
        let ciphertext = Self::encrypt_aes_gcm(master_key, &nonce, plaintext)?;

        Ok(EncryptedSecret {
            ciphertext,
            nonce,
            key_version: 1,
            created_at: chrono::Utc::now().timestamp(),
        })
    }

    pub fn decrypt_secret_payload(
        master_key: &[u8],
        encrypted: &EncryptedSecret,
    ) -> Result<String> {
        let plaintext = Self::decrypt_aes_gcm(master_key, &encrypted.nonce, &encrypted.ciphertext)?;

        String::from_utf8(plaintext).map_err(|e| AegisError::SecurityViolation {
            reason: format!("Decrypted secret is not valid UTF-8: {}", e),
        })
    }

    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        ring::constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        let key = CryptoProvider::generate_random_bytes(AES256_KEY_LEN);
        let nonce = CryptoProvider::generate_random_bytes(ring::aead::NONCE_LEN);
        let plaintext = b"aegis-waf secret data for testing";

        let ciphertext = CryptoProvider::encrypt_aes_gcm(&key, &nonce, plaintext).unwrap();
        let decrypted = CryptoProvider::decrypt_aes_gcm(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_gcm_tampering_detected() {
        let key = CryptoProvider::generate_random_bytes(AES256_KEY_LEN);
        let nonce = CryptoProvider::generate_random_bytes(ring::aead::NONCE_LEN);
        let plaintext = b"sensitive payload";

        let mut ciphertext = CryptoProvider::encrypt_aes_gcm(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0x01;

        let result = CryptoProvider::decrypt_aes_gcm(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_sign_and_verify() {
        let key = CryptoProvider::generate_random_bytes(32);
        let data = b"authenticated message";

        let tag = CryptoProvider::hmac_sign(&key, data);
        assert!(CryptoProvider::hmac_verify(&key, data, &tag));
        assert!(!CryptoProvider::hmac_verify(&key, b"different data", &tag));
    }

    #[test]
    fn test_hkdf_derive_key() {
        let ikm = CryptoProvider::generate_random_bytes(16);
        let salt = CryptoProvider::generate_random_bytes(16);
        let info = b"aegis-waf-key-derivation";

        let key1 = CryptoProvider::derive_key(&ikm, &salt, info, 32).unwrap();
        let key2 = CryptoProvider::derive_key(&ikm, &salt, info, 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        let key_diff = CryptoProvider::derive_key(&ikm, &salt, b"different-info", 32).unwrap();
        assert_ne!(key1, key_diff);
    }

    #[test]
    fn test_constant_time_equality() {
        let a = b"secret_value_12345";
        let b = b"secret_value_12345";
        let c = b"secret_value_12346";

        assert!(CryptoProvider::constant_time_eq(a, b));
        assert!(!CryptoProvider::constant_time_eq(a, c));
    }

    #[test]
    fn test_encrypt_secret_payload() {
        let key = CryptoProvider::generate_random_bytes(AES256_KEY_LEN);
        let secret = "my-super-secret-api-key-12345678";

        let encrypted = CryptoProvider::encrypt_secret_payload(&key, secret).unwrap();
        let decrypted = CryptoProvider::decrypt_secret_payload(&key, &encrypted).unwrap();

        assert_eq!(decrypted, secret);
    }
}
