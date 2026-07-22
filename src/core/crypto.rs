//! Pure cross-platform crypto primitives.
//!
//! This module owns AES-256-GCM encryption, the auth-token → cipher-key
//! derivation, and the passphrase-secret derivation. It has no I/O and no
//! platform-specific dependencies — anything that touches the macOS keychain
//! lives in `crate::server_macos::security`.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;
use zeroize::Zeroizing;

/// HKDF info string for the v2 envelope DEK derivation. Domain-separates this
/// derivation from any other use of the master key.
pub const DEK_HKDF_INFO: &[u8] = b"vt-dek-v2";

/// Derive a per-record envelope DEK from the master key and a 16-byte salt.
///
/// SECURITY: salt MUST be unique per record. Birthday bound is ~2^64 records
/// before 50% collision; in this design a salt collision would simultaneously
/// collapse the DEK *and* the AES-GCM nonce (`salt[..12]`), which is
/// catastrophic for AES-GCM. `OsRng` filling 16 random bytes makes this
/// negligible at any realistic scale.
pub fn derive_dek(mac_key: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), mac_key);
    let mut okm = [0u8; 32];
    hk.expand(DEK_HKDF_INFO, &mut okm)
        .expect("32-byte HKDF expand cannot fail");
    okm
}

/// Fixed final derivation term for wrap v2 (docs/app-bundle.md §2). Replaces
/// the wrap-v1 binary-path term so the store no longer locks to an install
/// location. Domain-separated from any real path by not starting with `/`.
pub const WRAP_V2_LABEL: &str = "vt-wrap-v2";

/// Derive the wrap-v1 (legacy) passphrase secret. Pure: SHA-256(SHA-256(
/// `base64(passcode):$USER:bin_path`)). `bin_path` defaults to
/// `current_exe()` when not supplied. Kept for reading/upgrading v1 stores
/// and for `vt secret rebind --to-v1` (downgrade before rolling back to an
/// old binary); new stores are always wrap v2.
pub fn derive_passphrase_secret(passcode: &[u8; 32], bin_path: Option<&str>) -> Result<[u8; 32]> {
    let bin_path = match bin_path {
        Some(s) => s.to_string(),
        // `?` rather than `.unwrap()`: current_exe() can fail in restricted /
        // containerized contexts, and this is on the key-derivation path.
        None => env::current_exe()?.to_string_lossy().to_string(),
    };
    derive_passphrase_secret_with_term(passcode, &bin_path)
}

/// Derive the wrap-v2 passphrase secret: the derivation string ends in the
/// fixed [`WRAP_V2_LABEL`] instead of a binary path, so moving or renaming
/// the binary (e.g. into VT.app) does not invalidate the wrap.
pub fn derive_passphrase_secret_v2(passcode: &[u8; 32]) -> Result<[u8; 32]> {
    derive_passphrase_secret_with_term(passcode, WRAP_V2_LABEL)
}

fn derive_passphrase_secret_with_term(passcode: &[u8; 32], term: &str) -> Result<[u8; 32]> {
    // The b64 passcode and the concatenated derivation string both carry the
    // master secret; keep them in scrubbed memory so they don't linger on the
    // heap after the SHA-256 collapse.
    let passcode = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(passcode));
    let derived_str = Zeroizing::new(format!("{}:{}:{}", passcode.as_str(), env::var("USER")?, term));
    let hash = Sha256::digest(&Sha256::digest(derived_str.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    Ok(key)
}

/// Decode a base64-url-no-pad auth token (as exported by `vt init` in
/// `VT_AUTH`) and double-SHA256 it into a 32-byte AES-GCM key.
pub fn decode_auth_cipher_from_b64(b64_token: &str) -> Result<[u8; 32]> {
    // The decoded bytes are the raw VT_AUTH secret; scrub them after hashing.
    let token_bytes = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(b64_token)?);
    let hash = Sha256::digest(&Sha256::digest(token_bytes.as_slice()));
    let mut token = [0u8; 32];
    token.copy_from_slice(&hash[..32]);
    Ok(token)
}

pub struct AesGcmCrypto {
    cipher: Aes256Gcm,
}

impl AesGcmCrypto {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        ensure!(key.len() == 32, "Invalid key length, expected 32 bytes");
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;
        Ok(Self { cipher })
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt data. The result contains nonce (first 12 bytes) and ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption error: {e}"))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data. Input should contain nonce (first 12 bytes) and ciphertext.
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        ensure!(encrypted_data.len() >= 12, "Data too short, missing nonce");
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption error: {e}"))?;
        Ok(plaintext)
    }

    /// AEAD encrypt with caller-supplied 12-byte nonce and AAD. Returns
    /// `ciphertext || tag` only — the nonce is NOT prepended (the caller is
    /// expected to transmit/store the nonce out-of-band, e.g. as part of the
    /// v2 URL salt prefix).
    pub fn encrypt_with_nonce_and_aad(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        let ct = self
            .cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("Encryption error: {e}"))?;
        Ok(ct)
    }

    /// AEAD decrypt with caller-supplied 12-byte nonce and AAD. Input is
    /// `ciphertext || tag`.
    pub fn decrypt_with_nonce_and_aad(
        &self,
        nonce: &[u8; 12],
        ct_and_tag: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = Nonce::from_slice(nonce);
        let pt = self
            .cipher
            .decrypt(nonce, Payload { msg: ct_and_tag, aad })
            .map_err(|e| anyhow::anyhow!("Decryption error: {e}"))?;
        Ok(Zeroizing::new(pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let text = b"to be encoded".to_vec();
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(&text), "dG8gYmUgZW5jb2RlZA");
    }

    #[test]
    fn test_generation() {
        let key1 = AesGcmCrypto::generate_key();
        let key2 = AesGcmCrypto::generate_key();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2);

        // test nonce generation
        let nonce1 = AesGcmCrypto::generate_nonce();
        let nonce2 = AesGcmCrypto::generate_nonce();
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Hello, World!";

        let encrypted = crypto.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = vec![0xAB; 1024 * 1024];
        let encrypted = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Original message";
        let mut encrypted = crypto.encrypt(plaintext).unwrap();

        encrypted[15] ^= 0xFF;

        let result = crypto.decrypt(&encrypted);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Decryption error"));
    }

    #[test]
    fn test_multiple_encryptions_different_results() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = b"Same message";
        let encrypted1 = crypto.encrypt(plaintext).unwrap();
        let encrypted2 = crypto.encrypt(plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);

        let decrypted1 = crypto.decrypt(&encrypted1).unwrap();
        let decrypted2 = crypto.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_derive_dek_deterministic_and_unique() {
        let mac_key = [0x42u8; 32];
        let salt_a = [0x11u8; 16];
        let salt_b = [0x22u8; 16];

        let dek_a1 = derive_dek(&mac_key, &salt_a);
        let dek_a2 = derive_dek(&mac_key, &salt_a);
        let dek_b = derive_dek(&mac_key, &salt_b);

        assert_eq!(dek_a1, dek_a2, "same inputs -> same DEK");
        assert_ne!(dek_a1, dek_b, "different salts -> different DEK");
        assert_eq!(dek_a1.len(), 32);
    }

    #[test]
    fn test_derive_dek_master_separation() {
        let salt = [0x33u8; 16];
        let dek_1 = derive_dek(&[0u8; 32], &salt);
        let dek_2 = derive_dek(&[1u8; 32], &salt);
        assert_ne!(dek_1, dek_2, "different masters -> different DEK");
    }

    #[test]
    fn test_aad_encrypt_decrypt_roundtrip() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();
        let nonce = [0x77u8; 12];
        let aad = b"vt:v2:0";
        let plaintext = b"hello world";

        let ct = crypto
            .encrypt_with_nonce_and_aad(&nonce, plaintext, aad)
            .unwrap();
        // Output is ct || tag, no nonce prefix.
        assert_eq!(ct.len(), plaintext.len() + 16);

        let pt = crypto
            .decrypt_with_nonce_and_aad(&nonce, &ct, aad)
            .unwrap();
        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn test_aad_tamper_detection() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();
        let nonce = [0x77u8; 12];
        let plaintext = b"secret";

        let ct = crypto
            .encrypt_with_nonce_and_aad(&nonce, plaintext, b"vt:v2:1")
            .unwrap();

        // Decrypting with mismatched AAD must fail.
        let bad = crypto.decrypt_with_nonce_and_aad(&nonce, &ct, b"vt:v2:0");
        assert!(bad.is_err(), "AAD mismatch must reject");
    }

    #[test]
    fn test_aad_does_not_prepend_nonce() {
        // Regression guard: the AAD encrypt API must produce ct||tag only,
        // never the nonce-prefixed format used by the legacy `encrypt()`.
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();
        let nonce = [0xAAu8; 12];
        let plaintext = b"";
        let ct = crypto
            .encrypt_with_nonce_and_aad(&nonce, plaintext, b"")
            .unwrap();
        // Empty plaintext -> 16-byte tag only.
        assert_eq!(ct.len(), 16);
        // Nonce bytes should not appear at the start.
        assert_ne!(&ct[..12.min(ct.len())], &nonce[..]);
    }

    #[test]
    fn test_unicode_text() {
        let key = AesGcmCrypto::generate_key();
        let crypto = AesGcmCrypto::new(&key).unwrap();

        let plaintext = "Hello, 世界! 🌍".as_bytes();
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "Hello, 世界! 🌍");
    }
}
