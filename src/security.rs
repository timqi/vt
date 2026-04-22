use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;

pub fn set_keychain(name: &str, _value: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::set_generic_password;
        let service = "rusty.vault.".to_string() + name;
        set_generic_password(&service, &"prod".to_string(), &_value)?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

pub fn get_keychain(name: &str) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::get_generic_password;
        let service = "rusty.vault.".to_string() + name;
        get_generic_password(&service, &"prod".to_string())
            .map_err(|e| anyhow::anyhow!("Failed to get keychain {}: {}", name, e))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
}

#[allow(dead_code)]
pub fn delete_keychain(name: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use security_framework::passwords::delete_generic_password;
        let service = "rusty.vault.".to_string() + name;
        delete_generic_password(&service, &"prod".to_string())
            .map_err(|e| anyhow::anyhow!("Failed to delete keychain {}: {}", name, e))?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        anyhow::bail!("keychain is only supported on macOS");
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

/// Which method satisfied the auth request. Useful for callers that want to
/// treat factor strength differently (e.g. the SSH agent cache doesn't cache
/// FIDO2 since touch-only is weaker than Touch ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Biometric,
    Fido2,
    Password,
}

/// Authentication chain: biometric → FIDO2 (YubiKey) → system password.
///
/// Step 1 uses `DeviceOwnerAuthenticationWithBiometrics` (no built-in password
/// fallback) so we control the boundary and can slot FIDO2 between biometric
/// and password. `can_evaluate_policy` is checked first so we skip biometric
/// cleanly on hardware without Touch ID.
///
/// FIDO2 returns a three-way outcome: a `Rejected` result (user clicked the
/// dialog's Reject button, or a sign-counter regression was detected) aborts
/// the entire chain — we do NOT silently fall back to password, because the
/// user explicitly said no, or a security invariant was violated.
///
/// Limitation: `localauthentication-rs` only exposes a `bool` — we cannot
/// distinguish user-cancel from biometric failure. A canceled Touch ID prompt
/// therefore falls through to FIDO2/password rather than aborting. If that
/// becomes a problem, switch to direct `objc2-local-authentication` FFI to
/// inspect `LAError` codes.
#[cfg(target_os = "macos")]
pub fn authenticate(reason: &str) -> Option<AuthMethod> {
    use crate::fido2::FidoOutcome;

    if touch_id_authentication(reason) {
        return Some(AuthMethod::Biometric);
    }

    match crate::fido2::authenticate(reason) {
        FidoOutcome::Success => return Some(AuthMethod::Fido2),
        FidoOutcome::Rejected => return None,
        FidoOutcome::Skip => {}
    }

    use localauthentication_rs::{LAPolicy, LocalAuthentication};
    let la = LocalAuthentication::new();
    if la.evaluate_policy(LAPolicy::DeviceOwnerAuthentication, reason) {
        return Some(AuthMethod::Password);
    }

    None
}

#[cfg(not(target_os = "macos"))]
pub fn authenticate(_reason: &str) -> Option<AuthMethod> {
    tracing::warn!("local authentication is not supported on this platform");
    None
}

#[cfg(target_os = "macos")]
pub fn touch_id_authentication(reason: &str) -> bool {
    use localauthentication_rs::{LAPolicy, LocalAuthentication};

    let la = LocalAuthentication::new();
    la.can_evaluate_policy(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        && la.evaluate_policy(LAPolicy::DeviceOwnerAuthenticationWithBiometrics, reason)
}

#[cfg(not(target_os = "macos"))]
pub fn touch_id_authentication(_reason: &str) -> bool {
    tracing::warn!("Touch ID authentication is not supported on this platform");
    false
}

pub fn local_authentication(reason: &str) -> bool {
    authenticate(reason).is_some()
}

pub fn derive_passphrase_secret(passcode: &[u8; 32], bin_path: Option<&str>) -> Result<[u8; 32]> {
    let passcode = BASE64_URL_SAFE_NO_PAD.encode(&passcode);
    let bin_path = bin_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| env::current_exe().unwrap().to_string_lossy().to_string());
    let derived_str = format!("{}:{}:{}", passcode, env::var("USER")?, bin_path,);
    let hash = Sha256::digest(&Sha256::digest(derived_str.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    Ok(key)
}

pub fn create_and_save_passcode_passphrase(
    real_passphrase: &[u8; 32],
    bin_path: Option<&str>,
) -> Result<()> {
    let origin_auth_token = AesGcmCrypto::generate_key();
    let hash = Sha256::digest(&Sha256::digest(origin_auth_token));
    let mut auth_token = [0u8; 32];
    auth_token.copy_from_slice(&hash[..32]);

    let passcode = AesGcmCrypto::generate_key();
    let mut passcode_and_auth_token = Vec::with_capacity(passcode.len() + auth_token.len());
    passcode_and_auth_token.extend_from_slice(&passcode);
    passcode_and_auth_token.extend_from_slice(&auth_token);

    set_keychain("passcode", &passcode_and_auth_token).expect("set keychain passcode");
    tracing::info!("passcode set!");

    let passphrase_secret = derive_passphrase_secret(&passcode, bin_path)?;
    let aes = AesGcmCrypto::new(&passphrase_secret)?;
    // let real_passphrase = AesGcmCrypto::generate_key();
    let encrypted_passphrase = aes.encrypt(real_passphrase)?;

    set_keychain("passphrase", &encrypted_passphrase).expect("set keychain passphrase");
    tracing::info!("passphrase set!");

    tracing::info!(
        "export VT_AUTH={};",
        BASE64_URL_SAFE_NO_PAD.encode(origin_auth_token)
    );
    Ok(())
}

pub fn load_mac_cipher(passphrase_cipher: &AesGcmCrypto) -> Result<AesGcmCrypto> {
    let encrypted_passphrase = get_keychain("passphrase")?;
    let decrypted_passphrase = passphrase_cipher.decrypt(&encrypted_passphrase)?;
    AesGcmCrypto::new(decrypted_passphrase.as_slice().try_into()?)
}

/// Load the mac_cipher directly from the keychain in one call. The passphrase
/// cipher is dropped immediately so the master key doesn't linger in memory.
pub fn load_mac_cipher_from_keychain() -> Result<AesGcmCrypto> {
    let (_, passphrase_cipher) = load_passcode_ciphers()?;
    load_mac_cipher(&passphrase_cipher)
}

// Return auth_token, auth_cipher, passphrase_cipher
pub fn load_passcode_ciphers() -> Result<(AesGcmCrypto, AesGcmCrypto)> {
    let passcode = get_keychain("passcode")?;
    ensure!(
        passcode.len() == 64,
        "Passcode length is {}, expected 64",
        passcode.len()
    );
    let passcode_arr: [u8; 32] = passcode[..32].try_into()?;
    let auth_token: [u8; 32] = passcode[32..].try_into()?;

    let passphrase_secret = derive_passphrase_secret(&passcode_arr, None)?;
    let passphrase_cipher = AesGcmCrypto::new(&passphrase_secret)?;
    let auth_cipher = AesGcmCrypto::new(&auth_token)?;

    Ok((auth_cipher, passphrase_cipher))
}

pub fn decode_auth_cipher_from_b64(b64_token: &str) -> Result<[u8; 32]> {
    let token_bytes = BASE64_URL_SAFE_NO_PAD.decode(b64_token)?;
    let hash = Sha256::digest(&Sha256::digest(token_bytes));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    fn test_base64_encode() {
        let text = b"to be encoded".to_vec();
        assert_eq!(BASE64_URL_SAFE_NO_PAD.encode(&text), "dG8gYmUgZW5jb2RlZA");
    }

    #[traced_test]
    #[test]
    #[ignore]
    fn test_create_and_save_passcode_passphrase() {
        let real_passphrase = AesGcmCrypto::generate_key();
        let result = create_and_save_passcode_passphrase(&real_passphrase, None);
        assert!(result.is_ok())
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

    #[test]
    #[ignore]
    fn test_encrypt_body() {
        let body = r#"{"items":[]}"#.to_string();
        let (cipher, _) = load_passcode_ciphers().expect("load auth cipher");
        let encrypted = cipher.encrypt(body.as_bytes()).expect("encrypt body");
        let decrypted = cipher.decrypt(&encrypted).expect("decrypt body");
        assert_eq!(decrypted, body.as_bytes());
    }

    #[test]
    #[ignore]
    fn test_biometric_authentication() {
        assert!(local_authentication(&"test biometric authentication"));
    }
}
