//! Single-keychain-item storage for all vt secrets.
//!
//! Background: vt previously used four separate keychain items
//! (`rusty.vault.passcode`, `rusty.vault.passphrase`, `rusty.vault.ssh_keys`,
//! `rusty.vault.fido2_credentials`). Each item carries its own ACL, so a binary
//! whose codesign requirement no longer matches gets one login-password prompt
//! per item on first access — three to four prompts after every rebuild.
//!
//! Consolidating into a single `rusty.vault.store` reduces that to at most one
//! prompt per process, regardless of how many secret types are read.
//!
//! The store is JSON-serialized so it can be eyeballed via
//! `security find-generic-password -s rusty.vault.store -w | base64 -D | jq`,
//! and so a future `v: 2` field can drive backwards-incompatible migrations.

use anyhow::{anyhow, ensure, Context, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;

use super::security::{get_keychain, set_keychain};

const STORE_NAME: &str = "store";
const LOCK_FILE_NAME: &str = "vt-keychain.lock";
pub const STORE_SCHEMA_VERSION: u32 = 1;

/// Wrap-derivation versions for `encrypted_passphrase` (docs/app-bundle.md §2).
/// v1 mixes the binary path into the wrap key; v2 uses a fixed label so the
/// binary can move (VT.app migration). `STORE_SCHEMA_VERSION` intentionally
/// stays 1: old binaries can still parse a v2 store (they fail the unwrap,
/// not the parse), preserving the export/import escape hatch.
pub const WRAP_V1: u32 = 1;
pub const WRAP_V2: u32 = 2;

fn default_wrap_v() -> u32 {
    WRAP_V1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainStore {
    pub v: u32,
    /// Which derivation wraps `encrypted_passphrase`. Serde default 1 so
    /// stores written before this field existed read as wrap v1.
    #[serde(default = "default_wrap_v")]
    pub wrap_v: u32,
    /// base64 of 64 bytes: passcode (32B) + auth_token (32B).
    pub passcode_and_auth_token: String,
    /// base64 of AES-GCM ciphertext (nonce || ct) wrapping the 32-byte master passphrase.
    pub encrypted_passphrase: String,
    /// base64 of AES-GCM ciphertext wrapping the SSH-key JSON blob.
    /// `None` means no SSH keys have been added yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ssh_keys: Option<String>,
    /// base64 of AES-GCM ciphertext wrapping the FIDO2-credential JSON blob.
    /// `None` means no FIDO2 credentials have been registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_fido2: Option<String>,
}

impl KeychainStore {
    /// New stores are always wrap v2 (fixed-label derivation); only
    /// `vt secret rebind --to-v1` produces a v1 wrap after this version.
    pub fn new(passcode_and_auth_token: &[u8], encrypted_passphrase: &[u8]) -> Self {
        Self {
            v: STORE_SCHEMA_VERSION,
            wrap_v: WRAP_V2,
            passcode_and_auth_token: BASE64_URL_SAFE_NO_PAD.encode(passcode_and_auth_token),
            encrypted_passphrase: BASE64_URL_SAFE_NO_PAD.encode(encrypted_passphrase),
            encrypted_ssh_keys: None,
            encrypted_fido2: None,
        }
    }

    pub fn set_encrypted_passphrase(&mut self, bytes: &[u8], wrap_v: u32) {
        self.encrypted_passphrase = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        self.wrap_v = wrap_v;
    }

    /// Read the store from the keychain. Returns an error if the item does
    /// not exist or cannot be parsed — callers should treat "not initialized"
    /// distinctly from "parse failure" by inspecting the error message if
    /// they need to.
    pub fn load() -> Result<Self> {
        let raw = get_keychain(STORE_NAME)
            .context("failed to read rusty.vault.store from keychain (run `vt init` or `vt secret import`)")?;
        let store: KeychainStore = serde_json::from_slice(&raw)
            .context("rusty.vault.store payload is not valid JSON — keychain item may be corrupted")?;
        ensure!(
            store.v == STORE_SCHEMA_VERSION,
            "rusty.vault.store has schema version {}, this binary supports {}",
            store.v,
            STORE_SCHEMA_VERSION
        );
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_vec(self)?;
        set_keychain(STORE_NAME, &json)
    }

    pub fn passcode_and_auth_token_bytes(&self) -> Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD
            .decode(&self.passcode_and_auth_token)
            .context("invalid base64 in passcode_and_auth_token")
    }

    pub fn encrypted_passphrase_bytes(&self) -> Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD
            .decode(&self.encrypted_passphrase)
            .context("invalid base64 in encrypted_passphrase")
    }

    pub fn encrypted_ssh_keys_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.encrypted_ssh_keys {
            Some(b64) => Ok(Some(
                BASE64_URL_SAFE_NO_PAD
                    .decode(b64)
                    .context("invalid base64 in encrypted_ssh_keys")?,
            )),
            None => Ok(None),
        }
    }

    pub fn set_encrypted_ssh_keys(&mut self, bytes: &[u8]) {
        self.encrypted_ssh_keys = Some(BASE64_URL_SAFE_NO_PAD.encode(bytes));
    }

    pub fn encrypted_fido2_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.encrypted_fido2 {
            Some(b64) => Ok(Some(
                BASE64_URL_SAFE_NO_PAD
                    .decode(b64)
                    .context("invalid base64 in encrypted_fido2")?,
            )),
            None => Ok(None),
        }
    }

    pub fn set_encrypted_fido2(&mut self, bytes: &[u8]) {
        self.encrypted_fido2 = Some(BASE64_URL_SAFE_NO_PAD.encode(bytes));
    }

    /// Acquire the cross-process write lock, load the store, run `f`, then
    /// save. Used for user-triggered RMW operations (ssh add/remove,
    /// rotate-passcode, fido2 register/remove). Blocks if another vt process
    /// is currently inside its own `modify` call.
    pub fn modify<F>(f: F) -> Result<()>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        let _lock = StoreLock::acquire_blocking()?;
        let mut store = Self::load()?;
        f(&mut store)?;
        store.save()?;
        Ok(())
    }

    /// Best-effort RMW. Returns `Ok(false)` if the file lock is currently
    /// held by another process — caller should accept that the update did
    /// not happen and continue. Used by the FIDO2 sign-counter persistence
    /// path, which runs inside the SSH `sign()` handler while a tokio read
    /// lock is held; blocking on a file lock there could starve other SSH
    /// sessions waiting to add/remove keys.
    pub fn try_modify<F>(f: F) -> Result<bool>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        let Some(_lock) = StoreLock::try_acquire()? else {
            return Ok(false);
        };
        let mut store = Self::load()?;
        f(&mut store)?;
        store.save()?;
        Ok(true)
    }
}

fn lock_path() -> PathBuf {
    std::env::temp_dir().join(LOCK_FILE_NAME)
}

/// File-lock guard that releases on drop. We never delete the lock file —
/// `$TMPDIR` is per-user on macOS and is cleared on reboot, so there is no
/// stale-lock concern, and leaving the file in place avoids the inode-recycle
/// race where two processes lock different inodes that happen to share a path.
struct StoreLock {
    file: std::fs::File,
}

impl StoreLock {
    fn open_lock_file() -> Result<std::fs::File> {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path())
            .with_context(|| format!("failed to open lock file {}", lock_path().display()))
    }

    fn acquire_blocking() -> Result<Self> {
        let file = Self::open_lock_file()?;
        file.lock()
            .map_err(|e| anyhow!("failed to acquire keychain lock: {e}"))?;
        Ok(Self { file })
    }

    fn try_acquire() -> Result<Option<Self>> {
        let file = Self::open_lock_file()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(anyhow!("failed to try-acquire keychain lock: {e}"))
            }
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip_minimal() {
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let json = serde_json::to_vec(&store).unwrap();
        let parsed: KeychainStore = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.v, STORE_SCHEMA_VERSION);
        assert_eq!(parsed.passcode_and_auth_token_bytes().unwrap(), vec![0u8; 64]);
        assert_eq!(parsed.encrypted_passphrase_bytes().unwrap(), vec![1u8; 60]);
        assert!(parsed.encrypted_ssh_keys.is_none());
        assert!(parsed.encrypted_fido2.is_none());
    }

    #[test]
    fn test_serde_roundtrip_with_optional_fields() {
        let mut store = KeychainStore::new(&[2u8; 64], &[3u8; 60]);
        store.set_encrypted_ssh_keys(&[4u8; 100]);
        store.set_encrypted_fido2(&[5u8; 50]);
        let json = serde_json::to_vec(&store).unwrap();
        let parsed: KeychainStore = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.encrypted_ssh_keys_bytes().unwrap(), Some(vec![4u8; 100]));
        assert_eq!(parsed.encrypted_fido2_bytes().unwrap(), Some(vec![5u8; 50]));
    }

    #[test]
    fn test_optional_fields_omitted_in_json_when_none() {
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let json = serde_json::to_string(&store).unwrap();
        assert!(!json.contains("encrypted_ssh_keys"));
        assert!(!json.contains("encrypted_fido2"));
    }

    #[test]
    fn test_optional_fields_default_to_none_on_parse() {
        let json = r#"{"v":1,"passcode_and_auth_token":"AA","encrypted_passphrase":"BB"}"#;
        let parsed: KeychainStore = serde_json::from_str(json).unwrap();
        assert!(parsed.encrypted_ssh_keys.is_none());
        assert!(parsed.encrypted_fido2.is_none());
    }
}
