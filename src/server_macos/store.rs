//! Single-keychain-item storage for all vt secrets.
//!
//! Background: vt previously used separate keychain items per secret type
//! (`rusty.vault.passcode`, `rusty.vault.passphrase`, `rusty.vault.ssh_keys`,
//! ...). Each item carries its own ACL, so a binary whose codesign requirement
//! no longer matches gets one login-password prompt per item on first access
//! — several prompts after every rebuild.
//!
//! Consolidating into a single `rusty.vault.store` reduces that to at most one
//! prompt per process, regardless of how many secret types are read.
//!
//! The store is JSON-serialized so it can be eyeballed via
//! `security find-generic-password -s rusty.vault.store -w | base64 -D | jq`,
//! and so a future `v: 2` field can drive backwards-incompatible migrations.
//!
//! Wrap versions (docs/app-bundle.md#master-key-wrap-v3): v3 seals the master
//! to a Secure Enclave key (`se_key` blob + `se_wrapped_master` ECIES
//! ciphertext); v2 wraps it under a passcode-derived AES-GCM key and is read
//! this release only as the `rotate-passcode` migration source.

use anyhow::{anyhow, ensure, Context, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;

use super::security::{get_keychain, set_keychain};

const STORE_NAME: &str = "store";
const LOCK_FILE_NAME: &str = "vt-keychain.lock";
pub const STORE_SCHEMA_VERSION: u32 = 1;

/// Passcode-derived wrap with a fixed label (`crypto::WRAP_V2_LABEL`). The
/// retired v1 mixed the binary path in; `check_wrap` rejects anything but
/// v2/v3. `STORE_SCHEMA_VERSION` intentionally stays 1: old binaries can
/// still parse a newer store (they fail the unwrap, not the parse),
/// preserving the export/import escape hatch.
pub const WRAP_V2: u32 = 2;
/// Secure Enclave wrap: the only version new stores are written as.
pub const WRAP_V3: u32 = 3;

/// Public half of one stored SSH key, kept in plaintext so identities can be
/// listed without the master. Mirrors the private entry in `encrypted_ssh_keys`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshPublicEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH one-line public key.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychainStore {
    pub v: u32,
    /// Which derivation wraps `encrypted_passphrase`. Stores written before
    /// the marker existed are wrap v1; they parse (default 0) and are
    /// rejected at unwrap with the operator remedy.
    #[serde(default)]
    pub wrap_v: u32,
    /// Wrap v2 only: base64 of 64 bytes, passcode (32B) + 32 unread bytes.
    /// Written empty by v3 (the field stays so older binaries parse the
    /// store and fail at the wrap check, not the parse).
    pub passcode_and_auth_token: String,
    /// Wrap v2 only: base64 of AES-GCM ciphertext (nonce || ct) wrapping the
    /// 32-byte master. Empty under v3.
    pub encrypted_passphrase: String,
    /// Wrap v3: base64 of the Secure Enclave key's `kSecAttrTokenOID` blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub se_key: Option<String>,
    /// Wrap v3: base64 of the ECIES ciphertext of the 32-byte master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub se_wrapped_master: Option<String>,
    /// base64 of AES-GCM ciphertext wrapping the SSH-key JSON blob.
    /// `None` means no SSH keys have been added yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ssh_keys: Option<String>,
    /// Plaintext public halves of `encrypted_ssh_keys`, rewritten with it.
    /// Empty on stores written before the field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_public_keys: Vec<SshPublicEntry>,
}

impl KeychainStore {
    #[cfg(test)]
    pub fn new(passcode_and_auth_token: &[u8], encrypted_passphrase: &[u8]) -> Self {
        Self {
            v: STORE_SCHEMA_VERSION,
            wrap_v: WRAP_V2,
            passcode_and_auth_token: BASE64_URL_SAFE_NO_PAD.encode(passcode_and_auth_token),
            encrypted_passphrase: BASE64_URL_SAFE_NO_PAD.encode(encrypted_passphrase),
            se_key: None,
            se_wrapped_master: None,
            encrypted_ssh_keys: None,
            ssh_public_keys: Vec::new(),
        }
    }

    /// A wrap v3 store with no SSH keys yet.
    pub fn new_v3(se_key: &[u8], se_wrapped_master: &[u8]) -> Self {
        Self {
            v: STORE_SCHEMA_VERSION,
            wrap_v: WRAP_V3,
            passcode_and_auth_token: String::new(),
            encrypted_passphrase: String::new(),
            se_key: Some(BASE64_URL_SAFE_NO_PAD.encode(se_key)),
            se_wrapped_master: Some(BASE64_URL_SAFE_NO_PAD.encode(se_wrapped_master)),
            encrypted_ssh_keys: None,
            ssh_public_keys: Vec::new(),
        }
    }

    /// Read the store from the keychain. Returns an error if the item does
    /// not exist or cannot be parsed — callers should treat "not initialized"
    /// distinctly from "parse failure" by inspecting the error message if
    /// they need to.
    pub fn load() -> Result<Self> {
        let raw = get_keychain(STORE_NAME).context(
            "failed to read rusty.vault.store from keychain (run `vt init` or `vt secret import`)",
        )?;
        let store: KeychainStore = serde_json::from_slice(&raw).context(
            "rusty.vault.store payload is not valid JSON — keychain item may be corrupted",
        )?;
        ensure!(
            store.v == STORE_SCHEMA_VERSION,
            "rusty.vault.store has schema version {}, this binary supports {}",
            store.v,
            STORE_SCHEMA_VERSION
        );
        Ok(store)
    }

    pub fn require_absent() -> Result<()> {
        Self::check_absent(
            security_framework::passwords::get_generic_password("rusty.vault.store", "prod")
                .map(|_| ())
                .map_err(|error| error.code()),
        )
    }

    fn check_absent(result: std::result::Result<(), i32>) -> Result<()> {
        match result {
            Err(-25300) => Ok(()), // errSecItemNotFound
            Ok(()) => Err(anyhow!("rusty.vault.store already exists")),
            Err(code) => Err(anyhow!("cannot establish store absence ({code})")),
        }
    }

    /// Add-only creation: a racing initializer or unreadable existing item
    /// can never be replaced by init/import.
    pub fn create(&self) -> Result<()> {
        use core_foundation::{
            base::TCFType, data::CFData, dictionary::CFDictionary, string::CFString,
        };
        use security_framework_sys::item::*;
        use security_framework_sys::keychain_item::SecItemAdd;
        super::security::require_v3(self)?;
        let json = serde_json::to_vec(self)?;
        let status = unsafe {
            let query = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::new("rusty.vault.store").as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::new("prod").as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecValueData),
                    CFData::from_buffer(&json).as_CFType(),
                ),
            ]);
            SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut())
        };
        ensure!(
            status == 0,
            "store creation refused ({status}); existing items are never replaced"
        );
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        super::security::require_v3(self)?;
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

    /// `(se_key, se_wrapped_master)`; an absent field is a malformed v3 store.
    pub fn se_material_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let decode = |field: &Option<String>, name: &str| -> Result<Vec<u8>> {
            let b64 = field
                .as_deref()
                .ok_or_else(|| anyhow!("wrap v3 store lacks {name}"))?;
            BASE64_URL_SAFE_NO_PAD
                .decode(b64)
                .with_context(|| format!("invalid base64 in {name}"))
        };
        Ok((
            decode(&self.se_key, "se_key")?,
            decode(&self.se_wrapped_master, "se_wrapped_master")?,
        ))
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

    /// Acquire the cross-process write lock, load the store, run `f`, then
    /// save. Used for user-triggered RMW operations (ssh add/remove,
    /// rotate-passcode). Blocks if another vt process
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
            // The lock file's contents are never used; keeping any existing
            // bytes avoids a needless write to a file two processes share.
            .truncate(false)
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
    fn creation_requires_confirmed_absence() {
        assert!(KeychainStore::check_absent(Err(-25300)).is_ok());
        for result in [Ok(()), Err(-25293), Err(-25299), Err(-50)] {
            assert!(KeychainStore::check_absent(result).is_err());
        }
    }

    #[test]
    fn test_serde_roundtrip_minimal() {
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let json = serde_json::to_vec(&store).unwrap();
        let parsed: KeychainStore = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.v, STORE_SCHEMA_VERSION);
        assert_eq!(
            parsed.passcode_and_auth_token_bytes().unwrap(),
            vec![0u8; 64]
        );
        assert_eq!(parsed.encrypted_passphrase_bytes().unwrap(), vec![1u8; 60]);
        assert!(parsed.encrypted_ssh_keys.is_none());
    }

    #[test]
    fn test_serde_roundtrip_with_optional_fields() {
        let mut store = KeychainStore::new(&[2u8; 64], &[3u8; 60]);
        store.set_encrypted_ssh_keys(&[4u8; 100]);
        let json = serde_json::to_vec(&store).unwrap();
        let parsed: KeychainStore = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            parsed.encrypted_ssh_keys_bytes().unwrap(),
            Some(vec![4u8; 100])
        );
    }

    #[test]
    fn test_optional_fields_omitted_in_json_when_none() {
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let json = serde_json::to_string(&store).unwrap();
        assert!(!json.contains("encrypted_ssh_keys"));
    }

    #[test]
    fn test_optional_fields_default_to_none_on_parse() {
        let json = r#"{"v":1,"passcode_and_auth_token":"AA","encrypted_passphrase":"BB"}"#;
        let parsed: KeychainStore = serde_json::from_str(json).unwrap();
        assert!(parsed.encrypted_ssh_keys.is_none());
        assert!(parsed.se_key.is_none());
        assert!(parsed.ssh_public_keys.is_empty());
        // Marker-less stores are wrap v1: parse, then fail the wrap check.
        assert_eq!(parsed.wrap_v, 0);
    }

    #[test]
    fn test_v3_roundtrip_keeps_v2_fields_present_but_empty() {
        let mut store = KeychainStore::new_v3(&[7u8; 570], &[8u8; 113]);
        store.ssh_public_keys.push(SshPublicEntry {
            fingerprint: "SHA256:x".into(),
            algorithm: "ssh-ed25519".into(),
            comment: "c".into(),
            public_key: "ssh-ed25519 AAAA c".into(),
        });
        let json = serde_json::to_string(&store).unwrap();
        // An older binary requires both v2 fields: they must serialize.
        assert!(json.contains(r#""passcode_and_auth_token":"""#));
        assert!(json.contains(r#""encrypted_passphrase":"""#));
        let parsed: KeychainStore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.wrap_v, WRAP_V3);
        let (blob, wrapped) = parsed.se_material_bytes().unwrap();
        assert_eq!(blob, vec![7u8; 570]);
        assert_eq!(wrapped, vec![8u8; 113]);
        assert_eq!(parsed.ssh_public_keys, store.ssh_public_keys);
        assert!(parsed.passcode_and_auth_token_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_v2_store_still_parses_and_has_no_se_material() {
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let json = serde_json::to_string(&store).unwrap();
        assert!(!json.contains("se_key"));
        assert!(!json.contains("ssh_public_keys"));
        let parsed: KeychainStore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.wrap_v, WRAP_V2);
        let err = parsed.se_material_bytes().unwrap_err().to_string();
        assert!(err.contains("lacks se_key"), "{err}");
    }
}
