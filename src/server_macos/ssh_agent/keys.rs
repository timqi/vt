//! The SSH key store inside `rusty.vault.store`: private entries sealed under
//! the master (`encrypted_ssh_keys`), public halves in plaintext
//! (`ssh_public_keys`) so identities list without unwrapping the master.

use std::collections::HashMap;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use ssh_key::private::PrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::require_ed25519;
use crate::core::crypto::AesGcmCrypto;
use crate::server_macos::security::{require_v3, MasterAccess};
use crate::server_macos::store::{KeychainStore, SshPublicEntry};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SshKeyEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH-format private key (plaintext, encrypted at the keychain level)
    pub key_data: String,
}

fn parse_private(entry: &SshKeyEntry) -> Result<PrivateKey> {
    let key = PrivateKey::from_openssh(entry.key_data.as_bytes())
        .context("stored SSH private key does not parse")?;
    ensure!(
        key.fingerprint(ssh_key::HashAlg::Sha256).to_string() == entry.fingerprint
            && key.algorithm().to_string() == entry.algorithm,
        "stored SSH private key identity mismatch"
    );
    Ok(key)
}

/// The public half of a private entry, for the plaintext list.
pub fn public_entry(entry: &SshKeyEntry) -> Result<SshPublicEntry> {
    let privkey = parse_private(entry)?;
    Ok(SshPublicEntry {
        fingerprint: entry.fingerprint.clone(),
        algorithm: entry.algorithm.clone(),
        comment: entry.comment.clone(),
        public_key: privkey.public_key().to_openssh()?,
    })
}

/// Decode the SSH-keys blob from a loaded store. Empty when the store has no
/// SSH keys yet.
fn decode_ssh_keys(store: &KeychainStore, master: &[u8; 32]) -> Result<Vec<SshKeyEntry>> {
    let Some(encrypted) = store.encrypted_ssh_keys_bytes()? else {
        return Ok(Vec::new());
    };
    let decrypted = Zeroizing::new(AesGcmCrypto::new(master)?.decrypt(&encrypted)?);
    let entries: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted)?;
    Ok(entries)
}

/// Re-encrypt the entries and rewrite the plaintext public list beside them.
/// Caller saves (or goes through `KeychainStore::modify`).
fn encode_ssh_keys_into(
    store: &mut KeychainStore,
    master: &[u8; 32],
    entries: &[SshKeyEntry],
) -> Result<()> {
    let public = entries
        .iter()
        .map(public_entry)
        .collect::<Result<Vec<_>>>()?;
    let json = Zeroizing::new(serde_json::to_vec(entries)?);
    store.set_encrypted_ssh_keys(&AesGcmCrypto::new(master)?.encrypt(&json)?);
    store.ssh_public_keys = public;
    Ok(())
}

/// List plaintext public halves without opening the master.
pub fn public_entries(store: &KeychainStore) -> Result<Vec<SshPublicEntry>> {
    require_v3(store)?;
    for entry in &store.ssh_public_keys {
        let key = ssh_key::PublicKey::from_openssh(&entry.public_key)?;
        ensure!(
            key.fingerprint(ssh_key::HashAlg::Sha256).to_string() == entry.fingerprint
                && key.algorithm().to_string() == entry.algorithm,
            "stored SSH public key identity mismatch"
        );
    }
    Ok(store.ssh_public_keys.clone())
}

/// Decrypt every stored private key. A stored key of another type fails the
/// whole load, with its fingerprint and the `vt ssh remove` remedy; it is
/// never skipped.
pub fn load_private_keys(
    store: &KeychainStore,
    master: &[u8; 32],
) -> Result<HashMap<String, PrivateKey>> {
    let mut keys = HashMap::new();
    for entry in &decode_ssh_keys(store, master)? {
        let privkey = parse_private(entry)?;
        require_ed25519(&privkey).with_context(|| {
            format!(
                "stored SSH key {}: remove it with `vt ssh remove {}`",
                entry.fingerprint, entry.fingerprint
            )
        })?;
        ensure!(
            keys.insert(entry.fingerprint.clone(), privkey).is_none(),
            "duplicate stored SSH key"
        );
    }
    let public = public_entries(store)?;
    ensure!(
        public.len() == keys.len()
            && public.iter().all(|entry| {
                keys.get(&entry.fingerprint).is_some_and(|key| {
                    key.public_key().to_openssh().ok().as_deref() == Some(entry.public_key.as_str())
                })
            }),
        "stored SSH public and private lists disagree"
    );
    Ok(keys)
}

/// Pure read-modify-write over an in-memory store: decode, let `f` mutate,
/// re-encode when it reports a change. A blob this master cannot decrypt or
/// parse aborts before `f` runs, so an unreadable blob is never overwritten
/// by an empty or partial one.
pub fn modify_ssh_keys(
    store: &mut KeychainStore,
    master: &[u8; 32],
    f: impl FnOnce(&mut Vec<SshKeyEntry>) -> Result<bool>,
) -> Result<()> {
    let mut entries = decode_ssh_keys(store, master)?;
    if f(&mut entries)? {
        encode_ssh_keys_into(store, master, &entries)?;
    }
    Ok(())
}

/// The one write path for the SSH key store from the CLI: `modify_ssh_keys`
/// under the cross-process flock, through an already-authorized `access`.
pub fn with_ssh_keys(
    access: &MasterAccess,
    f: impl FnOnce(&mut Vec<SshKeyEntry>) -> Result<bool>,
) -> Result<()> {
    KeychainStore::modify(|store| {
        let master = access.master(store)?;
        modify_ssh_keys(store, &master, f)
    })
}

/// Carry the SSH keys of `from` into `to`, both sealed under `master`
/// (`rotate-passcode`). Re-encodes so the plaintext public list exists even
/// when `from` predates it.
pub fn carry_ssh_keys(
    from: &KeychainStore,
    master: &[u8; 32],
    to: &mut KeychainStore,
) -> Result<()> {
    let entries = decode_ssh_keys(from, master)?;
    if !entries.is_empty() {
        encode_ssh_keys_into(to, master, &entries)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_macos::security::tests::v2_store;

    /// In-memory v2 store and its master; no keychain access.
    fn test_store() -> (KeychainStore, [u8; 32]) {
        let master = AesGcmCrypto::generate_key();
        (KeychainStore::new_v3(&[1; 8], &[2; 113]), master)
    }

    fn real_entry(comment: &str) -> SshKeyEntry {
        let privkey = PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("gen key");
        let privkey = PrivateKey::new(privkey.key_data().clone(), comment).unwrap();
        SshKeyEntry {
            fingerprint: privkey.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            algorithm: "ssh-ed25519".to_string(),
            comment: comment.to_string(),
            key_data: privkey
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        }
    }

    #[test]
    fn private_entries_scrub_on_drop() {
        fn requires_drop_wipe<T: ZeroizeOnDrop>() {}
        requires_drop_wipe::<SshKeyEntry>();
        let mut entry = real_entry("wipe");
        entry.zeroize();
        assert!(entry.key_data.is_empty());
    }

    #[test]
    fn test_ssh_key_entry_serde_roundtrip() {
        let entries = vec![
            SshKeyEntry {
                fingerprint: "SHA256:abcdef123456".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                comment: "test@host".to_string(),
                key_data: "fake-key-data".to_string(),
            },
            SshKeyEntry {
                fingerprint: "SHA256:xyz789".to_string(),
                algorithm: "ssh-rsa".to_string(),
                comment: "another@host".to_string(),
                key_data: "fake-key-data-2".to_string(),
            },
        ];
        let json = serde_json::to_vec(&entries).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].fingerprint, "SHA256:abcdef123456");
        assert_eq!(decoded[0].key_data, "fake-key-data");
        assert_eq!(decoded[1].fingerprint, "SHA256:xyz789");
    }

    #[test]
    fn test_decode_ssh_keys_returns_empty_when_field_missing() {
        let (store, master) = test_store();
        assert!(decode_ssh_keys(&store, &master).unwrap().is_empty());
        assert!(public_entries(&store).unwrap().is_empty());
        assert!(load_private_keys(&store, &master).unwrap().is_empty());
    }

    /// Writing entries rewrites the plaintext public list; listing needs no
    /// master; the private key loads back under the master only.
    #[test]
    fn test_modify_writes_public_list_and_private_blob() {
        let (mut store, master) = test_store();
        let entry = real_entry("laptop");
        modify_ssh_keys(&mut store, &master, |entries| {
            entries.push(entry.clone());
            Ok(true)
        })
        .unwrap();
        let blob = store.encrypted_ssh_keys.clone();
        assert!(blob.is_some());
        assert_eq!(store.ssh_public_keys.len(), 1);
        assert_eq!(store.ssh_public_keys[0].fingerprint, entry.fingerprint);
        assert_eq!(store.ssh_public_keys[0].comment, "laptop");
        assert!(store.ssh_public_keys[0]
            .public_key
            .starts_with("ssh-ed25519 "));
        assert_eq!(public_entries(&store).unwrap(), store.ssh_public_keys);
        assert!(load_private_keys(&store, &master)
            .unwrap()
            .contains_key(&entry.fingerprint));
        assert!(load_private_keys(&store, &[9u8; 32]).is_err());

        modify_ssh_keys(&mut store, &master, |entries| {
            entries.clear();
            Ok(false)
        })
        .unwrap();
        assert_eq!(store.encrypted_ssh_keys, blob, "no change, no re-encrypt");
    }

    /// V2 cannot list identities by silently unwrapping its private blob.
    #[test]
    fn test_public_entries_rejects_v2() {
        let master = AesGcmCrypto::generate_key();
        let mut store = v2_store(&master);
        modify_ssh_keys(&mut store, &master, |entries| {
            entries.push(real_entry("old"));
            Ok(true)
        })
        .unwrap();
        store.ssh_public_keys.clear();
        assert!(public_entries(&store).is_err());

        let mut v3 = KeychainStore::new_v3(&[1u8; 8], &[2u8; 113]);
        v3.encrypted_ssh_keys = store.encrypted_ssh_keys.clone();
        assert!(public_entries(&v3).unwrap().is_empty());
    }

    /// A blob this master cannot decrypt must fail before the mutation runs
    /// and leave the stored bytes as they were, never re-encoded as empty.
    #[test]
    fn test_modify_ssh_keys_refuses_corrupt_blob() {
        let (mut store, master) = test_store();
        store.set_encrypted_ssh_keys(b"not-a-ciphertext");
        let before = store.encrypted_ssh_keys.clone();
        let mut ran = false;
        let err = modify_ssh_keys(&mut store, &master, |_| {
            ran = true;
            Ok(true)
        });
        assert!(err.is_err());
        assert!(!ran, "mutation must not run on an unreadable blob");
        assert_eq!(store.encrypted_ssh_keys, before);
        assert!(load_private_keys(&store, &master).is_err());
    }

    #[test]
    fn fingerprint_mismatch_cannot_select_another_private_key() {
        let (mut store, master) = test_store();
        let mut entry = real_entry("mismatch");
        entry.fingerprint = real_entry("other").fingerprint.clone();
        let json = serde_json::to_vec(&vec![entry.clone()]).unwrap();
        store.set_encrypted_ssh_keys(&AesGcmCrypto::new(&master).unwrap().encrypt(&json).unwrap());
        assert!(public_entry(&entry).is_err());
        assert!(load_private_keys(&store, &master).is_err());
    }

    #[test]
    fn public_list_mismatch_and_failed_write_fail_closed() {
        let (mut store, master) = test_store();
        modify_ssh_keys(&mut store, &master, |entries| {
            entries.push(real_entry("good"));
            Ok(true)
        })
        .unwrap();
        let before = serde_json::to_vec(&store).unwrap();
        assert!(modify_ssh_keys(&mut store, &master, |entries| {
            entries[0].fingerprint = "SHA256:wrong".into();
            Ok(true)
        })
        .is_err());
        assert_eq!(serde_json::to_vec(&store).unwrap(), before);
        store.ssh_public_keys[0] = public_entry(&real_entry("foreign")).unwrap();
        assert!(load_private_keys(&store, &master).is_err());
        store.ssh_public_keys[0].fingerprint = "SHA256:wrong".into();
        assert!(public_entries(&store).is_err());
    }

    #[test]
    fn test_carry_ssh_keys_fills_public_list() {
        let master = AesGcmCrypto::generate_key();
        let mut from = v2_store(&master);
        modify_ssh_keys(&mut from, &master, |entries| {
            entries.push(real_entry("carried"));
            Ok(true)
        })
        .unwrap();
        from.ssh_public_keys.clear();
        let mut to = KeychainStore::new_v3(&[1u8; 8], &[2u8; 113]);
        carry_ssh_keys(&from, &master, &mut to).unwrap();
        assert!(to.encrypted_ssh_keys.is_some());
        assert_eq!(to.ssh_public_keys.len(), 1);
        assert_eq!(load_private_keys(&to, &master).unwrap().len(), 1);
    }
}
