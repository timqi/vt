//! macOS-only admin command bodies: `init`, `secret
//! export/import/rotate-passcode`. Every write produces a wrap v3 store
//! (docs/app-bundle.md#master-key-wrap-v3).

use super::security::{new_store_v3, MasterAccess};
use super::ssh_agent::keys::carry_ssh_keys;
use super::store::KeychainStore;
use crate::core::crypto::AesGcmCrypto;
use anyhow::{ensure, Context, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn init() -> Result<()> {
    ensure!(
        KeychainStore::load_if_present()?.is_none(),
        "rusty.vault.store already exists"
    );
    new_store_v3(&Zeroizing::new(AesGcmCrypto::generate_key()))?.save()?;
    tracing::info!("keychain store saved!");
    Ok(())
}

/// Export-file cipher: SHA-256(SHA-256(passphrase)).
fn passphrase_cipher(prompt: &str, echo: &str) -> Result<AesGcmCrypto> {
    let passphrase = Zeroizing::new(crate::tty::prompt_input_password(prompt, echo)?);
    let hash = Sha256::digest(Sha256::digest(passphrase.as_bytes()));
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&hash[..32]);
    AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")
}

pub async fn export_secret() -> Result<()> {
    let store = KeychainStore::load()?;
    let access = MasterAccess::open(&store, "export master secret")?;
    let exported = export_master(&store, &access, || {
        passphrase_cipher(
            "Enter master secret passphrase: ",
            "Master secret passphrase entered: ",
        )
    })?;
    println!(
        "Encrypted master secret passphrase (base64): {}",
        BASE64_URL_SAFE_NO_PAD.encode(exported)
    );
    Ok(())
}

fn export_master(
    store: &KeychainStore,
    access: &MasterAccess,
    cipher: impl FnOnce() -> Result<AesGcmCrypto>,
) -> Result<Vec<u8>> {
    let cipher = cipher()?;
    let master = access.master(store)?;
    cipher
        .encrypt(master.as_slice())
        .context("Failed to encrypt master secret passphrase")
}

/// Install an exported master. With no store, a fresh wrap v3 store is
/// created. With one present, import is a re-wrap under a new Secure Enclave
/// key (fingerprint enrollment changed): the imported master must open the
/// stored SSH keys, which proves it is this store's master and carries them
/// over. A store with nothing to prove that against is never replaced.
pub async fn import_secret() -> Result<()> {
    let existing = KeychainStore::load_if_present()?;
    let master_secret =
        crate::tty::prompt_input_password("Enter master secret: ", "Master secret entered: ")?;
    let encrypted = BASE64_URL_SAFE_NO_PAD.decode(master_secret)?;
    let import_cipher = passphrase_cipher(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let master = Zeroizing::new(import_cipher.decrypt(&encrypted)?);
    let master: Zeroizing<[u8; 32]> = Zeroizing::new(
        master
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?,
    );
    match existing {
        None => new_store_v3(&master)?
            .save()
            .context("Failed to save the wrap v3 store")?,
        Some(_) => KeychainStore::modify(|current| reimport(current, &master, new_store_v3))?,
    }
    tracing::info!("keychain store saved!");
    Ok(())
}

fn reimport(
    current: &mut KeychainStore,
    master: &[u8; 32],
    wrap: impl FnOnce(&[u8; 32]) -> Result<KeychainStore>,
) -> Result<()> {
    ensure!(
        current.encrypted_ssh_keys.is_some(),
        "rusty.vault.store already exists and holds no SSH keys that could prove the same \
         master; delete it first: security delete-generic-password -s rusty.vault.store"
    );
    rewrap(current, master, wrap)
        .context("the imported master does not open this store's SSH keys; refusing to replace it")
}

/// Rewrite a wrap v2 or v3 store as wrap v3 under a new Secure Enclave key:
/// one Touch ID opens the current master, the SSH keys carry over under it.
pub async fn rotate_passcode() -> Result<()> {
    let store = KeychainStore::load()?;
    let access = MasterAccess::open_migration(&store)?;
    KeychainStore::modify(|current| {
        let master = access.master(current)?;
        rewrap(current, &master, new_store_v3)
    })?;
    eprintln!(
        "Store rewritten as wrap v3 under a new Secure Enclave key. If `vt ssh agent` is \
        running, restart it so its approval sessions bind to the new key."
    );
    Ok(())
}

/// Replace `current` with `wrap(master)`, SSH keys carried over. A blob the
/// master cannot open aborts before anything is replaced.
fn rewrap(
    current: &mut KeychainStore,
    master: &[u8; 32],
    wrap: impl FnOnce(&[u8; 32]) -> Result<KeychainStore>,
) -> Result<()> {
    let mut next = wrap(master)?;
    carry_ssh_keys(current, master, &mut next)?;
    *current = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_one_key(master: &[u8; 32]) -> KeychainStore {
        use crate::server_macos::ssh_agent::keys;
        let mut store = KeychainStore::new_v3(&[1; 8], &[2; 113]);
        let key = ssh_key::private::PrivateKey::random(
            &mut rand::rngs::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        keys::modify_ssh_keys(&mut store, master, |entries| {
            entries.push(keys::SshKeyEntry {
                fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
                comment: String::new(),
                key_data: key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            });
            Ok(true)
        })
        .unwrap();
        store
    }

    fn fake_wrap(_: &[u8; 32]) -> Result<KeychainStore> {
        Ok(KeychainStore::new_v3(&[3; 8], &[4; 113]))
    }

    /// Rotation and re-import replace the store only when the master opens
    /// its SSH keys; a blob under another master leaves the store untouched.
    #[test]
    fn rewrap_carries_keys_or_leaves_the_store_alone() {
        use crate::server_macos::ssh_agent::keys;
        let master = [7; 32];
        let mut current = store_with_one_key(&master);
        rewrap(&mut current, &master, fake_wrap).unwrap();
        assert_eq!(current.se_key.as_deref(), Some("AwMDAwMDAwM"));
        assert_eq!(keys::load_private_keys(&current, &master).unwrap().len(), 1);

        let mut other = store_with_one_key(&[8; 32]);
        let before = serde_json::to_vec(&other).unwrap();
        assert!(rewrap(&mut other, &master, fake_wrap).is_err());
        assert_eq!(serde_json::to_vec(&other).unwrap(), before);
    }

    /// Import over an existing store is a same-master re-wrap: it needs SSH
    /// keys to prove the master and refuses otherwise.
    #[test]
    fn reimport_requires_proof_of_the_same_master() {
        let master = [7; 32];
        let mut current = store_with_one_key(&master);
        reimport(&mut current, &master, fake_wrap).unwrap();
        assert_eq!(current.se_key.as_deref(), Some("AwMDAwMDAwM"));

        let mut empty = KeychainStore::new_v3(&[1; 8], &[2; 113]);
        let err = reimport(&mut empty, &master, |_| panic!("no wrap without proof"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("delete it first"), "{err}");

        let mut other = store_with_one_key(&[8; 32]);
        let err = reimport(&mut other, &master, fake_wrap)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not open"), "{err}");
        assert_eq!(other.se_key.as_deref(), Some("AQEBAQEBAQE"));
    }

    #[test]
    fn export_prompts_before_unwrapping() {
        let access =
            MasterAccess::Enclave(crate::server_macos::se::test_support::software_session());
        let store = KeychainStore::new_v3(&[1; 8], &[2; 113]);
        let mut prompted = false;
        assert!(export_master(&store, &access, || {
            prompted = true;
            anyhow::bail!("cancelled passphrase prompt")
        })
        .is_err());
        assert!(prompted, "unwrap must not precede the passphrase prompt");
    }
}
