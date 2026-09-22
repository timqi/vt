//! macOS-only admin command bodies: `init`, `secret
//! export/import/rotate-passcode`. Every write produces a wrap v3 store
//! (docs/app-bundle.md#master-key-wrap-v3).

use super::security::{new_store_v3, MasterAccess};
use super::ssh_agent::keys::carry_ssh_keys;
use super::store::KeychainStore;
use crate::core::crypto::AesGcmCrypto;
use anyhow::{Context, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn init() -> Result<()> {
    KeychainStore::require_absent()?;
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

pub async fn import_secret() -> Result<()> {
    KeychainStore::require_absent()?;
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
    new_store_v3(&master)?
        .save()
        .context("Failed to save the wrap v3 store")?;
    tracing::info!("keychain store saved!");
    Ok(())
}

/// Rewrite a wrap v2 or v3 store as wrap v3 under a new Secure Enclave key:
/// one Touch ID opens the current master, the SSH keys carry over under it.
pub async fn rotate_passcode() -> Result<()> {
    let store = KeychainStore::load()?;
    let access = MasterAccess::open_migration(&store)?;
    KeychainStore::modify(|current| rewrap(current, &access, new_store_v3))?;
    eprintln!(
        "Store rewritten as wrap v3 under a new Secure Enclave key. If `vt ssh agent` is \
        running, restart it so its approval sessions bind to the new key."
    );
    Ok(())
}

fn rewrap(
    current: &mut KeychainStore,
    access: &MasterAccess,
    wrap: impl FnOnce(&[u8; 32]) -> Result<KeychainStore>,
) -> Result<()> {
    let master = access.master(current)?;
    let mut next = wrap(&master)?;
    carry_ssh_keys(current, &master, &mut next)?;
    *current = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_uses_current_store_and_rejects_changed_master() {
        use crate::server_macos::{
            security::{derive_passcode_cipher, tests::v2_store},
            ssh_agent::keys,
        };
        let master = [7; 32];
        let mut current = v2_store(&master);
        let access = MasterAccess::Passcode(Box::new(derive_passcode_cipher(&current).unwrap()));
        let key = ssh_key::private::PrivateKey::random(
            &mut rand::rngs::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        keys::modify_ssh_keys(&mut current, &master, |entries| {
            entries.push(keys::SshKeyEntry {
                fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
                comment: String::new(),
                key_data: key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            });
            Ok(true)
        })
        .unwrap();
        rewrap(&mut current, &access, |_| {
            Ok(KeychainStore::new_v3(&[1; 8], &[2; 113]))
        })
        .unwrap();
        assert_eq!(keys::load_private_keys(&current, &master).unwrap().len(), 1);
        let mut changed = v2_store(&[8; 32]);
        let before = serde_json::to_vec(&changed).unwrap();
        assert!(rewrap(&mut changed, &access, |_| panic!(
            "must not replace changed master"
        ))
        .is_err());
        assert_eq!(serde_json::to_vec(&changed).unwrap(), before);
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
