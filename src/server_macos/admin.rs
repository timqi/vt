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
    if KeychainStore::load().is_ok() {
        Err(anyhow::anyhow!(
            "Error: already initialized? Please delete 'rusty.vault.store' from the keychain first"
        ))?;
        std::process::exit(1);
    }
    new_store_v3(&Zeroizing::new(AesGcmCrypto::generate_key()))?.save()?;
    tracing::info!("keychain store saved!");
    Ok(())
}

/// Export-file cipher: SHA-256(SHA-256(passphrase)).
fn passphrase_cipher(prompt: &str, echo: &str) -> Result<AesGcmCrypto> {
    let passphrase = crate::tty::prompt_input_password(prompt, echo)?;
    let hash = Sha256::digest(Sha256::digest(passphrase.as_bytes()));
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&hash[..32]);
    AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")
}

pub async fn export_secret() -> Result<()> {
    let store = KeychainStore::load()?;
    let access = MasterAccess::open(&store, "export master secret")?;
    let master = access.master(&store)?;
    let export_cipher = passphrase_cipher(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let exported = export_cipher
        .encrypt(master.as_slice())
        .context("Failed to encrypt master secret passphrase")?;
    println!(
        "Encrypted master secret passphrase (base64): {}",
        BASE64_URL_SAFE_NO_PAD.encode(exported)
    );
    Ok(())
}

pub async fn import_secret() -> Result<()> {
    if KeychainStore::load().is_ok() {
        Err(anyhow::anyhow!(
            "Error: already imported? Please delete 'rusty.vault.store' from the keychain first"
        ))?;
        std::process::exit(1);
    }
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
    let access = MasterAccess::open(&store, "rotate passcode")?;
    let master = access
        .master(&store)
        .context("Failed to unwrap the master (docs/app-bundle.md#master-key-wrap-v3)")?;
    let mut next = new_store_v3(&master)?;
    carry_ssh_keys(&store, &master, &mut next)?;
    drop(master);
    next.save()?;
    eprintln!(
        "Store rewritten as wrap v3 under a new Secure Enclave key. If `vt ssh agent` is \
        running, restart it so its approval sessions bind to the new key."
    );
    Ok(())
}
