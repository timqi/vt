//! macOS-only admin command bodies: `init`, `secret
//! export/import/rotate-passcode`.

use super::security::{
    create_and_save_passcode_passphrase, derive_passcode_cipher, local_authentication,
};
use super::store::KeychainStore;
use crate::core::crypto::AesGcmCrypto;
use anyhow::{Context, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

pub fn init() -> Result<()> {
    if KeychainStore::load().is_ok() {
        Err(anyhow::anyhow!(
            "Error: already initialized? Please delete 'rusty.vault.store' from the keychain first"
        ))?;
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase(&AesGcmCrypto::generate_key())?;
    Ok(())
}

pub async fn export_secret() -> Result<()> {
    if !local_authentication("export master secret") {
        Err(anyhow::anyhow!(
            "Local authentication failed for export master secret"
        ))?;
    }
    let store = KeychainStore::load()?;
    let passphrase_cipher = derive_passcode_cipher(&store)?;
    let encrypted_passphrase = store.encrypted_passphrase_bytes()?;
    let decrypted_passphrase = passphrase_cipher
        .decrypt(&encrypted_passphrase)
        .context("Failed to decrypt passphrase")?;

    let master_secret_passphrase = crate::tty::prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let export_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    let new_encrypted_passphrase_bytes = export_cipher
        .encrypt(&decrypted_passphrase)
        .context("Failed to encrypt master secret passphrase")?;
    println!(
        "Encrypted master secret passphrase (base64): {}",
        BASE64_URL_SAFE_NO_PAD.encode(new_encrypted_passphrase_bytes)
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
    let encrypted_passphrase_bytes = BASE64_URL_SAFE_NO_PAD.decode(master_secret)?;

    let master_secret_passphrase = crate::tty::prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let import_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    // Wrap v2 derivation is path-independent — no binary-path prompt needed.
    let real_passphrase = import_cipher.decrypt(&encrypted_passphrase_bytes)?;
    let passphrase_array: [u8; 32] = real_passphrase
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?;

    create_and_save_passcode_passphrase(&passphrase_array)
        .context("Failed to create and save passcode passphrase")?;

    Ok(())
}

pub async fn rotate_passcode() -> Result<()> {
    if !local_authentication("rotate passcode") {
        Err(anyhow::anyhow!(
            "Local authentication failed for rotate passcode"
        ))?;
    }
    let store = KeychainStore::load()?;
    let passphrase_cipher = derive_passcode_cipher(&store)?;
    let encrypted_passphrase = store.encrypted_passphrase_bytes()?;
    let decrypted_passphrase = passphrase_cipher
        .decrypt(&encrypted_passphrase)
        .context("Failed to decrypt passphrase (docs/app-bundle.md#master-key-wrap-v2).")?;
    let passphrase_array: [u8; 32] = decrypted_passphrase
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?;
    create_and_save_passcode_passphrase(&passphrase_array)?;
    eprintln!(
        "Passcode rotated. If `vt ssh agent` is running, restart it — the cached passphrase cipher \
        is now stale and decrypt requests will fail until a fresh process is started."
    );
    Ok(())
}
