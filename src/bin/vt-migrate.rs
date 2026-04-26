//! One-shot migration: legacy 4-item keychain layout → `rusty.vault.store`.
//!
//! Build:   `cargo build --release --bin vt-migrate`
//! Run:     `./target/release/vt-migrate`
//!
//! This binary is intentionally separate from `vt` so the main CLI does not
//! ship with migration code that's only relevant once. Ordinary users on
//! fresh installs never need this — it exists only to bridge upgrades from
//! the old layout (`rusty.vault.{passcode,passphrase,ssh_keys,fido2_credentials}`).
//!
//! What it does:
//!   1. Reads the four legacy keychain items.
//!   2. Confirms the legacy passphrase decrypts (catches "binary moved
//!      since `vt init`" / wrong `$USER` early — before any write).
//!   3. Writes a new `rusty.vault.store` with the same passcode +
//!      passphrase + (optional) ssh_keys + (optional) fido2 fields.
//!   4. Re-reads the new store and verifies, by full decrypt, that the
//!      plaintext matches the legacy items.
//!
//! What it does NOT do: delete the legacy items. After this command
//! reports success, run `vt ssh list` / `vt fido2 list` / `vt read …`
//! to confirm the consolidated store works, then remove the four legacy
//! items manually via Keychain Access.

// `security.rs` and `store.rs` are pulled in wholesale via `#[path]`; this
// migration tool only uses a small subset of their public API, so the rest
// shows up as "dead code" in this build target. The warnings are noise here.
#![allow(dead_code, unused_imports)]

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("vt-migrate only runs on macOS");
    std::process::exit(1);
}

// Provide a stub `crate::fido2` so the included `security.rs` compiles —
// migration code never calls `security::authenticate`, but the function
// definition references `crate::fido2::FidoOutcome`. Implementing it
// fully here would pull in the USB HID dependency tree, which is dead
// weight for this tool.
#[cfg(target_os = "macos")]
mod fido2 {
    #[allow(dead_code)]
    pub enum FidoOutcome {
        Success,
        Rejected,
        Skip,
    }
    #[allow(dead_code)]
    pub fn authenticate(_reason: &str) -> FidoOutcome {
        FidoOutcome::Skip
    }
}

#[cfg(target_os = "macos")]
#[path = "../security.rs"]
mod security;

#[cfg(target_os = "macos")]
#[path = "../store.rs"]
mod store;

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = run() {
        eprintln!("migration failed: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};

    use security::{derive_passphrase_secret, get_keychain, AesGcmCrypto};
    use store::KeychainStore;

    if KeychainStore::load().is_ok() {
        anyhow::bail!(
            "rusty.vault.store already exists — refusing to overwrite. \
            Delete it via Keychain Access first if you really want to re-migrate."
        );
    }

    // Required: passcode + passphrase. Optional: ssh_keys + fido2.
    let legacy_passcode = get_keychain("passcode")
        .context("failed to read legacy rusty.vault.passcode — nothing to migrate?")?;
    ensure!(
        legacy_passcode.len() == 64,
        "legacy passcode is {} bytes, expected 64",
        legacy_passcode.len()
    );
    let legacy_encrypted_passphrase =
        get_keychain("passphrase").context("failed to read legacy rusty.vault.passphrase")?;
    let legacy_ssh_keys = get_keychain("ssh_keys").ok();
    let legacy_fido2 = get_keychain("fido2_credentials").ok();

    // Functional decrypt check before any write — verifies the migration
    // is recoverable on the current host.
    let passcode_arr: [u8; 32] = legacy_passcode[..32].try_into()?;
    let passphrase_secret = derive_passphrase_secret(&passcode_arr, None)?;
    let passphrase_cipher = AesGcmCrypto::new(&passphrase_secret)?;
    let real_passphrase = passphrase_cipher
        .decrypt(&legacy_encrypted_passphrase)
        .context(
            "failed to decrypt legacy passphrase — confirm this binary path matches the one used \
            at `vt init` time and that $USER is the same",
        )?;
    ensure!(
        real_passphrase.len() == 32,
        "decrypted passphrase is {} bytes, expected 32",
        real_passphrase.len()
    );

    let mut new_store = KeychainStore::new(&legacy_passcode, &legacy_encrypted_passphrase);
    if let Some(ssh) = &legacy_ssh_keys {
        new_store.set_encrypted_ssh_keys(ssh);
    }
    if let Some(fido2) = &legacy_fido2 {
        new_store.set_encrypted_fido2(fido2);
    }
    new_store
        .save()
        .context("failed to write new rusty.vault.store")?;

    // Round-trip verify. Byte-equality alone wouldn't catch a field swap
    // (e.g. ssh_keys put into encrypted_fido2) since both round-trip
    // through base64 cleanly; decrypt-and-compare confirms equivalence.
    let reloaded = KeychainStore::load().context("verification load failed")?;
    let reloaded_passcode = reloaded.passcode_and_auth_token_bytes()?;
    ensure!(
        reloaded_passcode == legacy_passcode,
        "verification: passcode bytes mismatch after round-trip"
    );
    let reloaded_passphrase = passphrase_cipher
        .decrypt(&reloaded.encrypted_passphrase_bytes()?)
        .context("verification: failed to decrypt passphrase from new store")?;
    ensure!(
        reloaded_passphrase == real_passphrase,
        "verification: passphrase plaintext mismatch after round-trip"
    );

    let passphrase_array: [u8; 32] = real_passphrase
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("passphrase length check failed"))?;
    let mac_cipher = AesGcmCrypto::new(&passphrase_array)?;

    if let Some(legacy_ssh) = &legacy_ssh_keys {
        let legacy_plain = mac_cipher
            .decrypt(legacy_ssh)
            .context("failed to decrypt legacy ssh_keys")?;
        let new_enc = reloaded
            .encrypted_ssh_keys_bytes()?
            .ok_or_else(|| anyhow::anyhow!("verification: new store missing ssh_keys field"))?;
        let new_plain = mac_cipher
            .decrypt(&new_enc)
            .context("verification: failed to decrypt ssh_keys from new store")?;
        ensure!(
            legacy_plain == new_plain,
            "verification: ssh_keys plaintext mismatch after round-trip"
        );
    }
    if let Some(legacy_f) = &legacy_fido2 {
        let legacy_plain = mac_cipher
            .decrypt(legacy_f)
            .context("failed to decrypt legacy fido2_credentials")?;
        let new_enc = reloaded
            .encrypted_fido2_bytes()?
            .ok_or_else(|| anyhow::anyhow!("verification: new store missing fido2 field"))?;
        let new_plain = mac_cipher
            .decrypt(&new_enc)
            .context("verification: failed to decrypt fido2 from new store")?;
        ensure!(
            legacy_plain == new_plain,
            "verification: fido2 plaintext mismatch after round-trip"
        );
    }

    println!("Migration complete. New item: rusty.vault.store");
    println!();
    println!("Verify functionality (e.g. `vt ssh list`, `vt fido2 list`, `vt read …`),");
    println!("then delete the legacy items in Keychain Access:");
    println!("  - rusty.vault.passcode");
    println!("  - rusty.vault.passphrase");
    if legacy_ssh_keys.is_some() {
        println!("  - rusty.vault.ssh_keys");
    }
    if legacy_fido2.is_some() {
        println!("  - rusty.vault.fido2_credentials");
    }
    Ok(())
}
