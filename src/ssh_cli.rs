use anyhow::{Context, Result};
use ssh_key::private::PrivateKey;
use ssh_key::HashAlg;

use crate::security::{derive_passcode_ciphers, load_mac_cipher, local_authentication};
use crate::ssh_agent::{decode_ssh_keys, encode_ssh_keys_into, SshKeyEntry};
use crate::store::KeychainStore;

pub fn ssh_add(file: Option<String>, comment: Option<String>) -> Result<()> {
    if !local_authentication("add SSH key") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    let interactive = file.is_none();
    let key_data = match file {
        Some(path) => {
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path))?
        }
        None => {
            eprintln!("Paste your private key (end with Ctrl+D):");
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf.trim().to_string()
        }
    };

    let mut privkey = PrivateKey::from_openssh(key_data.as_bytes())
        .context("Failed to parse SSH private key")?;

    // If encrypted, prompt for passphrase
    if privkey.is_encrypted() {
        let passphrase = rpassword::prompt_password("Enter key passphrase: ")
            .context("Failed to read passphrase")?;
        privkey = privkey
            .decrypt(passphrase.as_bytes())
            .context("Failed to decrypt key (wrong passphrase?)")?;
    }

    let comment = comment.unwrap_or_else(|| {
        if interactive {
            // stdin is EOF after Ctrl+D, read from /dev/tty instead
            if let Ok(mut tty) = std::fs::File::open("/dev/tty") {
                use std::io::BufRead;
                eprint!("Comment (leave empty to use key's default): ");
                let mut input = String::new();
                if std::io::BufReader::new(&mut tty)
                    .read_line(&mut input)
                    .is_ok()
                {
                    let trimmed = input.trim().to_string();
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }
            }
        }
        privkey.comment().to_string()
    });

    // Rebuild key with the desired comment so it's embedded in the stored OpenSSH format
    let privkey = PrivateKey::new(privkey.key_data().clone(), &comment)
        .context("Failed to set comment on key")?;

    let pubkey = privkey.public_key();
    let fp = ssh_key::Fingerprint::new(HashAlg::Sha256, pubkey.key_data());
    let fp_str = fp.to_string();
    let algorithm = pubkey.algorithm().to_string();

    let key_openssh = privkey
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to serialize key")?;

    let fp_for_modify = fp_str.clone();
    let algorithm_for_modify = algorithm.clone();
    let comment_for_modify = comment.clone();
    let key_openssh_str = key_openssh.to_string();
    KeychainStore::modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let mac_cipher = load_mac_cipher(store, &passphrase_cipher)?;
        let mut entries = decode_ssh_keys(store, &mac_cipher)?;
        if !entries.iter().any(|e| e.fingerprint == fp_for_modify) {
            entries.push(SshKeyEntry {
                fingerprint: fp_for_modify,
                algorithm: algorithm_for_modify,
                comment: comment_for_modify,
                key_data: key_openssh_str,
            });
            encode_ssh_keys_into(store, &mac_cipher, &entries)?;
        }
        Ok(())
    })?;

    println!("Added: {} {} {}", algorithm, fp_str, comment);
    Ok(())
}

pub fn ssh_list() -> Result<()> {
    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    let (_, passphrase_cipher) = derive_passcode_ciphers(&store)?;
    let mac_cipher = load_mac_cipher(&store, &passphrase_cipher)?;
    let entries = decode_ssh_keys(&store, &mac_cipher)?;
    if entries.is_empty() {
        println!("No SSH keys stored.");
        return Ok(());
    }

    for entry in &entries {
        let pubkey_line = PrivateKey::from_openssh(entry.key_data.as_bytes())
            .ok()
            .and_then(|pk| pk.public_key().to_openssh().ok())
            .unwrap_or_default();
        println!(
            "{} {} {}\n  {}",
            entry.algorithm, entry.fingerprint, entry.comment, pubkey_line
        );
    }
    Ok(())
}

pub fn ssh_remove(fingerprint: &str) -> Result<()> {
    if !local_authentication("remove SSH key") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    let needle = fingerprint.to_string();
    let mut removed_info: Option<String> = None;
    KeychainStore::modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let mac_cipher = load_mac_cipher(store, &passphrase_cipher)?;
        let mut entries = decode_ssh_keys(store, &mac_cipher)?;

        let matches: Vec<_> = entries
            .iter()
            .filter(|e| e.fingerprint.contains(&needle))
            .cloned()
            .collect();

        if matches.is_empty() {
            return Err(anyhow::anyhow!("No key found matching '{}'", needle));
        }
        if matches.len() > 1 {
            println!("Multiple keys match '{}':", needle);
            for m in &matches {
                println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
            }
            return Err(anyhow::anyhow!(
                "Ambiguous fingerprint, please be more specific"
            ));
        }

        let entry = &matches[0];
        removed_info = Some(format!(
            "{} {} {}",
            entry.algorithm, entry.fingerprint, entry.comment
        ));

        entries.retain(|e| e.fingerprint != entry.fingerprint);
        encode_ssh_keys_into(store, &mac_cipher, &entries)?;
        Ok(())
    })?;

    if let Some(info) = removed_info {
        println!("Removed: {}", info);
    }
    Ok(())
}

pub fn ssh_remove_all() -> Result<()> {
    if !local_authentication("remove all SSH keys") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    KeychainStore::modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let mac_cipher = load_mac_cipher(store, &passphrase_cipher)?;
        encode_ssh_keys_into(store, &mac_cipher, &[])?;
        Ok(())
    })?;

    println!("Removed all SSH keys.");
    Ok(())
}

pub fn ssh_comment(fingerprint: &str, comment: &str) -> Result<()> {
    if !local_authentication("change SSH key comment") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    let needle = fingerprint.to_string();
    let new_comment = comment.to_string();
    let mut updated_info: Option<(String, String)> = None;
    KeychainStore::modify(|store| {
        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
        let mac_cipher = load_mac_cipher(store, &passphrase_cipher)?;
        let mut entries = decode_ssh_keys(store, &mac_cipher)?;

        let matches: Vec<_> = entries
            .iter()
            .filter(|e| e.fingerprint.contains(&needle))
            .collect();

        if matches.is_empty() {
            return Err(anyhow::anyhow!("No key found matching '{}'", needle));
        }
        if matches.len() > 1 {
            println!("Multiple keys match '{}':", needle);
            for m in &matches {
                println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
            }
            return Err(anyhow::anyhow!(
                "Ambiguous fingerprint, please be more specific"
            ));
        }

        let fp = matches[0].fingerprint.clone();
        let algorithm = matches[0].algorithm.clone();
        let entry = entries.iter_mut().find(|e| e.fingerprint == fp).unwrap();

        let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
            .context("Failed to parse stored key")?;
        let privkey = PrivateKey::new(privkey.key_data().clone(), &new_comment)
            .context("Failed to set comment on key")?;
        let key_openssh = privkey
            .to_openssh(ssh_key::LineEnding::LF)
            .context("Failed to serialize key")?;

        entry.comment = new_comment.clone();
        entry.key_data = key_openssh.to_string();
        encode_ssh_keys_into(store, &mac_cipher, &entries)?;

        updated_info = Some((algorithm, fp));
        Ok(())
    })?;

    if let Some((algorithm, fp)) = updated_info {
        println!("Updated: {} {} {}", algorithm, fp, comment);
    }
    Ok(())
}

pub fn ssh_show(fingerprint: &str) -> Result<()> {
    if !local_authentication("show SSH public key") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    let (_, passphrase_cipher) = derive_passcode_ciphers(&store)?;
    let mac_cipher = load_mac_cipher(&store, &passphrase_cipher)?;
    let entries = decode_ssh_keys(&store, &mac_cipher)?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.fingerprint.contains(fingerprint))
        .cloned()
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("No key found matching '{}'", fingerprint));
    }
    if matches.len() > 1 {
        println!("Multiple keys match '{}':", fingerprint);
        for m in &matches {
            println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
        }
        return Err(anyhow::anyhow!(
            "Ambiguous fingerprint, please be more specific"
        ));
    }

    let entry = &matches[0];
    let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
        .context("Failed to parse stored key")?;
    let pubkey_str = privkey
        .public_key()
        .to_openssh()
        .context("Failed to serialize public key")?;
    println!("{}", pubkey_str);
    Ok(())
}
