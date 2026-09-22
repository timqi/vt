use anyhow::{Context, Result};
use ssh_key::private::PrivateKey;
use ssh_key::HashAlg;

use super::security::{local_authentication, MasterAccess};
use super::ssh_agent::keys::{public_entries, with_ssh_keys};
use super::ssh_agent::{require_ed25519, SshKeyEntry};
use super::store::{KeychainStore, SshPublicEntry};

/// One Touch ID that also opens the master for the key-store write.
fn open_master(reason: &str) -> Result<MasterAccess> {
    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    MasterAccess::open(&store, reason)
}

pub fn ssh_add(file: Option<String>, comment: Option<String>) -> Result<()> {
    let access = open_master("add SSH key")?;

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

    let mut privkey =
        PrivateKey::from_openssh(key_data.as_bytes()).context("Failed to parse SSH private key")?;

    // If encrypted, prompt for passphrase
    if privkey.is_encrypted() {
        let passphrase = rpassword::prompt_password("Enter key passphrase: ")
            .context("Failed to read passphrase")?;
        privkey = privkey
            .decrypt(passphrase.as_bytes())
            .context("Failed to decrypt key (wrong passphrase?)")?;
    }
    require_ed25519(&privkey)?;

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
    with_ssh_keys(&access, |entries| {
        if entries.iter().any(|e| e.fingerprint == fp_for_modify) {
            return Ok(false);
        }
        entries.push(SshKeyEntry {
            fingerprint: fp_for_modify,
            algorithm: algorithm_for_modify,
            comment: comment_for_modify,
            key_data: key_openssh_str,
        });
        Ok(true)
    })?;

    println!("Added: {} {} {}", algorithm, fp_str, comment);
    Ok(())
}

/// Public halves only: no master, no prompt.
pub fn ssh_list() -> Result<()> {
    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    let entries = public_entries(&store)?;
    if entries.is_empty() {
        println!("No SSH keys stored.");
        return Ok(());
    }

    for entry in &entries {
        println!(
            "{} {} {}\n  {}",
            entry.algorithm, entry.fingerprint, entry.comment, entry.public_key
        );
    }
    Ok(())
}

/// The one stored key whose fingerprint contains `needle`, from the plaintext
/// public list (no master, no prompt). No match and more than one match are
/// errors (the candidates are listed), so a caller never mutates on an
/// ambiguous prefix.
fn select_entry<'a>(entries: &'a [SshPublicEntry], needle: &str) -> Result<&'a SshPublicEntry> {
    let matches: Vec<&SshPublicEntry> = entries
        .iter()
        .filter(|e| e.fingerprint.contains(needle))
        .collect();
    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("No key found matching '{}'", needle)),
        [entry] => Ok(entry),
        _ => {
            println!("Multiple keys match '{}':", needle);
            for m in &matches {
                println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
            }
            Err(anyhow::anyhow!(
                "Ambiguous fingerprint, please be more specific"
            ))
        }
    }
}

/// Resolve `needle` before prompting so an ambiguous prefix costs no Touch ID.
fn select_stored(needle: &str) -> Result<SshPublicEntry> {
    let store = KeychainStore::load().map_err(|e| anyhow::anyhow!("Not initialized? {}", e))?;
    Ok(select_entry(&public_entries(&store)?, needle)?.clone())
}

pub fn ssh_remove(fingerprint: &str) -> Result<()> {
    let target = select_stored(fingerprint)?;
    let access = open_master("remove SSH key")?;
    with_ssh_keys(&access, |entries| {
        entries.retain(|e| e.fingerprint != target.fingerprint);
        Ok(true)
    })?;
    println!(
        "Removed: {} {} {}",
        target.algorithm, target.fingerprint, target.comment
    );
    Ok(())
}

pub fn ssh_remove_all() -> Result<()> {
    let access = open_master("remove all SSH keys")?;

    with_ssh_keys(&access, |entries| {
        entries.clear();
        Ok(true)
    })?;

    println!("Removed all SSH keys.");
    Ok(())
}

pub fn ssh_comment(fingerprint: &str, comment: &str) -> Result<()> {
    let target = select_stored(fingerprint)?;
    let access = open_master("change SSH key comment")?;
    let new_comment = comment.to_string();
    with_ssh_keys(&access, |entries| {
        let entry = entries
            .iter_mut()
            .find(|e| e.fingerprint == target.fingerprint)
            .ok_or_else(|| anyhow::anyhow!("key {} vanished", target.fingerprint))?;
        let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
            .context("Failed to parse stored key")?;
        let privkey = PrivateKey::new(privkey.key_data().clone(), &new_comment)
            .context("Failed to set comment on key")?;
        entry.key_data = privkey
            .to_openssh(ssh_key::LineEnding::LF)
            .context("Failed to serialize key")?
            .to_string();
        entry.comment = new_comment.clone();
        Ok(true)
    })?;
    println!(
        "Updated: {} {} {}",
        target.algorithm, target.fingerprint, comment
    );
    Ok(())
}

pub fn ssh_show(fingerprint: &str) -> Result<()> {
    if !local_authentication("show SSH public key") {
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    println!("{}", select_stored(fingerprint)?.public_key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fp: &str) -> SshPublicEntry {
        SshPublicEntry {
            fingerprint: fp.to_string(),
            algorithm: "ssh-ed25519".to_string(),
            comment: String::new(),
            public_key: String::new(),
        }
    }

    #[test]
    fn select_entry_is_unique_substring_match_or_error() {
        let entries = vec![
            entry("SHA256:abcdef"),
            entry("SHA256:abxyz"),
            entry("SHA256:qrs"),
        ];
        assert_eq!(
            select_entry(&entries, "cdef").unwrap().fingerprint,
            "SHA256:abcdef"
        );
        assert_eq!(
            select_entry(&entries, "SHA256:qrs").unwrap().fingerprint,
            "SHA256:qrs"
        );
        let none = select_entry(&entries, "zzz").unwrap_err().to_string();
        assert_eq!(none, "No key found matching 'zzz'");
        let many = select_entry(&entries, "SHA256:ab").unwrap_err().to_string();
        assert_eq!(many, "Ambiguous fingerprint, please be more specific");
        assert!(select_entry(&[], "").is_err());
    }
}
