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

/// The one stored entry whose fingerprint contains `needle`. No match and
/// more than one match are errors (the candidates are listed), so a caller
/// never mutates on an ambiguous prefix.
fn select_entry<E: Listed>(entries: &[E], needle: &str) -> Result<usize> {
    let matches: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].fingerprint().contains(needle))
        .collect();
    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("No key found matching '{}'", needle)),
        [i] => Ok(*i),
        _ => {
            println!("Multiple keys match '{}':", needle);
            for &i in &matches {
                println!("  {}", entries[i].line());
            }
            Err(anyhow::anyhow!(
                "Ambiguous fingerprint, please be more specific"
            ))
        }
    }
}

/// `select_entry` runs over private entries (mutations) and public entries
/// (`ssh show`).
trait Listed {
    fn fingerprint(&self) -> &str;
    fn line(&self) -> String;
}

impl Listed for SshKeyEntry {
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn line(&self) -> String {
        format!("{} {} {}", self.algorithm, self.fingerprint, self.comment)
    }
}

impl Listed for SshPublicEntry {
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn line(&self) -> String {
        format!("{} {} {}", self.algorithm, self.fingerprint, self.comment)
    }
}

pub fn ssh_remove(fingerprint: &str) -> Result<()> {
    let access = open_master("remove SSH key")?;

    let mut removed_info: Option<String> = None;
    with_ssh_keys(&access, |entries| {
        let entry = entries.remove(select_entry(entries, fingerprint)?);
        removed_info = Some(format!(
            "{} {} {}",
            entry.algorithm, entry.fingerprint, entry.comment
        ));
        Ok(true)
    })?;

    if let Some(info) = removed_info {
        println!("Removed: {}", info);
    }
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
    let access = open_master("change SSH key comment")?;

    let new_comment = comment.to_string();
    let mut updated_info: Option<(String, String)> = None;
    with_ssh_keys(&access, |entries| {
        let i = select_entry(entries, fingerprint)?;
        let entry = &mut entries[i];
        let fp = entry.fingerprint.clone();
        let algorithm = entry.algorithm.clone();

        let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
            .context("Failed to parse stored key")?;
        let privkey = PrivateKey::new(privkey.key_data().clone(), &new_comment)
            .context("Failed to set comment on key")?;
        let key_openssh = privkey
            .to_openssh(ssh_key::LineEnding::LF)
            .context("Failed to serialize key")?;

        entry.comment = new_comment.clone();
        entry.key_data = key_openssh.to_string();

        updated_info = Some((algorithm, fp));
        Ok(true)
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
    let entries = public_entries(&store)?;
    println!(
        "{}",
        entries[select_entry(&entries, fingerprint)?].public_key
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fp: &str) -> SshKeyEntry {
        SshKeyEntry {
            fingerprint: fp.to_string(),
            algorithm: "ssh-ed25519".to_string(),
            comment: String::new(),
            key_data: String::new(),
        }
    }

    #[test]
    fn select_entry_is_unique_substring_match_or_error() {
        let entries = vec![
            entry("SHA256:abcdef"),
            entry("SHA256:abxyz"),
            entry("SHA256:qrs"),
        ];
        assert_eq!(select_entry(&entries, "cdef").unwrap(), 0);
        assert_eq!(select_entry(&entries, "SHA256:qrs").unwrap(), 2);
        let none = select_entry(&entries, "zzz").unwrap_err().to_string();
        assert_eq!(none, "No key found matching 'zzz'");
        let many = select_entry(&entries, "SHA256:ab").unwrap_err().to_string();
        assert_eq!(many, "Ambiguous fingerprint, please be more specific");
        assert!(select_entry::<SshKeyEntry>(&[], "").is_err());
    }
}
