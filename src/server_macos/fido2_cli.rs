use anyhow::{bail, Result};

use super::fido2;
use super::security::touch_id_authentication;

pub fn fido2_register(label: Option<String>) -> Result<()> {
    if !touch_id_authentication("register YubiKey for vt") {
        bail!("Touch ID authentication failed");
    }

    let label = match label {
        Some(l) => l,
        None => {
            eprint!("Label for this YubiKey (e.g. 'yubikey5-blue'): ");
            use std::io::Write;
            std::io::stderr().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            let trimmed = buf.trim().to_string();
            if trimmed.is_empty() {
                "unnamed".into()
            } else {
                trimmed
            }
        }
    };

    let cred = fido2::register(label)?;
    println!(
        "Registered: {}  {}  alg={:?}",
        cred.short_id(),
        cred.label,
        cred.pubkey_alg
    );
    Ok(())
}

pub fn fido2_list() -> Result<()> {
    let creds = fido2::list()?;
    if creds.is_empty() {
        println!("No FIDO2 credentials registered. Use `vt fido2 register` to add one.");
        return Ok(());
    }
    println!(
        "{:<17} {:<20} {:<10} {:<10} {}",
        "SHORT-ID", "LABEL", "ALG", "COUNTER", "CREATED"
    );
    for c in &creds {
        println!(
            "{:<17} {:<20} {:<10} {:<10} {}",
            c.short_id(),
            c.label,
            format!("{:?}", c.pubkey_alg),
            c.sign_counter,
            format_unix(c.created_at_unix),
        );
    }
    Ok(())
}

pub fn fido2_remove(short_id: &str) -> Result<()> {
    if !touch_id_authentication("remove YubiKey credential") {
        bail!("Touch ID authentication failed");
    }
    let n = fido2::remove(short_id)?;
    println!("Removed {} credential(s).", n);
    Ok(())
}

pub fn fido2_remove_all() -> Result<()> {
    if !touch_id_authentication("remove all YubiKey credentials") {
        bail!("Touch ID authentication failed");
    }
    let n = fido2::remove_all()?;
    println!("Removed {} credential(s).", n);
    Ok(())
}

fn format_unix(secs: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let Some(t) = UNIX_EPOCH.checked_add(Duration::from_secs(secs)) else {
        return "-".into();
    };
    let now = std::time::SystemTime::now();
    let delta = now.duration_since(t).unwrap_or_default().as_secs();
    if delta < 60 {
        format!("{}s ago", delta)
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}
