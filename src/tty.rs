//! TTY interaction helpers shared by client and server admin commands.
//!
//! Lives at the crate root (rather than under `core`) because it does
//! terminal I/O — `core` is reserved for pure cross-platform logic.

use anyhow::{Context, Result};

/// Prompt for a secret on stdin without echo, then echo a redacted
/// confirmation showing only the first/last two characters. Used by
/// `vt create` and the `vt secret` admin commands.
pub fn prompt_input_password(prompt_before: &str, prompt_after: &str) -> Result<String> {
    let secret = rpassword::prompt_password(prompt_before).context("Failed to read password")?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret cannot be empty"));
    }
    println!(
        "{}{}****{}",
        prompt_after,
        &secret[..2],
        &secret[secret.len() - 2..]
    );
    Ok(secret.to_string())
}
