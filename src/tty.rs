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
    eprintln!("{}{}", prompt_after, mask_secret(secret));
    Ok(secret.to_string())
}

/// Mask a secret for confirmation echo. Reveals the first/last 2 chars only
/// when there are at least 4 (so head and tail can't overlap and a short secret
/// isn't substantially exposed); otherwise fully masked. Char-based, never
/// byte-indexed — so a 1-char or multibyte-leading secret can't panic.
fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() >= 4 {
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[chars.len() - 2..].iter().collect();
        format!("{head}****{tail}")
    } else {
        "****".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::mask_secret;

    #[test]
    fn masks_short_and_multibyte_without_panic() {
        assert_eq!(mask_secret("a"), "****");
        assert_eq!(mask_secret("ab"), "****");
        assert_eq!(mask_secret("abc"), "****");
        // multibyte leading char (would panic on byte-slice &s[..2])
        assert_eq!(mask_secret("€"), "****");
        assert_eq!(mask_secret("€¥"), "****");
    }

    #[test]
    fn reveals_head_tail_when_long_enough() {
        assert_eq!(mask_secret("abcd"), "ab****cd");
        assert_eq!(mask_secret("password123"), "pa****23");
        // multibyte, 4+ chars: char-based slicing stays on boundaries
        assert_eq!(mask_secret("€¥£$"), "€¥****£$");
    }
}
