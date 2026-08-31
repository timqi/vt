//! TTY interaction helpers shared by client and server admin commands.
//!
//! Lives at the crate root (rather than under `core`) because it does
//! terminal I/O — `core` is reserved for pure cross-platform logic.

use anyhow::{Context, Result};

/// Read a secret from a non-terminal stdin (pipe, file, here-doc) for
/// `vt create`. The counterpart of `prompt_input_password`: same contract
/// (non-empty plaintext back), no terminal required, and no confirmation echo
/// — nobody is watching. Exactly one trailing newline is stripped so
/// `echo -n`, `echo` and a here-doc all mean the same secret; any other
/// whitespace is part of the plaintext.
pub fn read_secret_from_stdin() -> Result<String> {
    use std::io::Read;
    let mut secret = String::new();
    std::io::stdin()
        .read_to_string(&mut secret)
        .context("Failed to read secret from stdin")?;
    // DO NOT log `secret` — plaintext.
    strip_one_trailing_newline(&mut secret);
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret cannot be empty"));
    }
    Ok(secret)
}

/// Drop one trailing `\n` (and the `\r` of a `\r\n` pair) in place. One only:
/// a secret whose last byte is genuinely a newline is written with two.
fn strip_one_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

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
    use super::{mask_secret, strip_one_trailing_newline};

    #[test]
    fn strips_exactly_one_trailing_newline() {
        let case = |input: &str| {
            let mut s = input.to_string();
            strip_one_trailing_newline(&mut s);
            s
        };
        assert_eq!(case("secret"), "secret");
        assert_eq!(case("secret\n"), "secret");
        assert_eq!(case("secret\r\n"), "secret");
        assert_eq!(case("secret\n\n"), "secret\n");
        // Interior and leading whitespace is plaintext, not framing.
        assert_eq!(case("two\nlines\n"), "two\nlines");
        assert_eq!(case(" pad \n"), " pad ");
        assert_eq!(case("\n"), "");
    }

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
