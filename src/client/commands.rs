//! `vt create` / `read` / `auth` / `run` / `rewrap` — the top-level command
//! entry points `main.rs` dispatches to, plus the legacy-URL rewrap helpers
//! and the shared multi-string decrypt used by `vt inject`.

use std::io::{self, IsTerminal, Write};

use super::{get_hostname, VTClient};
use crate::core::{has_vt_url, iter_vt_urls, sanitize_for_display, EncryptItem, SecretType};
use anyhow::{ensure, Context, Result};
use tracing::debug;

pub async fn create(vt_client: VTClient, type_arg: Option<&str>) -> Result<()> {
    // Non-interactive when stdin is not a terminal: the type comes from
    // `--type` (default raw) and stdin IS the plaintext. Interactively the two
    // prompts stay — the type on stdin, the value on /dev/tty without echo. A
    // piped run cannot answer the tty prompt at all, so a service rotating a
    // secret has no other way in, and the plaintext must never be an argv flag.
    let piped = !io::stdin().is_terminal();
    let secret_type = match type_arg {
        Some(t) => {
            let parsed = SecretType::from_str(&t.trim().to_lowercase());
            if parsed == SecretType::UNKNOWN {
                return Err(anyhow::anyhow!("Invalid secret type: {}", t));
            }
            parsed
        }
        None if piped => SecretType::RAW,
        None => {
            eprint!("Enter secret type (raw/totp) [default: raw]: ");
            io::stderr().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if input.trim().is_empty() {
                input = "raw".to_string();
            }
            debug!("User input for secret type: '{}'", input);
            let parsed = SecretType::from_str(&input.trim().to_lowercase());
            if parsed == SecretType::UNKNOWN {
                // The invalid answer is echoed back, so it must be the type the
                // user typed and never a plaintext read off a pipe.
                return Err(anyhow::anyhow!("Invalid secret type: {}", input.trim()));
            }
            parsed
        }
    };

    let secret = if piped {
        crate::tty::read_secret_from_stdin()?
    } else {
        crate::tty::prompt_input_password("Enter secret: ", "Secret entered: ")?
    };
    // DO NOT log `secret` — plaintext the user just typed.

    let res = vt_client
        .encrypt(&vec![EncryptItem {
            plaintext: secret.to_string(),
            t: secret_type,
        }])
        .await?;
    if res[0].err_message != "" {
        return Err(anyhow::anyhow!(
            "Failed to create secret: {}",
            res[0].err_message
        ));
    }
    println!("{}", res[0].result);
    Ok(())
}

pub async fn auth(vt_client: VTClient, reason: &str) -> Result<()> {
    vt_client.auth(reason).await
}

pub async fn run(vt_client: VTClient, argv: Vec<String>, reason: Option<&str>) -> Result<()> {
    vt_client.run(argv, reason).await
}

pub async fn read(vt_client: VTClient, vt: String, reason: Option<&str>) -> Result<()> {
    let mut command = "op: read".to_string();
    if let Some(r) = reason {
        command.push_str("\nreason: ");
        command.push_str(&sanitize_for_display(r, 200));
    }
    let res = vt_client
        .decrypt(&get_hostname(), &command, &[vt])
        .await?;
    ensure!(res.len() == 1, "Expected exactly one item in response");
    ensure!(
        res[0].err_message.is_empty(),
        "Error decrypting item: {}",
        res[0].err_message
    );
    // Interactive terminal: end the line so the shell prompt doesn't overwrite
    // or obscure a plaintext with no trailing newline (redrawing prompts like
    // starship/p10k clobber partial lines). Piped/redirected: byte-exact
    // output — `$(vt read …)` strips trailing newlines anyway, and
    // `vt read … > file` must not gain a byte.
    use std::io::Write;
    let mut stdout = io::stdout().lock();
    stdout.write_all(res[0].result.as_bytes())?;
    if stdout.is_terminal() && !res[0].result.ends_with('\n') {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

/// Find every legacy `vt://mac/{0|1|_}<body>` URL in `text` and return the
/// byte ranges. Body chars are `[A-Za-z0-9_-]` (base64url, no pad), matching
/// the Python migration script's `LEGACY_RE`.
fn find_legacy_urls(text: &str) -> Vec<(usize, usize)> {
    const PREFIX: &str = "vt://mac/";
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(PREFIX) {
        let start = search_from + rel;
        let type_idx = start + PREFIX.len();
        if type_idx >= bytes.len() {
            break;
        }
        let type_byte = bytes[type_idx];
        if !matches!(type_byte, b'0' | b'1' | b'_') {
            search_from = start + 1;
            continue;
        }
        let mut end = type_idx + 1;
        while end < bytes.len() {
            let c = bytes[end];
            let ok = c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
            if !ok {
                break;
            }
            end += 1;
        }
        if end > type_idx + 1 {
            out.push((start, end));
            search_from = end;
        } else {
            search_from = start + 1;
        }
    }
    out
}

fn legacy_secret_type(url: &str) -> SecretType {
    // Type byte sits at index len("vt://mac/") = 9.
    match url.as_bytes().get(9).copied() {
        Some(b'1') => SecretType::TOTP,
        _ => SecretType::RAW,
    }
}

/// Re-encrypt every legacy `vt://mac/...` URL found in the given files as the
/// v2 envelope format, and rewrite each file in place.
///
/// Strategy mirrors the old `migrate-vt-urls.py`:
///  - Decrypt all URLs in a single agent call (one Touch ID for the batch).
///    For TOTP (type=1) URLs we momentarily flip the type byte to 0 in the
///    request — the legacy agent path then returns the raw base32 seed
///    instead of generating a 6-digit code. This trick relies on legacy
///    ciphertexts having no AAD; v2 closes that hole, and
///    `vt ssh agent --no-legacy-decrypt` retires this path.
///  - Re-encrypt each plaintext (no Touch ID; `encrypt@vt` is unauthenticated
///    by design) and capture the new `vt://0...` / `vt://1...` URL.
///  - Rewrite each input file atomically via `rename(2)`. With `--backup`,
///    leave a `<file>.vt-rewrap-backup` copy next to each modified file.
pub async fn rewrap(
    vt_client: VTClient,
    files: Vec<std::path::PathBuf>,
    no_dry_run: bool,
    backup: bool,
) -> Result<()> {
    use std::collections::HashSet;

    let (files, missing): (Vec<_>, Vec<_>) = files.into_iter().partition(|p| p.is_file());
    for p in &missing {
        eprintln!("warning: not a file, skipping: {}", p.display());
    }

    // Discover unique URLs in encounter order across files.
    let mut pairs: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for f in &files {
        let text = std::fs::read_to_string(f)
            .with_context(|| format!("Failed to read file: {}", f.display()))?;
        for (s, e) in find_legacy_urls(&text) {
            let url = text[s..e].to_string();
            if seen.insert(url.clone()) {
                pairs.push((f.clone(), url));
            }
        }
    }

    if pairs.is_empty() {
        println!("no legacy vt://mac/ URLs found");
        return Ok(());
    }

    let urls: Vec<String> = pairs.iter().map(|(_, u)| u.clone()).collect();

    let (mut n_raw, mut n_totp) = (0usize, 0usize);
    for u in &urls {
        match legacy_secret_type(u) {
            SecretType::TOTP => n_totp += 1,
            _ => n_raw += 1,
        }
    }
    let mut summary_parts: Vec<String> = Vec::new();
    if n_raw > 0 {
        summary_parts.push(format!("{} raw", n_raw));
    }
    if n_totp > 0 {
        summary_parts.push(format!("{} totp", n_totp));
    }
    println!(
        "discovered {} unique legacy URL(s) across {} file(s): {}",
        urls.len(),
        files.len(),
        summary_parts.join(", ")
    );

    if !no_dry_run {
        for (f, u) in &pairs {
            let t = match legacy_secret_type(u) {
                SecretType::TOTP => "totp",
                _ => "raw",
            };
            println!("  {}: {}  ({})", f.display(), u, t);
        }
        println!();
        println!("[dry-run] no changes made. Re-run with --no-dry-run to apply.");
        return Ok(());
    }

    // TOTP type-flip trick: flip `vt://mac/1...` -> `vt://mac/0...` so the
    // legacy agent emits the raw base32 seed rather than a generated code.
    let flipped: Vec<String> = urls
        .iter()
        .map(|u| {
            if u.starts_with("vt://mac/1") {
                let mut s = String::with_capacity(u.len());
                s.push_str("vt://mac/0");
                s.push_str(&u["vt://mac/1".len()..]);
                s
            } else {
                u.clone()
            }
        })
        .collect();

    println!("requesting Touch ID for batch decrypt of all URLs...");
    let dec = vt_client
        .decrypt(&get_hostname(), "[rewrap]", &flipped)
        .await?;
    ensure!(
        dec.len() == urls.len(),
        "agent returned {} items for {} URLs",
        dec.len(),
        urls.len()
    );
    for (i, item) in dec.iter().enumerate() {
        ensure!(
            item.err_message.is_empty(),
            "decrypt failed for {}: {}",
            urls[i],
            item.err_message
        );
    }

    println!(
        "re-encrypting {} secret(s) as v2 (no Touch ID needed)...",
        urls.len()
    );
    let items: Vec<EncryptItem> = urls
        .iter()
        .zip(dec.iter())
        .map(|(u, plain)| EncryptItem {
            plaintext: plain.result.clone(),
            t: legacy_secret_type(u),
        })
        .collect();
    let enc = vt_client.encrypt(&items).await?;
    ensure!(
        enc.len() == urls.len(),
        "encrypt returned {} items for {} URLs",
        enc.len(),
        urls.len()
    );

    let mut url_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(urls.len());
    for (i, item) in enc.iter().enumerate() {
        ensure!(
            item.err_message.is_empty(),
            "encrypt failed for {}: {}",
            urls[i],
            item.err_message
        );
        ensure!(
            item.result.starts_with("vt://") && !item.result.starts_with("vt://mac/"),
            "vt encrypt did not return a v2 URL: {}",
            item.result
        );
        let st_label = match items[i].t {
            SecretType::TOTP => "totp",
            _ => "raw",
        };
        let old_short: String = urls[i].chars().take(24).collect();
        let new_short: String = item.result.chars().take(24).collect();
        println!(
            "  [{}/{}] {}: {}... -> {}...",
            i + 1,
            urls.len(),
            st_label,
            old_short,
            new_short
        );
        url_map.insert(urls[i].clone(), item.result.clone());
    }

    let mut total: usize = 0;
    for f in &files {
        let text = std::fs::read_to_string(f)
            .with_context(|| format!("Failed to read file: {}", f.display()))?;
        let mut count: usize = 0;
        for old in url_map.keys() {
            count += text.matches(old.as_str()).count();
        }
        if count == 0 {
            continue;
        }
        let mut new_text = text.clone();
        for (old, new) in &url_map {
            new_text = new_text.replace(old.as_str(), new.as_str());
        }
        // Write sidecars with O_NOFOLLOW so a pre-planted symlink at the
        // backup/tmp path can't redirect the write to overwrite an arbitrary
        // target. create+truncate keeps rewrap re-runnable for a regular file.
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let nofollow_write = |path: &std::ffi::OsStr, data: &[u8]| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .with_context(|| {
                    format!("Failed to open (refuses symlinks): {}", std::path::Path::new(path).display())
                })?;
            file.write_all(data).with_context(|| {
                format!("Failed to write: {}", std::path::Path::new(path).display())
            })?;
            Ok(())
        };
        if backup {
            let mut backup_path = f.clone().into_os_string();
            backup_path.push(".vt-rewrap-backup");
            nofollow_write(&backup_path, text.as_bytes())?;
        }
        let mut tmp_path = f.clone().into_os_string();
        tmp_path.push(".vt-rewrap-tmp");
        nofollow_write(&tmp_path, new_text.as_bytes())?;
        std::fs::rename(&tmp_path, f).with_context(|| {
            format!("Failed to atomically replace: {}", f.display())
        })?;
        if backup {
            println!(
                "  {}: {} substitution(s); backup at {}.vt-rewrap-backup",
                f.display(),
                count,
                f.display()
            );
        } else {
            println!("  {}: {} substitution(s)", f.display(), count);
        }
        total += count;
    }

    println!();
    println!(
        "done. {} substitution(s) across {} file(s).",
        total,
        files.len()
    );
    let tail = if backup {
        "verify the result, then delete .vt-rewrap-backup files and consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    } else {
        "verify the result, then consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    };
    println!("{}", tail);
    Ok(())
}

pub(super) async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
    command: String,
) -> Result<Vec<String>> {
    let mut encrypted_vec = Vec::<String>::new();
    // Extract `vt://...` patterns. Matches both v2 (`vt://0...`) and legacy
    // (`vt://mac/0...`) shapes; the optional `mac/` segment lets new and old
    // URLs coexist during migration. Body chars are base64url-no-pad.
    for item in &original_str_vec {
        for url in iter_vt_urls(item) {
            debug!("Found encrypted item: {}", url);
            encrypted_vec.push(url.to_string());
        }
    }

    let res = vt_client
        .decrypt(&get_hostname(), &command, &encrypted_vec)
        .await?;
    ensure!(
        res.len() == encrypted_vec.len(),
        "Expected same number of items in response"
    );
    let decrypted_vec: Vec<String> = res
        .into_iter()
        .filter_map(|item| {
            if item.err_message.is_empty() {
                Some(item.result)
            } else {
                Some(item.err_message)
            }
        })
        .collect();

    // Create a mapping from encrypted vault items to decrypted values.
    // DO NOT log `secret_map` — values are decrypted plaintext.
    let mut secret_map = std::collections::HashMap::new();
    for (i, encrypted) in encrypted_vec.iter().enumerate() {
        if i < decrypted_vec.len() {
            secret_map.insert(encrypted.clone(), decrypted_vec[i].clone());
        }
    }

    // Replace encrypted vault items with decrypted values in original strings
    let mut result_vec = Vec::new();
    for original_str in original_str_vec {
        let mut result_str = original_str.clone();
        for (encrypted_item, decrypted_value) in &secret_map {
            result_str = result_str.replace(encrypted_item, decrypted_value);
        }
        result_vec.push(result_str);
    }

    Ok(result_vec)
}

/// Whether an environment variable enters the decrypt pipeline: its value must
/// contain a `vt://` URL, and — when `--only-env` is given — its name must be in
/// that allow-list. This is the scoping that keeps `vt hook` from handing a
/// matched command every vt:// secret in the environment (confused-deputy guard).
pub(super) fn env_var_in_scope(key: &str, value: &str, only_env: Option<&[String]>) -> bool {
    has_vt_url(value) && only_env.map_or(true, |allow| allow.iter().any(|a| a == key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_env_scopes_decryption() {
        let v = "vt://0abc"; // a vt:// ciphertext value
        let plain = "ghp_plaintext";
        // No --only-env: every vt:// var is in scope; non-vt values never are.
        assert!(env_var_in_scope("GH_TOKEN", v, None));
        assert!(env_var_in_scope("ANYTHING", v, None));
        assert!(!env_var_in_scope("GH_TOKEN", plain, None));
        // With --only-env: only named vt:// vars are in scope (confused-deputy guard).
        let allow = [String::from("GH_TOKEN")];
        assert!(env_var_in_scope("GH_TOKEN", v, Some(&allow)));
        assert!(!env_var_in_scope("ANTHROPIC_API_KEY", v, Some(&allow))); // vt:// but not named → excluded
        assert!(!env_var_in_scope("GH_TOKEN", plain, Some(&allow))); // named but not vt:// → excluded
        // Empty allow-list excludes everything.
        assert!(!env_var_in_scope("GH_TOKEN", v, Some(&[])));
    }
}
