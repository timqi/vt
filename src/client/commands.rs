//! `vt create` / `read` / `auth` / `run` / `rewrap` — the top-level command
//! entry points `main.rs` dispatches to, plus the legacy-URL rewrap helpers
//! and the shared multi-string decrypt used by `vt inject`.

use std::io::{self, IsTerminal, Write};

use super::{get_hostname, VTClient};
use crate::core::{
    has_vt_url, iter_vt_urls, sanitize_for_display, CryptoResItem, EncryptItem, SecretType,
};
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
        .encrypt(&[EncryptItem {
            plaintext: secret.to_string(),
            t: secret_type,
        }])
        .await?;
    if !res[0].err_message.is_empty() {
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
    let res = vt_client.decrypt(&get_hostname(), &command, &[vt]).await?;
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
        let (text, _) = read_rewrap_file(f)?;
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
        .map(|u| match u.strip_prefix("vt://mac/1") {
            Some(rest) => {
                let mut s = String::with_capacity(u.len());
                s.push_str("vt://mac/0");
                s.push_str(rest);
                s
            }
            None => u.clone(),
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
        let (text, mode) = read_rewrap_file(f)?;
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
        write_rewrapped_file(f, text.as_bytes(), new_text.as_bytes(), mode, backup)?;
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

/// Read content and mode through the same no-follow descriptor. Rewrap must
/// not replace a private config using the process's default creation mode.
fn read_rewrap_file(path: &std::path::Path) -> Result<(String, u32)> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Failed to open (refuses symlinks): {}", path.display()))?;
    let md = f.metadata()?;
    ensure!(md.is_file(), "Not a regular file: {}", path.display());
    let mut text = String::new();
    f.read_to_string(&mut text)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    Ok((text, md.mode() & 0o7777))
}

fn write_new_private_file(path: &std::path::Path, data: &[u8]) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Failed to create exclusive sidecar: {}", path.display()))?;
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(e).with_context(|| format!("Failed to write sidecar: {}", path.display()));
    }
    Ok(f)
}

fn write_rewrapped_file(
    target: &std::path::Path,
    original: &[u8],
    replacement: &[u8],
    mode: u32,
    backup: bool,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut tmp_path = target.as_os_str().to_os_string();
    tmp_path.push(".vt-rewrap-tmp");
    let tmp_path = std::path::Path::new(&tmp_path);
    let tmp = write_new_private_file(tmp_path, replacement)?;
    let result = (|| -> Result<()> {
        if backup {
            let mut backup_path = target.as_os_str().to_os_string();
            backup_path.push(".vt-rewrap-backup");
            write_new_private_file(std::path::Path::new(&backup_path), original)?;
        }
        // fchmod after filling defeats umask without a world-readable creation
        // window. Backups remain private: the config can contain other secrets.
        tmp.set_permissions(std::fs::Permissions::from_mode(mode))?;
        tmp.sync_all()?;
        std::fs::rename(tmp_path, target)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp_path);
    }
    result.with_context(|| format!("Failed to atomically replace: {}", target.display()))
}

pub(super) async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
    command: String,
) -> Result<Vec<String>> {
    let plan = SubstitutionPlan::new(original_str_vec);
    let res = vt_client
        .decrypt(&get_hostname(), &command, &plan.encrypted)
        .await?;
    plan.apply(res)
}

/// Only original URL spans can be substituted: plaintext containing another
/// record is a literal value, never a second request for substitution.
struct SubstitutionPlan {
    originals: Vec<String>,
    encrypted: Vec<String>,
    spans: Vec<Vec<(std::ops::Range<usize>, usize)>>,
}

impl SubstitutionPlan {
    fn new(originals: Vec<String>) -> Self {
        let mut encrypted = Vec::new();
        let mut indices = std::collections::HashMap::new();
        let mut spans = Vec::with_capacity(originals.len());
        for text in &originals {
            let mut matches = Vec::new();
            let mut cursor = 0;
            for url in iter_vt_urls(text) {
                let index = *indices.entry(url).or_insert_with(|| {
                    encrypted.push(url.to_string());
                    encrypted.len() - 1
                });
                // The scanner returns slices in encounter order. Searching
                // only the remaining suffix keeps total scanning linear.
                let start = cursor + text[cursor..].find(url).expect("URL came from this suffix");
                cursor = start + url.len();
                matches.push((start..cursor, index));
            }
            spans.push(matches);
        }
        Self {
            originals,
            encrypted,
            spans,
        }
    }

    fn apply(self, results: Vec<CryptoResItem>) -> Result<Vec<String>> {
        ensure!(
            results.len() == self.encrypted.len(),
            "Expected same number of items in response"
        );
        // Validate the WHOLE batch before returning any file/env/argv values.
        // A per-item wire error is never a replacement secret.
        let values = results
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                ensure!(
                    item.err_message.is_empty(),
                    "Failed to decrypt record {}: {}",
                    index + 1,
                    item.err_message
                );
                Ok(item.result)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(self
            .originals
            .into_iter()
            .zip(self.spans)
            .map(|(text, spans)| {
                if spans.is_empty() {
                    return text;
                }
                let mut out = String::with_capacity(text.len());
                let mut cursor = 0;
                for (range, index) in spans {
                    out.push_str(&text[cursor..range.start]);
                    out.push_str(&values[index]);
                    cursor = range.end;
                }
                out.push_str(&text[cursor..]);
                out
            })
            .collect())
    }
}

/// Whether an environment variable enters the decrypt pipeline: its value must
/// contain a `vt://` URL, and — when `--only-env` is given — its name must be in
/// that allow-list. This is the scoping that keeps `vt hook` from handing a
/// matched command every vt:// secret in the environment (confused-deputy guard).
pub(super) fn env_var_in_scope(key: &str, value: &str, only_env: Option<&[String]>) -> bool {
    has_vt_url(value) && only_env.is_none_or(|allow| allow.iter().any(|a| a == key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success(value: &str) -> CryptoResItem {
        CryptoResItem {
            result: value.into(),
            err_message: String::new(),
        }
    }

    #[test]
    fn substitution_deduplicates_records_in_encounter_order() {
        let plan = SubstitutionPlan::new(vec![
            "vt://0abc + vt://mac/1def + vt://0abc".into(),
            "prefix vt://0abcxyz suffix vt://0abc".into(),
        ]);
        assert_eq!(
            plan.encrypted,
            ["vt://0abc", "vt://mac/1def", "vt://0abcxyz"]
        );
        assert_eq!(
            plan.apply(vec![success("short"), success("code"), success("long")])
                .unwrap(),
            ["short + code + short", "prefix long suffix short"],
        );
    }

    #[test]
    fn substitution_never_rescans_inserted_plaintext() {
        let plan = SubstitutionPlan::new(vec!["前 vt://0abc / vt://0abcdef 后".into()]);
        assert_eq!(
            plan.apply(vec![success("literal vt://0abcdef"), success("value")])
                .unwrap(),
            ["前 literal vt://0abcdef / value 后"],
        );
    }

    #[test]
    fn substitution_rejects_entire_mixed_batch_without_plaintext_output() {
        let plan = SubstitutionPlan::new(vec!["vt://0abc vt://0def".into()]);
        let err = plan
            .apply(vec![
                success("decrypted-value"),
                CryptoResItem {
                    result: "discarded-value".into(),
                    err_message: "authentication failed".into(),
                },
            ])
            .unwrap_err();
        assert!(err.to_string().contains("record 2"));
        assert!(!err.to_string().contains("decrypted-value"));
        assert!(!err.to_string().contains("discarded-value"));
    }

    #[test]
    fn substitution_checks_response_count_and_preserves_plain_inputs() {
        assert!(SubstitutionPlan::new(vec!["vt://0abc".into()])
            .apply(vec![])
            .is_err());
        assert!(SubstitutionPlan::new(vec![])
            .apply(vec![success("unexpected")])
            .is_err());
        let originals = vec![String::new(), "no record, just vt://".into()];
        assert_eq!(
            SubstitutionPlan::new(originals.clone())
                .apply(vec![])
                .unwrap(),
            originals
        );
    }

    fn rewrap_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vt-rewrap-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rewrap_preserves_permissions_even_with_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        const CHILD: &str = "VT_TEST_REWRAP_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "client::commands::tests::rewrap_preserves_permissions_even_with_permissive_umask",
            ])
            .env(CHILD, "1");
            // umask is process-global: change it only in a self-exec'd child,
            // never in the multithreaded test runner.
            unsafe {
                cmd.pre_exec(|| {
                    libc::umask(0);
                    Ok(())
                });
            }
            assert!(cmd.status().unwrap().success());
            return;
        }
        for mode in [0o600, 0o640, 0o400] {
            let dir = rewrap_test_dir(&format!("mode-{mode}"));
            let target = dir.join("config");
            std::fs::write(&target, b"unrelated private field; legacy ciphertext").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            let (text, captured) = read_rewrap_file(&target).unwrap();
            write_rewrapped_file(&target, text.as_bytes(), b"rewrapped", captured, true).unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"rewrapped");
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
                mode
            );
            let backup = dir.join("config.vt-rewrap-backup");
            assert_eq!(std::fs::read(&backup).unwrap(), text.as_bytes());
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(!dir.join("config.vt-rewrap-tmp").exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn rewrap_refuses_existing_sidecars_without_overwriting_them() {
        for suffix in [".vt-rewrap-tmp", ".vt-rewrap-backup"] {
            for kind in ["regular", "symlink", "hardlink"] {
                let dir = rewrap_test_dir(&format!("existing-{suffix}-{kind}"));
                let target = dir.join("config");
                let other = dir.join("other");
                let sidecar = dir.join(format!("config{suffix}"));
                std::fs::write(&target, b"original").unwrap();
                std::fs::write(&other, b"unrelated").unwrap();
                match kind {
                    "regular" => std::fs::write(&sidecar, b"unrelated").unwrap(),
                    "symlink" => std::os::unix::fs::symlink(&other, &sidecar).unwrap(),
                    _ => std::fs::hard_link(&other, &sidecar).unwrap(),
                }
                assert!(
                    write_rewrapped_file(&target, b"original", b"replacement", 0o600, true)
                        .is_err()
                );
                assert_eq!(std::fs::read(&target).unwrap(), b"original");
                assert_eq!(std::fs::read(&other).unwrap(), b"unrelated");
                assert_eq!(std::fs::read(&sidecar).unwrap(), b"unrelated");
                if suffix.ends_with("backup") {
                    assert!(!dir.join("config.vt-rewrap-tmp").exists());
                }
                std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn rewrap_read_refuses_symlinks_and_nonregular_files() {
        let dir = rewrap_test_dir("read-nofollow");
        let target = dir.join("config");
        let link = dir.join("link");
        std::fs::write(&target, b"original").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_rewrap_file(&link).is_err());
        assert!(read_rewrap_file(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

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
