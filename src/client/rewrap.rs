//! Legacy URL migration only; unrelated to the Keychain wrap_v migration.

use std::io::Write;

use super::VTClient;
use crate::caller_meta::get_hostname;
use crate::core::{EncryptItem, SecretType};
use anyhow::{ensure, Context, Result};

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

/// Legacy ciphertext has no type AAD: migration can request the raw TOTP seed.
/// This must never be applied to v2 records, whose type is authenticated.
fn legacy_raw_url(url: &str) -> String {
    match url.strip_prefix("vt://mac/1") {
        Some(rest) => {
            let mut raw = String::with_capacity(url.len());
            raw.push_str("vt://mac/0");
            raw.push_str(rest);
            raw
        }
        None => url.to_string(),
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
    let flipped: Vec<String> = urls.iter().map(|u| legacy_raw_url(u)).collect();

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
    let dec = dec
        .into_iter()
        .enumerate()
        .map(|(i, item)| item.map_err(|e| anyhow::anyhow!("decrypt failed for {}: {}", urls[i], e)))
        .collect::<Result<Vec<_>>>()?;

    println!(
        "re-encrypting {} secret(s) as v2 (no Touch ID needed)...",
        urls.len()
    );
    let items: Vec<EncryptItem> = urls
        .iter()
        .zip(dec.iter())
        .map(|(u, plain)| EncryptItem {
            plaintext: plain.clone(),
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
    for (i, item) in enc.into_iter().enumerate() {
        let value = item.map_err(|e| anyhow::anyhow!("encrypt failed for {}: {}", urls[i], e))?;
        ensure!(
            value.starts_with("vt://") && !value.starts_with("vt://mac/"),
            "vt encrypt did not return a v2 URL: {}",
            value
        );
        let st_label = match items[i].t {
            SecretType::TOTP => "totp",
            _ => "raw",
        };
        let old_short: String = urls[i].chars().take(24).collect();
        let new_short: String = value.chars().take(24).collect();
        println!(
            "  [{}/{}] {}: {}... -> {}...",
            i + 1,
            urls.len(),
            st_label,
            old_short,
            new_short
        );
        url_map.insert(urls[i].clone(), value);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrap_scanner_keeps_legacy_only_spans_and_types() {
        let text = "prefix vt://0abc vt://mac/0YWJj,vt://mac/1ZGVm vt://mac/_Z2hp vt://mac/9abc vt://mac/0 suffix";
        let urls = find_legacy_urls(text)
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect::<Vec<_>>();
        assert_eq!(urls, ["vt://mac/0YWJj", "vt://mac/1ZGVm", "vt://mac/_Z2hp"]);
        assert_eq!(
            urls.iter()
                .map(|url| legacy_secret_type(url))
                .collect::<Vec<_>>(),
            [SecretType::RAW, SecretType::TOTP, SecretType::RAW]
        );
        for url in ["vt://0abc", "vt://1abc", "vt://mac/0YWJj", "vt://mac/_Z2hp"] {
            assert_eq!(legacy_raw_url(url), url);
        }
    }

    #[test]
    fn rewrap_totp_type_flip_recovers_seed_for_v2_encryption() {
        use crate::core::{
            client_decrypt_v2, client_encrypt_v2, crypto::AesGcmCrypto, legacy_decrypt, VtUrl,
        };
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

        let cipher = AesGcmCrypto::new(&[7; 32]).unwrap();
        let seed = "JBSWY3DPEHPK3PXP";
        let legacy = format!(
            "vt://mac/1{}",
            BASE64_URL_SAFE_NO_PAD.encode(cipher.encrypt(seed.as_bytes()).unwrap())
        );
        let normal = legacy_decrypt(&cipher, &legacy);
        assert!(normal.err_message.is_empty());
        assert_eq!(normal.result.len(), 6);
        assert!(normal.result.bytes().all(|b| b.is_ascii_digit()));
        let raw = legacy_decrypt(&cipher, &legacy_raw_url(&legacy));
        assert!(raw.err_message.is_empty());
        assert_eq!(raw.result, seed);
        let v2 = client_encrypt_v2(
            legacy_secret_type(&legacy),
            &[8; 16],
            &[9; 32],
            raw.result.as_bytes(),
        )
        .unwrap();
        let VtUrl::V2 { t, salt, inner_ct } = VtUrl::parse(&v2).unwrap() else {
            panic!("expected v2 migration result");
        };
        assert_eq!(t, SecretType::TOTP);
        let code = client_decrypt_v2(t, &[9; 32], &salt, &inner_ct).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert!(client_decrypt_v2(SecretType::RAW, &[9; 32], &salt, &inner_ct).is_err());
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
                "client::rewrap::tests::rewrap_preserves_permissions_even_with_permissive_umask",
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
}
