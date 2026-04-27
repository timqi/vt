//! Cross-platform vt client.
//!
//! Talks to a local `vt ssh agent` over the SSH-agent Unix socket using the
//! `encrypt@vt` / `decrypt@vt` / `auth@vt` extension messages. The wire
//! payload is encrypted with the auth cipher derived from `VT_AUTH`. No
//! keychain, no LocalAuthentication, no `ssh-key` — those all live on the
//! macOS server side.

use std::env;
use std::io::{self, Write};

use crate::core::crypto::{decode_auth_cipher_from_b64, AesGcmCrypto};
use crate::core::{
    client_decrypt_v2, client_encrypt_v2, AuthReq, AuthRes, CryptoResItem, DecryptInput,
    DecryptReq, DecryptResItem, EncryptItem, EncryptReq, EncryptResItem, SecretType, VtUrl,
};
use anyhow::{ensure, Context, Result};
use ssh_agent_lib::proto::{Extension, Unparsed};
use tracing::debug;
use zeroize::{Zeroize, Zeroizing};

pub struct VTClient {
    auth_token: String,
}

impl VTClient {
    pub fn new(auth_token: String) -> Self {
        VTClient { auth_token }
    }

    /// Try to send an extension request via the SSH agent socket.
    /// Returns Ok(Some(bytes)) on success, Ok(None) if socket not available, Err on auth/agent errors.
    #[cfg(unix)]
    fn try_agent_extension(auth_token: &str, name: &str, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        use std::os::unix::net::UnixStream;

        let socket_path = if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            std::path::PathBuf::from(sock)
        } else {
            let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
            home.join(".ssh").join("vt.sock")
        };

        let stream = match UnixStream::connect(&socket_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let auth_key = decode_auth_cipher_from_b64(auth_token)?;
        let auth_cipher = AesGcmCrypto::new(&auth_key)?;
        let encrypted_payload = auth_cipher.encrypt(payload)?;

        let ext = Extension {
            name: name.to_string(),
            details: Unparsed::from(encrypted_payload),
        };

        let mut client = ssh_agent_lib::blocking::Client::new(stream);
        let response = client.extension(ext).map_err(|e| anyhow::anyhow!("{}", e))?;

        match response {
            Some(resp) => {
                // The decrypted payload may carry DEK bytes (decrypt@vt) or
                // freshly-allocated DEKs (encrypt@vt). Wrap it so the buffer
                // is wiped on drop after callers have consumed/copied what
                // they need.
                let decrypted = auth_cipher.decrypt(resp.details.as_ref())?;
                Ok(Some(decrypted))
            }
            None => Err(anyhow::anyhow!("Agent returned empty extension response")),
        }
    }

    /// v2 envelope encrypt. Asks the agent to allocate one fresh
    /// `(salt, DEK)` pair per `EncryptItem` (no plaintext leaves this
    /// process), then locally AEAD-encrypts each plaintext under its DEK and
    /// formats the resulting `vt://{type}{b64(salt||ct)}` URL. DEKs are
    /// zeroized after use.
    pub async fn encrypt(&self, items: &[EncryptItem]) -> Result<Vec<CryptoResItem>> {
        #[cfg(unix)]
        {
            let req = EncryptReq {
                types: items.iter().map(|i| i.t).collect(),
            };
            let payload = serde_json::to_vec(&req)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "encrypt@vt", &payload)
            })
            .await??;
            let bytes = match result {
                Some(b) => b,
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent not available — set SSH_AUTH_SOCK or run `vt ssh agent`"
                    ))
                }
            };
            let mut allocs: Vec<EncryptResItem> = serde_json::from_slice(&bytes)?;
            ensure!(
                allocs.len() == items.len(),
                "agent returned {} (salt,DEK) pairs for {} items",
                allocs.len(),
                items.len()
            );
            let mut out = Vec::with_capacity(items.len());
            for (item, alloc) in items.iter().zip(allocs.iter_mut()) {
                if !alloc.err_message.is_empty() {
                    out.push(CryptoResItem {
                        result: String::new(),
                        err_message: alloc.err_message.clone(),
                    });
                    alloc.dek.zeroize();
                    continue;
                }
                let res = match client_encrypt_v2(
                    item.t,
                    &alloc.salt,
                    &alloc.dek,
                    item.plaintext.as_bytes(),
                ) {
                    Ok(url) => CryptoResItem {
                        result: url,
                        err_message: String::new(),
                    },
                    Err(e) => CryptoResItem {
                        result: String::new(),
                        err_message: e.to_string(),
                    },
                };
                alloc.dek.zeroize();
                out.push(res);
            }
            // Defense in depth: also zeroize the original wire buffer.
            let mut bytes = bytes;
            bytes.zeroize();
            Ok(out)
        }
        #[cfg(not(unix))]
        {
            let _ = items;
            Err(anyhow::anyhow!("vt encrypt requires Unix (SSH agent socket)"))
        }
    }

    /// v2 envelope decrypt. Each input `vt://...` URL is parsed locally; v2
    /// URLs send only their salt to the agent (which returns a per-record
    /// DEK after Touch ID), and the inner ciphertext is decrypted client-side
    /// here. Legacy URLs are forwarded as-is and the agent returns the
    /// finished plaintext / TOTP code (legacy behavior).
    pub async fn decrypt(
        &self,
        host: &str,
        command: &str,
        urls: &[String],
    ) -> Result<Vec<CryptoResItem>> {
        // Don't bother the user for an empty batch — the agent would still
        // prompt Touch ID for "0 items" otherwise.
        if urls.is_empty() {
            return Ok(Vec::new());
        }
        #[cfg(unix)]
        {
            // Parse URLs locally; track v2 inner_ct + type so we can finish
            // decryption client-side once the agent returns the DEK.
            enum Local {
                V2 {
                    t: SecretType,
                    salt: [u8; crate::core::SALT_LEN],
                    inner_ct: Vec<u8>,
                },
                Legacy,
                ParseErr(String),
            }
            let mut wire_items: Vec<DecryptInput> = Vec::with_capacity(urls.len());
            let mut locals: Vec<Local> = Vec::with_capacity(urls.len());
            for raw_url in urls {
                match VtUrl::parse(raw_url) {
                    Ok(VtUrl::V2 { t, salt, inner_ct }) => {
                        wire_items.push(DecryptInput::V2 { t, salt });
                        locals.push(Local::V2 { t, salt, inner_ct });
                    }
                    Ok(VtUrl::Legacy { .. }) => {
                        wire_items.push(DecryptInput::Legacy {
                            url: raw_url.clone(),
                        });
                        locals.push(Local::Legacy);
                    }
                    Err(e) => {
                        // Skip the wire roundtrip for unparseable items by
                        // pushing a Legacy placeholder we'll override on the
                        // way back. Actually simpler: still push to keep
                        // index alignment — agent will fail-parse, but better
                        // to fail locally and avoid the extension call only if
                        // *every* item is bad. Here we fail locally per-item.
                        wire_items.push(DecryptInput::Legacy {
                            url: raw_url.clone(),
                        });
                        locals.push(Local::ParseErr(e.to_string()));
                    }
                }
            }

            let wire = DecryptReq {
                host: host.to_string(),
                command: command.to_string(),
                items: wire_items,
            };
            let payload = serde_json::to_vec(&wire)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "decrypt@vt", &payload)
            })
            .await??;
            let bytes = match result {
                Some(b) => b,
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent not available — set SSH_AUTH_SOCK or run `vt ssh agent`"
                    ))
                }
            };
            let mut wire_results: Vec<DecryptResItem> = serde_json::from_slice(&bytes)?;
            ensure!(
                wire_results.len() == locals.len(),
                "agent returned {} results for {} items",
                wire_results.len(),
                locals.len()
            );

            let mut out = Vec::with_capacity(locals.len());
            for (local, wire_res) in locals.into_iter().zip(wire_results.iter_mut()) {
                let item = match (local, wire_res) {
                    (Local::ParseErr(e), _) => CryptoResItem {
                        result: String::new(),
                        err_message: e,
                    },
                    (Local::V2 { t, salt, inner_ct }, DecryptResItem::V2 { dek, err_message }) => {
                        if !err_message.is_empty() {
                            let msg = std::mem::take(err_message);
                            dek.zeroize();
                            CryptoResItem {
                                result: String::new(),
                                err_message: msg,
                            }
                        } else {
                            let dek_copy: Zeroizing<[u8; 32]> = Zeroizing::new(*dek);
                            dek.zeroize();
                            match client_decrypt_v2(t, &dek_copy, &salt, &inner_ct) {
                                Ok(pt) => CryptoResItem {
                                    result: pt,
                                    err_message: String::new(),
                                },
                                Err(e) => CryptoResItem {
                                    result: String::new(),
                                    err_message: e.to_string(),
                                },
                            }
                        }
                    }
                    (
                        Local::Legacy,
                        DecryptResItem::Legacy {
                            result,
                            err_message,
                        },
                    ) => CryptoResItem {
                        result: std::mem::take(result),
                        err_message: std::mem::take(err_message),
                    },
                    // Mismatched variants — agent returned the wrong shape for
                    // this index. Should not happen unless the agent and
                    // client disagree on protocol.
                    _ => CryptoResItem {
                        result: String::new(),
                        err_message: "agent returned mismatched response variant".to_string(),
                    },
                };
                out.push(item);
            }
            // Defense in depth: scrub the wire buffer too.
            let mut bytes = bytes;
            bytes.zeroize();
            Ok(out)
        }
        #[cfg(not(unix))]
        {
            let _ = req;
            Err(anyhow::anyhow!("vt decrypt requires Unix (SSH agent socket)"))
        }
    }

    pub async fn auth(&self, reason: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let req = AuthReq {
                host: get_hostname(),
                reason: reason.to_string(),
            };
            let payload = serde_json::to_vec(&req)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "auth@vt", &payload)
            })
            .await??;

            match result {
                Some(bytes) => {
                    let _res: AuthRes =
                        serde_json::from_slice(&bytes).context("Failed to parse auth response")?;
                    return Ok(());
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent not available — need agent forwarding or ~/.ssh/vt.sock"
                    ));
                }
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("vt auth requires Unix (SSH agent socket)"))
        }
    }
}

pub async fn create(vt_client: VTClient) -> Result<()> {
    print!("Enter secret type (raw/totp) [default: raw]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().is_empty() {
        input = "raw".to_string();
    }
    debug!("User input for secret type: '{}'", input);
    let secret_type = SecretType::from_str(&input.trim().to_lowercase());
    if secret_type == SecretType::UNKNOWN {
        return Err(anyhow::anyhow!("Invalid secret type: {}", input));
    }

    let secret = crate::tty::prompt_input_password("Enter secret: ", "Secret entered: ")?;
    debug!("User input for secret: '{}'", secret);

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
    println!("Created item: {}", res[0].result);
    Ok(())
}

pub fn get_hostname() -> String {
    hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string()
}

pub async fn auth(vt_client: VTClient, reason: &str) -> Result<()> {
    vt_client.auth(reason).await
}

fn sanitize_prompt_field(s: &str, max_chars: usize) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() > max_chars {
        let truncated: String = cleaned.chars().take(max_chars).collect();
        format!("{}...", truncated)
    } else {
        cleaned
    }
}

pub async fn read(vt_client: VTClient, vt: String, reason: Option<&str>) -> Result<()> {
    let mut command = "[read]".to_string();
    if let Some(r) = reason {
        command.push_str(" reason: ");
        command.push_str(&sanitize_prompt_field(r, 200));
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
    print!("{}", res[0].result);
    Ok(())
}

async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
    command: String,
) -> Result<Vec<String>> {
    let mut encrypted_vec = Vec::<String>::new();
    // Extract `vt://...` patterns. Matches both v2 (`vt://0...`) and legacy
    // (`vt://mac/0...`) shapes; the optional `mac/` segment lets new and old
    // URLs coexist during migration. Body chars are base64url-no-pad.
    let vt_pattern = regex::Regex::new(r"vt://(?:mac/)?[A-Za-z0-9_-]+").unwrap();
    for item in &original_str_vec {
        for vt_match in vt_pattern.find_iter(item) {
            debug!("Found encrypted item: {}", vt_match.as_str());
            encrypted_vec.push(vt_match.as_str().to_string());
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

    // Create a mapping from encrypted vault items to decrypted values
    let mut secret_map = std::collections::HashMap::new();
    for (i, encrypted) in encrypted_vec.iter().enumerate() {
        if i < decrypted_vec.len() {
            secret_map.insert(encrypted.clone(), decrypted_vec[i].clone());
        }
    }
    debug!("secret_map: {:?}", secret_map);

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

pub async fn inject(
    vt_client: VTClient,
    replace_file: Option<String>,
    input_file: Option<String>,
    output_file: Option<String>,
    timeout: u32,
    reason: Option<&str>,
    mut args: Vec<String>,
) -> Result<()> {
    if replace_file.is_some() {
        if input_file.is_some() || output_file.is_some() {
            return Err(anyhow::anyhow!(
                "Cannot specify both replace file and input file or output file"
            ));
        }
    }

    let raw_command = args.join(" ");
    debug!("Original command: {}", raw_command);
    let mut original_command = String::from("[inject]");
    if let Some(p) = replace_file.as_ref() {
        original_command.push_str(" -r ");
        original_command.push_str(&sanitize_prompt_field(p, 100));
    }
    if let Some(p) = input_file.as_ref() {
        original_command.push_str(" -i ");
        original_command.push_str(&sanitize_prompt_field(p, 100));
    }
    if let Some(p) = output_file.as_ref() {
        original_command.push_str(" -o ");
        original_command.push_str(&sanitize_prompt_field(p, 100));
    }
    if raw_command.is_empty() {
        original_command.push_str(" [no shell command, output to stdout]");
    } else {
        let normalized = regex::Regex::new(r"\s+")
            .unwrap()
            .replace_all(&raw_command, " ")
            .to_string();
        let sanitized = regex::Regex::new(r"vt://(?:mac/)?[A-Za-z0-9_-]+")
            .unwrap()
            .replace_all(&normalized, "vt://***")
            .to_string();
        const MAX_CMD_LEN: usize = 60;
        let truncated = if sanitized.chars().count() > MAX_CMD_LEN {
            let s: String = sanitized.chars().take(MAX_CMD_LEN).collect();
            format!("{}...", s)
        } else {
            sanitized
        };
        original_command.push_str(" cmd: ");
        original_command.push_str(&truncated);
    }
    if let Some(r) = reason {
        original_command.push_str(" reason: ");
        original_command.push_str(&sanitize_prompt_field(r, 200));
    }

    let input_file_content = match replace_file.as_ref().or(input_file.as_ref()) {
        Some(file) => {
            debug!("Reading file: {}", file);
            std::fs::read_to_string(file)
                .with_context(|| format!("Failed to read file: {}", file))?
        }
        None => String::new(),
    };
    args.push(input_file_content);

    // Scan env vars locally for vt:// patterns — only those values enter the
    // decrypt pipeline. Env var names and non-vt values never leave this process.
    let vt_pattern = regex::Regex::new(r"vt://(?:mac/)?[A-Za-z0-9_-]+").unwrap();
    let env_vt_vars: Vec<(String, String)> = env::vars()
        .filter(|(_, v)| vt_pattern.is_match(v))
        .collect();
    for (_, value) in &env_vt_vars {
        args.push(value.clone());
    }

    let mut decrypted_args = decrypt_from_multi_str(vt_client, args, original_command).await?;

    // Pop decrypted env var values (in reverse push order) and set only those.
    for (key, _) in env_vt_vars.iter().rev() {
        let decrypted_value = decrypted_args.pop().unwrap();
        env::set_var(key, decrypted_value);
    }

    let output_file_content = decrypted_args.pop().unwrap();

    // For `--replace-file` and `--output-file`, write the plaintext safely:
    //   - open the original with `O_NOFOLLOW` so we refuse symlinks;
    //   - create backup and temp files with `O_CREAT|O_EXCL|O_NOFOLLOW` and
    //     mode copied from the original (or 0600 for new outputs), so a
    //     squatted sibling can't be opened and the file is not world-readable;
    //   - randomize backup/temp names so the target isn't predictable between
    //     the write and the eventual restore;
    //   - write the plaintext to a sibling temp file and atomically rename it
    //     over the original, eliminating the mid-write symlink race.
    // The backup path is then passed to the cleanup child, which renames it
    // back over the original after the timeout.
    let backup_path: Option<std::path::PathBuf> = if let Some(replace_file_path) = &replace_file {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let orig_path = std::path::Path::new(replace_file_path);
        let dir = orig_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let file_name = orig_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid replace file path: {}", replace_file_path))?
            .to_string_lossy()
            .into_owned();

        let mut src = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(replace_file_path)
            .with_context(|| {
                format!(
                    "Failed to open replace file (refuses symlinks): {}",
                    replace_file_path
                )
            })?;
        let meta = src
            .metadata()
            .with_context(|| format!("Failed to stat: {}", replace_file_path))?;
        if !meta.is_file() {
            return Err(anyhow::anyhow!(
                "Refusing to replace non-regular file: {}",
                replace_file_path
            ));
        }
        let orig_mode = meta.mode() & 0o7777;

        let mut rnd = [0u8; 8];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut rnd);
        }
        let suffix: String = rnd.iter().map(|b| format!("{:02x}", b)).collect();
        let backup_path = dir.join(format!(".{}.vt-backup-{}", file_name, suffix));
        let tmp_path = dir.join(format!(".{}.vt-tmp-{}", file_name, suffix));

        {
            let mut backup_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(orig_mode)
                .open(&backup_path)
                .with_context(|| {
                    format!("Failed to create backup file: {}", backup_path.display())
                })?;
            std::io::copy(&mut src, &mut backup_file).with_context(|| {
                format!(
                    "Failed to copy content to backup: {}",
                    backup_path.display()
                )
            })?;
            backup_file.sync_all().ok();
        }
        drop(src);
        debug!("Created backup at: {}", backup_path.display());

        {
            let mut tmp_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(orig_mode)
                .open(&tmp_path)
                .with_context(|| format!("Failed to create temp file: {}", tmp_path.display()))?;
            tmp_file
                .write_all(output_file_content.as_bytes())
                .with_context(|| format!("Failed to write temp file: {}", tmp_path.display()))?;
            tmp_file.sync_all().ok();
        }
        std::fs::rename(&tmp_path, replace_file_path).with_context(|| {
            format!("Failed to atomically replace file: {}", replace_file_path)
        })?;
        debug!("Content written to replace file: {}", replace_file_path);

        Some(backup_path)
    } else if let Some(output_file_path) = &output_file {
        use std::os::unix::fs::OpenOptionsExt;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(output_file_path)
            .with_context(|| {
                format!(
                    "Failed to create output file (refuses existing/symlink): {}",
                    output_file_path
                )
            })?;
        out.write_all(output_file_content.as_bytes())
            .with_context(|| format!("Failed to write output file: {}", output_file_path))?;
        out.sync_all().ok();
        debug!("Content written to output file: {}", output_file_path);
        None
    } else {
        print!("{}", output_file_content);
        None
    };

    // Restore the randomized backup over the original (replace mode) or
    // delete the output file. Used by both the cleanup child after the
    // timeout and the parent on exec failure.
    let restore_backup = |replace_file_path: Option<&String>,
                          output_file_path: Option<&String>,
                          backup_path: Option<&std::path::PathBuf>| {
        if let (Some(replace_file_path), Some(backup_path)) = (replace_file_path, backup_path) {
            if let Err(e) = std::fs::rename(backup_path, replace_file_path) {
                eprintln!("Failed to restore backup file: {}", e);
            } else {
                debug!("Restored backup file: {}", replace_file_path);
            }
        } else if let Some(output_file_path) = output_file_path {
            if let Err(e) = std::fs::remove_file(output_file_path) {
                eprintln!("Failed to delete output file: {}", e);
            } else {
                debug!("Deleted output file: {}", output_file_path);
            }
        }
    };

    let cleanup_pid = if timeout > 0 && (output_file.is_some() || replace_file.is_some()) {
        // Fork the process to handle file deletion in the background.
        // This is `unsafe` because it can violate Rust's memory safety guarantees,
        // especially in a multi-threaded context. However, for our simple case
        // where the child process only sleeps and deletes a file, it's acceptable.
        let pid = unsafe { libc::fork() };

        if pid > 0 {
            // Parent process: Continue to the exec call.
            debug!("Spawned cleanup process with PID: {}", pid);
            Some(pid)
        } else if pid == 0 {
            // Child process: Sleep, then restore backup or delete output file, and exit.
            // Using std::thread::sleep instead of tokio::time::sleep is safer after a fork.
            std::thread::sleep(std::time::Duration::from_secs(timeout as u64));

            if let (Some(replace_file_path), Some(backup_path)) =
                (replace_file.as_ref(), backup_path.as_ref())
            {
                if let Err(e) = std::fs::rename(backup_path, replace_file_path) {
                    eprintln!("Child process failed to restore backup file: {}", e);
                }
            } else if let Some(output_file_path) = output_file.as_ref() {
                if let Err(e) = std::fs::remove_file(output_file_path) {
                    eprintln!("Child process failed to delete output file: {}", e);
                }
            }
            // The child's work is done, it must exit.
            std::process::exit(0);
        } else {
            // Fork failed.
            return Err(anyhow::anyhow!(
                "Failed to fork cleanup process: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else {
        None
    };

    if decrypted_args.is_empty() {
        debug!("No command to execute, exiting.");
        return Ok(());
    }

    // Execute the command with decrypted arguments
    let command = &decrypted_args[0];
    let args = &decrypted_args[1..];

    debug!("Executing command: {} with args: {:?}", command, args);

    // If exec() fails, we need to immediately restore the backup and kill the cleanup child
    // exec() never returns if successful (it replaces the process), so if we reach the code below,
    // it means exec() failed
    let err = exec::Command::new(command).args(args).exec();

    // If we reach here, exec() failed - immediately restore backup and kill cleanup child
    if let Some(cleanup_pid) = cleanup_pid {
        // Kill the cleanup child process immediately since exec failed
        unsafe {
            libc::kill(cleanup_pid, libc::SIGTERM);
        }
        // Wait for the child to exit to avoid zombie processes
        let mut status = 0;
        unsafe {
            libc::waitpid(cleanup_pid, &mut status, 0);
        }
    }

    // Immediately restore the backup since exec failed
    restore_backup(
        replace_file.as_ref(),
        output_file.as_ref(),
        backup_path.as_ref(),
    );

    Err(anyhow::anyhow!("Failed to execute command: {}", err))
}
