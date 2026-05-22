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
use crate::core::wire::{ErrKind, WIRE_VERSION};
use crate::core::{
    client_decrypt_v2, client_encrypt_v2, AuthReq, AuthRes, CryptoResItem, DecryptInput,
    DecryptReq, DecryptResItem, EncryptItem, EncryptReq, EncryptResItem, SecretType, VtUrl,
};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::value::RawValue;
use ssh_agent_lib::proto::{Extension, Unparsed};
use tracing::debug;
use zeroize::{Zeroize, Zeroizing};

/// Typed client error so `main.rs` can route stable exit codes.
///
/// `Agent(kind, detail)` carries a structured `ErrKind` parsed from the
/// agent's `ExtResponse::Err` envelope; the optional `detail` is the static
/// allow-listed string the agent attached. `Transport` covers everything
/// else (socket missing, IO error, parse failure of the envelope itself).
#[derive(Debug)]
pub enum VtClientError {
    Agent(ErrKind, Option<String>),
    Transport(anyhow::Error),
}

impl VtClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            VtClientError::Agent(k, _) => k.exit_code(),
            VtClientError::Transport(_) => 1,
        }
    }
}

impl std::fmt::Display for VtClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VtClientError::Agent(kind, detail) => {
                write!(f, "{}", kind.human_message())?;
                if let Some(d) = detail {
                    write!(f, " ({})", d)?;
                }
                Ok(())
            }
            VtClientError::Transport(e) => write!(f, "vt: {}", e),
        }
    }
}

impl std::error::Error for VtClientError {}

/// Wrap any error as `VtClientError::Transport` so `?`/`.map_err()` sites
/// stay terse. Use only on the IO/serialization paths that should NOT
/// surface as structured agent errors.
fn transport<E: Into<anyhow::Error>>(e: E) -> anyhow::Error {
    anyhow::Error::from(VtClientError::Transport(e.into()))
}

/// Parse a decrypted agent envelope. Returns the inner `data` JSON bytes on
/// success (still potentially containing DEKs — caller is responsible for
/// scrubbing); maps the `err` variant to `VtClientError::Agent` and version
/// mismatch to `ErrKind::ProtocolVersion`.
///
/// We do NOT reuse the `ExtResponse<T>` type from `core::wire` here, because
/// it relies on `#[serde(flatten)]` which is incompatible with
/// `Box<RawValue>` — flatten goes through serde's internal `Content` buffer
/// that doesn't preserve the raw JSON span `RawValue` requires. Instead we
/// deserialize the wire form directly into this flat struct and switch on
/// `status` manually. The on-the-wire shape is identical to what
/// `ExtResponse` produces (verified by the round-trip tests in
/// `core::wire::tests`).
#[derive(Deserialize)]
struct ParsedEnvelope<'a> {
    v: u16,
    status: String,
    /// Present iff `status == "ok"`. Captured as `&RawValue` so any
    /// DEK-bearing bytes inside are not re-allocated through
    /// `serde_json::Value`.
    #[serde(borrow, default)]
    data: Option<&'a RawValue>,
    /// Present iff `status == "err"`.
    #[serde(default)]
    kind: Option<ErrKind>,
    #[serde(default)]
    detail: Option<String>,
}

fn parse_envelope(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let env: ParsedEnvelope = serde_json::from_slice(bytes)
        .map_err(|e| transport(anyhow::anyhow!("failed to parse agent envelope: {}", e)))?;
    if env.v != WIRE_VERSION {
        // Different protocol versions: refuse even an "ok"-looking body.
        // The client and agent binaries must be from the same build.
        return Err(VtClientError::Agent(ErrKind::ProtocolVersion, None).into());
    }
    match env.status.as_str() {
        "ok" => {
            let raw = env.data.ok_or_else(|| {
                transport(anyhow::anyhow!(
                    "agent envelope status=ok but missing `data` field"
                ))
            })?;
            Ok(Zeroizing::new(raw.get().as_bytes().to_vec()))
        }
        "err" => {
            let kind = env.kind.ok_or_else(|| {
                transport(anyhow::anyhow!(
                    "agent envelope status=err but missing `kind` field"
                ))
            })?;
            Err(VtClientError::Agent(kind, env.detail).into())
        }
        other => Err(transport(anyhow::anyhow!(
            "agent envelope has unknown status `{}`",
            other
        ))),
    }
}

pub struct VTClient {
    auth_token: String,
}

impl VTClient {
    pub fn new(auth_token: String) -> Self {
        VTClient { auth_token }
    }

    /// Try to send an extension request via the SSH agent socket.
    ///
    /// On the success arm returns `Ok(Some(bytes))` where `bytes` is the
    /// already-decrypted inner `data` body (i.e. the JSON the agent's
    /// per-extension handler produced — `Vec<EncryptResItem>`,
    /// `Vec<DecryptResItem>`, or `AuthRes`).
    ///
    /// Returns `Ok(None)` if the socket is missing or refused (no agent
    /// running — callers map this to a user-visible message). Returns
    /// `Err(anyhow::Error)` that always carries a `VtClientError`:
    ///
    /// - `VtClientError::Agent(kind, detail)` when the agent emitted a
    ///   structured `ExtResponse::Err` envelope.
    /// - `VtClientError::Transport(_)` for SSH-wire failures, envelope parse
    ///   errors, version mismatch, or unstructured `AgentError::Failure`
    ///   (e.g. agent lock or wrong `VT_AUTH` — see docs/structured-errors.md
    ///   for why those stay unstructured).
    #[cfg(unix)]
    fn try_agent_extension(
        auth_token: &str,
        name: &str,
        payload: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
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
            Err(e) => return Err(transport(e)),
        };

        let auth_key = decode_auth_cipher_from_b64(auth_token).map_err(transport)?;
        let auth_cipher = AesGcmCrypto::new(&auth_key).map_err(transport)?;
        let encrypted_payload = auth_cipher.encrypt(payload).map_err(transport)?;

        let ext = Extension {
            name: name.to_string(),
            details: Unparsed::from(encrypted_payload),
        };

        let mut client = ssh_agent_lib::blocking::Client::new(stream);
        // SSH-wire `SSH_AGENT_FAILURE` lands here — the agent took the
        // unstructured path (agent lock, wrong VT_AUTH, internal error
        // before cipher derivation). We surface a generic error and let the
        // caller's CLI message suggest `ssh-add -X`.
        let response = client
            .extension(ext)
            .map_err(|e| transport(anyhow::anyhow!("{}", e)))?;

        match response {
            Some(resp) => {
                // The decrypted payload is the ExtResponse envelope. Wrap
                // in Zeroizing so any inner DEK bytes are wiped on drop
                // once we've extracted the `data` body.
                let envelope_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
                    auth_cipher.decrypt(resp.details.as_ref()).map_err(transport)?,
                );
                Ok(Some(parse_envelope(&envelope_bytes)?))
            }
            None => Err(transport(anyhow::anyhow!(
                "Agent returned empty extension response"
            ))),
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
            // `bytes` is `Zeroizing<Vec<u8>>` — wiped on drop at end of scope.
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
            // `bytes` is `Zeroizing<Vec<u8>>` — wiped on drop at end of scope.
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
///    leave a `<file>.vt-migrate-backup` copy next to each modified file.
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
        if backup {
            let mut backup_path = f.clone().into_os_string();
            backup_path.push(".vt-migrate-backup");
            std::fs::copy(f, &backup_path).with_context(|| {
                format!("Failed to write backup: {}", std::path::Path::new(&backup_path).display())
            })?;
        }
        let mut tmp_path = f.clone().into_os_string();
        tmp_path.push(".vt-migrate-tmp");
        std::fs::write(&tmp_path, &new_text).with_context(|| {
            format!("Failed to write temp: {}", std::path::Path::new(&tmp_path).display())
        })?;
        std::fs::rename(&tmp_path, f).with_context(|| {
            format!("Failed to atomically replace: {}", f.display())
        })?;
        if backup {
            println!(
                "  {}: {} substitution(s); backup at {}.vt-migrate-backup",
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
        "verify the result, then delete .vt-migrate-backup files and consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    } else {
        "verify the result, then consider restarting the agent with --no-legacy-decrypt to retire the legacy path."
    };
    println!("{}", tail);
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

    // Execute the command with decrypted arguments.
    // DO NOT log `command` / `args` — post-decryption command line contains
    // plaintext values substituted in for `vt://` URLs.
    let command = &decrypted_args[0];
    let args = &decrypted_args[1..];

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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::wire::wrap_ok_envelope;

    /// Reproduces the agent's `ErrEnvelope` serialization shape.
    fn fake_err_envelope(kind: &str, detail: Option<&str>) -> Vec<u8> {
        let detail_part = detail
            .map(|d| format!(r#","detail":"{}""#, d))
            .unwrap_or_default();
        format!(
            r#"{{"v":{},"status":"err","kind":"{}"{}}}"#,
            WIRE_VERSION, kind, detail_part
        )
        .into_bytes()
    }

    /// Regression test for the `#[serde(flatten)]` + `RawValue` incompatibility
    /// that produced `invalid type: newtype struct, expected any valid JSON
    /// value` on the first attempt. If someone ever switches `parse_envelope`
    /// back to `ExtResponse<Box<RawValue>>`, this test must fail.
    #[test]
    fn parse_envelope_ok_with_array_data() {
        let inner = br#"[{"V2":{"dek":[1,2,3,4,5,6,7,8],"err_message":""}}]"#;
        let envelope = wrap_ok_envelope(inner);
        let data = parse_envelope(&envelope).expect("envelope should parse");
        assert_eq!(&data[..], &inner[..]);
    }

    #[test]
    fn parse_envelope_ok_with_object_data() {
        let inner = br#"{"approved":true}"#;
        let envelope = wrap_ok_envelope(inner);
        let data = parse_envelope(&envelope).expect("envelope should parse");
        assert_eq!(&data[..], &inner[..]);
    }

    #[test]
    fn parse_envelope_err_auth_rejected_maps_to_exit_10() {
        let envelope = fake_err_envelope("auth_rejected", Some("authentication was declined"));
        let err = parse_envelope(&envelope).expect_err("should be Err");
        let vt_err = err
            .downcast_ref::<VtClientError>()
            .expect("must carry VtClientError");
        match vt_err {
            VtClientError::Agent(kind, detail) => {
                assert_eq!(*kind, ErrKind::AuthRejected);
                assert_eq!(kind.exit_code(), 10);
                assert_eq!(detail.as_deref(), Some("authentication was declined"));
            }
            _ => panic!("expected Agent variant, got {:?}", vt_err),
        }
    }

    #[test]
    fn parse_envelope_err_without_detail() {
        let envelope = fake_err_envelope("session_locked", None);
        let err = parse_envelope(&envelope).expect_err("should be Err");
        let vt_err = err.downcast_ref::<VtClientError>().unwrap();
        match vt_err {
            VtClientError::Agent(kind, detail) => {
                assert_eq!(*kind, ErrKind::SessionLocked);
                assert!(detail.is_none(), "detail must be optional");
            }
            _ => panic!("expected Agent variant"),
        }
    }

    #[test]
    fn parse_envelope_version_mismatch() {
        // Old client, new agent with bumped version.
        let envelope = br#"{"v":99,"status":"ok","data":[1,2,3]}"#;
        let err = parse_envelope(envelope).expect_err("must reject mismatched v");
        let vt_err = err.downcast_ref::<VtClientError>().unwrap();
        match vt_err {
            VtClientError::Agent(ErrKind::ProtocolVersion, _) => {}
            _ => panic!("expected ProtocolVersion, got {:?}", vt_err),
        }
    }

    #[test]
    fn parse_envelope_unknown_future_kind_falls_back_to_unknown() {
        // Future agent emits a kind this client doesn't recognize. Per
        // wire-format policy (#[serde(other)] on ErrKind), this must become
        // ErrKind::Unknown (exit 1) — never a parse error.
        let envelope = fake_err_envelope("future_kind", Some("whatever"));
        let err = parse_envelope(&envelope).expect_err("should be Err");
        let vt_err = err.downcast_ref::<VtClientError>().unwrap();
        match vt_err {
            VtClientError::Agent(kind, _) => {
                assert_eq!(*kind, ErrKind::Unknown);
                assert_eq!(kind.exit_code(), 1);
            }
            _ => panic!("expected Agent"),
        }
    }

    #[test]
    fn parse_envelope_garbage_is_transport_error() {
        let err = parse_envelope(b"not json at all").expect_err("must fail");
        let vt_err = err.downcast_ref::<VtClientError>().unwrap();
        assert!(
            matches!(vt_err, VtClientError::Transport(_)),
            "garbage must surface as Transport, got {:?}",
            vt_err
        );
    }

    #[test]
    fn vt_client_error_display_appends_detail_when_present() {
        let e = VtClientError::Agent(
            ErrKind::AuthRejected,
            Some("authentication was declined".into()),
        );
        assert_eq!(
            e.to_string(),
            "vt: authentication rejected (authentication was declined)"
        );

        let e2 = VtClientError::Agent(ErrKind::SessionLocked, None);
        assert_eq!(e2.to_string(), "vt: screen is locked");
    }
}
