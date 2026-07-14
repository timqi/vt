//! Cross-platform vt client.
//!
//! Primary path: SSH agent via `$SSH_AUTH_SOCK` or `~/.ssh/vt.sock`.
//! Fallback path (Linux / macOS without agent): CF ceremony via
//! VT_PASSKEY_URL + VT_PASSKEY_TOKEN env vars — POST /api/challenge + WS /api/dek.

use std::env;
use std::io::{self, Write};

use crate::cf;
use crate::core::crypto::{decode_auth_cipher_from_b64, AesGcmCrypto};
use crate::core::wire::{ErrKind, WIRE_VERSION};
use crate::core::{
    client_decrypt_v2, client_encrypt_v2, collapse_whitespace, has_vt_url, iter_vt_urls,
    redact_vt_urls, sanitize_for_display, AuthReq, AuthRes, CryptoResItem, DecryptInput,
    DecryptReq, DecryptResItem, EncryptItem, EncryptReq, EncryptResItem, RunReq, RunRes,
    SecretType, SignReq, SignRes, VtUrl, SALT_LEN,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
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

/// Policy for the `auto` backend mode (currently the only mode): when an
/// SSH agent call fails, may we silently retry via the CF passkey path?
///
/// Falls back for:
/// - Transport failures (socket talk, envelope parse, version mismatch,
///   unstructured `AgentError::Failure`).
/// - Agent errors where the agent self-reports it cannot deliver key
///   material on this host (`SessionLocked`, `NoGuiSession`,
///   `NotInitialized`, `AgentLocked`, `Generic`, `Transient`, `Unknown`,
///   `LegacyDisabled`, `ProtocolVersion`).
///
/// Does NOT fall back for:
/// - `AuthRejected` — user explicitly declined on Touch ID / phone; silently
///   re-prompting via CF would be reverse of intent.
/// - `BadRequest` — client constructed a malformed request; CF won't fix
///   it and the structured error is more useful for debugging than a
///   second failure on a different path.
fn should_fallback_to_cf(err: &anyhow::Error) -> bool {
    match err.downcast_ref::<VtClientError>() {
        Some(VtClientError::Agent(kind, _)) => !matches!(
            kind,
            ErrKind::AuthRejected | ErrKind::BadRequest
        ),
        Some(VtClientError::Transport(_)) => true,
        None => false,
    }
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

#[derive(Clone)]
pub struct VTClient {
    auth_token: String,
    backend: crate::config::Backend,
}

impl VTClient {
    /// Build a client and verify that at least one decryption path is
    /// configured. Each path is opt-in by its own env vars:
    ///
    /// - SSH agent path: `VT_AUTH` (passed in as `auth_token`)
    /// - CF passkey path: `VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN`
    ///
    /// `VT_BACKEND` (auto | agent | passkey) pins the routing; its
    /// requirements are validated here too, so the user sees a single
    /// actionable error rather than a failure deep inside the routing code.
    pub fn new(auth_token: String) -> Result<Self> {
        let backend = crate::config::Backend::from_env()?;
        match backend {
            crate::config::Backend::Agent if auth_token.is_empty() => {
                anyhow::bail!("VT_BACKEND=agent requires VT_AUTH for the SSH agent path");
            }
            crate::config::Backend::Passkey if std::env::var("VT_PASSKEY_URL").is_err() => {
                anyhow::bail!(
                    "VT_BACKEND=passkey requires VT_PASSKEY_URL + VT_PASSKEY_TOKEN \
                     for the phone passkey ceremony"
                );
            }
            _ => {}
        }
        if auth_token.is_empty() && std::env::var("VT_PASSKEY_URL").is_err() {
            anyhow::bail!(
                "no decryption path configured — set VT_AUTH for the SSH agent path, \
                 or VT_PASSKEY_URL + VT_PASSKEY_TOKEN for the phone passkey ceremony"
            );
        }
        Ok(VTClient { auth_token, backend })
    }

    /// True when the SSH-agent path is usable: `VT_AUTH` set and not pinned
    /// away by `VT_BACKEND=passkey`. Gates agent-identity discovery in
    /// `vt ssh connect`: `sign@vt` needs this key, so discovery only makes
    /// sense when the agent path is in play.
    pub(crate) fn has_auth_token(&self) -> bool {
        !self.auth_token.is_empty() && self.backend != crate::config::Backend::Passkey
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
        // No VT_AUTH → caller hasn't opted in to the SSH-agent path; skip it
        // and let agent_call_or_fallback route to the CF passkey ceremony.
        // This also avoids decoding an empty auth token when $SSH_AUTH_SOCK
        // happens to point at an unrelated ssh-agent (common on Linux).
        if auth_token.is_empty() {
            return Ok(None);
        }

        let stream = match Self::connect_agent_socket()? {
            Some(s) => s,
            None => return Ok(None),
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

    /// Connect to the agent socket (`$SSH_AUTH_SOCK` if set, else
    /// `~/.ssh/vt.sock`). `Ok(None)` when the socket is missing/refused (no agent
    /// running) so callers can degrade gracefully; other IO errors propagate.
    /// Shared by `try_agent_extension` and `list_agent_identities`.
    #[cfg(unix)]
    fn connect_agent_socket() -> Result<Option<std::os::unix::net::UnixStream>> {
        use std::os::unix::net::UnixStream;
        let socket_path = if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            std::path::PathBuf::from(sock)
        } else {
            let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
            home.join(".ssh").join("vt.sock")
        };
        match UnixStream::connect(&socket_path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(None),
            Err(e) => Err(transport(e)),
        }
    }

    /// List the identities the agent holds via the standard
    /// `SSH_AGENTC_REQUEST_IDENTITIES` request (unencrypted, no Touch ID). Used
    /// by `vt ssh connect` to discover which key(s) to advertise when no
    /// explicit public key is configured.
    ///
    /// Returns `Ok(vec![])` when the socket is missing/refused (no agent), so
    /// callers can emit an actionable "configure a key / start the agent" error
    /// rather than a transport failure. Other IO/protocol errors propagate.
    ///
    /// This is a BLOCKING socket call — callers on an async context MUST invoke
    /// it via `tokio::task::spawn_blocking` (see `sign_vt`).
    ///
    /// NOTE: the listing is unauthenticated and does NOT require `VT_AUTH`, but
    /// the discovered keys can only be *signed* via `sign@vt`, which DOES need
    /// `VT_AUTH`. Callers must gate discovery on [`has_auth_token`] (as
    /// `resolve_identities` does) or the keys will fail at sign time.
    #[cfg(unix)]
    pub(crate) fn list_agent_identities(&self) -> Result<Vec<ssh_agent_lib::proto::Identity>> {
        let stream = match Self::connect_agent_socket()? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let mut client = ssh_agent_lib::blocking::Client::new(stream);
        client
            .request_identities()
            .map_err(|e| transport(anyhow::anyhow!("{}", e)))
    }

    /// Wrap `try_agent_extension` with the routing policy:
    ///
    /// - `VT_BACKEND=passkey` → `Ok(None)` immediately, without probing the
    ///   agent socket (a shared config.toml may set `VT_AUTH` on hosts where
    ///   `$SSH_AUTH_SOCK` points at an unrelated ssh-agent).
    /// - `VT_BACKEND=agent` → never fall back: socket-missing becomes an
    ///   actionable error, agent errors propagate unfiltered.
    /// - `auto` (default) → translate `Ok(None)` (socket missing/refused) and
    ///   recoverable `Err(_)` (per [`should_fallback_to_cf`]) into a single
    ///   `Ok(None)` so callers route to the CF path; non-recoverable errors
    ///   propagate.
    #[cfg(unix)]
    async fn agent_call_or_fallback(
        auth_token: String,
        backend: crate::config::Backend,
        name: &'static str,
        payload: Vec<u8>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        use crate::config::Backend;
        if backend == Backend::Passkey {
            return Ok(None);
        }
        let result = tokio::task::spawn_blocking(move || {
            Self::try_agent_extension(&auth_token, name, &payload)
        })
        .await?;
        match result {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) if backend == Backend::Agent => Err(anyhow::anyhow!(
                "SSH agent socket unavailable and VT_BACKEND=agent forbids the \
                 passkey fallback — is the vt agent running / forwarded?"
            )),
            Ok(None) => Ok(None),
            Err(e) => {
                if backend != Backend::Agent && should_fallback_to_cf(&e) {
                    // Keep the raw error out of default output (it reads as a
                    // scary internal failure); the CF path prints a clean,
                    // user-facing fallback line. `RUST_LOG=debug` still surfaces
                    // the underlying cause for diagnosing bad fallbacks.
                    debug!("agent call failed, falling back to phone passkey: {}", e);
                    Ok(None)
                } else {
                    Err(e)
                }
            }
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
            let result =
                Self::agent_call_or_fallback(auth_token, self.backend, "encrypt@vt", payload).await?;
            let bytes = match result {
                Some(b) => b,
                None => return Self::cf_encrypt(items, &get_hostname()).await,
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
                meta: cf::collect_client_meta(),
            };
            let payload = serde_json::to_vec(&wire)?;
            let auth_token = self.auth_token.clone();
            let result =
                Self::agent_call_or_fallback(auth_token, self.backend, "decrypt@vt", payload).await?;
            let bytes = match result {
                Some(b) => b,
                None => return Self::cf_decrypt(host, command, urls).await,
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

    /// `sign@vt`: ask the agent to sign `data` with the Keychain key identified
    /// by `pubkey` (SSH wire-encoded `KeyData`), displaying the vt context in
    /// the Touch ID prompt. See `docs/sign-vt-design.md`.
    ///
    /// - `Ok(Some((alg, sig)))` — the agent signed; the private key never left
    ///   the agent.
    /// - `Ok(None)` — the caller should fall back to decrypt-then-sign: socket
    ///   missing/refused, an old agent that doesn't know `sign@vt`, or any
    ///   recoverable agent error per [`should_fallback_to_cf`] (including
    ///   `Generic` = "this agent does not hold that key").
    /// - `Err(_)` — `AuthRejected` (user declined) or `BadRequest` (malformed):
    ///   do NOT fall back (guardrail G3).
    #[cfg(unix)]
    pub async fn sign_vt(
        &self,
        host: &str,
        command: &str,
        pubkey: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Option<(String, Vec<u8>)>> {
        let req = SignReq {
            host: host.to_string(),
            command: command.to_string(),
            pubkey: pubkey.to_vec(),
            data: data.to_vec(),
            flags,
            meta: cf::collect_client_meta(),
        };
        // VT_BACKEND=passkey pins routing away from the agent: skip the socket
        // probe and return the "fall back" signal — the caller's
        // decrypt-then-sign fallback routes its decrypt through this client
        // again, which then takes the passkey ceremony. `agent` mode is NOT
        // special-cased here for the same reason: the fallback's decrypt still
        // honors the agent-only pin.
        if self.backend == crate::config::Backend::Passkey {
            return Ok(None);
        }
        let payload = serde_json::to_vec(&req)?;
        let auth_token = self.auth_token.clone();
        // Same blocking + classification as `agent_call_or_fallback`, but
        // WITHOUT the "falling back to phone passkey" eprintln: our fallback is
        // local decrypt-then-sign, not necessarily the CF ceremony.
        let result = tokio::task::spawn_blocking(move || {
            Self::try_agent_extension(&auth_token, "sign@vt", &payload)
        })
        .await?;
        match result {
            Ok(Some(bytes)) => {
                let res: SignRes = serde_json::from_slice(&bytes)?;
                Ok(Some((res.algorithm, res.signature)))
            }
            Ok(None) => Ok(None),
            Err(e) if should_fallback_to_cf(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ── CF ceremony fallbacks ──────────────────────────────────────────────

    async fn cf_encrypt(items: &[EncryptItem], _host: &str) -> Result<Vec<CryptoResItem>> {
        let config = cf::load_config()
            .context("SSH agent unavailable; CF passkey env not configured")?;
        let mut salts = cf::random_salts(items.len());
        let meta = cf::collect_meta("encrypt", "", "");
        let deks = cf::get_deks(&config, &salts, meta).await?;
        let mut out = Vec::with_capacity(items.len());
        for ((item, salt), dek) in items.iter().zip(salts.iter()).zip(deks.iter()) {
            let res = match client_encrypt_v2(item.t, salt, dek, item.plaintext.as_bytes()) {
                Ok(url) => CryptoResItem { result: url, err_message: String::new() },
                Err(e)  => CryptoResItem { result: String::new(), err_message: e.to_string() },
            };
            out.push(res);
        }
        salts.iter_mut().for_each(|s| s.iter_mut().for_each(|b| *b = 0));
        Ok(out)
    }

    async fn cf_decrypt(_host: &str, command: &str, urls: &[String]) -> Result<Vec<CryptoResItem>> {
        let config = cf::load_config()
            .context("SSH agent unavailable; CF passkey env not configured")?;

        // Parse URLs; collect v2 salts in order
        struct Item {
            t: SecretType,
            salt: [u8; SALT_LEN],
            inner_ct: Vec<u8>,
        }
        let mut items: Vec<Result<Item, String>> = Vec::with_capacity(urls.len());
        let mut salts: Vec<[u8; SALT_LEN]> = Vec::new();
        for raw_url in urls {
            match VtUrl::parse(raw_url) {
                Ok(VtUrl::V2 { t, salt, inner_ct }) => {
                    salts.push(salt);
                    items.push(Ok(Item { t, salt, inner_ct }));
                }
                Ok(VtUrl::Legacy { .. }) => {
                    items.push(Err("legacy vt:// URLs require macOS SSH agent".to_string()));
                }
                Err(e) => items.push(Err(e.to_string())),
            }
        }

        // Fast path: try the opt-in DEK cache first (no phone if all salts are
        // cached for this IP+ppid within the approved TTL). The full meta is sent
        // so a cache HIT is audited with the same context as a ceremony decrypt.
        // On any miss / cache disabled / transport hiccup, fall through to the
        // full phone ceremony.
        let meta = cf::collect_meta("decrypt", command, "");
        let deks = match cf::try_cache(&config, &salts, &meta).await? {
            Some(d) => d,
            None => cf::get_deks(&config, &salts, meta).await?,
        };

        let mut out = Vec::with_capacity(urls.len());
        let mut dek_idx = 0usize;
        for item_res in items {
            match item_res {
                Err(e) => out.push(CryptoResItem { result: String::new(), err_message: e }),
                Ok(Item { t, salt, inner_ct }) => {
                    // Bounds-guard rather than index: open_sealed_deks already
                    // enforces deks.len() == salts.len(), but never let a short
                    // worker response panic the process here.
                    let dek = deks.get(dek_idx).ok_or_else(|| {
                        anyhow::anyhow!("internal: fewer DEKs returned than v2 records")
                    })?;
                    dek_idx += 1;
                    let res = match client_decrypt_v2(t, dek, &salt, &inner_ct) {
                        Ok(pt) => CryptoResItem { result: pt, err_message: String::new() },
                        Err(e) => CryptoResItem { result: String::new(), err_message: e.to_string() },
                    };
                    out.push(res);
                }
            }
        }
        Ok(out)
    }

    async fn cf_auth(reason: &str) -> Result<()> {
        let config = cf::load_config()
            .context("SSH agent unavailable; CF passkey env not configured")?;
        let meta = cf::collect_meta("auth", "", reason);
        cf::get_deks(&config, &[], meta).await?;
        Ok(())
    }

    /// Ask the local agent to run an allowlisted program. SSH-agent path
    /// only — there is no CF passkey fallback, because the whole feature
    /// only makes sense when "local" means "the Mac at the other end of the
    /// forwarded agent socket". If `VT_AUTH` is unset (no agent path
    /// configured) we refuse here instead of silently failing further down.
    pub async fn run(&self, argv: Vec<String>, reason: Option<&str>) -> Result<()> {
        #[cfg(unix)]
        {
            if self.auth_token.is_empty() {
                anyhow::bail!(
                    "vt run requires the SSH-agent path (set VT_AUTH and ensure \
                     SSH_AUTH_SOCK / ~/.ssh/vt.sock points at a vt agent — there \
                     is no phone-passkey fallback for run@vt)"
                );
            }
            if self.backend == crate::config::Backend::Passkey {
                anyhow::bail!(
                    "vt run is agent-only, but VT_BACKEND=passkey disables the agent path"
                );
            }
            if argv.is_empty() {
                anyhow::bail!("vt run: argv is empty");
            }
            let req = RunReq {
                host: get_hostname(),
                argv,
                reason: reason.map(str::to_string),
                meta: cf::collect_client_meta(),
            };
            let payload = serde_json::to_vec(&req)?;
            let auth_token = self.auth_token.clone();
            let result =
                Self::agent_call_or_fallback(auth_token, self.backend, "run@vt", payload).await?;
            match result {
                Some(bytes) => {
                    let res: RunRes = serde_json::from_slice(&bytes)
                        .context("Failed to parse run response")?;
                    tracing::debug!("vt run: spawned pid={}", res.pid);
                    Ok(())
                }
                None => Err(anyhow::anyhow!(
                    "vt run: SSH agent path unavailable (no fallback exists for run@vt)"
                )),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (argv, reason);
            Err(anyhow::anyhow!("vt run requires Unix (SSH agent socket)"))
        }
    }

    pub async fn auth(&self, reason: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let req = AuthReq {
                host: get_hostname(),
                reason: reason.to_string(),
                meta: cf::collect_client_meta(),
            };
            let payload = serde_json::to_vec(&req)?;
            let auth_token = self.auth_token.clone();
            let result =
                Self::agent_call_or_fallback(auth_token, self.backend, "auth@vt", payload).await?;

            match result {
                Some(bytes) => {
                    let _res: AuthRes =
                        serde_json::from_slice(&bytes).context("Failed to parse auth response")?;
                    return Ok(());
                }
                None => return Self::cf_auth(reason).await,
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("vt auth requires Unix (SSH agent socket)"))
        }
    }
}

pub async fn create(vt_client: VTClient) -> Result<()> {
    eprint!("Enter secret type (raw/totp) [default: raw]: ");
    io::stderr().flush()?;
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
    println!("{}", res[0].result);
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

async fn decrypt_from_multi_str(
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

/// Argv[1] that triggers the detached restore supervisor. Dispatched in
/// `main()` before tokio / clap, so the supervisor process is lean and never
/// pays the cost of the full vt initialization.
pub const SUPERVISOR_SUBCOMMAND: &str = "_internal-restore-after";

/// Whether an environment variable enters the decrypt pipeline: its value must
/// contain a `vt://` URL, and — when `--only-env` is given — its name must be in
/// that allow-list. This is the scoping that keeps `vt hook` from handing a
/// matched command every vt:// secret in the environment (confused-deputy guard).
fn env_var_in_scope(key: &str, value: &str, only_env: Option<&[String]>) -> bool {
    has_vt_url(value) && only_env.map_or(true, |allow| allow.iter().any(|a| a == key))
}

pub async fn inject(
    vt_client: VTClient,
    replace_file: Option<String>,
    timeout: u32,
    reason: Option<&str>,
    only_env: Option<Vec<String>>,
    mut args: Vec<String>,
) -> Result<()> {
    let raw_command = args.join(" ");
    debug!("Original command: {}", raw_command);
    let mut original_command = String::from("op: inject");
    if let Some(p) = replace_file.as_ref() {
        original_command.push_str("\nfile: ");
        original_command.push_str(&sanitize_for_display(p, 100));
    }
    if raw_command.is_empty() {
        original_command.push_str("\ncmd: [no shell command]");
    } else {
        let normalized = collapse_whitespace(&raw_command);
        let redacted = redact_vt_urls(&normalized, "vt://***");
        original_command.push_str("\ncmd: ");
        // Keep the full command in the audit/approval record (the detail dialog
        // renders it verbatim). The Touch ID prompt re-caps per line
        // (PROMPT_COMMAND_MAX_LINE_LEN) and the whole request body is bounded by
        // PROMPT_DISPLAY_MAX_BYTES (8 KiB) / CEREMONY_POST_MAX_BYTES, so a
        // generous cap here shows real commands in full without truncating to
        // "gh api…".
        original_command.push_str(&sanitize_for_display(&redacted, 1024));
    }
    if let Some(r) = reason {
        original_command.push_str("\nreason: ");
        original_command.push_str(&sanitize_for_display(r, 200));
    }

    // Open the target ONCE with O_NOFOLLOW, capture its mode, and read its
    // content. The same in-memory bytes are reused as both the decrypt source
    // and the ciphertext backup, so there is no second open to race: a
    // directory-writable attacker can't swap the file between "what we
    // decrypt" and "what we back up / restore". `orig_mode` carries the mode
    // captured here to the backup-creation step below.
    let mut orig_mode: u32 = 0o600;
    let replace_file_content = match replace_file.as_ref() {
        Some(file) => {
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            debug!("Reading file: {}", file);
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(file)
                .with_context(|| {
                    format!("Failed to open replace file (refuses symlinks): {}", file)
                })?;
            let meta = f
                .metadata()
                .with_context(|| format!("Failed to stat: {}", file))?;
            if !meta.is_file() {
                return Err(anyhow::anyhow!(
                    "Refusing to replace non-regular file: {}",
                    file
                ));
            }
            orig_mode = meta.mode() & 0o7777;
            let mut buf = String::new();
            f.read_to_string(&mut buf)
                .with_context(|| format!("Failed to read file: {}", file))?;
            buf
        }
        None => String::new(),
    };
    // Keep the original (ciphertext) bytes for the backup; the same bytes we
    // just read and are about to decrypt. Cheap clone (empty when no -r file).
    let orig_file_bytes = replace_file_content.clone().into_bytes();
    args.push(replace_file_content);

    // Scan env vars locally for vt:// patterns — only those values enter the
    // decrypt pipeline. Env var names and non-vt values never leave this process.
    // When `--only-env` is given, restrict decryption to exactly those names:
    // this is how `vt hook` keeps a matched command scoped to the secrets its
    // rule authorizes, instead of every vt:// var in the environment.
    let env_vt_vars: Vec<(String, String)> = env::vars()
        .filter(|(k, v)| env_var_in_scope(k, v, only_env.as_deref()))
        .collect();
    for (_, value) in &env_vt_vars {
        args.push(value.clone());
    }

    let mut decrypted_args = decrypt_from_multi_str(vt_client, args, original_command).await?;

    // Pop decrypted env var values (in reverse push order) and set only those.
    // decrypt_from_multi_str preserves length 1:1, so these pops always
    // succeed; guard anyway so a future contract change can't panic here.
    for (key, _) in env_vt_vars.iter().rev() {
        let decrypted_value = decrypted_args
            .pop()
            .ok_or_else(|| anyhow::anyhow!("internal: decrypted arg count underflow"))?;
        env::set_var(key, decrypted_value);
    }

    let decrypted_file_content = decrypted_args
        .pop()
        .ok_or_else(|| anyhow::anyhow!("internal: decrypted file content missing"))?;

    // Plaintext exposure protocol when -r is set:
    //   1. Open target with O_NOFOLLOW, stat to capture mode + reject non-regular.
    //   2. Write a backup file alongside the target (ciphertext copy, randomized
    //      hidden name, O_CREAT|O_EXCL|O_NOFOLLOW, mode = orig).
    //   3. Spawn the detached supervisor before any plaintext can hit disk.
    //      Failure here deletes the backup and aborts — target stays ciphertext.
    //   4. Write the tmp file (plaintext, same hidden-name rules as backup).
    //   5. rename(tmp, target) — atomic plaintext exposure.
    //   6. Parent execs the user command; supervisor restores after timeout.
    //
    // Steps 4, 5, and 6 each call `immediate_restore` on failure so the
    // observable post-failure state collapses to "target = ciphertext, no
    // sidecars" without waiting for the supervisor. The supervisor is the
    // durable backstop: even if a parent crash makes immediate_restore
    // unreachable, the supervisor's `unlink(tmp) + rename(backup, target)`
    // after timeout still brings everything home (modulo SIGKILL / reboot).
    let armed: Option<(String, std::path::PathBuf, std::path::PathBuf)> =
        if let Some(replace_file_path) = &replace_file
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

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

        let mut rnd = [0u8; 8];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut rnd);
        }
        let suffix: String = rnd.iter().map(|b| format!("{:02x}", b)).collect();
        let backup_path = dir.join(format!(".{}.vt-backup-{}", file_name, suffix));
        let tmp_path = dir.join(format!(".{}.vt-tmp-{}", file_name, suffix));
        // Crash-recovery sidecar path in the state dir. Computed up front so
        // the supervisor gets it at spawn and can delete it after a normal
        // restore. If the home dir can't be resolved we fall back to a path
        // beside the target: the supervisor can still delete it on the normal
        // path, but `vt inject --recover` (which only scans the state dir) will
        // not find it — crash-recovery is effectively unavailable without a
        // home dir. This mirrors `inject_recover`, which also bails on `None`.
        let sidecar_path = inject_state_dir()
            .map(|d| d.join(format!("{suffix}.json")))
            .unwrap_or_else(|| dir.join(format!(".{}.vt-recover-{}.json", file_name, suffix)));

        // Step 2: write backup from the in-memory ORIGINAL bytes (captured at
        // the single O_NOFOLLOW open above) — NOT a fresh re-read of the target,
        // which would be a TOCTOU window for a directory-writable attacker.
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
            backup_file.write_all(&orig_file_bytes).with_context(|| {
                format!(
                    "Failed to copy content to backup: {}",
                    backup_path.display()
                )
            })?;
            backup_file.sync_all().ok();
        }
        debug!("Created backup at: {}", backup_path.display());

        // Step 3: arm supervisor before any plaintext touches disk.
        match spawn_restore_supervisor(
            timeout,
            &tmp_path,
            &backup_path,
            replace_file_path,
            &sidecar_path,
        ) {
            Ok(()) => debug!("Restore supervisor armed (timeout={}s)", timeout),
            Err(e) => {
                let _ = std::fs::remove_file(&backup_path);
                return Err(e);
            }
        }

        // Step 3b: write the crash-recovery sidecar (before any plaintext hits
        // disk). Best-effort — losing it only forfeits reboot recovery for this
        // one injection, so a failure warns rather than aborts.
        let sidecar = InjectSidecar {
            target: absolutize(std::path::Path::new(replace_file_path))
                .to_string_lossy()
                .into_owned(),
            backup: absolutize(&backup_path).to_string_lossy().into_owned(),
            tmp: absolutize(&tmp_path).to_string_lossy().into_owned(),
            deadline_ms: now_ms().saturating_add((timeout as u64).saturating_mul(1000)),
        };
        if let Err(e) = write_inject_sidecar(&sidecar_path, &sidecar) {
            debug!("inject sidecar not written ({e:#}); crash-recovery disabled for this run");
        }

        // Step 4: write tmp (plaintext).
        if let Err(e) = write_plaintext_tmp(&tmp_path, orig_mode, &decrypted_file_content) {
            // Parent does immediate cleanup so the failure leaves no visible
            // sidecar state for the timeout window. Supervisor will later
            // observe ENOENT on backup and exit silently.
            let _ = std::fs::remove_file(&tmp_path);
            let _ = std::fs::remove_file(&sidecar_path);
            immediate_restore(replace_file_path, &backup_path);
            return Err(e);
        }

        // Step 5: atomically expose plaintext at target.
        if let Err(e) = std::fs::rename(&tmp_path, replace_file_path) {
            let _ = std::fs::remove_file(&tmp_path);
            let _ = std::fs::remove_file(&sidecar_path);
            immediate_restore(replace_file_path, &backup_path);
            return Err(e).with_context(|| {
                format!("Failed to atomically replace file: {}", replace_file_path)
            });
        }
        debug!("Content written to replace file: {}", replace_file_path);

        Some((replace_file_path.clone(), backup_path, sidecar_path))
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

    // exec() never returns on success; reaching here means it failed.
    let err = exec::Command::new(command).args(args).exec();

    // Restore immediately on exec failure so the user doesn't wait out the
    // supervisor's timeout. The supervisor will later observe ENOENT on the
    // backup and exit silently.
    if let Some((target, backup, sidecar)) = &armed {
        immediate_restore(target, backup);
        let _ = std::fs::remove_file(sidecar);
    }
    Err(anyhow::anyhow!("Failed to execute command: {}", err))
}

/// Best-effort parent-side restore. Called on any step-4/5/6 failure to
/// collapse the post-failure state to "target = ciphertext, no sidecars" as
/// fast as possible. The detached supervisor will later see ENOENT on backup
/// and exit silently — there are deliberately two restorers, with the parent
/// as the fast path and the supervisor as the durable fallback.
fn immediate_restore(target: &str, backup: &std::path::Path) {
    if let Err(e) = std::fs::rename(backup, target) {
        eprintln!(
            "vt inject: restore-on-fail failed: {}; backup remains at {}",
            e,
            backup.display()
        );
    }
}

fn write_plaintext_tmp(tmp: &std::path::Path, mode: u32, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(tmp)
        .with_context(|| format!("Failed to create temp file: {}", tmp.display()))?;
    tmp_file
        .write_all(content.as_bytes())
        .with_context(|| format!("Failed to write temp file: {}", tmp.display()))?;
    tmp_file.sync_all().ok();
    Ok(())
}

// ── Crash-recovery sidecar ──────────────────────────────────────────────────
//
// The restore supervisor holds its state (tmp/backup/target/deadline) only in
// its own argv. A reboot or SIGKILL kills the sleeper and leaves the plaintext
// exposed at `target` with an orphaned ciphertext backup beside it — with no
// record of what to restore. The sidecar closes that gap: a tiny JSON file
// written (before any plaintext hits disk) at a stable, discoverable location,
// so `vt inject --recover` can find and undo orphaned exposures after a crash.
// It carries no secret — only paths + a deadline.

/// One armed injection's recovery record. Absolute paths so `--recover` works
/// from any cwd.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct InjectSidecar {
    /// The file being exposed as plaintext (ciphertext must be restored here).
    target: String,
    /// The ciphertext backup to rename back over `target`.
    backup: String,
    /// The plaintext tmp file, removed on recovery if it was orphaned.
    tmp: String,
    /// Epoch ms after which the supervisor should already have restored; past
    /// this (plus a grace) a surviving backup means the supervisor died.
    deadline_ms: u64,
}

/// Wait past the deadline by this much before `--recover` acts, so a
/// legitimately-still-sleeping supervisor is never raced.
const RECOVER_GRACE_MS: u64 = 5_000;

/// What `--recover` should do with one sidecar entry.
#[derive(Debug, PartialEq, Eq)]
enum RecoverAction {
    /// Backup present and the window has elapsed → supervisor is dead; restore.
    Restore,
    /// Backup already consumed (normal completion) → sidecar is stale; delete.
    CleanStale,
}

/// Pure recovery decision. `None` = leave it alone (an injection whose window
/// has not yet elapsed — its supervisor is presumed still running).
fn plan_recovery(deadline_ms: u64, backup_exists: bool, now_ms: u64) -> Option<RecoverAction> {
    if !backup_exists {
        // The supervisor (or immediate_restore) already renamed the backup
        // over the target: the injection completed. Only the sidecar lingers.
        return Some(RecoverAction::CleanStale);
    }
    if now_ms >= deadline_ms.saturating_add(RECOVER_GRACE_MS) {
        Some(RecoverAction::Restore)
    } else {
        None
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `~/.local/state/vt/inject` — the sidecar directory (same on macOS and Linux
/// for a single recovery path). `None` if the home dir can't be resolved.
fn inject_state_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".local").join("state").join("vt").join("inject"))
}

/// Make `p` absolute (without requiring it to exist — the target is about to
/// be renamed over) so the recorded path resolves from any later cwd.
fn absolutize(p: &std::path::Path) -> std::path::PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

/// Write the sidecar at `path` (mode 0600), creating its parent dir. Best
/// effort at the call site: a failure here loses only crash-recovery for this
/// one injection (the in-memory supervisor still restores on the normal path),
/// so callers warn and continue rather than aborting the user's command.
fn write_inject_sidecar(path: &std::path::Path, sc: &InjectSidecar) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        // Create every missing component as 0700 in one step (no create-then-
        // chmod window) — the dir lists which files are mid-exposure.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating inject state dir {}", dir.display()))?;
    }
    let json = serde_json::to_vec(sc).context("serialize inject sidecar")?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating inject sidecar {}", path.display()))?;
    f.write_all(&json)
        .with_context(|| format!("writing inject sidecar {}", path.display()))?;
    f.sync_all().ok();
    Ok(())
}

/// Sweep the sidecar dir and restore any orphaned plaintext exposure. Invoked
/// by `vt inject --recover` (run at login/boot). Never errors on an individual
/// bad entry — it logs and moves on so one corrupt sidecar can't wedge the sweep.
pub fn inject_recover() -> Result<()> {
    let Some(dir) = inject_state_dir() else {
        eprintln!("vt inject --recover: cannot resolve home dir");
        return Ok(());
    };
    if !dir.exists() {
        println!("vt inject --recover: nothing to recover");
        return Ok(());
    }
    let now = now_ms();
    let (mut restored, mut cleaned, mut active) = (0u32, 0u32, 0u32);
    let entries = std::fs::read_dir(&dir)
        .with_context(|| format!("reading inject state dir {}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let sc: InjectSidecar = match std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(sc) => sc,
            None => {
                eprintln!("vt inject --recover: skipping unreadable sidecar {}", path.display());
                continue;
            }
        };
        let backup_exists = std::path::Path::new(&sc.backup).exists();
        match plan_recovery(sc.deadline_ms, backup_exists, now) {
            Some(RecoverAction::Restore) => {
                let _ = std::fs::remove_file(&sc.tmp);
                if let Err(e) = std::fs::rename(&sc.backup, &sc.target) {
                    eprintln!(
                        "vt inject --recover: failed to restore {} from {}: {}",
                        sc.target, sc.backup, e
                    );
                    continue; // leave the sidecar so a later sweep retries
                }
                let _ = std::fs::remove_file(&path);
                println!("vt inject --recover: restored {}", sc.target);
                restored += 1;
            }
            Some(RecoverAction::CleanStale) => {
                let _ = std::fs::remove_file(&sc.tmp);
                let _ = std::fs::remove_file(&path);
                cleaned += 1;
            }
            None => active += 1,
        }
    }
    println!(
        "vt inject --recover: {restored} restored, {cleaned} stale cleaned, {active} still active"
    );
    Ok(())
}

/// Spawn the restore supervisor as a self-exec'd child. The intermediate
/// process exits immediately after double-forking inside the supervisor
/// subcommand body; we reap that exit here, leaving the grandchild reparented
/// to init (or the nearest subreaper) and detached from the user's session.
fn spawn_restore_supervisor(
    timeout: u32,
    tmp_path: &std::path::Path,
    backup_path: &std::path::Path,
    target_path: &str,
    sidecar_path: &std::path::Path,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe =
        std::env::current_exe().with_context(|| "Failed to resolve current executable path")?;
    let mut cmd = Command::new(&exe);
    cmd.arg(SUPERVISOR_SUBCOMMAND)
        .arg(timeout.to_string())
        .arg(tmp_path)
        .arg(backup_path)
        .arg(target_path)
        .arg(sidecar_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs post-fork, pre-exec in the child. Body uses
    // only async-signal-safe syscalls (setsid) — no allocator, no Rust
    // globals, no FFI that could touch shared locks.
    unsafe {
        cmd.pre_exec(|| {
            // setsid: new session + pgroup. Detaches from controlling TTY so
            // SIGHUP on terminal close doesn't sweep us in via the session,
            // and Ctrl+C on the parent's foreground pgroup doesn't reach us.
            // Signal dispositions (SIG_IGN for HUP/INT/TERM/PIPE/QUIT) are
            // set in `supervisor_main` AFTER Rust's runtime init — installing
            // them here in pre_exec gets clobbered by the runtime's own
            // signal setup between execve and our entry point.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut spawned = cmd
        .spawn()
        .with_context(|| "Failed to spawn restore supervisor")?;
    let status = spawned
        .wait()
        .with_context(|| "Failed to reap supervisor intermediate")?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "Restore supervisor failed to launch: intermediate exited with {:?}",
            status
        ));
    }
    Ok(())
}

/// Pre-tokio, pre-clap entry point for the detached restore supervisor.
/// Dispatched from `main()` so this process never builds a tokio runtime,
/// parses clap definitions, or loads tracing — its RSS is just vt's text
/// segment (shared with the parent via page cache) + a few KB of heap.
///
/// Args (after the SUPERVISOR_SUBCOMMAND marker):
/// `<secs> <tmp> <backup> <target> <sidecar>`.
pub fn supervisor_main(args: &[std::ffi::OsString]) -> i32 {
    // Stdio is /dev/null — any failure here is invisible to the user. Parent
    // distinguishes the intermediate's success (exit 0 after double-fork)
    // from any failure (non-zero) via Child::wait().
    if args.len() != 5 {
        return 2;
    }
    let secs: u64 = match args[0].to_str().and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => return 2,
    };
    let tmp = std::path::PathBuf::from(&args[1]);
    let backup = std::path::PathBuf::from(&args[2]);
    let target = std::path::PathBuf::from(&args[3]);
    let sidecar = std::path::PathBuf::from(&args[4]);

    // Install SIG_IGN for the signals that would otherwise sweep us up when
    // the user closes the terminal, hits Ctrl+C, or runs `pkill vt`. These
    // are installed AFTER Rust's runtime init (which resets some of them to
    // SIG_DFL between execve and our entry point), and BEFORE the double-
    // fork so the grandchild inherits the same dispositions. SIGKILL and
    // SIGSTOP cannot be ignored — fundamental Unix limit.
    //
    // SAFETY: zeroed sigaction is a valid POSIX struct; SIG_IGN and the
    // listed signal numbers are libc constants; sigemptyset writes through a
    // valid &mut. Failures are intentionally ignored — best-effort.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        for &sig in &[
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGPIPE,
            libc::SIGQUIT,
        ] {
            // Best-effort — if this fails the supervisor still works, it's
            // just more vulnerable to signals. Don't abort the restore path.
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    // Double-fork: orphan the sleeper to init so it's invisible to the
    // user-cmd's process tree (no entry under `pstree user-cmd`, no
    // interference with `waitpid(-1)` from the user-cmd or its parent shell).
    //
    // SAFETY: fork has well-defined POSIX behavior; the grandchild runs
    // only async-signal-safe code below (thread::sleep, remove_file, rename
    // — all of which are async-signal-safe at the syscall level). The
    // intermediate uses _exit(0) which is async-signal-safe and skips any
    // Rust destructors that would touch shared global state.
    unsafe {
        match libc::fork() {
            -1 => return 3,
            0 => { /* grandchild continues */ }
            _ => libc::_exit(0),
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(secs));

    // Wipe any orphaned plaintext tmp first. If the parent crashed between
    // write_plaintext_tmp and rename(tmp,target), this is the only path
    // that removes it — the supervisor doesn't otherwise know.
    let _ = std::fs::remove_file(&tmp);
    // Restore ciphertext over the target. Either succeeds (normal case) or
    // returns ENOENT (parent already restored on exec failure / rename failure).
    let _ = std::fs::rename(&backup, &target);
    // The exposure is over; drop the crash-recovery sidecar so `--recover`
    // doesn't later see a stale entry.
    let _ = std::fs::remove_file(&sidecar);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::wire::wrap_ok_envelope;

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
    fn fallback_policy_auth_rejected_does_not_fall_back() {
        let e: anyhow::Error = VtClientError::Agent(ErrKind::AuthRejected, None).into();
        assert!(!should_fallback_to_cf(&e));
    }

    #[test]
    fn fallback_policy_bad_request_does_not_fall_back() {
        let e: anyhow::Error = VtClientError::Agent(ErrKind::BadRequest, None).into();
        assert!(!should_fallback_to_cf(&e));
    }

    #[test]
    fn fallback_policy_session_locked_falls_back() {
        let e: anyhow::Error = VtClientError::Agent(ErrKind::SessionLocked, None).into();
        assert!(should_fallback_to_cf(&e));
    }

    #[test]
    fn fallback_policy_other_agent_kinds_fall_back() {
        for kind in [
            ErrKind::NoGuiSession,
            ErrKind::NotInitialized,
            ErrKind::AgentLocked,
            ErrKind::Generic,
            ErrKind::Transient,
            ErrKind::Unknown,
            ErrKind::LegacyDisabled,
            ErrKind::ProtocolVersion,
        ] {
            let e: anyhow::Error = VtClientError::Agent(kind, None).into();
            assert!(
                should_fallback_to_cf(&e),
                "expected {:?} to fall back",
                kind
            );
        }
    }

    #[test]
    fn fallback_policy_transport_falls_back() {
        let e: anyhow::Error =
            VtClientError::Transport(anyhow::anyhow!("socket closed")).into();
        assert!(should_fallback_to_cf(&e));
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

    // ── inject crash-recovery ───────────────────────────────────────────────

    #[test]
    fn plan_recovery_cleans_stale_when_backup_gone() {
        // Backup already consumed (supervisor/immediate_restore renamed it) →
        // the injection completed; only the sidecar lingers. Deadline is
        // irrelevant on this arm.
        assert_eq!(
            plan_recovery(1_000, false, 500),
            Some(RecoverAction::CleanStale)
        );
        assert_eq!(
            plan_recovery(1_000, false, 999_999),
            Some(RecoverAction::CleanStale)
        );
    }

    #[test]
    fn plan_recovery_restores_only_past_deadline_plus_grace() {
        let deadline = 1_000_000;
        // Before the deadline: an active injection — leave it for its supervisor.
        assert_eq!(plan_recovery(deadline, true, deadline - 1), None);
        // At the deadline but within the grace window: still hands-off, so a
        // supervisor firing at exactly the deadline isn't raced.
        assert_eq!(plan_recovery(deadline, true, deadline), None);
        assert_eq!(plan_recovery(deadline, true, deadline + RECOVER_GRACE_MS - 1), None);
        // Past deadline + grace with a surviving backup → supervisor is dead.
        assert_eq!(
            plan_recovery(deadline, true, deadline + RECOVER_GRACE_MS),
            Some(RecoverAction::Restore)
        );
    }

    #[test]
    fn inject_sidecar_json_roundtrips() {
        let sc = InjectSidecar {
            target: "/abs/secret.env".into(),
            backup: "/abs/.secret.env.vt-backup-ab".into(),
            tmp: "/abs/.secret.env.vt-tmp-ab".into(),
            deadline_ms: 1_723_000_000_000,
        };
        let bytes = serde_json::to_vec(&sc).unwrap();
        let back: InjectSidecar = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(sc, back);
    }

    #[test]
    fn absolutize_leaves_absolute_paths_untouched() {
        let p = std::path::Path::new("/already/absolute");
        assert_eq!(absolutize(p), p);
        // A relative path becomes absolute (prefixed by some cwd).
        assert!(absolutize(std::path::Path::new("rel/x")).is_absolute());
    }
}
