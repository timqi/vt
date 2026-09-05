//! Cross-platform vt client.
//!
//! Primary path: SSH agent via `$SSH_AUTH_SOCK` or `~/.ssh/vt.sock`.
//! Fallback path (Linux / macOS without agent): CF ceremony via
//! VT_PASSKEY_URL + VT_PASSKEY_TOKEN env vars — POST /api/challenge + WS /api/dek.

mod commands;
mod doctor;
mod inject;

pub use commands::{auth, create, read, rewrap, run};
pub use doctor::doctor;
pub use inject::{inject, inject_recover, supervisor_main, SUPERVISOR_SUBCOMMAND};

use crate::cf;
use crate::core::crypto::{decode_auth_cipher_from_b64, AesGcmCrypto};
use crate::core::wire::{ErrKind, WIRE_VERSION};
use crate::core::{
    client_decrypt_v2, client_encrypt_v2, AuthReq, AuthRes, CryptoResItem, DecryptInput,
    DecryptReq, DecryptResItem, EncryptItem, EncryptReq, EncryptResItem, RunReq, RunRes,
    SecretType, SignReq, SignRes, VtUrl, SALT_LEN,
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
        Some(VtClientError::Agent(kind, _)) => {
            !matches!(kind, ErrKind::AuthRejected | ErrKind::BadRequest)
        }
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
        Ok(VTClient {
            auth_token,
            backend,
        })
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
                    auth_cipher
                        .decrypt(resp.details.as_ref())
                        .map_err(transport)?,
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
            let home =
                dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
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
                Self::agent_call_or_fallback(auth_token, self.backend, "encrypt@vt", payload)
                    .await?;
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
            Err(anyhow::anyhow!(
                "vt encrypt requires Unix (SSH agent socket)"
            ))
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
                Self::agent_call_or_fallback(auth_token, self.backend, "decrypt@vt", payload)
                    .await?;
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
            Err(anyhow::anyhow!(
                "vt decrypt requires Unix (SSH agent socket)"
            ))
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
        let config =
            cf::load_config().context("SSH agent unavailable; CF passkey env not configured")?;
        let mut salts = cf::random_salts(items.len());
        let meta = cf::collect_meta("encrypt", "", "");
        let deks = cf::get_deks(&config, &salts, meta).await?;
        let mut out = Vec::with_capacity(items.len());
        for ((item, salt), dek) in items.iter().zip(salts.iter()).zip(deks.iter()) {
            let res = match client_encrypt_v2(item.t, salt, dek, item.plaintext.as_bytes()) {
                Ok(url) => CryptoResItem {
                    result: url,
                    err_message: String::new(),
                },
                Err(e) => CryptoResItem {
                    result: String::new(),
                    err_message: e.to_string(),
                },
            };
            out.push(res);
        }
        salts
            .iter_mut()
            .for_each(|s| s.iter_mut().for_each(|b| *b = 0));
        Ok(out)
    }

    async fn cf_decrypt(_host: &str, command: &str, urls: &[String]) -> Result<Vec<CryptoResItem>> {
        let config =
            cf::load_config().context("SSH agent unavailable; CF passkey env not configured")?;

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
        // cached for this IP+pwd within the approved TTL). The full meta is sent
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
                Err(e) => out.push(CryptoResItem {
                    result: String::new(),
                    err_message: e,
                }),
                Ok(Item { t, salt, inner_ct }) => {
                    // Bounds-guard rather than index: open_sealed_deks already
                    // enforces deks.len() == salts.len(), but never let a short
                    // worker response panic the process here.
                    let dek = deks.get(dek_idx).ok_or_else(|| {
                        anyhow::anyhow!("internal: fewer DEKs returned than v2 records")
                    })?;
                    dek_idx += 1;
                    let res = match client_decrypt_v2(t, dek, &salt, &inner_ct) {
                        Ok(pt) => CryptoResItem {
                            result: pt,
                            err_message: String::new(),
                        },
                        Err(e) => CryptoResItem {
                            result: String::new(),
                            err_message: e.to_string(),
                        },
                    };
                    out.push(res);
                }
            }
        }
        Ok(out)
    }

    async fn cf_auth(reason: &str) -> Result<()> {
        let config =
            cf::load_config().context("SSH agent unavailable; CF passkey env not configured")?;
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
                    let res: RunRes =
                        serde_json::from_slice(&bytes).context("Failed to parse run response")?;
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
                    Ok(())
                }
                None => Self::cf_auth(reason).await,
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("vt auth requires Unix (SSH agent socket)"))
        }
    }
}

pub fn get_hostname() -> String {
    hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string()
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
        let e: anyhow::Error = VtClientError::Transport(anyhow::anyhow!("socket closed")).into();
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
}
