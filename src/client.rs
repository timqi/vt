//! Cross-platform vt client.
//!
//! Primary path: SSH agent via `$SSH_AUTH_SOCK` or `~/.ssh/vt.sock`.
//! Fallback path (Linux / macOS without agent): CF ceremony via
//! VT_PASSKEY_URL + VT_PASSKEY_TOKEN env vars — POST /api/challenge + WS /api/dek.

use std::env;
use std::io::{self, IsTerminal, Write};

use crate::cf;
use crate::core::crypto::{decode_auth_cipher_from_b64, AesGcmCrypto};
use crate::core::wire::{ErrKind, WIRE_VERSION};
use crate::core::{
    client_decrypt_v2, client_encrypt_v2, collapse_whitespace, has_vt_url, iter_vt_urls,
    redact_vt_urls, sanitize_for_display, AuthReq, AuthRes, ContextBasis, CryptoResItem,
    DecryptInput, DecryptReq, DecryptResItem, EncryptItem, EncryptReq, EncryptResItem, RunReq,
    RunRes, SecretType, SignReq, SignRes, VtUrl, SALT_LEN,
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
    debug!("Original command: {}", args.join(" "));
    // Display body shown on the Touch ID prompt, the approval page, and the
    // notifications. No `op:` header — the `cmd:`/`file:` lines themselves say
    // "inject" (`vt read` keeps its explicit `op: read`), and the surrounding
    // surface already names the operation (prompt header / 类型 field). The
    // command is shortened to basename + args and capped: a long absolute
    // argv[0] drowned the signal a human actually reads (operator feedback,
    // docs/approval-transparency.md §C5); the executable path was
    // client-claimed display data anyway, never a verified field.
    let mut lines: Vec<String> = Vec::new();
    if let Some(p) = replace_file.as_ref() {
        lines.push(format!("file: {}", sanitize_for_display(p, 100)));
    }
    let display_cmd = args
        .first()
        .map(|argv0| {
            std::iter::once(argv0.rsplit('/').next().unwrap_or(argv0))
                .chain(args[1..].iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let normalized = collapse_whitespace(&display_cmd);
    if normalized.is_empty() {
        lines.push("cmd: [no shell command]".to_string());
    } else {
        let redacted = redact_vt_urls(&normalized, "vt://***");
        lines.push(format!("cmd: {}", sanitize_for_display(&redacted, 160)));
    }
    if let Some(r) = reason {
        lines.push(format!("reason: {}", sanitize_for_display(r, 200)));
    }
    let original_command = lines.join("\n");

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
    // Exposure-overlap pre-checks, before the decrypt round trip spends a
    // Touch ID / phone approval. The O_EXCL backup create below (step 2) is
    // the authoritative, race-free gate; these two only fail earlier and
    // louder:
    //  - an existing backup means the target is mid-exposure (or a dead
    //    supervisor left it plaintext) — arming again would snapshot that
    //    plaintext as "ciphertext" and restore it permanently;
    //  - zero vt:// records means there is nothing to decrypt: either the
    //    wrong file, or plaintext left behind by a broken exposure.
    if let Some(file) = replace_file.as_ref() {
        let backup = exposure_backup_path(file)?;
        if backup.symlink_metadata().is_ok() {
            return Err(exposure_conflict_refusal(
                file,
                &backup,
                inject_state_dir().as_deref(),
            ));
        }
        if iter_vt_urls(&replace_file_content).next().is_none() {
            return Err(anyhow::anyhow!(
                "{} contains no vt:// records — nothing to decrypt. Was it \
                 left decrypted by another process, or is this the wrong file?",
                file
            ));
        }
    }

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
    //   2. Write a backup file alongside the target (ciphertext copy,
    //      O_CREAT|O_EXCL|O_NOFOLLOW, mode = orig) at the DETERMINISTIC
    //      per-target path `.{name}.vt-backup`. The backup doubles as the
    //      exposure lock (see `exposure_backup_path`): a second inject of the
    //      same target fails EEXIST here instead of snapshotting the exposed
    //      plaintext as its "ciphertext" backup — which its supervisor would
    //      later restore permanently.
    //   3. Spawn the detached supervisor before any plaintext can hit disk.
    //      Failure here deletes the backup and aborts — target stays ciphertext.
    //   4. Write the tmp file (plaintext, same hidden-name rules as backup).
    //   5. rename(tmp, target) — atomic plaintext exposure.
    //   6. Parent execs the user command; supervisor restores after timeout.
    //
    // Steps 4, 5, and 6 each call `restore_exposure` on failure so the
    // observable post-failure state normally collapses to "target =
    // ciphertext, no sidecars" without waiting for the supervisor — under
    // the same generation check the supervisor applies: a parent suspended
    // past its own window can resume to find the deterministic backup path
    // owned by a NEWER exposure, whose backup a blind rename would consume.
    // The supervisor is the durable backstop: even if a parent crash makes
    // the fast path unreachable, the supervisor's `unlink(tmp) +
    // rename(backup, target)` after timeout still brings everything home
    // (modulo SIGKILL / reboot).
    let armed: Option<ArmedExposure> = if let Some(replace_file_path) = &replace_file {
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
        // Backup: deterministic per-target name (the exposure lock). Tmp and
        // sidecar keep the random suffix — the tmp is consumed by rename()
        // within this function and a leftover must not block the next inject.
        let backup_path = exposure_backup_path(replace_file_path)?;
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
        // The backup fd also yields the (dev, ino) generation id for the
        // sidecar, binding the record to THIS backup — the deterministic
        // path alone is ambiguous across exposures of the same target.
        let backup_id: (u64, u64) =
            match create_exposure_backup(&backup_path, &orig_file_bytes, orig_mode) {
                Ok(id) => id,
                // EEXIST: another exposure of this target is open (or a dead
                // supervisor left one). The pre-decrypt check already refused
                // the common case; this is the authoritative race-free gate.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(exposure_conflict_refusal(
                        replace_file_path,
                        &backup_path,
                        inject_state_dir().as_deref(),
                    ));
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to write backup file: {}", backup_path.display())
                    });
                }
            };
        debug!("Created backup at: {}", backup_path.display());

        // Holding the exposure lock proves any older sidecar naming this
        // backup path is stale; retire it before a concurrent `--recover`
        // can pair its expired deadline with the backup just created.
        retire_stale_sidecars_for(&backup_path, inject_state_dir().as_deref());

        // Step 3: arm supervisor before any plaintext touches disk.
        match spawn_restore_supervisor(
            timeout,
            &tmp_path,
            &backup_path,
            replace_file_path,
            &sidecar_path,
            backup_id,
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
            backup_id: Some(backup_id),
        };
        if let Err(e) = write_inject_sidecar(&sidecar_path, &sidecar) {
            // Loud on stderr, not debug!: the user is about to expose
            // plaintext with no reboot recovery for it.
            eprintln!(
                "vt inject: warning: crash-recovery sidecar not written ({e:#}); \
                 a crash or reboot during this window will NOT be auto-restored"
            );
        }

        // Step 4: write tmp (plaintext). Parent-side cleanup here (and in
        // steps 5/6) normally leaves no visible sidecar state for the
        // timeout window; the supervisor later observes ENOENT on the
        // backup and exits silently.
        if let Err(e) = write_plaintext_tmp(&tmp_path, orig_mode, &decrypted_file_content) {
            restore_exposure(
                &tmp_path,
                &backup_path,
                std::path::Path::new(replace_file_path),
                &sidecar_path,
                backup_id,
            );
            return Err(e);
        }

        // Step 5: atomically expose plaintext at target.
        if let Err(e) = std::fs::rename(&tmp_path, replace_file_path) {
            restore_exposure(
                &tmp_path,
                &backup_path,
                std::path::Path::new(replace_file_path),
                &sidecar_path,
                backup_id,
            );
            return Err(e).with_context(|| {
                format!("Failed to atomically replace file: {}", replace_file_path)
            });
        }
        debug!("Content written to replace file: {}", replace_file_path);

        Some(ArmedExposure {
            target: replace_file_path.clone(),
            backup: backup_path,
            tmp: tmp_path,
            sidecar: sidecar_path,
            backup_id,
        })
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

    // Restore on exec failure so the user doesn't wait out the
    // supervisor's timeout. The supervisor will later observe ENOENT on the
    // backup and exit silently.
    if let Some(a) = &armed {
        restore_exposure(
            &a.tmp,
            &a.backup,
            std::path::Path::new(&a.target),
            &a.sidecar,
            a.backup_id,
        );
    }
    Err(anyhow::anyhow!("Failed to execute command: {}", err))
}

/// One armed exposure's unwind state, kept by the parent for the exec-failure
/// path — the same tuple the supervisor got via argv at spawn.
struct ArmedExposure {
    target: String,
    backup: std::path::PathBuf,
    tmp: std::path::PathBuf,
    sidecar: std::path::PathBuf,
    backup_id: (u64, u64),
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
    /// `(st_dev, st_ino)` of the backup at creation — the generation id that
    /// distinguishes THIS exposure's backup from a successor at the same
    /// deterministic path. `None` on records written by builds without the
    /// id; those keep existence-only matching.
    #[serde(default)]
    backup_id: Option<(u64, u64)>,
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
/// `backup_survives` must be the GENERATION-CHECKED answer from
/// [`probe_sidecar_backup`], not bare existence: the deterministic backup
/// path is reused by every exposure of a target.
fn plan_recovery(deadline_ms: u64, backup_survives: bool, now_ms: u64) -> Option<RecoverAction> {
    if !backup_survives {
        // The supervisor (or the parent's fast path) already renamed the
        // backup over the target — or the path now holds a NEWER exposure's
        // backup (generation mismatch). Either way this sidecar's injection
        // is over; only the sidecar lingers.
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
    // Same bound as read_sidecar_bounded: writing a record recovery would
    // later skip as unreadable is worse than writing none — the operator
    // would believe crash recovery exists when it doesn't.
    ensure!(
        json.len() as u64 <= SIDECAR_MAX_BYTES,
        "inject sidecar would be {} bytes, over the {} byte cap recovery reads",
        json.len(),
        SIDECAR_MAX_BYTES
    );
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

// ── Per-target exposure lock ────────────────────────────────────────────────
//
// Overlapping `inject -r` runs on the same target are unsafe by construction:
// the second run would read the first run's exposed plaintext, snapshot it as
// its "ciphertext" backup, and its supervisor — firing last — would rename
// that plaintext back over the target permanently, with no sidecar or backup
// left for `--recover` to find. The lock that prevents this is the backup
// file itself: its name is deterministic per target, it is created O_EXCL
// before any plaintext hits disk (and removed if filling it fails — a
// partial copy must not read as a lock), and it is consumed by rename() on
// every restore path (supervisor, parent failure paths, --recover). Its
// existence therefore means exactly "an exposure window is open, or a dead
// supervisor left the target plaintext" — and a new inject must refuse.
//
// The sidecar shares the path's ambiguity in the other direction: it records
// the deterministic backup path, so a stale record (crash between a restore's
// rename() and the sidecar's removal) must never be matched against a LATER
// exposure's backup — and no restore path may consume one. Four complementary
// guards enforce that: arming retires matching stale sidecars while the lock
// is held; every new sidecar MUST carry its backup's (dev, ino) generation
// id, verified before recovery consumes anything; recovery refuses any
// backup modified past the record's deadline — the ordering bound that
// covers id-less legacy records and a successor reusing the old inode;
// and every restorer re-checks the (dev, ino) it armed for before renaming
// (see `restore_exposure` — a suspend can delay the supervisor's monotonic
// sleep, or stop the parent short of its failure path, past the wall-clock
// deadline, letting --recover and a new exposure run first).

/// Deterministic ciphertext-backup path for `target`: `dir/.{name}.vt-backup`.
/// Deliberately NOT randomized — see the module comment above. Restore paths
/// must keep consuming it via rename(), never copy+delete (a copy would leave
/// the lock behind or release it before the target is ciphertext again).
fn exposure_backup_path(target: &str) -> Result<std::path::PathBuf> {
    let orig_path = std::path::Path::new(target);
    let dir = orig_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = orig_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid replace file path: {}", target))?
        .to_string_lossy()
        .into_owned();
    Ok(dir.join(format!(".{}.vt-backup", file_name)))
}

/// Create the exposure-lock backup (O_CREAT|O_EXCL|O_NOFOLLOW, `mode`), fill
/// it with the ciphertext `bytes`, and return its `(dev, ino)` generation id.
/// On any failure AFTER the exclusive create — a partial write (ENOSPC/EIO)
/// or the generation-id stat — the just-created file is removed before
/// returning: a partial backup with no sidecar and no supervisor would read
/// as an untracked exposure lock to the next inject, whose refusal guidance
/// would then move truncated bytes over the intact ciphertext target. No
/// plaintext exists yet at that point, so aborting (releasing the lock) is
/// safe. The EEXIST failure propagates untouched and must NEVER remove: that
/// file is another exposure's live lock (or its orphaned backup).
///
/// The generation id is REQUIRED on new records: silently degrading to None
/// would put recovery back on existence-only matching and reopen the
/// stale-sidecar race.
fn create_exposure_backup(
    backup_path: &std::path::Path,
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(backup_path)?;
    let filled = f.write_all(bytes).and_then(|()| {
        f.sync_all().ok();
        f.metadata().map(|m| (m.dev(), m.ino()))
    });
    if filled.is_err() {
        let _ = std::fs::remove_file(backup_path);
    }
    filled
}

/// Why an inject over an existing backup was refused — picks the operator
/// guidance in the refusal message.
#[derive(Debug, PartialEq, Eq)]
enum ExposureConflict {
    /// A supervisor is presumed alive; the window ends in ~`remaining_s`.
    Live { remaining_s: u64 },
    /// Deadline + grace elapsed with the backup still present: the supervisor
    /// died and the target may still be plaintext.
    Orphaned,
    /// No sidecar records this backup (its write failed, or it was cleaned);
    /// manual restore is the only guidance left.
    Untracked,
}

/// Pure classification of an exposure conflict from the sidecar (if one still
/// records the colliding backup) and the clock. Mirrors [`plan_recovery`]'s
/// liveness rule: within deadline + grace the supervisor is presumed alive.
fn classify_exposure_conflict(sidecar: Option<&InjectSidecar>, now_ms: u64) -> ExposureConflict {
    match sidecar {
        Some(sc) if now_ms < sc.deadline_ms.saturating_add(RECOVER_GRACE_MS) => {
            ExposureConflict::Live {
                remaining_s: sc.deadline_ms.saturating_sub(now_ms).div_ceil(1000),
            }
        }
        Some(_) => ExposureConflict::Orphaned,
        None => ExposureConflict::Untracked,
    }
}

/// What the sidecar's recorded backup path currently holds.
#[derive(Debug, PartialEq, Eq)]
enum BackupProbe {
    /// The exact generation the sidecar recorded — safe to restore.
    Ours,
    /// Consumed, or replaced by a successor generation: this exposure is
    /// settled and only the sidecar lingers.
    Gone,
    /// The stat failed for a reason other than "not there" (EACCES, EIO, a
    /// sick mount): the truth is unknowable right now. Callers must KEEP the
    /// sidecar and retry later — deleting it would silently turn a transient
    /// error into permanently unrecoverable exposed plaintext.
    Unknown,
}

/// Probe whether the sidecar's recorded backup still exists AS THE GENERATION
/// THE SIDECAR RECORDED. The backup path is deterministic per target, so bare
/// existence is ambiguous: a stale sidecar (crash between a restore's
/// rename() and its own removal) sees the path recreated by the target's
/// NEXT exposure, and acting on the old deadline would consume that newer
/// exposure's backup — early-restoring ciphertext mid-window at best,
/// stranding plaintext with no backup at worst. The `(dev, ino)` id
/// disambiguates, backed by an mtime ordering bound: a legitimate backup is
/// written BEFORE its sidecar's deadline is even computed (deadline = arm
/// time + timeout), so a backup modified after the deadline is a successor.
/// The bound is the only generation signal an id-less legacy record has —
/// it cannot catch a successor created before the deadline; arm-time
/// retirement covers those — and the guard against a successor reusing the
/// old inode.
fn probe_sidecar_backup(sc: &InjectSidecar) -> BackupProbe {
    use std::os::unix::fs::MetadataExt;
    let md = match std::fs::symlink_metadata(&sc.backup) {
        Ok(md) => md,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return BackupProbe::Gone;
        }
        Err(_) => return BackupProbe::Unknown,
    };
    // Generation id (always present on new records) must match.
    if let Some((dev, ino)) = sc.backup_id {
        if md.dev() != dev || md.ino() != ino {
            return BackupProbe::Gone;
        }
    }
    match md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
    {
        Some(mtime) if (mtime.as_millis() as u64) > sc.deadline_ms => BackupProbe::Gone,
        // At/before the deadline — or no mtime available, where we skip the
        // ordering bound rather than strand a genuine record (the id check
        // above still applies to new records).
        _ => BackupProbe::Ours,
    }
}

/// Upper bound for one sidecar read AND write. Sized so no legitimate record
/// is ever refused — three PATH_MAX (4096 on Linux) paths under worst-case
/// `\uXXXX` JSON escaping is ~72 KiB — while still bounding what a planted
/// file can make the refusal-path scan read. [`write_inject_sidecar`]
/// enforces the same limit, so a record recovery would skip as unreadable is
/// refused loudly at arm time (before plaintext exposure) instead.
const SIDECAR_MAX_BYTES: u64 = 128 * 1024;

/// Read and parse one sidecar file defensively: O_NOFOLLOW + O_NONBLOCK so a
/// planted symlink or FIFO can't redirect or hang the scan, a regular-file
/// check before reading, and a hard size cap. Needed because the refusal-path
/// scan can run over the TARGET's own directory (the no-home-dir fallback
/// sidecar lives there), which may be shared and attacker-writable — unlike
/// the 0700 state dir. `None` for anything unreadable or not sidecar-shaped.
fn read_sidecar_bounded(path: &std::path::Path) -> Option<InjectSidecar> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || md.len() > SIDECAR_MAX_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    // Cap the read too — fstat can't bind a file that grows after the check.
    f.take(SIDECAR_MAX_BYTES).read_to_end(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// Best-effort scan of `dir` for the sidecar recording `backup` — the CURRENT
/// generation of it, per [`probe_sidecar_backup`], so a stale record from
/// an earlier exposure of the same target can't hijack the classification.
/// Unreadable entries are skipped: this only upgrades the quality of a
/// refusal message, never gates the refusal itself.
fn find_sidecar_for_backup(
    dir: &std::path::Path,
    backup: &std::path::Path,
) -> Option<InjectSidecar> {
    let want = absolutize(backup);
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(sc) = read_sidecar_bounded(&path) {
            // Unknown reads as no-match: this scan only picks a refusal
            // message, and the conservative fallback is manual guidance.
            if std::path::Path::new(&sc.backup) == want.as_path()
                && probe_sidecar_backup(&sc) == BackupProbe::Ours
            {
                return Some(sc);
            }
        }
    }
    None
}

/// Retire state-dir sidecars that record `backup` as their ciphertext backup.
/// Called right after the O_EXCL backup create — holding the exposure lock
/// proves the target has no open exposure, so any sidecar still naming this
/// deterministic path is stale (a crash landed between a restore's rename()
/// and the sidecar's removal). Left in place, its long-expired deadline would
/// tell a concurrent `--recover` to consume the backup just created. Best
/// effort, and complementary to the generation id: the sweep also covers the
/// (filesystem-dependent) case of the new backup reusing the old inode, while
/// the id covers a `--recover` that read the stale record before this sweep.
fn retire_stale_sidecars_for(backup: &std::path::Path, state_dir: Option<&std::path::Path>) {
    let Some(dir) = state_dir else { return };
    let want = absolutize(backup);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(sc) = read_sidecar_bounded(&path) {
            if std::path::Path::new(&sc.backup) == want.as_path() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Build the refusal error for a colliding backup at `backup`. Consults the
/// sidecar in `state_dir` — falling back to the target's own directory, where
/// the no-home-dir fallback sidecar lives — purely to pick the guidance.
/// `--recover` sweeps only the state dir, so orphan guidance may name it only
/// for a sidecar found there; a fallback-dir orphan gets the manual restore.
fn exposure_conflict_refusal(
    target: &str,
    backup: &std::path::Path,
    state_dir: Option<&std::path::Path>,
) -> anyhow::Error {
    let (sidecar, in_recover_reach) =
        match state_dir.and_then(|d| find_sidecar_for_backup(d, backup)) {
            Some(sc) => (Some(sc), true),
            None => (
                backup
                    .parent()
                    .and_then(|d| find_sidecar_for_backup(d, backup)),
                false,
            ),
        };
    match classify_exposure_conflict(sidecar.as_ref(), now_ms()) {
        ExposureConflict::Live { remaining_s } => anyhow::anyhow!(
            "{} is mid-exposure by another vt inject (auto-restore in ~{}s); \
             retry after the window closes",
            target,
            remaining_s
        ),
        ExposureConflict::Orphaned if in_recover_reach => anyhow::anyhow!(
            "a previous exposure of {} was never restored (its supervisor is \
             gone) and the file may still be plaintext; run `vt inject \
             --recover` first",
            target
        ),
        // Orphaned, but the record lives beside the target (written when no
        // home dir was resolvable) where `--recover` never looks: naming
        // --recover here would end in "nothing to recover" while the
        // plaintext stays. Manual restore is the only honest guidance.
        ExposureConflict::Orphaned => anyhow::anyhow!(
            "a previous exposure of {} was never restored (its supervisor is \
             gone) and the file may still be plaintext; verify the file's \
             state, then restore the ciphertext manually: mv '{}' '{}'",
            target,
            backup.display(),
            target
        ),
        ExposureConflict::Untracked => anyhow::anyhow!(
            "found leftover backup {} for {}; verify the file's state, then \
             restore the ciphertext manually: mv '{}' '{}'",
            backup.display(),
            target,
            backup.display(),
            target
        ),
    }
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
        let sc: InjectSidecar = match read_sidecar_bounded(&path) {
            Some(sc) => sc,
            None => {
                eprintln!("vt inject --recover: skipping unreadable sidecar {}", path.display());
                continue;
            }
        };
        let backup_survives = match probe_sidecar_backup(&sc) {
            BackupProbe::Ours => true,
            BackupProbe::Gone => false,
            // Transient stat failure: leave the record for a later sweep —
            // cleaning it now could orphan exposed plaintext whose backup
            // still exists behind the error.
            BackupProbe::Unknown => {
                eprintln!(
                    "vt inject --recover: cannot stat backup {}; leaving {} for a later sweep",
                    sc.backup,
                    path.display()
                );
                active += 1;
                continue;
            }
        };
        match plan_recovery(sc.deadline_ms, backup_survives, now) {
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
    backup_id: (u64, u64),
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
        .arg(format!("{}:{}", backup_id.0, backup_id.1))
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

// ---------------------------------------------------------------------------
// vt doctor — read-only diagnosis of config, routing, and agent cache behavior
// ---------------------------------------------------------------------------

/// Outcome of the dedicated `diag@vt` call. Unlike [`VTClient::try_agent_extension`],
/// the wire shapes stay distinct (see `docs/diag-design.md` §4): an agent that
/// merely *ignores* the unknown extension name (an older vt agent) answers SSH
/// success with an empty payload, which is a different signal from an explicit
/// `SSH_AGENT_FAILURE` (non-vt agent, wrong VT_AUTH, or a locked agent).
#[cfg(unix)]
enum DiagOutcome {
    /// Socket missing/refused — no agent at all.
    NoSocket,
    /// SSH success, empty extension payload: the agent ignored `diag@vt`.
    TooOld,
    /// Explicit failure or an error envelope, with a display string.
    Refused(String),
    /// The agent answered a valid OK envelope whose body doesn't parse as
    /// `DiagRes` — client/agent version skew, not a transport problem.
    Skew(String),
    Report(Box<crate::core::DiagRes>),
}

/// Read/write timeout for the diag round-trip. Every other agent call must
/// wait indefinitely for a human Touch ID; diag@vt is interaction-free by
/// design, so a hung or foreign agent must not hang the doctor.
#[cfg(unix)]
const DIAG_SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(unix)]
fn call_diag(auth_token: &str) -> Result<DiagOutcome> {
    let stream = match VTClient::connect_agent_socket()? {
        Some(s) => s,
        None => return Ok(DiagOutcome::NoSocket),
    };
    stream.set_read_timeout(Some(DIAG_SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(DIAG_SOCKET_TIMEOUT))?;
    let auth_key = decode_auth_cipher_from_b64(auth_token)?;
    let auth_cipher = AesGcmCrypto::new(&auth_key)?;
    let payload = serde_json::to_vec(&crate::core::DiagReq::default())?;
    let ext = Extension {
        name: "diag@vt".to_string(),
        details: Unparsed::from(auth_cipher.encrypt(&payload)?),
    };
    let mut client = ssh_agent_lib::blocking::Client::new(stream);
    match client.extension(ext) {
        Err(e) => Ok(DiagOutcome::Refused(e.to_string())),
        Ok(None) => Ok(DiagOutcome::TooOld),
        Ok(Some(resp)) => {
            let envelope = match auth_cipher.decrypt(resp.details.as_ref()) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DiagOutcome::Refused(
                        "response did not decrypt under VT_AUTH".to_string(),
                    ))
                }
            };
            match parse_envelope(&envelope) {
                Ok(body) => match serde_json::from_slice(&body) {
                    Ok(res) => Ok(DiagOutcome::Report(Box::new(res))),
                    Err(e) => Ok(DiagOutcome::Skew(e.to_string())),
                },
                Err(e) => Ok(DiagOutcome::Refused(e.to_string())),
            }
        }
    }
}

/// Map a `ContextBasis` wire tag to an operator-facing explanation. Unknown
/// tags (a newer agent) degrade to naming the tag. The known-tag sentences
/// live on [`ContextBasis::human`] in core, next to `as_wire`, so adding an
/// agent-side variant forces the client sentence at compile time.
fn basis_human(tag: &str) -> String {
    match ContextBasis::from_wire(tag) {
        Some(basis) => basis.human().to_string(),
        None => format!("unknown basis '{}' (newer agent?)", tag),
    }
}

fn doctor_redact(key: &str, value: &str) -> String {
    // Bearer secrets: presence + length is enough to diagnose; showing a
    // prefix in terminal scrollback helps nobody.
    if matches!(key, "VT_AUTH" | "VT_PASSKEY_TOKEN") {
        return format!("set (len {})", value.len());
    }
    // Named PRIVATE_KEY: expected to hold a vt:// ciphertext record — safe to
    // acknowledge, never to echo. If it holds anything else the user has put
    // key material (or garbage) in it; either way don't print a prefix.
    if key == "VT_GIT_SSH_PRIVATE_KEY" {
        return if value.starts_with("vt://") {
            format!("set (vt:// record, len {})", value.len())
        } else {
            format!(
                "set (len {}) ⚠ not a vt:// record — value not shown; \
                 `vt ssh keygen` produces the expected format",
                value.len()
            )
        };
    }
    // Non-secrets: strip control chars (terminal-escape hygiene, same as
    // every other display surface) and truncate char-safely.
    let shown = sanitize_for_display(value, 60);
    if value.chars().count() > 60 {
        format!("{} (len {})", shown, value.len())
    } else {
        shown
    }
}

/// `vt doctor`: diagnose config sources, transport routing, and (when an
/// agent is reachable) cache behavior via `diag@vt`. Read-only, never
/// hard-fails on findings — always exits 0; see `docs/diag-design.md`.
pub async fn doctor(auth_token: &str, file_populated_keys: &[String]) -> Result<()> {
    println!("vt doctor — vt {}", env!("VT_VERSION"));

    // ── 1. Config ─────────────────────────────────────────────────────────
    println!("\nConfig (env beats config.toml):");
    match crate::config::config_path() {
        Some(path) if path.exists() => {
            println!("  file: {}", path.display());
            if let Some(mode) = crate::config::insecure_config_mode(&path) {
                println!(
                    "  ⚠ file is group/other accessible (mode {:o}); it holds \
                     secrets — run: chmod 600 {}",
                    mode,
                    path.display()
                );
            }
        }
        Some(path) => println!("  file: {} (absent — env vars only)", path.display()),
        None => println!("  file: none (no home directory and no $VT_CONFIG)"),
    }
    const DOCTOR_KEYS: &[&str] = &[
        "VT_BACKEND",
        "VT_AUTH",
        "VT_PASSKEY_URL",
        "VT_PASSKEY_TOKEN",
        "VT_GIT_SSH_PRIVATE_KEY",
        "VT_GIT_SSH_PUB",
        "VT_AGENT_CONFIG",
    ];
    for key in DOCTOR_KEYS {
        match env::var(key) {
            Ok(v) => {
                let source = if file_populated_keys.iter().any(|k| k == key) {
                    "config.toml"
                } else {
                    "env"
                };
                if v.is_empty() {
                    println!("  {:24} set but EMPTY ({})", key, source);
                } else {
                    println!("  {:24} {} ({})", key, doctor_redact(key, &v), source);
                }
            }
            Err(_) => println!("  {:24} unset", key),
        }
    }
    // A typo'd key (VT_PASKEY_URL…) hydrates silently and is the single most
    // likely config bug this command is run to find — surface names only.
    let unrecognized: Vec<&str> = file_populated_keys
        .iter()
        .map(String::as_str)
        .filter(|k| !DOCTOR_KEYS.contains(k))
        .collect();
    if !unrecognized.is_empty() {
        println!(
            "  ⚠ config.toml also sets: {} — not a key vt doctor knows; \
             check for typos",
            unrecognized.join(", ")
        );
    }

    // ── 2. Routing ────────────────────────────────────────────────────────
    // NOTE: mirrors VTClient::new (validation) + agent_call_or_fallback
    // (fallback gating: recoverable agent errors ALWAYS fall back under
    // auto, regardless of whether the passkey path is configured). When
    // changing either, keep this report in lockstep.
    println!("\nRouting:");
    let has_auth = !auth_token.is_empty();
    let has_passkey_url = env::var("VT_PASSKEY_URL").is_ok();
    let has_passkey_token = env::var("VT_PASSKEY_TOKEN").is_ok();
    let passkey_state = match (has_passkey_url, has_passkey_token) {
        (true, true) => "configured",
        (true, false) => "incomplete (VT_PASSKEY_TOKEN unset)",
        (false, true) => "incomplete (VT_PASSKEY_URL unset)",
        (false, false) => "unconfigured",
    };
    match crate::config::Backend::from_env() {
        Err(e) => println!("  ⚠ {}", e),
        Ok(crate::config::Backend::Agent) => {
            if has_auth {
                println!("  VT_BACKEND=agent: SSH agent only, no passkey fallback");
            } else {
                println!("  ⚠ VT_BACKEND=agent but VT_AUTH is unset — every call will fail");
            }
        }
        Ok(crate::config::Backend::Passkey) => {
            // Same precondition VTClient::new enforces (URL only) — plus the
            // token warning it defers to ceremony time.
            if !has_passkey_url {
                println!(
                    "  ⚠ VT_BACKEND=passkey but VT_PASSKEY_URL is unset — every call will fail"
                );
            } else if !has_passkey_token {
                println!(
                    "  VT_BACKEND=passkey: phone ceremony only — ⚠ VT_PASSKEY_TOKEN unset, \
                     ceremonies will fail"
                );
            } else {
                println!("  VT_BACKEND=passkey: phone ceremony only, agent never probed");
            }
        }
        Ok(crate::config::Backend::Auto) => match (has_auth, has_passkey_url && has_passkey_token)
        {
            (true, true) => println!(
                "  auto: try SSH agent first, fall back to phone passkey on \
                 recoverable errors"
            ),
            (true, false) => println!(
                "  auto: SSH agent first; recoverable agent errors still fall back \
                 to the passkey path, which is {} and will error there",
                passkey_state
            ),
            (false, true) => println!("  auto: phone passkey only (VT_AUTH unset — agent skipped)"),
            (false, false) => println!(
                "  ⚠ no usable path: VT_AUTH unset and passkey {} — vt commands \
                 needing auth will fail",
                passkey_state
            ),
        },
    }

    // ── 3. Agent (diag@vt) ────────────────────────────────────────────────
    println!("\nAgent:");
    let socket = env::var("SSH_AUTH_SOCK")
        .unwrap_or_else(|_| "~/.ssh/vt.sock (default; $SSH_AUTH_SOCK unset)".to_string());
    println!("  socket: {}", socket);
    #[cfg(unix)]
    if !has_auth {
        println!("  agent path disabled (VT_AUTH unset) — diag@vt skipped");
    } else {
        let token = auth_token.to_string();
        // Never hard-fail the report (doctor's contract): a panicked probe
        // (outer Err) is itself a finding, printed like any other.
        match tokio::task::spawn_blocking(move || call_diag(&token))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r)
        {
            Err(e) => println!("  ⚠ diag@vt transport error: {}", e),
            Ok(DiagOutcome::NoSocket) => {
                println!("  no agent listening (socket missing or connection refused)")
            }
            Ok(DiagOutcome::TooOld) => println!(
                "  agent reachable but ignored diag@vt — a vt agent older than \
                 this client (rebuild/restart it), or a non-vt agent"
            ),
            Ok(DiagOutcome::Refused(e)) => println!(
                "  agent refused diag@vt ({}). Likely causes: a `vt ssh connect` \
                 relay running without --forward-real-agent (or built before \
                 diag@vt existed), a non-vt agent, wrong VT_AUTH, an agent \
                 locked via ssh-add -x, or a dropped connection",
                e
            ),
            Ok(DiagOutcome::Skew(e)) => println!(
                "  agent answered but the reply didn't parse as a diag report \
                 ({}) — client/agent version skew; rebuild both from the same \
                 commit",
                e
            ),
            Ok(DiagOutcome::Report(d)) => {
                println!("  agent version: {}", d.agent_version);
                // The agent is a long-lived daemon and does not restart on CLI
                // upgrade — skew is common right after an update and changes
                // scope/diag behavior silently.
                if d.agent_version != env!("VT_VERSION") {
                    println!(
                        "  ⚠ agent is {}, this client is {} — restart the agent \
                         (`vt ssh agent`) so both run the same build",
                        d.agent_version,
                        env!("VT_VERSION")
                    );
                }
                // Over --forward-real-agent the upstream agent's peer is the
                // relay process on the agent's host — that IS the connection
                // relayed requests ride, so label it honestly.
                let peer_label = if d.peer.is_vt_relay {
                    "peer (the relay process on the agent host)"
                } else {
                    "peer (this process)"
                };
                println!(
                    "  {}: pid {}, exe {}, tty {}, ssh-client {}, vt-relay {}",
                    peer_label,
                    d.peer.pid.map_or("?".to_string(), |p| p.to_string()),
                    d.peer.exe.as_deref().unwrap_or("?"),
                    if d.peer.has_tty { "yes" } else { "no" },
                    if d.peer.is_ssh_client { "yes" } else { "no" },
                    if d.peer.is_vt_relay { "yes" } else { "no" },
                );
                for (label, c) in [("sign", &d.sign_cache), ("decrypt", &d.decrypt_cache)] {
                    println!(
                        "  {:8} ttl {}s, live grants (this caller): {}",
                        format!("{}:", label),
                        c.ttl_secs,
                        c.live_entries
                    );
                    println!("           → {}", basis_human(&c.context_basis));
                }
                println!(
                    "  run@vt: {}; audit push: {}",
                    if d.run_allow_len == 0 {
                        "disabled".to_string()
                    } else {
                        format!("{} allowlist entries", d.run_allow_len)
                    },
                    if d.audit_push { "on" } else { "off" }
                );
                println!(
                    "  (classification applies to connections opened the way this \
                     one was; a different launcher may classify differently)"
                );
            }
        }
    }

    // ── 4. Worker ─────────────────────────────────────────────────────────
    println!("\nWorker:");
    match env::var("VT_PASSKEY_URL") {
        Err(_) => println!("  not configured (VT_PASSKEY_URL unset)"),
        Ok(url) => {
            // Doctor never hard-fails: a TLS-init error is reported, not raised.
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Err(e) => println!("  ⚠ could not build HTTP client: {}", e),
                Ok(client) => match client.get(&url).send().await {
                    Ok(resp) => {
                        println!("  {} reachable (HTTP {})", url, resp.status().as_u16())
                    }
                    Err(e) => println!("  ⚠ {} unreachable: {}", url, e),
                },
            }
            if env::var("VT_PASSKEY_TOKEN").is_err() {
                println!("  ⚠ VT_PASSKEY_URL set but VT_PASSKEY_TOKEN unset");
            }
        }
    }

    Ok(())
}

/// Parse the supervisor's `dev:ino` argv token — the generation id of the
/// backup it armed for.
fn parse_dev_ino(s: &str) -> Option<(u64, u64)> {
    let (dev, ino) = s.split_once(':')?;
    Some((dev.parse().ok()?, ino.parse().ok()?))
}

/// The generation-checked restore shared by the supervisor (its post-sleep
/// body, extracted so tests can drive it without fork/sleep) and the parent's
/// step-4/5/6 failure paths. `armed_id` is the `(dev, ino)` of the backup
/// this caller armed. The backup path is deterministic per target, so a
/// DELAYED caller — a supervisor whose monotonic sleep a suspend paused while
/// the wall-clock deadline lapsed, or a parent stopped between arming and its
/// failure path — can find `--recover` already consumed its backup and a
/// NEWER exposure owning the path; renaming blindly would consume the
/// successor's backup — early-restoring its ciphertext mid-window, or
/// stranding its plaintext with no restore source if it hasn't renamed its
/// tmp yet. So: restore only our own generation, and keep the sidecar —
/// `--recover`'s retry record — on a real rename failure or when the backup's
/// state is unknowable (stat error other than "not there").
///
/// Failure warnings go to stderr: user-visible on the parent paths, /dev/null
/// in the supervisor.
///
/// Known, accepted residuals: (a) a successor reusing our exact inode is
/// indistinguishable here — unlike `--recover` we know no deadline to bound
/// mtime by; (b) the stat→rename pair is not atomic, so a window of
/// microseconds remains in which `--recover` consuming the verified backup
/// AND a new inject recreating the path would misdirect the rename. Both
/// events landing inside that window is negligible; absolute closure would
/// need every consumer to serialize on a parent-directory flock.
fn restore_exposure(
    tmp: &std::path::Path,
    backup: &std::path::Path,
    target: &std::path::Path,
    sidecar: &std::path::Path,
    armed_id: (u64, u64),
) {
    use std::os::unix::fs::MetadataExt;
    // Wipe any orphaned plaintext tmp first. If the parent crashed between
    // write_plaintext_tmp and rename(tmp,target), this is the only path that
    // removes it. Random-suffixed per run, so never another run's tmp.
    let _ = std::fs::remove_file(tmp);
    let ours = match std::fs::symlink_metadata(backup) {
        Ok(md) => md.dev() == armed_id.0 && md.ino() == armed_id.1,
        // Gone: the parent (or --recover) already restored this exposure.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            false
        }
        // Transient stat failure (EACCES, EIO, a sick mount): the truth is
        // unknowable — keep the backup AND the sidecar so `vt inject
        // --recover` retries once the path is reachable again.
        Err(e) => {
            eprintln!(
                "vt inject: cannot stat backup {}: {}; leaving it for `vt inject --recover`",
                backup.display(),
                e
            );
            return;
        }
    };
    if !ours {
        // Nothing of ours left at the path — the exposure is settled. The
        // sidecar (per-run random name, always ours) is stale; drop it.
        let _ = std::fs::remove_file(sidecar);
        return;
    }
    match std::fs::rename(backup, target) {
        Ok(()) => {
            let _ = std::fs::remove_file(sidecar);
        }
        // Consumed between the check and the rename: --recover won the race
        // and the exposure is settled — same as the gone case above.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(sidecar);
        }
        // Real failure (EACCES, EIO, ...): keep the sidecar so a later
        // `vt inject --recover` retries the restore we could not perform.
        Err(e) => {
            eprintln!(
                "vt inject: restore failed: {}; backup remains at {}",
                e,
                backup.display()
            );
        }
    }
}

/// Pre-tokio, pre-clap entry point for the detached restore supervisor.
/// Dispatched from `main()` so this process never builds a tokio runtime,
/// parses clap definitions, or loads tracing — its RSS is just vt's text
/// segment (shared with the parent via page cache) + a few KB of heap.
///
/// Args (after the SUPERVISOR_SUBCOMMAND marker):
/// `<secs> <tmp> <backup> <target> <sidecar> <dev>:<ino>`.
pub fn supervisor_main(args: &[std::ffi::OsString]) -> i32 {
    // Stdio is /dev/null — any failure here is invisible to the user. Parent
    // distinguishes the intermediate's success (exit 0 after double-fork)
    // from any failure (non-zero) via Child::wait().
    if args.len() != 6 {
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
    let armed_id = match args[5].to_str().and_then(parse_dev_ino) {
        Some(id) => id,
        None => return 2,
    };

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
    // only async-signal-safe code below (thread::sleep, stat, remove_file,
    // rename — all of which are async-signal-safe at the syscall level). The
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

    restore_exposure(&tmp, &backup, &target, &sidecar, armed_id);
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

    // ── vt doctor ────────────────────────────────────────────────────────

    #[test]
    fn doctor_redact_hides_secrets_and_truncates_on_char_boundaries() {
        // Bearer secrets never echo their value.
        let r = doctor_redact("VT_AUTH", "supersecrettoken");
        assert!(!r.contains("supersecret"), "got {r}");
        assert!(r.contains("len 16"));
        // The private-key slot acknowledges a vt:// record but never echoes
        // the value — not even a prefix — when it holds anything else.
        let r = doctor_redact("VT_GIT_SSH_PRIVATE_KEY", "vt://0abcdef");
        assert!(r.contains("vt:// record"), "got {r}");
        assert!(!r.contains("abcdef"), "got {r}");
        let raw_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA";
        let r = doctor_redact("VT_GIT_SSH_PRIVATE_KEY", raw_key);
        assert!(!r.contains("BEGIN"), "must not echo key material, got {r}");
        assert!(r.contains("not a vt:// record"), "got {r}");
        // Long non-secrets truncate by CHARS, not bytes — a multi-byte char
        // spanning the cut must not panic — and control chars are stripped
        // (terminal-escape hygiene via sanitize_for_display).
        let long = "变".repeat(61);
        let r = doctor_redact("VT_GIT_SSH_PUB", &long);
        assert!(r.ends_with(&format!("… (len {})", long.len())));
        assert_eq!(r.chars().take_while(|c| *c == '变').count(), 60);
        assert_eq!(doctor_redact("VT_BACKEND", "au\x1b[31mto"), "au[31mto");
        // Short values pass through verbatim.
        assert_eq!(doctor_redact("VT_BACKEND", "auto"), "auto");
    }

    #[test]
    fn doctor_basis_human_known_and_unknown_tags() {
        // Known-tag sentences are compile-checked on ContextBasis::human in
        // core (adding a variant forces an arm); here pin the two doctor-side
        // behaviors: wire tags resolve, unknown tags degrade by naming the tag.
        assert_eq!(
            basis_human("session-bind"),
            crate::core::ContextBasis::SessionBind.human()
        );
        assert!(basis_human("future-tag").contains("future-tag"));
    }

    #[test]
    fn diag_wire_round_trip() {
        // Client-side view of the agent's DiagRes JSON — pins the field names
        // the macOS handler serializes (they cross the wire; renames break
        // old clients).
        let json = r#"{
            "agent_version": "v1",
            "sign_cache": {"ttl_secs":120,"live_entries":1,"context_basis":"session-bind"},
            "decrypt_cache": {"ttl_secs":30,"live_entries":0,"context_basis":"disabled"},
            "peer": {"pid":42,"exe":"zsh","has_tty":true,"is_ssh_client":false,"is_vt_relay":false},
            "run_allow_len": 0,
            "audit_push": false
        }"#;
        let d: crate::core::DiagRes = serde_json::from_str(json).unwrap();
        assert_eq!(d.sign_cache.context_basis, "session-bind");
        assert_eq!(d.decrypt_cache.live_entries, 0);
        assert_eq!(d.peer.exe.as_deref(), Some("zsh"));
        // And the request serializes to an (empty) object.
        assert_eq!(
            serde_json::to_string(&crate::core::DiagReq::default()).unwrap(),
            "{}"
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
        // Backup already consumed (a restorer renamed it home) →
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
            backup: "/abs/.secret.env.vt-backup".into(),
            tmp: "/abs/.secret.env.vt-tmp-ab".into(),
            deadline_ms: 1_723_000_000_000,
            backup_id: Some((16_777_232, 42)),
        };
        let bytes = serde_json::to_vec(&sc).unwrap();
        let back: InjectSidecar = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(sc, back);

        // Records written by builds that predate the generation id must still
        // parse; they fall back to existence-only backup matching.
        let legacy: InjectSidecar = serde_json::from_slice(
            br#"{"target":"/t/f","backup":"/t/.f.vt-backup","tmp":"/t/.f.vt-tmp-ab","deadline_ms":7}"#,
        )
        .unwrap();
        assert_eq!(legacy.backup_id, None);
    }

    #[test]
    fn absolutize_leaves_absolute_paths_untouched() {
        let p = std::path::Path::new("/already/absolute");
        assert_eq!(absolutize(p), p);
        // A relative path becomes absolute (prefixed by some cwd).
        assert!(absolutize(std::path::Path::new("rel/x")).is_absolute());
    }

    #[test]
    fn exposure_backup_path_is_deterministic_per_target() {
        // Same target → same path: this determinism IS the exposure lock.
        let a = exposure_backup_path("/etc/app/config.yaml").unwrap();
        let b = exposure_backup_path("/etc/app/config.yaml").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a,
            std::path::PathBuf::from("/etc/app/.config.yaml.vt-backup")
        );
        // A bare file name resolves beside it in the cwd.
        assert_eq!(
            exposure_backup_path("config.yaml").unwrap(),
            std::path::Path::new(".").join(".config.yaml.vt-backup")
        );
        // Same basename in different dirs must not collide.
        assert_ne!(
            exposure_backup_path("/a/config.yaml").unwrap(),
            exposure_backup_path("/b/config.yaml").unwrap()
        );
        // A path with no file name is refused.
        assert!(exposure_backup_path("/").is_err());
    }

    #[test]
    fn create_exposure_backup_returns_live_id_and_keeps_foreign_locks() {
        let dir = std::env::temp_dir().join(format!("vt-inject-mkbak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let backup = dir.join(".f.vt-backup");

        // Success: bytes land, and the returned generation id is the live one.
        let id = create_exposure_backup(&backup, b"ciphertext", 0o600).unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), b"ciphertext");
        assert_eq!(id, current_backup_id(&backup));

        // EEXIST: propagated for the conflict-refusal path, and the existing
        // lock must NOT be removed — it is another exposure's live backup,
        // not something this call created and may clean up.
        let err = create_exposure_backup(&backup, b"other", 0o600).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&backup).unwrap(), b"ciphertext");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn classify_exposure_conflict_branches() {
        let sc = InjectSidecar {
            target: "/t/f".into(),
            backup: "/t/.f.vt-backup".into(),
            tmp: "/t/.f.vt-tmp-ab".into(),
            deadline_ms: 100_000,
            backup_id: None,
        };
        // Before the deadline: live, remaining seconds round up.
        assert_eq!(
            classify_exposure_conflict(Some(&sc), 98_500),
            ExposureConflict::Live { remaining_s: 2 }
        );
        // Inside the grace window: still presumed live (about to fire).
        assert_eq!(
            classify_exposure_conflict(Some(&sc), 100_000 + RECOVER_GRACE_MS - 1),
            ExposureConflict::Live { remaining_s: 0 }
        );
        // Past deadline + grace with the backup still present: dead supervisor.
        assert_eq!(
            classify_exposure_conflict(Some(&sc), 100_000 + RECOVER_GRACE_MS),
            ExposureConflict::Orphaned
        );
        assert_eq!(
            classify_exposure_conflict(None, 0),
            ExposureConflict::Untracked
        );
    }

    /// The real `(dev, ino)` of `backup` — a matching generation id for tests.
    fn current_backup_id(backup: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(backup).unwrap();
        (md.dev(), md.ino())
    }

    /// The real `(dev, ino)` of `backup` with the inode perturbed — a
    /// guaranteed generation mismatch for tests.
    fn mismatched_backup_id(backup: &std::path::Path) -> (u64, u64) {
        let (dev, ino) = current_backup_id(backup);
        (dev, ino.wrapping_add(1))
    }

    #[test]
    fn find_sidecar_for_backup_matches_and_skips_garbage() {
        let dir = std::env::temp_dir().join(format!("vt-inject-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let backup = dir.join(".secret.env.vt-backup");
        std::fs::write(&backup, b"ciphertext").unwrap();
        let sc = InjectSidecar {
            target: dir.join("secret.env").to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            tmp: "/abs/.secret.env.vt-tmp-ab".into(),
            // In-window deadline: the ordering bound must not filter a record
            // whose exposure is simply still open.
            deadline_ms: now_ms() + 60_000,
            backup_id: Some(current_backup_id(&backup)),
        };
        std::fs::write(dir.join("aa.json"), serde_json::to_vec(&sc).unwrap()).unwrap();
        std::fs::write(dir.join("bb.json"), b"not json").unwrap(); // skipped
        std::fs::write(dir.join("cc.txt"), b"wrong extension").unwrap(); // ignored

        assert_eq!(find_sidecar_for_backup(&dir, &backup), Some(sc.clone()));
        assert_eq!(
            find_sidecar_for_backup(&dir, std::path::Path::new("/abs/.other.vt-backup")),
            None
        );

        // A stale record whose generation id names a different inode is not a
        // match: it describes an earlier, already-consumed backup that
        // happened to live at the same deterministic path.
        let stale = InjectSidecar {
            backup_id: Some(mismatched_backup_id(&backup)),
            ..sc
        };
        std::fs::write(dir.join("aa.json"), serde_json::to_vec(&stale).unwrap()).unwrap();
        assert_eq!(find_sidecar_for_backup(&dir, &backup), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn probe_sidecar_backup_checks_generation_and_ordering() {
        let dir = std::env::temp_dir().join(format!("vt-inject-gen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let backup = dir.join(".f.vt-backup");
        std::fs::write(&backup, b"ciphertext").unwrap();
        let sc = |backup_id, deadline_ms| InjectSidecar {
            target: dir.join("f").to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            tmp: "unused".into(),
            deadline_ms,
            backup_id,
        };
        let future = now_ms() + 60_000;
        // Legacy in-window record: existence is enough.
        assert_eq!(probe_sidecar_backup(&sc(None, future)), BackupProbe::Ours);
        // Matching generation survives; a different inode means the recorded
        // backup was consumed and the path re-created by a later exposure.
        assert_eq!(
            probe_sidecar_backup(&sc(Some(current_backup_id(&backup)), future)),
            BackupProbe::Ours
        );
        assert_eq!(
            probe_sidecar_backup(&sc(Some(mismatched_backup_id(&backup)), future)),
            BackupProbe::Gone
        );
        // Ordering bound: a backup modified after the record's deadline is a
        // successor, whatever the record's id says — a legitimate backup
        // always predates its own deadline. This is what protects id-less
        // legacy records (and inode reuse) from the stale-sidecar race; the
        // fresh file here postdates the long-expired deadline.
        assert_eq!(probe_sidecar_backup(&sc(None, 0)), BackupProbe::Gone);
        assert_eq!(
            probe_sidecar_backup(&sc(Some(current_backup_id(&backup)), 0)),
            BackupProbe::Gone
        );
        // A genuinely old backup (mtime at or before the deadline) still
        // reads as ours for an id-less record: legacy crash recovery keeps
        // working, including the exact-deadline boundary a zero-timeout arm
        // produces. One millisecond past the deadline is already a successor
        // — a supervisor restoring at the deadline and a new inject arming
        // right after must not pair with this record.
        let f = std::fs::File::options().write(true).open(&backup).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_000))
            .unwrap();
        drop(f);
        assert_eq!(probe_sidecar_backup(&sc(None, 2_000)), BackupProbe::Ours);
        assert_eq!(probe_sidecar_backup(&sc(None, 1_000)), BackupProbe::Ours);
        assert_eq!(probe_sidecar_backup(&sc(None, 999)), BackupProbe::Gone);
        // Backup gone: consumed; settled regardless of id.
        std::fs::remove_file(&backup).unwrap();
        assert_eq!(probe_sidecar_backup(&sc(None, future)), BackupProbe::Gone);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn probe_sidecar_backup_reports_unknown_on_stat_errors() {
        // Directory modes don't bind root; the EACCES this test relies on
        // never happens there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vt-inject-probe-{}", std::process::id()));
        let sealed = dir.join("sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        let backup = sealed.join(".f.vt-backup");
        std::fs::write(&backup, b"ciphertext").unwrap();
        let sc = InjectSidecar {
            target: sealed.join("f").to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            tmp: "unused".into(),
            deadline_ms: 0,
            backup_id: None,
        };
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let probe = probe_sidecar_backup(&sc);
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
        // EACCES is not "consumed": recovery must keep the record, not clean
        // it as stale.
        assert_eq!(probe, BackupProbe::Unknown);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_exposure_keeps_sidecar_when_backup_state_unknown() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vt-inject-supstat-{}", std::process::id()));
        let sealed = dir.join("sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        let target = sealed.join("f");
        let backup = sealed.join(".f.vt-backup");
        std::fs::write(&target, b"plaintext").unwrap();
        std::fs::write(&backup, b"ciphertext").unwrap();
        let armed = current_backup_id(&backup);
        let sidecar = dir.join("sc.json");
        std::fs::write(&sidecar, b"{}").unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

        restore_exposure(&dir.join("no-tmp"), &backup, &target, &sidecar, armed);

        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            sidecar.exists(),
            "an unknowable backup state must keep the sidecar for --recover"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"ciphertext");
        assert_eq!(std::fs::read(&target).unwrap(), b"plaintext");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_inject_sidecar_refuses_records_over_the_read_cap() {
        let dir = std::env::temp_dir().join(format!("vt-inject-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aa.json");
        let sc = InjectSidecar {
            target: "t".repeat(2 * SIDECAR_MAX_BYTES as usize),
            backup: "/t/.f.vt-backup".into(),
            tmp: "unused".into(),
            deadline_ms: 0,
            backup_id: Some((1, 2)),
        };
        let err = write_inject_sidecar(&path, &sc).unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {err}");
        assert!(!path.exists(), "an over-cap record must not be written");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retire_stale_sidecars_removes_only_records_of_this_backup() {
        let dir = std::env::temp_dir().join(format!("vt-inject-retire-{}", std::process::id()));
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let backup = dir.join(".f.vt-backup");
        let other = dir.join(".other.vt-backup");
        let mk = |backup: &std::path::Path| InjectSidecar {
            target: dir.join("f").to_string_lossy().into_owned(),
            backup: backup.to_string_lossy().into_owned(),
            tmp: "unused".into(),
            deadline_ms: 0,
            backup_id: None,
        };
        std::fs::write(state.join("stale.json"), serde_json::to_vec(&mk(&backup)).unwrap())
            .unwrap();
        std::fs::write(state.join("other.json"), serde_json::to_vec(&mk(&other)).unwrap())
            .unwrap();

        retire_stale_sidecars_for(&backup, Some(&state));
        assert!(!state.join("stale.json").exists(), "stale record must be retired");
        assert!(state.join("other.json").exists(), "unrelated record must survive");
        // No resolvable state dir → quietly a no-op.
        retire_stale_sidecars_for(&backup, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_dev_ino_parses_and_rejects() {
        assert_eq!(parse_dev_ino("123:456"), Some((123, 456)));
        assert_eq!(parse_dev_ino("0:0"), Some((0, 0)));
        assert_eq!(parse_dev_ino("123"), None);
        assert_eq!(parse_dev_ino("a:1"), None);
        assert_eq!(parse_dev_ino("1:b"), None);
        assert_eq!(parse_dev_ino("-1:2"), None);
        assert_eq!(parse_dev_ino(""), None);
    }

    #[test]
    fn restore_exposure_restores_only_its_own_generation() {
        let dir = std::env::temp_dir().join(format!("vt-inject-sup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("f");
        let backup = dir.join(".f.vt-backup");
        let tmp = dir.join(".f.vt-tmp-ab");
        let sidecar = dir.join("sc.json");

        // Our generation: tmp wiped, backup renamed home, sidecar dropped.
        std::fs::write(&target, b"plaintext").unwrap();
        std::fs::write(&backup, b"ciphertext").unwrap();
        std::fs::write(&tmp, b"orphan").unwrap();
        std::fs::write(&sidecar, b"{}").unwrap();
        restore_exposure(&tmp, &backup, &target, &sidecar, current_backup_id(&backup));
        assert_eq!(std::fs::read(&target).unwrap(), b"ciphertext");
        assert!(!backup.exists() && !tmp.exists() && !sidecar.exists());

        // A successor's generation at the path (delayed supervisor waking
        // into a newer exposure): its backup and the target must be left
        // untouched; only our stale sidecar is dropped.
        std::fs::write(&target, b"plaintext-B").unwrap();
        std::fs::write(&backup, b"ciphertext-B").unwrap();
        std::fs::write(&sidecar, b"{}").unwrap();
        restore_exposure(&tmp, &backup, &target, &sidecar, mismatched_backup_id(&backup));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"plaintext-B",
            "successor's live exposure must not be restored early"
        );
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"ciphertext-B",
            "successor's backup must not be consumed"
        );
        assert!(!sidecar.exists());

        // Backup gone (already restored): just drop the sidecar.
        std::fs::remove_file(&backup).unwrap();
        std::fs::write(&sidecar, b"{}").unwrap();
        restore_exposure(&tmp, &backup, &target, &sidecar, (1, 2));
        assert_eq!(std::fs::read(&target).unwrap(), b"plaintext-B");
        assert!(!sidecar.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_exposure_keeps_sidecar_when_rename_fails() {
        // Directory modes don't bind root; the EACCES this test relies on
        // never happens there.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vt-inject-supfail-{}", std::process::id()));
        let ro = dir.join("ro");
        std::fs::create_dir_all(&ro).unwrap();
        let target = ro.join("f");
        let backup = ro.join(".f.vt-backup");
        let sidecar = dir.join("sc.json");
        std::fs::write(&target, b"plaintext").unwrap();
        std::fs::write(&backup, b"ciphertext").unwrap();
        std::fs::write(&sidecar, b"{}").unwrap();
        let armed = current_backup_id(&backup);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();

        restore_exposure(&dir.join("no-tmp"), &backup, &target, &sidecar, armed);

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            sidecar.exists(),
            "sidecar must survive a failed restore so --recover can retry"
        );
        assert_eq!(std::fs::read(&backup).unwrap(), b"ciphertext");
        assert_eq!(std::fs::read(&target).unwrap(), b"plaintext");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_sidecar_bounded_refuses_symlinks_fifos_and_oversize() {
        let dir = std::env::temp_dir().join(format!("vt-inject-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sc = InjectSidecar {
            target: "/t/f".into(),
            backup: "/t/.f.vt-backup".into(),
            tmp: "unused".into(),
            deadline_ms: 0,
            backup_id: None,
        };
        let real = dir.join("real.json");
        std::fs::write(&real, serde_json::to_vec(&sc).unwrap()).unwrap();
        assert_eq!(read_sidecar_bounded(&real), Some(sc));

        // Symlink final component: refused even when it points at a valid
        // sidecar — the fallback scan may run in an attacker-writable dir.
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_sidecar_bounded(&link), None);

        // Oversized file: never read past the cap.
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b'x'; (SIDECAR_MAX_BYTES + 1) as usize]).unwrap();
        assert_eq!(read_sidecar_bounded(&big), None);

        // FIFO: O_NONBLOCK + the regular-file check make this return, not hang.
        let fifo = dir.join("fifo.json");
        let cpath = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap()
        };
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert_eq!(read_sidecar_bounded(&fifo), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exposure_conflict_refusal_picks_the_right_guidance() {
        let dir = std::env::temp_dir().join(format!("vt-inject-refusal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("secret.env");
        let target_str = target.to_str().unwrap();
        let backup = exposure_backup_path(target_str).unwrap();
        std::fs::write(&backup, b"ciphertext").unwrap();
        // Backdate the backup so records with long-past deadlines read as
        // genuine orphans (a real orphan's backup predates its deadline; a
        // fresh mtime would trip the ordering bound and classify Untracked).
        let f = std::fs::File::options().write(true).open(&backup).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_000))
            .unwrap();
        drop(f);

        // A sidecar whose deadline is long past → Orphaned → names --recover.
        // The deadline sits at/after the backdated mtime, as it does for any
        // genuine orphan — the ordering bound rejects mtimes past it.
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let sc = InjectSidecar {
            target: target_str.to_string(),
            backup: backup.to_string_lossy().into_owned(),
            tmp: "unused".into(),
            deadline_ms: 2_000,
            backup_id: None,
        };
        std::fs::write(state.join("aa.json"), serde_json::to_vec(&sc).unwrap()).unwrap();
        let err = exposure_conflict_refusal(target_str, &backup, Some(&state));
        assert!(err.to_string().contains("--recover"), "got: {err}");

        // The same orphan record found only beside the target (the no-home-dir
        // fallback location) must NOT name --recover — it sweeps only the
        // state dir and would report nothing to recover. Manual restore only.
        std::fs::remove_file(state.join("aa.json")).unwrap();
        let fallback = dir.join(".secret.env.vt-recover-ab.json");
        std::fs::write(&fallback, serde_json::to_vec(&sc).unwrap()).unwrap();
        let err = exposure_conflict_refusal(target_str, &backup, Some(&state));
        assert!(
            err.to_string().contains("never restored") && err.to_string().contains("mv"),
            "got: {err}"
        );
        assert!(!err.to_string().contains("--recover"), "got: {err}");
        std::fs::remove_file(&fallback).unwrap();

        // A state-dir record whose generation id names a different inode
        // describes an EARLIER exposure's consumed backup, not this one →
        // classified Untracked (manual guidance), not Orphaned.
        std::fs::write(
            state.join("aa.json"),
            serde_json::to_vec(&InjectSidecar {
                backup_id: Some(mismatched_backup_id(&backup)),
                ..sc.clone()
            })
            .unwrap(),
        )
        .unwrap();
        let err = exposure_conflict_refusal(target_str, &backup, Some(&state));
        assert!(err.to_string().contains("found leftover backup"), "got: {err}");
        assert!(!err.to_string().contains("--recover"), "got: {err}");

        // A live sidecar (far-future deadline) → retry guidance.
        std::fs::write(
            state.join("aa.json"),
            serde_json::to_vec(&InjectSidecar {
                deadline_ms: u64::MAX / 2,
                ..sc.clone()
            })
            .unwrap(),
        )
        .unwrap();
        let err = exposure_conflict_refusal(target_str, &backup, Some(&state));
        assert!(err.to_string().contains("mid-exposure"), "got: {err}");

        // No sidecar anywhere → manual-restore guidance naming the backup.
        std::fs::remove_file(state.join("aa.json")).unwrap();
        let err = exposure_conflict_refusal(target_str, &backup, Some(&state));
        assert!(
            err.to_string().contains(&backup.display().to_string()),
            "got: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_vt_records_means_nothing_to_decrypt() {
        // The -r guard: zero vt:// records refuses the exposure protocol
        // (either the wrong file, or plaintext left by a broken exposure).
        assert!(iter_vt_urls("plain: text\nno records here").next().is_none());
        assert!(iter_vt_urls("key: vt://0abc").next().is_some());
    }
}
