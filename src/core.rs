pub mod authorization;
pub mod crypto;
pub mod session;
pub mod wire;

use crate::core::crypto::AesGcmCrypto;

use anyhow::{ensure, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

// ---- Public types -----------------------------------------------------------

/// Per-record envelope salt (also reused as the AES-GCM nonce via `salt[..12]`).
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length (RFC 5116).
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// Minimum v2 blob length: salt + tag (empty plaintext).
pub const V2_MIN_BLOB_LEN: usize = SALT_LEN + TAG_LEN;

/// AAD prefix used when encrypting/decrypting v2 records. Concatenated with
/// the literal type byte (`b'0'` or `b'1'`). Binds ciphertexts to the v2
/// protocol version *and* the secret type, defeating type-flip attacks
/// (e.g. TOTP→RAW to leak the seed instead of a generated code).
pub const V2_AAD_PREFIX: &[u8] = b"vt:v2:";

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptItem {
    pub plaintext: String,
    pub t: SecretType,
}

/// Display-only context about the client process collected on the CLI side.
/// Travels with `decrypt@vt` and `auth@vt` so the agent can show the operator
/// (Touch ID prompt) — and, on the CF ceremony path, the phone's approval
/// page — enough context to recognize the session before approving.
///
/// Wire shape is forward/backward compatible: every field is `#[serde(default)]`
/// so an older client without these fields still deserializes (yielding empty
/// strings), and a newer agent reading an older request gracefully gets a
/// `ClientMeta::default()`. The CLI sanitizes (control-char strip, char
/// truncation) before sending; the agent re-sanitizes defensively before
/// surfacing to a UI.
/// Strip ASCII/Unicode control chars and length-cap a string for display.
/// Used everywhere display text crosses a trust boundary (CF approval page,
/// Touch ID prompt, log lines). Truncates with an ellipsis (`…`).
pub fn sanitize_for_display(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars).saturating_add(4));
    let mut n = 0usize;
    for c in s.chars().filter(|c| !c.is_control()) {
        if n == max_chars {
            out.push('…');
            return out;
        }
        out.push(c);
        n += 1;
    }
    out
}

/// Like `sanitize_for_display_multiline` but WITHOUT length / line-count caps:
/// strips control chars and preserves `\n` only, never truncates or appends an
/// ellipsis. Used for the `command` field so a long command is shown in full on
/// the approval / audit surfaces. The overall ceremony request body is already
/// bounded (256 KiB, `CEREMONY_POST_MAX_BYTES` on the Worker), which is the real
/// size guard — so this cannot be abused into an unbounded payload.
pub fn sanitize_for_display_uncapped(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.extend(line.chars().filter(|c| !c.is_control()));
    }
    out
}

/// Like `sanitize_for_display` but preserves `\n`. Caps line count to bound
/// the rendered dialog height against a hostile peer pushing it off-screen.
pub fn sanitize_for_display_multiline(
    s: &str,
    max_chars_per_line: usize,
    max_lines: usize,
) -> String {
    let mut out = String::new();
    for (i, line) in s.split('\n').take(max_lines).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // Inline a single-pass sanitize per line so the whole multi-line
        // body lands in `out` with one allocation regardless of input size.
        let mut n = 0usize;
        for c in line.chars().filter(|c| !c.is_control()) {
            if n == max_chars_per_line {
                out.push('…');
                break;
            }
            out.push(c);
            n += 1;
        }
    }
    out
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct ClientMeta {
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub pwd: String,
    #[serde(default)]
    pub tty: String,
    #[serde(default)]
    pub ppid_cmd: String,
    #[serde(default)]
    pub ssh_client: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthReq {
    pub host: String,
    pub reason: String,
    #[serde(default)]
    pub meta: ClientMeta,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthRes {
    pub approved: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CryptoResItem {
    pub result: String,
    pub err_message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    RAW,
    TOTP,
    UNKNOWN,
}

impl SecretType {
    pub fn from_str(s: &str) -> SecretType {
        match s.to_lowercase().as_str() {
            "raw" | "0" => SecretType::RAW,
            "totp" | "1" => SecretType::TOTP,
            _ => SecretType::UNKNOWN,
        }
    }

    /// ASCII byte used in v2 URLs and as the trailing AAD byte.
    pub fn as_byte(&self) -> u8 {
        match self {
            SecretType::RAW => b'0',
            SecretType::TOTP => b'1',
            SecretType::UNKNOWN => b'_',
        }
    }
}

impl SecretType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretType::RAW => "0",
            SecretType::TOTP => "1",
            SecretType::UNKNOWN => "_",
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---- v2 wire schema ---------------------------------------------------------

/// Request from client → agent for `encrypt@vt`. The agent generates fresh
/// per-record salts (NEVER trust client-supplied salt — see below).
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptReq {
    pub types: Vec<SecretType>,
}

/// One agent-generated `(salt, dek)` pair. Client uses these locally to AEAD
/// encrypt the corresponding plaintext and assemble the v2 URL. The DEK
/// crosses the wire encrypted under `auth_cipher` (same as legacy plaintext
/// did) and is zeroized after use on both sides.
///
/// NOTE: there is intentionally no `salt` field on the *request* side. Letting
/// a client supply a salt would let an attacker holding `VT_AUTH` extract the
/// salt from a stored `vt://0{salt||ct}` URL, request its DEK via
/// `encrypt@vt` (no Touch ID), and decrypt the ciphertext locally — bypassing
/// the Touch ID gate that protects `decrypt@vt`. Salt MUST originate inside
/// the agent.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct EncryptResItem {
    pub salt: [u8; SALT_LEN],
    pub dek: [u8; 32],
    pub err_message: String,
}

/// One item in a `decrypt@vt` request. v2 items carry only the salt; the
/// inner ciphertext is decrypted locally by the client. Legacy items carry
/// the full URL string and continue to be decrypted server-side until users
/// have migrated.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum DecryptInput {
    /// v2: `vt://{type}{b64(salt||ct)}` — agent only sees the salt.
    V2 {
        t: SecretType,
        salt: [u8; SALT_LEN],
    },
    /// Legacy v0/v1: `vt://mac/{type}{b64(ct)}` — agent decrypts and may run
    /// TOTP server-side (legacy behavior).
    Legacy { url: String },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DecryptReq {
    pub host: String,
    pub command: String,
    pub items: Vec<DecryptInput>,
    #[serde(default)]
    pub meta: ClientMeta,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum DecryptResItem {
    /// Per-record DEK; client uses it to decrypt the inner ciphertext locally.
    V2 {
        dek: [u8; 32],
        err_message: String,
    },
    /// Plaintext or legacy-side-computed TOTP code.
    Legacy {
        result: String,
        err_message: String,
    },
}

/// Request from a (typically remote) client → local agent for `run@vt`.
/// Touch ID gates every call, allowlist is enforced server-side, no cache.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RunReq {
    /// Hostname the request originated from (display only; never trusted).
    pub host: String,
    /// `[program, arg1, arg2, ...]`. argv[0] is resolved against the agent's
    /// allowlist before any Touch ID prompt.
    pub argv: Vec<String>,
    /// Optional human-readable reason shown in the Touch ID prompt.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub meta: ClientMeta,
}

/// Response for an approved `run@vt`. Fire-and-forget — the child has been
/// spawned and detached. The client just gets the local PID for logging.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RunRes {
    pub pid: u32,
}

/// Request: client → agent for `sign@vt`. The agent looks up the Keychain key
/// identified by `pubkey` (SSH wire-encoded `KeyData`), prompts with vt
/// context, and signs `data` in-agent. The private key never leaves the agent.
/// See `docs/sign-vt-design.md`.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignReq {
    /// Display/audit only; never trusted (caller-asserted, esp. under `ssh -A`).
    pub host: String,
    /// Human label, e.g. "ssh-sign: push -> github.com". Bounded + sanitized
    /// agent-side like `DecryptReq::command`.
    pub command: String,
    /// SSH wire-encoded public key (`KeyData`) selecting WHICH Keychain key to
    /// sign with. The agent decodes it and computes the fingerprint with the
    /// same `fingerprint_str` used for stored keys, so lookup cannot drift.
    pub pubkey: Vec<u8>,
    /// Bytes to sign (the blob from the system ssh SIGN_REQUEST).
    pub data: Vec<u8>,
    /// SSH-agent signature flags (RSA SHA2 selection). Ed25519/ECDSA ignore.
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub meta: ClientMeta,
}

/// Response for `sign@vt`: the SSH signature, algorithm-tagged so the client
/// rebuilds an `ssh_key::Signature` without assuming the key type. Not secret.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignRes {
    /// e.g. "ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256".
    pub algorithm: String,
    pub signature: Vec<u8>,
}

/// Request: client → agent for `diag@vt` (read-only diagnostics; no Touch ID,
/// never cached, not audit-pushed). Empty in v1; reserved for future filters.
/// See `docs/diag-design.md`.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct DiagReq {}

/// Response for `diag@vt`: how the agent is configured and how it classifies
/// THIS connection for caching purposes. Discloses no secret, no cache keys,
/// and nothing about scopes the caller could not reuse (`live_entries`
/// counts only grants the caller's own scope classification would hit).
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DiagRes {
    pub agent_version: String,
    pub sign_cache: DiagCacheReport,
    pub decrypt_cache: DiagCacheReport,
    pub peer: DiagPeerReport,
    /// Number of `run@vt` allowlist entries; 0 = run@vt disabled.
    pub run_allow_len: usize,
    /// Whether fire-and-forget audit push is enabled on the agent.
    pub audit_push: bool,
}

/// Per-operation diagnostic report (one for sign, one for decrypt).
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DiagCacheReport {
    /// Configured cache duration; 0 = Fresh (always prompt).
    pub ttl_secs: u64,
    /// Currently-valid grants THIS caller could use (its workspace / relay
    /// connection, plus user-wide destination grants for sign) — never a
    /// whole-store count.
    pub live_entries: usize,
    /// Stable wire tag naming how this connection is scope-classified
    /// ([`ContextBasis::as_wire`] on the agent); the CLI maps it back via
    /// [`ContextBasis::from_wire`] and passes unknown tags through verbatim
    /// (client/agent version skew degrades to an "unknown basis" line).
    pub context_basis: String,
}

/// How the agent scope-classifies a connection (activity scopes V2 —
/// docs/authorization-scopes-v2.md). Lives here (not in the macOS-only agent
/// module) so the agent's wire tags and the CLI's human explanations are one
/// compile-checked mapping — adding a variant forces both [`Self::as_wire`]
/// and [`Self::human`] arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextBasis {
    /// Cache duration is 0 (the default): every request prompts.
    Disabled,
    /// Peer PID unavailable → Fresh.
    NoPeerPid,
    /// `vt ssh connect --forward-real-agent` relay: grants confined to this
    /// connection.
    RelayConnection,
    /// Plain ssh peer (possibly `ssh -A` carrying forwarded remote traffic):
    /// vt extensions confined to this connection.
    SshConnection,
    /// Destination proven by a verified `session-bind@openssh.com`.
    SessionBind,
    /// Bound connection marked forwarding-capable → Fresh.
    Forwarding,
    /// A session-bind failed verification/consistency; sticky → Fresh.
    Tainted,
    /// ssh peer that never sent a session-bind (OpenSSH < 8.9 or a filtered
    /// path) → Fresh.
    UnboundSsh,
    /// Local peer scoped to its kernel-derived `.git` workspace root.
    Workspace,
    /// Local peer with no `.git` ancestor, scoped to its kernel-derived cwd
    /// directory itself (distinct grant family from `Workspace`).
    CwdWorkspace,
    /// Local peer whose cwd is a broad shared directory ($HOME, `/`, temp
    /// roots): scoped to its kernel-derived parent process (application).
    ParentApp,
    /// Kernel cwd is too broad to scope and no usable parent process either
    /// (parent is launchd / lookup failed) → Fresh.
    NoWorkspaceRoot,
    /// A proc-info lookup (start time / cwd / workspace stat) failed → Fresh.
    ProcLookupFailed,
}

impl ContextBasis {
    /// Stable wire tag — a protocol surface; renaming a variant must not
    /// change its tag.
    pub fn as_wire(&self) -> &'static str {
        match self {
            ContextBasis::Disabled => "disabled",
            ContextBasis::NoPeerPid => "no-peer-pid",
            ContextBasis::RelayConnection => "relay-connection",
            ContextBasis::SshConnection => "ssh-connection",
            ContextBasis::SessionBind => "session-bind",
            ContextBasis::Forwarding => "forwarding",
            ContextBasis::Tainted => "tainted",
            ContextBasis::UnboundSsh => "unbound-ssh",
            ContextBasis::Workspace => "workspace",
            ContextBasis::CwdWorkspace => "cwd-fallback",
            ContextBasis::ParentApp => "parent-app",
            ContextBasis::NoWorkspaceRoot => "no-workspace-root",
            ContextBasis::ProcLookupFailed => "proc-lookup-failed",
        }
    }

    /// Inverse of [`Self::as_wire`]; `None` for a tag this client doesn't
    /// know (a newer agent).
    pub fn from_wire(tag: &str) -> Option<Self> {
        Some(match tag {
            "disabled" => ContextBasis::Disabled,
            "no-peer-pid" => ContextBasis::NoPeerPid,
            "relay-connection" => ContextBasis::RelayConnection,
            "ssh-connection" => ContextBasis::SshConnection,
            "session-bind" => ContextBasis::SessionBind,
            "forwarding" => ContextBasis::Forwarding,
            "tainted" => ContextBasis::Tainted,
            "unbound-ssh" => ContextBasis::UnboundSsh,
            "workspace" => ContextBasis::Workspace,
            "cwd-fallback" => ContextBasis::CwdWorkspace,
            "parent-app" => ContextBasis::ParentApp,
            "no-workspace-root" => ContextBasis::NoWorkspaceRoot,
            "proc-lookup-failed" => ContextBasis::ProcLookupFailed,
            _ => return None,
        })
    }

    /// Operator-facing explanation shown by `vt doctor`.
    pub fn human(&self) -> &'static str {
        match self {
            ContextBasis::Disabled => {
                "caching disabled (duration 0, the default): every request prompts"
            }
            ContextBasis::NoPeerPid => "agent could not identify the peer process",
            ContextBasis::RelayConnection => {
                "confined to this relay connection (grants die with it; other \
                 connections never share them)"
            }
            ContextBasis::SshConnection => {
                "peer is an ssh process (may carry forwarded remote traffic) — \
                 confined to this connection; grants die with it"
            }
            ContextBasis::SessionBind => {
                "destination-bound: reuses one approval per (key, server) \
                 across all local callers within the TTL"
            }
            ContextBasis::Forwarding => {
                "connection carries forwarded agent traffic — never cached"
            }
            ContextBasis::Tainted => {
                "a session-bind failed verification on this connection — never \
                 cached until reconnect"
            }
            ContextBasis::UnboundSsh => {
                "ssh peer without session-bind (OpenSSH < 8.9?) — cannot \
                 distinguish auth from forwarding, never cached"
            }
            ContextBasis::Workspace => {
                "scoped to this git workspace: any caller working in the same \
                 checkout shares one approval within the TTL"
            }
            ContextBasis::CwdWorkspace => {
                "no git checkout: scoped to this exact working directory — \
                 callers in the same directory share one approval within the \
                 TTL"
            }
            ContextBasis::ParentApp => {
                "broad working directory ($HOME, /, temp root): scoped to the \
                 calling application — repeated requests from the same app \
                 instance share one approval within the TTL"
            }
            ContextBasis::NoWorkspaceRoot => {
                "working directory is too broad to scope and the calling \
                 application could not be identified — never cached"
            }
            ContextBasis::ProcLookupFailed => "process info lookup failed",
        }
    }
}

/// How the agent sees the connecting peer process.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DiagPeerReport {
    pub pid: Option<i32>,
    /// Basename of the peer executable (never the full path).
    pub exe: Option<String>,
    pub has_tty: bool,
    pub is_ssh_client: bool,
    pub is_vt_relay: bool,
}

// ---- v2 URL parsing ---------------------------------------------------------

/// Parsed `vt://...` URL. Strict parser (no `url::Url`, no normalization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtUrl {
    /// New envelope format: `vt://{type}{b64(salt(16)||ct||tag(16))}`.
    V2 {
        t: SecretType,
        salt: [u8; SALT_LEN],
        inner_ct: Vec<u8>,
    },
    /// Legacy: `vt://mac/{type}{b64(nonce(12)||ct||tag(16))}`.
    Legacy { t: SecretType, body_b64: String },
}

impl VtUrl {
    pub fn parse(s: &str) -> Result<Self> {
        // Legacy first: it has the longer prefix.
        if let Some(rest) = s.strip_prefix("vt://mac/") {
            // Use byte-level access so a non-ASCII first byte doesn't panic
            // via `&rest[..1]` slicing at a non-char boundary. Reachable from
            // attacker-supplied URLs flowing into legacy_decrypt on the agent.
            let &first = rest
                .as_bytes()
                .first()
                .ok_or_else(|| anyhow::anyhow!("empty legacy vt body"))?;
            ensure!(first.is_ascii(), "legacy vt type byte must be ASCII");
            let type_buf = [first];
            let t = SecretType::from_str(std::str::from_utf8(&type_buf).unwrap());
            let body_b64 = rest[1..].to_string();
            ensure!(
                body_b64.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
                }),
                "legacy vt body must be base64url-no-pad"
            );
            return Ok(VtUrl::Legacy { t, body_b64 });
        }
        // v2: `vt://{type}{b64}`. No further `/` allowed.
        if let Some(rest) = s.strip_prefix("vt://") {
            ensure!(!rest.contains('/'), "v2 vt URL must not contain '/'");
            // Same panic-safety concern as the legacy arm above.
            let &first = rest
                .as_bytes()
                .first()
                .ok_or_else(|| anyhow::anyhow!("empty v2 vt body"))?;
            ensure!(first.is_ascii(), "v2 vt type byte must be ASCII");
            ensure!(rest.len() >= 2, "v2 vt URL too short");
            let type_buf = [first];
            let type_str = std::str::from_utf8(&type_buf).unwrap();
            let t = SecretType::from_str(type_str);
            // Type must be a known v2 type byte (`0` or `1`); reject `_`/UNKNOWN.
            ensure!(
                matches!(t, SecretType::RAW | SecretType::TOTP),
                "unknown v2 secret type: {}",
                type_str
            );
            let body_b64 = &rest[1..];
            let blob = BASE64_URL_SAFE_NO_PAD
                .decode(body_b64.as_bytes())
                .map_err(|e| anyhow::anyhow!("v2 base64 decode error: {}", e))?;
            ensure!(
                blob.len() >= V2_MIN_BLOB_LEN,
                "v2 blob too short ({} bytes; need >= {})",
                blob.len(),
                V2_MIN_BLOB_LEN
            );
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&blob[..SALT_LEN]);
            let inner_ct = blob[SALT_LEN..].to_vec();
            return Ok(VtUrl::V2 { t, salt, inner_ct });
        }
        Err(anyhow::anyhow!("not a vt URL: must start with vt://"))
    }
}

/// Format a v2 envelope into its canonical URL representation.
pub fn format_v2_url(t: SecretType, salt: &[u8; SALT_LEN], inner_ct: &[u8]) -> String {
    let mut blob = Vec::with_capacity(SALT_LEN + inner_ct.len());
    blob.extend_from_slice(salt);
    blob.extend_from_slice(inner_ct);
    format!("vt://{}{}", t, BASE64_URL_SAFE_NO_PAD.encode(&blob))
}

/// Build the AAD bound to a single v2 record: `b"vt:v2:" || type_byte`.
fn v2_aad(t: SecretType) -> [u8; 7] {
    let mut aad = [0u8; 7];
    aad[..6].copy_from_slice(V2_AAD_PREFIX);
    aad[6] = t.as_byte();
    aad
}

// ---- Client-side v2 crypto --------------------------------------------------

/// Encrypt one record locally with a (salt, dek) pair allocated by the agent.
/// Returns the canonical v2 URL string.
pub fn client_encrypt_v2(
    t: SecretType,
    salt: &[u8; SALT_LEN],
    dek: &[u8; 32],
    plaintext: &[u8],
) -> Result<String> {
    let cipher = AesGcmCrypto::new(dek)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&salt[..NONCE_LEN]);
    let aad = v2_aad(t);
    let inner_ct = cipher.encrypt_with_nonce_and_aad(&nonce, plaintext, &aad)?;
    Ok(format_v2_url(t, salt, &inner_ct))
}

/// Decrypt one v2 record locally given the agent-released DEK. For TOTP
/// records (`type=1`), runs `TOTP::generate_current()` on the recovered seed
/// and zeroizes the seed buffer; returns the 6-digit code. For RAW, returns
/// the recovered plaintext.
pub fn client_decrypt_v2(
    t: SecretType,
    dek: &[u8; 32],
    salt: &[u8; SALT_LEN],
    inner_ct: &[u8],
) -> Result<String> {
    let cipher = AesGcmCrypto::new(dek)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&salt[..NONCE_LEN]);
    let aad = v2_aad(t);
    let plaintext: Zeroizing<Vec<u8>> =
        cipher.decrypt_with_nonce_and_aad(&nonce, inner_ct, &aad)?;
    match t {
        SecretType::RAW => {
            // KNOWN LIMITATION: the returned `String` is the recovered secret
            // in plain (non-`Zeroizing`) heap memory. The `plaintext` buffer
            // here is scrubbed on drop, but the owned copy handed back to the
            // caller is not — callers print/consume it immediately. Containing
            // this would require threading a `Zeroizing<String>`/`SecretString`
            // return type through every caller; deferred (same class of
            // residual as the TOTP arm below).
            let s = String::from_utf8(plaintext.to_vec())
                .map_err(|e| anyhow::anyhow!("v2 raw plaintext utf8 error: {}", e))?;
            Ok(s)
        }
        SecretType::TOTP => {
            // Seed is base32-encoded. We decode and immediately run TOTP in a
            // tight scope. KNOWN LIMITATION: `Secret::Encoded(_).to_bytes()`
            // and `TOTP::new_unchecked` both internalize the seed in plain
            // `String`/`Vec<u8>` (totp_rs does not implement `Zeroize`), so
            // the raw seed bytes linger unzeroized in the heap until those
            // values drop. The lifetime is one function call; if you need
            // stronger zeroization here, this branch needs a TOTP impl that
            // exposes a `Zeroize` API or runs the computation in a subprocess.
            let seed_str = std::str::from_utf8(&plaintext)
                .map_err(|e| anyhow::anyhow!("v2 totp seed utf8 error: {}", e))?;
            let seed_bytes = Secret::Encoded(seed_str.to_string())
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("TOTP secret encode error: {}", e))?;
            let code = {
                let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, seed_bytes);
                let code = totp
                    .generate_current()
                    .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))?;
                drop(totp);
                code
            };
            Ok(code)
        }
        SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown v2 secret type")),
    }
}

// ---- Agent-side legacy decrypt ---------------------------------------------

/// Server-side decryption of legacy v0/v1 URLs. Preserves the pre-envelope
/// behavior: agent decrypts the ciphertext with the master cipher, and for
/// `type=1` runs TOTP server-side (legacy clients expected the 6-digit code,
/// not the seed). Used during the migration window.
pub fn legacy_decrypt(mac_cipher: &AesGcmCrypto, url: &str) -> CryptoResItem {
    let result: Result<String> = (|| {
        let parsed = VtUrl::parse(url)?;
        let (t, body_b64) = match parsed {
            VtUrl::Legacy { t, body_b64 } => (t, body_b64),
            VtUrl::V2 { .. } => {
                return Err(anyhow::anyhow!(
                    "legacy_decrypt called on a v2 URL"
                ))
            }
        };
        let raw = BASE64_URL_SAFE_NO_PAD
            .decode(body_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))?;
        let plaintext = mac_cipher.decrypt(&raw)?;
        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("decryption error: {}", e))?;
        match t {
            SecretType::RAW => Ok(plaintext_str),
            SecretType::TOTP => {
                let seed_bytes = Secret::Encoded(plaintext_str)
                    .to_bytes()
                    .map_err(|e| anyhow::anyhow!("TOTP secret encode error: {}", e))?;
                TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, seed_bytes)
                    .generate_current()
                    .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))
            }
            SecretType::UNKNOWN => Err(anyhow::anyhow!("unknown secret type")),
        }
    })();
    match result {
        Ok(decrypted_value) => CryptoResItem {
            result: decrypted_value,
            err_message: String::new(),
        },
        Err(e) => CryptoResItem {
            result: String::new(),
            err_message: e.to_string(),
        },
    }
}

// ---- vt:// URL scanning -----------------------------------------------------
//
// Hand-rolled scanners replace the `regex` dependency for the trivial pattern
// `vt://(?:mac/)?[A-Za-z0-9_-]+`. The regex crate adds ~600KB to the binary
// for just two patterns, so we inline them here.

#[inline]
fn is_vt_body_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Find the next `vt://` URL starting at or after `from`. Returns the byte
/// range `[start, end)` covering the full match, or `None` if no match.
fn next_vt_url(s: &str, from: usize) -> Option<std::ops::Range<usize>> {
    let bytes = s.as_bytes();
    let mut cursor = from;
    while let Some(rel) = s[cursor..].find("vt://") {
        let start = cursor + rel;
        let mut body = start + 5;
        if body + 4 <= bytes.len() && &bytes[body..body + 4] == b"mac/" {
            body += 4;
        }
        let mut end = body;
        while end < bytes.len() && is_vt_body_byte(bytes[end]) {
            end += 1;
        }
        if end > body {
            return Some(start..end);
        }
        cursor = start + 5;
    }
    None
}

/// Iterate over non-overlapping `vt://[mac/]?<body>` matches as `&str` slices.
pub fn iter_vt_urls(s: &str) -> impl Iterator<Item = &str> {
    let mut cursor = 0usize;
    std::iter::from_fn(move || {
        let r = next_vt_url(s, cursor)?;
        cursor = r.end;
        Some(&s[r])
    })
}

/// `true` if `s` contains at least one `vt://` URL match.
pub fn has_vt_url(s: &str) -> bool {
    next_vt_url(s, 0).is_some()
}

/// Replace every `vt://` URL in `s` with `replacement`. Non-URL bytes are
/// preserved verbatim (no other normalization).
pub fn redact_vt_urls(s: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    while let Some(r) = next_vt_url(s, cursor) {
        out.push_str(&s[cursor..r.start]);
        out.push_str(replacement);
        cursor = r.end;
    }
    out.push_str(&s[cursor..]);
    out
}

/// Collapse every run of Unicode whitespace to a single ASCII space.
/// Equivalent to `Regex::new(r"\s+").replace_all(s, " ")`: leading and
/// trailing whitespace runs are preserved as a single space (i.e. NOT
/// trimmed), matching the original regex behavior used for command display.
pub fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(ch);
            in_space = false;
        }
    }
    out
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::derive_dek;

    fn fixture_dek() -> [u8; 32] {
        let mac_key = [0x42u8; 32];
        let salt = [0x11u8; SALT_LEN];
        derive_dek(&mac_key, &salt)
    }

    #[test]
    fn context_basis_wire_round_trip_and_human_are_total() {
        // Compile-time exhaustiveness lives in the match arms; this pins the
        // wire tags (a protocol surface) and the from_wire inverse.
        const ALL: [ContextBasis; 11] = [
            ContextBasis::Disabled,
            ContextBasis::NoPeerPid,
            ContextBasis::RelayConnection,
            ContextBasis::SshConnection,
            ContextBasis::SessionBind,
            ContextBasis::Forwarding,
            ContextBasis::Tainted,
            ContextBasis::UnboundSsh,
            ContextBasis::Workspace,
            ContextBasis::NoWorkspaceRoot,
            ContextBasis::ProcLookupFailed,
        ];
        for b in ALL {
            assert_eq!(ContextBasis::from_wire(b.as_wire()), Some(b));
            assert!(!b.human().is_empty());
        }
        assert_eq!(ContextBasis::from_wire("future-tag"), None);
        assert_eq!(ContextBasis::Disabled.as_wire(), "disabled");
        assert_eq!(ContextBasis::SessionBind.as_wire(), "session-bind");
        assert_eq!(ContextBasis::Workspace.as_wire(), "workspace");
        assert_eq!(
            ContextBasis::RelayConnection.as_wire(),
            "relay-connection"
        );
    }

    #[test]
    fn sign_req_res_roundtrip() {
        let req = SignReq {
            host: "g1".into(),
            command: "ssh-sign: push -> github.com".into(),
            pubkey: vec![0u8, 1, 2, 3, 255],
            data: vec![9u8; 40],
            flags: 4,
            meta: ClientMeta::default(),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: SignReq = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.host, req.host);
        assert_eq!(back.command, req.command);
        assert_eq!(back.pubkey, req.pubkey);
        assert_eq!(back.data, req.data);
        assert_eq!(back.flags, req.flags);

        // `flags` and `meta` default when absent (older client compatibility).
        let minimal = serde_json::json!({
            "host": "g1", "command": "x", "pubkey": [1,2], "data": [3,4]
        });
        let parsed: SignReq = serde_json::from_value(minimal).unwrap();
        assert_eq!(parsed.flags, 0);
        assert!(parsed.meta.user.is_empty());

        let res = SignRes { algorithm: "ssh-ed25519".into(), signature: vec![7u8; 64] };
        let rb = serde_json::to_vec(&res).unwrap();
        let rback: SignRes = serde_json::from_slice(&rb).unwrap();
        assert_eq!(rback.algorithm, "ssh-ed25519");
        assert_eq!(rback.signature, vec![7u8; 64]);
    }

    #[test]
    fn sanitize_multiline_preserves_newlines_and_strips_other_controls() {
        let s = "op: inject\nfile: /tmp/x\tdata\nreason: hi";
        let out = sanitize_for_display_multiline(s, 100, 10);
        assert_eq!(out, "op: inject\nfile: /tmp/xdata\nreason: hi");
    }

    #[test]
    fn sanitize_multiline_caps_each_line_independently() {
        let s = "short\n".to_string() + &"x".repeat(200);
        let out = sanitize_for_display_multiline(&s, 10, 10);
        assert_eq!(out, "short\nxxxxxxxxxx…");
    }

    #[test]
    fn sanitize_multiline_caps_total_line_count() {
        let s = "a\nb\nc\nd\ne";
        let out = sanitize_for_display_multiline(s, 100, 3);
        assert_eq!(out, "a\nb\nc");
    }

    #[test]
    fn v2_url_roundtrip() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"hello").unwrap();
        assert!(url.starts_with("vt://0"), "got: {}", url);
        assert!(!url.contains("mac/"), "v2 URL must not contain `mac/`");

        let parsed = VtUrl::parse(&url).unwrap();
        match parsed {
            VtUrl::V2 { t, salt: s, inner_ct } => {
                assert_eq!(t, SecretType::RAW);
                assert_eq!(s, salt);
                let pt = client_decrypt_v2(t, &dek, &s, &inner_ct).unwrap();
                assert_eq!(pt, "hello");
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v2_blob_layout_known_vector() {
        // Salt + inner_ct length must equal SALT_LEN + plaintext.len() + TAG_LEN
        // — proves no extra nonce prefix slipped in.
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"").unwrap();
        let body_b64 = url.strip_prefix("vt://0").unwrap();
        let blob = BASE64_URL_SAFE_NO_PAD.decode(body_b64).unwrap();
        assert_eq!(blob.len(), SALT_LEN + TAG_LEN);
        assert_eq!(&blob[..SALT_LEN], &salt[..]);
    }

    #[test]
    fn v2_aad_type_tamper_rejected() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        // Encrypt as TOTP, then try to decrypt as RAW — type byte is in AAD,
        // tag must mismatch.
        let url = client_encrypt_v2(SecretType::TOTP, &salt, &dek, b"JBSWY3DPEHPK3PXP").unwrap();
        let parsed = VtUrl::parse(&url).unwrap();
        if let VtUrl::V2 { salt, inner_ct, .. } = parsed {
            let bad = client_decrypt_v2(SecretType::RAW, &dek, &salt, &inner_ct);
            assert!(bad.is_err(), "RAW decrypt of TOTP-AAD ciphertext must fail");
        } else {
            panic!("expected V2");
        }
    }

    #[test]
    fn v2_salt_tamper_rejected() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let url = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"abc").unwrap();
        let mut parsed = VtUrl::parse(&url).unwrap();
        if let VtUrl::V2 { ref mut salt, .. } = parsed {
            salt[0] ^= 0xFF; // flip a salt byte
        }
        if let VtUrl::V2 { t, salt, inner_ct } = parsed {
            // Salt is fed into HKDF (different DEK) and as nonce — both change,
            // but the test caller doesn't re-derive DEK; it uses the original
            // dek, which simulates an attacker mutating the URL. Tag must fail.
            let bad = client_decrypt_v2(t, &dek, &salt, &inner_ct);
            assert!(bad.is_err());
        }
    }

    #[test]
    fn parse_rejects_short_v2_blob() {
        // 12 bytes is shorter than V2_MIN_BLOB_LEN (32).
        let bad = format!(
            "vt://0{}",
            BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 12])
        );
        assert!(VtUrl::parse(&bad).is_err());
    }

    #[test]
    fn parse_rejects_extra_slash_in_v2() {
        // `vt://0/abcd` would be a v2 path but contains a `/`.
        let bad = "vt://0/abcdefghij";
        assert!(VtUrl::parse(bad).is_err());
    }

    #[test]
    fn parse_legacy_still_works() {
        let s = "vt://mac/0AAAAAAAAAA";
        let parsed = VtUrl::parse(s).unwrap();
        match parsed {
            VtUrl::Legacy { t, body_b64 } => {
                assert_eq!(t, SecretType::RAW);
                assert_eq!(body_b64, "AAAAAAAAAA");
            }
            _ => panic!("expected Legacy"),
        }
    }

    #[test]
    fn parse_rejects_non_ascii_v2_type_byte() {
        // Reachable via attacker-controlled `DecryptInput::Legacy { url }`; must
        // not panic on byte-slicing at a non-char boundary.
        let bad = "vt://é-padding";
        let res = VtUrl::parse(bad);
        assert!(res.is_err(), "non-ASCII v2 type byte must be rejected");
    }

    #[test]
    fn parse_rejects_non_ascii_legacy_type_byte() {
        let bad = "vt://mac/é-padding";
        let res = VtUrl::parse(bad);
        assert!(res.is_err(), "non-ASCII legacy type byte must be rejected");
    }

    #[test]
    fn parse_rejects_empty_legacy_body() {
        let res = VtUrl::parse("vt://mac/");
        assert!(res.is_err());
    }

    #[test]
    fn parse_rejects_empty_v2_body() {
        let res = VtUrl::parse("vt://");
        assert!(res.is_err());
    }

    #[test]
    fn parse_rejects_non_vt() {
        assert!(VtUrl::parse("http://example.com").is_err());
        assert!(VtUrl::parse("vt:/0abc").is_err());
        assert!(VtUrl::parse("").is_err());
    }

    #[test]
    fn parse_rejects_unknown_v2_type() {
        // Type byte `_` is reserved for UNKNOWN; v2 must reject.
        let bad = format!(
            "vt://_{}",
            BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 32])
        );
        assert!(VtUrl::parse(&bad).is_err());
    }

    #[test]
    fn legacy_decrypt_v2_url_errors() {
        // legacy_decrypt only handles legacy URLs.
        let key = [0xAAu8; 32];
        let cipher = AesGcmCrypto::new(&key).unwrap();
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        let v2 = client_encrypt_v2(SecretType::RAW, &salt, &dek, b"x").unwrap();
        let res = legacy_decrypt(&cipher, &v2);
        assert!(!res.err_message.is_empty());
    }

    #[test]
    fn v2_url_does_not_contain_mac_segment() {
        let dek = fixture_dek();
        let salt = [0x11u8; SALT_LEN];
        for t in [SecretType::RAW, SecretType::TOTP] {
            let url = client_encrypt_v2(t, &salt, &dek, b"x").unwrap();
            assert!(!url.contains("mac/"), "url must not contain mac/: {}", url);
            assert!(url.starts_with("vt://"));
        }
    }

    // ── ClientMeta wire-compat tests ──────────────────────────────────────
    //
    // The wire-version bump policy (#[serde(default)] on every new field) is
    // load-bearing for mixed CLI/agent rollouts. These tests pin that
    // behavior so a future #[serde(deny_unknown_fields)] or a removed
    // #[serde(default)] will fail the suite.

    #[test]
    fn auth_req_deserializes_when_meta_is_missing() {
        // An old client (pre-meta) sends only host/reason. The agent must
        // still parse the request and get an empty ClientMeta.
        let json = br#"{"host":"alpha","reason":"sudo"}"#;
        let req: AuthReq = serde_json::from_slice(json).expect("must parse old-shape AuthReq");
        assert_eq!(req.host, "alpha");
        assert_eq!(req.reason, "sudo");
        assert_eq!(req.meta.user, "");
        assert_eq!(req.meta.pwd, "");
        assert_eq!(req.meta.ssh_client, "");
    }

    #[test]
    fn decrypt_req_deserializes_when_meta_is_missing() {
        // Same forward-compat property for DecryptReq.
        let json = br#"{"host":"alpha","command":"[read]","items":[]}"#;
        let req: DecryptReq = serde_json::from_slice(json).expect("must parse old-shape DecryptReq");
        assert_eq!(req.host, "alpha");
        assert_eq!(req.command, "[read]");
        assert!(req.items.is_empty());
        assert_eq!(req.meta.user, "");
        assert_eq!(req.meta.pwd, "");
    }

    #[test]
    fn client_meta_roundtrip_preserves_all_fields() {
        let m = ClientMeta {
            user: "qiqi".into(),
            pwd: "/Users/qiqi/proj".into(),
            tty: "/dev/pts/3".into(),
            ppid_cmd: "zsh -i".into(),
            ssh_client: "10.0.0.5 5234 22".into(),
        };
        let json = serde_json::to_vec(&m).unwrap();
        let back: ClientMeta = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.user, "qiqi");
        assert_eq!(back.pwd, "/Users/qiqi/proj");
        assert_eq!(back.tty, "/dev/pts/3");
        assert_eq!(back.ppid_cmd, "zsh -i");
        assert_eq!(back.ssh_client, "10.0.0.5 5234 22");
    }

    #[test]
    fn run_req_deserializes_when_meta_and_reason_missing() {
        // Mirror the AuthReq/DecryptReq forward-compat policy: an older
        // client that omits `meta` and `reason` must still parse.
        let json = br#"{"host":"g1","argv":["zed","ssh://g1/x"]}"#;
        let req: RunReq = serde_json::from_slice(json).expect("must parse old-shape RunReq");
        assert_eq!(req.host, "g1");
        assert_eq!(req.argv, vec!["zed".to_string(), "ssh://g1/x".to_string()]);
        assert!(req.reason.is_none());
        assert_eq!(req.meta.user, "");
    }

    #[test]
    fn client_meta_partial_fields_default_the_rest() {
        // A future client that omits ssh_client (because the env var is
        // empty) must still produce a well-formed ClientMeta.
        let json = br#"{"user":"qiqi","pwd":"/tmp"}"#;
        let m: ClientMeta = serde_json::from_slice(json).unwrap();
        assert_eq!(m.user, "qiqi");
        assert_eq!(m.pwd, "/tmp");
        assert_eq!(m.tty, "");
        assert_eq!(m.ppid_cmd, "");
        assert_eq!(m.ssh_client, "");
    }

    // ── vt:// URL scanner tests ────────────────────────────────────────────
    //
    // These pin behavior against the previous regex (`vt://(?:mac/)?[A-Za-z0-9_-]+`)
    // so anyone touching the hand-rolled scanner sees breakage immediately.

    fn collect_urls(s: &str) -> Vec<&str> {
        iter_vt_urls(s).collect()
    }

    #[test]
    fn scan_single_url() {
        assert_eq!(collect_urls("vt://abc"), vec!["vt://abc"]);
    }

    #[test]
    fn scan_mac_variant() {
        assert_eq!(collect_urls("vt://mac/abc_def-ghi"), vec!["vt://mac/abc_def-ghi"]);
    }

    #[test]
    fn scan_multiple_urls_in_text() {
        assert_eq!(
            collect_urls("export FOO=vt://abc BAR=vt://mac/xyz BAZ=42"),
            vec!["vt://abc", "vt://mac/xyz"],
        );
    }

    #[test]
    fn scan_stops_at_non_body_char() {
        // '.', '!', '/', and unicode chars all terminate the body.
        assert_eq!(collect_urls("vt://abc.suffix"), vec!["vt://abc"]);
        assert_eq!(collect_urls("vt://abc! more"), vec!["vt://abc"]);
        assert_eq!(collect_urls("vt://abc/extra"), vec!["vt://abc"]);
        assert_eq!(collect_urls("vt://αβγ"), Vec::<&str>::new());
    }

    #[test]
    fn scan_rejects_empty_body() {
        // "vt://" with no body chars must not match (regex `+` requires 1+).
        assert!(collect_urls("vt://").is_empty());
        assert!(collect_urls("vt://mac/").is_empty());
        assert!(collect_urls("vt:// vt://").is_empty());
    }

    #[test]
    fn scan_adjacent_urls() {
        // Whitespace-separated; the scanner must not glue them together.
        assert_eq!(collect_urls("vt://a vt://b"), vec!["vt://a", "vt://b"]);
    }

    #[test]
    fn scan_charset_covers_b64url() {
        // Body matches base64url-no-pad alphabet plus alphanumerics: every
        // char a real URL body could contain must be accepted.
        let body = "ABCabc012_-";
        let s = format!("vt://{body}");
        assert_eq!(collect_urls(&s), vec![s.as_str()]);
    }

    #[test]
    fn has_vt_url_works() {
        assert!(has_vt_url("hello vt://abc world"));
        assert!(has_vt_url("vt://mac/x"));
        assert!(!has_vt_url("hello world"));
        assert!(!has_vt_url("vt://"));
        assert!(!has_vt_url(""));
    }

    #[test]
    fn redact_replaces_all_matches() {
        assert_eq!(
            redact_vt_urls("echo vt://abc and vt://mac/xyz!", "vt://***"),
            "echo vt://*** and vt://***!",
        );
        assert_eq!(redact_vt_urls("no urls here", "vt://***"), "no urls here");
        assert_eq!(redact_vt_urls("vt:// alone", "vt://***"), "vt:// alone");
    }

    #[test]
    fn collapse_whitespace_matches_regex() {
        // Internal runs collapse.
        assert_eq!(collapse_whitespace("a   b\tc\nd"), "a b c d");
        // Leading/trailing runs collapse to a single space (NOT trimmed),
        // matching `Regex::new(r"\s+").replace_all(s, " ")` semantics.
        assert_eq!(collapse_whitespace("  foo  "), " foo ");
        assert_eq!(collapse_whitespace(""), "");
        // Unicode whitespace is treated as whitespace too.
        assert_eq!(collapse_whitespace("a\u{00A0}b"), "a b");
    }
}
