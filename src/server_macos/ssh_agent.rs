use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::{listen, Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{
    AddIdentity, Credential, Extension, Identity, RemoveIdentity, SignRequest, Unparsed,
};
use ssh_key::private::{KeypairData, PrivateKey};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::sync::{Mutex, RwLock};

use super::audit::{self, AgentAuditContext, AgentAuditEntry, AuditPushConfig};
use super::authorization::{new_engine, sleep_diverged};
use super::security::{derive_passcode_ciphers, load_mac_cipher};
use super::store::KeychainStore;
use crate::core::authorization::{
    AuthorizationEngine, AuthorizationFailure, AuthorizationPermit, AuthorizationRequest,
    CommitError, Decision, GrantScope, Operation, ReusePolicy, SubjectId,
};
use crate::core::crypto::AesGcmCrypto;
use crate::core::session::AuthOutcome;
use crate::core::wire::{outcome_to_err_strict, wrap_ok_envelope, ErrKind, WIRE_VERSION};
use zeroize::{Zeroize, Zeroizing};

mod handlers;
mod scopes;

use scopes::{append_reuse_line, destination_label, BindState, WorkspaceResolution};

#[path = "socket_owner.rs"]
mod socket_owner;

/// SSH agent extension names used by vt.
pub const EXT_ENCRYPT: &str = "encrypt@vt";
pub const EXT_DECRYPT: &str = "decrypt@vt";
pub const EXT_AUTH: &str = "auth@vt";
pub const EXT_RUN: &str = "run@vt";
pub const EXT_SIGN: &str = "sign@vt";
pub const EXT_DIAG: &str = "diag@vt";
/// Token-gated shell status/revoke channel (docs/app-bundle.md §5).
/// Plaintext (pre-cipher) like `session-bind@openssh.com`; NOT in the vt
/// cipher-path match below and NOT permitted by the relay filter.
pub const EXT_UI_STATUS: &str = "ui-status@vt";

fn agent_err(e: anyhow::Error) -> AgentError {
    AgentError::Other(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    )))
}

// --- Key storage (lives in `encrypted_ssh_keys` field of rusty.vault.store) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH-format private key (plaintext, encrypted at the keychain level)
    pub key_data: String,
}

/// Decode the SSH-keys blob from a loaded store. Returns an empty vec when
/// the store has no SSH keys yet.
pub fn decode_ssh_keys(store: &KeychainStore, cipher: &AesGcmCrypto) -> Result<Vec<SshKeyEntry>> {
    let Some(encrypted) = store.encrypted_ssh_keys_bytes()? else {
        return Ok(Vec::new());
    };
    let decrypted = cipher.decrypt(&encrypted)?;
    let entries: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted)?;
    Ok(entries)
}

/// Re-encrypt SSH key entries and stash them on the in-memory store. Caller
/// is responsible for `store.save()` (or going through `KeychainStore::modify`).
pub fn encode_ssh_keys_into(
    store: &mut KeychainStore,
    cipher: &AesGcmCrypto,
    entries: &[SshKeyEntry],
) -> Result<()> {
    let json = serde_json::to_vec(entries)?;
    let encrypted = cipher.encrypt(&json)?;
    store.set_encrypted_ssh_keys(&encrypted);
    Ok(())
}

// --- Reuse policy -----------------------------------------------------------

/// Human-readable duration for the prompt reuse line ("8h", "90m", "45s").
fn reuse_ttl_label(secs: u64) -> String {
    if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

/// True when `timeout` has elapsed since the last activity on EITHER clock —
/// the same dual-clock rule as authorization grants, applied to the idle
/// timeout: without the wall clock a laptop that naps often could
/// stay "active" for days and never drop its keys.
fn idle_exceeded(
    last_mono: Instant,
    last_wall: SystemTime,
    now_mono: Instant,
    now_wall: SystemTime,
    timeout: Duration,
) -> bool {
    last_mono
        .checked_add(timeout)
        .is_some_and(|deadline| now_mono >= deadline)
        || last_wall
            .checked_add(timeout)
            .is_some_and(|deadline| now_wall >= deadline)
}

// --- Cache watcher (screen lock + sleep/wake invalidation) ---

/// How often the cache watcher samples screen-lock state and clock skew.
const WATCHER_TICK: Duration = Duration::from_secs(5);
/// Decide whether the auth caches must be flushed for this watcher tick.
///
/// Two triggers, both "the human walked away" signals that must revoke
/// standing grants (sudo-timestamp semantics):
///   1. Screen transitioned interactive → not interactive (locked, fast-user
///      -switched, or logged out). Only the *transition* clears, so a grant
///      issued after unlock isn't immediately eaten by the steady locked
///      state of some other display.
///   2. Sleep detected: wall time advanced by the shared sleep-divergence
///      threshold
///      more than monotonic time since the previous tick. `wall_delta` is
///      `None` when the wall clock stepped backwards — not a sleep signal;
///      the authorization engine's dual-clock TTL still bounds those entries.
fn watcher_should_clear(
    was_interactive: bool,
    is_interactive: bool,
    mono_delta: Duration,
    wall_delta: Option<Duration>,
) -> bool {
    if was_interactive && !is_interactive {
        return true;
    }
    sleep_diverged(mono_delta, wall_delta)
}

/// Wipe the decrypted-key map from RAM and mark `idle_cleared` so the next
/// interactive request silently reloads (docs/app-bundle.md §10). The single
/// source of the "wipe → later silent reload" handshake, shared by the idle
/// sweeper and the screen-lock/wake watcher so the flag can't be forgotten in
/// one of them. Returns the number of keys cleared. NOTE: the `ssh-add -x`
/// lock finalizer clears keys WITHOUT this flag on purpose — it relies on the
/// `locked` gate (not `idle_cleared`) to refuse reload — so it does not use
/// this helper.
async fn clear_keys_for_reload(
    keys: &Arc<RwLock<HashMap<String, PrivateKey>>>,
    idle_cleared: &Arc<RwLock<bool>>,
) -> usize {
    let mut guard = keys.write().await;
    let count = guard.len();
    if count > 0 {
        guard.clear();
        drop(guard);
        *idle_cleared.write().await = true;
    }
    count
}

// --- SSH Agent ---

// Defense-in-depth re-sanitization before surfacing wire meta to the Touch ID
// prompt — forwarded SSH agent sockets could be rewritten by a hostile hop.
use crate::core::sanitize_for_display as sanitize_prompt;
use crate::core::sanitize_for_display_multiline as sanitize_prompt_multiline;

/// Per-line cap and total-line cap for the multi-line `command` body the CLI
/// sends. The CLI builds something like `file: …\ncmd: …\nreason: …` (older
/// clients prepend `op: inject`), so 6 lines is enough headroom; further
/// lines from a hostile peer are silently dropped so the dialog can't be
/// pushed off-screen.
const PROMPT_COMMAND_MAX_LINES: usize = 6;
const PROMPT_COMMAND_MAX_LINE_LEN: usize = 120;

/// Hash a lock passphrase to a 32-byte SHA-256 digest.
fn hash_lock_passphrase(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(passphrase.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

// --- run@vt allowlist + spawn helpers ---------------------------------------
//
// `run@vt` lets a (typically remote) client request that the local agent
// spawn a program on this Mac after Touch ID. It is the only vt extension
// whose side effect is "fork/exec arbitrary code as the agent's UID", so the
// design is conservative: empty allowlist disables the feature entirely,
// argv[0] is resolved against the allowlist before any Touch ID prompt, the
// child's env is a fresh allowlist (not a denylist scrub of the agent's env),
// and concurrent `run@vt` calls are serialized so a remote attacker holding
// VT_AUTH cannot queue dozens of prompts at the user.

/// Parsed `--run-allow` flag. An empty allowlist means `run@vt` is disabled
/// outright. Slash-bearing entries match argv[0] post-canonicalization;
/// bare-name entries match argv[0] iff argv[0] is itself a bare name (the
/// agent then resolves it via its own PATH).
#[derive(Debug, Clone)]
pub struct RunAllowlist {
    bare_names: HashSet<String>,
    abs_paths: HashSet<PathBuf>,
}

impl RunAllowlist {
    /// Parse a comma-separated allowlist string. Whitespace around each item
    /// is trimmed; empty items are ignored so `--run-allow ""` parses to an
    /// empty (i.e. disabled) allowlist.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut bare_names = HashSet::new();
        let mut abs_paths = HashSet::new();
        for raw in spec.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            if item.contains('\0') {
                return Err(format!("run-allow item contains NUL: {:?}", item));
            }
            if item.contains('/') {
                let p = PathBuf::from(item);
                if !p.is_absolute() {
                    return Err(format!("run-allow path must be absolute (got {:?})", item));
                }
                let canon = std::fs::canonicalize(&p)
                    .map_err(|e| format!("run-allow canonicalize {:?}: {}", p, e))?;
                abs_paths.insert(canon);
            } else {
                if item.chars().any(|c| c.is_whitespace()) {
                    return Err(format!("run-allow name has whitespace: {:?}", item));
                }
                bare_names.insert(item.to_string());
            }
        }
        Ok(Self {
            bare_names,
            abs_paths,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.bare_names.is_empty() && self.abs_paths.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bare_names.len() + self.abs_paths.len()
    }

    /// Resolve a client-supplied argv[0] to a canonical absolute path that
    /// passes the allowlist, or return a static failure reason. The returned
    /// path is what the agent will pass to `Command::new` — never the raw
    /// client string. Bare-name argv[0]s are resolved against the agent's
    /// `PATH` (not the client's), which means PATH-injection from the remote
    /// side is impossible: the remote cannot influence what `zed` resolves
    /// to on this Mac.
    pub fn resolve(&self, argv0: &str) -> Result<PathBuf, &'static str> {
        if argv0.is_empty() {
            return Err("argv[0] empty");
        }
        if argv0.contains('\0') {
            return Err("argv[0] has NUL byte");
        }
        // Reject `..` components anywhere — canonicalize would resolve them
        // but we want to reject them outright so the user-visible allowlist
        // entries remain meaningful (no `/Applications/../etc/...` tricks).
        if argv0.split('/').any(|c| c == "..") {
            return Err("argv[0] has .. component");
        }
        if argv0.contains('/') {
            let p = PathBuf::from(argv0);
            if !p.is_absolute() {
                return Err("argv[0] with / must be absolute");
            }
            let canon = std::fs::canonicalize(&p).map_err(|_| "argv[0] canonicalize failed")?;
            if self.abs_paths.contains(&canon) {
                Ok(canon)
            } else {
                Err("argv[0] path not in allowlist")
            }
        } else {
            if !self.bare_names.contains(argv0) {
                return Err("argv[0] name not in allowlist");
            }
            let path_env = std::env::var("PATH").unwrap_or_default();
            resolve_in_path(argv0, &path_env).ok_or("argv[0] not found in agent PATH")
        }
    }
}

/// Tiny PATH lookup: walks `:`-separated dirs, returns the canonicalized path
/// of the first executable file matching `name`. Avoids adding the `which`
/// crate for ~10 lines of straightforward logic.
fn resolve_in_path(name: &str, path_env: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
            return std::fs::canonicalize(&candidate).ok();
        }
    }
    None
}

/// Cap on the total characters of joined argv shown in the Touch ID prompt.
/// Beyond this the prompt is truncated; argv itself is still passed in full.
const RUN_PROMPT_ARGV_MAX: usize = 400;

/// Cap on the total bytes of argv strings the agent will accept. Avoids
/// extreme inputs (e.g. multi-MB argv) being kept alive across the Touch ID
/// prompt window or being rendered to the UI.
const RUN_REQ_ARGV_MAX_BYTES: usize = 8 * 1024;

/// Cap on the size of free-form display strings (`DecryptReq.command`,
/// `AuthReq.reason`) the agent will sanitize and render. Without this, a
/// hostile peer holding a forwarded `VT_AUTH` could push arbitrarily large
/// strings and amplify per-prompt CPU/memory work. Generous compared to
/// the few-hundred-char display caps so we never reject legitimate input.
const PROMPT_DISPLAY_MAX_BYTES: usize = 8 * 1024;

/// Cap on the number of items in a single encrypt@vt / decrypt@vt batch. A
/// peer holding `VT_AUTH` can call these without a Touch ID gate (encrypt) or
/// before one (decrypt parse), so an unbounded batch is a CPU/RAM
/// amplification vector (e.g. 500k HKDF+AES ops, ~24 MB response). Generous
/// vs. any real file/env scan, so legitimate batches are never rejected.
const MAX_CRYPTO_BATCH: usize = 4096;

/// Environment variables passed through to the spawned child. The list is
/// deliberately short: it MUST NOT include any vt credentials (VT_AUTH,
/// VT_PASSKEY_*), the forwarded SSH agent socket (SSH_AUTH_SOCK,
/// SSH_AGENT_PID), GPG agent info, or any dynamic-linker injection vector
/// (DYLD_*, LD_*, PYTHONPATH, RUBYOPT, NODE_OPTIONS, PERL5LIB). Adding a
/// new entry here is a security-sensitive decision — see codex review in
/// PR history.
const RUN_ENV_PASSTHROUGH: &[&str] = &[
    "HOME", "USER", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
    "DISPLAY",
];

/// Default idle timeout: 2 hours.
///
/// Idle timeout overlaps in purpose with screen-lock / sleep invalidation —
/// both are "the human walked away" backstops — and lock/sleep fire far
/// faster (seconds, via the cache watcher). On a Mac with prompt auto-lock
/// the idle timeout is largely redundant, so a longer default favors fewer
/// surprise re-prompts after a quiet spell while lock/sleep remain the fast
/// guard. It is still a real backstop for the unlocked-but-unattended
/// window; hosts without reliable auto-lock should lower it via
/// `--timeout` / `[agent].timeout`.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 2 * 60 * 60;

/// Cache durations for the two reusable operations, carried together with
/// named fields so sign and decrypt cannot be transposed at any call layer —
/// they carry deliberately different blast radii (a cached decrypt grant
/// releases per-record DEK material). `0` = the engine's `Fresh` policy.
#[derive(Debug, Clone, Copy)]
pub struct AuthCacheTtls {
    pub sign_secs: u64,
    pub decrypt_secs: u64,
}

/// Load all SSH keys from the keychain store into a HashMap. The store and
/// derived ciphers are dropped after this returns so the master key does not
/// linger in memory.
fn load_all_keys() -> Result<HashMap<String, PrivateKey>> {
    let store = KeychainStore::load()?;
    let (_, passphrase_cipher) = derive_passcode_ciphers(&store)?;
    let (mac_cipher, _mac_key) = load_mac_cipher(&store, &passphrase_cipher)?;
    let entries = decode_ssh_keys(&store, &mac_cipher)?;
    let mut keys = HashMap::new();
    for entry in &entries {
        match PrivateKey::from_openssh(entry.key_data.as_bytes()) {
            Ok(privkey) => {
                tracing::info!("Loaded SSH key: {} ({})", entry.fingerprint, entry.comment);
                keys.insert(entry.fingerprint.clone(), privkey);
            }
            Err(e) => {
                tracing::warn!("Failed to parse SSH key {}: {}", entry.fingerprint, e);
            }
        }
    }
    Ok(keys)
}

fn fingerprint_str(key_data: &KeyData) -> String {
    let fp = ssh_key::Fingerprint::new(HashAlg::Sha256, key_data);
    fp.to_string()
}

/// Pure signing core: given an unlocked `PrivateKey`, sign `data` honoring the
/// SSH `flags` (RSA SHA2 selection). No auth, no lookup, no cache — callers do
/// that. Shared by the standard `Session::sign` and the `sign@vt` extension so
/// their algorithm coverage cannot drift.
fn sign_data_with_privkey(
    privkey: &PrivateKey,
    data: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    match privkey.key_data() {
        KeypairData::Ed25519(ref key) => {
            use ed25519_dalek::Signer;
            let signing_key: ed25519_dalek::SigningKey =
                key.try_into().map_err(AgentError::other)?;
            let sig = signing_key.sign(data);
            Signature::new(Algorithm::Ed25519, sig.to_bytes().to_vec()).map_err(AgentError::other)
        }
        KeypairData::Rsa(ref key) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::{RandomizedSigner, SignatureEncoding};
            use rsa::BigUint;
            use ssh_agent_lib::proto::signature;

            // Build the rsa key from its components directly rather than via
            // ssh-key's `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey`: that
            // conversion (ssh-key 0.6.7) rejects otherwise-valid OpenSSH RSA
            // keys with `Error::Crypto`, while `from_components` (which itself
            // validates + precomputes) accepts the exact same n/e/d/p/q. An
            // Mpint stores a signed big-endian integer; `as_positive_bytes`
            // strips the leading sign byte so `from_bytes_be` sees the raw
            // magnitude.
            let mp = |m: &ssh_key::Mpint| {
                m.as_positive_bytes()
                    .map(BigUint::from_bytes_be)
                    .ok_or_else(|| {
                        agent_err(anyhow::anyhow!("RSA component is not a positive integer"))
                    })
            };
            let private_key = rsa::RsaPrivateKey::from_components(
                mp(&key.public.n)?,
                mp(&key.public.e)?,
                mp(&key.private.d)?,
                vec![mp(&key.private.p)?, mp(&key.private.q)?],
            )
            .map_err(AgentError::other)?;
            let mut rng = rand::thread_rng();

            if flags & signature::RSA_SHA2_512 != 0 {
                let sig =
                    SigningKey::<sha2::Sha512>::new(private_key).sign_with_rng(&mut rng, data);
                Signature::new(
                    Algorithm::new("rsa-sha2-512").map_err(AgentError::other)?,
                    sig.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)
            } else if flags & signature::RSA_SHA2_256 != 0 {
                let sig =
                    SigningKey::<sha2::Sha256>::new(private_key).sign_with_rng(&mut rng, data);
                Signature::new(
                    Algorithm::new("rsa-sha2-256").map_err(AgentError::other)?,
                    sig.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)
            } else {
                let sig = SigningKey::<sha1::Sha1>::new(private_key).sign_with_rng(&mut rng, data);
                Signature::new(
                    Algorithm::new("ssh-rsa").map_err(AgentError::other)?,
                    sig.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)
            }
        }
        KeypairData::Ecdsa(ref key) => {
            use ssh_key::EcdsaCurve;
            match key.curve() {
                EcdsaCurve::NistP256 => {
                    use p256::ecdsa::{signature::Signer, SigningKey};
                    let secret_key = p256::SecretKey::from_slice(key.private_key_bytes())
                        .map_err(AgentError::other)?;
                    let signing_key = SigningKey::from(secret_key);
                    let sig: p256::ecdsa::DerSignature = signing_key.sign(data);
                    Signature::new(
                        Algorithm::new("ecdsa-sha2-nistp256").map_err(AgentError::other)?,
                        sig.as_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                }
                EcdsaCurve::NistP384 => {
                    use p384::ecdsa::{signature::Signer, SigningKey};
                    let secret_key = p384::SecretKey::from_slice(key.private_key_bytes())
                        .map_err(AgentError::other)?;
                    let signing_key = SigningKey::from(secret_key);
                    let sig: p384::ecdsa::DerSignature = signing_key.sign(data);
                    Signature::new(
                        Algorithm::new("ecdsa-sha2-nistp384").map_err(AgentError::other)?,
                        sig.as_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                }
                _ => Err(AgentError::Failure),
            }
        }
        _ => Err(AgentError::Failure),
    }
}

// --- Factory (shared state, implements Agent) ---

pub struct VtSshAgentFactory {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    /// Last request time on both clocks — see [`idle_exceeded`] for why the
    /// monotonic clock alone can't drive the idle timeout.
    last_activity: Arc<RwLock<(Instant, SystemTime)>>,
    locked: Arc<AtomicBool>,
    /// Serializes SSH-agent lock/unlock state transitions. The synchronous
    /// atomic remains the live authorization validator's fast state source.
    lock_transition: Arc<Mutex<()>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    authorization: Arc<AuthorizationEngine>,
    /// 0 = Fresh (always prompt); named fields prevent sign/decrypt
    /// transposition (see [`AuthCacheTtls`]).
    cache_ttls: AuthCacheTtls,
    /// When true, `decrypt@vt` rejects `Legacy` items (v0/v1 URLs). v2 envelope
    /// items continue to work. Lets users who have fully migrated harden the
    /// agent so the "agent emits plaintext over wire" path can never be
    /// triggered.
    disable_legacy_decrypt: bool,
    /// run@vt allowlist. Empty = feature disabled.
    run_allow: Arc<RunAllowlist>,
    /// Fire-and-forget audit push config. Cloned per session like `run_allow`.
    /// Disabled config = audit push is a no-op.
    audit_push: Arc<AuditPushConfig>,
    /// Fire a system notification when a grant reuse satisfies sign/decrypt
    /// without a prompt (docs/app-bundle.md §3). Default on.
    notify_cache_hits: bool,
    /// 32-byte spawn token read from `--ui-token-fd` at startup; gates
    /// `ui-status@vt`. `None` (CLI-started agent) refuses every request.
    ui_token: Option<[u8; 32]>,
    /// Configured idle timeout (seconds) — reported over `ui-status@vt` so
    /// the shell can display it (docs/app-bundle.md §10).
    idle_timeout_secs: u64,
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        cache_ttls: AuthCacheTtls,
        disable_legacy_decrypt: bool,
        run_allow: RunAllowlist,
        audit_push: Arc<AuditPushConfig>,
        notify_cache_hits: bool,
        ui_token: Option<[u8; 32]>,
        idle_timeout_secs: u64,
    ) -> Self {
        let locked = Arc::new(AtomicBool::new(false));
        let authorization = new_engine(Arc::clone(&locked));
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new((Instant::now(), SystemTime::now()))),
            locked,
            lock_transition: Arc::new(Mutex::new(())),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            authorization,
            cache_ttls,
            disable_legacy_decrypt,
            run_allow: Arc::new(run_allow),
            audit_push,
            notify_cache_hits,
            ui_token,
            idle_timeout_secs,
        }
    }
}

impl Agent<tokio::net::UnixListener> for VtSshAgentFactory {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        let peer = scopes::PeerIdentity::from_socket(socket);
        VtSshSession {
            keys: Arc::clone(&self.keys),
            last_activity: Arc::clone(&self.last_activity),
            locked: Arc::clone(&self.locked),
            lock_transition: Arc::clone(&self.lock_transition),
            lock_passphrase: Arc::clone(&self.lock_passphrase),
            idle_cleared: Arc::clone(&self.idle_cleared),
            authorization: Arc::clone(&self.authorization),
            cache_ttls: self.cache_ttls,
            run_allow: Arc::clone(&self.run_allow),
            audit_push: Arc::clone(&self.audit_push),
            peer_pid: peer.peer_pid,
            peer_exe: peer.peer_exe,
            peer_is_vt_relay: peer.peer_is_vt_relay,
            peer_is_ssh_client: peer.peer_is_ssh_client,
            connection_subject: peer.connection_subject,
            workspace: std::sync::OnceLock::new(),
            bind_state: BindState::Unbound,
            destination_label: None,
            disable_legacy_decrypt: self.disable_legacy_decrypt,
            notify_cache_hits: self.notify_cache_hits,
            ui_token: self.ui_token,
            idle_timeout_secs: self.idle_timeout_secs,
        }
    }
}

// --- Per-connection session (implements Session) ---

struct VtSshSession {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<(Instant, SystemTime)>>,
    locked: Arc<AtomicBool>,
    lock_transition: Arc<Mutex<()>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    authorization: Arc<AuthorizationEngine>,
    cache_ttls: AuthCacheTtls,
    /// Cloned per session for cheap reads; the underlying allowlist is
    /// constant for the lifetime of the agent process.
    run_allow: Arc<RunAllowlist>,
    /// Shared fire-and-forget audit push config (disabled = no-op).
    audit_push: Arc<AuditPushConfig>,
    peer_pid: Option<i32>,
    /// Peer executable basename (kernel `proc_pidpath`), captured once for
    /// prompts and diag.
    peer_exe: Option<String>,
    /// Peer is a `vt ssh connect --forward-real-agent` relay (kernel-argv
    /// check, resolved once at session creation): its requests originated on
    /// a remote host and every prompt carries the relay-origin marker.
    peer_is_vt_relay: bool,
    /// Peer executable basename is `ssh` (kernel `proc_pidpath`). An ssh
    /// peer can carry forwarded remote traffic, so it is confined per
    /// connection for vt extensions and its raw signs are cacheable only via
    /// a non-forwarding session-bind.
    peer_is_ssh_client: bool,
    /// `(pid, start_tvsec)` confinement subject for relay and ssh peers;
    /// `None` for local vt peers or when the proc lookup failed (the
    /// connection then degrades to Fresh via the scope constructors).
    connection_subject: Option<SubjectId>,
    /// Workspace resolution for local peers (Unavailable for relay/ssh).
    /// Resolved lazily on first use — `resolve_workspace` does filesystem
    /// I/O on a peer-controlled cwd, and `new_session` runs on the accept
    /// loop, where a hung network mount would stall every client. Still
    /// once per connection (never re-resolved per request).
    workspace: std::sync::OnceLock<WorkspaceResolution>,
    /// Destination binding driven by `session-bind@openssh.com` (§3.2 of
    /// docs/authorization-scopes-v2.md). Mutated by `extension()`.
    bind_state: BindState,
    /// Display label for the bound destination, computed once per bind so a
    /// sign burst does not re-read known_hosts.
    destination_label: Option<String>,
    disable_legacy_decrypt: bool,
    /// Cache-hit transparency notifications (docs/app-bundle.md §3).
    notify_cache_hits: bool,
    /// Spawn token gating `ui-status@vt`; `None` refuses every request.
    ui_token: Option<[u8; 32]>,
    /// Configured idle timeout (seconds), reported over `ui-status@vt`.
    idle_timeout_secs: u64,
}

impl VtSshSession {
    /// Build an `AgentAuditEntry` from the post-decision context and hand it to
    /// the fire-and-forget pusher. No-op when audit push is disabled. Holds NO
    /// cache lock; never blocks (spawn_push returns immediately).
    #[allow(clippy::too_many_arguments)]
    fn emit_audit(
        &self,
        op_kind: &str,
        outcome: &str,
        host: &str,
        meta: &crate::core::ClientMeta,
        command: &str,
        reason: &str,
        salts: usize,
        latency_ms: u64,
        agent_ctx: AgentAuditContext,
    ) {
        if !self.audit_push.enabled {
            return;
        }
        let entry = AgentAuditEntry::build(
            op_kind,
            outcome,
            host,
            meta,
            command,
            reason,
            self.peer_pid,
            salts,
            latency_ms,
            self.audit_push.agent_id(),
            agent_ctx,
        );
        audit::spawn_push(Arc::clone(&self.audit_push), entry);
    }

    /// Ensure keys are loaded. If they were cleared by the idle sweeper or by
    /// the screen-lock/sleep watcher (docs/app-bundle.md §10), silently reload
    /// from keychain. The unified authorization engine still gates every
    /// operation before a loaded key can be used.
    async fn ensure_keys_loaded(&self) -> Result<(), AgentError> {
        let keys = self.keys.read().await;
        if !keys.is_empty() {
            return Ok(());
        }
        drop(keys);

        // Check if keys were cleared by idle timeout / lock (vs just empty).
        let idle = *self.idle_cleared.read().await;
        if !idle {
            return Ok(());
        }

        // Do NOT repopulate RAM while the screen is locked (§10, C). A sign
        // here is rejected by the validator anyway; reloading would undo the
        // lock-wipe. Checked before the keychain I/O to skip a pointless read,
        // and RE-checked after it (below) because the screen can lock during
        // the read. `idle_cleared` is left set so a later interactive call
        // reloads.
        if !super::security::session_interactive_now() {
            return Ok(());
        }

        tracing::info!("Keys cleared (idle/lock), reloading from keychain");
        let loaded = load_all_keys().map_err(agent_err)?;
        tracing::info!("Reloaded {} SSH keys", loaded.len());
        let mut keys = self.keys.write().await;
        // A lock transition (agent lock OR screen lock) may have started while
        // Keychain I/O was in progress. Re-check both while holding the same
        // key-map guard used by lock() so loaded private keys can never be
        // installed after a clear.
        if self.locked.load(Ordering::Acquire) || !super::security::session_interactive_now() {
            return Ok(());
        }
        *keys = loaded;

        // Reset idle_cleared flag
        let mut idle_cleared = self.idle_cleared.write().await;
        *idle_cleared = false;

        Ok(())
    }

    async fn touch_activity(&self) {
        let mut last = self.last_activity.write().await;
        *last = (Instant::now(), SystemTime::now());
    }

    /// Fire the cache-hit transparency notification for a committed permit,
    /// if enabled. MUST be called only AFTER `permit.commit()` (or
    /// `commit_authorization`) has returned — while a permit is live its
    /// security read guard blocks revocation, and this must not add
    /// unbounded-latency work there. The notify itself is fire-and-forget
    /// (docs/app-bundle.md §3). Single-sourced so both sign paths keep the
    /// ordering invariant identical.
    fn fire_cache_hit_note(
        &self,
        note: Option<(&'static str, String)>,
        reuse_remaining: Option<Duration>,
    ) {
        if !self.notify_cache_hits {
            return;
        }
        if let Some((operation, label)) = note {
            super::security::notify_cache_hit(operation, &label, reuse_remaining);
        }
    }
}

/// Finish an agent lock transition independently of the requesting
/// connection. Dropping the returned JoinHandle detaches rather than cancels
/// the task, and the owned transition guard prevents a concurrent unlock from
/// publishing `locked = false` before keys and grants are cleared.
fn spawn_lock_finalizer(
    transition: tokio::sync::OwnedMutexGuard<()>,
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    authorization: Arc<AuthorizationEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut keys = keys.write().await;
        keys.clear();
        drop(keys);

        authorization.invalidate_all().await;
        drop(transition);
    })
}

/// Spawn `exe` with `args` as a detached background process. Returns the
/// child PID for logging. The child:
/// - inherits a freshly-built environment containing only `RUN_ENV_PASSTHROUGH`
///   variables (so `VT_AUTH`, `SSH_AUTH_SOCK`, `DYLD_*`, etc. are dropped),
/// - has stdin/stdout/stderr redirected to `/dev/null`,
/// - starts in `$HOME` (or `/` if `HOME` is unset),
/// - calls `setsid` and closes fds >= 3 via `pre_exec` so it cannot interact
///   with the agent's open sockets or terminal,
/// - is reaped by a background tokio task to avoid zombies if it exits while
///   the agent is still running.
fn spawn_detached(exe: &std::path::Path, args: &[String]) -> std::io::Result<u32> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let cwd = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));

    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(&cwd)
        .env_clear();
    for &k in RUN_ENV_PASSTHROUGH {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    // SAFETY: pre_exec runs in the forked child between fork and exec.
    // Only async-signal-safe libc calls are allowed; `setsid` and `close`
    // satisfy that constraint. We do NOT touch heap-allocated state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Close every fd >= 3 so the agent's listener socket,
            // keychain fds, tokio sleeper pipes, etc. don't leak into
            // the child. We cap at the soft RLIMIT_NOFILE so this scales
            // with whatever the agent was started with.
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let max_fd = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0
                && rlim.rlim_cur > 0
                && rlim.rlim_cur < libc::rlim_t::MAX
            {
                rlim.rlim_cur as libc::c_int
            } else {
                1024
            };
            for fd in 3..max_fd {
                libc::close(fd);
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let pid = child.id();

    // Reap asynchronously to avoid zombies. We must own `child` for the
    // entire wait, otherwise `Drop for Child` would leak the zombie.
    tokio::spawn(async move {
        let mut child = child;
        // `child.wait()` is blocking. Hop to the blocking pool so we don't
        // peg a tokio worker for the lifetime of a possibly-long GUI app.
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    });
    Ok(pid)
}

// ---- Static detail-string allow-list ----------------------------------------
//
// Every `&'static str` here is safe to forward to a remote `auth@vt` peer
// (over a forwarded SSH agent socket). They contain no dynamic data — no
// host, command, reason, fingerprint, file path, or user identifier. If you
// add a new constant, audit it against that rule.

const DETAIL_BAD_REQUEST_JSON: &str = "request body could not be parsed";
const DETAIL_UNKNOWN_SECRET_TYPE: &str = "v2 request used an unknown SecretType";
const DETAIL_NOT_INITIALIZED: &str = "agent store could not be unlocked — run `vt init`";
const DETAIL_LEGACY_DISABLED: &str = "legacy decryption disabled (--no-legacy-decrypt)";
const DETAIL_AUTH_REJECTED: &str = "authentication was declined";
const DETAIL_SCREEN_LOCKED: &str = "screen is locked";
const DETAIL_NO_GUI: &str = "no active GUI session";
const DETAIL_AUTH_INVALIDATED: &str = "authorization state changed; retry";
const DETAIL_AUTH_INVALID_TTL: &str = "authorization cache duration is too large";
const DETAIL_INTERNAL_SERIALIZE: &str = "agent failed to serialize response";
// run@vt-specific failure reasons. All strings are static program info
// (no host/argv/user data) and therefore safe to surface to a remote peer.
const DETAIL_RUN_DISABLED: &str = "run@vt disabled (--run-allow not set on agent)";
const DETAIL_RUN_ARGV_EMPTY: &str = "run@vt argv is empty";
const DETAIL_RUN_ARGV_TOO_LARGE: &str = "run@vt argv exceeds size cap";
const DETAIL_DISPLAY_FIELD_TOO_LARGE: &str = "display field exceeds size cap";
const DETAIL_BATCH_TOO_LARGE: &str = "batch exceeds the per-request item cap";
const DETAIL_BATCH_EMPTY: &str = "batch contains no items";
const DETAIL_RUN_NOT_ALLOWLISTED: &str = "run@vt program is not in the agent's allowlist";
const DETAIL_RUN_SPAWN_FAILED: &str = "run@vt failed to spawn the program";
// sign@vt-specific failure reasons. All strings are static program info
// (no key/host/user data) and therefore safe to surface to the client.
const DETAIL_SIGN_BAD_PUBKEY: &str = "sign@vt request public key could not be decoded";
const DETAIL_SIGN_KEYS_LOAD: &str = "sign@vt could not load agent keys";
const DETAIL_SIGN_KEY_NOT_IN_AGENT: &str = "this agent does not hold the requested key";
const DETAIL_SIGN_FAILED: &str = "sign@vt signing operation failed";

/// Map the three auth-outcome-derived [`ErrKind`]s to their canonical
/// detail strings. Defined alongside the `DETAIL_*` constants so the
/// allow-list discipline is enforced in one place.
///
/// Callers must only pass kinds emitted by [`outcome_to_err`]
/// (`AuthRejected` / `SessionLocked` / `NoGuiSession`). Other kinds
/// explicitly map to `None`; the enumeration is exhaustive so a newly
/// added [`ErrKind`] forces a compile error here rather than silently
/// dropping into a wildcard.
fn auth_outcome_detail(kind: ErrKind) -> Option<&'static str> {
    match kind {
        ErrKind::AuthRejected => Some(DETAIL_AUTH_REJECTED),
        ErrKind::SessionLocked => Some(DETAIL_SCREEN_LOCKED),
        ErrKind::NoGuiSession => Some(DETAIL_NO_GUI),
        // These kinds are never produced by `outcome_to_err`; passing one
        // here is a programmer error. Each must be enumerated explicitly
        // so adding a new ErrKind triggers a compile failure (no `_` arm).
        ErrKind::Generic
        | ErrKind::NotInitialized
        | ErrKind::AgentLocked
        | ErrKind::BadRequest
        | ErrKind::LegacyDisabled
        | ErrKind::ProtocolVersion
        | ErrKind::Transient
        | ErrKind::Unknown => None,
    }
}

type WireFailure = (ErrKind, Option<&'static str>);

struct HandlerSuccess {
    bytes: Zeroizing<Vec<u8>>,
    authorization: Option<AuthorizationPermit>,
    /// `(operation, scope display)` when the permit's decision was a cache
    /// hit. The dispatcher fires the transparency notification from this
    /// AFTER `commit()` — never while the permit (and its security read
    /// guard) is live (docs/app-bundle.md §3).
    cache_hit_note: Option<(&'static str, String)>,
}

impl HandlerSuccess {
    fn authorized(bytes: Zeroizing<Vec<u8>>, authorization: AuthorizationPermit) -> Self {
        Self {
            bytes,
            authorization: Some(authorization),
            cache_hit_note: None,
        }
    }

    fn without_authorization(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            authorization: None,
            cache_hit_note: None,
        }
    }

    fn with_cache_hit_note(mut self, note: Option<(&'static str, String)>) -> Self {
        self.cache_hit_note = note;
        self
    }
}

/// Build the dispatcher's post-commit notification note for a permit whose
/// decision was `CacheHit`. `None` label (a fresh basis can't hit — defensive)
/// degrades to the family-free "cached scope".
fn cache_hit_note_for(
    permit: &AuthorizationPermit,
    operation: &'static str,
    reuse_label: &Option<String>,
) -> Option<(&'static str, String)> {
    (permit.decision() == Decision::CacheHit).then(|| {
        (
            operation,
            reuse_label
                .clone()
                .unwrap_or_else(|| "cached scope".to_string()),
        )
    })
}

fn authorization_failure_wire(failure: &AuthorizationFailure) -> WireFailure {
    match failure.decision() {
        Decision::Rejected => (ErrKind::AuthRejected, Some(DETAIL_AUTH_REJECTED)),
        Decision::Unavailable(reason) => {
            let kind =
                outcome_to_err_strict(AuthOutcome::Unavailable(reason)).unwrap_or(ErrKind::Generic);
            (kind, auth_outcome_detail(kind))
        }
        Decision::Invalidated => (ErrKind::Transient, Some(DETAIL_AUTH_INVALIDATED)),
        Decision::CacheHit | Decision::Approved(_) => {
            (ErrKind::Generic, Some(DETAIL_AUTH_INVALIDATED))
        }
    }
}

async fn commit_authorization(permit: AuthorizationPermit) -> Result<(), WireFailure> {
    permit.commit().await.map_err(|error| match error {
        CommitError::Invalidated => (ErrKind::Transient, Some(DETAIL_AUTH_INVALIDATED)),
        CommitError::InvalidTtl => (ErrKind::Generic, Some(DETAIL_AUTH_INVALID_TTL)),
    })
}

// ---- Envelope serialization helpers -----------------------------------------

/// Concrete shape used to serialize an `err` envelope. Mirrors the JSON
/// produced by `ExtResponse<T> { v, body: ExtBody::Err { .. } }`.
#[derive(Serialize)]
struct ErrEnvelope {
    v: u16,
    status: &'static str,
    kind: ErrKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'static str>,
}

#[async_trait]
impl Session for VtSshSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        if self.locked.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }

        // Reload keys from keychain if cleared by idle timeout.
        // Listing public keys is not security-sensitive; Touch ID is
        // enforced on sign/extension requests.
        self.ensure_keys_loaded().await?;
        if self.locked.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }

        let keys = self.keys.read().await;
        let identities = keys
            .values()
            .map(|privkey| Identity {
                pubkey: privkey.public_key().key_data().clone(),
                comment: privkey.comment().to_string(),
            })
            .collect();
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if self.locked.load(Ordering::Acquire) {
            return Err(AgentError::Failure);
        }

        self.ensure_keys_loaded().await?;
        self.touch_activity().await;

        let fp_str = fingerprint_str(&request.pubkey);

        // Clone the key out and drop the read-lock BEFORE the Touch ID prompt.
        // Holding the `keys` read-guard across authorization (which can
        // block on a human for up to ~30s) would starve every writer
        // (add/remove/unlock) for the prompt's duration — a non-VT_AUTH peer can
        // trigger SIGN_REQUESTs to weaponize this. (Mirrors handle_sign_vt.)
        let privkey = {
            let keys = self.keys.read().await;
            keys.get(&fp_str).ok_or(AgentError::Failure)?.clone()
        };
        let comment = privkey.comment();
        // Sanitized like the sign@vt key line: the comment is user-set at add
        // time, so it may not inject fake prompt lines.
        let key_label = if comment.is_empty() {
            fp_str.clone()
        } else {
            sanitize_prompt(comment, 80)
        };
        // Same layout as the sign@vt prompt (header, then key/caller/dest/
        // reuse truth lines) so the two sign paths read as one UI — raw signs
        // just carry no client meta. The caller line replaces the old
        // `sign: key (proc)` parenthetical.
        let mut auth_message = format!("ssh-sign\nkey: {}", key_label);
        self.append_caller_line(&mut auth_message);
        let (scope, reuse_label) = self.raw_sign_scope(&fp_str);
        // The reuse-line label doubles as the grant's display string
        // (ui-status snapshots, cache-hit notifications).
        let scope = scope.with_display(reuse_label.clone().unwrap_or_default());
        // Destination truth line BEFORE the reuse line: with the default
        // TTL of 0 the reuse line never appears, and the verified
        // session-bind destination must still be shown (a non-relay bound
        // peer's reuse label IS the destination label, so `reuse_label`
        // being present means the line below would be a duplicate).
        self.append_destination_line(&mut auth_message, reuse_label.is_some());
        append_reuse_line(&mut auth_message, &reuse_label, self.cache_ttls.sign_secs);
        let audit_ctx = {
            let mut ctx =
                self.audit_ctx_scoped(scope.family(), &reuse_label, self.cache_ttls.sign_secs);
            ctx.key_fp = fp_str.clone();
            ctx.dest = self.audit_destination();
            ctx
        };

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(
                vec![scope],
                ReusePolicy::from_ttl_secs(self.cache_ttls.sign_secs),
                auth_message.clone(),
            ))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "sign",
                    permit.decision().audit_outcome(),
                    "",
                    &crate::core::ClientMeta::default(),
                    &auth_message,
                    "",
                    0,
                    permit.latency_ms(),
                    audit_ctx,
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "sign",
                    failure.decision().audit_outcome(),
                    "",
                    &crate::core::ClientMeta::default(),
                    &auth_message,
                    "",
                    0,
                    failure.latency_ms(),
                    audit_ctx,
                );
                return Err(AgentError::Failure);
            }
        };

        let signature = sign_data_with_privkey(&privkey, &request.data, request.flags)?;
        let cache_hit_note = cache_hit_note_for(&permit, "sign", &reuse_label);
        let reuse_remaining = permit.reuse_remaining();
        permit.commit().await.map_err(|_| AgentError::Failure)?;
        self.fire_cache_hit_note(cache_hit_note, reuse_remaining);
        Ok(signature)
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        // `session-bind@openssh.com` is a standard OpenSSH extension: plain
        // SSH-wire bytes, never VT_AUTH-encrypted. It MUST be intercepted
        // before the lock check and the keychain/auth-cipher path below —
        // binding grants nothing by itself, must work on connections opened
        // while the agent is locked, and would otherwise fail to decrypt so
        // destination caching would silently never engage. It also must not
        // touch the idle clock — it precedes any human-gated operation. A
        // bind that fails to decode (host certificate, unsupported curve) is
        // refused without changing state, mirroring `BindState::apply`. See
        // docs/authorization-scopes-v2.md §3.1.
        if extension.name.as_str() == "session-bind@openssh.com" {
            let outcome = match extension.parse_message::<SessionBind>() {
                Ok(Some(bind)) => {
                    let applied = self.bind_state.apply(&bind);
                    // The label is display-only; compute it once per bind
                    // (≤ MAX_SESSION_BINDS per connection) instead of
                    // re-reading known_hosts on every sign request.
                    self.destination_label = self
                        .bind_state
                        .destination()
                        .map(|(_, hostkey)| destination_label(hostkey));
                    applied
                }
                _ => Err(()),
            };
            return match outcome {
                Ok(()) => Ok(None), // plain SSH_AGENT_SUCCESS
                Err(()) => Err(AgentError::Failure),
            };
        }
        // `ui-status@vt` is the shell's token-gated plaintext channel
        // (docs/app-bundle.md §5). Like session-bind it precedes the lock
        // check (a locked agent must still report `locked: true`), the
        // keychain/auth-cipher path (the shell holds no VT_AUTH), and the
        // idle-clock touch (it is meant to be polled; keeping the agent
        // "active" would defeat the idle revocation). A missing or wrong
        // token fails unstructured — indistinguishable from an unknown
        // extension.
        if extension.name.as_str() == EXT_UI_STATUS {
            return self.handle_ui_status(&extension).await;
        }
        if self.locked.load(Ordering::Acquire) {
            // The lock check fires before keychain ciphers are derived, so
            // we have no `auth_cipher` to encrypt a structured envelope
            // with. Surface as an unstructured SSH-wire failure — clients
            // map this to `ErrKind::Generic` (exit 1) and show a hint to
            // run `ssh-add -X`. See docs/structured-errors.md.
            return Err(AgentError::Failure);
        }

        // Only handle vt custom protocol extensions; ignore standard SSH extensions
        if !matches!(
            extension.name.as_str(),
            EXT_ENCRYPT | EXT_DECRYPT | EXT_AUTH | EXT_RUN | EXT_SIGN | EXT_DIAG
        ) {
            return Ok(None);
        }

        // diag@vt must NOT reset the idle clock: it is read-only, requires no
        // Touch ID, and is meant to be pollable — if it counted as activity,
        // a monitoring loop (or a hostile peer) could keep the agent "active"
        // forever and defeat the idle-timeout key clear and cache flush.
        if extension.name.as_str() != EXT_DIAG {
            self.touch_activity().await;
        }

        // Load the store once, derive auth + passphrase ciphers, drop the
        // store. Mac_cipher is loaded on demand inside the encrypt/decrypt
        // arms so the decrypted master key only lives across that operation.
        //
        // Both failure modes here stay unstructured: `KeychainStore::load`
        // fails before any cipher exists, and `derive_passcode_ciphers` IS
        // the function that produces `auth_cipher`, so its failure means
        // we have no key to encrypt a structured reply with. The client
        // surfaces these as `ErrKind::Generic` via SSH-wire failure.
        let store = KeychainStore::load().map_err(agent_err)?;
        let (auth_cipher, passphrase_cipher) =
            derive_passcode_ciphers(&store).map_err(agent_err)?;

        // Decrypt the extension details with auth cipher (verifies VT_AUTH).
        // Stays unstructured: without VT_AUTH we have no key to encrypt a
        // structured reply, and emitting an unencrypted envelope would be a
        // presence oracle for "is this socket a vt agent?".
        let decrypted = auth_cipher
            .decrypt(extension.details.as_ref())
            .map_err(|_| {
                tracing::warn!("Extension auth failed (wrong VT_AUTH?)");
                AgentError::Failure
            })?;

        // Dispatch into a per-extension handler that returns either
        // serialized ok-body bytes (containing DEKs for encrypt/decrypt —
        // wrapped in Zeroizing so the buffer is wiped on drop) or a
        // structured `(ErrKind, Option<&'static str>)` failure. The handler
        // never returns `AgentError` for vt-level failures; only true
        // transport-layer failures (e.g. an internal serialize call) bubble
        // up as unstructured.
        let dispatch: Result<HandlerSuccess, WireFailure> = match extension.name.as_str() {
            EXT_ENCRYPT => {
                self.handle_encrypt(&decrypted, &store, &passphrase_cipher)
                    .await
            }
            EXT_DECRYPT => {
                self.handle_decrypt(&decrypted, &store, &passphrase_cipher)
                    .await
            }
            EXT_AUTH => self.handle_auth(&decrypted).await,
            EXT_RUN => self.handle_run(&decrypted).await,
            EXT_SIGN => self.handle_sign_vt(&decrypted).await,
            EXT_DIAG => self.handle_diag(&decrypted).await,
            _ => unreachable!(),
        };

        // Build the envelope. OK responses use a manual concat so the
        // serialized inner body (which carries DEKs for encrypt/decrypt) is
        // only ever held in `Zeroizing` buffers — no intermediate
        // `serde_json::Value` allocation that wouldn't be wiped on drop.
        let (envelope_bytes, authorization, cache_hit_note): (
            Zeroizing<Vec<u8>>,
            Option<AuthorizationPermit>,
            Option<(&'static str, String)>,
        ) = match dispatch {
            Ok(success) => (
                Zeroizing::new(wrap_ok_envelope(&success.bytes)),
                success.authorization,
                success.cache_hit_note,
            ),
            Err((kind, detail)) => (
                Zeroizing::new(
                    serde_json::to_vec(&ErrEnvelope {
                        v: WIRE_VERSION,
                        status: "err",
                        kind,
                        detail,
                    })
                    .map_err(|e| agent_err(e.into()))?,
                ),
                None,
                None,
            ),
        };

        // Encrypt the successful response before committing a pending grant.
        // If envelope encryption fails, HandlerSuccess drops its non-cloneable
        // permit and no approval becomes reusable.
        //
        // The commit-failure arm below is defensive: while this permit is
        // alive its security read guard blocks epoch advancement, so
        // `CommitError::Invalidated` cannot fire today. If a future change
        // releases the guard before this point, note that the operation has
        // already executed — a client retrying the resulting Transient error
        // would re-run a non-idempotent handler (run@vt spawns twice).
        let mut encrypted_response = auth_cipher.encrypt(&envelope_bytes).map_err(agent_err)?;
        if let Some(permit) = authorization {
            // Captured before commit consumes the permit; used only after the
            // guard is released — a blocking notify while the permit is live
            // would stall revocation (docs/app-bundle.md §3).
            let reuse_remaining = permit.reuse_remaining();
            if let Err((kind, detail)) = commit_authorization(permit).await {
                tracing::warn!("authorization commit invalidated after operation success");
                let error_envelope = Zeroizing::new(
                    serde_json::to_vec(&ErrEnvelope {
                        v: WIRE_VERSION,
                        status: "err",
                        kind,
                        detail,
                    })
                    .map_err(|e| agent_err(e.into()))?,
                );
                encrypted_response = auth_cipher.encrypt(&error_envelope).map_err(agent_err)?;
            } else {
                self.fire_cache_hit_note(cache_hit_note, reuse_remaining);
            }
        }

        Ok(Some(Extension {
            name: extension.name,
            details: Unparsed::from(encrypted_response),
        }))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        if self.locked.load(Ordering::Acquire) {
            return Err(AgentError::Failure);
        }

        match identity.credential {
            Credential::Key { privkey, comment } => {
                let private_key =
                    PrivateKey::new(privkey, comment.clone()).map_err(AgentError::other)?;
                let pubkey = private_key.public_key();
                let fp_str = fingerprint_str(pubkey.key_data());

                let key_openssh = private_key
                    .to_openssh(ssh_key::LineEnding::LF)
                    .map_err(AgentError::other)?;

                let algorithm = pubkey.algorithm().to_string();
                let fp_for_modify = fp_str.clone();
                let comment_for_modify = comment.clone();
                let key_openssh_str = key_openssh.to_string();
                tokio::task::spawn_blocking(move || {
                    KeychainStore::modify(|store| {
                        let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
                        let (mac_cipher, _mac_key) = load_mac_cipher(store, &passphrase_cipher)?;
                        let mut entries = decode_ssh_keys(store, &mac_cipher).unwrap_or_default();
                        if !entries.iter().any(|e| e.fingerprint == fp_for_modify) {
                            entries.push(SshKeyEntry {
                                fingerprint: fp_for_modify.clone(),
                                algorithm,
                                comment: comment_for_modify,
                                key_data: key_openssh_str,
                            });
                            encode_ssh_keys_into(store, &mac_cipher, &entries)?;
                        }
                        Ok(())
                    })
                })
                .await
                .map_err(|e| agent_err(anyhow::anyhow!("join error: {e}")))?
                .map_err(agent_err)?;

                let mut keys = self.keys.write().await;
                keys.insert(fp_str.clone(), private_key);

                self.touch_activity().await;
                tracing::info!("Added SSH key: {}", fp_str);
                Ok(())
            }
            _ => Err(AgentError::Failure),
        }
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        let fp_str = fingerprint_str(&identity.pubkey);

        let fp_for_modify = fp_str.clone();
        match tokio::task::spawn_blocking(move || {
            KeychainStore::modify(|store| {
                let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
                let (mac_cipher, _mac_key) = load_mac_cipher(store, &passphrase_cipher)?;
                let mut entries = decode_ssh_keys(store, &mac_cipher).unwrap_or_default();
                entries.retain(|e| e.fingerprint != fp_for_modify);
                encode_ssh_keys_into(store, &mac_cipher, &entries)?;
                Ok(())
            })
        })
        .await
        {
            Err(e) => tracing::warn!("remove_identity join error: {}", e),
            Ok(Err(e)) => tracing::warn!("remove_identity keychain update failed: {}", e),
            Ok(Ok(())) => {}
        }

        let mut keys = self.keys.write().await;
        keys.remove(&fp_str);

        tracing::info!("Removed SSH key: {}", fp_str);
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        match tokio::task::spawn_blocking(|| {
            KeychainStore::modify(|store| {
                let (_, passphrase_cipher) = derive_passcode_ciphers(store)?;
                let (mac_cipher, _mac_key) = load_mac_cipher(store, &passphrase_cipher)?;
                encode_ssh_keys_into(store, &mac_cipher, &[])?;
                Ok(())
            })
        })
        .await
        {
            Err(e) => tracing::warn!("remove_all_identities join error: {}", e),
            Ok(Err(e)) => tracing::warn!("remove_all_identities keychain update failed: {}", e),
            Ok(Ok(())) => {}
        }

        let mut keys = self.keys.write().await;
        keys.clear();

        tracing::info!("Removed all SSH keys");
        Ok(())
    }

    async fn lock(&mut self, passphrase: String) -> Result<(), AgentError> {
        let transition = Arc::clone(&self.lock_transition).lock_owned().await;
        if self.locked.load(Ordering::Acquire) {
            return Err(AgentError::Failure);
        }
        let mut lp = self.lock_passphrase.write().await;
        *lp = Some(hash_lock_passphrase(&passphrase));
        // No await between publishing the locked state and spawning the
        // finalizer: cancellation can only happen once the finalizer owns the
        // transition guard and is guaranteed to keep running.
        self.locked.store(true, Ordering::Release);
        drop(lp);

        // Wait for outstanding permits, then advance the epoch even if no
        // grant exists. The finalizer keeps running if this connection drops.
        let finalizer = spawn_lock_finalizer(
            transition,
            Arc::clone(&self.keys),
            Arc::clone(&self.authorization),
        );
        finalizer
            .await
            .map_err(|error| agent_err(anyhow::anyhow!("lock finalizer failed: {error}")))?;

        tracing::info!("Agent locked");
        Ok(())
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        use subtle::ConstantTimeEq;
        use zeroize::Zeroize;

        let _transition = self.lock_transition.lock().await;
        if !self.locked.load(Ordering::Acquire) {
            return Err(AgentError::Failure);
        }
        let candidate = hash_lock_passphrase(&passphrase);
        let lp = self.lock_passphrase.read().await;
        let matches = match lp.as_ref() {
            Some(stored) => stored.ct_eq(&candidate).into(),
            None => false,
        };
        drop(lp);
        if !matches {
            return Err(AgentError::Failure);
        }
        // Reload keys after unlock
        match load_all_keys() {
            Ok(loaded) => {
                let mut keys = self.keys.write().await;
                *keys = loaded;
            }
            Err(e) => {
                tracing::warn!("Failed to reload keys after unlock: {}", e);
            }
        }

        // A cancelled lock request may have published the locked bit before
        // its caller disappeared. Revoke again before unlocking so no grant
        // from before that transition can ever become live again.
        self.authorization.invalidate_all().await;

        // Keep the passphrase intact across every await above. If this future
        // is cancelled, the agent remains locked and a later unlock can retry.
        let mut lp = self.lock_passphrase.write().await;
        if let Some(ref mut hash) = *lp {
            hash.zeroize();
        }
        *lp = None;
        self.locked.store(false, Ordering::Release);

        tracing::info!("Agent unlocked");
        Ok(())
    }
}

// --- Agent startup ---

/// Run the SSH agent on `~/.ssh/vt.sock`.
/// Loads the cipher from keychain to decrypt stored keys, then drops it.
/// When `print_env` is true, prints `export SSH_AUTH_SOCK=...` for eval.
pub async fn run_ssh_agent(
    print_env: bool,
    idle_timeout_secs: u64,
    cache_ttls: AuthCacheTtls,
    disable_legacy_decrypt: bool,
    run_allow: RunAllowlist,
    audit_push: Arc<AuditPushConfig>,
    notify_cache_hits: bool,
    ui_token: Option<[u8; 32]>,
) -> Result<()> {
    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    let socket_path = home.join(".ssh").join("vt.sock");
    // Acquire ownership before Keychain reads/migration. The guard survives
    // every exit path and the signal task, and never removes another socket.
    let (socket_owner, listener) = socket_owner::SocketOwner::bind(&socket_path)?;
    let socket_owner = Arc::new(socket_owner);
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;

    // Transparent wrap v1->v2 upgrade (docs/app-bundle.md §2): flock-guarded,
    // touches only encrypted_passphrase + wrap_v. Failure is non-fatal here —
    // a store bound to a moved binary path surfaces the same error with a
    // clearer remedy below when keys are loaded.
    match super::security::upgrade_wrap_v2_if_needed() {
        Ok(true) => tracing::info!("master-key wrap upgraded to v2 (path-independent)"),
        Ok(false) => {}
        Err(e) => tracing::warn!(
            "master-key wrap v2 upgrade did not run: {e:#} — run `vt secret rebind` \
             (with --old-bin-path if the binary moved)"
        ),
    }

    // Load keys (cipher is loaded and dropped inside load_all_keys)
    let keys = load_all_keys()?;
    tracing::info!("Loaded {} SSH keys", keys.len());

    if print_env {
        println!("export SSH_AUTH_SOCK={};", socket_path.to_string_lossy());
        println!("echo Agent pid {};", std::process::id());
    }

    let run_allow_empty = run_allow.is_empty();
    let audit_enabled = audit_push.enabled;
    let factory = VtSshAgentFactory::new(
        keys,
        cache_ttls,
        disable_legacy_decrypt,
        run_allow,
        audit_push,
        notify_cache_hits,
        ui_token,
        idle_timeout_secs,
    );
    if audit_enabled {
        tracing::info!("Agent audit push enabled");
    }
    if disable_legacy_decrypt {
        tracing::info!("Legacy decrypt path disabled — only v2 envelope URLs accepted");
    }
    if run_allow_empty {
        tracing::info!("run@vt disabled (no --run-allow entries)");
    } else {
        tracing::info!("run@vt enabled (allowlist configured)");
    }

    // Spawn idle sweeper that clears keys from memory after inactivity.
    // Judged on both clocks (see `idle_exceeded`) so time asleep counts.
    // Clearing keys also invalidates unified authorization grants: "idle long enough to drop
    // keys" implies the human is gone, so standing grants must not survive
    // the silent keychain reload that serves the next request.
    let sweeper_keys = Arc::clone(&factory.keys);
    let sweeper_last = Arc::clone(&factory.last_activity);
    let sweeper_idle_cleared = Arc::clone(&factory.idle_cleared);
    let sweeper_authorization = Arc::clone(&factory.authorization);
    let sweeper_timeout = idle_timeout;
    tokio::spawn(async move {
        let check_interval = Duration::from_secs(60).min(sweeper_timeout);
        loop {
            tokio::time::sleep(check_interval).await;
            let (last_mono, last_wall) = *sweeper_last.read().await;
            if idle_exceeded(
                last_mono,
                last_wall,
                Instant::now(),
                SystemTime::now(),
                sweeper_timeout,
            ) {
                // Grants must not outlive the idle window even when no SSH
                // keys are loaded (decrypt-only agents), so the cache flush
                // is unconditional — not tied to the keys branch below.
                let dropped = sweeper_authorization.invalidate_all().await;
                if dropped > 0 {
                    tracing::info!("Idle timeout, dropped {} auth cache grants", dropped);
                }
                let cleared = clear_keys_for_reload(&sweeper_keys, &sweeper_idle_cleared).await;
                if cleared > 0 {
                    tracing::info!(
                        "Idle timeout ({} min), cleared {} keys from memory",
                        sweeper_timeout.as_secs() / 60,
                        cleared
                    );
                }
            }
        }
    });

    // Poll even while the grant store is empty. A human prompt deliberately
    // creates no grant until its protected operation succeeds, so using store
    // emptiness as a watcher shortcut would miss lock/wake invalidation while
    // that prompt is in flight.
    let watcher_authorization = Arc::clone(&factory.authorization);
    let watcher_keys = Arc::clone(&factory.keys);
    let watcher_idle_cleared = Arc::clone(&factory.idle_cleared);
    tokio::spawn(async move {
        let mut was_interactive = super::security::session_interactive_now();
        let mut prev_mono = Instant::now();
        let mut prev_wall = SystemTime::now();
        loop {
            tokio::time::sleep(WATCHER_TICK).await;
            let now_mono = Instant::now();
            let now_wall = SystemTime::now();
            let is_interactive = super::security::session_interactive_now();
            if watcher_should_clear(
                was_interactive,
                is_interactive,
                now_mono.saturating_duration_since(prev_mono),
                now_wall.duration_since(prev_wall).ok(),
            ) {
                let dropped = watcher_authorization.invalidate_all().await;
                // §10 (C): lock/sleep must also wipe decrypted SSH keys from
                // RAM, not just grants — screen lock does not otherwise clear
                // them and (with a long idle timeout) they would linger.
                // `ensure_keys_loaded` reloads silently on the next use once
                // the screen is interactive again.
                let cleared = clear_keys_for_reload(&watcher_keys, &watcher_idle_cleared).await;
                tracing::info!(
                    "Screen lock / wake: {} grants dropped, {} keys cleared from memory",
                    dropped,
                    cleared
                );
            } else {
                watcher_authorization.sweep_expired().await;
            }
            was_interactive = is_interactive;
            prev_mono = now_mono;
            prev_wall = now_wall;
        }
    });
    tracing::info!(
        "Authorization: sign(ttl={}s) decrypt(ttl={}s) auth=fresh run=fresh (0 = always prompt; \
         scopes: destination/workspace/connection — see docs/authorization-scopes-v2.md)",
        cache_ttls.sign_secs,
        cache_ttls.decrypt_secs,
    );

    tracing::info!(
        "SSH agent listening on {} (idle timeout: {} min)",
        socket_path.display(),
        idle_timeout.as_secs() / 60
    );

    // Register signal handler for cleanup
    let signal_owner = Arc::clone(&socket_owner);
    tokio::spawn(async move {
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
        tracing::info!("Cleaning up socket");
        if let Err(error) = signal_owner.cleanup() {
            tracing::warn!("Could not clean agent socket: {error}");
        }
        std::process::exit(0);
    });

    listen(listener, factory)
        .await
        .map_err(|e| anyhow::anyhow!("Agent error: {}", e))?;

    // Cleanup on normal exit
    socket_owner.cleanup()?;
    Ok(())
}

/// Standalone entry point: runs the agent with env output.
pub async fn start_ssh_agent(
    idle_timeout_secs: u64,
    cache_ttls: AuthCacheTtls,
    disable_legacy_decrypt: bool,
    run_allow: RunAllowlist,
    audit_push: Arc<AuditPushConfig>,
    notify_cache_hits: bool,
    ui_token: Option<[u8; 32]>,
) -> Result<()> {
    run_ssh_agent(
        true,
        idle_timeout_secs,
        cache_ttls,
        disable_legacy_decrypt,
        run_allow,
        audit_push,
        notify_cache_hits,
        ui_token,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::authorization::{
        AuthorizationAuthenticator, AuthorizationValidator, ScopeFamily, ValidationError,
    };
    use crate::core::session::AuthMethod;
    use crate::core::{ContextBasis, UiStatusReq, UiStatusRes};

    struct TestAuthenticator;

    #[async_trait]
    impl AuthorizationAuthenticator for TestAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            AuthOutcome::Success(AuthMethod::Biometric)
        }
    }

    struct TestValidator;

    impl AuthorizationValidator for TestValidator {
        fn validate(
            &self,
            _revocation_pending: &AtomicBool,
        ) -> std::result::Result<(), ValidationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn detached_lock_finalizer_holds_transition_and_clears_grants() {
        let authorization =
            AuthorizationEngine::new(Arc::new(TestAuthenticator), Arc::new(TestValidator));
        let subject = (1, 2);
        authorization
            .authorize(AuthorizationRequest::new(
                vec![GrantScope::sign(Some(subject), "cached", "")],
                ReusePolicy::strict_ttl_secs(30),
                "seed",
            ))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let active = authorization
            .authorize(AuthorizationRequest::new(
                vec![GrantScope::sign(Some(subject), "active", "")],
                ReusePolicy::strict_ttl_secs(30),
                "active",
            ))
            .await
            .unwrap();

        let transition = Arc::new(Mutex::new(()));
        let guard = Arc::clone(&transition).lock_owned().await;
        let keys = Arc::new(RwLock::new(HashMap::<String, PrivateKey>::new()));
        let finalizer = spawn_lock_finalizer(guard, keys, Arc::clone(&authorization));
        // Model cancellation of the connection waiting for lock() to finish.
        // Tokio detaches the finalizer, which must retain the owned guard.
        drop(finalizer);
        assert!(transition.try_lock().is_err());

        active.commit().await.unwrap();
        let transition_guard = tokio::time::timeout(Duration::from_secs(1), transition.lock())
            .await
            .expect("detached lock finalizer did not complete");
        drop(transition_guard);
        assert_eq!(
            authorization
                .live_len(Operation::Sign, ScopeFamily::Connection, subject)
                .await,
            0
        );
    }

    // sign@vt's signing core: an Ed25519 PrivateKey signs `data` and the
    // signature verifies under its own public key, tagged `ssh-ed25519`. This is
    // the same code path the standard `Session::sign` now uses (shared helper),
    // so it also guards against algorithm/encoding drift after the refactor.
    #[test]
    fn sign_data_with_privkey_ed25519_signs_and_verifies() {
        use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
        use ssh_key::private::PrivateKey;

        let privkey =
            PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).expect("gen key");
        let data = b"sign@vt test payload";
        let sig = sign_data_with_privkey(&privkey, data, 0).expect("sign");
        assert_eq!(sig.algorithm().to_string(), "ssh-ed25519");

        let pub_bytes: [u8; 32] = match privkey.public_key().key_data() {
            KeyData::Ed25519(k) => k.0,
            _ => unreachable!("generated an Ed25519 key"),
        };
        let vk = VerifyingKey::from_bytes(&pub_bytes).expect("vk");
        let sig_arr: [u8; 64] = sig.as_bytes().try_into().expect("64-byte ed25519 sig");
        vk.verify(data, &DalekSig::from_bytes(&sig_arr))
            .expect("signature must verify under the key's own public key");
    }

    // Regression test for the ssh-key 0.6.7 `TryFrom<&RsaKeypair> for
    // rsa::RsaPrivateKey` bug (passes `p` twice, omits `q` → `Πprimes = p² ≠ n`
    // → `validate()` fails with `InvalidModulus` → `Error::Crypto`). Before the
    // `from_components`-with-correct-p/q fix, this `.expect("sign")` panicked and
    // every RSA identity was unusable ("agent refused operation"). We build the
    // key from a fixed 2048-bit OpenSSH RSA key (no slow keygen), sign under
    // each SHA2 variant OpenSSH requests, and verify each signature under the
    // key's own public modulus so a correct-but-wrong-key regression can't slip
    // through either.
    #[test]
    fn sign_data_with_privkey_rsa_signs_and_verifies() {
        use rsa::signature::Verifier;
        use rsa::{BigUint, RsaPublicKey};
        use ssh_agent_lib::proto::signature;
        use ssh_key::private::PrivateKey;

        // Throwaway key generated solely for this test (never used elsewhere).
        const RSA_TEST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAv1DuBUp4HN3VKYb7f/4iMGxx3pC0r3AEql67eYoT+J5dm21EuOQE
pSz7+B2YnylnQ0ypMEsp0bOn99IlBeG++66Rp18Ypp6RUS8v27gNd4ZoI22gXDpQ3t/EIf
v5FYMNhqHYS9OWCSxwY0pVASVdQkKSV7LX+cD/Q0TwFFe+0pvweXd085T1L/IgD/fvroIb
3ckJ22ENGkdAH6wlcYqsTvxk2avZCRLifUZ+O3htBdfRa7MIuKBqD+QZyouXmkEPwiKkFo
NINzUCJmC19GoiaLwfW0OL2Md60ogmA+HO44k3pGcP2kWPJSO21wfmkLMMv6kLqHSDKUDP
1L+qFkxYXQAAA9DW6UJQ1ulCUAAAAAdzc2gtcnNhAAABAQC/UO4FSngc3dUphvt//iIwbH
HekLSvcASqXrt5ihP4nl2bbUS45ASlLPv4HZifKWdDTKkwSynRs6f30iUF4b77rpGnXxim
npFRLy/buA13hmgjbaBcOlDe38Qh+/kVgw2GodhL05YJLHBjSlUBJV1CQpJXstf5wP9DRP
AUV77Sm/B5d3TzlPUv8iAP9++ughvdyQnbYQ0aR0AfrCVxiqxO/GTZq9kJEuJ9Rn47eG0F
19Frswi4oGoP5BnKi5eaQQ/CIqQWg0g3NQImYLX0aiJovB9bQ4vYx3rSiCYD4c7jiTekZw
/aRY8lI7bXB+aQswy/qQuodIMpQM/Uv6oWTFhdAAAAAwEAAQAAAQAPdTtKH6Z9VJou0Qp8
oLzD81su+7uxqigiWOWmcBblgWw4TPeexcOvUedo+IE2qPqAOE86SPRvzmeNsUPPChqrjM
MVhixAeDLvH5QrGV+zLt+2rxqkIQ0cOPHIuip5x709ydFnbQjkJFxPVXfxUALNQgI/hkKH
mkW1unn4ds+DBjT4JDlNQUsP/u9JLEnQtcsJT4tNrNT3TjqIc6L/MEf84POPI8WDwh/oJr
3txJCSSbDcvZe8e+Dks7Te81efsFqCfVOJdSO2HlYjIT2C60E/jh8+AC5CnXrG8uxw0LVe
Efm47qAy9Jey7CtqtqdWZ/lHYz09xo2jREbAba1Tt4RJAAAAgCSkmvIoXNd4atHlem/xkk
+RdaGh7kLmzuRSnFGSUZbHOxniXTetE80sr4PLpRfmATUw7ARLMYBpMGfVT09hF1FVHhLP
2bZwWNvyQeID3Mf9DdjxDojMrosTBFSDzTcy4vO+tzj2tSQvl64gfIAamhyhkMwziubbX5
xZukhlVfp3AAAAgQD6567L89SEqjrduzyISvkDSdIfhQ/CLCt5e95YJ9kc4jrnHLYx83SJ
dwxb2C9I3QDoOskhDxhxMW3kL1xiIm9WcgBJzkimRImX8DpniNsEc03UEK5ovQxaOXHtV4
7GtxAz6Lk6t1maFY5vskFBL6ZiqAcrYtFI18Xs+fKnOS97NQAAAIEAwzN6JnfM5bJ4uRkO
8ej2jLwDvtol/iOhG5X09snhK/iSuF1HztKhJ+eCM3o2t6fj30uy+UrdnArTZCrIl7EiMm
zlOx88YIANh/5p3Kf6SlADCbea0TJ9bpUQf3BhkzN6cE8RF04Uc3VtvUG1CKcyBr2Tj0TW
d0EI4yKGPuCZ5YkAAAAWdnQtcnNhLXJlZ3Jlc3Npb24tdGVzdAECAwQF
-----END OPENSSH PRIVATE KEY-----
";

        let privkey = PrivateKey::from_openssh(RSA_TEST_KEY).expect("parse RSA test key");
        let data = b"sign@vt rsa regression payload";

        // Public modulus for verification, rebuilt from the ssh public key's
        // Mpint components the same way the signing core rebuilds the private key.
        let mp = |m: &ssh_key::Mpint| {
            BigUint::from_bytes_be(m.as_positive_bytes().expect("positive component"))
        };
        let pubkey = match privkey.public_key().key_data() {
            KeyData::Rsa(k) => RsaPublicKey::new(mp(&k.n), mp(&k.e)).expect("rsa pubkey"),
            _ => unreachable!("embedded key is RSA"),
        };

        // rsa-sha2-256
        let sig =
            sign_data_with_privkey(&privkey, data, signature::RSA_SHA2_256).expect("sign 256");
        assert_eq!(sig.algorithm().to_string(), "rsa-sha2-256");
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pubkey.clone())
            .verify(
                data,
                &rsa::pkcs1v15::Signature::try_from(sig.as_bytes()).expect("sig256"),
            )
            .expect("rsa-sha2-256 signature must verify");

        // rsa-sha2-512
        let sig =
            sign_data_with_privkey(&privkey, data, signature::RSA_SHA2_512).expect("sign 512");
        assert_eq!(sig.algorithm().to_string(), "rsa-sha2-512");
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(pubkey)
            .verify(
                data,
                &rsa::pkcs1v15::Signature::try_from(sig.as_bytes()).expect("sig512"),
            )
            .expect("rsa-sha2-512 signature must verify");

        // NOTE: the legacy ssh-rsa (SHA-1, `flags == 0`) branch is intentionally
        // NOT asserted here. ssh-key 0.6.7 `Signature::new` only accepts RSA
        // signatures with `Algorithm::Rsa { hash: Some(_) }`; a plain `ssh-rsa`
        // (hash: None) hits the catch-all arm and returns `Encoding(Length)`, so
        // that branch of `sign_data_with_privkey` can never succeed on this
        // ssh-key version. That is a pre-existing limitation orthogonal to the
        // from_components fix (which the SHA-2 paths above fully exercise), and
        // SHA-1 ssh-rsa is deprecated (OpenSSH disables it by default ≥ 8.8).
    }

    #[test]
    fn test_ssh_key_entry_serde_roundtrip() {
        let entries = vec![
            SshKeyEntry {
                fingerprint: "SHA256:abcdef123456".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                comment: "test@host".to_string(),
                key_data: "fake-key-data".to_string(),
            },
            SshKeyEntry {
                fingerprint: "SHA256:xyz789".to_string(),
                algorithm: "ssh-rsa".to_string(),
                comment: "another@host".to_string(),
                key_data: "fake-key-data-2".to_string(),
            },
        ];
        let json = serde_json::to_vec(&entries).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].fingerprint, "SHA256:abcdef123456");
        assert_eq!(decoded[0].algorithm, "ssh-ed25519");
        assert_eq!(decoded[0].comment, "test@host");
        assert_eq!(decoded[0].key_data, "fake-key-data");
        assert_eq!(decoded[1].fingerprint, "SHA256:xyz789");
    }

    #[test]
    fn test_ssh_keys_encrypt_decrypt_roundtrip() {
        let key = AesGcmCrypto::generate_key();
        let cipher = AesGcmCrypto::new(&key).unwrap();

        let entries = vec![SshKeyEntry {
            fingerprint: "SHA256:test".to_string(),
            algorithm: "ssh-ed25519".to_string(),
            comment: "test".to_string(),
            key_data:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
                    .to_string(),
        }];

        let json = serde_json::to_vec(&entries).unwrap();
        let encrypted = cipher.encrypt(&json).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].fingerprint, "SHA256:test");
    }

    #[test]
    fn test_decode_ssh_keys_returns_empty_when_field_missing() {
        use super::super::store::KeychainStore;
        let store = KeychainStore::new(&[0u8; 64], &[1u8; 60]);
        let key = AesGcmCrypto::generate_key();
        let cipher = AesGcmCrypto::new(&key).unwrap();
        let entries = decode_ssh_keys(&store, &cipher).unwrap();
        assert!(entries.is_empty());
    }

    // --- Activity-scope classification tests (V2) ---

    pub(super) fn test_session(sign_ttl: u64, decrypt_ttl: u64) -> VtSshSession {
        let locked = Arc::new(AtomicBool::new(false));
        VtSshSession {
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_activity: Arc::new(RwLock::new((Instant::now(), SystemTime::now()))),
            locked: Arc::clone(&locked),
            lock_transition: Arc::new(Mutex::new(())),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            authorization: new_engine(locked),
            cache_ttls: AuthCacheTtls {
                sign_secs: sign_ttl,
                decrypt_secs: decrypt_ttl,
            },
            run_allow: Arc::new(RunAllowlist::parse("").unwrap()),
            audit_push: Arc::new(AuditPushConfig::disabled()),
            peer_pid: Some(std::process::id() as i32),
            peer_exe: Some("test".to_string()),
            peer_is_vt_relay: false,
            peer_is_ssh_client: false,
            connection_subject: None,
            // Pre-set: the lazy resolver would otherwise resolve the test
            // process's real repo workspace.
            workspace: std::sync::OnceLock::from(WorkspaceResolution::NoRoot),
            bind_state: BindState::Unbound,
            destination_label: None,
            disable_legacy_decrypt: false,
            notify_cache_hits: false,
            ui_token: None,
            idle_timeout_secs: 1800,
        }
    }

    pub(super) fn test_bind(
        privkey: &PrivateKey,
        session_id: &[u8],
        forwarding: bool,
    ) -> SessionBind {
        let signature = sign_data_with_privkey(privkey, session_id, 0).expect("sign session id");
        SessionBind {
            host_key: privkey.public_key().key_data().clone(),
            session_id: session_id.to_vec(),
            signature,
            is_forwarding: forwarding,
        }
    }

    pub(super) fn test_hostkey() -> PrivateKey {
        PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).expect("gen key")
    }

    #[tokio::test]
    async fn extension_intercepts_plaintext_session_bind_before_auth_cipher() {
        // The seam most likely to regress: session-bind is plain SSH wire
        // bytes and must be handled before the keychain/auth-cipher path —
        // this test passes precisely because no keychain access happens.
        let mut session = test_session(300, 0);
        session.peer_is_ssh_client = true;
        let host = test_hostkey();
        let ext =
            Extension::new_message(test_bind(&host, b"sid-1", false)).expect("encode session-bind");
        let reply = session
            .extension(ext)
            .await
            .expect("bind must succeed without keychain");
        assert!(reply.is_none(), "plain SSH_AGENT_SUCCESS, no envelope");
        assert!(session.bind_state.destination().is_some());
        assert!(
            session.destination_label.is_some(),
            "label precomputed at bind time"
        );
        assert_eq!(session.sign_basis(), ContextBasis::SessionBind);

        // Malformed bind: refused without poisoning state (an undecodable
        // host key — certificates, unsupported curves — is not an attack).
        let mut session = test_session(300, 0);
        let malformed = Extension {
            name: "session-bind@openssh.com".to_string(),
            details: Unparsed::from(vec![1u8, 2, 3]),
        };
        assert!(session.extension(malformed).await.is_err());
        assert!(matches!(session.bind_state, BindState::Unbound));
    }

    // --- ui-status@vt tests (docs/app-bundle.md §5) ---

    fn ui_status_req(token_b64: &str, action: &str) -> Extension {
        Extension {
            name: EXT_UI_STATUS.to_string(),
            details: Unparsed::from(
                serde_json::to_vec(&UiStatusReq {
                    token: token_b64.to_string(),
                    action: action.to_string(),
                })
                .unwrap(),
            ),
        }
    }

    #[tokio::test]
    async fn ui_status_token_gate_locked_report_and_revoke() {
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
        let token = [7u8; 32];
        let token_b64 = BASE64_URL_SAFE_NO_PAD.encode(token);

        // CLI-started agent (no token configured): a well-formed request is
        // refused — indistinguishable from an unknown extension.
        let mut session = test_session(300, 300);
        assert!(session
            .extension(ui_status_req(&token_b64, "status"))
            .await
            .is_err());

        // Wrong token refused; correct token answers WITHOUT keychain access
        // (this test has no keychain store — like the session-bind test, it
        // passes precisely because the plaintext path never derives ciphers).
        let mut session = test_session(300, 300);
        session.ui_token = Some(token);
        session.authorization =
            AuthorizationEngine::new(Arc::new(TestAuthenticator), Arc::new(TestValidator));
        let wrong = BASE64_URL_SAFE_NO_PAD.encode([8u8; 32]);
        assert!(session
            .extension(ui_status_req(&wrong, "status"))
            .await
            .is_err());
        // Unknown action: token holder still cannot invoke anything but
        // status/revoke_all.
        assert!(session
            .extension(ui_status_req(&token_b64, "approve_all"))
            .await
            .is_err());

        let reply = session
            .extension(ui_status_req(&token_b64, "status"))
            .await
            .unwrap()
            .expect("status reply");
        assert_eq!(reply.name.as_str(), EXT_UI_STATUS);
        let res: UiStatusRes = serde_json::from_slice(reply.details.as_ref()).unwrap();
        assert!(!res.locked);
        assert_eq!(res.sign_ttl_secs, 300);
        assert_eq!(res.idle_timeout_secs, 1800); // test_session default
        assert!(res.grants.is_empty());
        assert!(res.revoked.is_none());

        // A locked agent still reports status (the UI must be able to show
        // the lock) — this rides the pre-lock-check dispatch position.
        session.locked.store(true, Ordering::Release);
        let reply = session
            .extension(ui_status_req(&token_b64, "status"))
            .await
            .unwrap()
            .expect("locked status reply");
        let res: UiStatusRes = serde_json::from_slice(reply.details.as_ref()).unwrap();
        assert!(res.locked);
        session.locked.store(false, Ordering::Release);

        // Snapshot carries the scope display label and expiry; revoke_all
        // drops the grant and advances the epoch (stale commits refused).
        session
            .authorization
            .authorize(AuthorizationRequest::new(
                vec![GrantScope::sign_destination(b"hostkey-wire", "SHA256:k")
                    .with_display("github.com (ED25519 SHA256:hk)")],
                ReusePolicy::strict_ttl_secs(300),
                "seed",
            ))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let reply = session
            .extension(ui_status_req(&token_b64, "status"))
            .await
            .unwrap()
            .unwrap();
        let res: UiStatusRes = serde_json::from_slice(reply.details.as_ref()).unwrap();
        assert_eq!(res.grants.len(), 1);
        let grant = &res.grants[0];
        assert_eq!(grant.operation, "sign");
        assert_eq!(grant.family, "destination");
        assert_eq!(grant.display, "github.com (ED25519 SHA256:hk)");
        assert_eq!(grant.ttl_secs, 300);
        assert!(grant.remaining_secs > 290 && grant.remaining_secs <= 300);

        let reply = session
            .extension(ui_status_req(&token_b64, "revoke_all"))
            .await
            .unwrap()
            .unwrap();
        let res: UiStatusRes = serde_json::from_slice(reply.details.as_ref()).unwrap();
        assert_eq!(res.revoked, Some(1));
        assert!(res.grants.is_empty());
    }

    // --- idle_exceeded tests ---

    #[test]
    fn test_idle_exceeded_counts_sleep_via_wall_clock() {
        // 1s of awake time but 31 minutes of wall time → idle (the mono-only
        // check would have kept keys in memory forever on a nap-happy laptop).
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        let timeout = Duration::from_secs(30 * 60);
        assert!(idle_exceeded(
            m0,
            w0,
            m0 + Duration::from_secs(1),
            w0 + Duration::from_secs(31 * 60),
            timeout,
        ));
    }

    #[test]
    fn test_idle_not_exceeded_when_recently_active() {
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        let timeout = Duration::from_secs(30 * 60);
        assert!(!idle_exceeded(
            m0,
            w0,
            m0 + Duration::from_secs(60),
            w0 + Duration::from_secs(60),
            timeout,
        ));
    }

    #[test]
    fn test_idle_exceeded_via_mono_despite_backwards_wall() {
        // Wall clock stepped backwards (duration_since errors → treated as
        // zero); the monotonic clock alone must still drive the timeout.
        let m0 = Instant::now();
        let w0 = SystemTime::now() + Duration::from_secs(3600);
        let timeout = Duration::from_secs(30 * 60);
        assert!(idle_exceeded(
            m0,
            w0,
            m0 + Duration::from_secs(31 * 60),
            SystemTime::now(),
            timeout,
        ));
    }

    // --- watcher_should_clear tests ---

    #[test]
    fn test_watcher_clears_on_lock_transition() {
        let tick = Duration::from_secs(5);
        assert!(watcher_should_clear(true, false, tick, Some(tick)));
    }

    #[test]
    fn test_watcher_does_not_clear_on_steady_states_or_unlock() {
        let tick = Duration::from_secs(5);
        // Steady locked: the transition already cleared; don't churn.
        assert!(!watcher_should_clear(false, false, tick, Some(tick)));
        // Steady interactive: nothing happened.
        assert!(!watcher_should_clear(true, true, tick, Some(tick)));
        // Unlock: fresh grants after unlock must not be eaten.
        assert!(!watcher_should_clear(false, true, tick, Some(tick)));
    }

    #[test]
    fn test_watcher_clears_on_sleep_divergence() {
        // Wall advanced 5s (tick) + 35s more than mono → system slept.
        let mono = Duration::from_secs(5);
        let wall = Some(Duration::from_secs(40));
        assert!(watcher_should_clear(true, true, mono, wall));
    }

    #[test]
    fn test_watcher_ignores_small_divergence_and_backwards_wall() {
        let mono = Duration::from_secs(5);
        // Small NTP adjustment below the threshold: no clear.
        assert!(!watcher_should_clear(
            true,
            true,
            mono,
            Some(Duration::from_secs(20))
        ));
        // Wall stepped backwards (None): not a sleep signal.
        assert!(!watcher_should_clear(true, true, mono, None));
    }

    // --- AuthMethod::is_cacheable tests ---

    #[test]
    fn test_auth_method_is_cacheable_includes_fido2() {
        // FIDO2 (YubiKey touch) is treated as equivalent to Touch ID for
        // cache-grant purposes — verify the policy is in effect.
        assert!(AuthMethod::Biometric.is_cacheable());
        assert!(AuthMethod::Fido2.is_cacheable());
        assert!(AuthMethod::Password.is_cacheable());
    }
}
