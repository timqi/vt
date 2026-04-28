use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::{listen, Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, Credential, Extension, Identity, RemoveIdentity, SignRequest, Unparsed,
};
use ssh_key::private::{KeypairData, PrivateKey};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::sync::RwLock;

use crate::core::crypto::{derive_dek, AesGcmCrypto};
use crate::core::session::AuthOutcome;
use crate::core::{
    legacy_decrypt, AuthReq, AuthRes, DecryptInput, DecryptReq, DecryptResItem, EncryptReq,
    EncryptResItem, SALT_LEN,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use super::security::{
    authenticate, derive_passcode_ciphers, load_mac_cipher, local_authentication,
};
use super::store::KeychainStore;

/// SSH agent extension names used by vt.
pub const EXT_ENCRYPT: &str = "encrypt@vt";
pub const EXT_DECRYPT: &str = "decrypt@vt";
pub const EXT_AUTH: &str = "auth@vt";

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
pub fn decode_ssh_keys(
    store: &KeychainStore,
    cipher: &AesGcmCrypto,
) -> Result<Vec<SshKeyEntry>> {
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

// --- Auth Cache ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCacheMode {
    None,
    PerSession,
    PerApp,
}

impl FromStr for AuthCacheMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(AuthCacheMode::None),
            "per-session" | "per_session" | "session" => Ok(AuthCacheMode::PerSession),
            "per-app" | "per_app" | "app" => Ok(AuthCacheMode::PerApp),
            _ => Err(format!(
                "invalid auth cache mode '{}': expected none, per-session, or per-app",
                s
            )),
        }
    }
}

impl std::fmt::Display for AuthCacheMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthCacheMode::None => write!(f, "none"),
            AuthCacheMode::PerSession => write!(f, "per-session"),
            AuthCacheMode::PerApp => write!(f, "per-app"),
        }
    }
}

/// Auth cache context: `(context_id, context_start_tvsec)`.
///
/// Including the process start time defeats PID/TTY-device reuse: if the
/// original context process (app or TTY owner) exits and its PID or tdev is
/// recycled, the new process has a different start time and won't match a
/// cached grant.
pub type CacheContext = (u64, u64);

pub struct AuthCache {
    /// Each entry stores when it expires (computed at grant time).
    entries: HashMap<(CacheContext, String), Instant>,
    /// Lifetime of a fresh grant.
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn is_authorized(&self, context: CacheContext, fingerprint: &str) -> bool {
        if let Some(expires_at) = self.entries.get(&(context, fingerprint.to_string())) {
            Instant::now() < *expires_at
        } else {
            false
        }
    }

    /// Strict-TTL grant: a still-valid entry's expiry is left untouched.
    /// Concurrent grants for the same key cannot extend the original TTL.
    /// Expired entries (or absent ones) are replaced with a fresh expiry.
    pub fn grant(&mut self, context: CacheContext, fingerprint: &str) {
        let now = Instant::now();
        let new_expires = now + self.ttl;
        self.entries
            .entry((context, fingerprint.to_string()))
            .and_modify(|expires_at| {
                if *expires_at <= now {
                    *expires_at = new_expires;
                }
            })
            .or_insert(new_expires);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn sweep_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| now < *expires_at);
    }
}

// --- macOS process introspection ---

mod proc_info {
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    const MAXPATHLEN: u32 = 1024;
    const MAXCOMLEN: usize = 16;

    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; MAXCOMLEN],
        pbi_name: [u8; 2 * MAXCOMLEN],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }

    /// Get process BSD info: returns (ppid, tdev, start_tvsec) or None.
    pub fn get_proc_bsdinfo(pid: i32) -> Option<(u32, u32, u64)> {
        let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
        let ret = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if ret == size {
            Some((info.pbi_ppid, info.e_tdev, info.pbi_start_tvsec))
        } else {
            None
        }
    }

    /// Get process executable path.
    pub fn get_proc_path(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; MAXPATHLEN as usize];
        let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN) };
        if ret > 0 {
            buf.truncate(ret as usize);
            String::from_utf8(buf).ok()
        } else {
            None
        }
    }

    /// Get the controlling TTY device number for a process. Returns None
    /// for processes with no controlling terminal (`tdev == 0`) so the
    /// caller can treat them as uncacheable — otherwise every daemon
    /// without a TTY would share a single cache slot keyed on 0.
    pub fn get_tty_dev(pid: i32) -> Option<u32> {
        let (_, tdev, _) = get_proc_bsdinfo(pid)?;
        if tdev == 0 {
            None
        } else {
            Some(tdev)
        }
    }

    /// Get the process start time (seconds since epoch).
    pub fn get_start_tvsec(pid: i32) -> Option<u64> {
        get_proc_bsdinfo(pid).map(|(_, _, s)| s)
    }

    /// Get the session leader PID (POSIX sid) for `pid`.
    ///
    /// Under macOS terminal stacks `forkpty()` calls `setsid()` in the child
    /// before exec, so the resulting shell IS the session leader of its own
    /// session. `getsid()` therefore returns:
    ///   - Terminal.app/iTerm direct shell  → that shell's PID
    ///   - tmux/screen pane shell           → the pane's shell PID (the
    ///                                          multiplexer server has its own
    ///                                          separate session)
    ///   - ssh-spawned remote shell         → that shell's PID
    ///   - nested shells (no setsid)        → the outer shell's PID
    pub fn get_sid(pid: i32) -> Option<i32> {
        let sid = unsafe { libc::getsid(pid) };
        if sid > 0 {
            Some(sid)
        } else {
            None
        }
    }

    /// Walk the process tree upward to find a `.app/Contents/` ancestor.
    /// Returns the PID of the app process, or `peer_pid` itself if no app
    /// ancestor is found — never falls back to the parent, which would
    /// conflate sibling CLI tools sharing a shell.
    pub fn find_app_pid(peer_pid: i32) -> i32 {
        let mut current_pid = peer_pid;
        // Limit traversal to prevent infinite loops
        for _ in 0..64 {
            if current_pid <= 1 {
                break;
            }
            if let Some(path) = get_proc_path(current_pid) {
                if path.contains(".app/Contents/") {
                    return current_pid;
                }
            }
            match get_proc_bsdinfo(current_pid) {
                Some((ppid, _, _)) if ppid > 0 && ppid as i32 != current_pid => {
                    current_pid = ppid as i32;
                }
                _ => break,
            }
        }
        peer_pid
    }
}

// --- SSH Agent ---

/// Hash a lock passphrase to a 32-byte SHA-256 digest.
fn hash_lock_passphrase(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(passphrase.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Default idle timeout: 30 minutes.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30 * 60;
/// Default auth cache duration for sign: 2 minutes.
pub const DEFAULT_AUTH_CACHE_DURATION_SECS: u64 = 120;
/// Default auth cache duration for decrypt@vt: 30 seconds.
/// Shorter than sign because a cached decrypt grant releases per-record DEK
/// material, whose blast radius is wider than a single-challenge signature.
pub const DEFAULT_DECRYPT_AUTH_CACHE_DURATION_SECS: u64 = 30;

/// Configuration for one of the agent's auth caches. Carries (mode, ttl)
/// together so the sign and decrypt caches can't have their fields
/// accidentally swapped at any of the call layers.
#[derive(Debug, Clone, Copy)]
pub struct AuthCacheConfig {
    pub mode: AuthCacheMode,
    pub ttl_secs: u64,
}

/// Derive the decrypt-cache lookup string for a single v2 item.
///
/// Domain-tagged so a digest from this hash can never collide with a digest
/// from any other use of SHA-256 in the codebase. `host` is length-prefixed
/// so the boundary between fields is unambiguous.
///
/// `host` is taken from the client-supplied `DecryptReq.host` and is NOT
/// trusted for security — it only partitions the cache so two different
/// hostnames don't share entries. A compromised peer can lie about `host` to
/// force a cache miss (DoS, not privilege elevation).
fn decrypt_cache_key(t: crate::core::SecretType, salt: &[u8; SALT_LEN], host: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let mut h = Sha256::new();
    h.update(b"vt-decrypt-cache-v1");
    h.update([t.as_byte()]);
    h.update(salt);
    h.update((host.len() as u32).to_le_bytes());
    h.update(host.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        let _ = write!(s, "{:02x}", b);
    }
    s
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

/// Get the peer PID from a Unix stream using macOS LOCAL_PEERPID.
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut pid_size = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut pid_size,
        )
    };
    if ret == 0 && pid > 0 {
        Some(pid)
    } else {
        None
    }
}

// --- Factory (shared state, implements Agent) ---

pub struct VtSshAgentFactory {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<Instant>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    sign_auth_cache: Arc<RwLock<AuthCache>>,
    decrypt_auth_cache: Arc<RwLock<AuthCache>>,
    sign_cache_mode: AuthCacheMode,
    decrypt_cache_mode: AuthCacheMode,
    /// When true, `decrypt@vt` rejects `Legacy` items (v0/v1 URLs). v2 envelope
    /// items continue to work. Lets users who have fully migrated harden the
    /// agent so the "agent emits plaintext over wire" path can never be
    /// triggered.
    disable_legacy_decrypt: bool,
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        sign_cache: AuthCacheConfig,
        decrypt_cache: AuthCacheConfig,
        disable_legacy_decrypt: bool,
    ) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            locked: Arc::new(RwLock::new(false)),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            sign_auth_cache: Arc::new(RwLock::new(AuthCache::new(sign_cache.ttl_secs))),
            decrypt_auth_cache: Arc::new(RwLock::new(AuthCache::new(decrypt_cache.ttl_secs))),
            sign_cache_mode: sign_cache.mode,
            decrypt_cache_mode: decrypt_cache.mode,
            disable_legacy_decrypt,
        }
    }
}

/// Resolve the auth-cache context for this session.
///
/// Returns `None` when the session must not be cached (no peer PID,
/// `tdev == 0` for per-session, or missing proc info). The context is
/// captured once at session creation — not recomputed per request — so a
/// cache lookup can never race proc-tree state between connection and the
/// actual `sign` call.
///
/// `PerSession` keys on the **session leader's** PID and start time, not the
/// peer process's. The peer process (e.g. `gh`, `vt read`) is short-lived and
/// has a unique start_tvsec per invocation, so anchoring on it would prevent
/// the cache from ever hitting across separate CLI calls. The session leader
/// (the shell at the head of the pty — see `proc_info::get_sid`) lives for the
/// full terminal session, giving the cache a stable anchor. `tdev != 0` is
/// still required so daemons without a controlling terminal stay uncacheable.
fn resolve_cache_context(
    peer_pid: Option<i32>,
    mode: AuthCacheMode,
) -> Option<CacheContext> {
    let pid = peer_pid?;
    // Both cache modes require the peer to have a controlling terminal.
    // launchd-managed daemons and other non-interactive peers always prompt
    // and never enter the cache — caching only makes sense for explicit
    // human-driven terminal sessions.
    if matches!(mode, AuthCacheMode::PerSession | AuthCacheMode::PerApp)
        && proc_info::get_tty_dev(pid).is_none()
    {
        return None;
    }
    match mode {
        AuthCacheMode::None => None,
        AuthCacheMode::PerSession => {
            let sid = proc_info::get_sid(pid)?;
            let start = proc_info::get_start_tvsec(sid)?;
            Some((sid as u64, start))
        }
        AuthCacheMode::PerApp => {
            let app_pid = proc_info::find_app_pid(pid);
            let start = proc_info::get_start_tvsec(app_pid)?;
            Some((app_pid as u64, start))
        }
    }
}

impl Agent<tokio::net::UnixListener> for VtSshAgentFactory {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        let peer_pid = get_peer_pid(socket);
        if let Some(pid) = peer_pid {
            tracing::debug!("New session from PID {}", pid);
        }
        let sign_cache_context = resolve_cache_context(peer_pid, self.sign_cache_mode);
        let decrypt_cache_context = resolve_cache_context(peer_pid, self.decrypt_cache_mode);
        VtSshSession {
            keys: Arc::clone(&self.keys),
            last_activity: Arc::clone(&self.last_activity),
            locked: Arc::clone(&self.locked),
            lock_passphrase: Arc::clone(&self.lock_passphrase),
            idle_cleared: Arc::clone(&self.idle_cleared),
            sign_auth_cache: Arc::clone(&self.sign_auth_cache),
            decrypt_auth_cache: Arc::clone(&self.decrypt_auth_cache),
            peer_pid,
            sign_cache_context,
            decrypt_cache_context,
            disable_legacy_decrypt: self.disable_legacy_decrypt,
        }
    }
}

// --- Per-connection session (implements Session) ---

struct VtSshSession {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<Instant>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    sign_auth_cache: Arc<RwLock<AuthCache>>,
    decrypt_auth_cache: Arc<RwLock<AuthCache>>,
    peer_pid: Option<i32>,
    /// Resolved once at session creation. `None` = always prompt for sign.
    sign_cache_context: Option<CacheContext>,
    /// Resolved once at session creation. `None` = always prompt for decrypt.
    decrypt_cache_context: Option<CacheContext>,
    disable_legacy_decrypt: bool,
}

impl VtSshSession {
    /// Ensure keys are loaded. If they were cleared by the idle sweeper,
    /// silently reload from keychain. Touch ID is enforced per sign/extension
    /// request via `check_or_prompt_auth()` using the normal cache rules.
    async fn ensure_keys_loaded(&self) -> Result<(), AgentError> {
        let keys = self.keys.read().await;
        if !keys.is_empty() {
            return Ok(());
        }
        drop(keys);

        // Check if keys were cleared by idle timeout (vs just being empty)
        let idle = *self.idle_cleared.read().await;
        if !idle {
            return Ok(());
        }

        tracing::info!("Keys cleared by idle timeout, reloading from keychain");
        let loaded = load_all_keys().map_err(agent_err)?;
        tracing::info!("Reloaded {} SSH keys", loaded.len());
        let mut keys = self.keys.write().await;
        *keys = loaded;

        // Reset idle_cleared flag
        let mut idle_cleared = self.idle_cleared.write().await;
        *idle_cleared = false;

        Ok(())
    }

    async fn touch_activity(&self) {
        let mut last = self.last_activity.write().await;
        *last = Instant::now();
    }

    /// Check auth cache or prompt the user. Returns true if authorized.
    ///
    /// Used for `sign` (SSH authentication). `auth@vt` always prompts because
    /// forwarded agents share one local process. `decrypt@vt` has its own
    /// cache (see `check_or_prompt_decrypt_batch`).
    ///
    /// All three success methods (Biometric, FIDO2, Password) are cached:
    /// FIDO2 (YubiKey touch) is treated as equivalent to Touch ID for
    /// authorization purposes — a deliberate policy choice.
    async fn check_or_prompt_auth(&self, fingerprint: &str, auth_message: &str) -> bool {
        // If we couldn't resolve a cache context at session creation (no
        // peer PID, no TTY, missing proc info), always prompt.
        let Some(context) = self.sign_cache_context else {
            return local_authentication(auth_message);
        };

        // Check cache (read lock, released before auth prompt)
        {
            let cache = self.sign_auth_cache.read().await;
            if cache.is_authorized(context, fingerprint) {
                tracing::debug!(
                    "Sign auth cache hit for context={:?} fingerprint={}",
                    context,
                    fingerprint
                );
                return true;
            }
        }

        // Prompt (no locks held)
        let method = match authenticate(auth_message) {
            AuthOutcome::Success(m) => m,
            AuthOutcome::Rejected => return false,
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!(
                    "Auth unavailable for fingerprint={} reason={:?}",
                    fingerprint,
                    reason
                );
                return false;
            }
        };

        if method.is_cacheable() {
            let mut cache = self.sign_auth_cache.write().await;
            cache.grant(context, fingerprint);
            tracing::debug!(
                "Sign auth cache grant for context={:?} fingerprint={} method={:?}",
                context,
                fingerprint,
                method
            );
        }

        true
    }

    /// Cache-aware authorization for a `decrypt@vt` batch.
    ///
    /// Any legacy item in the batch disables caching for the whole batch —
    /// legacy items release plaintext, and the invariant "legacy-containing
    /// batch always prompts" is load-bearing for that decision. Otherwise:
    /// full hit skips Touch ID; partial hit prompts once and grants only the
    /// previously-missing items so existing strict TTLs are not refreshed.
    async fn check_or_prompt_decrypt_batch(
        &self,
        v2_items: &[(crate::core::SecretType, [u8; SALT_LEN])],
        has_legacy: bool,
        host: &str,
        auth_message: &str,
    ) -> bool {
        // Cacheable iff there's a resolved context AND the batch is non-empty
        // pure-v2; everything else falls through to the always-prompt path.
        let context = match self.decrypt_cache_context {
            Some(c) if !has_legacy && !v2_items.is_empty() => c,
            _ => return matches!(authenticate(auth_message), AuthOutcome::Success(_)),
        };

        let keys: Vec<String> = v2_items
            .iter()
            .map(|(t, salt)| decrypt_cache_key(*t, salt, host))
            .collect();

        let missing: Vec<String> = {
            let cache = self.decrypt_auth_cache.read().await;
            keys.iter()
                .filter(|k| !cache.is_authorized(context, k))
                .cloned()
                .collect()
        };

        if missing.is_empty() {
            tracing::debug!(
                "Decrypt auth cache hit for context={:?} ({} v2 items)",
                context,
                v2_items.len()
            );
            return true;
        }

        let method = match authenticate(auth_message) {
            AuthOutcome::Success(m) => m,
            AuthOutcome::Rejected => return false,
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!("decrypt@vt unavailable: {:?}", reason);
                return false;
            }
        };

        if method.is_cacheable() {
            let mut cache = self.decrypt_auth_cache.write().await;
            for k in &missing {
                cache.grant(context, k);
            }
            tracing::debug!(
                "Decrypt auth cache grant for context={:?} method={:?} new_entries={}",
                context,
                method,
                missing.len()
            );
        }

        true
    }
}

#[async_trait]
impl Session for VtSshSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Ok(Vec::new());
        }
        drop(locked);

        // Reload keys from keychain if cleared by idle timeout.
        // Listing public keys is not security-sensitive; Touch ID is
        // enforced on sign/extension requests.
        self.ensure_keys_loaded().await?;

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
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

        self.ensure_keys_loaded().await?;
        self.touch_activity().await;

        let fp_str = fingerprint_str(&request.pubkey);

        let keys = self.keys.read().await;
        let privkey = keys.get(&fp_str).ok_or(AgentError::Failure)?;
        let comment = privkey.comment();
        let proc_name = self
            .peer_pid
            .and_then(proc_info::get_proc_path)
            .and_then(|p| p.rsplit('/').next().map(String::from))
            .unwrap_or_default();
        let key_label = if comment.is_empty() {
            fp_str.clone()
        } else {
            comment.to_string()
        };
        let auth_message = if proc_name.is_empty() {
            format!("SSH sign: {}", key_label)
        } else {
            format!("SSH sign: {} by {}", key_label, proc_name)
        };

        // Check auth cache or prompt Touch ID
        if !self.check_or_prompt_auth(&fp_str, &auth_message).await {
            return Err(AgentError::Failure);
        }

        match privkey.key_data() {
            KeypairData::Ed25519(ref key) => {
                use ed25519_dalek::Signer;
                let signing_key: ed25519_dalek::SigningKey =
                    key.try_into().map_err(AgentError::other)?;
                let sig = signing_key.sign(&request.data);
                Signature::new(Algorithm::Ed25519, sig.to_bytes().to_vec())
                    .map_err(AgentError::other)
            }
            KeypairData::Rsa(ref key) => {
                use rsa::pkcs1v15::SigningKey;
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                use ssh_agent_lib::proto::signature;

                let private_key: rsa::RsaPrivateKey = key.try_into().map_err(AgentError::other)?;
                let mut rng = rand::thread_rng();

                if request.flags & signature::RSA_SHA2_512 != 0 {
                    let sig = SigningKey::<sha2::Sha512>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
                    Signature::new(
                        Algorithm::new("rsa-sha2-512").map_err(AgentError::other)?,
                        sig.to_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                } else if request.flags & signature::RSA_SHA2_256 != 0 {
                    let sig = SigningKey::<sha2::Sha256>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
                    Signature::new(
                        Algorithm::new("rsa-sha2-256").map_err(AgentError::other)?,
                        sig.to_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                } else {
                    let sig = SigningKey::<sha1::Sha1>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
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
                        let sig: p256::ecdsa::DerSignature = signing_key.sign(&request.data);
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
                        let sig: p384::ecdsa::DerSignature = signing_key.sign(&request.data);
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

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

        // Only handle vt custom protocol extensions; ignore standard SSH extensions
        if !matches!(extension.name.as_str(), EXT_ENCRYPT | EXT_DECRYPT | EXT_AUTH) {
            return Ok(None);
        }

        self.touch_activity().await;

        // Load the store once, derive auth + passphrase ciphers, drop the
        // store. Mac_cipher is loaded on demand inside the encrypt/decrypt
        // arms so the decrypted master key only lives across that operation.
        let store = KeychainStore::load().map_err(agent_err)?;
        let (auth_cipher, passphrase_cipher) =
            derive_passcode_ciphers(&store).map_err(agent_err)?;

        // Decrypt the extension details with auth cipher (verifies VT_AUTH)
        let decrypted = auth_cipher
            .decrypt(extension.details.as_ref())
            .map_err(|_| {
                tracing::warn!("Extension auth failed (wrong VT_AUTH?)");
                AgentError::Failure
            })?;

        let response_bytes: Zeroizing<Vec<u8>> = match extension.name.as_str() {
            EXT_ENCRYPT => {
                // v2 envelope: agent allocates a fresh per-record (salt, DEK)
                // pair for each requested SecretType. The agent NEVER receives
                // plaintext on this path. The salt is generated server-side
                // (never accepted from the client) — this is the security
                // invariant that prevents an attacker holding `VT_AUTH` from
                // extracting a salt from a stored vt://0{salt||ct} URL and
                // requesting its DEK to bypass Touch ID.
                let req: EncryptReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                let (_mac_cipher, mac_key) =
                    load_mac_cipher(&store, &passphrase_cipher).map_err(agent_err)?;
                let mut result: Vec<EncryptResItem> = Vec::with_capacity(req.types.len());
                for _t in &req.types {
                    let mut salt = [0u8; SALT_LEN];
                    rand::thread_rng().fill_bytes(&mut salt);
                    let dek = derive_dek(&mac_key, &salt);
                    result.push(EncryptResItem {
                        salt,
                        dek,
                        err_message: String::new(),
                    });
                }
                drop(mac_key);
                let bytes = serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?;
                // The DEKs now live inside `bytes`; scrub the in-memory
                // `Vec<EncryptResItem>` copy before it falls out of scope.
                for item in result.iter_mut() {
                    item.dek.zeroize();
                }
                Zeroizing::new(bytes)
            }
            EXT_DECRYPT => {
                let req: DecryptReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;

                // Reject `SecretType::UNKNOWN` v2 items: serde would otherwise
                // accept them from a malformed `DecryptInput::V2`, the
                // downstream decrypt would fail on AAD mismatch, but the
                // cache could be polluted with `t.as_byte() == b'_'` entries
                // in the meantime.
                let mut legacy_count = 0usize;
                let mut v2_inputs: Vec<(crate::core::SecretType, [u8; SALT_LEN])> =
                    Vec::with_capacity(req.items.len());
                for item in &req.items {
                    match item {
                        DecryptInput::V2 {
                            t: crate::core::SecretType::UNKNOWN,
                            ..
                        } => {
                            tracing::warn!("decrypt@vt rejecting v2 item with UNKNOWN type");
                            return Err(AgentError::Failure);
                        }
                        DecryptInput::V2 { t, salt } => v2_inputs.push((*t, *salt)),
                        DecryptInput::Legacy { .. } => legacy_count += 1,
                    }
                }
                let local_auth_message = format!(
                    "decrypt {} items ({} legacy plaintext + {} v2 key-release) from {} to run `{}`",
                    req.items.len(),
                    legacy_count,
                    v2_inputs.len(),
                    req.host,
                    req.command,
                );
                // Cache-aware authorization. Pure v2 batches may skip the
                // prompt on a full hit; any legacy item disables caching for
                // the entire batch.
                if !self
                    .check_or_prompt_decrypt_batch(
                        &v2_inputs,
                        legacy_count > 0,
                        &req.host,
                        &local_auth_message,
                    )
                    .await
                {
                    return Err(AgentError::Failure);
                }
                let (mac_cipher, mac_key) =
                    load_mac_cipher(&store, &passphrase_cipher).map_err(agent_err)?;
                let mut result: Vec<DecryptResItem> = Vec::with_capacity(req.items.len());
                for item in req.items {
                    match item {
                        DecryptInput::V2 { t: _, salt } => {
                            let dek = derive_dek(&mac_key, &salt);
                            result.push(DecryptResItem::V2 {
                                dek,
                                err_message: String::new(),
                            });
                        }
                        DecryptInput::Legacy { url } => {
                            if self.disable_legacy_decrypt {
                                result.push(DecryptResItem::Legacy {
                                    result: String::new(),
                                    err_message:
                                        "legacy decryption disabled on this agent".to_string(),
                                });
                            } else {
                                let item = legacy_decrypt(&mac_cipher, &url);
                                result.push(DecryptResItem::Legacy {
                                    result: item.result,
                                    err_message: item.err_message,
                                });
                            }
                        }
                    }
                }
                drop(mac_key);
                let bytes = serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?;
                // Scrub DEKs inside the response Vec before drop. `bytes`
                // already carries them (still wiped via `Zeroizing` below).
                for item in result.iter_mut() {
                    if let DecryptResItem::V2 { dek, .. } = item {
                        dek.zeroize();
                    }
                }
                Zeroizing::new(bytes)
            }
            EXT_AUTH => {
                let req: AuthReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;

                // Sanitize untrusted remote strings: strip control chars, truncate
                let sanitize = |s: &str| -> String {
                    s.chars().filter(|c| !c.is_control()).take(100).collect()
                };
                let reason = sanitize(&req.reason);
                let host = sanitize(&req.host);

                let auth_message = format!("bio auth: {} from {}", reason, host);

                // Always prompt Touch ID — no auth caching for auth@vt.
                // Over forwarded agents, all remote sessions share the same local
                // process, so caching would approve all sudo from any session.
                match authenticate(&auth_message) {
                    AuthOutcome::Success(_) => {}
                    AuthOutcome::Rejected => return Err(AgentError::Failure),
                    AuthOutcome::Unavailable(reason) => {
                        tracing::warn!("auth@vt unavailable: {:?}", reason);
                        return Err(AgentError::Failure);
                    }
                }

                let result = AuthRes { approved: true };
                Zeroizing::new(serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?)
            }
            _ => unreachable!(),
        };

        // Encrypt response with auth cipher
        let encrypted_response = auth_cipher.encrypt(&response_bytes).map_err(agent_err)?;

        Ok(Some(Extension {
            name: extension.name,
            details: Unparsed::from(encrypted_response),
        }))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

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
        let mut locked = self.locked.write().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        *locked = true;
        let mut lp = self.lock_passphrase.write().await;
        *lp = Some(hash_lock_passphrase(&passphrase));

        // Clear keys from memory on lock
        let mut keys = self.keys.write().await;
        keys.clear();

        // Clear both auth caches on lock.
        self.sign_auth_cache.write().await.clear();
        self.decrypt_auth_cache.write().await.clear();

        tracing::info!("Agent locked");
        Ok(())
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        use subtle::ConstantTimeEq;
        use zeroize::Zeroize;

        let mut locked = self.locked.write().await;
        if !*locked {
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
        *locked = false;
        let mut lp = self.lock_passphrase.write().await;
        if let Some(ref mut hash) = *lp {
            hash.zeroize();
        }
        *lp = None;

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
    sign_cache: AuthCacheConfig,
    decrypt_cache: AuthCacheConfig,
    disable_legacy_decrypt: bool,
) -> Result<()> {
    let idle_timeout = Duration::from_secs(idle_timeout_secs);

    // Load keys (cipher is loaded and dropped inside load_all_keys)
    let keys = load_all_keys()?;
    tracing::info!("Loaded {} SSH keys", keys.len());

    // Resolve socket path
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    let socket_path = home.join(".ssh").join("vt.sock");

    // Clean stale socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Ensure .ssh dir exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if print_env {
        println!("export SSH_AUTH_SOCK={};", socket_path.to_string_lossy());
        println!("echo Agent pid {};", std::process::id());
    }

    let factory =
        VtSshAgentFactory::new(keys, sign_cache, decrypt_cache, disable_legacy_decrypt);
    if disable_legacy_decrypt {
        tracing::info!("Legacy decrypt path disabled — only v2 envelope URLs accepted");
    }

    // Spawn idle sweeper that clears keys from memory after inactivity
    let sweeper_keys = Arc::clone(&factory.keys);
    let sweeper_last = Arc::clone(&factory.last_activity);
    let sweeper_idle_cleared = Arc::clone(&factory.idle_cleared);
    let sweeper_timeout = idle_timeout;
    tokio::spawn(async move {
        let check_interval = Duration::from_secs(60).min(sweeper_timeout);
        loop {
            tokio::time::sleep(check_interval).await;
            let last = *sweeper_last.read().await;
            if last.elapsed() >= sweeper_timeout {
                let mut keys = sweeper_keys.write().await;
                if !keys.is_empty() {
                    let count = keys.len();
                    keys.clear();
                    let mut idle_cleared = sweeper_idle_cleared.write().await;
                    *idle_cleared = true;
                    tracing::info!(
                        "Idle timeout ({} min), cleared {} keys from memory",
                        sweeper_timeout.as_secs() / 60,
                        count
                    );
                }
            }
        }
    });

    // Spawn auth cache sweeper (sweeps both sign and decrypt caches).
    if sign_cache.mode != AuthCacheMode::None || decrypt_cache.mode != AuthCacheMode::None {
        let sweeper_sign = Arc::clone(&factory.sign_auth_cache);
        let sweeper_decrypt = Arc::clone(&factory.decrypt_auth_cache);
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(60);
            loop {
                tokio::time::sleep(check_interval).await;
                sweeper_sign.write().await.sweep_expired();
                sweeper_decrypt.write().await.sweep_expired();
            }
        });
        tracing::info!(
            "Auth cache: sign(mode={}, ttl={}s) decrypt(mode={}, ttl={}s); auth@vt never cached",
            sign_cache.mode,
            sign_cache.ttl_secs,
            decrypt_cache.mode,
            decrypt_cache.ttl_secs,
        );
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!(
        "SSH agent listening on {} (idle timeout: {} min)",
        socket_path.display(),
        idle_timeout.as_secs() / 60
    );

    // Register signal handler for cleanup
    let socket_path_clone = socket_path.clone();
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
        let _ = std::fs::remove_file(&socket_path_clone);
        std::process::exit(0);
    });

    listen(listener, factory)
        .await
        .map_err(|e| anyhow::anyhow!("Agent error: {}", e))?;

    // Cleanup on normal exit
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Standalone entry point: runs the agent with env output.
pub async fn start_ssh_agent(
    idle_timeout_secs: u64,
    sign_cache: AuthCacheConfig,
    decrypt_cache: AuthCacheConfig,
    disable_legacy_decrypt: bool,
) -> Result<()> {
    run_ssh_agent(
        true,
        idle_timeout_secs,
        sign_cache,
        decrypt_cache,
        disable_legacy_decrypt,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::AuthMethod;

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

    // --- AuthCacheMode tests ---

    #[test]
    fn test_auth_cache_mode_from_str() {
        assert_eq!(
            AuthCacheMode::from_str("none").unwrap(),
            AuthCacheMode::None
        );
        assert_eq!(
            AuthCacheMode::from_str("per-session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("per_session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("per-app").unwrap(),
            AuthCacheMode::PerApp
        );
        assert_eq!(
            AuthCacheMode::from_str("per_app").unwrap(),
            AuthCacheMode::PerApp
        );
        assert_eq!(
            AuthCacheMode::from_str("app").unwrap(),
            AuthCacheMode::PerApp
        );
    }

    #[test]
    fn test_auth_cache_mode_from_str_case_insensitive() {
        assert_eq!(
            AuthCacheMode::from_str("None").unwrap(),
            AuthCacheMode::None
        );
        assert_eq!(
            AuthCacheMode::from_str("NONE").unwrap(),
            AuthCacheMode::None
        );
        assert_eq!(
            AuthCacheMode::from_str("Per-Session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("PER-APP").unwrap(),
            AuthCacheMode::PerApp
        );
    }

    #[test]
    fn test_auth_cache_mode_from_str_invalid() {
        assert!(AuthCacheMode::from_str("invalid").is_err());
        assert!(AuthCacheMode::from_str("").is_err());
        assert!(AuthCacheMode::from_str("per").is_err());
    }

    #[test]
    fn test_auth_cache_mode_display() {
        assert_eq!(AuthCacheMode::None.to_string(), "none");
        assert_eq!(AuthCacheMode::PerSession.to_string(), "per-session");
        assert_eq!(AuthCacheMode::PerApp.to_string(), "per-app");
    }

    // --- AuthCache tests ---

    #[test]
    fn test_auth_cache_grant_and_hit() {
        let mut cache = AuthCache::new(300);
        let ctx = (1u64, 100u64);
        assert!(!cache.is_authorized(ctx, "fp1"));

        cache.grant(ctx, "fp1");
        assert!(cache.is_authorized(ctx, "fp1"));
    }

    #[test]
    fn test_auth_cache_grant_is_strict_ttl_idempotent() {
        // A repeated grant on a still-valid entry must NOT extend its TTL —
        // otherwise concurrent grants from racing sessions would silently
        // refresh the entry and violate the strict-TTL invariant.
        let mut cache = AuthCache::new(300);
        let ctx = (1u64, 100u64);
        cache.grant(ctx, "fp1");
        let first_expiry = *cache.entries.get(&(ctx, "fp1".to_string())).unwrap();

        // Sleep long enough that a second grant would compute a strictly
        // later expiry if it were allowed to overwrite.
        std::thread::sleep(std::time::Duration::from_millis(20));
        cache.grant(ctx, "fp1");
        let second_expiry = *cache.entries.get(&(ctx, "fp1".to_string())).unwrap();
        assert_eq!(
            first_expiry, second_expiry,
            "valid entry's TTL must not be refreshed by a repeat grant"
        );
    }

    #[test]
    fn test_auth_cache_grant_replaces_expired_entry() {
        // An expired entry (still in the map because the sweeper hasn't run
        // yet) must be replaced by a fresh grant — otherwise a successful
        // re-auth after expiry would silently fail to populate the cache.
        let mut cache = AuthCache::new(0);
        let ctx = (1u64, 100u64);
        cache.grant(ctx, "fp1");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!cache.is_authorized(ctx, "fp1"), "entry should be expired");

        // Switch to a non-zero TTL and re-grant; the entry is replaced with
        // a fresh expiry.
        cache.ttl = std::time::Duration::from_secs(300);
        cache.grant(ctx, "fp1");
        assert!(cache.is_authorized(ctx, "fp1"));
    }

    #[test]
    fn test_auth_cache_different_context_misses() {
        let mut cache = AuthCache::new(300);
        let ctx1 = (1u64, 100u64);
        let ctx2 = (2u64, 100u64);
        cache.grant(ctx1, "fp1");

        // Same fingerprint, different context
        assert!(!cache.is_authorized(ctx2, "fp1"));
        // Same context, different fingerprint
        assert!(!cache.is_authorized(ctx1, "fp2"));
    }

    #[test]
    fn test_auth_cache_start_time_distinguishes_reused_pid() {
        // Same PID, different start time → different context (PID reuse)
        let mut cache = AuthCache::new(300);
        let orig = (1234u64, 1_700_000_000u64);
        let reused = (1234u64, 1_700_000_500u64);
        cache.grant(orig, "fp1");

        assert!(cache.is_authorized(orig, "fp1"));
        assert!(!cache.is_authorized(reused, "fp1"));
    }

    #[test]
    fn test_auth_cache_expiry() {
        let mut cache = AuthCache::new(0); // 0 second duration = immediately expired
        let ctx = (1u64, 100u64);
        cache.grant(ctx, "fp1");

        // With 0 duration, entries expire immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!cache.is_authorized(ctx, "fp1"));
    }

    #[test]
    fn test_auth_cache_clear() {
        let mut cache = AuthCache::new(300);
        let ctx1 = (1u64, 100u64);
        let ctx2 = (2u64, 100u64);
        cache.grant(ctx1, "fp1");
        cache.grant(ctx2, "fp2");
        assert!(cache.is_authorized(ctx1, "fp1"));

        cache.clear();
        assert!(!cache.is_authorized(ctx1, "fp1"));
        assert!(!cache.is_authorized(ctx2, "fp2"));
    }

    #[test]
    fn test_auth_cache_sweep_expired() {
        let mut cache = AuthCache::new(0); // 0 second = immediately expired
        cache.grant((1u64, 100u64), "fp1");
        cache.grant((2u64, 100u64), "fp2");

        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.sweep_expired();
        assert!(cache.entries.is_empty());
    }

    // --- decrypt_cache_key tests ---

    #[test]
    fn test_decrypt_cache_key_deterministic() {
        let salt = [0x42u8; SALT_LEN];
        let k1 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "host1");
        let k2 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "host1");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_decrypt_cache_key_changes_with_type() {
        let salt = [0x42u8; SALT_LEN];
        let k_raw = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "host1");
        let k_totp = decrypt_cache_key(crate::core::SecretType::TOTP, &salt, "host1");
        assert_ne!(k_raw, k_totp);
    }

    #[test]
    fn test_decrypt_cache_key_changes_with_salt() {
        let s1 = [0x42u8; SALT_LEN];
        let s2 = [0x43u8; SALT_LEN];
        let k1 = decrypt_cache_key(crate::core::SecretType::RAW, &s1, "host1");
        let k2 = decrypt_cache_key(crate::core::SecretType::RAW, &s2, "host1");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_decrypt_cache_key_changes_with_host() {
        let salt = [0x42u8; SALT_LEN];
        let k1 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "host1");
        let k2 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "host2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_decrypt_cache_key_length_prefix_prevents_collision() {
        // Length-prefix means "ab"+"c" must hash differently from "a"+"bc"
        // even though concatenation matches — there's no way for the host
        // string to absorb adjacent context bytes.
        let salt = [0x42u8; SALT_LEN];
        let k1 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "ab");
        let k2 = decrypt_cache_key(crate::core::SecretType::RAW, &salt, "abc");
        assert_ne!(k1, k2);
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

    // --- proc_info tests (macOS only, require running process) ---

    #[test]
    #[ignore]
    fn test_proc_bsdinfo_self() {
        let pid = std::process::id() as i32;
        let result = proc_info::get_proc_bsdinfo(pid);
        assert!(result.is_some(), "Should be able to query own process");
        let (ppid, _tdev, start) = result.unwrap();
        assert!(ppid > 0, "Parent PID should be positive");
        assert!(start > 0, "Start time should be positive");
    }

    #[test]
    #[ignore]
    fn test_proc_path_self() {
        let pid = std::process::id() as i32;
        let result = proc_info::get_proc_path(pid);
        assert!(result.is_some(), "Should be able to get own process path");
        let path = result.unwrap();
        assert!(!path.is_empty(), "Path should not be empty");
    }

    #[test]
    #[ignore]
    fn test_get_sid_self_returns_session_leader() {
        // The current test process inherits its session from `cargo test`,
        // so getsid(self) should return a positive PID — typically the
        // shell that ran cargo, or cargo's own PID if it called setsid.
        let pid = std::process::id() as i32;
        let sid = proc_info::get_sid(pid).expect("getsid should succeed");
        assert!(sid > 0, "Session leader PID should be positive");
        // The session leader's start time must be queryable.
        let start = proc_info::get_start_tvsec(sid)
            .expect("Session leader's start_tvsec should be queryable");
        assert!(start > 0, "Session leader start_tvsec should be positive");
    }
}
