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

use crate::core::{
    do_decrypt, do_encrypt, AuthReq, AuthRes, CryptoResItem, DecryptReq, EncryptItem,
};
use crate::security::{
    authenticate, get_keychain, load_mac_cipher, load_mac_cipher_from_keychain,
    load_passcode_ciphers, local_authentication, set_keychain, AesGcmCrypto, AuthMethod,
};

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

// --- Key storage (single keychain item: rusty.vault.ssh_keys) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH-format private key (plaintext, encrypted at the keychain level)
    pub key_data: String,
}

pub fn load_ssh_keys(cipher: &AesGcmCrypto) -> Result<Vec<SshKeyEntry>> {
    match get_keychain("ssh_keys") {
        Ok(encrypted) => {
            let decrypted = cipher.decrypt(&encrypted)?;
            let entries: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted)?;
            Ok(entries)
        }
        Err(_) => Ok(Vec::new()),
    }
}

pub fn save_ssh_keys(cipher: &AesGcmCrypto, entries: &[SshKeyEntry]) -> Result<()> {
    let json = serde_json::to_vec(entries)?;
    let encrypted = cipher.encrypt(&json)?;
    set_keychain("ssh_keys", &encrypted)
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
    sign_duration: Duration,
}

impl AuthCache {
    pub fn new(sign_duration_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            sign_duration: Duration::from_secs(sign_duration_secs),
        }
    }

    pub fn is_authorized(&self, context: CacheContext, fingerprint: &str) -> bool {
        if let Some(expires_at) = self.entries.get(&(context, fingerprint.to_string())) {
            Instant::now() < *expires_at
        } else {
            false
        }
    }

    pub fn grant(&mut self, context: CacheContext, fingerprint: &str) {
        self.entries.insert(
            (context, fingerprint.to_string()),
            Instant::now() + self.sign_duration,
        );
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

/// Load all SSH keys from keychain into a HashMap. Cipher is dropped after use.
fn load_all_keys() -> Result<HashMap<String, PrivateKey>> {
    let mac_cipher = load_mac_cipher_from_keychain()?;
    let entries = load_ssh_keys(&mac_cipher)?;
    // mac_cipher dropped after this block
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
    auth_cache: Arc<RwLock<AuthCache>>,
    cache_mode: AuthCacheMode,
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        cache_mode: AuthCacheMode,
        cache_duration_secs: u64,
    ) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            locked: Arc::new(RwLock::new(false)),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            auth_cache: Arc::new(RwLock::new(AuthCache::new(cache_duration_secs))),
            cache_mode,
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
fn resolve_cache_context(
    peer_pid: Option<i32>,
    mode: AuthCacheMode,
) -> Option<CacheContext> {
    let pid = peer_pid?;
    match mode {
        AuthCacheMode::None => None,
        AuthCacheMode::PerSession => {
            let tdev = proc_info::get_tty_dev(pid)?;
            let start = proc_info::get_start_tvsec(pid)?;
            Some((tdev as u64, start))
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
        let cache_context = resolve_cache_context(peer_pid, self.cache_mode);
        VtSshSession {
            keys: Arc::clone(&self.keys),
            last_activity: Arc::clone(&self.last_activity),
            locked: Arc::clone(&self.locked),
            lock_passphrase: Arc::clone(&self.lock_passphrase),
            idle_cleared: Arc::clone(&self.idle_cleared),
            auth_cache: Arc::clone(&self.auth_cache),
            peer_pid,
            cache_context,
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
    auth_cache: Arc<RwLock<AuthCache>>,
    peer_pid: Option<i32>,
    /// Resolved once at session creation. `None` = always prompt.
    cache_context: Option<CacheContext>,
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
    /// Only used for `sign` (SSH authentication). `decrypt@vt` and `auth@vt`
    /// always prompt — decrypt because the plaintext blast radius of a cache
    /// hit is too large; auth because forwarded agents share one local process.
    ///
    /// FIDO2 (YubiKey touch) results are NOT cached — touch-only is a weaker
    /// factor than Touch ID, and a YubiKey tap is fast enough that caching
    /// adds little value. Biometric and password results are cached normally.
    async fn check_or_prompt_auth(&self, fingerprint: &str, auth_message: &str) -> bool {
        // If we couldn't resolve a cache context at session creation (no
        // peer PID, no TTY, missing proc info), always prompt.
        let Some(context) = self.cache_context else {
            return local_authentication(auth_message);
        };

        // Check cache (read lock, released before auth prompt)
        {
            let cache = self.auth_cache.read().await;
            if cache.is_authorized(context, fingerprint) {
                tracing::debug!(
                    "Auth cache hit for context={:?} fingerprint={}",
                    context,
                    fingerprint
                );
                return true;
            }
        }

        // Prompt (no locks held)
        let Some(method) = authenticate(auth_message) else {
            return false;
        };

        // Cache Biometric and Password; skip FIDO2 (weaker factor).
        if matches!(method, AuthMethod::Biometric | AuthMethod::Password) {
            let mut cache = self.auth_cache.write().await;
            cache.grant(context, fingerprint);
            tracing::debug!(
                "Auth cache grant for context={:?} fingerprint={} method={:?}",
                context,
                fingerprint,
                method
            );
        } else {
            tracing::debug!(
                "Auth succeeded via {:?}; not caching (weaker factor)",
                method
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

        // Load auth cipher from keychain to verify VT_AUTH
        let (auth_cipher, passphrase_cipher) = load_passcode_ciphers().map_err(agent_err)?;

        // Decrypt the extension details with auth cipher (verifies VT_AUTH)
        let decrypted = auth_cipher
            .decrypt(extension.details.as_ref())
            .map_err(|_| {
                tracing::warn!("Extension auth failed (wrong VT_AUTH?)");
                AgentError::Failure
            })?;

        let response_bytes = match extension.name.as_str() {
            EXT_ENCRYPT => {
                let items: Vec<EncryptItem> =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                let mac_cipher = load_mac_cipher(&passphrase_cipher).map_err(agent_err)?;
                let result: Vec<CryptoResItem> = do_encrypt(&mac_cipher, items);
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
            }
            EXT_DECRYPT => {
                let req: DecryptReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                let local_auth_message = format!(
                    "decrypt {} items from {} to run `{}`",
                    req.items.len(),
                    req.host,
                    req.command,
                );
                // Always prompt — never cached. Decrypting emits plaintext, so
                // the blast radius of a cached grant is too large.
                if !local_authentication(&local_auth_message) {
                    return Err(AgentError::Failure);
                }
                let mac_cipher = load_mac_cipher(&passphrase_cipher).map_err(agent_err)?;
                let result: Vec<CryptoResItem> = do_decrypt(&mac_cipher, req.items);
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
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
                if !local_authentication(&auth_message) {
                    return Err(AgentError::Failure);
                }

                let result = AuthRes { approved: true };
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
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

                // Load cipher on demand, update single keychain item
                let cipher = load_mac_cipher_from_keychain().map_err(agent_err)?;
                let mut entries = load_ssh_keys(&cipher).unwrap_or_default();
                if !entries.iter().any(|e| e.fingerprint == fp_str) {
                    entries.push(SshKeyEntry {
                        fingerprint: fp_str.clone(),
                        algorithm: pubkey.algorithm().to_string(),
                        comment,
                        key_data: key_openssh.to_string(),
                    });
                    save_ssh_keys(&cipher, &entries).map_err(agent_err)?;
                }

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

        if let Ok(cipher) = load_mac_cipher_from_keychain() {
            let mut entries = load_ssh_keys(&cipher).unwrap_or_default();
            entries.retain(|e| e.fingerprint != fp_str);
            let _ = save_ssh_keys(&cipher, &entries);
        }

        let mut keys = self.keys.write().await;
        keys.remove(&fp_str);

        tracing::info!("Removed SSH key: {}", fp_str);
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        if let Ok(cipher) = load_mac_cipher_from_keychain() {
            let _ = save_ssh_keys(&cipher, &[]);
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

        // Clear auth cache on lock
        let mut cache = self.auth_cache.write().await;
        cache.clear();

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
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
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

    let factory = VtSshAgentFactory::new(keys, cache_mode, cache_duration_secs);

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

    // Spawn auth cache sweeper (reuse same pattern)
    if cache_mode != AuthCacheMode::None {
        let sweeper_cache = Arc::clone(&factory.auth_cache);
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(60);
            loop {
                tokio::time::sleep(check_interval).await;
                let mut cache = sweeper_cache.write().await;
                cache.sweep_expired();
            }
        });
        tracing::info!(
            "Auth cache: mode={}, sign={}s (decrypt/auth never cached)",
            cache_mode,
            cache_duration_secs,
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
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
) -> Result<()> {
    run_ssh_agent(true, idle_timeout_secs, cache_mode, cache_duration_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_ssh_keys_empty_on_missing() {
        let key = AesGcmCrypto::generate_key();
        let cipher = AesGcmCrypto::new(&key).unwrap();
        let entries = load_ssh_keys(&cipher);
        // If keychain item doesn't exist: Ok(empty vec).
        // If it exists but decryption fails (wrong key): Err.
        // Both are valid outcomes depending on keychain state.
        match entries {
            Ok(v) => assert!(v.is_empty()),
            Err(_) => {} // keychain item exists but can't be decrypted with random key
        }
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
}
