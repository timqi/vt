use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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
use tokio::sync::{RwLock, Semaphore};

use crate::core::crypto::{derive_dek, AesGcmCrypto};
use crate::core::session::{AuthOutcome, UnavailableReason};
use crate::core::wire::{
    outcome_to_err_strict, wrap_ok_envelope, ErrKind, WIRE_VERSION,
};
use crate::core::{
    legacy_decrypt, AuthReq, AuthRes, DecryptInput, DecryptReq, DecryptResItem, EncryptReq,
    EncryptResItem, RunReq, RunRes, SignReq, SignRes, SALT_LEN,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use super::security::{authenticate, derive_passcode_ciphers, load_mac_cipher};
use super::store::KeychainStore;
use super::audit::{self, AgentAuditEntry, AuditPushConfig};

/// SSH agent extension names used by vt.
pub const EXT_ENCRYPT: &str = "encrypt@vt";
pub const EXT_DECRYPT: &str = "decrypt@vt";
pub const EXT_AUTH: &str = "auth@vt";
pub const EXT_RUN: &str = "run@vt";
pub const EXT_SIGN: &str = "sign@vt";

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
    /// One shared context for the whole agent process — no TTY or session
    /// requirement. The only mode that serves orchestrated callers (AI
    /// agents, CI, make) whose spawned commands have no controlling terminal
    /// and a fresh session per call, so per-session/per-app can never hit.
    /// Coarsest blast radius: within the TTL, ANY caller that can reach the
    /// socket (including every session of a forwarded agent) rides one grant.
    Global,
}

impl FromStr for AuthCacheMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(AuthCacheMode::None),
            "per-session" | "per_session" | "session" => Ok(AuthCacheMode::PerSession),
            "per-app" | "per_app" | "app" => Ok(AuthCacheMode::PerApp),
            "global" => Ok(AuthCacheMode::Global),
            _ => Err(format!(
                "invalid auth cache mode '{}': expected none, per-session, per-app, or global",
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
            AuthCacheMode::Global => write!(f, "global"),
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

/// A cache entry's expiry, tracked on two clocks.
///
/// `std::time::Instant` on macOS reads `CLOCK_UPTIME_RAW`, which does NOT
/// advance while the system is asleep — an expiry tracked only on `Instant`
/// pauses its countdown when the lid closes, so a grant issued just before
/// sleep would still be live on wake hours (or days) later. The wall clock
/// keeps counting through sleep but can be stepped backwards (NTP), which
/// would stretch a wall-only expiry. An entry is therefore valid only while
/// BOTH clocks agree: `mono` caps total awake time at the TTL, `wall` caps
/// total real time at the TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheExpiry {
    mono: Instant,
    wall: SystemTime,
}

impl CacheExpiry {
    fn is_valid_at(&self, now_mono: Instant, now_wall: SystemTime) -> bool {
        now_mono < self.mono && now_wall < self.wall
    }
}

pub struct AuthCache {
    /// Each entry stores when it expires (computed at grant time).
    entries: HashMap<(CacheContext, String), CacheExpiry>,
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
        self.is_authorized_at(context, fingerprint, Instant::now(), SystemTime::now())
    }

    /// Clock-injectable core of [`is_authorized`], unit-testable for the
    /// sleep scenario (mono frozen, wall advanced) without real sleeping.
    fn is_authorized_at(
        &self,
        context: CacheContext,
        fingerprint: &str,
        now_mono: Instant,
        now_wall: SystemTime,
    ) -> bool {
        self.entries
            .get(&(context, fingerprint.to_string()))
            .is_some_and(|e| e.is_valid_at(now_mono, now_wall))
    }

    /// Strict-TTL grant: a still-valid entry's expiry is left untouched.
    /// Concurrent grants for the same key cannot extend the original TTL.
    /// Expired entries (or absent ones) are replaced with a fresh expiry.
    pub fn grant(&mut self, context: CacheContext, fingerprint: &str) {
        self.grant_at(context, fingerprint, Instant::now(), SystemTime::now());
    }

    fn grant_at(
        &mut self,
        context: CacheContext,
        fingerprint: &str,
        now_mono: Instant,
        now_wall: SystemTime,
    ) {
        let fresh = CacheExpiry {
            mono: now_mono + self.ttl,
            wall: now_wall + self.ttl,
        };
        self.entries
            .entry((context, fingerprint.to_string()))
            .and_modify(|e| {
                if !e.is_valid_at(now_mono, now_wall) {
                    *e = fresh;
                }
            })
            .or_insert(fresh);
    }

    /// Drop every entry; returns how many were dropped (for flush logging).
    pub fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn sweep_expired(&mut self) {
        let now_mono = Instant::now();
        let now_wall = SystemTime::now();
        self.entries.retain(|_, e| e.is_valid_at(now_mono, now_wall));
    }
}

/// True when `timeout` has elapsed since the last activity on EITHER clock —
/// the same dual-clock rule as [`CacheExpiry`] (which documents why), applied
/// to the idle timeout: without the wall clock a laptop that naps often could
/// stay "active" for days and never drop its keys.
fn idle_exceeded(
    last_mono: Instant,
    last_wall: SystemTime,
    now_mono: Instant,
    now_wall: SystemTime,
    timeout: Duration,
) -> bool {
    let deadline = CacheExpiry {
        mono: last_mono + timeout,
        wall: last_wall + timeout,
    };
    !deadline.is_valid_at(now_mono, now_wall)
}

// --- Cache watcher (screen lock + sleep/wake invalidation) ---

/// How often the cache watcher samples screen-lock state and clock skew.
const WATCHER_TICK: Duration = Duration::from_secs(5);
/// Wall clock advancing this much further than the monotonic clock between
/// two watcher ticks means the system slept (mono pauses during sleep).
/// Large enough to also absorb small NTP steps without spurious clears.
const WATCHER_SLEEP_DIVERGENCE: Duration = Duration::from_secs(30);

/// Decide whether the auth caches must be flushed for this watcher tick.
///
/// Two triggers, both "the human walked away" signals that must revoke
/// standing grants (sudo-timestamp semantics):
///   1. Screen transitioned interactive → not interactive (locked, fast-user
///      -switched, or logged out). Only the *transition* clears, so a grant
///      issued after unlock isn't immediately eaten by the steady locked
///      state of some other display.
///   2. Sleep detected: wall time advanced ≥ [`WATCHER_SLEEP_DIVERGENCE`]
///      more than monotonic time since the previous tick. `wall_delta` is
///      `None` when the wall clock stepped backwards — not a sleep signal;
///      the dual-clock TTL ([`CacheExpiry`]) still bounds those entries.
fn watcher_should_clear(
    was_interactive: bool,
    is_interactive: bool,
    mono_delta: Duration,
    wall_delta: Option<Duration>,
) -> bool {
    if was_interactive && !is_interactive {
        return true;
    }
    match wall_delta {
        Some(wall) => wall.saturating_sub(mono_delta) >= WATCHER_SLEEP_DIVERGENCE,
        None => false,
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

// Defense-in-depth re-sanitization before surfacing wire meta to the Touch ID
// prompt — forwarded SSH agent sockets could be rewritten by a hostile hop.
use crate::core::sanitize_for_display as sanitize_prompt;
use crate::core::sanitize_for_display_multiline as sanitize_prompt_multiline;

/// Per-line cap and total-line cap for the multi-line `command` body the CLI
/// sends. The CLI builds something like `op: inject\nfile: …\ncmd: …\nreason: …`
/// so 6 lines is enough headroom; further lines from a hostile peer are
/// silently dropped so the dialog can't be pushed off-screen.
const PROMPT_COMMAND_MAX_LINES: usize = 6;
const PROMPT_COMMAND_MAX_LINE_LEN: usize = 120;

fn plural_secrets(n: usize) -> &'static str {
    if n == 1 { "secret" } else { "secrets" }
}

/// First line of every Touch ID prompt: `"{verb}"` for old clients that
/// don't send `meta.user`/`host`, or `"{verb} {prep} {who}"` when we have
/// somewhere to attribute the request to. `prep` is per-call ("on" for
/// decrypt/auth on the box; "from" for `run` which spawns *on* this Mac
/// but *originates* on the remote host).
fn header_with_who(verb: &str, prep: &str, who: &str) -> String {
    if who.is_empty() {
        verb.to_string()
    } else {
        format!("{} {} {}", verb, prep, who)
    }
}

/// Render `user@host`, omitting either side when empty so the prompt
/// degrades gracefully for old clients that don't send `meta.user`.
fn who_at_host(user: &str, host: &str) -> String {
    let u = sanitize_prompt(user, 40);
    let h = sanitize_prompt(host, 60);
    match (u.is_empty(), h.is_empty()) {
        (true, true)   => String::new(),
        (true, false)  => h,
        (false, true)  => u,
        (false, false) => format!("{}@{}", u, h),
    }
}

/// Append the extra context lines (pwd, parent process, ssh-from) to the
/// Touch ID prompt body. Each is on its own line — `LAContext`'s
/// `localizedReason` renders multi-line strings. Empty fields are skipped so
/// the prompt stays compact for old clients.
fn append_meta_lines(message: &mut String, meta: &crate::core::ClientMeta) {
    if !meta.pwd.is_empty() {
        message.push_str("\npwd: ");
        message.push_str(&sanitize_prompt(&meta.pwd, 100));
    }
    if !meta.ppid_cmd.is_empty() {
        message.push_str("\nvia: ");
        message.push_str(&sanitize_prompt(&meta.ppid_cmd, 100));
    }
    if !meta.ssh_client.is_empty() {
        message.push_str("\nssh: ");
        message.push_str(&sanitize_prompt(&meta.ssh_client, 80));
    }
}

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
                    return Err(format!(
                        "run-allow path must be absolute (got {:?})",
                        item
                    ));
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
    "HOME", "USER", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "LANG",
    "LC_ALL", "LC_CTYPE", "DISPLAY",
];

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
                    .ok_or_else(|| agent_err(anyhow::anyhow!("RSA component is not a positive integer")))
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
                let sig = SigningKey::<sha2::Sha512>::new(private_key).sign_with_rng(&mut rng, data);
                Signature::new(
                    Algorithm::new("rsa-sha2-512").map_err(AgentError::other)?,
                    sig.to_bytes().to_vec(),
                )
                .map_err(AgentError::other)
            } else if flags & signature::RSA_SHA2_256 != 0 {
                let sig = SigningKey::<sha2::Sha256>::new(private_key).sign_with_rng(&mut rng, data);
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
    /// Last request time on both clocks — see [`idle_exceeded`] for why the
    /// monotonic clock alone can't drive the idle timeout.
    last_activity: Arc<RwLock<(Instant, SystemTime)>>,
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
    /// run@vt allowlist. Empty = feature disabled.
    run_allow: Arc<RunAllowlist>,
    /// Global serializer for ALL human auth prompts; see
    /// [`VtSshSession::authenticate_serialized`] for the rationale.
    prompt_sem: Arc<Semaphore>,
    /// Fire-and-forget audit push config. Cloned per session like `run_allow`.
    /// Disabled config = audit push is a no-op.
    audit_push: Arc<AuditPushConfig>,
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        sign_cache: AuthCacheConfig,
        decrypt_cache: AuthCacheConfig,
        disable_legacy_decrypt: bool,
        run_allow: RunAllowlist,
        audit_push: Arc<AuditPushConfig>,
    ) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new((Instant::now(), SystemTime::now()))),
            locked: Arc::new(RwLock::new(false)),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            sign_auth_cache: Arc::new(RwLock::new(AuthCache::new(sign_cache.ttl_secs))),
            decrypt_auth_cache: Arc::new(RwLock::new(AuthCache::new(decrypt_cache.ttl_secs))),
            sign_cache_mode: sign_cache.mode,
            decrypt_cache_mode: decrypt_cache.mode,
            disable_legacy_decrypt,
            run_allow: Arc::new(run_allow),
            prompt_sem: Arc::new(Semaphore::new(1)),
            audit_push,
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
///
/// `Global` is the escape hatch for orchestrated callers (AI agents / CI /
/// make) whose spawned commands have **no controlling terminal and a fresh
/// session per call** — under per-session/per-app they resolve to `None` and
/// can never hit. It maps every peer to one fixed context; the only remaining
/// boundary is the TTL (plus the lock/wake/idle flushes).
fn resolve_cache_context(
    peer_pid: Option<i32>,
    mode: AuthCacheMode,
) -> Option<CacheContext> {
    let pid = peer_pid?;
    // Per-session / per-app require the peer to have a controlling terminal.
    // launchd-managed daemons and other non-interactive peers always prompt
    // and never enter the cache — for these modes caching only makes sense
    // for explicit human-driven terminal sessions.
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
        // (0, 0) can never collide with a real context: sid/app_pid are
        // always > 0.
        AuthCacheMode::Global => Some((0, 0)),
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
            run_allow: Arc::clone(&self.run_allow),
            prompt_sem: Arc::clone(&self.prompt_sem),
            audit_push: Arc::clone(&self.audit_push),
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
    last_activity: Arc<RwLock<(Instant, SystemTime)>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    sign_auth_cache: Arc<RwLock<AuthCache>>,
    decrypt_auth_cache: Arc<RwLock<AuthCache>>,
    /// Cloned per session for cheap reads; the underlying allowlist is
    /// constant for the lifetime of the agent process.
    run_allow: Arc<RunAllowlist>,
    /// Shared across all sessions; see [`VtSshSession::authenticate_serialized`].
    prompt_sem: Arc<Semaphore>,
    /// Shared fire-and-forget audit push config (disabled = no-op).
    audit_push: Arc<AuditPushConfig>,
    peer_pid: Option<i32>,
    /// Resolved once at session creation. `None` = always prompt for sign.
    sign_cache_context: Option<CacheContext>,
    /// Resolved once at session creation. `None` = always prompt for decrypt.
    decrypt_cache_context: Option<CacheContext>,
    disable_legacy_decrypt: bool,
}

/// Outcome of a `sign` authorization, carrying enough to audit it. Replaces
/// the old `bool` so the emit point in `Session::sign` can distinguish a
/// silent cache hit from a fresh approval and from a denial.
enum AuthDecision {
    CacheHit,
    Approved,
    Rejected,
    Unavailable,
}

impl AuthDecision {
    /// True when signing should proceed.
    fn is_ok(&self) -> bool {
        matches!(self, AuthDecision::CacheHit | AuthDecision::Approved)
    }
    fn outcome(&self) -> &'static str {
        match self {
            AuthDecision::CacheHit => "cache_hit",
            AuthDecision::Approved => "approved",
            AuthDecision::Rejected => "rejected",
            AuthDecision::Unavailable => "unavailable",
        }
    }
}

/// Outcome of a `decrypt@vt` batch authorization. Carries the structured
/// `ErrKind` on the failure arm so the existing client-facing error mapping
/// (`SessionLocked`/`NoGuiSession` → the right `DETAIL_*`) is preserved
/// (NEW-1): a bare `Unavailable` would collapse that distinction.
enum DecryptDecision {
    CacheHit,
    Approved,
    Rejected,
    Err(ErrKind),
}

impl DecryptDecision {
    fn outcome(&self) -> &'static str {
        match self {
            DecryptDecision::CacheHit => "cache_hit",
            DecryptDecision::Approved => "approved",
            DecryptDecision::Rejected => "rejected",
            DecryptDecision::Err(_) => "unavailable",
        }
    }
}

/// Run the blocking auth chain on the blocking pool. No serialization —
/// callers must already hold the prompt permit (or deliberately not need
/// one). Join error means the auth chain panicked; fail closed.
async fn authenticate_on_blocking_pool(reason: &str) -> AuthOutcome {
    let msg = reason.to_string();
    match tokio::task::spawn_blocking(move || authenticate(&msg)).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!("auth prompt task failed: {}", e);
            AuthOutcome::Unavailable(UnavailableReason::NotInteractive)
        }
    }
}

/// Map a single `authenticate()` outcome (the always-prompt, no-cache path)
/// onto a `DecryptDecision`, preserving the structured `ErrKind` for the
/// failure arms. `Rejected` is its own variant; a `None` from
/// `outcome_to_err_strict` (future enum variant) fails closed to `Generic`.
fn decrypt_decision_from_authenticate(outcome: AuthOutcome) -> DecryptDecision {
    match outcome {
        AuthOutcome::Success(_) => DecryptDecision::Approved,
        AuthOutcome::Rejected => DecryptDecision::Rejected,
        AuthOutcome::Unavailable(reason) => DecryptDecision::Err(
            outcome_to_err_strict(AuthOutcome::Unavailable(reason)).unwrap_or(ErrKind::Generic),
        ),
    }
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
        );
        audit::spawn_push(Arc::clone(&self.audit_push), entry);
    }

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
        *last = (Instant::now(), SystemTime::now());
    }

    /// Run the blocking auth chain (`authenticate`) for `reason`, serialized
    /// through the global one-permit prompt semaphore and moved off the async
    /// workers via `spawn_blocking`.
    ///
    /// Serialization: every accepted socket runs in its own tokio task, so
    /// without the permit a peer holding VT_AUTH (or any process reaching a
    /// forwarded socket) could stack N concurrent dialogs at the user —
    /// prompt-fatigue that trains reflexive approval. `spawn_blocking`:
    /// `authenticate` blocks on a human for up to ~30s; run inline it would
    /// pin one runtime worker per concurrent prompt and, at worker-count
    /// prompts, stall the whole agent including unrelated sessions.
    ///
    /// The cached paths (`check_or_prompt_auth`,
    /// `check_or_prompt_decrypt_batch`) don't use this wrapper: they acquire
    /// the permit themselves so they can re-check the cache after the queue
    /// wait. Use this only where no cache is involved.
    async fn authenticate_serialized(&self, reason: &str) -> AuthOutcome {
        // The semaphore is never closed, so acquire only fails if that ever
        // changes; fail closed as "cannot prompt" rather than a user reject.
        let Ok(_permit) = self.prompt_sem.acquire().await else {
            return AuthOutcome::Unavailable(UnavailableReason::NotInteractive);
        };
        authenticate_on_blocking_pool(reason).await
    }

    /// Check auth cache or prompt the user. Returns an [`AuthDecision`]
    /// distinguishing a silent cache hit from a fresh approval / denial so the
    /// `Session::sign` call site can audit the outcome.
    ///
    /// Used for `sign` (SSH authentication). `auth@vt` always prompts because
    /// forwarded agents share one local process. `decrypt@vt` has its own
    /// cache (see `check_or_prompt_decrypt_batch`).
    ///
    /// All three success methods (Biometric, FIDO2, Password) are cached:
    /// FIDO2 (YubiKey touch) is treated as equivalent to Touch ID for
    /// authorization purposes — a deliberate policy choice.
    async fn check_or_prompt_auth(&self, fingerprint: &str, auth_message: &str) -> AuthDecision {
        // If we couldn't resolve a cache context at session creation (no
        // peer PID, no TTY, missing proc info), always prompt.
        let Some(context) = self.sign_cache_context else {
            return match self.authenticate_serialized(auth_message).await {
                AuthOutcome::Success(_) => AuthDecision::Approved,
                AuthOutcome::Rejected => AuthDecision::Rejected,
                AuthOutcome::Unavailable(_) => AuthDecision::Unavailable,
            };
        };

        // Fast path: cache hit without touching the prompt queue.
        if self.sign_cache_hit(context, fingerprint, "").await {
            return AuthDecision::CacheHit;
        }

        // Queue for the prompt, then RE-CHECK the cache: a racing request for
        // the same key may have been approved (and granted — grants happen
        // while the permit is still held) during the wait, so an N-request
        // burst costs one dialog instead of N.
        let Ok(_permit) = self.prompt_sem.acquire().await else {
            return AuthDecision::Unavailable;
        };
        if self.sign_cache_hit(context, fingerprint, " after prompt-queue wait").await {
            return AuthDecision::CacheHit;
        }

        // Prompt (permit held, no cache locks held)
        let method = match authenticate_on_blocking_pool(auth_message).await {
            AuthOutcome::Success(m) => m,
            AuthOutcome::Rejected => return AuthDecision::Rejected,
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!(
                    "Auth unavailable for fingerprint={} reason={:?}",
                    fingerprint,
                    reason
                );
                return AuthDecision::Unavailable;
            }
        };

        if method.is_cacheable() {
            // Granted while the permit is still held, so queued waiters are
            // guaranteed to observe this entry on their re-check.
            let mut cache = self.sign_auth_cache.write().await;
            cache.grant(context, fingerprint);
            tracing::debug!(
                "Sign auth cache grant for context={:?} fingerprint={} method={:?}",
                context,
                fingerprint,
                method
            );
        }

        AuthDecision::Approved
    }

    /// Cache-aware authorization for a `decrypt@vt` batch.
    ///
    /// Any legacy item in the batch disables caching for the whole batch —
    /// legacy items release plaintext, and the invariant "legacy-containing
    /// batch always prompts" is load-bearing for that decision. Otherwise:
    /// full hit skips Touch ID; partial hit prompts once and then grants the
    /// whole batch (strict-TTL — see the grant loop below).
    ///
    /// Returns a [`DecryptDecision`]: `CacheHit`/`Approved` allow the decrypt,
    /// `Rejected`/`Err(kind)` block it (the caller maps those to the structured
    /// `ExtResponse::Err` envelope). Both failure arms `return` before any
    /// `cache.grant` call, preserving the invariant that failure paths never
    /// extend or create cache entries.
    async fn check_or_prompt_decrypt_batch(
        &self,
        v2_items: &[(crate::core::SecretType, [u8; SALT_LEN])],
        has_legacy: bool,
        host: &str,
        auth_message: &str,
    ) -> DecryptDecision {
        // Cacheable iff there's a resolved context AND the batch is non-empty
        // pure-v2; everything else falls through to the always-prompt path.
        let context = match self.decrypt_cache_context {
            Some(c) if !has_legacy && !v2_items.is_empty() => c,
            // No cache eligibility: prompt once. Preserve the structured
            // ErrKind via `outcome_to_err_strict` so the client-facing error
            // (SessionLocked/NoGuiSession) is not flattened (NEW-1). Fail
            // closed: a `None` for a non-Success outcome (future enum variant)
            // becomes an Err rather than a silent allow.
            _ => {
                return decrypt_decision_from_authenticate(
                    self.authenticate_serialized(auth_message).await,
                )
            }
        };

        let keys: Vec<String> = v2_items
            .iter()
            .map(|(t, salt)| decrypt_cache_key(*t, salt, host))
            .collect();

        // Fast path: full hit without touching the prompt queue.
        if self.decrypt_miss_count(context, &keys).await == 0 {
            tracing::debug!(
                "Decrypt auth cache hit for context={:?} ({} v2 items)",
                context,
                v2_items.len()
            );
            return DecryptDecision::CacheHit;
        }

        // Queue for the prompt, then RE-CHECK: a racing request covering the
        // same records may have been approved (and granted — grants happen
        // while the permit is still held) during the wait, so an N-request
        // burst costs one dialog instead of N.
        let Ok(_permit) = self.prompt_sem.acquire().await else {
            return decrypt_decision_from_authenticate(AuthOutcome::Unavailable(
                UnavailableReason::NotInteractive,
            ));
        };
        let miss_count = self.decrypt_miss_count(context, &keys).await;
        if miss_count == 0 {
            tracing::debug!(
                "Decrypt auth cache hit after prompt-queue wait for context={:?} ({} v2 items)",
                context,
                v2_items.len()
            );
            return DecryptDecision::CacheHit;
        }

        let method = match authenticate_on_blocking_pool(auth_message).await {
            AuthOutcome::Success(m) => m,
            AuthOutcome::Rejected => return DecryptDecision::Rejected,
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!("decrypt@vt unavailable: {:?}", reason);
                return DecryptDecision::Err(
                    outcome_to_err_strict(AuthOutcome::Unavailable(reason))
                        .unwrap_or(ErrKind::Generic),
                );
            }
        };

        if method.is_cacheable() {
            // The user just approved the ENTIRE batch, so grant every key in
            // it, not just the previously-missing ones — an entry that was
            // valid at the check above but expired while the prompt sat on
            // screen would otherwise stay expired despite the fresh approval.
            // `grant_at` is strict-TTL: keys still valid at this instant keep
            // their original expiry (no sliding refresh). Granted while the
            // permit is still held, so queued waiters observe the entries on
            // their re-check.
            let now_mono = Instant::now();
            let now_wall = SystemTime::now();
            let mut cache = self.decrypt_auth_cache.write().await;
            for k in &keys {
                cache.grant_at(context, k, now_mono, now_wall);
            }
            tracing::debug!(
                "Decrypt auth cache grant for context={:?} method={:?} cache_misses={}",
                context,
                method,
                miss_count
            );
        }

        DecryptDecision::Approved
    }

    /// Sign-cache lookup with a hit-path debug log; `phase` distinguishes the
    /// fast-path check from the post-queue re-check in the log line.
    async fn sign_cache_hit(&self, context: CacheContext, fingerprint: &str, phase: &str) -> bool {
        let hit = self.sign_auth_cache.read().await.is_authorized(context, fingerprint);
        if hit {
            tracing::debug!(
                "Sign auth cache hit{} for context={:?} fingerprint={}",
                phase,
                context,
                fingerprint
            );
        }
        hit
    }

    /// Count how many of `keys` are NOT currently authorized for `context` —
    /// 0 means a full cache hit. One clock capture per call.
    async fn decrypt_miss_count(&self, context: CacheContext, keys: &[String]) -> usize {
        let now_mono = Instant::now();
        let now_wall = SystemTime::now();
        let cache = self.decrypt_auth_cache.read().await;
        keys.iter()
            .filter(|k| !cache.is_authorized_at(context, k, now_mono, now_wall))
            .count()
    }

    // ---- Structured-envelope dispatch helpers --------------------------------
    //
    // Each `handle_*` returns either the inner JSON body (DEKs included for
    // encrypt/decrypt, wrapped in Zeroizing) or a `(ErrKind, Option<&'static
    // str>)` failure that the caller serializes into `ExtResponse::Err`. The
    // `detail` string is bounded to the `DETAIL_*` allow-list defined below
    // so dynamic user-supplied data (host, command, reason, fingerprints)
    // can never leak across `auth@vt` over a forwarded socket.

    async fn handle_encrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
        passphrase_cipher: &AesGcmCrypto,
    ) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
        // v2 envelope: agent allocates a fresh per-record (salt, DEK) pair
        // for each requested SecretType. The agent NEVER receives plaintext
        // on this path. The salt is generated server-side (never accepted
        // from the client) — this is the security invariant that prevents
        // an attacker holding `VT_AUTH` from extracting a salt from a
        // stored vt://0{salt||ct} URL and requesting its DEK to bypass
        // Touch ID.
        let req: EncryptReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
        if req.types.len() > MAX_CRYPTO_BATCH {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_TOO_LARGE)));
        }
        let (_mac_cipher, mac_key) = load_mac_cipher(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;
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
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        // The DEKs now live inside `bytes`; scrub the in-memory
        // `Vec<EncryptResItem>` copy before it falls out of scope.
        for item in result.iter_mut() {
            item.dek.zeroize();
        }
        // encrypt@vt has no Touch ID gate; record the mint as `approved` so the
        // audit shows "agent minted N DEKs". EncryptReq carries no client meta,
        // so host/meta are empty. latency 0 (no prompt).
        self.emit_audit(
            "encrypt",
            "approved",
            "",
            &crate::core::ClientMeta::default(),
            "",
            "",
            req.types.len(),
            0,
        );
        Ok(Zeroizing::new(bytes))
    }

    async fn handle_decrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
        passphrase_cipher: &AesGcmCrypto,
    ) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
        let req: DecryptReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        if req.command.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }
        if req.items.len() > MAX_CRYPTO_BATCH {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_TOO_LARGE)));
        }
        // An empty batch has nothing to authorize; without this guard it
        // would fall through to the uncached always-prompt path and put a
        // "decrypt 0 secrets" dialog in front of the user — free prompt spam
        // for any peer holding VT_AUTH.
        if req.items.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_BATCH_EMPTY)));
        }

        // Reject `SecretType::UNKNOWN` v2 items: serde would otherwise
        // accept them from a malformed `DecryptInput::V2`, the downstream
        // decrypt would fail on AAD mismatch, but the cache could be
        // polluted with `t.as_byte() == b'_'` entries in the meantime.
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
                    return Err((ErrKind::BadRequest, Some(DETAIL_UNKNOWN_SECRET_TYPE)));
                }
                DecryptInput::V2 { t, salt } => v2_inputs.push((*t, *salt)),
                DecryptInput::Legacy { .. } => legacy_count += 1,
            }
        }

        // Fail fast on `--no-legacy-decrypt`: if the agent is configured to
        // reject legacy URLs, surface a dedicated kind before prompting the
        // user. We still let pure-v2 batches through here.
        if self.disable_legacy_decrypt && legacy_count > 0 {
            return Err((ErrKind::LegacyDisabled, Some(DETAIL_LEGACY_DISABLED)));
        }

        let who = who_at_host(&req.meta.user, &req.host);
        let n = req.items.len();
        let mut local_auth_message = header_with_who(
            &format!("decrypt {} {}", n, plural_secrets(n)),
            "on",
            &who,
        );
        let body = sanitize_prompt_multiline(
            &req.command,
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            local_auth_message.push('\n');
            local_auth_message.push_str(&body);
        }
        append_meta_lines(&mut local_auth_message, &req.meta);
        // Cache-aware authorization. Pure v2 batches may skip the prompt on
        // a full hit; any legacy item disables caching for the entire batch.
        // Failure paths inside `check_or_prompt_decrypt_batch` never grant
        // cache entries (verified by inspection of the helper).
        let t0 = Instant::now();
        let decision = self
            .check_or_prompt_decrypt_batch(
                &v2_inputs,
                legacy_count > 0,
                &req.host,
                &local_auth_message,
            )
            .await;
        // Cache hits never prompted → 0 latency; otherwise prompt→decision.
        let latency_ms = if matches!(decision, DecryptDecision::CacheHit) {
            0
        } else {
            t0.elapsed().as_millis() as u64
        };
        self.emit_audit(
            "decrypt",
            decision.outcome(),
            &req.host,
            &req.meta,
            &req.command,
            "",
            req.items.len(),
            latency_ms,
        );
        match decision {
            DecryptDecision::CacheHit | DecryptDecision::Approved => {}
            DecryptDecision::Rejected => {
                return Err((ErrKind::AuthRejected, auth_outcome_detail(ErrKind::AuthRejected)))
            }
            DecryptDecision::Err(kind) => return Err((kind, auth_outcome_detail(kind))),
        }
        let (mac_cipher, mac_key) = load_mac_cipher(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;
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
                        // Should be unreachable: we returned LegacyDisabled
                        // above before prompting. Keep a defensive arm so
                        // the per-item err is still well-formed.
                        result.push(DecryptResItem::Legacy {
                            result: String::new(),
                            err_message: "legacy decryption disabled on this agent".to_string(),
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
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        // Scrub DEKs inside the response Vec before drop. `bytes` already
        // carries them (still wiped via `Zeroizing` below).
        for item in result.iter_mut() {
            if let DecryptResItem::V2 { dek, .. } = item {
                dek.zeroize();
            }
        }
        Ok(Zeroizing::new(bytes))
    }

    async fn handle_auth(
        &self,
        decrypted: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
        let req: AuthReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        if req.reason.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }

        let who = who_at_host(&req.meta.user, &req.host);
        let mut auth_message = header_with_who("auth", "on", &who);
        let reason = sanitize_prompt(&req.reason, 100);
        if !reason.is_empty() {
            auth_message.push_str("\nreason: ");
            auth_message.push_str(&reason);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        // Always prompt Touch ID — no auth caching for auth@vt. Over
        // forwarded agents, all remote sessions share the same local
        // process, so caching would approve all sudo from any session.
        let t0 = Instant::now();
        let outcome = self.authenticate_serialized(&auth_message).await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        let outcome_str = match &outcome {
            AuthOutcome::Success(_) => "approved",
            AuthOutcome::Rejected => "rejected",
            AuthOutcome::Unavailable(_) => "unavailable",
        };
        self.emit_audit(
            "auth",
            outcome_str,
            &req.host,
            &req.meta,
            "",
            &req.reason,
            0,
            latency_ms,
        );
        match outcome {
            AuthOutcome::Success(_) => {}
            AuthOutcome::Rejected => {
                return Err((ErrKind::AuthRejected, Some(DETAIL_AUTH_REJECTED)));
            }
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!("auth@vt unavailable: {:?}", reason);
                // Fail closed on a future-variant miss in `outcome_to_err`.
                let kind = outcome_to_err_strict(AuthOutcome::Unavailable(reason))
                    .unwrap_or(ErrKind::Generic);
                return Err((kind, auth_outcome_detail(kind)));
            }
        }

        let result = AuthRes { approved: true };
        Ok(Zeroizing::new(serde_json::to_vec(&result).map_err(|_| {
            (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE))
        })?))
    }

    /// Touch-ID-gated local command launcher. Every call prompts — no auth
    /// cache, by design. Mirrors the auth@vt policy: forwarded agents share
    /// a single local process, so caching would let any one remote session's
    /// approval be reused by every other session's request, defeating the
    /// guarantee that each `vt run` is acknowledged by a human tap.
    ///
    /// Returns the structured envelope body for the OK arm (`RunRes`) or an
    /// `(ErrKind, detail)` pair the dispatcher turns into `ExtResponse::Err`.
    async fn handle_run(
        &self,
        decrypted: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
        let req: RunReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        // Fast-fail before any user interaction --------------------------------
        if self.run_allow.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_DISABLED)));
        }
        if req.argv.is_empty() {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_EMPTY)));
        }
        let argv_total: usize = req.argv.iter().map(|s| s.len()).sum();
        if argv_total > RUN_REQ_ARGV_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_TOO_LARGE)));
        }
        // NUL bytes in any argv string would either be rejected by `Command`
        // later or, worse, silently truncated by some downstream consumers.
        // Reject up front with a stable static reason.
        if req.argv.iter().any(|s| s.contains('\0')) {
            return Err((ErrKind::BadRequest, Some(DETAIL_RUN_ARGV_EMPTY)));
        }

        let resolved = self.run_allow.resolve(&req.argv[0]).map_err(|why| {
            tracing::warn!("run@vt rejected: {} (argv0={:?})", why, &req.argv[0]);
            (ErrKind::BadRequest, Some(DETAIL_RUN_NOT_ALLOWLISTED))
        })?;

        // Build the Touch ID message. The resolved canonical path is shown on
        // its own line so the user is approving the *resolved* program, not
        // the (potentially confusing) raw argv[0] from a remote peer.
        let who = who_at_host(&req.meta.user, &req.host);
        let argv_joined: String = req
            .argv
            .iter()
            .map(|a| sanitize_prompt(a, 80))
            .collect::<Vec<_>>()
            .join(" ");
        let argv_for_prompt = sanitize_prompt(&argv_joined, RUN_PROMPT_ARGV_MAX);
        let exe_display = sanitize_prompt(&resolved.display().to_string(), 160);
        let mut auth_message = header_with_who("run on this Mac", "from", &who);
        auth_message.push_str("\nexe: ");
        auth_message.push_str(&exe_display);
        auth_message.push_str("\nargv: ");
        auth_message.push_str(&argv_for_prompt);
        if let Some(reason) = req.reason.as_deref() {
            if !reason.is_empty() {
                auth_message.push_str("\nreason: ");
                auth_message.push_str(&sanitize_prompt(reason, 120));
            }
        }
        append_meta_lines(&mut auth_message, &req.meta);

        // NEVER cache. run@vt is treated like auth@vt — every call prompts
        // because a forwarded agent socket is shared across all remote
        // sessions, and any cache here would let one session's approval
        // be reused by another to run arbitrary allowlisted programs.
        // Prompt serialization (one dialog at a time) is inside
        // `authenticate_serialized`, shared with every other prompting path.
        // run@vt: exe + argv joined as the audit `command` (reuses the prompt
        // builders above). All emit points carry it.
        let run_command = format!("exe: {}\nargv: {}", exe_display, argv_for_prompt);
        let run_reason = req.reason.as_deref().unwrap_or("");
        let t0 = Instant::now();
        let outcome = self.authenticate_serialized(&auth_message).await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        match outcome {
            AuthOutcome::Success(_) => {}
            AuthOutcome::Rejected => {
                self.emit_audit(
                    "run", "rejected", &req.host, &req.meta, &run_command, run_reason, 0,
                    latency_ms,
                );
                return Err((ErrKind::AuthRejected, Some(DETAIL_AUTH_REJECTED)));
            }
            AuthOutcome::Unavailable(reason) => {
                tracing::warn!("run@vt unavailable: {:?}", reason);
                let kind = outcome_to_err_strict(AuthOutcome::Unavailable(reason))
                    .unwrap_or(ErrKind::Generic);
                self.emit_audit(
                    "run", "unavailable", &req.host, &req.meta, &run_command, run_reason, 0,
                    latency_ms,
                );
                return Err((kind, auth_outcome_detail(kind)));
            }
        }
        // Q5: emit `approved` at the human tap, BEFORE the spawn attempt, so a
        // denied launch (below) is distinguishable from a failed one (two rows).
        self.emit_audit(
            "run", "approved", &req.host, &req.meta, &run_command, run_reason, 0, latency_ms,
        );

        // Spawn detached. `setsid` makes the child a new session leader so it
        // survives agent exit; closing fds 3..1024 prevents the child from
        // inheriting the agent's listener / keychain / tokio fds; redirecting
        // stdio to /dev/null means no remote channel back. The child inherits
        // the agent's UID and macOS TCC grants — that is intentional for a
        // GUI launcher (e.g. `zed` needs disk access) but documented here so
        // future maintainers don't accidentally widen what `run@vt` is.
        let pid = match spawn_detached(&resolved, &req.argv[1..]) {
            Ok(pid) => pid,
            Err(e) => {
                tracing::warn!("run@vt spawn failed: {}", e);
                // Second row: the launch was approved but failed to spawn.
                self.emit_audit(
                    "run", "spawn_failed", &req.host, &req.meta, &run_command, run_reason, 0, 0,
                );
                return Err((ErrKind::Generic, Some(DETAIL_RUN_SPAWN_FAILED)));
            }
        };
        tracing::info!(
            "run@vt: spawned pid={} exe={} from={}",
            pid,
            resolved.display(),
            who,
        );

        let result = RunRes { pid };
        Ok(Zeroizing::new(serde_json::to_vec(&result).map_err(|_| {
            (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE))
        })?))
    }

    /// `sign@vt`: VT_AUTH-gated signing with a Keychain-held key, displaying vt
    /// execution context (host/command/meta) in the Touch ID prompt. Unlike the
    /// standard `SIGN_REQUEST` path, the request is authenticated by the
    /// auth-cipher envelope and carries human context. The private key never
    /// leaves the agent. v1 ALWAYS prompts (no cache — see docs/sign-vt-design.md).
    async fn handle_sign_vt(
        &self,
        decrypted: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> {
        use ssh_agent_lib::ssh_encoding::Decode;

        let req: SignReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;
        if req.command.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }

        // Decode the requested pubkey → KeyData → fingerprint (same fn as
        // storage, so the lookup key matches what the client advertised).
        // `&[u8]: Reader`, so `decode(&mut &[u8])` is the correct call pattern.
        let key_data = KeyData::decode(&mut req.pubkey.as_slice())
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_SIGN_BAD_PUBKEY)))?;
        let fp_str = fingerprint_str(&key_data);

        // Look up the key. "Not in this agent" is FALLBACK-ELIGIBLE (Generic),
        // NOT BadRequest — an agent-less/other-key host must be able to fall
        // back to decrypt-then-sign. Clone the PrivateKey out so the keys
        // read-lock is not held across the Touch ID prompt.
        self.ensure_keys_loaded()
            .await
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_KEYS_LOAD)))?;
        let privkey = {
            let keys = self.keys.read().await;
            match keys.get(&fp_str) {
                Some(k) => k.clone(),
                None => return Err((ErrKind::Generic, Some(DETAIL_SIGN_KEY_NOT_IN_AGENT))),
            }
        };

        // Rich prompt from vt context (mirrors handle_decrypt formatting).
        let who = who_at_host(&req.meta.user, &req.host);
        let mut auth_message = header_with_who("ssh-sign", "for", &who);
        let body = sanitize_prompt_multiline(
            &req.command,
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        if !body.is_empty() {
            auth_message.push('\n');
            auth_message.push_str(&body);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        // v1: ALWAYS PROMPT (no cache). Distinguish reject vs unavailable so the
        // client gets the right ErrKind (AuthRejected => no fallback, G3).
        let t0 = Instant::now();
        let outcome = self.authenticate_serialized(&auth_message).await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        // Audit the decision (op_kind="ssh-sign", same as the CF ceremony sign
        // path) — without this, agent-side `vt ssh connect` signing left no
        // audit row, a visibility gap vs every other handler.
        let outcome_str = match outcome {
            AuthOutcome::Success(_) => "approved",
            AuthOutcome::Rejected => "rejected",
            AuthOutcome::Unavailable(_) => "unavailable",
        };
        self.emit_audit(
            "ssh-sign",
            outcome_str,
            &req.host,
            &req.meta,
            &req.command,
            "",
            0,
            latency_ms,
        );
        if let Some(kind) = outcome_to_err_strict(outcome) {
            return Err((kind, auth_outcome_detail(kind)));
        }

        let sig = sign_data_with_privkey(&privkey, &req.data, req.flags)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_FAILED)))?;
        let res = SignRes {
            algorithm: sig.algorithm().to_string(),
            signature: sig.as_bytes().to_vec(),
        };
        serde_json::to_vec(&res)
            .map(Zeroizing::new)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))
    }
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
            let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
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

        // Clone the key out and drop the read-lock BEFORE the Touch ID prompt.
        // Holding the `keys` read-guard across check_or_prompt_auth (which can
        // block on a human for up to ~30s) would starve every writer
        // (add/remove/unlock) for the prompt's duration — a non-VT_AUTH peer can
        // trigger SIGN_REQUESTs to weaponize this. (Mirrors handle_sign_vt.)
        let privkey = {
            let keys = self.keys.read().await;
            keys.get(&fp_str).ok_or(AgentError::Failure)?.clone()
        };
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
            format!("sign: {}", key_label)
        } else {
            format!("sign: {} ({})", key_label, proc_name)
        };

        // Check auth cache or prompt Touch ID
        let t0 = Instant::now();
        let decision = self.check_or_prompt_auth(&fp_str, &auth_message).await;
        let latency_ms = if matches!(decision, AuthDecision::CacheHit) {
            0
        } else {
            t0.elapsed().as_millis() as u64
        };
        // Session::sign is the raw SSH auth path (op_kind='sign', distinct from
        // auth@vt) — it carries no vt ClientMeta, so use the prompt label as the
        // audit `command` and leave meta empty.
        self.emit_audit(
            "sign",
            decision.outcome(),
            "",
            &crate::core::ClientMeta::default(),
            &auth_message,
            "",
            0,
            latency_ms,
        );
        if !decision.is_ok() {
            return Err(AgentError::Failure);
        }

        sign_data_with_privkey(&privkey, &request.data, request.flags)
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            // The lock check fires before keychain ciphers are derived, so
            // we have no `auth_cipher` to encrypt a structured envelope
            // with. Surface as an unstructured SSH-wire failure — clients
            // map this to `ErrKind::Generic` (exit 1) and show a hint to
            // run `ssh-add -X`. See docs/structured-errors.md.
            return Err(AgentError::Failure);
        }
        drop(locked);

        // Only handle vt custom protocol extensions; ignore standard SSH extensions
        if !matches!(
            extension.name.as_str(),
            EXT_ENCRYPT | EXT_DECRYPT | EXT_AUTH | EXT_RUN | EXT_SIGN
        ) {
            return Ok(None);
        }

        self.touch_activity().await;

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
        let dispatch: Result<Zeroizing<Vec<u8>>, (ErrKind, Option<&'static str>)> =
            match extension.name.as_str() {
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
                _ => unreachable!(),
            };

        // Build the envelope. OK responses use a manual concat so the
        // serialized inner body (which carries DEKs for encrypt/decrypt) is
        // only ever held in `Zeroizing` buffers — no intermediate
        // `serde_json::Value` allocation that wouldn't be wiped on drop.
        let envelope_bytes: Zeroizing<Vec<u8>> = match dispatch {
            Ok(inner_bytes) => Zeroizing::new(wrap_ok_envelope(&inner_bytes)),
            Err((kind, detail)) => Zeroizing::new(
                serde_json::to_vec(&ErrEnvelope {
                    v: WIRE_VERSION,
                    status: "err",
                    kind,
                    detail,
                })
                .map_err(|e| agent_err(e.into()))?,
            ),
        };

        // Encrypt envelope with auth cipher.
        let encrypted_response = auth_cipher.encrypt(&envelope_bytes).map_err(agent_err)?;

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
    run_allow: RunAllowlist,
    audit_push: Arc<AuditPushConfig>,
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

    let run_allow_empty = run_allow.is_empty();
    let audit_enabled = audit_push.enabled;
    let factory = VtSshAgentFactory::new(
        keys,
        sign_cache,
        decrypt_cache,
        disable_legacy_decrypt,
        run_allow,
        audit_push,
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
    // Clearing keys also clears both auth caches: "idle long enough to drop
    // keys" implies the human is gone, so standing grants must not survive
    // the silent keychain reload that serves the next request.
    let sweeper_keys = Arc::clone(&factory.keys);
    let sweeper_last = Arc::clone(&factory.last_activity);
    let sweeper_idle_cleared = Arc::clone(&factory.idle_cleared);
    let sweeper_sign_cache = Arc::clone(&factory.sign_auth_cache);
    let sweeper_decrypt_cache = Arc::clone(&factory.decrypt_auth_cache);
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
                let dropped = sweeper_sign_cache.write().await.clear()
                    + sweeper_decrypt_cache.write().await.clear();
                if dropped > 0 {
                    tracing::info!("Idle timeout, dropped {} auth cache grants", dropped);
                }
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

    // Spawn the cache watcher: flushes both auth caches when the screen
    // locks or the system wakes from sleep (sudo-timestamp semantics), and
    // sweeps expired entries periodically. See `watcher_should_clear`.
    if sign_cache.mode != AuthCacheMode::None || decrypt_cache.mode != AuthCacheMode::None {
        let watcher_sign = Arc::clone(&factory.sign_auth_cache);
        let watcher_decrypt = Arc::clone(&factory.decrypt_auth_cache);
        tokio::spawn(async move {
            // `None` while there's nothing cached: the WindowServer poll is
            // skipped, so no lock-state history exists. On the first tick
            // with entries the unknown history defaults to "was interactive"
            // — grants can only be created under an interactive screen
            // (`authenticate` pre-checks session state), so finding the
            // screen locked with live entries means it locked after the
            // grant and the transition must fire.
            let mut was_interactive: Option<bool> = None;
            let mut prev_mono = Instant::now();
            let mut prev_wall = SystemTime::now();
            loop {
                tokio::time::sleep(WATCHER_TICK).await;
                let now_mono = Instant::now();
                let now_wall = SystemTime::now();
                let empty = watcher_sign.read().await.is_empty()
                    && watcher_decrypt.read().await.is_empty();
                if empty {
                    // Nothing to flush — with 30-120s TTLs this is the common
                    // case, so skip the CGSession poll entirely.
                    was_interactive = None;
                } else {
                    let is_interactive = super::security::session_interactive_now();
                    if watcher_should_clear(
                        was_interactive.unwrap_or(true),
                        is_interactive,
                        now_mono.saturating_duration_since(prev_mono),
                        now_wall.duration_since(prev_wall).ok(),
                    ) {
                        let dropped = watcher_sign.write().await.clear()
                            + watcher_decrypt.write().await.clear();
                        tracing::info!(
                            "Auth caches cleared on screen lock / wake ({} grants dropped)",
                            dropped
                        );
                    } else {
                        watcher_sign.write().await.sweep_expired();
                        watcher_decrypt.write().await.sweep_expired();
                    }
                    was_interactive = Some(is_interactive);
                }
                prev_mono = now_mono;
                prev_wall = now_wall;
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
    run_allow: RunAllowlist,
    audit_push: Arc<AuditPushConfig>,
) -> Result<()> {
    run_ssh_agent(
        true,
        idle_timeout_secs,
        sign_cache,
        decrypt_cache,
        disable_legacy_decrypt,
        run_allow,
        audit_push,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::AuthMethod;

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

    // --- AuthCacheMode tests ---

    #[test]
    fn test_auth_cache_mode_from_str() {
        assert_eq!(
            AuthCacheMode::from_str("none").unwrap(),
            AuthCacheMode::None
        );
        assert_eq!(
            AuthCacheMode::from_str("global").unwrap(),
            AuthCacheMode::Global
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
    fn test_resolve_cache_context_global_needs_no_tty() {
        // Global must resolve for ANY identified peer — including TTY-less
        // orchestrated callers (AI agents / CI) whose fresh-session spawns
        // make per-session/per-app permanently miss. Our own test process
        // works regardless of whether the runner has a controlling terminal.
        let me = std::process::id() as i32;
        assert_eq!(
            resolve_cache_context(Some(me), AuthCacheMode::Global),
            Some((0, 0))
        );
        // No peer PID → still uncacheable even in global mode.
        assert_eq!(resolve_cache_context(None, AuthCacheMode::Global), None);
        // None mode never caches.
        assert_eq!(resolve_cache_context(Some(me), AuthCacheMode::None), None);
    }

    // (Strict-TTL idempotence and expired-entry replacement are covered
    // deterministically by the clock-injected `_at` tests below — no
    // sleep-based duplicates.)

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

    // --- Dual-clock expiry tests (sleep / clock-step scenarios) ---
    //
    // Clock-injected regression tests for the grant-survives-sleep bug;
    // see [`CacheExpiry`] for the CLOCK_UPTIME_RAW rationale.

    #[test]
    fn test_auth_cache_wall_clock_expires_grant_across_sleep() {
        let mut cache = AuthCache::new(120);
        let ctx = (1u64, 100u64);
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        cache.grant_at(ctx, "fp1", m0, w0);

        // 1s of awake time, but 10 minutes of wall time passed (slept).
        let asleep_mono = m0 + Duration::from_secs(1);
        let asleep_wall = w0 + Duration::from_secs(600);
        assert!(
            !cache.is_authorized_at(ctx, "fp1", asleep_mono, asleep_wall),
            "grant must not survive a sleep longer than the TTL"
        );
    }

    #[test]
    fn test_auth_cache_mono_clock_bounds_stalled_wall_clock() {
        // Wall clock stalled or stepped backwards (NTP): the monotonic bound
        // still caps total awake time at the TTL.
        let mut cache = AuthCache::new(120);
        let ctx = (1u64, 100u64);
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        cache.grant_at(ctx, "fp1", m0, w0);

        let late_mono = m0 + Duration::from_secs(121);
        let early_wall = w0 + Duration::from_secs(1);
        assert!(
            !cache.is_authorized_at(ctx, "fp1", late_mono, early_wall),
            "a backwards/stalled wall clock must not extend the grant"
        );
    }

    #[test]
    fn test_auth_cache_valid_while_both_clocks_within_ttl() {
        let mut cache = AuthCache::new(120);
        let ctx = (1u64, 100u64);
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        cache.grant_at(ctx, "fp1", m0, w0);

        assert!(cache.is_authorized_at(
            ctx,
            "fp1",
            m0 + Duration::from_secs(60),
            w0 + Duration::from_secs(60),
        ));
    }

    #[test]
    fn test_auth_cache_strict_ttl_not_extended_by_midway_regrant() {
        // A re-grant at TTL/2 (e.g. racing prompt resolved late) must not
        // move the original expiry.
        let mut cache = AuthCache::new(120);
        let ctx = (1u64, 100u64);
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        cache.grant_at(ctx, "fp1", m0, w0);
        cache.grant_at(
            ctx,
            "fp1",
            m0 + Duration::from_secs(60),
            w0 + Duration::from_secs(60),
        );

        assert!(
            !cache.is_authorized_at(
                ctx,
                "fp1",
                m0 + Duration::from_secs(121),
                w0 + Duration::from_secs(121),
            ),
            "midway re-grant must not extend the original expiry"
        );
    }

    #[test]
    fn test_auth_cache_regrant_after_wall_expiry_refreshes() {
        // Fresh approval after a sleep-induced expiry must produce a live
        // entry (models the decrypt batch grant-all-keys path where an entry
        // expired while the prompt sat on screen).
        let mut cache = AuthCache::new(120);
        let ctx = (1u64, 100u64);
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        cache.grant_at(ctx, "fp1", m0, w0);

        // Slept past the TTL, then the user re-approved.
        let m1 = m0 + Duration::from_secs(1);
        let w1 = w0 + Duration::from_secs(600);
        assert!(!cache.is_authorized_at(ctx, "fp1", m1, w1));
        cache.grant_at(ctx, "fp1", m1, w1);
        assert!(cache.is_authorized_at(
            ctx,
            "fp1",
            m1 + Duration::from_secs(1),
            w1 + Duration::from_secs(1),
        ));
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
        assert!(!watcher_should_clear(true, true, mono, Some(Duration::from_secs(20))));
        // Wall stepped backwards (None): not a sleep signal.
        assert!(!watcher_should_clear(true, true, mono, None));
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

    // ── Touch-ID prompt helpers ────────────────────────────────────────────

    #[test]
    fn sanitize_prompt_strips_control_chars() {
        // Newline, tab, carriage return, NUL, DEL — all must go. The decrypt
        // prompt is shown via LAContext.localizedReason; an attacker who
        // controls a forwarded agent socket could try to break out of the
        // prompt layout or smuggle in extra newlines that look like
        // legitimate `pwd:` / `via:` fields.
        let evil = "good\n\r\t\x00\x7fend";
        assert_eq!(sanitize_prompt(evil, 100), "goodend");
    }

    #[test]
    fn sanitize_prompt_truncates_with_ellipsis() {
        let long: String = "x".repeat(50);
        let out = sanitize_prompt(&long, 10);
        assert_eq!(out.chars().count(), 11, "10 chars + …");
        assert!(out.ends_with('…'));
        assert!(out.starts_with("xxxxxxxxxx"));
    }

    #[test]
    fn sanitize_prompt_passes_short_input_unchanged() {
        assert_eq!(sanitize_prompt("hi", 100), "hi");
        assert_eq!(sanitize_prompt("", 10), "");
    }

    #[test]
    fn who_at_host_renders_user_and_host() {
        assert_eq!(who_at_host("qiqi", "alpha"), "qiqi@alpha");
    }

    #[test]
    fn who_at_host_degrades_gracefully_for_old_clients() {
        // Old client doesn't send meta.user — fall back to bare host so the
        // prompt still reads naturally.
        assert_eq!(who_at_host("", "alpha"), "alpha");
        // Symmetrically, a missing host should not produce a leading "@".
        assert_eq!(who_at_host("qiqi", ""), "qiqi");
        assert_eq!(who_at_host("", ""), "");
    }

    #[test]
    fn who_at_host_strips_control_chars_in_either_field() {
        // Defense-in-depth: a hostile forwarded peer could lie about user
        // or host. The agent never trusts the wire for layout.
        assert_eq!(who_at_host("qi\nqi", "al\tpha"), "qiqi@alpha");
    }

    #[test]
    fn append_meta_lines_emits_only_populated_fields() {
        let meta = crate::core::ClientMeta {
            user: "qiqi".into(),
            pwd: "/tmp".into(),
            tty: "/dev/pts/3".into(), // intentionally skipped on prompt
            ppid_cmd: "".into(),       // empty — must be skipped
            ssh_client: "".into(),     // empty — must be skipped
        };
        let mut msg = String::from("auth: sudo on qiqi@alpha");
        append_meta_lines(&mut msg, &meta);
        assert_eq!(msg, "auth: sudo on qiqi@alpha\npwd: /tmp");
    }

    #[test]
    fn append_meta_lines_emits_all_when_present() {
        let meta = crate::core::ClientMeta {
            user: "qiqi".into(),
            pwd: "/tmp".into(),
            tty: "/dev/pts/3".into(),
            ppid_cmd: "zsh -i".into(),
            ssh_client: "10.0.0.5 5234 22".into(),
        };
        let mut msg = String::from("decrypt 1: [read] on qiqi@alpha");
        append_meta_lines(&mut msg, &meta);
        let lines: Vec<&str> = msg.split('\n').collect();
        assert_eq!(lines[0], "decrypt 1: [read] on qiqi@alpha");
        assert_eq!(lines[1], "pwd: /tmp");
        assert_eq!(lines[2], "via: zsh -i");
        assert_eq!(lines[3], "ssh: 10.0.0.5 5234 22");
        assert_eq!(lines.len(), 4, "tty must not be rendered on prompt");
    }

    #[test]
    fn append_meta_lines_is_noop_for_default_meta() {
        // Old clients deserialize to ClientMeta::default() — empty everywhere.
        // The prompt must remain a single line in that case.
        let meta = crate::core::ClientMeta::default();
        let mut msg = String::from("auth: sudo on alpha");
        append_meta_lines(&mut msg, &meta);
        assert_eq!(msg, "auth: sudo on alpha");
        assert!(!msg.contains('\n'));
    }

    // --- run@vt allowlist tests ----------------------------------------------

    #[test]
    fn run_allowlist_empty_means_disabled() {
        let a = RunAllowlist::parse("").unwrap();
        assert!(a.is_empty());
        let a = RunAllowlist::parse("   ,  ").unwrap();
        assert!(a.is_empty());
    }

    #[test]
    fn run_allowlist_rejects_relative_path_entry() {
        // Slash-bearing entries must be absolute; otherwise the canonicalize
        // would resolve against the agent's cwd at parse time — surprising.
        let err = RunAllowlist::parse("bin/zed").unwrap_err();
        assert!(err.contains("absolute"), "got: {}", err);
    }

    #[test]
    fn run_allowlist_rejects_nul_in_entry() {
        let err = RunAllowlist::parse("zed,fo\0o").unwrap_err();
        assert!(err.contains("NUL"), "got: {}", err);
    }

    #[test]
    fn run_allowlist_rejects_relative_argv0() {
        let a = RunAllowlist::parse("zed").unwrap();
        assert_eq!(a.resolve("./zed"), Err("argv[0] with / must be absolute"));
    }

    #[test]
    fn run_allowlist_rejects_dotdot_in_argv0() {
        let a = RunAllowlist::parse("/usr/bin/zed").unwrap_or_else(|_| {
            // /usr/bin/zed may not exist on this machine; fall back to a
            // bare-name allowlist for the .. rejection check.
            RunAllowlist::parse("zed").unwrap()
        });
        assert_eq!(a.resolve("/Applications/../etc/passwd"), Err("argv[0] has .. component"));
        assert_eq!(a.resolve("/foo/../bar"), Err("argv[0] has .. component"));
    }

    #[test]
    fn run_allowlist_rejects_empty_and_nul_argv0() {
        let a = RunAllowlist::parse("zed").unwrap();
        assert_eq!(a.resolve(""), Err("argv[0] empty"));
        assert_eq!(a.resolve("ze\0d"), Err("argv[0] has NUL byte"));
    }

    #[test]
    fn run_allowlist_bare_name_rejects_path_argv0() {
        // bare name "zed" must NOT let an attacker pass /tmp/zed.
        let a = RunAllowlist::parse("zed").unwrap();
        // /tmp exists; create a transient executable there to be sure
        // canonicalize doesn't trip on a missing file.
        use std::io::Write;
        let mut path = std::env::temp_dir();
        path.push(format!("vt-run-allow-test-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "#!/bin/sh\necho hi").unwrap();
        }
        // chmod +x so it'd be considered executable by resolve_in_path.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let res = a.resolve(&path.display().to_string());
        let _ = std::fs::remove_file(&path);
        assert_eq!(res, Err("argv[0] path not in allowlist"));
    }

    #[test]
    fn run_allowlist_resolves_bare_name_via_path() {
        // /bin/sh is essentially always on PATH on macOS dev hosts.
        let a = RunAllowlist::parse("sh").unwrap();
        let resolved = a.resolve("sh").expect("sh should resolve via PATH");
        assert!(resolved.is_absolute(), "expected absolute path, got {:?}", resolved);
        // basename should be `sh`; on some systems /bin/sh is a symlink so we
        // just sanity-check that the resolved file exists.
        assert!(resolved.exists());
    }

    #[test]
    fn run_allowlist_abs_path_exact_match() {
        // Use /bin/sh (or its canonicalized form) as a real exec on disk.
        let sh = std::fs::canonicalize("/bin/sh").expect("/bin/sh must exist on macOS");
        let spec = sh.display().to_string();
        let a = RunAllowlist::parse(&spec).unwrap();
        assert_eq!(a.resolve(&spec).unwrap(), sh);
        // Different absolute path → not allowlisted (use a canonicalize-able path).
        let other = std::fs::canonicalize("/bin/ls").expect("/bin/ls must exist on macOS");
        assert_eq!(
            a.resolve(&other.display().to_string()),
            Err("argv[0] path not in allowlist")
        );
    }

    #[test]
    fn plural_secrets_matches_count() {
        assert_eq!(plural_secrets(0), "secrets");
        assert_eq!(plural_secrets(1), "secret");
        assert_eq!(plural_secrets(2), "secrets");
    }

    /// End-to-end shape of the new decrypt prompt: header on line 1,
    /// the CLI's multi-line `command` body, then `append_meta_lines` rows.
    #[test]
    fn decrypt_prompt_renders_multiline_command_and_meta() {
        let who = who_at_host("qiqi", "xy4");
        let n = 5usize;
        let mut msg = format!("decrypt {} {} on {}", n, plural_secrets(n), who);
        let body = sanitize_prompt_multiline(
            "op: inject\nfile: /Users/qiqi/.config/aux/config.jsonc\ncmd: /bin/cat /Users/qiqi/.config/aux/config.jsonc\nreason: aux config.jsonc",
            PROMPT_COMMAND_MAX_LINE_LEN,
            PROMPT_COMMAND_MAX_LINES,
        );
        assert!(!body.is_empty());
        msg.push('\n');
        msg.push_str(&body);
        append_meta_lines(
            &mut msg,
            &crate::core::ClientMeta {
                user: "qiqi".into(),
                pwd: "/".into(),
                tty: String::new(),
                ppid_cmd: "/Applications/aux.app/Contents/MacOS/aux".into(),
                ssh_client: String::new(),
            },
        );
        let lines: Vec<&str> = msg.split('\n').collect();
        assert_eq!(lines[0], "decrypt 5 secrets on qiqi@xy4");
        assert_eq!(lines[1], "op: inject");
        assert_eq!(lines[2], "file: /Users/qiqi/.config/aux/config.jsonc");
        assert_eq!(lines[3], "cmd: /bin/cat /Users/qiqi/.config/aux/config.jsonc");
        assert_eq!(lines[4], "reason: aux config.jsonc");
        assert_eq!(lines[5], "pwd: /");
        assert_eq!(lines[6], "via: /Applications/aux.app/Contents/MacOS/aux");
        assert_eq!(lines.len(), 7);
    }

    #[test]
    fn decrypt_prompt_caps_hostile_command_line_count() {
        // A malicious peer floods `command` with extra lines trying to push
        // the dialog off-screen — the multiline sanitizer must drop the tail.
        let huge = (0..50).map(|i| format!("line {}", i)).collect::<Vec<_>>().join("\n");
        let body = sanitize_prompt_multiline(&huge, PROMPT_COMMAND_MAX_LINE_LEN, PROMPT_COMMAND_MAX_LINES);
        assert_eq!(body.split('\n').count(), PROMPT_COMMAND_MAX_LINES);
    }

    #[test]
    fn append_meta_lines_caps_long_fields() {
        // A hostile peer that floods e.g. pwd with megabytes of junk must
        // not be able to push the Touch ID dialog off-screen.
        let huge = "a".repeat(1000);
        let meta = crate::core::ClientMeta {
            pwd: huge.clone(),
            ppid_cmd: huge.clone(),
            ssh_client: huge,
            ..Default::default()
        };
        let mut msg = String::new();
        append_meta_lines(&mut msg, &meta);
        // pwd:100, via:100, ssh:80 — plus the labels and newlines.
        // Conservative upper bound: each line under 120 chars (label + 100 + …).
        for line in msg.split('\n').filter(|l| !l.is_empty()) {
            assert!(
                line.chars().count() <= 120,
                "prompt line too long ({} chars): {}",
                line.chars().count(),
                line,
            );
        }
    }
}
