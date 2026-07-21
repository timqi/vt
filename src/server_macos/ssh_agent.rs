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

use crate::core::authorization::{
    AuthorizationEngine, AuthorizationFailure, AuthorizationPermit, AuthorizationRequest,
    CommitError, Decision, GrantScope, Operation, ReusePolicy, SubjectId,
};
use crate::core::crypto::{derive_dek, AesGcmCrypto};
use crate::core::session::AuthOutcome;
use crate::core::wire::{
    outcome_to_err_strict, wrap_ok_envelope, ErrKind, WIRE_VERSION,
};
use crate::core::{
    legacy_decrypt, AuthReq, AuthRes, ContextBasis, DecryptInput, DecryptReq, DecryptResItem,
    DiagCacheReport, DiagPeerReport, DiagReq, DiagRes, EncryptReq, EncryptResItem, RunReq,
    RunRes, SignReq, SignRes, SALT_LEN,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use super::authorization::{new_engine, sleep_diverged};
use super::security::{derive_passcode_ciphers, load_mac_cipher, validate_mac_key_material};
use super::store::KeychainStore;
use super::audit::{self, AgentAuditEntry, AuditPushConfig};

/// SSH agent extension names used by vt.
pub const EXT_ENCRYPT: &str = "encrypt@vt";
pub const EXT_DECRYPT: &str = "decrypt@vt";
pub const EXT_AUTH: &str = "auth@vt";
pub const EXT_RUN: &str = "run@vt";
pub const EXT_SIGN: &str = "sign@vt";
pub const EXT_DIAG: &str = "diag@vt";

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

// --- Reuse policy -----------------------------------------------------------

/// Map a configured cache duration to an engine reuse policy. `0` selects the
/// engine's first-class `Fresh` policy (never reads or writes grants) — NOT
/// `StrictTtl(0)`.
fn reuse_policy(ttl_secs: u64) -> ReusePolicy {
    if ttl_secs == 0 {
        ReusePolicy::Fresh
    } else {
        ReusePolicy::strict_ttl_secs(ttl_secs)
    }
}

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
    /// for processes with no controlling terminal (`tdev == 0`). Diag-only
    /// since scopes V2; behavior must never depend on it.
    pub fn get_tty_dev(pid: i32) -> Option<u32> {
        let (_, tdev, _) = get_proc_bsdinfo(pid)?;
        if tdev == 0 {
            None
        } else {
            Some(tdev)
        }
    }

    const PROC_PIDVNODEPATHINFO: libc::c_int = 9;

    /// Layout mirror of `struct vnode_info_path` from `<sys/proc_info.h>`:
    /// `struct vnode_info` (a 136-byte `vinfo_stat` + type/pad/fsid = 152
    /// bytes, opaque here) followed by a MAXPATHLEN path buffer.
    #[repr(C)]
    struct VnodeInfoPath {
        vip_vi: [u8; 152],
        vip_path: [u8; MAXPATHLEN as usize],
    }

    #[repr(C)]
    struct ProcVnodePathInfo {
        pvi_cdir: VnodeInfoPath,
        pvi_rdir: VnodeInfoPath,
    }

    /// Kernel-derived current working directory of `pid`
    /// (`proc_pidinfo(PROC_PIDVNODEPATHINFO)` → `pvi_cdir.vip_path`). Same
    /// trust level as `get_proc_path`; `None` on any failure. The strict
    /// `ret == size` check makes a layout mismatch fail closed instead of
    /// reading a truncated struct.
    pub fn get_cwd(pid: i32) -> Option<std::path::PathBuf> {
        const _: () = assert!(std::mem::size_of::<ProcVnodePathInfo>() == 2 * (152 + 1024));
        let mut info: ProcVnodePathInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ProcVnodePathInfo>() as libc::c_int;
        let ret = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDVNODEPATHINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if ret != size {
            return None;
        }
        let path = &info.pvi_cdir.vip_path;
        let len = path.iter().position(|&b| b == 0)?;
        if len == 0 {
            return None;
        }
        let s = std::str::from_utf8(&path[..len]).ok()?;
        Some(std::path::PathBuf::from(s))
    }

    /// Get the process start time (seconds since epoch).
    pub fn get_start_tvsec(pid: i32) -> Option<u64> {
        get_proc_bsdinfo(pid).map(|(_, _, s)| s)
    }

    /// Fetch a process's argv via `sysctl(KERN_PROCARGS2)`, kernel-derived (same
    /// trust level as `proc_pidpath`). `None` on any sysctl failure or malformed
    /// buffer — callers treat that as "not the vt relay". The byte-buffer parse
    /// itself is the pure, host-tested `ssh_sign::parse_procargs2`.
    pub fn get_proc_argv(pid: i32) -> Option<Vec<String>> {
        // 1. Upper bound on the args buffer size (`kern.argmax`).
        let mut argmax: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                &mut argmax as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || argmax <= 0 {
            return None;
        }

        // 2. Fetch KERN_PROCARGS2 for `pid` into a buffer of that size.
        let mut buf = vec![0u8; argmax as usize];
        let mut size = buf.len();
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || size == 0 || size > buf.len() {
            return None;
        }
        buf.truncate(size);
        crate::ssh_sign::parse_procargs2(&buf)
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
    "HOME", "USER", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "LANG",
    "LC_ALL", "LC_CTYPE", "DISPLAY",
];

/// Default idle timeout: 30 minutes.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30 * 60;

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
    locked: Arc<AtomicBool>,
    /// Serializes SSH-agent lock/unlock state transitions. The synchronous
    /// atomic remains the live authorization validator's fast state source.
    lock_transition: Arc<Mutex<()>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    authorization: Arc<AuthorizationEngine>,
    /// 0 = Fresh (always prompt). Kept separate from decrypt because a cached
    /// decrypt grant releases per-record DEK material, whose blast radius is
    /// wider than a single-challenge signature.
    sign_cache_ttl_secs: u64,
    decrypt_cache_ttl_secs: u64,
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
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        cache_ttls: AuthCacheTtls,
        disable_legacy_decrypt: bool,
        run_allow: RunAllowlist,
        audit_push: Arc<AuditPushConfig>,
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
            sign_cache_ttl_secs: cache_ttls.sign_secs,
            decrypt_cache_ttl_secs: cache_ttls.decrypt_secs,
            disable_legacy_decrypt,
            run_allow: Arc::new(run_allow),
            audit_push,
        }
    }
}

// --- Peer classification (activity scopes V2) --------------------------------
//
// The caller-topology cache modes are gone. Grants are keyed by activity:
// raw SSH signs by session-bind-verified destination (BindState, below),
// local vt peers by kernel-derived workspace, relay peers per connection.
// See docs/authorization-scopes-v2.md.

/// A workspace the peer is operating in: the nearest `.git`-containing
/// ancestor of its kernel-derived cwd. `subject` is the root directory's
/// `(st_dev, st_ino)`; `root` is the canonical path captured from the SAME
/// file descriptor (fstat + F_GETPATH), so the pair cannot be split by a
/// rename between two lookups. The digest binds both.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Workspace {
    subject: SubjectId,
    root: PathBuf,
}

impl Workspace {
    fn root_str(&self) -> &str {
        self.root.to_str().unwrap_or_default()
    }

    /// Client-reported `pwd` is display metadata, but if it is present and
    /// does not lie inside this workspace the request degrades to Fresh — a
    /// consistency check against confused callers, not a security boundary.
    fn contains_claimed_pwd(&self, pwd: &str) -> bool {
        pwd.is_empty() || std::path::Path::new(pwd).starts_with(&self.root)
    }
}

/// How the connection's workspace resolution ended, kept for diag.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkspaceResolution {
    Resolved(Workspace),
    /// Kernel cwd known but no `.git` ancestor: deliberately Fresh. A cwd
    /// fallback would pool $HOME / /tmp / CI scratch dirs into one broad
    /// unlabeled bucket.
    NoRoot,
    /// No peer pid or proc/cwd lookup failed (also used for relay peers,
    /// which never use workspace scopes).
    Unavailable,
}

impl WorkspaceResolution {
    fn workspace(&self) -> Option<&Workspace> {
        match self {
            WorkspaceResolution::Resolved(ws) => Some(ws),
            _ => None,
        }
    }
}

/// Ascend from `start` to the nearest directory containing a `.git` entry
/// (dir or file — worktrees use a file). Depth-capped as a syscall bound on
/// pathological trees.
fn find_git_root(start: &std::path::Path) -> Option<PathBuf> {
    let mut dir = start;
    for _ in 0..64 {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

/// A `.git` root is an acceptable workspace boundary only when it does not
/// pool unrelated work into one bucket:
///
/// - a dotfiles repository AT `$HOME` (`git init ~`, yadm) would make every
///   caller anywhere under the home directory share one grant scope — the
///   exact broad bucket the `NoRoot ⇒ Fresh` rule exists to prevent;
/// - symmetrically, when the cwd lives under `$HOME`, a root found ABOVE
///   `$HOME` (e.g. a stray `/Users/.git`) is rejected rather than pooling
///   every user directory.
///
/// Both degrade to Fresh, never to a wider scope.
fn workspace_root_acceptable(
    root: &std::path::Path,
    cwd: &std::path::Path,
    home: Option<&std::path::Path>,
) -> bool {
    let Some(home) = home else { return true };
    if root == home {
        return false;
    }
    if cwd.starts_with(home) && !root.starts_with(home) {
        return false;
    }
    true
}

/// Capture the workspace identity through one file descriptor:
/// `open(O_RDONLY|O_DIRECTORY)` → `fstat` → `fcntl(F_GETPATH)`. Deriving the
/// `(dev, ino)` subject and the canonical path from the same fd removes the
/// rename race between two separate path lookups.
fn workspace_identity(root: &std::path::Path) -> Option<Workspace> {
    use std::os::unix::ffi::OsStrExt;
    let c_root = std::ffi::CString::new(root.as_os_str().as_bytes()).ok()?;
    let fd = unsafe { libc::open(c_root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return None;
    }
    // Everything below must close `fd` on every path.
    let result = (|| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return None;
        }
        let mut buf = [0u8; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } == -1 {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0)?;
        let path = std::str::from_utf8(&buf[..len]).ok()?;
        Some(Workspace {
            subject: (st.st_dev as u64, st.st_ino),
            root: PathBuf::from(path),
        })
    })();
    unsafe { libc::close(fd) };
    result
}

/// Resolve the peer's workspace once per connection (vt CLI connections are
/// per-command; a process cwd does not change mid-connection in practice).
fn resolve_workspace(peer_pid: Option<i32>) -> WorkspaceResolution {
    let Some(pid) = peer_pid else {
        return WorkspaceResolution::Unavailable;
    };
    let Some(cwd) = proc_info::get_cwd(pid) else {
        return WorkspaceResolution::Unavailable;
    };
    let Some(root) = find_git_root(&cwd) else {
        return WorkspaceResolution::NoRoot;
    };
    if !workspace_root_acceptable(&root, &cwd, dirs::home_dir().as_deref()) {
        return WorkspaceResolution::NoRoot;
    }
    match workspace_identity(&root) {
        Some(ws) => WorkspaceResolution::Resolved(ws),
        None => WorkspaceResolution::Unavailable,
    }
}

/// True when `path` (the peer's canonical executable path from
/// `proc_pidpath`) is an OpenSSH client binary, matched by basename so any
/// install location (system, homebrew, nix) qualifies. A renamed copy evades
/// the match — acceptable: it lands in the unbound-non-ssh workspace arm,
/// which stays within the documented same-UID concession
/// (docs/authorization-scopes-v2.md §3.3).
fn is_ssh_client_path(path: &str) -> bool {
    path.rsplit('/').next() == Some("ssh")
}

// --- session-bind@openssh.com state machine -----------------------------------

/// Local cap on recorded session ids per connection — a DoS defense (bounded
/// memory), not a claimed protocol contract.
const MAX_SESSION_BINDS: usize = 16;

/// Destination binding state of one agent connection, driven by verified
/// `session-bind@openssh.com` messages (OpenSSH ≥ 8.9 sends one per hop).
/// See docs/authorization-scopes-v2.md §3.2.
#[derive(Debug)]
enum BindState {
    Unbound,
    Bound {
        /// Exact wire-encoded `KeyData` bytes of the FIRST bound host key —
        /// the destination digest input.
        hostkey_wire: Vec<u8>,
        /// Parsed copy of the same key, display-only (fingerprint /
        /// known_hosts lookup for the prompt).
        hostkey: KeyData,
        /// Once true the connection may carry traffic from beyond the first
        /// hop (agent forwarding) and is never destination-cacheable again.
        forwarding: bool,
        session_ids: Vec<Vec<u8>>,
    },
    /// A bind failed verification or consistency checks; sticky for the
    /// connection lifetime. All raw signs degrade to Fresh.
    Tainted,
}

impl BindState {
    /// Destination host key wire bytes when — and only when — the connection
    /// is bound to exactly one destination and has never been marked
    /// forwarding.
    fn destination(&self) -> Option<(&[u8], &KeyData)> {
        match self {
            BindState::Bound {
                hostkey_wire,
                hostkey,
                forwarding: false,
                ..
            } => Some((hostkey_wire, hostkey)),
            _ => None,
        }
    }

    /// Apply one `session-bind` message. `Err(())` means the bind was
    /// refused; the caller replies with an agent failure. Refusal mirrors
    /// OpenSSH: an **unverifiable** bind (bad signature, or a host key this
    /// build cannot decode/verify — certificates, curves without an enabled
    /// feature) is refused WITHOUT poisoning the recorded state, so benign
    /// cert/p521 infrastructure merely gets no destination caching instead of
    /// an attack-flavored sticky Tainted. Only **consistency violations**
    /// (duplicate session id under a different key, forwarding→auth
    /// downgrade) taint, because they indicate the peer is playing games with
    /// state we must remember.
    fn apply(&mut self, bind: &SessionBind) -> std::result::Result<(), ()> {
        use ssh_agent_lib::ssh_encoding::Encode;

        if bind.verify_signature().is_err() {
            return Err(());
        }
        let mut wire = Vec::new();
        if bind.host_key.encode(&mut wire).is_err() {
            return Err(());
        }
        match self {
            BindState::Tainted => Err(()),
            BindState::Unbound => {
                *self = BindState::Bound {
                    hostkey_wire: wire,
                    hostkey: bind.host_key.clone(),
                    forwarding: bind.is_forwarding,
                    session_ids: vec![bind.session_id.clone()],
                };
                Ok(())
            }
            BindState::Bound {
                hostkey_wire,
                forwarding,
                session_ids,
                ..
            } => {
                let same_key = *hostkey_wire == wire;
                if session_ids.iter().any(|id| id == &bind.session_id) {
                    // Re-binding a recorded session id: refuse a different
                    // host key and a forwarding→auth downgrade.
                    if !same_key || (*forwarding && !bind.is_forwarding) {
                        *self = BindState::Tainted;
                        return Err(());
                    }
                    *forwarding = *forwarding || bind.is_forwarding;
                    return Ok(());
                }
                if session_ids.len() >= MAX_SESSION_BINDS {
                    // Local DoS cap: refuse the excess bind but keep the
                    // recorded state intact (OpenSSH behavior).
                    return Err(());
                }
                session_ids.push(bind.session_id.clone());
                // A second destination or an explicit forwarding bind means
                // requests can originate beyond the first hop. Sticky.
                if !same_key || bind.is_forwarding {
                    *forwarding = true;
                }
                Ok(())
            }
        }
    }
}

/// Best-effort display name for a bound destination: scan unhashed
/// `~/.ssh/known_hosts` entries for a key whose blob equals `hostkey_wire`
/// and return its first host name. Cosmetic only — the grant is keyed on the
/// host key bytes, never on this name.
fn known_hosts_name(hostkey_wire: &[u8]) -> Option<String> {
    let path = dirs::home_dir()?.join(".ssh").join("known_hosts");
    let content = std::fs::read_to_string(path).ok()?;
    known_hosts_name_in(&content, hostkey_wire)
}

/// Human label for a destination-bound sign grant: known_hosts name when
/// resolvable, always the host key fingerprint. Display-only.
fn destination_label(hostkey_wire: &[u8], hostkey: &KeyData) -> String {
    match known_hosts_name(hostkey_wire) {
        Some(name) => format!("{} ({})", name, fingerprint_str(hostkey)),
        None => fingerprint_str(hostkey),
    }
}

/// Human label for a workspace-bound grant.
fn workspace_label(ws: &Workspace) -> String {
    format!("workspace {}", ws.root_str())
}

/// Append the §6 prompt transparency line: present exactly when an approval
/// can create a reusable grant. The label is agent-derived (kernel workspace
/// path / verified host key) but sanitized like every other prompt field.
fn append_reuse_line(message: &mut String, label: &Option<String>, ttl_secs: u64) {
    if let Some(label) = label {
        message.push_str("\nreuse: ");
        message.push_str(&sanitize_prompt(label, 160));
        message.push_str(" · ");
        message.push_str(&reuse_ttl_label(ttl_secs));
    }
}

fn known_hosts_name_in(content: &str, hostkey_wire: &[u8]) -> Option<String> {
    use base64::Engine;
    for line in content.lines() {
        let line = line.trim();
        // Skip comments, hashed hosts (|1|…), and @marker lines.
        if line.is_empty() || line.starts_with('#') || line.starts_with('|') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (hosts, first) = match line.starts_with('@') {
            true => {
                fields.next();
                match fields.next() {
                    Some(h) => (h, h),
                    None => continue,
                }
            }
            false => match fields.next() {
                Some(h) => (h, h),
                None => continue,
            },
        };
        let _ = first;
        let _keytype = fields.next();
        let Some(b64) = fields.next() else { continue };
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        if blob == hostkey_wire {
            return Some(hosts.split(',').next().unwrap_or(hosts).to_string());
        }
    }
    None
}

impl Agent<tokio::net::UnixListener> for VtSshAgentFactory {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        let peer_pid = get_peer_pid(socket);
        if let Some(pid) = peer_pid {
            tracing::debug!("New session from PID {}", pid);
        }
        // One kernel-argv fetch per connection, shared by the scope
        // classification and the prompt origin marker so they can never
        // classify the peer differently.
        let peer_is_vt_relay = peer_pid
            .and_then(proc_info::get_proc_argv)
            .map(|argv| crate::ssh_sign::is_vt_relay_invocation(&argv))
            .unwrap_or(false);
        let peer_path = peer_pid.and_then(proc_info::get_proc_path);
        let peer_is_ssh_client = peer_path.as_deref().is_some_and(is_ssh_client_path);
        let peer_exe = peer_path
            .as_deref()
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string());
        // Relay AND plain-ssh peers are confined to a `(pid, start_tvsec)`
        // connection subject: both can carry traffic that originated on a
        // remote host (forwarded agent socket), so neither may ever reach the
        // workspace arm. Local vt peers get a workspace resolution instead.
        // All resolved once per connection so a scope lookup can never race
        // proc-tree state against the request.
        let confined_to_connection = peer_is_vt_relay || peer_is_ssh_client;
        let connection_subject = if confined_to_connection {
            peer_pid.and_then(|pid| {
                proc_info::get_start_tvsec(pid).map(|start| (pid as u64, start))
            })
        } else {
            None
        };
        let workspace = if confined_to_connection {
            WorkspaceResolution::Unavailable
        } else {
            resolve_workspace(peer_pid)
        };
        VtSshSession {
            keys: Arc::clone(&self.keys),
            last_activity: Arc::clone(&self.last_activity),
            locked: Arc::clone(&self.locked),
            lock_transition: Arc::clone(&self.lock_transition),
            lock_passphrase: Arc::clone(&self.lock_passphrase),
            idle_cleared: Arc::clone(&self.idle_cleared),
            authorization: Arc::clone(&self.authorization),
            sign_cache_ttl_secs: self.sign_cache_ttl_secs,
            decrypt_cache_ttl_secs: self.decrypt_cache_ttl_secs,
            run_allow: Arc::clone(&self.run_allow),
            audit_push: Arc::clone(&self.audit_push),
            peer_pid,
            peer_exe,
            peer_is_vt_relay,
            peer_is_ssh_client,
            connection_subject,
            workspace,
            bind_state: BindState::Unbound,
            destination_label: None,
            disable_legacy_decrypt: self.disable_legacy_decrypt,
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
    sign_cache_ttl_secs: u64,
    decrypt_cache_ttl_secs: u64,
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
    workspace: WorkspaceResolution,
    /// Destination binding driven by `session-bind@openssh.com` (§3.2 of
    /// docs/authorization-scopes-v2.md). Mutated by `extension()`.
    bind_state: BindState,
    /// Display label for the bound destination, computed once per bind so a
    /// sign burst does not re-read known_hosts.
    destination_label: Option<String>,
    disable_legacy_decrypt: bool,
}

impl VtSshSession {
    /// Append the relay-origin marker when the peer is a
    /// `vt ssh connect --forward-real-agent` relay — the request reached this
    /// agent THROUGH that relay process (either a forwarded remote request or
    /// the relay's own outbound handshake sign; the agent cannot tell the two
    /// apart, so the wording stays neutral and does not claim "remote"). Called
    /// right after the header so this agent-derived line precedes the
    /// client-reported body/meta and a hostile caller cannot pad it off-screen.
    /// Peer classification is kernel-derived and shared with the cache
    /// narrowing; a spoofed argv only ADDS the marker to a local caller's
    /// prompts, never removes it from a genuine relay's.
    fn append_relay_origin(&self, message: &mut String) {
        if self.peer_is_vt_relay {
            message.push_str("\nvia forwarded vt relay");
        }
    }

    // ---- Activity-scope construction (docs/authorization-scopes-v2.md) ----
    //
    // Each helper returns the scope(s) plus a human reuse label. The label is
    // `Some` exactly when an approval can create a reusable grant, and is
    // built from the same data the scope digest binds — the prompt must state
    // what is being granted (§6 transparency invariant).

    /// The per-connection confinement arm shared by relay and plain-ssh
    /// peers: `Some(label)` exactly when the connection subject resolved.
    fn connection_label(&self) -> Option<String> {
        self.connection_subject.map(|_| {
            if self.peer_is_vt_relay {
                "this relay connection".to_string()
            } else {
                "this forwarded ssh connection".to_string()
            }
        })
    }

    /// True when this connection may carry traffic that originated on a
    /// remote host (vt relay or plain `ssh -A`): vt extensions must then be
    /// confined per connection and must never reach the workspace arm.
    fn confined_to_connection(&self) -> bool {
        self.peer_is_vt_relay || self.peer_is_ssh_client
    }

    /// Scope for a raw `SIGN_REQUEST`.
    fn raw_sign_scope(&self, fingerprint: &str) -> (GrantScope, Option<String>) {
        if self.sign_cache_ttl_secs == 0 {
            return (GrantScope::fresh(Operation::Sign), None);
        }
        if self.peer_is_vt_relay {
            return (
                GrantScope::sign(self.connection_subject, fingerprint, ""),
                self.connection_label(),
            );
        }
        match &self.bind_state {
            BindState::Bound { .. } => match self.bind_state.destination() {
                Some((wire, hostkey)) => (
                    GrantScope::sign_destination(wire, fingerprint),
                    // Normally precomputed at bind time; fall back to an
                    // on-demand lookup so the reuse line can never be
                    // silently absent for a destination-bound approval.
                    self.destination_label
                        .clone()
                        .or_else(|| Some(destination_label(wire, hostkey))),
                ),
                // Forwarding-capable: traffic may originate beyond hop one.
                None => (GrantScope::fresh(Operation::Sign), None),
            },
            BindState::Tainted => (GrantScope::fresh(Operation::Sign), None),
            // No bind and the peer is ssh: authentication and forwarding are
            // indistinguishable — Fresh.
            BindState::Unbound if self.peer_is_ssh_client => {
                (GrantScope::fresh(Operation::Sign), None)
            }
            // No bind, non-ssh local caller (ssh-keygen -Y sign etc.):
            // workspace scope.
            BindState::Unbound => match self.workspace.workspace() {
                Some(ws) => (
                    GrantScope::sign_workspace(Some(ws.subject), ws.root_str(), fingerprint),
                    Some(workspace_label(ws)),
                ),
                None => (GrantScope::fresh(Operation::Sign), None),
            },
        }
    }

    /// Scope for `sign@vt` (local vt ⇒ workspace, relay/ssh ⇒ per-connection).
    fn sign_vt_scope(&self, fingerprint: &str, claimed_pwd: &str) -> (GrantScope, Option<String>) {
        if self.sign_cache_ttl_secs == 0 {
            return (GrantScope::fresh(Operation::Sign), None);
        }
        if self.confined_to_connection() {
            return (
                GrantScope::sign(self.connection_subject, fingerprint, claimed_pwd),
                self.connection_label(),
            );
        }
        match self.workspace.workspace() {
            Some(ws) if ws.contains_claimed_pwd(claimed_pwd) => (
                GrantScope::sign_workspace(Some(ws.subject), ws.root_str(), fingerprint),
                Some(workspace_label(ws)),
            ),
            _ => (GrantScope::fresh(Operation::Sign), None),
        }
    }

    fn connection_basis(&self) -> ContextBasis {
        match self.connection_subject {
            Some(_) if self.peer_is_vt_relay => ContextBasis::RelayConnection,
            Some(_) => ContextBasis::SshConnection,
            None => ContextBasis::ProcLookupFailed,
        }
    }

    /// diag basis for the sign scope classification of THIS connection.
    fn sign_basis(&self) -> ContextBasis {
        if self.sign_cache_ttl_secs == 0 {
            return ContextBasis::Disabled;
        }
        if self.peer_is_vt_relay {
            return self.connection_basis();
        }
        match &self.bind_state {
            BindState::Bound {
                forwarding: false, ..
            } => ContextBasis::SessionBind,
            BindState::Bound { .. } => ContextBasis::Forwarding,
            BindState::Tainted => ContextBasis::Tainted,
            BindState::Unbound if self.peer_is_ssh_client => ContextBasis::UnboundSsh,
            BindState::Unbound => self.workspace_basis(),
        }
    }

    /// diag basis for the vt-extension (sign@vt / decrypt) classification of
    /// THIS connection.
    fn decrypt_basis(&self) -> ContextBasis {
        if self.decrypt_cache_ttl_secs == 0 {
            return ContextBasis::Disabled;
        }
        if self.confined_to_connection() {
            return self.connection_basis();
        }
        self.workspace_basis()
    }

    fn workspace_basis(&self) -> ContextBasis {
        match &self.workspace {
            WorkspaceResolution::Resolved(_) => ContextBasis::Workspace,
            WorkspaceResolution::NoRoot => ContextBasis::NoWorkspaceRoot,
            WorkspaceResolution::Unavailable => match self.peer_pid {
                None => ContextBasis::NoPeerPid,
                Some(_) => ContextBasis::ProcLookupFailed,
            },
        }
    }

    /// Scopes for a pure-v2 decrypt batch (one per `(type, salt)` record).
    fn decrypt_scopes(
        &self,
        v2_inputs: &[(crate::core::SecretType, [u8; SALT_LEN])],
        claimed_host: &str,
        claimed_pwd: &str,
    ) -> (Vec<GrantScope>, Option<String>) {
        let fresh = || vec![GrantScope::fresh(Operation::Decrypt)];
        if self.decrypt_cache_ttl_secs == 0 {
            return (fresh(), None);
        }
        if self.confined_to_connection() {
            return (
                v2_inputs
                    .iter()
                    .map(|(t, salt)| {
                        GrantScope::decrypt_v2(
                            self.connection_subject,
                            t.as_byte(),
                            salt,
                            claimed_host,
                            claimed_pwd,
                        )
                    })
                    .collect(),
                self.connection_label(),
            );
        }
        match self.workspace.workspace() {
            Some(ws) if ws.contains_claimed_pwd(claimed_pwd) => (
                v2_inputs
                    .iter()
                    .map(|(t, salt)| {
                        GrantScope::decrypt_workspace(
                            Some(ws.subject),
                            ws.root_str(),
                            t.as_byte(),
                            salt,
                        )
                    })
                    .collect(),
                Some(workspace_label(ws)),
            ),
            _ => (fresh(), None),
        }
    }

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
    /// silently reload from keychain. The unified authorization engine still
    /// gates every operation before a loaded key can be used.
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
        // A lock transition may have started while Keychain I/O was in
        // progress. Check while holding the same key-map guard used by lock()
        // so loaded private keys can never be installed after its clear.
        if self.locked.load(Ordering::Acquire) {
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
    ) -> Result<HandlerSuccess, WireFailure> {
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
        Ok(HandlerSuccess::without_authorization(Zeroizing::new(bytes)))
    }

    async fn handle_decrypt(
        &self,
        decrypted: &[u8],
        store: &KeychainStore,
        passphrase_cipher: &AesGcmCrypto,
    ) -> Result<HandlerSuccess, WireFailure> {
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

        // Verify that the stored master key is present and decryptable before
        // consulting reusable authorization state or prompting. Drop this
        // short-lived copy immediately; the operation reloads it only after a
        // permit is obtained, so raw key material is not held across a human
        // prompt. Validation is deterministic over the already-loaded store
        // and passphrase cipher, making the later load a non-fallible
        // precondition in normal operation while retaining defensive mapping.
        validate_mac_key_material(store, passphrase_cipher)
            .map_err(|_| (ErrKind::NotInitialized, Some(DETAIL_NOT_INITIALIZED)))?;

        let who = who_at_host(&req.meta.user, &req.host);
        let n = req.items.len();
        let mut local_auth_message = header_with_who(
            &format!("decrypt {} {}", n, plural_secrets(n)),
            "on",
            &who,
        );
        self.append_relay_origin(&mut local_auth_message);
        // Pure-v2 batches use one atomic scope per record and require an all-of
        // hit. Any legacy member makes the entire request explicitly Fresh.
        // The reuse line is agent-derived truth and is appended BEFORE the
        // client-reported body/meta below, for the same reason as the relay
        // origin marker: a hostile caller must not be able to pad the one
        // line that says the tap creates a standing grant off-screen.
        let (scopes, reuse) = if legacy_count > 0 {
            (vec![GrantScope::fresh(Operation::Decrypt)], ReusePolicy::Fresh)
        } else {
            let (scopes, reuse_label) =
                self.decrypt_scopes(&v2_inputs, &req.host, &req.meta.pwd);
            append_reuse_line(
                &mut local_auth_message,
                &reuse_label,
                self.decrypt_cache_ttl_secs,
            );
            (scopes, reuse_policy(self.decrypt_cache_ttl_secs))
        };
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
        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(scopes, reuse, local_auth_message))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "decrypt",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    req.items.len(),
                    permit.latency_ms(),
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "decrypt",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    req.items.len(),
                    failure.latency_ms(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };
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
        let bytes = Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        );
        // Scrub DEKs inside the response Vec before drop. `bytes` already
        // carries them (still wiped via `Zeroizing` below).
        for item in result.iter_mut() {
            if let DecryptResItem::V2 { dek, .. } = item {
                dek.zeroize();
            }
        }
        Ok(HandlerSuccess::authorized(bytes, permit))
    }

    async fn handle_auth(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
        let req: AuthReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        if req.reason.len() > PROMPT_DISPLAY_MAX_BYTES {
            return Err((ErrKind::BadRequest, Some(DETAIL_DISPLAY_FIELD_TOO_LARGE)));
        }

        let who = who_at_host(&req.meta.user, &req.host);
        let mut auth_message = header_with_who("auth", "on", &who);
        self.append_relay_origin(&mut auth_message);
        let reason = sanitize_prompt(&req.reason, 100);
        if !reason.is_empty() {
            auth_message.push_str("\nreason: ");
            auth_message.push_str(&reason);
        }
        append_meta_lines(&mut auth_message, &req.meta);

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::fresh(
                GrantScope::fresh(Operation::Auth),
                auth_message,
            ))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "auth",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    "",
                    &req.reason,
                    0,
                    permit.latency_ms(),
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "auth",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    "",
                    &req.reason,
                    0,
                    failure.latency_ms(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };

        let result = AuthRes { approved: true };
        let bytes = Zeroizing::new(serde_json::to_vec(&result).map_err(|_| {
            (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE))
        })?);
        Ok(HandlerSuccess::authorized(bytes, permit))
    }

    /// `diag@vt`: read-only diagnostics for `vt doctor`. No Touch ID (it
    /// discloses no secret and mints no DEK), never cached, not audit-pushed
    /// (no human decision to record), and — enforced in `extension()` — it
    /// does not reset the idle-activity clock. `live_entries` is scoped to
    /// THIS connection's resolved context; see `docs/diag-design.md` §3.4 for
    /// the accepted disclosure tradeoffs.
    async fn handle_diag(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
        let _req: DiagReq = serde_json::from_slice(decrypted)
            .map_err(|_| (ErrKind::BadRequest, Some(DETAIL_BAD_REQUEST_JSON)))?;

        let peer = DiagPeerReport {
            pid: self.peer_pid,
            exe: self.peer_exe.clone(),
            has_tty: self
                .peer_pid
                .is_some_and(|pid| proc_info::get_tty_dev(pid).is_some()),
            is_ssh_client: self.peer_is_ssh_client,
            is_vt_relay: self.peer_is_vt_relay,
        };
        // live_entries counts only grants THIS connection's own scope
        // classification could reuse — never a whole-store count, and never
        // grants a differently-classified caller would need. A caller whose
        // basis says "never cached" therefore always reports 0.
        let sign_basis = self.sign_basis();
        let sign_live = match sign_basis {
            ContextBasis::SessionBind => {
                self.authorization
                    .live_len(
                        Operation::Sign,
                        crate::core::authorization::DESTINATION_SUBJECT,
                    )
                    .await
            }
            ContextBasis::Workspace => match self.workspace.workspace() {
                Some(ws) => {
                    self.authorization
                        .live_len(Operation::Sign, ws.subject)
                        .await
                }
                None => 0,
            },
            ContextBasis::RelayConnection | ContextBasis::SshConnection => {
                match self.connection_subject {
                    Some(subject) => {
                        self.authorization.live_len(Operation::Sign, subject).await
                    }
                    None => 0,
                }
            }
            _ => 0,
        };
        let decrypt_basis = self.decrypt_basis();
        let decrypt_live = match decrypt_basis {
            ContextBasis::Workspace => match self.workspace.workspace() {
                Some(ws) => {
                    self.authorization
                        .live_len(Operation::Decrypt, ws.subject)
                        .await
                }
                None => 0,
            },
            ContextBasis::RelayConnection | ContextBasis::SshConnection => {
                match self.connection_subject {
                    Some(subject) => {
                        self.authorization
                            .live_len(Operation::Decrypt, subject)
                            .await
                    }
                    None => 0,
                }
            }
            _ => 0,
        };
        let sign_cache = DiagCacheReport {
            ttl_secs: self.sign_cache_ttl_secs,
            live_entries: sign_live,
            context_basis: sign_basis.as_wire().to_string(),
        };
        let decrypt_cache = DiagCacheReport {
            ttl_secs: self.decrypt_cache_ttl_secs,
            live_entries: decrypt_live,
            context_basis: decrypt_basis.as_wire().to_string(),
        };
        let result = DiagRes {
            agent_version: env!("VT_VERSION").to_string(),
            sign_cache,
            decrypt_cache,
            peer,
            run_allow_len: self.run_allow.len(),
            audit_push: self.audit_push.enabled,
        };
        Ok(HandlerSuccess::without_authorization(Zeroizing::new(
            serde_json::to_vec(&result)
                .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?,
        )))
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
    ) -> Result<HandlerSuccess, WireFailure> {
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

        // Validation, allowlist resolution, and canonicalization above all run
        // before authorization. run@vt uses the shared engine but an explicit
        // Fresh policy, so every invocation still requires a human approval.
        let run_command = format!("exe: {}\nargv: {}", exe_display, argv_for_prompt);
        let run_reason = req.reason.as_deref().unwrap_or("");
        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::fresh(
                GrantScope::fresh(Operation::Run),
                auth_message,
            ))
            .await
        {
            Ok(permit) => permit,
            Err(failure) => {
                self.emit_audit(
                    "run",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &run_command,
                    run_reason,
                    0,
                    failure.latency_ms(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };
        // Q5: emit `approved` at the human tap, BEFORE the spawn attempt, so a
        // denied launch (below) is distinguishable from a failed one (two rows).
        self.emit_audit(
            "run",
            permit.decision().audit_outcome(),
            &req.host,
            &req.meta,
            &run_command,
            run_reason,
            0,
            permit.latency_ms(),
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
        let bytes = Zeroizing::new(serde_json::to_vec(&result).map_err(|_| {
            (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE))
        })?);
        Ok(HandlerSuccess::authorized(bytes, permit))
    }

    /// `sign@vt`: VT_AUTH-gated signing with a Keychain-held key, displaying vt
    /// execution context (host/command/meta) in the Touch ID prompt. Unlike the
    /// standard `SIGN_REQUEST` path, the request is authenticated by the
    /// auth-cipher envelope and carries human context. The private key never
    /// leaves the agent.
    ///
    /// Uses the same `Operation::Sign` grant store as standard `SIGN_REQUEST`.
    /// Local callers get a kernel-verified workspace scope (one approval
    /// covers a same-project multi-host fan-out); relay callers stay confined
    /// to their connection. Duration `0` (the default) keeps per-request
    /// prompts. See docs/authorization-scopes-v2.md §3.4.
    async fn handle_sign_vt(
        &self,
        decrypted: &[u8],
    ) -> Result<HandlerSuccess, WireFailure> {
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
        self.append_relay_origin(&mut auth_message);
        // sign@vt can name ANY agent key, so the prompt must say which one
        // (comment, else SHA256 fingerprint — same label rule as
        // `Session::sign`). This line is agent-derived truth (the requested
        // key resolved against our own Keychain) and precedes the
        // client-reported command body below; sanitize the comment like every
        // other prompt field so a control-char/newline comment cannot inject
        // fake lines.
        auth_message.push_str("\nkey: ");
        if privkey.comment().is_empty() {
            auth_message.push_str(&fp_str);
        } else {
            auth_message.push_str(&sanitize_prompt(privkey.comment(), 80));
        }
        // Reuse line before the client-reported body/meta — same padding
        // rationale as the relay origin marker.
        let (scope, reuse_label) = self.sign_vt_scope(&fp_str, &req.meta.pwd);
        append_reuse_line(&mut auth_message, &reuse_label, self.sign_cache_ttl_secs);
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

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(
                vec![scope],
                reuse_policy(self.sign_cache_ttl_secs),
                auth_message,
            ))
            .await
        {
            Ok(permit) => {
                self.emit_audit(
                    "ssh-sign",
                    permit.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    0,
                    permit.latency_ms(),
                );
                permit
            }
            Err(failure) => {
                self.emit_audit(
                    "ssh-sign",
                    failure.decision().audit_outcome(),
                    &req.host,
                    &req.meta,
                    &req.command,
                    "",
                    0,
                    failure.latency_ms(),
                );
                return Err(authorization_failure_wire(&failure));
            }
        };

        let sig = sign_data_with_privkey(&privkey, &req.data, req.flags)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_SIGN_FAILED)))?;
        let res = SignRes {
            algorithm: sig.algorithm().to_string(),
            signature: sig.as_bytes().to_vec(),
        };
        let bytes = serde_json::to_vec(&res)
            .map(Zeroizing::new)
            .map_err(|_| (ErrKind::Generic, Some(DETAIL_INTERNAL_SERIALIZE)))?;
        Ok(HandlerSuccess::authorized(bytes, permit))
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
}

impl HandlerSuccess {
    fn authorized(bytes: Zeroizing<Vec<u8>>, authorization: AuthorizationPermit) -> Self {
        Self {
            bytes,
            authorization: Some(authorization),
        }
    }

    fn without_authorization(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            authorization: None,
        }
    }
}

fn authorization_failure_wire(failure: &AuthorizationFailure) -> WireFailure {
    match failure.decision() {
        Decision::Rejected => (ErrKind::AuthRejected, Some(DETAIL_AUTH_REJECTED)),
        Decision::Unavailable(reason) => {
            let kind = outcome_to_err_strict(AuthOutcome::Unavailable(reason))
                .unwrap_or(ErrKind::Generic);
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
        let proc_name = self.peer_exe.clone().unwrap_or_default();
        let key_label = if comment.is_empty() {
            fp_str.clone()
        } else {
            comment.to_string()
        };
        let mut auth_message = if proc_name.is_empty() {
            format!("sign: {}", key_label)
        } else {
            format!("sign: {} ({})", key_label, proc_name)
        };
        let (scope, reuse_label) = self.raw_sign_scope(&fp_str);
        append_reuse_line(&mut auth_message, &reuse_label, self.sign_cache_ttl_secs);

        let permit = match self
            .authorization
            .authorize(AuthorizationRequest::new(
                vec![scope],
                reuse_policy(self.sign_cache_ttl_secs),
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
                );
                return Err(AgentError::Failure);
            }
        };

        let signature = sign_data_with_privkey(&privkey, &request.data, request.flags)?;
        permit
            .commit()
            .await
            .map_err(|_| AgentError::Failure)?;
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
                        .map(|(wire, hostkey)| destination_label(wire, hostkey));
                    applied
                }
                _ => Err(()),
            };
            return match outcome {
                Ok(()) => Ok(None), // plain SSH_AGENT_SUCCESS
                Err(()) => Err(AgentError::Failure),
            };
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
        let dispatch: Result<HandlerSuccess, WireFailure> =
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
                EXT_DIAG => self.handle_diag(&decrypted).await,
                _ => unreachable!(),
            };

        // Build the envelope. OK responses use a manual concat so the
        // serialized inner body (which carries DEKs for encrypt/decrypt) is
        // only ever held in `Zeroizing` buffers — no intermediate
        // `serde_json::Value` allocation that wouldn't be wiped on drop.
        let (envelope_bytes, authorization): (
            Zeroizing<Vec<u8>>,
            Option<AuthorizationPermit>,
        ) = match dispatch {
            Ok(success) => (
                Zeroizing::new(wrap_ok_envelope(&success.bytes)),
                success.authorization,
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
        cache_ttls,
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

    // Poll even while the grant store is empty. A human prompt deliberately
    // creates no grant until its protected operation succeeds, so using store
    // emptiness as a watcher shortcut would miss lock/wake invalidation while
    // that prompt is in flight.
    let watcher_authorization = Arc::clone(&factory.authorization);
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
                tracing::info!(
                    "Authorization grants invalidated on screen lock / wake ({} grants dropped)",
                    dropped
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
    cache_ttls: AuthCacheTtls,
    disable_legacy_decrypt: bool,
    run_allow: RunAllowlist,
    audit_push: Arc<AuditPushConfig>,
) -> Result<()> {
    run_ssh_agent(
        true,
        idle_timeout_secs,
        cache_ttls,
        disable_legacy_decrypt,
        run_allow,
        audit_push,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::authorization::{
        AuthorizationAuthenticator, AuthorizationValidator, ValidationError,
    };
    use crate::core::session::AuthMethod;

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
        let finalizer =
            spawn_lock_finalizer(guard, keys, Arc::clone(&authorization));
        // Model cancellation of the connection waiting for lock() to finish.
        // Tokio detaches the finalizer, which must retain the owned guard.
        drop(finalizer);
        assert!(transition.try_lock().is_err());

        active.commit().await.unwrap();
        let transition_guard = tokio::time::timeout(Duration::from_secs(1), transition.lock())
            .await
            .expect("detached lock finalizer did not complete");
        drop(transition_guard);
        assert_eq!(authorization.live_len(Operation::Sign, subject).await, 0);
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

    fn test_session(sign_ttl: u64, decrypt_ttl: u64) -> VtSshSession {
        let locked = Arc::new(AtomicBool::new(false));
        VtSshSession {
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_activity: Arc::new(RwLock::new((Instant::now(), SystemTime::now()))),
            locked: Arc::clone(&locked),
            lock_transition: Arc::new(Mutex::new(())),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            authorization: new_engine(locked),
            sign_cache_ttl_secs: sign_ttl,
            decrypt_cache_ttl_secs: decrypt_ttl,
            run_allow: Arc::new(RunAllowlist::parse("").unwrap()),
            audit_push: Arc::new(AuditPushConfig::disabled()),
            peer_pid: Some(std::process::id() as i32),
            peer_exe: Some("test".to_string()),
            peer_is_vt_relay: false,
            peer_is_ssh_client: false,
            connection_subject: None,
            workspace: WorkspaceResolution::NoRoot,
            bind_state: BindState::Unbound,
            destination_label: None,
            disable_legacy_decrypt: false,
        }
    }

    fn test_workspace() -> Workspace {
        Workspace {
            subject: (7, 42),
            root: PathBuf::from("/repo"),
        }
    }

    fn test_bind(privkey: &PrivateKey, session_id: &[u8], forwarding: bool) -> SessionBind {
        let signature = sign_data_with_privkey(privkey, session_id, 0).expect("sign session id");
        SessionBind {
            host_key: privkey.public_key().key_data().clone(),
            session_id: session_id.to_vec(),
            signature,
            is_forwarding: forwarding,
        }
    }

    fn test_hostkey() -> PrivateKey {
        PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).expect("gen key")
    }

    #[test]
    fn bind_state_valid_bind_exposes_destination() {
        let host = test_hostkey();
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&host, b"sid-1", false)).is_ok());
        let (wire, key) = state.destination().expect("destination-bound");
        assert!(!wire.is_empty());
        assert_eq!(fingerprint_str(key), fingerprint_str(host.public_key().key_data()));
        // A second session id under the SAME key (re-KEX) keeps the binding.
        assert!(state.apply(&test_bind(&host, b"sid-2", false)).is_ok());
        assert!(state.destination().is_some());
    }

    #[test]
    fn bind_state_bad_signature_refused_without_poisoning() {
        let host = test_hostkey();
        let mut bind = test_bind(&host, b"sid-1", false);
        bind.session_id = b"sid-other".to_vec(); // signature no longer matches
        let mut state = BindState::Unbound;
        assert!(state.apply(&bind).is_err());
        // Unverifiable binds (bad signature, cert/unsupported-curve host
        // keys) are refused but do NOT poison the state: a later genuine
        // bind still works (OpenSSH behavior).
        assert!(matches!(state, BindState::Unbound));
        assert!(state.apply(&test_bind(&host, b"sid-2", false)).is_ok());
        assert!(state.destination().is_some());
    }

    #[test]
    fn bind_state_forwarding_never_destination_cacheable() {
        let host = test_hostkey();
        // Forwarding on the first bind.
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&host, b"sid-1", true)).is_ok());
        assert!(state.destination().is_none());
        // Forwarding after an auth bind: sticky.
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&host, b"sid-1", false)).is_ok());
        assert!(state.apply(&test_bind(&host, b"sid-2", true)).is_ok());
        assert!(state.destination().is_none());
    }

    #[test]
    fn bind_state_second_destination_marks_forwarding() {
        let (h1, h2) = (test_hostkey(), test_hostkey());
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&h1, b"sid-1", false)).is_ok());
        assert!(state.apply(&test_bind(&h2, b"sid-2", false)).is_ok());
        assert!(state.destination().is_none());
    }

    #[test]
    fn bind_state_duplicate_session_id_conflicts_taint() {
        let (h1, h2) = (test_hostkey(), test_hostkey());
        // Same session id under a different key.
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&h1, b"sid-1", false)).is_ok());
        assert!(state.apply(&test_bind(&h2, b"sid-1", false)).is_err());
        assert!(matches!(state, BindState::Tainted));
        // Forwarding→auth downgrade for the same session id.
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&h1, b"sid-1", true)).is_ok());
        assert!(state.apply(&test_bind(&h1, b"sid-1", false)).is_err());
        assert!(matches!(state, BindState::Tainted));
    }

    #[test]
    fn bind_state_caps_recorded_session_ids_without_poisoning() {
        let host = test_hostkey();
        let mut state = BindState::Unbound;
        for i in 0..MAX_SESSION_BINDS {
            let sid = format!("sid-{i}");
            assert!(state.apply(&test_bind(&host, sid.as_bytes(), false)).is_ok());
        }
        // The excess bind is refused but the established binding survives.
        assert!(state.apply(&test_bind(&host, b"sid-overflow", false)).is_err());
        assert!(state.destination().is_some());
    }

    #[test]
    fn raw_sign_scope_classification() {
        // Duration 0: Fresh, no reuse line, regardless of state.
        let mut s = test_session(0, 0);
        s.workspace = WorkspaceResolution::Resolved(test_workspace());
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::Disabled);

        // Unbound ssh peer: Fresh (auth vs forwarding indistinguishable).
        let mut s = test_session(300, 0);
        s.peer_is_ssh_client = true;
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::UnboundSsh);

        // Unbound non-ssh with a workspace: workspace scope + label.
        let mut s = test_session(300, 0);
        s.workspace = WorkspaceResolution::Resolved(test_workspace());
        let (_, label) = s.raw_sign_scope("fp");
        assert_eq!(label.as_deref(), Some("workspace /repo"));
        assert_eq!(s.sign_basis(), ContextBasis::Workspace);

        // No workspace root: Fresh.
        let s = test_session(300, 0);
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::NoWorkspaceRoot);

        // Destination-bound: destination label (fingerprint at minimum).
        let mut s = test_session(300, 0);
        s.peer_is_ssh_client = true;
        let host = test_hostkey();
        assert!(s.bind_state.apply(&test_bind(&host, b"sid", false)).is_ok());
        let (_, label) = s.raw_sign_scope("fp");
        assert!(label
            .expect("destination-bound must offer reuse")
            .contains(&fingerprint_str(host.public_key().key_data())));
        assert_eq!(s.sign_basis(), ContextBasis::SessionBind);

        // Tainted: Fresh.
        let mut s = test_session(300, 0);
        s.bind_state = BindState::Tainted;
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::Tainted);

        // Relay: confined per connection.
        let mut s = test_session(300, 0);
        s.peer_is_vt_relay = true;
        s.connection_subject = Some((123, 456));
        assert_eq!(
            s.raw_sign_scope("fp").1.as_deref(),
            Some("this relay connection")
        );
        assert_eq!(s.sign_basis(), ContextBasis::RelayConnection);
    }

    #[test]
    fn sign_vt_and_decrypt_scopes_respect_workspace_and_pwd() {
        let mut s = test_session(300, 300);
        s.workspace = WorkspaceResolution::Resolved(test_workspace());
        // Claimed pwd inside the workspace: reusable.
        assert!(s.sign_vt_scope("fp", "/repo/sub").1.is_some());
        let inputs = vec![(crate::core::SecretType::RAW, [9u8; SALT_LEN])];
        assert!(s.decrypt_scopes(&inputs, "h", "/repo").1.is_some());
        // Claimed pwd outside the workspace: consistency check → Fresh.
        assert!(s.sign_vt_scope("fp", "/elsewhere").1.is_none());
        assert!(s.decrypt_scopes(&inputs, "h", "/elsewhere").1.is_none());
        // Empty pwd (raw-style caller): allowed.
        assert!(s.sign_vt_scope("fp", "").1.is_some());
        // Relay: per-connection scope, not workspace.
        let mut s = test_session(300, 300);
        s.peer_is_vt_relay = true;
        s.connection_subject = Some((123, 456));
        assert_eq!(
            s.decrypt_scopes(&inputs, "h", "/x").1.as_deref(),
            Some("this relay connection")
        );
        assert_eq!(s.decrypt_basis(), ContextBasis::RelayConnection);
    }

    #[test]
    fn ssh_peer_vt_extensions_are_confined_per_connection_never_workspace() {
        // An `ssh -A` peer can carry a REMOTE host's vt extensions; even if a
        // workspace were somehow resolved it must never be used — otherwise
        // the remote rides local workspace grants.
        let mut s = test_session(300, 300);
        s.peer_is_ssh_client = true;
        s.connection_subject = Some((123, 456));
        s.workspace = WorkspaceResolution::Resolved(test_workspace());
        let inputs = vec![(crate::core::SecretType::RAW, [9u8; SALT_LEN])];
        assert_eq!(
            s.sign_vt_scope("fp", "/repo").1.as_deref(),
            Some("this forwarded ssh connection")
        );
        assert_eq!(
            s.decrypt_scopes(&inputs, "h", "/repo").1.as_deref(),
            Some("this forwarded ssh connection")
        );
        assert_eq!(s.decrypt_basis(), ContextBasis::SshConnection);
        // With no resolvable connection subject the arm degrades to Fresh.
        s.connection_subject = None;
        assert!(s.sign_vt_scope("fp", "/repo").1.is_none());
        assert!(s.decrypt_scopes(&inputs, "h", "/repo").1.is_none());
        assert_eq!(s.decrypt_basis(), ContextBasis::ProcLookupFailed);
    }

    #[test]
    fn workspace_root_acceptability_rejects_home_pooling() {
        let home = std::path::Path::new("/Users/x");
        // A dotfiles repo AT $HOME must not become a workspace.
        assert!(!workspace_root_acceptable(
            home,
            std::path::Path::new("/Users/x/Downloads"),
            Some(home)
        ));
        // A root above $HOME for a cwd inside $HOME is rejected too.
        assert!(!workspace_root_acceptable(
            std::path::Path::new("/Users"),
            std::path::Path::new("/Users/x/proj"),
            Some(home)
        ));
        // Ordinary project roots pass, inside or outside $HOME.
        assert!(workspace_root_acceptable(
            std::path::Path::new("/Users/x/code/vt"),
            std::path::Path::new("/Users/x/code/vt/src"),
            Some(home)
        ));
        assert!(workspace_root_acceptable(
            std::path::Path::new("/opt/work/repo"),
            std::path::Path::new("/opt/work/repo/a"),
            Some(home)
        ));
    }

    #[tokio::test]
    async fn extension_intercepts_plaintext_session_bind_before_auth_cipher() {
        // The seam most likely to regress: session-bind is plain SSH wire
        // bytes and must be handled before the keychain/auth-cipher path —
        // this test passes precisely because no keychain access happens.
        let mut session = test_session(300, 0);
        session.peer_is_ssh_client = true;
        let host = test_hostkey();
        let ext = Extension::new_message(test_bind(&host, b"sid-1", false))
            .expect("encode session-bind");
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

    // --- Workspace resolution tests ---

    fn temp_workspace(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vt-authz-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn find_git_root_prefers_nearest_marker_dir_or_file() {
        let root = temp_workspace("git-root");
        std::fs::create_dir_all(root.join(".git")).unwrap(); // dir marker
        let inner = root.join("a");
        let nested = inner.join("b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_git_root(&nested), Some(root.clone()));
        // A nearer `.git` FILE (worktree layout) wins over the outer dir.
        std::fs::write(inner.join(".git"), "gitdir: elsewhere").unwrap();
        assert_eq!(find_git_root(&nested), Some(inner));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn workspace_identity_binds_dev_ino_and_canonical_path() {
        use std::os::unix::fs::MetadataExt;
        let root = temp_workspace("identity");
        let ws = workspace_identity(&root).expect("identity");
        let meta = std::fs::metadata(&root).unwrap();
        assert_eq!(ws.subject, (meta.dev(), meta.ino()));
        // F_GETPATH returns the resolved path (e.g. /tmp → /private/tmp).
        assert_eq!(ws.root, std::fs::canonicalize(&root).unwrap());
        assert!(ws.contains_claimed_pwd(""));
        assert!(ws.contains_claimed_pwd(ws.root.join("sub").to_str().unwrap()));
        assert!(!ws.contains_claimed_pwd("/somewhere/else"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn get_cwd_matches_own_process_cwd() {
        let pid = std::process::id() as i32;
        let kernel = proc_info::get_cwd(pid).expect("own cwd");
        let expected = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(kernel, expected);
    }

    // --- known_hosts display resolution ---

    #[test]
    fn known_hosts_lookup_matches_key_blob_and_skips_hashed() {
        use base64::Engine as _;
        use ssh_agent_lib::ssh_encoding::Encode;
        let host = test_hostkey();
        let mut wire = Vec::new();
        host.public_key().key_data().encode(&mut wire).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let content = format!(
            "# comment line\n\
             |1|hashhash|morehash ssh-ed25519 {b64}\n\
             other.example ssh-ed25519 AAAAnotthekey\n\
             github.com,gh.alias ssh-ed25519 {b64}\n"
        );
        assert_eq!(
            known_hosts_name_in(&content, &wire).as_deref(),
            Some("github.com")
        );
        assert_eq!(known_hosts_name_in("", &wire), None);
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

    // --- is_ssh_client_path tests ---

    #[test]
    fn test_is_ssh_client_path_matches_basename_only() {
        assert!(is_ssh_client_path("/usr/bin/ssh"));
        assert!(is_ssh_client_path("/opt/homebrew/bin/ssh"));
        assert!(is_ssh_client_path("ssh"));
        assert!(!is_ssh_client_path("/usr/sbin/sshd"));
        assert!(!is_ssh_client_path("/usr/bin/ssh-agent"));
        assert!(!is_ssh_client_path("/usr/bin/ssh-add"));
        assert!(!is_ssh_client_path("/Users/x/notssh"));
        assert!(!is_ssh_client_path(""));
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
