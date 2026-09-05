//! Kernel-derived peer identity, activity scopes, and verified destination bindings.

use std::path::PathBuf;

use ssh_agent_lib::proto::extension::SessionBind;
use ssh_key::public::KeyData;

use super::super::audit::AgentAuditContext;
use super::{fingerprint_str, reuse_ttl_label, sanitize_prompt, VtSshSession};
use crate::core::authorization::{GrantScope, Operation, ScopeFamily, SubjectId};
use crate::core::{ContextBasis, SALT_LEN};

mod paths;
mod process;

use paths::{find_git_root, is_ssh_client_path, workspace_root_acceptable};

fn cwd_fallback_acceptable(cwd: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    paths::cwd_root_acceptable(cwd, home) && !darwin_user_temp_dir().is_some_and(|t| cwd == t)
}

pub(super) struct PeerIdentity {
    pub(super) peer_pid: Option<i32>,
    pub(super) peer_exe: Option<String>,
    pub(super) peer_is_vt_relay: bool,
    pub(super) peer_is_ssh_client: bool,
    pub(super) connection_subject: Option<SubjectId>,
}

impl PeerIdentity {
    pub(super) fn from_socket(socket: &tokio::net::UnixStream) -> Self {
        let peer_pid = process::get_peer_pid(socket);
        if let Some(pid) = peer_pid {
            tracing::debug!("New session from PID {}", pid);
        }
        // One kernel-argv fetch per connection, shared by the scope
        // classification and the prompt origin marker so they can never
        // classify the peer differently.
        let peer_is_vt_relay = peer_pid
            .and_then(process::get_proc_argv)
            .map(|argv| crate::ssh_sign::is_vt_relay_invocation(&argv))
            .unwrap_or(false);
        let peer_path = peer_pid.and_then(process::get_proc_path);
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
            peer_pid.and_then(|pid| process::get_start_tvsec(pid).map(|start| (pid as u64, start)))
        } else {
            None
        };
        Self {
            peer_pid,
            peer_exe,
            peer_is_vt_relay,
            peer_is_ssh_client,
            connection_subject,
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
pub(super) struct Workspace {
    subject: SubjectId,
    /// Stored as `String` because it is only ever built from validated UTF-8
    /// and feeds the grant digest — a lossy conversion fallback here would
    /// silently bind an empty root path.
    root: String,
}

impl Workspace {
    fn root_str(&self) -> &str {
        &self.root
    }

    /// Client-reported `pwd` is display metadata, but if it is present and
    /// does not lie inside this workspace the request degrades to Fresh — a
    /// consistency check against confused callers, not a security boundary.
    fn contains_claimed_pwd(&self, pwd: &str) -> bool {
        pwd.is_empty() || std::path::Path::new(pwd).starts_with(std::path::Path::new(&self.root))
    }
}

/// The caller's kernel-derived parent process, used as the activity identity
/// when the caller's cwd is a broad shared directory: "this application
/// instance keeps making the same request" (e.g. an app probing `gh` through
/// the hook from cwd `/`). `subject` is the parent's `(pid, start_tvsec)`,
/// so grants die when the app exits; `exe` is the parent's kernel-verified
/// executable path (`proc_pidpath`), bound into the digest — never the
/// client-claimed `ppid_cmd` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AppIdentity {
    subject: SubjectId,
    exe: String,
}

impl AppIdentity {
    /// Display name: executable basename (the digest uses the full path).
    fn name(&self) -> &str {
        self.exe.rsplit('/').next().unwrap_or(&self.exe)
    }
}

/// The scope basis a resolved connection routes to. The three arms use
/// distinct digest domains, so a directory that gains or loses a `.git`
/// entry — or an app that later runs from a repository — starts a new grant
/// family instead of silently continuing the old grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopedBasis<'a> {
    Git(&'a Workspace),
    Cwd(&'a Workspace),
    App(&'a AppIdentity),
}

/// How the connection's workspace resolution ended, kept for diag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkspaceResolution {
    /// Nearest `.git` ancestor of the kernel cwd.
    Resolved(Workspace),
    /// No usable `.git` ancestor: the kernel cwd directory itself, provided
    /// it is not a broad shared bucket (see `cwd_fallback_acceptable`).
    CwdFallback(Workspace),
    /// Cwd is a broad shared bucket ($HOME, `/`, temp roots): the caller's
    /// kernel-derived parent application.
    AppFallback(AppIdentity),
    /// Cwd too broad to scope AND no usable parent process (parent is
    /// launchd / lookup failed): Fresh.
    NoRoot,
    /// No peer pid or proc/cwd lookup failed (also used for relay peers,
    /// which never use workspace scopes).
    Unavailable,
}

impl WorkspaceResolution {
    fn scoped(&self) -> Option<ScopedBasis<'_>> {
        match self {
            WorkspaceResolution::Resolved(ws) => Some(ScopedBasis::Git(ws)),
            WorkspaceResolution::CwdFallback(ws) => Some(ScopedBasis::Cwd(ws)),
            WorkspaceResolution::AppFallback(app) => Some(ScopedBasis::App(app)),
            _ => None,
        }
    }
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
        let path = process::nul_terminated_path(&buf)?;
        Some(Workspace {
            subject: (st.st_dev as u64, st.st_ino),
            root: path.to_str()?.to_string(),
        })
    })();
    unsafe { libc::close(fd) };
    result
}

/// The per-user Darwin temp root (`confstr(_CS_DARWIN_USER_TEMP_DIR)`),
/// canonicalized and cached. Queried from the OS, never from a peer's
/// `$TMPDIR`. `None` when the query fails.
fn darwin_user_temp_dir() -> Option<&'static PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let len = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if len == 0 || len > buf.len() {
            return None;
        }
        let path = process::nul_terminated_path(&buf)?;
        // Canonicalize so it compares against F_GETPATH-derived paths.
        std::fs::canonicalize(path).ok()
    })
    .as_ref()
}

/// The peer's parent process as an activity identity. `None` when the parent
/// is launchd/init (`ppid <= 1` — a daemon orphan or a peer whose parent
/// already exited; scoping to launchd would pool every daemon on the box)
/// or when a kernel lookup fails.
fn parent_app_identity(peer_pid: i32) -> Option<AppIdentity> {
    let (ppid, _, _) = process::get_proc_bsdinfo(peer_pid)?;
    let ppid = i32::try_from(ppid).ok()?;
    if ppid <= 1 {
        return None;
    }
    let start = process::get_start_tvsec(ppid)?;
    let exe = process::get_proc_path(ppid)?;
    Some(AppIdentity {
        subject: (ppid as u64, start),
        exe,
    })
}

/// Resolve the peer's workspace once per connection (vt CLI connections are
/// per-command; a process cwd does not change mid-connection in practice).
/// Preference order: nearest acceptable `.git` root, else the cwd directory
/// itself, else the parent application (each a distinct grant family), else
/// Fresh.
fn resolve_workspace(peer_pid: Option<i32>) -> WorkspaceResolution {
    let Some(pid) = peer_pid else {
        return WorkspaceResolution::Unavailable;
    };
    let Some(cwd) = process::get_cwd(pid) else {
        return WorkspaceResolution::Unavailable;
    };
    let home = dirs::home_dir();
    if let Some(root) = find_git_root(&cwd) {
        if workspace_root_acceptable(&root, &cwd, home.as_deref()) {
            return match workspace_identity(&root) {
                Some(ws) => WorkspaceResolution::Resolved(ws),
                None => WorkspaceResolution::Unavailable,
            };
        }
    }
    // No usable git root: fall back to the cwd itself. Acceptability is
    // checked on the fd-derived canonical path, so /tmp aliases and symlinked
    // cwds cannot dodge the shared-root exclusions.
    let Some(ws) = workspace_identity(&cwd) else {
        return WorkspaceResolution::Unavailable;
    };
    if cwd_fallback_acceptable(std::path::Path::new(ws.root_str()), home.as_deref()) {
        return WorkspaceResolution::CwdFallback(ws);
    }
    // Broad shared cwd (daemons launch from `/`, terminals from `$HOME`):
    // identify the activity by the calling application instead.
    match parent_app_identity(pid) {
        Some(app) => WorkspaceResolution::AppFallback(app),
        None => WorkspaceResolution::NoRoot,
    }
}

// --- session-bind@openssh.com state machine -----------------------------------

/// Local cap on recorded session ids per connection — a DoS defense (bounded
/// memory), not a claimed protocol contract.
const MAX_SESSION_BINDS: usize = 16;

/// Destination binding state of one agent connection, driven by verified
/// `session-bind@openssh.com` messages (OpenSSH ≥ 8.9 sends one per hop).
/// See docs/authorization-scopes-v2.md §3.2.
#[derive(Debug)]
pub(super) enum BindState {
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
    pub(super) fn destination(&self) -> Option<(&[u8], &KeyData)> {
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
    pub(super) fn apply(&mut self, bind: &SessionBind) -> std::result::Result<(), ()> {
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

/// Best-effort display name for a bound destination: scan plain-name
/// `~/.ssh/known_hosts` entries (via ssh-key's parser) for `hostkey` and
/// return the first host name. Cosmetic only — the grant is keyed on the
/// host key bytes, never on this name.
fn known_hosts_name(hostkey: &KeyData) -> Option<String> {
    let path = dirs::home_dir()?.join(".ssh").join("known_hosts");
    let content = std::fs::read_to_string(path).ok()?;
    known_hosts_name_in(&content, hostkey)
}

/// Human label for a destination-bound sign grant: known_hosts name when
/// resolvable, always the host key fingerprint. Display-only.
pub(super) fn destination_label(hostkey: &KeyData) -> String {
    match known_hosts_name(hostkey) {
        Some(name) => format!("{} ({})", name, fingerprint_str(hostkey)),
        None => fingerprint_str(hostkey),
    }
}

/// Sign scope for a resolved basis — one place holds the basis→family
/// mapping shared by the raw-sign and `sign@vt` arms.
fn sign_scope_for_basis(basis: ScopedBasis<'_>, fingerprint: &str) -> GrantScope {
    match basis {
        ScopedBasis::Git(ws) => GrantScope::sign_workspace(ws.subject, ws.root_str(), fingerprint),
        ScopedBasis::Cwd(ws) => GrantScope::sign_cwd(ws.subject, ws.root_str(), fingerprint),
        ScopedBasis::App(app) => GrantScope::sign_app(app.subject, &app.exe, fingerprint),
    }
}

/// Decrypt scope for a resolved basis, per `(type, salt)` record.
fn decrypt_scope_for_basis(basis: ScopedBasis<'_>, secret_type: u8, salt: &[u8]) -> GrantScope {
    match basis {
        ScopedBasis::Git(ws) => {
            GrantScope::decrypt_workspace(ws.subject, ws.root_str(), secret_type, salt)
        }
        ScopedBasis::Cwd(ws) => {
            GrantScope::decrypt_cwd(ws.subject, ws.root_str(), secret_type, salt)
        }
        ScopedBasis::App(app) => GrantScope::decrypt_app(app.subject, &app.exe, secret_type, salt),
    }
}

/// Contract a `$HOME` prefix to `~` for prompt display. Display-only —
/// grants and digests always bind the canonical absolute path.
fn contract_home(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home.as_ref()) {
            if rest.is_empty() {
                return "~".to_string();
            }
            if rest.starts_with('/') {
                return format!("~{}", rest);
            }
        }
    }
    path.to_string()
}

/// Human label for a reuse line. The wording distinguishes the scope
/// families so the prompt states exactly what the approval covers: the
/// workspace root is the common case and stays unmarked (a bare,
/// home-contracted path always means "the whole repository"), while the
/// narrower fallback families keep an explicit prefix so "this exact
/// directory" / "this app" can never read as a repository scope.
fn scoped_label(basis: ScopedBasis<'_>) -> String {
    match basis {
        ScopedBasis::Git(ws) => contract_home(ws.root_str()),
        ScopedBasis::Cwd(ws) => format!("directory {}", contract_home(ws.root_str())),
        ScopedBasis::App(app) => format!("app {}", app.name()),
    }
}

/// Append the §6 prompt transparency line: present exactly when an approval
/// can create a reusable grant. The label is agent-derived (kernel workspace
/// path / verified host key) but sanitized like every other prompt field.
pub(super) fn append_reuse_line(message: &mut String, label: &Option<String>, ttl_secs: u64) {
    if let Some(label) = label {
        message.push_str("\nreuse: ");
        message.push_str(&sanitize_prompt(label, 160));
        message.push_str(" · ");
        message.push_str(&reuse_ttl_label(ttl_secs));
    }
}

fn known_hosts_name_in(content: &str, hostkey: &KeyData) -> Option<String> {
    use ssh_key::known_hosts::{HostPatterns, KnownHosts};
    KnownHosts::new(content)
        .filter_map(std::result::Result::ok)
        // @revoked / @cert-authority entries do not name a host's own key.
        .filter(|entry| entry.marker().is_none())
        .filter(|entry| entry.public_key().key_data() == hostkey)
        // Hashed (`|1|…`) entries are irreversible: skip them and keep
        // looking for a plain-name entry of the same key.
        .find_map(|entry| match entry.host_patterns() {
            HostPatterns::Patterns(patterns) => patterns.first().cloned(),
            HostPatterns::HashedName { .. } => None,
        })
}

impl VtSshSession {
    pub(super) fn peer_has_tty(&self) -> bool {
        self.peer_pid
            .is_some_and(|pid| process::get_tty_dev(pid).is_some())
    }

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
    pub(super) fn append_relay_origin(&self, message: &mut String) {
        if self.peer_is_vt_relay {
            message.push_str("\nvia forwarded vt relay");
        }
    }

    /// Append the kernel-verified caller line. Unlike the client-reported
    /// `via:` (`meta.ppid_cmd`), `peer_exe` comes from `proc_pidpath` on the
    /// socket peer and cannot be forged by the request body — but the
    /// basename is still attacker-chosen (a local process names its own
    /// binary), so it is sanitized like every other prompt field. Placed with
    /// the agent-derived truth lines, before the client-reported body/meta.
    ///
    /// Exception display: the overwhelmingly common caller is the vt CLI
    /// itself, so `caller: vt` carries no information and is suppressed —
    /// the line appears only for other basenames (`ssh -A` forwarded
    /// traffic, `ssh-keygen`, renamed binaries). Suppressing on the name
    /// hides nothing a rename could not already hide: the line is display
    /// signal, not a boundary. Audit rows keep `peer_exe` unconditionally.
    pub(super) fn append_caller_line(&self, message: &mut String) {
        if let Some(exe) = self.peer_exe.as_deref() {
            if !exe.is_empty() && exe != "vt" {
                message.push_str("\ncaller: ");
                message.push_str(&sanitize_prompt(exe, 80));
            }
        }
    }

    /// Append the raw-sign destination truth line from the session-bind
    /// state (docs/approval-transparency.md §A1). `reuse_names_destination`
    /// is true when the reuse line already carries the destination label (a
    /// destination-reusable scope — the only reusable arm a bound non-relay
    /// peer can reach), in which case the plain line would be a duplicate. A
    /// forwarding-capable bind is always flagged: the signed request may
    /// originate beyond hop one. A tainted bind failed verification outright.
    pub(super) fn append_destination_line(
        &self,
        message: &mut String,
        reuse_names_destination: bool,
    ) {
        match &self.bind_state {
            BindState::Bound {
                forwarding: false,
                hostkey,
                ..
            } => {
                if !reuse_names_destination {
                    let label = self
                        .destination_label
                        .clone()
                        .unwrap_or_else(|| destination_label(hostkey));
                    message.push_str("\ndest: ");
                    message.push_str(&sanitize_prompt(&label, 160));
                }
            }
            BindState::Bound {
                forwarding: true,
                hostkey,
                ..
            } => {
                let label = self
                    .destination_label
                    .clone()
                    .unwrap_or_else(|| destination_label(hostkey));
                message.push_str("\ndest: ");
                message.push_str(&sanitize_prompt(&label, 160));
                message.push_str(" (forwarding — may serve a relayed request)");
            }
            BindState::Tainted => {
                message.push_str("\nwarning: session-bind verification failed");
            }
            BindState::Unbound => {}
        }
    }

    /// The verified destination for audit rows: the bound, non-forwarding
    /// session-bind label; empty otherwise. Mirrors `append_destination_line`
    /// but never reports a forwarding-capable or tainted bind as a
    /// destination.
    pub(super) fn audit_destination(&self) -> String {
        match &self.bind_state {
            BindState::Bound {
                forwarding: false,
                hostkey,
                ..
            } => self
                .destination_label
                .clone()
                .unwrap_or_else(|| destination_label(hostkey)),
            _ => String::new(),
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

    /// Lazy once-per-connection workspace resolution (see the field doc).
    /// Confined connections never resolve one.
    fn workspace_resolution(&self) -> &WorkspaceResolution {
        self.workspace.get_or_init(|| {
            if self.confined_to_connection() {
                WorkspaceResolution::Unavailable
            } else {
                resolve_workspace(self.peer_pid)
            }
        })
    }

    /// The scope basis, with the §4 consistency check applied to the
    /// directory-shaped arms: a claimed `pwd` outside the git/cwd root
    /// degrades to Fresh. The app arm carries no root to check against —
    /// its claimed pwd stays display-only, like the connection arms.
    fn reusable_scope(&self, claimed_pwd: &str) -> Option<ScopedBasis<'_>> {
        self.workspace_resolution()
            .scoped()
            .filter(|basis| match basis {
                ScopedBasis::Git(ws) | ScopedBasis::Cwd(ws) => ws.contains_claimed_pwd(claimed_pwd),
                ScopedBasis::App(_) => true,
            })
    }

    /// Scope for a raw `SIGN_REQUEST`.
    pub(super) fn raw_sign_scope(&self, fingerprint: &str) -> (GrantScope, Option<String>) {
        if self.cache_ttls.sign_secs == 0 {
            return (GrantScope::fresh(Operation::Sign), None);
        }
        if self.peer_is_vt_relay {
            return (
                GrantScope::sign(self.connection_subject, fingerprint, ""),
                self.connection_label(),
            );
        }
        match &self.bind_state {
            BindState::Bound {
                hostkey_wire,
                hostkey,
                forwarding: false,
                ..
            } => (
                GrantScope::sign_destination(hostkey_wire, fingerprint),
                // Precomputed at bind time; the on-demand fallback is
                // unreachable in production (extension() sets the label on
                // every successful bind) but keeps the reuse line
                // self-contained for direct-construction tests.
                self.destination_label
                    .clone()
                    .or_else(|| Some(destination_label(hostkey))),
            ),
            // Forwarding-capable: traffic may originate beyond hop one.
            BindState::Bound { .. } | BindState::Tainted => {
                (GrantScope::fresh(Operation::Sign), None)
            }
            // No bind and the peer is ssh: authentication and forwarding are
            // indistinguishable — Fresh.
            BindState::Unbound if self.peer_is_ssh_client => {
                (GrantScope::fresh(Operation::Sign), None)
            }
            // No bind, non-ssh local caller (ssh-keygen -Y sign etc.):
            // workspace / cwd / parent-app scope.
            BindState::Unbound => match self.workspace_resolution().scoped() {
                Some(basis) => (
                    sign_scope_for_basis(basis, fingerprint),
                    Some(scoped_label(basis)),
                ),
                None => (GrantScope::fresh(Operation::Sign), None),
            },
        }
    }

    /// Scope for `sign@vt` (local vt ⇒ workspace, relay/ssh ⇒ per-connection).
    pub(super) fn sign_vt_scope(
        &self,
        fingerprint: &str,
        claimed_pwd: &str,
    ) -> (GrantScope, Option<String>) {
        if self.cache_ttls.sign_secs == 0 {
            return (GrantScope::fresh(Operation::Sign), None);
        }
        if self.confined_to_connection() {
            return (
                GrantScope::sign(self.connection_subject, fingerprint, claimed_pwd),
                self.connection_label(),
            );
        }
        match self.reusable_scope(claimed_pwd) {
            Some(basis) => (
                sign_scope_for_basis(basis, fingerprint),
                Some(scoped_label(basis)),
            ),
            None => (GrantScope::fresh(Operation::Sign), None),
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
    pub(super) fn sign_basis(&self) -> ContextBasis {
        if self.cache_ttls.sign_secs == 0 {
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
    pub(super) fn decrypt_basis(&self) -> ContextBasis {
        if self.cache_ttls.decrypt_secs == 0 {
            return ContextBasis::Disabled;
        }
        if self.confined_to_connection() {
            return self.connection_basis();
        }
        self.workspace_basis()
    }

    fn workspace_basis(&self) -> ContextBasis {
        match self.workspace_resolution() {
            WorkspaceResolution::Resolved(_) => ContextBasis::Workspace,
            WorkspaceResolution::CwdFallback(_) => ContextBasis::CwdWorkspace,
            WorkspaceResolution::AppFallback(_) => ContextBasis::ParentApp,
            WorkspaceResolution::NoRoot => ContextBasis::NoWorkspaceRoot,
            WorkspaceResolution::Unavailable => match self.peer_pid {
                None => ContextBasis::NoPeerPid,
                Some(_) => ContextBasis::ProcLookupFailed,
            },
        }
    }

    /// Grants this connection's own classification could reuse — the single
    /// basis→(family, subject) mapping behind both diag counts. The family
    /// filter matters when a directory gains or loses a `.git` entry: the
    /// workspace and cwd families then share a `(dev, ino)` subject, and a
    /// caller must not count the other family's grants. `decrypt_basis`
    /// never yields `SessionBind`, so one shared mapping is safe.
    pub(super) async fn live_grants(&self, basis: ContextBasis, operation: Operation) -> usize {
        let scoped = match basis {
            ContextBasis::SessionBind => Some((
                ScopeFamily::Destination,
                crate::core::authorization::DESTINATION_SUBJECT,
            )),
            ContextBasis::Workspace | ContextBasis::CwdWorkspace | ContextBasis::ParentApp => self
                .workspace_resolution()
                .scoped()
                .map(|basis| match basis {
                    ScopedBasis::Git(ws) => (ScopeFamily::Workspace, ws.subject),
                    ScopedBasis::Cwd(ws) => (ScopeFamily::CwdFallback, ws.subject),
                    ScopedBasis::App(app) => (ScopeFamily::ParentApp, app.subject),
                }),
            ContextBasis::RelayConnection | ContextBasis::SshConnection => self
                .connection_subject
                .map(|subject| (ScopeFamily::Connection, subject)),
            _ => None,
        };
        match scoped {
            Some((family, subject)) => {
                self.authorization
                    .live_len(operation, family, subject)
                    .await
            }
            None => 0,
        }
    }

    /// Scopes for a pure-v2 decrypt batch (one per `(type, salt)` record).
    pub(super) fn decrypt_scopes(
        &self,
        v2_inputs: &[(crate::core::SecretType, [u8; SALT_LEN])],
        claimed_host: &str,
        claimed_pwd: &str,
    ) -> (Vec<GrantScope>, Option<String>) {
        let fresh = || vec![GrantScope::fresh(Operation::Decrypt)];
        if self.cache_ttls.decrypt_secs == 0 {
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
        match self.reusable_scope(claimed_pwd) {
            Some(basis) => (
                v2_inputs
                    .iter()
                    .map(|(t, salt)| decrypt_scope_for_basis(basis, t.as_byte(), salt))
                    .collect(),
                Some(scoped_label(basis)),
            ),
            None => (fresh(), None),
        }
    }

    /// Agent-derived audit context shared by every row: kernel peer identity
    /// and relay provenance. Operation-specific fields (key, destination,
    /// scope) start empty — see `audit_ctx_scoped` and the sign handlers.
    pub(super) fn audit_ctx(&self) -> AgentAuditContext {
        AgentAuditContext {
            peer_exe: self.peer_exe.clone().unwrap_or_default(),
            relayed: self.peer_is_vt_relay,
            ..AgentAuditContext::default()
        }
    }

    /// Audit context for an operation that can mint (or hit) a reusable
    /// grant: records the scope family, the exact label the prompt's reuse
    /// line displayed, and the effective TTL. `family` and `label` are `Some`
    /// together by construction (both derive from the same scope helper); a
    /// Fresh request leaves all three fields empty/zero.
    pub(super) fn audit_ctx_scoped(
        &self,
        family: Option<ScopeFamily>,
        label: &Option<String>,
        ttl_secs: u64,
    ) -> AgentAuditContext {
        let mut ctx = self.audit_ctx();
        if let (Some(family), Some(label)) = (family, label.as_deref()) {
            ctx.scope_family = family.as_wire().to_string();
            ctx.scope_label = label.to_string();
            ctx.grant_ttl_s = ttl_secs;
        }
        ctx
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{test_bind, test_hostkey, test_session};
    use super::*;

    fn test_workspace() -> Workspace {
        Workspace {
            subject: (7, 42),
            root: "/repo".to_string(),
        }
    }

    #[test]
    fn bind_state_valid_bind_exposes_destination() {
        let host = test_hostkey();
        let mut state = BindState::Unbound;
        assert!(state.apply(&test_bind(&host, b"sid-1", false)).is_ok());
        let (wire, key) = state.destination().expect("destination-bound");
        assert!(!wire.is_empty());
        assert_eq!(
            fingerprint_str(key),
            fingerprint_str(host.public_key().key_data())
        );
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
            assert!(state
                .apply(&test_bind(&host, sid.as_bytes(), false))
                .is_ok());
        }
        // The excess bind is refused but the established binding survives.
        assert!(state
            .apply(&test_bind(&host, b"sid-overflow", false))
            .is_err());
        assert!(state.destination().is_some());
    }

    #[test]
    fn destination_line_shown_when_bound_and_fresh() {
        // docs/approval-transparency.md §A1: with the default TTL of 0 the
        // reuse line never appears, so the verified destination must get its
        // own truth line.
        let mut s = test_session(0, 0);
        s.peer_is_ssh_client = true;
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", false))
            .unwrap();
        let mut msg = String::from("sign: k");
        s.append_destination_line(&mut msg, false);
        assert!(msg.contains("\ndest: SHA256:"), "missing dest line: {msg}");
        assert!(
            !msg.contains("forwarding"),
            "non-forwarding bind flagged: {msg}"
        );
    }

    #[test]
    fn destination_line_skipped_when_reuse_line_names_it() {
        let mut s = test_session(300, 0);
        s.peer_is_ssh_client = true;
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", false))
            .unwrap();
        let (_, reuse_label) = s.raw_sign_scope("fp");
        assert!(
            reuse_label.is_some(),
            "bound non-forwarding peer must be reusable"
        );
        let mut msg = String::from("sign: k");
        s.append_destination_line(&mut msg, reuse_label.is_some());
        assert_eq!(
            msg, "sign: k",
            "dest line must not duplicate the reuse label: {msg}"
        );
    }

    #[test]
    fn destination_line_flags_forwarding_and_taint() {
        // Forwarding-capable bind: destination shown WITH the forwarding flag.
        let mut s = test_session(0, 0);
        s.peer_is_ssh_client = true;
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", true))
            .unwrap();
        let mut msg = String::new();
        s.append_destination_line(&mut msg, false);
        assert!(
            msg.contains("\ndest: SHA256:"),
            "forwarding bind must still name hop one: {msg}"
        );
        assert!(
            msg.contains("(forwarding"),
            "missing forwarding flag: {msg}"
        );
        // Tainted bind: explicit warning, no destination claim.
        let mut s = test_session(0, 0);
        s.bind_state = BindState::Tainted;
        let mut msg = String::new();
        s.append_destination_line(&mut msg, false);
        assert_eq!(msg, "\nwarning: session-bind verification failed");
        // Unbound: nothing.
        let s = test_session(0, 0);
        let mut msg = String::new();
        s.append_destination_line(&mut msg, false);
        assert!(msg.is_empty());
    }

    #[test]
    fn caller_line_is_kernel_exe_and_sanitized() {
        let mut s = test_session(0, 0);
        s.peer_exe = Some("git\nremote".to_string());
        let mut msg = String::from("h");
        s.append_caller_line(&mut msg);
        assert!(msg.starts_with("h\ncaller: "), "missing caller line: {msg}");
        // The control character must not survive to inject a fake line.
        assert_eq!(
            msg.matches('\n').count(),
            1,
            "unsanitized caller exe: {msg}"
        );
        // Unknown peer exe → no line.
        let mut s = test_session(0, 0);
        s.peer_exe = None;
        let mut msg = String::from("h");
        s.append_caller_line(&mut msg);
        assert_eq!(msg, "h");
        // The vt CLI itself is the no-information common case → suppressed
        // (exception display; audit still records peer_exe unconditionally).
        let mut s = test_session(0, 0);
        s.peer_exe = Some("vt".to_string());
        let mut msg = String::from("h");
        s.append_caller_line(&mut msg);
        assert_eq!(msg, "h");
    }

    #[test]
    fn contract_home_display_only() {
        let home = dirs::home_dir()
            .expect("home")
            .to_string_lossy()
            .into_owned();
        assert_eq!(contract_home(&format!("{home}/code/vt")), "~/code/vt");
        assert_eq!(contract_home(&home), "~");
        // A sibling path sharing the prefix without a separator must NOT
        // contract (e.g. /Users/qiqi2 vs /Users/qiqi).
        assert_eq!(contract_home(&format!("{home}2/x")), format!("{home}2/x"));
        assert_eq!(contract_home("/repo"), "/repo");
    }

    #[test]
    fn audit_ctx_reports_scope_and_destination() {
        // Workspace-scoped sign: family/label/ttl populated.
        let mut s = test_session(300, 0);
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
        let (scope, label) = s.sign_vt_scope("fp", "/repo/sub");
        let ctx = s.audit_ctx_scoped(scope.family(), &label, 300);
        assert_eq!(ctx.scope_family, "workspace");
        assert_eq!(ctx.scope_label, "/repo");
        assert_eq!(ctx.grant_ttl_s, 300);
        assert_eq!(ctx.peer_exe, "test");
        assert!(!ctx.relayed);
        // Fresh (ttl 0): scope fields stay empty even though a basis exists.
        let (scope, label) = test_session(0, 0).sign_vt_scope("fp", "");
        let ctx = s.audit_ctx_scoped(scope.family(), &label, 0);
        assert_eq!(ctx.scope_family, "");
        assert_eq!(ctx.scope_label, "");
        assert_eq!(ctx.grant_ttl_s, 0);
        // audit_destination: only a bound, non-forwarding session-bind counts.
        let mut s = test_session(0, 0);
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", false))
            .unwrap();
        assert!(s.audit_destination().starts_with("SHA256:"));
        let mut s = test_session(0, 0);
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", true))
            .unwrap();
        assert_eq!(s.audit_destination(), "");
        assert_eq!(test_session(0, 0).audit_destination(), "");
    }

    #[test]
    fn reuse_label_present_iff_scope_reusable() {
        // §6 transparency invariant: the prompt reuse line exists exactly
        // when the approval can create a standing grant — across every
        // classification arm.
        let inputs = vec![(crate::core::SecretType::RAW, [9u8; SALT_LEN])];
        let mut sessions = Vec::new();
        // workspace-resolved local caller
        let mut s = test_session(300, 300);
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
        sessions.push(s);
        // destination-bound ssh caller
        let mut s = test_session(300, 300);
        s.peer_is_ssh_client = true;
        s.bind_state
            .apply(&test_bind(&test_hostkey(), b"sid", false))
            .unwrap();
        sessions.push(s);
        // confined relay caller
        let mut s = test_session(300, 300);
        s.peer_is_vt_relay = true;
        s.connection_subject = Some((123, 456));
        sessions.push(s);
        // disabled + no-workspace-root callers
        sessions.push(test_session(0, 0));
        sessions.push(test_session(300, 300));

        for s in &sessions {
            for pwd in ["", "/repo/sub", "/elsewhere"] {
                let (scope, label) = s.sign_vt_scope("fp", pwd);
                assert_eq!(scope.is_reusable(), label.is_some());
                let (scope, label) = s.raw_sign_scope("fp");
                assert_eq!(scope.is_reusable(), label.is_some());
                let (scopes, label) = s.decrypt_scopes(&inputs, "h", pwd);
                assert_eq!(scopes.iter().all(GrantScope::is_reusable), label.is_some());
            }
        }
    }

    #[test]
    fn raw_sign_scope_classification() {
        // Duration 0: Fresh, no reuse line, regardless of state.
        let mut s = test_session(0, 0);
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::Disabled);

        // Unbound ssh peer: Fresh (auth vs forwarding indistinguishable).
        let mut s = test_session(300, 0);
        s.peer_is_ssh_client = true;
        assert!(s.raw_sign_scope("fp").1.is_none());
        assert_eq!(s.sign_basis(), ContextBasis::UnboundSsh);

        // Unbound non-ssh with a workspace: workspace scope + label (bare
        // path = workspace root; narrower families keep their prefix).
        let mut s = test_session(300, 0);
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
        let (_, label) = s.raw_sign_scope("fp");
        assert_eq!(label.as_deref(), Some("/repo"));
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
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
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
        s.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
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

    #[test]
    fn cwd_fallback_rejects_broad_shared_directories() {
        let home = std::path::Path::new("/Users/x");
        let p = std::path::Path::new;
        // $HOME and its ancestors pool everything launched from them.
        assert!(!cwd_fallback_acceptable(home, Some(home)));
        assert!(!cwd_fallback_acceptable(p("/Users"), Some(home)));
        assert!(!cwd_fallback_acceptable(p("/"), Some(home)));
        // Shared temp roots (canonical forms — F_GETPATH resolves /tmp).
        assert!(!cwd_fallback_acceptable(p("/private/tmp"), Some(home)));
        assert!(!cwd_fallback_acceptable(p("/private/var/tmp"), Some(home)));
        assert!(!cwd_fallback_acceptable(p("/Volumes"), Some(home)));
        if let Some(t) = darwin_user_temp_dir() {
            assert!(!cwd_fallback_acceptable(t, Some(home)));
        }
        // Subdirectories of the shared roots name one activity: acceptable.
        assert!(cwd_fallback_acceptable(
            p("/private/tmp/scratch"),
            Some(home)
        ));
        assert!(cwd_fallback_acceptable(p("/Users/x/notes"), Some(home)));
        assert!(cwd_fallback_acceptable(p("/opt/deploy"), Some(home)));
    }

    #[test]
    fn resolve_workspace_falls_back_to_cwd_without_git_root() {
        // End-to-end through the kernel-cwd path: a peer whose cwd has no
        // `.git` ancestor lands in the cwd-fallback arm keyed on the
        // canonical cwd; the same directory flips to the git family once a
        // `.git` marker appears (grant separation between the two families
        // is pinned at the digest level by scope_families_are_domain_separated).
        let dir = temp_workspace("cwd-fallback");
        let canonical = std::fs::canonicalize(&dir).unwrap();
        if find_git_root(&canonical).is_some() {
            // Defensive: a `.git` above the temp dir would invalidate the
            // scenario; skip rather than assert a wrong arm.
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .current_dir(&dir)
            .spawn()
            .expect("spawn peer stand-in");
        let pid = child.id() as i32;

        match resolve_workspace(Some(pid)) {
            WorkspaceResolution::CwdFallback(ws) => {
                assert_eq!(PathBuf::from(ws.root_str()), canonical);
            }
            other => panic!("expected cwd fallback, got {other:?}"),
        }
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        match resolve_workspace(Some(pid)) {
            WorkspaceResolution::Resolved(ws) => {
                assert_eq!(PathBuf::from(ws.root_str()), canonical);
            }
            other => panic!("expected git workspace after git init, got {other:?}"),
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cwd_fallback_scopes_use_directory_label_and_basis() {
        // sign@vt / decrypt: cwd fallback behaves like a workspace but with
        // the "directory" wording and the cwd-fallback basis.
        let mut s = test_session(300, 300);
        s.workspace = WorkspaceResolution::CwdFallback(test_workspace()).into();
        let (scope, label) = s.sign_vt_scope("fp", "/repo/sub");
        assert!(scope.is_reusable());
        assert_eq!(label.as_deref(), Some("directory /repo"));
        assert_eq!(s.decrypt_basis(), ContextBasis::CwdWorkspace);
        // pwd consistency check still applies.
        assert!(s.sign_vt_scope("fp", "/elsewhere").1.is_none());

        let inputs = vec![(crate::core::SecretType::RAW, [9u8; SALT_LEN])];
        assert_eq!(
            s.decrypt_scopes(&inputs, "h", "/repo").1.as_deref(),
            Some("directory /repo")
        );

        // Raw sign, unbound non-ssh peer: same fallback arm.
        let (scope, label) = s.raw_sign_scope("fp");
        assert!(scope.is_reusable());
        assert_eq!(label.as_deref(), Some("directory /repo"));
        assert_eq!(s.sign_basis(), ContextBasis::CwdWorkspace);

        // The cwd-fallback scope must differ from the git-workspace scope of
        // the same directory identity.
        let mut git = test_session(300, 300);
        git.workspace = WorkspaceResolution::Resolved(test_workspace()).into();
        assert_eq!(git.sign_vt_scope("fp", "/repo").1.as_deref(), Some("/repo"));
    }

    #[test]
    fn parent_app_identity_resolves_kernel_parent() {
        // A child we spawn has US as its kernel parent: identity must carry
        // this process's (pid, start) subject and executable path.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn child");
        let app = parent_app_identity(child.id() as i32).expect("parent identity");
        let me = std::process::id() as u64;
        assert_eq!(app.subject.0, me);
        assert_eq!(app.exe, process::get_proc_path(me as i32).expect("own exe"));
        assert!(!app.name().contains('/'));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn resolve_workspace_uses_parent_app_for_broad_cwd() {
        // A peer whose cwd is an excluded shared root (the per-user Darwin
        // temp dir) must resolve to its parent application, not NoRoot.
        let dir = std::env::temp_dir();
        let canonical = std::fs::canonicalize(&dir).unwrap();
        if find_git_root(&canonical).is_some()
            || cwd_fallback_acceptable(&canonical, dirs::home_dir().as_deref())
        {
            // Defensive: scenario requires an excluded, non-git cwd.
            return;
        }
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .current_dir(&dir)
            .spawn()
            .expect("spawn peer stand-in");
        match resolve_workspace(Some(child.id() as i32)) {
            WorkspaceResolution::AppFallback(app) => {
                assert_eq!(app.subject.0, std::process::id() as u64);
            }
            other => panic!("expected parent-app fallback, got {other:?}"),
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn parent_app_scopes_use_app_label_and_basis() {
        let app = AppIdentity {
            subject: (77, 4242),
            exe: "/Applications/Paseo.app/Contents/MacOS/Paseo Daemon".to_string(),
        };
        let mut s = test_session(300, 300);
        s.workspace = WorkspaceResolution::AppFallback(app).into();
        // sign@vt / decrypt: reusable, "app" wording, parent-app basis. The
        // claimed pwd is display-only in this arm (no root to check against).
        let (scope, label) = s.sign_vt_scope("fp", "/anywhere");
        assert!(scope.is_reusable());
        assert_eq!(label.as_deref(), Some("app Paseo Daemon"));
        assert_eq!(s.decrypt_basis(), ContextBasis::ParentApp);
        let inputs = vec![(crate::core::SecretType::RAW, [9u8; SALT_LEN])];
        assert_eq!(
            s.decrypt_scopes(&inputs, "h", "/").1.as_deref(),
            Some("app Paseo Daemon")
        );
        // Raw sign, unbound non-ssh peer: same fallback arm.
        let (scope, label) = s.raw_sign_scope("fp");
        assert!(scope.is_reusable());
        assert_eq!(label.as_deref(), Some("app Paseo Daemon"));
        assert_eq!(s.sign_basis(), ContextBasis::ParentApp);
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
        assert_eq!(
            PathBuf::from(&ws.root),
            std::fs::canonicalize(&root).unwrap()
        );
        assert!(ws.contains_claimed_pwd(""));
        assert!(ws.contains_claimed_pwd(&format!("{}/sub", ws.root)));
        assert!(!ws.contains_claimed_pwd("/somewhere/else"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn get_cwd_matches_own_process_cwd() {
        let pid = std::process::id() as i32;
        let kernel = process::get_cwd(pid).expect("own cwd");
        let expected = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(kernel, expected);
    }

    // --- known_hosts display resolution ---

    #[test]
    fn known_hosts_lookup_matches_key_and_skips_hashed_and_marked() {
        use base64::Engine as _;
        use ssh_agent_lib::ssh_encoding::Encode;
        let host = test_hostkey();
        let hostkey = host.public_key().key_data().clone();
        let mut wire = Vec::new();
        hostkey.encode(&mut wire).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let content = format!(
            "# comment line\n\
             |1|hashhash|morehash ssh-ed25519 {b64}\n\
             @revoked revoked.example ssh-ed25519 {b64}\n\
             github.com,gh.alias ssh-ed25519 {b64}\n"
        );
        assert_eq!(
            known_hosts_name_in(&content, &hostkey).as_deref(),
            Some("github.com")
        );
        assert_eq!(known_hosts_name_in("", &hostkey), None);
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
}
