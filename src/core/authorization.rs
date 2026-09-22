//! Shared authorization engine used by the macOS SSH-agent transport.
//!
//! The state machine is platform-neutral: callers inject the human authenticator
//! and the real-time session validator. A successful authorization returns a
//! non-cloneable [`AuthorizationPermit`]. Reusable grants are written only when
//! the protected operation succeeds and consumes the permit with `commit()`.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::{watch, OwnedRwLockReadGuard, OwnedSemaphorePermit, RwLock, Semaphore};
use zeroize::Zeroizing;

use super::session::{AuthOutcome, UnavailableReason};

/// Kernel-derived caller anchor: `(context_id, context_start_tvsec)`.
pub type SubjectId = (u64, u64);

/// Secret a grant releases again on a cache hit without the master: the
/// record DEK of a decrypt grant. Lives and dies with its grant, zeroized on
/// drop, never printed.
pub type GrantMaterial = Zeroizing<[u8; 32]>;

/// Security operation authorized by a grant. This discriminator is part of
/// every reusable key, so grants can never cross operation boundaries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    Auth,
    Run,
    Sign,
    Decrypt,
    Encrypt,
    /// SSH key store mutation over the agent protocol (`ssh-add`); always fresh.
    KeyStore,
}

impl Operation {
    /// Stable tag for `ui-status@vt` snapshots. One-way, never parsed back.
    pub fn as_wire(self) -> &'static str {
        match self {
            Operation::Auth => "auth",
            Operation::Run => "run",
            Operation::Sign => "sign",
            Operation::Decrypt => "decrypt",
            Operation::Encrypt => "encrypt",
            Operation::KeyStore => "keystore",
        }
    }

    /// Operations whose protected step needs the unwrapped master key. A
    /// platform authenticator opens its key-custody session only for these.
    pub fn needs_master(self) -> bool {
        !matches!(self, Operation::Auth | Operation::Run)
    }
}

/// Which scope family a grant belongs to. Redundant with the digest's domain
/// label for matching (the digest already separates families), but carried
/// explicitly so diag counting can filter by family: workspace and
/// cwd-fallback grants can share a `(dev, ino)` subject when a directory
/// gains or loses a `.git` entry, and a caller must never count the other
/// family's grants as reusable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScopeFamily {
    /// Per-connection confinement (relay / plain-ssh peers).
    Connection,
    /// Session-bind-verified destination host key.
    Destination,
    /// Kernel-derived `.git` workspace root.
    Workspace,
    /// No `.git` root: the kernel-derived cwd itself.
    CwdFallback,
    /// Broad shared cwd ($HOME, `/`, temp roots): the kernel-derived parent
    /// process (application) of the caller.
    ParentApp,
}

impl ScopeFamily {
    /// Stable tag for audit telemetry (docs/approval-transparency.md#presentation).
    /// One-way: never parsed back, so — unlike `ContextBasis` — no
    /// `from_wire` counterpart exists.
    pub fn as_wire(self) -> &'static str {
        match self {
            ScopeFamily::Connection => "connection",
            ScopeFamily::Destination => "destination",
            ScopeFamily::Workspace => "workspace",
            ScopeFamily::CwdFallback => "cwd-fallback",
            ScopeFamily::ParentApp => "parent-app",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct GrantKey {
    operation: Operation,
    family: ScopeFamily,
    subject: SubjectId,
    digest: [u8; 32],
}

/// One atomic authorization scope. A request may contain several scopes;
/// decrypt batches use one scope per v2 record and require an all-of hit.
#[derive(Clone, Debug)]
pub struct GrantScope {
    operation: Operation,
    key: Option<GrantKey>,
    /// Human label of the scoped resource (destination host, workspace root,
    /// parent app) — the same string the Touch ID reuse line shows. Never
    /// hashed; carried into the grant store for `ui-status@vt` snapshots and
    /// cache-hit notifications (docs/app-bundle.md#status-and-revoke-boundary). Memory-only.
    display: String,
}

/// Subject for destination-bound sign grants. They are deliberately
/// user-wide (any local caller could drive the real ssh to the same
/// destination anyway); the destination host key lives in the resource
/// digest. It cannot merge with a kernel `(pid, start_tvsec)` or workspace
/// `(dev, ino)` subject because every scope family uses a distinct digest
/// domain label — a subject collision alone never merges grants.
pub const DESTINATION_SUBJECT: SubjectId = (0, 0);

impl GrantScope {
    /// An explicitly non-reusable scope. `auth@vt`, `run@vt`, and callers
    /// without a resolvable subject use this constructor.
    pub fn fresh(operation: Operation) -> Self {
        Self {
            operation,
            key: None,
            display: String::new(),
        }
    }

    /// Attach the human scope label (the reuse-line string). Display-only:
    /// never part of the digest or the lookup key.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Relay sign scope: fingerprint + claimed working directory, bounded by
    /// the relay connection's kernel-derived `(pid, start_tvsec)` subject.
    pub fn sign(subject: Option<SubjectId>, fingerprint: &str, pwd: &str) -> Self {
        let Some(subject) = subject else {
            return Self::fresh(Operation::Sign);
        };
        Self::hashed(
            Operation::Sign,
            ScopeFamily::Connection,
            subject,
            b"vt-authorization-sign-v1",
            &[Field(fingerprint.as_bytes()), Field(pwd.as_bytes())],
        )
    }

    /// Destination-bound sign scope: the connection proved its destination
    /// with a verified `session-bind@openssh.com`. `hostkey_wire` must be the
    /// exact wire-encoded `KeyData` bytes of the destination host key —
    /// string fingerprints are display-only and never hashed here.
    pub fn sign_destination(hostkey_wire: &[u8], fingerprint: &str) -> Self {
        Self::hashed(
            Operation::Sign,
            ScopeFamily::Destination,
            DESTINATION_SUBJECT,
            b"vt-authz-sign-dest-v1",
            &[Field(hostkey_wire), Field(fingerprint.as_bytes())],
        )
    }

    /// Workspace-bound sign scope (local `sign@vt` and unbound non-ssh raw
    /// signers such as `ssh-keygen -Y sign`). `subject` is the workspace
    /// root's `(st_dev, st_ino)`; `root_path` is the canonical root path
    /// captured from the same file descriptor, bound into the digest so a
    /// recycled inode under a different path cannot match. A resolved
    /// workspace always has a subject, so unlike the relay constructors
    /// there is no `Option` fallback.
    pub fn sign_workspace(subject: SubjectId, root_path: &str, fingerprint: &str) -> Self {
        Self::hashed(
            Operation::Sign,
            ScopeFamily::Workspace,
            subject,
            b"vt-authz-sign-ws-v1",
            &[Field(root_path.as_bytes()), Field(fingerprint.as_bytes())],
        )
    }

    /// Cwd-fallback sign scope: the peer's kernel cwd has no `.git` ancestor,
    /// so the cwd directory itself is the activity boundary. Same fd-derived
    /// `(dev, ino)` + canonical-path binding as [`Self::sign_workspace`], but
    /// a distinct digest domain: a directory that later gains a `.git` must
    /// start a new grant family, never silently continue this one.
    pub fn sign_cwd(subject: SubjectId, root_path: &str, fingerprint: &str) -> Self {
        Self::hashed(
            Operation::Sign,
            ScopeFamily::CwdFallback,
            subject,
            b"vt-authz-sign-cwd-v1",
            &[Field(root_path.as_bytes()), Field(fingerprint.as_bytes())],
        )
    }

    /// Workspace-bound decrypt scope for local pure-v2 batches. Same subject
    /// and path-binding rules as [`Self::sign_workspace`].
    pub fn decrypt_workspace(
        subject: SubjectId,
        root_path: &str,
        secret_type: u8,
        salt: &[u8],
    ) -> Self {
        Self::hashed(
            Operation::Decrypt,
            ScopeFamily::Workspace,
            subject,
            b"vt-authz-decrypt-ws-v1",
            &[Field(root_path.as_bytes()), Tag(secret_type), Field(salt)],
        )
    }

    /// Parent-app sign scope: the caller's kernel cwd is a broad shared
    /// directory ($HOME, `/`, a temp root), so the activity is identified by
    /// the caller's kernel-derived parent process instead — "this application
    /// instance keeps making the same request". `subject` is the parent's
    /// `(pid, start_tvsec)` (grants die with the parent); the digest binds
    /// the parent's kernel-verified executable path, never the
    /// client-claimed `ppid_cmd`.
    pub fn sign_app(subject: SubjectId, parent_exe: &str, fingerprint: &str) -> Self {
        Self::hashed(
            Operation::Sign,
            ScopeFamily::ParentApp,
            subject,
            b"vt-authz-sign-app-v1",
            &[Field(parent_exe.as_bytes()), Field(fingerprint.as_bytes())],
        )
    }

    /// Parent-app decrypt scope. Same rules as [`Self::sign_app`].
    pub fn decrypt_app(subject: SubjectId, parent_exe: &str, secret_type: u8, salt: &[u8]) -> Self {
        Self::hashed(
            Operation::Decrypt,
            ScopeFamily::ParentApp,
            subject,
            b"vt-authz-decrypt-app-v1",
            &[Field(parent_exe.as_bytes()), Tag(secret_type), Field(salt)],
        )
    }

    /// Cwd-fallback decrypt scope. Same rules as [`Self::sign_cwd`].
    pub fn decrypt_cwd(subject: SubjectId, root_path: &str, secret_type: u8, salt: &[u8]) -> Self {
        Self::hashed(
            Operation::Decrypt,
            ScopeFamily::CwdFallback,
            subject,
            b"vt-authz-decrypt-cwd-v1",
            &[Field(root_path.as_bytes()), Tag(secret_type), Field(salt)],
        )
    }

    /// Relay decrypt scope: type + salt + claimed host/pwd, bounded by the
    /// relay connection's kernel-derived subject.
    pub fn decrypt_v2(
        subject: Option<SubjectId>,
        secret_type: u8,
        salt: &[u8],
        host: &str,
        pwd: &str,
    ) -> Self {
        let Some(subject) = subject else {
            return Self::fresh(Operation::Decrypt);
        };
        Self::hashed(
            Operation::Decrypt,
            ScopeFamily::Connection,
            subject,
            b"vt-authorization-decrypt-v1",
            &[
                Tag(secret_type),
                Field(salt),
                Field(host.as_bytes()),
                Field(pwd.as_bytes()),
            ],
        )
    }

    /// The one digest encoder behind every reusable scope: `label` is the
    /// family's domain separator, `parts` the resource fields in wire order.
    /// The subject is not hashed — it is a separate key component, so the
    /// same resource under two callers is two grants.
    fn hashed(
        operation: Operation,
        family: ScopeFamily,
        subject: SubjectId,
        label: &[u8],
        parts: &[Part<'_>],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(label);
        for part in parts {
            match part {
                Tag(byte) => h.update([*byte]),
                Field(value) => {
                    h.update((value.len() as u64).to_le_bytes());
                    h.update(value);
                }
            }
        }
        Self::reusable(operation, family, subject, h.finalize().into())
    }

    fn reusable(
        operation: Operation,
        family: ScopeFamily,
        subject: SubjectId,
        digest: [u8; 32],
    ) -> Self {
        Self {
            operation,
            key: Some(GrantKey {
                operation,
                family,
                subject,
                digest,
            }),
            display: String::new(),
        }
    }

    /// True when an approval under this scope can create a standing grant —
    /// the condition under which the prompt must carry a reuse line
    /// (docs/approval-transparency.md). Currently exercised only by the
    /// invariant tests.
    #[cfg(test)]
    pub fn is_reusable(&self) -> bool {
        self.key.is_some()
    }

    /// The scope family when this scope can mint a grant; `None` for fresh.
    /// Feeds the audit rows' `scope_family` field.
    pub fn family(&self) -> Option<ScopeFamily> {
        self.key.as_ref().map(|k| k.family)
    }
}

/// One digest input. `Field` is length-prefixed so adjacent variable-width
/// inputs cannot shift into each other; `Tag` is the record's fixed-width
/// `secret_type` byte, which has no prefix on the wire.
enum Part<'a> {
    Tag(u8),
    Field(&'a [u8]),
}
use Part::{Field, Tag};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReusePolicy {
    /// Authenticate every request and never read or write a grant.
    Fresh,
    /// Reuse grants until either clock reaches the fixed deadline. Hits and
    /// repeated approvals never slide an existing live deadline.
    StrictTtl(Duration),
}

impl ReusePolicy {
    pub fn strict_ttl_secs(seconds: u64) -> Self {
        Self::StrictTtl(Duration::from_secs(seconds))
    }

    /// Map a configured cache duration to a policy: `0` selects the
    /// first-class `Fresh` policy (never reads or writes grants) — NOT
    /// `StrictTtl(0)`. Lives on the type so every engine consumer inherits
    /// the rule.
    pub fn from_ttl_secs(seconds: u64) -> Self {
        if seconds == 0 {
            Self::Fresh
        } else {
            Self::strict_ttl_secs(seconds)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    CacheHit,
    Approved,
    Rejected,
    Unavailable(UnavailableReason),
    /// The authorization epoch or real-time security state invalidated the
    /// request. Extension handlers map this retryable condition to Transient.
    Invalidated,
}

impl Decision {
    pub fn audit_outcome(self) -> &'static str {
        match self {
            Decision::CacheHit => "cache_hit",
            Decision::Approved => "approved",
            Decision::Rejected => "rejected",
            Decision::Unavailable(_) | Decision::Invalidated => "unavailable",
        }
    }
}

pub struct AuthorizationRequest {
    scopes: Vec<GrantScope>,
    reuse: ReusePolicy,
    prompt: String,
}

impl AuthorizationRequest {
    pub fn new(scopes: Vec<GrantScope>, reuse: ReusePolicy, prompt: impl Into<String>) -> Self {
        Self {
            scopes,
            reuse,
            prompt: prompt.into(),
        }
    }

    pub fn fresh(scope: GrantScope, prompt: impl Into<String>) -> Self {
        Self::new(vec![scope], ReusePolicy::Fresh, prompt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Unavailable(UnavailableReason),
    Invalidated,
}

/// `operation` lets a platform authenticator bind a master-needing approval
/// to its key custody; the pending custody follows the approval guard.
#[async_trait]
pub trait AuthorizationAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        prompt: &str,
        operation: Operation,
        revocation_pending: Arc<AtomicBool>,
    ) -> AuthOutcome;

    /// Drop pending custody with the approval's permit, before the prompt
    /// slot is released. Must not block on I/O.
    fn approval_complete(&self) {}
}

/// Must query current state rather than a TTL-cached snapshot. The engine calls
/// it immediately before returning a cache hit and after a fresh prompt. A
/// validator that observes an unsafe state must publish `revocation_pending`
/// before returning an error, closing the window for concurrent readers.
pub trait AuthorizationValidator: Send + Sync {
    fn validate(&self, revocation_pending: &AtomicBool) -> Result<(), ValidationError>;

    /// Called under the security write gate after grants are cleared. Stateful
    /// validators can reset wake/session baselines before the pending latch is
    /// released.
    fn invalidation_complete(&self) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheExpiry {
    // `Instant` bounds awake time; `SystemTime` keeps expiring through sleep.
    // Requiring both also prevents a backwards wall-clock step from extending
    // the grant indefinitely.
    mono: Instant,
    wall: SystemTime,
    /// Policy under which this grant was issued. A request may reuse an entry
    /// only when it asks for an equal or wider TTL; policy tightening must
    /// require a fresh approval.
    ttl: Duration,
}

impl CacheExpiry {
    fn checked(
        ttl: Duration,
        approved_mono: Instant,
        approved_wall: SystemTime,
    ) -> Result<Self, CommitError> {
        Ok(Self {
            mono: approved_mono
                .checked_add(ttl)
                .ok_or(CommitError::InvalidTtl)?,
            wall: approved_wall
                .checked_add(ttl)
                .ok_or(CommitError::InvalidTtl)?,
            ttl,
        })
    }

    fn is_valid_at(self, now_mono: Instant, now_wall: SystemTime) -> bool {
        now_mono < self.mono && now_wall < self.wall
    }

    /// Time left before the earlier of the two deadlines; zero once either
    /// clock has passed. Display-only companion to [`Self::is_valid_at`].
    fn remaining_at(self, now_mono: Instant, now_wall: SystemTime) -> Duration {
        let mono_left = self.mono.saturating_duration_since(now_mono);
        let wall_left = self.wall.duration_since(now_wall).unwrap_or(Duration::ZERO);
        mono_left.min(wall_left)
    }
}

/// Stored value per live grant: the dual-clock expiry, the human scope
/// label (display-only; feeds `ui-status@vt` snapshots), and the material a
/// hit serves.
struct GrantEntry {
    expiry: CacheExpiry,
    display: String,
    material: Option<GrantMaterial>,
}

impl fmt::Debug for GrantEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantEntry")
            .field("expiry", &self.expiry)
            .field("display", &self.display)
            .field("material", &self.material.is_some())
            .finish()
    }
}

/// A reusable key paired with its scope's display label — what `authorize`
/// carries from request scopes into lookups and pending commits.
#[derive(Clone, Debug)]
struct KeyedScope {
    key: GrantKey,
    display: String,
}

/// One live grant as reported to the token-gated `ui-status@vt` channel
/// (docs/app-bundle.md#status-and-revoke-boundary) — the deliberate whole-store exception to
/// diag@vt's caller-scoped counts. No digests, subjects, or key material;
/// `display` is the same string the approval prompt showed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GrantSnapshot {
    /// Stable operation tag: "sign" | "decrypt" | "auth" | "run".
    pub operation: String,
    /// `ScopeFamily::as_wire` tag.
    pub family: String,
    pub display: String,
    pub remaining_secs: u64,
    pub ttl_secs: u64,
}

#[derive(Debug)]
struct GrantStore {
    entries: HashMap<GrantKey, GrantEntry>,
    epoch: u64,
}

impl GrantStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            epoch: 0,
        }
    }

    fn lookup_at(
        &self,
        keys: &[KeyedScope],
        requested_ttl: Duration,
        now_mono: Instant,
        now_wall: SystemTime,
    ) -> Lookup {
        let hits: Vec<&GrantEntry> = keys
            .iter()
            .filter_map(|scoped| self.entries.get(&scoped.key))
            .filter(|entry| {
                entry.expiry.is_valid_at(now_mono, now_wall) && entry.expiry.ttl <= requested_ttl
            })
            .collect();
        let epoch = self.epoch;
        if hits.len() != keys.len() {
            return Lookup {
                epoch,
                all_hit: false,
                remaining: None,
                materials: Vec::new(),
            };
        }
        // Tightest remaining lifetime across the hit set — informational only
        // (cache-hit notifications / ui-status); never feeds a reuse decision.
        let remaining = hits
            .iter()
            .map(|entry| entry.expiry.remaining_at(now_mono, now_wall))
            .min();
        // Materials travel only as a complete, scope-aligned set.
        let mut materials: Vec<GrantMaterial> = hits
            .iter()
            .filter_map(|entry| entry.material.clone())
            .collect();
        if materials.len() != keys.len() {
            materials.clear();
        }
        Lookup {
            epoch,
            all_hit: true,
            remaining,
            materials,
        }
    }

    /// `materials` is empty or aligned one-to-one with `keys`; a refreshed
    /// entry takes the new material with its new expiry (same resource,
    /// same material).
    fn commit_at(
        &mut self,
        expected_epoch: u64,
        keys: &[KeyedScope],
        materials: &[GrantMaterial],
        ttl: Duration,
        approved_mono: Instant,
        approved_wall: SystemTime,
    ) -> Result<usize, CommitError> {
        if self.epoch != expected_epoch {
            return Err(CommitError::Invalidated);
        }
        if !materials.is_empty() && materials.len() != keys.len() {
            return Err(CommitError::MaterialMismatch);
        }
        let fresh = CacheExpiry::checked(ttl, approved_mono, approved_wall)?;
        let mut inserted = 0;
        for (i, scoped) in keys.iter().enumerate() {
            let material = materials.get(i).cloned();
            self.entries
                .entry(scoped.key.clone())
                .and_modify(|entry| {
                    if !entry.expiry.is_valid_at(approved_mono, approved_wall)
                        || entry.expiry.ttl > ttl
                    {
                        entry.expiry = fresh;
                        entry.display = scoped.display.clone();
                        entry.material = material.clone();
                        inserted += 1;
                    }
                })
                .or_insert_with(|| {
                    inserted += 1;
                    GrantEntry {
                        expiry: fresh,
                        display: scoped.display.clone(),
                        material,
                    }
                });
        }
        Ok(inserted)
    }

    fn invalidate_all(&mut self) -> usize {
        let dropped = self.entries.len();
        self.entries.clear();
        self.epoch = self
            .epoch
            .checked_add(1)
            .expect("authorization epoch exhausted");
        dropped
    }

    fn sweep_expired_at(&mut self, now_mono: Instant, now_wall: SystemTime) {
        self.entries
            .retain(|_, entry| entry.expiry.is_valid_at(now_mono, now_wall));
    }

    fn live_len_at(
        &self,
        operation: Operation,
        family: ScopeFamily,
        subject: SubjectId,
        now_mono: Instant,
        now_wall: SystemTime,
    ) -> usize {
        self.entries
            .iter()
            .filter(|(key, entry)| {
                key.operation == operation
                    && key.family == family
                    && key.subject == subject
                    && entry.expiry.is_valid_at(now_mono, now_wall)
            })
            .count()
    }

    /// Whole-store enumeration for the token-gated `ui-status@vt` channel
    /// ONLY (docs/app-bundle.md#status-and-revoke-boundary). Sorted for stable UI ordering.
    fn snapshot_at(&self, now_mono: Instant, now_wall: SystemTime) -> Vec<GrantSnapshot> {
        let mut grants: Vec<GrantSnapshot> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expiry.is_valid_at(now_mono, now_wall))
            .map(|(key, entry)| GrantSnapshot {
                operation: key.operation.as_wire().to_string(),
                family: key.family.as_wire().to_string(),
                display: entry.display.clone(),
                remaining_secs: entry.expiry.remaining_at(now_mono, now_wall).as_secs(),
                ttl_secs: entry.expiry.ttl.as_secs(),
            })
            .collect();
        grants.sort_by(|a, b| {
            (&a.operation, &a.family, &a.display).cmp(&(&b.operation, &b.family, &b.display))
        });
        grants
    }
}

struct Lookup {
    epoch: u64,
    all_hit: bool,
    /// Tightest remaining lifetime across the hit set when `all_hit`.
    remaining: Option<Duration>,
    /// Every hit grant's material, aligned with the keys; empty when any
    /// grant carries none.
    materials: Vec<GrantMaterial>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    Invalidated,
    InvalidTtl,
    /// Attached materials do not align with the request's scopes.
    MaterialMismatch,
}

struct PendingGrant {
    expected_epoch: u64,
    keys: Vec<KeyedScope>,
    materials: Vec<GrantMaterial>,
    ttl: Duration,
    approved_mono: Instant,
    approved_wall: SystemTime,
}

struct ApprovalGuard {
    authenticator: Arc<dyn AuthorizationAuthenticator>,
    _prompt: OwnedSemaphorePermit,
}

impl Drop for ApprovalGuard {
    fn drop(&mut self) {
        self.authenticator.approval_complete();
    }
}

/// Capability returned by a successful authorization. It deliberately does
/// not implement Clone. Dropping it releases the security gate and prompt
/// permit without writing a pending grant.
pub struct AuthorizationPermit {
    decision: Decision,
    latency_ms: u64,
    /// Tightest remaining grant lifetime when `decision` is `CacheHit`.
    /// Informational only (cache-hit notifications); never a reuse input.
    reuse_remaining: Option<Duration>,
    /// The hit grants' materials, one per request scope in request order;
    /// empty for a fresh approval or when any grant carried none.
    materials: Vec<GrantMaterial>,
    pending: Option<PendingGrant>,
    store: Arc<RwLock<GrantStore>>,
    /// Holds the prompt slot and the authenticator's pending custody for a
    /// new approval; both end when the permit does.
    _approval: Option<ApprovalGuard>,
    _security: OwnedRwLockReadGuard<()>,
}

impl AuthorizationPermit {
    pub fn decision(&self) -> Decision {
        self.decision
    }

    pub fn reuse_remaining(&self) -> Option<Duration> {
        self.reuse_remaining
    }

    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Materials served by a `CacheHit`, aligned with the request scopes.
    pub fn materials(&self) -> &[GrantMaterial] {
        &self.materials
    }

    /// Store `materials` (one per request scope, in request order) with the
    /// grant this permit will commit. Dropped when nothing is pending.
    pub fn attach_materials(&mut self, materials: Vec<GrantMaterial>) {
        if let Some(pending) = &mut self.pending {
            pending.materials = materials;
        }
    }

    /// Commit the pending reusable grant after the protected operation has
    /// completed successfully. Cache hits and Fresh policies have no pending
    /// write but still consume the permit to release its gates explicitly.
    pub async fn commit(mut self) -> Result<(), CommitError> {
        if let Some(pending) = self.pending.take() {
            self.store.write().await.commit_at(
                pending.expected_epoch,
                &pending.keys,
                &pending.materials,
                pending.ttl,
                pending.approved_mono,
                pending.approved_wall,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationFailure {
    decision: Decision,
    latency_ms: u64,
}

impl AuthorizationFailure {
    pub fn decision(&self) -> Decision {
        self.decision
    }

    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }
}

pub struct AuthorizationEngine {
    store: Arc<RwLock<GrantStore>>,
    security_gate: Arc<RwLock<()>>,
    prompt_sem: Arc<Semaphore>,
    revocation_pending: Arc<AtomicBool>,
    revoker_running: AtomicBool,
    revocation_generation: AtomicU64,
    revocation_completed: watch::Sender<u64>,
    authenticator: Arc<dyn AuthorizationAuthenticator>,
    validator: Arc<dyn AuthorizationValidator>,
}

impl AuthorizationEngine {
    pub fn new(
        authenticator: Arc<dyn AuthorizationAuthenticator>,
        validator: Arc<dyn AuthorizationValidator>,
    ) -> Arc<Self> {
        let (revocation_completed, _) = watch::channel(0);
        Arc::new(Self {
            store: Arc::new(RwLock::new(GrantStore::new())),
            security_gate: Arc::new(RwLock::new(())),
            prompt_sem: Arc::new(Semaphore::new(1)),
            revocation_pending: Arc::new(AtomicBool::new(false)),
            revoker_running: AtomicBool::new(false),
            revocation_generation: AtomicU64::new(0),
            revocation_completed,
            authenticator,
            validator,
        })
    }

    pub async fn authorize(
        self: &Arc<Self>,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationPermit, AuthorizationFailure> {
        let started = Instant::now();
        if let ReusePolicy::StrictTtl(ttl) = request.reuse {
            // Reject hostile or corrupt configuration before a cache lookup,
            // human prompt, or protected operation. `commit_at` repeats this
            // check defensively because it is also exercised independently.
            if CacheExpiry::checked(ttl, Instant::now(), SystemTime::now()).is_err() {
                return Err(failure(Decision::Invalidated, started));
            }
        }
        let Some(operation) = request.scopes.first().map(|scope| scope.operation) else {
            return Err(failure(Decision::Invalidated, started));
        };
        if request
            .scopes
            .iter()
            .any(|scope| scope.operation != operation)
        {
            return Err(failure(Decision::Invalidated, started));
        }
        let mut subjects = request
            .scopes
            .iter()
            .filter_map(|scope| scope.key.as_ref().map(|key| key.subject));
        if let Some(subject) = subjects.next() {
            if subjects.any(|candidate| candidate != subject) {
                return Err(failure(Decision::Invalidated, started));
            }
        }

        let keys = reusable_keys(&request.scopes, request.reuse);
        let reusable_ttl = match request.reuse {
            ReusePolicy::StrictTtl(ttl) => Some(ttl),
            ReusePolicy::Fresh => None,
        };
        if let (Some(keys), Some(ttl)) = (keys.as_deref(), reusable_ttl) {
            let security = Arc::clone(&self.security_gate).read_owned().await;
            let lookup = self.lookup(keys, ttl).await;
            if lookup.all_hit {
                if let Err(error) = self.validate_live() {
                    drop(security);
                    self.revoke_after_validation_failure().await;
                    return Err(failure(validation_decision(error), started));
                }
                return Ok(AuthorizationPermit {
                    decision: Decision::CacheHit,
                    latency_ms: 0,
                    reuse_remaining: lookup.remaining,
                    materials: lookup.materials,
                    pending: None,
                    store: Arc::clone(&self.store),
                    _approval: None,
                    _security: security,
                });
            }
        }

        let prompt = match Arc::clone(&self.prompt_sem).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                return Err(failure(
                    Decision::Unavailable(UnavailableReason::NotInteractive),
                    started,
                ))
            }
        };
        // Recheck under a temporary security read gate. It is deliberately
        // dropped before displaying a prompt: invalidation must be able to
        // acquire the write gate and revoke an in-flight prompt via epoch.
        let epoch = {
            let security = Arc::clone(&self.security_gate).read_owned().await;
            if let Err(error) = self.validate_live() {
                drop(security);
                self.revoke_after_validation_failure().await;
                return Err(failure(validation_decision(error), started));
            }
            if let (Some(keys), Some(ttl)) = (keys.as_deref(), reusable_ttl) {
                let lookup = self.lookup(keys, ttl).await;
                if lookup.all_hit {
                    if let Err(error) = self.validate_live() {
                        drop(security);
                        drop(prompt);
                        self.revoke_after_validation_failure().await;
                        return Err(failure(validation_decision(error), started));
                    }
                    drop(prompt);
                    return Ok(AuthorizationPermit {
                        decision: Decision::CacheHit,
                        latency_ms: 0,
                        reuse_remaining: lookup.remaining,
                        materials: lookup.materials,
                        pending: None,
                        store: Arc::clone(&self.store),
                        _approval: None,
                        _security: security,
                    });
                }
                lookup.epoch
            } else {
                self.store.read().await.epoch
            }
        };

        // The task owns the semaphore permit while the platform prompt is
        // active. Dropping/cancelling the caller's future detaches this task,
        // so a blocking system prompt cannot outlive the serialization guard
        // and overlap a later request.
        let authenticator = Arc::clone(&self.authenticator);
        let revocation_pending = Arc::clone(&self.revocation_pending);
        let prompt_engine = Arc::clone(self);
        let prompt_task = tokio::spawn(async move {
            let approval = ApprovalGuard {
                authenticator: Arc::clone(&authenticator),
                _prompt: prompt,
            };
            let outcome = authenticator
                .authenticate(&request.prompt, operation, Arc::clone(&revocation_pending))
                .await;
            if matches!(outcome, AuthOutcome::Unavailable(_)) {
                // Defensive fallback for authenticators that did not publish
                // the latch at the point where unavailability was observed.
                revocation_pending.store(true, Ordering::Release);
                // This worker owns the prompt independently of the requesting
                // connection. Drain here as well so a caller cancelled while
                // the system dialog is open cannot leave old grants standing.
                prompt_engine.drain_pending_revocation().await;
            }
            (outcome, approval)
        });
        let (outcome, approval) = match prompt_task.await {
            Ok(result) => result,
            Err(_) => {
                // Treat an authenticator task failure as an unsafe prompt
                // failure too. The task normally converts platform errors to
                // `Unavailable`, but this keeps custom adapters fail-closed.
                self.invalidate_all().await;
                return Err(failure(
                    Decision::Unavailable(UnavailableReason::NotInteractive),
                    started,
                ));
            }
        };
        match outcome {
            AuthOutcome::Success => {}
            AuthOutcome::Rejected => return Err(failure(Decision::Rejected, started)),
            AuthOutcome::Unavailable(reason) => {
                return Err(failure(Decision::Unavailable(reason), started))
            }
        };

        // The returned permit owns this read gate through the protected
        // operation. If invalidation won the write gate during the prompt, the
        // epoch comparison below observes it and the operation never starts.
        let security = Arc::clone(&self.security_gate).read_owned().await;
        if self.store.read().await.epoch != epoch {
            return Err(failure(Decision::Invalidated, started));
        }
        if let Err(error) = self.validate_live() {
            drop(security);
            drop(approval);
            self.revoke_after_validation_failure().await;
            return Err(failure(validation_decision(error), started));
        }

        let approved_mono = Instant::now();
        let approved_wall = SystemTime::now();
        let pending = match (keys, request.reuse) {
            (Some(keys), ReusePolicy::StrictTtl(ttl)) => Some(PendingGrant {
                expected_epoch: epoch,
                keys,
                materials: Vec::new(),
                ttl,
                approved_mono,
                approved_wall,
            }),
            _ => None,
        };
        Ok(AuthorizationPermit {
            decision: Decision::Approved,
            latency_ms: started.elapsed().as_millis() as u64,
            reuse_remaining: None,
            materials: Vec::new(),
            pending,
            store: Arc::clone(&self.store),
            _approval: Some(approval),
            _security: security,
        })
    }

    /// Linearized, cancellation-safe invalidation. The first caller starts one
    /// detached revoker; concurrent callers wait for it instead of queueing a
    /// writer per failed request. The pending latch blocks new permits before
    /// the writer can acquire the security gate.
    pub async fn invalidate_all(self: &Arc<Self>) -> usize {
        self.revocation_pending.store(true, Ordering::Release);
        self.drain_pending_revocation().await
    }

    async fn drain_pending_revocation(self: &Arc<Self>) -> usize {
        let mut completed = self.revocation_completed.subscribe();
        loop {
            let pending = self.revocation_pending.load(Ordering::Acquire);
            let running = self.revoker_running.load(Ordering::Acquire);
            if !pending && !running {
                return 0;
            }
            if pending
                && self
                    .revoker_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let engine = Arc::clone(self);
                let revoker = tokio::spawn(async move { engine.run_revoker().await });
                return revoker.await.unwrap_or(0);
            }

            // Subscribe before inspecting state (above), so a completion
            // between the inspection and this await remains visible. After
            // every wake, retry the claim: separate pending/running atomics
            // can transiently leave an orphaned pending state during revoker
            // hand-off, and a waiter must be able to recover it.
            if completed.changed().await.is_err() {
                return 0;
            }
        }
    }

    pub async fn sweep_expired(&self) {
        self.store
            .write()
            .await
            .sweep_expired_at(Instant::now(), SystemTime::now());
    }

    pub async fn live_len(
        &self,
        operation: Operation,
        family: ScopeFamily,
        subject: SubjectId,
    ) -> usize {
        self.store.read().await.live_len_at(
            operation,
            family,
            subject,
            Instant::now(),
            SystemTime::now(),
        )
    }

    /// Whole-store grant enumeration. ONLY for the token-gated `ui-status@vt`
    /// handler (docs/app-bundle.md#status-and-revoke-boundary) — every other read surface stays
    /// caller-scoped (`live_len`). Read-lock only; never sweeps or mutates.
    pub async fn snapshot(&self) -> Vec<GrantSnapshot> {
        self.store
            .read()
            .await
            .snapshot_at(Instant::now(), SystemTime::now())
    }

    async fn lookup(&self, keys: &[KeyedScope], requested_ttl: Duration) -> Lookup {
        self.store
            .read()
            .await
            .lookup_at(keys, requested_ttl, Instant::now(), SystemTime::now())
    }

    /// Once a live validator observes an unsafe state, old grants must not
    /// become usable again merely because the state later returns to normal.
    /// Spawn first so cancellation of the requesting connection cannot cancel
    /// the revocation after the observation has already been made.
    async fn revoke_after_validation_failure(self: &Arc<Self>) {
        // The validator (or validate_live's defensive fallback) published the
        // latch synchronously. Do not reassert it here: a concurrent revoker
        // may already have covered this observation before this task resumes.
        self.drain_pending_revocation().await;
    }

    fn validate_live(&self) -> Result<(), ValidationError> {
        if self.revocation_pending.load(Ordering::Acquire) {
            return Err(ValidationError::Invalidated);
        }
        match self.validator.validate(&self.revocation_pending) {
            Err(error) => {
                // Defensive publication for validators that did not follow the
                // trait contract. Platform validators publish before return.
                self.revocation_pending.store(true, Ordering::Release);
                Err(error)
            }
            Ok(()) if self.revocation_pending.load(Ordering::Acquire) => {
                Err(ValidationError::Invalidated)
            }
            Ok(()) => Ok(()),
        }
    }

    async fn run_revoker(self: Arc<Self>) -> usize {
        let mut dropped_total = 0usize;
        loop {
            let security = Arc::clone(&self.security_gate).write_owned().await;
            if self.revocation_pending.load(Ordering::Acquire) {
                dropped_total += self.store.write().await.invalidate_all();
                self.validator.invalidation_complete();
                self.revocation_pending.store(false, Ordering::Release);
            }
            drop(security);

            self.revoker_running.store(false, Ordering::Release);
            if self.revocation_pending.load(Ordering::Acquire)
                && self
                    .revoker_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                continue;
            }

            let generation = self
                .revocation_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            self.revocation_completed.send_replace(generation);
            return dropped_total;
        }
    }
}

/// One key per scope, in request order (duplicates included, so attached
/// materials stay index-aligned with the scopes); `None` unless every scope
/// is reusable under a `StrictTtl` policy.
fn reusable_keys(scopes: &[GrantScope], policy: ReusePolicy) -> Option<Vec<KeyedScope>> {
    if !matches!(policy, ReusePolicy::StrictTtl(_)) {
        return None;
    }
    let mut keys = Vec::with_capacity(scopes.len());
    for scope in scopes {
        keys.push(KeyedScope {
            key: scope.key.as_ref()?.clone(),
            display: scope.display.clone(),
        });
    }
    (!keys.is_empty()).then_some(keys)
}

fn validation_decision(error: ValidationError) -> Decision {
    match error {
        ValidationError::Unavailable(reason) => Decision::Unavailable(reason),
        ValidationError::Invalidated => Decision::Invalidated,
    }
}

fn failure(decision: Decision, started: Instant) -> AuthorizationFailure {
    AuthorizationFailure {
        decision,
        latency_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Barrier;
    use tokio::sync::Notify;

    struct AllowValidator {
        allowed: AtomicBool,
    }

    impl AllowValidator {
        fn allowed() -> Arc<Self> {
            Arc::new(Self {
                allowed: AtomicBool::new(true),
            })
        }
    }

    impl AuthorizationValidator for AllowValidator {
        fn validate(&self, revocation_pending: &AtomicBool) -> Result<(), ValidationError> {
            if self.allowed.load(Ordering::Acquire) {
                Ok(())
            } else {
                revocation_pending.store(true, Ordering::Release);
                Err(ValidationError::Invalidated)
            }
        }
    }

    struct SuccessAuthenticator {
        calls: AtomicUsize,
    }

    struct FixedAuthenticator {
        calls: AtomicUsize,
        outcome: AuthOutcome,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for FixedAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if matches!(self.outcome, AuthOutcome::Unavailable(_)) {
                revocation_pending.store(true, Ordering::Release);
            }
            self.outcome
        }
    }

    impl SuccessAuthenticator {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl AuthorizationAuthenticator for SuccessAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            self.calls.fetch_add(1, Ordering::AcqRel);
            AuthOutcome::Success
        }
    }

    fn sign_scope(subject: SubjectId, fingerprint: &str) -> GrantScope {
        GrantScope::sign(Some(subject), fingerprint, "/repo")
    }

    fn sign_request(subject: SubjectId, fingerprint: &str) -> AuthorizationRequest {
        AuthorizationRequest::new(
            vec![sign_scope(subject, fingerprint)],
            ReusePolicy::strict_ttl_secs(120),
            "sign",
        )
    }

    /// Direct-store tests address entries as `KeyedScope` (key + display),
    /// mirroring what `reusable_keys` hands the store.
    fn keyed(scope: GrantScope) -> KeyedScope {
        KeyedScope {
            key: scope.key.unwrap(),
            display: scope.display,
        }
    }

    #[test]
    fn strict_ttl_requires_both_clocks() {
        let key = keyed(sign_scope((1, 2), "fp"));
        let mut store = GrantStore::new();
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        store
            .commit_at(
                0,
                std::slice::from_ref(&key),
                &[],
                Duration::from_secs(120),
                m0,
                w0,
            )
            .unwrap();
        assert!(
            store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(120),
                    m0 + Duration::from_secs(60),
                    w0 + Duration::from_secs(60)
                )
                .all_hit
        );
        assert!(
            !store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(120),
                    m0 + Duration::from_secs(60),
                    w0 + Duration::from_secs(121)
                )
                .all_hit
        );
        assert!(
            !store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(120),
                    m0 + Duration::from_secs(121),
                    w0 + Duration::from_secs(60)
                )
                .all_hit
        );
    }

    #[test]
    fn strict_ttl_does_not_slide() {
        let key = keyed(sign_scope((1, 2), "fp"));
        let mut store = GrantStore::new();
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        store
            .commit_at(
                0,
                std::slice::from_ref(&key),
                &[],
                Duration::from_secs(120),
                m0,
                w0,
            )
            .unwrap();
        store
            .commit_at(
                0,
                std::slice::from_ref(&key),
                &[],
                Duration::from_secs(120),
                m0 + Duration::from_secs(60),
                w0 + Duration::from_secs(60),
            )
            .unwrap();
        assert!(
            !store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(120),
                    m0 + Duration::from_secs(121),
                    w0 + Duration::from_secs(121)
                )
                .all_hit
        );
    }

    #[test]
    fn shorter_policy_replaces_a_live_wider_ttl_without_sliding() {
        let key = keyed(sign_scope((1, 2), "fp"));
        let mut store = GrantStore::new();
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        store
            .commit_at(
                0,
                std::slice::from_ref(&key),
                &[],
                Duration::from_secs(120),
                m0,
                w0,
            )
            .unwrap();
        assert!(
            !store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(30),
                    m0 + Duration::from_secs(1),
                    w0 + Duration::from_secs(1),
                )
                .all_hit
        );

        store
            .commit_at(
                0,
                std::slice::from_ref(&key),
                &[],
                Duration::from_secs(30),
                m0 + Duration::from_secs(1),
                w0 + Duration::from_secs(1),
            )
            .unwrap();
        assert!(
            store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(30),
                    m0 + Duration::from_secs(30),
                    w0 + Duration::from_secs(30),
                )
                .all_hit
        );
        assert!(
            !store
                .lookup_at(
                    std::slice::from_ref(&key),
                    Duration::from_secs(30),
                    m0 + Duration::from_secs(32),
                    w0 + Duration::from_secs(32),
                )
                .all_hit
        );
    }

    #[test]
    fn scope_families_are_domain_separated() {
        // The same source material must never produce the same grant key
        // across scope families: a subject collision (e.g. workspace
        // (dev, ino) numerically equal to a relay (pid, tvsec)) is harmless
        // only because the digest domain labels differ.
        let subject = (7, 42);
        let relay_sign = GrantScope::sign(Some(subject), "fp", "/repo").key.unwrap();
        let ws_sign = GrantScope::sign_workspace(subject, "/repo", "fp")
            .key
            .unwrap();
        let dest_sign = GrantScope::sign_destination(b"hostkey-wire", "fp")
            .key
            .unwrap();
        assert_ne!(relay_sign, ws_sign);
        assert_ne!(relay_sign, dest_sign);
        assert_ne!(ws_sign, dest_sign);

        // Cwd-fallback is its own family: the SAME directory (same subject,
        // same canonical path) must never match a git-workspace grant, so a
        // later `git init` (or `.git` removal) starts a new family instead
        // of silently continuing the old grants.
        let cwd_sign = GrantScope::sign_cwd(subject, "/repo", "fp").key.unwrap();
        assert_ne!(cwd_sign, ws_sign);
        assert_ne!(cwd_sign, relay_sign);
        assert_ne!(cwd_sign, dest_sign);

        // Parent-app is its own family too (and partitions on the exe path).
        let app_sign = GrantScope::sign_app(subject, "/repo", "fp").key.unwrap();
        assert_ne!(app_sign, ws_sign);
        assert_ne!(app_sign, cwd_sign);
        assert_ne!(app_sign, relay_sign);
        assert_ne!(
            GrantScope::sign_app(subject, "/App/A", "fp").key.unwrap(),
            GrantScope::sign_app(subject, "/App/B", "fp").key.unwrap()
        );

        let relay_dec = GrantScope::decrypt_v2(Some(subject), b'0', &[7; 16], "/repo", "/repo")
            .key
            .unwrap();
        let ws_dec = GrantScope::decrypt_workspace(subject, "/repo", b'0', &[7; 16])
            .key
            .unwrap();
        let cwd_dec = GrantScope::decrypt_cwd(subject, "/repo", b'0', &[7; 16])
            .key
            .unwrap();
        let app_dec = GrantScope::decrypt_app(subject, "/repo", b'0', &[7; 16])
            .key
            .unwrap();
        assert_ne!(relay_dec, ws_dec);
        assert_ne!(cwd_dec, ws_dec);
        assert_ne!(cwd_dec, relay_dec);
        assert_ne!(app_dec, ws_dec);
        assert_ne!(app_dec, cwd_dec);
        assert_ne!(app_dec, relay_dec);

        // Destination scope partitions on host key and key fingerprint.
        assert_ne!(
            GrantScope::sign_destination(b"hostkey-a", "fp")
                .key
                .unwrap(),
            GrantScope::sign_destination(b"hostkey-b", "fp")
                .key
                .unwrap()
        );
        assert_ne!(
            GrantScope::sign_destination(b"hostkey-a", "fp-a")
                .key
                .unwrap(),
            GrantScope::sign_destination(b"hostkey-a", "fp-b")
                .key
                .unwrap()
        );
        // Workspace scope partitions on root path.
        assert_ne!(
            GrantScope::sign_workspace(subject, "/repo-a", "fp")
                .key
                .unwrap(),
            GrantScope::sign_workspace(subject, "/repo-b", "fp")
                .key
                .unwrap()
        );
        // Reusability is observable: it gates the prompt reuse line.
        assert!(GrantScope::sign_workspace(subject, "/repo", "fp").is_reusable());
        assert!(!GrantScope::fresh(Operation::Sign).is_reusable());
        assert!(!GrantScope::sign(None, "fp", "/repo").is_reusable());
    }

    /// Pins the exact scope key of every reusable constructor. A digest is
    /// the grant identity: a changed label, field order or length prefix
    /// silently invalidates every stored grant or, worse, merges families.
    /// A failure here is a wire-compatibility decision, never a value to
    /// re-paste.
    #[test]
    fn scope_key_digests_are_pinned() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let subject = (7, 42);
        let salt = [7u8; 16];
        let cases: [(&str, GrantScope, Operation, ScopeFamily, SubjectId, &str); 9] = [
            (
                "sign",
                GrantScope::sign(Some(subject), "SHA256:fp", "/repo"),
                Operation::Sign,
                ScopeFamily::Connection,
                subject,
                "8b892dddbb70fca39abb87835a6560d5a8f5d2e105cca7f95df4dc045d30f056",
            ),
            (
                "sign_destination",
                GrantScope::sign_destination(b"hostkey-wire", "SHA256:fp"),
                Operation::Sign,
                ScopeFamily::Destination,
                DESTINATION_SUBJECT,
                "055a298e1488e59fb98419efab0ff040f87a077eef9b533c8b7d8156e1852399",
            ),
            (
                "sign_workspace",
                GrantScope::sign_workspace(subject, "/repo", "SHA256:fp"),
                Operation::Sign,
                ScopeFamily::Workspace,
                subject,
                "e8031eb4e65a043aee1593dcbfce230365e220559fa029ddde4d58fdf91dfdf8",
            ),
            (
                "sign_cwd",
                GrantScope::sign_cwd(subject, "/repo", "SHA256:fp"),
                Operation::Sign,
                ScopeFamily::CwdFallback,
                subject,
                "747231724e8646721e8dfe431e599ad3f716af5c09a758c63f30e02ba153ec7e",
            ),
            (
                "sign_app",
                GrantScope::sign_app(subject, "/Applications/A.app/Contents/MacOS/A", "SHA256:fp"),
                Operation::Sign,
                ScopeFamily::ParentApp,
                subject,
                "3732e33f56ed554ec12b3c7d6923671fd8d8ce9e00fe1ef5490299783e4e3913",
            ),
            (
                "decrypt_workspace",
                GrantScope::decrypt_workspace(subject, "/repo", b'0', &salt),
                Operation::Decrypt,
                ScopeFamily::Workspace,
                subject,
                "5371f98b9b83974469416fa7c2168d3ee15f58722b0a3f2fd705f2221e991671",
            ),
            (
                "decrypt_cwd",
                GrantScope::decrypt_cwd(subject, "/repo", b'0', &salt),
                Operation::Decrypt,
                ScopeFamily::CwdFallback,
                subject,
                "3ee252717bc9e98b3239e121c81152fe7b77d43d7eac90b60ed143f3233b225b",
            ),
            (
                "decrypt_app",
                GrantScope::decrypt_app(
                    subject,
                    "/Applications/A.app/Contents/MacOS/A",
                    b'0',
                    &salt,
                ),
                Operation::Decrypt,
                ScopeFamily::ParentApp,
                subject,
                "cb5fddec68f2816ed1b606e08ea976ff44caf08e75f32f8dfe8b52c30d8b3dcb",
            ),
            (
                "decrypt_v2",
                GrantScope::decrypt_v2(Some(subject), b'0', &salt, "host", "/repo"),
                Operation::Decrypt,
                ScopeFamily::Connection,
                subject,
                "0edb5650e5dc5c6d84b2096a99d0caf7fb43a5c8d95fa91170e8c2936b075e7d",
            ),
        ];
        for (name, scope, operation, family, subject, digest) in cases {
            let key = scope.key.expect(name);
            assert_eq!(key.operation, operation, "{name}");
            assert_eq!(key.family, family, "{name}");
            assert_eq!(key.subject, subject, "{name}");
            assert_eq!(hex(&key.digest), digest, "{name}");
        }
    }

    #[test]
    fn typed_operation_and_subject_partition_grants() {
        let sign = sign_scope((1, 2), "fp").key.unwrap();
        let other_subject = sign_scope((2, 2), "fp").key.unwrap();
        let decrypt = GrantScope::decrypt_v2(Some((1, 2)), b'0', &[7; 16], "h", "/repo")
            .key
            .unwrap();
        assert_ne!(sign, other_subject);
        assert_ne!(sign.operation, decrypt.operation);
        assert_ne!(sign, decrypt);
    }

    #[test]
    fn sign_scope_partitions_fingerprint_and_pwd() {
        let base = sign_scope((1, 2), "fp-a").key.unwrap();
        let fingerprint = GrantScope::sign(Some((1, 2)), "fp-b", "/repo").key.unwrap();
        let pwd = GrantScope::sign(Some((1, 2)), "fp-a", "/other")
            .key
            .unwrap();
        assert_ne!(base, fingerprint);
        assert_ne!(base, pwd);
    }

    #[test]
    fn decrypt_scope_partitions_type_salt_host_and_pwd() {
        let key = |kind, salt: u8, host: &str, pwd: &str| {
            GrantScope::decrypt_v2(Some((1, 2)), kind, &[salt; 16], host, pwd)
                .key
                .unwrap()
        };
        let base = key(b'0', 1, "host-a", "/repo");
        assert_ne!(base, key(b'1', 1, "host-a", "/repo"));
        assert_ne!(base, key(b'0', 2, "host-a", "/repo"));
        assert_ne!(base, key(b'0', 1, "host-b", "/repo"));
        assert_ne!(base, key(b'0', 1, "host-a", "/other"));
    }

    #[test]
    fn invalidation_bumps_empty_store_epoch_and_blocks_stale_commit() {
        let key = keyed(sign_scope((1, 2), "fp"));
        let mut store = GrantStore::new();
        assert_eq!(store.invalidate_all(), 0);
        assert_eq!(store.epoch, 1);
        assert_eq!(
            store.commit_at(
                0,
                &[key],
                &[],
                Duration::from_secs(120),
                Instant::now(),
                SystemTime::now(),
            ),
            Err(CommitError::Invalidated)
        );
    }

    #[test]
    fn oversized_ttl_fails_without_panicking() {
        let key = keyed(sign_scope((1, 2), "fp"));
        let mut store = GrantStore::new();
        assert_eq!(
            store.commit_at(
                0,
                &[key],
                &[],
                Duration::from_secs(u64::MAX),
                Instant::now(),
                SystemTime::now(),
            ),
            Err(CommitError::InvalidTtl)
        );
    }

    #[tokio::test]
    async fn oversized_ttl_fails_before_prompting() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let failure = engine
            .authorize(AuthorizationRequest::new(
                vec![sign_scope((1, 2), "fp")],
                ReusePolicy::strict_ttl_secs(u64::MAX),
                "sign",
            ))
            .await
            .err()
            .expect("oversized TTL must fail authorization");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(auth.calls.load(Ordering::Acquire), 0);
    }

    /// Pending custody ends with every approval's permit — dropped or
    /// committed alike; a hit owns none.
    #[tokio::test]
    async fn approval_custody_ends_with_permit() {
        struct Custody(AtomicUsize);
        #[async_trait]
        impl AuthorizationAuthenticator for Custody {
            async fn authenticate(&self, _: &str, _: Operation, _: Arc<AtomicBool>) -> AuthOutcome {
                AuthOutcome::Success
            }
            fn approval_complete(&self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let auth = Arc::new(Custody(AtomicUsize::new(0)));
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        drop(engine.authorize(sign_request((1, 2), "fp")).await.unwrap());
        assert_eq!(auth.0.load(Ordering::Acquire), 1);
        engine
            .authorize(sign_request((1, 2), "fp"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(auth.0.load(Ordering::Acquire), 2);
        drop(engine.authorize(sign_request((1, 2), "fp")).await.unwrap());
        assert_eq!(
            auth.0.load(Ordering::Acquire),
            2,
            "hits own no pending custody"
        );
    }

    fn decrypt_request(subject: SubjectId, salts: &[[u8; 16]]) -> AuthorizationRequest {
        AuthorizationRequest::new(
            salts
                .iter()
                .map(|salt| GrantScope::decrypt_v2(Some(subject), b'0', salt, "h", "/repo"))
                .collect(),
            ReusePolicy::strict_ttl_secs(120),
            "decrypt",
        )
    }

    /// Material attached to an approval comes back on the hit in scope order,
    /// including for a repeated scope, and dies with the grants.
    #[tokio::test]
    async fn grant_material_travels_with_the_grant() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let salts = [[1u8; 16], [2u8; 16], [1u8; 16]];
        let deks = vec![
            Zeroizing::new([0xa1; 32]),
            Zeroizing::new([0xb2; 32]),
            Zeroizing::new([0xa1; 32]),
        ];

        let mut permit = engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap();
        assert_eq!(permit.decision(), Decision::Approved);
        assert!(permit.materials().is_empty());
        permit.attach_materials(deks.clone());
        permit.commit().await.unwrap();

        let hit = engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap();
        assert_eq!(hit.decision(), Decision::CacheHit);
        assert_eq!(hit.materials(), &deks[..]);
        let subset = engine
            .authorize(decrypt_request((1, 2), &salts[1..2]))
            .await
            .unwrap();
        assert_eq!(subset.materials(), &deks[1..2]);
        drop(hit);
        drop(subset);
        assert_eq!(auth.calls.load(Ordering::Acquire), 1);

        engine.invalidate_all().await;
        let fresh = engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap();
        assert_eq!(fresh.decision(), Decision::Approved);
        assert!(fresh.materials().is_empty());
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    /// A hit over grants that carry no material serves none, and a grant
    /// committed without material never gains one from a later hit.
    #[tokio::test]
    async fn grant_without_material_serves_none() {
        let engine =
            AuthorizationEngine::new(SuccessAuthenticator::new(), AllowValidator::allowed());
        let salts = [[1u8; 16], [2u8; 16]];
        let mut permit = engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap();
        permit.attach_materials(vec![Zeroizing::new([7; 32])]);
        assert_eq!(
            permit.commit().await,
            Err(CommitError::MaterialMismatch),
            "partial material never commits"
        );
        engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let hit = engine
            .authorize(decrypt_request((1, 2), &salts))
            .await
            .unwrap();
        assert_eq!(hit.decision(), Decision::CacheHit);
        assert!(hit.materials().is_empty());
    }

    /// Direct-store: material follows expiry — an expired entry re-approved
    /// under the same key takes the new material, a live one keeps its own,
    /// and a swept entry is gone. Debug output never renders material bytes.
    #[test]
    fn store_material_follows_expiry_and_stays_out_of_debug() {
        let key = keyed(GrantScope::decrypt_v2(
            Some((1, 2)),
            b'0',
            &[7; 16],
            "h",
            "/repo",
        ));
        let keys = std::slice::from_ref(&key);
        let ttl = Duration::from_secs(120);
        let mut store = GrantStore::new();
        let m0 = Instant::now();
        let w0 = SystemTime::now();
        let first = [Zeroizing::new([0x5a; 32])];
        store.commit_at(0, keys, &first, ttl, m0, w0).unwrap();
        let lookup = store.lookup_at(keys, ttl, m0 + ttl / 2, w0 + ttl / 2);
        assert_eq!(lookup.materials, first.to_vec());

        let rendered = format!("{store:?}");
        assert!(rendered.contains("material: true"), "{rendered}");
        assert!(!rendered.contains("90, 90, 90"), "{rendered}");
        assert!(!rendered.contains("5a5a5a"), "{rendered}");

        // Live entry, equal TTL: untouched.
        let second = [Zeroizing::new([0x6b; 32])];
        store
            .commit_at(0, keys, &second, ttl, m0 + ttl / 2, w0 + ttl / 2)
            .unwrap();
        assert_eq!(
            store
                .lookup_at(keys, ttl, m0 + ttl / 2, w0 + ttl / 2)
                .materials,
            first.to_vec()
        );
        // Expired entry: refreshed with the new material.
        let later_m = m0 + ttl * 2;
        let later_w = w0 + ttl * 2;
        store
            .commit_at(0, keys, &second, ttl, later_m, later_w)
            .unwrap();
        assert_eq!(
            store.lookup_at(keys, ttl, later_m, later_w).materials,
            second.to_vec()
        );
        assert!(store
            .lookup_at(keys, ttl, later_m + ttl, later_w + ttl)
            .materials
            .is_empty());
        store.sweep_expired_at(later_m + ttl, later_w + ttl);
        assert!(store.entries.is_empty());

        assert_eq!(
            store.commit_at(0, keys, &[first[0].clone(), second[0].clone()], ttl, m0, w0),
            Err(CommitError::MaterialMismatch)
        );
        assert!(store.entries.is_empty(), "a mismatch writes nothing");
    }

    #[tokio::test]
    async fn grant_is_written_only_after_operation_commits_permit() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let permit = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
        assert!(matches!(permit.decision(), Decision::Approved));
        drop(permit);

        let permit = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
        assert!(matches!(permit.decision(), Decision::Approved));
        permit.commit().await.unwrap();

        let hit = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
        assert_eq!(hit.decision(), Decision::CacheHit);
        hit.commit().await.unwrap();
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn ttl_policy_tightening_requires_fresh_approval() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let request = |ttl| {
            AuthorizationRequest::new(
                vec![sign_scope((1, 2), "fp")],
                ReusePolicy::strict_ttl_secs(ttl),
                "sign",
            )
        };

        engine
            .authorize(request(120))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let tighter = engine.authorize(request(30)).await.unwrap();
        assert!(matches!(tighter.decision(), Decision::Approved));
        tighter.commit().await.unwrap();
        let hit = engine.authorize(request(30)).await.unwrap();
        assert_eq!(hit.decision(), Decision::CacheHit);
        hit.commit().await.unwrap();
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn empty_scope_set_fails_closed_without_prompting() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let failure = engine
            .authorize(AuthorizationRequest::new(
                Vec::new(),
                ReusePolicy::strict_ttl_secs(30),
                "empty",
            ))
            .await
            .err()
            .expect("empty scope set must fail");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(auth.calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn duplicate_scopes_create_one_live_grant() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
        let scope = sign_scope((1, 2), "fp");
        let permit = engine
            .authorize(AuthorizationRequest::new(
                vec![scope.clone(), scope],
                ReusePolicy::strict_ttl_secs(30),
                "sign",
            ))
            .await
            .unwrap();
        permit.commit().await.unwrap();
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            1
        );
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (2, 2))
                .await,
            0
        );
        assert_eq!(
            engine
                .live_len(Operation::Decrypt, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn live_len_filters_by_scope_family() {
        // A workspace grant and a cwd-fallback grant can share a (dev, ino)
        // subject (the same directory before/after `git init`); diag counts
        // must not report the other family's grants as reusable.
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
        let subject = (7, 42);
        let permit = engine
            .authorize(AuthorizationRequest::new(
                vec![GrantScope::sign_cwd(subject, "/dir", "fp")],
                ReusePolicy::strict_ttl_secs(30),
                "sign",
            ))
            .await
            .unwrap();
        permit.commit().await.unwrap();
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::CwdFallback, subject)
                .await,
            1
        );
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Workspace, subject)
                .await,
            0
        );
    }

    #[tokio::test]
    async fn rejection_and_unavailable_never_grant() {
        for outcome in [
            AuthOutcome::Rejected,
            AuthOutcome::Unavailable(UnavailableReason::NoGuiSession),
            AuthOutcome::Unavailable(UnavailableReason::BiometryUnavailable),
        ] {
            let auth = Arc::new(FixedAuthenticator {
                calls: AtomicUsize::new(0),
                outcome,
            });
            let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
            assert!(engine.authorize(sign_request((1, 2), "fp")).await.is_err());
            assert_eq!(
                engine
                    .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                    .await,
                0
            );
        }
    }

    struct UnavailableOnSecondAuthenticator {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for UnavailableOnSecondAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            match self.calls.fetch_add(1, Ordering::AcqRel) {
                1 => {
                    revocation_pending.store(true, Ordering::Release);
                    AuthOutcome::Unavailable(UnavailableReason::NotInteractive)
                }
                _ => AuthOutcome::Success,
            }
        }
    }

    /// Touch ID locked out / not enrolled is reported without a prompt and
    /// without touching the latch itself; the engine still publishes
    /// revocation, drops standing grants, and writes no new one.
    struct BiometryUnavailableOnSecondAuthenticator {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for BiometryUnavailableOnSecondAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            match self.calls.fetch_add(1, Ordering::AcqRel) {
                1 => AuthOutcome::Unavailable(UnavailableReason::BiometryUnavailable),
                _ => AuthOutcome::Success,
            }
        }
    }

    #[tokio::test]
    async fn biometry_unavailable_revokes_grants_and_grants_nothing() {
        let auth = Arc::new(BiometryUnavailableOnSecondAuthenticator {
            calls: AtomicUsize::new(0),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            1
        );

        let failure = engine
            .authorize(sign_request((3, 4), "no biometry"))
            .await
            .err()
            .expect("biometry unavailable");
        assert_eq!(
            failure.decision(),
            Decision::Unavailable(UnavailableReason::BiometryUnavailable)
        );
        assert_eq!(failure.decision().audit_outcome(), "unavailable");
        for subject in [(1, 2), (3, 4)] {
            assert_eq!(
                engine
                    .live_len(Operation::Sign, ScopeFamily::Connection, subject)
                    .await,
                0
            );
        }
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn prompt_unavailable_revokes_preexisting_grants() {
        let auth = Arc::new(UnavailableOnSecondAuthenticator {
            calls: AtomicUsize::new(0),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        let failure = engine
            .authorize(sign_request((1, 2), "unavailable"))
            .await
            .err()
            .expect("second prompt must be unavailable");
        assert_eq!(
            failure.decision(),
            Decision::Unavailable(UnavailableReason::NotInteractive)
        );
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );

        let retry = engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap();
        assert!(matches!(retry.decision(), Decision::Approved));
        drop(retry);
        assert_eq!(auth.calls.load(Ordering::Acquire), 3);
    }

    struct BlockingUnavailableAuthenticator {
        calls: AtomicUsize,
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for BlockingUnavailableAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                return AuthOutcome::Success;
            }
            self.entered.notify_one();
            self.release.notified().await;
            AuthOutcome::Unavailable(UnavailableReason::NotInteractive)
        }
    }

    #[tokio::test]
    async fn cancelled_unavailable_prompt_still_revokes_preexisting_grants() {
        let auth = Arc::new(BlockingUnavailableAuthenticator {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        let request_engine = Arc::clone(&engine);
        let request = tokio::spawn(async move {
            request_engine
                .authorize(sign_request((1, 2), "unavailable"))
                .await
        });
        auth.entered.notified().await;
        request.abort();
        match request.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("cancelled authorization unexpectedly completed"),
        }
        auth.release.notify_one();

        tokio::time::timeout(Duration::from_secs(1), async {
            while engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await
                != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached unavailable prompt did not revoke old grants");
        assert_eq!(engine.store.read().await.epoch, 1);
        assert!(!engine.revocation_pending.load(Ordering::Acquire));
        assert!(!engine.revoker_running.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn different_reusable_scopes_do_not_coalesce() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        for fingerprint in ["fp-a", "fp-b"] {
            let permit = engine
                .authorize(sign_request((1, 2), fingerprint))
                .await
                .unwrap();
            permit.commit().await.unwrap();
        }
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn fresh_policy_never_reuses() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        for _ in 0..2 {
            let permit = engine
                .authorize(AuthorizationRequest::fresh(
                    GrantScope::fresh(Operation::Auth),
                    "auth",
                ))
                .await
                .unwrap();
            permit.commit().await.unwrap();
        }
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
        assert_eq!(
            engine
                .live_len(Operation::Auth, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn missing_subject_makes_strict_ttl_request_effectively_fresh() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        for _ in 0..2 {
            engine
                .authorize(AuthorizationRequest::new(
                    vec![GrantScope::sign(None, "fp", "/repo")],
                    ReusePolicy::strict_ttl_secs(30),
                    "sign",
                ))
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
        }
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn operation_subject_and_resource_are_runtime_isolation_boundaries() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let digest = [7; 32];
        let base = GrantScope::reusable(Operation::Sign, ScopeFamily::Connection, (1, 2), digest);
        engine
            .authorize(AuthorizationRequest::new(
                vec![base.clone()],
                ReusePolicy::strict_ttl_secs(30),
                "base",
            ))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        let hit = engine
            .authorize(AuthorizationRequest::new(
                vec![base],
                ReusePolicy::strict_ttl_secs(30),
                "hit",
            ))
            .await
            .unwrap();
        assert_eq!(hit.decision(), Decision::CacheHit);
        hit.commit().await.unwrap();

        for isolated in [
            GrantScope::reusable(Operation::Decrypt, ScopeFamily::Connection, (1, 2), digest),
            GrantScope::reusable(Operation::Sign, ScopeFamily::Connection, (2, 2), digest),
            GrantScope::reusable(Operation::Sign, ScopeFamily::Connection, (1, 2), [8; 32]),
        ] {
            let permit = engine
                .authorize(AuthorizationRequest::new(
                    vec![isolated],
                    ReusePolicy::strict_ttl_secs(30),
                    "isolated",
                ))
                .await
                .unwrap();
            assert!(matches!(permit.decision(), Decision::Approved));
            drop(permit);
        }
        assert_eq!(auth.calls.load(Ordering::Acquire), 4);
    }

    #[tokio::test]
    async fn mixed_operation_scope_set_fails_closed_without_prompting() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let failure = engine
            .authorize(AuthorizationRequest::new(
                vec![
                    GrantScope::fresh(Operation::Sign),
                    GrantScope::fresh(Operation::Decrypt),
                ],
                ReusePolicy::Fresh,
                "mixed",
            ))
            .await
            .err()
            .expect("mixed operation request must fail");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(auth.calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn mixed_subject_scope_set_fails_closed_without_prompting() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let failure = engine
            .authorize(AuthorizationRequest::new(
                vec![sign_scope((1, 2), "fp-a"), sign_scope((2, 2), "fp-b")],
                ReusePolicy::strict_ttl_secs(30),
                "mixed subjects",
            ))
            .await
            .err()
            .expect("mixed subject request must fail");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(auth.calls.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn concurrent_same_scope_singleflights_to_one_prompt() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let permit = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
                let decision = permit.decision();
                permit.commit().await.unwrap();
                decision
            }));
        }
        barrier.wait().await;
        let a = tasks.remove(0).await.unwrap();
        let b = tasks.remove(0).await.unwrap();
        assert!(matches!(a, Decision::Approved | Decision::CacheHit));
        assert!(matches!(b, Decision::Approved | Decision::CacheHit));
        assert_ne!(a, b);
        assert_eq!(auth.calls.load(Ordering::Acquire), 1);
    }

    struct BlockingAuthenticator {
        calls: AtomicUsize,
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for BlockingAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.notify_one();
            self.release.notified().await;
            AuthOutcome::Success
        }
    }

    #[tokio::test]
    async fn concurrent_fresh_requests_serialize_but_never_coalesce() {
        let auth = Arc::new(BlockingAuthenticator {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let mut requests = Vec::new();
        for _ in 0..2 {
            let engine = Arc::clone(&engine);
            requests.push(tokio::spawn(async move {
                let permit = engine
                    .authorize(AuthorizationRequest::fresh(
                        GrantScope::fresh(Operation::Run),
                        "run",
                    ))
                    .await
                    .unwrap();
                assert!(matches!(permit.decision(), Decision::Approved));
                permit.commit().await.unwrap();
            }));
        }

        auth.entered.notified().await;
        tokio::task::yield_now().await;
        assert_eq!(auth.calls.load(Ordering::Acquire), 1);
        auth.release.notify_one();
        auth.entered.notified().await;
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
        auth.release.notify_one();
        for request in requests {
            request.await.unwrap();
        }
        assert_eq!(
            engine
                .live_len(Operation::Run, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn invalidation_during_prompt_revokes_authorization() {
        let auth = Arc::new(BlockingAuthenticator {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let request_engine = Arc::clone(&engine);
        let request =
            tokio::spawn(async move { request_engine.authorize(sign_request((1, 2), "fp")).await });
        auth.entered.notified().await;
        assert_eq!(engine.invalidate_all().await, 0);

        auth.release.notify_one();
        let failure = request
            .await
            .unwrap()
            .err()
            .expect("in-flight prompt must be revoked");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn cache_hit_revalidates_live_security_state() {
        let auth = SuccessAuthenticator::new();
        let validator = AllowValidator::allowed();
        let engine = AuthorizationEngine::new(auth.clone(), validator.clone());
        engine
            .authorize(sign_request((1, 2), "fp"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        validator.allowed.store(false, Ordering::Release);

        let failure = engine
            .authorize(sign_request((1, 2), "fp"))
            .await
            .err()
            .expect("a stale hit must fail live validation");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(auth.calls.load(Ordering::Acquire), 1);

        validator.allowed.store(true, Ordering::Release);
        let retry = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
        assert!(matches!(retry.decision(), Decision::Approved));
        drop(retry);
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn approval_revalidates_live_security_state_after_prompt() {
        let auth = Arc::new(BlockingAuthenticator {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let validator = AllowValidator::allowed();
        let engine = AuthorizationEngine::new(auth.clone(), validator.clone());
        let request_engine = Arc::clone(&engine);
        let request =
            tokio::spawn(async move { request_engine.authorize(sign_request((1, 2), "fp")).await });
        auth.entered.notified().await;
        validator.allowed.store(false, Ordering::Release);
        auth.release.notify_one();

        let failure = request
            .await
            .unwrap()
            .err()
            .expect("post-prompt live validation must fail");
        assert_eq!(failure.decision(), Decision::Invalidated);
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    struct ConcurrentInvalidValidator {
        armed: AtomicBool,
        calls: AtomicUsize,
        completions: AtomicUsize,
        barrier: Barrier,
    }

    impl AuthorizationValidator for ConcurrentInvalidValidator {
        fn validate(&self, revocation_pending: &AtomicBool) -> Result<(), ValidationError> {
            if !self.armed.load(Ordering::Acquire) {
                return Ok(());
            }
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            if call == 1 {
                revocation_pending.store(true, Ordering::Release);
            }
            self.barrier.wait();
            if call == 1 {
                Err(ValidationError::Invalidated)
            } else {
                Ok(())
            }
        }

        fn invalidation_complete(&self) {
            self.armed.store(false, Ordering::Release);
            self.completions.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_readers_cannot_cross_pending_revocation() {
        let auth = SuccessAuthenticator::new();
        let validator = Arc::new(ConcurrentInvalidValidator {
            armed: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            completions: AtomicUsize::new(0),
            barrier: Barrier::new(2),
        });
        let engine = AuthorizationEngine::new(auth.clone(), validator.clone());
        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        validator.armed.store(true, Ordering::Release);
        let mut readers = Vec::new();
        for _ in 0..2 {
            let engine = Arc::clone(&engine);
            readers.push(tokio::spawn(async move {
                engine.authorize(sign_request((1, 2), "cached")).await
            }));
        }
        for reader in readers {
            assert!(reader.await.unwrap().is_err());
        }
        assert_eq!(validator.calls.load(Ordering::Acquire), 2);
        assert_eq!(validator.completions.load(Ordering::Acquire), 1);
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );

        let retry = engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap();
        assert!(matches!(retry.decision(), Decision::Approved));
        drop(retry);
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simultaneous_revocation_observations_share_one_epoch() {
        const OBSERVERS: usize = 32;

        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        let published = Arc::new(tokio::sync::Barrier::new(OBSERVERS + 1));
        let mut observers = Vec::with_capacity(OBSERVERS);
        for _ in 0..OBSERVERS {
            let engine = Arc::clone(&engine);
            let published = Arc::clone(&published);
            observers.push(tokio::spawn(async move {
                engine.revocation_pending.store(true, Ordering::Release);
                published.wait().await;
                engine.drain_pending_revocation().await
            }));
        }
        published.wait().await;

        let mut dropped = 0;
        for observer in observers {
            dropped += observer.await.unwrap();
        }
        assert_eq!(dropped, 1);
        assert_eq!(engine.store.read().await.epoch, 1);
        assert_eq!(engine.revocation_generation.load(Ordering::Acquire), 1);
        assert!(!engine.revocation_pending.load(Ordering::Acquire));
        assert!(!engine.revoker_running.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn revocation_waiter_recovers_orphaned_pending_state() {
        let engine =
            AuthorizationEngine::new(SuccessAuthenticator::new(), AllowValidator::allowed());
        engine.revocation_pending.store(true, Ordering::Release);
        // Model a waiter that initially observes an exiting revoker. The
        // synthetic completion then exposes pending=true/running=false, the
        // cross-atomic hand-off state that must be reclaimed rather than wait
        // forever for a revoker that no longer exists.
        engine.revoker_running.store(true, Ordering::Release);
        let waiting_engine = Arc::clone(&engine);
        let waiter = tokio::spawn(async move { waiting_engine.drain_pending_revocation().await });
        while engine.revocation_completed.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        engine.revoker_running.store(false, Ordering::Release);
        engine.revocation_completed.send_replace(1);

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("orphaned revocation waiter hung")
                .unwrap(),
            0
        );
        assert_eq!(engine.store.read().await.epoch, 1);
        assert!(!engine.revocation_pending.load(Ordering::Acquire));
        assert!(!engine.revoker_running.load(Ordering::Acquire));
    }

    struct SignalingValidator {
        allowed: AtomicBool,
        invalid_seen: Notify,
    }

    impl AuthorizationValidator for SignalingValidator {
        fn validate(&self, revocation_pending: &AtomicBool) -> Result<(), ValidationError> {
            if self.allowed.load(Ordering::Acquire) {
                Ok(())
            } else {
                revocation_pending.store(true, Ordering::Release);
                self.invalid_seen.notify_one();
                Err(ValidationError::Invalidated)
            }
        }
    }

    #[tokio::test]
    async fn observed_invalid_state_revokes_even_if_request_is_cancelled() {
        let auth = SuccessAuthenticator::new();
        let validator = Arc::new(SignalingValidator {
            allowed: AtomicBool::new(true),
            invalid_seen: Notify::new(),
        });
        let engine = AuthorizationEngine::new(auth.clone(), validator.clone());

        engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let active = engine
            .authorize(sign_request((1, 2), "active"))
            .await
            .unwrap();

        validator.allowed.store(false, Ordering::Release);
        let failing_engine = Arc::clone(&engine);
        let failing = tokio::spawn(async move {
            failing_engine
                .authorize(sign_request((1, 2), "cached"))
                .await
        });
        validator.invalid_seen.notified().await;
        failing.abort();
        match failing.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("cancelled validation unexpectedly completed"),
        }

        validator.allowed.store(true, Ordering::Release);
        active.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await
                != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached revocation did not complete");

        let retry = engine
            .authorize(sign_request((1, 2), "cached"))
            .await
            .unwrap();
        assert!(matches!(retry.decision(), Decision::Approved));
        drop(retry);
        assert_eq!(auth.calls.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn cancelled_authorize_keeps_prompt_serialized_until_authenticator_finishes() {
        let auth = Arc::new(BlockingAuthenticator {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());

        let first_engine = Arc::clone(&engine);
        let first =
            tokio::spawn(
                async move { first_engine.authorize(sign_request((1, 2), "first")).await },
            );
        auth.entered.notified().await;
        first.abort();
        match first.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("aborted authorization unexpectedly completed"),
        }

        let second_engine = Arc::clone(&engine);
        let second = tokio::spawn(async move {
            let permit = second_engine
                .authorize(sign_request((1, 2), "second"))
                .await
                .unwrap();
            permit.commit().await.unwrap();
        });
        tokio::task::yield_now().await;
        assert_eq!(auth.calls.load(Ordering::Acquire), 1);

        auth.release.notify_one();
        auth.entered.notified().await;
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
        auth.release.notify_one();
        second.await.unwrap();
    }

    #[tokio::test]
    async fn invalidation_waits_for_active_operation_permit() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
        let permit = engine.authorize(sign_request((1, 2), "fp")).await.unwrap();
        let invalidate_engine = Arc::clone(&engine);
        let invalidate = tokio::spawn(async move { invalidate_engine.invalidate_all().await });
        tokio::task::yield_now().await;
        assert!(!invalidate.is_finished());
        permit.commit().await.unwrap();
        assert_eq!(invalidate.await.unwrap(), 1);
        assert_eq!(
            engine
                .live_len(Operation::Sign, ScopeFamily::Connection, (1, 2))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn partial_batch_prompts_once_then_becomes_full_hit() {
        let auth = SuccessAuthenticator::new();
        let engine = AuthorizationEngine::new(auth.clone(), AllowValidator::allowed());
        let a = GrantScope::decrypt_v2(Some((1, 2)), b'0', &[1; 16], "h", "/p");
        let b = GrantScope::decrypt_v2(Some((1, 2)), b'0', &[2; 16], "h", "/p");
        let first = engine
            .authorize(AuthorizationRequest::new(
                vec![a.clone()],
                ReusePolicy::strict_ttl_secs(30),
                "decrypt",
            ))
            .await
            .unwrap();
        first.commit().await.unwrap();
        let partial = engine
            .authorize(AuthorizationRequest::new(
                vec![a.clone(), b.clone()],
                ReusePolicy::strict_ttl_secs(30),
                "decrypt",
            ))
            .await
            .unwrap();
        assert!(matches!(partial.decision(), Decision::Approved));
        partial.commit().await.unwrap();
        let full = engine
            .authorize(AuthorizationRequest::new(
                vec![a, b],
                ReusePolicy::strict_ttl_secs(30),
                "decrypt",
            ))
            .await
            .unwrap();
        assert_eq!(full.decision(), Decision::CacheHit);
        full.commit().await.unwrap();
        assert_eq!(auth.calls.load(Ordering::Acquire), 2);
    }

    struct ApproveThenRejectAuthenticator {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthorizationAuthenticator for ApproveThenRejectAuthenticator {
        async fn authenticate(
            &self,
            _prompt: &str,
            _operation: Operation,
            _revocation_pending: Arc<AtomicBool>,
        ) -> AuthOutcome {
            match self.calls.fetch_add(1, Ordering::AcqRel) {
                0 => AuthOutcome::Success,
                _ => AuthOutcome::Rejected,
            }
        }
    }

    #[tokio::test]
    async fn rejected_partial_batch_preserves_existing_grants_and_adds_none() {
        let auth = Arc::new(ApproveThenRejectAuthenticator {
            calls: AtomicUsize::new(0),
        });
        let engine = AuthorizationEngine::new(auth, AllowValidator::allowed());
        let a = GrantScope::decrypt_v2(Some((1, 2)), b'0', &[1; 16], "h", "/p");
        let b = GrantScope::decrypt_v2(Some((1, 2)), b'0', &[2; 16], "h", "/p");
        engine
            .authorize(AuthorizationRequest::new(
                vec![a.clone()],
                ReusePolicy::strict_ttl_secs(30),
                "first",
            ))
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();

        let failure = engine
            .authorize(AuthorizationRequest::new(
                vec![a, b],
                ReusePolicy::strict_ttl_secs(30),
                "partial",
            ))
            .await
            .err()
            .expect("second prompt is rejected");
        assert_eq!(failure.decision(), Decision::Rejected);
        assert_eq!(
            engine
                .live_len(Operation::Decrypt, ScopeFamily::Connection, (1, 2))
                .await,
            1
        );
    }
}
