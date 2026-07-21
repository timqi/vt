# Unified SSH-agent authorization engine

Status: **implemented**

This document defines the V1 refactor that routes `auth@vt`, `run@vt`, raw
SSH signing, `sign@vt`, and `decrypt@vt` through one authorization engine.
It replaces duplicated prompt/cache state machines without making every
operation equally reusable.

## 1. Decision

Unify the authorization mechanism, not the risk policy:

| Operation | V1 reuse policy | Existing behavior |
|---|---|---|
| raw SSH sign / `sign@vt` | configured strict TTL | preserved |
| pure-v2 `decrypt@vt` | configured strict TTL | preserved |
| legacy-containing `decrypt@vt` | fresh | preserved |
| `auth@vt` | fresh | preserved |
| `run@vt` | fresh | preserved |

`Fresh` is a first-class policy. It never reads or writes grants; it is not
implemented as a zero-second TTL. `auth` and `run` still use the same scope,
prompt serialization, epoch validation, typed decision, permit, and audit
path as reusable operations.

V1 does not add CLI flags, change the extension wire format, or make
client-reported command text a security boundary. Future caching for `auth`
or `run` requires structured scopes described in section 11.

## 2. Goals

1. One state machine for cache lookup, prompt serialization, authentication,
   invalidation, and grant commit.
2. One in-memory grant store, partitioned by typed operation and subject.
3. Preserve current sign/decrypt cache keys, TTLs, diagnostics, audit labels,
   and full-batch decrypt semantics.
4. Route `auth` and `run` through the engine while keeping them fresh.
5. Fix the clear-versus-in-flight-prompt race with an epoch and security gate.
6. Do not create a grant when the authorized operation itself fails.
7. Keep the authorization state machine platform-neutral and deterministically
   testable without Touch ID or Keychain access.

## 3. Non-goals

- Workspace/repository discovery and normalized command intents.
- Caching `auth@vt` or `run@vt` in V1.
- Implementing OpenSSH `session-bind@openssh.com` or destination constraints.
- Changing the Worker DEK cache.
- Combining authorization decisions with secret/signature execution code.
- Persisting grants across agent restarts.

## 4. Model

The reusable lookup identity is:

```text
GrantKey = Operation x SubjectId x ResourceDigest
```

`Operation` is typed and always participates in equality:

```rust
enum Operation {
    Auth,
    Run,
    Sign,
    Decrypt,
}
```

This prevents cross-capability reuse even if two resource digests happen to
contain equivalent source material. Raw SSH sign and `sign@vt` intentionally
share `Operation::Sign`, matching current behavior. Their existing `pwd`
inputs still usually partition them because raw agent requests have no
`ClientMeta` and use an empty `pwd`.

`SubjectId` is the existing `(context_id, process_start_time)` context. The
macOS adapter continues to derive it from session leader, app ancestor,
global, ssh process, or vt relay classification. A missing subject makes a
configured reusable request effectively fresh.

`ResourceDigest` remains domain-separated:

- sign: fingerprint + client-reported `pwd`;
- decrypt: secret type + salt + client-reported host + `pwd`.

The store never retains raw host, path, command, reason, key material, DEK, or
signature data.

## 5. Policies and decisions

```rust
enum ReusePolicy {
    Fresh,
    StrictTtl(Duration),
}

enum Decision {
    CacheHit,
    Approved(AuthMethod),
    Rejected,
    Unavailable(UnavailableReason),
    Invalidated,
}
```

Successful authorization returns a non-cloneable `AuthorizationPermit`, not
a boolean. A failed authorization returns an `AuthorizationFailure` carrying
the failure `Decision` and latency. The permit records the success decision and owns the synchronization
guards needed to linearize the operation against invalidation.

Failure mapping remains stable:

| Engine failure | Extension error | Raw SSH sign |
|---|---|---|
| rejected | `AuthRejected` | agent failure |
| not interactive | `SessionLocked` | agent failure |
| no GUI session | `NoGuiSession` | agent failure |
| revoked during authorization | `Transient` | agent failure |

`Invalidated` uses a static detail string only. It never reflects request data.

## 6. Authorization state machine

All four operation families follow this sequence:

```text
handler validation and policy checks
  -> build typed scope and reuse policy
  -> reusable full-set lookup
       hit -> live security validation -> permit(CacheHit)
              unsafe -> publish revocation latch -> invalidate -> failure
       miss/fresh
  -> acquire the global prompt permit
  -> reusable full-set lookup again
       hit -> live security validation -> permit(CacheHit)
       miss/fresh
  -> capture epoch
  -> invoke the injected authenticator
       reject -> failure, no grant
       unavailable -> publish revocation latch -> invalidate -> failure
  -> acquire security read gate
  -> compare epoch and revalidate locked/interactive state
       changed/invalid -> failure, no grant
  -> permit(Approved, pending grant)
  -> handler executes and serializes the already-validated operation
       failure -> drop permit, no grant
  -> extension dispatcher builds and encrypts the success envelope
       failure -> drop permit, no grant
       success -> permit.commit()
  -> return encrypted result
```

Raw SSH signing has no extension envelope: it commits after signature
generation succeeds. Decision audit is emitted when authorization resolves;
operation-specific failure audit (for example `run` spawn failure) remains
separate from grant commit.

The prompt semaphore remains held by an approval permit until commit or drop.
Consequently, a same-scope waiter cannot slip between approval and grant: it
rechecks only after the first operation has either committed its grant or
failed without one.

No grant-store lock, agent-lock lock, or security write gate is held while a
human prompt is displayed.

A live permit holds the global prompt slot and a security read guard until
commit or drop. Handlers therefore must not perform unbounded-latency work
while a permit is live: a slow handler delays every other prompt-requiring
request and stalls lock/wake revocation, which waits for outstanding permits.
Today's handlers only sign, derive, spawn, and serialize locally; keep it
that way.

## 7. Permit and invalidation linearization

The engine owns:

```text
epoch: generation protected by the grant-store lock
revocation_pending: atomic latch
revoker_running: atomic single-revoker claim
security_gate: async RwLock
grant_store: async RwLock<HashMap<GrantKey, CacheExpiry>>
prompt_sem: one-permit semaphore
```

An `AuthorizationPermit` owns a security read guard through the sensitive
operation. An invalidator takes the security write guard, increments the epoch,
and clears the store. This defines a deterministic order:

- if the operation obtained its permit first, it completes before lock/wake/
  idle invalidation completes;
- if invalidation obtained the write gate first, the pending authorization
  observes a changed epoch and cannot execute or grant.

Every completed revocation cycle increments the epoch even when the grant store
is empty. Concurrent observations are coalesced into one cycle. This is required
to revoke a prompt that is currently displayed before it has created any entry.

Unsafe live validation publishes `revocation_pending` synchronously before it
returns. Concurrent readers recheck that latch before receiving a permit. One
CAS-claimed, cancellation-safe revoker clears the store and advances the epoch;
concurrent failures wait for that revoker instead of queueing duplicate writers.
Waiters retry the CAS claim after every completion notification, so a
cross-atomic hand-off cannot leave `revocation_pending=true` without an owner.
The detached prompt worker drains revocation itself on `Unavailable`, even if
the requesting connection was cancelled while the system prompt was visible.

Invalidation sources are:

- `ssh-add -x` agent lock;
- idle timeout;
- interactive to locked/off-console transition;
- sleep/wake clock divergence.

Cache-hit and post-prompt paths both perform an uncached macOS session-state
check. The five-second watcher is revocation backup and cleanup, not the sole
hit-path security gate. The macOS validator also compares monotonic and wall
clock progress so a detected wake is rejected before the next watcher tick.

## 8. Grant commit and TTL

Fresh approval does not immediately write the reusable grant. The pending
grant is committed only after the handler successfully signs, derives and
serializes the decrypt result, or completes its operation-specific success
point. Extension grants commit only after the success envelope is serialized
and encrypted. If any of those steps fails, dropping the permit writes nothing.

Grant commit is all-or-nothing for the deduplicated scope set and checks the
captured epoch again under the security read gate.

Expiry retains the existing rules:

- both monotonic and wall deadlines are stored;
- an entry is valid only while both clocks are before their deadlines;
- a still-valid re-grant does not extend either deadline;
- an expired entry may be replaced after a fresh approval;
- one batch captures one clock pair and one deadline.

Duration construction uses checked arithmetic both before lookup/prompt and at
commit; hostile configuration fails closed without prompting or executing the
protected operation and cannot panic the agent.

## 9. Operation adapters

### Sign

Raw `SIGN_REQUEST` and `sign@vt` complete key lookup and request validation
before authorization. Both submit one sign resource and the configured sign
policy. A successful signature is produced before the permit commits a new
grant.

### Decrypt

Parsing, size limits, empty-batch rejection, `UNKNOWN` rejection, legacy
policy, and key-store availability all precede reusable lookup.

Pure-v2 batches submit one resource per `(type, salt)`. A cache hit requires
all resources. A partial hit prompts once and a successful operation commits
the complete deduplicated set. A rejected or failed request preserves existing
entries and adds none. Any legacy item makes the whole request fresh.

### Auth

`auth@vt` submits `Operation::Auth` with `Fresh`. It uses the same prompt,
epoch, live-state validation, permit, decision mapping, and audit path, but
never looks up or writes a grant.

### Run

`run@vt` parses limits, resolves the canonical executable against the
allowlist, and builds its sanitized prompt before authorization. It submits
`Operation::Run` with `Fresh`. Spawn happens while the permit is live. A spawn
failure drops the permit and retains the existing second `spawn_failed` audit
event.

A future reusable run policy must not be able to bypass these validations.

## 10. Diagnostics and audit

The `diag@vt` wire shape remains unchanged. Sign/decrypt live counts query the
unified store with both operation and current context, so counts remain scoped
to the caller. Mode, TTL, and context basis still come from existing configs.

Audit operation labels remain unchanged (`sign`, `ssh-sign`, `decrypt`,
`auth`, `run`). Engine decisions map to the existing outcomes:

- cache hit -> `cache_hit`, latency `0`;
- fresh approval -> `approved`;
- rejection -> `rejected`;
- unavailable or revoked -> `unavailable`.

Audit is observational and never authorizes an operation.

## 11. Future auth/run reuse

The V1 engine supports reusable policies for any typed operation, but V1 does
not define cacheable scopes for `auth` or `run`.

Before enabling them:

- auth needs structured service, target user, TTY/PAM session, and consumer
  identity; free-form `reason` is display metadata only;
- run needs an explicit allowlist rule opt-in, canonical executable identity,
  full argv digest, fixed cwd/environment profile, policy version, short TTL,
  and preferably `max_uses`/rate limiting.

These additions require a separate security review and user-visible policy.

## 12. Forwarding limitation

The existing ssh/vt relay context remains process-based, not a cryptographically
verified SSH destination. V1 preserves that behavior but must not describe it
as destination-bound.

Implementing `session-bind@openssh.com` requires host-key signature validation,
duplicate session-id rejection, authentication-versus-forwarding separation,
and binding consistency. Until then, forwarding retains its documented
per-process risk and should stay uncached on untrusted hosts.

## 13. Test requirements

Cross-platform engine tests must cover:

1. Fresh always prompts and never creates a grant.
2. Reusable first approval then cache hit.
3. Operation, subject, and resource isolation.
4. Full, partial, duplicate, and empty resource sets.
5. Rejected/unavailable outcomes never grant.
6. Same-scope concurrent misses produce one prompt.
7. Different scopes and Fresh requests do not coalesce incorrectly.
8. Invalidation during a prompt returns revoked and cannot commit.
9. Invalidation waits for an active operation permit.
10. Failed operation drops a pending grant.
11. Strict dual-clock TTL and non-sliding re-grant.
12. Live counts remain operation/context scoped.

macOS adapter and handler verification must cover:

- live locked/interactive checks on hit and post-prompt paths;
- sign and `sign@vt` using the same typed operation;
- pure-v2 full/partial hit and legacy-fresh behavior;
- auth/run always traversing the engine as Fresh;
- run validation occurring before authorization;
- lock/idle/wake invalidation;
- unchanged structured-error, audit, and diagnostic output.

## 14. Migration and completion criteria

Migration is a direct replacement, not dual-write:

1. Add and test the platform-neutral engine.
2. Add the macOS authenticator/session-state adapter.
3. Migrate sign, decrypt, auth, then run handlers.
4. Replace both old caches and the standalone prompt semaphore.
5. Switch lock/idle/wake invalidation and diagnostic counts.
6. Delete old decisions, cache helpers, and duplicated state machines.
7. Update repository invariants and implementation documentation.

The refactor is complete only when all four operations call the same engine,
the old cache/prompt decision paths are absent, the race and concurrency tests
pass, and the repository Rust checks pass on macOS and Linux CI targets.
