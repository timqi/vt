# Unified SSH-agent authorization engine

This document owns the current authorization state machine, grant lifecycle,
and verification entry points. Activity classification and digest construction
belong to [authorization scopes V2](authorization-scopes-v2.md); the Worker DEK
cache is a separate system described in [dek-cache.md](dek-cache.md).

## 1. Operations and policy

The macOS agent routes `auth@vt`, `run@vt`, raw SSH signing, `sign@vt`, and
`decrypt@vt` through `AuthorizationEngine` in `src/core/authorization.rs`.
The mechanism is shared; the risk policy is not:

| Operation | Reuse policy |
|---|---|
| raw SSH sign / `sign@vt` | configured sign TTL, only with a reusable scope |
| pure-v2 `decrypt@vt` | configured decrypt TTL, only with a reusable scope |
| legacy-containing `decrypt@vt` | fresh for the whole batch |
| `auth@vt` | always fresh |
| `run@vt` | always fresh, after allowlist validation |

Both cache durations default to `0`. `ReusePolicy::from_ttl_secs(0)` selects
first-class `Fresh`, never `StrictTtl(0)`. Fresh requests do not read or write
grants but still use prompt serialization, live validation, epoch checks,
permits, and decision audit. A missing reusable subject also makes a request
effectively fresh. Biometric, FIDO2, and password approvals are cacheable
methods when the operation and scope permit reuse (`AuthMethod::is_cacheable`).

Agent flags and `[agent]` defaults are documented in
[app-bundle.md](app-bundle.md). Grants are memory-only and disappear on restart;
there is no persisted grant migration or dual-write store.

## 2. Grant identity and retained data

The current lookup key is:

```text
GrantKey = Operation x ScopeFamily x SubjectId x digest
```

`Operation` distinguishes `Auth`, `Run`, `Sign`, and `Decrypt`.
`ScopeFamily` distinguishes `Connection`, `Destination`, `Workspace`,
`CwdFallback`, and `ParentApp`. Family participates in equality and diagnostic
counts as well as the domain-separated digest: a directory gaining or losing
`.git` must not silently reuse or count grants from the other family.

`SubjectId` is an opaque `(u64, u64)` anchor. Depending on the family it is a
kernel-derived process identity, a directory `(dev, ino)`, or the fixed
`DESTINATION_SUBJECT` with the verified destination host key in the digest.
Sign resources bind the signing-key fingerprint; decrypt resources bind
`(type, salt)`. Path, destination, and relay metadata inputs are family-specific.
See [authorization-scopes-v2.md](authorization-scopes-v2.md) for their exact
derivation, fallback ordering, forwarding restrictions, and same-UID threat model.

Raw signing and `sign@vt` share `Operation::Sign`, not every grant. Local
workspace signing can share a grant for the same key; destination and
connection families remain separate. Client-reported host, cwd, command, and
reason are not verified provenance or independent security boundaries.

`GrantEntry` stores `CacheExpiry` plus a human `display` label copied from
`GrantScope`. Labels may contain a destination name, workspace/cwd path, or
parent-application name. They are display-only, not lookup inputs. They remain
in agent memory for grant snapshots; request-side labels also feed cache-hit
notifications. The store contains no private keys, DEKs, signatures, command
bodies, or reason text. Grant storage is memory-only; audit rows separately
record request and agent context rather than serializing the store. See
[app-bundle.md](app-bundle.md) for token-gated whole-store visibility and
notification retention outside the agent.

## 3. Authorization and operation commitment

Handlers finish parsing, limits, key lookup, and operation policy checks before
authorization. `AuthorizationEngine::authorize` then:

1. Rejects invalid scope sets or overflowing TTLs before prompting or execution.
2. Checks the full reusable resource set under a security read gate. A hit
   still requires an uncached live security check.
3. On a miss or Fresh request, acquires the global prompt semaphore, validates
   live state, rechecks the full set, and captures the authorization epoch.
4. Runs the injected authenticator without holding a grant-store lock or the
   security gate. The detached prompt worker keeps the semaphore even if the
   requesting connection is cancelled, so system prompts cannot overlap.
5. After approval, acquires the security read gate, compares the epoch, and
   revalidates live state before returning an `AuthorizationPermit`.
6. Lets the handler execute and serialize the protected operation. An extension
   dispatcher also builds and encrypts the success envelope before consuming
   the permit with `commit()`. Raw SSH signing commits after signature generation.

The permit is non-cloneable. Dropping it on signing, derivation, spawn,
serialization, or encryption failure adds no grant. A Fresh or cache-hit permit
has no pending grant write but must still be consumed or dropped to release
its guards. An approved reusable permit carries the pending deduplicated scope
set; commit checks the epoch and writes it atomically under the store lock.

Every live permit holds the security read gate and therefore blocks completed
revocation. An approval permit also retains the global prompt slot through
commit/drop; cache-hit permits do not retain that slot. A same-scope miss
waiter cannot pass the first approval before its grant commits or its operation
fails. Handlers must not perform unbounded-latency work while a permit is live.
Cache-hit notifications run only after commit releases the guards.

## 4. Revocation and expiry

`invalidate_all()` publishes `revocation_pending` synchronously, then a
cancellation-safe revoker takes the security write gate, clears the store,
and advances its epoch. Every completed revocation cycle advances the epoch,
even for an empty store: a displayed prompt has not created a grant yet but
must still be revoked. Concurrent observations coalesce into one cycle.

The gate establishes the execution order:

- A protected operation that obtained its permit first finishes before
  invalidation completes.
- Invalidation that wins during a prompt changes the epoch; that approval
  cannot later execute the operation or create a grant.

Unsafe live validation publishes the pending latch before returning, and
concurrent readers recheck it before receiving a permit. One CAS-claimed
revoker drains the latch; waiters retry the claim after completion so a
cross-atomic hand-off cannot strand pending revocation. The detached prompt
worker also drains revocation on `Unavailable`, even after caller cancellation.

Revocation sources are agent lock (`ssh-add -x`), idle timeout, an observed
interactive-to-locked/off-console transition, detected sleep/wake clock
divergence, and the menu's token-gated `revoke_all`. A failed live session check
also revokes all grants. `MacValidator` checks current session state and clock
progress on hit and post-prompt paths. The five-second watcher is backup
revocation/cleanup, not the sole hit-path security check. Key-map wiping and
guarded reload are separate from grant revocation; see
[app-bundle.md](app-bundle.md), section 10.

`CacheExpiry` uses both monotonic and wall deadlines; either expiring ends reuse.
One approval captures one clock pair for the complete batch. Hits and repeated
approvals under an equal or wider policy do not slide a live deadline. A tighter
requested TTL cannot reuse a wider-policy grant: fresh approval replaces it
with the tighter policy. Expired entries may also be replaced after approval.
Checked deadline arithmetic runs before lookup/prompt and again at commit;
invalid configuration fails closed without panicking or executing an operation.

## 5. Handler and visibility boundaries

Sign handlers validate the request and resolve the requested key before asking
for one sign scope. [sign-vt-design.md](sign-vt-design.md) owns identity routing,
wire fields, and the security differences of decrypt-then-sign fallback.

Decrypt validates parsing, batch limits, non-emptiness, `UNKNOWN` types, legacy
policy, and key-store availability before lookup. Pure-v2 batches require an
all-of hit for their `(type, salt)` resources. A partial hit prompts once and
successful execution commits the full deduplicated set. Rejection or operation
failure preserves existing entries and adds none. Any legacy item makes the
whole request Fresh.

`auth@vt` remains Fresh. `run@vt` resolves a canonical executable against the
allowlist and sanitizes its prompt before Fresh authorization. Spawn occurs
while the permit is live; spawn failure drops it and emits the separate
`spawn_failed` audit event. Neither free-form reason nor command text can turn
these operations into reusable authority.

Any future reuse would require a separate security review and user-visible
policy: auth needs structured service, target user, TTY/PAM session, and consumer
identity; run needs explicit allowlist-rule opt-in, canonical executable
identity, a full argv digest, a fixed cwd/environment profile, policy version,
short TTL, and `max_uses`. These are security-review prerequisites, not current
features or an implementation plan; both operations remain Fresh.

`diag@vt` counts only live grants matching the caller's operation, family, and
subject; an uncacheable caller sees zero. It is read-only and never resets the
idle clock. The sole whole-store channel is the spawn-token-gated
`ui-status@vt`, limited to status and authority-reducing revocation.

Decision audit labels are `sign`, `ssh-sign`, `decrypt`, `auth`, and `run`.
Outcomes are `cache_hit` (latency zero), `approved`, `rejected`, and
`unavailable` (also used for invalidation). Decision audit happens when
authorization resolves, not when the operation commits; it never authorizes
anything. See [agent-audit.md](agent-audit.md) and
[approval-transparency.md](approval-transparency.md) for event context.

Failures map through `authorization_failure_wire`: rejection to `AuthRejected`,
non-interactive state to `SessionLocked`, no GUI session to `NoGuiSession`,
and invalidation to `Transient` with static detail only. Raw SSH signing returns
agent failure. The [structured error contract](structured-errors.md) owns the
envelope, pre-cipher failures, exit codes, and fallback classification.

## 6. Verification entry points

The platform-neutral tests in `src/core/authorization.rs` cover Fresh behavior,
operation/family/subject/resource isolation, full and partial batches, duplicate
and invalid scope sets, dual-clock TTLs, policy tightening, concurrent prompt
serialization, cancellation, live-state validation, epoch races, and permit
commit/drop. Run:

```bash
cargo test --locked core::authorization::tests
```

The macOS adapter is `src/server_macos/authorization.rs`. Dispatcher and
key-lifecycle tests are in `src/server_macos/ssh_agent.rs`; handler validation
and prompt helpers are tested in `src/server_macos/ssh_agent/handlers.rs`.
Scope-specific tests and procedures remain with
[authorization-scopes-v2.md](authorization-scopes-v2.md). On macOS:

```bash
cargo test --locked server_macos::authorization::tests
cargo test --locked server_macos::ssh_agent
```

Repository gates are `cargo test`, `just check`, and `just check-worker`.
Linux does not compile the macOS adapter or handlers. Unit tests do not replace
native Touch ID/FIDO2/password, lock/wake/idle, Keychain, and notification checks.
