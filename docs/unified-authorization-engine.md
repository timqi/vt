# SSH-agent authorization

This document defines what a local approval authorizes, when it may be reused,
and when it must stop working. Worker approval is a separate custody described
in [worker-slim.md](worker-slim.md).

## Purpose and threat model

Approval reuse represents the activity the human approved, rather than every
process that happens to share a terminal. It reduces repeated prompts while
containing forwarded requests and preventing accidental reuse across activities.

- Local scope identity comes from the kernel; a verified SSH destination comes
  from `session-bind@openssh.com`.
- Client-supplied host, project, cwd, command, and reason can narrow a scope or
  explain a request; they never establish trust.
- A scope is not a boundary against same-UID malware, which can run real tools
  inside another activity. Reuse deliberately grants authority for its lifetime.
- The master key, decrypted SSH keys, and authorization grants have separate
  lifetimes; revoking a grant does not erase material already released to a caller.

## Approval policy

| Operation | Reuse |
|---|---|
| Raw SSH signing / `sign@vt` | Sign TTL, when the caller has a reusable scope |
| `decrypt@vt` | Decrypt TTL, when the caller has a reusable scope |
| `auth@vt` | Always fresh: attest human presence now |
| `run@vt` | Always fresh, after executable allowlist validation; argv that would not fit the prompt is refused, never truncated |

Both reuse durations default to zero, meaning fresh approval. Sign and decrypt
have separate policies because a signature answers one challenge while a
decrypt grant releases record key material. Configuration belongs in
[config.example.toml](../config.example.toml).

Fresh requests still require live security validation and obey revocation.
Reusable grants bind operation, scope family, caller subject, and resource;
a sign grant never authorizes decryption or another signing key.

## Scopes

| Activity | Reusable scope |
|---|---|
| Raw sign with a verified, non-forwarding session bind | Destination host key and signing key; shared across local callers |
| Local `sign@vt`, decrypt, or unbound non-SSH signer in a repository | Kernel-derived workspace and requested key/record |
| Local caller outside a repository | Exact kernel-derived cwd, in a separate grant family |
| Caller in a broad shared cwd | Immediate parent application instance and requested key/record |
| vt extension carried by SSH or the filtering relay | Connection-confined; never a local activity grant |
| Forwarding-capable or tainted raw sign; unbound SSH client | Fresh only |

- Workspace detection uses the nearest `.git` entry; submodules and worktrees
  can be narrower than the parent repository. Worker project grouping differs.
- Home, ancestors of home, and shared temporary/mount roots cannot become broad
  directory scopes. A missing usable parent or failed identity lookup means Fresh.
- Workspace, cwd, application, destination, and connection grants stay distinct,
  even when their underlying process/directory identifiers coincide.
- Directory identity binds both the directory generation and canonical path;
  a rename or reused inode must not silently change the authorized activity.
- A claimed cwd inconsistent with a local workspace/directory degrades to Fresh.
  Scope resolution must not let a peer-controlled filesystem stall the accept loop.
- Long-lived connections retain their resolved scope; reconnect to resolve a
  different workspace. Parent-app scope lasts only for that application instance.
- Unsupported or unverifiable destination bindings never enable destination reuse.
  Session binding precedes agent lock checks and does not reset idle activity.
- Binding identifies a verified destination; it is not an additional check that
  every raw sign payload embeds the bound session identifier.

Prompts must state the scope and duration a successful operation will grant;
[approval-transparency.md](approval-transparency.md) owns their presentation.

## Commitment and revocation

- An approval becomes reusable only after the protected operation succeeds and
  its response envelope is complete; failure adds no grant.
- Decrypt batches require all requested records for a cache hit. A partial hit
  prompts once; rejection preserves existing grants and adds none.
- A live non-cloneable permit orders operation completion before revocation;
  handlers must not hold it across unbounded-latency work.
- Revocation that wins while a prompt is open invalidates that approval, even
  when the grant store was empty. It must not create authority afterward.
- Prompts are serialized, including after caller cancellation; cancellation
  must not release the prompt slot while a system prompt remains active.
- Cache hits and post-prompt execution require fresh checks of live security
  state. An unavailable/unsafe session revokes grants; ordinary rejection does not.
- Agent lock, idle timeout, observed screen lock, detected wake, and menu
  revoke-all advance the revocation epoch. Background polling is a backstop,
  not a substitute for checks on the operation path.
- Either wall-clock or monotonic expiry ends reuse. Hits never slide expiry;
  a tighter requested policy requires fresh approval before replacing a grant.
- Notifications run after permit commitment releases its guards.

Approval audit records the decision, not successful execution. A failed reply
can follow a completed side effect; retries have no exactly-once guarantee.
See [structured-errors.md](structured-errors.md) and [agent-audit.md](agent-audit.md).

## Visibility

`diag@vt` exposes configuration and only grants this caller could reuse; an
uncacheable caller sees zero. It creates no grant, requires no operation approval,
emits no audit push, and never resets idle. Polling reveals the agent build and
caller-scoped reuse state without an audit trail.

Only the spawn-token-gated `ui-status@vt` exposes the whole grant list; it may
report status or revoke authority, never grant or extend it. The menu, key
wiping, and native permission limits belong to [app-bundle.md](app-bundle.md).

## Source

The engine and its race tests are in
[src/core/authorization.rs](../src/core/authorization.rs); native validation and
scope construction are in [server_macos/authorization.rs](../src/server_macos/authorization.rs)
and [ssh_agent/scopes.rs](../src/server_macos/ssh_agent/scopes.rs).
