# `diag@vt` + `vt doctor` — cache/routing observability

Status: implemented (codex-expert review round folded in; this file is the
feature's decision record — verify current behavior against `src/client.rs`
`doctor` and `src/server_macos/ssh_agent.rs` `handle_diag`)

## 1. Problem

vt's behavior is decided by three config layers (env → config.toml → defaults),
routing rules (`VT_BACKEND` pin, agent probe, passkey fallback), and agent-side
scope-classification rules (session-bind destination binding, workspace
resolution, relay/ssh connection confinement, durations defaulting to `0`).
Each rule is individually justified, but the composition is opaque to the
operator: the observable symptom is just "Touch ID prompted again" or "the
phone buzzed", and diagnosing *why* otherwise requires reading the
classification helpers (`sign_basis` / `decrypt_basis`) in
`src/server_macos/ssh_agent.rs`.

## 2. Goal

One command — `vt doctor` — that answers:

1. Which config values are in effect and where each came from (env vs file).
2. Which transport path a call from *this* process would take, and why.
3. On the agent path: what cache durations the agent is running with, and how
   the agent scope-classifies *this caller's* connection (cacheable? which
   scope — destination, workspace, or connection?).

Non-goals: fixing anything (pure diagnosis); worker-side deep checks (an
HMAC-validating `/api/health` is deferred); auditing/pushing diag events.

## 3. New agent extension: `diag@vt`

Read-only. Same envelope discipline as the other five extensions: payload is
AES-GCM encrypted under the VT_AUTH-derived `auth_cipher`, so only VT_AUTH
holders can query, and a non-vt agent answers `SSH_AGENT_FAILURE`. **No Touch
ID prompt** (it discloses no secret and mints no DEK), **never cached, not
audit-pushed** (no human decision to record).

### Wire (src/core.rs)

```rust
pub struct DiagReq {}                     // reserved; no fields in v1

pub struct DiagRes {
    pub agent_version: String,            // env!("CARGO_PKG_VERSION")
    pub sign_cache: DiagCacheReport,
    pub decrypt_cache: DiagCacheReport,
    pub peer: DiagPeerReport,
    pub run_allow_len: usize,             // 0 = run@vt disabled
    pub audit_push: bool,
}

pub struct DiagCacheReport {
    pub ttl_secs: u64,                    // 0 = Fresh (always prompt)
    pub live_entries: usize,              // unexpired grants THIS caller
                                          // could use right now
    pub context_basis: String,            // see §3.2 (cacheability is implied
                                          // by the basis; no separate bool)
}

pub struct DiagPeerReport {
    pub pid: Option<i32>,
    pub exe: Option<String>,              // proc_pidpath basename only
    pub has_tty: bool,
    pub is_ssh_client: bool,
    pub is_vt_relay: bool,
}
```

### 3.1 Handler

`handle_diag` on `VtSshSession`. The session already resolves both cache
contexts at `new_session`; the handler reports those plus the *basis* for the
resolution (§3.2) and counts live entries through
`AuthorizationEngine::live_len(operation, subject)`. The unified grant store
uses **both clocks**, the same dual-clock validity predicate as authorization
lookup (review R3), and filters by typed operation plus the caller's subject.

Two hard rules from review:

- **`diag@vt` skips `touch_activity()`** (review R1). `extension()` currently
  resets the idle clock before dispatch; a pollable no-Touch-ID extension must
  not keep the agent "active" forever and defeat the idle-timeout cache flush
  and key clear.
- **`live_entries` counts only grants the caller's own scope classification
  could reuse** (review R2), never a global count. A relayed remote (or an
  uncacheable local caller) must not learn how many grants other scopes on
  the Mac hold. A basis that never caches → `live_entries = 0`; a
  destination-bound (`session-bind`) caller counts the user-wide destination
  grants because those ARE the grants its own requests would hit.

### 3.2 Basis reporting (activity scopes V2)

> The original design described the caller-topology classifier
> (`resolve_cache_context`, modes, TTY gate). That machinery was replaced by
> activity scopes — see
> [`authorization-scopes-v2.md`](authorization-scopes-v2.md). This section
> describes the current basis surface.

`ContextBasis` still lives in core.rs so the agent's wire tags and the CLI's
human sentences are one compile-checked mapping. The V2 variants name how the
connection is scope-classified:

```rust
enum ContextBasis {
    Disabled,        // duration 0 (the default): every request prompts
    NoPeerPid,       // peer PID unavailable → Fresh
    RelayConnection, // grants confined to this relay connection
    SessionBind,     // sign: destination proven by session-bind@openssh.com
    Forwarding,      // sign: bound connection carries forwarded traffic → Fresh
    Tainted,         // sign: a session-bind failed verification → Fresh
    UnboundSsh,      // sign: ssh peer without session-bind → Fresh
    Workspace,       // local peer scoped to its kernel .git workspace root
    CwdWorkspace,    // no .git root: scoped to the kernel cwd directory itself
    ParentApp,       // broad cwd ($HOME, /, temp roots): scoped to the calling app
    NoWorkspaceRoot, // cwd too broad and no usable parent process → Fresh
    ProcLookupFailed,// proc-info/cwd/stat lookup failed → Fresh
}
```

The sign basis is derived per connection from the bind state, relay flag, and
workspace resolution; the decrypt basis from the relay flag and workspace
resolution. The enum serializes to the wire as a stable string; the CLI maps
it to a human sentence and passes unknown tags through verbatim. `vt doctor`
additionally warns when `agent_version` differs from the client's own version
(the agent is a long-lived daemon and does not restart on CLI upgrade).

### 3.3 Relay

`route_extension` (src/ssh_sign.rs) adds `"diag@vt"` to the relayed set —
remote "why doesn't my cache hit" is the primary use case. Note the relayed
report describes the **relay's** connection to the upstream agent (that IS the
context relayed requests ride), so it is the right answer for the remote
caller. Disclosure to the remote = cache config + live counts; a remote holding
VT_AUTH can already exercise decrypts, so this adds no new capability.

### 3.4 Information-disclosure notes (accepted tradeoffs)

- `live_entries` (scoped to the caller's own context, §3.1) reveals "grants I
  could silently use are live". Accepted: the caller can already *use* them —
  cache hits are silent by design; the count only makes that state visible.
  No cache keys, no other sessions' contexts, no record identifiers cross the
  wire.
- `run_allow_len` is not a new oracle: `handle_run` already fast-fails on an
  empty allowlist / unlisted argv[0] before any prompt, so run@vt's enablement
  is probeable with zero prompts today; diag only makes the count cheaper.
- `agent_version` becomes remotely obtainable over the relay (previously not
  exposed there). Low severity: the remote already has Touch-ID-gated
  decrypt/encrypt/auth through the same relay.
- `diag@vt` leaves **no audit trail** even when `--audit-url` is set — the
  only vt extension with none. Accepted: there is no human decision to
  record, and auditing a pollable read-only op would flood the table; the
  cost is that repeated remote fingerprinting of agent_version/cache state is
  invisible.

## 4. `vt doctor` (client, cross-platform)

Sections, in order; never hard-fails — reports and lints:

1. **Config** — each `VT_*` knob: effective value (secrets redacted to
   `set(…8 chars)`), source `env` / `config.toml` / `unset`. Source tracking:
   `hydrate_env_from_file` returns the list of keys it populated, threaded
   into the doctor as a plain parameter (no global state); anything set but
   not in that list is `env`. Re-lint config file permissions (same check as
   loading, but visible on demand).
2. **Routing** — replicate `VTClient::new` validation + the `VT_BACKEND`
   table: "this host would try agent first, then fall back to passkey" /
   errors the constructor would raise.
3. **Agent** — socket path used (`$SSH_AUTH_SOCK` vs `~/.ssh/vt.sock`),
   connectable?, then `diag@vt` via a **dedicated helper** (not the generic
   `try_agent_extension` contract — review R4, the two failure shapes are
   distinguishable on the wire and must be reported separately):
   - `Ok(Some(payload))` → print DiagRes (modes, TTLs, live entries, peer
     classification, cacheable + human reason per cache);
   - `Ok(None)` (SSH success with empty extension payload — an agent that
     ignored the unknown name) → "vt agent too old for diag@vt (or a non-vt
     agent that ignores unknown extensions)";
   - `Err` from the extension call (`SSH_AGENT_FAILURE`) → "agent refused:
     non-vt agent, wrong VT_AUTH, or agent locked";
   - `VT_AUTH` empty → "agent path disabled (VT_AUTH unset)".
4. **Worker** — `VT_PASSKEY_URL` reachability (GET base URL, status only;
   no token validation in v1), token present/absent.

Exit code 0 always in v1 (diagnostic, not a health gate).

## 5. Testing

- Pure: `ContextBasis` mapping unit tests (all branches of the
  `sign_basis`/`decrypt_basis` classifiers, asserted by the scope
  classification tests); DiagReq/DiagRes serde round-trip; basis→human-string
  mapping total.
- `route_extension` test updated for `diag@vt`.
- macOS handler compiles only under `cfg(target_os = "macos")` — verified by
  CI (macos-latest), not locally on Linux.

## 6. Files touched

| file | change |
|---|---|
| `src/core.rs` | DiagReq/DiagRes/DiagCacheReport/DiagPeerReport |
| `src/core/authorization.rs` | operation/subject-scoped live grant counts |
| `src/server_macos/ssh_agent.rs` | EXT_DIAG, classification refactor, handle_diag |
| `src/ssh_sign.rs` | relay `diag@vt` + tests |
| `src/client.rs` | doctor body (config/routing/agent/worker sections) |
| `src/config.rs` | hydrate returns populated keys |
| `src/main.rs` | `vt doctor` subcommand |
| `README.md`, `docs/README.md` | command row / map row |
