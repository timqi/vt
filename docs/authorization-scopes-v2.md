# Authorization scopes V2 — activity-scoped grants

Status: **design, pre-implementation**

V2 replaces the caller-topology cache modes (`none` / `per-session` /
`per-app` / `global`) with per-operation activity scopes. The unified
authorization engine (`src/core/authorization.rs`) is unchanged; V2 only
changes how handlers construct `GrantScope` values, how connections classify
their peer, and what the operator can configure.

## 1. Decision

A grant names **the activity the human approved**, in the dimension where
that operation's risk actually lives:

| Operation | Grant identity | Rationale |
|---|---|---|
| raw SSH sign | key fingerprint × **destination host key** (session-bind) | The risk of a signature is "authenticate as me to some server". Which directory or process asked is incidental. |
| `sign@vt` from local vt | key fingerprint × **workspace** | The local vt client is kernel-verified; a multi-host fan-out from one project is one human activity. |
| `sign@vt` via relay | key fingerprint × claimed pwd, bounded **per relay connection** | Unchanged from V1: a remote host reuses only its own approvals. |
| `decrypt@vt` local, pure v2 | secret `(type, salt)` × **workspace** | Secrets belong to projects. "I am working in this project" is the approval unit. |
| `decrypt@vt` via relay, pure v2 | secret `(type, salt)` × claimed host/pwd, bounded per relay connection | Unchanged from V1. |
| legacy-containing `decrypt@vt` | — | Fresh, unchanged. |
| `auth@vt` | — | Fresh by definition: it attests "a human is present now". |
| `run@vt` | — | Fresh. A future reusable policy needs exe identity + argv digest + `max_uses`; out of scope. |

The four cache modes are deleted. They existed to describe caller topology
(terminal session, app bundle, global escape hatch for TTY-less
orchestrators); activity scopes do not care who the caller is, so the knob —
and the TTY gate that made AI agents and CI uncacheable — disappears.

## 2. Threat-model stance (what a cache key is for)

Key components ranked by who can forge them:

1. **Cryptographic** — session-bind destination: the server host key's
   signature over the KEX session identifier. Unforgeable by a remote host.
2. **Kernel-derived** — peer pid, start time, executable path, **cwd**
   (`proc_pidinfo(PROC_PIDVNODEPATHINFO)`). Trustworthy against remote and
   cross-context confusion; forgeable by a same-UID local process (it can
   `chdir` anywhere and exec real tools).
3. **Client-claimed** — pwd/host strings in vt request metadata. Partitioning
   for honest callers only; never a security boundary.

Stated plainly: **against same-UID local malware no cache key is a boundary**
— such a process can drive the real ssh/vt binaries inside any scope. The
boundaries against that adversary are the revocation epoch (lock, wake,
idle), the strict TTL, and audit push. The job of the scope is (a) matching
honest intent so prompts are rare and meaningful, and (b) containing
**remote** peers (forwarded sockets, relays) and accidental cross-context
reuse. V1's per-session/TTY machinery paid usability for no additional
protection within this model; V2 spends the same budget on intent-matching.

## 3. Sign: session-bind destination scope

### 3.1 Protocol

OpenSSH ≥ 8.9 clients send `session-bind@openssh.com` on every agent
connection before requesting signatures: `(host_key, session_id,
signature, is_forwarding)`. `ssh-agent-lib` 0.5 ships the `SessionBind`
message type and `verify_signature()` (host key over session id). The agent
currently answers extensions it does not parse with generic success; V2
parses and enforces this one.

### 3.2 Per-connection bind state machine

Each `VtSshSession` (one per socket connection) tracks:

```text
BindState = Unbound
          | Bound { destination: HostKeyFp, forwarding: bool, session_ids: Vec<SessionId> }
          | Tainted
```

Rules, mirroring OpenSSH `process_ext_session_bind` where it matters for
caching:

- Signature verification failure, a duplicate `session_id` under a different
  host key, a forwarding→non-forwarding downgrade for the same session id,
  or more than 16 recorded ids ⇒ `Tainted` + extension failure reply.
- First valid bind ⇒ `Bound` with that host key and flag.
- A further valid bind for a **different** host key, or any bind with
  `is_forwarding = true`, marks the connection as forwarding-capable:
  requests can originate beyond the first hop, so the connection is no
  longer destination-cacheable (state stays `Bound` with
  `forwarding = true`).
- `Tainted` never recovers for the connection lifetime.

### 3.3 Scope derivation for raw `SIGN_REQUEST`

```text
Bound { forwarding: false, destination } ⇒ reusable scope
    subject = (0, 0)                    // destination grants are user-wide
    digest  = H("vt-authz-sign-dest-v1", destination_hostkey_fp, key_fp)
anything else (Unbound / forwarding / Tainted) ⇒ Fresh
```

Destination grants are deliberately shared across all local callers: any
same-UID process could drive the real ssh anyway (§2), and the human intent
"talk to github.com with this key" is caller-independent. Repeated one-shot
`git fetch` therefore hits after one approval; forwarded (`ssh -A`) traffic
never reads or writes these grants — strictly stronger than V1's
per-ssh-process narrowing, which could not distinguish the two cases at all.

Prompt display: the agent knows the destination only as a host key. The
prompt shows its SHA256 fingerprint and, best-effort, a hostname resolved by
scanning unhashed `~/.ssh/known_hosts` entries for that key. The display
name is cosmetic; the grant is keyed on the host key fingerprint only.

### 3.4 `sign@vt`

- Local peer (kernel-verified vt process, not the relay): workspace scope
  (§4) — `digest = H("vt-authz-sign-ws-v1", key_fp)`, subject = workspace
  identity. One approval covers a same-project multi-host fan-out
  (`tssh h1 h2 …`), preserving the V1 fan-out behavior with a
  kernel-verified boundary instead of a claimed `pwd`.
- Relay peer (`vt ssh connect --forward-real-agent`, detected via kernel
  argv as today): per-connection subject `(pid, start_tvsec)` with the V1
  digest `H("vt-authorization-sign-v1", key_fp, claimed_pwd)`. Unchanged.

## 4. Workspace identity

For local vt peers (decrypt and sign@vt):

1. Read the peer's kernel cwd: `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO)`
   (`pvi_cdir.vip_path`). Failure ⇒ Fresh.
2. Ascend from cwd to the nearest ancestor containing a `.git` entry (dir
   **or** file — worktrees use a file). None found ⇒ the cwd itself is the
   workspace root.
3. Workspace identity = `(st_dev, st_ino)` of the root directory, used as
   the engine `SubjectId`; the digest additionally binds the canonical root
   path, so an inode recycled for a different path cannot match:
   `H("vt-authz-decrypt-ws-v1", root_path, secret_type, salt)`.

Client-reported `pwd` remains display metadata. If it is present and does
not lie inside the workspace root, the request degrades to Fresh
(consistency check, not a boundary). Resolution happens once per connection
(vt CLI connections are per-command; a process cwd does not change
mid-connection in practice).

Subject spaces overlap structurally (`(dev, ino)` vs relay `(pid, tvsec)`
vs `(0, 0)`), but every scope family uses a distinct digest domain label,
so a subject collision alone can never merge grants.

## 5. Configuration

Deleted: `--ssh-auth-cache-mode`, `--ssh-auth-cache-duration`,
`--decrypt-auth-cache-mode`, `--decrypt-auth-cache-duration`,
`AuthCacheMode`, `AuthCacheConfig`, `classify_cache_context`, the TTY gate,
and the mode-specific `ContextBasis` variants.

Added: one flag.

```text
--auth-cache-duration <secs>    default 0
```

- `0` ⇒ every operation uses the engine's first-class `Fresh` policy
  (not `StrictTtl(0)`). Default preserves V1's out-of-box behavior:
  always prompt.
- `> 0` ⇒ sign and decrypt reusable scopes use `StrictTtl(n)`. One value for
  both: the risk differentiation lives in the scopes and the revocation
  epoch, not in two knobs. `auth@vt` and `run@vt` ignore the flag (existing
  invariant).

TTL semantics are unchanged mechanically (strict dual-clock, non-sliding)
but should be read as "cap within a presence session": screen lock, wake,
agent lock, and idle timeout still revoke everything, so generous values
(hours) are reasonable — the human leaving is the real expiry event.
Suggested value in examples: `28800` (8 h).

## 6. Prompt transparency invariant

**The prompt must state the reuse scope whenever an approval can create a
grant.** When the effective policy is reusable, the prompt gains a final
line:

```text
reuse: github.com (SHA256:…) · 8h        # destination sign
reuse: workspace ~/code/vt · 8h          # workspace sign@vt / decrypt
```

Fresh operations (`auth@vt`, `run@vt`, legacy decrypt, unbound sign) show no
reuse line. The approved range and the displayed range must be the same
sentence; handlers build the label from the same data the scope digest uses.

## 7. Diagnostics

`diag@vt` replaces `mode` + V1 `ContextBasis` with the scope classification:

- sign report: `basis ∈ {session-bind, workspace, relay-connection,
  unbound, tainted, disabled}`, `ttl_secs`, `live_entries` = destination
  grants `live_len(Sign, (0,0))` + caller workspace grants (when resolved).
- decrypt report: `basis ∈ {workspace, relay-connection, disabled}`,
  `ttl_secs`, `live_entries` scoped to the caller's workspace or relay
  connection.

`vt doctor` explanations updated accordingly. The diag JSON shape changes;
client and agent ship in one binary and the wire envelope already hard-fails
on version mismatch, so no compatibility shim is needed. `diag@vt` remains
read-only, prompt-free, and must still not reset the idle clock.

## 8. What does not change

- The engine: `Operation × SubjectId × ResourceDigest`, permits,
  commit-after-success, epoch revocation, strict dual-clock TTL, prompt
  serialization. V2 is scope construction + connection classification only.
- Relay behavior (`--forward-real-agent`): filter, per-connection
  confinement, `run@vt` refusal.
- `auth@vt`/`run@vt` fresh-always; legacy decrypt fresh; `--no-legacy-decrypt`.
- Idle/lock/wake/sweep machinery and audit labels/outcomes.

## 9. Non-goals

- OpenSSH destination constraints (`restrict-destination-v00@openssh.com`).
- Verifying that a sign request's embedded session id matches the bound
  session (hardening note for a later pass; forwarding exclusion already
  covers the cache-relevant case).
- Unattended periodic jobs: still a credential-tiering problem (read-only
  deploy keys), not a caching problem. Document in README/FAQ.
- Approval-time scope choice UI ("allow once / allow 8 h"): the prompt text
  states the scope; interactive choice is a later UX pass.
- Config-file per-scope TTL overrides.

## 10. Residual risks (accepted, documented)

- Same-UID local processes can operate inside any scope (§2). Unchanged
  from V1 in substance; V1's session/TTY gates provided at most nuisance
  resistance (a process cannot join an existing session) and are dropped
  knowingly in exchange for scopes that match intent.
- A destination grant covers that server for every local caller for the
  TTL. Within the presence-session reading of TTL this is the intended
  meaning of the approval.
- Workspace identity follows `.git` root detection; a repository nested via
  submodules/worktrees resolves to the nearest `.git` entry, which may be
  narrower than the superproject. Acceptable: narrower = more prompts, never
  broader reuse.
- Old clients (OpenSSH < 8.9, non-ssh tools doing raw signs) never benefit
  from destination caching; they degrade to Fresh, not to a coarser scope.

## 11. Test plan

Engine tests are untouched. New/changed coverage:

1. Bind state machine: valid bind, bad signature ⇒ Tainted, duplicate
   session id with different key ⇒ Tainted, forwarding flag ⇒ never
   destination-cacheable, >16 ids ⇒ Tainted, Tainted is sticky.
2. Scope derivation: bound⇒destination digest, unbound/tainted/forwarding ⇒
   Fresh; digest domain separation across scope families.
3. Workspace resolution: `.git` dir and `.git` file roots, no-root fallback
   to cwd, pwd-outside-workspace ⇒ Fresh, dev/ino identity + path binding.
4. `sign@vt` local=workspace vs relay=per-connection classification.
5. Decrypt batches: workspace scope per `(type, salt)`, all-of hit,
   legacy⇒fresh (existing tests adapted).
6. CLI: duration 0 ⇒ Fresh everywhere; >0 ⇒ StrictTtl; removed flags gone.
7. Diag: new basis strings, live counts scoped as specified.
8. known_hosts display resolution: match, hashed-entry miss, absent file.

## 12. Migration steps

1. Add `proc_info::get_cwd` + workspace resolution + tests.
2. Add bind state machine + `session-bind` handling in `extension()` +
   tests.
3. Add new `GrantScope` constructors with domain-separated digests.
4. Rewire handlers (raw sign, sign@vt, decrypt) to the new scopes.
5. Replace CLI flags/config plumbing with `--auth-cache-duration`.
6. Replace diag basis reporting; update `vt doctor`.
7. Add prompt reuse lines.
8. Delete `AuthCacheMode`, `classify_cache_context`, TTY/app/session
   helpers that lose their last caller, and V1 `ContextBasis` variants.
9. Update `docs/README.md`, `docs/diag-design.md`, `docs/sign-vt-design.md`,
   `CLAUDE.md` invariants, `config.example.toml`, `README.md` FAQ
   (ControlMaster + read-only-credential guidance).
