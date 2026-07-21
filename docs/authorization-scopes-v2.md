# Authorization scopes V2 — activity-scoped grants

Status: **design, revised after expert review R1**

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
| raw SSH sign, session-bound | key fingerprint × **destination host key** | The risk of a signature is "authenticate as me to some server". Which directory or process asked is incidental. |
| raw SSH sign, unbound non-ssh peer | key fingerprint × **workspace** | `ssh-keygen -Y sign` (git commit signing) never binds; the local kernel-verified caller's project is the activity. |
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
   signature over the KEX session identifier. Unforgeable by a **remote**
   host. A same-UID local process that captured a genuine
   `(session_id, signature)` pair (e.g. a trojaned ssh) can replay it on its
   own connection — which grants it nothing it could not get by driving the
   real ssh, so this stays within the concession below.
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

## 3. Sign scopes

### 3.1 session-bind is a plaintext extension — dispatcher restructure

OpenSSH ≥ 8.9 clients send `session-bind@openssh.com` on every agent
connection before requesting signatures: `(host_key, session_id, signature,
is_forwarding)`, plain SSH-wire encoded. **It is not a vt extension and is
never VT_AUTH-encrypted.** `Session::extension()` currently early-returns
for non-vt names and only decrypts `details` with the auth cipher for vt
names; session-bind must be intercepted **before** the keychain load /
auth-cipher path:

```text
extension():
  locked check (unchanged)
  name == "session-bind@openssh.com"
      -> parse_message::<SessionBind>() on the raw details
      -> update per-connection bind state (§3.2)
      -> Ok(None) on success (plain SSH_AGENT_SUCCESS),
         Err(AgentError::Failure) on any invalid bind
  other non-vt names -> Ok(None) (unchanged)
  vt names -> keychain, auth cipher, envelope dispatch (unchanged)
```

`ssh-agent-lib` 0.5 ships the `SessionBind` message type and
`verify_signature()` (host key over session id). A failed or absent bind is
non-fatal to the ssh client; it only means the connection never becomes
destination-cacheable. `session-bind` must not touch the idle-activity
clock (it precedes any human-gated operation).

### 3.2 Per-connection bind state machine

Each `VtSshSession` (one per socket connection) tracks:

```text
BindState = Unbound
          | Bound { destination: KeyData-wire-bytes digest, forwarding: bool,
                    session_ids: Vec<SessionId> }
          | Tainted
```

Rules (the shape follows OpenSSH's `process_ext_session_bind`; the numeric
cap is a **local DoS-defense choice**, not a claimed protocol contract):

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
Bound { forwarding: false, destination }
    ⇒ subject = (0, 0)                    // destination grants are user-wide
      digest  = H("vt-authz-sign-dest-v1",
                  wire-encoded KeyData bytes of the destination host key,
                  key_fp)
Bound { forwarding: true } | Tainted
    ⇒ Fresh
Unbound, peer executable is an OpenSSH client (basename "ssh")
    ⇒ Fresh                               // cannot distinguish auth from
                                          // forwarding without a bind
Unbound, peer is any other local process (ssh-keygen, custom tools)
    ⇒ workspace scope (§4):
      subject = workspace identity
      digest  = H("vt-authz-sign-ws-v1", key_fp)
```

The digest hashes the **exact wire-encoded `KeyData` bytes** from
`SessionBind.host_key`; string fingerprints are display-only.

Destination grants are deliberately shared across all local callers: any
same-UID process could drive the real ssh anyway (§2), and the human intent
"talk to github.com with this key" is caller-independent. Repeated one-shot
`git fetch` therefore hits after one approval; forwarded (`ssh -A`) traffic
never reads or writes these grants — strictly stronger than V1's
per-ssh-process narrowing, which could not distinguish the two cases at all.

The unbound-non-ssh workspace arm exists for SSH-based git commit signing
(`ssh-keygen -Y sign` sends no bind). A renamed ssh binary would take this
arm and could expose workspace grants to traffic it forwards; renaming ssh
is a deliberate same-UID local action and stays within the §2 concession
(documented, accepted — V1's `is_ssh_client_path` basename match had the
same evasion property).

Prompt display: the agent knows a bound destination only as a host key. The
prompt shows its SHA256 fingerprint and, best-effort, a hostname resolved by
scanning unhashed `~/.ssh/known_hosts` entries for that key. The display
name is cosmetic; the grant is keyed on the host key bytes only.

### 3.4 `sign@vt`

- Local peer (kernel-verified vt process, not the relay): workspace scope
  (§4) — `digest = H("vt-authz-sign-ws-v1", key_fp)`, subject = workspace
  identity. One approval covers a same-project multi-host fan-out
  (`tssh h1 h2 …`), preserving the V1 fan-out behavior with a
  kernel-verified boundary instead of a claimed `pwd`. Raw commit-signing
  grants (§3.3) and `sign@vt` grants from the same workspace and key
  intentionally share this scope family.
- Relay peer (`vt ssh connect --forward-real-agent`, detected via kernel
  argv as today): per-connection subject `(pid, start_tvsec)` with the V1
  digest `H("vt-authorization-sign-v1", key_fp, claimed_pwd)`. Unchanged.

## 4. Workspace identity

For local vt peers (decrypt and sign@vt) and unbound non-ssh raw signers:

1. Read the peer's kernel cwd: `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO)`
   (`pvi_cdir.vip_path`). Failure ⇒ Fresh.
2. Ascend from cwd to the nearest ancestor containing a `.git` entry (dir
   **or** file — worktrees use a file). **None found ⇒ Fresh** (diag basis
   `no-workspace-root`). A cwd fallback would silently pool `$HOME`, `/tmp`,
   and CI scratch directories into one broad unlabeled bucket; V2 fails
   narrow instead.
3. Capture the workspace identity through **one file descriptor**:
   `open(root, O_RDONLY | O_DIRECTORY)` → `fstat(fd)` for `(st_dev, st_ino)`
   → `fcntl(fd, F_GETPATH)` for the canonical path → close. The dev/ino pair
   is the engine `SubjectId`; the digest additionally binds the canonical
   path, so an inode recycled for a different path cannot match:
   `H("vt-authz-decrypt-ws-v1", root_path, secret_type, salt)`. Deriving
   path and identity from the same fd removes the rename race between two
   separate lookups.

Client-reported `pwd` remains display metadata. If it is present and does
not lie inside the workspace root, the request degrades to Fresh
(consistency check, not a boundary). Resolution happens once per connection
(vt CLI connections are per-command; a process cwd does not change
mid-connection in practice).

Subject spaces overlap structurally (`(dev, ino)` vs relay `(pid, tvsec)`
vs `(0, 0)`), but every scope family uses a distinct digest domain label,
so a subject collision alone can never merge grants.

## 5. Configuration

Deleted: `--ssh-auth-cache-mode`, `--decrypt-auth-cache-mode`,
`AuthCacheMode`, `classify_cache_context`, the TTY gate, and the
mode-specific `ContextBasis` variants.

Kept, with changed semantics: the two duration flags, because sign and
decrypt carry deliberately different blast radii (a cached decrypt grant
releases per-record DEK material; a sign grant concedes single challenges).
Collapsing them would force an operator who caches signs but keeps decrypt
always-fresh to widen decrypt exposure.

```text
--ssh-auth-cache-duration <secs>       default 0
--decrypt-auth-cache-duration <secs>   default 0
```

- `0` ⇒ that operation uses the engine's first-class `Fresh` policy (not
  `StrictTtl(0)`). Defaults preserve V1's out-of-box behavior: always
  prompt.
- `> 0` ⇒ that operation's reusable scopes use `StrictTtl(n)`. `auth@vt`
  and `run@vt` ignore both flags (existing invariant).

TTL semantics are unchanged mechanically (strict dual-clock, non-sliding)
but should be read as "cap within a presence session": screen lock, wake,
agent lock, and idle timeout still revoke everything, so generous values
(hours) are reasonable — the human leaving is the real expiry event.
Suggested values in examples: `28800` (8 h) sign, `3600` decrypt.

## 6. Prompt transparency invariant

**The prompt must state the reuse scope whenever an approval can create a
grant.** When the effective policy is reusable, the prompt gains a final
line:

```text
reuse: github.com (SHA256:…) · 8h        # destination sign
reuse: workspace ~/code/vt · 8h          # workspace sign / decrypt
```

Fresh operations (`auth@vt`, `run@vt`, legacy decrypt, unbound-ssh sign)
show no reuse line. The approved range and the displayed range must be the
same sentence; handlers build the label from the same fd-derived data the
scope digest uses (§4.3).

## 7. Diagnostics

`diag@vt` replaces `mode` + V1 `ContextBasis` with the scope classification:

- sign report: `basis ∈ {session-bind, workspace, no-workspace-root,
  relay-connection, unbound-ssh, tainted, disabled}`, `ttl_secs`,
  `live_entries` = destination grants `live_len(Sign, (0,0))` + caller
  workspace grants (when resolved).
- decrypt report: `basis ∈ {workspace, no-workspace-root, relay-connection,
  disabled}`, `ttl_secs`, `live_entries` scoped to the caller's workspace or
  relay connection.

The agent is a long-lived daemon and does not restart on CLI upgrade, so
`vt doctor` must handle a stale agent gracefully: compare the existing
`agent_version` field against the client's own version and print an explicit
"agent is vX, client is vY — restart the agent" warning; a diag body that
fails to parse produces the same hint instead of a raw error. `diag@vt`
remains read-only, prompt-free, and must still not reset the idle clock.

## 8. What does not change

- The engine: `Operation × SubjectId × ResourceDigest`, permits,
  commit-after-success, epoch revocation, strict dual-clock TTL, prompt
  serialization. V2 is scope construction + connection classification only.
- Relay behavior (`--forward-real-agent`): filter, per-connection
  confinement, `run@vt` refusal. The relay's own filter continues to refuse
  `session-bind@openssh.com` (it is not in the allow-list), so remote hosts
  cannot bind the upstream connection.
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

## 10. Residual risks and regressions (accepted, documented)

- Same-UID local processes can operate inside any scope (§2), including by
  renaming an ssh binary into the unbound-non-ssh workspace arm (§3.3) or
  replaying a captured session-bind. Unchanged in substance from V1.
- A destination grant covers that server for every local caller for the
  TTL. Within the presence-session reading of TTL this is the intended
  meaning of the approval.
- Workspace identity follows `.git` root detection; submodules/worktrees
  resolve to the nearest `.git` entry, which may be narrower than the
  superproject. Narrower = more prompts, never broader reuse.
- Raw signs from OpenSSH < 8.9 (no session-bind) are permanently Fresh —
  they previously could cache under an explicit `Global`/`PerSession` mode.
  macOS has shipped ≥ 8.9 since Ventura; treat via README note, no knob.
- `sign@vt` via relay signs with the relay's configured `--host` label, not
  a verified downstream destination (unchanged V1 behavior); it is
  per-connection confined and must never be described as destination-bound.
- Working outside any git repository never caches (§4.2). Deliberate
  fail-narrow; revisit only with an explicit opt-in.

## 11. Test plan

Engine tests are untouched. New/changed coverage:

1. Bind state machine: valid bind, bad signature ⇒ Tainted, duplicate
   session id with different key ⇒ Tainted, forwarding flag ⇒ never
   destination-cacheable, >16 ids ⇒ Tainted, Tainted is sticky.
2. **`Session::extension()` integration test with a real plaintext
   `session-bind@openssh.com` payload** — asserting it is parsed before the
   auth-cipher path, answers plain success, and flips the connection state
   (the seam most likely to be implemented wrong).
3. Scope derivation: bound ⇒ destination digest over wire KeyData bytes;
   forwarding/tainted/unbound-ssh ⇒ Fresh; unbound-non-ssh ⇒ workspace;
   digest domain separation across scope families.
4. Workspace resolution: `.git` dir and `.git` file roots, no-root ⇒ Fresh,
   pwd-outside-workspace ⇒ Fresh, fd-derived dev/ino + path binding.
5. `sign@vt` local=workspace vs relay=per-connection classification; raw
   commit-sign and sign@vt sharing the workspace scope family.
6. Decrypt batches: workspace scope per `(type, salt)`, all-of hit,
   legacy ⇒ fresh (existing tests adapted).
7. CLI: duration 0 ⇒ Fresh for that operation; >0 ⇒ StrictTtl; mode flags
   rejected/absent.
8. Diag: new basis strings, live counts scoped as specified; doctor
   version-mismatch warning on `agent_version` skew and on unparsable diag
   body.
9. known_hosts display resolution: match, hashed-entry miss, absent file.

## 12. Migration steps

1. Add `proc_info::get_cwd` + fd-based workspace resolution + tests.
2. Add bind state machine + plaintext `session-bind` interception in
   `extension()` **before** the keychain/auth-cipher path + tests (§3.1).
3. Add new `GrantScope` constructors with domain-separated digests.
4. Rewire handlers (raw sign, sign@vt, decrypt) to the new scopes.
5. Re-semanticize the two duration flags (0 = Fresh default); delete the
   two mode flags.
6. Replace diag basis reporting; update `vt doctor` incl. agent-version
   skew handling.
7. Add prompt reuse lines.
8. Delete `AuthCacheMode`, `classify_cache_context`, TTY/app/session
   helpers that lose their last caller, and V1 `ContextBasis` variants.
9. Update `docs/README.md`, `docs/diag-design.md`, `docs/sign-vt-design.md`,
   `CLAUDE.md` invariants, `config.example.toml`, `README.md` FAQ
   (ControlMaster + read-only-credential guidance + OpenSSH <8.9 note).
