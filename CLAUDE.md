# CLAUDE.md — vt passkey v2

Single-binary KMS with Passkey-based approval for Linux. No daemon, no
master_key cache. Secrets stay encrypted at rest and are decrypted
on-demand via a phone WebAuthn ceremony.

**Opt-in DEK cache (off by default).** The approver may grant a short TTL
(8m / 20m / 2h) at approval time; within that window, decrypt requests for the
same records from the **same source IP and same working directory** are served
from a server-side cache **without a phone approval**. This deliberately trades
the "every decrypt needs the phone" guarantee for convenience: in the window,
those records collapse to a single factor (possession of `VT_PASSKEY_TOKEN`) for
a caller behind the same egress IP in the same cwd. The cache key `ctx` binds
two factors: (1) **IP** (worker-derived from `CF-Connecting-IP`, unspoofable by
the client) — the **hard boundary** that defeats token exfiltration to another
host; and (2) the client-reported **`pwd`** — an **advisory** same-host
blast-radius reducer, so a cached grant for one project tree does not serve a
decrypt from an unrelated directory. `pwd` is client-reported (a fully
compromised local host can spoof it, so it never widens the real IP boundary),
but it is **stable** across orchestrated callers (Claude Code / CI / make / tmux
spawn a fresh shell per command from the same project dir), so the cache still
hits. (An earlier build keyed on the client-reported PPID instead; removed
because `getppid()` is both spoofable AND *unstable* — it changed every call so
the cache never hit. `ppid` is now forensic-only: stored on each entry + audit
row, not in the cache key.) On the cache hit, a real-time notice is also pushed
to any configured notification channel (best-effort, fire-and-forget).
Default is 0 (no cache, historical behaviour); caching is fully disabled unless
the `CACHE_SECKEY` worker secret is set. Every cache read (hit/miss) is audited.
See `docs/dek-cache.md` for the full design, threat model, and `wrangler secret
put CACHE_SECKEY` setup.

## Build

Recipes live in the `justfile` (`just` lists them):

```bash
just build                                           # release build (native)
just install                                         # build (musl-static on Linux) + install to ~/.local/bin
just check                                            # cargo check host + x86_64-unknown-linux-gnu (must stay green)
cargo test                                           # unit tests
```

## Source tree

```
src/
├── main.rs          clap routing
├── cf.rs            CF ceremony client (POST /api/challenge + WS /api/dek)
├── client.rs        CLI bodies; tries SSH agent, falls back to CF
├── core.rs          vt:// URL format, AES-GCM v2 envelope, wire types
├── core/
│   ├── crypto.rs    AesGcmCrypto, HKDF, derive_auth_cipher
│   ├── session.rs   AuthOutcome / SessionFlags
│   └── wire.rs      ExtResponse / ErrKind
├── tty.rs           password prompt
├── ssh_sign.rs      portable SSH identity: `vt ssh keygen` / `vt ssh connect` (cross-platform; see docs/ssh-vt-design.md)
└── server_macos/    macOS Keychain + Touch ID + SSH agent (cfg-gated)

cf-worker/            TypeScript Cloudflare Worker + PWA
├── src/
│   ├── index.ts      Hono router
│   ├── do_account.ts AccountDO (hibernating WebSocket + DO storage)
│   ├── crypto.ts     challenge_hash, HMAC, b64u
│   ├── access.ts     Cloudflare Access JWT verify (gates /<ADMIN_SEG>/*)
│   ├── credentials.ts CredentialsBlob parse + lookup
│   ├── webauthn.ts   WebAuthn assertion verify (P-256, Ed25519)
│   ├── notify.ts     shared message builders + fan-out to stateless channels
│   ├── pushover.ts   Pushover delivery (stateless)
│   ├── slack.ts      Slack Incoming Webhook delivery (stateless, one-way)
│   ├── slack_app.ts  Slack bot channel (stateful: @mention + chat.update edit)
│   └── feishu.ts     Feishu/Lark bot channel (stateful: @mention + editable card)
└── pwa/
    ├── approve.html  (rendered dynamically with page data)
    ├── approve.js    WebAuthn ceremony; derives DEKs, seals to daemon pubkey
    ├── common.js     b64u, HKDF helpers
    ├── approve.css
    ├── icon.svg      key-themed app icon (vector master + tab favicon)
    ├── icon-512.png  512×512 app icon (iOS home-screen / PWA install)
    ├── admin/        audit + Passkey pages (Access-gated): audit.js, setup.js, cbor.js, admin.css
    └── libsodium.js  (vendored/committed, ISC — see pwa/libsodium.README + THIRD_PARTY_LICENSES)
```

The admin tab labelled **Passkey** (route `/<ADMIN_SEG>/setup`, `setup.js`)
manages `CREDENTIALS_JSON` — bootstrap / add / revoke plus a list of currently
enrolled Passkeys. See "Passkey enrollment" below. Favicons/app-icon are wired
in via `FAVICON_TAGS` in `index.ts` (vector `icon.svg` for tabs, `icon-512.png`
for `apple-touch-icon`).

## Architecture

```
CLI (vt read / write / auth / run / inject)
  |
  +-- if $VT_AUTH set: try $SSH_AUTH_SOCK / ~/.ssh/vt.sock  (macOS: vt ssh agent)
  |    -> SSH extension protocol encrypt@vt / decrypt@vt / auth@vt / run@vt
  |
  +-- if $VT_PASSKEY_URL + $VT_PASSKEY_TOKEN set, CF ceremony
  |   (used as fallback when agent path is unavailable, or as the only path
  |    when $VT_AUTH is unset — e.g. Linux servers):
       1. Read VT_PASSKEY_URL + VT_PASSKEY_TOKEN from env
       2. Generate ephemeral X25519 keypair + per-record salts
       3. POST /api/challenge  (HMAC-signed)
       4. Open WS /api/dek?poll_token=X
       5. User approves on phone (Passkey WebAuthn + PRF)
       6. PWA derives DEK[i] = HKDF(master_key, salt[i], "vt-dek-v2")
          seals [DEK_0||...||DEK_n] to daemon's X25519 pubkey (libsodium)
       7. WS delivers sealed bytes; CLI opens sealed_box -> DEKs
       8. CLI encrypts/decrypts records locally with DEKs

Worker (CF TypeScript, wss://vt-passkey.example.com)
  AccountDO -- singleton with hibernating WS, storage alarms, SQLite audit table
  Ceremony endpoints at the root (/api/challenge, /api/dek, /api/approve,
  /api/reject, /a/:token); secured by HMAC(VT_AUTH_CF) + unguessable tokens +
  WebAuthn (no secret path prefix).
  Admin surface at /<ADMIN_SEG>/ (audit + setup) -- gated by Cloudflare Access
  (edge) + access.ts JWT verification. ADMIN_SEG is a constant in index.ts.
```

## CLI configuration

Each transport path is gated by its own env vars. At least one must be set.

| env | enables | required on |
|---|---|---|
| `VT_AUTH` | SSH agent path (CLI ↔ local `vt ssh agent`, AES-GCM payload key) | macOS workstations running the agent; hosts that reach it over a forwarded socket; generated by `vt init` |
| `VT_PASSKEY_URL` | CF passkey path — worker base URL, e.g. `https://vt-passkey.example.com` | every host using the phone-approval ceremony |
| `VT_PASSKEY_TOKEN` | CF passkey path — HMAC key for `/api/challenge` request signing | every host using the phone-approval ceremony |
| `VT_BACKEND` | routing pin: `auto` (default) \| `agent` \| `passkey` | optional; see routing rules |

`VT_PASSKEY_TOKEN` must match the `VT_AUTH_CF` wrangler secret on the worker.

Routing rules (`VT_BACKEND=auto`, the default):
- `VT_AUTH` set → try SSH agent first; fall back to passkey on recoverable errors.
- `VT_AUTH` unset → skip agent, go straight to passkey.
- Neither configured → CLI refuses at startup with an actionable error.

Pins (`src/config.rs::Backend`, validated in `VTClient::new`):
- `VT_BACKEND=agent` → agent only, never falls back to the passkey ceremony
  (unreachable socket is an error instead of silently paging the phone).
  Requires `VT_AUTH`. `sign@vt`'s decrypt-then-sign fallback still applies —
  its decrypt honors the pin.
- `VT_BACKEND=passkey` → never probes the agent socket even when `VT_AUTH` is
  set. Requires `VT_PASSKEY_URL`. `vt run` (agent-only) errors out under it.
- Invalid values fail loudly at startup, not silently as `auto`.

Config-file hydration makes a config.toml `VT_AUTH` fully equivalent to the
env var: under `auto` it still means "probe the agent path first" — the CLI
verifies the path per call (socket connect; a non-vt agent answers the
extension with a failure) and falls back to the passkey ceremony cleanly, so
keeping `VT_AUTH` in a config shared across hosts is fine. The cost on a
host with no reachable vt agent is one failed local socket round-trip per
call; pin `VT_BACKEND=passkey` there if you want to skip even that. To force
the phone path for a single invocation: `VT_AUTH= vt …` (set-but-empty env
var beats the file and an empty token skips the agent) or
`VT_BACKEND=passkey vt …`.

**Config-file fallback.** Env vars are primary and always win. As a fallback,
any unset `VT_*` variable is loaded from a flat TOML file at
`~/.config/vt/config.toml` (override the path with `$VT_CONFIG`). Only keys
matching `^VT_[A-Z0-9_]+$` are honoured; a set env var is never overridden.
Loading happens once in `main()` (`src/config.rs::hydrate_env_from_file`) before
`Cli::parse()`, by populating `std::env`, so every existing read (including
clap's `env = "VT_AUTH"`) transparently picks up file values. Malformed/absent
file → silent no-op (env path still works); a
group/other-readable file logs a `chmod 600` warning since it holds secrets. See
`config.example.toml` for the template. (The previous JSON file
`~/.config/vt/cf_config.json` was removed; this TOML fallback replaces it.)

### Agent auth cache (opt-in)

`vt ssh agent` can cache a successful Touch ID / FIDO2 / password decision so
repeat `sign` / `decrypt@vt` requests within a TTL skip the prompt. Both caches
default to `none` (every request prompts):

| flag | default TTL | scope |
|---|---|---|
| `--ssh-auth-cache-mode` + `--ssh-auth-cache-duration` | 120s | SSH `sign` + `sign@vt` (`vt ssh connect`), per `SHA-256(fingerprint‖pwd)` — the two share one cache |
| `--decrypt-auth-cache-mode` + `--decrypt-auth-cache-duration` | 30s | `decrypt@vt`, per record (`SHA-256(type‖salt‖host‖pwd)`); any legacy item in a batch disables caching for that batch |

Both cache keys fold in the client-reported **`pwd`** (from `ClientMeta`) as an
**advisory** narrower, mirroring the Worker DEK cache: it scopes a grant to one
project tree (load-bearing for `global` mode, where the context itself is
shared) but never widens the hard context boundary — a compromised caller can
spoof `pwd`, so it is a blast-radius reducer, not an authentication factor.
Plain agent-protocol `sign` requests carry no `ClientMeta` and key on an empty
`pwd` (one shared slot per fingerprint, as before).

Modes: `per-session` keys on the terminal session leader (`getsid` + start
time); `per-app` keys on the nearest `.app/Contents/` ancestor (all tabs of one
terminal app share a context; **no ancestor found → uncacheable**, so under
tmux / ssh logins per-app always prompts rather than silently keying on the
short-lived peer). Both require the caller to have a controlling TTY —
**orchestrated callers (AI agents / CI / make) spawn TTY-less commands with a
fresh session per call, so they can never hit these modes.** `global` is the
escape hatch for that case: ONE shared context for the whole agent, no TTY
requirement — the coarsest blast radius (within the TTL any socket reacher
rides one grant per `pwd`; only the pwd key component, the TTL and the
lock/wake/idle flushes bound it). `auth@vt` / `run@vt` NEVER cache.

Expiry is tracked on **both** the monotonic and the wall clock (macOS `Instant`
freezes during sleep — either clock passing the TTL kills the entry), grants are
strict-TTL (no sliding refresh), and both caches are flushed on: agent `lock`,
screen lock, wake-from-sleep (detected via clock divergence), and idle key
clearing. All prompts are serialized through a global one-permit semaphore so a
hostile peer cannot stack dialogs; cached paths **re-check the cache after the
queue wait** (grants land while the permit is still held), so an N-request
burst for the same key/records costs one Touch ID, and the waiters resolve as
silent cache hits.

When audit push is configured (`--audit-url`/`--audit-key`), every agent-side
cache hit also triggers a **免审批 notice** on the same notification channels
as the Worker DEK-cache hit (Pushover / Slack / Slack App / Feishu), with the
note 「缓存命中，免 Touch ID」. Throttled Worker-side to one notice per
(op_kind, host) per 60s — the audit table still records every hit.

**Forwarded-agent narrowing (per-connection contexts):** when the local peer
is the OpenSSH client (basename `ssh`), every mode — including `global` —
anchors the context on that ssh process itself (`(pid, start_time)`) instead
of its terminal session / app ancestor. A remote host can therefore reuse its
*own* approvals within the TTL (caching still works over forwarding), but it
can never ride grants issued by other local tabs or by other remote hosts, and
the context dies with the ssh connection. Residual (deliberate) tradeoffs:
within the TTL, any process on that one remote host can silently reuse that
connection's grants — keep `none` when forwarding to hosts you don't trust at
all. And because the agent cannot distinguish ssh authenticating itself from
ssh relaying a forwarded request (same peer process), plain outbound `ssh
host` signs are narrowed too: repeated one-shot ssh invocations no longer
share a grant within the TTL (ControlMaster-multiplexed connections still do —
one long-lived master process). Detection is by binary basename, so a renamed
ssh evades it (it then falls through to the normal mode rules, incl. the
per-session/per-app TTY gate); the goal is grant scoping for honest forwarding
setups, not containing local malware. **The `vt ssh connect
--forward-real-agent` relay (peer basename `vt`) gets the SAME per-connection
narrowing** — `resolve_cache_context` recognises it by kernel-derived argv
(`KERN_PROCARGS2` → pure `parse_procargs2` → `is_vt_relay_invocation`: basename
`vt` + `ssh connect` + `--forward-real-agent`) and anchors on the relay
`(pid, start_time)` in every mode (incl. `global`, no TTY gate), so a relayed
`decrypt@vt` grant dies with that `vt ssh connect` process and is never ridden
by local tabs or other hosts. Argv is process-controlled but a spoofed match
only narrows a caller to its own context (never widens), so trusting it here is
safe — same asymmetry as the ssh basename check.

### Agent audit push (opt-in)

`vt ssh agent` can push one audit record per Touch ID decision (encrypt@vt /
decrypt@vt / auth@vt / run@vt / sign, including auth-cache hits) to the Worker,
which stores it in the same `audit` table the phone ceremony uses, marked
`source='agent'`. Fire-and-forget — never blocks the decision. Opt-in via agent
flags (no new env vars, no new worker secret — it reuses `VT_AUTH_CF`):

| agent flag | meaning |
|---|---|
| `--audit-url <URL>` | Worker base URL, e.g. `https://vt.example.com`. Unset = audit push off. |
| `--audit-key <KEY>` | the worker master (`VT_AUTH_CF`, == `VT_PASSKEY_TOKEN`). The agent derives its per-host audit subkey from this + the hostname at startup. On the command line → visible in `ps`; avoid on shared hosts. |
| `--no-audit-push` | disable even when `--audit-url` is set. |

Zero-token: no pre-derivation, no per-agent file. `agent_id` is the hostname; the
agent computes `HKDF(VT_AUTH_CF, hostname)` itself (Worker verifies the same).

```bash
vt ssh agent --audit-url https://vt.example.com --audit-key "$VT_PASSKEY_TOKEN"
```

Tradeoff: this puts the worker master on the agent host — a compromised agent can
forge any host's audit rows and make authenticated worker requests: `/api/challenge`
is still phone-gated, but `/api/dek-cache` returns cached DEKs with no phone in the
loop within the TTL window for the same egress IP (same IP binding as the CLI). It
still cannot decrypt secrets that aren't cached — the vault master stays on the
phone. Full design and threat model: `docs/agent-audit.md`.

## run@vt — remote-triggered local command launcher

`vt run -- <argv...>` (typically run on a remote host with the SSH agent
forwarded back to a Mac) asks the local agent to fork/exec a program on the
Mac after Touch ID. Use case: `vt run -- zed ssh://g1/some/path` from inside
a remote shell opens Zed locally on the remote folder.

Properties:
- **Allowlist-gated.** Agent only spawns programs whose `argv[0]` matches
  `--run-allow` (comma-separated). Bare names (`zed`) match argv[0] only
  when argv[0] also has no `/`; the agent resolves them against its own
  PATH. Slash-bearing entries must be absolute and match argv[0] post-
  canonicalize. Empty allowlist disables the feature.
- **Touch ID every call.** Same policy as `auth@vt` — never cached,
  because forwarded agents share one process across all remote sessions.
- **Concurrent prompts serialized** via a global `Semaphore(1)` so a
  hostile peer with `VT_AUTH` cannot queue dozens of prompts at the user.
- **Fire-and-forget.** Child detaches via `setsid`, stdio → /dev/null,
  fds ≥ 3 closed, cwd = `$HOME`. Reaped by a background task.
- **Env scrubbed.** Child inherits `env_clear()` plus an allowlist of
  benign vars (HOME / USER / PATH / SHELL / TERM / TMPDIR / LANG /
  LC_ALL / LC_CTYPE / DISPLAY). VT_AUTH, VT_PASSKEY_*, SSH_AUTH_SOCK,
  SSH_AGENT_PID, DYLD_*, LD_*, PYTHONPATH, RUBYOPT, NODE_OPTIONS,
  PERL5LIB etc. are all dropped — a granted Touch ID cannot be used to
  exfil credentials or re-enter the agent via the forwarded socket.
- **No CF passkey fallback.** `run@vt` is SSH-agent-only by design.
- **Never relayed.** The `vt ssh connect --forward-real-agent` relay refuses
  `run@vt` (see below) — a forwarded remote can never trigger local spawns.
- TCC grants are inherited (intentional — Zed needs disk access).

Enable on the agent:

```bash
vt ssh agent --run-allow zed,code,subl
# or with absolute paths:
vt ssh agent --run-allow /Applications/Zed.app/Contents/MacOS/cli
```

## vt ssh connect --forward-real-agent — filtered relay over agent forwarding

Default OFF. Plain `vt ssh connect` runs an ephemeral in-process agent that
only answers `REQUEST_IDENTITIES` + `SIGN_REQUEST` (with vt context injected
into the Touch ID prompt); a remote `vt read`/`vt inject` behind
`vt ssh connect -A host` therefore couldn't reach the local vt agent and fell
back to the phone ceremony. With `--forward-real-agent`, the ephemeral agent
also implements the agent `extension` op as a **transparent, filtering relay**
to the UPSTREAM real vt agent (socket captured at startup: parent
`$SSH_AUTH_SOCK`, else `~/.ssh/vt.sock` — never the child's overridden env),
and the child ssh is pinned with `-o ForwardAgent=<ephemeral sock>` (OpenSSH ≥
8.2 path form; beats a config `ForwardAgent /real.sock` that would forward the
real agent unfiltered). Filter (`route_extension` in `src/ssh_sign.rs`, pure +
unit-tested, matched on the cleartext extension name — the payload stays an
opaque AES-GCM(VT_AUTH) blob; the relay holds no VT_AUTH):
`decrypt@vt`/`encrypt@vt`/`auth@vt`/`sign@vt` → relayed verbatim (fresh
upstream connection per request); `run@vt` and everything else → refused
with `SSH_AGENT_FAILURE` (remote falls back to the passkey ceremony).
`sign@vt` relays (it was originally refused) so a nested remote
`vt ssh connect` (git on the remote) signs with the Mac-held key instead of
falling back to decrypt-then-sign, which landed the raw git-key seed in
remote process memory. It can name ANY upstream agent key and the relay
cannot filter by key, so the mitigation lives upstream: per-op Touch ID whose
prompt shows the agent-derived `key:` label (comment, else fingerprint) and a
`via forwarded vt relay` origin marker (all relayed-op prompts carry it), and
per-connection sign-cache narrowing (below). This is
the deliberate narrowing vs raw `ssh -A` of the real agent; residual risk is
the same as any agent forwarding — while the connection is up, any process on
the remote can trigger relayed (Touch-ID-gated) requests. The upstream agent's
per-connection cache narrowing IS preserved for the relay (see "Forwarded-agent
narrowing" above): a relayed `decrypt@vt` grant is scoped to that
`vt ssh connect` process. `sign`/`request_identities` behavior is unchanged.
Full design + threat model: `docs/ssh-vt-design.md` §11.

## vt inject — transient in-place decryption

`vt inject [-r FILE] [-t SECS] -- <cmd...>` decrypts every `vt://` it finds in
(a) the `-r` file, (b) the trailing argv, and (c) any env var whose value
contains a `vt://`, then `exec`s `cmd` so the child sees plaintext.

The plaintext-exposure protocol (when `-r` is set):

1. Open target with `O_NOFOLLOW`, stat to capture mode + reject non-regular.
2. Write a sibling `.{name}.vt-backup-{rand}` (ciphertext copy, `O_CREAT|O_EXCL|O_NOFOLLOW`, mode = orig).
3. **Spawn the restore supervisor** (self-exec'd `vt _internal-restore-after`, hidden subcommand). On spawn failure, delete the backup and return — no plaintext has touched disk yet.
4. Write the plaintext to a sibling `.{name}.vt-tmp-{rand}` (same hidden-name rules as backup).
5. `rename(tmp, target)` — atomic plaintext exposure.
6. Parent `exec`s the user command. Supervisor restores ciphertext after `--timeout`.

On exec failure the parent immediately `rename`s the backup back over target so the user doesn't wait out the timeout. The still-running supervisor later observes `ENOENT` on the backup and exits silently.

Properties of the supervisor:

- **Self-exec'd, not in-process fork.** Spawn happens via `Command::spawn()` with `pre_exec`; the supervisor is `vt _internal-restore-after <secs> <tmp> <backup> <target>` — a hidden subcommand dispatched in `main()` *before* tokio / clap / tracing load. Avoids the multi-threaded-`fork()` malloc-deadlock class and gives the supervisor process a tiny RSS (vt's text segment shared with the parent via the page cache; no tokio runtime).
- **`setsid()` in `pre_exec`** detaches from the controlling TTY + session, so SIGHUP on terminal close and SIGINT on Ctrl+C of the parent's foreground pgroup don't reach us.
- **Signal dispositions installed in the subcommand body, not `pre_exec`.** Rust's runtime resets signals between `execve` and our entry point; installing `SIG_IGN` for HUP/INT/TERM/PIPE/QUIT *after* runtime init and *before* the double-fork is the only way to make them survive into the grandchild. Verified via `/proc/$pid/status` `SigIgn` mask.
- **Double-fork inside the subcommand body** orphans the sleeper to init (`PPID = 1`). The supervisor is invisible to user-cmd's process tree and `waitpid(-1)` loops.
- **Stdio attached to `/dev/null`** so output never leaks back to the user's terminal.
- **SIGKILL is the only kill that lands.** SIGSTOP would pause but not terminate. Everything else is ignored. Reboot or `kill -9` is out of the supervisor's reach; the file is left plaintext on disk with an orphaned `.vt-backup-*` sibling — recoverable via the crash-recovery sidecar + `vt inject --recover` (see "Crash recovery" below).

Other properties:

- **`--timeout` must be ≥ 1.** Enforced at clap layer (`value_parser = clap::value_parser!(u32).range(1..)`); `vt inject -r FILE -t 0` is rejected upfront.
- **Plaintext routing via Unix composition, not flags.** No `--output-file` or `--stdout` mode — use the child: `vt inject -r a.vt -- cat a.vt`, `… -- cp a.vt /tmp/b`, `… -- jq .key a.vt`.
- **env/argv decryption is independent of `-r`.** `vt inject -- cmd ...` (no file) still scans the parent's env and the trailing argv, decrypts any `vt://` values, sets the resolved env vars into the child, and execs.
- **Symlinks refused.** `O_NOFOLLOW` on the original `-r` file and on every backup/temp create means a squatted symlink can't redirect the write.
- **Path agnostic.** Same routing as the other CLI verbs — tries SSH agent first when `VT_AUTH` is set, falls back to the CF passkey ceremony.

**Crash recovery.** When the supervisor is armed, a sidecar JSON
(`~/.local/state/vt/inject/<rand>.json`, mode 0600, carrying only
`{target, backup, tmp, deadline_ms}` — no secret) is written *before any
plaintext hits disk*. It is deleted on every normal restore path (parent's
immediate-restore and the supervisor's post-timeout restore). If the machine
reboots or the supervisor is SIGKILLed mid-sleep, the sidecar survives:
`vt inject --recover` (run at login/boot — no `VT_AUTH` needed, it only moves
the ciphertext backup back) sweeps the dir and restores any entry whose backup
still exists and whose window has elapsed (past `deadline_ms + 5s` grace, so a
still-sleeping supervisor is never raced). The pure decision is
`plan_recovery` in `src/client.rs` (unit-tested); a not-yet-elapsed entry is
reported as "still active" and left for its supervisor.

Known gaps:

- **Reboot inside a long window.** `--recover` restores only past-deadline
  entries, so plaintext exposed under a long `--timeout` stays exposed until
  the window elapses; re-running `--recover` after that restores it. (Strictly
  better than the previous "no recovery at all" — the sidecar guarantees the
  exposure is discoverable.)
- **Snapshot / backup leakage.** If Time Machine, ZFS snapshots, restic, etc., run while the plaintext is exposed, the snapshot retains plaintext indefinitely even after the supervisor restores. Out of scope.
- **No master-key rotation.** `master_key == mac_key` is a deliberate unified-vault invariant, so revoking a Passkey or rotating `CACHE_SECKEY` does not re-key stored records: a leaked master leaves every past/future `vt://` decryptable. Accepted for now; a break-glass `vt rotate-master` (re-wrap under all Passkeys + re-encrypt every record) is not implemented.

## vt hook — transparent secrets for AI coding agents

`vt hook claude` is a PreToolUse hook processor: it reads an agent's proposed
shell command (JSON on stdin), matches it against a `[[hook.rules]]` whitelist
in `config.toml`, and emits a decision on stdout — **accept** (no output),
**block** (`permissionDecision: deny`), or **rewrite** (Claude Code's
`hookSpecificOutput.updatedInput.command`). The rewrite wraps the command as
`vt inject --only-env <vars> --reason 'vt hook: <prog>' -- bash -c '<orig>'`, so
vt:// secrets in the environment are decrypted on-demand and the child sees
plaintext. Goal: an agent keeps `KEY=vt://…` in its env and never knows the
secret is protected.

- **Whitelist** (`config.rs::HookConfig` / `load_hook_config`): rules live in a
  DEDICATED file `~/.config/vt/agent.toml` (override `$VT_AGENT_CONFIG`), NOT in
  `config.toml` — config.toml holds secrets (never synced) while hook rules
  carry no secrets and are meant to be synced (symlink into dotfiles / point
  `$VT_AGENT_CONFIG` at a checked-in copy). Template: `agent.example.toml`. Top-
  level `[[rules]]`; each rule has `command` (matched by argv[0] **basename**),
  optional `args` (a positional subcommand prefix, e.g. `["auth","token"]` →
  `gh auth token`), `env_vars` (decrypted only when vt://-valued, via
  `--only-env` — never leaks unrelated secrets), optional `block`/`reason`.
  **Block rules win over inject rules** regardless of order, so a specific deny
  (`gh auth token`) overrides a broad inject (`gh`).
- **Env-var values** can be supplied centrally in the same file via
  `[env.default]` (all PWDs) and per-directory `[env.dirs."<abs path>"]`
  (longest CWD-prefix wins; a leading `~`/`~/` in the key is expanded to
  `$HOME`), so the agent need not export secrets. Per-var
  precedence: **`dirs` > `default` > process env** (agent config wins; a stray
  ambient env var can't silently override a per-project value). Config-sourced
  values are prepended to the rewrite as `NAME='vt://…'`; env-sourced values are
  used as-is. Accepted tradeoff of config-first: shim+PreToolUse no longer
  compose without double-injecting — once an outer layer decrypts a var to
  plaintext, an inner layer still re-reads the config `vt://` value and decrypts
  it again (silent DEK-cache hit when caching is on, else an extra approval).
  CWD comes from the PreToolUse event's `cwd` (else the hook's CWD).
- **Compound commands**: the string paths (`claude`/`check`) split the command
  at top-level `|`/`||`/`&&`/`;`/newline (`split_segments`, quote/escape/paren
  aware) and evaluate each segment, so a target after an operator still injects
  and a block can't be bypassed by `true && gh auth token`; multiple targets
  union their env vars into one `bash -c` rewrite. Blind spots: `$(…)`/backtick/
  `(subshell)` interiors and a background `cmd &` tail. The exec-gateway/shim
  path is per-command (clean argv), so it needs no segmentation.
- **Program resolution**: `effective_invocation` skips leading `NAME=val`
  assignments, then takes the next token as the program (basename-matched, so a
  full path already works everywhere).
- **Surfaces** (all share `decide()`): `vt hook claude` (PreToolUse JSON →
  `updatedInput` rewrite); `vt hook check <cmd>` (dry-run ACCEPT/BLOCK/REWRITE);
  `vt hook exec -- <argv>` (exec-gateway — execs argv, or `vt inject -- argv`,
  or exits 126 on block; no shell/`bash -c` since argv is clean); `vt hook
  install-shims [--dir]` (one PATH shim per command). Shims are **symlinks to
  the vt binary** (busybox-style): `main()` dispatches any non-`vt` `argv[0]` to
  `hook::shim_main` → `run_exec`. When re-execing the real tool, `resolve_real`
  skips PATH candidates that canonicalize to the vt binary (self), so a shim
  never resolves to itself — robust to symlinked PATH entries (`/home`→`/essd`);
  a `VT_HOOK_DEPTH` counter is the loop backstop. Shells have no rewrite-capable
  pre-exec hook, so shims are the universal (interactive + scripts +
  non-interactive) integration.
- **Default policy is accept** — unlisted commands run unchanged (the hook is
  additive, not a sandbox). The whitelist's real job is scoping *which* commands
  may trigger a decryption approval (so `ls` with a stray vt:// env var doesn't
  prompt the phone).
- **Recursion guard:** a command whose leading program is `vt` is always
  accepted, so a re-fired hook never re-wraps `vt inject …`.
- **`bash -c "…"` is opaque** to argv[0] matching (documented limit). Logic
  lives in `src/hook.rs` (`evaluate()` is the pure, unit-tested core);
  `vt hook check <cmd>` is a dry-run. Full design + threat model: `docs/hook.md`.

## Worker deployment

```bash
cd cf-worker && npm install
# pwa/libsodium.js is vendored/committed (see pwa/libsodium.README to refresh it)
just deploy-worker                        # runs `wrangler deploy` in cf-worker/ (works from any dir in the repo)
# Set secrets (once):
wrangler secret put VT_AUTH_CF
wrangler secret put CREDENTIALS_JSON      # generated by the admin setup page — see below
wrangler secret put PUSHOVER_JSON         # {"app_token","user_key"} — optional; generated by the 推送渠道 tab
wrangler secret put SLACK_JSON            # {"webhook_url"} — optional; one-way Slack Incoming Webhook; 推送渠道 tab
wrangler secret put SLACK_APP_JSON        # {"bot_token","channel","mention"?} — optional; Slack bot: @mention + editable msg; see docs/slack-app.md
wrangler secret put FEISHU_JSON           # 飞书/Lark bot — optional; @mention + editable card; see docs/feishu.md
```

Notification channels (Pushover, Slack webhook, Slack App, Feishu/Lark) are
independent and opt-in: each is one JSON secret generated client-side on the
Access-gated admin "推送渠道" tab at `/<ADMIN_SEG>/channels`. Enable any subset or
none. Empty/absent secret → that channel is disabled. Delivery is best-effort and
never blocks approval.

**Slack App (`SLACK_APP_JSON`, `src/slack_app.ts`)** and **Feishu/Lark
(`FEISHU_JSON`, `src/feishu.ts`)** are the richer, *stateful* channels: unlike
the one-way Pushover/Slack-webhook posts they use a bot identity to (1)
**@-mention** approvers on a request and (2) **edit the message/card in place** on
the decision (✅/❌/⌛). Slack App uses a long-lived `xoxb-` bot token via
`chat.postMessage`/`chat.update` (no token cache); its DO wiring mirrors Feishu's
(`slackAppSendAndStore`/`slackAppEdit`, `challenge.slackapp` = {channel, ts}). See
docs/slack-app.md.

**Feishu/Lark (`FEISHU_JSON`, `src/feishu.ts`)** uses the self-built-app (bot)
API; its decision edit (✅ approved / ❌ rejected / ⌛ expired) names the Passkey
that approved. Because editing needs the sent `message_id`, Feishu is owned by
the **DO** (`do_account.ts`): `opCreate` fires the card via
`waitUntil` (NOT on the ceremony path) and writes back `feishu_message_id`;
`opApprove`/`opReject`/the `alarm` expire-sweep PATCH the card. A cached
`tenant_access_token` lives in DO storage (`feishu:tat:<app_id>`, refreshed on
`<60s` left or a token-invalid API error). The approval button is a plain URL
open-link (no card callback → no new inbound endpoint); cards set
`config.update_multi:true` so the edit reaches all group recipients. The API
host is derived ONLY from the `base` enum (`feishu`|`larksuite`) — the SSRF
boundary. The 免审批 (DEK-cache-hit) notice is trimmed to one line across ALL
channels and never @-mentions. Full setup + threat model: `docs/feishu.md`
(design notes: `docs/feishu-design.md`).

## Passkey enrollment (admin setup page)

`CREDENTIALS_JSON` is produced by the Access-gated admin setup page at
`/<ADMIN_SEG>/setup` (ADMIN_SEG is a constant in `index.ts`, currently
`kestrel`). The page has three modes; the resulting blob is copied out and
deployed manually via `wrangler secret put CREDENTIALS_JSON` (the page never
writes the secret itself).

**Unified vault invariant: the passkey-domain `master_key` IS the macOS
`mac_key`.** Because both domains derive DEKs identically
(`HKDF(master, salt, "vt-dek-v2")`, salt carried in the `vt://` URL), sharing
the master makes every v2 `vt://0…`/`vt://1…` record cross-decryptable between
the local Mac (keychain / SSH agent) and the phone passkey ceremony. Legacy
`vt://mac/…` records do not use a DEK — `vt rewrap` them to v2 first.

- **bootstrap (first Passkey)** — the master must come from the Mac, so this
  step needs the CLI. On the Mac: `vt secret export` (Touch ID), set a one-time
  export passphrase, copy the base64. On the setup page (ideally in the Mac's
  own browser to avoid cross-device copy): paste the base64 + passphrase; the
  page recovers `mac_key` in-browser (`SHA-256(SHA-256(utf8(passphrase)))` →
  AES-GCM decrypt of `nonce(12)||ct(32)||tag(16)`), registers the Passkey,
  reads its PRF, and wraps `mac_key` under it. "自检" verifies the Passkey
  unwraps the master.
- **add / revoke** — no macOS interaction. The Worker injects the current
  `CREDENTIALS_JSON` (env binding) into the page, so add/revoke read it
  directly (no manual paste). add uses an existing Passkey's PRF to unwrap the
  master, then wraps it under the new Passkey; revoke removes an entry and
  bumps `epoch`.
- The page also lists the currently enrolled Passkeys (label, credId prefix,
  date, count, epoch) read from the injected `CREDENTIALS_JSON`.

The injected blob is safe to embed: it holds only PRF-wrapped (encrypted)
master material plus public credential data (credId, COSE pubkey, label,
SHA-256(credId)), and the route is Cloudflare-Access gated.

## Key derivation

1. Phone PRF output K (32 bytes, deterministic per credential)
2. K_wrap = HKDF-SHA256(K, salt="", info="vt-master-wrap-v1", L=32)
3. master_key = AES-GCM-decrypt(K_wrap, stored k field, AAD="vt-master-key-v1"||h_bytes)
4. DEK[i] = HKDF-SHA256(master_key, salt=salt[i], info="vt-dek-v2", L=32)
5. vt:// record: AES-256-GCM(DEK[i], nonce=salt[..12], plaintext, AAD="vt:v2:"||type_byte)

At ceremony time master_key never leaves the phone and the daemon never holds
it. `master_key` equals the macOS `mac_key` (the keychain `passphrase`): the
macOS agent derives the same DEK at step 4 via `derive_dek(mac_key, salt)`
(`core/crypto.rs`), so the two domains share one root and v2 records
cross-decrypt. The only time the raw master crosses a boundary is the one-time
bootstrap (`vt secret export` → admin setup page), where it is recovered
in-browser to be wrapped under the first Passkey's PRF.

Consequence (accepted, unavoidable for cross-decryptability): the two
isolation domains are collapsed into one — a compromise of the Worker / phone
side can derive DEKs for records created on the Mac too.

## challenge_hash binding

challenge_hash = SHA-256(
  "vt-challenge-v2" (15 B)
  || daemon_pubkey   (32 B)
  || worker_nonce    (16 B)
  || timestamp_be    ( 8 B)
  || SHA-256(concat(salts)) (32 B)  -- binds salts to phone's assertion
  || action_byte     ( 1 B)         -- 0x01 approve / 0x02 reject (domain-separates the two flows)
)

The phone's WebAuthn assertion signs an *effective* challenge:
  approve: SHA-256(approve_challenge_hash || pwa_pk)   -- binds the PWA's ephemeral X25519 pubkey
  reject:  reject_challenge_hash
This prevents salt-swap and approve/reject replay; the daemon-side binding HMAC
(ECDH(pwa_sk, daemon_pk)) closes the malicious-Worker pwa_pk-substitution gap.

## Test gates

`just check` (host + `x86_64-unknown-linux-gnu` boundary) and `cargo test` must
stay green.
