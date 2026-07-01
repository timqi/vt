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
but unlike the removed PPID it is **stable** across orchestrated callers (Claude
Code / CI / make / tmux spawn a fresh shell per command from the same project
dir), so the cache still hits. (A previous build folded in the client-reported
parent PID instead of pwd; it was **removed** — PPID is both spoofable AND
*unstable* — `getppid()` changed every call so the cache never hit. The reported
`ppid` is now forensic-only: stored on each entry + audit row, not part of the
cache key.) On the cache hit, a real-time notice is also
pushed to any configured Pushover/Slack channel (best-effort, fire-and-forget).
Default is 0 (no cache, historical behaviour); caching is fully disabled unless
the `CACHE_SECKEY` worker secret is set. Every cache read (hit/miss) is audited.
See `docs/dek-cache.md` for the full design, threat model, and `wrangler secret
put CACHE_SECKEY` setup.

## Build

```bash
cargo build --release                                # native build
cargo check --target x86_64-unknown-linux-gnu        # Linux surface check (must stay green)
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
│   └── pushover.ts   Pushover delivery
└── pwa/
    ├── approve.html  (rendered dynamically with page data)
    ├── approve.js    WebAuthn ceremony; derives DEKs, seals to daemon pubkey
    ├── common.js     b64u, HKDF helpers
    ├── approve.css
    ├── icon.svg      key-themed app icon (vector master + tab favicon)
    ├── icon-512.png  512×512 app icon (iOS home-screen / PWA install)
    ├── admin/        audit + Passkey pages (Access-gated): audit.js, setup.js, cbor.js, admin.css
    └── libsodium.js  (not committed — see pwa/libsodium.README)
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
| `VT_AUTH` | SSH agent path (CLI ↔ local `vt ssh agent`, AES-GCM payload key) | macOS workstations running the agent; generated by `vt init` |
| `VT_PASSKEY_URL` | CF passkey path — worker base URL, e.g. `https://vt-passkey.example.com` | every host using the phone-approval ceremony |
| `VT_PASSKEY_TOKEN` | CF passkey path — HMAC key for `/api/challenge` request signing | every host using the phone-approval ceremony |

`VT_PASSKEY_TOKEN` must match the `VT_AUTH_CF` wrangler secret on the worker.

Routing rules:
- `VT_AUTH` set → try SSH agent first; fall back to passkey on recoverable errors.
- `VT_AUTH` unset → skip agent, go straight to passkey.
- Neither configured → CLI refuses at startup with an actionable error.

**Config-file fallback.** Env vars are primary and always win. As a fallback,
any unset `VT_*` variable is loaded from a flat TOML file at
`~/.config/vt/config.toml` (override the path with `$VT_CONFIG`). Only keys
matching `^VT_[A-Z0-9_]+$` are honoured; a set env var is never overridden.
Loading happens once in `main()` (`src/config.rs::hydrate_env_from_file`) before
`Cli::parse()` and before the tokio runtime is built, by populating `std::env`,
so every existing read (including clap's `env = "VT_AUTH"`) transparently picks
up file values. Malformed/absent file → silent no-op (env path still works); a
group/other-readable file logs a `chmod 600` warning since it holds secrets. See
`config.example.toml` for the template. (The previous JSON file
`~/.config/vt/cf_config.json` was removed; this TOML fallback replaces it.)

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
phone. See `docs/agent-audit.md`.

See `docs/agent-audit.md` for the full design and threat model.

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
- TCC grants are inherited (intentional — Zed needs disk access).

Enable on the agent:

```bash
vt ssh agent --run-allow zed,code,subl
# or with absolute paths:
vt ssh agent --run-allow /Applications/Zed.app/Contents/MacOS/cli
```

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
- **SIGKILL is the only kill that lands.** SIGSTOP would pause but not terminate. Everything else is ignored. Reboot or `kill -9` is out of vt's reach; the file is left plaintext on disk with an orphaned `.vt-backup-*` next to it (no automatic crash-recovery yet — see "Known gaps" below).

Other properties:

- **`--timeout` must be ≥ 1.** Enforced at clap layer (`value_parser = clap::value_parser!(u32).range(1..)`); `vt inject -r FILE -t 0` is rejected upfront.
- **Plaintext routing via Unix composition, not flags.** No `--output-file` or `--stdout` mode — use the child: `vt inject -r a.vt -- cat a.vt`, `… -- cp a.vt /tmp/b`, `… -- jq .key a.vt`.
- **env/argv decryption is independent of `-r`.** `vt inject -- cmd ...` (no file) still scans the parent's env and the trailing argv, decrypts any `vt://` values, sets the resolved env vars into the child, and execs.
- **Symlinks refused.** `O_NOFOLLOW` on the original `-r` file and on every backup/temp create means a squatted symlink can't redirect the write.
- **Path agnostic.** Same routing as the other CLI verbs — tries SSH agent first when `VT_AUTH` is set, falls back to the CF passkey ceremony.

Known gaps:

- **No crash-recovery on reboot.** If the system reboots while the supervisor is sleeping, the supervisor dies and never restores. Plaintext stays at `target`, ciphertext sits at the orphaned `.{name}.vt-backup-*` sibling. Manual recovery is `mv .{name}.vt-backup-* target`. A future on-boot sweep (sidecar state files + `vt inject --recover`) is deferred.
- **Snapshot / backup leakage.** If Time Machine, ZFS snapshots, restic, etc., run while the plaintext is exposed, the snapshot retains plaintext indefinitely even after the supervisor restores. Out of scope.

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
  (longest CWD-prefix wins), so the agent need not export secrets. Per-var
  precedence: **process env > `dirs` > `default`** (env always wins; config is a
  fallback, matching config.toml's convention). Config-sourced values are
  prepended to the rewrite as `NAME='vt://…'`; env-sourced values are used
  as-is. env-first also makes shim+PreToolUse compose without double-injecting
  (a var already plaintext in the env is not re-injected). CWD comes from the
  PreToolUse event's `cwd` (else the hook's CWD).
- **Compound commands**: the string paths (`claude`/`check`) split the command
  at top-level `|`/`||`/`&&`/`;`/newline (`split_segments`, quote/escape/paren
  aware) and evaluate each segment, so a target after an operator still injects
  and a block can't be bypassed by `true && gh auth token`; multiple targets
  union their env vars into one `bash -c` rewrite. Blind spots: `$(…)`/backtick/
  `(subshell)` interiors and a background `cmd &` tail. The exec-gateway/shim
  path is per-command (clean argv), so it needs no segmentation.
- **Launchers**: a top-level `launchers = ["mise exec","env",…]` list peels
  wrapper prefixes so `mise exec gh …` matches the `gh` rule (`effective_invocation`
  skips launcher tokens + their options/`NAME=val`/`tool@ver`, honoring `--`,
  then re-checks for nesting). The command runs verbatim; injected env
  propagates through. First launcher token matched by basename; `sudo` excluded
  (scrubs env). Full path already works everywhere (basename matching).
- **Surfaces** (all share `decide()`): `vt hook claude` (PreToolUse JSON →
  `updatedInput` rewrite); `vt hook check <cmd>` (dry-run ACCEPT/BLOCK/REWRITE);
  `vt hook exec -- <argv>` (exec-gateway — execs argv, or `vt inject -- argv`,
  or exits 126 on block; no shell/`bash -c` since argv is clean); `vt hook
  install-shims [--dir]` (one PATH shim per command AND per launcher leading
  token). Shims are **symlinks to the vt binary** (busybox-style): `main()`
  dispatches any non-`vt` `argv[0]` to `hook::shim_main` → `run_exec`. When
  re-execing the real tool, `resolve_real` skips PATH candidates that
  canonicalize to the vt binary (self), so a shim never resolves to itself —
  robust to symlinked PATH entries (`/home`→`/essd`); a `VT_HOOK_DEPTH` counter
  is the loop backstop. The launcher shim (e.g. `mise`) is what catches
  `mise exec <managed-tool>`, which bypasses `$PATH` and so wouldn't hit the
  per-tool shim. Shells have no rewrite-capable pre-exec hook, so shims are the
  universal (interactive + scripts + non-interactive) integration.
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
cd cf-worker
npm install
# Place pwa/libsodium.js (see pwa/libsodium.README)
wrangler deploy
# Set secrets (once):
wrangler secret put VT_AUTH_CF
wrangler secret put CREDENTIALS_JSON      # generated by the admin setup page — see below
wrangler secret put PUSHOVER_JSON         # {"app_token","user_key"} — optional; generated by the 推送渠道 tab
wrangler secret put SLACK_JSON            # {"webhook_url"} — optional; generated by the 推送渠道 tab
```

Notification channels (Pushover, Slack) are independent and opt-in: each is one
JSON secret generated client-side on the Access-gated admin "推送渠道" tab at
`/<ADMIN_SEG>/channels`. Enable either, both, or none. Empty/absent secret →
that channel is disabled. Delivery is best-effort and never blocks approval.

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

1. `cargo check` -- must compile
2. `cargo check --target x86_64-unknown-linux-gnu` -- Linux boundary check
3. `cargo test` -- unit tests
