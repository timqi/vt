# VT.app — bundle, menu bar UI, native notifications, key-wrap rebind

Design R2 (post codex-expert review; R1 findings folded in). Owner: this
document. Implements the migration of the
`vt` binary into a signed `.app` bundle with a Swift menu-bar shell, native
`UNUserNotificationCenter` notifications (replacing `osascript`), and the
master-key wrap-derivation migration that the path move requires.

## Goals

- VT-branded system notifications (own icon and name in System Settings →
  Notifications) instead of Script Editor via `osascript`.
- A persistent menu-bar presence: agent status at a glance, live grants with
  scope and remaining TTL, recent activity, and a panic "revoke everything"
  action.
- Cache-hit transparency: a grant reuse that skips Touch ID now fires a system
  notification (op + scope + remaining TTL), so silent reuse is observable in
  real time, complementing [`approval-transparency.md`](approval-transparency.md).
- Survive the binary path change: the master-key wrap currently derives from
  `current_exe()`; moving into the bundle must not lock the store.

## Non-goals (v1)

- No approval from the UI, ever. Touch ID sheets remain the only approval
  surface. The menu never gains a "grant"/"approve"/"extend" affordance.
- No `run@vt` surface in the UI beyond the existing allowlist count.
- No Worker/phone-approval integration.
- No per-grant revocation and no cache-TTL editing from the menu (v1.5).
- No Sparkle/auto-update (distribution remains `just install-app`).

## 1. Bundle layout and packaging

```
VT.app/Contents/
  Info.plist                 CFBundleIdentifier dev.rustyvault.vt, LSUIElement=true
  MacOS/VTApp                Swift menu-bar shell (also handles `VTApp notify ...`)
  MacOS/vt                   the Rust binary, unmodified role; CLI symlink target
  Resources/AppIcon.icns     generated from cf-worker/pwa/icon.svg / icon-512.png
```

The shell executable is `VTApp`, not `VT`: the default APFS volume is
case-insensitive, so `MacOS/VT` and `MacOS/vt` would be one file. Menu bar
and notifications show `CFBundleDisplayName` (`VT`) regardless.

- Executables under `Contents/MacOS/` share the bundle identity, so the Rust
  agent process itself counts as "VT" for notification and TCC purposes.
- Packaging is a `just app` recipe: `cargo build --release`, `swiftc` the
  shell, generate `AppIcon.icns` (`sips` scale-down set from `icon-512.png`;
  1024 upscaled once for `512@2x` — acceptable softness), assemble, then
  `codesign --force --deep -s "${VT_CODESIGN_ID:--}"` (ad-hoc by default,
  Developer ID when the env var is set).
- `just install-app` copies to `/Applications/VT.app` and symlinks
  `~/.local/bin/vt → /Applications/VT.app/Contents/MacOS/vt` (same target dir
  the existing `just install` uses).
- Menu-bar icon: the hex-nut key shape from the SVG redrawn as an `NSImage`
  template (code-drawn paths in Swift; monochrome, so it adapts to
  light/dark and lets us render state variants).

## 2. Master-key wrap v2 and `vt secret rebind`

Verified breakage: `derive_passphrase_secret` (`src/core/crypto.rs`) mixes
`current_exe()` into the wrap key; moving the binary makes the AES-GCM unwrap
fail. The path term is a soft binding with ~zero security value (the passcode
sits in the same keychain item; path and `$USER` are attacker-knowable), and
it also breaks Homebrew prefix moves.

- **Wrap v2**: derivation string becomes
  `base64(passcode):$USER:vt-wrap-v2` — the binary-path term is replaced by a
  fixed domain label. `$USER` stays (no added brittleness from the bundle
  move; dropping it would widen review scope for no gain).
- **Store marker**: `KeychainStore` gains `#[serde(default = "...")] wrap_v:
  u32` (serde default fn returning 1). `STORE_SCHEMA_VERSION` stays 1 so
  pre-migration binaries can still parse the store (they will fail the
  unwrap, not the parse — see rollback).
- **Transparent upgrade**: wherever the store is loaded and the unwrap
  *succeeds* with a v1 key (agent startup preflight, CLI ops), rewrap to v2.
  Review-mandated shape: a **new, minimal mutator** run as a closure inside
  `KeychainStore::modify` (the real `vt-keychain.lock` flock path) that
  re-reads the store under the lock, re-verifies `wrap_v == 1`, decrypts and
  re-encrypts **only** `encrypted_passphrase`, and sets `wrap_v = 2`. It must
  never touch `passcode_and_auth_token` (else VT_AUTH silently rotates),
  `encrypted_ssh_keys`, or `encrypted_fido2`, and must not reuse
  `create_and_save_passcode_passphrase` (which mints fresh secrets by design
  and saves without the flock). After the first successful run of the new
  binary at the *old path*, the store is path-independent before the move.
- **Old/new binary coexistence hazard**: an old binary still on `$PATH` that
  runs `init`/`import`/`rotate-passcode` performs a full store rewrite with
  the *old* derivation and drops the `wrap_v` field it does not know —
  silently downgrading a v2 store to "bound to the old binary's path".
  Operator doc must say: remove old `vt` binaries once migrated. The new
  binary's own `rotate-passcode`/`import` always write wrap v2.
- **`vt secret rebind [--old-bin-path <path>]`**: for stores that jumped
  straight to the new location. Gated by `local_authentication` (same as
  `vt secret export`). Tries, in order: v2 label, `current_exe()`, the
  explicit `--old-bin-path` string (the old binary need not exist — only the
  string enters the derivation). On first success, rewraps to v2 and saves.
  Passcode, auth_token (VT_AUTH), encrypted SSH keys, and FIDO2 blobs are
  preserved byte-for-byte; only `encrypted_passphrase` and `wrap_v` change.
- **Rollback**: a v2 store is unreadable by old binaries. Escape hatch:
  `vt secret rebind --to-v1` (rewraps back using `current_exe()`), or the
  existing `vt secret export` / `import` pair.
- Naming: the top-level `vt rewrap` (re-encrypts `vt://` URLs in files) is
  unrelated; `rebind` avoids the collision.

## 3. Native notifications

- `notify_macos` (`src/server_macos/security.rs`) gains a first path: if
  `current_exe()` lives under `*.app/Contents/MacOS/`, spawn
  `<bundle>/Contents/MacOS/VTApp notify --title <t> --body <b>` (argv, no
  AppleScript interpolation; control-character filtering and length caps
  stay). The Swift binary handles `notify` before `NSApplicationMain`: post
  via `UNUserNotificationCenter`, wait for the add-request callback, exit.
  First use triggers the one-time system authorization prompt.
- Fallback is the existing `osascript` path (binary outside a bundle, helper
  missing, or spawn failure). Notification failure must never affect the
  protected operation (`let _ =` semantics preserved).
- **Cache-hit notifications (new requirement)**: in the two places the server
  observes `Decision::CacheHit` (raw/`sign@vt` sign, `handle_decrypt`), fire
  `notify_cache_hit(op, scope_display, remaining_ttl)` → e.g.
  “sign · github.com · 4m12s left (no Touch ID — cached grant)”.
  - **Call-site constraint (review-mandated)**: the notification fires only
    **after `permit.commit()` returns** — a `CacheHit` permit holds the
    security read gate, and `run_revoker` needs the write side; a blocking
    notify (worst case: the first-use notification-permission dialog) while
    the permit is live would stall revocation, violating the live-permit
    invariant. The call is fire-and-forget (spawn, never await the helper),
    so it also adds no latency to the sign/decrypt response.
  - The scope display string comes from the **request-side** `GrantScope`
    (the server builds it for the lookup anyway), not from the store — so P1
    needs no store changes.
  - New `NotifyKind::CacheHit`, reusing the 30 s per-kind throttle
    (`notify_throttle_should_fire`) so a burst (multi-sign `git push`)
    notifies once; coalesced counts are a later refinement.
  - Default on; opt-out via `--no-cache-hit-notify` on `vt ssh agent` and the
    matching `[agent]` config key (§4).
  - Residual visibility note: banners persist in Notification Center after
    the event (and on the lock screen if the user's preview settings allow),
    longer than the Touch ID sheet showed the same strings. Users who treat
    hostnames/workspace paths as sensitive can opt out.
  - Both the helper path and the `osascript` fallback route through the
    **same** sanitize call (control-char filter + length caps) before the
    text leaves the agent.

## 4. Agent defaults from config (`[agent]` section)

The shell supervises the agent (§6) and must not hardcode the operator's
flags. `~/.config/vt/config.toml` gains an optional section read by
`vt ssh agent` at startup as *defaults*; explicit CLI flags override:

```toml
[agent]
timeout = 1800                      # --timeout
ssh_auth_cache_duration = 900       # --ssh-auth-cache-duration
decrypt_auth_cache_duration = 0     # --decrypt-auth-cache-duration
cache_hit_notify = true             # --no-cache-hit-notify inverts
run_allow = "/opt/homebrew/bin/zed" # --run-allow (agent policy, not a secret)
```

`run_allow` lives here (not just the flag) so a supervisor that spawns the
agent without flags — the VT.app shell — keeps `run@vt` working. It is agent
policy, contains no secret, and follows the same `flag > config > default`
precedence.

Env-over-file precedence is unchanged (no new env vars; `hydrate_env_from_file`
already skips structured TOML sections). Duration `0` still maps to
first-class `Fresh`.

**Menu-driven cache policy.** The menu-bar shell does NOT rewrite this
(mode-600, secret-bearing) file. Because the shell is the agent's sole
lifecycle owner (§6), a cache choice from the menu is persisted in the
shell's own `UserDefaults` and applied as an explicit spawn flag on the next
(re)start — precedence stays `flag > [agent] config > default`, so a user who
prefers the file can set `[agent]` and never touch the menu. The menu
checkmark reflects the agent's *live* TTL from `ui-status@vt`, whatever its
source. Applying a change restarts the managed agent (TTL is read at
startup; there is no hot reload), which drops current grants — acceptable for
a policy change and consistent with every other revoke path.

Implementation note (review finding): the `vt ssh agent` clap args currently
use eager `default_value_t`, which cannot distinguish "flag passed" from
"compiled default". They move to `Option<T>` (and a tri-state for the new
notify boolean) so the merge is `flag.or(config).unwrap_or(default)`.

## 5. `ui-status@vt` — token-gated read/revoke channel for the shell

`diag@vt` cannot serve the UI: it rides the VT_AUTH cipher path (the shell
holds no VT_AUTH) and is deliberately caller-scoped (`live_entries` is never
a whole-store count — that stays true). Whole-store visibility needs a
deliberately gated channel:

- **Spawn token**: the shell generates 32 random bytes, writes them into a
  pipe, and spawns `vt ssh agent --ui-token-fd <n>` with the read end
  inherited. The agent reads the token at startup and drops the fd. No env
  var (visible to same-user `ps e`), no file. A CLI-started agent has no
  token → the extension always fails → the UI degrades to "agent running,
  restart from VT.app for details".
- **Dispatch position**: handled with the plaintext pre-cipher extensions —
  after `session-bind@openssh.com`, *before* the lock check (a locked agent
  must still report `locked: true`) and before keychain/auth-cipher work.
  Constant-time token compare; on mismatch, plain `AgentError::Failure`
  (indistinguishable from unknown-extension).
- **Never resets the idle clock** — added to the same `touch_activity`
  exclusion as `EXT_DIAG`. Not audit-pushed, never cached, no Touch ID.
- **Request** (JSON, like diag): `{ token_b64, action: "status" | "revoke_all" }`.
  - `status` → response:
    `{ agent_version, locked, sign_ttl_secs, decrypt_ttl_secs, run_allow_len,
       audit_push, grants: [ { operation, family, display, expires_in_secs,
       ttl_secs } ] }`.
  - `revoke_all` → `engine.invalidate_all()` (the existing linearized
    revoker; epoch advances even when the store is empty). Authority-reducing
    only, hence token-but-not-Touch-ID is acceptable. If a live permit holds
    the prompt slot, revocation queues exactly as it does today; the UI shows
    "waiting for the in-flight approval".
- **Grant display labels**: `GrantKey` digests are one-way, so the store
  cannot reconstruct "github.com" or a workspace path. `GrantScope` gains a
  `display: String` set by each constructor (destination host + key type,
  workspace root, cwd, parent app name — the same phrasing the Touch ID
  prompt already shows), stored alongside `CacheExpiry` in a new
  `GrantEntry { expiry, display }` value. A new `GrantStore::snapshot()` /
  `AuthorizationEngine::snapshot()` enumerates live entries for this handler
  only. Memory-only; labels never hit disk or audit push.
- Information-disclosure stance: the full grant list (hosts, workspace paths)
  is exposed *only* to a holder of the spawn token, i.e. the shell that
  parented the agent. Same-user processes without the token get nothing,
  preserving today's diag@vt posture. Two consequences made explicit
  (review): (a) `ui-status@vt` is a deliberate, token-gated exception to the
  "never a whole-store count" diag@vt invariant — CLAUDE.md gets a companion
  line naming it as the one legitimate whole-store channel; (b) scope
  display strings, today shown only transiently in Touch ID prompts, are now
  retained in agent memory for the grant's TTL and readable by the token
  holder throughout that window. Memory-only, never disk/audit.
- Token compare reuses the `subtle::ConstantTimeEq` idiom already used by
  the agent's `unlock()` path (`None => false` when no token configured).

## 6. Swift menu-bar shell (`VTApp`)

Single-file AppKit app (`app/VTShell.swift`), no third-party deps.

- **Role — sole agent lifecycle owner.** The shell is the intended way the
  agent runs (replacing a hand-rolled launchd/supervisor): it registers as a
  login item (`SMAppService.mainApp`), spawns `vt ssh agent --ui-token-fd 0`
  (token over the stdin pipe), supervises it, and restarts it. Also serves
  `VTApp notify` helper mode (§3).
  - **Exit intent** drives the termination handler: `stop` (leave down),
    `restart` (respawn after the OS releases the socket — the new agent also
    self-heals a stale socket file on bind), or `crash` (backoff restart, up
    to 5 attempts).
  - **Never fights an external agent**: `startIfNeeded` defers if something is
    already listening on the socket; it only supervises an agent it spawned.
    An externally-started agent yields a degraded, read-only menu (no token).
  - **Version-skew restart**: after `just install-app` replaces the binary,
    the still-running agent runs old code. The shell compares the running
    `agent_version` to the bundled `vt version`; when they differ *and the
    agent is shell-managed*, the menu offers a one-click "Restart Agent to
    update". A restart is the trigger for the transparent wrap-v2 upgrade
    (§2) to run.
  - **Start-failure surfacing**: the agent's stderr is captured; a fast
    (< 3 s) or non-zero exit keeps the last line and shows it in the menu
    with a Doctor shortcut. This is the visible path for the common
    "keychain wrap still bound to the old binary path — run `vt secret
    rebind`" failure (§2), instead of a silent "not running".
- **Data flow**: speaks the ssh-agent wire protocol over `~/.ssh/vt.sock`
  (u32-BE length framing, `SSH_AGENTC_EXTENSION` 27 → `ui-status@vt`, reply
  `SSH_AGENT_EXTENSION_RESPONSE` 29). Poll every 3 s for icon state; refresh
  on `menuWillOpen`. Polling is safe by construction (no idle-clock reset).
  The fixed `~/.ssh/vt.sock` path is what lets a login-item-started agent be
  found by the vt client's built-in fallback with no `SSH_AUTH_SOCK` export.
- **Icon**: the hex-nut key from `icon.svg`, code-drawn as a monochrome
  template `NSImage`. Its content bounding box (512-space x 152..360,
  y 90..412) is aspect-fit into a padded ~16 pt cell so it carries the same
  internal padding as SF Symbol menu-bar glyphs rather than filling the bar
  height. The badge text (grant count / lock glyph) sits to its right.
- **Menu (v1)**:
  - status line: `Agent running · <version> · N grants` (disabled item;
    `<version>` already carries its own leading `v`)
  - version-skew: one-click restart (managed) or warning line (external)
  - agent start-failure hint + reason (when the managed agent won't start)
  - `Grants ▸` one item per grant: `sign · github.com · 4m12s`
    (display-only)
  - `Revoke All Grants` (⌘L accelerator while menu open) → `revoke_all`
  - `Cache Duration ▸ Signing / Decrypt ▸ Off / 5 min / 15 min / 1 h / 2 h /
    8 h / Follow config file` (managed agent only; applying restarts the
    agent)
  - `Idle timeout — <value> (clears cache when unused)` line + submenu
    (`15 min / 30 min / 1 h / 2 h / 8 h / Follow config file`) — surfaced so
    cache expiry is discoverable/debuggable (§10)
  - `Start Agent` / `Stop Agent` / `Restart Agent` (managed agent only)
  - `Start at Login` toggle (`SMAppService.mainApp`)
  - `Run Doctor…` (opens Terminal with `vt doctor`)
  - `Quit (agent keeps running)` / `Stop Agent and Quit`
- "Recent activity" (audit-log tail) is **v1.5** — cache-hit notifications
  cover the transparency need in v1 without the shell parsing audit files.

## 7. Migration from an existing (non-bundle) install

A store created by a pre-bundle `vt` is wrap v1, bound to *that* binary's
resolved path. `install-app` makes `~/.local/bin/vt` a symlink into the
bundle, so `current_exe()` now resolves to the bundle path — the transparent
upgrade (§2) cannot unwrap, and a shell-started agent would fail to boot.
Rebind once, in this order:

```
1. Stop the current agent (whatever supervises it today).
2. just install-app
3. vt secret rebind --old-bin-path <resolved path of the old vt binary>
   # e.g. /Users/you/.local/bin/vt (the real file, symlinks resolved)
4. Launch VT.app — the shell starts the agent; wrap is now v2 (path-independent).
```

If step 3 is skipped, the shell surfaces the failure and the `vt secret
rebind` hint in its menu (§6) rather than failing silently. Once on wrap v2,
future bundle moves need no rebind.

### Keychain ACL note (operational, not code)

Moving the binary re-triggers the legacy keychain ACL prompt once
(`rusty.vault.store` is a single generic-password item). The first
`vt secret rebind` run from the bundle doubles as that prompt. With a stable
`VT_CODESIGN_ID`, it is the last such prompt; with ad-hoc signing the
per-rebuild prompt behavior is unchanged from today.

## 8. Invariants preserved

- `session-bind@openssh.com` stays first in dispatch; `ui-status@vt` slots
  after it and never touches the VT_AUTH cipher path.
- `diag@vt` semantics untouched (caller-scoped counts, no idle reset).
- `auth@vt`/`run@vt` fresh-only; `run@vt` unreachable from the UI.
- Cache duration `0` → `Fresh`, never `StrictTtl(0)`.
- Revocation/epoch semantics unchanged; `revoke_all` reuses the existing
  linearized revoker.
- No secret or private-key material crosses `ui-status@vt`; grant labels are
  the same strings already shown in Touch ID prompts.
- Notification failure never blocks or fails a protected operation.

## 9. Phasing and tests

- **P1 (Rust)**: wrap v2 + `vt secret rebind` (+ `--to-v1`), `[agent]` config
  defaults, cache-hit notify (request-side scope display, post-commit
  fire-and-forget), bundle-aware `notify_macos`.
  Tests: derivation vectors old/new, rebind round-trip (v1→v2→v1), the
  transparent-upgrade mutator preserves passcode/auth_token/ssh/fido2
  byte-for-byte, config precedence (flag > file > default), throttle
  behavior for `CacheHit`.
- **P2 (agent)**: spawn token fd, `ui-status@vt` handler, `GrantEntry`
  display labels, `snapshot()`, revoke action.
  Tests: token gate (no token/wrong token/right token), locked-agent status,
  idle-clock non-reset, snapshot label/expiry correctness, revoke-all epoch
  advance.
- **P3 (app)**: Swift shell, icns, `just app` / `install-app`, docs.
  Manual verification: notification identity, menu states, agent
  supervision, ACL prompt flow.
- Gates: `cargo test`, `just check`, `just check-worker` (untouched but run).

## 10. Key-wipe on lock + menu-configurable/visible idle timeout (R3)

**Motivation.** The idle timeout couples two concerns onto one timer: wiping
decrypted SSH keys from RAM (memory hygiene, wants *short*) and invalidating
cached grants (walked-away backstop, wants *long* for cache convenience).
Raising the default to 2 h (§4) for cache convenience therefore also
lengthened key memory-residency to 2 h — and the screen-lock watcher today
only `invalidate_all()`s grants, it does **not** clear the key map. So a
locked screen currently leaves decrypted private keys resident until the
2 h idle sweep. A same-machine memory-scraping attacker (root/debugger
`task_for_pid`) is not stopped by screen lock. Fix: **lock/sleep also wipes
keys** (C), and keep idle as a long backstop that is now **surfaced and
configurable in the menu** so cache expiry is debuggable rather than
"mysterious".

### C — lock/sleep clears keys, not just grants

- The cache watcher, on a `watcher_should_clear` trigger (lock transition or
  detected sleep), in addition to `invalidate_all()` (grants), clears the
  key map and sets `idle_cleared = true` so the next use silently reloads
  (no Touch ID). The watcher gains `Arc` clones of `keys` and `idle_cleared`
  (mirroring the idle sweeper).
- **Race that must be closed (review Finding 1, blocker):** a sign request
  arriving *while the screen is locked* would today hit `ensure_keys_loaded`
  (which sees `idle_cleared` and reloads) — repopulating RAM with the very
  keys we just wiped. The interactive guard must be checked in **two** places
  (mirroring the existing post-I/O `self.locked` re-check): (a) before
  `load_all_keys()` to skip the pointless read, and **(b) again immediately
  before `*keys = loaded`** — because the screen can lock *during* the
  blocking (possibly ACL-prompting) keychain read, and an entry-only check
  would then install keys into RAM during the lock. Both `self.locked` and
  the screen-interactive check gate the install; either failing → no-op
  reload, `idle_cleared` left set so a later interactive call reloads. A sign
  during lock is independently rejected at `authorize` (validator
  `NotInteractive`); the guard's sole job is keeping decrypted keys out of
  RAM (memory-scraping hygiene), since *use* is already blocked. Scope: covers
  the automatic reload path (`sign`, `sign@vt`, and `request_identities`, all
  sharing `ensure_keys_loaded`); does **not** cover the explicit `ssh-add -X`
  `unlock()` path, which reloads on a caller-supplied passphrase by design and
  is outside the memory-scraping threat model.
- Agent lock (`ssh-add -x`) already wipes keys via the lock finalizer;
  unchanged. Menu "Revoke All" stays grants-only (it is not a lock).
- Reload cost after unlock is one silent keychain read on the first
  post-unlock use; no Touch ID.

### Menu-configurable + visible idle timeout

- `UiStatusRes` gains `idle_timeout_secs` so the shell can display and
  reconcile it.
- The menu shows the active idle timeout (e.g. a disabled "Idle timeout: 2h"
  line) — this is the "make timeout perceivable" requirement: a user seeing
  the value understands *why* grants clear after a quiet spell, so cache
  disappearance is debuggable instead of mysterious. The grant list already
  shows each grant's remaining TTL; the idle line explains the orthogonal
  expiry axis.
- An "Idle Timeout ▸ 15m / 30m / 1h / 2h / 8h / Follow config file" submenu
  (managed agent only) persists the choice to `UserDefaults`
  (`vt.idleTimeoutSecs`), passed as `--timeout` on the next spawn; applying
  restarts the managed agent (same mechanism/among-caveats as the cache
  submenu, §4/§6). Precedence stays `flag > [agent] config > default`.
- **Floor clamp (review Finding 5):** `timeout` is clamped to ≥ 60 s where it
  becomes a `Duration` in `run_ssh_agent`. Unlike the cache durations, idle
  `0` is **not** a "Fresh"-style special case — `0` would make the sweeper
  `sleep(0)` busy-loop (`check_interval = min(60, timeout)`). The menu presets
  never offer 0, but the clamp protects the config/CLI/UserDefaults paths.
- Idle is **not removed** — it remains a long backstop for the
  unlocked-but-unattended window that screen lock does not cover (e.g.
  display sleep without password-on-wake, or auto-lock disabled). Removing
  the only automatic non-lock guard would make screen lock a single point of
  failure; keeping it long costs nothing (silent reload, rarely fires before
  lock does).

### Invariants preserved

- Lock, sleep/wake, and idle still advance the authorization epoch even with
  an empty store; key reload is always silent (no Touch ID).
- `ui-status@vt` stays token-gated read + authority-reducing revoke; setting
  the idle timeout happens via UserDefaults + agent restart (the shell's
  lifecycle ownership), not a new mutating agent channel — no approval, grant,
  or extend action is ever added.
- No secret or key material crosses any new surface; `idle_timeout_secs` is
  policy, not a secret.
