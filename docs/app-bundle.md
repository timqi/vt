# VT.app: bundle, menu bar, notifications, and key-wrap migration

VT.app is the macOS menu-bar shell and intended agent lifecycle owner. This
document owns installation/migration, menu behavior, notifications, and the
shell's status/revoke boundary. Authorization mechanics and activity scopes
remain in [unified-authorization-engine.md](unified-authorization-engine.md)
and [authorization-scopes-v2.md](authorization-scopes-v2.md).

## 1. Bundle layout and packaging

```text
VT.app/Contents/
  Info.plist                 dev.rustyvault.vt; LSUIElement=true
  MacOS/VTApp                Swift menu-bar shell and notification helper
  MacOS/vt                   Rust CLI and agent
  Resources/AppIcon.icns     generated from cf-worker/pwa/icon-512.png
```

`VTApp` avoids a filename collision with `vt` on case-insensitive APFS.
`CFBundleDisplayName` is `VT`; the menu icon is a monochrome template drawing
of the project's key symbol. The helper posts notifications under VT's bundle
identity, rather than Script Editor's.

On macOS with Rust, Swift, and the system packaging tools installed:

```bash
just app
just install-app
```

`just app` builds the release binary, compiles `app/VTShell.swift`, generates
the icon, assembles `build/VT.app`, and signs with
`codesign --force --deep -s "${VT_CODESIGN_ID:--}"`. `VT_APP_BIN` can select an
already-built binary. Signing is ad-hoc unless `VT_CODESIGN_ID` names an
installed signing identity. `just install-app` replaces `/Applications/VT.app`
and makes `~/.local/bin/vt` a symlink to its `Contents/MacOS/vt`.
For a pre-wrap-v2 store, follow section 7 before launching the new agent.

`.github/workflows/release.yml` also ships
`VT-app-darwin-arm64-<tag>.tar.gz` alongside the bare binary. Release bundles
are ad-hoc signed, not Developer-ID-notarized. CLI extraction with `tar xzf`
usually avoids Finder's quarantine propagation; it is not a guarantee that
Gatekeeper will accept every download. For a trusted bundle blocked solely by
quarantine, the fallback is:

```bash
xattr -dr com.apple.quarantine /Applications/VT.app
```

Ad-hoc signatures change per build, so upgrades can trigger a new Keychain ACL
prompt. A stable signing identity reduces this friction. There is no in-app
auto-updater; installation remains explicit.

## 2. Master-key wrap v2

The wrap key is `SHA-256(SHA-256(base64url(passcode):$USER:vt-wrap-v2))`
(`src/core/crypto.rs`, `derive_passphrase_secret_v2`). The fixed label is the
only derivation this release reads; the retired wrap v1 put the resolved
binary path there, an attacker-knowable soft binding that made bundle and
package-prefix moves break access.

`KeychainStore` always writes `wrap_v = 2`. `derive_passcode_cipher`
(`src/server_macos/security.rs`) is the single unwrap gate: a store whose
marker is not 2 — an explicit `1`, or the marker-less form older stores
parse as `0` — fails closed before any unwrap with

```
rusty.vault.store has wrap version 1, this release reads only wrap v2 — run `vt secret rebind` on the previous vt release first
```

There is no in-binary upgrade and no `vt secret rebind` in this release. A
v1 store is migrated by running the previous release's `vt secret rebind`
(that binary still reads v1) before installing this one; the alternative is
the `vt secret export` / `vt secret import` route, handling its secret
material accordingly. `STORE_SCHEMA_VERSION` remains 1, so an older binary
still parses a v2 store for that route. Only `create_and_save_passcode_passphrase`
(init/import, which mints a fresh passcode) and `rotate_passcode` write
`encrypted_passphrase`; both write `wrap_v = 2`.

The blob's second 32 bytes are unread (new stores fill them with random
bytes); the width stays so existing stores need no migration.

Remove obsolete `vt` binaries after upgrading. An older binary's full-store
writers (`init`, `import`, `rotate-passcode`) can rewrite the store as wrap
v1, which this release then rejects until it is rebound on that binary.

## 3. Native notifications

`notify_macos` in `src/server_macos/security.rs` strips control characters
from title and body, with 100-character title and 150-character body limits. A
reaper thread invokes bundled `VTApp notify --title <t> --body <b>` without a
shell. The Swift helper handles this mode before starting the menu app, uses
`UNUserNotificationCenter`, and can request system notification permission on
first use. The bundled helper is the only transport: a bare `vt` outside
VT.app logs at debug and drops the notification; a helper failure is logged,
never retried through another path.

Notification work is fire-and-forget from the protected operation. The thread
waits for/reaps the helper, not the signing or decrypt handler; notification
failure must never fail the operation.

Successful cache reuse in raw signing, `sign@vt`, and `decrypt@vt` emits a
cache-hit notice with operation, request-side scope display, and remaining
lifetime. `NotifyKind::CacheHit` shares a 30-second per-kind throttle, so a
burst notifies once per window. Calls occur only **after `permit.commit()`
returns**: even a cache-hit permit holds a security read guard, and a helper
permission dialog must not delay the revoker's write gate.

Cache-hit notifications default on. Disable them with `--no-cache-hit-notify`
on `vt ssh agent` or `[agent].cache_hit_notify = false`. This is independent of
the Worker's opt-in cache-hit push. Banners can retain hostnames/workspace
paths in Notification Center, and on the lock screen depending on preview
settings, after the grant or prompt is gone. Opt out when that visibility is
unwanted. Prompt and audit context are documented in
[approval-transparency.md](approval-transparency.md).

## 4. Agent defaults and menu overrides

`vt ssh agent` reads optional defaults from `~/.config/vt/config.toml`
(`VT_CONFIG` overrides the path). Explicit duration and allowlist flags take
precedence over `[agent]`, then built-in defaults:

```toml
[agent]
timeout = 7200                    # --timeout; built-in default: 2 hours
ssh_auth_cache_duration = 0        # --ssh-auth-cache-duration
decrypt_auth_cache_duration = 0    # --decrypt-auth-cache-duration
cache_hit_notify = true            # --no-cache-hit-notify disables
run_allow = "/opt/homebrew/bin/zed" # --run-allow; omitted default: disabled
```

Cache duration `0` selects Fresh approval, never `StrictTtl(0)`. Idle timeout
is different: it is floored at 60 seconds, including a configured `0` (section
10). `--no-cache-hit-notify` always disables notifications; without it the file
boolean governs, defaulting to true. There is no positive flag overriding a
file value of false. Existing environment-over-file secret configuration is
unchanged; these agent defaults do not introduce new environment variables.

The shell never rewrites this mode-600, secret-bearing config file. Menu
choices persist in its own `UserDefaults` (`vt.signCacheSecs`,
`vt.decryptCacheSecs`, `vt.idleTimeoutSecs`) and become explicit spawn flags.
"Follow config file" removes that override. Submenu checkmarks show the shell's
override choice; parent menu labels show the agent's live effective durations
from `ui-status@vt`. Applying a choice restarts the managed agent and drops
existing grants. There is no hot reload or policy-write action on the UI channel.

## 5. `ui-status@vt`: token-gated status and revoke

`diag@vt` exposes only caller-scoped counts, so it cannot serve a shell that
needs the whole store. `ui-status@vt` is the one deliberate whole-store
visibility channel, protected by a per-spawn token:

- The shell generates 32 random bytes, pipes them to the child's inherited
  stdin, and launches `vt ssh agent --ui-token-fd 0`. The agent reads exactly
  32 bytes and closes the descriptor. Token bytes never enter env, argv, or a
  file; the fd number is not the token.
- Dispatch is plaintext, after `session-bind@openssh.com` but before the agent
  lock check, Keychain/cipher work, and idle activity update. A locked agent
  can still report status. Constant-time comparison gates the request; absent,
  malformed, or wrong tokens and unknown actions fail as unstructured
  `AgentError::Failure`. A CLI-started agent with no token refuses every call.
- The channel never resets idle activity, prompts, caches approval, or pushes
  an audit event. It permits only `status` and `revoke_all`, never approval,
  grant creation, extension, TTL editing, or `run@vt`. The forwarding relay
  refuses it. This boundary is distinct from Worker Passkey-gated cache extension.

The JSON request has `token` (base64url without padding) and `action` fields.
`UiStatusRes` in `src/core.rs` returns `agent_version`, `locked`,
`sign_ttl_secs`, `decrypt_ttl_secs`, `idle_timeout_secs`, `run_allow_len`,
`audit_push`, and `grants`; `revoked` is present only for a revoke response.
`GrantSnapshot` entries contain `operation`, `family`, `display`,
`remaining_secs`, and `ttl_secs`, never subjects, digests, or key material.
`locked` reports agent lock, not a separate screen-lock indicator.

`AuthorizationEngine::snapshot()` returns sorted live entries. The stored
`GrantEntry.display` is a memory-only label, not a security input or a persisted
audit record. Token possession exposes the full list of host/workspace/app
labels for their lifetime; same-user callers without the token get no list.
Ordinary `diag@vt` remains caller-scoped.

`revoke_all` calls the existing linearized `invalidate_all()`, advancing the
epoch even for an empty store. It can wait for a live operation permit; an
approval still in progress cannot recreate a grant after revocation. A timed
out or failed UI request is **not confirmation**: the shell reports
"Revocation not confirmed". Revoking grants is not locking the agent or
wiping its key map.

## 6. Menu-bar shell and lifecycle

`app/VTShell.swift` is a single-file AppKit shell with no third-party
dependencies. It polls `~/.ssh/vt.sock` every three seconds and on menu opening,
using SSH-agent length framing and extension messages. The fixed socket is
also the client's built-in fallback when `SSH_AUTH_SOCK` is unset.

The menu provides:

- Agent status/version, lock or grant count, live grant labels and remaining
  TTLs; grants themselves are display-only. No recent-activity log tail or
  per-grant revocation is implemented.
- `Revoke All Grants` (Command-L while the menu is open).
- Managed-agent cache choices: Signing/Decrypt, Off, 5 min, 15 min, 1 h, 2 h,
  8 h, or Follow config file. Idle timeout choices are 15 min, 30 min, 1 h,
  2 h, 8 h, or Follow config file, alongside the live value.
- Start when no agent is reachable; Stop for a managed agent. A managed
  version mismatch offers `Restart Agent to update`; external agents receive
  limited status and are not controlled by the shell.
- `Start at Login` via `SMAppService.mainApp` on macOS 13+, `Run Doctor...`
  opening Terminal with `vt doctor`, `Quit (agent keeps running)`, and
  `Stop Agent and Quit` for a managed agent.

The shell supervises only the child it started. Stop leaves it down, intentional
restart waits for exit/socket release, and crashes use backoff with at most five
restart attempts. Delayed callbacks retain process/generation identity so Stop
or a newer child cannot be overridden by an old callback. Quitting while leaving
the agent running loses the shell's token; a later shell sees an external agent
with limited visibility. There is no persisted token or takeover mechanism.

The Rust agent takes a nonblocking lifetime flock on `~/.ssh/vt.sock.lock`
before Keychain work or listening. This mode-600, no-symlink lock file is never
unlinked; do not delete it to restart. Its descriptor is close-on-exec.
A live legacy listener is also refused by a nonblocking probe; only stale
sockets are replaced. Shutdown removes only its recorded socket `(dev, ino)`
generation. Older binaries do not honor this ownership protocol; remove them
after upgrading.

Managed stderr is drained continuously, retaining only the last 64 KiB in
memory, not a log file. Exit snapshots do not wait for EOF from descendants.
A fast (under three seconds) or nonzero exit surfaces the last nonempty stderr
line (up to 120 characters) and a Doctor shortcut, including a rejected wrap
version. After installation, running code does not change until restart;
version comparison uses `agent_version` and the bundled `vt version`.

## 7. Migration from a non-bundle install

The store must already be wrap v2 (section 2). If the old install predates
wrap v2, run its own `vt secret rebind` first — the previous release still
reads and upgrades v1 — then stop the existing agent and its supervisor and:

```bash
just install-app
open /Applications/VT.app
```

If the store is still v1, startup fails closed and the menu surfaces the last
nonempty stderr line and a Doctor shortcut as described in section 6; the
error names the remedy. Binary moves never affect the wrap. Remove obsolete
binaries; the downgrade caveat is in section 2.

Moving the binary can trigger the legacy Keychain ACL prompt for the
`rusty.vault.store` generic-password item. Stable code signing helps preserve authorization;
ad-hoc rebuilds can prompt again. Native ACL/notification behavior must be
verified on the installed, signed bundle, not inferred from unit tests.

## 8. Security boundaries

The menu is never an approval surface. Touch ID and the agent's configured
authentication alternatives remain in the authorization path. `auth@vt` and
`run@vt` stay Fresh; the UI cannot launch allowlisted programs or integrate
Worker/phone approval. Cache policy choices use lifecycle restart, not an
authority-increasing UI extension.

`session-bind@openssh.com` remains first in dispatch; UI status and `diag@vt`
polling never extend idle lifetime. All revoke paths preserve permit/epoch
linearization. No secret or private key crosses the UI channel, and notification
failure cannot block or fail an operation. Scope labels are an intentional
information disclosure to the spawn-token holder and notification viewers.

## 9. Verification entry points

Implementation anchors are `app/VTShell.swift`, `app/Info.plist`, `justfile`,
`src/server_macos/security.rs` (wrap/notifications), `src/main.rs` and
`src/config.rs` (defaults), and `src/server_macos/ssh_agent/handlers.rs`
(`handle_ui_status`). Focused checks:

```bash
cargo test --locked --test agent_socket_owner
cargo test --locked core::authorization::tests
```

On macOS, `test_rewrap_preserves_store` and `test_non_v2_wrap_is_rejected` in
`src/server_macos/security.rs` check the v2 rewrap, untouched token/SSH fields,
and the wrap v1/0/unknown rejection over an in-memory store. `ui_status_token_gate_locked_report_and_revoke`
in `src/server_macos/ssh_agent.rs` checks absent/wrong/correct tokens, unknown
actions, locked status, labels/expiry, and revoke. The same module tests idle
dual-clock expiry and lock/wake watcher classification. Run its tests and the
native stderr regression harness:

```bash
cargo test --locked server_macos::security::tests
cargo test --locked server_macos::ssh_agent
swiftc -D VT_LIFECYCLE_TEST app/VTShell.swift -o /tmp/vt-lifecycle-tests
/tmp/vt-lifecycle-tests
```

The Swift harness emits 4 MiB of stderr to detect backpressure and retains an
extra writer to verify exit never waits for EOF. Socket tests run on Linux and
macOS. Repository gates are `cargo test`, `just check`, and `just check-worker`.
Linux cannot verify AppKit, Keychain, or macOS-only Rust modules. Native checks
must exercise menu/login/supervision, config overrides after restart, revoke
failure reporting, notification identity/permission/fallback, migration/ACL,
and key reload across screen lock, wake, and idle timeout.

## 10. Key wiping and idle timeout

The five-second watcher detects interactive-to-non-interactive transitions and
sleep/wake clock divergence. On either trigger it revokes grants, then
`clear_keys_for_reload` clears the decrypted SSH-key map and sets
`idle_cleared` only if the map is nonempty. The idle sweeper likewise revokes
even with an empty key map, then calls the same helper. Request-time live
validation independently rejects unsafe authorization before the next watcher
tick; watcher-based key wiping is not instantaneous at lock.

`ensure_keys_loaded` silently reloads cleared keys on the next interactive use.
It checks screen-interactive state **before** Keychain I/O and **again before
installing the result**, also rechecking agent lock under the key-map guard.
If unsafe, it leaves `idle_cleared` set and does not repopulate the map. This
guards automatic reload for raw signing, `sign@vt`, and identity listing; it
does not cover the explicit passphrase-driven `ssh-add -X` unlock path.
Silent reload adds no VT approval prompt, though a changed Keychain ACL can
still require system permission.

Agent lock (`ssh-add -x`) separately wipes keys through its lock finalizer.
Menu Revoke All remains grants-only. Key-map clearing reduces memory residency;
it is not protection against root/debugger inspection of an active operation's
key material.

Idle timeout defaults to two hours and is floored at 60 seconds in the
`vt ssh agent` CLI handling in `src/main.rs`. Idle `0` is not Fresh: without the
floor it would make the sweeper busy-loop. The sweeper checks at most once per
minute and counts either clock's
elapsed inactivity, including sleep. Idle remains a backstop for unlocked but
unattended sessions (for example, auto-lock disabled); it is separate from each
grant's fixed TTL. The menu exposes the live value and restarts the managed
agent when changing it, without adding a mutating UI protocol action.
