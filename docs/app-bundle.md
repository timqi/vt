# VT.app operation and security

VT.app is the macOS menu-bar owner of the local agent lifecycle. It exposes
status and revocation; it is never an approval surface.

## Install and signing

Build and install on macOS:

```bash
just install-app
open /Applications/VT.app
```

Release download instructions are in [README.md](../README.md#installation).
Build inputs and bundle layout are defined in [justfile](../justfile).

Release bundles are ad-hoc signed and not notarized. A new build can require
renewed Keychain permission; a stable `VT_CODESIGN_ID` reduces repeated prompts.
Keychain permission is separate from vt operation approval. For a trusted
bundle blocked solely by quarantine:

```bash
xattr -dr com.apple.quarantine /Applications/VT.app
```

`just install-app` restarts a running VT.app and its managed agent, dropping
current grants; an agent started outside the bundle is left running the old
code. VT.app has no automatic updater.

## Master-key wrap v3

The master key is sealed to a non-permanent Secure Enclave P-256 key whose
access control is `biometryCurrentSet | privateKeyUsage`,
`WhenUnlockedThisDeviceOnly`; the store keeps the key's `kSecAttrTokenOID`
blob and the ECIES ciphertext. Platform facts: [secure-enclave.md](secure-enclave.md).
Store and wrap definitions belong to [store.rs](../src/server_macos/store.rs)
and [se.rs](../src/server_macos/se.rs).

- `vt init`, `vt secret import`, and `vt secret rotate-passcode` write wrap v3
  only. Without a Secure Enclave they refuse with `se.unavailable`
  ([structured-errors.md](structured-errors.md#secure-enclave)).
- Unwrapping requires a Touch ID approval: the approval's `LAContext` is bound
  to the Secure Enclave key and held in memory as the approval session. A
  reusable grant keeps its session until revocation (lock, idle, screen lock,
  wake, revoke-all) drops it; a fresh approval's session ends with its
  operation. Password fallback authenticates but cannot unwrap: with Touch ID
  unavailable (sensor absent, lid closed, biometry locked out) the local agent
  fails closed and only the Worker transport remains.
- A blob is bound to this device and the enrolled fingerprint set. After
  enrollment changes or on another Mac, recover with `vt secret import` from
  the exported master; there is no other path.
- `encrypt@vt` is authorized like `decrypt@vt` because minting a DEK also needs
  the master ([unified-authorization-engine.md](unified-authorization-engine.md#approval-policy)).
- Public SSH keys, fingerprints, and comments live in plaintext in the store;
  listing identities never unwraps the master. Private keys stay sealed under
  the master and load on the next authorized sign after a wipe.

Wrap v2 (passcode-derived) is readable this release only by
`vt secret rotate-passcode`; the agent and every other command refuse it until
migrated. Migrate once per Mac, then restart the agent:

```bash
vt secret rotate-passcode
```

Non-v2/v3 markers fail before unwrap; there is no in-binary upgrade. Before
upgrading a v1 store, run `vt secret rebind` with the previous release. Remove
obsolete binaries: an old full-store writer can put the store back into a
format the current release refuses.

## Notifications

vt-branded notifications require the bundled helper; a bare CLI drops them.
Delivery failure never blocks or fails signing/decryption and has no alternate
notification transport.

Cache-hit notices disclose operation, reusable scope, and remaining lifetime.
They run only after authorization commitment releases its guards and are
throttled. Local hit notices default on, independently of Worker hit pushes.
Disable through `--no-cache-hit-notify` or the agent config.

Notification Center and lock-screen previews can retain hostnames and workspace
paths after a grant expires. Configure previews or disable notices when that
disclosure is unwanted.

## Agent defaults and menu overrides

[config.example.toml](../config.example.toml) owns agent settings. Explicit
flags override file settings, which override built-in defaults.

The menu keeps overrides in its own preferences and never rewrites the
secret-bearing config file. Choosing "Follow config file" removes the menu
override. Applying a policy choice restarts the managed agent and drops grants;
there is no hot policy mutation through the UI protocol.

## Status and revoke boundary

`ui-status@vt` is the only whole-grant-store channel. The shell holds a fresh
spawn token passed through a pipe; it never persists the token or puts it in
environment variables, arguments, or files.

- Without the token, a caller cannot list all grants. The forwarding relay
  refuses this channel.
- Status works while the agent is locked, without Keychain access or idle
  activity. Reported lock status is agent lock, not a separate screen indicator.
- Only status and revoke-all are permitted; the UI cannot approve, extend,
  launch a program, or create grants.
- Grant labels remain in memory and expose activity names to the token holder;
  replies contain no keys, resource digests, or authority-bearing material.
- Revoke-all invalidates pending approval even with no stored grants. A timeout
  or failed response is not confirmation of revocation.
- Revoke-all clears grants, not decrypted keys, and does not lock the agent.

Caller-scoped diagnostics belong to the
[authorization contract](unified-authorization-engine.md#visibility).
Wire declarations live in [src/core.rs](../src/core.rs).

## Lifecycle ownership

The shell supervises only the child it started. External agents have limited
status and are not stopped or taken over. Stop leaves a managed agent stopped;
crash recovery is bounded and cannot let an old callback restart a newer child.

Quitting while leaving the agent running loses the shell's token; a later shell
sees an external agent. There is no persistent token or automatic takeover.
Start-at-login requires macOS 13 or later.

One process owns the socket at a time. Do not delete `~/.ssh/vt.sock.lock` to
restart the agent; shutdown must not remove a successor's socket. A failed
startup surfaces an error and a Doctor shortcut, without retaining a disk log.

## Upgrade from a standalone agent

Complete the wrap-v3 migration above if needed, then stop the existing agent and its
supervisor before installing and opening VT.app. Remove old launch-at-login
entries so a second supervisor does not compete for the socket.

Use the installed, signed bundle to verify Keychain and notification permission;
unit tests cannot establish macOS permission behavior.

## Native validation

Validate startup/login, managed versus external agents, policy overrides after
restart, failed revocation, notifications, and lock/wake/idle reload on macOS.
The shell and lifecycle harness are in [VTShell.swift](../app/VTShell.swift);
repository gates are in [AGENTS.md](../AGENTS.md#validation-and-deployment-entry-points).

## Key wiping and idle timeout

Screen-lock/wake observation and idle timeout revoke grants and clear decrypted
SSH keys. Background key wiping is not instantaneous at lock; operation-time
security validation must reject unsafe use independently of the watcher.

Private keys reload on the next authorized sign, through that approval's master
session: no extra prompt and no silent Keychain unwrap. Reload checks
interactivity before decrypting and before installing keys, including current
agent lock. Unsafe state leaves the key map empty. Identity listing reads only
the plaintext public list. `ssh-add -X` unlock is a separate path and loads nothing.

Idle is a backstop for an unlocked, unattended session, separate from grant TTL.
Its minimum is 60 seconds; zero does not mean Fresh or disabled. Key-map clearing
reduces memory residency but cannot erase copies in an active operation or caller.
