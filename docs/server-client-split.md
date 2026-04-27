# Server / Client Split Proposal

## Problem

`vt` now has two distinct responsibilities:

- Client workflows: `create`, `read`, `inject`, and `auth` send encrypted SSH-agent extension requests. These should work on macOS and Linux.
- Server workflows: keychain storage, Touch ID / local authentication, FIDO2 fallback, and the SSH agent. These are macOS-only.

The current source layout does not cleanly enforce that boundary. `cli.rs` contains both cross-platform client logic and macOS-only secret management helpers, which makes it easy for macOS-only APIs to leak into Linux builds.

## Recommendation

First split the code by responsibility while keeping the single user-facing `vt` binary.

Suggested modules:

- `core`: shared request/response types, `vt://` parsing, encryption/decryption helpers, and TOTP handling.
- `client`: cross-platform SSH-agent extension client (`encrypt@vt`, `decrypt@vt`, `auth@vt`) plus command implementations for `create`, `read`, `inject`, and `auth`.
- `server_macos`: macOS-only keychain store, key derivation, local authentication, FIDO2, SSH agent, and admin commands (`init`, `secret`, `ssh`, `fido2`).
- `main`: clap routing only. It exposes client commands on every target and server/admin commands only under `#[cfg(target_os = "macos")]`.

This keeps the current CLI UX stable while making target-specific ownership explicit. It also lets CI check the client surface on Linux without compiling or type-checking macOS-only modules.

## Alternative: Two Binaries

A later cleanup could publish two binaries:

- `vt`: cross-platform client only.
- `vt-agent` or `vt-server`: macOS-only keychain and SSH-agent server.

That boundary is cleaner, but it changes installation, docs, LaunchAgent setup, and user expectations. It is better as a second step after the module split has made the internal boundary clear.

## Target End State

- Linux builds never reference `KeychainStore`, LocalAuthentication, FIDO2, `ssh-key`, or macOS process-introspection APIs.
- macOS builds include both client and server/admin commands.
- Client code depends only on `VT_AUTH`, `SSH_AUTH_SOCK`, `ssh-agent-lib` blocking client APIs, and shared protocol types.
- Server code owns all keychain reads/writes and all plaintext access.
- Tests can be grouped by boundary: pure shared tests, cross-platform client tests, and macOS-only server tests.

## Migration Plan

1. Move cross-platform `VTClient`, hostname handling, and `create/read/inject/auth` command logic from `cli.rs` into `client.rs`.
2. Move `init`, `secret export/import/rotate-passcode`, and other keychain-backed command logic into a macOS-only `server_macos` module.
3. Keep `main.rs` as the only clap-aware module and wire commands to either `client` or `server_macos`.
4. Add a Linux CI check once the local build can type-check client code without macOS-only symbols.
5. Revisit whether a separate `vt-agent` binary is worth the UX and packaging churn.
