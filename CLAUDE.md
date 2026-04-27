# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build --release        # Release build (uses real macOS keychain)
cargo build                  # Debug build
cargo test                   # Run non-ignored tests (pure crypto tests, no agent needed)
cargo test test_name         # Run a specific test
cargo test -- --ignored      # Run ALL tests (requires running agent + macOS keychain)
```

## Architecture

VT (Vault) is a macOS-based KMS using the system keychain for secret storage and AES-256-GCM encryption.

### Source Files (src/)

- **main.rs** — CLI entry point (clap). Subcommands: `init`, `create`, `read`, `inject`, `auth`, `secret {export,import,rotate-passcode}`, `ssh {agent,add,list,remove,remove-all,comment,show}`, `fido2 {register,list,remove,remove-all}`. macOS-only commands (`init`, `secret`, `ssh`, `fido2`) are `#[cfg(target_os = "macos")]`. `auth` is platform-agnostic (client runs on Linux, agent runs on macOS).
- **core.rs** — Shared domain types (`EncryptItem`, `DecryptReq`, `CryptoResItem`, `SecretType`) and crypto logic (`do_encrypt`, `do_decrypt`). Used by `ssh_agent.rs`.
- **cli.rs** — Client logic. `VTClient` sends extension requests over the SSH agent Unix socket (`encrypt@vt` / `decrypt@vt` / `auth@vt`); each extension payload is encrypted with the `VT_AUTH`-derived auth cipher. `inject` uses `libc::fork()` for timed file cleanup and `exec::Command` to replace the process.
- **security.rs** — `AesGcmCrypto` wrapper (AES-256-GCM with 12-byte nonce prepended to ciphertext). Low-level keychain access via `security-framework` crate (`set_keychain`, `get_keychain`, `delete_keychain`); higher-level callers should go through `KeychainStore` instead. `derive_passcode_ciphers(&KeychainStore)` and `load_mac_cipher(&KeychainStore, &passphrase_cipher)` are the canonical entry points. Local auth uses `objc2-local-authentication` so LAError codes can be classified precisely.
- **store.rs** — `KeychainStore` type backing the single `rusty.vault.store` keychain item. JSON-serialized blob with fields `passcode_and_auth_token`, `encrypted_passphrase`, optional `encrypted_ssh_keys`, optional `encrypted_fido2`. Provides `load`/`save` and the cross-process `modify` (blocking flock) and `try_modify` (non-blocking flock, used by FIDO2 sign-counter persistence to avoid stalling SSH sessions) helpers. Lock file lives at `$TMPDIR/vt-keychain.lock` and is never deleted (per-user, cleared on reboot).
- **ssh_agent.rs** — SSH agent implementation using `ssh-agent-lib`. Split into `VtSshAgentFactory` (implements `Agent<UnixListener>`, owns shared state) and `VtSshSession` (per-connection, implements `Session`). Includes `AuthCacheMode`/`AuthCache` for optional per-session or per-app Touch ID caching, and a `proc_info` module for macOS process introspection (`proc_pidinfo`/`proc_pidpath`). Keys live inside `KeychainStore.encrypted_ssh_keys` (a single encrypted JSON blob, formerly its own keychain item). Touch ID required for `sign()` and `decrypt@vt` (with optional caching). Non-vt extensions (e.g. `session-bind@openssh.com`) are passed through gracefully. Touch ID prompt includes the calling process name. Supports Ed25519, RSA, ECDSA P-256/P-384. Lock passphrase is SHA-256 hashed (never stored in plaintext) and compared with constant-time equality (`subtle`); stored hash is zeroized on unlock. Lock also clears keys from memory; unlock reloads them from keychain. `add_identity`/`remove_identity`/`remove_all_identities` go through `KeychainStore::modify` on a `tokio::task::spawn_blocking` worker so the file lock and synchronous keychain I/O don't block the async runtime.
- **ssh_cli.rs** — CLI functions for SSH key management: `ssh_add` (parse key from file or stdin with interactive comment prompt, encrypt, store), `ssh_list` (read index), `ssh_remove`/`ssh_remove_all` (delete from keychain + index), `ssh_show` (display public key).

### Keychain Access

All builds (debug and release) use the real macOS keychain. There are no hardcoded test stubs. This means `vt init` must be run before `ssh agent`/`secret`/etc. commands work in any build. Pure crypto unit tests do not require keychain access.

All vt secrets live in a **single keychain item**: `rusty.vault.store`. The blob is JSON with versioning (`v: 1`), holding the passcode+auth_token, the encrypted master passphrase, and optional encrypted SSH-keys and FIDO2-credentials sub-blobs. One item means one ACL means at most one login-password prompt per process when the binary's codesign requirement no longer matches. Reads use `KeychainStore::load()`. Writes (RMW) go through `KeychainStore::modify(|store| ...)` which takes a cross-process flock at `$TMPDIR/vt-keychain.lock` for the duration of the closure. The FIDO2 sign-counter update path uses `try_modify` instead — best-effort with a non-blocking lock, so that a SSH `sign()` flow can never starve waiting on the file lock.

There is no automatic migration binary for the old 4-item layout (`rusty.vault.{passcode,passphrase,ssh_keys,fido2_credentials}`). Upgrades from that layout are a documented breaking change: users must run `vt secret export` with the old binary before upgrading, then `vt secret import` with the new binary, then re-add SSH keys and FIDO2 credentials.

### SSH Agent Architecture

SSH keys are stored encrypted as the `encrypted_ssh_keys` field of `rusty.vault.store`, using the same `mac_cipher` as other secrets:
- **Keys**: stored as a single encrypted JSON array (fingerprint, algorithm, comment, OpenSSH private key) inside `KeychainStore.encrypted_ssh_keys`
- **Agent socket**: `~/.ssh/vt.sock` — Unix domain socket, cleaned up on SIGINT/SIGTERM
- **Eager loading**: All keys loaded into `Arc<RwLock<HashMap>>` at agent startup
- **Touch ID**: Required for `sign()` and `decrypt@vt` requests; listing keys does not require auth. After idle timeout, keys are silently reloaded on demand but `request_identities` returns empty until then; the normal auth cache rules enforce Touch ID on the subsequent `sign`/extension request.
- **Auth caching**: Optional per-session (by TTY device) or per-app (by `.app` ancestor PID) caching of Touch ID authorization for `sign` only. Configured via `--ssh-auth-cache-mode` (`none`/`per-session`/`per-app`) and `--ssh-auth-cache-duration` (seconds, default 120). Cache is cleared on agent lock. A background sweeper removes expired entries. Note: `decrypt@vt` and `auth@vt` always prompt (no caching) — `decrypt@vt` because plaintext blast radius is too large; `auth@vt` because over forwarded agents all remote sessions share the same local process.
- **Bio auth extension**: `auth@vt` extension triggers Touch ID without encrypting/decrypting data. Used for remote sudo via PAM. See README for setup.
- **Factory/Session split**: `VtSshAgentFactory` implements `Agent<UnixListener>` to extract peer PID via `LOCAL_PEERPID` socket option. Each connection gets a `VtSshSession` with the peer PID for process-aware auth caching.
- **Process introspection**: `proc_info` module uses `proc_pidinfo(PROC_PIDTBSDINFO)` for parent PID / TTY device and `proc_pidpath()` for executable path. Used for auth cache context resolution and displaying the calling process name in Touch ID prompts.

### Key Derivation Chain

1. `vt init` generates: `passcode` (32 random bytes) + `auth_token` (32 random bytes), stored together (64 bytes) in `KeychainStore.passcode_and_auth_token`
2. `auth_token` is double-SHA256 hashed from the original random bytes; `VT_AUTH` env var holds the base64 of the *original* bytes
3. `passphrase_secret` = double-SHA256(`base64(passcode):$USER:binary_path`) — ties decryption to specific user and binary location
4. The real passphrase (32 bytes) is encrypted with `passphrase_secret` and stored in `KeychainStore.encrypted_passphrase`

`vt secret rotate-passcode` overwrites the store with a fresh passcode/auth_token while preserving the existing `encrypted_ssh_keys` and `encrypted_fido2` fields (the master passphrase that protects them does not change). After rotate, a running `vt ssh agent` process holds a stale `passphrase_cipher` in its in-memory state and must be restarted — the rotate command prints a warning to that effect.

### Client-Agent Protocol

The CLI talks to `vt ssh agent` over the Unix socket at `~/.ssh/vt.sock` (or `$SSH_AUTH_SOCK`) using SSH-agent extension messages: `encrypt@vt`, `decrypt@vt`, `auth@vt`. The extension payload is double-encrypted: the wire payload is encrypted with the `VT_AUTH`-derived auth cipher, and the inner content carries vt-protocol strings encrypted with the passphrase. The agent decrypts incoming payloads, performs the operation (Touch ID gated where required), then re-encrypts the response with the same auth cipher. There is no HTTP transport.

### VT Protocol Format

`vt://{location}/{type}{data}` — location is `mac`, type is `0` (raw) or `1` (TOTP), data is base64-url-no-pad encoded encrypted bytes. All base64 throughout the codebase uses `BASE64_URL_SAFE_NO_PAD`.

### Environment Variables

- `VT_AUTH`: Auth token from `vt init` (base64-encoded original random bytes); keys the auth cipher used to encrypt every agent-extension payload
- `SSH_AUTH_SOCK`: Path to the agent socket; client falls back to `~/.ssh/vt.sock` if unset
- `RUST_LOG`: Log level (`debug` in debug builds, `info` in release)

## Git Workflow

- Do not push to remote after committing unless explicitly requested
