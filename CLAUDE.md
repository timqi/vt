# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build --release        # Release build (uses real macOS keychain)
cargo build                  # Debug build
cargo test                   # Run non-ignored tests (pure crypto tests, no server needed)
cargo test test_name         # Run a specific test
cargo test -- --ignored      # Run ALL tests (requires running server + macOS keychain)
```

## Architecture

VT (Vault) is a macOS-based KMS using the system keychain for secret storage and AES-256-GCM encryption.

### Source Files (src/)

- **main.rs** — CLI entry point (clap). Subcommands: `serve`, `init`, `create`, `read`, `inject`, `auth`, `secret {export,import,rotate-passcode}`, `ssh {agent,add,list,remove,remove-all,comment,show}`. Server-side commands (`serve`, `init`, `secret`, `ssh`) are `#[cfg(target_os = "macos")]`. `auth` is platform-agnostic (client runs on Linux, agent runs on macOS).
- **core.rs** — Shared domain types (`EncryptItem`, `DecryptReq`, `CryptoResItem`, `SecretType`) and crypto logic (`do_encrypt`, `do_decrypt`). Used by both `serve.rs` and `ssh_agent.rs`.
- **serve.rs** — Axum HTTP server with `/encrypt` and `/decrypt` POST endpoints. Auth middleware encrypts/decrypts the entire request and response body using `VT_AUTH`-derived key, including error responses (all post-auth responses are encrypted; pre-auth errors return generic plaintext). Decrypt requires Touch ID/local auth. Also spawns the SSH agent as a background tokio task on startup.
- **cli.rs** — Client logic. `VTClient` sends body-encrypted requests; error responses are decrypted if possible (post-auth), falling back to raw bytes (pre-auth). `inject` uses `libc::fork()` for timed file cleanup and `exec::Command` to replace the process.
- **security.rs** — `AesGcmCrypto` wrapper (AES-256-GCM with 12-byte nonce prepended to ciphertext). Keychain access via `security-framework` crate (`set_keychain`, `get_keychain`, `delete_keychain`), local auth via `localauthentication-rs`.
- **ssh_agent.rs** — SSH agent implementation using `ssh-agent-lib`. Split into `VtSshAgentFactory` (implements `Agent<UnixListener>`, owns shared state) and `VtSshSession` (per-connection, implements `Session`). Includes `AuthCacheMode`/`AuthCache` for optional per-session or per-app Touch ID caching, and a `proc_info` module for macOS process introspection (`proc_pidinfo`/`proc_pidpath`). Keys stored in keychain as `rusty.vault.ssh_keys` (single encrypted JSON blob). Touch ID required for `sign()` and `decrypt@vt` (with optional caching). Non-vt extensions (e.g. `session-bind@openssh.com`) are passed through gracefully. Touch ID prompt includes the calling process name. Supports Ed25519, RSA, ECDSA P-256/P-384. Lock passphrase is SHA-256 hashed (never stored in plaintext) and compared with constant-time equality (`subtle`); stored hash is zeroized on unlock. Lock also clears keys from memory; unlock reloads them from keychain.
- **ssh_cli.rs** — CLI functions for SSH key management: `ssh_add` (parse key from file or stdin with interactive comment prompt, encrypt, store), `ssh_list` (read index), `ssh_remove`/`ssh_remove_all` (delete from keychain + index), `ssh_show` (display public key).

### Keychain Access

All builds (debug and release) use the real macOS keychain. There are no hardcoded test stubs. This means `vt init` must be run before `serve`/`ssh` commands work in any build. Pure crypto unit tests do not require keychain access.

### SSH Agent Architecture

SSH keys are stored encrypted in the macOS keychain using the same `mac_cipher` as other secrets:
- **Keys**: `rusty.vault.ssh_keys` — single encrypted JSON blob containing all key entries (fingerprint, algorithm, comment, OpenSSH private key)
- **Agent socket**: `~/.ssh/vt.sock` — Unix domain socket, cleaned up on SIGINT/SIGTERM
- **Eager loading**: All keys loaded into `Arc<RwLock<HashMap>>` at agent startup
- **Touch ID**: Required for `sign()` and `decrypt@vt` requests; listing keys does not require auth. After idle timeout, keys are silently reloaded on demand but `request_identities` returns empty until then; the normal auth cache rules enforce Touch ID on the subsequent `sign`/extension request.
- **Auth caching**: Optional per-session (by TTY device) or per-app (by `.app` ancestor PID) caching of Touch ID authorization for `sign` only. Configured via `--ssh-auth-cache-mode` (`none`/`per-session`/`per-app`) and `--ssh-auth-cache-duration` (seconds, default 120). Cache is cleared on agent lock. A background sweeper removes expired entries. Note: `decrypt@vt` and `auth@vt` always prompt (no caching) — `decrypt@vt` because plaintext blast radius is too large; `auth@vt` because over forwarded agents all remote sessions share the same local process.
- **Bio auth extension**: `auth@vt` extension triggers Touch ID without encrypting/decrypting data. Used for remote sudo via PAM. See README for setup.
- **Factory/Session split**: `VtSshAgentFactory` implements `Agent<UnixListener>` to extract peer PID via `LOCAL_PEERPID` socket option. Each connection gets a `VtSshSession` with the peer PID for process-aware auth caching.
- **Process introspection**: `proc_info` module uses `proc_pidinfo(PROC_PIDTBSDINFO)` for parent PID / TTY device and `proc_pidpath()` for executable path. Used for auth cache context resolution and displaying the calling process name in Touch ID prompts.

### Key Derivation Chain

1. `vt init` generates: `passcode` (32 random bytes) + `auth_token` (32 random bytes), stored together (64 bytes) in keychain as `rusty.vault.passcode`
2. `auth_token` is double-SHA256 hashed from the original random bytes; `VT_AUTH` env var holds the base64 of the *original* bytes
3. `passphrase_secret` = double-SHA256(`base64(passcode):$USER:binary_path`) — ties decryption to specific user and binary location
4. The real passphrase (32 bytes) is encrypted with `passphrase_secret` and stored in keychain as `rusty.vault.passphrase`

### Client-Server Protocol

All HTTP communication is double-encrypted: the body is encrypted with the auth key derived from `VT_AUTH` (handled by auth middleware), and the payload contains vt-protocol strings encrypted with the passphrase. The auth middleware decrypts incoming requests and encrypts all outgoing responses (including errors) transparently. Pre-auth errors (wrong `VT_AUTH`, unreadable body) return generic plaintext; post-auth errors are encrypted like success responses. The client tries to decrypt error bodies first, falling back to raw bytes for pre-auth errors.

### VT Protocol Format

`vt://{location}/{type}{data}` — location is `mac`, type is `0` (raw) or `1` (TOTP), data is base64-url-no-pad encoded encrypted bytes. All base64 throughout the codebase uses `BASE64_URL_SAFE_NO_PAD`.

### Environment Variables

- `VT_ADDR`: Server address (default: `127.0.0.1:5757`); auto-prefixes `http://` for IP addresses, `https://` for hostnames
- `VT_AUTH`: Auth token from `vt init` (base64-encoded original random bytes)
- `RUST_LOG`: Log level (`debug` in debug builds, `info` in release)

## Git Workflow

- Do not push to remote after committing unless explicitly requested
