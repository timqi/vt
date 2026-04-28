# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build --release                              # Release build (uses real macOS keychain)
cargo build                                        # Debug build (macOS)
cargo check --target x86_64-unknown-linux-gnu      # Cross-platform client surface check (no macOS server)
cargo test                                         # Run non-ignored tests (pure crypto tests, no agent needed)
cargo test test_name                               # Run a specific test
cargo test -- --ignored                            # Run ALL tests (requires running agent + macOS keychain)
```

The Linux cross-check is the boundary guard for the client/server split: it must stay green so any future change that smuggles a macOS-only symbol into the client surface fails locally.

## Architecture

VT (Vault) is a macOS-based KMS using the system keychain for secret storage and AES-256-GCM encryption. The codebase is split into a cross-platform client + protocol core, and a macOS-only server tree. The same `vt` binary contains both; on Linux the macOS tree is `cfg`-gated out.

### Source Tree (src/)

```
main.rs                    cross-platform; clap routing only
client.rs                  cross-platform; VTClient + create/read/inject/auth bodies
core.rs                    cross-platform; protocol types, vt:// parsing, do_encrypt/do_decrypt
core/
├── crypto.rs              AesGcmCrypto, derive_passphrase_secret, decode_auth_cipher_from_b64
└── session.rs             SessionFlags/SessionState/AuthOutcome/AuthMethod + classify_session
tty.rs                     cross-platform; prompt_input_password (used by client + server admin)
server_macos/              #[cfg(target_os = "macos")]
├── mod.rs
├── admin.rs               init, secret export/import/rotate-passcode
├── security.rs            keychain (set/get/delete_keychain), LA chain (authenticate, classify_la_error),
│                          create_and_save_passcode_passphrase, derive_passcode_ciphers, load_mac_cipher
├── store.rs               KeychainStore — single `rusty.vault.store` JSON blob, flock RMW
├── ssh_agent.rs           SSH-agent (VtSshAgentFactory/VtSshSession), AuthCache, proc_info
├── ssh_cli.rs             ssh add/list/remove/comment/show command bodies
├── fido2.rs               FIDO2 enrollment + assertion, encrypted-credential storage
└── fido2_cli.rs           fido2 register/list/remove command bodies
```

Layer rules:

- `core` has no I/O and no platform deps. Pure types, pure crypto, pure classifiers.
- `client` depends only on `core`, `tty`, `ssh-agent-lib` (blocking client), and Unix-but-cross-platform crates (`dirs`, `hostname`, `regex`, `exec`, `libc`). It must never reach into `server_macos`.
- `server_macos` is the only consumer of `KeychainStore`, `LAContext`, FIDO2/CTAP, `ssh-key`, and macOS framework FFI.
- `main.rs` routes commands. Client commands (`create`/`read`/`inject`/`auth`) are unconditional; admin commands (`init`/`secret`/`ssh`/`fido2`) are gated on macOS at the clap-derive level.
- In `Cargo.toml`, `ssh-agent-lib` is listed twice on purpose: once in `[dependencies]` with `default-features = false` (the client only needs `proto::Extension` + `blocking::Client`) and once under `[target.'cfg(target_os = "macos")'.dependencies]` adding `["agent","codec"]` for the agent server. `ssh-key`, `security-framework`, all `objc2*`, FIDO2/CTAP, and the curve crates live entirely in the macOS target block. Anything new that reaches the keychain or LA goes there too.

### Detailed Module Notes

- **client.rs** — `VTClient` sends extension requests over the SSH agent Unix socket (`encrypt@vt` / `decrypt@vt` / `auth@vt`); each extension payload is encrypted with the `VT_AUTH`-derived auth cipher. `inject` uses `libc::fork()` for timed file cleanup and `exec::Command` to replace the process.
- **core/crypto.rs** — `AesGcmCrypto` (AES-256-GCM with 12-byte nonce prepended to ciphertext), `derive_passphrase_secret` (SHA-256(SHA-256(`base64(passcode):$USER:bin_path`))), `decode_auth_cipher_from_b64` (turns the `VT_AUTH` env var into the auth cipher key).
- **core/session.rs** — Platform-neutral session-state classifier. The macOS adapter in `server_macos::security` reads `CGSessionCopyCurrentDictionary` into a `SessionFlags` and feeds it through `classify_session`.
- **server_macos/security.rs** — Low-level keychain access via `security-framework` (`set_keychain`, `get_keychain`); higher-level callers should go through `KeychainStore` instead. `derive_passcode_ciphers(&KeychainStore)` and `load_mac_cipher(&KeychainStore, &passphrase_cipher)` are the canonical entry points. The auth chain (`authenticate`) is Touch ID → FIDO2 → password, with `classify_la_error` lifting `LAError` codes into `EvalOutcome` for testable fallback decisions. Local auth uses `objc2-local-authentication` so LAError codes can be classified precisely.
- **server_macos/store.rs** — `KeychainStore` type backing the single `rusty.vault.store` keychain item. JSON-serialized blob with fields `passcode_and_auth_token`, `encrypted_passphrase`, optional `encrypted_ssh_keys`, optional `encrypted_fido2`. Provides `load`/`save` and the cross-process `modify` (blocking flock) and `try_modify` (non-blocking flock, used by FIDO2 sign-counter persistence to avoid stalling SSH sessions) helpers. Lock file lives at `$TMPDIR/vt-keychain.lock` and is never deleted (per-user, cleared on reboot).
- **server_macos/ssh_agent.rs** — SSH agent implementation using `ssh-agent-lib`. Split into `VtSshAgentFactory` (implements `Agent<UnixListener>`, owns shared state) and `VtSshSession` (per-connection, implements `Session`). Includes `AuthCacheMode`/`AuthCache` for optional per-session or per-app Touch ID caching, and a `proc_info` module for macOS process introspection (`proc_pidinfo`/`proc_pidpath`). Keys live inside `KeychainStore.encrypted_ssh_keys` (a single encrypted JSON blob, formerly its own keychain item). Touch ID required for `sign()` and `decrypt@vt` (with optional caching). Non-vt extensions (e.g. `session-bind@openssh.com`) are passed through gracefully. Touch ID prompt includes the calling process name. Supports Ed25519, RSA, ECDSA P-256/P-384. Lock passphrase is SHA-256 hashed (never stored in plaintext) and compared with constant-time equality (`subtle`); stored hash is zeroized on unlock. Lock also clears keys from memory; unlock reloads them from keychain. `add_identity`/`remove_identity`/`remove_all_identities` go through `KeychainStore::modify` on a `tokio::task::spawn_blocking` worker so the file lock and synchronous keychain I/O don't block the async runtime.
- **server_macos/ssh_cli.rs** — CLI functions for SSH key management: `ssh_add` (parse key from file or stdin with interactive comment prompt, encrypt, store), `ssh_list` (read index), `ssh_remove`/`ssh_remove_all` (delete from keychain + index), `ssh_show` (display public key).

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
- **Auth caching**: Two independent caches — one for `sign`, one for `decrypt@vt` v2 items.
  - **Sign cache**: `--ssh-auth-cache-mode` (`none`/`per-session`/`per-app`, default `none`), `--ssh-auth-cache-duration` (seconds, default 120). `per-session` keys on the **POSIX session leader** (`getsid(peer_pid)`) — i.e. the shell at the head of the pty (Terminal/iTerm shell, tmux/screen pane shell, or remote ssh shell). `per-app` keys on the first `.app/Contents/` ancestor PID, falling back to peer_pid (no cross-CLI cache when not under an app). Both modes additionally encode the leader/app PID's `start_tvsec` so PID reuse can never resurrect a stale grant.
  - **Decrypt cache**: `--decrypt-auth-cache-mode` (default `none`), `--decrypt-auth-cache-duration` (default 30s, strict TTL — hits do not refresh; `AuthCache::grant` is idempotent for still-valid entries so concurrent grants on the same key cannot extend the original expiry). Only v2 envelope items are cache-eligible: a request batch containing any legacy item disables caching for the whole batch. Cache key per v2 item is `SHA256("vt-decrypt-cache-v1" || t || salt || len(host) || host)` — domain-tagged and length-prefixed; `host` is taken from `DecryptReq.host` (client-supplied, used for partitioning only, not trust). `SecretType::UNKNOWN` is rejected up front so a malformed v2 item cannot pollute the cache. On a fully-cached batch the Touch ID prompt is skipped entirely; on a partial-hit batch the user is prompted once and grants are issued only for the previously-missing items.
  - **Cacheable methods**: Touch ID (`Biometric`), FIDO2 YubiKey touch (`Fido2`), and password (`Password`) all grant cache entries. FIDO2 is treated as equivalent to Touch ID for authorization — earlier "FIDO2 is a weaker factor" carve-out is dropped by policy.
  - **TTY requirement**: Both `per-session` and `per-app` modes inherit the `tdev != 0` gate from `resolve_cache_context` — peers without a controlling terminal (launchd-managed daemons, anything detached from a pty) always prompt and never enter the cache. Fail-closed: if `getsid` or `proc_pidinfo` fails for any reason, the connection's `cache_context` is `None` and the cache is bypassed for that session.
  - **Threat model**: a cache hit is authorization scoped to `(session_leader_or_app_pid, start_tvsec)`. Any process inside that POSIX session (or under that `.app`) can replay a peer's `(t, salt, host)` tuple to inherit a still-valid grant without a new prompt. This is the deliberate trade-off — the user's "one Touch ID per session" target requires accepting that the session boundary is the trust boundary, not the individual process. Use `none` if any process inside your session is untrusted.
  - **Lock and sweep**: Both caches are cleared on `ssh-add -x` (agent lock) and on agent restart (which is itself required after `vt secret rotate-passcode` — see Key Derivation Chain). One background sweeper removes expired entries from both every 60s. `auth@vt` is never cached (forwarded agents share one local process — caching would approve any remote sudo).
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
