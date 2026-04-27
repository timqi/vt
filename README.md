# VT (Vault)

A simple KMS solution based on macOS keychain. No plaintext secrets, explicit authentication everywhere.

## Features

- Secure secret storage using macOS keychain
- AES-256-GCM encryption
- Touch ID / local authentication for decrypt operations
- TOTP support for time-based one-time passwords
- Environment variable and file injection with automatic cleanup
- SSH agent with Touch ID gated signing (Ed25519, RSA, ECDSA P-256/P-384) and optional per-session/per-app auth caching
- Remote sudo via Touch ID through SSH agent forwarding

## Installation

Download prebuilt binaries from [GitHub Releases](https://github.com/timqi/vt/releases) (macOS arm64, Linux amd64).

Or build from source:

```bash
cargo build --release
cp target/release/vt /usr/local/bin/
```

## Upgrade Warning

### v2.0.0 — protocol redesign (BREAKING)

v2.0.0 switches the client ↔ agent wire protocol to **envelope encryption**: the agent never sees plaintext on encrypt and never sees stored ciphertext on decrypt — it only releases a per-record DEK after Touch ID. The `vt://` URL format also changes: new secrets are emitted as `vt://0…` / `vt://1…` (no `mac/` segment); old `vt://mac/…` URLs continue to be readable for migration. See `src/core.rs` and the v2.0.0 release notes for full protocol details.

This is a **breaking protocol change**. The client and the running `vt ssh agent` must upgrade in lockstep — an old client speaking to a new agent will fail with `unknown variant ... expected V2 or Legacy`. To upgrade:

1. Build/install the new binary: `cargo install --path .` (or copy `target/release/vt` to your PATH location).
2. Stop the running agent: `pkill -f 'vt ssh agent'`.
3. Restart the agent from the new binary (in a fresh shell so PATH resolves correctly): `vt ssh agent`.
4. **Migrate stored secrets** (recommended): legacy `vt://mac/…` URLs in your dotfiles / env files can be bulk-migrated to v2 with the included script:
   ```bash
   uv run migrate-vt-urls.py path/to/file …             # dry-run preview
   uv run migrate-vt-urls.py --no-dry-run path/to/file … # actually rewrite
   ```
   The script handles RAW and TOTP types (TOTP migration uses a one-time legacy-path trick to recover the seed). Backups are left at `*.vt-migrate-backup`.
5. Once all secrets are migrated, restart the agent with `--no-legacy-decrypt` to permanently retire the legacy code path:
   ```bash
   vt ssh agent --no-legacy-decrypt
   ```

### Earlier breaking change — keychain consolidation

Older installs (pre-1.0.0) used four separate keychain items. The current single `rusty.vault.store` layout requires `vt secret export` with the old version, then `vt secret import` after installing. See [Secret Management](#secret-management) for the full upgrade path.

## Quick Start

1. Initialize the vault (creates the `rusty.vault.store` keychain item):
   ```bash
   vt init
   ```

2. Start the SSH agent (listens on `~/.ssh/vt.sock`):
   ```bash
   vt ssh agent
   ```

3. Export the auth token (shown during `vt init`):
   ```bash
   export VT_AUTH=<your_auth_token>
   ```

4. Create and read secrets:
   ```bash
   # Create an encrypted secret (reads from stdin)
   vt create

   # Read/decrypt a vt protocol string
   vt read vt://mac/0xxxxx
   ```

## Commands

| Command | Description |
|---------|-------------|
| `version` | Show version information |
| `init` | (macOS) Initialize passcode and passphrase in keychain |
| `create` | Read plaintext from stdin, output encrypted vt protocol |
| `read <vt>` | Decrypt a vt protocol string |
| `inject` | Decrypt vt protocols in env/files, optionally run a command |
| `auth [--reason <text>]` | Trigger bio auth via SSH agent forwarding (for PAM/sudo) |
| `secret export` | (macOS) Export the encrypted master secret |
| `secret import` | (macOS) Import an encrypted master secret |
| `secret rotate-passcode` | (macOS) Rotate the passcode for the master secret |
| `ssh agent` | (macOS) Start the SSH agent (supports `--timeout`, `--ssh-auth-cache-mode`, `--ssh-auth-cache-duration`) |
| `ssh add [-f <file>] [-c <comment>]` | (macOS) Add an SSH private key (from file or stdin) |
| `ssh list` | (macOS) List stored SSH keys (shows fingerprint, algorithm, comment, and public key) |
| `ssh comment <fingerprint> -c <comment>` | (macOS) Change the comment of a stored key |
| `ssh remove <fingerprint>` | (macOS) Remove an SSH key by fingerprint |
| `ssh remove-all` | (macOS) Remove all stored SSH keys |
| `ssh show <fingerprint>` | (macOS) Show the public key for a stored key |

### Inject Command

The `inject` command supports several modes:

```bash
# Replace vt:// patterns in a file
vt inject -r config.yaml

# Read from input file, write to output file, then run command
vt inject -i template.env -o .env -- myapp --config .env

# Inject env vars and run command (output file auto-deleted after timeout)
vt inject -o secrets.env -t 5 -- ./run.sh
```

Options:
- `-r, --replace-file <FILE>`: Replace vt protocols in-place
- `-i, --input-file <FILE>`: Input file with vt protocols
- `-o, --output-file <FILE>`: Output file for decrypted content
- `-t, --timeout <SECONDS>`: Seconds before deleting output file (default: 2)

### SSH Agent

VT can act as an SSH agent, storing private keys encrypted in the macOS keychain and requiring Touch ID for every signing operation.

```bash
# Add a key from file (supports Ed25519, RSA, ECDSA P-256/P-384)
vt ssh add -f ~/.ssh/id_ed25519
# Optionally override the key's embedded comment
vt ssh add -f ~/.ssh/id_ed25519 -c "work laptop"
# Add a key interactively (paste key, Ctrl+D, then enter comment)
vt ssh add

# List stored keys
vt ssh list

# Show public key (for adding to GitHub, servers, etc.)
vt ssh show SHA256:...

# Start the SSH agent (it listens on ~/.ssh/vt.sock):
eval $(vt ssh agent)

# Start with auth caching (skip repeated Touch ID within a time window):
# per-session: cache by terminal session (TTY)
eval $(vt ssh agent --ssh-auth-cache-mode per-session --ssh-auth-cache-duration 300)
# per-app: cache by application (e.g., Terminal.app, iTerm2)
eval $(vt ssh agent --ssh-auth-cache-mode per-app --ssh-auth-cache-duration 300)

# Set SSH_AUTH_SOCK to use the agent (add to your shell profile)
export SSH_AUTH_SOCK=~/.ssh/vt.sock

# Now ssh/git commands use vt for authentication
# Touch ID prompt shows the calling process name (e.g., "SSH sign: key (SHA256:...) by ssh")
ssh git@github.com
git push origin main

# Change a key's comment
vt ssh comment SHA256:... -c "new comment"

# Remove a key
vt ssh remove SHA256:...
```

Keys are stored as a single encrypted JSON blob inside `rusty.vault.store` (under `encrypted_ssh_keys`), using the same `mac_cipher` as other secrets.

#### Auth Caching

By default, Touch ID is required for every sign/decrypt request. You can enable auth caching to skip repeated prompts within a time window:

| Mode | `--ssh-auth-cache-mode` | Scope |
|------|-------------------------|-------|
| None (default) | `none` | Touch ID every time |
| Per-session | `per-session` | Shared within same terminal/TTY |
| Per-app | `per-app` | Shared within same application (e.g., Terminal.app) |

`--ssh-auth-cache-duration <SECONDS>` controls how long a grant lasts (default: 300s). The cache is cleared when the agent is locked.

### Remote sudo via Touch ID

Use `vt auth` to trigger Touch ID on your macOS when running `sudo` on a remote Linux server. If macOS is unreachable or Touch ID is rejected, sudo falls back to password.

```
macOS (vt SSH agent)  ◄──SSH agent forwarding──  Linux: sudo
       │                                            │
   Touch ID prompt                              PAM → vt auth
       │                                            │
   approve/reject   ──────────────────────────►  proceed/fallback to password
```

**Setup on macOS:**

```bash
# Ensure vt agent is your SSH agent
export SSH_AUTH_SOCK=~/.ssh/vt.sock
vt ssh agent

# SSH with agent forwarding
ssh -A user@your-server
```

**Setup on the remote Linux server:**

Install the `vt` binary, then run the setup script:

```bash
sudo VT_AUTH="your-token" ./setup-pam.sh
```

Or configure manually:

1. Create `/usr/local/bin/vt-sudo-auth.sh` (root:root, chmod 700):
   ```bash
   #!/bin/bash
   export VT_AUTH="your-base64-token-here"
   # pam_exec doesn't inherit user's env; read SSH_AUTH_SOCK from /proc
   if [ -z "$SSH_AUTH_SOCK" ]; then
       SUDO_PID=$PPID
       USER_PID=$(awk '/^PPid:/{print $2}' /proc/$SUDO_PID/status 2>/dev/null)
       if [ -n "$USER_PID" ]; then
           SSH_AUTH_SOCK=$(tr '\0' '\n' < /proc/$USER_PID/environ 2>/dev/null | sed -n 's/^SSH_AUTH_SOCK=//p')
           export SSH_AUTH_SOCK
       fi
   fi
   if [ -z "$SSH_AUTH_SOCK" ]; then exit 1; fi
   timeout 30 /usr/local/bin/vt auth \
       --reason "sudo ${PAM_SERVICE:-sudo} by ${PAM_USER:-unknown}" 2>/dev/null
   ```

2. Edit `/etc/pam.d/sudo`, add **before** `@include common-auth`:
   ```
   auth    sufficient    pam_exec.so seteuid quiet /usr/local/bin/vt-sudo-auth.sh
   ```

**Security notes:**
- `auth@vt` always prompts Touch ID (no caching) — over forwarded agents, all remote sessions share the same local process
- `VT_AUTH` in the helper script is a full credential (also authorizes encrypt/decrypt) — keep the script root-only
- `sufficient` means Touch ID success skips password; failure falls through to password prompt

## VT Protocol Format

```
vt://{location}/{type}{data}
```

- **location**: Secret storage location (`mac` for macOS keychain)
- **type**: `0` for raw secrets, `1` for TOTP
- **data**: Base64 URL-safe encoded encrypted data

Example: `vt://mac/0SGVsbG8gV29ybGQ`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_AUTH` | Authentication token (from `vt init`) | - |
| `SSH_AUTH_SOCK` | SSH agent socket path (used by clients to reach `vt ssh agent`) | falls back to `~/.ssh/vt.sock` |
| `RUST_LOG` | Log level | `info` (release) / `debug` (dev) |

## Secret Management

VT stores all secrets in a **single keychain item**: `rusty.vault.store`. The blob is a JSON document containing:

- the random `passcode` + `auth_token` (used to derive the passphrase encryption key and `VT_AUTH`)
- the encrypted master `passphrase` (the actual AES-256-GCM key, wrapped with a key derived from passcode + `$USER` + binary path)
- optional encrypted SSH keys (under `encrypted_ssh_keys`)
- optional encrypted FIDO2 credentials (under `encrypted_fido2`)

One item means one keychain ACL. After the binary's first run is granted "Always Allow", subsequent rebuilds signed with the same code-signing identity reuse that grant — no repeated login-password prompts.

### Breaking Change: Legacy Keychain Layout

Earlier versions of vt used four separate keychain items: `rusty.vault.passcode`, `rusty.vault.passphrase`, `rusty.vault.ssh_keys`, and `rusty.vault.fido2_credentials`. This version does **not** include an automatic migration tool for that layout.

Before upgrading from a version that uses the four-item layout, export the master secret with the old binary:

```bash
vt secret export
```

After installing the new version, import that exported master secret:

```bash
vt secret import
```

This preserves the ability to decrypt existing `vt://mac/...` secret values because those values are protected by the master secret. The import creates a fresh `rusty.vault.store`, fresh passcode, and fresh `VT_AUTH`; update your shell profile or secret manager with the new token printed by `vt secret import`.

SSH keys and FIDO2 credentials are not part of `secret export`, so re-add them after the import:

```bash
vt ssh add -f ~/.ssh/id_ed25519
vt fido2 register --label yubikey
```

After verifying `vt read`, `vt ssh list`, and `vt fido2 list`, remove the legacy keychain items manually in Keychain Access:

- `rusty.vault.passcode`
- `rusty.vault.passphrase`
- `rusty.vault.ssh_keys`
- `rusty.vault.fido2_credentials`

If `rusty.vault.store` already exists, `vt init` and `vt secret import` refuse to overwrite it. Delete `rusty.vault.store` in Keychain Access first if you need to re-import.

### Security Requirements

- Run `vt ssh agent` from the same user who ran `vt init`
- Keep the `vt` binary at the same absolute path as during `vt init`
- The agent requires Touch ID or local authentication for decrypt operations

## Migrating from versions with HTTP transport

Earlier versions of `vt` exposed an HTTP server (`vt serve`) on `127.0.0.1:5757` with `/encrypt` and `/decrypt` endpoints. **The HTTP transport has been removed; the SSH agent at `~/.ssh/vt.sock` is now the only way clients reach the keychain.**

### Why

`VTClient` already preferred the SSH agent socket and only fell back to HTTP when the socket was unavailable. The agent extensions (`encrypt@vt`, `decrypt@vt`, `auth@vt`) cover every operation the HTTP endpoints did, with the same `VT_AUTH`-keyed double-encryption model. Keeping a second transport meant:

- An extra long-running TCP listener (even if loopback-bound)
- ~50+ transitive crates pulled by `axum` + `reqwest`
- A second auth-middleware code path to maintain
- Doubled wire-format decisions whenever the protocol evolves (error responses, retry semantics, etc.)

Removing it is net-negative LOC, fewer dependencies, and a single canonical path.

### What was removed

| Item | Replacement |
|---|---|
| `vt serve` subcommand | `vt ssh agent` |
| `--addr` flag and `VT_ADDR` env var | (removed; not needed) |
| `--enable-http` flag on `serve` | (removed) |
| HTTP fallback inside `VTClient` | SSH-agent-only; errors out if the socket is unreachable |
| `axum`, `reqwest` crates | (gone) |
| `src/serve.rs` | (deleted) |

### What was preserved

- Secret encryption format and existing `vt://mac/...` values remain usable after exporting/importing the master secret
- `VT_AUTH` still keys the auth cipher (now used to encrypt SSH-agent extension payloads)
- All `vt ssh agent` flags work identically: `--timeout`, `--ssh-auth-cache-mode`, `--ssh-auth-cache-duration`

### Steps to upgrade

1. **Update your LaunchAgent / supervisor.** Replace `vt serve` invocations with `vt ssh agent`. The flags `--ssh-idle-timeout` / `--ssh-auth-cache-mode` / `--ssh-auth-cache-duration` from `vt serve` map directly to `--timeout` / `--ssh-auth-cache-mode` / `--ssh-auth-cache-duration` on `vt ssh agent`.
2. **Unset `VT_ADDR`** from shell profiles. It's now an unrecognized flag and will fail clap parsing.
3. **Verify the agent socket.** Run `ls -l ~/.ssh/vt.sock` after starting `vt ssh agent`. Clients fail with `SSH agent not available — set SSH_AUTH_SOCK or run \`vt ssh agent\`` if the socket is missing.

### Behavior change

If your local `SSH_AUTH_SOCK` points to a non-vt agent (e.g. forwarded from a host without `vt`), client commands previously fell back to HTTP. They now fail with the agent-unavailable error. Either set `SSH_AUTH_SOCK=~/.ssh/vt.sock` for `vt` clients, or unset it so the client uses the default path.

## Architecture

```
┌─────────────┐  Unix socket  ┌──────────────┐     ┌─────────────┐
│  vt client  │ ─────────────▶│ vt ssh agent │────▶│   Keychain  │
│  (create,   │  encrypted    │  (decrypt,   │     │  (passcode, │
│   read,     │◀───────────── │   encrypt,   │◀────│  passphrase,│
│   inject,   │   extension   │   sign,      │     │  ssh keys,  │
│   auth)     │   payload     │   auth@vt)   │     │  fido2)     │
└─────────────┘               └──────────────┘     └─────────────┘
                                     │
                                     ▼
                              ┌─────────────┐
                              │  Touch ID   │
                              │  (decrypt,  │
                              │   sign)     │
                              └─────────────┘
```

All keychain access (passcode, passphrase, SSH keys, FIDO2) routes through a single `rusty.vault.store` item — see [Secret Management](#secret-management) for the layout and the breaking-change upgrade path from the legacy four-item layout.

### Client / Server Split

The `vt` source tree is split into a cross-platform client (`create`/`read`/`inject`/`auth`) and a macOS-only server (`init`/`secret`/`ssh`/`fido2`, including the SSH agent itself). Both ship in the same binary; on Linux the macOS server is `cfg`-gated out, so the Linux build only contains the client commands.

## License

MIT
