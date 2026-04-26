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

## Quick Start

1. Initialize the vault (creates keychain entries):
   ```bash
   vt init
   ```

2. Start the KMS server (also starts the SSH agent on `~/.ssh/vt.sock`):
   ```bash
   vt serve
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
| `serve` | (macOS) Start the KMS HTTP server and SSH agent (supports `--ssh-idle-timeout`, `--ssh-auth-cache-mode`, `--ssh-auth-cache-duration`) |
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

# The SSH agent starts automatically with `vt serve`.
# To start it standalone:
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
vt serve  # or: vt ssh agent

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
| `VT_ADDR` | Server address | `127.0.0.1:5757` |
| `VT_AUTH` | Authentication token (from `vt init`) | - |
| `RUST_LOG` | Log level | `info` (release) / `debug` (dev) |

## Secret Management

VT stores all secrets in a **single keychain item**: `rusty.vault.store`. The blob is a JSON document containing:

- the random `passcode` + `auth_token` (used to derive the passphrase encryption key and `VT_AUTH`)
- the encrypted master `passphrase` (the actual AES-256-GCM key, wrapped with a key derived from passcode + `$USER` + binary path)
- optional encrypted SSH keys (under `encrypted_ssh_keys`)
- optional encrypted FIDO2 credentials (under `encrypted_fido2`)

One item means one keychain ACL. After the binary's first run is granted "Always Allow", subsequent rebuilds signed with the same code-signing identity reuse that grant — no repeated login-password prompts.

### Migrating from the legacy 4-item layout

Earlier versions of vt used four separate keychain items: `rusty.vault.passcode`, `rusty.vault.passphrase`, `rusty.vault.ssh_keys`, and `rusty.vault.fido2_credentials`. If you're upgrading from one of those versions, run the **`vt-migrate`** one-shot tool to consolidate them into `rusty.vault.store`.

The migration tool ships as a separate binary so the main `vt` CLI doesn't carry one-time upgrade code. It's not needed on fresh installs.

```bash
# Build the tool (not built by default)
cargo build --release --bin vt-migrate

# Run it. Use the same binary path / $USER you used at `vt init` time —
# the tool decrypts the legacy passphrase as a sanity check before writing
# anything, so a wrong path/user fails up front.
./target/release/vt-migrate
```

What it does:

1. Reads the four legacy items.
2. Decrypts the legacy passphrase to confirm it can be unwrapped on this host.
3. Writes the consolidated `rusty.vault.store`.
4. Re-reads the new store and verifies, by full decrypt, that it matches the legacy data.

It does **not** delete the legacy items. After it reports success, verify with `vt ssh list` / `vt fido2 list` / `vt read …`, then remove the four legacy items manually in Keychain Access:

- `rusty.vault.passcode`
- `rusty.vault.passphrase`
- `rusty.vault.ssh_keys`
- `rusty.vault.fido2_credentials`

If the new store already exists the tool refuses to overwrite — delete it via Keychain Access first if you really want to re-run.

### Security Requirements

- Run `vt serve` from the same user who ran `vt init`
- Keep the `vt` binary at the same absolute path as during `vt init`
- The server requires Touch ID or local authentication for decrypt operations

## Architecture

```
┌─────────────┐     HTTP      ┌─────────────┐     ┌─────────────┐
│  vt client  │ ─────────────▶│  vt serve   │────▶│   Keychain  │
│  (create,   │  encrypted    │  (decrypt,  │     │  (passcode, │
│   read,     │◀───────────── │   encrypt)  │◀────│  passphrase,│
│   inject)   │    body       └─────────────┘     │  ssh keys)  │
└─────────────┘                      │            └─────────────┘
                                     ▼                   ▲
                              ┌─────────────┐            │
                              │  Touch ID   │     ┌──────┴──────┐
                              │  (decrypt,  │     │ vt ssh agent│
                              │   sign)     │     │ (Unix sock) │
                              └─────────────┘     └─────────────┘
```

All keychain access (passcode, passphrase, SSH keys, FIDO2) routes through a single `rusty.vault.store` item — see [Secret Management](#secret-management) for layout and migration from the legacy four-item layout.

## License

MIT
