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
- Portable SSH identity for `git push`: one Ed25519 key stored as a `vt://` record and used on macOS / Linux / CI via `vt ssh keygen` + `vt ssh connect` — signing reuses the existing approval ceremony (Touch ID locally, phone passkey on headless hosts), and the private key never lives in plaintext on disk

## Installation

Download prebuilt binaries from [GitHub Releases](https://github.com/timqi/vt/releases) (macOS arm64, Linux amd64).

Or build from source (recipes live in the `justfile`, run `just` to list them):

```bash
# Builds (musl-static on Linux, native on macOS) and installs to ~/.local/bin
just install
```

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
   vt read vt://0xxxxx
   ```

## Commands

| Command | Description |
|---------|-------------|
| `version` | Show version information |
| `init` | (macOS) Initialize passcode and passphrase in keychain |
| `create` | Read plaintext from stdin, output encrypted vt protocol |
| `read <vt>` | Decrypt a vt protocol string |
| `rewrap [--no-dry-run] [--backup] <file>...` | Re-encrypt legacy `vt://mac/...` URLs in files to the current envelope format (one Touch ID per batch) |
| `inject [-r FILE] -- cmd...` | Transiently decrypt `vt://` in the file / env / argv, then exec the command |
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
| `ssh keygen [-l <label>] [--key-file <path>]` | Generate a portable Ed25519 identity stored as a `vt://` record; prints the OpenSSH public key (cross-platform) |
| `ssh connect [ssh args...]` | Git SSH driver — `GIT_SSH_COMMAND="vt ssh connect"`; signs with the `vt://` identity (cross-platform) |

### Inject Command

`inject` temporarily decrypts a config file (and/or env vars and argv) so a
child process can read plaintext, then atomically restores the ciphertext
backup after `--timeout` seconds.

```bash
# Run a service against an in-place-decrypted config; restored to ciphertext
# ~2s after exec, regardless of when the child finishes.
vt inject -r config.yaml -- ./run.sh

# Need the plaintext elsewhere? Compose with standard Unix tools — the file
# stays decrypted for the lifetime of the child:
vt inject -r config.yaml -- cat config.yaml        # decrypt → stdout
vt inject -r config.yaml -- cp config.yaml /tmp/c  # decrypt → another path
vt inject -r config.yaml -- jq .api_key config.yaml

# No file: only substitute vt:// in env vars and argv, then exec.
vt inject -- ./run.sh
```

Options:
- `-r, --replace-file <FILE>`: Decrypt vt:// in the file in place; restore from backup after timeout
- `-t, --timeout <SECONDS>`: Seconds before the backup is rolled back over the decrypted original (default: 2)

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

### Portable SSH identity for git (`vt://`)

Unlike `vt ssh add` (which stores keys in the macOS keychain, macOS-only), `vt ssh keygen`
mints an Ed25519 key whose private seed is stored as an ordinary `vt://` record — the same
encrypted format as every other secret. One key works on macOS, Linux, and headless/CI hosts,
and the plaintext seed never touches disk.

```
# Generate once (on any host). Writes ~/.config/vt/git-ssh (ciphertext, 0600)
# and ~/.config/vt/git-ssh.pub, and prints the public key to add to GitHub.
vt ssh keygen -l github

# On each host that runs git push (copy the ciphertext key file there, or set
# VT_GIT_SSH_PRIVATE_KEY to the raw vt:// record), wire git to sign through vt:
git config core.sshCommand "vt ssh connect"
git push        # signs via the existing ceremony: Touch ID locally, phone passkey on headless hosts
```

How it works: `vt ssh connect` is a `GIT_SSH_COMMAND` driver. It starts an ephemeral in-process
SSH agent (answering identity requests from the cleartext public key, no prompt), execs the system
`ssh` (which keeps doing transport + `known_hosts`), and on each signature decrypts the seed on
demand via the normal `vt://` decrypt path — SSH agent (`$SSH_AUTH_SOCK`, incl. a forwarded laptop
agent) first, CF passkey ceremony as fallback. The remote host needs `VT_AUTH` set to use a forwarded
agent; otherwise it goes straight to the phone passkey. See `docs/ssh-vt-design.md` for the full design.

### sudo via Touch ID or phone passkey

Use `vt auth` as a `sudo` authentication factor. Two approval paths, tried in
the order vt itself routes — agent first, then worker:

1. **SSH agent (macOS Touch ID)** over a forwarded agent (`VT_AUTH`).
2. **Phone passkey (Cloudflare Worker)** ceremony (`VT_PASSKEY_URL` +
   `VT_PASSKEY_TOKEN`) — the only path on a plain Linux server with no forwarded
   macOS agent.

A host may configure either or both. If the chosen path is unreachable or the
approval is rejected, `sudo` falls back to the password prompt.

```
macOS (vt SSH agent)  ◄──SSH agent forwarding──  Linux: sudo
       │                                            │
   Touch ID prompt                              PAM → vt auth ──► agent path (VT_AUTH)
       │                                            │                 │ (no agent / socket down)
   approve/reject   ──────────────────────────►    │                 ▼
                                                    │            worker path → /api/challenge
                                                    │                 │
   phone (Passkey)  ◄───────────────────────────────────────  approve on phone
                                                    ▼
                                       proceed / fall back to password
```

**Setup on macOS (agent path only):**

```bash
# Ensure vt agent is your SSH agent
export SSH_AUTH_SOCK=~/.ssh/vt.sock
vt ssh agent

# SSH with agent forwarding
ssh -A user@your-server
```

**Setup on the Linux server:**

Install the `vt` binary, then run the setup script. It reads `VT_AUTH` /
`VT_PASSKEY_URL` / `VT_PASSKEY_TOKEN` with the same precedence vt uses —
environment variable wins, else the invoking user's `~/.config/vt/config.toml`
(resolved via `$SUDO_USER`; override with `VT_CONFIG`). So if your CLI config is
already in place, no arguments are needed:

```bash
sudo ./setup-pam.sh                          # read everything from ~/.config/vt/config.toml
sudo VT_PASSKEY_TOKEN=… ./setup-pam.sh       # or override a value from the env
sudo VT_CONFIG=/path/config.toml ./setup-pam.sh
```

Or configure manually:

1. Create `/usr/local/bin/vt-sudo-auth.sh` (root:root, chmod 700). Embed the
   values you use — leave `VT_AUTH` empty on a worker-only host:
   ```bash
   #!/bin/bash
   export VT_AUTH=''                          # empty = agent path disabled
   export VT_PASSKEY_URL='https://vt-passkey.example.com'
   export VT_PASSKEY_TOKEN='your-worker-token'
   # Agent path: pam_exec doesn't inherit the user's env; recover SSH_AUTH_SOCK
   # from the invoking shell via /proc (skipped when VT_AUTH is empty).
   if [ -z "${SSH_AUTH_SOCK:-}" ] && [ -n "$VT_AUTH" ]; then
       USER_PID=$(awk '/^PPid:/{print $2}' /proc/$PPID/status 2>/dev/null)
       if [ -n "$USER_PID" ]; then
           SSH_AUTH_SOCK=$(tr '\0' '\n' < /proc/$USER_PID/environ 2>/dev/null | sed -n 's/^SSH_AUTH_SOCK=//p')
           [ -n "$SSH_AUTH_SOCK" ] && export SSH_AUTH_SOCK
       fi
   fi
   if [ -z "$VT_AUTH" ] && [ -z "$VT_PASSKEY_URL" ]; then exit 1; fi
   # No 2>/dev/null: pam_exec keeps stderr on the terminal, so the
   # "approve on your phone: <url>" line reaches the user.
   timeout 60 /usr/local/bin/vt auth \
       --reason "sudo ${PAM_SERVICE:-sudo} by ${PAM_USER:-unknown}"
   ```

2. Edit `/etc/pam.d/sudo`, add **before** `@include common-auth`:
   ```
   auth    sufficient    pam_exec.so seteuid quiet /usr/local/bin/vt-sudo-auth.sh
   ```

**Security notes:**
- `auth@vt` always prompts Touch ID (no caching) — over forwarded agents, all remote sessions share the same local process.
- `sufficient` means an approved ceremony skips the password; failure/timeout falls through to the password prompt.
- **Worker path spreads the worker master.** `VT_PASSKEY_TOKEN` equals the worker master `VT_AUTH_CF` — a static, network-reachable credential. Embedding it on every sudo host is a larger blast radius than the agent path (whose `VT_AUTH` is only useful while a live forwarded socket exists): theft lets an attacker POST `/api/challenge` from anywhere (still phone-gated — no decrypt without a tap, but they can spam approval prompts) and, if `CACHE_SECKEY` is set, probe `/api/dek-cache` within the TTL (bounded by its IP+pwd binding). Keep the helper script root-only (700); prefer enabling the worker path on a small set of bastion hosts. A per-host derived key (like the agent-audit design in `docs/agent-audit.md`) would need a worker-side change and is not yet available here.
- **No terminal feedback under some setups.** `pam_exec` swallows stdout; the approval URL is on stderr. Enable a push channel (Pushover/Slack/Feishu) so approvals reach your phone directly. The 60s timeout means sudo can hang that long before falling back to the password stack.

## VT Protocol Format

```
vt://{type}{data}
```

- **type**: `0` for raw secrets, `1` for TOTP
- **data**: Base64 URL-safe encoded AES-256-GCM envelope (per-record DEK derived from the master key + a salt carried in the URL)

Example: `vt://0SGVsbG8gV29ybGQ`

> Legacy `vt://mac/…` records (pre-2.0) remain readable for migration; convert them to the current envelope format with `vt rewrap`.

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

### Security Requirements

- Run `vt ssh agent` from the same user who ran `vt init`
- Keep the `vt` binary at the same absolute path as during `vt init`
- The agent requires Touch ID or local authentication for decrypt operations

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

## Passkey Approval (Cloudflare Worker)

For hosts without a macOS keychain (Linux servers, CI, headless boxes), `vt`
decrypts `vt://` records through a phone WebAuthn ceremony served by the
Cloudflare Worker in `cf-worker/`. The CLI reaches it via `VT_PASSKEY_URL` +
`VT_PASSKEY_TOKEN`.

See [docs/cf-worker-deploy.md](docs/cf-worker-deploy.md) for the full deployment
guide (wrangler config, Cloudflare Access gate, secrets, first-Passkey
bootstrap, and CLI wiring).

## License

MIT
