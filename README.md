# VT (Vault)

A small KMS for macOS Keychain and phone Passkey approval. Secrets stay
encrypted at rest and every decrypt/sign operation has an explicit approval
path.

## Features

- Secure secret storage using VT's encrypted macOS Keychain-backed store
- AES-256-GCM encryption
- Touch ID / local authentication for decrypt operations
- TOTP support for time-based one-time passwords
- Environment variable and file injection with automatic cleanup
- SSH agent with Touch ID gated signing (Ed25519, RSA, ECDSA P-256/P-384) and optional scoped auth caching
- Remote sudo via Touch ID through SSH agent forwarding or phone Passkey approval
- Portable SSH identity for `git push`: one Ed25519 key stored as a `vt://` record and used on macOS / Linux / CI via `vt ssh keygen` + `vt ssh connect` — signing reuses the existing approval ceremony (Touch ID locally, phone passkey on headless hosts), and the private key never lives in plaintext on disk

## Documentation

Use [`docs/README.md`](docs/README.md) as the documentation map. The most
common paths are:

- [`docs/cf-worker-deploy.md`](docs/cf-worker-deploy.md): deploy phone approval;
- [`docs/sudo.md`](docs/sudo.md): use VT as a Linux sudo/PAM factor;
- [`docs/hook.md`](docs/hook.md): integrate with AI coding agents;
- [`docs/ssh-vt-design.md`](docs/ssh-vt-design.md): SSH implementation and
  security decision record;
- [`config.example.toml`](config.example.toml) and [`agent.example.toml`](agent.example.toml): configuration templates.

## Installation

Download prebuilt artifacts from [GitHub Releases](https://github.com/timqi/vt/releases):
the bare `vt` binary (macOS arm64, Linux amd64) and, for macOS, **VT.app** — a
menu-bar app bundling the same `vt` CLI plus native VT-branded notifications
(including cache-hit transparency), live grant status with one-click
revoke-all, and agent supervision.

Or build from source (recipes live in the `justfile`, run `just` to list them):

```bash
# CLI only: builds (musl-static on Linux, native on macOS) and installs to ~/.local/bin
just install

# macOS menu-bar app: assembles VT.app, installs to /Applications, symlinks ~/.local/bin/vt
just install-app
```

Installing the **downloaded** VT.app tarball (vs `just install-app`):

```bash
tar xzf VT-app-darwin-arm64-*.tar.gz            # CLI extract avoids Gatekeeper quarantine
mv VT.app /Applications/
ln -sf /Applications/VT.app/Contents/MacOS/vt ~/.local/bin/vt   # put the CLI on PATH
# If Gatekeeper still blocks it (e.g. extracted via Finder):
#   xattr -dr com.apple.quarantine /Applications/VT.app
```

The release build is **ad-hoc signed**, so each release re-triggers the
one-time Keychain authorization prompt on first launch. See
[docs/app-bundle.md](docs/app-bundle.md) — including the one-time
`vt secret rebind` migration if your keychain store was created by a `vt`
binary at another path.

## Quick Start

> **Platform note.** Vault bootstrap and key storage (`init`, `secret *`,
> `fido2 *`, `ssh agent`/`add`/`list`/`remove`/`comment`/`show`) are
> macOS-only — they use the Keychain + Touch ID. A Linux host has no local
> vault: it decrypts by pointing `VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN` at the
> Cloudflare Worker and approving each ceremony on a phone (see the passkey
> deployment docs). Steps 1–2 below assume macOS.

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
   # Create an encrypted secret (prompts for type, then the value without echo)
   vt create

   # Non-interactive (no terminal): stdin is the plaintext, type from --type
   printf %s "$SECRET" | vt create --type raw

   # Paste a URL printed by `vt create` to decrypt it.
   vt read 'vt://0<your-record>'
   ```

### Linux / headless quick start

There is no local Keychain on Linux. Configure the Worker transport, then use
the same `create`, `read`, and `inject` commands; the approval URL is opened on
the phone.

```bash
export VT_PASSKEY_URL=https://vt.example.com
export VT_PASSKEY_TOKEN=<the-worker-VT_AUTH_CF-value>
# Paste a URL produced by `vt create`.
vt read 'vt://0<your-record>'
```

For a persistent setup, put these values in `~/.config/vt/config.toml` using
[`config.example.toml`](config.example.toml). Keep that file private.

## Commands

| Command | Description |
|---------|-------------|
| `version` | Show version information |
| `init` | (macOS) Initialize passcode and passphrase in keychain |
| `doctor` | Diagnose config sources (env vs config.toml), transport routing, worker reachability, and — via the read-only `diag@vt` extension — how a reachable vt agent classifies this connection for caching and why |
| `create [--type raw\|totp]` | Output an encrypted vt protocol record. On a terminal: prompts for the type, then reads the value without echo. With stdin piped it is fully non-interactive — stdin is the plaintext (one trailing newline stripped), type from `--type` (default `raw`). The plaintext is never a command-line argument |
| `read <vt>` | Decrypt a vt protocol string |
| `rewrap [--no-dry-run] [--backup] <file>...` | Re-encrypt legacy `vt://mac/...` URLs in files to the current envelope format (one agent/phone approval per batch) |
| `inject [-r FILE] -- cmd...` | Transiently decrypt `vt://` in the file / env / argv, then exec the command |
| `inject --recover` | Restore ciphertext for any file left decrypted by a crashed/rebooted supervisor (run at login/boot; no auth) |
| `auth [--reason <text>]` | Trigger bio auth via SSH agent forwarding (for PAM/sudo) |
| `run -- argv...` | (SSH-agent path) Ask a forwarded macOS agent to launch an allowlisted program locally after Touch ID |
| `hook {claude,check,exec,install-shims}` | AI-agent command hook: decide/rewrite a proposed command per `~/.config/vt/agent.toml` so `vt://` env secrets decrypt on demand (see below) |
| `fido2 {register,list,remove,remove-all}` | (macOS) Manage FIDO2/YubiKey credentials used as a Touch-ID fallback factor |
| `secret export` | (macOS) Export the encrypted master secret |
| `secret import` | (macOS) Import an encrypted master secret |
| `secret rotate-passcode` | (macOS) Rotate the passcode for the master secret |
| `ssh agent` | (macOS) Start the SSH agent (supports sign/decrypt auth caches, audit push, and `run@vt` allowlisting) |
| `ssh add [-f <file>] [-c <comment>]` | (macOS) Add an SSH private key (from file or stdin) |
| `ssh list` | (macOS) List stored SSH keys (shows fingerprint, algorithm, comment, and public key) |
| `ssh comment <fingerprint> -c <comment>` | (macOS) Change the comment of a stored key |
| `ssh remove <fingerprint>` | (macOS) Remove an SSH key by fingerprint |
| `ssh remove-all` | (macOS) Remove all stored SSH keys |
| `ssh show <fingerprint>` | (macOS) Show the public key for a stored key |
| `ssh keygen [-l <label>] [-c <comment>] [--key-file <path>]` | Generate a portable Ed25519 identity stored as a `vt://` record; prints the OpenSSH public key (cross-platform) |
| `ssh connect [--forward-real-agent] [ssh args...]` | Git SSH driver — `GIT_SSH_COMMAND="vt ssh connect"`; signs with a portable `vt://` identity or a discovered VT-agent key. The flag must precede SSH args. |

`rewrap` preserves the target's POSIX permission bits. Temporary files and optional
backups are created privately and exclusively; existing `.vt-rewrap-tmp` or
`.vt-rewrap-backup` paths are refused rather than overwritten. Inspect any leftover
sidecars before removing them and retrying. Ownership, ACLs, and extended attributes
are not copied when the target inode is replaced.

### Inject Command

`inject` temporarily decrypts a config file (and/or env vars and argv) so a
child process can read plaintext, then atomically restores the ciphertext
backup after `--timeout` seconds.

```bash
# Run a service against an in-place-decrypted config; restored to ciphertext
# ~2s after exec, regardless of when the child finishes.
vt inject -r config.yaml -- ./run.sh

# Need the plaintext elsewhere? Compose with standard Unix tools; the command
# must read the file before the same timeout window closes:
vt inject -r config.yaml -- cat config.yaml        # decrypt → stdout
vt inject -r config.yaml -- cp config.yaml /tmp/c  # decrypt → another path
vt inject -r config.yaml -- jq .api_key config.yaml

# No file: only substitute vt:// in env vars and argv, then exec.
vt inject -- ./run.sh
```

Options:
- `-r, --replace-file <FILE>`: Decrypt vt:// in the file in place; restore from backup after timeout
- `-t, --timeout <SECONDS>`: Seconds before the backup is rolled back over the decrypted original (default: 2)
- `--recover`: Sweep `~/.local/state/vt/inject/` and restore any file a crashed
  or rebooted restore supervisor left decrypted. Needs no auth (it only moves
  the ciphertext backup back). Safe to run from a login/boot hook.

Overlap protection: only one exposure window per file may be open at a time.
A second `inject -r` of the same file is refused while the first window is
open — retry after it closes (the error says how long). If a previous run's
restore supervisor died (crash/reboot), the refusal points at
`vt inject --recover`. A file containing no `vt://` records is also refused:
there is nothing to decrypt, which usually means the wrong file — or plaintext
left behind by a broken exposure.

Injection aborts the entire batch if any record fails to decrypt: no environment
values or files are changed and the command is not started. Repeated records are
decrypted once, and a decrypted value containing `vt://` text is inserted literally.

The temporary publication file is reserved empty before the supervisor starts;
restoration cancels its name before consuming the ciphertext backup. A delayed
parent cannot recreate that file after restoration. The recovery deadline is
recorded before supervisor startup, so `--recover` can also cancel a stalled
startup after the deadline and grace period; that parent's publication then fails.
The normal restore timer starts in the supervisor. Cancellation or restore errors
preserve the backup and any existing recovery record for a later retry.

### SSH Agent

VT can act as an SSH agent, storing private keys in VT's encrypted
macOS Keychain-backed store
and requiring Touch ID by default for every signing operation. Opt-in auth
caching can reduce repeated prompts; see [Auth Caching](#auth-caching).

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

# Start with approval reuse (skip repeated Touch ID within a time window;
# grants are activity-scoped — see "Auth Caching" below):
eval $(vt ssh agent --ssh-auth-cache-duration 28800 --decrypt-auth-cache-duration 3600)

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

By default (`--ssh-auth-cache-duration 0`), Touch ID is required for every
sign/decrypt request. Setting a duration enables **activity-scoped** approval
reuse — the Touch ID prompt always states exactly what is being granted and
for how long:

| Caller | Grant scope |
|--------|-------------|
| `ssh` / `git fetch` / `git push` (OpenSSH ≥ 8.9) | The **destination server** (verified via `session-bind@openssh.com`): one approval covers repeated one-shot connections to the same host with the same key, from any local caller |
| `ssh-keygen -Y sign` (git commit signing), local `vt ssh connect` | The caller's **git workspace** (kernel-derived `.git` root): one approval covers the project, including multi-host fan-outs and TTY-less AI agents / CI working in the same checkout |
| Local caller outside any git repository | The caller's **exact working directory** (kernel-derived, a separate grant family from git workspaces) |
| Local caller from a broad shared directory (`$HOME`, `/`, temp roots) | The **calling application** (kernel-derived parent process): repeated requests from the same app instance — e.g. a daemon probing `gh` through the hook — share one approval; grants die when the app exits |
| Forwarded / relay traffic (`ssh -A`, `--forward-real-agent`) | vt extensions (`decrypt@vt`, `sign@vt`) are confined **per connection**: a remote host can reuse only its own approvals and never rides local grants. Raw SSH signs arriving through a forwarding-capable connection are never cached at all |
| OpenSSH < 8.9, `auth@vt`, `run@vt`, legacy URLs | Never cached — always prompts |

`--ssh-auth-cache-duration <SECS>` and `--decrypt-auth-cache-duration <SECS>`
are separate knobs (a cached decrypt grant releases per-record DEK material,
so you may want it shorter or disabled). TTLs are strict (no sliding
refresh), and every grant is revoked immediately when the agent locks, the
screen locks, the Mac sleeps/wakes, or the idle timeout fires — the duration
is effectively "within this presence session, at most N hours", so generous
values (8h sign / 1h decrypt) are reasonable.

For **unattended periodic jobs** (editor auto-fetch, cron), caching is the
wrong tool — any TTL eventually prompts while you are away. Give fetch a
read-only credential instead (a GitHub read-only deploy key via a `Host`
alias with `IdentitiesOnly yes`, or HTTPS with a `contents:read` token), or
keep an ssh `ControlMaster`/`ControlPersist` window longer than the fetch
interval so the connection never re-authenticates.

### Portable SSH identity for git (`vt://`)

Unlike `vt ssh add` (which stores keys in VT's encrypted macOS Keychain-backed
store, macOS-only), `vt ssh keygen`
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

Prefer the default key file. `VT_GIT_SSH_PRIVATE_KEY` is useful for CI or
wrappers, but generic `vt inject -- …` scans `vt://` values in inherited
environment variables; do not let that variable reach an unrestricted inject
command.

How it works: `vt ssh connect` is a `GIT_SSH_COMMAND` driver. It starts an ephemeral in-process
SSH agent (answering identity requests from the cleartext public key, no prompt), execs the system
`ssh` (which keeps doing transport + `known_hosts`), and on each signature decrypts the seed on
demand via the normal `vt://` decrypt path — SSH agent (`$SSH_AUTH_SOCK`, incl. a forwarded laptop
agent) first, CF passkey ceremony as fallback. The remote host needs `VT_AUTH` set to use a forwarded
agent; otherwise it goes straight to the phone passkey. See `docs/ssh-vt-design.md` for the full design.

### sudo via Touch ID or phone passkey

Use `vt auth` as a `sudo` authentication factor: a forwarded Mac agent gives a
Touch ID approval, while a headless host uses the phone Passkey path. An
unavailable or rejected VT approval falls through to the normal password stack.

Use [`docs/sudo.md`](docs/sudo.md) for the supported `setup-pam.sh` workflow,
verification, removal, and the Worker-token security boundary.

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
| `VT_AUTH` | SSH-agent authentication token (from `vt init`) | unset |
| `VT_PASSKEY_URL` | Cloudflare Worker base URL for phone approval | unset |
| `VT_PASSKEY_TOKEN` | HMAC token matching the Worker `VT_AUTH_CF` secret | unset |
| `VT_BACKEND` | `auto`, `agent`, or `passkey` transport selection | `auto` |
| `VT_CONFIG` | Override the config-file path | `~/.config/vt/config.toml` |
| `VT_AGENT_CONFIG` | Override the AI-agent hook config path | `~/.config/vt/agent.toml` |
| `VT_GIT_SSH_PRIVATE_KEY` / `VT_GIT_SSH_PUB` | Optional portable SSH identity inputs | unset |
| `VT_HOOK_BIN` | Override the binary used by hook rewrites | current `vt` binary |
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

All keychain access (passcode, passphrase, SSH keys, FIDO2) routes through a single `rusty.vault.store` item — see [Secret Management](#secret-management) for the layout.

### Client / Server Split

The `vt` source tree is split into a cross-platform client (`create`/`read`/`inject`/`auth`) and a macOS-only server (`init`/`secret`/`ssh`/`fido2`, including the SSH agent itself). Both ship in the same binary; on Linux the macOS server is `cfg`-gated out, so the Linux build only contains the client commands.

## Passkey Approval (Cloudflare Worker)

For hosts without the local macOS agent/Keychain store (Linux servers, CI,
headless boxes), `vt`
decrypts `vt://` records through a phone WebAuthn ceremony served by the
Cloudflare Worker in `cf-worker/`. The CLI reaches it via `VT_PASSKEY_URL` +
`VT_PASSKEY_TOKEN`.

See [docs/cf-worker-deploy.md](docs/cf-worker-deploy.md) for the full deployment
guide (Wrangler config, Cloudflare Access gate, secrets, first-Passkey
bootstrap, and CLI wiring). See [docs/README.md](docs/README.md) for cache,
hook, SSH, error-protocol, audit, and notification documentation.

## License

MIT
