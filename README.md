# vt (Vault)

vt keeps secrets encrypted and releases them through macOS Keychain / Touch ID
or phone Passkey approval. It supports raw secrets, TOTP, transient injection,
Ed25519 SSH identities, and remote sudo approval.

## Installation

Download `vt` (macOS arm64 or Linux amd64) or **VT.app** (macOS) from
[GitHub Releases](https://github.com/timqi/vt/releases). VT.app bundles the CLI
with agent supervision, grant status, revocation, and native notifications.
Put `~/.local/bin` on your `PATH`.

To install a downloaded VT.app archive:

```bash
tar xzf VT-app-darwin-arm64-*.tar.gz
mv VT.app /Applications/
mkdir -p ~/.local/bin
ln -sf /Applications/VT.app/Contents/MacOS/vt ~/.local/bin/vt
```

Or build and install from source:

```bash
just install       # CLI
just install-app   # macOS app and CLI
```

Release bundles are ad-hoc signed; upgrades may require renewed Keychain
permission. The local agent needs a Mac with a Secure Enclave and Touch ID;
an existing vault is migrated once with `vt secret rotate-passcode`. For
Gatekeeper, an existing agent installation, or the migration, follow the
[macOS installation and upgrade guide](docs/app-bundle.md).

## Upgrading to v20260922: Secure Enclave master key (wrap v3)

From release `v20260922` the local master key is sealed to a Secure Enclave
key gated by Touch ID instead of a Keychain-wrapped passcode. Every local
approval is Touch ID: there is no system-password fallback, and while Touch ID
is unavailable only phone approval works. The agent refuses an unmigrated
vault; run the one-time migration in
[app-bundle.md](docs/app-bundle.md#migrating-a-wrap-v2-store) after
installing. Macs without a Secure Enclave can use only phone approval.
`vt secret set` and `ssh-add` over the agent socket now ask for Touch ID too.

## Upgrading to v20260915: breaking change for phone approval

Release `v20260915-b2f3a0e` replaces the Worker's trust model: Passkey-only
admin instead of Cloudflare Access, per-host tokens issued by `vt enroll` instead of a shared
`VT_AUTH_CF`, and a new sealed-box format for cached keys. A Worker deployed
before `v20260915` cannot be updated in place, and a `v20260915` or later CLI
cannot talk to it.

Deploy a new Worker and re-enroll every host by following
[worker-redeploy.md](docs/worker-redeploy.md): export the vault, delete the old
Worker and its Access application, deploy, bootstrap with a Passkey, then
`vt enroll` each host and re-run `setup-pam.sh` on sudo hosts. Stored `vt://`
records are unaffected. Local Touch ID use without a Worker needs only the new
VT.app.

## Quick Start

| Approval path | Setup |
|---|---|
| Local Touch ID on macOS | [macOS quick start](#macos-quick-start) |
| Phone approval on Linux, CI, or macOS | [Phone approval](#phone-approval) |
| Remote host using a Mac agent | [SSH forwarding](docs/sign-vt-design.md#forwarded-relay) |

Local vault and stored-key management require macOS. Portable SSH identities
and the client commands work on macOS and Linux.

### macOS quick start

Initialize the vault:

```bash
vt init
```

Start the agent through VT.app, or use `vt ssh agent` for a standalone CLI
installation:

```bash
open /Applications/VT.app
```

Then [create and read a secret](#create-and-read-secrets).

### Phone approval

First [deploy and bootstrap a Worker](docs/cf-worker-deploy.md), or use an
existing one. Enroll each host:

```bash
vt enroll --url https://vt.example.com
```

Open the approval URL on your phone and compare the pairing code before
approving. Enrollment saves the host's credentials in the vt config file;
keep it private. Host revocation and token renewal are covered by the
[Worker guide](docs/cf-worker-deploy.md#enroll-hosts).

### Create and read secrets

```bash
vt create                         # choose raw or TOTP, then enter the value
vt read 'vt://0<your-record>'      # replace with the URL printed by create
```

For piped input, send plaintext through stdin rather than command arguments:

```bash
printf %s "$SECRET" | vt create --type raw
```

Treat the printed `vt://` record as opaque encrypted data. Pre-2.0 `vt://mac/`
records are refused; convert them with the previous release's
`vt rewrap --no-dry-run` before upgrading.

## Inject Command

Use `inject` to give a command decrypted environment values without storing
those values in shell configuration:

```bash
# API_TOKEN and DATABASE_URL already contain vt:// records.
vt inject --only-env API_TOKEN,DATABASE_URL -- ./run.sh
```

`--only-env` limits environment-variable decryption; other variables remain
inherited, and argument/file substitution still applies. Without it, `inject`
substitutes records in all inherited environment variables and command arguments.

For a config file containing records:

```bash
vt inject -r config.yaml -- ./run.sh
```

The file is decrypted in place, then restored after `--timeout` (default two
seconds), independently of when the command finishes. The command must read it
within that window. Restoration does not erase copies, arguments, or the child
process's environment. A decryption failure prevents the command from starting.

Overlapping file injections and files with no records are refused. After a
crash or reboot leaves a file decrypted, restore its ciphertext backup with:

```bash
vt inject --recover
```

Recovery requires no approval and can run from a login/boot hook. Failed
restoration preserves recovery state for a retry.

## Command Shims

To make a tool receive its secret without any wrapper in your muscle memory,
name the command and its variables in `~/.config/vt/agent.toml`, then install
the shims:

```bash
vt hook install-shims                 # ~/.local/share/vt/shims/{gh,glab,…}
export PATH="$HOME/.local/share/vt/shims:$PATH"
```

Each shim is a symlink to `vt`; invoked as `gh` it execs the real tool under
`vt inject --only-env`, so only that rule's variables are decrypted. A rule can
also refuse a command (`gh auth token` printing the token it was just handed).
The rules file carries no plaintext and can be synced.
[`hook.md`](docs/hook.md) owns the schema, precedence, and limits;
[`agent.example.toml`](agent.example.toml) is the template.

## SSH

With the Mac agent running, import an existing Ed25519 key and use its socket:

```bash
vt ssh add -f ~/.ssh/id_ed25519
export SSH_AUTH_SOCK=~/.ssh/vt.sock
ssh user@your-server
```

For a portable identity backed by your configured approval path:

```bash
vt ssh keygen -l github
git config core.sshCommand "vt ssh connect"
```

Register the printed public key with your server or Git provider. Agent signing
keeps the key on the Mac; portable signing can decrypt it into caller memory.
See the [SSH contract](docs/sign-vt-design.md) for identity distribution, selection,
fallback, and forwarding.

### Auth Caching

Approval reuse allows repeated operations without another prompt during the
approved window. Configure it only when that standing authority is acceptable;
lock and presence checks can end local reuse before its TTL.

[Agent authorization](docs/unified-authorization-engine.md) and
[Worker DEK caching](docs/dek-cache.md) define their separate scopes and limits.
For unattended periodic jobs, prefer a restricted credential such as a read-only
deploy key; approval caching cannot guarantee unattended access.

## Configuration and help

The [config template](config.example.toml) owns variables, defaults, and routing
precedence. Use `VT_BACKEND=agent` or `VT_BACKEND=passkey` to require one approval
path; `auto` permits fallback on eligible agent failures.

```bash
vt --help
vt inject --help
```

Use `vt <command> --help` for the full command and option reference. Shim rules
live in their own file (`VT_AGENT_CONFIG`) — see [hook.md](docs/hook.md). Linux sudo
setup and removal are in [sudo.md](docs/sudo.md); other tasks are indexed in the
[documentation map](docs/README.md).

## Diagnostics

```bash
vt doctor
```

Doctor reports configuration sources, routing, and caller-visible agent reuse.
It probes the agent and configured Worker independently of backend pins, without
authorizing work. Missing sockets, refused/unsupported diagnostics, and build
mismatches are reported separately.

Findings do not cause a nonzero exit code. HTTP reachability does not validate a
host token or prove approval works. Scope classification applies to this probe's
launcher and connection; another caller may differ. Doctor does not repair
configuration or restart agents.

## License

MIT
