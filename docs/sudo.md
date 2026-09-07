# sudo / PAM approval

Use `vt auth` as an optional `sudo` factor on a Linux host. A successful VT
approval satisfies PAM; a failure or timeout falls through to the normal
password stack.

## Choose an approval path

| Path | Host setup | Approval |
|---|---|---|
| Forwarded agent | `VT_AUTH` and a forwarded `vt ssh agent` socket | Touch ID on the Mac |
| Phone Passkey | `VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN` | WebAuthn approval on the phone |

With the default `VT_BACKEND=auto`, VT tries the agent first, then the Worker
path when configured. A plain Linux server normally uses only the phone path;
a host reached with `ssh -A` can use the forwarded Mac agent. `VT_BACKEND=agent`
or `passkey` disables that fallback; see `config.example.toml`.

## Install

Run the repository's setup script as root on the target Linux host. It reads
the invoking user's `~/.config/vt/config.toml`; explicit environment values
still take precedence.

```bash
sudo ./setup-pam.sh

# Or use a particular config file / one-time override.
sudo VT_CONFIG=/path/to/config.toml ./setup-pam.sh
sudo VT_PASSKEY_TOKEN='…' ./setup-pam.sh
```

The script validates the configured path, asks which `vt` binary to use (see
below), copies it to `/usr/local/bin/vt` (root:root, 0755), writes a root-only
helper at `/usr/local/bin/vt-sudo-auth.sh` that calls that copy, and adds this
line before the existing sudo authentication stack when it is not already
present:

```
auth    sufficient    pam_exec.so seteuid quiet /usr/local/bin/vt-sudo-auth.sh
```

Re-running the script refreshes both the binary copy and the helper's embedded
values without adding a second PAM line.

### Which binary gets installed

sudo replaces `PATH` with `secure_path`, so a `vt` in `~/.local/bin` (where
`just install` puts it) is not on the script's `PATH`. The script therefore
probes `$PATH`, `~/.local/bin`, `~/bin`, the repository's `target/*/release`,
`/usr/local/bin`, and `/usr/bin`, prints each hit with its owner, mtime, and
`--version`, and — when more than one turns up — asks which to install:

```
Found vt binary/binaries:
  1) /home/you/.local/bin/vt
      owner=you  mtime=2026-01-01 12:00:00  vt v20260101-abc1234
  2) /usr/local/bin/vt
      owner=root  mtime=2025-12-01 09:00:00  vt v20251201-def5678
Install which one to /usr/local/bin/vt? [1-2, default 1]
```

The version string of a candidate is obtained as the invoking user (`runuser`)
where possible, so nothing runs as root before you have chosen it. With no
terminal available the script takes candidate 1 and says so. `VT_BIN=/path/to/vt`
in the environment pins the choice and skips the prompt entirely.

## Verify

For the forwarded-agent path, make the Mac agent available before connecting:

```bash
export SSH_AUTH_SOCK=~/.ssh/vt.sock
vt ssh agent
ssh -A user@your-server
sudo whoami
```

For the phone path, run `sudo whoami` on the server and approve the ceremony on
the phone. The helper waits up to 60 seconds, then PAM falls back to the normal
password prompt.

## Security and operational limits

- The generated helper is `root:root` and mode `0700`; it embeds the configured
  tokens. Keep it readable only by root.
- The helper must call a binary the authenticating user cannot write. PAM runs it
  as root, so pointing it at a user-owned `~/.local/bin/vt` would let any process
  running as that user replace the binary and have it executed as root. That is
  why the script installs its own root-owned copy under `/usr/local/bin` rather
  than referencing the resolved path, and why a symlink back to the user's copy
  is not a substitute. The copy is a snapshot: after upgrading `vt`, re-run
  `setup-pam.sh`. A stale copy keeps working until it no longer matches the
  Worker protocol, at which point sudo falls back to the password stack.
- `VT_PASSKEY_TOKEN` is the Worker master `VT_AUTH_CF`. Putting it on every sudo
  host increases the blast radius: theft can create approval requests and probe
  an enabled DEK cache from the same IP context, but it cannot decrypt without
  a phone approval or matching cache grant. Prefer a small set of bastion hosts
  for the Worker path.
- `pam_exec` often exposes stderr but not stdout. The Worker URL is emitted on
  stderr; configure Pushover, Slack, or Feishu if terminal feedback is not
  reliable in your PAM environment.
- `auth@vt` is never cached. An approval always requires Touch ID or a phone
  Passkey ceremony.
- Only `/etc/pam.d/sudo` is modified. `sudo -i` reads `/etc/pam.d/sudo-i` on
  Debian and Ubuntu; add the same `auth` line there if you want login shells
  covered.

To remove the integration, delete the `pam_exec.so` line from `/etc/pam.d/sudo`
and then remove `/usr/local/bin/vt-sudo-auth.sh`, plus the `/usr/local/bin/vt`
copy if nothing else on the host uses it.
