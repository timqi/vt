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

The script validates the configured path, writes a root-only helper at
`/usr/local/bin/vt-sudo-auth.sh`, and adds this line before the existing sudo
authentication stack when it is not already present:

```
auth    sufficient    pam_exec.so seteuid quiet /usr/local/bin/vt-sudo-auth.sh
```

Re-running the script refreshes the helper's embedded values without adding a
second PAM line.

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

To remove the integration, delete the `pam_exec.so` line from `/etc/pam.d/sudo`
and then remove `/usr/local/bin/vt-sudo-auth.sh`.
