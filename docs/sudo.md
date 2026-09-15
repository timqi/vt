# Linux sudo approval

vt provides an optional PAM factor: successful human approval satisfies sudo;
failure or timeout falls through to the normal password stack.

## Install

Choose a forwarded Mac agent for Touch ID or enroll this host for phone approval.
[config.example.toml](../config.example.toml) controls backend selection.
Run the installer on the Linux host:

```bash
sudo ./setup-pam.sh
```

The installer reads the invoking user's vt config and asks which binary to
install when needed. Pin either input explicitly:

```bash
sudo VT_CONFIG=/path/to/config.toml VT_BIN=/path/to/vt ./setup-pam.sh
```

It installs a root-owned binary copy and a root-only helper, then adds the PAM
factor to `/etc/pam.d/sudo`. Re-running refreshes the copy and helper without
adding another PAM entry. After upgrading vt, run the installer again.

## Verify

With the Mac agent running, forward its socket to the server:

```bash
export SSH_AUTH_SOCK=~/.ssh/vt.sock
ssh -A user@your-server
sudo whoami
```

For the phone path, run `sudo whoami` on the server and approve on the phone.
The helper waits up to 60 seconds before falling back to the password stack.
Subscribe the phone to Web Push if PAM does not reliably display the approval URL.

## Security limits

- The helper must execute a root-owned binary that the authenticating user
  cannot replace; a symlink to a user-owned CLI is not an equivalent installation.
- The root-only helper embeds its configured token; do not broaden its permissions.
- `auth@vt` is always fresh; a cache entry cannot satisfy sudo presence approval.
- Host-token theft permits approval requests and access to that token's live
  cached DEKs; it does not remove the approval requirement for sudo.
- The displayed command is advisory, not an authorization fact. It is sent to
  the phone and retained in audit; ordinary secret arguments may be exposed even
  though environment assignments are blanked.
- To omit command text, remove the `${SUDO_CMD…}` part of the generated helper's
  reason. Re-running the installer restores it.
- Only `/etc/pam.d/sudo` is configured. Debian/Ubuntu login shells may use
  `/etc/pam.d/sudo-i`; configure that stack separately if required.

## Remove

Delete the vt `pam_exec.so` entry from each PAM file you configured, then remove
`/usr/local/bin/vt-sudo-auth.sh`. Remove the `/usr/local/bin/vt` copy only when
nothing else uses it.

The installed helper and PAM line are defined by [setup-pam.sh](../setup-pam.sh).
