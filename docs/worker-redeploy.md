# Worker redeploy: upgrading across the v20260915 boundary

Operator runbook for replacing a Worker deployed before `v20260915-b2f3a0e`
(Cloudflare Access admin, master-derived host tokens, libsodium sealed boxes) with the
current Passkey-admin Worker. Everyday updates, KEK rotation, and factory reset
stay in [cf-worker-deploy.md](cf-worker-deploy.md).

**Applies to:** any Worker deployed from `v20260911-a312763` or earlier.
**Target:** `v20260915-b2f3a0e` and later, which requires the root-key
configuration `0309690` and sealed-box-v1 CLI support `b9b1d89`.
**Removal:** delete this document in the release after `v20260915-b2f3a0e`;
later operators upgrade through that release first.

The old and new formats are not interchangeable: old host tokens are refused,
old DEK-cache entries fail with `sealed_box open failed`, and the admin page no
longer accepts Cloudflare Access headers. Persistent `vt://` records do not
change. Install matching CLI and Worker builds in the same window.

## Before touching Cloudflare

On the Mac that owns the vault:

```bash
vt secret export          # choose an export passphrase; keep the output for bootstrap
git pull --ff-only
just install-app          # restarts a running VT.app and its agent
vt version                # must match the release you deploy
```

Keep the export and passphrase at hand: bootstrap is the only step that
consumes them, and the first successful registration owns the new account.

## Delete the old Worker

1. Zero Trust → Access → delete the Access application for the Worker hostname.
2. Workers & Pages → the old Worker → Settings → Delete (or
   `wrangler delete --name <old-name>`). Deleting the Worker deletes its Durable
   Object storage: Passkeys, host tokens, configuration, push subscriptions, and
   cache entries. The custom domain detaches; a stale DNS record may remain and
   is replaced by the next deploy.

Keeping the old Worker instead of deleting it is possible only by removing the
Access application, deleting `[vars]`, and running
`wrangler secret delete VT_AUTH_CF CREDENTIALS_JSON CACHE_SECKEY` before the
steps below; the result is the same fresh bootstrap.

## Deploy the new Worker

From `cf-worker/`:

```bash
cp wrangler.toml.example wrangler.toml     # fill account_id and the [[routes]] custom_domain block
npm ci --include=dev && npm run typecheck
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | wrangler secret put SECRET
cd .. && just deploy-worker
```

Declare the custom domain in `wrangler.toml`; keep the `LIMITER` binding, or
enrollment and login return 503. The first `wrangler secret put` on a fresh
name creates an empty Worker, which is expected.

Immediately open `https://<hostname>/admin` and bootstrap: paste the export and
passphrase, label the Passkey, choose Register and log in, then run the
Settings tab's Passkeys self-check. Do not leave the Worker deployed and
unbootstrapped.

## Restore operator state

In the console:

- Settings: UV policy, cache-hit notifications, then subscribe each phone to
  Web Push (iOS: add to home screen first).
- Add any further Passkeys. Adding, revoking, and rotating `SECRET` now require
  an assertion by an existing Passkey, not only a session.

On every host:

```bash
vt enroll --url https://<hostname>       # compare the pairing code on the phone
```

Replace each Mac agent's audit token as described in
[agent-audit.md](agent-audit.md#enable). Linux sudo hosts re-run
`setup-pam.sh` after enrollment so the helper embeds the new token.

## Verify

```bash
vt doctor
vt read 'vt://0<your-record>'            # one real phone approval
```

Check the audit tab for the approval, then test one session-plus-Passkey
action (add a Passkey) to confirm the assertion prompt appears. Delete any
leftover old Worker only after `<hostname>` resolves to the new one. Watch
Workers Logs for `config.unreadable` and rejected tokens during the first day.

## Forwarded Touch ID after upgrading

`vt ssh connect --forward-real-agent` relays vt extensions to the agent named
by `$SSH_AUTH_SOCK` on the Mac at connect time. If the remote `vt doctor`
reports `agent refused diag@vt`, the relay's upstream is not the vt agent or
the old agent is still running: stop it (`another vt agent owns this socket`
means the previous process still holds `~/.ssh/vt.sock.lock`), start the new
one, and reconnect.
