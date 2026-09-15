# Worker deployment and recovery

This runbook installs and operates phone approval. Key custody and authorization
boundaries belong to [worker-slim.md](worker-slim.md).

## Prerequisites

- A Cloudflare account with SQLite-backed Durable Objects and a custom domain.
- Node.js and the Wrangler version declared in
  [package.json](../cf-worker/package.json).
- A browser/authenticator combination supporting WebAuthn PRF and WebCrypto
  X25519; X25519 alone requires Safari 17+, Chrome/Edge 133+, or Firefox 130+.
  PRF support is an additional requirement, including the chosen authenticator.
- Access to the macOS vault's encrypted master export for bootstrap.

The origin chosen for bootstrap is permanent until factory reset.

## Install dependencies

From the repository root:

```bash
cd cf-worker
npm ci --include=dev
npm run typecheck
```

## Configure Wrangler

While in `cf-worker/`:

```bash
cp wrangler.toml.example wrangler.toml
```

Set your account ID and custom-domain route in the copied file. Keep the
Durable Object, assets, and limiter bindings from the example. Missing
`LIMITER` makes enrollment, bootstrap, and login-challenge return 503.

The Worker serves only the custom domain, not a workers.dev preview. There is
no Cloudflare Access application and no `[vars]` block; settings live in the
admin console. Keep real secrets out of the file.

## Set the KEK

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | wrangler secret put SECRET
```

`SECRET` wraps the account root. Do not distribute it to enrolled hosts.
Replacing it outside the rotation procedure makes the existing root unreadable.

## Deploy

```bash
just deploy-worker
```

Configure the custom domain/route in Cloudflare if needed. Until bootstrap,
protected routes fail with `503 not_configured` and `/admin` shows setup.
Bootstrap immediately: the first successful registration owns the account.

## Bootstrap

Open `https://vt.example.com/admin` on the canonical hostname.

1. On the Mac, run `vt secret export`, choose an export passphrase, and copy
   the encrypted export.
2. Paste the export and passphrase into setup, label the Passkey, and choose
   Register and log in. The browser unwraps the master locally; the Worker
   receives only the wrapped credential material.
3. Run the Settings tab's Passkeys self-check.

If setup reports a prior registration with an unfamiliar time/IP, use the reset
procedure below. Add further Passkeys from the console. Revoking one ends every
admin session; the last credential cannot be revoked.

## Settings

- **Cache-hit notifications:** off by default; enable to notify subscribed phones
  about no-tap decrypts. The approval page separately defaults to no caching.
- **UV policy:** sets the verification floor for approval; host and CLI requests
  can only raise it. Registration, enrollment, admin login, and cache extension
  require verification. For example:

  ```json
  {"default":"discouraged","by_op":{"decrypt":"required"},"by_host":{"prod-db":"required"}}
  ```

  Allowed levels are `discouraged`, `preferred`, and `required`; host rules use
  the token record's hostname. User presence is mandatory at every level.
  With CTAP2 security keys, prefer `{"default":"required"}`: the PRF result
  can differ without verification, preventing the master from unwrapping.
- **Push subscriptions:** on iOS, add the site to the home screen, open that app,
  sign in, then enable push. Notification permission is per device.
- **End all sessions:** invalidates every admin session. Browser logout ends
  only that browser's copy.

Cache inventory, extension, and revocation are described in
[dek-cache.md](dek-cache.md).

## Enroll hosts

On each host that needs phone approval:

```bash
vt enroll --url https://vt.example.com
```

Compare the pairing code in the terminal with the phone before approving.
Enrollment writes the URL and this host's token to `~/.config/vt/config.toml`
or `VT_CONFIG`; keep the file mode 600. Challenge/cache use renews the seven-day
window; background audit does not. Revoke individual hosts on the tokens tab.

Test with a record printed by `vt create`:

```bash
vt read 'vt://0<your-record>'
```

Agent audit setup belongs to [agent-audit.md](agent-audit.md).

## Verify and observe

`vt doctor` reports routing and HTTP reachability, not token validity. Verify
an actual approval, then inspect the audit tab. The cache tab alone inventories
live cached records; an audit event does not prove a cache entry is live.

Use Workers Logs for `config.unreadable`, rejected tokens, and delivery failures.
Audit retention is bounded; an incompatible audit-schema change rebuilds the
table and loses prior rows. Audit history is not a backup.

## Updates, rotation, reset

- **Code update:** run `just deploy-worker`. After any PWA change, first run
  `just bump-assets` so browsers fetch the updated assets.
- **Rotate the KEK:** choose Rotate SECRET in Settings, confirm with a Passkey,
  then install the returned value with `wrangler secret put SECRET` within 24
  hours (after that the new value is void; rotate again). The value is shown once. Existing
  Passkeys, tokens, configuration, subscriptions, and cached entries survive.
  Do not replace it with a separately generated secret.
- **Factory reset:** set a fresh `SECRET` without console rotation, then bootstrap
  again. The new root invalidates host tokens and cached entries; re-enroll hosts,
  restore settings, and re-subscribe phones. Plaintext audit/token rows can survive;
  revoke stale token rows. This is recovery for a compromised root or lost KEK.
- **Revoke access:** revoke a host token to stop its requests, clear the cache to
  require phone approval again, or end all admin sessions to invalidate cookies.
  These actions do not erase material already released to a caller.

## Current upgrade steps

**Source:** `v20260911-a312763`, or an older deployment using Access/master-derived
host tokens and libsodium sealed boxes.

**Target:** the first release containing both the root-key configuration change
`0309690` and sealed-box-v1 CLI support `b9b1d89`; this release is not yet tagged.
Record its tag here when releasing. The steps below apply only across this
boundary, not to ordinary updates or KEK rotation.

**Removal:** delete this section in the release immediately following that target
release. Afterward, operators crossing from the old formats must first use the
target release's runbook. Do not retain these instructions as a permanent appendix.

**Sealed-box format:** install matching CLI and Worker/PWA builds in the same
window and clear all DEK cache entries on the cache tab. Old/new key-delivery
formats are not interchangeable; mismatches can fail with `sealed_box open
failed`. Persistent `vt://` records do not change. See
[sealed-box-v1.md](sealed-box-v1.md).

**Pre-Passkey-admin/Access deployment:** remove the Access application and all
`[vars]`, use the current Wrangler example's `LIMITER` binding, set a fresh
`SECRET`, and remove retired secrets:

```bash
wrangler secret delete VT_AUTH_CF
wrangler secret delete CREDENTIALS_JSON
wrangler secret delete CACHE_SECKEY
```

Deploy and bootstrap, re-enroll every host, replace each agent's audit token,
and restore settings/push subscriptions. Old master-derived tokens are refused.

## Local development

From `cf-worker/`:

```bash
npm run dev
```

Use isolated test configuration; validation recipes live in
[justfile](../justfile). Tests are not deployment.
