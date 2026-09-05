# Deploying the Cloudflare Worker (`cf-worker/`)

The `cf-worker/` directory is the **passkey approval service**: a TypeScript
Cloudflare Worker (Hono + a `AccountDO` Durable Object) plus a PWA. It runs the
phone WebAuthn ceremony that lets any host — Linux servers, CI, headless boxes —
decrypt `vt://` records without a local macOS keychain. The CLI talks to it via
`VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN`.

```
CLI  ──POST /api/challenge (HMAC)──▶  Worker ──▶ AccountDO (hibernating WS + SQLite audit)
CLI  ──WS /api/dek?poll_token──────▶  Worker
phone (PWA) ── approve: WebAuthn + PRF ─▶ derives DEKs, seals to CLI pubkey ─▶ WS delivers
```

- Ceremony endpoints live at the root (`/api/challenge`, `/api/dek`, `/api/approve`, `/api/reject`, `/a/:token`), secured by `HMAC(VT_AUTH_CF)` + unguessable tokens + WebAuthn.
- The admin surface (`/<ADMIN_SEG>/…`, currently `ADMIN_SEG = "kestrel"` in `cf-worker/src/index.ts`) is gated by **Cloudflare Access** at the edge plus `cf-worker/src/access.ts` JWT verification.

Request bodies for `/api/challenge`, `/api/dek-cache`, `/api/approve`, and
`/api/reject` are limited to 256 KiB; `/api/audit-ingest` retains its 64 KiB
limit. The Worker bounds streamed reads before HMAC verification or JSON parsing,
including requests with absent or understated `Content-Length`, and returns
HTTP 413 for oversized bodies. HMAC verification uses the original bytes, without
JSON reserialization.

---

## Prerequisites

- A Cloudflare account. SQLite-backed Durable Objects are available on the
  Workers Free plan; the Paid plan is useful for higher quotas and longer
  Workers Logs retention. See [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
  and [Workers Logs pricing](https://developers.cloudflare.com/workers/observability/logs/workers-logs/).
- A domain on Cloudflare you can point at the Worker (e.g. `vt.example.com`).
- Node.js 18+ and the repo checked out. Wrangler is pinned in `cf-worker/package.json`.
- A phone with a Passkey authenticator that supports the **PRF** extension
  (iOS 17+/modern Android + password manager).

---

## 1. Install dependencies

```bash
cd cf-worker
npm ci
npm run typecheck
```

`pwa/libsodium.js` is vendored/committed (ISC) — no build step fetches it. If it
is ever missing, refresh it per `pwa/libsodium.README`.

## 2. Configure `wrangler.toml`

The real `wrangler.toml` is gitignored (it carries account/Access ids). Copy the
example and fill in your own values:

```bash
cp wrangler.toml.example wrangler.toml
```

Edit these fields:

| Field | Value |
|---|---|
| `account_id` | Cloudflare Dashboard → Workers → Account details |
| `[vars] WORKER_ORIGIN` | Public HTTPS origin, e.g. `https://vt.example.com` |
| `[vars] RP_ID` | WebAuthn RP id = the bare host, e.g. `vt.example.com` |
| `[vars] ACCESS_TEAM_DOMAIN` | `<team>.cloudflareaccess.com` (filled in step 3) |
| `[vars] ACCESS_AUD` | Access Application AUD tag (filled in step 3) |

Notes already baked into the example:
- `workers_dev = false` and `preview_urls = false` — the Worker is served **only**
  from your custom domain, never `*.workers.dev`.
- `[assets]` binds the `pwa/` directory as `ASSETS` with `run_worker_first = true`
  so every request hits the Worker (admin assets stay behind Access).
- `[[durable_objects.bindings]]` + `[[migrations]]` declare the `AccountDO`
  SQLite class — leave these as-is.
- `[observability]` persists structured audit events (challenge.created /
  approved / rejected / expired / error) to Workers Logs.

## 3. Create the Cloudflare Access application (admin gate)

The admin surface must be gated **before** it is exposed. In Zero Trust →
Access → Applications, create a **self-hosted** application:

- **Path** = the admin segment, e.g. `vt.example.com/kestrel` (must equal
  `ADMIN_SEG`).
- Add a policy that allows only you (email / IdP group).
- After creating it, copy the **Application AUD** tag and your team domain
  (`<team>.cloudflareaccess.com`) into `wrangler.toml`
  (`ACCESS_AUD`, `ACCESS_TEAM_DOMAIN`).

> If either value is empty the Worker **fails closed** (403) on every
> admin-surface request.

## 4. Set secrets (`wrangler secret put`)

Secrets are never inlined in `wrangler.toml`. Set them per environment:

```bash
# Required — 32-byte base64url token; CLI↔Worker HMAC on /api/challenge.
# This value = the CLI's VT_PASSKEY_TOKEN.
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | wrangler secret put VT_AUTH_CF

# Required — passkey credentials blob. Produced by the admin setup page in
# step 6; on first deploy you may seed an empty set: {"v":1,"epoch":0,"c":[]}
wrangler secret put CREDENTIALS_JSON

# Optional — enables the opt-in DEK cache (approve-time TTL → approval-free
# decrypt within same IP+pwd). Empty/absent → caching disabled. Rotate to
# instantly invalidate all cached DEKs. See docs/dek-cache.md.
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | wrangler secret put CACHE_SECKEY

# Optional notification channels (independent, opt-in):
wrangler secret put PUSHOVER_JSON   # {"app_token":"…","user_key":"…"}
wrangler secret put SLACK_JSON      # {"webhook_url":"https://hooks.slack.com/services/…"} (one-way webhook)
wrangler secret put SLACK_APP_JSON  # {"bot_token":"xoxb-…","channel":"C…","mention"?:["U…"]}: @mention + editable msg — see docs/slack-app.md
wrangler secret put FEISHU_JSON     # 飞书/Lark bot: @mention + editable card — see docs/feishu.md
```

## 5. Deploy

```bash
just deploy-worker   # runs `wrangler deploy` in cf-worker/ (works from any dir in the repo)
```

Then point the custom domain at the Worker: in the Workers dashboard add a
**Custom Domain** (or Route) for `vt.example.com`. Because `workers_dev = false`,
this is the only way to reach it.

## 6. Enroll the first Passkey (bootstrap)

`CREDENTIALS_JSON` holds PRF-wrapped master material. Generate it on the
Access-gated setup page `https://vt.example.com/kestrel/setup`:

1. On your Mac: `vt secret export` (Touch ID), set a one-time export passphrase,
   copy the base64.
2. On the setup page (ideally in the Mac's own browser): paste the base64 +
   passphrase, register the Passkey (phone), and let the page wrap the master
   under the Passkey's PRF. Run **自检 / self-check** to verify.
3. Copy the resulting blob out and deploy it:
   ```bash
   wrangler secret put CREDENTIALS_JSON   # paste the blob
   ```

`add` / `revoke` of further Passkeys need no macOS interaction — the Worker
injects the current `CREDENTIALS_JSON` into the page; still copy the result out
and re-run `wrangler secret put CREDENTIALS_JSON`. The bootstrap and update
flow is intentionally kept in this deployment guide so it is usable without
reading repository-specific agent instructions.

## 7. Wire up the CLI

On every host that uses the phone-approval ceremony:

```bash
export VT_PASSKEY_URL="https://vt.example.com"
export VT_PASSKEY_TOKEN="<the VT_AUTH_CF value from step 4>"
```

`VT_PASSKEY_TOKEN` **must** equal the `VT_AUTH_CF` secret. Test:

```bash
# Paste a record previously printed by `vt create`.
vt read 'vt://0<your-record>'    # approve on your phone
```

---

## Local development

```bash
cd cf-worker
npm run dev        # wrangler dev — local Worker + DO
```

## Verify & observe

- Workers Logs (dashboard) show the structured audit events; retention is
  platform-managed (~3 days Free, ~7 days Paid).
- The admin **audit** page (`/kestrel/audit`) shows the SQLite audit table, cache
  TTL/expiry columns, and the **“清除 DEK 缓存”** (clear-cache) button.
- The admin **DEK 缓存** page (`/kestrel/cache`) is the inventory of entries that
  actually exist right now, grouped by the approval that armed them, with
  per-group and bulk clear. Extending a group's window is gated on both Access
  and a fresh phone Passkey approval, and is off unless `CACHE_ADMIN_EXTEND` is
  set — see [`docs/dek-cache.md`](dek-cache.md).

## Updates & rotation

- **Redeploy code/PWA:** `just deploy-worker`.
- **After editing anything in `cf-worker/pwa/`:** `just bump-assets` stamps
  `<YYYYMMDD>-<git short hash>` into `ASSET_VER` (cache-busts the `?v=` asset
  URLs), then redeploy.
- **Rotate the CLI token:** `wrangler secret put VT_AUTH_CF`, then update
  `VT_PASSKEY_TOKEN` on all hosts.
- **Invalidate all cached DEKs:** rotate `CACHE_SECKEY` (or use the admin
  clear-cache button).
- **Revoke a Passkey:** use the setup page (bumps `epoch`), then
  `wrangler secret put CREDENTIALS_JSON`.

See also: [the documentation map](README.md),
[`docs/dek-cache.md`](dek-cache.md) (DEK cache design + threat model), and
[`docs/agent-audit.md`](agent-audit.md) (audit push).
