# Deploying the Cloudflare Worker (`cf-worker/`)

The `cf-worker/` directory is the **passkey approval service**: a TypeScript
Cloudflare Worker (Hono + a `AccountDO` Durable Object) plus a PWA. It runs the
phone WebAuthn ceremony that lets any host — Linux servers, CI, headless boxes —
decrypt `vt://` records without a local macOS keychain. The CLI talks to it via
`VT_PASSKEY_URL` + `VT_PASSKEY_TOKEN`.

```
CLI  ──POST /api/challenge (HMAC)──▶  Worker ──▶ AccountDO (root key, config, hibernating WS, SQLite audit)
CLI  ──WS /api/dek?poll_token──────▶  Worker
phone (PWA) ── approve: WebAuthn + PRF ─▶ derives DEKs, seals to CLI pubkey ─▶ WS delivers
```

- Ceremony endpoints live at the root (`/api/challenge`, `/api/dek`,
  `/api/approve`, `/api/reject`, `/a/:token`), secured by a body HMAC keyed on
  the caller's per-host token + unguessable tokens + WebAuthn. The token secret
  derives from the Durable Object's root key, so the edge checks header shape
  and body caps and the DO compares the MAC ([host-token.md](host-token.md)).
  `/api/enroll` is the unauthenticated, rate-limited request for such a token.
- The admin surface — one shell at `/admin` (tabs in the URL hash: `#audit`
  `#cache` `#tokens` `#setup` `#settings`) and its API under `/api/admin/*` — is
  a **passkey login**: the same passkeys that approve ceremonies sign in, the
  session is an 8-hour `__Host-vt_admin` cookie verified inside the Durable
  Object ([worker-slim.md](worker-slim.md) §3). No Cloudflare Access application.
  The shell's assets under `/pwa/admin/*` are public and hold no data.
- One Wrangler secret, **`SECRET`**, and no `[vars]`: everything the operator
  can set lives encrypted in the Durable Object and is edited on the 设置 tab
  ([worker-slim.md](worker-slim.md) §2, §4).

Request bodies for `/api/challenge`, `/api/dek-cache`, `/api/approve`, and
`/api/reject` are limited to 256 KiB; `/api/audit-ingest` retains its 64 KiB
limit. The Worker bounds streamed reads before JSON parsing, including requests
with absent or understated `Content-Length`, and returns HTTP 413 for oversized
bodies. HMAC verification uses the original bytes, without JSON reserialization.

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

The real `wrangler.toml` is gitignored (it carries your account id). Copy the
example and fill in your own values:

```bash
cp wrangler.toml.example wrangler.toml
```

Edit `account_id` (Cloudflare Dashboard → Workers → Account details) and the
`[[routes]]` pattern (your hostname). Nothing else is per-deployment:

- `workers_dev = false` and `preview_urls = false` — the Worker is served **only**
  from your custom domain, never `*.workers.dev`.
- `[assets]` binds the `pwa/` directory as `ASSETS` with `run_worker_first = true`
  so every request hits the Worker.
- `[[durable_objects.bindings]]` + `[[migrations]]` declare the `AccountDO`
  SQLite class — leave these as-is.
- `[[unsafe.bindings]] LIMITER` is the 3/min/IP rate limit on the three
  unauthenticated POSTs (`/api/enroll`, admin bootstrap, login-challenge).
  Without it those routes answer 503 rather than run unthrottled.
- `[observability]` persists structured audit events (challenge.created /
  approved / rejected / expired / error) to Workers Logs.

There is **no `[vars]` block**. The WebAuthn origin is captured at bootstrap
(step 5); caching, cache-hit pushes and the approval UV policy are set on the
设置 tab (step 6).

## 3. Set the secret

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | wrangler secret put SECRET
```

`SECRET` is a key-encryption key over the Durable Object's root key `R`
([worker-slim.md](worker-slim.md) §2). Host tokens, admin sessions, the config
blob and the DEK-cache key all derive from `R`, so `SECRET` alone opens
nothing and DO storage alone opens nothing. It is never sent to a host, a
browser, or a log; never hand it to anyone.

## 4. Deploy

```bash
just deploy-worker   # runs `wrangler deploy` in cf-worker/ (works from any dir in the repo)
```

Then point the custom domain at the Worker: in the Workers dashboard add a
**Custom Domain** (or Route) for `vt.example.com`. Because `workers_dev = false`,
this is the only way to reach it.

Until step 5 the Worker is **unconfigured**: every ceremony and admin data
route answers `503 not_configured`, `/admin` shows the setup view, and only the
public PWA assets and `POST /api/admin/bootstrap` (rate limited per IP) answer.
Bootstrap right after deploying: a new hostname is public within minutes via
certificate transparency, and whoever registers first owns the console until
you reset it (below).

## 5. Bootstrap: register the first Passkey

Open `https://vt.example.com/admin` — from the canonical hostname, since the
request origin becomes the WebAuthn origin for good — and you get the setup view:

1. On your Mac: `vt secret export` (Touch ID), set a one-time export passphrase,
   copy the base64.
2. On the setup view (ideally in the Mac's own browser): paste the base64 +
   passphrase, give the passkey a label, press **注册并登录**. The page decrypts
   the master locally, registers the passkey (phone), wraps the master under its
   PRF and posts only the credential entry. The Worker generates `R`, stores
   the encrypted configuration in the Durable Object and signs you in.
3. On the Passkey tab run **自检 / self-check** once.

If the view answers **已被初始化** with a time and IP that are not yours,
someone bootstrapped first: factory-reset (below) and redo. Further passkeys
are added and revoked on the Passkey tab; no secret changes hands. Revoking one
ends every admin session (yours included); the last passkey cannot be revoked.

## 6. Settings (设置 tab)

Saved into the encrypted config blob; effective immediately.

- There is no cache switch: the approval page always offers a cache TTL with
  `不缓存` as the default, and the DEK 缓存 tab offers extension (each still
  needs a passkey approval). The cache key is derived from `R`, so nothing
  rotates it but a factory reset. See [dek-cache.md](dek-cache.md).
- **缓存命中时推送通知** — off by default; every no-tap decrypt pushes a notice.
- **UV 策略** — WebAuthn user-verification level for **approval** ceremonies
  (registration and admin login always require verification):

  ```json
  {"default":"discouraged","by_op":{"decrypt":"required"},"by_host":{"prod-db":"required"}}
  ```

  Empty → `discouraged`: approving is one click in the platform/1Password
  prompt, with no second biometric step; user presence is still mandatory and
  checked server-side, and the approve URL is an unguessable 96-bit token that
  lives five minutes. Levels: `discouraged` | `preferred` | `required`. `by_op`
  keys are op kinds (`decrypt`, `encrypt`, `auth`, …); `by_host` keys are the
  token's verified hostname. Every rule and the client's `vt --uv` request can
  only **raise** the level; the level is read back from the stored challenge at
  verification time. A malformed value is refused at save (`400`), never
  stored. The `cache-extend` ceremony is pinned to `required`.

  > **Security-key caveat.** A CTAP2 security key (YubiKey) derives PRF from a
  > *different* secret when it completes without user verification, so a
  > credential enrolled under `required` cannot unwrap its master from a
  > `discouraged` ceremony — the approval fails, nothing leaks. Deployments
  > approving with a security key should set `{"default":"required"}`.
- **推送** — Web Push to this device: on iOS 16.4+ add the site to the home
  screen first, open it from the icon, sign in, tap 开启推送. No third party
  and no secret; the VAPID key pair lives in the config blob.
- **轮换 SECRET** — see below. **退出所有会话** ends every admin session.

## 7. Wire up the CLI

On every host that uses the phone-approval ceremony:

```bash
vt enroll --url https://vt.example.com
```

It prints an approve URL and a pairing code; approve on the phone once the page
shows the same code. The host's own `VT_PASSKEY_TOKEN` (valid 7 days, refreshed
on every use) and `VT_PASSKEY_URL` are written to `~/.config/vt/config.toml`.
Tokens are listed and revoked on the admin **主机令牌** tab. `VT_PASSKEY_TOKEN`
must be a `vt1.` host token — the CLI and the Worker both refuse anything else.
Details: [host-token.md](host-token.md).

Optional: `VT_PASSKEY_UV` (or the global `vt --uv <level>` flag) asks a single
host or command for a stricter approval than the Worker's policy requires —
raise-only, so it can add the biometric step but never remove one.

Macs running the agent with audit push use the same token:
`vt ssh agent --audit-key vt1.…` ([agent-audit.md](agent-audit.md)).

Test:

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

The DO alarm pages `ch:` records (1,000 per `list()`, ending only on an empty
page), expires pending challenges after 5 minutes via a fresh re-read so a
concurrent approval is never overwritten, and deletes finalized records plus
their `pt:` keys after 10 minutes in batches of at most 128. A failed sweep is
logged and still rearms the alarm; read-time checks remain the authoritative
expiry guard.

- Workers Logs (dashboard) show the structured audit events; retention is
  platform-managed (~3 days Free, ~7 days Paid). `config.unreadable` there
  means the root key does not unwrap under the current `SECRET` (see reset).
- The admin **审计** tab (`/admin#audit`) shows the SQLite audit table with the
  cache TTL/expiry columns; a cache-armed row links to the DEK 缓存 tab.
- The admin **DEK 缓存** tab (`/admin#cache`) is the inventory of live entries,
  one per record under 主机 · 项目 headers, with 撤销 of the selection and
  清除全部. Extending is gated on both the admin session and a fresh phone
  Passkey approval, one project per ceremony — see
  [`docs/dek-cache.md`](dek-cache.md).

## Updates, rotation, reset

- **Redeploy code/PWA:** `just deploy-worker`.
- **After editing anything in `cf-worker/pwa/`:** `just bump-assets` stamps
  `<YYYYMMDD>-<git short hash>` into `ASSET_VER` (cache-busts the `?v=` asset
  URLs), then redeploy.
- **Cut one host off:** revoke its token on the 主机令牌 tab (immediate; the
  host re-runs `vt enroll` to come back).
- **Rotate `SECRET` (keeps everything):** 设置 → 轮换 SECRET. The Worker
  generates a new value, wraps `R` under it beside the current wrap, and shows
  the value **once**. Run `wrangler secret put SECRET` with it. Both values
  open `R` until the Worker first loads under the new one, which deletes the
  old wrap; nothing is retyped into the browser. Host tokens, passkeys, config,
  subscriptions and cache entries all survive. Rotating twice before deploying
  replaces the pending wrap — there are never more than two.
- **Factory reset** — `R` compromised (DO storage read), or `SECRET` lost
  before a rotation was deployed: `wrangler secret put SECRET` with a **fresh**
  value *without* rotating first. The stored root no longer unwraps
  (`config.unreadable` once in the logs), the Worker is unconfigured, and
  `/admin` shows the setup view flagged as a reset; bootstrap again (step 5).
  A new `R` means: every host runs `vt enroll` again, phones re-subscribe on
  the 设置 tab, cache entries become misses and lapse, settings are re-entered.
  The audit table and the `host_token` rows are plaintext SQLite and survive;
  revoke stale token rows by hand.
- **Invalidate all cached DEKs:** the admin clear-cache button (or a reset).
- **Revoke a Passkey:** Passkey tab → 吊销 (bumps the session epoch: every
  admin session ends). **End all sessions:** 设置 → 退出所有会话.
- **Upgrading from the `VT_AUTH_CF` / Access build:** delete the Access
  application; drop every `[vars]` line; rename the limiter binding to
  `LIMITER`; `wrangler secret put SECRET` (any fresh value — host tokens no
  longer derive from it); `wrangler secret delete VT_AUTH_CF CREDENTIALS_JSON
  CACHE_SECKEY`; deploy; bootstrap on `/admin` (step 5); then, **once**, on
  every host `vt enroll` and on every audit-pushing Mac switch `--audit-key`
  to that token — the old tokens were derived from `VT_AUTH_CF` and fail with
  `hmac mismatch`. Re-enter caching / hit-notify / UV on the 设置 tab and
  re-subscribe phones.

See also: [the documentation map](README.md),
[`docs/dek-cache.md`](dek-cache.md) (DEK cache design + threat model), and
[`docs/agent-audit.md`](agent-audit.md) (audit push).
