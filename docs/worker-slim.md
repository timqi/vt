# Worker slim — Web Push, passkey admin, config in the DO

Status: **plan**. Owns the `cf-worker/` half of the slim branch after
[refactor.md](refactor.md) steps 1–3: one Wrangler secret, one notification
channel, one admin gate, one config store. Each numbered change in §7 is one
commit; its row here is deleted when it lands and the owning feature doc is
updated in the same commit. Verify against `cf-worker/src/index.ts`,
`do_account.ts`, `types.ts` (`Env`) before implementing.

Fixed by the operator, not reopened here: Web Push replaces Pushover, Slack App
and Feishu; `SECRET` is the only Wrangler secret; Cloudflare Access and
`ADMIN_SEG` go, admin is passkey login; nothing is added that the above does
not need; `dryoc`/`libsodium.js` stay (refactor.md step 4).

## 1. Scope — what leaves

| Leaves | Files / symbols | Operator step |
| --- | --- | --- |
| Cloudflare Access | `access.ts`, `requireAccess`, `AccessVars`, `accessEmail`/`accessExp`, `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, the `?exp=` query on `/ws-admin` | delete the Access application; remove both `[vars]` |
| `ADMIN_SEG` | constant and every `/${ADMIN_SEG}` route → `/admin`, `/api/admin/*`; `PageChrome.adminSeg`; `seg` derivation in `audit.js`/`cache.js`/`tokens.js` | bookmarks change to `/admin` |
| Admin asset gate | `isAdminAssetPath`, the `/<seg>/pwa/*` mount; `pwa/admin/*` served by the public `/pwa/*` route (shells carry no data until rendered) | none; flips one AGENTS.md line (§9 Q1) |
| Per-tab admin shells | `pwa/admin/{audit,cache,tokens,setup,push}.html`, `adminTabs` | none |
| `CREDENTIALS_JSON` | `Env.CREDENTIALS_JSON`, `parseCredentials` of the `{v,c}` envelope, the setup page's textarea/copy/`wrangler secret put` loop | re-register passkeys through `/admin` (§3.4); `wrangler secret delete CREDENTIALS_JSON` |
| `CACHE_SECKEY` | `Env.CACHE_SECKEY`; the scalar is derived (§2) | `wrangler secret delete CACHE_SECKEY`; existing sealed entries become misses — 清除全部 once |
| `CACHE_ADMIN_EXTEND` | `cacheAdminExtendEnabled`, `extend_enabled` plumbing; extension is available whenever caching is | remove the `[vars]` line |
| `CACHE_HIT_NOTIFY`, `APPROVAL_UV_JSON` | `Env` fields; values move to the config blob (§4) | remove the `[vars]` lines; re-enter on the 设置 tab |
| `WORKER_ORIGIN`, `RP_ID` | `Env` fields; origin is captured at bootstrap (§3.3), RP id is its hostname | remove the `[vars]` lines |
| `VT_AUTH_CF` (name only) | renamed `SECRET`; derivation unchanged, so host tokens survive | `wrangler secret put SECRET` with the **same value**, then `wrangler secret delete VT_AUTH_CF` |
| `ENROLL_LIMITER` (name only) | renamed `LIMITER`, shared by enroll and login (§3.2) | rename the binding in `wrangler.toml` |

Stays untouched: ceremony routes and their HMAC/replay/body caps, host tokens,
DEK cache ladders and admin actions, audit table and stream, alarm sweep,
`approve.js` ceremony, `libsodium.js`.

## 2. Trust model

All derivations take `ikm = utf8(SECRET)`, HKDF-SHA256, `L = 32`.

| Key | salt | info | Protects |
| --- | --- | --- | --- |
| host token secret | `token_id` | `vt-host-token-v1` | daemon HMAC (unchanged, [host-token.md](host-token.md)) |
| `K_cfg` AES-256-GCM | empty | `vt-config-key-v1` | the config blob at rest (§4) |
| `K_sess` HMAC | empty | `vt-admin-session-v1` | admin session cookie (§3.1) |
| cache X25519 scalar | empty | `vt-cache-seckey-v1` | DEK sealed boxes; `cachePublicKey` derives the point as today |
| setup token | — | `b64u(HMAC-SHA256(utf8(SECRET), "vt-setup-token-v1"))` | first registration (§3.3); HMAC, not HKDF, because the operator computes it with one `openssl` line |

Not derived: the VAPID key pair (§5.2) — WebCrypto cannot turn a derived
scalar into its public point, so it is generated once and stored under `K_cfg`.

- `SECRET` is 32 random bytes, base64url, set once with `wrangler secret put`.
  It is never sent to a host, a browser, or a log.
- **Rotation is a factory reset.** New `SECRET` ⇒ every host token fails
  (`vt enroll` everywhere), `K_cfg` changes so `cfg:v1` is unreadable ⇒ the
  Worker is *unconfigured* (§4.3): ceremony routes answer `503 not_configured`,
  `/admin` shows the setup view, passkeys, settings and push subscriptions are
  re-entered, cached DEKs are misses. Audit rows and the `host_token` table are
  plaintext SQLite and survive; revoke stale rows by hand.
- **A stolen `SECRET` yields:** forging a live host's token (its `token_id` is
  public) — paging the phone as that host and reading its live cached DEKs for
  their TTL; forging admin sessions — every console action, including passkey
  revocation (lockout) and subscribing a phone to pushes; with a copy of DO
  storage, the config blob and VAPID private key. It does **not** yield the
  master key (PRF-wrapped), record plaintext beyond live cache entries, a
  passkey approval, or a cache extension (passkey-gated). Same envelope as
  today's `VT_AUTH_CF` + `CACHE_SECKEY` + a Cloudflare Access session, minus
  Access.
- The setup token is useless once one credential exists (§3.3 step 5).

## 3. Admin auth

Every `/admin` and `/api/admin/*` request is verified in the DO, the only place
that knows the current `epoch`. The edge adds rate limiting and body caps
(4 KiB on the three unauthenticated POSTs) and forwards `Cookie` and `Origin`.

### 3.1 Session cookie

```
__Host-vt_admin=1.<exp_s>.<epoch>.<nonce_b64u>.<mac_b64u>
mac = HMAC-SHA256(K_sess, "vt-admin-session-v1|" + exp_s + "|" + epoch + "|" + nonce)
Set-Cookie: …; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800
```

- `exp_s = now + 8 h`, absolute; no sliding. `nonce` is 16 random bytes.
- Verify: shape, constant-time MAC, `now < exp_s`, `epoch == config.epoch`.
  Any failure → `401 {error: session_invalid}`; the shell shows the login view.
- The audit-stream WebSocket reads `exp_s` from the verified cookie and closes
  itself at that time (replaces `?exp=`).
- CSRF: `SameSite=Strict`, plus every non-GET `/api/admin/*` request and the
  WebSocket upgrade require `Origin == config.origin` (403 otherwise). CSP keeps
  `form-action 'none'`.
- Logout (`POST /api/admin/logout`) clears the browser copy only; a copied
  cookie lives to `exp_s` or the next epoch bump. 退出所有会话
  (`POST /api/admin/sessions-revoke`) and every passkey revocation bump
  `epoch`, killing all sessions at once.

### 3.2 Routes

| Route | Gate | Does |
| --- | --- | --- |
| `GET /admin` | none | DO reports `setup` (unconfigured) / `login` / `console` (valid cookie); the one admin shell renders that state |
| `POST /api/admin/bootstrap` | `LIMITER login:<ip>` | §3.3 |
| `POST /api/admin/login-challenge` | `LIMITER login:<ip>` | mints `login:<id>` (32 random bytes, 120 s, ≤ 5 pending → 429); returns `{challenge_id, challenge_b64u, rp_id}`; no `allowCredentials` — registration already requires resident keys, so the authenticator discovers the credential and nothing is leaked before login |
| `POST /api/admin/login` | none (challenge is the gate) | reads **and deletes** `login:<id>` in one step; `verifyAssertion` with `expectedChallenge` = stored bytes, `rpId` = hostname of `config.origin`, `expectedOrigin` = `config.origin`, `userVerification: 'required'`, no PRF; success → `204` + cookie; unknown credential / bad assertion / expired → `401` |
| `POST /api/admin/logout`, `/sessions-revoke` | cookie | §3.1 |
| `GET /api/admin/credentials`, `POST …/credentials-add`, `POST …/credentials-revoke` | cookie | §3.4 |
| `GET/PUT /api/admin/config` | cookie | §4 |
| `GET /api/admin/push/vapid`, `POST …/push/subscribe`, `…/push/unsubscribe`, `…/push/test` | cookie | §5 |
| existing `audit`, `audit-stream`, `cache-*`, `clear-cache`, `clear-audit`, `tokens`, `tokens-revoke` | cookie | unchanged bodies; `admin_email` fields become the credential label |

- `LIMITER` is the existing 3/min/IP Workers Rate Limiting binding, keyed
  `enroll:<ip>` by `/api/enroll` and `login:<ip>` by bootstrap and
  login-challenge. Absent → `503` on those routes, never unthrottled.
- Login failures log `admin.login_failed` (throttled like `admin.auth_failed`
  today); nothing is written to the audit table for them.
- A `Cf-Access-Jwt-Assertion` header has no effect anywhere (rejected-input test).

### 3.3 Bootstrap

1. `wrangler secret put SECRET`; `just deploy-worker`. No `cfg:v1` ⇒
   unconfigured: ceremony routes and `/api/enroll` answer `503 not_configured`.
2. Operator, in the shell that holds `SECRET`:
   ```bash
   printf 'vt-setup-token-v1' | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
   ```
3. Open `https://<host>/admin` — the setup view. Fill in the setup token, a
   label, and the `vt secret export` blob + passphrase (the passkey master must
   equal the macOS `mac_key`, as today; the blob is decrypted in the browser
   only). The page registers the passkey (`residentKey: 'required'`,
   `userVerification: 'required'`, `prf`), asserts once for PRF, wraps the
   master and builds the credential entry (`setup.js` byte formats unchanged).
4. `POST /api/admin/bootstrap {setup_token, entry}`.
5. DO, one gated step: `cfg:v1` exists → `409 already_configured`; constant-time
   compare of `setup_token` → `403` (log `admin.bootstrap_refused`); else write
   `{v:1, origin: <request origin>, epoch:1, credentials:[entry], …defaults}`
   and return a session cookie. A concurrent stranger can at most receive the
   403; the not-exists check and the put share the step.
6. The console opens on the 设置 tab: enable caching, subscribe this phone.

`origin` is the request origin of the bootstrap call; it is the WebAuthn
origin, the RP id source and the approve-URL base from then on, immutable
until reset. Bootstrap from the canonical hostname.

### 3.4 Passkeys after bootstrap

- `GET /api/admin/credentials` returns entries (wrapped `k`, public `p`, ids,
  labels) — the same material the setup page is injected with today.
- Add: the page unwraps the master with an existing passkey's PRF, registers
  the new one, wraps, `POST …/credentials-add {entry}`; the DO refuses a
  duplicate `h`. No `epoch` change.
- Revoke: `POST …/credentials-revoke {h}` removes the entry and bumps `epoch`
  (all sessions end, including the revoker's). Revoking the last credential is
  refused (`409 last_credential`); reset is `SECRET` rotation.
- 自检 (per-entry PRF unwrap and compare) stays client-side, unchanged.

## 4. Config in the DO

### 4.1 Schema

```
cfg:v1  →  { n: b64u(nonce 12), c: b64u(AES-256-GCM(K_cfg, nonce, aad="vt-config-v1", plaintext) ‖ tag) }

plaintext (JSON) = {
  v: 1,
  origin: "https://vt.example.com",   // §3.3, immutable
  epoch: 1,                           // §3.1
  credentials: [ {h, i, k, p, l, t} ],// credentials.ts entry, unchanged bytes
  cache_enabled: false,               // was: CACHE_SECKEY present
  cache_hit_notify: false,            // was: CACHE_HIT_NOTIFY
  uv_policy: null,                    // was: APPROVAL_UV_JSON; same object, validated by parseUvPolicy on PUT
  vapid: null | { pub_b64u, jwk },    // §5.2; jwk is the exported P-256 private key
  push: [ {endpoint, p256dh, auth, label, created_ms} ]   // §5.1, ≤ 10
}
```

- One blob, one storage key, one writer (`account_admin.ts`). Every write
  re-encrypts the whole blob with a fresh random nonce; the DO is the sole
  writer, so random nonces are safe at this write rate.
- The DO keeps the decrypted blob in memory after first load and replaces it in
  the same synchronous step as the `put`; ceremony ops read `credentials`,
  `origin`, `uv_policy`, `cache_enabled` from that copy on every request, push
  fan-out reads `vapid`/`push`. The edge reads nothing from config.
- `uv_policy` moves from `index.ts` into `opCreate`; the raise-only rule,
  `cache-extend` pin and malformed → `required` behavior are unchanged.
- `PUT /api/admin/config` accepts only `cache_enabled`, `cache_hit_notify`,
  `uv_policy`; anything else in the body is `400`. Disabling caching does not
  delete entries; 清除全部 does.
- Deleted as knobs: `CACHE_ADMIN_EXTEND` (extension is offered iff
  `cache_enabled`; every extension still needs a passkey approval),
  `WORKER_ORIGIN`, `RP_ID`.

### 4.2 Migration

None. No importer: the operator re-enters. Host tokens and the audit table are
untouched when `SECRET` keeps the old `VT_AUTH_CF` value.

### 4.3 Unconfigured state

Absent `cfg:v1` and an undecryptable `cfg:v1` are the same state; the latter is
logged once as `config.unreadable`. In that state: `/admin` = setup view,
`/api/admin/bootstrap` open, every other `/api/*` route `503 not_configured`,
static assets served. There is no defaults fallback for a broken blob — a
`required` UV policy must not silently become `discouraged`.

## 5. Web Push

RFC 8030 delivery, RFC 8291 encryption, RFC 8292 VAPID — `crypto.subtle` only,
in `webpush.ts` (`encryptPush`, `vapidAuthorization`, `sendPush`). Reference
shape: pier's `src/web/webpush.ts`; VT ships no dependency and no Node API.

### 5.1 Subscriptions

- Created on the 设置 tab of the installed PWA by a user gesture:
  `registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey})`,
  then `POST /api/admin/push/subscribe {endpoint, p256dh, auth, label}`.
- Stored in `config.push` (§4.1), upsert by `endpoint`, newest-first cap 10
  (an expired browser subscription is replaced by a new endpoint; the oldest
  rows are the dead ones). `endpoint`, `p256dh` and `auth` together let anyone
  push readable notifications to that phone, so they live under `K_cfg`.
- `POST …/push/unsubscribe {endpoint}` deletes one; `POST …/push/test` sends a
  test payload to one endpoint and returns the push service status.

### 5.2 VAPID

- Generated once (`generateKey ECDSA P-256`, exported as JWK) on the first
  `GET /api/admin/push/vapid`, stored in `config.vapid`. Rotating it would kill
  every subscription, so nothing rotates it but `SECRET` reset.
- JWT: `{typ:"JWT", alg:"ES256"}` · `{aud: <endpoint origin>, exp: now + 12 h, sub: config.origin}`,
  signed with `crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'})` — WebCrypto
  already returns the raw `r‖s` JOSE wants, no DER step.
  `Authorization: vapid t=<jwt>, k=<pub_b64u>`.

### 5.3 Encryption

- Import `p256dh` as a raw ECDH P-256 public key (`importKey` rejects an
  off-curve point), generate an ephemeral pair, `deriveBits` the shared secret.
- `IKM = HKDF(shared, salt=auth, info="WebPush: info\0"‖ua_pub‖as_pub, 32)`;
  `salt = 16 random bytes`;
  `CEK = HKDF(IKM, salt, "Content-Encoding: aes128gcm\0", 16)`;
  `NONCE = HKDF(IKM, salt, "Content-Encoding: nonce\0", 12)`.
- Body: `salt(16) ‖ rs=4096 (u32 BE) ‖ 65 ‖ as_pub(65) ‖ AES-128-GCM(plaintext ‖ 0x02)`.
  Headers: `Content-Encoding: aes128gcm`, `Content-Type: application/octet-stream`,
  `TTL`, `Urgency`.
- The RFC 8291 §5 worked example (fixed salt and server key injected) is the
  unit test; plaintext over 3993 bytes throws before any network call.

### 5.4 Payload and events

```json
{ "v": 1, "kind": "approval" | "enroll" | "cache_hit", "title": "…", "body": "…", "url": "…", "tag": "…" }
```

| Event | title/body | url | tag | TTL / Urgency |
| --- | --- | --- | --- | --- |
| challenge created (`opCreate`) | `buildApprovalMessage` (kept in `notify.ts`) | approve URL | `a:<approve_token>` | 300 s / high |
| enrollment requested | same, `op_kind = enroll` | approve URL | `a:<approve_token>` | 300 s / high |
| Worker DEK-cache hit, agent Touch-ID-cache hit (`cache_hit_notify` on; agent 60 s throttle kept) | `buildCacheHitMessage` | `/admin#audit` | `cache:<host>` | 3600 s / normal |

- Not pushed: decisions (approved/rejected/expired — `TTL 300` lets the service
  drop an unanswered request instead), cache-extend ceremonies (console-resident,
  unchanged), audit rows (the audit tab is the ledger), login/bootstrap events.
- `body` is truncated to 1000 characters; the approve URL is never truncated.
- Fan-out runs in the DO via `waitUntil` after the ceremony write, one
  `sendPush` per subscription, 6 s timeout each; never awaited on a ceremony
  path, never a `push_warning` to the CLI.

### 5.5 Failure handling

| Push service answer | Action |
| --- | --- |
| 201 / 2xx | nothing |
| 404, 410 | delete that subscription (dead for good) |
| 413 | log `push.too_large` (payload bug) |
| 401, 403 | log `push.vapid_rejected` |
| 429, 5xx, network / timeout (`status 0`) | log `push.failed`, keep the subscription, no retry |

### 5.6 Service worker and install

- `pwa/sw.js` served at `/sw.js` (root scope): `push` → `showNotification(title, {body, tag, data:{url}})`;
  `notificationclick` → close, `clients.openWindow(url)`. No fetch handler,
  no caching.
- `pwa/manifest.webmanifest` at `/manifest.webmanifest`: `scope "/"`,
  `start_url "/admin"`, `display "standalone"`, `icons: [/pwa/icon-512.png]`.
  Linked from both shells; `admin.js` registers the service worker.
- iOS: 16.4+, Safari → 分享 → 添加到主屏幕, open from the icon, sign in,
  tap 开启推送 and grant permission. Pushes stop when the icon is removed (the
  next send answers 410 and the row is dropped). Notification taps open
  `/a/<token>` inside the standalone app; WebAuthn works there.

## 6. UI/UX

Pier's `docs/design/06-ui-ux.md` (sibling repo `pier`) ports to
`docs/design/ui-ux.md` (new; registered in `docs/README.md` by §7 step 3).

Ports verbatim: **Hierarchy** (all); **Materials** — solid for content and
modals, glass + hairline + shadow for the tab strip only, coordinated radii, no
page-specific styles; **Layout › Headings** (page head is the slim inset glass
strip; phone hides the title and wraps); **Editing and forms** minus the
message-edit bullet; **Motion** (all); **Foundations** minus the Icons bullet;
**Validation** (all).

Changes: Icons — no icon set and no build step, so status is a text label plus
a `.badge-*` class, never a glyph alone; **Conversation and activity** → "Audit
rows": status beyond color, absolute time plus relative when space allows,
nothing that happened disappears (a cleared table says so); add VT's own
rules — agent-derived truth lines precede every client-reported line
([approval-transparency.md](approval-transparency.md)), the cache scope
sentence sits directly above the duration control, the pairing code is the
largest element on an enroll approval.

Dropped: Sidebar, Drawer, Meta chips, Dock cards, Rail rows, Palette, Menus,
Session info, Two-pane views, Model picker, message editing.

Pages: two shells. `pwa/approve.html` (`/a/:token`, unchanged). `pwa/admin/admin.html`
(`/admin`) renders one of three states from `VT_DATA.state`: **setup** (§3.3),
**login** (one button), **console** with tabs 审计 · DEK 缓存 · 主机令牌 ·
Passkey · 设置 (config toggles, UV policy JSON, push subscriptions, 退出所有会话).
Fewer is not argued for: Passkey is a ceremony with its own flow, the other
four are distinct data sets already implemented as separate scripts.

## 7. Implementation order

Each step: `just check-worker`, then `just bump-assets` + `just deploy-worker`
where `pwa/` changed. Steps 1–2 (Web Push added, channels deleted) have landed;
step 3 is independent of refactor.md step 3 (cache key v5); steps 4–5 land
after it.

| # | Change | Files | Tests moving to rejected-input |
| --- | --- | --- | --- |
| 3 | **One admin shell**, assets public, ui-ux doc | `pwa/admin/admin.html` + `admin.js` replace five shells (`push.js` folds into the 设置 tab) and `adminTabs`; `isAdminAssetPath` and the `/<seg>/pwa/*` mount go; `docs/design/ui-ux.md`; `docs/README.md`; AGENTS.md asset line (Q1) | `page.test.ts` `isAdminAssetPath` cases → "public `/pwa/admin/admin.js` serves 200"; `adminTabs follows ADMIN_SEG` deleted |
| 4 | **Passkey admin auth** (after v5) | new `admin_auth.ts` (cookie mint/verify, setup token, pure); `account_admin.ts` gains `credentials`, `origin`, `epoch`, login challenges, bootstrap, add/revoke; `do_account.ts` dispatches `admin-*` ops and verifies the cookie on every admin op and `/ws-admin`; `index.ts` `/admin`, `/api/admin/*`, `LIMITER login:` keys; `access.ts`, `ADMIN_SEG`, `CREDENTIALS_JSON` deleted; `setup.js` → bootstrap/add/revoke over the API; `credentials.ts` parses entries, not the envelope; `host-token.md` §4, `dek-cache.md` gate table, `cf-worker-deploy.md`, AGENTS.md admin lines | `credentials.test.ts` "tolerates epoch" → "`{v,c}` envelope posted to credentials-add is 400"; new `admin_auth.test.ts` (MAC tamper/expiry/epoch → 401, wrong `Origin` → 403, `Cf-Access-Jwt-Assertion` ignored, challenge single-use and 120 s, pending cap 429, limiter absent 503, bootstrap 403/409 then login 204, last-credential revoke 409) |
| 5 | **Config in DO**, one secret | `account_admin.ts` gains `cache_enabled`, `cache_hit_notify`, `uv_policy`, `GET/PUT config`; `opCreate` applies UV; `account_cache.ts`/`cache_crypto.ts` derive the scalar; `CACHE_ADMIN_EXTEND`, `CACHE_HIT_NOTIFY`, `APPROVAL_UV_JSON`, `WORKER_ORIGIN`, `RP_ID`, `CACHE_SECKEY` leave `Env`; `VT_AUTH_CF` → `SECRET`, `ENROLL_LIMITER` → `LIMITER`; 设置 tab; `wrangler.toml.example` (no `[vars]`), `cf-worker-deploy.md` rewrite, `dek-cache.md`, AGENTS.md cache lines; `test/do_helpers.ts` env → `{SECRET, LIMITER?, ACCOUNT, ASSETS}` | `do_account.uv.test.ts` reads policy from config; `do_account.dek_cache.test.ts` adds "`cache_enabled=false` with live entries → miss, approve page offers `[0]`, extend routes 404"; `do_account.host_token.test.ts` rotation case keeps its name with `SECRET` |

## 8. Budget

Non-blank, non-comment lines; `just size` numbers before this plan:
`cf-worker/src/` 4444 (ceiling 3500), `do_account.ts` 929 (ceiling 750).

| Step | `cf-worker/src/` | `pwa/` (excl. `libsodium.js`) |
| --- | --- | --- |
| 1 Web Push | +230 (`webpush` 110, `account_admin` 80, wiring 40) | +80 (sw, manifest, subscribe UI) |
| 2 channels | −770 (`feishu` 256, `slack_app` 182, `pushover` 78, notifications/notify/index/page/types/do_account 254) | −270 (channels html/js) |
| 3 shell | −30 | −200 (four shells −344, `admin.html` +60, tabs in `admin.js` +80) |
| 4 auth | +45 (`access` −126, `admin_auth` +60, admin ops +100, index ±0) | +40 (setup.js API flows −60/+100) |
| 5 config | −10 | +80 (设置 tab) |
| **net** | **≈ −535 → ≈ 3.9k** | **≈ −270** |

`do_account.ts` gains ~15 (dispatch) and loses ~40 (channel refs, extend
switch); admin state lives in `account_admin.ts` (~200 after step 5), which
has one reason to exist: what the console owns in storage. The area ceiling is
not reached by this plan plus refactor.md 1–3 (≈ 3.8k); see Q2.

## 9. Open questions for the operator

1. **Admin assets public.** §1 serves `pwa/admin/*` through the public `/pwa/*`
   route because the login page needs its script before any cookie exists and
   the shells hold no data until rendered. This deletes `isAdminAssetPath` and
   flips the AGENTS.md line "public `/pwa/*` must reject paths resolving into
   `pwa/admin/`". Alternative that keeps the line: a separate public
   `login.js` and a cookie-gated `/admin/pwa/*` mount (+~25 lines, one more
   route). Which?
2. **Ceiling.** After this plan and refactor.md steps 1–3, `cf-worker/src/`
   lands near 3.8k against the 3.5k ceiling with `account_cache`, `account_audit`,
   `types` (618, mostly declarations) and `do_account` as the remaining
   weight. Raise to 4.0k with that sentence, or name the next deletion before
   step 5 lands?
