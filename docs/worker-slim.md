# Worker slim — one secret, passkey admin, config in the DO

Status: **implemented**. Owns the `cf-worker/` trust model after the slim: one
Wrangler secret over a stored root key, one notification channel (Web Push),
one admin gate (passkey session), one config store (the encrypted blob in the
Durable Object). §2–§5 are the current contract; verify against
`cf-worker/src/account_admin.ts`, `admin_auth.ts`, `do_account.ts`, `index.ts`
and `types.ts` (`Env`). Operator procedures live in
[cf-worker-deploy.md](cf-worker-deploy.md); the PWA's presentation contract in
[design/ui-ux.md](design/ui-ux.md).

Landed, in order: Web Push beside the channels, channels deleted, one admin
shell, passkey admin auth with `root:v1` from bootstrap (Cloudflare Access,
`ADMIN_SEG`, `CREDENTIALS_JSON` gone), config in the DO with every derivation
rooted on `R` (`CACHE_SECKEY`, `CACHE_ADMIN_EXTEND`, `CACHE_HIT_NOTIFY`,
`APPROVAL_UV_JSON`, `WORKER_ORIGIN`, `RP_ID`, `ACCESS_*` gone; `VT_AUTH_CF` →
`SECRET`, `ENROLL_LIMITER` → `LIMITER`). Every host token was re-issued once
by `vt enroll` at that last step, and the hostname-keyed agent audit key went
with it ([refactor.md](refactor.md) §1).

## 2. Trust model

`SECRET` is a KEK. The root key `R` (32 random bytes, generated at bootstrap)
is stored as `root:v1 = {wraps: [AES-256-GCM(K_kek, R)]}` (AAD `vt-root-v1`);
every other key derives from `R`, so `SECRET` alone and DO storage alone are
each worthless.

| Key | ikm | salt | info | Protects |
| --- | --- | --- | --- | --- |
| `K_kek` AES-256-GCM | `utf8(SECRET)` | empty | `vt-kek-v1` | `R` at rest |
| host token secret | `R` | `token_id` | `vt-host-token-v1` | daemon HMAC, compared in the DO ([host-token.md](host-token.md) §2) |
| `K_cfg` AES-256-GCM | `R` | empty | `vt-config-key-v1` | the config blob at rest (§4) |
| `K_sess` HMAC | `R` | empty | `vt-admin-session-v1` | admin session cookie (§3.1) |
| cache X25519 scalar | `R` | empty | `vt-cache-seckey-v1` | DEK sealed boxes; `cachePublicKey` derives the point as today |

HKDF-SHA256, `L = 32`. Not derived: the VAPID key pair (§5.2) — WebCrypto
cannot turn a derived scalar into its public point, so it is generated once and
stored under `K_cfg`.

- `SECRET` is 32 random bytes, base64url, set with `wrangler secret put`. It is
  never sent to a host, a browser, or a log. The DO unwraps `R` once per
  instance and keeps it in memory.
- **Rotation keeps `R`.** 设置 → 轮换 SECRET (passkey session): the DO generates
  a new `SECRET`, appends a second wrap of `R`, and returns the value once for
  `wrangler secret put SECRET`. Unwrap tries each wrap (at most two); the first
  success under the new `SECRET` deletes the other. Host tokens, passkeys,
  config, subscriptions and cache entries survive. Nothing is typed into the
  browser; the two wraps live only in the DO and only during the window.
- **Factory reset** is `R` compromise (DO storage read) or a lost `SECRET`
  before rotation completes: `wrangler secret put SECRET` with a fresh value
  *without* rotating. `root:v1` no longer unwraps ⇒ unconfigured (§4.3):
  ceremony routes answer `503 not_configured`, `/admin` shows the setup view
  flagged `reset`, and bootstrap replaces root and blob; every host runs
  `vt enroll`. (Wrangler offers no console for DO keys, so the unreadable root
  is the reset signal; an attacker who can make it unreadable can write his
  own.) Audit rows and the `host_token` table are plaintext SQLite and survive;
  revoke stale rows by hand.
- **A stolen `SECRET` yields nothing** without DO storage. `SECRET` + DO storage
  yields: forging a live host's token — paging the phone as that host and
  reading its live cached DEKs for their TTL; forging admin sessions — every
  console action, including passkey revocation (lockout) and subscribing a
  phone to pushes; the config blob and VAPID private key. It does **not** yield
  the master key (PRF-wrapped), record plaintext beyond live cache entries, a
  passkey approval, or a cache extension (passkey-gated).

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
| `POST /api/admin/rotate-secret` | cookie | §2 rotation; returns `{secret}` once |
| existing `audit`, `audit-stream`, `cache-*`, `clear-cache`, `clear-audit`, `tokens`, `tokens-revoke` | cookie | unchanged bodies; the former `admin_email` fields are gone — the cookie carries no credential identity, so extend/revoke rows name no operator |

- `LIMITER` is the existing 3/min/IP Workers Rate Limiting binding, keyed
  `enroll:<ip>` by `/api/enroll` and `login:<ip>` by bootstrap and
  login-challenge. Absent → `503` on those routes, never unthrottled.
- Login failures log `admin.login_failed` (throttled like `admin.auth_failed`
  today); nothing is written to the audit table for them.
- A `Cf-Access-Jwt-Assertion` header has no effect anywhere (rejected-input test).

### 3.3 Bootstrap

No setup token: before bootstrap the Worker holds nothing worth taking, and a
stranger who registers first is visible and evictable (item 5 below). Certificate
transparency publishes a new hostname within minutes, so treat the window as
public and bootstrap right after `just deploy-worker`.

1. `wrangler secret put SECRET`; `just deploy-worker`. No `root:v1` ⇒
   unconfigured: every route except `/admin`, `/api/admin/bootstrap` and the
   public PWA assets answers `503 not_configured`.
2. Open `https://<host>/admin` — the setup view. Fill in a label and the
   `vt secret export` blob + passphrase (the passkey master must equal the
   macOS `mac_key`, as today; the blob is decrypted in the browser only). The
   page registers the passkey (`residentKey: 'required'`,
   `userVerification: 'required'`, `prf`), asserts once for PRF, wraps the
   master and builds the credential entry (`setup.js` byte formats unchanged).
3. `POST /api/admin/bootstrap {entry}`.
4. DO, serialized with every other write: a readable `root:v1` →
   `409 already_configured` with `{ms, ip}` of the first registration
   (`config.bootstrap`); else generate `R`, write `root:v1` and `{v:1, origin:
   <request origin>, epoch:1, credentials:[entry], bootstrap, …defaults}`,
   return a session cookie (204). A concurrent stranger runs after and
   receives the 409.
5. The 409 view shows that time and IP and one line: not you ⇒ factory reset
   (§2) and redo. Nothing else exists yet.
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
  bootstrap: { ms, ip },              // first registration, shown on a 409 (§3.3)
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
- `uv_policy` is applied in `opCreate` only, against the verified host; the
  raise-only rule and the `cache-extend` pin are unchanged. A malformed object
  is refused at PUT (400); a malformed stored one (a bug) reads as `required`.
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
