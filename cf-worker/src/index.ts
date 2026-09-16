// vt-passkey v2 Worker — Hono router.
//
// Endpoints sit at the root (no secret path prefix). Security rests on:
//   • /api/challenge, /api/dek-cache, /api/audit-ingest — HMAC over the request
//     body keyed on the caller's host token (HKDF(R, token_id), host_token.ts).
//     The edge checks header shape and caps the body; the DO, which alone holds
//     R, compares the MAC and checks the token's liveness
//   • /api/enroll           — unauthenticated, per-IP rate limited; mints a
//     Passkey ceremony that issues a host token
//   • /a/:token, approve    — 12-byte (96-bit) unguessable approve/poll tokens + WebAuthn
//   • /admin, /api/admin/* — passkey admin session verified in the DO; the
//     one admin shell (tabs in the URL hash) plus its data API

import { Hono, type Context } from 'hono';
import { Env } from './types';
import { b64uEnc, decodeB64uExact, challengeHash, randomBytes, inReplayWindow } from './crypto';
import { ApprovePageData, ChallengeRequest, ChallengeResponse, ChallengeMeta, ApproveRequest, RejectRequest, DekCacheRequest, AgentAuditIngestRequest, DaemonAuth, DoAuditIngestOp, DoCreateOp, DoDekCacheOp, EnrollRequest, EnrollResponse, DoEnrollCreateOp } from './types';
import { isTokenId } from './host_token';
import { log, logErr, tokenPrefix } from './log';
import { escapeJsonForHtml, renderTemplate, pageVars, type PageChrome } from './page';
import { tokenRefused } from './do_account';
import { NAME_MAX } from './account_names';

export { AccountDO } from './do_account';

// Shared strict CSP for Worker-rendered HTML pages (approval + admin). All page
// scripts are same-origin and use only crypto.subtle / WebAuthn / fetch — no
// inline or eval — so 'self' is sufficient.
const STRICT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// Shared favicon / app-icon / manifest links. Assets live in pwa/ and are served
// at /pwa/*. Allowed under CSP `img-src 'self'` (same-origin). Minimal set: a
// vector favicon (any tab size), the 512 PNG for iOS home-screen / PWA install
// (iOS does not accept SVG for apple-touch-icon), and the manifest that makes
// the installed app standalone so Web Push works on iOS (docs/worker-slim.md#installed-app).
const FAVICON_TAGS =
  '<link rel="icon" href="/pwa/icon.svg" type="image/svg+xml">' +
  '<link rel="apple-touch-icon" href="/pwa/icon-512.png">' +
  '<link rel="manifest" href="/manifest.webmanifest">';

// Cache-busting token appended (?v=…) to PWA asset URLs. Bump on any change to
// a shipped .css/.js so browsers fetch the new file instead of a stale
// far-future-cached copy. (Workers Assets serves static files with a cacheable
// response; without a versioned URL a changed audit.js can refresh while
// admin.css stays stale, which desyncs markup from styles. The .html page
// shells need no token — the Worker reads them server-side per request.)
// Stamped by `just bump-assets` (<YYYYMMDD>-<git short hash>) — don't hand-edit.
const ASSET_VER = '20260916-a80fd08';

// Defensive cap on display-only meta fields. The CLI already sanitizes, but
// the worker has no reason to trust the body — anything over the cap is
// truncated, control chars are stripped to prevent layout breakage on the
// approval page (PWA still treats values as text via .textContent, but
// stripping here keeps stored DO state tidy too).
function capMeta(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  // Strip ASCII control chars (0x00–0x1F, 0x7F) and U+2028 / U+2029.
  // eslint-disable-next-line no-control-regex
  const cleaned = v.replace(/[\x00-\x1f\x7f\u2028\u2029]/g, '');
  return cleaned.length <= max ? cleaned : cleaned.slice(0, max) + '…';
}

// For the multi-line `command` body the CLI builds (`op: …\ncmd: …\nreason: …`):
// sanitize but do NOT truncate — strip control chars EXCEPT newline (0x0a), so a
// long command renders in full on the approval / audit surfaces. The ceremony
// request body is already bounded (CEREMONY_POST_MAX_BYTES = 256 KiB), which is
// the real size guard — so this is not an unbounded-payload risk.
function sanitizeMultilineUncapped(v: unknown): string {
  if (typeof v !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\x00-\x09\x0b-\x1f\x7f\u2028\u2029]/g, '');
}

// Build a sanitized ChallengeMeta from an untrusted client `meta` body. Shared
// by /api/challenge and /api/dek-cache so a cache hit is audited with the same
// fields as a ceremony. `ip` ALWAYS comes from CF-Connecting-IP, never the body
// (a compromised CLI could otherwise spoof the source IP shown/recorded).
// `host` / `user` are read here as client claims; on the host-token path the DO
// overwrites both from the token record (the only place that knows them).
function capChallengeMeta(raw: Partial<ChallengeMeta> | undefined, connectingIp: string | undefined): ChallengeMeta {
  return {
    op_kind:    capMeta(raw?.op_kind, 32),
    command:    sanitizeMultilineUncapped(raw?.command),
    host:       capMeta(raw?.host, 100),
    user:       capMeta(raw?.user, 64),
    pwd:        capMeta(raw?.pwd, 200),
    project:    capMeta(raw?.project, 200),
    ppid_cmd:   capMeta(raw?.ppid_cmd, 200),
    ip:         capMeta(connectingIp, 64),
    reason:     capMeta(raw?.reason, 200),
  };
}

// Client record-name suggestions: absent → none; else exactly one string per
// salt, each within NAME_MAX before control characters are stripped. Anything
// else is null (400): a name that silently moved or shrank would label the
// wrong record. Returned '' entries mean "unknown".
function checkNames(raw: unknown, count: number): string[] | null {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.length !== count) return null;
  if (!raw.every(n => typeof n === 'string' && n.length <= NAME_MAX)) return null;
  return raw.map(n => capMeta(n, NAME_MAX));
}

// `request.cf` country + AS organisation — Cloudflare-derived, so an enrollment
// approver gets a second verified origin signal next to the bare IP.
function requestOrigin(c: Context<{ Bindings: Env }>): string {
  const cf = (c.req.raw as Request & { cf?: { country?: string; asOrganization?: string } }).cf;
  return [cf?.country, cf?.asOrganization].filter(Boolean).map(v => capMeta(v, 60)).join(' · ');
}

function accountStub(c: Context<{ Bindings: Env }>): DurableObjectStub {
  return c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
}

const app = new Hono<{ Bindings: Env }>();

// ── Global security headers ───────────────────────────────────────────────

app.use('*', async (c, next) => {
  await next();
  // WebSocket upgrades (101 Switching Protocols) carry a non-standard `webSocket`
  // field that `new Response(body, init)` would drop, breaking the handshake —
  // and HTTP security headers are meaningless on a 101. Leave it untouched.
  // (Guards both /api/dek and the admin /api/audit-stream sockets.)
  if (c.res.status === 101) return;
  // Responses from ASSETS.fetch / fetch() have immutable headers; rebuild
  // so the security headers below can be applied uniformly.
  c.res = new Response(c.res.body, c.res);
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000');
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
});

// ── Healthz (no prefix) ────────────────────────────────────────────────────

app.get('/healthz', c => c.text('ok'));

// Static PWA assets, UNAUTHENTICATED — including pwa/admin/*: the shells and
// scripts carry no data (a raw shell is `{{VT_DATA}}` plus markup); data reaches
// a page only through the gated admin route or the gated API. Strip "/pwa" so
// ASSETS resolves against the pwa/ root: /pwa/common.js → pwa/common.js.
app.get('/pwa/*', async (c) => {
  const url = new URL(c.req.url);
  url.pathname = url.pathname.slice('/pwa'.length) || '/';
  return c.env.ASSETS.fetch(new Request(url.toString(), c.req.raw));
});

// Service worker at root scope (a worker under /pwa/ could not control /a/*
// or the admin shell) and the install manifest. Both public: they hold no data.
for (const p of ['/sw.js', '/manifest.webmanifest']) {
  app.get(p, (c) => c.env.ASSETS.fetch(new Request(new URL(p, c.req.url).toString(), c.req.raw)));
}

// ── Admin surface (passkey session) ───────────────────────────────────────
//
// Every request here is verified in the DO, the only place that knows the
// current epoch (docs/worker-slim.md#sessions): the edge adds rate limiting and body
// caps and forwards Cookie, Origin and CF-Connecting-IP. Three POSTs are open
// (bootstrap, login-challenge, login); everything else needs the session cookie.

// The admin shell (pwa/admin/admin.html) renders one of setup / login / console
// from the state the DO reports for this request's cookie.
app.get('/admin', async (c) => {
  const resp = await accountStub(c).fetch('https://account.do/op/admin-state', { headers: adminHeaders(c) });
  const data = await resp.json() as { state: string; rp_id: string | null; reset?: boolean };
  return servePage(c, '/admin/admin', {
    ...pageVars(CHROME),
    VT_DATA: escapeJsonForHtml({ ...data, rp_id: data.rp_id ?? new URL(c.req.url).hostname }),
  });
});

const ADMIN_OPEN_POST_MAX_BYTES = 4 * 1024;
const ADMIN_POST_MAX_BYTES = 64 * 1024;
// URL tail → DO op. Anything not listed is 404; the DO decides on the session.
const ADMIN_GET: Record<string, string> = {
  audit: 'audit-query', 'cache-list': 'cache-list', tokens: 'tokens-list',
  credentials: 'admin-credentials', config: 'admin-config', 'push/vapid': 'push-vapid',
};
const ADMIN_POST: Record<string, string> = {
  'cache-clear-entries': 'cache-clear-entries', 'cache-extend-request': 'cache-extend-create',
  'tokens-revoke': 'tokens-revoke', 'clear-cache': 'clear-cache',
  'push/subscribe': 'push-subscribe', 'push/unsubscribe': 'push-unsubscribe', 'push/test': 'push-test',
  logout: 'admin-logout', 'sessions-revoke': 'admin-sessions-revoke',
  'credentials-add': 'admin-credentials-add', 'credentials-revoke': 'admin-credentials-revoke',
  'rotate-secret': 'admin-rotate-secret',
};
// Open, so rate limited per IP (bootstrap and login-challenge) or gated by the
// challenge it consumes (login).
const ADMIN_OPEN_POST: Record<string, string> = {
  bootstrap: 'admin-bootstrap', 'login-challenge': 'admin-login-challenge', login: 'admin-login',
};

function adminHeaders(c: Context<{ Bindings: Env }>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of ['Cookie', 'Origin', 'CF-Connecting-IP']) {
    const v = c.req.header(h);
    if (v !== undefined) out[h] = v;
  }
  return out;
}

async function adminPost(c: Context<{ Bindings: Env }>, op: string, maxBytes: number): Promise<Response> {
  const raw = await readCappedBody(c, maxBytes);
  if (!raw) return c.text('body too large', 413);
  return adminResponse(await accountStub(c).fetch(`https://account.do/op/${op}`, {
    method: c.req.method, headers: { 'Content-Type': 'application/json', ...adminHeaders(c) }, body: raw,
  }));
}

// `no-store` on every admin payload: it is live security state (what is
// decryptable without a tap, which tokens are alive), never replayable from a
// cache or the back button.
function adminResponse(resp: Response): Response {
  const out = new Response(resp.body, resp);
  out.headers.set('Cache-Control', 'no-store');
  return out;
}

app.get('/api/admin/audit-stream', async (c) => {
  if (c.req.header('Upgrade') !== 'websocket') return c.text('expected websocket', 426);
  return accountStub(c).fetch(new Request('https://account.do/ws-admin', { headers: c.req.raw.headers }));
});

app.get('/api/admin/*', async (c) => {
  const url = new URL(c.req.url);
  const op = ADMIN_GET[url.pathname.slice('/api/admin/'.length)];
  if (!op) return c.text('not found', 404);
  return adminResponse(await accountStub(c).fetch(`https://account.do/op/${op}${url.search}`, { headers: adminHeaders(c) }));
});

// Two PUTs: the config knobs (other fields in the body are rejected) and a
// record rename — `{salt_b64u, name}`, name checked like a suggestion, ''
// deletes. Both session-gated in the DO.
app.put('/api/admin/config', (c) => adminPost(c, 'admin-config', ADMIN_OPEN_POST_MAX_BYTES));
app.put('/api/admin/names', async (c) => {
  const raw = await readCappedBody(c, ADMIN_OPEN_POST_MAX_BYTES);
  if (!raw) return c.text('body too large', 413);
  let body: { salt_b64u?: unknown; name?: unknown };
  try { body = JSON.parse(new TextDecoder().decode(raw)); }
  catch { return c.text('invalid json', 400); }
  const name = checkNames([body.name], 1);
  if (!name) return c.text('bad name', 400);
  return adminResponse(await accountStub(c).fetch('https://account.do/op/names-set', {
    method: 'PUT', headers: { 'Content-Type': 'application/json', ...adminHeaders(c) },
    body: JSON.stringify({ salt_b64u: body.salt_b64u, name: name[0] }),
  }));
});

app.post('/api/admin/*', async (c) => {
  const tail = new URL(c.req.url).pathname.slice('/api/admin/'.length);
  const open = ADMIN_OPEN_POST[tail];
  if (open) {
    if (tail !== 'login') {
      const limited = await rateLimit(c, `login:${c.req.header('CF-Connecting-IP') ?? ''}`);
      if (limited) return limited;
    }
    return adminPost(c, open, ADMIN_OPEN_POST_MAX_BYTES);
  }
  const op = ADMIN_POST[tail];
  if (!op) return c.text('not found', 404);
  return adminPost(c, op, ADMIN_POST_MAX_BYTES);
});

// The one 3/min/IP binding, keyed by route family. Absent → refuse: neither a
// phone page nor a session mint may run unthrottled.
async function rateLimit(c: Context<{ Bindings: Env }>, key: string): Promise<Response | null> {
  const limiter = c.env.LIMITER;
  if (!limiter) return c.text('rate limiter not configured', 503);
  const { success } = await limiter.limit({ key });
  return success ? null : c.text('rate limited', 429);
}


// POST /api/challenge — daemon creates a challenge
app.post('/api/challenge', async (c) => {
  // 1. Auth header shape, token id shape, body cap. The MAC itself is compared
  //    in the DO (step 8); nothing here is trusted until then.
  const authed = await readDaemonBody(c);
  if (authed instanceof Response) return authed;
  const { body: rawBody, auth } = authed;

  // 2. Parse body
  let body: ChallengeRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }

  // 3. Replay window
  if (!inReplayWindow(Date.now(), body.timestamp_ms)) return c.text('timestamp skew', 400);

  // 4. Validate daemon pubkey + salts (each 16 bytes, count <= 256)
  const saltsB64u = body.salts_b64u ?? [];
  if (saltsB64u.length > 256) return c.text('too many salts', 400);
  let daemonPk: Uint8Array;
  let saltArrays: Uint8Array[];
  try {
    daemonPk = decodeB64uExact(body.daemon_pubkey_b64u, 32, 'daemon_pubkey');
    saltArrays = saltsB64u.map((s, i) => decodeB64uExact(s, 16, `salt[${i}]`));
  } catch (e) {
    return c.text((e as Error).message, 400);
  }

  // 5. Meta: capped here; host/user are overwritten by the DO from the token.
  const meta = capChallengeMeta(body.meta, c.req.header('CF-Connecting-IP'));
  const names = checkNames(body.meta?.names, saltsB64u.length);
  if (!names) return c.text('bad names', 400);
  if (names.length) meta.names = names;

  // 6. Generate tokens. 12 bytes = 96-bit capability tokens (16 b64url chars):
  // unguessable within the 5-min single-use TTL, and approval still requires a
  // server-verified WebAuthn assertion regardless. Shortens the approve URL.
  const approveToken = b64uEnc(randomBytes(12));
  const pollToken   = b64uEnc(randomBytes(12));
  const workerNonce = randomBytes(16);

  // 7. Compute approve + reject challenge hashes
  const approveHash = await challengeHash(daemonPk, workerNonce, body.timestamp_ms, saltArrays, 'approve');
  const rejectHash  = await challengeHash(daemonPk, workerNonce, body.timestamp_ms, saltArrays, 'reject');

  const ch: DoCreateOp['challenge'] = {
    approve_token: approveToken,
    poll_token: pollToken,
    daemon_pubkey_b64u: body.daemon_pubkey_b64u,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    approve_challenge_hash_b64u: b64uEnc(approveHash),
    reject_challenge_hash_b64u: b64uEnc(rejectHash),
    salts_b64u: saltsB64u,
    meta,
    // The DO decides the level (stored policy + the raise-only request below)
    // against the verified host and stores it on the challenge.
    status: 'pending',
    created_ms: Date.now(),
  };

  // 8. Store in DO. The DO verifies the MAC and the token FIRST (401 with a
  //    structured reason the CLI turns into "run `vt enroll`"), fills
  //    meta.host / user from the record and returns the stored meta plus the
  //    approve URL on the configured origin.
  const doResp = await accountStub(c).fetch('https://account.do/op/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge: ch, uv_request: body.uv, auth } satisfies DoCreateOp),
  });
  // Refusals (bad MAC, dead token, unconfigured Worker) reach the CLI as-is.
  if (doResp.status === 401 || doResp.status === 503) return new Response(doResp.body, doResp);
  if (!doResp.ok) return c.text(`do create: ${await doResp.text()}`, 500);
  const stored = await doResp.json() as { meta: ChallengeMeta; approve_url: string };
  ch.meta = stored.meta;

  // 9. The DO already pushed the phone (storeAndAnnounce); nothing to await.
  const approveUrl = stored.approve_url;

  log('challenge.created', {
    at: tokenPrefix(approveToken),
    op_kind: ch.meta.op_kind,
    host: ch.meta.host,
    user: ch.meta.user,
    ip: ch.meta.ip,
    salts: saltArrays.length,
  });

  const resp: ChallengeResponse = {
    approve_token: approveToken,
    poll_token: pollToken,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    approve_url: approveUrl,
  };
  return c.json(resp);
});

// GET /api/dek — WebSocket; client waits for sealed DEKs
app.get('/api/dek', async (c) => {
  // Forward to DO which handles WS hibernation
  const wsUrl = `https://account.do/ws?poll_token=${c.req.query('poll_token') ?? ''}`;
  return accountStub(c).fetch(new Request(wsUrl, { headers: c.req.raw.headers }));
});

// POST /api/dek-cache — daemon tries the opt-in DEK cache before a ceremony.
// Same host-token gate + replay window as /api/challenge. On a full hit the DO
// returns DEKs re-sealed to the daemon's ephemeral pubkey; otherwise
// {miss:true} and the daemon falls through to the normal phone approval.
//
// The IP is taken from CF-Connecting-IP (trustworthy) — NOT from the body — as
// audit metadata; the token the DO verifies is the cache key's hard half.
// See docs/dek-cache.md.
app.post('/api/dek-cache', async (c) => {
  const authed = await readDaemonBody(c);
  if (authed instanceof Response) return authed;
  const { body: rawBody, auth } = authed;

  let body: DekCacheRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }

  if (!inReplayWindow(Date.now(), body.timestamp_ms)) return c.text('timestamp skew', 400);

  // Cap the client meta and force `ip` from CF-Connecting-IP — identical to the
  // challenge path, so a cache hit records the same context.
  const meta = capChallengeMeta(body.meta, c.req.header('CF-Connecting-IP'));
  const names = checkNames(body.meta?.names, Array.isArray(body.salts_b64u) ? body.salts_b64u.length : 0);
  if (!names) return c.text('bad names', 400);
  if (names.length) meta.names = names;
  return accountStub(c).fetch('https://account.do/op/dek-cache', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      daemon_pubkey_b64u: body.daemon_pubkey_b64u,
      salts_b64u: body.salts_b64u,
      meta,
      auth,
    } satisfies DoDekCacheOp),
  });
});

// POST /api/enroll — a host asks for its own credential. UNAUTHENTICATED by
// design (a fresh host has nothing to sign with), which makes it the one public
// route that can page the operator's phone. Three independent bounds:
//   • per-IP Workers Rate Limiting (`enroll:<ip>`; absent → refuse outright),
//   • the DO's caps on concurrently pending enrollments (per IP and global),
//   • the usual 5-minute ceremony TTL.
// Nothing is issued here: the response is a pending Passkey ceremony plus the
// pairing code the approver compares against the requesting terminal.
const ENROLL_POST_MAX_BYTES = 4 * 1024;
app.post('/api/enroll', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? '';
  const limited = await rateLimit(c, `enroll:${ip}`);
  if (limited) return limited;

  const raw = await readCappedBody(c, ENROLL_POST_MAX_BYTES);
  if (!raw) return c.text('body too large', 413);
  let body: EnrollRequest;
  try { body = JSON.parse(new TextDecoder().decode(raw)); }
  catch { return c.text('json parse error', 400); }
  if (typeof body.timestamp_ms !== 'number' || !inReplayWindow(Date.now(), body.timestamp_ms)) {
    return c.text('timestamp skew', 400);
  }
  const op: DoEnrollCreateOp = {
    host: capMeta(body.host, 100),
    user: capMeta(body.user, 64),
    ip: capMeta(ip, 64),
    origin: requestOrigin(c),
  };
  if (!op.host) return c.text('missing host', 400);
  const doResp = await accountStub(c).fetch('https://account.do/op/enroll-create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(op),
  });
  if (!doResp.ok) return new Response(doResp.body, doResp);
  const created = await doResp.json() as { approve_token: string; poll_token: string; pair_code: string; approve_url: string };
  log('enroll.requested', { at: tokenPrefix(created.approve_token), host: op.host, user: op.user, ip: op.ip });
  return c.json({
    approve_url: created.approve_url,
    poll_token: created.poll_token,
    pair_code: created.pair_code,
  } satisfies EnrollResponse);
});

// POST /api/audit-ingest — the SSH agent pushes one audit record per decision,
// signed with the Mac's own host token (`vt ssh agent --audit-key vt1.…`,
// `agent_id = t:<token_id>`). Same gate as the daemon routes: shape and cap
// here, MAC and liveness in the DO — a revoked token stops writing rows. The
// Only per-host tokens are accepted (docs/worker-slim.md#host-tokens).
const AUDIT_INGEST_MAX_BYTES = 64 * 1024;
app.post('/api/audit-ingest', async (c) => {
  // 0. Reject a declared oversized body before parsing the auth header;
  //    readCappedBody also enforces the limit while streaming below.
  const clen = c.req.header('Content-Length');
  if (clen && Number(clen) > AUDIT_INGEST_MAX_BYTES) return c.text('body too large', 413);

  const providedHmac = hmacHeader(c);
  if (providedHmac instanceof Response) return providedHmac;

  const rawBody = await readCappedBody(c, AUDIT_INGEST_MAX_BYTES);
  if (!rawBody) return c.text('body too large', 413);

  // 1. Parse the body to get agent_id (UNVERIFIED — it only selects the key).
  let body: AgentAuditIngestRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }
  if (typeof body.agent_id !== 'string' || !body.agent_id.startsWith('t:') || !isTokenId(body.agent_id.slice(2))) {
    return c.text('bad agent token id', 401);
  }
  const auth: DaemonAuth = { token_id: body.agent_id.slice(2), mac_b64u: b64uEnc(providedHmac), signed_b64u: b64uEnc(rawBody) };

  // 4. Replay window on the body timestamp.
  if (typeof body.timestamp_ms !== 'number' || !inReplayWindow(Date.now(), body.timestamp_ms))
    return c.text('timestamp skew', 400);

  // 5. Validate + cap the entry. capChallengeMeta sanitizes the display fields
  //    and FORCES ip from CF-Connecting-IP (the body never carries a usable ip).
  const entry = body.entry;
  if (!entry || typeof entry !== 'object') return c.text('missing entry', 400);
  const tokenId = capMeta(entry.token_id, 80);
  if (!tokenId) return c.text('missing token_id', 400);

  const clampInt = (v: unknown): number =>
    (typeof v === 'number' && Number.isFinite(v) && v >= 0) ? Math.floor(v) : 0;
  // Null-preserving variants for the agent-authoritative fields: an old agent
  // that never sent the field must store SQL NULL, distinguishable from a new
  // agent's explicit ''/0/false ("not applicable"). capMeta/clampInt would
  // coerce absent to ''/0 and erase that distinction.
  const capOrNull = (v: unknown, max: number): string | null =>
    v === undefined || v === null ? null : capMeta(v, max);
  const clampIntOrNull = (v: unknown): number | null =>
    v === undefined || v === null ? null : clampInt(v);
  const boolOrNull = (v: unknown): number | null =>
    typeof v === 'boolean' ? (v ? 1 : 0) : null;
  // ts_ms must itself be within the replay window — otherwise an HMAC-verified
  // (but buggy/compromised) agent could write a far-future ts_ms that escapes
  // the 90-day retention sweep, or a ts_ms=0 row that's swept immediately.
  const tsMs = (typeof entry.ts_ms === 'number' && Number.isFinite(entry.ts_ms)
    && inReplayWindow(Date.now(), entry.ts_ms))
    ? entry.ts_ms : body.timestamp_ms;

  const op: DoAuditIngestOp = {
    token_id: tokenId,
    outcome: capMeta(entry.outcome, 32),
    salts: clampInt(entry.salts),
    latency_ms: clampInt(entry.latency_ms),
    ts_ms: tsMs,
    meta: capChallengeMeta(entry.meta, c.req.header('CF-Connecting-IP')),
    peer_exe: capOrNull(entry.peer_exe, 160),
    key_fp: capOrNull(entry.key_fp, 160),
    dest: capOrNull(entry.dest, 160),
    scope_family: capOrNull(entry.scope_family, 32),
    scope_label: capOrNull(entry.scope_label, 160),
    grant_ttl_s: clampIntOrNull(entry.grant_ttl_s),
    relayed: boolOrNull(entry.relayed),
    auth,
  };

  return accountStub(c).fetch('https://account.do/op/audit-ingest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(op),
  });
});

// Shared cap for challenge/cache probes and approve/reject bodies. Bound reads
// before HMAC/JSON work, even when Content-Length is absent or understated.
const CEREMONY_POST_MAX_BYTES = 256 * 1024;

async function readCappedBody(c: Context, maxBytes = CEREMONY_POST_MAX_BYTES): Promise<Uint8Array | null> {
  const clen = c.req.header('Content-Length');
  if (clen && Number(clen) > maxBytes) return null;
  const reader = c.req.raw.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength === 0) continue;
      if (value.byteLength > maxBytes - length) {
        await reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
      length += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

// Daemon challenge/cache requests: the `Authorization: VT-HMAC <mac>` and
// `VT-Token-Id` headers, checked for shape before the body is read and capped.
// The MAC is NOT compared here — the token secret is HKDF(R, token_id) and R
// lives in the DO — so the exact bytes and the MAC travel with the op and the
// DO refuses before it touches the token or stores anything. A request without
// the header gets the same structured 401 as a dead token: the remedy is
// `vt enroll` either way.
// `Authorization: VT-HMAC <mac>` — shape only; the MAC itself is compared in
// the DO.
function hmacHeader(c: Context<{ Bindings: Env }>): Uint8Array | Response {
  const authHeader = c.req.header('Authorization') ?? '';
  const prefix = 'VT-HMAC ';
  if (!authHeader.startsWith(prefix)) return c.text('missing auth', 401);
  try { return decodeB64uExact(authHeader.slice(prefix.length), 32, 'hmac'); }
  catch { return c.text('hmac length', 401); }
}

async function readDaemonBody(
  c: Context<{ Bindings: Env }>,
): Promise<{ body: Uint8Array; auth: DaemonAuth } | Response> {
  const providedHmac = hmacHeader(c);
  if (providedHmac instanceof Response) return providedHmac;
  const tokenHeader = c.req.header('VT-Token-Id');
  if (tokenHeader === undefined) return tokenRefused('token_missing');
  if (!isTokenId(tokenHeader)) return c.text('bad token id', 401);

  const rawBody = await readCappedBody(c);
  if (!rawBody) return c.text('body too large', 413);
  return { body: rawBody, auth: { token_id: tokenHeader, mac_b64u: b64uEnc(providedHmac), signed_b64u: b64uEnc(rawBody) } };
}

// POST /api/approve — the PWA submits sealed DEKs after WebAuthn;
// POST /api/reject — the PWA rejects. Same shape: cap, parse, hand to the DO.
for (const op of ['approve', 'reject'] as const) {
  app.post(`/api/${op}`, async (c) => {
    const raw = await readCappedBody(c);
    if (!raw) return c.text('body too large', 413);
    let body: ApproveRequest | RejectRequest;
    try { body = JSON.parse(new TextDecoder().decode(raw)); }
    catch { return c.text('invalid json', 400); }
    // Typed record names are cleaned like a rename (checkNames); the DO checks
    // each index against the ceremony's salts.
    const adopt = (body as ApproveRequest).adopt_names;
    if (op === 'approve' && adopt !== undefined) {
      const names = Array.isArray(adopt) ? checkNames(adopt.map(e => e?.name), adopt.length) : null;
      if (!names) return c.text('bad adopt_names', 400);
      (body as ApproveRequest).adopt_names = adopt.map((e, i) => ({ index: e.index, name: names[i]! }));
    }
    return accountStub(c).fetch(`https://account.do/op/${op}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  });
}

// Fetch ApprovePageData for a token from the DO. Shared by the HTML page
// (/a/:token) and the JSON sibling (/api/page/:token). Returns a discriminated
// result; a non-pending / unknown token maps to 410 / 404. The token is
// url-encoded defensively (it feeds a query param) even though real tokens are
// b64url and carry no special chars.
async function fetchApprovePageData(
  c: Context<{ Bindings: Env }>,
  approveToken: string,
): Promise<{ ok: true; data: ApprovePageData } | { ok: false; status: 404 | 410 | 503 }> {
  const dataResp = await accountStub(c).fetch(
    `https://account.do/op/page?approve_token=${encodeURIComponent(approveToken)}`);
  if (dataResp.status === 503) return { ok: false, status: 503 };
  if (!dataResp.ok) return { ok: false, status: dataResp.status === 410 ? 410 : 404 };
  return { ok: true, data: await dataResp.json() };
}

// GET /a/:approve_token — serve the approval PWA page
app.get('/a/:approve_token', async (c) => {
  const res = await fetchApprovePageData(c, c.req.param('approve_token'));
  if (!res.ok) {
    return c.text(res.status === 410 ? 'Request already handled or expired'
      : res.status === 503 ? 'Worker not configured' : 'Not found', res.status);
  }
  // Inject page data into the HTML shell (pwa/approve.html).
  // servePage sets the tight CSP: <script type="application/json"> is
  // non-executable and exempt from script-src; same-origin /pwa/* scripts and
  // styles match 'self'; fetch() to /api/* is same-origin.
  return servePage(c, '/approve', {
    ...pageVars(CHROME),
    VT_DATA: escapeJsonForHtml(res.data),
  });
});

// GET /api/page/:approve_token — same ApprovePageData as /a/:token but as JSON,
// so the admin shell can mount the approval ceremony inline in
// its detail dialog instead of opening the standalone page in a new tab. The
// approve_token is an unguessable 96-bit capability and the payload holds only
// public/PRF-wrapped material — this exposes nothing /a/:token doesn't already.
app.get('/api/page/:approve_token', async (c) => {
  const res = await fetchApprovePageData(c, c.req.param('approve_token'));
  if (!res.ok) return c.json({ error: res.status === 410 ? 'gone' : res.status === 503 ? 'not_configured' : 'not_found' }, res.status);
  return c.json(res.data, 200, { 'Cache-Control': 'no-store' });
});

// ── Page shells (static assets + placeholder substitution) ────────────────
//
// The shells are real files: pwa/approve.html and pwa/admin/admin.html, both
// public assets holding no data. They are read through the ASSETS binding from
// INSIDE the route handler and filled with what the DO reported.

// Read a page shell out of the ASSETS binding.
//
// Two deliberate details:
//  • The request is built fresh instead of forwarding c.req.raw. A conditional
//    request (If-None-Match from the browser) would come back 304 with an empty
//    body, and we need the bytes to substitute into.
//  • Path, then path + ".html". With the default assets `html_handling`
//    ("auto-trailing-slash") a fetch of "/admin/admin.html" answers 307 →
//    "/admin/admin", so the extensionless form is the one that returns the file;
//    with html_handling = "none" it is the other way round. Trying both keeps
//    the pages working under either setting without a build step.
async function fetchShell(c: Context<{ Bindings: Env }>, path: string): Promise<string> {
  const origin = new URL(c.req.url).origin;
  const get = (p: string) => c.env.ASSETS.fetch(new Request(origin + p, { method: 'GET' }));
  let resp = await get(path);
  if (!resp.ok) resp = await get(`${path}.html`);
  if (!resp.ok) throw new Error(`page shell ${path}: ${resp.status}`);
  return resp.text();
}

// Serve a page shell with the substituted values and the page security headers.
// A fresh Response is built (ASSETS responses have immutable headers), and the
// global middleware then rebuilds it again to add HSTS / nosniff /
// Referrer-Policy — so every page carries the full set. `no-store`: the
// rendered shell carries per-request data (ceremony material, session state).
async function servePage(
  c: Context<{ Bindings: Env }>,
  path: string,
  vars: Record<string, string>,
): Promise<Response> {
  const html = renderTemplate(await fetchShell(c, path), vars);
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': STRICT_CSP,
      'Cache-Control': 'no-store',
    },
  });
}

// The Worker-owned values every shell interpolates.
const CHROME: PageChrome = { assetVer: ASSET_VER, faviconTags: FAVICON_TAGS };

// Unhandled exceptions → one structured error event + opaque 500 to caller.
app.onError((err, c) => {
  logErr('error', err, { path: new URL(c.req.url).pathname });
  return c.text('internal error', 500);
});

export default app;
