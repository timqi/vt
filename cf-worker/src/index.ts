// vt-passkey v2 Worker — Hono router.
//
// Endpoints sit at the root (no secret path prefix). Security rests on:
//   • /api/challenge, /api/dek-cache — HMAC(VT_AUTH_CF) over the request body
//   • /api/audit-ingest     — HMAC(HKDF(VT_AUTH_CF, agent_id)) over the request body
//   • /a/:token, approve    — 12-byte (96-bit) unguessable approve/poll tokens + WebAuthn
//   • /<ADMIN_SEG>/*        — Cloudflare Access (edge) + Worker JWT verification
//
// Admin landing redirects to the audit view; Setup is a sibling tab.

import { Hono, type Context } from 'hono';
import { Env } from './types';
import { b64uEnc, decodeB64uExact, ctEq, challengeHash, randomBytes, hmacSha256, hkdfSha256, inReplayWindow } from './crypto';
import { notifyApproval } from './notify';
import { parsePushoverConfig } from './pushover';
import { parseSlackConfig } from './slack';
import { parseSlackAppConfig } from './slack_app';
import { parseFeishuConfig } from './feishu';
import { ApprovePageData, ChallengeRequest, ChallengeResponse, Challenge, ChallengeMeta, ApproveRequest, RejectRequest, DekCacheRequest, AgentAuditIngestRequest, DoAuditIngestOp } from './types';
import { log, logErr, tokenPrefix } from './log';
import { requireAccess, type AccessVars } from './access';
import {
  escapeJsonForHtml, renderTemplate, isAdminAssetPath,
  pageVars, adminVars, channelVars, type AdminTab, type PageChrome,
} from './page';

export { AccountDO } from './do_account';

// Shared strict CSP for Worker-rendered HTML pages (approval + admin). All page
// scripts are same-origin and use only crypto.subtle / WebAuthn / fetch — no
// inline or eval — so 'self' is sufficient.
const STRICT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// Shared favicon / app-icon links. Assets live in pwa/ and are served at /pwa/*.
// Allowed under CSP `img-src 'self'` (same-origin). Minimal set: a vector
// favicon (any tab size) + the 512 PNG for iOS home-screen / PWA install
// (iOS does not accept SVG for apple-touch-icon).
const FAVICON_TAGS =
  '<link rel="icon" href="/pwa/icon.svg" type="image/svg+xml">' +
  '<link rel="apple-touch-icon" href="/pwa/icon-512.png">';

// URL segment for the admin surface. Deliberately non-obvious so scanners that
// probe /admin, /dashboard, etc. miss it (the real gate is Cloudflare Access —
// this is just to cut noise). Change to any value you like, but keep it in sync
// with the Cloudflare Access application's Path. The on-disk asset folder stays
// pwa/admin/ regardless of this value.
const ADMIN_SEG = 'kestrel';

// Cache-busting token appended (?v=…) to admin/PWA asset URLs. Bump on any
// change to a shipped .css/.js so browsers fetch the new file instead of a
// stale far-future-cached copy. (Workers Assets serves static files with a
// cacheable response; without a versioned URL a changed audit.js can refresh
// while admin.css stays stale, which desyncs markup from styles. The .html
// page shells need no token — the Worker reads them server-side per request.)
// Stamped by `just bump-assets` (<YYYYMMDD>-<git short hash>) — don't hand-edit.
const ASSET_VER = '20260729-6';

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
function capChallengeMeta(raw: Partial<ChallengeMeta> | undefined, connectingIp: string | undefined): ChallengeMeta {
  return {
    op_kind:    capMeta(raw?.op_kind, 32),
    command:    sanitizeMultilineUncapped(raw?.command),
    host:       capMeta(raw?.host, 100),
    user:       capMeta(raw?.user, 64),
    pwd:        capMeta(raw?.pwd, 200),
    tty:        capMeta(raw?.tty, 40),
    ppid_cmd:   capMeta(raw?.ppid_cmd, 200),
    // Numeric PPID — the PPID half of the DEK-cache binding ctx (IP is the
    // other, trustworthy, half). Clamp to u32; non-numeric → 0.
    ppid:       (typeof raw?.ppid === 'number' && Number.isFinite(raw.ppid)) ? (raw.ppid >>> 0) : 0,
    ssh_client: capMeta(raw?.ssh_client, 100),
    ip:         capMeta(connectingIp, 64),
    reason:     capMeta(raw?.reason, 200),
  };
}

const app = new Hono<{ Bindings: Env; Variables: AccessVars }>();

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

// Static PWA assets. Strip "/pwa" so ASSETS resolves against the pwa/ root:
// /pwa/libsodium.js → /libsodium.js → pwa/libsodium.js
//
// This route is UNAUTHENTICATED (the approval page's ceremony scripts have to
// load for anyone holding an approve token), so it must never resolve into the
// admin asset folder — which now holds the admin page shells as well as
// admin.css and the per-tab .js. Those are served only by the Access-gated
// /{ADMIN_SEG}/pwa/* mount below.
app.get('/pwa/*', async (c) => {
  const url = new URL(c.req.url);
  url.pathname = url.pathname.slice('/pwa'.length) || '/';
  if (isAdminAssetPath(url.pathname)) return c.text('Not found', 404);
  return c.env.ASSETS.fetch(new Request(url.toString(), c.req.raw));
});

// ── Admin surface (Cloudflare Access protected) ───────────────────────────
//
// requireAccess verifies the Cf-Access-Jwt-Assertion JWT (RS256, kid, aud, iss,
// exp) and fails closed. It gates BOTH the bare `/${ADMIN_SEG}` entry and
// everything under `/${ADMIN_SEG}/*` (Hono's `/*` does not match the bare path,
// so register both). The Cloudflare Access application's Path must equal
// `${ADMIN_SEG}` (no secret prefix to keep in sync).
app.use(`/${ADMIN_SEG}`, requireAccess);
app.use(`/${ADMIN_SEG}/*`, requireAccess);

// Admin static assets. Map /{ADMIN_SEG}/pwa/X → /admin/X → pwa/admin/X
// (the single [assets] dir is "pwa"; the on-disk folder stays "admin").
app.get(`/${ADMIN_SEG}/pwa/*`, async (c) => {
  const url = new URL(c.req.url);
  url.pathname = '/admin' + url.pathname.slice(`/${ADMIN_SEG}/pwa`.length);
  return c.env.ASSETS.fetch(new Request(url.toString(), c.req.raw));
});

// Admin landing → default to the audit view (Setup is a sibling tab).
app.get(`/${ADMIN_SEG}`, (c) => c.redirect(`/${ADMIN_SEG}/audit`, 302));

// Audit page (HTML shell; data fetched from the JSON API below).
app.get(`/${ADMIN_SEG}/audit`, (c) => servePage(c, '/admin/audit', adminShellVars('audit')));

// DEK-cache page (HTML shell; data from /api/cache-list).
app.get(`/${ADMIN_SEG}/cache`, (c) => servePage(c, '/admin/cache', adminShellVars('cache')));

// Setup page (client-side CREDENTIALS_JSON generator). The current
// CREDENTIALS_JSON secret is injected into the page so add/revoke read it
// directly from the env binding (no manual paste). It carries only wrapped
// (encrypted) master-key material and public credential data, and the route is
// Cloudflare-Access gated, so embedding it for the admin is acceptable.
app.get(`/${ADMIN_SEG}/setup`, (c) => servePage(c, '/admin/setup', {
  ...adminShellVars('setup'),
  // `credentials` is the raw CREDENTIALS_JSON secret (or '' on very first
  // setup). The page parses it client-side for add/revoke; bootstrap ignores
  // it. Only wrapped (encrypted) key material is exposed — never a plaintext
  // master.
  VT_DATA: escapeJsonForHtml({ rp_id: c.env.RP_ID, credentials: c.env.CREDENTIALS_JSON ?? '' }),
}));

// Channels page (client-side notification-secret generator). Unlike Passkey,
// the live PUSHOVER_JSON / SLACK_JSON secrets are plaintext credentials and are
// NEVER injected — only booleans indicating whether each is currently set, so
// the page can show a configured/not-configured badge without echoing tokens.
// The badge runs the SAME parser the dispatch paths use (config !== null), so a
// present-but-malformed secret reads as "not configured" here too — matching
// what actually fires, instead of the old presence-only `&& trim()` check that
// would show ✓ for a secret that silently never delivers.
app.get(`/${ADMIN_SEG}/channels`, (c) => {
  const pushoverSet = parsePushoverConfig(c.env.PUSHOVER_JSON).config !== null;
  const slackSet = parseSlackConfig(c.env.SLACK_JSON).config !== null;
  const slackAppSet = parseSlackAppConfig(c.env.SLACK_APP_JSON).config !== null;
  const feishuSet = parseFeishuConfig(c.env.FEISHU_JSON).config !== null;
  return servePage(c, '/admin/channels', {
    ...adminShellVars('channels'),
    VT_DATA: escapeJsonForHtml({
      pushover_set: pushoverSet, slack_set: slackSet,
      slackapp_set: slackAppSet, feishu_set: feishuSet,
    }),
    ...channelVars('PUSHOVER', pushoverSet),
    ...channelVars('SLACK', slackSet),
    ...channelVars('SLACKAPP', slackAppSet),
    ...channelVars('FEISHU', feishuSet),
  });
});

// Audit data API — forwards a read-only cursor query to the DO.
app.get(`/${ADMIN_SEG}/api/audit`, async (c) => {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const u = new URL('https://account.do/op/audit-query');
  for (const k of ['limit', 'before_id', 'after_seq', 'status', 'host', 'source']) {
    const v = c.req.query(k);
    if (v) u.searchParams.set(k, v);
  }
  return stub.fetch(u.toString());
});

// Real-time audit stream (WebSocket). Access-gated by the /${ADMIN_SEG}/* mount
// above, exactly like the REST audit API — the upgrade is a plain GET, so
// requireAccess runs and fails closed BEFORE this handler (the DO's /ws-admin is
// never reached on an auth failure). The verified JWT `exp` is forwarded so the
// DO can bind the hibernating socket's lifetime to the admin's session.
app.get(`/${ADMIN_SEG}/api/audit-stream`, async (c) => {
  if (c.req.header('Upgrade') !== 'websocket') return c.text('expected websocket', 426);
  const exp = c.get('accessExp');
  if (typeof exp !== 'number') return c.text('forbidden', 403); // requireAccess must have set it
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const wsUrl = `https://account.do/ws-admin?exp=${encodeURIComponent(String(exp))}`;
  return stub.fetch(new Request(wsUrl, { headers: c.req.raw.headers }));
});

// Clear the cached DEKs written by ONE approval (by its audit token_id). Powers
// the per-row "清除缓存" button on the audit page. Access-gated.
app.post(`/${ADMIN_SEG}/api/cache-clear-origin`, async (c) => {
  let body: { token_id?: unknown };
  try { body = await c.req.json(); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/cache-clear-origin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token_id: body.token_id }),
  });
});

// Cache inventory — what is actually cached right now, grouped by the approval
// that armed it. Read-only. `no-store` because the payload is live security state
// (an intermediary or a back-button replay must not resurrect a stale view of what
// is decryptable without a phone tap).
app.get(`/${ADMIN_SEG}/api/cache-list`, async (c) => {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const resp = await stub.fetch('https://account.do/op/cache-list');
  const out = new Response(resp.body, resp);
  out.headers.set('Cache-Control', 'no-store');
  return out;
});

// Bulk clear by group — authority-REDUCING, so the Access gate alone is enough.
app.post(`/${ADMIN_SEG}/api/cache-clear-groups`, async (c) => {
  let body: { group_ids?: unknown };
  try { body = await c.req.json(); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/cache-clear-groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group_ids: body.group_ids }),
  });
});

// REQUEST a cache extension. Unlike every other admin action this one GRANTS
// authority (it prolongs no-phone-in-the-loop decrypts), so the Access gate is
// explicitly NOT sufficient: this endpoint only mints a pending Passkey ceremony,
// and nothing expires later until that ceremony is approved. The verified Access
// identity is forwarded for the audit trail — the body cannot claim it.
app.post(`/${ADMIN_SEG}/api/cache-extend-request`, async (c) => {
  let body: { group_ids?: unknown; ttl_s?: unknown };
  try { body = await c.req.json(); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const doResp = await stub.fetch('https://account.do/op/cache-extend-create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      group_ids: body.group_ids,
      ttl_s: body.ttl_s,
      admin_email: c.get('accessEmail') ?? '',
      admin_ip: c.req.header('CF-Connecting-IP') ?? '',
    }),
  });
  // Deliberately NO notification fan-out here. The whole extension flow lives in
  // the admin console: the operator selects the groups, presses 延长, and the
  // Passkey ceremony mounts inline on the same page. A pushed approval card would
  // be noise for a request whose requester is already looking at the result — and
  // the audit tab still records both the request (op_kind='cache-extend') and its
  // effect (status='extended') in real time, so the action stays observable there.
  return doResp;
});

// POST clear-cache — emergency revocation: drop ALL cached DEKs now. Access-gated.
app.post(`/${ADMIN_SEG}/api/clear-cache`, async (c) => {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/clear-cache', { method: 'POST' });
});

// POST clear-audit — wipe ALL audit rows (ceremony + cache events). Access-gated.
app.post(`/${ADMIN_SEG}/api/clear-audit`, async (c) => {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/clear-audit', { method: 'POST' });
});

// POST /api/challenge — daemon creates a challenge
app.post('/api/challenge', async (c) => {
  // 1. HMAC auth
  const rawBody = await readAuthenticatedDaemonBody(c);
  if (rawBody instanceof Response) return rawBody;

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

  // 6. Generate tokens. 12 bytes = 96-bit capability tokens (16 b64url chars):
  // unguessable within the 5-min single-use TTL, and approval still requires a
  // server-verified WebAuthn assertion regardless. Shortens the approve URL.
  const approveToken = b64uEnc(randomBytes(12));
  const pollToken   = b64uEnc(randomBytes(12));
  const workerNonce = randomBytes(16);

  // 7. Compute approve + reject challenge hashes
  const approveHash = await challengeHash(daemonPk, workerNonce, body.timestamp_ms, saltArrays, 'approve');
  const rejectHash  = await challengeHash(daemonPk, workerNonce, body.timestamp_ms, saltArrays, 'reject');

  const ch: Challenge = {
    approve_token: approveToken,
    poll_token: pollToken,
    daemon_pubkey_b64u: body.daemon_pubkey_b64u,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    approve_challenge_hash_b64u: b64uEnc(approveHash),
    reject_challenge_hash_b64u: b64uEnc(rejectHash),
    salts_b64u: saltsB64u,
    meta: capChallengeMeta(body.meta, c.req.header('CF-Connecting-IP')),
    status: 'pending',
    created_ms: Date.now(),
  };

  // 8. Store in DO
  const ns = c.env.ACCOUNT;
  const id = ns.idFromName('account');
  const stub = ns.get(id);
  const doResp = await stub.fetch('https://account.do/op/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge: ch }),
  });
  if (!doResp.ok) return c.text(`do create: ${await doResp.text()}`, 500);

  // 9. Notifications — Pushover and/or Slack, both opt-in and non-fatal.
  const origin = c.env.WORKER_ORIGIN;
  const approveUrl = `${origin}/a/${approveToken}`;

  const pushWarning = await notifyApproval(
    c.env, ch.meta.op_kind, ch.meta, approveUrl,
    Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0,
  );
  if (pushWarning) logErr('notify.failed', pushWarning, { at: tokenPrefix(approveToken) });

  log('challenge.created', {
    at: tokenPrefix(approveToken),
    op_kind: ch.meta.op_kind,
    host: ch.meta.host,
    user: ch.meta.user,
    tty: ch.meta.tty,
    ip: ch.meta.ip,
    salts: saltArrays.length,
  });

  const resp: ChallengeResponse = {
    approve_token: approveToken,
    poll_token: pollToken,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    approve_url: approveUrl,
    ...(pushWarning ? { push_warning: pushWarning } : {}),
  };
  return c.json(resp);
});

// GET /api/dek — WebSocket; client waits for sealed DEKs
app.get('/api/dek', async (c) => {
  // Forward to DO which handles WS hibernation
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const wsUrl = `https://account.do/ws?poll_token=${c.req.query('poll_token') ?? ''}`;
  return stub.fetch(new Request(wsUrl, {
    headers: c.req.raw.headers,
  }));
});

// POST /api/dek-cache — daemon tries the opt-in DEK cache before a ceremony.
// Same HMAC(VT_AUTH_CF) gate + replay window as /api/challenge. On a full hit
// the DO returns DEKs re-sealed to the daemon's ephemeral pubkey; otherwise
// {miss:true} and the daemon falls through to the normal phone approval.
//
// The IP is taken from CF-Connecting-IP (trustworthy) — NOT from the body — and
// forms half of the cache binding context; the ppid (client-reported) is the
// advisory half. See docs/dek-cache.md §2.5.
app.post('/api/dek-cache', async (c) => {
  const rawBody = await readAuthenticatedDaemonBody(c);
  if (rawBody instanceof Response) return rawBody;

  let body: DekCacheRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }

  if (!inReplayWindow(Date.now(), body.timestamp_ms)) return c.text('timestamp skew', 400);

  // Cap the client meta and force `ip` from CF-Connecting-IP — identical to the
  // challenge path, so a cache hit records the same context.
  const meta = capChallengeMeta(body.meta, c.req.header('CF-Connecting-IP'));
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/dek-cache', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      daemon_pubkey_b64u: body.daemon_pubkey_b64u,
      salts_b64u: body.salts_b64u,
      meta,
    }),
  });
});

// POST /api/audit-ingest — the SSH agent pushes one audit record per decision.
// Unlike /api/challenge (HMAC keyed on VT_AUTH_CF directly), this is keyed on a
// PER-AGENT HKDF subkey: the agent never holds the master. The Worker reads the
// (still-unverified) `agent_id` from the body, derives the same subkey, then
// verifies the VT-HMAC over the raw body. A forged agent_id only yields a key
// that won't verify — parsing it before verification is safe. One HKDF per
// request is negligible; the 64 KB cap + 401-on-bad-HMAC bound abuse.
const AUDIT_INGEST_MAX_BYTES = 64 * 1024;
app.post('/api/audit-ingest', async (c) => {
  // 0. Reject a declared oversized body before parsing the auth header;
  //    readCappedBody also enforces the limit while streaming below.
  const clen = c.req.header('Content-Length');
  if (clen && Number(clen) > AUDIT_INGEST_MAX_BYTES) return c.text('body too large', 413);

  const auth = c.req.header('Authorization') ?? '';
  const prefix = 'VT-HMAC ';
  if (!auth.startsWith(prefix)) return c.text('missing auth', 401);
  let providedHmac: Uint8Array;
  try { providedHmac = decodeB64uExact(auth.slice(prefix.length), 32, 'hmac'); }
  catch { return c.text('hmac length', 401); }

  const rawBody = await readCappedBody(c, AUDIT_INGEST_MAX_BYTES);
  if (!rawBody) return c.text('body too large', 413);

  // 1. Parse the body to get agent_id (UNVERIFIED — it only selects the key).
  let body: AgentAuditIngestRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }
  if (typeof body.agent_id !== 'string' || !body.agent_id) return c.text('missing agent_id', 400);
  // Defensive cap before the HKDF salt step (agent_id is the hostname, ≤255 per
  // RFC 1123). A forged value can't verify anyway, but bound the input.
  if (body.agent_id.length > 256) return c.text('agent_id too long', 400);

  // 2. Derive the per-agent key and 3. verify the HMAC over the raw body.
  const enc = new TextEncoder();
  const key = await hkdfSha256(
    enc.encode(c.env.VT_AUTH_CF), enc.encode(body.agent_id), enc.encode('vt-agent-audit-v1'), 32);
  const expected = await hmacSha256(key, rawBody);
  if (!ctEq(providedHmac, expected)) return c.text('hmac mismatch', 401);

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
  };

  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/audit-ingest', {
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

// Only daemon challenge/cache requests use this key; audit ingestion derives
// a per-agent key and deliberately retains its own validation order.
async function readAuthenticatedDaemonBody(
  c: Context<{ Bindings: Env; Variables: AccessVars }>,
): Promise<Uint8Array | Response> {
  const auth = c.req.header('Authorization') ?? '';
  const prefix = 'VT-HMAC ';
  if (!auth.startsWith(prefix)) return c.text('missing auth', 401);
  let providedHmac: Uint8Array;
  try { providedHmac = decodeB64uExact(auth.slice(prefix.length), 32, 'hmac'); }
  catch { return c.text('hmac length', 401); }

  const rawBody = await readCappedBody(c);
  if (!rawBody) return c.text('body too large', 413);
  const keyBytes = new TextEncoder().encode(c.env.VT_AUTH_CF);
  const expected = await hmacSha256(keyBytes, rawBody);
  if (!ctEq(providedHmac, expected)) return c.text('hmac mismatch', 401);
  return rawBody;
}

// POST /api/approve — PWA submits sealed DEKs after WebAuthn
app.post('/api/approve', async (c) => {
  const raw = await readCappedBody(c);
  if (!raw) return c.text('body too large', 413);
  let body: ApproveRequest;
  try { body = JSON.parse(new TextDecoder().decode(raw)); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// POST /api/reject — PWA rejects
app.post('/api/reject', async (c) => {
  const raw = await readCappedBody(c);
  if (!raw) return c.text('body too large', 413);
  let body: RejectRequest;
  try { body = JSON.parse(new TextDecoder().decode(raw)); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/reject', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// Fetch ApprovePageData for a token from the DO. Shared by the HTML page
// (/a/:token) and the JSON sibling (/api/page/:token). Returns a discriminated
// result; a non-pending / unknown token maps to 410 / 404. The token is
// url-encoded defensively (it feeds a query param) even though real tokens are
// b64url and carry no special chars.
async function fetchApprovePageData(
  c: Context<{ Bindings: Env; Variables: AccessVars }>,
  approveToken: string,
): Promise<{ ok: true; data: ApprovePageData } | { ok: false; status: 404 | 410 }> {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const dataResp = await stub.fetch(
    `https://account.do/op/page?approve_token=${encodeURIComponent(approveToken)}`);
  if (!dataResp.ok) return { ok: false, status: dataResp.status === 410 ? 410 : 404 };
  return { ok: true, data: await dataResp.json() };
}

// GET /a/:approve_token — serve the approval PWA page
app.get('/a/:approve_token', async (c) => {
  const res = await fetchApprovePageData(c, c.req.param('approve_token'));
  if (!res.ok) {
    return c.text(res.status === 410 ? 'Request already handled or expired' : 'Not found', res.status);
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
// so the (Access-gated) audit page can mount the approval ceremony inline in its
// detail modal instead of opening the standalone page in a new tab. The
// approve_token is an unguessable 96-bit capability and the payload holds only
// public/PRF-wrapped material — this exposes nothing /a/:token doesn't already.
app.get('/api/page/:approve_token', async (c) => {
  const res = await fetchApprovePageData(c, c.req.param('approve_token'));
  if (!res.ok) return c.json({ error: res.status === 410 ? 'gone' : 'not_found' }, res.status);
  return c.json(res.data);
});

// ── Page shells (static assets + placeholder substitution) ────────────────
//
// The shells are real files under pwa/ (approve.html) and pwa/admin/ (one per
// admin tab). They are read through the ASSETS binding from INSIDE the route
// handler, so the admin ones inherit the Cloudflare Access gate registered on
// /${ADMIN_SEG} and /${ADMIN_SEG}/* above; the public /pwa/* route refuses the
// admin folder outright (isAdminAssetPath).

// Read a page shell out of the ASSETS binding.
//
// Two deliberate details:
//  • The request is built fresh instead of forwarding c.req.raw. A conditional
//    request (If-None-Match from the browser) would come back 304 with an empty
//    body, and we need the bytes to substitute into.
//  • Path, then path + ".html". With the default assets `html_handling`
//    ("auto-trailing-slash") a fetch of "/admin/audit.html" answers 307 →
//    "/admin/audit", so the extensionless form is the one that returns the file;
//    with html_handling = "none" it is the other way round. Trying both keeps
//    the pages working under either setting without a build step.
async function fetchShell(c: Context<{ Bindings: Env; Variables: AccessVars }>, path: string): Promise<string> {
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
// Referrer-Policy — so every page carries the full set.
async function servePage(
  c: Context<{ Bindings: Env; Variables: AccessVars }>,
  path: string,
  vars: Record<string, string>,
): Promise<Response> {
  const html = renderTemplate(await fetchShell(c, path), vars);
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': STRICT_CSP,
    },
  });
}

// The Worker-owned values every shell interpolates.
const CHROME: PageChrome = { adminSeg: ADMIN_SEG, assetVer: ASSET_VER, faviconTags: FAVICON_TAGS };
const adminShellVars = (active: AdminTab) => adminVars(CHROME, active);

// Unhandled exceptions → one structured error event + opaque 500 to caller.
app.onError((err, c) => {
  logErr('error', err, { path: new URL(c.req.url).pathname });
  return c.text('internal error', 500);
});

export default app;
