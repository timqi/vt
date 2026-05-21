// vt-passkey v2 Worker — Hono router.
//
// All sensitive endpoints live under a secret path prefix derived from
// VT_AUTH_CF so random scanners never see the API surface. The prefix is
// 16 base64url chars (≈96 bits) — unguessable in practice.

import { Hono } from 'hono';
import { Env } from './types';
import { derivePathPrefix, b64uEnc, decodeB64uExact, ctEq, challengeHash, randomBytes, hmacSha256, inReplayWindow } from './crypto';
import { notifyApproval } from './pushover';
import { ApprovePageData, ChallengeRequest, ChallengeResponse, Challenge, ApproveRequest, RejectRequest } from './types';
import { log, logErr, tokenPrefix } from './log';

export { AccountDO } from './do_account';

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

const app = new Hono<{ Bindings: Env }>();

// ── Global security headers ───────────────────────────────────────────────

app.use('*', async (c, next) => {
  await next();
  // Responses from ASSETS.fetch / fetch() have immutable headers; rebuild
  // so the security headers below can be applied uniformly.
  c.res = new Response(c.res.body, c.res);
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000');
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
});

// ── Healthz (no prefix) ────────────────────────────────────────────────────

app.get('/healthz', c => c.text('ok'));

// ── Static PWA assets — routed through the ASSETS binding ─────────────────
// The pwa/ directory is bound to ASSETS in wrangler.toml. Assets are served
// at /pwa/* directly, without the secret prefix. This is intentional: the
// assets themselves carry no secrets and the HTML they load always includes
// the approve_token in the dynamic path.

app.get('/pwa/*', async (c) => {
  // ASSETS directory = "pwa", so files are indexed without the /pwa prefix.
  // Strip it before fetching: /pwa/libsodium.js → /libsodium.js → pwa/libsodium.js.
  const url = new URL(c.req.url);
  url.pathname = url.pathname.slice('/pwa'.length) || '/';
  return c.env.ASSETS.fetch(new Request(url.toString(), c.req.raw));
});

// ── Secret-prefixed routes ────────────────────────────────────────────────

app.all('/:prefix/*', async (c, next) => {
  const provided = c.req.param('prefix');
  const expected = await derivePathPrefix(c.env.VT_AUTH_CF);
  const enc = new TextEncoder();
  if (!ctEq(enc.encode(provided), enc.encode(expected))) {
    return c.text('Not Found', 404);
  }
  return next();
});

// POST /api/challenge — daemon creates a challenge
app.post('/:prefix/api/challenge', async (c) => {
  // 1. HMAC auth
  const auth = c.req.header('Authorization') ?? '';
  const prefix = 'VT-HMAC ';
  if (!auth.startsWith(prefix)) return c.text('missing auth', 401);
  let providedHmac: Uint8Array;
  try { providedHmac = decodeB64uExact(auth.slice(prefix.length), 32, 'hmac'); }
  catch { return c.text('hmac length', 401); }

  const rawBody = await c.req.arrayBuffer();
  const keyBytes = new TextEncoder().encode(c.env.VT_AUTH_CF);
  const expected = await hmacSha256(keyBytes, new Uint8Array(rawBody));
  if (!ctEq(providedHmac, expected)) return c.text('hmac mismatch', 401);

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

  // 6. Generate tokens
  const approveToken = b64uEnc(randomBytes(32));
  const pollToken   = b64uEnc(randomBytes(32));
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
    meta: {
      op_kind:    capMeta(body.meta?.op_kind, 32),
      command:    capMeta(body.meta?.command, 300),
      host:       capMeta(body.meta?.host, 100),
      user:       capMeta(body.meta?.user, 64),
      pwd:        capMeta(body.meta?.pwd, 200),
      tty:        capMeta(body.meta?.tty, 40),
      ppid_cmd:   capMeta(body.meta?.ppid_cmd, 200),
      ssh_client: capMeta(body.meta?.ssh_client, 100),
      // IP is set by the worker from CF-Connecting-IP, never trusted from the
      // CLI body — a compromised or misconfigured CLI could otherwise spoof
      // the source IP shown to the approver.
      ip:         capMeta(c.req.header('CF-Connecting-IP'), 64),
      reason:     capMeta(body.meta?.reason, 200),
    },
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

  // 9. Pushover (non-fatal)
  const origin = c.env.WORKER_ORIGIN;
  const pathPrefix = await derivePathPrefix(c.env.VT_AUTH_CF);
  const approveUrl = `${origin}/${pathPrefix}/a/${approveToken}`;

  const secrets = (c.env.PUSHOVER_APP_TOKEN && c.env.PUSHOVER_USER_TOKEN)
    ? { appToken: c.env.PUSHOVER_APP_TOKEN, userToken: c.env.PUSHOVER_USER_TOKEN }
    : null;
  const pushWarning = await notifyApproval(secrets, ch.meta.op_kind, ch.meta, approveUrl);
  if (pushWarning) logErr('pushover.failed', pushWarning, { at: tokenPrefix(approveToken) });

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
app.get('/:prefix/api/dek', async (c) => {
  // Forward to DO which handles WS hibernation
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const wsUrl = `https://account.do/ws?poll_token=${c.req.query('poll_token') ?? ''}`;
  return stub.fetch(new Request(wsUrl, {
    headers: c.req.raw.headers,
  }));
});

// POST /api/approve — PWA submits sealed DEKs after WebAuthn
app.post('/:prefix/api/approve', async (c) => {
  let body: ApproveRequest;
  try { body = await c.req.json<ApproveRequest>(); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// POST /api/reject — PWA rejects
app.post('/:prefix/api/reject', async (c) => {
  let body: RejectRequest;
  try { body = await c.req.json<RejectRequest>(); }
  catch { return c.text('invalid json', 400); }
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/reject', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// GET /a/:approve_token — serve the approval PWA page
app.get('/:prefix/a/:approve_token', async (c) => {
  const approveToken = c.req.param('approve_token');
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  // Fetch page data from DO
  const dataResp = await stub.fetch(`https://account.do/op/page?approve_token=${approveToken}`);
  if (!dataResp.ok) {
    const status = dataResp.status === 410 ? 410 : 404;
    return c.text(status === 410 ? 'Request already handled or expired' : 'Not found', status);
  }
  const pageData: ApprovePageData = await dataResp.json();

  // Inject page data into HTML template
  const html = buildApprovePage(pageData);
  const resp = c.html(html);
  // Tight CSP for the approval page. <script type="application/json"> is
  // non-executable and exempt from script-src; same-origin /pwa/* scripts and
  // styles match 'self'; fetch() to /:prefix/api/* is same-origin.
  resp.headers.set(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
  return resp;
});

// ── HTML template ─────────────────────────────────────────────────────────

function buildApprovePage(data: ApprovePageData): string {
  const dataJson = JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
  return `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>VT 审批请求</title>
  <link rel="stylesheet" href="/pwa/approve.css">
</head>
<body>
  <script type="application/json" id="vt-data">${dataJson}</script>
  <main>
    <header>
      <h1>VT 审批请求</h1>
      <p class="hint">请用 Passkey（iCloud / 1Password / YubiKey）确认下列操作。</p>
    </header>
    <section id="meta-section">
      <h2>请求信息</h2>
      <dl id="meta"></dl>
    </section>
    <section id="actions">
      <button id="approve" type="button">✓ 同意</button>
      <button id="reject" type="button">拒绝</button>
    </section>
    <p id="status" role="status" aria-live="polite"></p>
  </main>
  <script src="/pwa/libsodium.js"></script>
  <script src="/pwa/common.js"></script>
  <script src="/pwa/approve.js"></script>
</body>
</html>`;
}

// Unhandled exceptions → one structured error event + opaque 500 to caller.
app.onError((err, c) => {
  logErr('error', err, { path: new URL(c.req.url).pathname });
  return c.text('internal error', 500);
});

export default app;
