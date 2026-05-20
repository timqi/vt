// vt-passkey v2 Worker — Hono router.
//
// All sensitive endpoints live under a secret path prefix derived from
// VT_AUTH_CF so random scanners never see the API surface. The prefix is
// 16 base64url chars (≈96 bits) — unguessable in practice.

import { Hono } from 'hono';
import { Env } from './types';
import { derivePathPrefix, b64uEnc, b64uDec, challengeHash, randomBytes, hmacSha256, inReplayWindow } from './crypto';
import { notifyApproval } from './pushover';
import { ApprovePageData, ChallengeRequest, ChallengeResponse, Challenge, ApproveRequest, RejectRequest } from './types';

export { AccountDO } from './do_account';

const app = new Hono<{ Bindings: Env }>();

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
  // Constant-time comparison on the 16-char prefix
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= (provided.charCodeAt(i) ?? 0) ^ (expected.charCodeAt(i) ?? 0);
  if (diff !== 0 || provided.length !== expected.length) {
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
  const providedHmac = b64uDec(auth.slice(prefix.length));

  const rawBody = await c.req.arrayBuffer();
  const keyBytes = new TextEncoder().encode(c.env.VT_AUTH_CF);
  const expected = await hmacSha256(keyBytes, new Uint8Array(rawBody));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= (providedHmac[i] ?? 0) ^ (expected[i] ?? 0);
  if (diff !== 0 || providedHmac.length !== 32) return c.text('hmac mismatch', 401);

  // 2. Parse body
  let body: ChallengeRequest;
  try { body = JSON.parse(new TextDecoder().decode(rawBody)); }
  catch { return c.text('json parse error', 400); }

  // 3. Replay window
  if (!inReplayWindow(Date.now(), body.timestamp_ms)) return c.text('timestamp skew', 400);

  // 4. Validate daemon pubkey
  const daemonPk = b64uDec(body.daemon_pubkey_b64u);
  if (daemonPk.length !== 32) return c.text('daemon_pubkey must be 32 bytes', 400);

  // 5. Generate tokens
  const approveToken = b64uEnc(randomBytes(32));
  const pollToken   = b64uEnc(randomBytes(32));
  const inboxToken  = b64uEnc(randomBytes(32));
  const workerNonce = randomBytes(16);

  // 6. Compute challenge_hash (binds pubkey + nonce + ts + salts)
  const saltArrays = (body.salts_b64u ?? []).map(s => b64uDec(s));
  const chHash = await challengeHash(daemonPk, workerNonce, body.timestamp_ms, saltArrays);

  const ch: Challenge = {
    approve_token: approveToken,
    poll_token: pollToken,
    inbox_token: inboxToken,
    daemon_pubkey_b64u: body.daemon_pubkey_b64u,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    challenge_hash_b64u: b64uEnc(chHash),
    salts_b64u: body.salts_b64u ?? [],
    meta: {
      op_kind: body.meta?.op_kind ?? '',
      command: body.meta?.command ?? '',
      host: body.meta?.host ?? '',
      ip: body.meta?.ip ?? (c.req.header('CF-Connecting-IP') ?? ''),
      reason: body.meta?.reason ?? '',
    },
    status: 'pending',
    created_ms: Date.now(),
  };

  // 7. Store in DO
  const ns = c.env.ACCOUNT;
  const id = ns.idFromName('account');
  const stub = ns.get(id);
  const doResp = await stub.fetch('https://account.do/op/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge: ch }),
  });
  if (!doResp.ok) return c.text(`do create: ${await doResp.text()}`, 500);

  // 8. Pushover (non-fatal)
  const origin = c.env.WORKER_ORIGIN;
  const pathPrefix = await derivePathPrefix(c.env.VT_AUTH_CF);
  const approveUrl = `${origin}/${pathPrefix}/a/${approveToken}`;
  const inboxUrl   = `${origin}/${pathPrefix}/inbox/${inboxToken}`;

  const secrets = (c.env.PUSHOVER_APP_TOKEN && c.env.PUSHOVER_USER_TOKEN)
    ? { appToken: c.env.PUSHOVER_APP_TOKEN, userToken: c.env.PUSHOVER_USER_TOKEN }
    : null;
  const pushWarning = await notifyApproval(secrets, ch.meta.op_kind, ch.meta, approveUrl);
  if (pushWarning) console.error('pushover (non-fatal):', pushWarning);

  const resp: ChallengeResponse = {
    approve_token: approveToken,
    poll_token: pollToken,
    inbox_token: inboxToken,
    worker_nonce_b64u: b64uEnc(workerNonce),
    timestamp_ms: body.timestamp_ms,
    approve_url: approveUrl,
    inbox_url: inboxUrl,
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
  const body = await c.req.json<ApproveRequest>();
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  return stub.fetch('https://account.do/op/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
});

// POST /api/reject — PWA rejects
app.post('/:prefix/api/reject', async (c) => {
  const body = await c.req.json<RejectRequest>();
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
  return c.html(html);
});

// GET /inbox/:inbox_token — simple inbox page listing pending approval
app.get('/:prefix/inbox/:inbox_token', async (c) => {
  // For now redirect to the approve page if there's exactly one pending challenge
  return c.text('inbox not yet implemented', 501);
});

// ── HTML template ─────────────────────────────────────────────────────────

function buildApprovePage(data: ApprovePageData): string {
  const dataJson = JSON.stringify(data).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
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

export default app;
