// vt-passkey v2 Worker — Hono router.
//
// Endpoints sit at the root (no secret path prefix). Security rests on:
//   • /api/challenge        — HMAC(VT_AUTH_CF) over the request body
//   • /a/:token, approve    — 12-byte (96-bit) unguessable approve/poll tokens + WebAuthn
//   • /<ADMIN_SEG>/*        — Cloudflare Access (edge) + Worker JWT verification
//
// Admin landing redirects to the audit view; Setup is a sibling tab.

import { Hono } from 'hono';
import { Env } from './types';
import { b64uEnc, decodeB64uExact, ctEq, challengeHash, randomBytes, hmacSha256, inReplayWindow } from './crypto';
import { notifyApproval } from './notify';
import { ApprovePageData, ChallengeRequest, ChallengeResponse, Challenge, ApproveRequest, RejectRequest } from './types';
import { log, logErr, tokenPrefix } from './log';
import { requireAccess } from './access';

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

// Escape a JSON string for safe embedding in a <script type="application/json"> block.
function escapeJsonForHtml(obj: unknown): string {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

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

// Variant that preserves `\n` for the multi-line `command` body the CLI
// builds (`op: …\nfile: …\ncmd: …\nreason: …`). Per-line cap + total line
// cap mirror the SSH-agent's `PROMPT_COMMAND_MAX_*` so the same input
// renders the same height on Touch ID and on the approval page.
function capMetaMultiline(v: unknown, maxCharsPerLine: number, maxLines: number): string {
  if (typeof v !== 'string') return '';
  return v.split('\n').slice(0, maxLines)
    .map(line => capMeta(line, maxCharsPerLine))
    .join('\n');
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

// Static PWA assets. Strip "/pwa" so ASSETS resolves against the pwa/ root:
// /pwa/libsodium.js → /libsodium.js → pwa/libsodium.js
app.get('/pwa/*', async (c) => {
  const url = new URL(c.req.url);
  url.pathname = url.pathname.slice('/pwa'.length) || '/';
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
app.get(`/${ADMIN_SEG}/audit`, (c) => {
  const resp = c.html(buildAuditPage());
  resp.headers.set('Content-Security-Policy', STRICT_CSP);
  return resp;
});

// Setup page (client-side CREDENTIALS_JSON generator). The current
// CREDENTIALS_JSON secret is injected into the page so add/revoke read it
// directly from the env binding (no manual paste). It carries only wrapped
// (encrypted) master-key material and public credential data, and the route is
// Cloudflare-Access gated, so embedding it for the admin is acceptable.
app.get(`/${ADMIN_SEG}/setup`, (c) => {
  const resp = c.html(buildSetupPage(c.env.RP_ID, c.env.CREDENTIALS_JSON ?? ''));
  resp.headers.set('Content-Security-Policy', STRICT_CSP);
  return resp;
});

// Channels page (client-side notification-secret generator). Unlike Passkey,
// the live PUSHOVER_JSON / SLACK_JSON secrets are plaintext credentials and are
// NEVER injected — only booleans indicating whether each is currently set, so
// the page can show a configured/not-configured badge without echoing tokens.
app.get(`/${ADMIN_SEG}/channels`, (c) => {
  const pushoverSet = !!(c.env.PUSHOVER_JSON && c.env.PUSHOVER_JSON.trim());
  const slackSet = !!(c.env.SLACK_JSON && c.env.SLACK_JSON.trim());
  const resp = c.html(buildChannelsPage(pushoverSet, slackSet));
  resp.headers.set('Content-Security-Policy', STRICT_CSP);
  return resp;
});

// Audit data API — forwards a read-only cursor query to the DO.
app.get(`/${ADMIN_SEG}/api/audit`, async (c) => {
  const stub = c.env.ACCOUNT.get(c.env.ACCOUNT.idFromName('account'));
  const u = new URL('https://account.do/op/audit-query');
  for (const k of ['limit', 'before_id', 'status', 'host']) {
    const v = c.req.query(k);
    if (v) u.searchParams.set(k, v);
  }
  return stub.fetch(u.toString());
});

// POST /api/challenge — daemon creates a challenge
app.post('/api/challenge', async (c) => {
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
    meta: {
      op_kind:    capMeta(body.meta?.op_kind, 32),
      command:    capMetaMultiline(body.meta?.command, 120, 6),
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

  // 9. Notifications — Pushover and/or Slack, both opt-in and non-fatal.
  const origin = c.env.WORKER_ORIGIN;
  const approveUrl = `${origin}/a/${approveToken}`;

  const pushWarning = await notifyApproval(c.env, ch.meta.op_kind, ch.meta, approveUrl);
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

// POST /api/approve — PWA submits sealed DEKs after WebAuthn
app.post('/api/approve', async (c) => {
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
app.post('/api/reject', async (c) => {
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
app.get('/a/:approve_token', async (c) => {
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
  // styles match 'self'; fetch() to /api/* is same-origin.
  resp.headers.set('Content-Security-Policy', STRICT_CSP);
  return resp;
});

// ── HTML template ─────────────────────────────────────────────────────────

function buildApprovePage(data: ApprovePageData): string {
  const dataJson = escapeJsonForHtml(data);
  const base = `/pwa`;
  return `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>VT 审批请求</title>
  ${FAVICON_TAGS}
  <link rel="stylesheet" href="${base}/approve.css">
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
  <script src="${base}/libsodium.js"></script>
  <script src="${base}/common.js"></script>
  <script src="${base}/approve.js"></script>
</body>
</html>`;
}

// ── Admin HTML templates ──────────────────────────────────────────────────

// Tab bar shared by all admin pages. Every tab carries equal weight; `active`
// marks the current one.
type AdminTab = 'audit' | 'setup' | 'channels';
function adminTabs(active: AdminTab): string {
  const tab = (href: string, key: AdminTab, label: string) =>
    `<a class="tab${key === active ? ' active' : ''}" href="${href}"${key === active ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<nav class="tabs">${tab(`/${ADMIN_SEG}/audit`, 'audit', '审计')}${tab(`/${ADMIN_SEG}/setup`, 'setup', 'Passkey')}${tab(`/${ADMIN_SEG}/channels`, 'channels', '推送渠道')}</nav>`;
}

function buildAuditPage(): string {
  const base = `/${ADMIN_SEG}`;
  return `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>VT 审计</title>
  ${FAVICON_TAGS}
  <link rel="stylesheet" href="${base}/pwa/admin.css">
</head>
<body>
  <main>
    ${adminTabs('audit')}
    <p class="hint">每个挑战一行（状态：pending / approved / rejected / expired）。点击行查看完整详情。保留 90 天。</p>
    <section id="filters">
      <label>状态 <select id="f-status">
        <option value="">全部</option>
        <option value="pending">pending</option>
        <option value="approved">approved</option>
        <option value="rejected">rejected</option>
        <option value="expired">expired</option>
      </select></label>
      <label>主机 <input id="f-host" type="text" placeholder="host"></label>
      <button id="apply" type="button">查询</button>
    </section>
    <div id="table-wrap"><table id="audit"><thead><tr>
      <th>时间</th><th>状态</th><th>主机</th><th>命令</th><th>IP</th><th>DEK</th><th>延迟ms</th>
    </tr></thead><tbody id="rows"></tbody></table></div>
    <section id="actions">
      <button id="more" type="button">加载更多</button>
      <span id="status" role="status" aria-live="polite"></span>
    </section>
  </main>
  <div id="detail-backdrop" hidden><div id="detail-card" role="dialog" aria-modal="true">
    <button id="detail-close" type="button" aria-label="关闭">×</button>
    <dl id="detail-dl"></dl>
  </div></div>
  <script src="${base}/pwa/audit.js"></script>
</body>
</html>`;
}

function buildSetupPage(rpId: string, credentialsJson: string): string {
  const adminBase = `/${ADMIN_SEG}`;
  const pwaBase = `/pwa`;
  // `credentials` is the raw CREDENTIALS_JSON secret (or '' on very first
  // setup). The page parses it client-side for add/revoke; bootstrap ignores
  // it. Only wrapped (encrypted) key material is exposed — never a plaintext
  // master.
  const dataJson = escapeJsonForHtml({ rp_id: rpId, credentials: credentialsJson });
  return `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>VT — Passkey 管理</title>
  ${FAVICON_TAGS}
  <link rel="stylesheet" href="${adminBase}/pwa/admin.css">
</head>
<body>
  <script type="application/json" id="vt-data">${dataJson}</script>
  <main>
    ${adminTabs('setup')}
    <header class="page-head">
      <h1>Passkey</h1>
      <p class="hint">管理 phone 审批 ceremony 用的 Passkey（<code>CREDENTIALS_JSON</code>）。首个 Passkey 的 master 必须等于 macOS <code>mac_key</code>；新增 / 吊销自动读取当前环境变量。生成后手动 <code>wrangler secret put CREDENTIALS_JSON</code> 并 <code>deploy</code>。</p>
    </header>

    <section id="current-section" class="card">
      <div class="card-head">
        <h2>当前 Passkey</h2>
        <span id="current-meta" class="badge"></span>
      </div>
      <ul id="current-list" class="cred-list"></ul>
    </section>

    <div id="modes" role="tablist" aria-label="操作模式">
      <label><input type="radio" name="mode" value="bootstrap" checked><span>首个（bootstrap）</span></label>
      <label><input type="radio" name="mode" value="add"><span>新增</span></label>
      <label><input type="radio" name="mode" value="revoke"><span>吊销</span></label>
    </div>

    <section id="bootstrap-section" class="card">
      <div class="card-head"><h2>从 macOS Master Key 引导</h2></div>
      <p class="hint">浏览器无法独立完成这一步：master 必须取自 Mac keychain 的 <code>mac_key</code>。在 <strong>Mac 本机</strong> 执行（Touch ID 门控），按提示设置一个一次性导出口令：</p>
      <pre class="cmd"><code>vt secret export</code></pre>
      <p class="hint">把输出的 base64 与导出口令填入下方——解密只在本浏览器进行，<code>mac_key</code> 不上传。建议直接在 Mac 的浏览器里完成本页，避免跨设备复制。</p>
      <div class="field">
        <label for="master-blob">导出串（base64）</label>
        <textarea id="master-blob" rows="3" placeholder="vt secret export 的输出，60 字节 base64url"></textarea>
      </div>
      <div class="field">
        <label for="master-pass">导出口令</label>
        <input id="master-pass" type="password" placeholder="export 时设置的一次性口令">
      </div>
    </section>

    <section id="existing-section" class="card" hidden>
      <div class="card-head">
        <h2>现有 CREDENTIALS_JSON</h2>
        <span class="badge">自动读取自环境变量</span>
      </div>
      <p class="hint">已从环境变量预填，通常无需改动；为空时可手动粘贴。</p>
      <textarea id="existing" rows="6" placeholder="环境变量 CREDENTIALS_JSON 为空；如需可手动粘贴"></textarea>
    </section>

    <section id="label-section" class="field">
      <label for="label">标签</label>
      <input id="label" type="text" placeholder="便于识别，如 iphone-icloud">
    </section>

    <section id="revoke-section" class="card" hidden>
      <div class="field">
        <label for="revoke-pick">吊销条目</label>
        <select id="revoke-pick"></select>
      </div>
      <p class="warn">⚠️ 吊销 ≠ 密钥轮换：仅从允许列表移除，master_key 不变。若该 Passkey 的密文与 PRF 曾泄露，仍可离线解出同一 master_key。</p>
    </section>

    <section id="actions">
      <button id="run" type="button">生成</button>
      <button id="selfcheck" type="button" class="ghost" hidden>自检（逐条验证）</button>
    </section>
    <p id="status" role="status" aria-live="polite"></p>

    <section id="output-section" class="card" hidden>
      <div class="card-head">
        <h2>输出</h2>
        <button id="copy" type="button" class="ghost">复制</button>
      </div>
      <textarea id="output" rows="10" readonly></textarea>
      <p class="hint">复制后执行 <code>wrangler secret put CREDENTIALS_JSON</code> 再 <code>wrangler deploy</code> 生效。</p>
    </section>
  </main>
  <script src="${pwaBase}/common.js"></script>
  <script src="${adminBase}/pwa/cbor.js"></script>
  <script src="${adminBase}/pwa/setup.js"></script>
</body>
</html>`;
}

// Notification-channel generator page. Pure client-side: the operator ticks the
// channels they want, fills the fields, and the page emits the JSON secret(s) to
// paste into `wrangler secret put`. Nothing is POSTed back to the Worker.
function buildChannelsPage(pushoverSet: boolean, slackSet: boolean): string {
  const adminBase = `/${ADMIN_SEG}`;
  const pwaBase = `/pwa`;
  const dataJson = escapeJsonForHtml({ pushover_set: pushoverSet, slack_set: slackSet });
  const badge = (set: boolean) =>
    set ? `<span class="badge badge-approved">已配置</span>` : `<span class="badge">未配置</span>`;
  return `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>VT — 推送渠道</title>
  ${FAVICON_TAGS}
  <link rel="stylesheet" href="${adminBase}/pwa/admin.css">
</head>
<body>
  <script type="application/json" id="vt-data">${dataJson}</script>
  <main>
    ${adminTabs('channels')}
    <header class="page-head">
      <h1>推送渠道</h1>
      <p class="hint">审批请求会推送到此处<strong>启用并配置</strong>的所有渠道——两个渠道相互独立，可只用其一，也可同时启用。每个卡片右上角的开关控制是否启用，启用后展开填写。本页只在浏览器内生成 JSON：填好字段点「生成」，再把结果 <code>wrangler secret put</code> 成对应的环境变量。<strong>现有 secret 的明文不会回显到本页</strong>。</p>
    </header>

    <section id="pushover-card" class="card channel">
      <div class="card-head">
        <h2>Pushover</h2>
        <div class="channel-ctrl">
          ${badge(pushoverSet)}
          <label class="switch" title="启用 Pushover"><input type="checkbox" id="chk-pushover"${pushoverSet ? ' checked' : ''}><span class="slider"></span></label>
        </div>
      </div>
      <div class="channel-body" id="pushover-body"${pushoverSet ? '' : ' hidden'}>
        ${pushoverSet ? '<p class="hint keep-note">✓ 当前已配置：留空点「生成」保持不变，填入新值则覆盖。</p>' : ''}
        <p class="hint">在 <a href="https://pushover.net" target="_blank" rel="noopener">pushover.net</a> 登录后：① 主页顶部的 <strong>Your User Key</strong> 即 <code>user_key</code>；② 在 <strong>Create an Application/API Token</strong> 新建一个应用，拿到 <strong>API Token</strong> 作为 <code>app_token</code>。手机装 Pushover App 并登录同一账号即可收推送。</p>
        <div class="field">
          <label for="po-app">API Token（app_token）</label>
          <input id="po-app" type="text" placeholder="axxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" autocomplete="off" spellcheck="false">
        </div>
        <div class="field">
          <label for="po-user">User Key（user_key）</label>
          <input id="po-user" type="text" placeholder="uxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" autocomplete="off" spellcheck="false">
        </div>
      </div>
    </section>

    <section id="slack-card" class="card channel">
      <div class="card-head">
        <h2>Slack</h2>
        <div class="channel-ctrl">
          ${badge(slackSet)}
          <label class="switch" title="启用 Slack"><input type="checkbox" id="chk-slack"${slackSet ? ' checked' : ''}><span class="slider"></span></label>
        </div>
      </div>
      <div class="channel-body" id="slack-body"${slackSet ? '' : ' hidden'}>
        ${slackSet ? '<p class="hint keep-note">✓ 当前已配置：留空点「生成」保持不变，填入新值则覆盖。</p>' : ''}
        <p class="hint">用 <strong>Incoming Webhook</strong> 方式——这是单向通知（真正的「同意」仍在审批页用 Passkey 完成），所以只需一个 Webhook URL，无需 bot、无需把机器人拉进频道：</p>
        <ol class="steps">
          <li>打开 <a href="https://api.slack.com/apps" target="_blank" rel="noopener">api.slack.com/apps</a> → <strong>Create New App</strong> → <strong>From scratch</strong>，填个名字（如 <code>vt-approval</code>）并选择目标 workspace。</li>
          <li>左侧 <strong>Incoming Webhooks</strong> → 打开 <strong>Activate Incoming Webhooks</strong> 开关。</li>
          <li>页面底部 <strong>Add New Webhook to Workspace</strong> → 选择接收审批通知的频道（如 <code>#vt-approvals</code>）→ <strong>Allow</strong>。</li>
          <li>复制生成的 <strong>Webhook URL</strong>（形如 <code>https://hooks.slack.com/services/T…/B…/…</code>），粘贴到下方。</li>
        </ol>
        <p class="hint">所需「权限」就是激活 Incoming Webhooks 时自动添加的 <code>incoming-webhook</code> scope，仅能向你授权的那个频道发消息，无其它权限。换频道就重做第 3 步再换 URL 即可。</p>
        <div class="field">
          <label for="sl-webhook">Webhook URL（webhook_url）</label>
          <input id="sl-webhook" type="text" placeholder="https://hooks.slack.com/services/T…/B…/…" autocomplete="off" spellcheck="false">
        </div>
      </div>
    </section>

    <section id="actions">
      <button id="run" type="button">生成</button>
    </section>
    <p id="status" role="status" aria-live="polite"></p>

    <section id="output-section" hidden></section>
  </main>
  <script src="${pwaBase}/common.js"></script>
  <script src="${adminBase}/pwa/channels.js"></script>
</body>
</html>`;
}

// Unhandled exceptions → one structured error event + opaque 500 to caller.
app.onError((err, c) => {
  logErr('error', err, { path: new URL(c.req.url).pathname });
  return c.text('internal error', 500);
});

export default app;
