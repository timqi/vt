// Feishu / Lark notification channel: config parse + send + in-place edit.
//
// Unlike pushover.ts / slack.ts (stateless fire-and-forget webhooks), Feishu is
// STATEFUL: to @-mention approvers and to edit the card in place on the final
// decision we must use the self-built-app (bot) API, which needs a cached
// tenant_access_token and the message_id of the sent card. So these functions
// take a small key/value accessor (backed by DO storage) for the token cache,
// and are called from inside the DO where the challenge lifecycle lives.
//
// Feishu error convention (NOT like Slack): the API returns {code,msg,data}
// with code !== 0 meaning failure — sometimes at HTTP 200, sometimes HTTP 400.
// So every call checks BOTH the HTTP status AND code === 0.

import { ChallengeMeta } from './types';
import { metaLines, buildCacheHitLines } from './notify';

// Bound every outbound fetch (see pushover.ts). Feishu calls are fired via
// ctx.waitUntil / Promise.allSettled off the ceremony path, but a hung endpoint
// must still not pin a request forever.
const TIMEOUT_MS = 6000;

// Refresh the cached tenant_access_token when fewer than this many ms remain.
const TOKEN_SKEW_MS = 60_000;

// Feishu error codes that mean "your tenant_access_token is invalid/expired" —
// evict the cache and retry once. Feishu invalidates outstanding tokens on an
// app_secret reset, so TTL-based refresh alone is not enough.
const TOKEN_ERR_CODES = new Set([99991661, 99991663, 99991664, 99991665, 99991677]);

export type FeishuState = 'pending' | 'approved' | 'rejected' | 'expired';

export interface FeishuConfig {
  appId: string;
  appSecret: string;
  receiveId: string;
  receiveIdType: 'chat_id' | 'open_id' | 'user_id' | 'email';
  mention: string[];   // open_ids to @ on approval requests; [] = none
  base: 'feishu' | 'larksuite';
}

// A tiny persistent KV, backed by DO storage in production. get/put may throw
// (storage errors) — callers guard accordingly.
export interface Kv {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
}

interface CachedToken { token: string; exp_ms: number }

const RECEIVE_ID_TYPES = new Set(['chat_id', 'open_id', 'user_id', 'email']);

// Parse the FEISHU_JSON secret. Same tri-state contract as parsePushoverConfig /
// parseSlackConfig: absent → not enabled; present-but-bad → error; valid → config.
export function parseFeishuConfig(raw: string | undefined): {
  config: FeishuConfig | null;
  error: string | null;
} {
  if (!raw || !raw.trim()) return { config: null, error: null };
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { return { config: null, error: 'invalid JSON' }; }
  if (typeof obj !== 'object' || obj === null) return { config: null, error: 'not an object' };
  const o = obj as Record<string, unknown>;

  const appId = o['app_id'];
  const appSecret = o['app_secret'];
  const receiveId = o['receive_id'];
  if (typeof appId !== 'string' || !appId) return { config: null, error: 'missing app_id' };
  if (typeof appSecret !== 'string' || !appSecret) return { config: null, error: 'missing app_secret' };
  if (typeof receiveId !== 'string' || !receiveId) return { config: null, error: 'missing receive_id' };

  let receiveIdType: FeishuConfig['receiveIdType'] = 'chat_id';
  if (o['receive_id_type'] !== undefined) {
    if (typeof o['receive_id_type'] !== 'string' || !RECEIVE_ID_TYPES.has(o['receive_id_type'])) {
      return { config: null, error: 'receive_id_type must be one of chat_id|open_id|user_id|email' };
    }
    receiveIdType = o['receive_id_type'] as FeishuConfig['receiveIdType'];
  }

  let mention: string[] = [];
  if (o['mention'] !== undefined) {
    if (!Array.isArray(o['mention']) || o['mention'].some((m) => typeof m !== 'string' || !m)) {
      return { config: null, error: 'mention must be an array of non-empty open_id strings' };
    }
    // Each id is interpolated raw into `<at id="…">` (lark_md), so reject any
    // char that could break out of the tag/attribute (quote, angle bracket,
    // ampersand, whitespace). open_ids are ou_-prefixed alphanumerics; this
    // stays permissive but closes the injection path.
    if ((o['mention'] as string[]).some((m) => /[\s"'<>&]/.test(m))) {
      return { config: null, error: 'mention ids must not contain quotes, angle brackets, ampersands, or whitespace' };
    }
    mention = o['mention'] as string[];
  }

  let base: FeishuConfig['base'] = 'feishu';
  if (o['base'] !== undefined) {
    if (o['base'] !== 'feishu' && o['base'] !== 'larksuite') {
      return { config: null, error: 'base must be feishu or larksuite' };
    }
    base = o['base'];
  }

  return { config: { appId, appSecret, receiveId, receiveIdType, mention, base }, error: null };
}

// The API host is derived ONLY from the `base` enum — never from a user-supplied
// URL — so a bad secret can't turn this channel into an SSRF primitive (same
// principle as slack.ts pinning hooks.slack.com).
function apiBase(cfg: FeishuConfig): string {
  return cfg.base === 'larksuite' ? 'https://open.larksuite.com' : 'https://open.feishu.cn';
}

// One bounded POST/PATCH to the Feishu Open API. Returns a discriminated result;
// never throws (transport errors are captured). `code` is the Feishu body code
// (0 = success); `httpOk` is the transport-level status.
async function apiCall(
  url: string,
  method: 'POST' | 'PATCH',
  body: unknown,
  token: string | null,
): Promise<{ httpOk: boolean; status: number; code: number; data: Record<string, unknown> }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json; charset=utf-8' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, { method, headers, body: JSON.stringify(body), signal: ctl.signal });
    let parsed: Record<string, unknown> = {};
    try { parsed = JSON.parse(await resp.text()) as Record<string, unknown>; } catch { /* non-JSON body */ }
    // Feishu ALWAYS returns a numeric `code` (0 = success). A 2xx body lacking
    // `code` is anomalous (edge/proxy/shape change), so treat it as failure (-1)
    // rather than optimistically as success — an editCard must not report '' for
    // a response that never confirmed the edit. `msg` is deliberately NOT
    // surfaced — Feishu's error message can echo config detail, and no caller
    // needs it (the status/code are enough to diagnose).
    const code = typeof parsed['code'] === 'number' ? parsed['code'] as number : -1;
    const data = (typeof parsed['data'] === 'object' && parsed['data']) ? parsed['data'] as Record<string, unknown> : {};
    return { httpOk: resp.ok, status: resp.status, code, data };
  } catch {
    return { httpOk: false, status: 0, code: -1, data: {} };
  } finally {
    clearTimeout(timer);
  }
}

// Fetch (and cache) a tenant_access_token. `force` bypasses the cache after a
// token-invalid API error. On success the token endpoint returns the token +
// its TTL (`expire`, seconds) at the TOP level (not under data).
async function tenantToken(cfg: FeishuConfig, kv: Kv, now: number, force = false): Promise<string | null> {
  const key = `feishu:tat:${cfg.appId}`;
  if (!force) {
    try {
      const cached = await kv.get<CachedToken>(key);
      if (cached && cached.token && cached.exp_ms - now > TOKEN_SKEW_MS) return cached.token;
    } catch { /* fall through to fetch */ }
  }
  const url = `${apiBase(cfg)}/open-apis/auth/v3/tenant_access_token/internal`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  let parsed: Record<string, unknown> = {};
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ app_id: cfg.appId, app_secret: cfg.appSecret }),
      signal: ctl.signal,
    });
    try { parsed = JSON.parse(await resp.text()) as Record<string, unknown>; } catch { /* non-JSON */ }
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
  if (parsed['code'] !== 0) return null;
  const token = parsed['tenant_access_token'];
  const expire = parsed['expire'];
  if (typeof token !== 'string' || !token) return null;
  const ttlS = typeof expire === 'number' && expire > 0 ? expire : 7200;
  try { await kv.put(key, { token, exp_ms: now + ttlS * 1000 } satisfies CachedToken); } catch { /* best-effort */ }
  return token;
}

// Run an authenticated API call, transparently refreshing the token once on a
// token-invalid error (99991661/99991663/…) or HTTP 401.
async function withToken(
  cfg: FeishuConfig,
  kv: Kv,
  now: number,
  run: (token: string) => Promise<Awaited<ReturnType<typeof apiCall>>>,
): Promise<Awaited<ReturnType<typeof apiCall>> | null> {
  let token = await tenantToken(cfg, kv, now);
  if (!token) return null;
  let res = await run(token);
  if (res.status === 401 || TOKEN_ERR_CODES.has(res.code)) {
    token = await tenantToken(cfg, kv, now, true);
    if (!token) return res;
    res = await run(token);
  }
  return res;
}

// ── Card rendering ──────────────────────────────────────────────────────────

const HEADER: Record<FeishuState, { emoji: string; label: string; template: string }> = {
  pending:  { emoji: '⏳', label: '待审批',  template: 'orange' },
  approved: { emoji: '✅', label: '已批准',  template: 'green' },
  rejected: { emoji: '❌', label: '已拒绝',  template: 'red' },
  expired:  { emoji: '⌛', label: '已过期',  template: 'grey' },
};

export interface EditExtra {
  approverLabel?: string;  // Passkey label that approved (state=approved)
  latencyMs?: number;      // ceremony latency (state=approved/rejected)
}

// Build the interactive card. `config.update_multi` makes the in-place PATCH
// visible to ALL recipients of a group/shared card. The approval button is a
// pure URL open-link ("跳转交互") — NOT a callback action — so no inbound Worker
// endpoint is required and no new attack surface is introduced.
//
// SECURITY: the context block (who/pwd/cmd/ssh/ip/reason) is caller-supplied and
// is rendered as `plain_text`, NOT `lark_md` — so a hostile CLI cannot inject
// Markdown links or fabricate worker-authoritative-looking lines into the card a
// human reads to approve. Only the @-mention line is `lark_md` (it must be, for
// the `<at>` tag), and its ids are charset-validated in parseFeishuConfig so they
// cannot break out of the tag/attribute. The context lines reuse notify.ts's
// shared metaLines() so the card and the webhook text can never drift.
function buildCard(
  state: FeishuState,
  opKind: string,
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
  opts: { approveUrl?: string; mention?: string[]; extra?: EditExtra },
): unknown {
  const h = HEADER[state];
  const title = `${h.emoji} VT 审批${opKind ? `: ${opKind}` : ''} — ${h.label}`;

  const context = metaLines(meta);
  if (state === 'approved') {
    const bits: string[] = [];
    if (opts.extra?.approverLabel) bits.push(`批准人(Passkey): ${opts.extra.approverLabel}`);
    if (typeof opts.extra?.latencyMs === 'number') bits.push(`用时 ${opts.extra.latencyMs} ms`);
    if (bits.length) context.push(bits.join(' · '));
  } else if (state === 'rejected') {
    context.push('已在手机端拒绝');
  } else if (state === 'expired') {
    context.push('审批超时未处理');
  }

  const elements: unknown[] = [];
  // @-mentions only while pending (an approval REQUEST). lark_md is required for
  // the <at> tag; ids are validated (parseFeishuConfig) so they can't inject markup.
  if (state === 'pending' && opts.mention && opts.mention.length) {
    elements.push({
      tag: 'div',
      text: { tag: 'lark_md', content: opts.mention.map((id) => `<at id="${id}"></at>`).join(' ') },
    });
  }
  elements.push({ tag: 'div', text: { tag: 'plain_text', content: context.join('\n') } });
  if (state === 'pending' && opts.approveUrl) {
    elements.push({
      tag: 'action',
      actions: [{
        tag: 'button',
        text: { tag: 'plain_text', content: '去审批' },
        type: 'primary',
        url: opts.approveUrl,
      }],
    });
  }

  return {
    config: { update_multi: true, wide_screen_mode: true },
    header: { template: h.template, title: { tag: 'plain_text', content: title } },
    elements,
  };
}

// ── Public API (called from inside the DO) ────────────────────────────────────

// Send the pending approval card. Returns the message_id (for a later edit) or
// null on any failure (best-effort; a warning is the caller's to log).
export async function sendApprovalCard(
  cfg: FeishuConfig,
  kv: Kv,
  now: number,
  opKind: string,
  meta: ChallengeMeta,
  approveUrl: string,
): Promise<string | null> {
  const card = buildCard('pending', opKind, meta, { approveUrl, mention: cfg.mention });
  const url = `${apiBase(cfg)}/open-apis/im/v1/messages?receive_id_type=${encodeURIComponent(cfg.receiveIdType)}`;
  const res = await withToken(cfg, kv, now, (token) => apiCall(url, 'POST', {
    receive_id: cfg.receiveId,
    msg_type: 'interactive',
    content: JSON.stringify(card),
  }, token));
  if (!res || !res.httpOk || res.code !== 0) return null;
  const id = res.data['message_id'];
  return typeof id === 'string' && id ? id : null;
}

// Edit a previously-sent card to its terminal state. Returns '' on success or a
// short warning string. Caller must have a stored message_id.
export async function editCard(
  cfg: FeishuConfig,
  kv: Kv,
  now: number,
  messageId: string,
  state: FeishuState,
  opKind: string,
  meta: ChallengeMeta,
  extra: EditExtra = {},
): Promise<string> {
  const card = buildCard(state, opKind, meta, { extra });
  const url = `${apiBase(cfg)}/open-apis/im/v1/messages/${encodeURIComponent(messageId)}`;
  const res = await withToken(cfg, kv, now, (token) => apiCall(url, 'PATCH', {
    content: JSON.stringify(card),
  }, token));
  if (!res) return 'token unavailable';
  if (!res.httpOk) return `http ${res.status}`;
  if (res.code !== 0) return `code ${res.code}`;
  return '';
}

// Send a compact cache-hit (免审批) notice — one short card, no @, no button, no
// edit lifecycle (it is a terminal FYI). Returns '' or a short warning.
export async function sendCacheHitNotice(
  cfg: FeishuConfig,
  kv: Kv,
  now: number,
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd'>,
  salts: number,
): Promise<string> {
  // Reuse the shared cache-hit builder so the card title + lines never drift
  // from the Pushover/Slack text.
  const { title, lines } = buildCacheHitLines(meta, salts);
  const card = {
    config: { wide_screen_mode: true },
    // plain_text (NOT lark_md): command/pwd are caller-supplied, so rendering as
    // Markdown would let a hostile CLI inject links/markup into the notice.
    header: { template: 'blue', title: { tag: 'plain_text', content: title } },
    elements: [{ tag: 'div', text: { tag: 'plain_text', content: lines.join('\n') } }],
  };
  const url = `${apiBase(cfg)}/open-apis/im/v1/messages?receive_id_type=${encodeURIComponent(cfg.receiveIdType)}`;
  const res = await withToken(cfg, kv, now, (token) => apiCall(url, 'POST', {
    receive_id: cfg.receiveId,
    msg_type: 'interactive',
    content: JSON.stringify(card),
  }, token));
  if (!res) return 'token unavailable';
  if (!res.httpOk) return `http ${res.status}`;
  if (res.code !== 0) return `code ${res.code}`;
  return '';
}
