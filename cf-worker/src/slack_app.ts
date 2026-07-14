// Slack "app" (Bot token + Web API) notification channel: config parse + send +
// in-place edit.
//
// This is the STATEFUL Slack channel, the counterpart to feishu.ts — distinct
// from the one-way Incoming Webhook in slack.ts. Like Feishu it uses a bot
// identity (a `xoxb-…` bot token) to (1) @-mention approvers on a request and
// (2) edit the message in place on the decision (✅ approved / ❌ rejected /
// ⌛ expired) via chat.update. Editing needs the sent message `ts`, so — like
// feishu.ts — these functions are called from inside the DO where the challenge
// lifecycle lives, and the returned {channel, ts} is stored on the challenge.
//
// Unlike Feishu, a Slack bot token is long-lived (no tenant_access_token
// exchange), so there is NO token cache / KV here — the config carries the
// bearer directly.
//
// Slack error convention (NOT HTTP-status based): the Web API returns HTTP 200
// with a body `{ok:false, error:"…"}` on logical failure. So every call checks
// BOTH the transport status AND `ok === true`.

import { ChallengeMeta, SlackAppMsgRef } from './types';
import { metaLines, buildCacheHitLines } from './notify';

export type { SlackAppMsgRef };

// Bound every outbound fetch (see feishu.ts / pushover.ts). Slack calls are
// fired via ctx.waitUntil off the ceremony path, but a hung endpoint must still
// not pin a request forever.
const TIMEOUT_MS = 6000;

export type SlackAppState = 'pending' | 'approved' | 'rejected' | 'expired';

export interface SlackAppConfig {
  botToken: string;
  channel: string;
  mention: string[];   // user ids to @ on approval requests; [] = none
}

// SlackAppMsgRef (the {channel, ts} edit handle) lives in types.ts so the DO's
// Challenge.slackapp field and this module's send return type share one shape.

// Parse the SLACK_APP_JSON secret. Same tri-state contract as
// parseFeishuConfig / parseSlackConfig: absent → not enabled; present-but-bad →
// error; valid → config.
export function parseSlackAppConfig(raw: string | undefined): {
  config: SlackAppConfig | null;
  error: string | null;
} {
  if (!raw || !raw.trim()) return { config: null, error: null };
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { return { config: null, error: 'invalid JSON' }; }
  if (typeof obj !== 'object' || obj === null) return { config: null, error: 'not an object' };
  const o = obj as Record<string, unknown>;

  const botToken = o['bot_token'];
  const channel = o['channel'];
  if (typeof botToken !== 'string' || !botToken) return { config: null, error: 'missing bot_token' };
  // A bot token is a bearer credential carried in the Authorization header —
  // reject whitespace (a pasted webhook URL / stray newline would break the
  // header or, worse, be a webhook_url in the wrong field).
  if (/\s/.test(botToken)) return { config: null, error: 'bot_token must not contain whitespace' };
  if (typeof channel !== 'string' || !channel) return { config: null, error: 'missing channel' };
  if (/\s/.test(channel)) return { config: null, error: 'channel must not contain whitespace' };

  let mention: string[] = [];
  if (o['mention'] !== undefined) {
    if (!Array.isArray(o['mention']) || o['mention'].some((m) => typeof m !== 'string' || !m)) {
      return { config: null, error: 'mention must be an array of non-empty user-id strings' };
    }
    // Each id is interpolated raw into `<@…>` (mrkdwn), so reject any char that
    // could break out of the mention tag: angle brackets, ampersand, the `|`
    // Slack uses for `<@ID|label>` link syntax, and whitespace. Slack user ids
    // are UPPERCASE-alphanumeric (Uxxxx / Wxxxx); this stays permissive but
    // closes the injection path.
    if ((o['mention'] as string[]).some((m) => /[\s<>&|]/.test(m))) {
      return { config: null, error: 'mention ids must not contain angle brackets, ampersands, pipes, or whitespace' };
    }
    mention = o['mention'] as string[];
  }

  return { config: { botToken, channel, mention }, error: null };
}

// One bounded POST to the Slack Web API. The host is pinned to slack.com — never
// derived from config — so a bad secret can't turn this channel into an SSRF
// primitive (same principle as slack.ts pinning hooks.slack.com and feishu.ts
// pinning the base enum). Returns a discriminated result; never throws.
async function apiCall(
  method: 'chat.postMessage' | 'chat.update',
  body: unknown,
  token: string,
): Promise<{ httpOk: boolean; status: number; ok: boolean; data: Record<string, unknown> }> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(`https://slack.com/api/${method}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
    let parsed: Record<string, unknown> = {};
    try { parsed = JSON.parse(await resp.text()) as Record<string, unknown>; } catch { /* non-JSON body */ }
    // Slack ALWAYS returns a boolean `ok`. A 2xx body lacking `ok` is anomalous
    // (edge/proxy/shape change) → treat as failure. `error` is deliberately NOT
    // surfaced to callers — it can echo config detail and the status/ok are
    // enough to diagnose.
    const ok = parsed['ok'] === true;
    return { httpOk: resp.ok, status: resp.status, ok, data: parsed };
  } catch {
    return { httpOk: false, status: 0, ok: false, data: {} };
  } finally {
    clearTimeout(timer);
  }
}

// Convert an apiCall result into a caller-facing warning ('' = success). Shared
// by the edit + cache-hit paths so the wording can't drift. `error` is echoed
// (it names the Slack failure, e.g. `channel_not_found`) but the transport
// status is preferred when the HTTP layer itself failed.
function resWarning(res: Awaited<ReturnType<typeof apiCall>>): string {
  if (!res.httpOk) return `http ${res.status}`;
  if (!res.ok) {
    const err = res.data['error'];
    return typeof err === 'string' && err ? `slack ${err}` : 'not ok';
  }
  return '';
}

// ── Card rendering (Block Kit inside a colored attachment) ───────────────────

// Slack blocks carry no per-message color, so state is conveyed by the colored
// left bar of a secondary attachment (mirroring Feishu's colored header).
const HEADER: Record<SlackAppState, { emoji: string; label: string; color: string }> = {
  pending:  { emoji: '⏳', label: '待审批', color: '#e8912d' },
  approved: { emoji: '✅', label: '已批准', color: '#2eb67d' },
  rejected: { emoji: '❌', label: '已拒绝', color: '#e01e5a' },
  expired:  { emoji: '⌛', label: '已过期', color: '#868686' },
};

const CACHE_HIT_COLOR = '#1d9bd1';

// Slack mrkdwn escaping: neutralize the three chars that drive link/entity
// parsing (`<url|label>` link syntax and HTML-ish entities) so caller-supplied
// context (command / pwd / …) cannot inject a clickable link or fabricate
// worker-authoritative-looking markup into the message a human reads to approve.
// We render context as `mrkdwn` (not `plain_text`) only because Slack's
// plain_text section objects COLLAPSE embedded `\n` into spaces — that
// flattening (every field crammed onto one line) is the bug this file fixes.
// `*` `_` `~` `` ` `` are left alone: at worst they yield cosmetic bold/italic,
// never a link, so they are not a security concern.
function escapeMrkdwn(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export interface EditExtra {
  approverLabel?: string;  // Passkey label that approved (state=approved)
  latencyMs?: number;      // ceremony latency (state=approved/rejected)
}

// Build the Block Kit blocks + the attachment color for a given state.
//
// The title lives ONLY in the message's top-level `text` (see sendApprovalCard /
// editCard). We deliberately do NOT emit a `header` block here — it would repeat
// the title a second time inside the colored attachment ("引用" quote line).
// State is still conveyed twice, harmlessly: by the title's leading emoji
// (✅/❌/⏳/⌛) and by the attachment's colored left bar.
//
// SECURITY: the context block (who/pwd/cmd/ssh/ip/reason) is caller-supplied.
// It is rendered as `mrkdwn` — Slack's `plain_text` section objects collapse
// embedded `\n` into spaces, which flattened every field onto one line — but
// every context value is run through escapeMrkdwn() first, so a hostile CLI
// still cannot inject a link or fabricate worker-authoritative markup (same
// guarantee plain_text gave for free). The @-mention line is also `mrkdwn` (it
// must be, for the `<@id>` tag) and its ids are charset-validated in
// parseSlackAppConfig so they cannot break out of the tag. The context lines
// reuse notify.ts's shared metaLines() so this message and the webhook text can
// never drift.
function buildMessage(
  state: SlackAppState,
  opKind: string,
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
  opts: { approveUrl?: string; mention?: string[]; extra?: EditExtra },
): { text: string; color: string; blocks: unknown[] } {
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

  const blocks: unknown[] = [];
  // @-mentions only while pending (an approval REQUEST). mrkdwn is required for
  // the <@id> tag; ids are validated (parseSlackAppConfig) so they can't inject.
  if (state === 'pending' && opts.mention && opts.mention.length) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: opts.mention.map((id) => `<@${id}>`).join(' ') },
    });
  }
  // One field per line: mrkdwn honors `\n` (plain_text does not); escapeMrkdwn
  // keeps the caller-supplied context injection-safe.
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: escapeMrkdwn(context.join('\n')) } });
  // The approval button is a pure URL open-link — NOT an interactive action — so
  // no inbound Worker endpoint / request URL is required (same as Feishu's
  // open-link button). Clicking opens /a/<token>; the real approval is still
  // gated by a registered Passkey + PRF on that page.
  if (state === 'pending' && opts.approveUrl) {
    blocks.push({
      type: 'actions',
      elements: [{
        type: 'button',
        text: { type: 'plain_text', text: '去审批' },
        style: 'primary',
        url: opts.approveUrl,
      }],
    });
  }

  return { text: title, color: h.color, blocks };
}

// ── Public API (called from inside the DO) ────────────────────────────────────

// Send the pending approval message. Returns {channel, ts} (for a later edit) or
// null on any failure (best-effort; a warning is the caller's to log).
export async function sendApprovalCard(
  cfg: SlackAppConfig,
  opKind: string,
  meta: ChallengeMeta,
  approveUrl: string,
): Promise<SlackAppMsgRef | null> {
  const { text, color, blocks } = buildMessage('pending', opKind, meta, { approveUrl, mention: cfg.mention });
  const res = await apiCall('chat.postMessage', {
    channel: cfg.channel,
    text,                                    // fallback (notifications / a11y)
    attachments: [{ color, blocks }],
  }, cfg.botToken);
  if (!res.httpOk || !res.ok) return null;
  const ts = res.data['ts'];
  // Prefer the channel ID echoed back (robust when config `channel` was a name);
  // fall back to the configured value.
  const channel = typeof res.data['channel'] === 'string' && res.data['channel'] ? res.data['channel'] as string : cfg.channel;
  return typeof ts === 'string' && ts ? { channel, ts } : null;
}

// Edit a previously-sent message to its terminal state. Returns '' on success or
// a short warning string. Caller must have a stored {channel, ts}.
export async function editCard(
  cfg: SlackAppConfig,
  ref: SlackAppMsgRef,
  state: SlackAppState,
  opKind: string,
  meta: ChallengeMeta,
  extra: EditExtra = {},
): Promise<string> {
  const { text, color, blocks } = buildMessage(state, opKind, meta, { extra });
  const res = await apiCall('chat.update', {
    channel: ref.channel,
    ts: ref.ts,
    text,
    attachments: [{ color, blocks }],
  }, cfg.botToken);
  return resWarning(res);
}

// Send a compact cache-hit (免审批) notice — one short message, no @, no button,
// no edit lifecycle (it is a terminal FYI). Returns '' or a short warning.
export async function sendCacheHitNotice(
  cfg: SlackAppConfig,
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd'>,
  salts: number,
  note?: string,
): Promise<string> {
  // Reuse the shared cache-hit builder so the title + lines never drift from the
  // Pushover/Slack/Feishu text.
  const { title, lines } = buildCacheHitLines(meta, salts, note);
  const res = await apiCall('chat.postMessage', {
    channel: cfg.channel,
    text: title,
    attachments: [{
      color: CACHE_HIT_COLOR,
      // Title lives in top-level `text`; no repeated header block. Context is
      // mrkdwn (plain_text collapses `\n`) with escapeMrkdwn keeping the
      // caller-supplied command/pwd injection-safe.
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: escapeMrkdwn(lines.join('\n')) } },
      ],
    }],
  }, cfg.botToken);
  return resWarning(res);
}
