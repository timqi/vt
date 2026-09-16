// Slack Bot channel (docs/slack.md): config parse, approval message + in-place
// edit on the decision, cache-hit notice. The bot token lives in the DO config
// blob (account_admin.ts); the host is pinned to slack.com so config can never
// aim this at another origin. Slack answers HTTP 200 with `{ok:false}` on a
// logical failure, so every call checks both.

import type { ChallengeMeta, SlackConfig, SlackMsgRef } from './types';
import { buildApprovalMessage, buildCacheHitMessage } from './notify';

const TIMEOUT_MS = 6000;

export type SlackState = 'pending' | 'approved' | 'rejected' | 'expired';

// Color is the only state carrier Slack offers on a message: the attachment's
// left bar.
const STATE: Record<SlackState, { emoji: string; label: string; color: string }> = {
  pending:  { emoji: '⏳', label: 'pending', color: '#e8912d' },
  approved: { emoji: '✅', label: 'approved', color: '#2eb67d' },
  rejected: { emoji: '❌', label: 'rejected', color: '#e01e5a' },
  expired:  { emoji: '⌛', label: 'expired', color: '#868686' },
};
const CACHE_HIT_COLOR = '#1d9bd1';

/** Validate a console PUT body. `bot_token` may be omitted to keep `prev`'s. */
export function parseSlackConfig(raw: unknown, prev: SlackConfig | null): SlackConfig | string {
  if (typeof raw !== 'object' || raw === null) return 'not an object';
  const o = raw as Record<string, unknown>;
  const botToken = o.bot_token === undefined || o.bot_token === '' ? prev?.bot_token : o.bot_token;
  if (typeof botToken !== 'string' || !botToken) return 'missing bot_token';
  if (/\s/.test(botToken) || botToken.length > 256) return 'bot_token must be one token without whitespace';
  if (typeof o.channel !== 'string' || !o.channel || /\s/.test(o.channel) || o.channel.length > 64) return 'missing channel';
  const mention = o.mention ?? [];
  // Each id lands raw inside `<@…>` mrkdwn; refuse anything that could close the tag.
  if (!Array.isArray(mention) || mention.length > 20
    || mention.some(m => typeof m !== 'string' || !m || m.length > 32 || /[\s<>&|]/.test(m))) {
    return 'mention must be an array of user ids';
  }
  return { bot_token: botToken, channel: o.channel, mention: mention as string[] };
}

// One bounded POST; never throws. `error` from Slack is the diagnosis (e.g.
// `channel_not_found`); the transport status wins when HTTP itself failed.
async function api(
  method: 'chat.postMessage' | 'chat.update', body: unknown, token: string,
): Promise<{ warning: string; data: Record<string, unknown> }> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(`https://slack.com/api/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
    let data: Record<string, unknown> = {};
    try { data = JSON.parse(await resp.text()) as Record<string, unknown>; } catch { /* non-JSON body */ }
    if (!resp.ok) return { warning: `http ${resp.status}`, data };
    if (data.ok !== true) return { warning: typeof data.error === 'string' ? `slack ${data.error}` : 'not ok', data };
    return { warning: '', data };
  } catch {
    return { warning: 'fetch failed', data: {} };
  } finally {
    clearTimeout(timer);
  }
}

// Context is client-reported, rendered as mrkdwn because plain_text collapses
// newlines; escaping `& < >` closes the link/entity injection Slack parses.
const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function message(
  state: SlackState, meta: ChallengeMeta, salts: number,
  opts: { approveUrl?: string; mention?: string[]; latencyMs?: number },
): { text: string; attachments: unknown[] } {
  const s = STATE[state];
  const { title, body } = buildApprovalMessage(meta.op_kind, meta, salts);
  const lines = [body];
  if (state === 'approved' && typeof opts.latencyMs === 'number') lines.push(`approved on the phone in ${opts.latencyMs} ms`);
  if (state === 'rejected') lines.push('rejected on the phone');
  if (state === 'expired') lines.push('expired without a decision');
  const blocks: unknown[] = [];
  if (state === 'pending' && opts.mention?.length) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: opts.mention.map(id => `<@${id}>`).join(' ') } });
  }
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: esc(lines.join('\n')) } });
  // A plain link button: approval still needs the Passkey on that page, so no
  // interactivity endpoint exists for Slack to call back.
  if (state === 'pending' && opts.approveUrl) {
    blocks.push({ type: 'actions', elements: [{ type: 'button', style: 'primary', url: opts.approveUrl, text: { type: 'plain_text', text: 'Approve' } }] });
  }
  return { text: `${s.emoji} ${title} — ${s.label}`, attachments: [{ color: s.color, blocks }] };
}

/** Post the pending message; the returned handle is what a later edit needs. */
export async function sendApproval(
  cfg: SlackConfig, meta: ChallengeMeta, salts: number, approveUrl: string,
): Promise<SlackMsgRef | string> {
  const { warning, data } = await api('chat.postMessage',
    { channel: cfg.channel, ...message('pending', meta, salts, { approveUrl, mention: cfg.mention }) }, cfg.bot_token);
  if (warning) return warning;
  if (typeof data.ts !== 'string' || !data.ts) return 'no ts';
  return { channel: typeof data.channel === 'string' && data.channel ? data.channel : cfg.channel, ts: data.ts };
}

/** Rewrite a sent message to its terminal state. '' on success. */
export async function editApproval(
  cfg: SlackConfig, ref: SlackMsgRef, state: Exclude<SlackState, 'pending'>,
  meta: ChallengeMeta, salts: number, latencyMs?: number,
): Promise<string> {
  return (await api('chat.update', { ...ref, ...message(state, meta, salts, { latencyMs }) }, cfg.bot_token)).warning;
}

/** A terminal FYI: no mention, no button, never edited. '' on success. */
export async function sendCacheHit(
  cfg: SlackConfig, meta: ChallengeMeta, salts: number, note?: string, names: string[] = [],
): Promise<string> {
  const { title, body } = buildCacheHitMessage(meta, salts, note, names);
  return (await api('chat.postMessage', {
    channel: cfg.channel, text: title,
    attachments: [{ color: CACHE_HIT_COLOR, blocks: [{ type: 'section', text: { type: 'mrkdwn', text: esc(body) } }] }],
  }, cfg.bot_token)).warning;
}
