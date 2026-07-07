// Multi-channel approval notifications. Channels are independent and opt-in:
// each is enabled by its own JSON secret, both can be on at once, and a failure
// in one never blocks the others (delivery is best-effort / non-fatal).

import { Env, ChallengeMeta } from './types';
import { parsePushoverConfig, notifyPushover } from './pushover';
import { parseSlackConfig, notifySlack } from './slack';

// Truncate the aggregated warning before it's logged upstream.
function truncate(s: string, max = 512): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

// The shared context lines (who / pwd / cmd / ssh / ip / reason) that every
// notification body carries. Approval and cache-hit notices differ only in their
// title and trailing line, so they build on this common block — keeping the two
// from silently drifting if a field is added later. Exported so feishu.ts renders
// the SAME context block (as plain_text) rather than keeping a third copy.
export function metaLines(
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
): string[] {
  const who = [meta.user, meta.host].filter(Boolean).join('@');
  const lines: string[] = [];
  if (who) lines.push(who);
  if (meta.pwd) lines.push(`pwd: ${meta.pwd}`);
  if (meta.command) {
    // The CLI sends `command` as a self-labelled multi-line body
    // (`op: …\nfile: …\ncmd: …\nreason: …`); prefixing with another `cmd:`
    // would duplicate the labels. Inline single-line legacy commands.
    lines.push(meta.command.includes('\n') ? meta.command : `cmd: ${meta.command}`);
  }
  if (meta.ssh_client) lines.push(`ssh: ${meta.ssh_client}`);
  if (meta.ip) lines.push(`ip: ${meta.ip}`);
  if (meta.reason) lines.push(`reason: ${meta.reason}`);
  return lines;
}

// Compose the human-facing approval message once; every channel reuses it.
export function buildApprovalMessage(
  opKind: string,
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
  approveUrl: string,
): { title: string; body: string } {
  const title = opKind ? `VT 审批: ${opKind}` : 'VT 审批请求';
  const lines = metaLines(meta);
  lines.push(approveUrl);
  return { title, body: lines.join('\n') };
}

// Compose the cache-hit message. A DEK-cache hit serves a decrypt WITHOUT a
// phone tap (the approver granted a TTL earlier), so this is a security-relevant
// "FYI: auto-decrypt happened" notice, not an approval request — there is no
// approve URL to tap and no action to take. The title is distinct so an operator
// can tell at a glance it was served from cache.
// Shared cache-hit content (title + context lines). Exported so feishu.ts's
// card renders the SAME title and lines as the Pushover/Slack text — the whole
// point of a shared builder is that the two can never drift. Compact — a cache
// hit is a terminal FYI, not an actionable approval, so it drops the
// ssh/ip/reason lines and leads with a one-line summary (who · N records · cache
// note), then the two highest-signal fields pwd + cmd (what ran, and where). No
// @-mention anywhere on this path. The durable audit row keeps the full context.
export function buildCacheHitLines(
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd'>,
  salts: number,
): { title: string; lines: string[] } {
  const title = meta.op_kind ? `VT 缓存命中(免审批): ${meta.op_kind}` : 'VT 缓存命中(免审批解密)';
  const who = [meta.user, meta.host].filter(Boolean).join('@');
  const head: string[] = [];
  if (who) head.push(who);
  head.push(`${salts} 条`);
  head.push('缓存命中，无手机审批');
  const lines: string[] = [head.join(' · ')];
  if (meta.pwd) lines.push(`pwd: ${meta.pwd}`);
  // Same self-labelled-multi-line handling as metaLines above.
  if (meta.command) lines.push(meta.command.includes('\n') ? meta.command : `cmd: ${meta.command}`);
  return { title, lines };
}

export function buildCacheHitMessage(
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd'>,
  salts: number,
): { title: string; body: string } {
  const { title, lines } = buildCacheHitLines(meta, salts);
  return { title, body: lines.join('\n') };
}

// Fan out one composed message to every configured channel in parallel. Returns
// '' when every enabled channel succeeded (or none was enabled), or a single
// aggregated, channel-prefixed warning string on a genuine config/delivery error.
//
// NOTE: this path only knows about the STATELESS channels (Pushover, Slack
// webhook). The STATEFUL channels (Slack App `SLACK_APP_JSON`, Feishu
// `FEISHU_JSON`) are dispatched independently from the DO's opCreate via
// waitUntil (see do_account.ts) and are invisible here. So fanOut MUST NOT try
// to decide whether "any channel is configured" — it can't see half of them,
// and a stateful-only deployment would produce a false "no channel" warning.
async function fanOut(
  env: Env,
  title: string,
  body: string,
): Promise<string> {
  const warnings: string[] = [];

  const po = parsePushoverConfig(env.PUSHOVER_JSON);
  const sl = parseSlackConfig(env.SLACK_JSON);
  if (po.error) warnings.push(`pushover config: ${po.error}`);
  if (sl.error) warnings.push(`slack config: ${sl.error}`);

  // Each task is .catch()-guarded so a notification channel can never reject
  // Promise.all and abort the awaited ceremony path (index.ts awaits
  // notifyApproval on /api/challenge). Delivery is strictly best-effort.
  const tasks: Promise<void>[] = [];
  if (po.config) {
    tasks.push(notifyPushover(po.config, title, body)
      .then((w) => { if (w) warnings.push(`pushover: ${w}`); })
      // Static label, not the raw error: this guard is only reachable from a
      // future .then() bug, and an interpolated error could in theory carry a
      // URL/secret. notifyPushover already returns its own diagnostics.
      .catch(() => { warnings.push('pushover: notify error'); }));
  }
  if (sl.config) {
    tasks.push(notifySlack(sl.config, title, body)
      .then((w) => { if (w) warnings.push(`slack: ${w}`); })
      .catch(() => { warnings.push('slack: notify error'); }));
  }

  await Promise.all(tasks);
  return warnings.length ? truncate(warnings.join('; ')) : '';
}

// Fan out an approval request to every configured STATELESS channel in parallel.
// Returns '' when every enabled channel succeeded (or none is enabled here), or a
// single aggregated, channel-prefixed warning string on a genuine error. Whether
// a stateful channel (Slack App / Feishu) covers this ceremony is decided in the
// DO, not here — see fanOut's note.
export async function notifyApproval(
  env: Env,
  opKind: string,
  meta: ChallengeMeta,
  approveUrl: string,
): Promise<string> {
  const { title, body } = buildApprovalMessage(opKind, meta, approveUrl);
  return fanOut(env, title, body);
}

// Fan out a DEK-cache-hit notice to every configured channel. Best-effort and
// non-fatal: a cache hit never has a phone in the loop, so this is the only
// real-time signal an operator gets that a record was decrypted without an
// approval. A missing channel is never a warning (the audit row already captures
// the hit). Returns the same aggregated warning string contract.
export async function notifyCacheHit(
  env: Env,
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
  salts: number,
): Promise<string> {
  const { title, body } = buildCacheHitMessage(meta, salts);
  return fanOut(env, title, body);
}
