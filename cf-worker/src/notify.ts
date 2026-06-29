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

// Compose the human-facing approval message once; every channel reuses it.
export function buildApprovalMessage(
  opKind: string,
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ssh_client' | 'ip' | 'reason'>,
  approveUrl: string,
): { title: string; body: string } {
  const title = opKind ? `VT 审批: ${opKind}` : 'VT 审批请求';
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
  lines.push(approveUrl);
  return { title, body: lines.join('\n') };
}

// Fan out to every configured channel in parallel. Returns '' when every
// enabled channel succeeded (and at least one was enabled), or a single
// aggregated, channel-prefixed warning string otherwise.
export async function notifyApproval(
  env: Env,
  opKind: string,
  meta: ChallengeMeta,
  approveUrl: string,
): Promise<string> {
  const { title, body } = buildApprovalMessage(opKind, meta, approveUrl);
  const warnings: string[] = [];

  const po = parsePushoverConfig(env.PUSHOVER_JSON);
  const sl = parseSlackConfig(env.SLACK_JSON);
  if (po.error) warnings.push(`pushover config: ${po.error}`);
  if (sl.error) warnings.push(`slack config: ${sl.error}`);

  const tasks: Promise<void>[] = [];
  if (po.config) {
    tasks.push(notifyPushover(po.config, title, body).then((w) => { if (w) warnings.push(`pushover: ${w}`); }));
  }
  if (sl.config) {
    tasks.push(notifySlack(sl.config, title, body).then((w) => { if (w) warnings.push(`slack: ${w}`); }));
  }
  if (tasks.length === 0 && warnings.length === 0) warnings.push('no notification channel configured');

  await Promise.all(tasks);
  return warnings.length ? truncate(warnings.join('; ')) : '';
}
