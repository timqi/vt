// The text of a notification, built once for the Web Push payload
// (account_notifications.ts). Pure string builders; test/notify.test.ts.

import { ChallengeMeta } from './types';

// The shared context lines (who / pwd / cmd / via / ip / reason) that every
// notification body carries. Approval and cache-hit notices differ only in
// their title and head line, so they build on this common block — keeping the
// two from silently drifting if a field is added later.
// `salts` (the decrypt batch size, from the ceremony's salts_b64u — worker-derived,
// not client-claimed meta) joins the head line as `user@host · N 条`, mirroring the
// cache-hit head: an anomalous batch is exactly what an approver should see before
// tapping the link. 0 (auth/encrypt, or callers without a ceremony) drops the segment.
export function metaLines(
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ppid_cmd' | 'ip' | 'reason' | 'ip_prev'>,
  salts = 0,
): string[] {
  const who = [meta.user, meta.host].filter(Boolean).join('@');
  const lines: string[] = [];
  const head = [who, salts > 0 ? `${salts} 条` : ''].filter(Boolean).join(' · ');
  if (head) lines.push(head);
  if (meta.pwd) lines.push(`pwd: ${meta.pwd}`);
  if (meta.command) {
    // The CLI sends `command` as a self-labelled multi-line body
    // (`op: …\nfile: …\ncmd: …\nreason: …`); prefixing with another `cmd:`
    // would duplicate the labels. Inline single-line legacy commands.
    lines.push(meta.command.includes('\n') ? meta.command : `cmd: ${meta.command}`);
  }
  // The parent-process line mirrors the approval page's 父进程 row: users often
  // decide from the notification alone, and "which program asked" is the
  // highest-signal client-claimed field. ip is worker-verified; on the host-token
  // path `ip_prev` flags that this token last spoke from somewhere else.
  if (meta.ppid_cmd) lines.push(`via: ${meta.ppid_cmd}`);
  if (meta.ip) lines.push(meta.ip_prev ? `ip: ${meta.ip}（上次 ${meta.ip_prev}）` : `ip: ${meta.ip}`);
  if (meta.reason) lines.push(`reason: ${meta.reason}`);
  return lines;
}

// The approval notice. The approve URL is not in the body: the push payload
// carries it in `url`, so body truncation can never cut it.
export function buildApprovalMessage(
  opKind: string,
  meta: Pick<ChallengeMeta, 'command' | 'host' | 'user' | 'pwd' | 'ppid_cmd' | 'ip' | 'reason' | 'ip_prev'>,
  salts = 0,
): { title: string; body: string } {
  const title = opKind ? `VT 审批: ${opKind}` : 'VT 审批请求';
  return { title, body: metaLines(meta, salts).join('\n') };
}

// The cache-hit notice. A DEK-cache hit serves a decrypt WITHOUT a phone tap
// (the approver granted a TTL earlier), so this is a security-relevant "FYI:
// auto-decrypt happened" notice, not an approval request — no approve URL, no
// action to take, and a distinct title so it reads as cache at a glance.
// Compact: it drops the via/ip/reason lines and leads with a one-line summary
// (who · N records · cache note), then pwd + cmd (what ran, and where). The
// durable audit row keeps the full context.
// `note` names the skipped factor: the default fits the Worker DEK cache
// (no phone approval); the agent's Touch-ID-cache ingest path passes its own
// (免 Touch ID). `salts` of 0 (e.g. an agent `sign` hit has no records) drops
// the count segment rather than printing "0 条".
export function buildCacheHitMessage(
  meta: Pick<ChallengeMeta, 'op_kind' | 'command' | 'host' | 'user' | 'pwd'>,
  salts: number,
  note = '缓存命中，无手机审批',
): { title: string; body: string } {
  const title = meta.op_kind ? `VT 缓存命中(免审批): ${meta.op_kind}` : 'VT 缓存命中(免审批解密)';
  const who = [meta.user, meta.host].filter(Boolean).join('@');
  const head: string[] = [];
  if (who) head.push(who);
  if (salts > 0) head.push(`${salts} 条`);
  head.push(note);
  const lines: string[] = [head.join(' · ')];
  if (meta.pwd) lines.push(`pwd: ${meta.pwd}`);
  // Same self-labelled-multi-line handling as metaLines above.
  if (meta.command) lines.push(meta.command.includes('\n') ? meta.command : `cmd: ${meta.command}`);
  return { title, body: lines.join('\n') };
}
