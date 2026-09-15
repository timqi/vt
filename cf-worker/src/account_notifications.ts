// Web Push fan-out (docs/worker-slim.md#web-push). Notifications never authorize or
// finalize a challenge and never run on the ceremony path: every send is a
// waitUntil task, and the CLI is never told whether it landed.

import { Challenge, ChallengeMeta, DoAuditIngestOp, PushPayload } from './types';
import { buildApprovalMessage, buildCacheHitMessage } from './notify';
import { sendPush } from './webpush';
import { AccountAdmin } from './account_admin';
import { ADMIN_AUDIT_PATH } from './page';
import { logErr } from './log';

// Agent Touch-ID-cache hits inside a TTL window can arrive many times a minute
// (orchestrated callers); notify at most once per key per this interval. The
// audit table still records every hit — the notice is a heads-up, not a ledger.
const AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS = 60 * 1000;

const chSalts = (ch: Challenge): number =>
  Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0;

export class AccountNotifications {
  // In-memory only: eviction can cause one extra notice, never a missing audit.
  private agentCacheNotifyMs = new Map<string, number>();

  constructor(
    private readonly ctx: Pick<DurableObjectState, 'waitUntil'>,
    private readonly admin: AccountAdmin,
  ) {}

  // One sendPush per subscription. The push service's answer decides the row
  // (docs/worker-slim.md#delivery-limits): 404/410 is dead for good, everything else keeps it
  // and is logged.
  private push(payload: PushPayload, ttlS: number, urgency: 'normal' | 'high'): void {
    this.ctx.waitUntil((async () => {
      const { vapid, push, origin } = await this.admin.pushConfig();
      if (!vapid || push.length === 0) return;
      const body = JSON.stringify({ ...payload, body: payload.body.slice(0, 1000) });
      await Promise.all(push.map(async (sub) => {
        const r = await sendPush(sub, body, vapid, origin, ttlS, urgency);
        if (r.status >= 200 && r.status < 300) return;
        if (r.status === 404 || r.status === 410) { await this.admin.unsubscribe(sub.endpoint); return; }
        const event = r.status === 413 ? 'push.too_large'
          : r.status === 401 || r.status === 403 ? 'push.vapid_rejected' : 'push.failed';
        logErr(event, new Error(r.error ?? ''), { status: r.status });
      }));
    })().catch((e) => logErr('push.failed', e)));
  }

  approval(challenge: Challenge): void {
    // A cache-extension ceremony is NOT pushed. Its entire flow is console-
    // resident: the operator picks the entries on the admin DEK Cache tab and the
    // Passkey ceremony mounts inline on that same page, so a push would notify
    // the person already watching the result. The audit tab still receives the
    // request row (op_kind='cache-extend') and the effect row (status='extended').
    if (challenge.extend) return;
    const { title, body } = buildApprovalMessage(challenge.meta.op_kind, challenge.meta, chSalts(challenge));
    this.push({
      v: 1, kind: challenge.enroll ? 'enroll' : 'approval', title, body,
      url: `${this.admin.current.origin}/a/${challenge.approve_token}`,
      tag: `a:${challenge.approve_token}`,
    }, 300, 'high');
  }

  // Approval-free notice shared by the Worker DEK-cache hit (opDekCache) and the agent
  // Touch-ID-cache hit (agentCacheHit); `note` names the skipped factor when it
  // isn't the default phone approval. Opt-in (`cache_hit_notify`, Settings tab, off
  // by default: hits can fire many times a minute and bury the approvals that
  // need a tap): silence drops only the real-time FYI — the audit row is
  // written unconditionally.
  cacheHit(meta: ChallengeMeta, salts: number, note?: string, names: string[] = []): void {
    if (!this.admin.current.cache_hit_notify) return;
    const { title, body } = buildCacheHitMessage(meta, salts, note, names);
    this.push({
      v: 1, kind: 'cache_hit', title, body,
      url: `${this.admin.current.origin}${ADMIN_AUDIT_PATH}`, tag: `cache:${meta.host}`,
    }, 3600, 'normal');
  }

  // Throttled per (op_kind, host); the note names the skipped factor — Touch
  // ID here, not a phone approval.
  agentCacheHit(op: DoAuditIngestOp): void {
    const key = `${op.meta.op_kind}|${op.meta.host}`;
    const now = Date.now();
    if (now - (this.agentCacheNotifyMs.get(key) ?? 0) < AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS) return;
    // Bound the map: keys are (op_kind, host) pairs, so growth needs a hostile
    // agent minting hostnames — cheap to cap anyway.
    if (this.agentCacheNotifyMs.size > 256) this.agentCacheNotifyMs.clear();
    this.agentCacheNotifyMs.set(key, now);
    this.cacheHit(op.meta, op.salts, 'cache hit, no Touch ID');
  }
}
