// Web Push fan-out (docs/worker-slim.md#web-push) plus the Slack Bot channel
// (docs/slack.md). Notifications never authorize or finalize a challenge and
// never run on the ceremony path: every send is a waitUntil task, and the CLI
// is never told whether it landed. Only the Slack message handle is merged
// into a freshly read challenge record.

import { Challenge, ChallengeMeta, ChallengeStatus, DoAuditIngestOp, PushPayload, SlackConfig } from './types';
import { buildApprovalMessage, buildCacheHitMessage } from './notify';
import { sendPush } from './webpush';
import { editApproval, sendApproval, sendCacheHit } from './slack';
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
    private readonly ctx: Pick<DurableObjectState, 'storage' | 'waitUntil'>,
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
    const url = `${this.admin.current.origin}/a/${challenge.approve_token}`;
    this.push({
      v: 1, kind: challenge.enroll ? 'enroll' : 'approval', title, body, url,
      tag: `a:${challenge.approve_token}`,
    }, 300, 'high');
    const slack = this.admin.slackConfig();
    if (slack) this.ctx.waitUntil(this.slackSend(slack, challenge, url).catch((e) => logErr('slack.send_failed', e)));
  }

  // Post the pending message and write its handle onto the latest record so the
  // decision can edit it. Slack awaits stay outside the get/put pair; a swept
  // record stays gone. If the decision raced ahead of the send, edit straight to
  // the terminal state — otherwise the message would sit at ⏳ forever.
  private async slackSend(cfg: SlackConfig, ch: Challenge, approveUrl: string): Promise<void> {
    const ref = await sendApproval(cfg, ch.meta, chSalts(ch), approveUrl);
    if (typeof ref === 'string') { logErr('slack.send_failed', new Error(ref)); return; }
    const key = `ch:${ch.approve_token}`;
    const cur = await this.ctx.storage.get<Challenge>(key);
    if (!cur) return;
    cur.slack = ref;
    await this.ctx.storage.put(key, cur);
    if (cur.status !== 'pending') await this.slackEdit(cfg, cur, cur.status);
  }

  private async slackEdit(cfg: SlackConfig, ch: Challenge, state: Exclude<ChallengeStatus, 'pending'>): Promise<void> {
    if (!ch.slack) return;
    const latency = ch.finalized_ms != null ? ch.finalized_ms - ch.created_ms : undefined;
    const warning = await editApproval(cfg, ch.slack, state, ch.meta, chSalts(ch), latency);
    if (warning) logErr('slack.edit_failed', new Error(warning), { state });
  }

  /** Rewrite the Slack message after a decision or expiry; `ch` must carry the
   *  handle (callers merge `slack` forward from the latest record). */
  decided(ch: Challenge, state: Exclude<ChallengeStatus, 'pending'>): void {
    const slack = this.admin.slackConfig();
    if (!slack || !ch.slack) return;
    this.ctx.waitUntil(this.slackEdit(slack, ch, state).catch((e) => logErr('slack.edit_failed', e)));
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
    const slack = this.admin.slackConfig();
    if (slack) {
      this.ctx.waitUntil(sendCacheHit(slack, meta, salts, note, names)
        .then((w) => { if (w) logErr('slack.cachehit_failed', new Error(w)); })
        .catch((e) => logErr('slack.cachehit_failed', e)));
    }
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
