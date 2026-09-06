// Account-local delivery bookkeeping. Notifications never authorize or finalize
// a challenge; only message references are merged into freshly read records.

import { Env, Challenge, ChallengeMeta, ChallengeStatus, DoAuditIngestOp } from './types';
import { notifyCacheHit } from './notify';
import { parseFeishuConfig, sendApprovalCard, editCard, sendCacheHitNotice, FeishuConfig, Kv as FeishuKv } from './feishu';
import {
  parseSlackAppConfig,
  sendApprovalCard as sendSlackAppCard,
  editCard as editSlackAppCard,
  sendCacheHitNotice as sendSlackAppCacheHitNotice,
  SlackAppConfig,
} from './slack_app';
import { logErr } from './log';

// Agent Touch-ID-cache hits inside a TTL window can arrive many times a minute
// (orchestrated callers); notify at most once per key per this interval. The
// audit table still records every hit — the notice is a heads-up, not a ledger.
const AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS = 60 * 1000;

// Cache-hit 免审批 notices are opt-in and OFF by default — they fire on every
// no-human-in-the-loop decrypt and bury the approval messages that do need a
// tap. Set CACHE_HIT_NOTIFY = "1" | "true" | "on" | "yes" in wrangler.toml
// [vars] to restore the push. The audit row is written either way.
function cacheHitNotifyEnabled(env: Env): boolean {
  const v = (env.CACHE_HIT_NOTIFY ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'on' || v === 'yes';
}

const chSalts = (ch: Challenge): number =>
  Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0;

export interface NotificationChannels {
  feishu: FeishuConfig | null;
  slackApp: SlackAppConfig | null;
}

type ReferenceField = 'feishu_message_id' | 'slackapp';
type TerminalState = Exclude<ChallengeStatus, 'pending'>;
type EditExtra = { approverLabel?: string; latencyMs?: number };

interface EditableChannel<K extends ReferenceField> {
  field: K;
  name: 'feishu' | 'slackapp';
  missingReference: string;
  send(ch: Challenge, approveUrl: string): Promise<NonNullable<Challenge[K]> | null>;
  edit(ref: NonNullable<Challenge[K]>, ch: Challenge, state: TerminalState, extra: EditExtra): Promise<string>;
}

export class AccountNotifications {
  // In-memory only: eviction can cause one extra notice, never a missing audit.
  private agentCacheNotifyMs = new Map<string, number>();

  constructor(
    private readonly ctx: Pick<DurableObjectState, 'storage' | 'waitUntil'>,
    private readonly env: Env,
  ) {}

  channels(): NotificationChannels {
    return { feishu: this.feishuCfg(), slackApp: this.slackAppCfg() };
  }

  edit(
    ch: Challenge,
    state: TerminalState,
    extra: EditExtra,
    channels?: NotificationChannels,
  ): void {
    const configs = channels ?? this.channels();
    if (configs.feishu) this.scheduleEdit(this.feishuChannel(configs.feishu), ch, state, extra);
    if (configs.slackApp) this.scheduleEdit(this.slackAppChannel(configs.slackApp), ch, state, extra);
  }

  approval(challenge: Challenge): void {
    // A cache-extension ceremony is NOT pushed to any channel. Its entire flow is
    // console-resident: the operator picks the groups on the admin DEK 缓存 tab and
    // the Passkey ceremony mounts inline on that same page, so a card would notify
    // the person already watching the result. Observability is preserved where it
    // belongs — the audit tab receives the request row (op_kind='cache-extend') and
    // the effect row (status='extended') over its real-time stream.
    if (challenge.extend) return;

    // Feishu approval card — fire-and-forget (waitUntil), NOT awaited: this keeps
    // a third-party API's latency out of the singleton DO's serialized op path.
    // Pushover/Slack are sent separately from index.ts (stateless). See feishu.ts.
    const cfg = this.feishuCfg();
    const slackCfg = this.slackAppCfg();
    if (cfg || slackCfg) {
      const approveUrl = `${this.env.WORKER_ORIGIN}/a/${challenge.approve_token}`;
      // Both channels do a read-modify-write of
      // the SAME `ch:` record, each writing only its own ref field
      // (feishu_message_id / slackapp). As independent waitUntil tasks their
      // `await get`s can both read the pre-write snapshot, so the later `put`
      // clobbers the sibling's ref — a lost update that strands that channel's
      // message at ⏳ with no error logged. Run them SEQUENTIALLY inside one
      // waitUntil so the second reads the first's committed write. Client latency
      // is unaffected: opCreate already returns before these settle.
      this.ctx.waitUntil((async () => {
        if (cfg) await this.sendAndStore(this.feishuChannel(cfg), challenge, approveUrl);
        if (slackCfg) await this.sendAndStore(this.slackAppChannel(slackCfg), challenge, approveUrl);
      })());
    }
  }

  // ── Feishu channel (stateful: token cache + editable card) ──────────────────
  // Parsed lazily per use; a malformed FEISHU_JSON is logged once and treated as
  // "channel off" (best-effort, never breaks the ceremony).
  private feishuCfg(): FeishuConfig | null {
    const { config, error } = parseFeishuConfig(this.env.FEISHU_JSON);
    if (error) logErr('feishu.config_error', error);
    return config;
  }

  // DO storage as the token cache backing store for feishu.ts.
  private feishuKv(): FeishuKv {
    return {
      get: <T>(k: string) => this.ctx.storage.get<T>(k),
      put: (k: string, v: unknown) => this.ctx.storage.put(k, v),
    };
  }

  // Merge only the delivered channel's reference into the latest challenge.
  // Provider awaits stay outside this get/put pair; a swept record stays gone.
  private async storeReference<K extends ReferenceField>(
    approveToken: string, field: K, reference: NonNullable<Challenge[K]>,
  ): Promise<Challenge | undefined> {
    const key = `ch:${approveToken}`;
    const current = await this.ctx.storage.get<Challenge>(key);
    if (!current) return;
    current[field] = reference;
    await this.ctx.storage.put(key, current);
    return current;
  }

  // Fire the pending approval card (off the ceremony path) and write the
  // resulting message_id back onto the challenge so a later approve/reject/expire
  // can edit it. If the decision raced ahead of the send (challenge already
  // terminal), edit the card straight to its final state instead — the only
  // failure mode of the race is a card that never leaves "⏳", which this closes.
  private async sendAndStore<K extends ReferenceField>(
    channel: EditableChannel<K>, ch: Challenge, approveUrl: string,
  ): Promise<void> {
    try {
      const ref = await channel.send(ch, approveUrl);
      if (!ref) { logErr(`${channel.name}.send_failed`, channel.missingReference); return; }
      const cur = await this.storeReference(ch.approve_token, channel.field, ref);
      if (!cur) return;
      if (cur.status !== 'pending') {
        // Decision landed first. Edit to the terminal state now that we have the
        // id. Approver label is unavailable on this path (opApprove already ran
        // without an id) — degrade to latency-only; this race is rare + cosmetic.
        const latencyMs = cur.finalized_ms != null ? cur.finalized_ms - cur.created_ms : undefined;
        await this.editDelivered(channel, ref, cur, cur.status, { latencyMs });
      }
    } catch (e) { logErr(`${channel.name}.send_failed`, e); }
  }

  private async editDelivered<K extends ReferenceField>(
    channel: EditableChannel<K>, ref: NonNullable<Challenge[K]>,
    ch: Challenge, state: TerminalState, extra: EditExtra,
  ): Promise<void> {
    try {
      const warning = await channel.edit(ref, ch, state, extra);
      if (warning) logErr(`${channel.name}.edit_failed`, warning);
    } catch (e) { logErr(`${channel.name}.edit_failed`, e); }
  }

  // The alarm supplies configs parsed once for the batch; individual decisions
  // parse on demand. Delivery remains outside the protected operation.
  private scheduleEdit<K extends ReferenceField>(
    channel: EditableChannel<K>, ch: Challenge, state: TerminalState, extra: EditExtra,
  ): void {
    const ref = ch[channel.field];
    if (ref) this.ctx.waitUntil(this.editDelivered(channel, ref, ch, state, extra));
  }

  private feishuChannel(cfg: FeishuConfig): EditableChannel<'feishu_message_id'> {
    return {
      field: 'feishu_message_id', name: 'feishu', missingReference: 'no message_id',
      send: (ch, url) => sendApprovalCard(
        cfg, this.feishuKv(), Date.now(), ch.meta.op_kind, ch.meta, url, chSalts(ch)),
      edit: (ref, ch, state, extra) => editCard(
        cfg, this.feishuKv(), Date.now(), ref, state, ch.meta.op_kind, ch.meta, extra, chSalts(ch)),
    };
  }

  // Slack's long-lived bot token needs no KV cache. A malformed config disables
  // only this channel, just like Feishu.
  private slackAppCfg(): SlackAppConfig | null {
    const { config, error } = parseSlackAppConfig(this.env.SLACK_APP_JSON);
    if (error) logErr('slackapp.config_error', error);
    return config;
  }

  private slackAppChannel(cfg: SlackAppConfig): EditableChannel<'slackapp'> {
    return {
      field: 'slackapp', name: 'slackapp', missingReference: 'no ts',
      send: (ch, url) => sendSlackAppCard(cfg, ch.meta.op_kind, ch.meta, url, chSalts(ch)),
      edit: (ref, ch, state, extra) => editSlackAppCard(
        cfg, ref, state, ch.meta.op_kind, ch.meta, extra, chSalts(ch)),
    };
  }

  // Fan a cache-hit notice out to every configured channel (stateless
  // Pushover/Slack-webhook fanOut + Feishu + Slack App), each via waitUntil —
  // compact, no @, no edit lifecycle (terminal FYI). Shared by the Worker
  // DEK-cache hit (opDekCache) and the agent Touch-ID-cache hit
  // (notifyAgentCacheHit); `note` names the skipped factor when it isn't the
  // default phone approval, `errTag` distinguishes the two sources in logs.
  //
  // Push is OPT-IN (CACHE_HIT_NOTIFY=1): a busy host hits the cache many times
  // a minute and the resulting stream drowns the approval messages that
  // actually need a human. Silence here only drops the real-time FYI — the
  // audit row (auditCacheEvent / auditAgent) is written unconditionally and
  // stays the durable record, visible on the admin audit page.
  cacheHit(
    meta: ChallengeMeta,
    salts: number,
    note: string | undefined = undefined,
    errTag = 'cachehit_failed',
  ): void {
    if (!cacheHitNotifyEnabled(this.env)) return;
    this.ctx.waitUntil(
      notifyCacheHit(this.env, meta, salts, note)
        .then((w) => { if (w) logErr(`notify.${errTag}`, w); })
        .catch((e) => logErr(`notify.${errTag}`, e)),
    );
    const feishu = this.feishuCfg();
    if (feishu) {
      this.ctx.waitUntil(
        sendCacheHitNotice(feishu, this.feishuKv(), Date.now(), meta, salts, note)
          .then((w) => { if (w) logErr(`feishu.${errTag}`, w); })
          .catch((e) => logErr(`feishu.${errTag}`, e)),
      );
    }
    const slackApp = this.slackAppCfg();
    if (slackApp) {
      this.ctx.waitUntil(
        sendSlackAppCacheHitNotice(slackApp, meta, salts, note)
          .then((w) => { if (w) logErr(`slackapp.${errTag}`, w); })
          .catch((e) => logErr(`slackapp.${errTag}`, e)),
      );
    }
  }

  // Throttled 免审批 notice for an agent-side cache hit; the actual dispatch
  // is the shared pushCacheHitNotices. The note names the skipped factor —
  // Touch ID here, not a phone approval.
  agentCacheHit(op: DoAuditIngestOp): void {
    const key = `${op.meta.op_kind}|${op.meta.host}`;
    const now = Date.now();
    if (now - (this.agentCacheNotifyMs.get(key) ?? 0) < AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS) return;
    // Bound the map: keys are (op_kind, host) pairs, so growth needs a hostile
    // agent minting hostnames — cheap to cap anyway.
    if (this.agentCacheNotifyMs.size > 256) this.agentCacheNotifyMs.clear();
    this.agentCacheNotifyMs.set(key, now);

    this.cacheHit(op.meta, op.salts, '缓存命中，免 Touch ID', 'agent_cachehit_failed');
  }

}
