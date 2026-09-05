// Account-local delivery bookkeeping. Notifications never authorize or finalize
// a challenge; only message references are merged into freshly read records.

import { Env, Challenge, ChallengeMeta, ChallengeStatus, DoAuditIngestOp } from './types';
import { notifyCacheHit } from './notify';
import { parseFeishuConfig, sendApprovalCard, editCard, sendCacheHitNotice, FeishuConfig, FeishuState, Kv as FeishuKv } from './feishu';
import {
  parseSlackAppConfig,
  sendApprovalCard as sendSlackAppCard,
  editCard as editSlackAppCard,
  sendCacheHitNotice as sendSlackAppCacheHitNotice,
  SlackAppConfig, SlackAppState, SlackAppMsgRef,
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
    state: Exclude<ChallengeStatus, 'pending'>,
    extra: { approverLabel?: string; latencyMs?: number },
    channels?: NotificationChannels,
  ): void {
    this.feishuEdit(ch, state, extra, channels?.feishu);
    this.slackAppEdit(ch, state, extra, channels?.slackApp);
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
      // Both feishuSendAndStore and slackAppSendAndStore do a read-modify-write of
      // the SAME `ch:` record, each writing only its own ref field
      // (feishu_message_id / slackapp). As independent waitUntil tasks their
      // `await get`s can both read the pre-write snapshot, so the later `put`
      // clobbers the sibling's ref — a lost update that strands that channel's
      // message at ⏳ with no error logged. Run them SEQUENTIALLY inside one
      // waitUntil so the second reads the first's committed write. Client latency
      // is unaffected: opCreate already returns before these settle.
      this.ctx.waitUntil((async () => {
        if (cfg) await this.feishuSendAndStore(cfg, challenge, approveUrl);
        if (slackCfg) await this.slackAppSendAndStore(slackCfg, challenge, approveUrl);
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

  // Fire the pending approval card (off the ceremony path) and write the
  // resulting message_id back onto the challenge so a later approve/reject/expire
  // can edit it. If the decision raced ahead of the send (challenge already
  // terminal), edit the card straight to its final state instead — the only
  // failure mode of the race is a card that never leaves "⏳", which this closes.
  private async feishuSendAndStore(cfg: FeishuConfig, ch: Challenge, approveUrl: string): Promise<void> {
    try {
      const id = await sendApprovalCard(
        cfg, this.feishuKv(), Date.now(), ch.meta.op_kind, ch.meta, approveUrl, chSalts(ch));
      if (!id) { logErr('feishu.send_failed', 'no message_id'); return; }
      const cur = await this.ctx.storage.get<Challenge>(`ch:${ch.approve_token}`);
      if (!cur) return; // expired + swept before the send returned
      cur.feishu_message_id = id;
      await this.ctx.storage.put(`ch:${ch.approve_token}`, cur);
      if (cur.status !== 'pending') {
        // Decision landed first. Edit to the terminal state now that we have the
        // id. Approver label is unavailable on this path (opApprove already ran
        // without an id) — degrade to latency-only; this race is rare + cosmetic.
        const latencyMs = cur.finalized_ms != null ? cur.finalized_ms - cur.created_ms : undefined;
        const w = await editCard(
          cfg, this.feishuKv(), Date.now(), id, cur.status as FeishuState,
          cur.meta.op_kind, cur.meta, { latencyMs }, chSalts(cur));
        if (w) logErr('feishu.edit_failed', w);
      }
    } catch (e) { logErr('feishu.send_failed', e); }
  }

  // Edit an already-sent card to a terminal state (off the decision path).
  // `cfgHint` lets a caller (the alarm sweep) pass a config parsed ONCE for the
  // whole batch, instead of this method re-parsing FEISHU_JSON — and re-logging
  // any config error — for every challenge in a loop. Omit it (undefined) for
  // the one-shot approve/reject paths, which parse on demand.
  private feishuEdit(
    ch: Challenge,
    state: FeishuState,
    extra: { approverLabel?: string; latencyMs?: number },
    cfgHint?: FeishuConfig | null,
  ): void {
    const cfg = cfgHint !== undefined ? cfgHint : this.feishuCfg();
    if (!cfg || !ch.feishu_message_id) return;
    const mid = ch.feishu_message_id;
    const meta = ch.meta;
    this.ctx.waitUntil(
      editCard(cfg, this.feishuKv(), Date.now(), mid, state, meta.op_kind, meta, extra, chSalts(ch))
        .then((w) => { if (w) logErr('feishu.edit_failed', w); })
        .catch((e) => logErr('feishu.edit_failed', e)),
    );
  }

  // ── Slack App channel (stateful: bot token + editable message) ───────────────
  // Structurally identical to the Feishu channel above (send → store ref → edit
  // on decision), minus the token cache: a Slack bot token is long-lived, so
  // there is no KV. A malformed SLACK_APP_JSON is logged once and treated as
  // "channel off" (best-effort, never breaks the ceremony).
  private slackAppCfg(): SlackAppConfig | null {
    const { config, error } = parseSlackAppConfig(this.env.SLACK_APP_JSON);
    if (error) logErr('slackapp.config_error', error);
    return config;
  }

  // Fire the pending approval message (off the ceremony path) and write the
  // resulting {channel, ts} back onto the challenge so a later approve/reject/
  // expire can edit it. Mirrors feishuSendAndStore, including the send-vs-decision
  // race: if the decision landed first, edit straight to the terminal state.
  private async slackAppSendAndStore(cfg: SlackAppConfig, ch: Challenge, approveUrl: string): Promise<void> {
    try {
      const ref = await sendSlackAppCard(cfg, ch.meta.op_kind, ch.meta, approveUrl, chSalts(ch));
      if (!ref) { logErr('slackapp.send_failed', 'no ts'); return; }
      const cur = await this.ctx.storage.get<Challenge>(`ch:${ch.approve_token}`);
      if (!cur) return; // expired + swept before the send returned
      cur.slackapp = ref;
      await this.ctx.storage.put(`ch:${ch.approve_token}`, cur);
      if (cur.status !== 'pending') {
        // Decision landed first — edit to the terminal state now that we have the
        // ref. Approver label is unavailable on this path (opApprove already ran
        // without a ref) — degrade to latency-only; this race is rare + cosmetic.
        const latencyMs = cur.finalized_ms != null ? cur.finalized_ms - cur.created_ms : undefined;
        const w = await editSlackAppCard(
          cfg, ref, cur.status as SlackAppState, cur.meta.op_kind, cur.meta,
          { latencyMs }, chSalts(cur));
        if (w) logErr('slackapp.edit_failed', w);
      }
    } catch (e) { logErr('slackapp.send_failed', e); }
  }

  // Edit an already-sent message to a terminal state (off the decision path).
  // `cfgHint` mirrors feishuEdit: the alarm sweep passes a config parsed ONCE for
  // the whole batch; the one-shot approve/reject paths omit it (parse on demand).
  private slackAppEdit(
    ch: Challenge,
    state: SlackAppState,
    extra: { approverLabel?: string; latencyMs?: number },
    cfgHint?: SlackAppConfig | null,
  ): void {
    const cfg = cfgHint !== undefined ? cfgHint : this.slackAppCfg();
    if (!cfg || !ch.slackapp) return;
    const ref: SlackAppMsgRef = ch.slackapp;
    const meta = ch.meta;
    this.ctx.waitUntil(
      editSlackAppCard(cfg, ref, state, meta.op_kind, meta, extra, chSalts(ch))
        .then((w) => { if (w) logErr('slackapp.edit_failed', w); })
        .catch((e) => logErr('slackapp.edit_failed', e)),
    );
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
