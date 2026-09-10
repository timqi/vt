// AccountDO — singleton ceremony state machine. AccountCache owns DEK storage;
// AccountAudit and AccountNotifications own audit persistence and delivery.
//
// Storage keys:
//   ch:{approve_token}        →  Challenge JSON
//   pt:{poll_token}           →  approve_token (WS tag routing)
//   dek:{ctx}:{salt_b64u}     →  CacheEntry (opt-in DEK cache; ctx binds IP+pwd)
//
// WebSocket hibernation: WS clients connect via Worker GET /api/dek, which
// forwards to the DO. The DO hibernates the WS tagged with the poll_token so
// it wakes on the approval HTTP request.
//
// Alarm: sweeps pending challenges older than TTL_MS and deletes finalized
// challenges after RETENTION_MS. Expiry re-reads each challenge under the DO
// input gate so a stale list snapshot cannot overwrite a committed decision.

import { DurableObject } from 'cloudflare:workers';
import { Env, Challenge, ChallengeMeta, ApprovePageData, DoCreateOp, DoApproveOp, DoRejectOp, DoDekCacheOp, DoAuditIngestOp, WsMessage, AdminWsMessage, DekCacheResponse, CacheExtendIntent, CacheExtendPreview, CacheGroupSummary, CacheListResponse, DoCacheExtendCreateOp, CacheExtendCreateResponse } from './types';
import { b64uDec, b64uEnc, isB64uString, decodeB64uExact, randomBytes, challengeHash } from './crypto';
import { parseCredentials, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';
import { cachePublicKey, discardedBoxPublicKey } from './cache_crypto';
import {
  isAllowedExtendTtl, approveTtlOptions, extendTtlOptions,
  isExtendableGroupId, cacheScopePwd,
} from './cache_policy';
import { challengeUvLevel } from './uv_policy';
import { log, logErr, tokenPrefix } from './log';
import { AccountAudit, auditKey } from './account_audit';
import { AccountNotifications, NotificationChannels } from './account_notifications';
import { AccountCache } from './account_cache';
import { deleteKeysBatched, listPrefixPages } from './storage_batch';

const TTL_MS = 5 * 60 * 1000;
const RETENTION_MS = 10 * 60 * 1000;
// The TTL whitelist and the extension arithmetic live in cache_policy.ts (pure +
// unit-tested); this module owns authorization and ceremony transitions.

// Admin-requested cache extension is a KILL SWITCH, not an authorization: even
// when enabled, an extension requires a fresh phone Passkey ceremony. Off by
// default so a deployment that never wants the capability does not have it.
function cacheAdminExtendEnabled(env: Env): boolean {
  const v = (env.CACHE_ADMIN_EXTEND ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'on' || v === 'yes';
}

// Cap on groups one extension ceremony may target. Keeps the approval page's
// summary readable (the approver must be able to see what they are signing for)
// and bounds the commit's read-modify-write work.
const CACHE_EXTEND_MAX_GROUPS = 32;

// Cap concurrent admin audit-stream sockets (multiple browser tabs / stale
// hibernated sockets). Bounds broadcast fan-out and DO memory; a new connect
// past the cap is refused (the client retries with backoff). Admin is a single
// operator, so this is generous.
const MAX_ADMIN_SOCKETS = 8;

function badRequest(msg: string): Response {
  return new Response(msg, { status: 400 });
}

// Human TTL label matching the PWA's (approve.js ttlLabel), used in the approval
// page's 命令 field so the approver reads the same wording everywhere.
function ttlLabelZh(s: number): string {
  // Days/weeks first: an approver reading "168 小时" on their phone cannot judge
  // it at a glance, and this string is the authority they are granting.
  if (s % (7 * 86400) === 0) return (s / (7 * 86400)) + ' 周';
  if (s % 86400 === 0) return (s / 86400) + ' 天';
  if (s % 3600 === 0) return (s / 3600) + ' 小时';
  if (s % 60 === 0) return (s / 60) + ' 分钟';
  return s + ' 秒';
}

function fmtTimeZh(ms: number): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '?';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

// The text an approver actually reads before touching their Passkey (it lands in
// ChallengeMeta.command, which the ceremony UI renders verbatim). It must name
// every dimension of the authority being granted: how many entries, on which
// hosts/IPs, and for how long.
function extendSummary(intent: CacheExtendIntent): string {
  const entries = intent.preview.reduce((n, t) => n + t.live, 0);
  const lines = [
    'op: 延长 DEK 缓存有效期',
    `scope: ${intent.preview.length} 组 / ${entries} 条缓存`,
    `ttl: ${ttlLabelZh(intent.ttl_s)}（自批准时刻起算，覆盖原有效期）`,
  ];
  for (const t of intent.preview) {
    lines.push(`target: ${t.host || '?'} ${t.ip || '?'} · ${t.live} 条 · 现有效期至 ${fmtTimeZh(t.expires_ms)}`);
  }
  if (intent.requested_by) lines.push(`by: ${intent.requested_by}`);
  return lines.join('\n');
}

// Outcome line for the audit row, so a partial commit is legible without digging
// through Worker logs (e.g. "4 条已延长 · 跳过: no_gain=2").
function extendOutcomeSummary(
  skips: Record<string, number>, total: number, latest: number,
): string {
  const parts = [`${total} 条已延长`];
  if (latest > 0) parts.push(`新有效期至 ${fmtTimeZh(latest)}`);
  const skipStr = Object.entries(skips).map(([k, v]) => `${k}=${v}`).join(' ');
  if (skipStr) parts.push(`跳过: ${skipStr}`);
  return parts.join(' · ');
}

// A challenge is effectively expired once TTL_MS has elapsed since creation,
// EVEN IF the alarm sweep has not yet flipped its stored status to 'expired'.
// The alarm (every TTL_MS) is best-effort cleanup + notification (WS close,
// audit finalize, Feishu edit); THIS read-time check is the AUTHORITATIVE expiry
// guard, mirroring opDekCache which likewise treats read-time expiry as
// authoritative and the sweep as mere storage bounding. Without it, a stalled or
// late alarm leaves a past-TTL challenge both visible on the approval page AND
// still approvable — a fail-open gap.
function isPendingExpired(ch: Challenge, now: number): boolean {
  return ch.status === 'pending' && now - ch.created_ms >= TTL_MS;
}

export class AccountDO extends DurableObject<Env> {
  private readonly expectedOrigin: string;
  private readonly audit: AccountAudit;
  private readonly notifications: AccountNotifications;
  private readonly cache: AccountCache;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.expectedOrigin = new URL(env.WORKER_ORIGIN).origin;
    this.audit = new AccountAudit(this.ctx.storage.sql, () => this.ctx.getWebSockets('admin'));
    this.notifications = new AccountNotifications(this.ctx, this.env);
    this.cache = new AccountCache(this.ctx.storage, this.env);
    this.ctx.blockConcurrencyWhile(async () => this.audit.initialize());
    // Schedule initial alarm if none set (alarm() re-arms itself thereafter).
    this.ctx.storage.getAlarm()
      .then(a => { if (a == null) return this.ctx.storage.setAlarm(Date.now() + TTL_MS); })
      .catch(e => logErr('alarm.init_failed', e));
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket upgrade. Two distinct channels:
    //   /ws        — per-ceremony daemon socket (tagged pt:{poll_token})
    //   /ws-admin  — admin audit stream (tagged 'admin'); Access-gated at the edge
    if (request.headers.get('Upgrade') === 'websocket') {
      if (url.pathname === '/ws-admin') return this.handleAdminWsUpgrade(url);
      return this.handleWsUpgrade(url);
    }

    const op = url.pathname.split('/').pop();
    switch (op) {
      case 'create':              return this.opCreate(request);
      case 'approve':             return this.opApprove(request);
      case 'reject':              return this.opReject(request);
      case 'dek-cache':           return this.opDekCache(request);
      case 'audit-ingest':        return this.opAuditIngest(request);
      case 'page':                return this.opPageData(url);
      case 'audit-query':         return this.opAuditQuery(url);
      case 'cache-clear-origin':  return this.opCacheClearByOrigin(request);
      case 'cache-list':          return this.opCacheList();
      case 'cache-clear-groups':  return this.opCacheClearGroups(request);
      case 'cache-extend-create': return this.opCacheExtendCreate(request);
      case 'clear-cache':         return this.opClearCache();
      case 'clear-audit':         return this.opClearAudit();
      default:                    return new Response('unknown op', { status: 400 });
    }
  }

  // ── WebSocket ──────────────────────────────────────────────────────────

  private async handleWsUpgrade(url: URL): Promise<Response> {
    const pollToken = url.searchParams.get('poll_token') ?? '';
    if (!pollToken) return new Response('missing poll_token', { status: 400 });

    // Look up approve_token for this poll_token
    const approveToken = await this.ctx.storage.get<string>(`pt:${pollToken}`);
    if (!approveToken) return new Response('unknown poll_token', { status: 404 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    // Tag by poll_token so opApprove can wake the right WS
    this.ctx.acceptWebSocket(server, [`pt:${pollToken}`]);
    // Send initial "waiting" message immediately
    server.send(JSON.stringify({ status: 'waiting' } satisfies WsMessage));

    // If challenge already terminal (race: user approved before WS connected),
    // send the result now.
    const ch = await this.ctx.storage.get<Challenge>(`ch:${approveToken}`);
    if (ch) {
      if (ch.status === 'approved' && ch.sealed_deks_b64u && ch.pwa_pk_b64u && ch.binding_tag_b64u) {
        server.send(JSON.stringify({
          status: 'approved',
          sealed_deks_b64u: ch.sealed_deks_b64u,
          pwa_pk_b64u: ch.pwa_pk_b64u,
          binding_tag_b64u: ch.binding_tag_b64u,
        } satisfies WsMessage));
        server.close(1000, 'approved');
      } else if (ch.status === 'rejected') {
        server.send(JSON.stringify({ status: 'rejected' } satisfies WsMessage));
        server.close(1000, 'rejected');
      } else if (ch.status === 'expired') {
        server.send(JSON.stringify({ status: 'expired' } satisfies WsMessage));
        server.close(1000, 'expired');
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  // Admin audit stream. Access-gated at the Worker edge (requireAccess), which
  // passes the VERIFIED JWT `exp` (epoch seconds) through as ?exp=. We bind the
  // socket's lifetime to that exp via serializeAttachment so a hibernating
  // stream cannot outlive the admin's authenticated session — the alarm() sweep
  // closes any socket past exp. (REST polling gets a fresh 403 the moment the
  // session ends; a long-lived socket needs this explicit re-check.)
  private async handleAdminWsUpgrade(url: URL): Promise<Response> {
    const expRaw = url.searchParams.get('exp') ?? '';
    if (!/^\d+$/.test(expRaw)) return new Response('missing exp', { status: 400 });
    const exp = parseInt(expRaw, 10);
    // Already-expired token → refuse before accepting (defence in depth; the edge
    // JWT check already enforces exp, but never trust a stale query param).
    if (Math.floor(Date.now() / 1000) >= exp) return new Response('expired', { status: 400 });

    // Bound concurrent admin sockets so broadcast fan-out and DO memory stay
    // bounded across many tabs / stale hibernated sockets. At the cap, evict the
    // oldest (likely a dead/stale tab) to make room rather than lock out a fresh,
    // authenticated client.
    const open = this.ctx.getWebSockets('admin');
    if (open.length >= MAX_ADMIN_SOCKETS) {
      try { open[0]!.close(4002, 'evicted: admin socket cap'); } catch {}
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, ['admin']);
    server.serializeAttachment({ exp });
    // 'hello' → the client runs an after_seq catch-up to reconcile anything it
    // missed between its REST snapshot and this socket opening.
    server.send(JSON.stringify({ kind: 'hello' } satisfies AdminWsMessage));
    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(ws: WebSocket, _message: string | ArrayBuffer): void {
    // No client-to-server messages are expected on this socket.
    try { ws.close(1003, 'no input expected'); } catch {}
  }

  webSocketClose(_ws: WebSocket, _code: number, _reason: string): void {}
  webSocketError(_ws: WebSocket, _error: unknown): void {}

  // ── Alarm — sweep expired + finalized challenges ───────────────────────

  async alarm(): Promise<void> {
    // Each sweep is isolated in its own try/catch, and the reschedule runs in a
    // finally — so a transient failure in one sweep can neither skip the others
    // nor (critically) prevent the next alarm from being scheduled. Without the
    // finally, a single throw here would stop ALL periodic cleanup permanently
    // once CF exhausts its automatic alarm retries.
    const now = Date.now();
    try {

    // 1. Challenges: expire pending past TTL_MS; delete finalized past RETENTION_MS.
    try {
      // Parse the Feishu + Slack App configs ONCE for the whole sweep (they
      // can't change mid-sweep) — avoids re-parsing the secrets and re-logging
      // any config error per expiring challenge.
      const channels = this.notifications.channels();
      for await (const page of listPrefixPages<Challenge>(this.ctx.storage, 'ch:')) {
        const toDelete: string[] = [];
        for (const [key, ch] of page) {
          if (ch.status === 'pending' && now - ch.created_ms >= TTL_MS) {
            // `ch` is a stale list snapshot; a decision may have committed after
            // it. expireChallenge re-reads atomically and no-ops if terminal,
            // preserving the decision, audit row, and notification state. It
            // drops pt: itself and dispatches notification edits via waitUntil.
            await this.expireChallenge(ch.approve_token, now, channels);
          } else if (
            ch.status !== 'pending'
            && ch.finalized_ms != null
            && now - ch.finalized_ms >= RETENTION_MS
          ) {
            toDelete.push(key, `pt:${ch.poll_token}`);
          }
        }
        if (toDelete.length) await deleteKeysBatched(this.ctx.storage, toDelete);
      }
    } catch (e) {
      logErr('alarm.challenge_sweep_failed', e);
    }

    // 2. DEK-cache entries: delete past expires_ms. Read-time expiry in
    // opDekCache is the authoritative guard; this just bounds storage growth.
    try {
      await this.cache.sweepExpired(now);
    } catch (e) {
      logErr('alarm.cache_sweep_failed', e);
    }

    // 3. Audit rows past 90-day retention (cheap: bound param + idx_audit_created).
    // Ceremony + cache events share this table, so one DELETE covers everything.
    this.audit.sweep(now);

    // 4. Admin audit-stream sockets: close any whose Access-JWT `exp` has passed,
    // so a hibernating stream cannot outlive the admin's authenticated session.
    // Bounds staleness to at most one alarm period (TTL_MS) past exp. A socket
    // with no/garbled attachment is treated as expired (fail closed).
    try {
      const nowSec = Math.floor(now / 1000);
      for (const ws of this.ctx.getWebSockets('admin')) {
        let exp = 0;
        try { exp = (ws.deserializeAttachment() as { exp?: number } | null)?.exp ?? 0; } catch {}
        if (nowSec >= exp) { try { ws.close(4001, 'access session expired'); } catch {} }
      }
    } catch (e) {
      logErr('alarm.admin_ws_sweep_failed', e);
    }

    } finally {
      // Always reschedule, even if a sweep threw, so periodic cleanup self-heals
      // instead of stopping forever once CF exhausts its automatic alarm retries.
      // If the reschedule ITSELF fails, rethrow so CF's at-least-once alarm retry
      // (exponential backoff, up to 6×) gets a chance to re-run and re-arm — the
      // sweep above is idempotent (expireChallenge no-ops on already-terminal
      // rows), so a re-run is safe. Swallowing here would forfeit that last line
      // of defense and leave the alarm dropped until the next cold start / opCreate.
      try {
        await this.ctx.storage.setAlarm(Date.now() + TTL_MS);
      } catch (e) {
        logErr('alarm.reschedule_failed', e);
        throw e;
      }
    }
  }

  // ── HTTP ops ──────────────────────────────────────────────────────────

  // Atomically expire ONE past-TTL pending challenge and fire all the terminal
  // side-effects: flip status→expired, notify the polling WS, finalize the audit
  // row, broadcast to admin streams, edit the Feishu card, and drop the pt:
  // routing key. Idempotent — a no-op if the challenge is already terminal or
  // gone. Re-reads under the DO gate (no await between get and put) so it cannot
  // clobber a decision that landed after the caller's snapshot, mirroring the
  // sweep's atomicity. SHARED by the alarm sweep AND the read-time expiry guards
  // (opPageData / opApprove / opReject), so a stale challenge is fully finalized
  // the moment anyone touches it — the audit row and Feishu card update even when
  // the alarm is not running, instead of waiting on (or depending on) the sweep.
  // The alarm passes once-parsed channel configs for the whole sweep.
  // One-shot expiry paths let notifications parse on demand.
  private async expireChallenge(
    approveToken: string,
    now: number,
    channels?: NotificationChannels,
  ): Promise<void> {
    const key = `ch:${approveToken}`;
    const fresh = await this.ctx.storage.get<Challenge>(key);
    if (!fresh || fresh.status !== 'pending') return; // already terminal / gone
    // Defense-in-depth: this method is named "expire", not "expire-if-due", so a
    // future caller could reasonably invoke it after checking only status. Re-
    // validate the TTL against the freshly-read record so a still-in-window
    // pending challenge can never be force-expired (which would be a DoS on a
    // legitimate approval). All current callers gate on isPendingExpired first;
    // this guarantees correctness even if one forgets.
    if (now - fresh.created_ms < TTL_MS) return;
    fresh.status = 'expired';
    fresh.finalized_ms = now;
    await this.ctx.storage.put(key, fresh);
    const wss = this.ctx.getWebSockets(`pt:${fresh.poll_token}`);
    for (const ws of wss) {
      try { ws.send(JSON.stringify({ status: 'expired' } satisfies WsMessage)); ws.close(1000, 'expired'); } catch {}
    }
    log('expired', {
      at: tokenPrefix(fresh.approve_token),
      op_kind: fresh.meta.op_kind,
      host: fresh.meta.host,
      user: fresh.meta.user,
      tty: fresh.meta.tty,
      age_ms: now - fresh.created_ms,
    });
    this.audit.finalize(fresh.approve_token, 'expired', now - fresh.created_ms);
    this.audit.broadcastRow(auditKey(fresh.approve_token), 'update');
    this.notifications.edit(fresh, 'expired', {}, channels);
    // Retain `ch:` for RETENTION_MS so an in-flight WS reconnect still sees the
    // terminal status; drop only the routing key now (a later RETENTION sweep
    // drops `ch:`).
    await this.ctx.storage.delete(`pt:${fresh.poll_token}`);
  }

  private async opCreate(request: Request): Promise<Response> {
    let parsed: DoCreateOp;
    try { parsed = await request.json() as DoCreateOp; }
    catch { return badRequest('invalid json'); }
    const challenge = parsed.challenge;
    if (!challenge || typeof challenge.approve_token !== 'string' || typeof challenge.poll_token !== 'string') {
      return badRequest('invalid challenge');
    }
    await this.storeAndAnnounce(challenge);
    return new Response('ok');
  }

  // Persist a pending challenge and its routing key, re-arm the alarm, then
  // record and broadcast its audit row. Both daemon and extension ceremonies
  // use this path; notifications keeps extension requests console-only.
  private async storeAndAnnounce(challenge: Challenge): Promise<void> {
    await this.ctx.storage.put({
      [`ch:${challenge.approve_token}`]: challenge,
      [`pt:${challenge.poll_token}`]: challenge.approve_token,
    });
    // Belt-and-suspenders: guarantee a sweep is scheduled for this new pending
    // challenge. If a prior alarm halted (older builds could throw before their
    // reschedule; CF then exhausts retries and CLEARS the alarm), getAlarm()
    // returns null and nothing would ever expire this row. Re-arm here so every
    // new ceremony revives the sweep, independent of constructor timing.
    try {
      if ((await this.ctx.storage.getAlarm()) == null) {
        await this.ctx.storage.setAlarm(Date.now() + TTL_MS);
      }
    } catch (e) {
      logErr('alarm.rearm_on_create_failed', e);
    }
    if (this.audit.create(challenge)) {
      this.audit.broadcastRow(auditKey(challenge.approve_token), 'insert');
    }

    this.notifications.approval(challenge);
  }

  private async opApprove(request: Request): Promise<Response> {
    let body: DoApproveOp;
    let pwaPkBytes: Uint8Array;
    try {
      body = await request.json() as DoApproveOp;
      // Length-cap before the token becomes a DO storage key (2048-byte limit):
      // an over-long key throws synchronously, surfacing as a 500 instead of a
      // controlled 404. Ceremony tokens are 16 chars; 128 is generous.
      if (typeof body.approve_token !== 'string' || !body.approve_token
          || body.approve_token.length > 128) throw new Error('approve_token');
      if (!isB64uString(body.credential_id_b64u)) throw new Error('credential_id_b64u');
      if (!isB64uString(body.sealed_deks_b64u)) throw new Error('sealed_deks_b64u');
      if (!isB64uString(body.client_data_json_b64u)) throw new Error('client_data_json_b64u');
      if (!isB64uString(body.authenticator_data_b64u)) throw new Error('authenticator_data_b64u');
      if (!isB64uString(body.signature_b64u)) throw new Error('signature_b64u');
      if (!isB64uString(body.binding_tag_b64u)) throw new Error('binding_tag_b64u');
      pwaPkBytes = decodeB64uExact(body.pwa_pk_b64u, 32, 'pwa_pk_b64u');
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }

    const ch = await this.ctx.storage.get<Challenge>(`ch:${body.approve_token}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') {
      // Idempotent re-delivery: if already approved return the existing sealed result
      if (ch.status === 'approved' && ch.sealed_deks_b64u && ch.pwa_pk_b64u && ch.binding_tag_b64u) {
        return Response.json({
          sealed_deks_b64u: ch.sealed_deks_b64u,
          pwa_pk_b64u: ch.pwa_pk_b64u,
          binding_tag_b64u: ch.binding_tag_b64u,
        });
      }
      return new Response('challenge not pending', { status: 410 });
    }
    // Fail closed on a past-TTL pending challenge even if the alarm has not yet
    // finalized it — a request may never be approved once its window has passed.
    // Finalize it here too so a decision attempt on a stale request still flips
    // the audit row + Feishu card, independent of the sweep.
    {
      const nowMs = Date.now();
      if (isPendingExpired(ch, nowMs)) {
        // Fail closed even if finalizing side-effects throw — the window passed.
        try { await this.expireChallenge(ch.approve_token, nowMs); }
        catch (e) { logErr('expire.approve_failed', e); }
        return new Response('challenge expired', { status: 410 });
      }
    }

    // Verify WebAuthn assertion
    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch (e) {
      logErr('credentials.parse_error', e);
      return new Response('server error', { status: 500 });
    }
    const credId = b64uDec(body.credential_id_b64u);
    const entry = await lookupByCredentialId(creds, credId);
    if (!entry) {
      this.audit.verifyFailure(ch.approve_token);
      return new Response('unknown credential', { status: 401 });
    }

    // Effective challenge = SHA-256(approve_challenge_hash || pwa_pk). Binding
    // pwa_pk into the authenticator signature means a wire-MITM cannot swap it
    // for their own pubkey and re-seal the DEKs. A malicious Worker can still
    // substitute its own pwa_pk (the Worker forwards page data), so the
    // daemon-side verify_binding HMAC is what closes that gap.
    const approveChallengeHash = b64uDec(ch.approve_challenge_hash_b64u);
    const effective = new Uint8Array(approveChallengeHash.length + pwaPkBytes.length);
    effective.set(approveChallengeHash, 0);
    effective.set(pwaPkBytes, approveChallengeHash.length);
    const expectedChallenge = new Uint8Array(
      await crypto.subtle.digest('SHA-256', effective)
    );

    const coseKey = b64uDec(entry.p);
    try {
      await verifyAssertion({
        cosePublicKey: coseKey,
        clientDataJson: b64uDec(body.client_data_json_b64u),
        authenticatorData: b64uDec(body.authenticator_data_b64u),
        signature: b64uDec(body.signature_b64u),
        expectedChallenge,
        rpId: this.env.RP_ID,
        expectedOrigin: this.expectedOrigin,
        // From the STORED ceremony, never the request: the level this challenge
        // was created with is the level its assertion is checked against.
        userVerification: challengeUvLevel(ch.uv),
      });
    } catch (e) {
      logErr('webauthn.verify_failed', e, { at: tokenPrefix(ch.approve_token) });
      this.audit.verifyFailure(ch.approve_token);
      return new Response('assertion verification failed', { status: 401 });
    }

    // `ch` was read before the (non-storage) crypto/verify awaits, during which
    // the DO input gate is open — so (a) the fire-and-forget notification send
    // may have written feishu_message_id, and (b) a concurrent expiry
    // (read-time expireChallenge from another tab/device, or the alarm) or a
    // racing decision may have finalized this challenge. Re-read once: bail if it
    // is no longer pending rather than clobber a terminal status (which would
    // double-finalize the audit row and emit a ✅ that contradicts the stored
    // ⌛/❌), else merge feishu_message_id forward. The get→put pair has no
    // intervening await, so nothing can slip between the check and the put.
    const latest = await this.ctx.storage.get<Challenge>(`ch:${ch.approve_token}`);
    if (!latest || latest.status !== 'pending') {
      // If a duplicate approve already sealed this, re-deliver idempotently.
      if (latest && latest.status === 'approved' && latest.sealed_deks_b64u && latest.pwa_pk_b64u && latest.binding_tag_b64u) {
        return Response.json({
          sealed_deks_b64u: latest.sealed_deks_b64u,
          pwa_pk_b64u: latest.pwa_pk_b64u,
          binding_tag_b64u: latest.binding_tag_b64u,
        });
      }
      return new Response('challenge not pending', { status: 410 });
    }
    // Verification can cross the TTL without an alarm or another request
    // finalizing this still-pending record. Check liveness at the write too.
    const finalizedMs = Date.now();
    if (isPendingExpired(latest, finalizedMs)) {
      try { await this.expireChallenge(ch.approve_token, finalizedMs); }
      catch (e) { logErr('expire.approve_failed', e); }
      return new Response('challenge expired', { status: 410 });
    }
    ch.status = 'approved';
    ch.sealed_deks_b64u = body.sealed_deks_b64u;
    ch.pwa_pk_b64u = body.pwa_pk_b64u;
    ch.binding_tag_b64u = body.binding_tag_b64u;
    ch.finalized_ms = finalizedMs;
    ch.feishu_message_id = latest.feishu_message_id;
    ch.slackapp = latest.slackapp;
    await this.ctx.storage.put(`ch:${ch.approve_token}`, ch);

    log('approved', {
      at: tokenPrefix(ch.approve_token),
      op_kind: ch.meta.op_kind,
      host: ch.meta.host,
      user: ch.meta.user,
      tty: ch.meta.tty,
      latency_ms: ch.finalized_ms - ch.created_ms,
    });
    this.audit.finalize(ch.approve_token, 'approved', ch.finalized_ms - ch.created_ms);

    // Edit the Feishu / Slack App message to ✅ 已批准, naming the Passkey that approved.
    this.notifications.edit(ch, 'approved', { approverLabel: entry.l, latencyMs: ch.finalized_ms - ch.created_ms });

    // Opt-in DEK cache write. Best-effort: a failure here must never break the
    // approval (the daemon already has its sealed DEKs via the WS path below).
    const ttlS = typeof body.cache_ttl_s === 'number' ? body.cache_ttl_s : 0;
    if (ttlS > 0) {
      try { await this.writeCache(ch, ttlS, body.cache_sealed_deks_b64u); }
      catch (e) { logErr('cache.write_failed', e, { at: tokenPrefix(ch.approve_token) }); }
    }

    // Cache-extension ceremony: moving expires_ms forward on the named groups is
    // the ONLY effect of approving one (it carries no salts, so the block above
    // never runs for it). Reached only after the assertion verified AND the
    // challenge was flipped to 'approved' under the DO gate, so the intent is
    // single-use: a replayed approve hits the idempotent early-return above and
    // cannot extend twice. Best-effort like writeCache — a failure here leaves the
    // ceremony approved with nothing extended, which is the fail-closed direction.
    if (ch.extend) {
      try { await this.commitExtend(ch, ch.extend); }
      catch (e) { logErr('cache.extend_failed', e, { at: tokenPrefix(ch.approve_token) }); }
    }

    // One admin broadcast for the whole approval — AFTER writeCache, so the
    // pushed row already carries the final cache_ttl_s (writeCache's
    // audit.setCacheTtl deliberately does not broadcast to avoid a duplicate).
    this.audit.broadcastRow(auditKey(ch.approve_token), 'update');

    // Wake waiting WS clients
    const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
    const wsMsg = JSON.stringify({
      status: 'approved',
      sealed_deks_b64u: body.sealed_deks_b64u,
      pwa_pk_b64u: body.pwa_pk_b64u,
      binding_tag_b64u: body.binding_tag_b64u,
    } satisfies WsMessage);
    for (const ws of wss) {
      try { ws.send(wsMsg); ws.close(1000, 'approved'); } catch {}
    }

    return Response.json({
      sealed_deks_b64u: body.sealed_deks_b64u,
      pwa_pk_b64u: body.pwa_pk_b64u,
      binding_tag_b64u: body.binding_tag_b64u,
    });
  }

  // Fast path: look up cached DEKs for (IP, salts). All-or-nothing — any
  // missing/expired/undecryptable salt yields a uniform miss (no oracle for
  // which salts are cached). On a full hit, re-seal each DEK to the requester's
  // ephemeral daemon pubkey so only this caller can open the response. Skips the
  // verify_binding path entirely (no PWA here); the Rust client asserts the
  // {source:'cache'} discriminant before accepting an unbound response.
  private async opDekCache(request: Request): Promise<Response> {
    let body: DoDekCacheOp;
    let daemonPk: Uint8Array;
    try {
      body = await request.json() as DoDekCacheOp;
      daemonPk = decodeB64uExact(body.daemon_pubkey_b64u, 32, 'daemon_pubkey_b64u');
      if (!Array.isArray(body.salts_b64u)) throw new Error('salts_b64u');
      if (!body.meta || typeof body.meta !== 'object') throw new Error('meta');
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }
    const meta = body.meta;
    // ip (worker-derived from CF-Connecting-IP, already forced by capChallengeMeta)
    // IP + pwd are the cache binding ctx. ppid is forensic-only (logged/audited).
    const ip = meta.ip ?? '';
    const ppid = (typeof meta.ppid === 'number' ? meta.ppid : 0) >>> 0;
    const salts = body.salts_b64u;
    const miss = (): Response => {
      // No audit row for misses (per design): a miss is a routine fallback and
      // the ceremony it triggers is itself audited. Keep only a debug log.
      log('cache.miss', { n: salts.length, ip, ppid });
      return Response.json({ miss: true } satisfies DekCacheResponse);
    };

    const sealedB64u = await this.cache.read(meta, salts, daemonPk);
    if (sealedB64u === null) return miss();

    // Audit the hit with the requester's full meta (host/user/command/…), so the
    // detail dialog is as rich as a ceremony decrypt.
    this.audit.cacheEvent(meta, salts.length, 'approved');
    log('cache.hit', { n: salts.length, ip, ppid });

    // Real-time notice: a cache hit serves a decrypt with NO phone in the loop,
    // so push the same opt-in channels used for approvals. Fire-and-forget —
    // delivery is best-effort and must never delay or fail the DEK response
    // (the audit row above is the durable record).
    this.notifications.cacheHit(meta, salts.length);
    return Response.json({ source: 'cache', sealed_deks_b64u: sealedB64u } satisfies DekCacheResponse);
  }

  // Ingest one SSH-agent audit record. The Worker has already verified the
  // per-agent HMAC, capped `meta`, and bounded the scalars; we just insert.
  // Return 200 on success so the agent's 1-retry stops (a non-2xx would make it
  // retry a row that already landed). Best-effort: audit.agent swallows DB errors.
  private async opAuditIngest(request: Request): Promise<Response> {
    let op: DoAuditIngestOp;
    try { op = await request.json() as DoAuditIngestOp; }
    catch { return badRequest('invalid json'); }
    if (!op || typeof op.token_id !== 'string' || !op.token_id
        || !op.meta || typeof op.meta !== 'object') {
      return badRequest('invalid audit op');
    }
    this.audit.agent(op);
    // An agent cache hit (sign / decrypt@vt served from the Touch ID auth
    // cache) had no human in the loop, so surface it on the same channels as
    // the Worker DEK-cache 免审批 notice. Throttled; fire-and-forget.
    if (op.outcome === 'cache_hit') this.notifications.agentCacheHit(op);
    return Response.json({ ok: true });
  }

  // Admin: clear the cached DEKs written by ONE approval, identified by its
  // audit token_id (cache entries store origin_token_id = the approval's
  // token_id). Powers the per-row "清除缓存" button on the audit page.
  private async opCacheClearByOrigin(request: Request): Promise<Response> {
    let tokenId: string;
    try {
      const body = await request.json() as { token_id?: unknown };
      if (typeof body.token_id !== 'string' || !body.token_id) throw new Error('token_id');
      tokenId = body.token_id;
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }
    const { deleted, scanned } = await this.cache.clearByOrigin(tokenId);
    // Clears are benign admin actions (no secret exposure) — logged to CF logs,
    // not the audit table, to keep it focused on DEK-delivery events.
    log('cache.cleared_by_origin', { at: tokenPrefix(tokenId), n: deleted, scanned });
    return Response.json({ cleared: deleted });
  }

  // ── Admin cache inventory + extension ──────────────────────────────────
  //
  // Design note. Everything below is Cloudflare-Access gated at the edge, but
  // Access alone is only sufficient for the AUTHORITY-REDUCING actions (list,
  // clear): their worst case is "secrets deleted, decrypts re-prompt". Extending
  // a cache prolongs no-human-in-the-loop DEK delivery, so an Access session must
  // NOT be able to do it by itself — opCacheExtendCreate only creates a pending
  // ceremony, and the expiry does not move until a Passkey approves it
  // (opApprove → commitExtend). See docs/dek-cache.md.

  // Admin: inventory of what is actually cached right now, grouped by the approval
  // that armed it. Read-only. Returns NO secret material (no sealed blob, no ctx,
  // no salts) — see the note on scanCacheGroups.
  private async opCacheList(): Promise<Response> {
    const now = Date.now();
    let scan;
    try {
      scan = await this.cache.scanCacheGroups(now);
    } catch (e) {
      logErr('cache.list_failed', e);
      return new Response('cache list failed', { status: 500 });
    }
    const ctxRows = this.audit.contextFor([...scan.groups.values()].map(g => g.origin_token_id));
    const groups: CacheGroupSummary[] = [];
    for (const g of scan.groups.values()) {
      const row = ctxRows.get(g.origin_token_id);
      // Extendability is decided here so the UI never has to re-derive the policy
      // (and can explain a refusal); the commit path re-checks it anyway. With the
      // lifetime budget gone, the only reasons left are structural: a lapsed grant
      // cannot be revived, and a drifted group cannot be reasoned about.
      let reason: string | null = null;
      if (!isExtendableGroupId(g.group_id)) reason = 'not_extendable';
      else if (!g.consistent) reason = 'inconsistent';
      else if (g.live === 0) reason = 'expired';
      groups.push({
        group_id: g.group_id,
        origin_token_id: g.origin_token_id,
        entries: g.entries,
        live: g.live,
        max_expires_ms: g.max_expires_ms,
        created_ms: g.created_ms,
        ip: g.ip,
        ppid: g.ppid,
        ppid_cmd: g.ppid_cmd,
        host: row?.host ?? null,
        user: row?.user ?? null,
        pwd: row?.pwd ?? null,
        command: row?.command ?? null,
        finalized_ms: row?.finalized_ms ?? null,
        cache_ttl_s: row?.cache_ttl_s ?? null,
        extendable: reason === null,
        reason,
      });
    }
    // Newest-first: the entries that matter most (longest still to run) on top.
    groups.sort((a, b) => b.max_expires_ms - a.max_expires_ms);
    if (scan.truncated) {
      log('cache.list_truncated', { scanned: scan.scanned, groups: groups.length });
    }
    const resp: CacheListResponse = {
      groups,
      now_ms: now,
      scanned: scan.scanned,
      truncated: scan.truncated,
      extend_enabled: cacheAdminExtendEnabled(this.env),
      ttl_options_s: extendTtlOptions(),
    };
    return Response.json(resp);
  }

  // Admin: clear whole groups in one round trip (bulk selection on the cache tab).
  // Authority-REDUCING, so Access alone is sufficient — no ceremony. Accepts
  // `legacy:` handles too, so pre-migration entries stay revocable.
  private async opCacheClearGroups(request: Request): Promise<Response> {
    let ids: string[];
    try {
      const body = await request.json() as { group_ids?: unknown };
      if (!Array.isArray(body.group_ids) || body.group_ids.length === 0) {
        throw new Error('group_ids');
      }
      ids = body.group_ids
        .filter((g): g is string => typeof g === 'string' && g.length > 0 && g.length <= 80)
        .slice(0, 512);
      if (ids.length === 0) throw new Error('group_ids');
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }
    // Deliberately NOT scanCacheGroups: that scan stops at CACHE_LIST_SCAN_MAX
    // and only the LISTING surfaces the resulting `truncated`. Reusing it here
    // meant a group sorting past the cap was never seen, never deleted, and the
    // route still answered 200 {"cleared":0} — a silent partial revocation on
    // the admin tab's only per-row revoke path. Clearing pages to the end.
    const { deleted, scanned, groups } = await this.cache.clearGroups(ids);
    log('cache.cleared_groups', { groups, n: deleted, scanned });
    return Response.json({ cleared: deleted, groups });
  }

  // Admin: REQUEST an extension. This mints a pending Passkey ceremony and nothing
  // else — no expiry moves here. The intent (groups + TTL + requester) is written
  // onto the challenge and never mutated, so the approval finalizes exactly what
  // was proposed, and the 5-minute challenge TTL bounds how long the request stays
  // approvable.
  private async opCacheExtendCreate(request: Request): Promise<Response> {
    if (!cacheAdminExtendEnabled(this.env)) {
      return new Response('cache extension disabled', { status: 404 });
    }
    let op: DoCacheExtendCreateOp;
    try { op = await request.json() as DoCacheExtendCreateOp; }
    catch { return badRequest('invalid json'); }
    if (!isAllowedExtendTtl(op.ttl_s)) return badRequest('ttl_s not whitelisted');
    const ttlS = op.ttl_s;
    if (!Array.isArray(op.group_ids) || op.group_ids.length === 0) {
      return badRequest('group_ids required');
    }
    if (op.group_ids.length > CACHE_EXTEND_MAX_GROUPS) {
      return badRequest(`at most ${CACHE_EXTEND_MAX_GROUPS} groups per request`);
    }
    const rejected: Array<{ group_id: string; reason: string }> = [];
    const requested: string[] = [];
    // Dedupe FIRST: a duplicated id would otherwise appear twice in
    // intent.preview and inflate the "N 组 / M 条" scope the approver reads on the
    // ceremony page. The commit dedupes anyway, so the effect was already correct
    // — but what the human is asked to approve must match it exactly.
    for (const g of new Set(op.group_ids)) {
      if (isExtendableGroupId(g)) requested.push(g);
      else rejected.push({ group_id: String(g).slice(0, 80), reason: 'not_extendable' });
    }
    if (requested.length === 0) return badRequest('no extendable group ids');

    const now = Date.now();
    const scan = await this.cache.scanCacheGroups(now, { want: new Set(requested) });
    const targets: CacheExtendPreview[] = [];
    const ctxRows = this.audit.contextFor([...scan.groups.values()].map(g => g.origin_token_id));
    for (const gid of requested) {
      const agg = scan.groups.get(gid);
      if (!agg) { rejected.push({ group_id: gid, reason: 'gone' }); continue; }
      if (!agg.consistent) { rejected.push({ group_id: gid, reason: 'inconsistent' }); continue; }
      if (agg.live === 0) { rejected.push({ group_id: gid, reason: 'expired' }); continue; }
      // Refuse a request that provably cannot move expiry forward, rather than mint
      // a ceremony that asks a human to approve a no-op.
      if (now + ttlS * 1000 <= agg.max_expires_ms) {
        rejected.push({ group_id: gid, reason: 'no_gain' }); continue;
      }
      targets.push({
        group_id: gid,
        live: agg.live,
        expires_ms: agg.max_expires_ms,
        host: ctxRows.get(agg.origin_token_id)?.host ?? '',
        ip: agg.ip,
      });
    }
    if (targets.length === 0) {
      return Response.json({ error: 'no_extendable_targets', rejected }, { status: 409 });
    }

    const intent: CacheExtendIntent = {
      group_ids: targets.map(t => t.group_id),
      ttl_s: ttlS,
      requested_by: op.admin_email ?? '',
      preview: targets,
    };
    const summary = extendSummary(intent);

    // Build the ceremony. Reuses the normal challenge shape so the standard PWA,
    // the alarm sweep, the audit lifecycle, and the notification channels all work
    // unchanged. salts=[] (an extension mints no DEKs), and the daemon pubkey is a
    // key whose secret was destroyed at birth, so the PWA's placeholder seal is
    // undecryptable by anyone rather than merely ignored.
    const approveToken = b64uEnc(randomBytes(12));
    const pollToken = b64uEnc(randomBytes(12));
    const workerNonce = randomBytes(16);
    const daemonPk = discardedBoxPublicKey();
    const meta: ChallengeMeta = {
      op_kind: 'cache-extend',
      command: summary,
      host: 'admin',
      user: op.admin_email ?? '',
      pwd: '',
      tty: '',
      ppid_cmd: '',
      ppid: 0,
      ssh_client: '',
      ip: op.admin_ip ?? '',
      reason: '延长已授权的 DEK 缓存有效期',
    };
    const ch: Challenge = {
      approve_token: approveToken,
      poll_token: pollToken,
      daemon_pubkey_b64u: b64uEnc(daemonPk),
      worker_nonce_b64u: b64uEnc(workerNonce),
      timestamp_ms: now,
      approve_challenge_hash_b64u: b64uEnc(
        await challengeHash(daemonPk, workerNonce, now, [], 'approve')),
      reject_challenge_hash_b64u: b64uEnc(
        await challengeHash(daemonPk, workerNonce, now, [], 'reject')),
      salts_b64u: [],
      meta,
      // An extension GRANTS cache lifetime (docs/dek-cache.md §extend), and it
      // is a rare desk-bound admin ceremony, so it keeps the biometric step
      // whatever APPROVAL_UV_JSON does to the hot decrypt path.
      uv: 'required',
      status: 'pending',
      created_ms: now,
      extend: intent,
    };
    await this.storeAndAnnounce(ch);
    log('cache.extend_requested', {
      at: tokenPrefix(approveToken), ttl_s: ttlS,
      groups: targets.length, entries: targets.reduce((n, t) => n + t.live, 0),
      by: op.admin_email ?? '',
    });
    const resp: CacheExtendCreateResponse = {
      approve_token: approveToken,
      approve_url: `${this.env.WORKER_ORIGIN}/a/${approveToken}`,
      summary,
      targets,
      rejected,
    };
    return Response.json(resp);
  }

  // Storage owns validation and writes; the DO records their effect only after
  // the verified approval above. A rejected write explains the later re-prompt.
  private async writeCache(ch: Challenge, ttlS: number, sealedList: string[] | undefined): Promise<void> {
    const result = await this.cache.writeCache(ch, ttlS, sealedList, auditKey(ch.approve_token));
    if (!result.ok) {
      logErr('cache.write_rejected', new Error(result.reason));
      this.audit.cacheEvent(ch.meta, ch.salts_b64u.length, 'write_failed');
      return;
    }
    this.audit.setCacheTtl(ch.approve_token, ttlS, result.expires_ms);
    log('cache.written', {
      at: tokenPrefix(ch.approve_token), ttl_s: ttlS, n: ch.salts_b64u.length, group: result.group_id,
    });
  }

  // ONLY opApprove calls this, after verification and single-use consumption.
  // The switch can remove authority, never supply the Passkey authorization.
  private async commitExtend(ch: Challenge, intent: CacheExtendIntent): Promise<void> {
    if (!cacheAdminExtendEnabled(this.env)) {
      logErr('cache.extend_disabled_at_commit', new Error('CACHE_ADMIN_EXTEND off'));
      return;
    }
    if (!isAllowedExtendTtl(intent.ttl_s)) {
      logErr('cache.extend_bad_ttl', new Error(`ttl ${intent.ttl_s}`));
      return;
    }
    if (!intent.group_ids.some(isExtendableGroupId)) return;
    const result = await this.cache.commitExtend(intent);
    for (const effect of result.effects) {
      this.audit.bumpCacheExpiry(effect.origin_token_id, effect.expires_ms);
      this.audit.broadcastRow(effect.origin_token_id, 'update');
    }
    // Include acknowledged batches even when a later group/batch failed, and
    // record approved no-ops too. The ceremony row records the authorization.
    this.audit.cacheEvent({
      ...ch.meta,
      command: extendSummary(intent),
      reason: extendOutcomeSummary(result.skipped, result.extended, result.latest),
    }, result.extended, 'extended');
    log('cache.extended', {
      at: tokenPrefix(ch.approve_token), ttl_s: intent.ttl_s, groups: result.groups,
      n: result.extended, by: intent.requested_by,
    });
  }

  // Admin: wipe ALL audit rows (ceremony + cache events). Destructive,
  // Cloudflare-Access gated at the edge.
  private async opClearAudit(): Promise<Response> {
    try {
      this.audit.clear();
    } catch (e) {
      logErr('audit.clear_failed', e);
      return new Response('clear failed', { status: 500 });
    }
    log('audit.cleared', {});
    return Response.json({ ok: true });
  }

  // Admin: drop ALL cached DEKs immediately (emergency revocation). After this,
  // every decrypt falls through to a phone approval until new entries are
  // written. Cloudflare-Access gated at the Worker edge.
  private async opClearCache(): Promise<Response> {
    const { deleted } = await this.cache.clearAll();
    log('cache.cleared', { n: deleted });
    return Response.json({ cleared: deleted });
  }

  private async opReject(request: Request): Promise<Response> {
    let body: DoRejectOp;
    try {
      body = await request.json() as DoRejectOp;
      if (typeof body.approve_token !== 'string' || !body.approve_token
          || body.approve_token.length > 128) throw new Error('approve_token');
      if (!isB64uString(body.credential_id_b64u)) throw new Error('credential_id_b64u');
      if (!isB64uString(body.client_data_json_b64u)) throw new Error('client_data_json_b64u');
      if (!isB64uString(body.authenticator_data_b64u)) throw new Error('authenticator_data_b64u');
      if (!isB64uString(body.signature_b64u)) throw new Error('signature_b64u');
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }

    const ch = await this.ctx.storage.get<Challenge>(`ch:${body.approve_token}`);
    if (!ch) return new Response('not found', { status: 404 });
    {
      const nowMs = Date.now();
      if (ch.status !== 'pending' || isPendingExpired(ch, nowMs)) {
        if (isPendingExpired(ch, nowMs)) {
          try { await this.expireChallenge(ch.approve_token, nowMs); }
          catch (e) { logErr('expire.reject_failed', e); }
        }
        return new Response('challenge not pending', { status: 410 });
      }
    }

    // Verify WebAuthn assertion (reject also requires physical presence)
    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch {
      return new Response('server error', { status: 500 });
    }
    const credId = b64uDec(body.credential_id_b64u);
    const entry = await lookupByCredentialId(creds, credId);
    if (!entry) {
      this.audit.verifyFailure(ch.approve_token);
      return new Response('unknown credential', { status: 401 });
    }

    try {
      await verifyAssertion({
        cosePublicKey: b64uDec(entry.p),
        clientDataJson: b64uDec(body.client_data_json_b64u),
        authenticatorData: b64uDec(body.authenticator_data_b64u),
        signature: b64uDec(body.signature_b64u),
        expectedChallenge: b64uDec(ch.reject_challenge_hash_b64u),
        rpId: this.env.RP_ID,
        expectedOrigin: this.expectedOrigin,
        userVerification: challengeUvLevel(ch.uv),
      });
    } catch (e) {
      logErr('webauthn.verify_failed', e, { at: tokenPrefix(ch.approve_token) });
      this.audit.verifyFailure(ch.approve_token);
      return new Response('assertion verification failed', { status: 401 });
    }

    ch.status = 'rejected';
    ch.finalized_ms = Date.now();
    // See opApprove: re-read once after the verify awaits. Bail if no longer
    // pending (a concurrent expiry or decision landed) rather than clobber the
    // terminal status; else merge feishu_message_id forward. No await between the
    // check and the put.
    const latest = await this.ctx.storage.get<Challenge>(`ch:${ch.approve_token}`);
    if (!latest || latest.status !== 'pending') {
      return new Response('challenge not pending', { status: 410 });
    }
    ch.feishu_message_id = latest.feishu_message_id;
    ch.slackapp = latest.slackapp;
    await this.ctx.storage.put(`ch:${ch.approve_token}`, ch);

    const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
    for (const ws of wss) {
      try { ws.send(JSON.stringify({ status: 'rejected' } satisfies WsMessage)); ws.close(1000, 'rejected'); } catch {}
    }

    log('rejected', {
      at: tokenPrefix(ch.approve_token),
      op_kind: ch.meta.op_kind,
      host: ch.meta.host,
      user: ch.meta.user,
      tty: ch.meta.tty,
      latency_ms: ch.finalized_ms - ch.created_ms,
    });
    this.audit.finalize(ch.approve_token, 'rejected', ch.finalized_ms - ch.created_ms);
    this.audit.broadcastRow(auditKey(ch.approve_token), 'update');

    // Edit the Feishu / Slack App message to ❌ 已拒绝.
    this.notifications.edit(ch, 'rejected', {});

    return new Response('ok');
  }

  // Returns the data the approval page needs: challenge + credential info for allowCredentials.
  private async opPageData(url: URL): Promise<Response> {
    const approveToken = url.searchParams.get('approve_token') ?? '';
    // Length-cap before the token becomes a DO storage key (2048-byte limit): an
    // over-long key throws synchronously, surfacing as an uncontrolled 500
    // instead of a clean 404. Mirrors opApprove/opReject. Real tokens are 16 chars.
    if (!approveToken || approveToken.length > 128) return new Response('missing approve_token', { status: 400 });

    const ch = await this.ctx.storage.get<Challenge>(`ch:${approveToken}`);
    if (!ch) return new Response('not found', { status: 404 });
    // Non-pending OR past-TTL → gone. The read-time TTL check is the fallback
    // for a stalled alarm: the page shows "expired" the instant it is opened, and
    // opening it also FINALIZES the challenge (audit row + Feishu card + WS), so
    // those side-effects no longer depend on the sweep ever running.
    const nowMs = Date.now();
    if (ch.status !== 'pending' || isPendingExpired(ch, nowMs)) {
      // Fail closed: even if finalizing side-effects throw (storage/Feishu), the
      // challenge is expired, so still return 410 rather than a 500.
      if (isPendingExpired(ch, nowMs)) {
        try { await this.expireChallenge(approveToken, nowMs); }
        catch (e) { logErr('expire.page_failed', e); }
      }
      return new Response('challenge not pending', { status: 410 });
    }

    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch {
      return new Response('server error', { status: 500 });
    }

    // DEK-cache UI data. Only offer caching when CACHE_SECKEY is configured AND
    // the ceremony actually has DEKs to cache (auth-only ceremonies cannot). On
    // any derivation failure, degrade to "caching off" rather than erroring the
    // approval page.
    let cacheOptionsS: number[] = [0];
    let cachePubkeyB64u = '';
    const cachingConfigured = !!(this.env.CACHE_SECKEY && this.env.CACHE_SECKEY.trim());
    if (cachingConfigured && ch.salts_b64u.length > 0) {
      try {
        cachePubkeyB64u = b64uEnc(cachePublicKey(this.env.CACHE_SECKEY));
        cacheOptionsS = [0, ...approveTtlOptions()];
      } catch (e) {
        logErr('cache.pubkey_failed', e);
        cacheOptionsS = [0];
        cachePubkeyB64u = '';
      }
    }

    const pageData: ApprovePageData = {
      approve_token: approveToken,
      approve_challenge_b64u: ch.approve_challenge_hash_b64u,
      reject_challenge_b64u: ch.reject_challenge_hash_b64u,
      daemon_pubkey_b64u: ch.daemon_pubkey_b64u,
      salts_b64u: ch.salts_b64u,
      rp_id: this.env.RP_ID,
      allow_credentials: creds.c.map(e => ({ id_b64u: e.i, h_b64u: e.h, k_b64u: e.k })),
      // What the page asks the authenticator for. Server state, so a tampered
      // page can only make the ceremony fail its own verification, never pass a
      // weaker one.
      user_verification: challengeUvLevel(ch.uv),
      metadata: ch.meta,
      cache_options_s: cacheOptionsS,
      cache_pubkey_b64u: cachePubkeyB64u,
      // The reuse scope the approval would arm — normalized, so an approver on a
      // worktree path sees that the grant also covers the trunk and its siblings.
      // metadata.pwd keeps the literal directory next to it.
      cache_scope_pwd: cacheScopePwd(ch.meta.pwd ?? ''),
    };
    return Response.json(pageData);
  }

  // Read-only audit query for the admin page. Cursor pagination by id DESC.
  private async opAuditQuery(url: URL): Promise<Response> {
    try {
      return Response.json(this.audit.query(url.searchParams));
    } catch (e) {
      logErr('audit.query_failed', e);
      return new Response('audit query failed', { status: 500 });
    }
  }
}
