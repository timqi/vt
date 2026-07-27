// AccountDO — singleton Durable Object managing all in-flight challenges.
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
// challenges after RETENTION_MS. CF Durable Objects serialize requests (and
// alarms) per-instance, so the alarm sweep cannot race a mid-flight op on the
// same DO — no extra locking is needed.

import { DurableObject } from 'cloudflare:workers';
import { Env, Challenge, ChallengeMeta, ApprovePageData, DoCreateOp, DoApproveOp, DoRejectOp, DoDekCacheOp, DoAuditIngestOp, WsMessage, AdminWsMessage, AuditRow, AuditQueryResponse, CacheEntry, DekCacheResponse } from './types';
import { b64uDec, b64uEnc, isB64uString, decodeB64uExact, sha256 } from './crypto';
import { parseCredentials, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';
import { seal, openToCache, cachePublicKey } from './cache_crypto';
import { notifyCacheHit } from './notify';
import { parseFeishuConfig, sendApprovalCard, editCard, sendCacheHitNotice, FeishuConfig, FeishuState, Kv as FeishuKv } from './feishu';
import {
  parseSlackAppConfig,
  sendApprovalCard as sendSlackAppCard,
  editCard as editSlackAppCard,
  sendCacheHitNotice as sendSlackAppCacheHitNotice,
  SlackAppConfig, SlackAppState, SlackAppMsgRef,
} from './slack_app';
import { log, logErr, tokenPrefix } from './log';

const TTL_MS = 5 * 60 * 1000;
const RETENTION_MS = 10 * 60 * 1000;
// Audit rows (ceremony + cache events) are kept 90 days, then swept by the alarm.
const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
// Agent Touch-ID-cache hits inside a TTL window can arrive many times a minute
// (orchestrated callers); notify at most once per key per this interval. The
// audit table still records every hit — the notice is a heads-up, not a ledger.
const AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS = 60 * 1000;

// Allowed positive DEK-cache TTLs (seconds). A write with any value outside
// this set is rejected, so neither a tampered approve body nor a future UI typo
// can mint an over-long window. 0 ("do not cache") is NOT a member — it is the
// absence of a write. The PWA's radio options are [0, ...this] (see opPageData).
const CACHE_TTL_WHITELIST = new Set([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);

// Cap concurrent admin audit-stream sockets (multiple browser tabs / stale
// hibernated sockets). Bounds broadcast fan-out and DO memory; a new connect
// past the cap is refused (the client retries with backoff). Admin is a single
// operator, so this is generous.
const MAX_ADMIN_SOCKETS = 8;

// Column projection shared by opAuditQuery and the real-time broadcast, so a
// pushed row is byte-for-byte the same shape the REST query returns (no field
// can leak into the stream that the query itself does not already expose).
// Decrypt batch size of a ceremony — worker-derived (from the salts array the
// DEKs are minted for), not client-claimed meta. Joins the notification head
// line as `user@host · N 条`.
const chSalts = (ch: Challenge): number =>
  Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0;

const AUDIT_SELECT_COLS =
  `id, token_id, created_ms, finalized_ms, status, op_kind, command, reason,
   host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms,
   verify_failures, cache_ttl_s, ppid, source, seq,
   peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed`;

// DEK cache entry key. ctx binds the entry to (a) the requester's worker-derived
// IP (CF-Connecting-IP — unspoofable by the client, the hard boundary) AND (b)
// the client-reported working directory (pwd). A lookup recomputes ctx from the
// same IP + pwd, so a request from a different egress IP OR a different cwd finds
// no key (a clean miss, no oracle).
//
// pwd is CLIENT-REPORTED, so — like the removed ppid — it is advisory: a fully
// compromised local host can spoof it, so it does not widen the real (IP) hard
// boundary. Its value is same-host blast-radius reduction: a process decrypting
// from an UNRELATED directory misses the cache, so a cached grant for one project
// tree does not silently serve another. Crucially — and unlike ppid — pwd is
// STABLE across orchestrated callers (Claude Code, CI, make, tmux) that spawn a
// fresh shell per command from the same project dir, so the cache still hits.
//
// History: ctx v1 folded in the client-reported parent PID; that was dropped
// (v1→v2) because ppid is BOTH spoofable AND unstable (getppid() changes every
// call under orchestrators, so the cache never hit). ppid is still recorded on
// each entry + audit row for forensics. v2→v3 adds pwd. The effective hard
// guarantee is unchanged: within the TTL, possession of VT_PASSKEY_TOKEN behind
// the SAME egress IP; pwd only narrows it further, it never widens it.
async function cacheCtx(ip: string, pwd: string): Promise<string> {
  const enc = new TextEncoder();
  const tag = enc.encode('vt-dek-ctx-v3');
  const ipBytes = enc.encode(ip);
  const pwdBytes = enc.encode(pwd);
  // Length-prefix the IP so (ip="a", pwd="bc") and (ip="ab", pwd="c") can't
  // collide into the same digest. IP has no NUL, so a NUL separator is
  // unambiguous, but an explicit u32 length is simplest and future-proof.
  const lenPrefix = new Uint8Array(4);
  new DataView(lenPrefix.buffer).setUint32(0, ipBytes.length, false);
  const buf = new Uint8Array(tag.length + lenPrefix.length + ipBytes.length + pwdBytes.length);
  let o = 0;
  buf.set(tag, o); o += tag.length;
  buf.set(lenPrefix, o); o += lenPrefix.length;
  buf.set(ipBytes, o); o += ipBytes.length;
  buf.set(pwdBytes, o);
  return b64uEnc(await sha256(buf));
}

function cacheKey(ctx: string, saltB64u: string): string {
  return `dek:${ctx}:${saltB64u}`;
}

function badRequest(msg: string): Response {
  return new Response(msg, { status: 400 });
}

// Audit row key. approve_token is a 12-byte (16-char) capability, so this is
// effectively the whole token. Deliberately accepted: the token is only "live"
// during the ~5-min pending TTL, the audit surface is behind Cloudflare Access
// (admin = the owner), and approval still requires a server-verified WebAuthn
// assertion — so a stored token grants nothing on its own.
function auditKey(approveToken: string): string {
  return approveToken.slice(0, 16);
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
  // Monotonic audit change counter. Seeded from MAX(seq) in the constructor so
  // it survives DO eviction (every write persists seq), then ++'d per write.
  private seqCounter = 0;
  // Last agent-cache-hit notice per `${op_kind}|${host}` (epoch ms). In-memory
  // only: resets on DO eviction/hibernation — worst case one extra notice.
  private agentCacheNotifyMs = new Map<string, number>();

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.expectedOrigin = new URL(env.WORKER_ORIGIN).origin;
    // Create the audit table before any request/alarm can be dispatched, so a
    // ceremony write never races ahead of table creation.
    this.ctx.blockConcurrencyWhile(async () => {
      // Migrate away from any pre-existing per-event audit schema (older builds
      // of this branch used audit(ts_ms,event,token_prefix,...)). Audit data is
      // non-critical and per-event rows can't be faithfully converted to
      // per-challenge rows, so drop & rebuild rather than ALTER.
      const cols = this.ctx.storage.sql
        .exec<{ name: string }>(`PRAGMA table_info(audit)`)
        .toArray();
      if (cols.length > 0 && !cols.some(c => c.name === 'token_id')) {
        this.ctx.storage.sql.exec(`DROP TABLE audit`);
      }
      // One row per challenge (keyed by token_id). The lifecycle events
      // (created → approved/rejected/expired, plus verify_failures) are stages
      // of the SAME challenge, so the params are stored ONCE on create and the
      // terminal state is updated in place — no duplication, no second table.
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS audit (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           token_id TEXT UNIQUE NOT NULL,
           created_ms INTEGER NOT NULL,
           finalized_ms INTEGER,
           status TEXT NOT NULL,
           op_kind TEXT,
           command TEXT,
           reason TEXT,
           host TEXT,
           user TEXT,
           pwd TEXT,
           tty TEXT,
           ppid_cmd TEXT,
           ssh_client TEXT,
           ip TEXT,
           salts INTEGER,
           latency_ms INTEGER,
           verify_failures INTEGER NOT NULL DEFAULT 0,
           cache_ttl_s INTEGER,
           ppid INTEGER,
           source TEXT NOT NULL DEFAULT 'ceremony',
           seq INTEGER,
           peer_exe TEXT,
           key_fp TEXT,
           dest TEXT,
           scope_family TEXT,
           scope_label TEXT,
           grant_ttl_s INTEGER,
           relayed INTEGER
         )`,
      );
      // Additive migrations for older audit tables (token_id present but newer
      // columns missing): ALTER preserves existing rows, unlike the drop/rebuild
      // above which only fires for the pre-token_id schema. DEK-cache events
      // (hit/miss/clear) live in THIS same table — marked op_kind='cache' — so
      // there is one unified audit surface, no second table.
      const auditCols = this.ctx.storage.sql
        .exec<{ name: string }>(`PRAGMA table_info(audit)`)
        .toArray();
      const hasCol = (n: string) => auditCols.some(c => c.name === n);
      if (auditCols.length > 0 && !hasCol('cache_ttl_s')) {
        this.ctx.storage.sql.exec(`ALTER TABLE audit ADD COLUMN cache_ttl_s INTEGER`);
      }
      if (auditCols.length > 0 && !hasCol('ppid')) {
        this.ctx.storage.sql.exec(`ALTER TABLE audit ADD COLUMN ppid INTEGER`);
      }
      // `source` distinguishes ceremony / cache / agent rows. SQLite DOES allow
      // a NOT NULL DEFAULT <literal> on ALTER ADD COLUMN — the literal backfills
      // existing rows (which are all ceremony rows), so no separate UPDATE is
      // needed. (Surprises people; hence this note.) This reuses the `auditCols`/
      // `hasCol` snapshot taken once above — fine because it is the LAST ALTER in
      // this block. If a future migration is appended after it, re-run
      // `PRAGMA table_info(audit)` rather than trusting this now-stale snapshot.
      if (auditCols.length > 0 && !hasCol('source')) {
        this.ctx.storage.sql.exec(
          `ALTER TABLE audit ADD COLUMN source TEXT NOT NULL DEFAULT 'ceremony'`);
      }
      // seq: monotonic per-row change counter for the real-time admin stream's
      // reconnect catch-up. Re-snapshot table_info first — the `source` ALTER
      // above invalidated the `auditCols` snapshot (per the note there). Backfill
      // existing rows with seq = id (a valid monotonic ordering) so no row has a
      // NULL seq and `after_seq` catch-up covers historical rows uniformly.
      const colsAfterSource = this.ctx.storage.sql
        .exec<{ name: string }>(`PRAGMA table_info(audit)`)
        .toArray();
      if (colsAfterSource.length > 0 && !colsAfterSource.some(c => c.name === 'seq')) {
        this.ctx.storage.sql.exec(`ALTER TABLE audit ADD COLUMN seq INTEGER`);
        this.ctx.storage.sql.exec(`UPDATE audit SET seq = id WHERE seq IS NULL`);
      }
      // Agent-authoritative audit context (docs/approval-transparency.md §B).
      // Re-snapshot table_info — the `source`/`seq` ALTERs above invalidated
      // the earlier snapshots (per the note on the `source` migration). All
      // seven are plain nullable adds: NULL on pre-migration rows means "the
      // agent never sent the field", which is exactly the ingest convention.
      const colsForAgentCtx = this.ctx.storage.sql
        .exec<{ name: string }>(`PRAGMA table_info(audit)`)
        .toArray();
      if (colsForAgentCtx.length > 0 && !colsForAgentCtx.some(c => c.name === 'peer_exe')) {
        for (const col of ['peer_exe TEXT', 'key_fp TEXT', 'dest TEXT',
                           'scope_family TEXT', 'scope_label TEXT',
                           'grant_ttl_s INTEGER', 'relayed INTEGER']) {
          this.ctx.storage.sql.exec(`ALTER TABLE audit ADD COLUMN ${col}`);
        }
      }
      // Drop the short-lived standalone cache_audit table from an earlier build
      // of this branch — its events now live in the unified audit table.
      this.ctx.storage.sql.exec(`DROP TABLE IF EXISTS cache_audit`);
      // idx_audit_created serves the retention DELETE (created_ms range); the
      // /<ADMIN_SEG>/api/audit cursor query uses the implicit primary-key (id) index.
      this.ctx.storage.sql.exec(
        `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_ms)`,
      );
      // idx_audit_seq serves the reconnect catch-up query (seq > ? ORDER BY seq).
      this.ctx.storage.sql.exec(
        `CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit(seq)`,
      );
      // Seed the in-memory counter from the durable high-water mark so a restart
      // never re-issues a seq (which would let a reconnecting client skip a row).
      const seqRow = this.ctx.storage.sql
        .exec<{ m: number }>(`SELECT COALESCE(MAX(seq), 0) AS m FROM audit`)
        .toArray()[0];
      this.seqCounter = seqRow?.m ?? 0;
    });
    // Schedule initial alarm if none set (alarm() re-arms itself thereafter).
    this.ctx.storage.getAlarm()
      .then(a => { if (a == null) return this.ctx.storage.setAlarm(Date.now() + TTL_MS); })
      .catch(e => logErr('alarm.init_failed', e));
  }

  // Audit writes are best-effort: a failure must never break the ceremony, so
  // we swallow and log. All three run inside the DO's single-threaded op.

  // Next monotonic change counter. DO ops (and the alarm) are serialized per
  // instance, so a plain ++ is race-free — no atomics needed.
  private nextSeq(): number { return ++this.seqCounter; }

  // Send one message to every connected admin stream. Best-effort and isolated:
  // a failure here (or a dead socket) must never affect the ceremony or block
  // delivery to the OTHER sockets, so the whole thing is try/caught and each send
  // is individually guarded (mirrors the pt: broadcast pattern).
  private broadcastAdmin(msg: AdminWsMessage): void {
    try {
      const wss = this.ctx.getWebSockets('admin');
      if (wss.length === 0) return;   // nobody listening
      const text = JSON.stringify(msg);
      for (const ws of wss) {
        try { ws.send(text); } catch { /* dead socket; skip, don't block others */ }
      }
    } catch (e) {
      logErr('audit.broadcast_failed', e);
    }
  }

  // Push one audit row to every admin stream. The re-SELECT uses the shared
  // projection, so the pushed row cannot expose any field the REST audit query
  // does not. Skips the SELECT entirely when no admin sockets are connected.
  private broadcastRow(tokenId: string, event: 'insert' | 'update'): void {
    try {
      if (this.ctx.getWebSockets('admin').length === 0) return;
      const rows = this.ctx.storage.sql
        .exec(`SELECT ${AUDIT_SELECT_COLS} FROM audit WHERE token_id = ?`, tokenId)
        .toArray() as unknown as AuditRow[];
      const row = rows[0];
      if (!row) return;
      this.broadcastAdmin({ kind: 'audit', event, row });
    } catch (e) {
      logErr('audit.broadcast_failed', e);
    }
  }

  // INSERT the full challenge params once, at creation (status=pending). Returns
  // true only if a row was actually written (false on an ON CONFLICT no-op), so
  // the caller can skip a wasted broadcast on an idempotent re-create.
  private auditCreate(ch: Challenge): boolean {
    const m = ch.meta ?? ({} as Challenge['meta']);
    try {
      // source='ceremony' set explicitly (not relying on the column default) so
      // a future schema change can never silently mis-categorize these rows.
      const cursor = this.ctx.storage.sql.exec(
        `INSERT INTO audit
           (token_id, created_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, ppid, source, seq)
         VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ceremony', ?)
         ON CONFLICT(token_id) DO NOTHING`,
        auditKey(ch.approve_token),
        ch.created_ms ?? Date.now(),
        m.op_kind ?? null,
        m.command ?? null,
        m.reason ?? null,
        m.host ?? null,
        m.user ?? null,
        m.pwd ?? null,
        m.tty ?? null,
        m.ppid_cmd ?? null,
        m.ssh_client ?? null,
        m.ip ?? null,
        Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0,
        typeof m.ppid === 'number' ? m.ppid : null,
        this.nextSeq(),
      );
      return cursor.rowsWritten > 0;
    } catch (e) {
      logErr('audit.create_failed', e);
      return false;
    }
  }

  // UPDATE the terminal state in place (approved | rejected | expired).
  private auditFinalize(approveToken: string, status: string, latencyMs: number): void {
    try {
      this.ctx.storage.sql.exec(
        `UPDATE audit SET status = ?, finalized_ms = ?, latency_ms = ?, seq = ? WHERE token_id = ?`,
        status,
        Date.now(),
        latencyMs,
        this.nextSeq(),
        auditKey(approveToken),
      );
    } catch (e) {
      logErr('audit.finalize_failed', e, { status });
    }
  }

  // Increment the failed-verification counter for this challenge.
  private auditVerifyFailure(approveToken: string): void {
    try {
      this.ctx.storage.sql.exec(
        `UPDATE audit SET verify_failures = verify_failures + 1, seq = ? WHERE token_id = ?`,
        this.nextSeq(),
        auditKey(approveToken),
      );
      this.broadcastRow(auditKey(approveToken), 'update');
    } catch (e) {
      logErr('audit.verifyfail_failed', e);
    }
  }

  // Record the cache TTL the approver chose (0 / null = not cached).
  private auditSetCacheTtl(approveToken: string, ttlS: number): void {
    try {
      this.ctx.storage.sql.exec(
        `UPDATE audit SET cache_ttl_s = ?, seq = ? WHERE token_id = ?`,
        ttlS,
        this.nextSeq(),
        auditKey(approveToken),
      );
      // No broadcast here: this runs inside the approve flow, which emits a
      // single 'update' after writeCache so the pushed row already carries the
      // final cache_ttl_s (avoids a duplicate mid-approve broadcast).
    } catch (e) {
      logErr('audit.cachettl_failed', e);
    }
  }

  // Record a DEK-cache event in the UNIFIED audit table (op_kind='cache') so it
  // shows up alongside ceremony rows. We deliberately do NOT record misses (a
  // routine fallback whose ceremony is audited anyway); only meaningful events:
  // 'approved' = cache hit (DEK delivered without a phone tap) — the key
  // forensic trace; 'write_failed' = approved-with-TTL but the entry couldn't be
  // written (misconfig); 'cleared' = admin flush.
  // `meta` carries the same display fields as a ceremony row (host/user/command/
  // …), so a cache hit's detail is as rich as a normal decrypt. Only meaningful
  // events are recorded: 'approved' = cache hit (DEK delivered without a phone
  // tap — the key forensic trace); 'write_failed' = approved-with-TTL but the
  // entry couldn't be written. Cache clears are NOT recorded (benign admin
  // actions, logged to CF logs only).
  private auditCacheEvent(
    meta: Partial<ChallengeMeta>, salts: number,
    status: 'approved' | 'write_failed',
  ): void {
    try {
      const now = Date.now();
      // Synthetic unique token_id (no approve_token exists for cache events).
      const tokenId = 'c_' + b64uEnc(crypto.getRandomValues(new Uint8Array(9)));
      this.ctx.storage.sql.exec(
        `INSERT INTO audit
           (token_id, created_ms, finalized_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, ppid, source, seq)
         VALUES (?, ?, ?, ?, 'cache', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cache', ?)
         ON CONFLICT(token_id) DO NOTHING`,
        tokenId, now, now, status,
        meta.command ?? null, meta.reason ?? null, meta.host ?? null, meta.user ?? null,
        meta.pwd ?? null, meta.tty ?? null, meta.ppid_cmd ?? null, meta.ssh_client ?? null,
        meta.ip ?? null, salts, typeof meta.ppid === 'number' ? meta.ppid : null,
        this.nextSeq(),
      );
      this.broadcastRow(tokenId, 'insert');
    } catch (e) {
      logErr('audit.cacheevent_failed', e);
    }
  }

  // Insert one SSH-agent decision row (source='agent'). The event is atomic —
  // created_ms == finalized_ms == ts_ms. `ON CONFLICT(token_id) DO NOTHING`
  // makes the agent's 1-retry idempotent. Best-effort: swallow + log.
  private auditAgent(op: DoAuditIngestOp): void {
    const m = op.meta;
    try {
      const cursor = this.ctx.storage.sql.exec(
        `INSERT INTO audit
           (token_id, created_ms, finalized_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms, ppid, source, seq,
            peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'agent', ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(token_id) DO NOTHING`,
        op.token_id, op.ts_ms, op.ts_ms, op.outcome,
        m.op_kind ?? null, m.command ?? null, m.reason ?? null, m.host ?? null,
        m.user ?? null, m.pwd ?? null, m.tty ?? null, m.ppid_cmd ?? null,
        m.ssh_client ?? null, m.ip ?? null, op.salts, op.latency_ms,
        typeof m.ppid === 'number' ? m.ppid : null,
        this.nextSeq(),
        // Agent-authoritative context: the ingest already normalized these to
        // string/number/null — `?? null` only guards a malformed internal op.
        op.peer_exe ?? null, op.key_fp ?? null, op.dest ?? null,
        op.scope_family ?? null, op.scope_label ?? null,
        op.grant_ttl_s ?? null, op.relayed ?? null,
      );
      // Skip the broadcast on an idempotent-retry no-op (agent's 1-retry).
      if (cursor.rowsWritten > 0) this.broadcastRow(op.token_id, 'insert');
    } catch (e) {
      logErr('audit.agent_failed', e);
    }
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
      const list = await this.ctx.storage.list<Challenge>({ prefix: 'ch:' });
      const toDelete: string[] = [];
      // Parse the Feishu + Slack App configs ONCE for the whole sweep (they
      // can't change mid-sweep) — avoids re-parsing the secrets and re-logging
      // any config error per expiring challenge.
      const feishuSweepCfg = this.feishuCfg();
      const slackAppSweepCfg = this.slackAppCfg();
      for (const [key, ch] of list) {
        const ptKey = `pt:${ch.poll_token}`;
        if (ch.status === 'pending' && now - ch.created_ms >= TTL_MS) {
          // `ch` is a stale snapshot from list() at sweep start; a decision may
          // have committed after it. expireChallenge re-reads atomically and is a
          // no-op if no longer pending, so it can't clobber a terminal status,
          // double-finalize the audit row, or emit a ⌛ card edit that conflicts
          // with the decision's ✅/❌. It drops the pt: key itself; feishuEdit /
          // slackAppEdit fire via waitUntil, so a burst of expiries doesn't
          // stretch the sweep.
          await this.expireChallenge(ch.approve_token, now, feishuSweepCfg, slackAppSweepCfg);
        } else if (
          ch.status !== 'pending'
          && ch.finalized_ms != null
          && now - ch.finalized_ms >= RETENTION_MS
        ) {
          toDelete.push(key, ptKey);
        }
      }
      if (toDelete.length) await this.ctx.storage.delete(toDelete);
    } catch (e) {
      logErr('alarm.challenge_sweep_failed', e);
    }

    // 2. DEK-cache entries: delete past expires_ms. Read-time expiry in
    // opDekCache is the authoritative guard; this just bounds storage growth.
    try {
      const cacheList = await this.ctx.storage.list<CacheEntry>({ prefix: 'dek:' });
      const cacheDelete: string[] = [];
      for (const [key, entry] of cacheList) {
        if (entry.expires_ms <= now) cacheDelete.push(key);
      }
      if (cacheDelete.length) await this.ctx.storage.delete(cacheDelete);
    } catch (e) {
      logErr('alarm.cache_sweep_failed', e);
    }

    // 3. Audit rows past 90-day retention (cheap: bound param + idx_audit_created).
    // Ceremony + cache events share this table, so one DELETE covers everything.
    try {
      this.ctx.storage.sql.exec(`DELETE FROM audit WHERE created_ms < ?`, now - AUDIT_RETENTION_MS);
    } catch (e) {
      logErr('audit.sweep_failed', e);
    }

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
  // Pass cfgHint / slackCfgHint to reuse a once-parsed Feishu / Slack App config
  // (the batch sweep); omit them on the one-shot read paths so they parse on
  // demand.
  private async expireChallenge(
    approveToken: string,
    now: number,
    cfgHint?: FeishuConfig | null,
    slackCfgHint?: SlackAppConfig | null,
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
    this.auditFinalize(fresh.approve_token, 'expired', now - fresh.created_ms);
    this.broadcastRow(auditKey(fresh.approve_token), 'update');
    this.feishuEdit(fresh, 'expired', {}, cfgHint);
    this.slackAppEdit(fresh, 'expired', {}, slackCfgHint);
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
    if (this.auditCreate(challenge)) {
      this.broadcastRow(auditKey(challenge.approve_token), 'insert');
    }

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
    return new Response('ok');
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
      this.auditVerifyFailure(ch.approve_token);
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
      });
    } catch (e) {
      logErr('webauthn.verify_failed', e, { at: tokenPrefix(ch.approve_token) });
      this.auditVerifyFailure(ch.approve_token);
      return new Response('assertion verification failed', { status: 401 });
    }

    ch.status = 'approved';
    ch.sealed_deks_b64u = body.sealed_deks_b64u;
    ch.pwa_pk_b64u = body.pwa_pk_b64u;
    ch.binding_tag_b64u = body.binding_tag_b64u;
    ch.finalized_ms = Date.now();
    // `ch` was read before the (non-storage) crypto/verify awaits, during which
    // the DO input gate is open — so (a) the fire-and-forget feishuSendAndStore
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
    this.auditFinalize(ch.approve_token, 'approved', ch.finalized_ms - ch.created_ms);

    // Edit the Feishu / Slack App message to ✅ 已批准, naming the Passkey that approved.
    this.feishuEdit(ch, 'approved', { approverLabel: entry.l, latencyMs: ch.finalized_ms - ch.created_ms });
    this.slackAppEdit(ch, 'approved', { approverLabel: entry.l, latencyMs: ch.finalized_ms - ch.created_ms });

    // Opt-in DEK cache write. Best-effort: a failure here must never break the
    // approval (the daemon already has its sealed DEKs via the WS path below).
    const ttlS = typeof body.cache_ttl_s === 'number' ? body.cache_ttl_s : 0;
    if (ttlS > 0) {
      try { await this.writeCache(ch, ttlS, body.cache_sealed_deks_b64u); }
      catch (e) { logErr('cache.write_failed', e, { at: tokenPrefix(ch.approve_token) }); }
    }

    // One admin broadcast for the whole approval — AFTER writeCache, so the
    // pushed row already carries the final cache_ttl_s (writeCache's
    // auditSetCacheTtl deliberately does not broadcast to avoid a duplicate).
    this.broadcastRow(auditKey(ch.approve_token), 'update');

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

  // Write one cache entry per salt, keyed by ctx(IP,pwd)+salt. Caller has
  // already verified the WebAuthn assertion, so this is authorized. INVARIANT
  // (M1): we only reach here because the PHONE sent cache material (the PWA
  // produces it solely when the human picks TTL > 0) — the Worker cannot
  // fabricate a cache entry the user did not authorize.
  private async writeCache(ch: Challenge, ttlS: number, sealedList: string[] | undefined): Promise<void> {
    // A rejected write means the user approved WITH a TTL but no cache entry
    // exists — so subsequent decrypts will surprisingly re-prompt. Record a
    // 'write_failed' row in the unified audit (M2) so this is diagnosable from
    // the admin page, not just buried in Worker logs.
    const reject = (reason: string): void => {
      logErr('cache.write_rejected', new Error(reason));
      this.auditCacheEvent(
        ch.meta,
        Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0,
        'write_failed',
      );
    };

    if (!CACHE_TTL_WHITELIST.has(ttlS)) { reject(`ttl ${ttlS} not whitelisted`); return; }
    if (!this.env.CACHE_SECKEY || !this.env.CACHE_SECKEY.trim()) {
      reject('CACHE_SECKEY unset (caching disabled)'); return;
    }
    const salts = ch.salts_b64u;
    // Auth-only ceremonies (no salts) have nothing to cache; a length mismatch
    // means the PWA and challenge disagree — refuse rather than store garbage.
    if (salts.length === 0 || !Array.isArray(sealedList) || sealedList.length !== salts.length) {
      reject('cache_sealed_deks length mismatch'); return;
    }
    // Each blob must be crypto_box_seal(32-byte DEK) = 32 + 48 = 80 bytes AND
    // must actually open to CACHE_PUBKEY. Verifying at write time turns a stale
    // /wrong cache_pubkey on the phone into one logged error here, instead of
    // silent permanent cache misses + lazy-delete churn at read time (N1).
    for (const s of sealedList) {
      try { decodeB64uExact(s, 80, 'cache_sealed_dek'); }
      catch { reject('cache_sealed_dek malformed'); return; }
      const probe = openToCache(s, this.env.CACHE_SECKEY);
      if (!probe || probe.length !== 32) {
        reject('cache_sealed_dek does not open to CACHE_PUBKEY'); return;
      }
      probe.fill(0);
    }

    const ip = ch.meta.ip ?? '';
    // ppid is not part of the binding ctx (ctx = IP + pwd) — kept solely as a
    // forensic field stored on each cache entry + audit row.
    const ppid = typeof ch.meta.ppid === 'number' ? ch.meta.ppid : 0;
    const ctx = await cacheCtx(ip, ch.meta.pwd ?? '');
    const expires = Date.now() + ttlS * 1000;
    const writes: Record<string, CacheEntry> = {};
    for (let i = 0; i < salts.length; i++) {
      writes[cacheKey(ctx, salts[i]!)] = {
        sealed_to_cache_b64u: sealedList[i]!,
        expires_ms: expires,
        origin_token_id: auditKey(ch.approve_token),
        ip,
        ppid,
        ppid_cmd: ch.meta.ppid_cmd ?? '',
      };
    }
    await this.ctx.storage.put(writes);
    this.auditSetCacheTtl(ch.approve_token, ttlS);
    log('cache.written', { at: tokenPrefix(ch.approve_token), ttl_s: ttlS, n: salts.length });
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
    const pwd = meta.pwd ?? '';
    const salts = body.salts_b64u;
    const miss = (): Response => {
      // No audit row for misses (per design): a miss is a routine fallback and
      // the ceremony it triggers is itself audited. Keep only a debug log.
      log('cache.miss', { n: salts.length, ip, ppid });
      return Response.json({ miss: true } satisfies DekCacheResponse);
    };

    // Empty salt set: nothing to deliver. Never a hit.
    if (salts.length === 0 || salts.length > 256) return miss();
    if (!this.env.CACHE_SECKEY || !this.env.CACHE_SECKEY.trim()) return miss();
    for (const s of salts) { if (!isB64uString(s)) return miss(); }

    const ctx = await cacheCtx(ip, pwd);
    // Batch the lookups (M2): one storage.get over all keys, so response timing
    // does not leak the position of the first miss.
    const keys = salts.map(s => cacheKey(ctx, s));
    const map = await this.ctx.storage.get<CacheEntry>(keys);

    const now = Date.now();
    const orphaned: string[] = [];
    const dekParts: Uint8Array[] = [];
    for (const key of keys) {
      const entry = map.get(key);
      if (!entry || entry.expires_ms <= now) continue;
      const dek = openToCache(entry.sealed_to_cache_b64u, this.env.CACHE_SECKEY);
      if (!dek || dek.length !== 32) {
        // Undecryptable (e.g. CACHE_SECKEY rotated, M3) — treat as miss and
        // lazily drop the now-orphaned entry. Never surface a 500.
        orphaned.push(key);
        continue;
      }
      dekParts.push(dek);
    }
    if (orphaned.length) { try { await this.ctx.storage.delete(orphaned); } catch {} }

    // All-or-nothing: a full hit requires one opened DEK per salt. Any miss/
    // expired/undecryptable entry above simply didn't push, so a short count is
    // a uniform miss.
    if (dekParts.length !== salts.length) {
      return miss();
    }

    // Full hit: concatenate DEKs in salt order and re-seal to daemon pubkey.
    // try/finally guarantees the plaintext DEK bytes are wiped even if seal()
    // throws, so opened DEKs never linger in the Worker heap (S2).
    const flat = new Uint8Array(dekParts.length * 32);
    let sealedB64u: string;
    try {
      dekParts.forEach((d, i) => flat.set(d, i * 32));
      sealedB64u = seal(flat, daemonPk);
    } finally {
      flat.fill(0);
      dekParts.forEach(d => d.fill(0));
    }

    // Audit the hit with the requester's full meta (host/user/command/…), so the
    // detail dialog is as rich as a ceremony decrypt.
    this.auditCacheEvent(meta, salts.length, 'approved');
    log('cache.hit', { n: salts.length, ip, ppid });

    // Real-time notice: a cache hit serves a decrypt with NO phone in the loop,
    // so push the same opt-in channels used for approvals. Fire-and-forget —
    // delivery is best-effort and must never delay or fail the DEK response
    // (the audit row above is the durable record).
    this.pushCacheHitNotices(meta, salts.length, undefined, 'cachehit_failed');
    return Response.json({ source: 'cache', sealed_deks_b64u: sealedB64u } satisfies DekCacheResponse);
  }

  // Fan a cache-hit notice out to every configured channel (stateless
  // Pushover/Slack-webhook fanOut + Feishu + Slack App), each via waitUntil —
  // compact, no @, no edit lifecycle (terminal FYI). Shared by the Worker
  // DEK-cache hit (opDekCache) and the agent Touch-ID-cache hit
  // (notifyAgentCacheHit); `note` names the skipped factor when it isn't the
  // default phone approval, `errTag` distinguishes the two sources in logs.
  private pushCacheHitNotices(
    meta: ChallengeMeta,
    salts: number,
    note: string | undefined,
    errTag: string,
  ): void {
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

  // Ingest one SSH-agent audit record. The Worker has already verified the
  // per-agent HMAC, capped `meta`, and bounded the scalars; we just insert.
  // Return 200 on success so the agent's 1-retry stops (a non-2xx would make it
  // retry a row that already landed). Best-effort — auditAgent swallows DB errors.
  private async opAuditIngest(request: Request): Promise<Response> {
    let op: DoAuditIngestOp;
    try { op = await request.json() as DoAuditIngestOp; }
    catch { return badRequest('invalid json'); }
    if (!op || typeof op.token_id !== 'string' || !op.token_id
        || !op.meta || typeof op.meta !== 'object') {
      return badRequest('invalid audit op');
    }
    this.auditAgent(op);
    // An agent cache hit (sign / decrypt@vt served from the Touch ID auth
    // cache) had no human in the loop, so surface it on the same channels as
    // the Worker DEK-cache 免审批 notice. Throttled; fire-and-forget.
    if (op.outcome === 'cache_hit') this.notifyAgentCacheHit(op);
    return Response.json({ ok: true });
  }

  // Throttled 免审批 notice for an agent-side cache hit; the actual dispatch
  // is the shared pushCacheHitNotices. The note names the skipped factor —
  // Touch ID here, not a phone approval.
  private notifyAgentCacheHit(op: DoAuditIngestOp): void {
    const key = `${op.meta.op_kind}|${op.meta.host}`;
    const now = Date.now();
    if (now - (this.agentCacheNotifyMs.get(key) ?? 0) < AGENT_CACHE_NOTIFY_MIN_INTERVAL_MS) return;
    // Bound the map: keys are (op_kind, host) pairs, so growth needs a hostile
    // agent minting hostnames — cheap to cap anyway.
    if (this.agentCacheNotifyMs.size > 256) this.agentCacheNotifyMs.clear();
    this.agentCacheNotifyMs.set(key, now);

    this.pushCacheHitNotices(op.meta, op.salts, '缓存命中，免 Touch ID', 'agent_cachehit_failed');
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
    const list = await this.ctx.storage.list<CacheEntry>({ prefix: 'dek:' });
    const keys: string[] = [];
    for (const [key, e] of list) {
      if (e.origin_token_id === tokenId) keys.push(key);
    }
    if (keys.length) await this.ctx.storage.delete(keys);
    // Clears are benign admin actions (no secret exposure) — logged to CF logs,
    // not the audit table, to keep it focused on DEK-delivery events.
    log('cache.cleared_by_origin', { at: tokenPrefix(tokenId), n: keys.length });
    return Response.json({ cleared: keys.length });
  }

  // Admin: wipe ALL audit rows (ceremony + cache events). Destructive,
  // Cloudflare-Access gated at the edge.
  private async opClearAudit(): Promise<Response> {
    try {
      this.ctx.storage.sql.exec(`DELETE FROM audit`);
    } catch (e) {
      logErr('audit.clear_failed', e);
      return new Response('clear failed', { status: 500 });
    }
    // Notify every connected admin tab (not just the one that clicked) so none
    // keeps showing now-deleted rows. seqCounter is intentionally NOT reset —
    // staying monotonic means a reconnecting client's cursor never regresses.
    this.broadcastAdmin({ kind: 'clear' });
    log('audit.cleared', {});
    return Response.json({ ok: true });
  }

  // Admin: drop ALL cached DEKs immediately (emergency revocation). After this,
  // every decrypt falls through to a phone approval until new entries are
  // written. Cloudflare-Access gated at the Worker edge.
  private async opClearCache(): Promise<Response> {
    const list = await this.ctx.storage.list<CacheEntry>({ prefix: 'dek:' });
    const keys = [...list.keys()];
    if (keys.length) await this.ctx.storage.delete(keys);
    log('cache.cleared', { n: keys.length });
    return Response.json({ cleared: keys.length });
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
      this.auditVerifyFailure(ch.approve_token);
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
      });
    } catch (e) {
      logErr('webauthn.verify_failed', e, { at: tokenPrefix(ch.approve_token) });
      this.auditVerifyFailure(ch.approve_token);
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
    this.auditFinalize(ch.approve_token, 'rejected', ch.finalized_ms - ch.created_ms);
    this.broadcastRow(auditKey(ch.approve_token), 'update');

    // Edit the Feishu / Slack App message to ❌ 已拒绝.
    this.feishuEdit(ch, 'rejected', {});
    this.slackAppEdit(ch, 'rejected', {});

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
        cacheOptionsS = [0, ...[...CACHE_TTL_WHITELIST].sort((a, b) => a - b)];
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
      metadata: ch.meta,
      cache_options_s: cacheOptionsS,
      cache_pubkey_b64u: cachePubkeyB64u,
    };
    return Response.json(pageData);
  }

  // Read-only audit query for the admin page. Cursor pagination by id DESC.
  private async opAuditQuery(url: URL): Promise<Response> {
    const q = url.searchParams;
    const limRaw = parseInt(q.get('limit') ?? '100', 10);
    const limit = Math.min(Math.max(Number.isFinite(limRaw) ? limRaw : 100, 1), 500);

    const conds: string[] = [];
    const binds: (string | number)[] = [];
    const beforeId = q.get('before_id');
    if (beforeId && /^\d+$/.test(beforeId)) { conds.push('id < ?'); binds.push(parseInt(beforeId, 10)); }
    // after_seq: reconnect catch-up. Selects rows whose seq advanced past the
    // client's high-water mark — an id cursor cannot do this because a lifecycle
    // UPDATE bumps seq but not id. When present, order ASC by seq (chronological
    // replay) instead of the default id DESC (newest-first list).
    const afterSeqRaw = q.get('after_seq');
    const useAfterSeq = afterSeqRaw != null && /^\d+$/.test(afterSeqRaw);
    if (useAfterSeq) { conds.push('seq > ?'); binds.push(parseInt(afterSeqRaw!, 10)); }
    const status = q.get('status');
    // 'cache' is a pseudo-filter selecting records that ARMED a DEK cache (the
    // approvals where a TTL was chosen → cache_ttl_s set). It deliberately
    // EXCLUDES cache-event rows (hits/cleared/write_failed, op_kind='cache',
    // cache_ttl_s NULL) — those are consumption logs, not "records with a cache".
    if (status === 'cache') { conds.push(`cache_ttl_s IS NOT NULL`); }
    else if (status) { conds.push('status = ?'); binds.push(status); }
    const host = q.get('host');
    if (host) { conds.push('host = ?'); binds.push(host); }
    // Filter by row origin (ceremony / cache / agent). Independent of `status`.
    const source = q.get('source');
    if (source) { conds.push('source = ?'); binds.push(source); }

    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    const order = useAfterSeq ? 'ORDER BY seq ASC' : 'ORDER BY id DESC';
    const sql =
      `SELECT ${AUDIT_SELECT_COLS}
       FROM audit ${where} ${order} LIMIT ?`;
    binds.push(limit);

    try {
      const rows = this.ctx.storage.sql.exec(sql, ...binds).toArray() as unknown as AuditRow[];
      // Current high-water mark, so the client can set its reconnect cursor even
      // when this page returns no rows (e.g. an empty initial load).
      const snapRow = this.ctx.storage.sql
        .exec<{ m: number }>(`SELECT COALESCE(MAX(seq), 0) AS m FROM audit`)
        .toArray()[0];
      const resp: AuditQueryResponse = { rows, snapshot_seq: snapRow?.m ?? 0 };
      return Response.json(resp);
    } catch (e) {
      logErr('audit.query_failed', e);
      return new Response('audit query failed', { status: 500 });
    }
  }
}
