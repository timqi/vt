// AccountDO — singleton Durable Object managing all in-flight challenges.
//
// Storage keys:
//   ch:{approve_token}        →  Challenge JSON
//   pt:{poll_token}           →  approve_token (WS tag routing)
//   dek:{ctx}:{salt_b64u}     →  CacheEntry (opt-in DEK cache; ctx binds IP+PPID)
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
import { Env, Challenge, ChallengeMeta, ApprovePageData, DoCreateOp, DoApproveOp, DoRejectOp, DoDekCacheOp, WsMessage, AuditRow, AuditQueryResponse, CacheEntry, DekCacheResponse } from './types';
import { b64uDec, b64uEnc, isB64uString, decodeB64uExact, sha256 } from './crypto';
import { parseCredentials, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';
import { seal, openToCache, cachePublicKey } from './cache_crypto';
import { log, logErr, tokenPrefix } from './log';

const TTL_MS = 5 * 60 * 1000;
const RETENTION_MS = 10 * 60 * 1000;
// Audit rows (ceremony + cache events) are kept 90 days, then swept by the alarm.
const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

// Allowed positive DEK-cache TTLs (seconds). A write with any value outside
// this set is rejected, so neither a tampered approve body nor a future UI typo
// can mint an over-long window. 0 ("do not cache") is NOT a member — it is the
// absence of a write. The PWA's radio options are [0, ...this] (see opPageData).
const CACHE_TTL_WHITELIST = new Set([8 * 60, 20 * 60, 2 * 60 * 60]);

// DEK cache entry key. ctx binds the entry to (IP, PPID): a lookup recomputes
// ctx from the requester's worker-derived IP + reported PPID, so a mismatch
// simply finds no key (a clean miss, no oracle).
async function cacheCtx(ip: string, ppid: number): Promise<string> {
  const enc = new TextEncoder();
  const tag = enc.encode('vt-dek-ctx-v1');
  const ipBytes = enc.encode(ip);
  const buf = new Uint8Array(tag.length + ipBytes.length + 1 + 4);
  buf.set(tag, 0);
  buf.set(ipBytes, tag.length);
  buf[tag.length + ipBytes.length] = 0x00;
  new DataView(buf.buffer).setUint32(tag.length + ipBytes.length + 1, ppid >>> 0, true);
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

export class AccountDO extends DurableObject<Env> {
  private readonly expectedOrigin: string;

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
           ppid INTEGER
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
      // Drop the short-lived standalone cache_audit table from an earlier build
      // of this branch — its events now live in the unified audit table.
      this.ctx.storage.sql.exec(`DROP TABLE IF EXISTS cache_audit`);
      // idx_audit_created serves the retention DELETE (created_ms range); the
      // /<ADMIN_SEG>/api/audit cursor query uses the implicit primary-key (id) index.
      this.ctx.storage.sql.exec(
        `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_ms)`,
      );
    });
    // Schedule initial alarm if none set (alarm() re-arms itself thereafter).
    this.ctx.storage.getAlarm()
      .then(a => { if (a == null) return this.ctx.storage.setAlarm(Date.now() + TTL_MS); })
      .catch(e => logErr('alarm.init_failed', e));
  }

  // Audit writes are best-effort: a failure must never break the ceremony, so
  // we swallow and log. All three run inside the DO's single-threaded op.

  // INSERT the full challenge params once, at creation (status=pending).
  private auditCreate(ch: Challenge): void {
    const m = ch.meta ?? ({} as Challenge['meta']);
    try {
      this.ctx.storage.sql.exec(
        `INSERT INTO audit
           (token_id, created_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, ppid)
         VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      );
    } catch (e) {
      logErr('audit.create_failed', e);
    }
  }

  // UPDATE the terminal state in place (approved | rejected | expired).
  private auditFinalize(approveToken: string, status: string, latencyMs: number): void {
    try {
      this.ctx.storage.sql.exec(
        `UPDATE audit SET status = ?, finalized_ms = ?, latency_ms = ? WHERE token_id = ?`,
        status,
        Date.now(),
        latencyMs,
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
        `UPDATE audit SET verify_failures = verify_failures + 1 WHERE token_id = ?`,
        auditKey(approveToken),
      );
    } catch (e) {
      logErr('audit.verifyfail_failed', e);
    }
  }

  // Record the cache TTL the approver chose (0 / null = not cached).
  private auditSetCacheTtl(approveToken: string, ttlS: number): void {
    try {
      this.ctx.storage.sql.exec(
        `UPDATE audit SET cache_ttl_s = ? WHERE token_id = ?`,
        ttlS,
        auditKey(approveToken),
      );
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
           (token_id, created_ms, finalized_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, ppid)
         VALUES (?, ?, ?, ?, 'cache', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        tokenId, now, now, status,
        meta.command ?? null, meta.reason ?? null, meta.host ?? null, meta.user ?? null,
        meta.pwd ?? null, meta.tty ?? null, meta.ppid_cmd ?? null, meta.ssh_client ?? null,
        meta.ip ?? null, salts, typeof meta.ppid === 'number' ? meta.ppid : null,
      );
    } catch (e) {
      logErr('audit.cacheevent_failed', e);
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket upgrade — client polls for DEK delivery
    if (request.headers.get('Upgrade') === 'websocket') {
      return this.handleWsUpgrade(url);
    }

    const op = url.pathname.split('/').pop();
    switch (op) {
      case 'create':              return this.opCreate(request);
      case 'approve':             return this.opApprove(request);
      case 'reject':              return this.opReject(request);
      case 'dek-cache':           return this.opDekCache(request);
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
      for (const [key, ch] of list) {
        const ptKey = `pt:${ch.poll_token}`;
        if (ch.status === 'pending' && now - ch.created_ms >= TTL_MS) {
          ch.status = 'expired';
          ch.finalized_ms = now;
          await this.ctx.storage.put(key, ch);
          const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
          for (const ws of wss) {
            try { ws.send(JSON.stringify({ status: 'expired' } satisfies WsMessage)); ws.close(1000, 'expired'); } catch {}
          }
          log('expired', {
            at: tokenPrefix(ch.approve_token),
            op_kind: ch.meta.op_kind,
            host: ch.meta.host,
            user: ch.meta.user,
            tty: ch.meta.tty,
            age_ms: now - ch.created_ms,
          });
          this.auditFinalize(ch.approve_token, 'expired', now - ch.created_ms);
          // Retain `ch:` for RETENTION_MS so an in-flight WS reconnect still
          // sees the terminal status; drop only the routing key now.
          toDelete.push(ptKey);
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

    } finally {
      // Always reschedule, even if a sweep threw, so periodic cleanup self-heals
      // instead of stopping forever once CF exhausts its automatic alarm retries.
      try { await this.ctx.storage.setAlarm(Date.now() + TTL_MS); }
      catch (e) { logErr('alarm.reschedule_failed', e); }
    }
  }

  // ── HTTP ops ──────────────────────────────────────────────────────────

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
    this.auditCreate(challenge);
    return new Response('ok');
  }

  private async opApprove(request: Request): Promise<Response> {
    let body: DoApproveOp;
    let pwaPkBytes: Uint8Array;
    try {
      body = await request.json() as DoApproveOp;
      if (typeof body.approve_token !== 'string' || !body.approve_token) throw new Error('approve_token');
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

    // Opt-in DEK cache write. Best-effort: a failure here must never break the
    // approval (the daemon already has its sealed DEKs via the WS path below).
    const ttlS = typeof body.cache_ttl_s === 'number' ? body.cache_ttl_s : 0;
    if (ttlS > 0) {
      try { await this.writeCache(ch, ttlS, body.cache_sealed_deks_b64u); }
      catch (e) { logErr('cache.write_failed', e, { at: tokenPrefix(ch.approve_token) }); }
    }

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

  // Write one cache entry per salt, keyed by ctx(IP,PPID)+salt. Caller has
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
    const ppid = typeof ch.meta.ppid === 'number' ? ch.meta.ppid : 0;
    const ctx = await cacheCtx(ip, ppid);
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

  // Fast path: look up cached DEKs for (IP, PPID, salts). All-or-nothing — any
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
    // ip + ppid (both already sanitized by the Worker's capChallengeMeta; ip is
    // worker-derived from CF-Connecting-IP) form the cache binding ctx.
    const ip = meta.ip ?? '';
    const ppid = (typeof meta.ppid === 'number' ? meta.ppid : 0) >>> 0;
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

    const ctx = await cacheCtx(ip, ppid);
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
    return Response.json({ source: 'cache', sealed_deks_b64u: sealedB64u } satisfies DekCacheResponse);
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
      if (typeof body.approve_token !== 'string' || !body.approve_token) throw new Error('approve_token');
      if (!isB64uString(body.credential_id_b64u)) throw new Error('credential_id_b64u');
      if (!isB64uString(body.client_data_json_b64u)) throw new Error('client_data_json_b64u');
      if (!isB64uString(body.authenticator_data_b64u)) throw new Error('authenticator_data_b64u');
      if (!isB64uString(body.signature_b64u)) throw new Error('signature_b64u');
    } catch (e) {
      return badRequest(`bad request: ${(e as Error).message}`);
    }

    const ch = await this.ctx.storage.get<Challenge>(`ch:${body.approve_token}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') return new Response('challenge not pending', { status: 410 });

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

    return new Response('ok');
  }

  // Returns the data the approval page needs: challenge + credential info for allowCredentials.
  private async opPageData(url: URL): Promise<Response> {
    const approveToken = url.searchParams.get('approve_token') ?? '';
    if (!approveToken) return new Response('missing approve_token', { status: 400 });

    const ch = await this.ctx.storage.get<Challenge>(`ch:${approveToken}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') return new Response('challenge not pending', { status: 410 });

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
    const status = q.get('status');
    // 'cache' is a pseudo-filter selecting records that ARMED a DEK cache (the
    // approvals where a TTL was chosen → cache_ttl_s set). It deliberately
    // EXCLUDES cache-event rows (hits/cleared/write_failed, op_kind='cache',
    // cache_ttl_s NULL) — those are consumption logs, not "records with a cache".
    if (status === 'cache') { conds.push(`cache_ttl_s IS NOT NULL`); }
    else if (status) { conds.push('status = ?'); binds.push(status); }
    const host = q.get('host');
    if (host) { conds.push('host = ?'); binds.push(host); }

    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    const sql =
      `SELECT id, token_id, created_ms, finalized_ms, status, op_kind, command, reason,
              host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms, verify_failures, cache_ttl_s, ppid
       FROM audit ${where} ORDER BY id DESC LIMIT ?`;
    binds.push(limit);

    try {
      const rows = this.ctx.storage.sql.exec(sql, ...binds).toArray() as unknown as AuditRow[];
      const resp: AuditQueryResponse = { rows };
      return Response.json(resp);
    } catch (e) {
      logErr('audit.query_failed', e);
      return new Response('audit query failed', { status: 500 });
    }
  }
}
