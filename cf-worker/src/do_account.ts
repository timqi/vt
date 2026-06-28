// AccountDO — singleton Durable Object managing all in-flight challenges.
//
// Storage keys:
//   ch:{approve_token}  →  Challenge JSON
//   pt:{poll_token}     →  approve_token (WS tag routing)
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
import { Env, Challenge, ApprovePageData, DoCreateOp, DoApproveOp, DoRejectOp, WsMessage, AuditRow, AuditQueryResponse } from './types';
import { b64uDec, isB64uString, decodeB64uExact } from './crypto';
import { parseCredentials, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';
import { log, logErr, tokenPrefix } from './log';

const TTL_MS = 5 * 60 * 1000;
const RETENTION_MS = 10 * 60 * 1000;
// Audit rows (ceremony events) are kept 90 days, then swept by the alarm.
const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

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
           verify_failures INTEGER NOT NULL DEFAULT 0
         )`,
      );
      // idx_audit_created serves the retention DELETE (created_ms range); the
      // /<ADMIN_SEG>/api/audit cursor query uses the implicit primary-key (id) index.
      this.ctx.storage.sql.exec(
        `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_ms)`,
      );
    });
    // Schedule initial alarm if none set
    this.ctx.storage.getAlarm().then(a => {
      if (a == null) this.ctx.storage.setAlarm(Date.now() + TTL_MS);
    });
  }

  // Audit writes are best-effort: a failure must never break the ceremony, so
  // we swallow and log. All three run inside the DO's single-threaded op.

  // INSERT the full challenge params once, at creation (status=pending).
  private auditCreate(ch: Challenge): void {
    const m = ch.meta ?? ({} as Challenge['meta']);
    try {
      this.ctx.storage.sql.exec(
        `INSERT INTO audit
           (token_id, created_ms, status, op_kind, command, reason, host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts)
         VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket upgrade — client polls for DEK delivery
    if (request.headers.get('Upgrade') === 'websocket') {
      return this.handleWsUpgrade(url);
    }

    const op = url.pathname.split('/').pop();
    switch (op) {
      case 'create':       return this.opCreate(request);
      case 'approve':      return this.opApprove(request);
      case 'reject':       return this.opReject(request);
      case 'page':         return this.opPageData(url);
      case 'audit-query':  return this.opAuditQuery(url);
      default:             return new Response('unknown op', { status: 400 });
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
    const now = Date.now();
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
    // Sweep audit rows past 90-day retention (cheap: bound param + idx_audit_created).
    try {
      this.ctx.storage.sql.exec(`DELETE FROM audit WHERE created_ms < ?`, now - AUDIT_RETENTION_MS);
    } catch (e) {
      logErr('audit.sweep_failed', e);
    }
    // Reschedule
    await this.ctx.storage.setAlarm(Date.now() + TTL_MS);
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

    const pageData: ApprovePageData = {
      approve_token: approveToken,
      approve_challenge_b64u: ch.approve_challenge_hash_b64u,
      reject_challenge_b64u: ch.reject_challenge_hash_b64u,
      daemon_pubkey_b64u: ch.daemon_pubkey_b64u,
      salts_b64u: ch.salts_b64u,
      rp_id: this.env.RP_ID,
      allow_credentials: creds.c.map(e => ({ id_b64u: e.i, h_b64u: e.h, k_b64u: e.k })),
      metadata: ch.meta,
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
    if (status) { conds.push('status = ?'); binds.push(status); }
    const host = q.get('host');
    if (host) { conds.push('host = ?'); binds.push(host); }

    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    const sql =
      `SELECT id, token_id, created_ms, finalized_ms, status, op_kind, command, reason,
              host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms, verify_failures
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
