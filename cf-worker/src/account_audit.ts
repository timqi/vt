// Account-local audit persistence and admin-stream projection. All SQL stays
// synchronous so an audit call cannot open a ceremony's storage input gate.

import { Challenge, ChallengeMeta, DoAuditIngestOp, AdminWsMessage, AuditRow, AuditQueryResponse } from './types';
import { b64uEnc } from './crypto';
import { logErr } from './log';

const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

// REST queries and broadcasts expose exactly the same fields.
const AUDIT_SELECT_COLS =
  `id, token_id, created_ms, finalized_ms, status, op_kind, command, reason,
   host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms,
   verify_failures, cache_ttl_s, cache_expires_ms, ppid, source, seq,
   peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed`;

// Audit row key. approve_token is a 12-byte (16-char) capability, so this is
// effectively the whole token. Deliberately accepted: the token is only "live"
// during the ~5-min pending TTL, the audit surface is behind Cloudflare Access
// (admin = the owner), and approval still requires a server-verified WebAuthn
// assertion — so a stored token grants nothing on its own.
export function auditKey(approveToken: string): string {
  return approveToken.slice(0, 16);
}

export class AccountAudit {
  private seqCounter = 0;

  constructor(
    private readonly sql: SqlStorage,
    private readonly adminSockets: () => WebSocket[],
  ) {}

  // Called by AccountDO inside blockConcurrencyWhile before any operation.
  initialize(): void {
    // Migrate away from any pre-existing per-event audit schema (older builds
    // of this branch used audit(ts_ms,event,token_prefix,...)). Audit data is
    // non-critical and per-event rows can't be faithfully converted to
    // per-challenge rows, so drop & rebuild rather than ALTER.
    const cols = this.sql
      .exec<{ name: string }>(`PRAGMA table_info(audit)`)
      .toArray();
    if (cols.length > 0 && !cols.some(c => c.name === 'token_id')) {
      this.sql.exec(`DROP TABLE audit`);
  }
  // One row per challenge (keyed by token_id). The lifecycle events
  // (created → approved/rejected/expired, plus verify_failures) are stages
  // of the SAME challenge, so the params are stored ONCE on create and the
  // terminal state is updated in place — no duplication, no second table.
  this.sql.exec(
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
       cache_expires_ms INTEGER,
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
  const auditCols = this.sql
    .exec<{ name: string }>(`PRAGMA table_info(audit)`)
    .toArray();
  const hasCol = (n: string) => auditCols.some(c => c.name === n);
  if (auditCols.length > 0 && !hasCol('cache_ttl_s')) {
    this.sql.exec(`ALTER TABLE audit ADD COLUMN cache_ttl_s INTEGER`);
  }
  if (auditCols.length > 0 && !hasCol('ppid')) {
    this.sql.exec(`ALTER TABLE audit ADD COLUMN ppid INTEGER`);
  }
  // `source` distinguishes ceremony / cache / agent rows. SQLite DOES allow
  // a NOT NULL DEFAULT <literal> on ALTER ADD COLUMN — the literal backfills
  // existing rows (which are all ceremony rows), so no separate UPDATE is
  // needed. (Surprises people; hence this note.) This reuses the `auditCols`/
  // `hasCol` snapshot taken once above — fine because it is the LAST ALTER in
  // this block. If a future migration is appended after it, re-run
  // `PRAGMA table_info(audit)` rather than trusting this now-stale snapshot.
  if (auditCols.length > 0 && !hasCol('source')) {
    this.sql.exec(
      `ALTER TABLE audit ADD COLUMN source TEXT NOT NULL DEFAULT 'ceremony'`);
  }
  // seq: monotonic per-row change counter for the real-time admin stream's
  // reconnect catch-up. Re-snapshot table_info first — the `source` ALTER
  // above invalidated the `auditCols` snapshot (per the note there). Backfill
  // existing rows with seq = id (a valid monotonic ordering) so no row has a
  // NULL seq and `after_seq` catch-up covers historical rows uniformly.
  const colsAfterSource = this.sql
    .exec<{ name: string }>(`PRAGMA table_info(audit)`)
    .toArray();
  if (colsAfterSource.length > 0 && !colsAfterSource.some(c => c.name === 'seq')) {
    this.sql.exec(`ALTER TABLE audit ADD COLUMN seq INTEGER`);
    this.sql.exec(`UPDATE audit SET seq = id WHERE seq IS NULL`);
  }
  // Agent-authoritative audit context (docs/approval-transparency.md §B).
  // Re-snapshot table_info — the `source`/`seq` ALTERs above invalidated
  // the earlier snapshots (per the note on the `source` migration). All
  // seven are plain nullable adds: NULL on pre-migration rows means "the
  // agent never sent the field", which is exactly the ingest convention.
  const colsForAgentCtx = this.sql
    .exec<{ name: string }>(`PRAGMA table_info(audit)`)
    .toArray();
  if (colsForAgentCtx.length > 0 && !colsForAgentCtx.some(c => c.name === 'peer_exe')) {
    for (const col of ['peer_exe TEXT', 'key_fp TEXT', 'dest TEXT',
                       'scope_family TEXT', 'scope_label TEXT',
                       'grant_ttl_s INTEGER', 'relayed INTEGER']) {
      this.sql.exec(`ALTER TABLE audit ADD COLUMN ${col}`);
    }
  }
  // cache_expires_ms: absolute expiry of the row's cache entries, so the
  // admin UI reads real liveness instead of inferring it from
  // finalized_ms + cache_ttl_s (an inference an approved extension makes
  // false). Re-snapshot table_info — the ALTERs above invalidated the
  // earlier snapshots. Deliberately NOT backfilled: a pre-migration row's
  // true expiry is unknown, and NULL means "fall back to the old
  // inference", which is exactly right for entries written before this
  // column existed (they can't have been extended either).
  const colsForCacheExpiry = this.sql
    .exec<{ name: string }>(`PRAGMA table_info(audit)`)
    .toArray();
  if (colsForCacheExpiry.length > 0
      && !colsForCacheExpiry.some(c => c.name === 'cache_expires_ms')) {
    this.sql.exec(`ALTER TABLE audit ADD COLUMN cache_expires_ms INTEGER`);
  }
  // Drop the short-lived standalone cache_audit table from an earlier build
  // of this branch — its events now live in the unified audit table.
  this.sql.exec(`DROP TABLE IF EXISTS cache_audit`);
  // idx_audit_created serves the retention DELETE (created_ms range); the
  // /<ADMIN_SEG>/api/audit cursor query uses the implicit primary-key (id) index.
  this.sql.exec(
    `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_ms)`,
  );
  // idx_audit_seq serves the reconnect catch-up query (seq > ? ORDER BY seq).
  this.sql.exec(
    `CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit(seq)`,
  );
  // Seed the in-memory counter from the durable high-water mark so a restart
  // never re-issues a seq (which would let a reconnecting client skip a row).
  const seqRow = this.sql
    .exec<{ m: number }>(`SELECT COALESCE(MAX(seq), 0) AS m FROM audit`)
    .toArray()[0];
  this.seqCounter = seqRow?.m ?? 0;
  }

  // Audit writes are best-effort: a failure must never break the ceremony, so
  // we swallow and log. They stay synchronous within the calling DO operation.

  // Next monotonic change counter. DO ops (and the alarm) are serialized per
  // instance, so a plain ++ is race-free — no atomics needed.
  private nextSeq(): number { return ++this.seqCounter; }

  // Send one message to every connected admin stream. Best-effort and isolated:
  // a failure here (or a dead socket) must never affect the ceremony or block
  // delivery to the OTHER sockets, so the whole thing is try/caught and each send
  // is individually guarded (mirrors the pt: broadcast pattern).
  private broadcastAdmin(msg: AdminWsMessage): void {
    try {
      const wss = this.adminSockets();
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
  broadcastRow(tokenId: string, event: 'insert' | 'update'): void {
    try {
      if (this.adminSockets().length === 0) return;
      const rows = this.sql
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
  create(ch: Challenge): boolean {
    const m = ch.meta ?? ({} as Challenge['meta']);
    try {
      // source='ceremony' set explicitly (not relying on the column default) so
      // a future schema change can never silently mis-categorize these rows.
      const cursor = this.sql.exec(
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
  finalize(approveToken: string, status: string, latencyMs: number): void {
    try {
      this.sql.exec(
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
  verifyFailure(approveToken: string): void {
    try {
      this.sql.exec(
        `UPDATE audit SET verify_failures = verify_failures + 1, seq = ? WHERE token_id = ?`,
        this.nextSeq(),
        auditKey(approveToken),
      );
      this.broadcastRow(auditKey(approveToken), 'update');
    } catch (e) {
      logErr('audit.verifyfail_failed', e);
    }
  }

  // Record the cache TTL the approver chose (0 / null = not cached) together with
  // the absolute expiry it produced. cache_ttl_s is the DECISION and is never
  // rewritten afterwards; cache_expires_ms is the live state and IS updated by an
  // approved extension (bumpCacheExpiry).
  setCacheTtl(approveToken: string, ttlS: number, expiresMs: number): void {
    try {
      this.sql.exec(
        `UPDATE audit SET cache_ttl_s = ?, cache_expires_ms = ?, seq = ? WHERE token_id = ?`,
        ttlS,
        expiresMs,
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

  // Move an origin approval's recorded cache expiry forward after an approved
  // extension. MAX() in SQL so a concurrent/older commit can never pull a row's
  // recorded expiry backwards, and so the column tracks the LATEST expiry across
  // the group (which is what "is this still live" needs). Broadcast is left to
  // the caller (one push per commit, not one per group).
  bumpCacheExpiry(originTokenId: string, expiresMs: number): void {
    try {
      this.sql.exec(
        `UPDATE audit
            SET cache_expires_ms = MAX(COALESCE(cache_expires_ms, 0), ?), seq = ?
          WHERE token_id = ?`,
        expiresMs,
        this.nextSeq(),
        originTokenId,
      );
    } catch (e) {
      logErr('audit.cacheexpiry_failed', e);
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
  // 'extended' is the fourth kind: the EFFECT of an approved extension ceremony
  // (how many entries actually moved, and to when). The ceremony's own row records
  // the authorization; this one records what it did to the cache. Unlike a clear
  // (authority-reducing, CF-logs only), an extension prolongs plaintext-DEK
  // availability, so it must land in the durable audit table.
  cacheEvent(
    meta: Partial<ChallengeMeta>, salts: number,
    status: 'approved' | 'write_failed' | 'extended',
  ): void {
    try {
      const now = Date.now();
      // Synthetic unique token_id (no approve_token exists for cache events).
      const tokenId = 'c_' + b64uEnc(crypto.getRandomValues(new Uint8Array(9)));
      this.sql.exec(
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
  agent(op: DoAuditIngestOp): void {
    const m = op.meta;
    try {
      const cursor = this.sql.exec(
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

  // Join the origin approvals' display context (the same fields the audit tab
  // already renders behind the same Access gate). Chunked so the IN list stays
  // small; a missing row (retention-swept origin) simply yields no context.
  contextFor(tokenIds: string[]): Map<string, AuditRow> {
    const out = new Map<string, AuditRow>();
    const ids = tokenIds.filter(t => typeof t === 'string' && t.length > 0);
    for (let i = 0; i < ids.length; i += 100) {
      const chunk = ids.slice(i, i + 100);
      const placeholders = chunk.map(() => '?').join(',');
      try {
        const rows = this.sql
          .exec(
            `SELECT token_id, host, user, pwd, command, finalized_ms, cache_ttl_s
               FROM audit WHERE token_id IN (${placeholders})`,
            ...chunk,
          )
          .toArray() as unknown as AuditRow[];
        for (const r of rows) out.set(r.token_id, r);
      } catch (e) {
        logErr('cache.list_join_failed', e);
      }
    }
    return out;
  }

  sweep(now: number): void {
    try {
      this.sql.exec(`DELETE FROM audit WHERE created_ms < ?`, now - AUDIT_RETENTION_MS);
    } catch (e) {
      logErr('audit.sweep_failed', e);
    }
  }

  clear(): void {
    this.sql.exec(`DELETE FROM audit`);
    // Retain the instance's sequence high-water mark across a clear.
    this.broadcastAdmin({ kind: 'clear' });
  }

  query(q: URLSearchParams): AuditQueryResponse {
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

    const rows = this.sql.exec(sql, ...binds).toArray() as unknown as AuditRow[];
    // Current high-water mark, so the client can set its reconnect cursor even
    // when this page returns no rows (e.g. an empty initial load).
    const snapRow = this.sql
      .exec<{ m: number }>(`SELECT COALESCE(MAX(seq), 0) AS m FROM audit`)
      .toArray()[0];
    const resp: AuditQueryResponse = { rows, snapshot_seq: snapRow?.m ?? 0 };
    return resp;
  }
}
