// Account-local audit persistence and admin-stream projection. All SQL stays
// synchronous so an audit call cannot open a ceremony's storage input gate.

import { Challenge, ChallengeMeta, DoAuditIngestOp, AdminWsMessage, AuditRow, AuditQueryResponse } from './types';
import { b64uEnc } from './crypto';
import { AccountNames } from './account_names';
import { logErr } from './log';

const AUDIT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

// REST queries and broadcasts expose exactly the same fields.
const AUDIT_SELECT_COLS =
  `id, token_id, created_ms, finalized_ms, status, op_kind, command, reason,
   host, user, pwd, tty, ppid_cmd, ssh_client, ip, salts, latency_ms,
   verify_failures, cache_ttl_s, cache_expires_ms, ppid, source, seq,
   peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed, records, project`;

// Columns added after the per-challenge schema shipped, in the order they
// landed. An older table gains each one it lacks by ALTER (rows preserved); a
// fresh table already has them all from CREATE. `source` backfills existing
// rows through its DEFAULT — SQLite allows that on ADD COLUMN.
const ADDED_COLUMNS = [
  'cache_ttl_s INTEGER', 'ppid INTEGER', "source TEXT NOT NULL DEFAULT 'ceremony'", 'seq INTEGER',
  'peer_exe TEXT', 'key_fp TEXT', 'dest TEXT', 'scope_family TEXT', 'scope_label TEXT',
  'grant_ttl_s INTEGER', 'relayed INTEGER', 'cache_expires_ms INTEGER', 'records TEXT', 'project TEXT',
];

// The stored form of AuditRow.records: `[salt_b64u, claimed]` pairs, or null.
function recordPairs(salts: unknown, names: unknown): string | null {
  if (!Array.isArray(salts) || salts.length === 0) return null;
  const claimed = Array.isArray(names) ? names : [];
  return JSON.stringify(salts.map((s, i) => [s, typeof claimed[i] === 'string' ? claimed[i] : '']));
}

// Audit row key. approve_token is a 12-byte (16-char) capability, so this is
// effectively the whole token. Deliberately accepted: the token is only "live"
// during the ~5-min pending TTL, the audit surface is behind the admin passkey
// session (admin = the owner), and approval still requires a server-verified WebAuthn
// assertion — so a stored token grants nothing on its own.
export function auditKey(approveToken: string): string {
  return approveToken.slice(0, 16);
}

export class AccountAudit {
  private seqCounter = 0;
  /** The record-name table; rows resolve their `records` against it on read. */
  readonly names: AccountNames;

  constructor(
    private readonly sql: SqlStorage,
    private readonly adminSockets: () => WebSocket[],
  ) {
    this.names = new AccountNames(sql);
  }

  // Called by AccountDO inside blockConcurrencyWhile before any operation.
  initialize(): void {
    // Migrate away from any pre-existing per-event audit schema (older builds
    // of this branch used audit(ts_ms,event,token_prefix,...)). Audit data is
    // non-critical and per-event rows can't be faithfully converted to
    // per-challenge rows, so drop & rebuild rather than ALTER.
    const columns = () => new Set(
      this.sql.exec<{ name: string }>(`PRAGMA table_info(audit)`).toArray().map(c => c.name));
    let have = columns();
    if (have.size > 0 && !have.has('token_id')) {
      this.sql.exec(`DROP TABLE audit`);
      have = new Set();
    }
    // One row per challenge (keyed by token_id). The lifecycle events
    // (created → approved/rejected/expired, plus verify_failures) are stages
    // of the SAME challenge, so the params are stored ONCE on create and the
    // terminal state is updated in place — no duplication, no second table.
    // DEK-cache events (hit/write_failed/extended) live in THIS same table —
    // marked op_kind='cache' — so there is one unified audit surface.
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
         ${ADDED_COLUMNS.join(',\n       ')}
       )`,
    );
    // Additive migrations for an older table: the `have` snapshot predates every
    // ALTER, which is fine because each name is checked exactly once. seq is
    // backfilled with id (a valid monotonic ordering) so `after_seq` catch-up
    // covers historical rows; cache_expires_ms is deliberately not backfilled
    // (a pre-migration row's true expiry is unknown; NULL = the old inference).
    if (have.size > 0) {
      for (const col of ADDED_COLUMNS) {
        if (have.has(col.split(' ')[0]!)) continue;
        this.sql.exec(`ALTER TABLE audit ADD COLUMN ${col}`);
        if (col === 'seq INTEGER') this.sql.exec(`UPDATE audit SET seq = id WHERE seq IS NULL`);
      }
    }
    this.names.initialize();
    // Drop the short-lived standalone cache_audit table from an earlier build
    // of this branch — its events now live in the unified audit table.
    this.sql.exec(`DROP TABLE IF EXISTS cache_audit`);
    // idx_audit_created serves the retention DELETE (created_ms range); the
    // /api/admin/audit cursor query uses the implicit primary-key (id) index.
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

  // Rows as the admin surfaces receive them: the stored `[salt, claimed]`
  // pairs resolved against the names table in one lookup per page.
  private project(rows: AuditRow[]): AuditRow[] {
    const pairs = new Map<number, Array<[string, string]>>();
    const salts: string[] = [];
    rows.forEach((r, i) => {
      let p: unknown;
      try { p = typeof r.records === 'string' ? JSON.parse(r.records) : null; } catch { p = null; }
      if (!Array.isArray(p) || p.length === 0) { r.records = null; return; }
      pairs.set(i, p as Array<[string, string]>);
      for (const [s] of p as Array<[string, string]>) salts.push(s);
    });
    const named = new Map(this.names.resolve(salts).map(n => [n.salt_b64u, n]));
    for (const [i, p] of pairs) {
      rows[i]!.records = p.map(([s, claimed]) => ({ ...named.get(s)!, claimed: claimed ?? '' }));
    }
    return rows;
  }

  // Push one audit row to every admin stream. The re-SELECT uses the shared
  // projection, so the pushed row cannot expose any field the REST audit query
  // does not. Skips the SELECT entirely when no admin sockets are connected.
  broadcastRow(tokenId: string, event: 'insert' | 'update'): void {
    try {
      if (this.adminSockets().length === 0) return;
      const rows = this.project(this.sql
        .exec(`SELECT ${AUDIT_SELECT_COLS} FROM audit WHERE token_id = ?`, tokenId)
        .toArray() as unknown as AuditRow[]);
      const row = rows[0];
      if (!row) return;
      this.broadcastAdmin({ kind: 'audit', event, row });
    } catch (e) {
      logErr('audit.broadcast_failed', e);
    }
  }

  // The one INSERT every row kind goes through. Column names are this module's
  // constants, never input. `source` is always set explicitly (not left to the
  // column default) so a schema change can never silently mis-categorize rows.
  // True only if a row was actually written: RETURNING names only a row this
  // statement inserted, whereas rowsWritten counts AUTOINCREMENT bookkeeping
  // on an ON CONFLICT no-op — so a caller can skip the broadcast on a retry.
  private insert(row: Record<string, unknown>): boolean {
    const cols = Object.keys(row);
    const cursor = this.sql.exec(
      `INSERT INTO audit (${cols.join(', ')}, seq) VALUES (${cols.map(() => '?').join(', ')}, ?)
       ON CONFLICT(token_id) DO NOTHING RETURNING token_id`,
      ...cols.map(c => row[c] ?? null), this.nextSeq(),
    );
    return cursor.toArray().length > 0;
  }

  // The display columns shared by every row kind, from a (partial) meta.
  private static metaCols(m: Partial<ChallengeMeta>): Record<string, unknown> {
    const { op_kind, command, reason, host, user, pwd, project, ppid_cmd, ip } = m;
    return { op_kind, command, reason, host, user, pwd, project, ppid_cmd, ip };
  }

  // INSERT the full challenge params once, at creation (status=pending).
  create(ch: Challenge): boolean {
    const m = ch.meta ?? ({} as Challenge['meta']);
    try {
      return this.insert({
        token_id: auditKey(ch.approve_token), created_ms: ch.created_ms ?? Date.now(), status: 'pending',
        ...AccountAudit.metaCols(m), salts: Array.isArray(ch.salts_b64u) ? ch.salts_b64u.length : 0,
        source: 'ceremony', records: recordPairs(ch.salts_b64u, m.names),
      });
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
  // the approval's entries (which is what "is this still live" needs).
  // Broadcast is left to the caller (one push per origin, not per entry).
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
  // `salts` are the records served (hit) or refused (write_failed); `count`
  // is what the row's salts column shows (entries moved, for 'extended').
  cacheEvent(
    meta: Partial<ChallengeMeta>, count: number,
    status: 'approved' | 'write_failed' | 'extended', salts: string[] = [],
  ): void {
    try {
      const now = Date.now();
      // Synthetic unique token_id (no approve_token exists for cache events).
      const tokenId = 'c_' + b64uEnc(crypto.getRandomValues(new Uint8Array(9)));
      this.insert({
        token_id: tokenId, created_ms: now, finalized_ms: now, status,
        ...AccountAudit.metaCols(meta), op_kind: 'cache', salts: count, source: 'cache',
        records: recordPairs(salts, meta.names),
      });
      this.broadcastRow(tokenId, 'insert');
    } catch (e) {
      logErr('audit.cacheevent_failed', e);
    }
  }

  // Insert one SSH-agent decision row (source='agent'). The event is atomic —
  // created_ms == finalized_ms == ts_ms. `ON CONFLICT(token_id) DO NOTHING`
  // makes the agent's 1-retry idempotent. Best-effort: swallow + log.
  agent(op: DoAuditIngestOp): void {
    try {
      // Agent-authoritative context: the ingest already normalized these to
      // string/number/null; insert() only guards a malformed internal op.
      const { peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed } = op;
      const written = this.insert({
        token_id: op.token_id, created_ms: op.ts_ms, finalized_ms: op.ts_ms, status: op.outcome,
        ...AccountAudit.metaCols(op.meta), salts: op.salts, latency_ms: op.latency_ms, source: 'agent',
        peer_exe, key_fp, dest, scope_family, scope_label, grant_ttl_s, relayed,
      });
      // Skip the broadcast on an idempotent-retry no-op (agent's 1-retry).
      if (written) this.broadcastRow(op.token_id, 'insert');
    } catch (e) {
      logErr('audit.agent_failed', e);
    }
  }

  // Retention is the only deletion: no admin op empties this table.
  sweep(now: number): void {
    try {
      this.sql.exec(`DELETE FROM audit WHERE created_ms < ?`, now - AUDIT_RETENTION_MS);
    } catch (e) {
      logErr('audit.sweep_failed', e);
    }
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
    if (status) { conds.push('status = ?'); binds.push(status); }
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

    const rows = this.project(this.sql.exec(sql, ...binds).toArray() as unknown as AuditRow[]);
    // Current high-water mark, so the client can set its reconnect cursor even
    // when this page returns no rows (e.g. an empty initial load).
    const snapRow = this.sql
      .exec<{ m: number }>(`SELECT COALESCE(MAX(seq), 0) AS m FROM audit`)
      .toArray()[0];
    const resp: AuditQueryResponse = { rows, snapshot_seq: snapRow?.m ?? 0 };
    return resp;
  }
}
