// Host-token lifecycle: the DO-local `host_token` table. The Worker verifies a
// token's HMAC statelessly (host_token.ts); this module answers whether the
// token is still ALIVE and slides its expiry on every authenticated use.
// All SQL is synchronous so a check can sit inside a ceremony op without
// opening the DO input gate (same rule as account_audit.ts).

import type { HostTokenRow, MasterKeyGen } from './types';
import { HOST_TOKEN_TTL_MS } from './host_token';
import { logErr } from './log';

export type TokenTouchResult =
  | { ok: true; host: string; user: string; prev_ip: string }
  | { ok: false; reason: 'token_unknown' | 'token_revoked' | 'token_expired' };

export interface NewHostToken {
  token_id: string;
  host: string;
  user: string;
  enroll_ip: string;
  /** Cloudflare-derived country + AS org at enrollment, display only. */
  origin: string;
  /** Audit key of the approving ceremony. */
  approve_token_id: string;
}

// Listing cap. A personal deployment has a handful of hosts; the cap only
// bounds a runaway enroll loop from producing an unbounded admin payload.
const LIST_MAX = 500;

export class AccountTokens {
  constructor(private readonly sql: SqlStorage) {}

  // Called inside blockConcurrencyWhile with the audit schema.
  initialize(): void {
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS host_token (
         token_id TEXT PRIMARY KEY,
         host TEXT NOT NULL,
         user TEXT NOT NULL,
         enroll_ip TEXT NOT NULL,
         origin TEXT NOT NULL DEFAULT '',
         approve_token_id TEXT NOT NULL DEFAULT '',
         created_ms INTEGER NOT NULL,
         expires_ms INTEGER NOT NULL,
         last_used_ms INTEGER NOT NULL,
         last_ip TEXT NOT NULL DEFAULT '',
         revoked_ms INTEGER
       )`,
    );
    // Additive migration for tables created before VT_AUTH_CF_PREV existed:
    // ALTER preserves the rows (a re-created table would revoke every host).
    // Nullable on purpose — NULL means "not used since the column existed",
    // which is not the same claim as `cur`.
    const cols = this.sql
      .exec<{ name: string }>(`PRAGMA table_info(host_token)`)
      .toArray();
    if (cols.length > 0 && !cols.some(c => c.name === 'last_key_gen')) {
      this.sql.exec(`ALTER TABLE host_token ADD COLUMN last_key_gen TEXT`);
    }
  }

  /** Insert a freshly approved token. Expiry starts one window from now; the
   *  enrollment counts as the first use so `last_ip` seeds the IP-change hint.
   *  A token is always minted from the CURRENT master, so its generation starts
   *  at `cur` — a host that just enrolled is never the one holding up a
   *  rotation. */
  create(t: NewHostToken, now: number): void {
    this.sql.exec(
      `INSERT INTO host_token
         (token_id, host, user, enroll_ip, origin, approve_token_id, created_ms, expires_ms, last_used_ms, last_ip, last_key_gen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cur')`,
      t.token_id, t.host, t.user, t.enroll_ip, t.origin, t.approve_token_id,
      now, now + HOST_TOKEN_TTL_MS, now, t.enroll_ip,
    );
  }

  /** Liveness check + sliding refresh for one authenticated request. Expiry is
   *  ALWAYS `now + TTL` (a window that slides, never a budget that accumulates);
   *  a revoked or lapsed token is never revived here — only a new enrollment
   *  can. `prev_ip` is the IP of the previous use when it differs from this
   *  one, '' otherwise: the approval surfaces show it as an IP-change hint.
   *  `keyGen` records which master verified this use (admin tokens tab). */
  touch(tokenId: string, ip: string, now: number, keyGen: MasterKeyGen = 'cur'): TokenTouchResult {
    const row = this.get(tokenId);
    if (!row) return { ok: false, reason: 'token_unknown' };
    if (row.revoked_ms != null) return { ok: false, reason: 'token_revoked' };
    if (row.expires_ms <= now) return { ok: false, reason: 'token_expired' };
    this.sql.exec(
      `UPDATE host_token SET expires_ms = ?, last_used_ms = ?, last_ip = ?, last_key_gen = ? WHERE token_id = ?`,
      now + HOST_TOKEN_TTL_MS, now, ip, keyGen, tokenId,
    );
    const prevIp = row.last_ip && row.last_ip !== ip ? row.last_ip : '';
    return { ok: true, host: row.host, user: row.user, prev_ip: prevIp };
  }

  /** Liveness WITHOUT sliding — for the agent audit push, which is a
   *  background side-effect, not a use the operator would count. */
  isLive(tokenId: string, now: number): boolean {
    const row = this.get(tokenId);
    return !!row && row.revoked_ms == null && row.expires_ms > now;
  }

  get(tokenId: string): HostTokenRow | undefined {
    return this.sql
      .exec(`SELECT * FROM host_token WHERE token_id = ?`, tokenId)
      .toArray()[0] as HostTokenRow | undefined;
  }

  list(): { tokens: HostTokenRow[]; truncated: boolean } {
    const rows = this.sql
      .exec(`SELECT * FROM host_token ORDER BY created_ms DESC LIMIT ?`, LIST_MAX + 1)
      .toArray() as unknown as HostTokenRow[];
    return { tokens: rows.slice(0, LIST_MAX), truncated: rows.length > LIST_MAX };
  }

  /** Authority-reducing: stamps revoked_ms, idempotent. Returns whether a live
   *  token was actually revoked (false: unknown or already revoked). */
  revoke(tokenId: string, now: number): boolean {
    try {
      const cursor = this.sql.exec(
        `UPDATE host_token SET revoked_ms = ? WHERE token_id = ? AND revoked_ms IS NULL RETURNING token_id`,
        now, tokenId,
      );
      return cursor.toArray().length > 0;
    } catch (e) {
      logErr('token.revoke_failed', e);
      return false;
    }
  }

  /** Storage bounding only: a revoked or lapsed token stays listed for 30 days
   *  (an operator reviewing "what happened last week" should still see it). */
  sweep(now: number): void {
    const cutoff = now - 30 * 24 * 60 * 60 * 1000;
    try {
      this.sql.exec(
        `DELETE FROM host_token
          WHERE (revoked_ms IS NOT NULL AND revoked_ms < ?) OR expires_ms < ?`,
        cutoff, cutoff,
      );
    } catch (e) {
      logErr('token.sweep_failed', e);
    }
  }
}
