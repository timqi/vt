// Operator-owned display names for records, keyed by the 16-byte salt the
// Worker sees on every ceremony (docs/dek-cache.md). The client may suggest a
// name (`meta.names`, 自报); nothing lands here without the approver typing or
// adopting it on the approval page or the console renaming it. Synchronous SQL
// like account_audit.ts, so a lookup never opens a ceremony's input gate.

import type { RecordName } from './types';

export const NAME_MAX = 40;

// Trusted or adopted names are ≤ NAME_MAX after the edge stripped control
// characters; anything else is refused, never truncated (a truncated name
// would silently label a different record).
export function isName(v: unknown): v is string {
  return typeof v === 'string' && v.length <= NAME_MAX;
}

// Names typed on the approval page: `{index, name}`, each salt at most once and
// in range; the edge stripped control characters, the cap is re-checked. One
// bad entry refuses the whole body — nothing is stored.
export function checkAdopt(raw: unknown, count: number): { index: number; name: string }[] | null {
  if (raw === undefined) return [];
  if (!Array.isArray(raw) || raw.length > count) return null;
  const seen = new Set<number>();
  const out: { index: number; name: string }[] = [];
  for (const e of raw as { index?: unknown; name?: unknown }[]) {
    const i = e?.index;
    if (typeof i !== 'number' || !Number.isInteger(i) || i < 0 || i >= count || seen.has(i) || !isName(e.name)) return null;
    seen.add(i);
    out.push({ index: i, name: e.name });
  }
  return out;
}

// What a surface prints for one record when it has to be a single string:
// the owned name, else the client's claim marked as such, else the salt's
// first 8 characters — a stable handle the operator can match across rows.
export function nameLabel(r: RecordName): string {
  return r.name ?? (r.claimed ? `${r.claimed}（自报）` : `${r.salt_b64u.slice(0, 8)}…`);
}

export class AccountNames {
  constructor(private readonly sql: SqlStorage) {}

  initialize(): void {
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS names (
         salt_b64u TEXT PRIMARY KEY,
         name TEXT NOT NULL,
         source TEXT NOT NULL,
         ms INTEGER NOT NULL
       )`,
    );
  }

  // One entry per salt, in order; `claimed[i]` is the client's suggestion for
  // `salts[i]` ('' when none). Chunked so the IN list stays bounded.
  resolve(salts: string[], claimed: string[] = []): RecordName[] {
    const owned = new Map<string, { name: string; source: RecordName['source'] }>();
    for (let i = 0; i < salts.length; i += 100) {
      const chunk = salts.slice(i, i + 100);
      const rows = this.sql
        .exec<{ salt_b64u: string; name: string; source: RecordName['source'] }>(
          `SELECT salt_b64u, name, source FROM names WHERE salt_b64u IN (${chunk.map(() => '?').join(',')})`,
          ...chunk,
        )
        .toArray();
      for (const r of rows) owned.set(r.salt_b64u, r);
    }
    return salts.map((s, i) => {
      const o = owned.get(s);
      return { salt_b64u: s, name: o?.name ?? null, source: o?.source ?? null, claimed: claimed[i] ?? '' };
    });
  }

  // Console rename: an empty name deletes the mapping.
  set(salt: string, name: string, now: number): void {
    if (name === '') { this.sql.exec(`DELETE FROM names WHERE salt_b64u = ?`, salt); return; }
    this.sql.exec(
      `INSERT INTO names (salt_b64u, name, source, ms) VALUES (?, ?, 'manual', ?)
       ON CONFLICT(salt_b64u) DO UPDATE SET name = excluded.name, source = 'manual', ms = excluded.ms`,
      salt, name, now,
    );
  }

  // Approval-page name (`source` 'client' when it is the client's claim, else
  // 'manual'): never overwrites a name the operator already owns.
  adopt(salt: string, name: string, source: RecordName['source'], now: number): void {
    if (name === '') return;
    this.sql.exec(
      `INSERT INTO names (salt_b64u, name, source, ms) VALUES (?, ?, ?, ?)
       ON CONFLICT(salt_b64u) DO NOTHING`,
      salt, name, source, now,
    );
  }
}
