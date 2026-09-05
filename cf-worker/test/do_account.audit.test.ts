import { describe, it, expect, vi } from 'vitest';
import { AccountAudit, auditKey } from '../src/account_audit';
import type { AdminWsMessage, DoAuditIngestOp } from '../src/types';
import { inDO, makeChallenge, makeMeta, nextToken } from './do_helpers';

function agentOp(): DoAuditIngestOp {
  return {
    token_id: nextToken('agent'), ts_ms: Date.now(), outcome: 'cache_hit',
    salts: 0, latency_ms: 10, meta: makeMeta({ op_kind: 'sign' }),
    peer_exe: 'ssh', key_fp: 'synthetic-fingerprint', dest: 'test-destination',
    scope_family: 'destination', scope_label: 'test scope', grant_ttl_s: 1200,
    relayed: 0,
  };
}

describe('AccountAudit persistence and projection', () => {
  it('broadcasts the same row as queries and isolates dead admin sockets', async () => {
    await inDO(({ state }) => {
      const pushed: AdminWsMessage[] = [];
      const audit = new AccountAudit(state.storage.sql, () => [
        { send() { throw new Error('closed socket'); } } as unknown as WebSocket,
        { send(text: string) { pushed.push(JSON.parse(text)); } } as unknown as WebSocket,
      ]);
      audit.initialize();
      const ch = makeChallenge();
      expect(audit.create(ch)).toBe(true);
      expect(audit.create(ch)).toBe(false);
      audit.broadcastRow(auditKey(ch.approve_token), 'insert');
      const initial = audit.query(new URLSearchParams());
      expect(pushed).toEqual([{ kind: 'audit', event: 'insert', row: initial.rows[0] }]);
      audit.finalize(ch.approve_token, 'approved', 123);
      audit.setCacheTtl(ch.approve_token, 1200, 1000);
      audit.bumpCacheExpiry(ch.approve_token, 2000);
      audit.bumpCacheExpiry(ch.approve_token, 1500);
      expect(pushed).toHaveLength(1);
      audit.broadcastRow(ch.approve_token, 'update');
      const updated = audit.query(new URLSearchParams(`after_seq=${initial.snapshot_seq}`));
      expect(updated.rows).toHaveLength(1);
      expect(updated.rows[0]).toMatchObject({ status: 'approved', cache_ttl_s: 1200, cache_expires_ms: 2000 });
      expect(pushed[1]).toEqual({ kind: 'audit', event: 'update', row: updated.rows[0] });
      expect(updated.snapshot_seq).toBeGreaterThan(initial.snapshot_seq);
    });
  });

  it('keeps agent retries idempotent and preserves authoritative context', async () => {
    await inDO(({ state }) => {
      const send = vi.fn();
      const audit = new AccountAudit(state.storage.sql, () => [{ send } as unknown as WebSocket]);
      audit.initialize();
      const op = agentOp();
      audit.agent(op);
      audit.agent(op);
      const rows = audit.query(new URLSearchParams('source=agent')).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        token_id: op.token_id, status: 'cache_hit', source: 'agent',
        peer_exe: 'ssh', dest: 'test-destination', scope_family: 'destination',
        scope_label: 'test scope', grant_ttl_s: 1200, relayed: 0,
      });
      expect(send).toHaveBeenCalledOnce();
    });
  });

  it('suppresses duplicate insert broadcasts through the DO create and ingest routes', async () => {
    await inDO(async ({ inst, state }) => {
      const ch = makeChallenge();
      const op = { ...agentOp(), outcome: 'approved' };
      const broadcast = vi.spyOn(inst.audit, 'broadcastRow');
      try {
        for (let i = 0; i < 2; i++) {
          const created = await inst.fetch(new Request('https://account.do/op/create', {
            method: 'POST', body: JSON.stringify({ challenge: ch }),
          }));
          expect(created.status).toBe(200);
          await created.text();
          const ingested = await inst.fetch(new Request('https://account.do/op/audit-ingest', {
            method: 'POST', body: JSON.stringify(op),
          }));
          expect(ingested.status).toBe(200);
          await ingested.text();
        }
        expect(broadcast.mock.calls).toEqual([
          [ch.approve_token, 'insert'], [op.token_id, 'insert'],
        ]);
        const rows = state.storage.sql.exec('SELECT token_id FROM audit').toArray();
        expect(rows).toHaveLength(2);
        expect(rows.map(row => row.token_id).sort()).toEqual([ch.approve_token, op.token_id].sort());
      } finally {
        broadcast.mockRestore();
      }
    });
  });

  it('retains sequence ordering across reinitialization and clear', async () => {
    await inDO(({ state }) => {
      const audit = new AccountAudit(state.storage.sql, () => []);
      audit.initialize();
      const first = makeChallenge();
      audit.create(first);
      audit.verifyFailure(first.approve_token);
      const before = audit.query(new URLSearchParams()).snapshot_seq;
      const messages: AdminWsMessage[] = [];
      const restarted = new AccountAudit(state.storage.sql, () => [{
        send(text: string) { messages.push(JSON.parse(text)); },
      } as unknown as WebSocket]);
      restarted.initialize();
      restarted.finalize(first.approve_token, 'rejected', 1);
      const terminal = restarted.query(new URLSearchParams()).snapshot_seq;
      expect(terminal).toBeGreaterThan(before);
      restarted.clear();
      expect(messages).toEqual([{ kind: 'clear' }]);
      expect(restarted.query(new URLSearchParams()).rows).toEqual([]);
      restarted.create(makeChallenge());
      expect(restarted.query(new URLSearchParams()).snapshot_seq).toBeGreaterThan(terminal);
    });
  });

  it('preserves filters, cursor order, retention, and origin joins', async () => {
    await inDO(({ state }) => {
      const audit = new AccountAudit(state.storage.sql, () => []);
      audit.initialize();
      const old = makeChallenge({ created_ms: Date.now() - 91 * 24 * 60 * 60_000 });
      const armed = makeChallenge();
      audit.create(old);
      audit.create(armed);
      audit.setCacheTtl(armed.approve_token, 1200, Date.now() + 1200_000);
      audit.cacheEvent(makeMeta(), 2, 'approved');
      const armedRows = audit.query(new URLSearchParams('status=cache')).rows;
      expect(armedRows.map(row => row.token_id)).toEqual([armed.approve_token]);
      const page = audit.query(new URLSearchParams('limit=1'));
      expect(page.rows).toHaveLength(1);
      const older = audit.query(new URLSearchParams(`before_id=${page.rows[0]!.id}`));
      expect(older.rows.map(row => row.token_id)).toEqual([armed.approve_token, old.approve_token]);
      expect(audit.query(new URLSearchParams('host=missing')).rows).toEqual([]);
      expect(audit.contextFor([armed.approve_token]).get(armed.approve_token)?.cache_ttl_s).toBe(1200);
      audit.sweep(Date.now());
      expect(audit.contextFor([old.approve_token]).size).toBe(0);
      expect(audit.query(new URLSearchParams()).rows).toHaveLength(2);
    });
  });

  it('keeps audit writes best-effort while clear and query errors propagate', async () => {
    await inDO(({ state }) => {
      const audit = new AccountAudit(state.storage.sql, () => []);
      audit.initialize();
      const exec = vi.spyOn(state.storage.sql, 'exec').mockImplementation(() => {
        throw new Error('synthetic SQL failure');
      });
      try {
        expect(audit.create(makeChallenge())).toBe(false);
        expect(() => audit.finalize('missing', 'approved', 1)).not.toThrow();
        expect(() => audit.cacheEvent(makeMeta(), 1, 'approved')).not.toThrow();
        expect(() => audit.agent(agentOp())).not.toThrow();
        expect(() => audit.sweep(Date.now())).not.toThrow();
        expect(() => audit.clear()).toThrow('synthetic SQL failure');
        expect(() => audit.query(new URLSearchParams())).toThrow('synthetic SQL failure');
      } finally {
        exec.mockRestore();
      }
    });
  });

  it('preserves historical rows through the existing additive migrations', async () => {
    await inDO(({ state }) => {
      const sql = state.storage.sql;
      sql.exec('DROP TABLE audit');
      sql.exec(`CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT UNIQUE NOT NULL,
        created_ms INTEGER NOT NULL, finalized_ms INTEGER, status TEXT NOT NULL,
        op_kind TEXT, command TEXT, reason TEXT, host TEXT, user TEXT, pwd TEXT,
        tty TEXT, ppid_cmd TEXT, ssh_client TEXT, ip TEXT, salts INTEGER,
        latency_ms INTEGER, verify_failures INTEGER NOT NULL DEFAULT 0
      )`);
      sql.exec("INSERT INTO audit (token_id, created_ms, status) VALUES ('historical', 123, 'approved')");
      const audit = new AccountAudit(sql, () => []);
      audit.initialize();
      audit.initialize();
      const row = audit.query(new URLSearchParams()).rows[0]!;
      expect(row).toMatchObject({
        token_id: 'historical', created_ms: 123, status: 'approved', seq: row.id,
        source: 'ceremony', cache_ttl_s: null, cache_expires_ms: null, peer_exe: null,
      });
      audit.create(makeChallenge());
      expect(audit.query(new URLSearchParams()).snapshot_seq).toBeGreaterThan(row.seq);
    });
  });
});
