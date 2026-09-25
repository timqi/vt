// AccountDO — writeCache and the two TTL ladders.
//
// "Two TTL ladders, one rule — a TTL is legal only if some PASSKEY ceremony
// offers it. APPROVE_TTL_WHITELIST (20m/2h/8h) guards writeCache, so a tampered
// approve body cannot arm a multi-day cache without the extension ceremony"
// (CLAUDE.md). Everything here drives the real `approve` op with a real WebAuthn
// assertion, so the guard is exercised where an attacker would actually push.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { CacheEntry } from '../src/types';
import {
  inDO, doPost, approve, makeChallenge, sealFakeDek, nextSalt, daemonAuth,
  allDekKeys, auditRows, DoHandle, liveTokenId,
  bootstrap,
} from './do_helpers';

const TTL_20M = 20 * 60;
const TTL_2H = 2 * 3600;
const TTL_8H = 8 * 3600;
const TTL_1D = 24 * 3600;
const TTL_1W = 7 * 24 * 3600;
const TTL_PERMANENT = 100 * 365 * 24 * 3600;

beforeEach(bootstrap);

/** Create a normal decrypt ceremony carrying `n` salts, ready to approve. */
async function createCeremony(n = 2) {
  const salts = Array.from({ length: n }, () => nextSalt());
  const ch = makeChallenge({ salts_b64u: salts });
  const res = await doPost('create', { challenge: ch, auth: await daemonAuth(await liveTokenId()) });
  expect(res.status).toBe(200);
  return { ch, salts, sealed: await Promise.all(salts.map((_, i) => sealFakeDek(i + 1))) };
}

async function entriesOf(h: DoHandle): Promise<CacheEntry[]> {
  const list = await h.state.storage.list<CacheEntry>({ prefix: 'dek:' });
  return [...list.values()];
}

// ── The approve ladder guards writeCache ──────────────────────────────────

describe('writeCache — approve-ladder only', () => {
  it('arms a cache for each approve-ladder rung', async () => {
    for (const ttl of [TTL_20M, TTL_2H, TTL_8H]) {
      const { ch, sealed } = await createCeremony(2);
      const res = await approve(ch, { cache_ttl_s: ttl, cache_sealed_deks_b64u: sealed });
      expect(res.status).toBe(200);

      const row = (await inDO(auditRows)).find(r => r.token_id === ch.approve_token)!;
      expect(row.status).toBe('approved');
      expect(row.cache_ttl_s).toBe(ttl);
      expect(Math.abs(row.cache_expires_ms! - (Date.now() + ttl * 1000))).toBeLessThan(10_000);
    }
    // Three approvals × 2 salts.
    expect(await inDO(allDekKeys)).toHaveLength(6);
  });

  it('refuses a tampered approve body asking for an extension-only or off-ladder TTL', async () => {
    // 21 min is merely short, but no ceremony offers it.
    for (const ttl of [TTL_1D, TTL_1W, TTL_PERMANENT, 21 * 60]) {
      const { ch, sealed } = await createCeremony(2);
      // The assertion is genuine — only the unsigned cache_ttl_s is doctored,
      // which is exactly the attack the approve ladder exists to stop.
      const res = await approve(ch, { cache_ttl_s: ttl, cache_sealed_deks_b64u: sealed });
      expect(res.status).toBe(200);            // the approval itself still succeeds

      expect(await inDO(allDekKeys)).toEqual([]);   // …but nothing was cached
      const rows = await inDO(auditRows);
      const failed = rows.filter(r => r.status === 'write_failed');
      expect(failed.length).toBeGreaterThan(0);
      const origin = rows.find(r => r.token_id === ch.approve_token)!;
      expect(origin.cache_ttl_s).toBeNull();
      expect(origin.cache_expires_ms).toBeNull();
    }
  });

  it('refuses a sealed batch whose length disagrees with the salts', async () => {
    const { ch, sealed } = await createCeremony(3);
    expect((await approve(ch, {
      cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: sealed.slice(0, 2),
    })).status).toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
  });

  it('refuses a blob that does not open to the cache public key', async () => {
    const { ch } = await createCeremony(1);
    // Right length (80 bytes), wrong key — a stale cache_pubkey on the phone.
    const bogus = 'A'.repeat(107);
    expect((await approve(ch, {
      cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: [bogus],
    })).status).toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
    expect((await inDO(auditRows)).map(r => r.status)).toEqual(['approved', 'write_failed']);
  });

  it('does not cache at all when the approver picked 0 (the default)', async () => {
    const { ch, sealed } = await createCeremony(2);
    expect((await approve(ch, { cache_ttl_s: 0, cache_sealed_deks_b64u: sealed })).status)
      .toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
    const row = (await inDO(auditRows)).find(r => r.token_id === ch.approve_token)!;
    expect(row.cache_ttl_s).toBeNull();
    // A deliberate no-cache is not a failure and must not be audited as one.
    expect((await inDO(auditRows)).some(r => r.status === 'write_failed')).toBe(false);
  });
});

// ── Per-entry metadata is stamped once, per write ──────────────────────────

describe('writeCache — creation stamp and metadata', () => {
  it('stamps one created_ms, the chosen TTL and the token record\'s host/user on every entry', async () => {
    const { ch, sealed } = await createCeremony(3);
    const before = Date.now();
    expect((await approve(ch, { cache_ttl_s: TTL_2H, cache_sealed_deks_b64u: sealed })).status)
      .toBe(200);

    const entries = await inDO(entriesOf);
    expect(entries).toHaveLength(3);
    for (const e of entries) {
      expect(e.created_ms).toBeGreaterThanOrEqual(before);
      expect(e.expires_ms).toBe(e.created_ms + TTL_2H * 1000);
      expect(e.ttl_s).toBe(TTL_2H);
      expect(e.origin_token_id).toBe(ch.approve_token);
      expect(e.host).toBe(ch.meta.host);
      expect(e.user).toBe(ch.meta.user);
      expect(e).not.toHaveProperty('cache_group_id');
    }
    // One batch, one stamp.
    expect(new Set(entries.map(e => e.created_ms)).size).toBe(1);
  });
});

// ── A storage failure mid-write never breaks the approval ─────────────────

describe('writeCache — storage failure inside approve', () => {
  it('keeps the approval when the cache store throws', async () => {
    const { ch, sealed } = await createCeremony(1);
    await inDO(({ state }) => {
      const put = state.storage.put.bind(state.storage);
      vi.spyOn(state.storage, 'put').mockImplementation(async (key: any, value?: any) => {
        if (typeof key !== 'string' && Object.keys(key).some(k => k.startsWith('dek:'))) {
          throw new Error('injected cache write failure');
        }
        return typeof key === 'string' ? put(key, value) : put(key);
      });
    });
    try {
      const res = await approve(ch, { cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: sealed });
      expect(res.status).toBe(200);
    } finally {
      await inDO(({ state }) => (state.storage.put as unknown as { mockRestore(): void }).mockRestore());
    }
    expect((await inDO(auditRows)).map(r => r.status)).toEqual(['approved']);
  });
});
