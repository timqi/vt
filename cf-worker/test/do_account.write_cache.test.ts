// AccountDO — writeCache and the two TTL ladders.
//
// "Two TTL ladders, one rule — a TTL is legal only if some PASSKEY ceremony
// offers it. APPROVE_TTL_WHITELIST (20m/2h/8h) guards writeCache, so a tampered
// approve body cannot arm a multi-day cache without the extension ceremony"
// (CLAUDE.md). Everything here drives the real `approve` op with a real WebAuthn
// assertion, so the guard is exercised where an attacker would actually push.

import { describe, it, expect, beforeEach } from 'vitest';
import type { CacheEntry } from '../src/types';
// @ts-expect-error — Vite raw import, for the "computed, never hardcoded" check.
import cachePolicySource from '../src/cache_policy.ts?raw';
import {
  APPROVE_TTL_WHITELIST, EXTEND_TTL_WHITELIST, MAX_EXTEND_TTL_MS,
  isAllowedApproveTtl, isAllowedExtendTtl,
} from '../src/cache_policy';
import {
  inDO, setDoVar, doPost, approve, makeChallenge, sealFakeDek, nextSalt,
  allDekKeys, auditRows, testEnv, DoHandle,
} from './do_helpers';

const TTL_20M = 20 * 60;
const TTL_2H = 2 * 3600;
const TTL_8H = 8 * 3600;
const TTL_1D = 24 * 3600;
const TTL_1W = 7 * 24 * 3600;
const TTL_PERMANENT = 100 * 365 * 24 * 3600;

// The DO instance survives a test; its env does not get rolled back with storage.
beforeEach(async () => {
  await setDoVar('CACHE_SECKEY', testEnv.CACHE_SECKEY);
  await setDoVar('CACHE_ADMIN_EXTEND', '0');
});

/** Create a normal decrypt ceremony carrying `n` salts, ready to approve. */
async function createCeremony(n = 2) {
  const salts = Array.from({ length: n }, () => nextSalt());
  const ch = makeChallenge({ salts_b64u: salts });
  const res = await doPost('create', { challenge: ch });
  expect(res.status).toBe(200);
  return { ch, salts, sealed: salts.map((_, i) => sealFakeDek(i + 1)) };
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

  it('refuses a tampered approve body asking for a multi-day (extension-only) TTL', async () => {
    for (const ttl of [TTL_1D, TTL_1W, TTL_PERMANENT]) {
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

  it('refuses an off-ladder TTL that is merely short', async () => {
    const { ch, sealed } = await createCeremony(1);
    const res = await approve(ch, { cache_ttl_s: 21 * 60, cache_sealed_deks_b64u: sealed });
    expect(res.status).toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
  });

  it('writes nothing when CACHE_SECKEY is unset — caching is opt-in', async () => {
    await setDoVar('CACHE_SECKEY', '');
    const { ch, sealed } = await createCeremony(1);
    expect((await approve(ch, { cache_ttl_s: TTL_8H, cache_sealed_deks_b64u: sealed })).status)
      .toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
    expect((await inDO(auditRows)).some(r => r.status === 'write_failed')).toBe(true);
  });

  it('refuses a sealed batch whose length disagrees with the salts', async () => {
    const { ch, sealed } = await createCeremony(3);
    expect((await approve(ch, {
      cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: sealed.slice(0, 2),
    })).status).toBe(200);
    expect(await inDO(allDekKeys)).toEqual([]);
  });

  it('refuses a blob that does not open to the cache public key', async () => {
    const { ch, salts } = await createCeremony(1);
    // Right length (80 bytes), wrong key — a stale cache_pubkey on the phone.
    const bogus = 'A'.repeat(107);
    expect((await approve(ch, {
      cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: [bogus],
    })).status).toBe(200);
    expect(salts).toHaveLength(1);
    expect(await inDO(allDekKeys)).toEqual([]);
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

// ── cache_group_id / created_ms are minted once, per write ─────────────────

describe('writeCache — group handle and creation stamp', () => {
  it('mints ONE fresh group id and one created_ms for the whole batch', async () => {
    const { ch, sealed } = await createCeremony(3);
    const before = Date.now();
    expect((await approve(ch, { cache_ttl_s: TTL_2H, cache_sealed_deks_b64u: sealed })).status)
      .toBe(200);

    const entries = await inDO(entriesOf);
    expect(entries).toHaveLength(3);
    const gids = new Set(entries.map(e => e.cache_group_id));
    expect(gids.size).toBe(1);
    const gid = [...gids][0]!;
    expect(gid.startsWith('g_')).toBe(true);
    expect(gid.length).toBeLessThanOrEqual(40);

    for (const e of entries) {
      expect(e.created_ms).toBeGreaterThanOrEqual(before);
      expect(e.expires_ms).toBe(e.created_ms! + TTL_2H * 1000);
      expect(e.origin_token_id).toBe(ch.approve_token);
    }
    // One batch, one stamp.
    expect(new Set(entries.map(e => e.created_ms)).size).toBe(1);
  });

  it('gives a second approval a different group id — the handle is per write', async () => {
    const a = await createCeremony(1);
    expect((await approve(a.ch, { cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: a.sealed })).status)
      .toBe(200);
    const b = await createCeremony(1);
    expect((await approve(b.ch, { cache_ttl_s: TTL_20M, cache_sealed_deks_b64u: b.sealed })).status)
      .toBe(200);

    const gids = (await inDO(entriesOf)).map(e => e.cache_group_id);
    expect(gids).toHaveLength(2);
    expect(new Set(gids).size).toBe(2);
  });
});

// ── The ladders themselves ────────────────────────────────────────────────

describe('two ladders, one rule', () => {
  it('keeps the multi-day rungs out of the approve ladder', () => {
    for (const rung of [TTL_20M, TTL_2H, TTL_8H]) {
      expect(isAllowedApproveTtl(rung)).toBe(true);
      expect(isAllowedExtendTtl(rung)).toBe(true);   // extend is a superset
    }
    for (const rung of [TTL_1D, 2 * TTL_1D, TTL_1W, TTL_PERMANENT]) {
      expect(isAllowedApproveTtl(rung)).toBe(false);
      expect(isAllowedExtendTtl(rung)).toBe(true);
    }
    for (const r of APPROVE_TTL_WHITELIST) expect(EXTEND_TTL_WHITELIST.has(r)).toBe(true);
  });

  it('computes the longest single hop FROM the extend ladder, never a literal', () => {
    // Structural: the constant is a fold over the ladder, so editing the ladder
    // moves it. A hardcoded number here would silently outlive a trimmed ladder.
    const decl = (cachePolicySource as string)
      .split('\n')
      .find(l => l.startsWith('export const MAX_EXTEND_TTL_MS'));
    expect(decl).toBe('export const MAX_EXTEND_TTL_MS = Math.max(...EXTEND_TTL_WHITELIST) * 1000;');

    // Behavioural: it is exactly the top rung, and trimming rungs off the top
    // shortens it — 1w and the permanent rung removed → the cap falls to 2d.
    expect(MAX_EXTEND_TTL_MS).toBe(Math.max(...EXTEND_TTL_WHITELIST) * 1000);
    const maxOf = (ladder: Iterable<number>) => Math.max(...ladder) * 1000;
    const trimmed = [...EXTEND_TTL_WHITELIST].filter(s => s <= 2 * TTL_1D);
    expect(maxOf(trimmed)).toBe(2 * TTL_1D * 1000);
    expect(maxOf(trimmed)).toBeLessThan(MAX_EXTEND_TTL_MS);
    expect(maxOf(EXTEND_TTL_WHITELIST)).toBe(MAX_EXTEND_TTL_MS);
  });

  it('keeps the permanent rung a finite far-future TTL, not a sentinel', () => {
    expect(Number.isFinite(TTL_PERMANENT)).toBe(true);
    expect(EXTEND_TTL_WHITELIST.has(TTL_PERMANENT)).toBe(true);
    const expiry = Date.now() + TTL_PERMANENT * 1000;
    expect(expiry).toBeLessThan(Number.MAX_SAFE_INTEGER);
    expect(new Date(expiry).getUTCFullYear()).toBeGreaterThan(2100);
  });
});
