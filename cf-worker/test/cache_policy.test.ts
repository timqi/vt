import { describe, it, expect } from 'vitest';
import {
  planExtend, isAllowedTtl, groupIdOf, isExtendableGroupId,
  CACHE_TTL_WHITELIST, MAX_CACHE_LIFETIME_MS, ttlOptions,
} from '../src/cache_policy';

const NOW = 1_800_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;

// A live entry created `ageMs` ago that expires `leftMs` from now.
const entry = (ageMs: number, leftMs: number) =>
  ({ created_ms: NOW - ageMs, expires_ms: NOW + leftMs });

describe('policy constants', () => {
  it('offers exactly the three approvable TTLs', () => {
    expect(ttlOptions()).toEqual([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);
  });

  // The ceiling must not exceed the longest window a human can grant on the
  // phone, or the admin surface could out-grant the approver.
  it('caps total lifetime at the longest whitelisted TTL', () => {
    expect(MAX_CACHE_LIFETIME_MS).toBe(Math.max(...CACHE_TTL_WHITELIST) * 1000);
  });

  it('accepts only whitelisted TTLs', () => {
    expect(isAllowedTtl(20 * 60)).toBe(true);
    expect(isAllowedTtl(8 * 3600)).toBe(true);
    expect(isAllowedTtl(0)).toBe(false);
    expect(isAllowedTtl(21 * 60)).toBe(false);
    expect(isAllowedTtl(24 * 3600)).toBe(false);
    expect(isAllowedTtl('1200')).toBe(false);
    expect(isAllowedTtl(NaN)).toBe(false);
    expect(isAllowedTtl(-1200)).toBe(false);
  });
});

describe('planExtend', () => {
  it('extends a live entry to now + ttl', () => {
    const p = planExtend(entry(5 * MIN, 10 * MIN), 20 * 60, NOW);
    expect(p).toEqual({ ok: true, expires_ms: NOW + 20 * MIN });
  });

  // The core anti-resurrection rule: once an entry has lapsed, only a new phone
  // approval can bring the capability back.
  it('never resurrects an expired entry', () => {
    expect(planExtend({ created_ms: NOW - MIN, expires_ms: NOW - 1 }, 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'expired' });
    // Exactly at expires_ms counts as expired, matching the read path's `<=`.
    expect(planExtend({ created_ms: NOW - MIN, expires_ms: NOW }, 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'expired' });
  });

  // Regression: a naive `min(now+ttl, ceiling)` SHORTENS an entry when the
  // requested TTL is smaller than the time already remaining.
  it('never shortens an entry', () => {
    const p = planExtend(entry(MIN, 3 * HOUR), 20 * 60, NOW);
    expect(p).toEqual({ ok: false, skip: 'no_gain' });
  });

  it('clamps to the absolute lifetime ceiling', () => {
    // Created 7h ago, 30m left, asks for 8h → only 1h of headroom remains.
    const p = planExtend(entry(7 * HOUR, 30 * MIN), 8 * 3600, NOW);
    expect(p).toEqual({ ok: true, expires_ms: NOW - 7 * HOUR + MAX_CACHE_LIFETIME_MS });
  });

  // Repeated small extensions must converge on the ceiling, not walk past it.
  it('cannot synthesize an unbounded window by repeating', () => {
    const created = NOW;
    let e = { created_ms: created, expires_ms: created + 20 * MIN };
    let t = created;
    for (let i = 0; i < 100; i++) {
      t += 19 * MIN;                       // re-extend just before each lapse
      const p = planExtend(e, 20 * 60, t);
      if (!p.ok) break;
      e = { created_ms: created, expires_ms: p.expires_ms };
    }
    expect(e.expires_ms).toBeLessThanOrEqual(created + MAX_CACHE_LIFETIME_MS);
  });

  it('refuses once the ceiling has passed', () => {
    expect(planExtend(entry(9 * HOUR, 10 * MIN), 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'capped' });
  });

  // Pre-migration entries have no created_ms, so their total exposure cannot be
  // bounded — they stay clearable but are never extendable.
  it('refuses legacy entries with no created_ms', () => {
    expect(planExtend({ expires_ms: NOW + HOUR }, 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'legacy' });
    expect(planExtend({ created_ms: 0, expires_ms: NOW + HOUR }, 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'legacy' });
  });

  it('treats a malformed expiry as expired', () => {
    expect(planExtend({ created_ms: NOW, expires_ms: undefined as unknown as number }, 20 * 60, NOW))
      .toEqual({ ok: false, skip: 'expired' });
  });
});

describe('group handles', () => {
  it('uses the minted id when present', () => {
    expect(groupIdOf({ cache_group_id: 'g_abc', origin_token_id: 'tok' })).toBe('g_abc');
  });

  it('falls back to a legacy handle that is not extendable', () => {
    const gid = groupIdOf({ origin_token_id: 'tok0123456789ab' });
    expect(gid).toBe('legacy:tok0123456789ab');
    expect(isExtendableGroupId(gid)).toBe(false);
  });

  it('rejects forged / oversized handles', () => {
    expect(isExtendableGroupId('legacy:tok')).toBe(false);
    expect(isExtendableGroupId('g_' + 'x'.repeat(60))).toBe(false);
    expect(isExtendableGroupId('')).toBe(false);
    expect(isExtendableGroupId(null)).toBe(false);
    // A value that merely *starts* with g_ after junk must not pass.
    expect(isExtendableGroupId(' g_abc')).toBe(false);
    // And such a value must not be mistaken for a minted id when grouping.
    expect(groupIdOf({ cache_group_id: ' g_abc', origin_token_id: 'tok' })).toBe('legacy:tok');
  });
});
