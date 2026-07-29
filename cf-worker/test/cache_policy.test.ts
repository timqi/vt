import { describe, it, expect } from 'vitest';
import {
  planExtend, isAllowedApproveTtl, isAllowedExtendTtl, groupIdOf, isExtendableGroupId,
  APPROVE_TTL_WHITELIST, EXTEND_TTL_WHITELIST, MAX_EXTEND_TTL_MS,
  approveTtlOptions, extendTtlOptions,
} from '../src/cache_policy';

const NOW = 1_800_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;

// A live entry created `ageMs` ago that expires `leftMs` from now.
const entry = (ageMs: number, leftMs: number) =>
  ({ created_ms: NOW - ageMs, expires_ms: NOW + leftMs });

describe('policy constants', () => {
  it('keeps the phone approve ladder short', () => {
    expect(approveTtlOptions()).toEqual([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);
  });

  it('offers the multi-day rungs only for extension', () => {
    expect(extendTtlOptions()).toEqual([
      20 * 60, 2 * 60 * 60, 8 * 60 * 60, 24 * 3600, 2 * 24 * 3600, 7 * 24 * 3600,
    ]);
  });

  // The per-hop cap is derived from the extend ladder, so trimming the ladder
  // shortens the longest single grant automatically.
  it('derives the per-hop cap from the extend ladder', () => {
    expect(MAX_EXTEND_TTL_MS).toBe(Math.max(...EXTEND_TTL_WHITELIST) * 1000);
    expect(MAX_EXTEND_TTL_MS).toBe(7 * 24 * 3600 * 1000);
    expect(MAX_EXTEND_TTL_MS).toBeGreaterThan(Math.max(...APPROVE_TTL_WHITELIST) * 1000);
  });

  it('accepts only approve-ladder TTLs at approval time', () => {
    expect(isAllowedApproveTtl(20 * 60)).toBe(true);
    expect(isAllowedApproveTtl(8 * 3600)).toBe(true);
    // Extension-only rungs must NOT be armable straight from a phone approval.
    expect(isAllowedApproveTtl(24 * 3600)).toBe(false);
    expect(isAllowedApproveTtl(7 * 24 * 3600)).toBe(false);
    expect(isAllowedApproveTtl(0)).toBe(false);
    expect(isAllowedApproveTtl(21 * 60)).toBe(false);
    expect(isAllowedApproveTtl('1200')).toBe(false);
    expect(isAllowedApproveTtl(NaN)).toBe(false);
    expect(isAllowedApproveTtl(-1200)).toBe(false);
  });

  it('accepts only extend-ladder TTLs for an extension', () => {
    expect(isAllowedExtendTtl(20 * 60)).toBe(true);
    expect(isAllowedExtendTtl(24 * 3600)).toBe(true);
    expect(isAllowedExtendTtl(7 * 24 * 3600)).toBe(true);
    expect(isAllowedExtendTtl(0)).toBe(false);
    expect(isAllowedExtendTtl(3 * 24 * 3600)).toBe(false);   // 3d is not a rung
    expect(isAllowedExtendTtl(30 * 24 * 3600)).toBe(false);
    expect(isAllowedExtendTtl('86400')).toBe(false);
    expect(isAllowedExtendTtl(NaN)).toBe(false);
  });

  it('keeps every extend rung within the per-hop cap', () => {
    for (const t of extendTtlOptions()) {
      expect(t * 1000).toBeLessThanOrEqual(MAX_EXTEND_TTL_MS);
    }
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

  // The headline semantic: every extension is measured from the approval moment,
  // regardless of how old the entry is — so an entry can be renewed indefinitely,
  // one Passkey-approved hop at a time.
  it('always measures from now, never from creation', () => {
    for (const age of [0, 8 * HOUR, 30 * 24 * HOUR]) {
      expect(planExtend({ created_ms: NOW - age, expires_ms: NOW + MIN }, 24 * 3600, NOW))
        .toEqual({ ok: true, expires_ms: NOW + 24 * HOUR });
    }
  });

  it('extends an entry with no created_ms at all (pre-migration)', () => {
    expect(planExtend({ expires_ms: NOW + MIN }, 7 * 24 * 3600, NOW))
      .toEqual({ ok: true, expires_ms: NOW + 7 * 24 * HOUR });
  });

  // Renewal is unbounded in total, but only ever forward and only from a LIVE
  // grant: the moment a window lapses, the capability is gone for good.
  it('renews indefinitely while live, and stops dead once lapsed', () => {
    let e: { expires_ms: number } = { expires_ms: NOW + 20 * MIN };
    let t = NOW;
    for (let i = 0; i < 10; i++) {
      t = e.expires_ms - MIN;                    // renew just before each lapse
      const p = planExtend(e, 24 * 3600, t);
      expect(p.ok).toBe(true);
      if (!p.ok) break;
      expect(p.expires_ms).toBe(t + 24 * HOUR);  // exactly now + ttl, no budget
      e = { expires_ms: p.expires_ms };
    }
    // One second past expiry, the same request is refused forever after.
    expect(planExtend(e, 24 * 3600, e.expires_ms + 1000))
      .toEqual({ ok: false, skip: 'expired' });
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

  // Pre-migration entries fall back to an origin-derived handle, and that handle IS
  // a valid extend target: origin_token_id is a full 96-bit approve token, and the
  // group is refused anyway if its entries disagree about their origin. Without
  // this, everything already cached would be stranded until it lapsed.
  it('falls back to a legacy handle that is still extendable', () => {
    const gid = groupIdOf({ origin_token_id: 'tok0123456789ab' });
    expect(gid).toBe('legacy:tok0123456789ab');
    expect(isExtendableGroupId(gid)).toBe(true);
  });

  it('rejects forged / oversized / empty handles', () => {
    expect(isExtendableGroupId('g_' + 'x'.repeat(60))).toBe(false);  // over the cap
    expect(isExtendableGroupId('legacy:' + 'x'.repeat(60))).toBe(false);
    expect(isExtendableGroupId('g_')).toBe(false);                   // no body
    expect(isExtendableGroupId('legacy:')).toBe(false);
    expect(isExtendableGroupId('')).toBe(false);
    expect(isExtendableGroupId(null)).toBe(false);
    expect(isExtendableGroupId('dek:ctx:salt')).toBe(false);         // not a group handle
    // A value that merely *starts* with g_ after junk must not pass, in either
    // direction — neither as a selector nor as a minted id when grouping.
    expect(isExtendableGroupId(' g_abc')).toBe(false);
    expect(groupIdOf({ cache_group_id: ' g_abc', origin_token_id: 'tok' })).toBe('legacy:tok');
  });
});
