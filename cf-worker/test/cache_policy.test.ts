import { describe, it, expect } from 'vitest';
import {
  planExtend, isAllowedApproveTtl, isAllowedExtendTtl, groupIdOf, isExtendableGroupId,
  APPROVE_TTL_WHITELIST, EXTEND_TTL_WHITELIST, MAX_CACHE_LIFETIME_MS,
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

  // The ceiling is DERIVED from what a Passkey ceremony can grant, never
  // hardcoded — so it can only move when some ceremony can actually grant that
  // long, and no admin path can out-grant an approver.
  it('derives the lifetime ceiling from the longest grantable TTL', () => {
    expect(MAX_CACHE_LIFETIME_MS)
      .toBe(Math.max(...APPROVE_TTL_WHITELIST, ...EXTEND_TTL_WHITELIST) * 1000);
    expect(MAX_CACHE_LIFETIME_MS).toBe(7 * 24 * 3600 * 1000);
  });

  // The ceiling must be strictly greater than the longest APPROVE-time TTL, or an
  // 8h grant sits at its ceiling from birth and every extension of it is a no-op
  // — which is what made the first version of this feature useless in practice.
  it('leaves headroom above the longest approvable TTL', () => {
    expect(MAX_CACHE_LIFETIME_MS).toBeGreaterThan(Math.max(...APPROVE_TTL_WHITELIST) * 1000);
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

  // Every extend rung must be reachable: a TTL that always clamps to the ceiling
  // would be a menu entry that silently does something else.
  it('keeps every extend rung within the ceiling', () => {
    for (const t of extendTtlOptions()) {
      expect(t * 1000).toBeLessThanOrEqual(MAX_CACHE_LIFETIME_MS);
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

  it('clamps to the absolute lifetime ceiling', () => {
    // Created 6d23h ago, 30m left, asks for 1w → only ~1h of headroom remains.
    const age = 7 * 24 * HOUR - HOUR;
    const p = planExtend(entry(age, 30 * MIN), 7 * 24 * 3600, NOW);
    expect(p).toEqual({ ok: true, expires_ms: NOW - age + MAX_CACHE_LIFETIME_MS });
  });

  // The case the multi-day ladder exists for: an 8h grant used to be stuck at its
  // ceiling from birth, so extending it did nothing.
  it('can extend a fresh 8h grant now that the ceiling is a week', () => {
    const p = planExtend(entry(0, 8 * HOUR), 24 * 3600, NOW);
    expect(p).toEqual({ ok: true, expires_ms: NOW + 24 * HOUR });
  });

  // Repeated small extensions must converge on the ceiling, not walk past it.
  // Re-extend forever, always with the LONGEST rung and always just before the
  // current window lapses (so no iteration is thrown away as 'expired' — that
  // would make this test vacuous). It must converge exactly on the ceiling and
  // then refuse, never walk past it.
  it('cannot synthesize an unbounded window by repeating', () => {
    const created = NOW;
    const ceiling = created + MAX_CACHE_LIFETIME_MS;
    let e = { created_ms: created, expires_ms: created + 20 * MIN };
    let extensions = 0;
    let refused: string | null = null;
    for (let i = 0; i < 50; i++) {
      const t = e.expires_ms - MIN;        // one minute before it would lapse
      const p = planExtend(e, 7 * 24 * 3600, t);
      if (!p.ok) { refused = p.skip; break; }
      expect(p.expires_ms).toBeLessThanOrEqual(ceiling);
      expect(p.expires_ms).toBeGreaterThan(e.expires_ms);   // strictly monotonic
      e = { created_ms: created, expires_ms: p.expires_ms };
      extensions++;
    }
    expect(extensions).toBeGreaterThan(0);   // the loop really did extend
    expect(e.expires_ms).toBe(ceiling);      // and landed exactly on the ceiling
    expect(refused).toBe('no_gain');         // then stopped, rather than creeping
  });

  it('refuses once the ceiling has passed', () => {
    expect(planExtend(entry(8 * 24 * HOUR, 10 * MIN), 20 * 60, NOW))
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
