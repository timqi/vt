import { describe, it, expect } from 'vitest';
import {
  planExtend, isAllowedApproveTtl, isAllowedExtendTtl,
  approveTtlOptions, extendTtlOptions,
} from '../src/cache_policy';

const NOW = 1_800_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;
const PERMANENT = 100 * 365 * 24 * 3600;

// A live entry created `ageMs` ago that expires `leftMs` from now.
const entry = (ageMs: number, leftMs: number) =>
  ({ created_ms: NOW - ageMs, expires_ms: NOW + leftMs });

describe('policy constants', () => {
  it('keeps the phone approve ladder short', () => {
    expect(approveTtlOptions()).toEqual([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);
  });

  // "Permanent" is a finite far-future TTL on purpose: every consumer (read
  // check, sweeper, audit, countdown) keeps working with no special case, and
  // its expiry must still land past the next century.
  it('offers the multi-day rungs only for extension', () => {
    expect(extendTtlOptions()).toEqual([
      20 * 60, 2 * 60 * 60, 8 * 60 * 60, 24 * 3600, 2 * 24 * 3600, 7 * 24 * 3600, PERMANENT,
    ]);
    expect(new Date(NOW + PERMANENT * 1000).getUTCFullYear()).toBeGreaterThan(2100);
  });

  it('accepts only approve-ladder TTLs at approval time', () => {
    expect(isAllowedApproveTtl(20 * 60)).toBe(true);
    expect(isAllowedApproveTtl(8 * 3600)).toBe(true);
    // Extension-only rungs must NOT be armable straight from a phone approval.
    expect(isAllowedApproveTtl(24 * 3600)).toBe(false);
    expect(isAllowedApproveTtl(7 * 24 * 3600)).toBe(false);
    expect(isAllowedApproveTtl(PERMANENT)).toBe(false);
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
});

describe('planExtend', () => {
  const TTL_1D = 24 * 3600;
  it.each([
    // Every extension is measured from the approval moment, regardless of how
    // old the entry is — so an entry renews indefinitely, one hop at a time.
    ['a live entry, to now + ttl', entry(5 * MIN, 10 * MIN), 20 * 60,
      { ok: true, expires_ms: NOW + 20 * MIN }],
    ['an 8h-old entry, from now', entry(8 * HOUR, MIN), TTL_1D, { ok: true, expires_ms: NOW + 24 * HOUR }],
    ['a 30-day-old entry, from now', entry(30 * 24 * HOUR, MIN), TTL_1D, { ok: true, expires_ms: NOW + 24 * HOUR }],
    // Anti-resurrection: once an entry has lapsed, only a new phone approval
    // brings the capability back. Exactly at expires_ms counts as expired,
    // matching the read path's `<=`.
    ['a lapsed entry', { created_ms: NOW - MIN, expires_ms: NOW - 1 }, 20 * 60, { ok: false, skip: 'expired' }],
    ['an entry at exactly expires_ms', { created_ms: NOW - MIN, expires_ms: NOW }, 20 * 60,
      { ok: false, skip: 'expired' }],
    // created_ms is required (entries written before 2026-05-20 lack it).
    ['an entry with no created_ms', { expires_ms: NOW + MIN }, 7 * TTL_1D, { ok: false, skip: 'expired' }],
    ['a malformed expiry', { created_ms: NOW, expires_ms: undefined }, 20 * 60, { ok: false, skip: 'expired' }],
    // Regression: a naive `min(now+ttl, ceiling)` SHORTENS an entry when the
    // requested TTL is smaller than the time already remaining.
    ['a hop that would shorten the entry', entry(MIN, 3 * HOUR), 20 * 60, { ok: false, skip: 'no_gain' }],
  ] as const)('plans %s', (_name, e, ttl, want) => {
    expect(planExtend(e, ttl, NOW)).toEqual(want);
  });
});
