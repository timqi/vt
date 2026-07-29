// DEK-cache duration policy — the pure, testable half of the cache lifecycle.
//
// Everything here is side-effect free so the security-relevant arithmetic (what
// a TTL is allowed to be, how far an entry may be extended) can be unit-tested
// without a Durable Object harness. The storage/audit/ceremony plumbing lives in
// do_account.ts.

import { CacheEntry } from './types';

// Two ladders, one rule: a TTL is legal only if some PASSKEY ceremony offers it.
//
// APPROVE — what the phone offers at approval time. Deliberately short and
// unchanged: that tap happens in a hurry, often one-handed, and a mis-tap here
// silently widens the no-phone-approval window for the whole batch. 0 ("do not
// cache") is not a member — it is the absence of a write. The PWA's radios are
// [0, ...this] (see opPageData).
export const APPROVE_TTL_WHITELIST = new Set([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);

// EXTEND — what the admin cache tab may REQUEST, still settled by a Passkey
// ceremony. A superset: extension is a deliberate, desk-bound act on a named set
// of live entries, reviewed on the approval page before the tap, so the
// multi-day rungs live here rather than on the phone's approve-time radios.
//
// The multi-day options exist because the 8h-ceiling design made extension
// useless for the case that actually matters: an 8h grant is at its ceiling from
// birth, so every extension of it was a no-op. Long-running CI and attended
// desktop sessions need a window longer than one workday or the feature is
// decoration.
export const EXTEND_TTL_WHITELIST = new Set([
  20 * 60, 2 * 60 * 60, 8 * 60 * 60,
  24 * 60 * 60,        // 1d
  2 * 24 * 60 * 60,    // 2d
  7 * 24 * 60 * 60,    // 1w
]);

// Hard ceiling on the TOTAL lifetime of one cache entry, measured from the
// moment the phone approval created it — NOT from the last extension.
//
// It is COMPUTED as the longest TTL any Passkey ceremony can grant (the union of
// the two ladders above), never hardcoded. That derivation is the invariant: the
// ceiling can only move when a ceremony is actually able to grant that long, so
// no admin path can ever out-grant what a human approved, and repeated small
// extensions converge here instead of walking forever.
//
// SECURITY NOTE: with 1w on the extend ladder this ceiling is ONE WEEK. For that
// whole window, possession of VT_PASSKEY_TOKEN from the same egress IP and `pwd`
// decrypts the approved records with no phone tap. That is a deliberate operator
// choice, not a default — reaching it takes an explicit extension request plus a
// Passkey approval whose page states the new expiry. Shorten this ladder for
// high-assurance deployments.
export const MAX_CACHE_LIFETIME_MS =
  Math.max(...APPROVE_TTL_WHITELIST, ...EXTEND_TTL_WHITELIST) * 1000;

/** Why an entry was left untouched by an extension. Reported per group so the
 *  admin UI can explain a partial result instead of silently doing nothing. */
export type ExtendSkip =
  /** Already past expires_ms — an extension must never resurrect a lapsed
   *  entry (that would be the Worker minting cache authority from nothing). */
  | 'expired'
  /** Pre-migration entry with no created_ms, so its total lifetime cannot be
   *  bounded. Listable and clearable, never extendable. */
  | 'legacy'
  /** Already at (or past) created_ms + MAX_CACHE_LIFETIME_MS. */
  | 'capped'
  /** The requested TTL would not move expiry forward. Never shorten an entry:
   *  "extend" is monotonic by definition, and a shortening extend would be a
   *  confusing way to spell "clear". */
  | 'no_gain';

export type ExtendPlan =
  | { ok: true; expires_ms: number }
  | { ok: false; skip: ExtendSkip };

/** Decide the new absolute expiry for ONE entry, or why it is skipped.
 *
 *  Pure: the caller re-reads the entry under the DO gate and applies this to the
 *  fresh copy, so a stale plan can never be written back. */
export function planExtend(
  entry: Pick<CacheEntry, 'expires_ms' | 'created_ms'>,
  ttlS: number,
  now: number,
  maxLifetimeMs: number = MAX_CACHE_LIFETIME_MS,
): ExtendPlan {
  if (typeof entry.expires_ms !== 'number' || entry.expires_ms <= now) {
    return { ok: false, skip: 'expired' };
  }
  const created = entry.created_ms;
  if (typeof created !== 'number' || !Number.isFinite(created) || created <= 0) {
    return { ok: false, skip: 'legacy' };
  }
  const ceiling = created + maxLifetimeMs;
  if (now >= ceiling) return { ok: false, skip: 'capped' };
  const candidate = Math.min(now + ttlS * 1000, ceiling);
  if (candidate <= entry.expires_ms) return { ok: false, skip: 'no_gain' };
  return { ok: true, expires_ms: candidate };
}

/** A phone approval may only arm a cache with a TTL from the approve ladder.
 *  Guards writeCache, so a tampered approve body cannot smuggle in an extend-only
 *  (multi-day) rung and bypass the deliberate extension ceremony. */
export function isAllowedApproveTtl(ttlS: unknown): ttlS is number {
  return typeof ttlS === 'number' && Number.isFinite(ttlS) && APPROVE_TTL_WHITELIST.has(ttlS);
}

/** An extension request may only ask for a TTL from the extend ladder. */
export function isAllowedExtendTtl(ttlS: unknown): ttlS is number {
  return typeof ttlS === 'number' && Number.isFinite(ttlS) && EXTEND_TTL_WHITELIST.has(ttlS);
}

/** Sorted approve-time options (ascending seconds), excluding 0 — the phone's radios. */
export function approveTtlOptions(): number[] {
  return [...APPROVE_TTL_WHITELIST].sort((a, b) => a - b);
}

/** Sorted extension options (ascending seconds) — the admin tab's dropdown. */
export function extendTtlOptions(): number[] {
  return [...EXTEND_TTL_WHITELIST].sort((a, b) => a - b);
}

/** Stable grouping handle for a cache entry.
 *
 *  New entries carry a random `cache_group_id` minted once per writeCache call
 *  (= per approval, per binding ctx), which is what an extension selects on.
 *  Pre-migration entries have none; they are grouped under a `legacy:` handle
 *  derived from the origin audit token so they remain listable and clearable —
 *  but `legacy:` is deliberately NOT a valid extend selector (planExtend also
 *  refuses them for lack of created_ms), because a truncated approve_token is
 *  too weak a key to hang an authority-granting mutation on. */
export function groupIdOf(entry: Pick<CacheEntry, 'cache_group_id' | 'origin_token_id'>): string {
  const gid = entry.cache_group_id;
  if (typeof gid === 'string' && gid.startsWith('g_') && gid.length <= 40) return gid;
  return `legacy:${entry.origin_token_id ?? ''}`;
}

/** Is this group handle one an extension is allowed to target? */
export function isExtendableGroupId(groupId: unknown): groupId is string {
  return typeof groupId === 'string' && groupId.startsWith('g_') && groupId.length <= 40;
}
