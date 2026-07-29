// DEK-cache duration policy — the pure, testable half of the cache lifecycle.
//
// Everything here is side-effect free so the security-relevant arithmetic (what
// a TTL is allowed to be, how far an entry may be extended) can be unit-tested
// without a Durable Object harness. The storage/audit/ceremony plumbing lives in
// do_account.ts.

import { CacheEntry } from './types';

// Allowed positive DEK-cache TTLs (seconds). A write with any value outside this
// set is rejected, so neither a tampered approve body nor a future UI typo can
// mint an over-long window. 0 ("do not cache") is NOT a member — it is the
// absence of a write. The PWA's radio options are [0, ...this] (see opPageData),
// and an extension may only request a member of this same set.
export const CACHE_TTL_WHITELIST = new Set([20 * 60, 2 * 60 * 60, 8 * 60 * 60]);

// Hard ceiling on the TOTAL lifetime of one cache entry, measured from the
// moment the phone approval created it — NOT from the last extension.
//
// It equals the longest TTL a human can pick on the approval page
// (max(CACHE_TTL_WHITELIST) = 8h). That equality is the whole point: an
// extension may only re-spend time inside the window the approver could have
// granted in the first place, so repeated 20m extensions can never synthesize a
// 24h window that nobody ever approved. Raising this above the whitelist maximum
// would mean the admin surface can grant more exposure than the phone can, which
// is exactly the authority inversion the extend feature must not introduce.
export const MAX_CACHE_LIFETIME_MS = Math.max(...CACHE_TTL_WHITELIST) * 1000;

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

/** An extension may only request a TTL the phone itself could have granted. */
export function isAllowedTtl(ttlS: unknown): ttlS is number {
  return typeof ttlS === 'number' && Number.isFinite(ttlS) && CACHE_TTL_WHITELIST.has(ttlS);
}

/** Sorted TTL options for a UI (ascending seconds), excluding 0. */
export function ttlOptions(): number[] {
  return [...CACHE_TTL_WHITELIST].sort((a, b) => a - b);
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
