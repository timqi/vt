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
  24 * 60 * 60,          // 1d
  2 * 24 * 60 * 60,      // 2d
  7 * 24 * 60 * 60,      // 1w
  100 * 365 * 24 * 3600, // effectively permanent — see below
]);

// The "permanent" rung is a FINITE 100-year TTL, deliberately not a null/Infinity
// sentinel. An unbounded expiry would need a special case in every consumer —
// opDekCache's `expires_ms <= now` read check, the alarm sweep, audit
// cache_expires_ms, the admin countdown — and expiry logic is exactly where a
// missed branch becomes a cache that outlives its revocation. A far-future
// timestamp keeps all of those paths on their normal course: it simply never
// arrives. (The TTL itself is ~3.15e12 ms; the expiry it produces lands around
// year 2126, ~4.9e12 ms — both far inside the safe-integer range and SQLite
// INTEGER.)
//
// SECURITY NOTE: this rung opts a record OUT of the phone-approval premise for
// practical purposes. Liveness is what bounds every other rung — stop approving and
// the capability dies on its own — and an entry on this one never lapses, so
// nothing revokes it but an explicit admin clear or rotating CACHE_SECKEY, and it
// is never swept. There is also no expiry to prompt a future review. Consider
// CACHE_HIT_NOTIFY=1 alongside it so each no-tap decrypt remains visible somewhere.

// The cap is PER OPERATION, not per entry lifetime: one extension may move expiry
// to at most `now + max(EXTEND_TTL_WHITELIST)`. Total lifetime is deliberately
// unbounded — each hop costs a fresh Passkey approval, so the human is in the loop
// every single time rather than once at the start.
//
// This replaced an absolute `created_ms + 1w` ceiling. Two reasons:
//   • It made the feature inert for the common case. Operators cache for 8h, and
//     the interesting question at hour seven is "another day from now", not "how
//     much of a week-old budget is left".
//   • It bought little. The ceiling only constrains someone who can already
//     complete a WebAuthn ceremony — i.e. holds the Passkey — and against that
//     adversary nothing here helps. What it did constrain was the legitimate
//     operator, plus it permanently excluded pre-`created_ms` entries.
//
// SECURITY NOTE: an entry can therefore live indefinitely, one approved hop at a
// time. For each window, possession of VT_PASSKEY_TOKEN from the same egress IP
// and a `pwd` in the same cacheScopePwd scope decrypts the approved records with
// no phone tap. The safeguards that
// remain are the ones that hold without a budget: a lapsed entry is never revived
// (extension only ever continues a LIVE grant), expiry never moves backwards, the
// per-hop TTL is laddered, and every hop is audited with the approver's identity.
// Trim EXTEND_TTL_WHITELIST to shorten the longest single hop.
export const MAX_EXTEND_TTL_MS = Math.max(...EXTEND_TTL_WHITELIST) * 1000;

// ── Cache scope: how a working directory becomes the `pwd` half of the ctx ──
//
// The binding ctx is derived from a NORMALIZED pwd, not the literal one: every
// path segment loses its final `.suffix`, so a git-worktree tree
// (`<repo>.<branch>`, the layout `wt`/worktrunk generates as a sibling of the
// trunk) shares one cache with its trunk instead of demanding a fresh phone
// approval per branch.
//
//   /home/me/code/pier.stable/skills  ->  /home/me/code/pier/skills
//   /home/me/code/pier                ->  /home/me/code/pier       (unchanged)
//
// This WIDENS the advisory half of the binding on purpose: `pier.stable`,
// `pier.dev` and `pier` become one cache scope, and so do incidental neighbours
// like `node-v20.11` / `node-v20.12`. It does not touch the hard boundary — a
// hit still requires the same worker-derived egress IP — and it changes only
// the KEY: `meta.pwd` keeps the literal directory everywhere a human reads it
// (approval page, notifications, audit, admin listing), and the approval page
// additionally states the normalized scope the approval would arm.
function stripSegmentExt(seg: string): string {
  // All-dots segments (`.`, `..`) are path syntax, never a name with an
  // extension — stripping `..` would rewrite the path itself.
  if (/^\.+$/.test(seg)) return seg;
  const dot = seg.lastIndexOf('.');
  // dot <= 0: no extension, or a leading dot (`.config`, `.git`) whose "base"
  // would be empty — a hidden directory keeps its whole name.
  return dot <= 0 ? seg : seg.slice(0, dot);
}

/** The `pwd` half of the cache binding ctx. Pure; see the note above.
 *
 *  Typed `string` so a call site cannot pass the wrong field by accident (this
 *  derives a storage key), but the body still tolerates a non-string: the value
 *  originates in a client-controlled JSON body, and a throw here would be a 500
 *  on the decrypt path. */
export function cacheScopePwd(pwd: string): string {
  if (typeof pwd !== 'string' || pwd === '') return '';
  return pwd.split('/').map(stripSegmentExt).join('/');
}

/** Why an entry was left untouched by an extension. Tallied across the commit so
 *  the audit row can explain a partial result instead of silently doing nothing. */
export type ExtendSkip =
  /** Already past expires_ms — an extension must never resurrect a lapsed
   *  entry (that would be the Worker minting cache authority from nothing).
   *  This is now the load-bearing bound: extension CONTINUES a live grant and
   *  can never recreate one the operator let go. */
  | 'expired'
  /** The requested TTL would not move expiry forward — i.e. more time is already
   *  on the clock than the request asks for. Never shorten an entry: "extend" is
   *  monotonic by definition, and a shortening extend would be a confusing way to
   *  spell "clear". */
  | 'no_gain';

export type ExtendPlan =
  | { ok: true; expires_ms: number }
  | { ok: false; skip: ExtendSkip };

/** Decide the new absolute expiry for ONE entry, or why it is skipped.
 *
 *  Always measured from NOW — the moment of approval — so "延长 1 天" means one day
 *  from the tap, not one day from whenever the entry happened to be created.
 *  created_ms is deliberately NOT consulted: it is forensic metadata now, which is
 *  what lets pre-migration entries be extended like any other.
 *
 *  Pure: the caller re-reads the entry under the DO gate and applies this to the
 *  fresh copy, so a stale plan can never be written back. */
export function planExtend(
  entry: Pick<CacheEntry, 'expires_ms'>,
  ttlS: number,
  now: number,
): ExtendPlan {
  if (typeof entry.expires_ms !== 'number' || entry.expires_ms <= now) {
    return { ok: false, skip: 'expired' };
  }
  const candidate = now + ttlS * 1000;
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
 *  (= per approval, per binding ctx). Pre-migration entries have none and are
 *  grouped under a `legacy:` handle derived from the origin audit token.
 *
 *  Both forms are valid selectors. The `legacy:` half rests on origin_token_id
 *  being a FULL 96-bit approve token (auditKey keeps all 16 b64u chars of a
 *  12-byte token — it is "truncated" only in name), so a collision is not a real
 *  ambiguity; and the group is refused anyway if its entries disagree about their
 *  origin. That is what makes already-cached entries extendable instead of
 *  stranded until they lapse. */
export function groupIdOf(entry: Pick<CacheEntry, 'cache_group_id' | 'origin_token_id'>): string {
  const gid = entry.cache_group_id;
  if (typeof gid === 'string' && gid.startsWith('g_') && gid.length <= 40) return gid;
  return `legacy:${entry.origin_token_id ?? ''}`;
}

/** Is this a well-formed group handle an extension may target? Shape-checked so a
 *  hostile body cannot smuggle in a wildcard or an over-long storage key. */
export function isExtendableGroupId(groupId: unknown): groupId is string {
  if (typeof groupId !== 'string' || groupId.length > 40) return false;
  if (groupId.startsWith('g_')) return groupId.length > 2;
  if (groupId.startsWith('legacy:')) return groupId.length > 'legacy:'.length;
  return false;
}
