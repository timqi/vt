// Account-local DEK storage. Uses the AccountDO storage and input gate; it
// cannot authenticate a request, finalize a ceremony, or dispatch notifications.

import { Env, Challenge, ChallengeMeta, CacheEntry, CacheExtendIntent } from './types';
import { b64uEnc, isB64uString, decodeB64uExact, sha256, randomBytes } from './crypto';
import { seal, openToCache } from './cache_crypto';
import { planExtend, isAllowedApproveTtl, groupIdOf, isExtendableGroupId, cacheScopePwd } from './cache_policy';
import { logErr } from './log';

// DO storage batch limits: at most 128 keys per get() and 128 pairs per put().
const STORAGE_BATCH = 128;
// Entries read per internal list() page when aggregating the admin cache listing.
const CACHE_LIST_PAGE = 1000;
// Hard cap on entries scanned for one listing. Bounds DO CPU/memory on a
// pathologically large cache; the response reports `truncated` so the UI can say
// the view is partial rather than imply completeness.
const CACHE_LIST_SCAN_MAX = 20000;

// DEK cache entry key. ctx binds the entry to (a) the requester's worker-derived
// IP (CF-Connecting-IP — unspoofable by the client, the hard boundary) AND (b)
// the client-reported working directory (pwd), normalized by cacheScopePwd. A
// lookup recomputes ctx from the same IP + scope, so a request from a different
// egress IP OR an unrelated cwd finds no key (a clean miss, no oracle).
//
// pwd is CLIENT-REPORTED, so — like the removed ppid — it is advisory: a fully
// compromised local host can spoof it, so it does not widen the real (IP) hard
// boundary. Its value is same-host blast-radius reduction: a process decrypting
// from an UNRELATED directory misses the cache, so a cached grant for one project
// tree does not silently serve another. Crucially — and unlike ppid — pwd is
// STABLE across orchestrated callers (Claude Code, CI, make, tmux) that spawn a
// fresh shell per command from the same project dir, so the cache still hits.
//
// History: ctx v1 folded in the client-reported parent PID; that was dropped
// (v1→v2) because ppid is BOTH spoofable AND unstable (getppid() changes every
// call under orchestrators, so the cache never hit). ppid is still recorded on
// each entry + audit row for forensics. v2→v3 adds pwd. v3→v4 folds in
// cacheScopePwd (worktree suffixes stripped) instead of the literal pwd; the tag
// bump keeps the two derivations from ever sharing a storage key, at the cost of
// stranding v3 entries (they lapse/sweep normally, and can be cleared from the
// admin tab). The effective hard guarantee is unchanged: within the TTL,
// possession of VT_PASSKEY_TOKEN behind the SAME egress IP; the pwd scope only
// narrows it further, it never widens beyond that IP.
//
// Normalization happens HERE, not at the call sites, so no future caller can
// key a write and a read on different halves of the rule.
async function cacheCtx(ip: string, pwd: string): Promise<string> {
  const enc = new TextEncoder();
  const tag = enc.encode('vt-dek-ctx-v4');
  const ipBytes = enc.encode(ip);
  const pwdBytes = enc.encode(cacheScopePwd(pwd));
  // Length-prefix the IP so (ip="a", pwd="bc") and (ip="ab", pwd="c") can't
  // collide into the same digest. IP has no NUL, so a NUL separator is
  // unambiguous, but an explicit u32 length is simplest and future-proof.
  const lenPrefix = new Uint8Array(4);
  new DataView(lenPrefix.buffer).setUint32(0, ipBytes.length, false);
  const buf = new Uint8Array(tag.length + lenPrefix.length + ipBytes.length + pwdBytes.length);
  let o = 0;
  buf.set(tag, o); o += tag.length;
  buf.set(lenPrefix, o); o += lenPrefix.length;
  buf.set(ipBytes, o); o += ipBytes.length;
  buf.set(pwdBytes, o);
  return b64uEnc(await sha256(buf));
}

function cacheKey(ctx: string, saltB64u: string): string {
  return `dek:${ctx}:${saltB64u}`;
}

// One aggregated DEK-cache group, as scanned from storage. `keys` holds the
// `dek:{ctx}:{salt}` storage keys and is populated ONLY for the extension commit
// — it must never reach a response body (the ctx digest plus a known IP would let
// a reader brute-force the client-reported `pwd` offline).
interface CacheAgg {
  group_id: string;
  keys: string[];
  origin_token_id: string;
  entries: number;
  live: number;
  max_expires_ms: number;
  created_ms: number | null;
  ip: string;
  ppid: number;
  ppid_cmd: string;
  consistent: boolean;
}

type CacheWriteResult =
  | { ok: false; reason: string }
  | { ok: true; expires_ms: number; group_id: string };

interface CacheExtendResult {
  groups: number;
  skipped: Record<string, number>;
  extended: number;
  latest: number;
  effects: Array<{ origin_token_id: string; expires_ms: number }>;
}

export class AccountCache {
  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly env: Pick<Env, 'CACHE_SECKEY'>,
  ) {}

  // Delete an arbitrary number of keys, in the batches the platform accepts.
  //
  // DO storage takes at most STORAGE_BATCH keys per delete() call — the same
  // documented cap as get()/put(). Handing it a longer array THROWS, and on a
  // delete that means the cleanup (or the revocation) removes nothing at all
  // while its caller happily reports the length it intended to remove. Returns
  // the count storage actually removed, so a caller can report the truth rather
  // than its intent.
  private async deleteKeysBatched(keys: string[]): Promise<number> {
    let deleted = 0;
    for (let i = 0; i < keys.length; i += STORAGE_BATCH) {
      deleted += await this.storage.delete(keys.slice(i, i + STORAGE_BATCH));
    }
    return deleted;
  }

  // Read an arbitrary number of keys, in the batches the platform accepts.
  //
  // Same STORAGE_BATCH cap as delete()/put(): a longer array THROWS, which on
  // the cache-read path turns a clean `{miss:true}` into a 500. The chunk
  // boundaries depend only on keys.length, never on which key is present, so
  // this keeps the batched-lookup property the caller relies on — response
  // timing must not leak the position of the first miss.
  private async getKeysBatched(keys: string[]): Promise<Map<string, CacheEntry>> {
    const out = new Map<string, CacheEntry>();
    for (let i = 0; i < keys.length; i += STORAGE_BATCH) {
      const part = await this.storage.get<CacheEntry>(keys.slice(i, i + STORAGE_BATCH));
      for (const [k, v] of part) out.set(k, v);
    }
    return out;
  }

  // Delete every `dek:` entry `pick` selects, paging the prefix to its END.
  //
  // This is the REVOKE direction, so completeness is the contract. Unlike
  // scanCacheGroups — which stops at CACHE_LIST_SCAN_MAX and makes its caller
  // surface `truncated` — a clear that stopped early would leave DEKs
  // decryptable while answering 200 with a count, i.e. a success the operator
  // cannot tell from a real one. There is deliberately NO cap here; the only
  // bound left is the request's own CPU/wall budget, and exhausting that fails
  // LOUDLY instead of under-delivering silently.
  //
  // Memory stays O(one page + one delete batch): a matched key is deleted as it
  // is found and never accumulated, so this is safe on a cache far larger than
  // an unbounded list() could hold (list() with no options loads the whole
  // prefix into the isolate's memory).
  //
  // Deleting while paging is safe: `startAfter` is a key VALUE, not an index, so
  // removing keys the cursor already passed cannot make it skip anything.
  private async sweepCacheEntries(
    pick: (entry: CacheEntry, key: string) => boolean,
  ): Promise<{ deleted: number; scanned: number }> {
    let deleted = 0;
    let scanned = 0;
    let startAfter: string | undefined;
    let batch: string[] = [];
    for (;;) {
      const page: Map<string, CacheEntry> = await this.storage.list<CacheEntry>({
        prefix: 'dek:',
        limit: CACHE_LIST_PAGE,
        ...(startAfter ? { startAfter } : {}),
      });
      // Terminate ONLY on an empty page. A short-but-nonempty page does not mean
      // "end of prefix" (DO storage may cut one below the requested limit to stay
      // under a response-size cap), and treating it as the end is precisely the
      // silent partial clear this exists to prevent.
      if (page.size === 0) break;
      for (const [key, entry] of page) {
        startAfter = key;
        scanned++;
        if (!entry || typeof entry !== 'object' || !pick(entry, key)) continue;
        batch.push(key);
        if (batch.length >= STORAGE_BATCH) {
          deleted += await this.storage.delete(batch);
          batch = [];
        }
      }
    }
    if (batch.length) deleted += await this.storage.delete(batch);
    return { deleted, scanned };
  }

  sweepExpired(now: number): Promise<{ deleted: number; scanned: number }> {
    return this.sweepCacheEntries(entry => entry.expires_ms <= now);
  }

  clearByOrigin(tokenId: string): Promise<{ deleted: number; scanned: number }> {
    return this.sweepCacheEntries(entry => entry.origin_token_id === tokenId);
  }

  clearAll(): Promise<{ deleted: number; scanned: number }> {
    return this.sweepCacheEntries(() => true);
  }

  async clearGroups(ids: string[]): Promise<{ deleted: number; scanned: number; groups: number }> {
    const want = new Set(ids);
    const hit = new Set<string>();
    const result = await this.sweepCacheEntries(entry => {
      const gid = groupIdOf(entry);
      if (!want.has(gid)) return false;
      hit.add(gid);
      return true;
    });
    return { ...result, groups: hit.size };
  }

  // Write one cache entry per salt, keyed by ctx(IP,pwd)+salt. Caller has
  // already verified the WebAuthn assertion, so this is authorized. INVARIANT
  // (M1): we only reach here because the PHONE sent cache material (the PWA
  // produces it solely when the human picks TTL > 0) — the Worker cannot
  // fabricate a cache entry the user did not authorize.
  async writeCache(
    ch: Challenge, ttlS: number, sealedList: string[] | undefined, originTokenId: string,
  ): Promise<CacheWriteResult> {
    const reject = (reason: string): CacheWriteResult => ({ ok: false, reason });

    // Approve ladder only: the multi-day rungs are extension-only, so a tampered
    // approve body cannot skip the deliberate extension ceremony.
    if (!isAllowedApproveTtl(ttlS)) return reject(`ttl ${ttlS} not approvable`);
    if (!this.env.CACHE_SECKEY || !this.env.CACHE_SECKEY.trim()) {
      return reject('CACHE_SECKEY unset (caching disabled)');
    }
    const salts = ch.salts_b64u;
    // Auth-only ceremonies (no salts) have nothing to cache; a length mismatch
    // means the PWA and challenge disagree — refuse rather than store garbage.
    if (salts.length === 0 || !Array.isArray(sealedList) || sealedList.length !== salts.length) {
      return reject('cache_sealed_deks length mismatch');
    }
    // Each blob must be crypto_box_seal(32-byte DEK) = 32 + 48 = 80 bytes AND
    // must actually open to CACHE_PUBKEY. Verifying at write time turns a stale
    // /wrong cache_pubkey on the phone into one logged error here, instead of
    // silent permanent cache misses + lazy-delete churn at read time (N1).
    for (const s of sealedList) {
      try { decodeB64uExact(s, 80, 'cache_sealed_dek'); }
      catch { return reject('cache_sealed_dek malformed'); }
      const probe = openToCache(s, this.env.CACHE_SECKEY);
      if (!probe || probe.length !== 32) {
        probe?.fill(0);
        return reject('cache_sealed_dek does not open to CACHE_PUBKEY');
      }
      probe.fill(0);
    }

    const ip = ch.meta.ip ?? '';
    // ppid is not part of the binding ctx (ctx = IP + pwd) — kept solely as a
    // forensic field stored on each cache entry + audit row.
    const ppid = typeof ch.meta.ppid === 'number' ? ch.meta.ppid : 0;
    const ctx = await cacheCtx(ip, ch.meta.pwd ?? '');
    const createdMs = Date.now();
    const expires = createdMs + ttlS * 1000;
    // One group handle per write: unique, random, and independent of the
    // approve_token — an authority-GRANTING mutation (extend) must not hang off a
    // selector that could ever be ambiguous. created_ms is forensic only (extension
    // measures from the approval) and is never rewritten afterwards.
    const groupId = 'g_' + b64uEnc(randomBytes(9));
    const writes: Record<string, CacheEntry> = {};
    for (let i = 0; i < salts.length; i++) {
      writes[cacheKey(ctx, salts[i]!)] = {
        sealed_to_cache_b64u: sealedList[i]!,
        expires_ms: expires,
        origin_token_id: originTokenId,
        ip,
        ppid,
        ppid_cmd: ch.meta.ppid_cmd ?? '',
        cache_group_id: groupId,
        created_ms: createdMs,
      };
    }
    // put() accepts at most STORAGE_BATCH pairs; a ceremony may carry up to 256
    // salts, so chunk. Partial failure leaves fewer cached entries than approved
    // — the all-or-nothing read then simply misses and re-prompts (fail-closed).
    const entries = Object.entries(writes);
    for (let i = 0; i < entries.length; i += STORAGE_BATCH) {
      await this.storage.put(Object.fromEntries(entries.slice(i, i + STORAGE_BATCH)));
    }
    return { ok: true, expires_ms: expires, group_id: groupId };
  }

  async read(meta: ChallengeMeta, salts: string[], daemonPk: Uint8Array): Promise<string | null> {
    const ip = meta.ip ?? '';
    const pwd = meta.pwd ?? '';
    if (salts.length === 0 || salts.length > 256) return null;
    if (!this.env.CACHE_SECKEY || !this.env.CACHE_SECKEY.trim()) return null;
    for (const s of salts) { if (!isB64uString(s)) return null; }

    const ctx = await cacheCtx(ip, pwd);
    // Batch the lookups (M2): the whole key set is read before anything is
    // decided, so response timing does not leak the position of the first miss.
    // Batched via getKeysBatched because salts may run to 256, twice the
    // STORAGE_BATCH cap a single get() accepts.
    const keys = salts.map(s => cacheKey(ctx, s));
    const map = await this.getKeysBatched(keys);

    const now = Date.now();
    const orphaned: string[] = [];
    const dekParts: Uint8Array[] = [];
    let flat: Uint8Array | undefined;
    let sealedB64u: string;
    try {
      for (const key of keys) {
        const entry = map.get(key);
        if (!entry || entry.expires_ms <= now) continue;
        const dek = openToCache(entry.sealed_to_cache_b64u, this.env.CACHE_SECKEY);
        if (!dek || dek.length !== 32) {
          dek?.fill(0);
          // Undecryptable (e.g. CACHE_SECKEY rotated, M3): uniformly miss and
          // lazily drop the orphaned entry, never surface a 500.
          orphaned.push(key);
          continue;
        }
        dekParts.push(dek);
      }
      if (orphaned.length) { try { await this.deleteKeysBatched(orphaned); } catch {} }

      // All-or-nothing, including partial hits: every opened DEK is covered
      // by finally, even when a later salt is missing or opening/sealing fails.
      if (dekParts.length !== salts.length) return null;
      flat = new Uint8Array(dekParts.length * 32);
      for (let i = 0; i < dekParts.length; i++) flat.set(dekParts[i]!, i * 32);
      sealedB64u = seal(flat, daemonPk);
    } finally {
      flat?.fill(0);
      dekParts.forEach(d => d.fill(0));
    }

    return sealedB64u;
  }

  // One aggregated group as scanned from storage. `keys` is populated only when
  // the caller needs to mutate/delete (kept out of the listing response, which
  // must never expose a `dek:{ctx}:{salt}` key: ctx plus a known IP would turn the
  // listing into an offline oracle for the client-reported `pwd`).
  private static aggInit(groupId: string, e: CacheEntry): CacheAgg {
    return {
      group_id: groupId,
      keys: [],
      origin_token_id: e.origin_token_id ?? '',
      entries: 0,
      live: 0,
      max_expires_ms: 0,
      created_ms: typeof e.created_ms === 'number' ? e.created_ms : null,
      ip: e.ip ?? '',
      ppid: typeof e.ppid === 'number' ? e.ppid : 0,
      ppid_cmd: e.ppid_cmd ?? '',
      consistent: true,
    };
  }

  // Aggregate every `dek:` entry into groups. Paged internally (list() caps what
  // one call should hold in memory) and hard-capped by CACHE_LIST_SCAN_MAX, which
  // the caller must surface as `truncated` rather than pass off as a full view.
  //
  // That cap makes this the wrong tool for a REVOKE: a group past it is simply
  // never seen, so a clear built on this scan reports success for entries it did
  // not touch. Clearing therefore uses sweepCacheEntries (uncapped, streaming);
  // what is left here is the listing and the extension commit, where stopping
  // short only ever under-grants — and is tallied in the extension's audit row.
  //
  // `want` restricts aggregation to specific groups (still a full scan — the group
  // id is inside the value, not the key — but bounds memory to what is needed).
  // `collectKeys` additionally records each group's storage keys for a mutation.
  async scanCacheGroups(
    now: number,
    opts: { want?: Set<string>; collectKeys?: boolean } = {},
  ): Promise<{ groups: Map<string, CacheAgg>; scanned: number; truncated: boolean }> {
    const groups = new Map<string, CacheAgg>();
    let scanned = 0;
    let truncated = false;
    let startAfter: string | undefined;
    for (;;) {
      const page: Map<string, CacheEntry> = await this.storage.list<CacheEntry>({
        prefix: 'dek:',
        limit: CACHE_LIST_PAGE,
        ...(startAfter ? { startAfter } : {}),
      });
      if (page.size === 0) break;
      for (const [key, e] of page) {
        startAfter = key;
        scanned++;
        if (!e || typeof e !== 'object') continue;
        const gid = groupIdOf(e);
        if (opts.want && !opts.want.has(gid)) continue;
        let agg = groups.get(gid);
        if (!agg) { agg = AccountCache.aggInit(gid, e); groups.set(gid, agg); }
        if (opts.collectKeys) agg.keys.push(key);
        agg.entries++;
        const exp = typeof e.expires_ms === 'number' ? e.expires_ms : 0;
        if (exp > now) agg.live++;
        if (exp > agg.max_expires_ms) agg.max_expires_ms = exp;
        // Entries of one group are written by a single put batch, so they MUST
        // agree on origin/creation/IP. If they don't, something wrote across a
        // group boundary: report it and refuse to extend (clearing stays safe).
        const created = typeof e.created_ms === 'number' ? e.created_ms : null;
        if (agg.origin_token_id !== (e.origin_token_id ?? '')
            || agg.created_ms !== created
            || agg.ip !== (e.ip ?? '')) {
          agg.consistent = false;
        }
      }
      // Terminate ONLY on an empty page. A short-but-nonempty page does not mean
      // "end of prefix": DO storage may cut a page below the requested limit to
      // stay under an internal response-size cap. Treating that as completion
      // would silently drop the remaining groups while still reporting
      // truncated=false — precisely the silent-partial-view failure this listing
      // must never have. The cost is one extra empty list() per scan.
      if (scanned >= CACHE_LIST_SCAN_MAX) { truncated = true; break; }
    }
    return { groups, scanned, truncated };
  }

  // Commit an APPROVED extension. AccountDO calls this only after the WebAuthn
  // assertion verified, the challenge was consumed, and the kill switch and TTL
  // were rechecked. Results describe acknowledged effects for the DO's audit.
  //
  // Per group, per storage batch: re-read the entries and apply planExtend to the
  // FRESH copy with no await between the read and the write. The DO input gate
  // reopens at every await, so a plan computed from the request-time scan could
  // otherwise be written over an entry that opDekCache's orphan sweep just
  // deleted, or that the alarm just expired — i.e. resurrect it. Re-reading in the
  // same atomic step makes that impossible: only keys still present and still live
  // at write time are touched.
  async commitExtend(intent: CacheExtendIntent): Promise<CacheExtendResult> {
    const want = new Set(intent.group_ids.filter(isExtendableGroupId));
    const scan = await this.scanCacheGroups(Date.now(), { want, collectKeys: true });
    // One merged skip tally for the whole commit — the audit line reports totals,
    // and nothing consumed the per-group breakdown.
    const skipped: Record<string, number> = {};
    let totalExtended = 0;
    let latest = 0;
    const effects: CacheExtendResult['effects'] = [];

    for (const g of scan.groups.values()) {
      let extended = 0;
      let groupLatest = 0;
      // A group that drifted between request and commit is refused outright — we
      // will not guess which record the approver meant.
      if (!g.consistent) {
        skipped.inconsistent = (skipped.inconsistent ?? 0) + g.entries;
        continue;
      }
      // Isolate each group: a storage failure on one must not abort the loop, or
      // groups that already mutated would go unrecorded by the trailing audit row
      // (the mutation is durable, so its trail must be too).
      try {
        for (let i = 0; i < g.keys.length; i += STORAGE_BATCH) {
          const chunk = g.keys.slice(i, i + STORAGE_BATCH);
          const fresh = await this.storage.get<CacheEntry>(chunk);
          // ── atomic section: no await until the put ──
          const now = Date.now();
          const writes: Record<string, CacheEntry> = {};
          let chunkLatest = 0;
          for (const key of chunk) {
            const entry = fresh.get(key);
            if (!entry) { skipped.gone = (skipped.gone ?? 0) + 1; continue; }
            const plan = planExtend(entry, intent.ttl_s, now);
            if (!plan.ok) { skipped[plan.skip] = (skipped[plan.skip] ?? 0) + 1; continue; }
            writes[key] = { ...entry, expires_ms: plan.expires_ms };
            if (plan.expires_ms > chunkLatest) chunkLatest = plan.expires_ms;
          }
          const count = Object.keys(writes).length;
          if (count > 0) {
            await this.storage.put(writes);
            // Account for effects only after storage acknowledges this batch.
            // A failed later batch must retain the earlier successful tally.
            extended += count;
            if (chunkLatest > groupLatest) groupLatest = chunkLatest;
          }
          // ── end atomic section ──
        }
      } catch (e) {
        logErr('cache.extend_group_failed', e, { group: g.group_id });
        skipped.error = (skipped.error ?? 0) + 1;
      }
      totalExtended += extended;
      if (groupLatest > latest) latest = groupLatest;
      if (extended > 0 && g.origin_token_id) {
        effects.push({ origin_token_id: g.origin_token_id, expires_ms: groupLatest });
      }
    }

    return { groups: scan.groups.size, skipped, extended: totalExtended, latest, effects };
  }
}
