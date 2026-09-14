// Account-local DEK storage. Uses the AccountDO storage and input gate; it
// cannot authenticate a request, finalize a ceremony, or dispatch notifications.

import { Challenge, ChallengeMeta, CacheEntry, CacheEntryRef, CacheExtendIntent } from './types';
import { b64uEnc, isB64uString, decodeB64uExact, sha256 } from './crypto';
import { seal, openToCache } from './cache_crypto';
import { planExtend, isAllowedApproveTtl, isLive } from './cache_policy';
import { isTokenId } from './host_token';
import { logErr } from './log';
import { STORAGE_BATCH, deleteKeysBatched, listPrefixPages } from './storage_batch';

// Hard cap on entries scanned for one listing. Bounds DO CPU/memory on a
// pathologically large cache; the response reports `truncated` so the UI can say
// the view is partial rather than imply completeness.
const CACHE_LIST_SCAN_MAX = 20000;

// DEK cache entry key: `dek:{token_id}:{project_h}:{salt_b64u}`.
//
// token_id is the hard boundary: the host token the edge verified on THIS
// request (host_token.ts), so a cached grant serves only the host that earned
// it, wherever its egress IP goes. `meta.ip` stays on the entry as audit
// metadata only. project_h is the client-reported `project` (the repository's
// common git dir, else the cwd — src/cf.rs), hashed under the ctx tag and
// truncated to 16 bytes. It is advisory, as `pwd` was: a compromised host can
// spoof it, so it never widens the token boundary; it narrows it so one
// project's grant does not serve an unrelated tree on the same host, while
// every worktree of one repository shares the grant.
//
// The tag names the derivation, so a bumped derivation can never share a
// storage key with the old one; v4 (`dek:{ctx}:{salt}`) entries are unreachable
// and lapse or are cleared from the admin tab. Derived HERE for reads and
// writes alike, so no caller can key the two on different rules.
export async function cacheCtx(tokenId: string, project: string): Promise<string> {
  // Fail closed: a key with an empty token half would be one every host could
  // reach. opCreate/opDekCache already refuse such bodies; this is the seam's
  // own guard, so a throw here is a DO bug surfacing as a 500, never a hit.
  if (!isTokenId(tokenId)) throw new Error('cache ctx without token_id');
  const enc = new TextEncoder();
  const tag = enc.encode('vt-dek-ctx-v5');
  const projectBytes = enc.encode(project);
  const buf = new Uint8Array(tag.length + projectBytes.length);
  buf.set(tag, 0);
  buf.set(projectBytes, tag.length);
  const projectH = b64uEnc((await sha256(buf)).slice(0, 16));
  return `${tokenId}:${projectH}`;
}

function cacheKey(ctx: string, saltB64u: string): string {
  return `dek:${ctx}:${saltB64u}`;
}

type CacheWriteResult =
  | { ok: false; reason: string }
  | { ok: true; expires_ms: number };

interface CacheExtendResult {
  skipped: Record<string, number>;
  extended: number;
  latest: number;
  /** Latest new expiry per origin approval, for its audit row. */
  effects: Map<string, number>;
}

export class AccountCache {
  /** `seckey` is the X25519 scalar derived from the root key
   *  (AccountAdmin.cacheSeckey). */
  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly seckey: () => Uint8Array,
  ) {}

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
  // listLive — which stops at CACHE_LIST_SCAN_MAX and makes its caller surface
  // `truncated` — a clear that stopped early would leave DEKs decryptable
  // while answering 200 with a count, i.e. a success the operator cannot tell
  // from a real one. There is deliberately NO cap here; the only
  // bound left is the request's own CPU/wall budget, and exhausting that fails
  // LOUDLY instead of under-delivering silently.
  //
  // Memory stays O(one page + one delete batch): a matched key is deleted as it
  // is found and never accumulated, so this is safe on a cache far larger than
  // an unbounded list() could hold (list() with no options loads the whole
  // prefix into the isolate's memory).
  //
  // `pick` sees the raw stored value: the shape check belongs to the predicate,
  // so a clear-all selects every key under the prefix whatever its value.
  private async sweepCacheEntries(
    pick: (value: unknown) => boolean,
  ): Promise<{ deleted: number; scanned: number }> {
    let deleted = 0;
    let scanned = 0;
    let batch: string[] = [];
    for await (const page of listPrefixPages<unknown>(this.storage, 'dek:')) {
      for (const [key, value] of page) {
        scanned++;
        if (!pick(value)) continue;
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
    return this.sweepCacheEntries(v => !isLive(v, now));
  }

  clearAll(): Promise<{ deleted: number; scanned: number }> {
    return this.sweepCacheEntries(() => true);
  }

  // The console names entries by (token_id, project, salt); the key is derived
  // here, so a clear can only ever address what a read would. Exact keys, no
  // scan: the count is what storage removed.
  async clearEntries(refs: CacheEntryRef[]): Promise<number> {
    const keys: string[] = [];
    for (const r of refs) keys.push(cacheKey(await cacheCtx(r.token_id, r.project), r.salt_b64u));
    return deleteKeysBatched(this.storage, keys);
  }

  // Write one cache entry per salt, keyed by ctx(token_id, project)+salt. Caller
  // has already verified the WebAuthn assertion, so this is authorized. INVARIANT
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
    const sk = this.seckey();
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
      const probe = openToCache(s, sk);
      if (!probe || probe.length !== 32) {
        probe?.fill(0);
        return reject('cache_sealed_dek does not open to the cache key');
      }
      probe.fill(0);
    }

    // Ceremonies no host token opened (enroll, extension) carry no salts and
    // were rejected above; a salted ceremony without one is a Worker bug.
    if (!isTokenId(ch.token_id)) return reject('missing token_id');
    const ip = ch.meta.ip ?? '';
    const ctx = await cacheCtx(ch.token_id, ch.meta.project ?? '');
    const createdMs = Date.now();
    const expires = createdMs + ttlS * 1000;
    // created_ms is forensic only (extension measures from the approval) and is
    // never rewritten afterwards. host/user are the token record's (opCreate).
    const writes: Record<string, CacheEntry> = {};
    for (let i = 0; i < salts.length; i++) {
      writes[cacheKey(ctx, salts[i]!)] = {
        sealed_to_cache_b64u: sealedList[i]!,
        expires_ms: expires,
        origin_token_id: originTokenId,
        ip,
        ppid_cmd: ch.meta.ppid_cmd ?? '',
        project: ch.meta.project ?? '',
        name: ch.meta.names?.[i] ?? '',
        host: ch.meta.host,
        user: ch.meta.user,
        ttl_s: ttlS,
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
    return { ok: true, expires_ms: expires };
  }

  async read(tokenId: string, meta: ChallengeMeta, salts: string[], daemonPk: Uint8Array): Promise<string | null> {
    if (salts.length === 0 || salts.length > 256) return null;
    const sk = this.seckey();
    for (const s of salts) { if (!isB64uString(s)) return null; }

    const ctx = await cacheCtx(tokenId, meta.project ?? '');
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
        if (!isLive(entry, now)) continue;
        const dek = openToCache(entry.sealed_to_cache_b64u, sk);
        if (!dek || dek.length !== 32) {
          dek?.fill(0);
          // Undecryptable (sealed under a previous root key, M3): uniformly
          // miss and lazily drop the orphaned entry, never surface a 500.
          orphaned.push(key);
          continue;
        }
        dekParts.push(dek);
      }
      if (orphaned.length) { try { await deleteKeysBatched(this.storage, orphaned); } catch {} }

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

  // Every live `dek:` entry with its storage key. Paged internally (list() caps
  // what one call should hold in memory) and hard-capped by CACHE_LIST_SCAN_MAX,
  // which the caller must surface as `truncated` rather than pass off as a full
  // view. Expired entries are already a miss on the read path and the alarm's
  // to sweep, so they are not the console's to see. Keys stay inside the DO.
  //
  // That cap makes this the wrong tool for a REVOKE: an entry past it is simply
  // never seen. Clearing uses exact keys (clearEntries) or sweepCacheEntries.
  async listLive(now: number): Promise<{ live: Array<[string, CacheEntry]>; scanned: number; truncated: boolean }> {
    const live: Array<[string, CacheEntry]> = [];
    let scanned = 0;
    let truncated = false;
    for await (const page of listPrefixPages<unknown>(this.storage, 'dek:')) {
      for (const [key, e] of page) {
        scanned++;
        if (!isLive(e, now)) continue;
        live.push([key, e]);
      }
      if (scanned >= CACHE_LIST_SCAN_MAX) { truncated = true; break; }
    }
    return { live, scanned, truncated };
  }

  // The named entries of one scope as stored right now, by salt (absent = gone).
  async getEntries(tokenId: string, project: string, salts: string[]): Promise<Map<string, CacheEntry>> {
    const ctx = await cacheCtx(tokenId, project);
    const map = await this.getKeysBatched(salts.map(s => cacheKey(ctx, s)));
    const out = new Map<string, CacheEntry>();
    for (const [k, v] of map) out.set(k.slice(k.lastIndexOf(':') + 1), v);
    return out;
  }

  // Commit an APPROVED extension. AccountDO calls this only after the WebAuthn
  // assertion verified, the challenge was consumed, and the TTL was rechecked.
  // Results describe acknowledged effects for the DO's audit.
  //
  // Per storage batch: re-read the entries and apply planExtend to the FRESH
  // copy with no await between the read and the write. The DO input gate
  // reopens at every await, so a plan computed from the request-time read could
  // otherwise be written over an entry that opDekCache's orphan sweep just
  // deleted, or that the alarm just expired — i.e. resurrect it. Re-reading in
  // the same atomic step makes that impossible: only keys still present and
  // still live at write time are touched.
  async commitExtend(intent: CacheExtendIntent): Promise<CacheExtendResult> {
    const ctx = await cacheCtx(intent.token_id, intent.project);
    const keys = intent.salts_b64u.map(s => cacheKey(ctx, s));
    const skipped: Record<string, number> = {};
    const effects = new Map<string, number>();
    let extended = 0;
    let latest = 0;
    // A storage failure stops the commit but is caught here, so batches that
    // already mutated reach the trailing audit row (the mutation is durable,
    // so its trail must be too).
    try {
      for (let i = 0; i < keys.length; i += STORAGE_BATCH) {
        const chunk = keys.slice(i, i + STORAGE_BATCH);
        const fresh = await this.storage.get<CacheEntry>(chunk);
        // ── atomic section: no await until the put ──
        const now = Date.now();
        const writes: Record<string, CacheEntry> = {};
        const origins = new Map<string, number>();
        for (const key of chunk) {
          const entry = fresh.get(key);
          if (!entry) { skipped.gone = (skipped.gone ?? 0) + 1; continue; }
          const plan = planExtend(entry, intent.ttl_s, now);
          if (!plan.ok) { skipped[plan.skip] = (skipped[plan.skip] ?? 0) + 1; continue; }
          writes[key] = { ...entry, expires_ms: plan.expires_ms };
          if (entry.origin_token_id) origins.set(entry.origin_token_id, plan.expires_ms);
        }
        const count = Object.keys(writes).length;
        if (count === 0) continue;
        // Account for effects only after storage acknowledges this batch.
        await this.storage.put(writes);
        // ── end atomic section ──
        extended += count;
        for (const [origin, exp] of origins) {
          if (exp > (effects.get(origin) ?? 0)) effects.set(origin, exp);
          if (exp > latest) latest = exp;
        }
      }
    } catch (e) {
      logErr('cache.extend_failed', e);
      skipped.error = 1;
    }
    return { skipped, extended, latest, effects };
  }
}
