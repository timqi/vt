// What the console owns in storage (docs/worker-slim.md): the root key
// and the config blob, plus the admin session and login ceremonies that guard
// them. Two keys, one writer:
//
//   root:v1  {wraps: [{n, c}]}   AES-256-GCM(K_kek, R), K_kek = HKDF(SECRET, "vt-kek-v1")
//   cfg:v1   {n, c}              AES-256-GCM(K_cfg, config JSON), K_cfg = HKDF(R, "vt-config-key-v1")
//
// R never leaves this object's memory. Every write re-encrypts the whole blob
// under a fresh nonce; writes are serialized here because the crypto awaits
// open the DO input gate.

import type { PushPayload, PushSubscription } from './types';
import { b64uEnc, b64uDec, ctEq, decodeB64uExact, hkdfSha256, hmacSha256, isB64uString, randomBytes } from './crypto';
import { generateVapid, sendPush, type VapidKeys } from './webpush';
import { type CredentialEntry, parseCredentialEntry, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';
import { mintSession, verifySession, sessionSetCookie, sessionCookieValue } from './admin_auth';
import { deriveHostTokenSecret } from './host_token';
import { parseUvPolicy, type UvPolicy } from './uv_policy';
import { ADMIN_AUDIT_PATH } from './page';
import { log, logErr } from './log';

const ROOT_KEY = 'root:v1';
const CFG_KEY = 'cfg:v1';
const ROOT_AAD = new TextEncoder().encode('vt-root-v1');
const CFG_AAD = new TextEncoder().encode('vt-config-v1');
// An expired browser subscription is replaced by a new endpoint, so the oldest
// rows are the dead ones; the cap bounds fan-out, not devices.
const PUSH_MAX = 10;
const LOGIN_TTL_MS = 120_000;
const LOGIN_PENDING_MAX = 5;
const LOGIN_FAIL_LOG_THROTTLE_MS = 5000;

export interface Config {
  v: 1;
  /** Request origin of the bootstrap call: WebAuthn origin, RP id source and
   *  approve-URL base from then on. Immutable until reset. */
  origin: string;
  epoch: number;
  credentials: CredentialEntry[];
  /** When and from where the first credential was registered — what a 409 on
   *  a second bootstrap shows. */
  bootstrap: { ms: number; ip: string };
  cache_hit_notify: boolean;
  uv_policy: unknown;
  vapid: VapidKeys | null;
  push: PushSubscription[];
}

interface Sealed { n: string; c: string }
interface RootRecord { wraps: Sealed[] }
interface LoginChallenge { c: string; t: number }

interface Loaded {
  root: Uint8Array;
  kcfg: CryptoKey;
  ksess: Uint8Array;
  /** X25519 scalar the DEK cache seals to. */
  kcache: Uint8Array;
  cfg: Config;
}

export type AdminStorage = Pick<DurableObjectStorage, 'get' | 'put' | 'delete' | 'list'>;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  Response.json(body, { status, headers });

export function notConfigured(): Response {
  return json({ error: 'not_configured' }, 503);
}

function sessionInvalid(): Response {
  return json({ error: 'session_invalid' }, 401, { 'Set-Cookie': sessionSetCookie(null) });
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function sealWith(key: CryptoKey, aad: Uint8Array, plaintext: Uint8Array): Promise<Sealed> {
  const n = randomBytes(12);
  const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: n, additionalData: aad }, key, plaintext);
  return { n: b64uEnc(n), c: b64uEnc(new Uint8Array(c)) };
}

async function openWith(key: CryptoKey, aad: Uint8Array, sealed: Sealed): Promise<Uint8Array | null> {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64uDec(sealed.n), additionalData: aad }, key, b64uDec(sealed.c)));
  } catch {
    return null;
  }
}

function parseSubscription(body: unknown, now: number): PushSubscription | Response {
  const b = (body ?? {}) as Record<string, unknown>;
  const endpoint = typeof b.endpoint === 'string' ? b.endpoint : '';
  let url: URL | undefined;
  try { url = new URL(endpoint); } catch { /* refused below */ }
  if (!url || url.protocol !== 'https:' || endpoint.length > 1024) {
    return new Response('bad endpoint', { status: 400 });
  }
  try {
    decodeB64uExact(b.p256dh, 65, 'p256dh');
    decodeB64uExact(b.auth, 16, 'auth');
  } catch (e) {
    return new Response((e as Error).message, { status: 400 });
  }
  return {
    endpoint,
    p256dh: b.p256dh as string,
    auth: b.auth as string,
    label: typeof b.label === 'string' ? b.label.slice(0, 64) : '',
    created_ms: now,
  };
}

/** A well-formed https origin from an `Origin` header, else null. */
function parseOrigin(v: string | null): string | null {
  if (!v) return null;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' && u.origin === v ? v : null;
  } catch {
    return null;
  }
}

export class AccountAdmin {
  // undefined = not loaded yet; null = unconfigured (absent or unreadable).
  private loaded?: Loaded | null;
  private loading?: Promise<Loaded | null>;
  private kkek?: Promise<CryptoKey>;
  private queue: Promise<unknown> = Promise.resolve();
  private lastLoginFailLog = 0;

  constructor(
    private readonly storage: AdminStorage,
    private readonly secret: string,
  ) {}

  // ── Keys ─────────────────────────────────────────────────────────────

  private kek(): Promise<CryptoKey> {
    return this.kkek ??= (async () => aesKey(await hkdfSha256(
      new TextEncoder().encode(this.secret), new Uint8Array(), new TextEncoder().encode('vt-kek-v1'), 32)))();
  }

  private async derive(root: Uint8Array, info: string): Promise<Uint8Array> {
    return hkdfSha256(root, new Uint8Array(), new TextEncoder().encode(info), 32);
  }

  private async keysFor(root: Uint8Array, cfg: Config): Promise<Loaded> {
    return {
      root,
      kcfg: await aesKey(await this.derive(root, 'vt-config-key-v1')),
      ksess: await this.derive(root, 'vt-admin-session-v1'),
      kcache: await this.derive(root, 'vt-cache-seckey-v1'),
      cfg,
    };
  }

  // ── Derivations the ceremony path reads (valid once loaded) ───────────

  hostTokenSecret(tokenId: string): Promise<Uint8Array> {
    if (!this.loaded) throw new Error('config not loaded');
    return deriveHostTokenSecret(this.loaded.root, tokenId);
  }

  /** True when `mac_b64u` is HMAC(host token secret, signed) — the daemon body
   *  check the edge cannot do without `R`. Constant-time; malformed → false. */
  async verifyHostMac(tokenId: string, macB64u: unknown, signedB64u: unknown): Promise<boolean> {
    if (!isB64uString(macB64u) || typeof signedB64u !== 'string') return false;
    let mac: Uint8Array;
    let signed: Uint8Array;
    try { mac = b64uDec(macB64u); signed = b64uDec(signedB64u); } catch { return false; }
    return ctEq(mac, await hmacSha256(await this.hostTokenSecret(tokenId), signed));
  }

  /** The cache scalar (docs/dek-cache.md); rooted on `R`, so nothing but a
   *  factory reset changes it. */
  cacheSeckey(): Uint8Array {
    if (!this.loaded) throw new Error('config not loaded');
    return this.loaded.kcache;
  }

  /** The stored policy was validated on PUT, so an error here is a bug and
   *  parseUvPolicy's strict fallback is the right answer to it. */
  uvPolicy(): UvPolicy {
    const { policy, error } = parseUvPolicy(this.current.uv_policy);
    if (error) logErr('uv_policy.invalid', new Error(error));
    return policy;
  }

  // ── Load ─────────────────────────────────────────────────────────────

  /** The decrypted state, or null when unconfigured. Loaded once per instance;
   *  an unreadable root or blob is logged once and is the same state as absent
   *  (docs/worker-slim.md#bootstrap) — there is no defaults fallback. */
  load(): Promise<Loaded | null> {
    if (this.loaded !== undefined) return Promise.resolve(this.loaded);
    return this.loading ??= (async () => {
      const result = await this.loadFromStorage();
      this.loaded ??= result;
      return this.loaded;
    })();
  }

  private async loadFromStorage(): Promise<Loaded | null> {
    const rootRec = await this.storage.get<RootRecord>(ROOT_KEY);
    if (!rootRec) return null;
    const kek = await this.kek();
    let root: Uint8Array | null = null;
    let at = -1;
    for (let i = 0; i < (rootRec.wraps ?? []).length && root === null; i++) {
      root = await openWith(kek, ROOT_AAD, rootRec.wraps[i]!);
      at = i;
    }
    if (root === null) {
      logErr('config.unreadable', new Error('root:v1 does not unwrap under SECRET'));
      return null;
    }
    // First success under the NEW SECRET (the appended wrap) ends the rotation
    // window; under the old one both wraps stay until it is deployed.
    if (at > 0) await this.storage.put(ROOT_KEY, { wraps: [rootRec.wraps[at]!] } satisfies RootRecord);
    const kcfg = await aesKey(await this.derive(root, 'vt-config-key-v1'));
    const sealed = await this.storage.get<Sealed>(CFG_KEY);
    const pt = sealed ? await openWith(kcfg, CFG_AAD, sealed) : null;
    if (!pt) {
      logErr('config.unreadable', new Error(sealed ? 'cfg:v1 does not decrypt' : 'cfg:v1 missing'));
      return null;
    }
    return this.keysFor(root, JSON.parse(new TextDecoder().decode(pt)) as Config);
  }

  /** The current config; only valid after `load()` resolved non-null, which
   *  the DO's dispatch guarantees for every configured-only op. */
  get current(): Config {
    if (!this.loaded) throw new Error('config not loaded');
    return this.loaded.cfg;
  }

  private write(mutate: (cfg: Config) => void): Promise<Config> {
    const run = this.queue.then(async () => {
      const cur = await this.load();
      if (!cur) throw new Error('config not loaded');
      const next = structuredClone(cur.cfg);
      mutate(next);
      const sealed = await sealWith(cur.kcfg, CFG_AAD, new TextEncoder().encode(JSON.stringify(next)));
      // The in-memory copy and the put share this synchronous step.
      cur.cfg = next;
      await this.storage.put(CFG_KEY, sealed);
      return next;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  // ── Sessions ─────────────────────────────────────────────────────────

  private async cookieFor(cur: Loaded): Promise<string> {
    return sessionSetCookie((await mintSession(cur.ksess, cur.cfg.epoch, Date.now())).value);
  }

  /** `exp_s` of the caller's session, or the refusal. Every non-GET request
   *  and every WebSocket upgrade must also come from the configured origin. */
  async session(request: Request): Promise<number | Response> {
    const cur = await this.load();
    if (!cur) return notConfigured();
    const value = sessionCookieValue(request.headers.get('Cookie'));
    const expS = value === null ? null : await verifySession(cur.ksess, value, cur.cfg.epoch, Date.now());
    if (expS === null) return sessionInvalid();
    const mutating = request.method !== 'GET' || request.headers.get('Upgrade') === 'websocket';
    if (mutating && request.headers.get('Origin') !== cur.cfg.origin) return json({ error: 'bad_origin' }, 403);
    return expS;
  }

  // ── Open ops (no session) ────────────────────────────────────────────

  /** What the shell renders. `reset` flags a root that exists but does not
   *  unwrap under the current SECRET: bootstrapping again replaces it. */
  async state(request: Request): Promise<Response> {
    const cur = await this.load();
    if (!cur) {
      const reset = (await this.storage.get(ROOT_KEY)) !== undefined;
      return json({ state: 'setup', rp_id: null, reset });
    }
    const rpId = new URL(cur.cfg.origin).hostname;
    const s = await this.session(request);
    return json({ state: typeof s === 'number' ? 'console' : 'login', rp_id: rpId });
  }

  async bootstrap(request: Request): Promise<Response> {
    let entry: CredentialEntry;
    try { entry = parseCredentialEntry(((await request.json()) as { entry?: unknown }).entry); }
    catch (e) { return new Response(`bad request: ${(e as Error).message}`, { status: 400 }); }
    const origin = parseOrigin(request.headers.get('Origin'));
    if (!origin) return new Response('origin required', { status: 400 });
    const ip = request.headers.get('CF-Connecting-IP') ?? '';
    const run = this.queue.then(async (): Promise<Response> => {
      // Serialized with every other write: a concurrent stranger runs after
      // this task and sees the state it set.
      const existing = await this.load();
      if (existing) return json({ error: 'already_configured', ...existing.cfg.bootstrap }, 409);
      const root = randomBytes(32);
      const cfg: Config = {
        v: 1, origin, epoch: 1, credentials: [entry], bootstrap: { ms: Date.now(), ip },
        cache_hit_notify: false, uv_policy: null, vapid: null, push: [],
      };
      const cur = await this.keysFor(root, cfg);
      const rootRec: RootRecord = { wraps: [await sealWith(await this.kek(), ROOT_AAD, root)] };
      const sealed = await sealWith(cur.kcfg, CFG_AAD, new TextEncoder().encode(JSON.stringify(cfg)));
      this.loaded = cur;
      await this.storage.put({ [ROOT_KEY]: rootRec, [CFG_KEY]: sealed });
      log('admin.bootstrap', { ip, label: entry.l });
      return new Response(null, { status: 204, headers: { 'Set-Cookie': await this.cookieFor(cur) } });
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async loginChallenge(): Promise<Response> {
    const cur = await this.load();
    if (!cur) return notConfigured();
    const now = Date.now();
    const pending = await this.storage.list<LoginChallenge>({ prefix: 'login:' });
    const stale = [...pending].filter(([, v]) => now - v.t >= LOGIN_TTL_MS).map(([k]) => k);
    if (stale.length) await this.storage.delete(stale);
    if (pending.size - stale.length >= LOGIN_PENDING_MAX) return new Response('too many pending logins', { status: 429 });
    const id = b64uEnc(randomBytes(12));
    const challenge = b64uEnc(randomBytes(32));
    await this.storage.put(`login:${id}`, { c: challenge, t: now } satisfies LoginChallenge);
    return json({ challenge_id: id, challenge_b64u: challenge, rp_id: new URL(cur.cfg.origin).hostname });
  }

  async login(request: Request): Promise<Response> {
    const cur = await this.load();
    if (!cur) return notConfigured();
    const ip = request.headers.get('CF-Connecting-IP') ?? '';
    const fail = (reason: string): Response => {
      const now = Date.now();
      if (now - this.lastLoginFailLog >= LOGIN_FAIL_LOG_THROTTLE_MS) {
        this.lastLoginFailLog = now;
        log('admin.login_failed', { reason, ip });
      }
      return json({ error: 'login_failed' }, 401);
    };
    let body: Record<string, unknown>;
    try { body = (await request.json()) as Record<string, unknown>; }
    catch { return new Response('invalid json', { status: 400 }); }
    for (const f of ['challenge_id', 'credential_id_b64u', 'client_data_json_b64u', 'authenticator_data_b64u', 'signature_b64u']) {
      if (!isB64uString(body[f]) || (body[f] as string).length > 8192) return new Response(`bad ${f}`, { status: 400 });
    }
    // Read and delete in one step: a challenge answers exactly one login.
    const key = `login:${body.challenge_id as string}`;
    const stored = await this.storage.get<LoginChallenge>(key);
    if (stored) await this.storage.delete(key);
    if (!stored || Date.now() - stored.t >= LOGIN_TTL_MS) return fail('challenge');
    const entry = await lookupByCredentialId(cur.cfg.credentials, b64uDec(body.credential_id_b64u as string));
    if (!entry) return fail('unknown_credential');
    try {
      await verifyAssertion({
        cosePublicKey: b64uDec(entry.p),
        clientDataJson: b64uDec(body.client_data_json_b64u as string),
        authenticatorData: b64uDec(body.authenticator_data_b64u as string),
        signature: b64uDec(body.signature_b64u as string),
        expectedChallenge: b64uDec(stored.c),
        rpId: new URL(cur.cfg.origin).hostname,
        expectedOrigin: cur.cfg.origin,
        userVerification: 'required',
      });
    } catch {
      return fail('assertion');
    }
    log('admin.login', { label: entry.l, ip });
    return new Response(null, { status: 204, headers: { 'Set-Cookie': await this.cookieFor(cur) } });
  }

  // ── Rotation: R stays, a second wrap is appended ────────────────────

  /** Mint a new SECRET, wrap R under it beside the current wrap, and return
   *  the value once for `wrangler secret put SECRET`. The first successful
   *  load under the new SECRET drops the old wrap (loadFromStorage); a second
   *  rotation before that replaces the pending wrap, so there are never more
   *  than two. */
  private rotateSecret(): Promise<Response> {
    const run = this.queue.then(async (): Promise<Response> => {
      const cur = await this.load();
      if (!cur) return notConfigured();
      const secret = b64uEnc(randomBytes(32));
      const kek = await aesKey(await hkdfSha256(
        new TextEncoder().encode(secret), new Uint8Array(), new TextEncoder().encode('vt-kek-v1'), 32));
      const fresh = await sealWith(kek, ROOT_AAD, cur.root);
      const rec = await this.storage.get<RootRecord>(ROOT_KEY);
      if (!rec?.wraps[0]) return new Response('root missing', { status: 500 });
      // wraps[0] is the wrap the current SECRET opened (load collapses to it).
      await this.storage.put(ROOT_KEY, { wraps: [rec.wraps[0], fresh] } satisfies RootRecord);
      log('admin.secret_rotated', {});
      return json({ secret });
    });
    this.queue = run.catch(() => {});
    return run;
  }

  // ── Session ops (the DO verified the cookie) ─────────────────────────

  private async bumpEpoch(mutate?: (cfg: Config) => void): Promise<Response> {
    await this.write(cfg => { cfg.epoch += 1; mutate?.(cfg); });
    return new Response(null, { status: 204, headers: { 'Set-Cookie': sessionSetCookie(null) } });
  }

  // `op` is the DO path's `admin-` suffix.
  async adminOp(op: string, request: Request): Promise<Response> {
    await this.load();
    const cfg = this.current;
    switch (op) {
      case 'logout':
        return new Response(null, { status: 204, headers: { 'Set-Cookie': sessionSetCookie(null) } });
      case 'sessions-revoke':
        log('admin.sessions_revoked', {});
        return this.bumpEpoch();
      case 'credentials':
        return json({ credentials: cfg.credentials, epoch: cfg.epoch });
      case 'config': {
        const { origin, epoch, cache_hit_notify, uv_policy } = cfg;
        if (request.method !== 'PUT') return json({ origin, epoch, cache_hit_notify, uv_policy });
        let body: Record<string, unknown>;
        try { body = (await request.json()) as Record<string, unknown>; }
        catch { return new Response('invalid json', { status: 400 }); }
        if (!body || typeof body !== 'object' || Array.isArray(body)) return new Response('not an object', { status: 400 });
        for (const k of Object.keys(body)) {
          if (!['cache_hit_notify', 'uv_policy'].includes(k)) return new Response(`unknown key ${k}`, { status: 400 });
        }
        if ('cache_hit_notify' in body && typeof body.cache_hit_notify !== 'boolean') return new Response('cache_hit_notify must be a boolean', { status: 400 });
        if ('uv_policy' in body && body.uv_policy !== null) {
          const { error } = parseUvPolicy(body.uv_policy);
          if (error) return new Response(`uv_policy: ${error}`, { status: 400 });
        }
        const next = await this.write(c => {
          if ('cache_hit_notify' in body) c.cache_hit_notify = body.cache_hit_notify as boolean;
          if ('uv_policy' in body) c.uv_policy = body.uv_policy;
        });
        log('admin.config', { cache_hit_notify: next.cache_hit_notify, uv_policy: next.uv_policy !== null });
        return json({ cache_hit_notify: next.cache_hit_notify, uv_policy: next.uv_policy });
      }
      case 'rotate-secret':
        return this.rotateSecret();
      case 'credentials-add': {
        let entry: CredentialEntry;
        try { entry = parseCredentialEntry(((await request.json()) as { entry?: unknown }).entry); }
        catch (e) { return new Response(`bad request: ${(e as Error).message}`, { status: 400 }); }
        if (cfg.credentials.some(c => c.h === entry.h)) return json({ error: 'duplicate' }, 409);
        await this.write(c => { c.credentials.push(entry); });
        log('admin.credential_added', { label: entry.l });
        return json({ ok: true });
      }
      case 'credentials-revoke': {
        let h: unknown;
        try { h = ((await request.json()) as { h?: unknown }).h; }
        catch { return new Response('invalid json', { status: 400 }); }
        if (!cfg.credentials.some(c => c.h === h)) return new Response('unknown credential', { status: 404 });
        if (cfg.credentials.length <= 1) return json({ error: 'last_credential' }, 409);
        log('admin.credential_revoked', { h });
        return this.bumpEpoch(c => { c.credentials = c.credentials.filter(e => e.h !== h); });
      }
      default:
        return new Response('unknown op', { status: 400 });
    }
  }

  // ── Push (settings tab) ──────────────────────────────────────────────

  /** What fan-out reads on every event; a null `vapid` means nothing was ever
   *  subscribed. Async so a caller's first step is a yield, never push I/O. */
  async pushConfig(): Promise<{ vapid: VapidKeys | null; push: PushSubscription[]; origin: string }> {
    const { vapid, push, origin } = this.current;
    return { vapid, push, origin };
  }

  /** Delete one subscription (a 404/410 from its push service, or the console). */
  async unsubscribe(endpoint: string): Promise<boolean> {
    const before = this.current.push.length;
    const next = await this.write(cfg => { cfg.push = cfg.push.filter(s => s.endpoint !== endpoint); });
    return next.push.length < before;
  }

  // Generated once; rotating it would kill every subscription, so nothing but
  // a factory reset does.
  private async vapid(): Promise<VapidKeys> {
    const cur = this.current.vapid;
    if (cur) return cur;
    const fresh = await generateVapid();
    return (await this.write(cfg => { cfg.vapid ??= fresh; })).vapid!;
  }

  // `op` is the DO path's `push-` suffix: vapid | subscribe | unsubscribe | test.
  async pushOp(op: string, request: Request): Promise<Response> {
    await this.load();
    let body: unknown;
    try { body = op === 'vapid' ? null : await request.json(); }
    catch { return new Response('invalid json', { status: 400 }); }
    const endpoint = (body as { endpoint?: unknown } | null)?.endpoint;
    switch (op) {
      case 'vapid': {
        const { pub_b64u } = await this.vapid();
        const push = this.current.push.map(({ endpoint, label, created_ms }) => ({ endpoint, label, created_ms }));
        return Response.json({ pub_b64u, subscriptions: push });
      }
      case 'subscribe': {
        const sub = parseSubscription(body, Date.now());
        if (sub instanceof Response) return sub;
        await this.write(cfg => {
          cfg.push = [sub, ...cfg.push.filter(s => s.endpoint !== sub.endpoint)].slice(0, PUSH_MAX);
        });
        return Response.json({ ok: true });
      }
      case 'unsubscribe': {
        if (typeof endpoint !== 'string') return new Response('bad endpoint', { status: 400 });
        return Response.json({ removed: await this.unsubscribe(endpoint) });
      }
      case 'test': {
        const cfg = this.current;
        const sub = cfg.push.find(s => s.endpoint === endpoint);
        if (!sub || !cfg.vapid) return new Response('unknown subscription', { status: 404 });
        const payload: PushPayload = {
          v: 1, kind: 'test', title: 'VT push test', body: `${sub.label || 'This device'} is subscribed to approval notices`,
          url: `${cfg.origin}${ADMIN_AUDIT_PATH}`, tag: 'test',
        };
        return Response.json(await sendPush(sub, JSON.stringify(payload), cfg.vapid, cfg.origin, 60, 'normal'));
      }
      default:
        return new Response('unknown op', { status: 400 });
    }
  }
}
