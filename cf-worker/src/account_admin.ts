// What the console owns in storage: one AES-256-GCM blob under `cfg:v1`,
// keyed by K_cfg = HKDF(VT_AUTH_CF, "vt-config-key-v1") (docs/worker-slim.md
// §2, §4). It holds the VAPID key pair and the push subscriptions; every write
// re-encrypts the whole blob under a fresh nonce, and the DO is the only writer.
// Writes are serialized here because the crypto awaits open the DO input gate.

import type { Env, PushPayload, PushSubscription } from './types';
import { b64uEnc, b64uDec, decodeB64uExact, hkdfSha256, randomBytes } from './crypto';
import { generateVapid, sendPush, type VapidKeys } from './webpush';
import { ADMIN_AUDIT_PATH } from './page';
import { logErr } from './log';

const CFG_KEY = 'cfg:v1';
const CFG_AAD = new TextEncoder().encode('vt-config-v1');
// An expired browser subscription is replaced by a new endpoint, so the oldest
// rows are the dead ones; the cap bounds fan-out, not devices.
const PUSH_MAX = 10;

interface Config {
  v: 1;
  vapid: VapidKeys | null;
  push: PushSubscription[];
}

interface SealedConfig {
  n: string;
  c: string;
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

export class AccountAdmin {
  private cfg?: Config;
  private loading?: Promise<Config>;
  private key?: Promise<CryptoKey>;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly storage: Pick<DurableObjectStorage, 'get' | 'put'>,
    private readonly env: Env,
  ) {}

  private kcfg(): Promise<CryptoKey> {
    return this.key ??= (async () => {
      const enc = new TextEncoder();
      const raw = await hkdfSha256(
        enc.encode(this.env.VT_AUTH_CF), new Uint8Array(), enc.encode('vt-config-key-v1'), 32);
      return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    })();
  }

  private config(): Promise<Config> {
    if (this.cfg) return Promise.resolve(this.cfg);
    return this.loading ??= (async () => {
      const sealed = await this.storage.get<SealedConfig>(CFG_KEY);
      let cfg: Config = { v: 1, vapid: null, push: [] };
      if (sealed) {
        try {
          const pt = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64uDec(sealed.n), additionalData: CFG_AAD },
            await this.kcfg(), b64uDec(sealed.c));
          cfg = JSON.parse(new TextDecoder().decode(pt)) as Config;
        } catch (e) {
          // K_cfg changed (VT_AUTH_CF rotated) or the blob is corrupt. Until the
          // blob carries policy (worker-slim.md step 5) this is "no push"; the
          // next console write replaces it.
          logErr('config.unreadable', e);
        }
      }
      this.cfg = cfg;
      return cfg;
    })();
  }

  private write(mutate: (cfg: Config) => void): Promise<Config> {
    const run = this.queue.then(async () => {
      const next = structuredClone(await this.config());
      mutate(next);
      const n = randomBytes(12);
      const c = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: n, additionalData: CFG_AAD },
        await this.kcfg(), new TextEncoder().encode(JSON.stringify(next)));
      this.cfg = next;
      await this.storage.put(CFG_KEY, { n: b64uEnc(n), c: b64uEnc(new Uint8Array(c)) } satisfies SealedConfig);
      return next;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  /** What fan-out reads on every event; a null `vapid` means nothing was ever
   *  subscribed. */
  async pushConfig(): Promise<{ vapid: VapidKeys | null; push: PushSubscription[] }> {
    const { vapid, push } = await this.config();
    return { vapid, push };
  }

  /** Delete one subscription (a 404/410 from its push service, or the console). */
  async unsubscribe(endpoint: string): Promise<boolean> {
    const before = (await this.config()).push.length;
    const next = await this.write(cfg => { cfg.push = cfg.push.filter(s => s.endpoint !== endpoint); });
    return next.push.length < before;
  }

  // Generated once; rotating it would kill every subscription, so nothing but
  // a VT_AUTH_CF reset does.
  private async vapid(): Promise<VapidKeys> {
    const cur = (await this.config()).vapid;
    if (cur) return cur;
    const fresh = await generateVapid();
    return (await this.write(cfg => { cfg.vapid ??= fresh; })).vapid!;
  }

  // `op` is the DO path's `push-` suffix: vapid | subscribe | unsubscribe | test.
  async pushOp(op: string, request: Request): Promise<Response> {
    let body: unknown;
    try { body = op === 'vapid' ? null : await request.json(); }
    catch { return new Response('invalid json', { status: 400 }); }
    const endpoint = (body as { endpoint?: unknown } | null)?.endpoint;
    switch (op) {
      case 'vapid': {
        const { pub_b64u } = await this.vapid();
        const push = (await this.config()).push.map(({ endpoint, label, created_ms }) => ({ endpoint, label, created_ms }));
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
        const cfg = await this.config();
        const sub = cfg.push.find(s => s.endpoint === endpoint);
        if (!sub || !cfg.vapid) return new Response('unknown subscription', { status: 404 });
        const payload: PushPayload = {
          v: 1, kind: 'test', title: 'VT 推送测试', body: `${sub.label || '此设备'} 已订阅审批通知`,
          url: `${this.env.WORKER_ORIGIN}${ADMIN_AUDIT_PATH}`, tag: 'test',
        };
        return Response.json(await sendPush(sub, JSON.stringify(payload), cfg.vapid, this.env.WORKER_ORIGIN, 60, 'normal'));
      }
      default:
        return new Response('unknown op', { status: 400 });
    }
  }
}
