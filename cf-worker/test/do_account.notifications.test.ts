// Web Push is the only channel. These tests pin what the ceremony path must
// never do (await a push, report one to the CLI) and what fan-out does with
// the push service's answers, inside the real DO (docs/worker-slim.md §5).

import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import app from '../src/index';
import { AccountNotifications } from '../src/account_notifications';
import { AccountAdmin } from '../src/account_admin';
import { b64uEnc, hmacSha256 } from '../src/crypto';
import * as webpush from '../src/webpush';
import type { DoAuditIngestOp } from '../src/types';
import { accountStub, inDO, makeChallenge, makeMeta, liveTokenId, bootstrap, doGet, doPost, hostSecret } from './do_helpers';

beforeEach(bootstrap);

async function browserSub(n: number) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
  return {
    endpoint: `https://push.test.invalid/s/${n}`, label: `dev${n}`,
    p256dh: b64uEnc(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer)),
    auth: b64uEnc(new Uint8Array(16).fill(n)),
  };
}

const post = (body: unknown) => new Request('https://account.do/op/x', { method: 'POST', body: JSON.stringify(body) });

// Two subscriptions in the DO's own config blob, a notifications instance whose
// waitUntil tasks the test can await, and sendPush spied so no network is touched.
async function withPush(
  test: (h: {
    notifications: AccountNotifications;
    admin: AccountAdmin;
    /** Flip `cache_hit_notify` on the instance the notifications read. */
    hitNotify: (on: boolean) => Promise<void>;
    tasks: Promise<unknown>[];
    send: ReturnType<typeof vi.spyOn<typeof webpush, 'sendPush'>>;
  }) => Promise<void>,
): Promise<void> {
  await inDO(async ({ inst, state }) => {
    const admin = new AccountAdmin(state.storage, inst.env.SECRET);
    for (const n of [1, 2]) expect((await admin.pushOp('subscribe', post(await browserSub(n)))).status).toBe(200);
    await admin.pushOp('vapid', new Request('https://account.do/op/x'));
    const hitNotify = async (on: boolean) => {
      const r = await admin.adminOp('config', new Request('https://account.do/op/x', { method: 'PUT', body: JSON.stringify({ cache_hit_notify: on }) }));
      expect(r.status).toBe(200);
    };
    const tasks: Promise<unknown>[] = [];
    const notifications = new AccountNotifications(
      { waitUntil(task: Promise<unknown>) { tasks.push(task); } }, admin);
    const send = vi.spyOn(webpush, 'sendPush').mockResolvedValue({ status: 201 });
    try {
      await test({ notifications, admin, hitNotify, tasks, send });
      await Promise.all(tasks);
    } finally {
      vi.restoreAllMocks();
    }
  });
}

const labels = async (admin: AccountAdmin) =>
  ((await (await admin.pushOp('vapid', new Request('https://account.do/op/x'))).json()) as
    { subscriptions: Array<{ label: string }> }).subscriptions.map(s => s.label);

describe('AccountNotifications push contract', () => {
  afterEach(() => vi.restoreAllMocks());

  it('pushes one approval per subscription with the approve URL in the payload, not the body', async () => {
    await withPush(async ({ notifications, tasks, send }) => {
      const ch = makeChallenge();
      notifications.approval(ch);
      expect(send).not.toHaveBeenCalled(); // nothing inline
      await Promise.all(tasks);
      expect(send).toHaveBeenCalledTimes(2);
      const [, payload, , subject, ttl, urgency] = send.mock.calls[0]!;
      const p = JSON.parse(payload) as { kind: string; url: string; body: string; tag: string; title: string };
      expect([subject, ttl, urgency]).toEqual(['https://vt.test.invalid', 300, 'high']);
      expect(p.kind).toBe('approval');
      expect(p.url).toBe(`https://vt.test.invalid/a/${ch.approve_token}`);
      expect(p.tag).toBe(`a:${ch.approve_token}`);
      expect(p.title).toBe('VT 审批: decrypt');
      expect(p.body).not.toContain('https://');
      expect(p.body).toContain(`${ch.meta.user}@${ch.meta.host}`);
    });
  });

  it('marks enrollment pushes and keeps extension ceremonies console-only', async () => {
    await withPush(async ({ notifications, tasks, send }) => {
      notifications.approval(makeChallenge({ extend: {
        token_id: 'testtoken0000000', project: '', salts_b64u: [], ttl_s: 1200, host: '', records: [], expires_ms: 0,
      } }));
      expect(tasks).toEqual([]);
      notifications.approval(makeChallenge({ enroll: {
        host: 'h', user: 'u', ip: '203.0.113.9', origin: '', pair_code: '123-456',
      } }));
      await Promise.all(tasks);
      expect((JSON.parse(send.mock.calls[0]![1]) as { kind: string }).kind).toBe('enroll');
    });
  });

  it('drops a subscription on 410, keeps it on 5xx and network failure', async () => {
    await withPush(async ({ notifications, admin, tasks, send }) => {
      send.mockImplementation(async (sub) => ({ status: sub.endpoint.endsWith('/1') ? 410 : 503, error: 'x' }));
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      notifications.approval(makeChallenge());
      await Promise.all(tasks);
      expect(await labels(admin)).toEqual(['dev2']);
      expect(err.mock.calls.map(c => (JSON.parse(String(c[0])) as { event: string }).event)).toEqual(['push.failed']);
      send.mockResolvedValue({ status: 0, error: 'timeout' });
      notifications.approval(makeChallenge());
      await Promise.all(tasks);
      expect(await labels(admin)).toEqual(['dev2']);
    });
  });

  it('keeps cache-hit pushes opt-in, and throttles agent hits by operation and host', async () => {
    await withPush(async ({ notifications, hitNotify, tasks, send }) => {
      notifications.cacheHit(makeMeta(), 2);
      expect(tasks).toEqual([]);
      await hitNotify(true);
      const clock = vi.spyOn(Date, 'now').mockReturnValue(120_000);
      const op: DoAuditIngestOp = {
        token_id: 'synthetic-agent-event', ts_ms: Date.now(), outcome: 'cache_hit',
        salts: 0, latency_ms: 1, meta: makeMeta({ op_kind: 'sign' }),
        peer_exe: null, key_fp: null, dest: null, scope_family: null,
        scope_label: null, grant_ttl_s: null, relayed: null,
      };
      notifications.agentCacheHit(op);
      notifications.agentCacheHit(op);
      expect(tasks).toHaveLength(1);
      notifications.agentCacheHit({ ...op, meta: { ...op.meta, host: 'another-host' } });
      notifications.agentCacheHit({ ...op, meta: { ...op.meta, op_kind: 'decrypt' } });
      expect(tasks).toHaveLength(3);
      clock.mockReturnValue(180_000);
      notifications.agentCacheHit(op);
      expect(tasks).toHaveLength(4);
      await Promise.all(tasks);
      expect(send).toHaveBeenCalledTimes(8);
      const p = JSON.parse(send.mock.calls[0]![1]) as { kind: string; body: string; url: string; tag: string };
      expect(p.kind).toBe('cache_hit');
      expect(p.body).toContain('缓存命中，免 Touch ID');
      expect(p.url).toBe('https://vt.test.invalid/admin#audit');
      expect(p.tag).toBe(`cache:${op.meta.host}`);
      expect(send.mock.calls[0]!.slice(4)).toEqual([3600, 'normal']);
    });
  });
});

describe('ceremony routes and push', () => {
  afterEach(() => vi.restoreAllMocks());

  it('/api/challenge returns before any push settles and carries no push_warning', async () => {
    const tokenId = await liveTokenId();
    const body = new TextEncoder().encode(JSON.stringify({
      daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(11)),
      timestamp_ms: Date.now(), salts_b64u: [], meta: makeMeta(),
    }));
    const tag = await hmacSha256(await hostSecret(tokenId), body);
    // Drain the internal create response so workerd's isolated storage stack
    // does not retain an open DO response stream after the public route returns.
    const account = {
      idFromName: () => 'account',
      get: () => ({ fetch: async (url: string, init: RequestInit) => {
        const response = await accountStub().fetch(url, init);
        return new Response(await response.text(), { status: response.status });
      } }),
    };
    const response = await app.fetch(new Request('https://vt.test.invalid/api/challenge', {
      method: 'POST', body, headers: { Authorization: `VT-HMAC ${b64uEnc(tag)}`, 'VT-Token-Id': tokenId },
    }), { ...env, ACCOUNT: account });
    expect(response.status).toBe(200);
    const result = await response.json() as Record<string, unknown>;
    expect(result).not.toHaveProperty('push_warning');
    await inDO(async ({ state }) => {
      expect(await state.storage.get(`ch:${result.approve_token as string}`)).toMatchObject({ status: 'pending' });
    });
  });

  it('push ops reach the console-owned blob through the DO; unknown ops are refused', async () => {
    const first = await doGet('push-vapid');
    expect(first.status).toBe(200);
    const a = first.json as { pub_b64u: string; subscriptions: unknown[] };
    expect(a.subscriptions).toEqual([]);
    const b = (await doGet('push-vapid')).json as { pub_b64u: string };
    expect(b.pub_b64u).toBe(a.pub_b64u);
    const bogus = await doPost('push-bogus', {});
    expect([bogus.status, bogus.text]).toEqual([400, 'unknown op']);
    await inDO(async ({ state }) => {
      expect(JSON.stringify(await state.storage.get('cfg:v1'))).not.toContain(a.pub_b64u);
    });
  });
});
