// Web Push is the only channel. These tests pin what the ceremony path must
// never do (await a push, report one to the CLI) and what fan-out does with
// the push service's answers, inside the real DO (docs/worker-slim.md#web-push).

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
      { storage: state.storage, waitUntil(task: Promise<unknown>) { tasks.push(task); } }, admin);
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
      expect(p.title).toBe('vt approval: decrypt');
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
      expect(p.body).toContain('cache hit, no Touch ID');
      expect(p.url).toBe('https://vt.test.invalid/admin#audit');
      expect(p.tag).toBe(`cache:${op.meta.host}`);
      expect(send.mock.calls[0]!.slice(4)).toEqual([3600, 'normal']);
    });
  });
});

// The Slack Bot channel (docs/slack.md): fetch is stubbed so the assertions are
// on the request bodies, the challenge writeback and the logged failures.
describe('AccountNotifications slack channel', () => {
  afterEach(() => vi.restoreAllMocks());

  type Call = { method: string; body: Record<string, unknown> };
  function stubSlack(answer: (c: Call) => Record<string, unknown> | Response | Promise<Record<string, unknown>>) {
    const calls: Call[] = [];
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      expect(init.headers).toMatchObject({ Authorization: 'Bearer xoxb-test' });
      const c = { method: url.replace('https://slack.com/api/', ''), body: JSON.parse(init.body as string) as Record<string, unknown> };
      calls.push(c);
      const a = await answer(c);
      return a instanceof Response ? a : Response.json(a);
    });
    return calls;
  }
  const slackOn = async (admin: AccountAdmin) => {
    const r = await admin.adminOp('config', new Request('https://account.do/op/x', { method: 'PUT',
      body: JSON.stringify({ slack: { bot_token: 'xoxb-test', channel: 'C123', mention: ['U1', 'U2'] } }) }));
    expect(r.status).toBe(200);
  };

  it('posts the pending message, stores its handle, and edits it on the decision', async () => {
    await withPush(async ({ notifications, admin, tasks }) => {
      await slackOn(admin);
      const calls = stubSlack(() => ({ ok: true, ts: '1.2', channel: 'C999' }));
      const ch = makeChallenge({ salts_b64u: ['a', 'b'] });
      await inDO(({ state }) => state.storage.put(`ch:${ch.approve_token}`, ch));
      notifications.approval(ch);
      await Promise.all(tasks);
      expect(calls).toHaveLength(1);
      const post = calls[0]!.body as { channel: string; text: string; attachments: Array<{ blocks: Array<Record<string, unknown>> }> };
      expect(post.channel).toBe('C123');
      expect(post.text).toBe('⏳ vt approval: decrypt — pending');
      const blocks = post.attachments[0]!.blocks;
      expect(blocks[0]).toMatchObject({ text: { text: '<@U1> <@U2>' } });
      expect((blocks[1]!.text as { text: string }).text).toContain('2 records');
      expect(blocks[2]).toMatchObject({ elements: [{ url: `https://vt.test.invalid/a/${ch.approve_token}` }] });
      const stored = await inDO(({ state }) => state.storage.get<typeof ch>(`ch:${ch.approve_token}`));
      expect(stored!.slack).toEqual({ channel: 'C999', ts: '1.2' });

      stored!.status = 'approved';
      stored!.finalized_ms = stored!.created_ms + 1500;
      notifications.decided(stored!, 'approved');
      await Promise.all(tasks);
      expect(calls[1]!.method).toBe('chat.update');
      const upd = calls[1]!.body as { channel: string; ts: string; text: string; attachments: Array<{ color: string; blocks: Array<Record<string, unknown>> }> };
      expect([upd.channel, upd.ts, upd.text]).toEqual(['C999', '1.2', '✅ vt approval: decrypt — approved']);
      expect(upd.attachments[0]!.blocks).toHaveLength(1);
      expect((upd.attachments[0]!.blocks[0]!.text as { text: string }).text).toContain('1500 ms');
    });
  });

  it('edits straight to the terminal state when the decision beat the send', async () => {
    await withPush(async ({ notifications, admin, tasks }) => {
      await slackOn(admin);
      const ch = makeChallenge();
      const calls = stubSlack(async () => {
        // The decision lands while the post is in flight.
        await inDO(({ state }) => state.storage.put(`ch:${ch.approve_token}`, { ...ch, status: 'rejected', finalized_ms: ch.created_ms + 10 }));
        return { ok: true, ts: '9.9' };
      });
      await inDO(({ state }) => state.storage.put(`ch:${ch.approve_token}`, ch));
      notifications.approval(ch);
      await Promise.all(tasks);
      expect(calls.map(c => c.method)).toEqual(['chat.postMessage', 'chat.update']);
      expect((calls[1]!.body as { text: string }).text).toBe('❌ vt approval: decrypt — rejected');
    });
  });

  it('escapes client context, logs failures, and never writes a handle without a ts', async () => {
    await withPush(async ({ notifications, admin, tasks }) => {
      await slackOn(admin);
      const err = vi.spyOn(console, 'error').mockImplementation(() => {});
      const calls = stubSlack(() => ({ ok: false, error: 'channel_not_found' }));
      const ch = makeChallenge({ meta: makeMeta({ pwd: '<https://evil|/tmp>' }) });
      await inDO(({ state }) => state.storage.put(`ch:${ch.approve_token}`, ch));
      notifications.approval(ch);
      await Promise.all(tasks);
      const section = (calls[0]!.body as { attachments: Array<{ blocks: Array<{ text: { text: string } }> }> }).attachments[0]!.blocks[1]!.text.text;
      expect(section).toContain('&lt;https://evil|/tmp&gt;');
      expect(section).not.toContain('<https');
      expect((await inDO(({ state }) => state.storage.get<typeof ch>(`ch:${ch.approve_token}`)))!.slack).toBeUndefined();
      expect(err.mock.calls.map(c => JSON.parse(String(c[0])) as { event: string; err: string }))
        .toEqual([{ event: 'slack.send_failed', err: 'slack channel_not_found', stack: expect.any(String) }]);
      notifications.decided(ch, 'expired'); // no handle → nothing to edit
      await Promise.all(tasks);
      expect(calls).toHaveLength(1);
    });
  });

  it('posts cache hits only when hit notify is on, with no mention or button', async () => {
    await withPush(async ({ notifications, admin, hitNotify, tasks }) => {
      await slackOn(admin);
      const calls = stubSlack(() => ({ ok: true }));
      notifications.cacheHit(makeMeta(), 2);
      expect(tasks).toEqual([]);
      await hitNotify(true);
      notifications.cacheHit(makeMeta(), 2, undefined, ['db']);
      await Promise.all(tasks);
      expect(calls).toHaveLength(1);
      const body = calls[0]!.body as { text: string; attachments: Array<{ blocks: Array<{ text: { text: string } }> }> };
      expect(body.text).toBe('vt cache hit (no approval): decrypt');
      expect(body.attachments[0]!.blocks).toHaveLength(1);
      expect(body.attachments[0]!.blocks[0]!.text.text).toContain('records: db');
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
