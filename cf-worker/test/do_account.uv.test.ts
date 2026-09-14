// AccountDO — the UV level a ceremony is served AND verified at.
//
// The policy arithmetic is unit-tested in uv_policy.test.ts; what matters here
// is that the DO reads the level from the STORED challenge on both sides. The
// approval page is told that level, the assertion is checked against that same
// level, and no field in an approve/reject body can move it — so a caller can
// only ever fail its own check, never pass a weaker one.

import { describe, it, expect, beforeEach } from 'vitest';
import type { Challenge } from '../src/types';
import {
  inDO, doPost, doGet, configure, makeChallenge, approve, reject, seedGroup, daemonAuth, accountStub, adminHeaders,
  FLAGS_UP_ONLY, FLAGS_UP_UV, liveTokenId,
  bootstrap,
} from './do_helpers';

const HOUR = 60 * 60_000;
const GROUP = 'g_testgroup00000';

beforeEach(bootstrap);

/** Store a pending challenge the CLI requested at `uv` (raise-only over the
 *  default policy, so the stored level equals it). Omit it for a pre-policy
 *  one: that is written straight into storage, since `create` always decides
 *  a level against the verified host. */
async function pending(uv?: Challenge['uv']): Promise<Challenge> {
  const ch = makeChallenge();
  if (!uv) {
    await inDO(async ({ inst, state }) => {
      await state.storage.put({ [`ch:${ch.approve_token}`]: ch, [`pt:${ch.poll_token}`]: ch.approve_token });
      inst.audit.create(ch);
    });
    return ch;
  }
  const res = await doPost('create', { challenge: ch, uv_request: uv, auth: await daemonAuth(await liveTokenId()) });
  expect(res.status).toBe(200);
  ch.uv = uv;
  return ch;
}

async function storedUv(ch: Challenge): Promise<string | undefined> {
  return (await inDO(h => h.state.storage.get<Challenge>(`ch:${ch.approve_token}`)))!.uv;
}

describe('the policy is read from the config blob', () => {
  it('applies default, by_op and by_host from the stored policy, raise-only over the request', async () => {
    expect(await storedUv(await pending('discouraged'))).toBe('discouraged');
    await configure({ uv_policy: { default: 'preferred', by_op: { decrypt: 'required' }, by_host: {} } });
    const ch = makeChallenge();
    expect((await doPost('create', { challenge: ch, uv_request: 'discouraged', auth: await daemonAuth(await liveTokenId()) })).status).toBe(200);
    expect(await storedUv(ch)).toBe('required');
    await configure({ uv_policy: { default: 'preferred' } });
    const ch2 = makeChallenge();
    expect((await doPost('create', { challenge: ch2, uv_request: 'garbage', auth: await daemonAuth(await liveTokenId()) })).status).toBe(200);
    expect(await storedUv(ch2)).toBe('preferred');
    await configure({ uv_policy: null });
    expect(await storedUv(await pending('discouraged'))).toBe('discouraged');
  });

  it('refuses a malformed policy at PUT rather than storing it', async () => {
    const put = async (body: unknown) => {
      const r = await accountStub().fetch('https://account.do/op/admin-config', {
        method: 'PUT', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: JSON.stringify(body),
      });
      return { status: r.status, text: await r.text() };
    };
    expect((await put({ uv_policy: { default: 'sometimes' } })).status).toBe(400);
    expect((await put({ uv_policy: 'required' })).status).toBe(400);
    expect((await put({ uv_policy: ['required'] })).status).toBe(400);
    expect((await put({ cache_hit_notify: 'yes' })).status).toBe(400);
    expect((await put({ origin: 'https://evil.test.invalid' })).status).toBe(400);
    expect((await put({ epoch: 99 })).status).toBe(400);
    const cfg = await doGet('admin-config');
    expect(cfg.json).toMatchObject({ uv_policy: null, cache_hit_notify: false, epoch: 1, origin: 'https://vt.test.invalid' });
  });
});

async function pageData(token: string) {
  const res = await doGet(`page?approve_token=${token}`);
  expect(res.status).toBe(200);
  return res.json;
}

describe('the page is served the ceremony’s own level', () => {
  it('relays each stored level verbatim', async () => {
    for (const uv of ['discouraged', 'preferred', 'required'] as const) {
      const ch = await pending(uv);
      expect((await pageData(ch.approve_token)).user_verification).toBe(uv);
    }
  });

  it('shows required for a challenge minted before the policy existed', async () => {
    const ch = await pending();
    expect(ch.uv).toBeUndefined();
    expect((await pageData(ch.approve_token)).user_verification).toBe('required');
  });
});

describe('the assertion is checked against that same level', () => {
  it('accepts a presence-only assertion when the level is not required', async () => {
    for (const uv of ['discouraged', 'preferred'] as const) {
      const ch = await pending(uv);
      const res = await approve(ch, {}, FLAGS_UP_ONLY);
      expect(res.status).toBe(200);
      expect(res.json.sealed_deks_b64u).toBeTruthy();
    }
  });

  it('refuses a presence-only assertion when the level is required', async () => {
    const ch = await pending('required');
    const res = await approve(ch, {}, FLAGS_UP_ONLY);
    expect(res.status).toBe(401);
    expect(res.text).toBe('assertion verification failed');
    // Nothing was sealed: the ceremony is still pending, not silently approved.
    const stored = await inDO(h => h.state.storage.get<Challenge>(`ch:${ch.approve_token}`));
    expect(stored!.status).toBe('pending');
    expect(stored!.sealed_deks_b64u).toBeUndefined();
    // The same authenticator with UV set goes through.
    expect((await approve(ch, {}, FLAGS_UP_UV)).status).toBe(200);
  });

  it('refuses a presence-only assertion on a pre-policy challenge', async () => {
    const ch = await pending();
    expect((await approve(ch, {}, FLAGS_UP_ONLY)).status).toBe(401);
  });

  it('still demands user presence at every level', async () => {
    const uvOnly = 0x04;                       // UV set, UP clear
    for (const uv of ['discouraged', 'preferred', 'required'] as const) {
      const ch = await pending(uv);
      const res = await approve(ch, {}, uvOnly);
      expect(res.status).toBe(401);
    }
  });

  it('applies the same level to a rejection', async () => {
    const loose = await pending('discouraged');
    expect((await reject(loose, FLAGS_UP_ONLY)).status).toBe(200);
    expect((await inDO(h => h.state.storage.get<Challenge>(`ch:${loose.approve_token}`)))!.status)
      .toBe('rejected');

    const strict = await pending('required');
    expect((await reject(strict, FLAGS_UP_ONLY)).status).toBe(401);
    expect((await inDO(h => h.state.storage.get<Challenge>(`ch:${strict.approve_token}`)))!.status)
      .toBe('pending');
  });
});

describe('the cache-extension ceremony keeps its biometric step', () => {
  it('mints a required ceremony even under a fully discouraged policy', async () => {
    await configure({
      uv_policy: { default: 'discouraged', by_op: { 'cache-extend': 'discouraged' } },
    });
    await inDO(h => seedGroup(h, 1, { expires_ms: Date.now() + HOUR }));
    const res = await doPost('cache-extend-create', {
      group_ids: [GROUP], ttl_s: 24 * 3600,
    });
    expect(res.status).toBe(200);
    const ch = await inDO(h =>
      h.state.storage.get<Challenge>(`ch:${res.json.approve_token}`));
    expect(ch!.uv).toBe('required');
    expect((await approve(ch!, {}, FLAGS_UP_ONLY)).status).toBe(401);
  });
});
