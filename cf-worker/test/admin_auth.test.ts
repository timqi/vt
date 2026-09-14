// The session cookie's pure half: mint/verify round trip and each way a
// cookie stops being valid. The DO-level behaviour (401 bodies, Origin, epoch
// bumps) is in test/do_account.admin_auth.test.ts.

import { describe, it, expect } from 'vitest';
import { mintSession, verifySession, sessionSetCookie, sessionCookieValue, SESSION_COOKIE, SESSION_TTL_S } from '../src/admin_auth';

const K = new Uint8Array(32).fill(7);
const NOW = 1_800_000_000_000;

describe('admin session cookie', () => {
  it('round-trips and expires at exactly exp_s', async () => {
    const { value, exp_s } = await mintSession(K, 3, NOW);
    expect(exp_s).toBe(Math.floor(NOW / 1000) + SESSION_TTL_S);
    expect(value).toMatch(/^1\.\d+\.3\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);
    expect(await verifySession(K, value, 3, NOW)).toBe(exp_s);
    expect(await verifySession(K, value, 3, exp_s * 1000 - 1)).toBe(exp_s);
    expect(await verifySession(K, value, 3, exp_s * 1000)).toBeNull();
  });

  it('fails on a tampered MAC, another key, another epoch, or a rewritten claim', async () => {
    const { value } = await mintSession(K, 3, NOW);
    const parts = value.split('.');
    const flip = (s: string) => (s.startsWith('A') ? 'B' : 'A') + s.slice(1);
    expect(await verifySession(K, [...parts.slice(0, 4), flip(parts[4]!)].join('.'), 3, NOW)).toBeNull();
    expect(await verifySession(new Uint8Array(32).fill(8), value, 3, NOW)).toBeNull();
    expect(await verifySession(K, value, 4, NOW)).toBeNull();
    // Claims are under the MAC: bumping exp_s or the epoch in the string fails.
    expect(await verifySession(K, [parts[0], String(Number(parts[1]) + 1), ...parts.slice(2)].join('.'), 3, NOW)).toBeNull();
    expect(await verifySession(K, [parts[0], parts[1], '4', ...parts.slice(3)].join('.'), 4, NOW)).toBeNull();
    for (const bad of ['', 'x', '2.1.1.a.b', value + 'A']) expect(await verifySession(K, bad, 3, NOW)).toBeNull();
  });

  it('formats a __Host- cookie and clears it with Max-Age=0', async () => {
    const { value } = await mintSession(K, 1, NOW);
    expect(sessionSetCookie(value)).toBe(`${SESSION_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_S}`);
    expect(sessionSetCookie(null)).toBe(`${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    expect(sessionCookieValue(`a=b; ${SESSION_COOKIE}=${value}; c=d`)).toBe(value);
    expect(sessionCookieValue(`${SESSION_COOKIE}x=1; a=b`)).toBeNull();
    expect(sessionCookieValue(undefined)).toBeNull();
  });
});
