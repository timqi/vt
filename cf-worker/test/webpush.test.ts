// The Web Push wire format against its published vectors. Pure WebCrypto, so
// it runs on plain vitest. The VAPID pair is generated per run — no test key
// is committed.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { b64uEnc, b64uDec } from '../src/crypto';
import { encryptPush, generateVapid, vapidAuthorization, sendPush, MAX_PUSH_PLAINTEXT } from '../src/webpush';

// RFC 8291 §5 / Appendix A — every value is copied from the RFC. The ua and as
// private keys are the RFC's, published for exactly this purpose.
const RFC = {
  plaintext: 'When I grow up, I want to be a watermelon',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  asPublic: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  body: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
};
const target = { endpoint: 'https://push.example.net/push/x', p256dh: RFC.uaPublic, auth: RFC.auth, label: '', created_ms: 0 };
const ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;
const enc = new TextEncoder();

async function rfcServerPair(): Promise<CryptoKeyPair> {
  const pub = b64uDec(RFC.asPublic);
  const jwk = { kty: 'EC', crv: 'P-256', d: RFC.asPrivate, x: b64uEnc(pub.slice(1, 33)), y: b64uEnc(pub.slice(33, 65)) };
  return {
    privateKey: await crypto.subtle.importKey('jwk', jwk, ECDH, false, ['deriveBits']),
    publicKey: await crypto.subtle.importKey('raw', pub, ECDH, true, []),
  };
}

describe('encryptPush', () => {
  it('reproduces the RFC 8291 example byte for byte', async () => {
    const body = await encryptPush(enc.encode(RFC.plaintext), target, {
      salt: b64uDec(RFC.salt), keyPair: await rfcServerPair(),
    });
    expect(b64uEnc(body)).toBe(RFC.body);
  });

  it('uses a fresh salt and ephemeral key for every message', async () => {
    const a = await encryptPush(enc.encode('hello'), target);
    const b = await encryptPush(enc.encode('hello'), target);
    expect(b64uEnc(a.slice(0, 16))).not.toBe(b64uEnc(b.slice(0, 16)));
    expect(b64uEnc(a.slice(21, 86))).not.toBe(b64uEnc(b.slice(21, 86)));
  });

  it('accepts the cap and refuses one byte over it before any key work', async () => {
    const max = await encryptPush(new Uint8Array(MAX_PUSH_PLAINTEXT), target);
    expect(max.length).toBe(4096);
    await expect(encryptPush(new Uint8Array(MAX_PUSH_PLAINTEXT + 1), target)).rejects.toThrow(/cap 3993/);
  });

  it('refuses a public key that is not on the curve', async () => {
    const bogus = { ...target, p256dh: b64uEnc(new Uint8Array(65).fill(4)) };
    await expect(encryptPush(enc.encode('hi'), bogus)).rejects.toThrow();
  });
});

describe('vapidAuthorization', () => {
  it('signs an ES256 token bound to the push service origin, raw r‖s', async () => {
    const keys = await generateVapid();
    const header = await vapidAuthorization(
      'https://web.push.apple.com/abc/def', keys, 'https://vt.example.com', 1_700_000_000_000);
    const m = /^vapid t=([^,]+), k=(.+)$/.exec(header);
    expect(m).not.toBeNull();
    const [, token, pub] = m!;
    expect(pub).toBe(keys.pub_b64u);
    const [head, payload, sig] = token!.split('.');
    const json = (s: string) => JSON.parse(new TextDecoder().decode(b64uDec(s)));
    expect(json(head!)).toEqual({ typ: 'JWT', alg: 'ES256' });
    expect(json(payload!)).toEqual({
      aud: 'https://web.push.apple.com', exp: 1_700_000_000 + 12 * 3600, sub: 'https://vt.example.com',
    });
    expect(b64uDec(sig!).length).toBe(64);
    // The published public key verifies the token: the pair is one pair.
    const verifyKey = await crypto.subtle.importKey(
      'raw', b64uDec(keys.pub_b64u), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    expect(await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, verifyKey, b64uDec(sig!), enc.encode(`${head}.${payload}`))).toBe(true);
  });
});

describe('sendPush', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('posts the aes128gcm body with VAPID, TTL and Urgency, and reports the answer', async () => {
    const keys = await generateVapid();
    let seen: { url: string; init: RequestInit } | undefined;
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      seen = { url, init };
      return new Response('', { status: 201 });
    });
    expect(await sendPush(target, '{"v":1}', keys, 'https://vt.example.com', 300, 'high')).toEqual({ status: 201 });
    expect(seen!.url).toBe(target.endpoint);
    const h = seen!.init.headers as Record<string, string>;
    expect(h['Content-Encoding']).toBe('aes128gcm');
    expect(h.TTL).toBe('300');
    expect(h.Urgency).toBe('high');
    expect(h.Authorization).toMatch(/^vapid t=/);
    expect((seen!.init.body as Uint8Array).byteLength).toBeGreaterThan(86);

    vi.stubGlobal('fetch', async () => new Response('gone', { status: 410 }));
    expect(await sendPush(target, '{}', keys, 'https://vt.example.com', 60, 'normal')).toEqual({ status: 410, error: 'gone' });

    vi.stubGlobal('fetch', async () => { throw new Error('connect ECONNREFUSED'); });
    expect(await sendPush(target, '{}', keys, 'https://vt.example.com', 60, 'normal')).toMatchObject({ status: 0 });
  });
});
