// Unit tests for the runtime-free crypto primitives. These run under plain
// vitest (Node's global WebCrypto + btoa/atob), no workerd needed — the point
// is a fast gate on the load-bearing pure logic (b64u, challenge_hash domain
// separation, constant-time compare, replay window).

import { describe, it, expect } from 'vitest';
import {
  b64uEnc,
  b64uDec,
  decodeB64uExact,
  isB64uString,
  ctEq,
  inReplayWindow,
  challengeHash,
} from '../src/crypto';

describe('b64u', () => {
  it('round-trips arbitrary bytes', () => {
    for (const len of [0, 1, 2, 3, 16, 32, 100]) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
      expect(Array.from(b64uDec(b64uEnc(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it('emits url-safe alphabet with no padding', () => {
    const s = b64uEnc(new Uint8Array([0xff, 0xef, 0xfe]));
    expect(s).not.toMatch(/[+/=]/);
  });

  it('rejects a length ≡ 1 (mod 4) that decodes to no byte sequence', () => {
    expect(() => b64uDec('A')).toThrow(/length/);
  });
});

describe('decodeB64uExact', () => {
  it('accepts the exact length', () => {
    expect(decodeB64uExact(b64uEnc(new Uint8Array(32)), 32, 'x').length).toBe(32);
  });
  it('rejects the wrong length', () => {
    expect(() => decodeB64uExact(b64uEnc(new Uint8Array(16)), 32, 'x')).toThrow(/wrong length/);
  });
  it('rejects non-string / non-b64u input', () => {
    expect(() => decodeB64uExact(123, 32, 'x')).toThrow(/not b64u/);
    expect(() => decodeB64uExact('has spaces!', 32, 'x')).toThrow(/not b64u/);
  });
  it('isB64uString guards', () => {
    expect(isB64uString('AbC-_9')).toBe(true);
    expect(isB64uString('')).toBe(false);
    expect(isB64uString('a=b')).toBe(false);
    expect(isB64uString(42)).toBe(false);
  });
});

describe('ctEq', () => {
  it('true iff equal, and length-mismatch is false', () => {
    expect(ctEq(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(ctEq(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(ctEq(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe('inReplayWindow', () => {
  it('accepts within ±5min, rejects outside', () => {
    const now = 1_700_000_000_000;
    expect(inReplayWindow(now, now)).toBe(true);
    expect(inReplayWindow(now, now - 5 * 60 * 1000)).toBe(true);
    expect(inReplayWindow(now, now + 5 * 60 * 1000)).toBe(true);
    expect(inReplayWindow(now, now - 5 * 60 * 1000 - 1)).toBe(false);
    expect(inReplayWindow(now, now + 5 * 60 * 1000 + 1)).toBe(false);
  });
});

describe('challengeHash', () => {
  const pk = new Uint8Array(32).fill(1);
  const nonce = new Uint8Array(16).fill(2);
  const salts = [new Uint8Array(16).fill(3), new Uint8Array(16).fill(4)];

  it('is deterministic for identical inputs', async () => {
    const a = await challengeHash(pk, nonce, 12345, salts, 'approve');
    const b = await challengeHash(pk, nonce, 12345, salts, 'approve');
    expect(ctEq(a, b)).toBe(true);
    expect(a.length).toBe(32);
  });

  it('domain-separates approve from reject (replay guard)', async () => {
    const approve = await challengeHash(pk, nonce, 12345, salts, 'approve');
    const reject = await challengeHash(pk, nonce, 12345, salts, 'reject');
    expect(ctEq(approve, reject)).toBe(false);
  });

  it('changes when any bound field changes', async () => {
    const base = await challengeHash(pk, nonce, 12345, salts, 'approve');
    const diffTs = await challengeHash(pk, nonce, 12346, salts, 'approve');
    const diffSalt = await challengeHash(pk, nonce, 12345, [salts[0]!, new Uint8Array(16).fill(9)], 'approve');
    expect(ctEq(base, diffTs)).toBe(false);
    expect(ctEq(base, diffSalt)).toBe(false);
  });
});
