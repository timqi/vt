// Pure host-token helpers (host_token.ts). The golden vector's secret is the
// same b64u string the Rust client tests parse (src/cf.rs
// `worker_auth_parses_host_token_and_rejects_bare_master`), so the two suites pin the
// identical token shape; only the Worker derives — hosts just hold the result.

import { describe, it, expect } from 'vitest';
import {
  deriveHostTokenSecret, formatHostToken, isTokenId, mintTokenId, mintPairCode,
  HOST_TOKEN_TTL_MS,
} from '../src/host_token';
import { b64uEnc } from '../src/crypto';

describe('host token derivation', () => {
  it('pins the HKDF golden vector shared with the Rust client', async () => {
    const secret = await deriveHostTokenSecret('test-master-token', 'AAAAAAAAAAAAAAAA');
    expect(b64uEnc(secret)).toBe('iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI');
  });

  it('formats vt1.<id>.<secret> and derives a different secret per id', async () => {
    const tok = await formatHostToken('test-master-token', 'AAAAAAAAAAAAAAAA');
    expect(tok).toBe('vt1.AAAAAAAAAAAAAAAA.iaR45SwFl4C19e0hLGVnh32aBZlyjE4i47Jp_FbuKAI');
    const other = await formatHostToken('test-master-token', 'BBBBBBBBBBBBBBBB');
    expect(other.split('.')[2]).not.toBe(tok.split('.')[2]);
  });

  it('accepts only 16-char b64u token ids', () => {
    expect(isTokenId(mintTokenId())).toBe(true);
    expect(isTokenId('AAAAAAAAAAAAAAAA')).toBe(true);
    expect(isTokenId('AAAAAAAAAAAAAAA')).toBe(false);
    expect(isTokenId('AAAAAAAAAAAAAAA+')).toBe(false);
    expect(isTokenId('')).toBe(false);
    expect(isTokenId(42)).toBe(false);
  });

  it('mints ddd-ddd pairing codes', () => {
    for (let i = 0; i < 50; i++) expect(mintPairCode()).toMatch(/^\d{3}-\d{3}$/);
  });

  it('keeps the sliding window at seven days', () => {
    expect(HOST_TOKEN_TTL_MS).toBe(7 * 86400 * 1000);
  });
});
