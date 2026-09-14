import { describe, it, expect } from 'vitest';
import { parseCredentialEntry, lookupByCredentialId } from '../src/credentials';
import { b64uEnc, sha256 } from '../src/crypto';

const entry = (over: Record<string, unknown> = {}) => ({
  h: 'L0JnHXnwlzt3HXjLqjzbrgit2WcsVKLQIAFOIdeGB3s',
  i: 'aWQ',
  k: 'a2V5',
  p: 'cHVi',
  l: 'label',
  t: 1716105600,
  ...over,
});

describe('parseCredentialEntry', () => {
  it('accepts a well-formed entry and normalizes label and time', () => {
    const e = parseCredentialEntry(entry({ l: 'x'.repeat(100), t: 12.7 }));
    expect(e.l).toHaveLength(64);
    expect(e.t).toBe(12);
    expect(parseCredentialEntry(entry({ l: undefined, t: undefined }))).toMatchObject({ l: '', t: 0 });
  });

  it('rejects the old {v,c} envelope and anything but an entry', () => {
    // The Worker parses entries, not the CREDENTIALS_JSON envelope, so the
    // envelope posted where an entry belongs is a bad request.
    expect(() => parseCredentialEntry({ v: 1, c: [entry()] })).toThrow(/bad h/);
    expect(() => parseCredentialEntry(null)).toThrow(/not an object/);
    expect(() => parseCredentialEntry('{}')).toThrow(/not an object/);
  });

  it('rejects a missing, non-b64u or wrong-length field', () => {
    expect(() => parseCredentialEntry(entry({ k: undefined }))).toThrow(/bad k/);
    expect(() => parseCredentialEntry(entry({ p: 'not base64!' }))).toThrow(/bad p/);
    expect(() => parseCredentialEntry(entry({ h: 'aGFzaA' }))).toThrow(/not a SHA-256/);
  });
});

describe('lookupByCredentialId', () => {
  it('finds the entry whose h == b64u(sha256(credId))', async () => {
    const credId = new Uint8Array([9, 8, 7, 6, 5]);
    const h = b64uEnc(await sha256(credId));
    expect(await lookupByCredentialId([parseCredentialEntry(entry({ h }))], credId)).toBeDefined();
  });

  it('returns undefined for an unknown credId', async () => {
    expect(await lookupByCredentialId([parseCredentialEntry(entry())], new Uint8Array([1, 2, 3]))).toBeUndefined();
  });
});
