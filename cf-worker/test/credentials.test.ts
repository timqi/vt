import { describe, it, expect } from 'vitest';
import { parseCredentials, lookupByCredentialId } from '../src/credentials';
import { b64uEnc, sha256 } from '../src/crypto';

const entry = (over: Record<string, unknown> = {}) => ({
  h: 'aGFzaA',
  i: 'aWQ',
  k: 'a2V5',
  p: 'cHVi',
  l: 'label',
  t: 1716105600,
  ...over,
});

describe('parseCredentials', () => {
  it('accepts a well-formed v1 blob', () => {
    const blob = parseCredentials(JSON.stringify({ v: 1, epoch: 3, c: [entry()] }));
    expect(blob.c).toHaveLength(1);
    expect(blob.epoch).toBe(3);
  });

  it('rejects an unsupported version', () => {
    expect(() => parseCredentials(JSON.stringify({ v: 2, c: [] }))).toThrow(/version/);
  });

  it('rejects a non-array `c`', () => {
    expect(() => parseCredentials(JSON.stringify({ v: 1, c: {} }))).toThrow(/`c` must be an array/);
  });

  it('rejects an entry missing a required string field', () => {
    expect(() => parseCredentials(JSON.stringify({ v: 1, c: [entry({ k: undefined })] })))
      .toThrow(/missing required string field/);
  });
});

describe('lookupByCredentialId', () => {
  it('finds the entry whose h == b64u(sha256(credId))', async () => {
    const credId = new Uint8Array([9, 8, 7, 6, 5]);
    const h = b64uEnc(await sha256(credId));
    const blob = parseCredentials(JSON.stringify({ v: 1, c: [entry({ h })] }));
    expect(await lookupByCredentialId(blob, credId)).toBeDefined();
  });

  it('returns undefined for an unknown credId', async () => {
    const blob = parseCredentials(JSON.stringify({ v: 1, c: [entry()] }));
    expect(await lookupByCredentialId(blob, new Uint8Array([1, 2, 3]))).toBeUndefined();
  });
});
