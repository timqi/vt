// Approval UV policy — the pure half (cf-worker/src/uv_policy.ts).
//
// The property under test everywhere below: nothing can LOWER a level. The
// policy default is the floor, every rule and the client's request may only
// raise it, and a malformed policy lands on `required` rather than on the
// permissive default.

import { describe, it, expect } from 'vitest';
import {
  parseUvPolicy, defaultUvPolicy, effectiveUvLevel,
  parseUvLevel, maxUvLevel, challengeUvLevel,
  DEFAULT_APPROVAL_UV, LEGACY_CHALLENGE_UV,
} from '../src/uv_policy';

const DECRYPT = { op_kind: 'decrypt', host: 'laptop' };

describe('level parsing and ordering', () => {
  it('accepts only the three spec levels', () => {
    for (const l of ['discouraged', 'preferred', 'required'] as const) {
      expect(parseUvLevel(l)).toBe(l);
    }
    for (const bad of ['REQUIRED', 'strict', '', ' required', 1, true, null, undefined, {}]) {
      expect(parseUvLevel(bad)).toBeNull();
    }
  });

  it('orders discouraged < preferred < required', () => {
    expect(maxUvLevel('discouraged', 'preferred')).toBe('preferred');
    expect(maxUvLevel('preferred', 'discouraged')).toBe('preferred');
    expect(maxUvLevel('preferred', 'required')).toBe('required');
    expect(maxUvLevel('required', 'discouraged')).toBe('required');
    expect(maxUvLevel('discouraged', 'discouraged')).toBe('discouraged');
  });
});

describe('policy defaults', () => {
  it('defaults an approval to discouraged — the single-click case', () => {
    expect(DEFAULT_APPROVAL_UV).toBe('discouraged');
    expect(effectiveUvLevel(defaultUvPolicy(), DECRYPT)).toBe('discouraged');
    expect(parseUvPolicy(undefined)).toEqual({ policy: defaultUvPolicy(), error: null });
    expect(parseUvPolicy('   ').policy).toEqual(defaultUvPolicy());
  });
});

describe('configured policy', () => {
  const policy = parseUvPolicy(JSON.stringify({
    default: 'discouraged',
    by_op: { decrypt: 'preferred', auth: 'required' },
    by_host: { 'prod-db': 'required', laptop: 'discouraged' },
  })).policy;

  it('raises per op and per host', () => {
    expect(effectiveUvLevel(policy, { op_kind: 'encrypt', host: 'laptop' })).toBe('discouraged');
    expect(effectiveUvLevel(policy, { op_kind: 'decrypt', host: 'laptop' })).toBe('preferred');
    expect(effectiveUvLevel(policy, { op_kind: 'auth', host: 'laptop' })).toBe('required');
    expect(effectiveUvLevel(policy, { op_kind: 'encrypt', host: 'prod-db' })).toBe('required');
  });

  it('never lets one rule weaken another', () => {
    // by_host.laptop is 'discouraged' — it must not pull the op rule down.
    expect(effectiveUvLevel(policy, { op_kind: 'auth', host: 'laptop' })).toBe('required');
    // …nor may a low default weaken a host rule.
    expect(effectiveUvLevel(policy, { op_kind: 'decrypt', host: 'prod-db' })).toBe('required');
  });

  it('ignores unparseable entries instead of dropping the whole policy', () => {
    const { policy: p, error } = parseUvPolicy(JSON.stringify({
      default: 'preferred', by_op: { decrypt: 'nonsense', auth: 'required' }, by_host: 'oops',
    }));
    expect(error).toBeNull();
    expect(effectiveUvLevel(p, { op_kind: 'decrypt' })).toBe('preferred');
    expect(effectiveUvLevel(p, { op_kind: 'auth' })).toBe('required');
  });

  it('falls back to required — never to the permissive default — when malformed', () => {
    for (const bad of ['{', '[]', 'null', '"required"', JSON.stringify({ default: 'off' })]) {
      const { policy: p, error } = parseUvPolicy(bad);
      expect(error).toBeTruthy();
      expect(effectiveUvLevel(p, DECRYPT)).toBe('required');
    }
  });
});

describe('client request folds in as a raise only', () => {
  const loose = defaultUvPolicy();
  const strict = parseUvPolicy(JSON.stringify({ default: 'required' })).policy;

  it('lets a client raise the level', () => {
    expect(effectiveUvLevel(loose, DECRYPT, 'required')).toBe('required');
    expect(effectiveUvLevel(loose, DECRYPT, 'preferred')).toBe('preferred');
  });

  it('cannot lower a required policy', () => {
    for (const asked of ['discouraged', 'preferred', undefined]) {
      expect(effectiveUvLevel(strict, DECRYPT, asked)).toBe('required');
    }
  });

  it('treats an unknown or absent request as no request', () => {
    for (const asked of [undefined, null, '', 'REQUIRED', 'yes', 7, {}]) {
      expect(effectiveUvLevel(loose, DECRYPT, asked)).toBe('discouraged');
    }
  });
});

describe('stored ceremony level', () => {
  it('verifies a pre-policy challenge at required', () => {
    expect(LEGACY_CHALLENGE_UV).toBe('required');
    expect(challengeUvLevel(undefined)).toBe('required');
    expect(challengeUvLevel('bogus')).toBe('required');
    expect(challengeUvLevel('discouraged')).toBe('discouraged');
  });
});
