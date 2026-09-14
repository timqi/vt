// Per-host Worker credentials ("host tokens"). Pure helpers — no storage, no
// Worker types — so they unit-test on plain vitest; the lifecycle table lives in
// account_tokens.ts.
//
// A host token is `vt1.<token_id>.<secret_b64u>`:
//   token_id = b64u(12 random bytes)                          (16 chars, public)
//   secret   = HKDF-SHA256(ikm=R, salt=token_id, info="vt-host-token-v1", 32)
//
// R is the root key that lives only in the Durable Object (account_admin.ts),
// so the body HMAC is verified there: the edge checks the header syntax and
// caps the body, the DO re-derives the secret and compares before touching the
// token (AccountAdmin.verifyHostMac, AccountTokens.touch). Nothing but the
// token_id is stored; a host only ever holds its own derived secret.
//
// The Rust side parses the same string in src/cf.rs (`WorkerAuth::parse`);
// the derivation is pinned by a golden vector in test/host_token.test.ts.

import { b64uEnc, hkdfSha256, randomBytes } from './crypto';

export const HOST_TOKEN_PREFIX = 'vt1.';
export const HOST_TOKEN_INFO = 'vt-host-token-v1';
/** Sliding validity window: every authenticated use moves expiry to now + 7 d. */
export const HOST_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const TOKEN_ID_RE = /^[A-Za-z0-9_-]{16}$/;

/** True for a well-formed token_id (16 b64u chars = 12 bytes). Cheap syntactic
 *  guard run BEFORE the HKDF so a garbage header never reaches the KDF. */
export function isTokenId(v: unknown): v is string {
  return typeof v === 'string' && TOKEN_ID_RE.test(v);
}

export function mintTokenId(): string {
  return b64uEnc(randomBytes(12));
}

export async function deriveHostTokenSecret(root: Uint8Array, tokenId: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  return hkdfSha256(root, enc.encode(tokenId), enc.encode(HOST_TOKEN_INFO), 32);
}

/** The string a host stores as VT_PASSKEY_TOKEN. */
export function formatHostToken(tokenId: string, secret: Uint8Array): string {
  return `${HOST_TOKEN_PREFIX}${tokenId}.${b64uEnc(secret)}`;
}

/** Six-digit pairing code shown on BOTH the requesting CLI and the approval
 *  page, so the approver can tell "my enroll" from a concurrent stranger's
 *  (device-code style). Rendered `123-456`. Uniform over 0..999999 via
 *  rejection sampling on a u32. */
export function mintPairCode(): string {
  for (;;) {
    const b = randomBytes(4);
    const n = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
    // Largest multiple of 1e6 below 2^32, so `n % 1e6` is unbiased.
    if (n >= 4294000000) continue;
    const code = String(n % 1000000).padStart(6, '0');
    return `${code.slice(0, 3)}-${code.slice(3)}`;
  }
}
