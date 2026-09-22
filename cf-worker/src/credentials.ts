// Passkey credential entries — the shape the setup page builds and the config
// blob stores (`config.credentials`, account_admin.ts). Byte formats are those
// of pwa/admin/setup.js; the Worker never sees the wrapped master in the clear.
//
//   h  b64u(SHA-256(credential_id))   lookup index
//   i  b64u(credential_id)            page matches the used rawId to h/k
//   k  b64u(iv(12)||ct(32)||tag(16))  AES-GCM(K_wrap, master_key)
//   p  b64u(COSE pubkey)              for signature verify
//   l  label
//   t  unix epoch seconds

import { b64uEnc, isB64uString, sha256 } from './crypto';

export interface CredentialEntry {
  h: string;
  i: string;
  k: string;
  p: string;
  l: string;
  t: number;
}

const LABEL_MAX = 64;

/** One entry from an untrusted body; throws on any shape problem. Only what
 *  the Worker later trusts is validated — `k` is opaque to it. */
export function parseCredentialEntry(raw: unknown): CredentialEntry {
  const e = raw as Partial<Record<keyof CredentialEntry, unknown>> | null;
  if (!e || typeof e !== 'object') throw new Error('credential: not an object');
  for (const f of ['h', 'i', 'k', 'p'] as const) {
    if (!isB64uString(e[f]) || (e[f] as string).length > 4096) throw new Error(`credential: bad ${f}`);
  }
  if ((e.h as string).length !== 43) throw new Error('credential: h is not a SHA-256');
  return {
    h: e.h as string,
    i: e.i as string,
    k: e.k as string,
    p: e.p as string,
    l: typeof e.l === 'string' ? e.l.slice(0, LABEL_MAX) : '',
    t: typeof e.t === 'number' && Number.isFinite(e.t) ? Math.floor(e.t) : 0,
  };
}

// Locate an entry by credential_id (raw bytes). Returns undefined if not found.
export async function lookupByCredentialId(
  entries: readonly CredentialEntry[],
  credentialId: Uint8Array,
): Promise<CredentialEntry | undefined> {
  const h = b64uEnc(await sha256(credentialId));
  return entries.find(e => e.h === h);
}
