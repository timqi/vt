// CREDENTIALS_JSON parse + credential lookup.
//
// Schema (same as v1, unchanged):
// {
//   "v": 1, "epoch": 3,
//   "c": [{
//     "h": "<b64u(SHA-256(credential_id))>",  // lookup index
//     "i": "<b64u(credential_id)>",            // for allowCredentials
//     "k": "<b64u(iv(12)||ct(32)||tag(16))>",  // AES-GCM(K_wrap, master_key)
//     "p": "<b64u(COSE pubkey)>",              // for signature verify
//     "l": "label",
//     "t": 1716105600
//   }]
// }

import { b64uDec, b64uEnc, sha256 } from './crypto';

export interface CredentialEntry {
  h: string;   // b64u(SHA-256(credential_id))
  i: string;   // b64u(credential_id)
  k: string;   // b64u(AES-GCM wrapped master_key)
  p: string;   // b64u(COSE pubkey)
  l: string;   // label
  t: number;   // unix epoch seconds
}

export interface CredentialsBlob {
  v: number;
  epoch?: number;
  c: CredentialEntry[];
}

export function parseCredentials(raw: string): CredentialsBlob {
  const blob = JSON.parse(raw) as CredentialsBlob;
  if (blob.v !== 1) throw new Error(`unsupported credentials version ${blob.v}`);
  // `as CredentialsBlob` is a compile-time-only assertion; validate the runtime
  // shape so a malformed CREDENTIALS_JSON fails loudly here instead of throwing
  // an opaque error deep inside assertion verification.
  if (!Array.isArray(blob.c)) throw new Error('credentials: `c` must be an array');
  for (const e of blob.c) {
    if (
      !e ||
      typeof e.h !== 'string' ||
      typeof e.i !== 'string' ||
      typeof e.k !== 'string' ||
      typeof e.p !== 'string'
    ) {
      throw new Error('credentials: entry missing required string field(s)');
    }
  }
  return blob;
}

// Locate an entry by credential_id (raw bytes). Returns undefined if not found.
export async function lookupByCredentialId(
  blob: CredentialsBlob,
  credentialId: Uint8Array,
): Promise<CredentialEntry | undefined> {
  const h = b64uEnc(await sha256(credentialId));
  return blob.c.find(e => e.h === h);
}
