// Shared harness for the AccountDO tests.
//
// Two things it provides that the tests would otherwise repeat:
//
//   • direct access to the singleton DO (storage, SQL, and the private cache
//     methods — TypeScript `private` is erased at runtime, so the tests reach
//     writeCache/commitExtend without any export-surface change to
//     do_account.ts, which is being refactored on a sibling branch);
//   • a software authenticator that produces a REAL WebAuthn assertion the
//     Worker's own verifyAssertion accepts, so "expires_ms moves only after a
//     verified assertion" is proven by driving the whole ceremony rather than by
//     calling commitExtend directly.
//
// The P-256 keypair below is a throwaway generated for this suite; its public
// half is the single credential `bootstrap()` registers. It is not a
// credential for anything, anywhere.

import { env, runInDurableObject } from 'cloudflare:test';
import { b64uEnc, b64uDec, hmacSha256, sha256 } from '../src/crypto';
import { seal, cachePublicKey } from '../src/cache_crypto';
import { sessionCookieValue, SESSION_COOKIE } from '../src/admin_auth';
import { AccountAdmin } from '../src/account_admin';
import { AccountNotifications } from '../src/account_notifications';
import { AccountCache, cacheCtx } from '../src/account_cache';
import type { CacheEntry, CacheEntryRef, Challenge, ChallengeMeta, DaemonAuth } from '../src/types';

// ── DO access ──────────────────────────────────────────────────────────────

export const testEnv = env as unknown as { ACCOUNT: DurableObjectNamespace };

/** The origin `bootstrap()` registers: WebAuthn origin, RP id source and
 *  approve-URL base for every test. */
export const TEST_ORIGIN = 'https://vt.test.invalid';
export const TEST_RP_ID = 'vt.test.invalid';

/** The singleton instance index.ts always talks to (idFromName('account')). */
export function accountStub(): DurableObjectStub {
  const ns = testEnv.ACCOUNT;
  return ns.get(ns.idFromName('account'));
}

/** Anything reachable from inside the DO: the instance (including its private
 *  methods and its own mutable `env`) and its storage/SQL. */
export interface DoHandle {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  inst: any;
  state: DurableObjectState;
}

export function inDO<T>(fn: (h: DoHandle) => T | Promise<T>): Promise<T> {
  return runInDurableObject(accountStub(), (inst, state) =>
    fn({ inst: inst as unknown as DoHandle['inst'], state }),
  ) as Promise<T>;
}

/** Set config knobs (cache_hit_notify, uv_policy) through the
 *  real PUT op with the session bootstrap() minted. */
export async function configure(partial: Record<string, unknown>): Promise<void> {
  const res = await accountStub().fetch('https://account.do/op/admin-config', {
    method: 'PUT', headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: JSON.stringify(partial),
  });
  await res.text();
  if (res.status !== 200) throw new Error(`configure: ${res.status}`);
}

/** What a redeploy with another SECRET does to the singleton: a fresh
 *  AccountAdmin (and the two collaborators that hold it) over the same
 *  storage, mirroring the AccountDO constructor. */
export function redeployWithSecret(secret: string): Promise<void> {
  return inDO(({ inst }) => {
    inst.admin = new AccountAdmin(inst.ctx.storage, secret);
    inst.notifications = new AccountNotifications(inst.ctx, inst.admin);
    inst.cache = new AccountCache(inst.ctx.storage, () => inst.admin.cacheSeckey());
  });
}

/** The DEK-cache scalar of this test's root key. */
export function cacheSeckey(): Promise<Uint8Array> {
  return inDO(({ inst }) => inst.admin.cacheSeckey() as Uint8Array);
}

/** The secret a host holding `tokenId` would present, derived from this
 *  test's root key exactly as the DO does. */
export function hostSecret(tokenId: string): Promise<Uint8Array> {
  return inDO(({ inst }) => inst.admin.hostTokenSecret(tokenId));
}

/** What the edge forwards for a daemon body: the token, the MAC the host
 *  computed over `signed`, and those bytes. The DO ops verify it before
 *  anything else, so every direct `create` / `dek-cache` fixture carries one. */
export async function daemonAuth(tokenId: string, signed = '{}'): Promise<DaemonAuth> {
  const raw = new TextEncoder().encode(signed);
  return { token_id: tokenId, mac_b64u: b64uEnc(await hmacSha256(await hostSecret(tokenId), raw)), signed_b64u: b64uEnc(raw) };
}

// ── Admin session ──────────────────────────────────────────────────────────

/** The entry the test authenticator registers: `p` is the COSE public key of
 *  the throwaway P-256 keypair below; `k` is filler (the wrapped master is
 *  never touched by the Worker). */
export const TEST_CREDENTIAL_ENTRY = {
  h: 'L0JnHXnwlzt3HXjLqjzbrgit2WcsVKLQIAFOIdeGB3s',
  i: 'dnQtdGVzdC1jcmVkZW50aWFs',
  k: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  p: 'pQECAyYgASFYIIM-1_8pVqW7YUwLEF1aZb4dIBZimOydM-fAJpdQX9N8IlggIcsGbg-NW_rShPt68QxCXmBA7dV9v8NEw2B2OqvOW_4',
  l: 'test-passkey',
  t: 1716105600,
};

let adminCookie: string | null = null;

/** Bootstrap the DO (root key + config with the test credential) from
 *  TEST_ORIGIN and keep the session cookie for every later admin op. Storage
 *  is isolated per test, so each test's `beforeEach` runs this. */
export async function bootstrap(): Promise<void> {
  const resp = await accountStub().fetch('https://account.do/op/admin-bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN, 'CF-Connecting-IP': '203.0.113.1' },
    body: JSON.stringify({ entry: TEST_CREDENTIAL_ENTRY }),
  });
  await resp.text();
  if (resp.status !== 204) throw new Error(`bootstrap: ${resp.status}`);
  adminCookie = sessionCookieValue(resp.headers.get('Set-Cookie'));
}

/** Cookie + Origin the DO's admin gate wants; also what a browser tab sends. */
export function adminHeaders(): Record<string, string> {
  return adminCookie ? { Cookie: `${SESSION_COOKIE}=${adminCookie}`, Origin: TEST_ORIGIN } : {};
}

// ── Storage fixtures ───────────────────────────────────────────────────────

/** A token id the key derivation accepts; no host_token row is needed for an
 *  entry to be listed, cleared or extended (the entry carries its host). */
export const TEST_TOKEN_ID = 'testtoken0000000';
export const TEST_PROJECT = '/home/tester/repo/.git';
/** The ctx half of every seeded key: `dek:{ctx}:{salt}` under the test token
 *  and project, derived by the same seam production uses. */
export const testCtx = (project = TEST_PROJECT): Promise<string> => cacheCtx(TEST_TOKEN_ID, project);
/** A v4-shaped ctx (no token half): such keys stay listable and clearable
 *  through 清除全部 but can never be addressed by the console. */
export const FAKE_CTX = 'testctx0000000000000000000000000000000000';

let saltCounter = 0;
/** Unique per call (the counter is in the first bytes), so a 300-entry seed
 *  is 300 keys. */
export function nextSalt(): string {
  saltCounter++;
  return b64uEnc(new Uint8Array(16).map((_, i) => i < 4 ? (saltCounter >>> (8 * (3 - i))) & 0xff : (saltCounter * 31 + i) & 0xff));
}

/** A sealed blob writeCache/opDekCache will accept: crypto_box_seal of a 32-byte
 *  fake DEK to the cache public key of this test's root key. */
export async function sealFakeDek(fill = 7): Promise<string> {
  const dek = new Uint8Array(32).fill(fill);
  return seal(dek, cachePublicKey(await cacheSeckey()));
}

export async function makeEntry(over: Partial<CacheEntry> = {}): Promise<CacheEntry> {
  const now = Date.now();
  return {
    sealed_to_cache_b64u: await sealFakeDek(),
    expires_ms: now + 60_000,
    origin_token_id: 'origin0000000000',
    ip: '203.0.113.9',
    ppid_cmd: 'zsh -c fake',
    project: TEST_PROJECT,
    host: 'testbox',
    user: 'tester',
    ttl_s: 20 * 60,
    created_ms: now - 60_000,
    ...over,
  };
}

/** Write `n` entries straight into storage under the test token + project —
 *  the shortest path to "an entry in state X exists", without an approval.
 *  One template for every key, as one writeCache batch would produce. */
export async function seedEntries(
  h: DoHandle,
  n: number,
  over: Partial<CacheEntry> = {},
): Promise<string[]> {
  const entry = await makeEntry(over);
  const ctx = await testCtx(entry.project);
  const keys: string[] = [];
  for (let i = 0; i < n; i++) {
    const key = `dek:${ctx}:${nextSalt()}`;
    keys.push(key);
    await h.state.storage.put(key, entry);
  }
  return keys;
}

/** The console's address of a seeded key: how cache-clear-entries and
 *  cache-extend-create name it. */
export function refOf(key: string, project = TEST_PROJECT): CacheEntryRef {
  return { token_id: key.split(':')[1]!, project, salt_b64u: key.slice(key.lastIndexOf(':') + 1) };
}

export async function readEntries(h: DoHandle, keys: string[]): Promise<CacheEntry[]> {
  const out: CacheEntry[] = [];
  for (const k of keys) {
    const e = await h.state.storage.get<CacheEntry>(k);
    if (e) out.push(e);
  }
  return out;
}

export async function allDekKeys(h: DoHandle): Promise<string[]> {
  return [...(await h.state.storage.list<CacheEntry>({ prefix: 'dek:' })).keys()];
}

/** Insert a live host_token row for makeMeta()'s host/user and return its id.
 *  The DO ops refuse a body without one, so every direct `create` / `dek-cache`
 *  fixture needs it; going through /api/enroll is the host_token suite's job. */
export async function liveTokenId(): Promise<string> {
  const tokenId = nextToken('hst');
  const meta = makeMeta();
  await inDO(({ inst }) => inst.tokens.create({
    token_id: tokenId, host: meta.host, user: meta.user, enroll_ip: meta.ip,
    origin: '', approve_token_id: '',
  }, Date.now()));
  return tokenId;
}

// ── Challenge fixtures ─────────────────────────────────────────────────────

export function makeMeta(over: Partial<ChallengeMeta> = {}): ChallengeMeta {
  return {
    op_kind: 'decrypt',
    command: 'vt read .env',
    host: 'testbox',
    user: 'tester',
    pwd: '/home/tester/repo',
    project: '/home/tester/repo/.git',
    ppid_cmd: 'zsh -c fake',
    ip: '203.0.113.9',
    reason: '',
    ...over,
  };
}

let tokenCounter = 0;
/** 16-char token, so auditKey() (slice(0,16)) is the whole thing — the same
 *  property the production 12-byte b64u tokens have. */
export function nextToken(prefix = 'tok'): string {
  tokenCounter++;
  return (prefix + String(tokenCounter).padStart(13 - prefix.length, '0') + 'zzzzzzzzzzzzzzzz')
    .slice(0, 16);
}

export function makeChallenge(over: Partial<Challenge> = {}): Challenge {
  const token = nextToken();
  return {
    approve_token: token,
    poll_token: 'poll' + token,
    daemon_pubkey_b64u: b64uEnc(new Uint8Array(32).fill(1)),
    worker_nonce_b64u: b64uEnc(new Uint8Array(16).fill(2)),
    timestamp_ms: Date.now(),
    approve_challenge_hash_b64u: b64uEnc(new Uint8Array(32).fill(3)),
    reject_challenge_hash_b64u: b64uEnc(new Uint8Array(32).fill(4)),
    salts_b64u: [],
    meta: makeMeta(),
    status: 'pending',
    created_ms: Date.now(),
    ...over,
  };
}

// ── Audit access ───────────────────────────────────────────────────────────

export interface AuditSnapshot {
  token_id: string;
  status: string;
  op_kind: string | null;
  source: string;
  cache_ttl_s: number | null;
  cache_expires_ms: number | null;
  command: string | null;
  reason: string | null;
}

export async function auditRows(h: DoHandle): Promise<AuditSnapshot[]> {
  return h.state.storage.sql
    .exec(`SELECT token_id, status, op_kind, source, cache_ttl_s, cache_expires_ms,
                  command, reason
             FROM audit ORDER BY id`)
    .toArray() as unknown as AuditSnapshot[];
}

export async function auditRow(h: DoHandle, tokenId: string): Promise<AuditSnapshot | undefined> {
  return (await auditRows(h)).find(r => r.token_id === tokenId);
}

// ── Software authenticator (throwaway P-256 keypair) ───────────────────────

// TEST FIXTURE ONLY. Generated for this suite; the matching public key is the
// lone credential bootstrap() registers. Grants nothing anywhere.
const TEST_AUTHENTICATOR_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'gz7X_ylWpbthTAsQXVplvh0gFmKY7J0z58Aml1Bf03w',
  y: 'IcsGbg-NW_rShPt68QxCXmBA7dV9v8NEw2B2OqvOW_4',
  d: 'zh_7N-Uz6LoAmmbU4iErdP2oTxD3nKuPUY5rbcEiGsU',
};

/** b64u(credential_id) of TEST_CREDENTIAL_ENTRY ("vt-test-credential"). */
export const TEST_CREDENTIAL_ID_B64U = TEST_CREDENTIAL_ENTRY.i;

/** The PWA's ephemeral X25519 pubkey. An extension ceremony delivers no key
 *  material, so any 32 bytes will do — it only has to be bound into the
 *  assertion, which is precisely what the test is checking. */
export const TEST_PWA_PK = new Uint8Array(32).fill(9);

/** WebCrypto returns raw r||s; verifyAssertion decodes DER (what a real
 *  authenticator emits). Re-encode so the fixture goes through the same
 *  derToRaw path production does. */
function rawSigToDer(raw: Uint8Array): Uint8Array {
  const trim = (b: Uint8Array): number[] => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const out = Array.from(b.slice(i));
    if ((out[0]! & 0x80) !== 0) out.unshift(0);   // ASN.1 INTEGER is signed
    return out;
  };
  const r = trim(raw.slice(0, 32));
  const s = trim(raw.slice(32, 64));
  const body = [0x02, r.length, ...r, 0x02, s.length, ...s];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/** authenticatorData flags byte: UP is bit0, UV is bit2. The default is what a
 *  verifying authenticator emits; a test that drives the UV policy passes
 *  UP_ONLY (a 1Password/Chrome prompt that only confirmed presence). */
export const FLAGS_UP_UV = 0x05;
export const FLAGS_UP_ONLY = 0x01;

/** Sign one assertion over `expectedChallenge` with the fixture credential. */
export async function signChallenge(expectedChallenge: Uint8Array, flags: number): Promise<{
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
}> {
  const clientDataJson = new TextEncoder().encode(JSON.stringify({
    type: 'webauthn.get',
    challenge: b64uEnc(expectedChallenge),
    origin: TEST_ORIGIN,
    crossOrigin: false,
  }));

  // rpIdHash || flags(UP|UV) || signCount
  const rpIdHash = await sha256(new TextEncoder().encode(TEST_RP_ID));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = flags;

  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(await sha256(clientDataJson), authData.length);

  const key = await crypto.subtle.importKey(
    'jwk', TEST_AUTHENTICATOR_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signedData));

  return {
    credential_id_b64u: TEST_CREDENTIAL_ID_B64U,
    client_data_json_b64u: b64uEnc(clientDataJson),
    authenticator_data_b64u: b64uEnc(authData),
    signature_b64u: b64uEnc(rawSigToDer(rawSig)),
  };
}

/** Build the assertion the Worker expects for `approve`:
 *  challenge = SHA-256(approve_challenge_hash || pwa_pk). */
export async function signApproval(
  approveChallengeHashB64u: string,
  flags = FLAGS_UP_UV,
): Promise<{
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
  pwa_pk_b64u: string;
}> {
  const hash = b64uDec(approveChallengeHashB64u);
  const effective = new Uint8Array(hash.length + TEST_PWA_PK.length);
  effective.set(hash, 0);
  effective.set(TEST_PWA_PK, hash.length);
  const expectedChallenge = new Uint8Array(await crypto.subtle.digest('SHA-256', effective));
  return {
    ...(await signChallenge(expectedChallenge, flags)),
    pwa_pk_b64u: b64uEnc(TEST_PWA_PK),
  };
}

/** Drive a full approval through the DO's public `approve` op: a genuine
 *  WebAuthn assertion over the stored challenge, verified by the Worker's own
 *  verifyAssertion. Extra body fields (cache_ttl_s, cache_sealed_deks_b64u) go
 *  through untouched so a tampered approve body can be tested too. */
export async function approve(
  ch: Pick<Challenge, 'approve_token' | 'approve_challenge_hash_b64u'>,
  extra: Record<string, unknown> = {},
  flags = FLAGS_UP_UV,
): Promise<DoResult> {
  const assertion = await signApproval(ch.approve_challenge_hash_b64u, flags);
  return doPost('approve', {
    approve_token: ch.approve_token,
    sealed_deks_b64u: b64uEnc(new Uint8Array(48).fill(5)),
    binding_tag_b64u: b64uEnc(new Uint8Array(32).fill(6)),
    ...assertion,
    ...extra,
  });
}

/** The rejection half of the same ceremony: the assertion is over the stored
 *  reject_challenge_hash itself (no pwa_pk — a rejection delivers no key
 *  material). Same authenticator, same flags knob. */
export async function reject(
  ch: Pick<Challenge, 'approve_token' | 'reject_challenge_hash_b64u'>,
  flags = FLAGS_UP_UV,
): Promise<DoResult> {
  return doPost('reject', {
    approve_token: ch.approve_token,
    ...(await signChallenge(b64uDec(ch.reject_challenge_hash_b64u), flags)),
  });
}

// ── DO ops ───────────────────────────────────────────────────────────

export interface DoResult {
  status: number;
  text: string;
  json: any;
}

/** Always drains the body. An unconsumed response body holds the isolated
 *  storage stack frame open and makes the WHOLE FILE fail at teardown
 *  (cloudflare/workers-sdk#5629), so no test may check a status alone. */
async function consume(resp: Response): Promise<DoResult> {
  const text = await resp.text();
  let json: unknown = null;
  try { json = JSON.parse(text); } catch { /* plain-text error body */ }
  return { status: resp.status, text, json };
}

/** Admin headers ride along on every op: the public ops ignore them, the
 *  admin ops need them. A test that wants an unauthenticated admin call passes
 *  its own headers. */
export async function doPost(op: string, body: unknown, headers: Record<string, string> = adminHeaders()): Promise<DoResult> {
  return consume(await accountStub().fetch(`https://account.do/op/${op}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }));
}

export async function doGet(op: string, headers: Record<string, string> = adminHeaders()): Promise<DoResult> {
  return consume(await accountStub().fetch(`https://account.do/op/${op}`, { headers }));
}
