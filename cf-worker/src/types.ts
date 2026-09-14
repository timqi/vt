// Shared types for the vt-passkey v2 Worker.

import type { UvLevel } from './uv_policy';

export interface Env {
  ACCOUNT: DurableObjectNamespace;
  ASSETS: Fetcher;
  /** The one Wrangler secret: a KEK over the root key `R` stored in the
   *  Durable Object (account_admin.ts, docs/worker-slim.md §2). Every other
   *  key — host tokens, admin sessions, the config blob, the cache scalar —
   *  derives from `R`, so this value alone opens nothing. Never logged, never
   *  sent to a host or a browser. */
  SECRET: string;
  /** Workers Rate Limiting binding shared by the unauthenticated POSTs: enroll
   *  (`enroll:<ip>`), admin bootstrap and login-challenge (`login:<ip>`).
   *  Absent → those routes refuse (503): an endpoint that can page the phone or
   *  mint a session must never run unthrottled. */
  LIMITER?: RateLimit;
}

// ── Audit (DO SQLite) ──────────────────────────────────────────────────────

/** One row of the DO-internal `audit` table — one row PER CHALLENGE (the
 *  lifecycle stages update this row in place; params are stored once). */
export interface AuditRow {
  id: number;
  token_id: string;
  created_ms: number;
  finalized_ms: number | null;
  status: string;            // pending | approved | rejected | expired
  op_kind: string | null;
  command: string | null;
  reason: string | null;
  host: string | null;
  user: string | null;
  pwd: string | null;
  /** The client's project root (ChallengeMeta.project); NULL on rows written
   *  before the column existed. */
  project: string | null;
  tty: string | null;
  ppid_cmd: string | null;
  ssh_client: string | null;
  ip: string | null;
  salts: number | null;
  latency_ms: number | null;
  verify_failures: number;
  /** DEK-cache TTL (seconds) the approver chose; 0/null = not cached. This keeps
   *  its original meaning forever — it is the DECISION, not the live state, so an
   *  admin extension does NOT rewrite it (see cache_expires_ms). */
  cache_ttl_s: number | null;
  /** Absolute epoch-ms this row's cache entries currently expire at, mirroring
   *  CacheEntry.expires_ms. Written with the cache and UPDATED by an approved
   *  extension, so the admin UI can show real liveness instead of inferring
   *  finalized_ms + cache_ttl_s (which an extension would make a lie). NULL on
   *  pre-migration rows and on rows that never armed a cache — the UI falls back
   *  to the old inference there. */
  cache_expires_ms: number | null;
  /** Numeric parent PID. Set for ceremony rows (from meta) and DEK-cache rows
   *  (op_kind='cache'). */
  ppid: number | null;
  /** Origin of the row: 'ceremony' (phone approval), 'cache' (DEK-cache event),
   *  or 'agent' (SSH-agent Touch ID decision pushed by the Mac). The column is
   *  NOT NULL DEFAULT 'ceremony', so a read always has a value. */
  source: string;
  // Agent-authoritative context, source='agent' rows only
  // (docs/approval-transparency.md §B). NULL = pre-field agent or non-agent
  // row; '' / 0 = a new agent said "not applicable" (fresh scope, non-sign op).
  /** Kernel-verified peer executable basename. */
  peer_exe: string | null;
  /** Sign operations: `SHA256:…` of the signing key. */
  key_fp: string | null;
  /** Verified non-forwarding session-bind destination label. */
  dest: string | null;
  /** connection | destination | workspace | cwd-fallback | parent-app. */
  scope_family: string | null;
  /** The exact label the Touch ID reuse line displayed. */
  scope_label: string | null;
  /** Effective TTL of the reusable scope (seconds); 0 = fresh. */
  grant_ttl_s: number | null;
  /** Peer is the vt relay: 0 | 1. */
  relayed: number | null;
  /** Stored as `[salt, claimed]` pairs, resolved against the names table on
   *  every read; NULL when the row carries no salts (auth, agent rows). */
  records: RecordName[] | null;
  /** Monotonic change counter, bumped on EVERY write to the row (create +
   *  each in-place lifecycle update). Unlike `id` (assigned once at INSERT), a
   *  later approve/reject/expire/verify-fail UPDATE advances `seq`, so the
   *  real-time admin stream can reconcile missed UPDATEs after a reconnect via
   *  `after_seq` (an `id`-cursor can never see an UPDATE to an older row). */
  seq: number;
}

export interface AuditQueryResponse {
  rows: AuditRow[];
  /** Highest `seq` present in the table at query time — the client uses it as
   *  the reconnect high-water mark (fetch `after_seq=<snapshot_seq>` to catch
   *  up on anything that changed while the WebSocket was down). */
  snapshot_seq: number;
}

/** Push messages sent to the admin audit page over the '/api/admin/audit-stream'
 *  WebSocket. A SEPARATE channel from the per-ceremony daemon socket (WsMessage).
 *  'hello' signals (re)connection — the client then runs an `after_seq` catch-up.
 *  'audit' carries one full row (same projection as AuditQueryResponse.rows) so
 *  the client never has to re-fetch on an event. */
export type AdminWsMessage =
  | { kind: 'hello' }
  | { kind: 'audit'; event: 'insert' | 'update'; row: AuditRow };

/** One record as every surface shows it: `name` is operator-owned (adopted or
 *  typed on the console), `claimed` is the client's 自报 (display only). */
export interface RecordName {
  salt_b64u: string;
  name: string | null;
  source: 'client' | 'manual' | null;
  claimed: string;
}

// DEK-cache events are NOT a separate table — they are rows in `audit` with
// op_kind='cache' and status ∈ {approved=hit, write_failed, extended}. One
// unified audit surface; clears are CF-logs only.


// ── Challenge stored in DO ─────────────────────────────────────────────────

export type ChallengeStatus = 'pending' | 'approved' | 'rejected' | 'expired';

export interface Challenge {
  approve_token: string;
  poll_token: string;
  /** base64url X25519 pubkey from client (32 bytes) */
  daemon_pubkey_b64u: string;
  /** base64url random 16 bytes generated by Worker */
  worker_nonce_b64u: string;
  /** milliseconds epoch, from client body */
  timestamp_ms: number;
  /** base64url SHA-256 commitment for approve flow (see crypto.ts challengeHash, action=approve) */
  approve_challenge_hash_b64u: string;
  /** base64url SHA-256 commitment for reject flow (action=reject) */
  reject_challenge_hash_b64u: string;
  /** per-DEK salts from client, each 16 bytes base64url */
  salts_b64u: string[];
  meta: ChallengeMeta;
  /** Effective WebAuthn user-verification level for THIS ceremony, decided
   *  server-side at creation as `max(policy, client request)` and never rewritten
   *  afterwards. The approval page asks for it and the assertion check enforces
   *  it, both from this stored field — a caller cannot downgrade a ceremony at
   *  verify time. ABSENT on challenges created by a pre-policy Worker, which are
   *  verified at `required` (uv_policy.challengeUvLevel). */
  uv?: UvLevel;
  status: ChallengeStatus;
  /** present after approval: sealed_box([DEK_0||...||DEK_n]) to daemon_pubkey */
  sealed_deks_b64u?: string;
  /** present after approval: PWA's ephemeral X25519 public key (32 bytes b64u) */
  pwa_pk_b64u?: string;
  /** present after approval: HMAC-SHA256 tag binding sealed_deks to pwa/daemon ECDH shared secret */
  binding_tag_b64u?: string;
  created_ms: number;
  /** ms epoch when status transitioned to a terminal state (approved/rejected/expired) */
  finalized_ms?: number;
  /** Present ONLY on a cache-extension ceremony (op_kind='cache-extend'): the
   *  immutable intent this approval authorizes. Written once by
   *  opCacheExtendCreate and never mutated, so the thing the approver's assertion
   *  finalizes is the thing that was proposed. A challenge carrying this has NO
   *  salts and mints no DEKs — approving it only moves expires_ms forward on the
   *  named entries. */
  extend?: CacheExtendIntent;
  /** Present ONLY on a host-token enrollment ceremony (op_kind='enroll'): what
   *  the unauthenticated requester claimed plus what the edge verified. Like
   *  `extend`, immutable after creation; approving mints exactly this token. */
  enroll?: EnrollIntent;
  /** Host token the daemon authenticated this ceremony with. Absent only on
   *  ceremonies no daemon opened (enroll, cache extension); the approval page
   *  labels host/user as verified when it is present. */
  token_id?: string;
  /** Set by commitEnroll in the same put that flips status to 'approved': the
   *  token_id minted for this ceremony. The secret is re-derived (never stored)
   *  when the poll socket delivers or re-delivers the token. */
  enroll_token_id?: string;
}

// ── Host-token enrollment (unauthenticated request, phone-approved) ────────

export interface EnrollIntent {
  /** Client-claimed hostname / user (display; become the token's identity). */
  host: string;
  user: string;
  /** Worker-derived: CF-Connecting-IP and `request.cf` country / AS org. */
  ip: string;
  origin: string;
  /** Six-digit pairing code (`123-456`) shown on the CLI and the approval page. */
  pair_code: string;
}

/** Inbound to POST /api/enroll (no auth; rate-limited per IP). */
export interface EnrollRequest {
  host: string;
  user: string;
  timestamp_ms: number;
}

export interface EnrollResponse {
  approve_url: string;
  poll_token: string;
  pair_code: string;
}

/** Internal DO op for POST /api/enroll. The Worker has already rate-limited
 *  the caller and derived `ip` / `origin`; the DO enforces the pending cap and
 *  mints the ceremony. */
export interface DoEnrollCreateOp {
  host: string;
  user: string;
  ip: string;
  origin: string;
}

/** One row of the DO `host_token` table (account_tokens.ts). Carries no
 *  secret: the secret is derived from the master + token_id on demand. */
export interface HostTokenRow {
  token_id: string;
  host: string;
  user: string;
  enroll_ip: string;
  origin: string;
  approve_token_id: string;
  created_ms: number;
  expires_ms: number;
  last_used_ms: number;
  last_ip: string;
  revoked_ms: number | null;
}

export interface HostTokenListResponse {
  tokens: HostTokenRow[];
  now_ms: number;
  truncated: boolean;
}

// ── Cache extension (admin-requested, phone-approved) ──────────────────────

/** One cache entry as the console addresses it: the two halves of the key the
 *  DO re-derives (`cacheCtx`) plus the salt. The storage key itself never
 *  leaves the DO — its project hash would be an offline oracle for the
 *  client-reported `project` path. */
export interface CacheEntryRef {
  token_id: string;
  project: string;
  salt_b64u: string;
}

/** What one cache-extension ceremony proposes. Stored on the Challenge, so it
 *  cannot be swapped between the request and the approval. One scope
 *  (token + project) per ceremony, so the approver reads one host · project. */
export interface CacheExtendIntent {
  token_id: string;
  project: string;
  salts_b64u: string[];
  /** Requested TTL in seconds; must be an EXTEND_TTL_WHITELIST member. Absolute
   *  from the moment of approval, not additive. */
  ttl_s: number;
  /** Snapshot at request time, so the approval page and the audit row show
   *  what the admin was actually looking at. */
  host: string;
  records: string[];
  /** Latest expiry across the targets at request time (epoch ms). */
  expires_ms: number;
}

// ── Admin cache listing ────────────────────────────────────────────────────

/** One live entry of the admin cache tab. Carries NO secret material: no
 *  sealed blob and no storage key; the salt (public in every vt:// URL) is the
 *  rename key and, with token_id + project, the entry's address. */
export interface CacheEntrySummary extends CacheEntryRef {
  record: RecordName;
  host: string;
  user: string;
  /** Worker-derived source IP at approval (audit metadata; not bound). */
  ip: string;
  /** Approval time (epoch ms); null on entries written before it was stored.
   *  Forensic only — extension is measured from the approval, not creation. */
  created_ms: number | null;
  expires_ms: number;
  /** The TTL the approver chose; null before it was stored. */
  ttl_s: number | null;
  /** Audit token_id of the approval that armed this entry. */
  origin_token_id: string;
}

export interface CacheListResponse {
  /** Live entries only (expires_ms > now_ms), latest expiry first. */
  entries: CacheEntrySummary[];
  /** Server clock, so the UI counts down against the same time base that
   *  enforces expiry (a skewed browser clock cannot invent liveness). */
  now_ms: number;
  /** Entries scanned to build this listing. */
  scanned: number;
  /** True when the scan hit its cap — some entries are NOT shown. Never silently
   *  truncate: the UI must say so, and 清除全部 still covers everything. */
  truncated: boolean;
  /** TTL options (seconds) an extension may request. */
  ttl_options_s: number[];
}

// ── Web Push (docs/worker-slim.md §5) ──────────────────────────────────────

/** One browser subscription, stored under K_cfg (account_admin.ts): endpoint +
 *  `p256dh` + `auth` together let anyone push readable notifications to that
 *  phone. Upserted by `endpoint`, newest first, capped at 10. */
export interface PushSubscription {
  endpoint: string;
  /** UA public key, uncompressed P-256 point, base64url (65 bytes). */
  p256dh: string;
  /** UA authentication secret, base64url (16 bytes). */
  auth: string;
  label: string;
  created_ms: number;
}

/** What pwa/sw.js receives. `url` is opened on tap; `tag` collapses repeats. */
export interface PushPayload {
  v: 1;
  kind: 'approval' | 'enroll' | 'cache_hit' | 'test';
  title: string;
  body: string;
  url: string;
  tag: string;
}

/** Display context for one approval. Trust levels differ per field and the
 *  surfaces label them accordingly (docs/approval-transparency.md):
 *   - `ip` — Worker-derived (CF-Connecting-IP), always.
 *   - `host` / `user` — from the host-token record on daemon ceremonies
 *     (verified at enrollment); client-claimed on agent audit rows (the agent
 *     names the session host).
 *   - everything else — client-claimed.
 *  Dropped from the wire (columns kept, NULL): tty, ppid, ssh_client. */
export interface ChallengeMeta {
  op_kind: string;
  command: string;
  host: string;
  user: string;
  /** Current working directory of the vt CLI */
  pwd: string;
  /** The CLI's project root: the repository's common git dir when inside one,
   *  else the cwd. Client-reported and advisory; the DEK cache narrows its
   *  token-bound key on it (account_cache.ts). */
  project: string;
  /** Parent process command line — which shell / script invoked vt */
  ppid_cmd: string;
  ip: string;
  reason: string;
  /** Token path only: the IP of the token's PREVIOUS use when it differs from
   *  `ip` — an IP-change hint for the approver. '' / absent otherwise. */
  ip_prev?: string;
  /** Client-suggested record names, one per salt, '' when unknown (自报). */
  names?: string[];
}

// ── Inbound from daemon via POST /api/challenge ────────────────────────────

export interface ChallengeRequest {
  daemon_pubkey_b64u: string;
  timestamp_ms: number;
  /** per-DEK salts; may be empty for auth-only requests */
  salts_b64u: string[];
  meta?: Partial<ChallengeMeta>;
  /** Requested user-verification level (`vt --uv` / VT_PASSKEY_UV). Advisory and
   *  raise-only: the Worker stores `max(policy, this)`. Unknown/absent = no
   *  request. */
  uv?: string;
}

// ── Outbound from /api/challenge ───────────────────────────────────────────

export interface ChallengeResponse {
  approve_token: string;
  poll_token: string;
  worker_nonce_b64u: string;
  timestamp_ms: number;
  approve_url: string;
}

// ── Inbound from PWA via POST /api/approve ─────────────────────────────────

export interface ApproveRequest {
  approve_token: string;
  credential_id_b64u: string;
  /** sealed_box(daemon_pubkey, [DEK_0||...||DEK_n]) from libsodium */
  sealed_deks_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
  /** ephemeral X25519 public key generated by the PWA (32 bytes b64u) */
  pwa_pk_b64u: string;
  /** HMAC-SHA256 tag over the binding transcript (see do_account.ts opApprove) */
  binding_tag_b64u: string;
  /**
   * DEK-cache TTL in seconds, chosen by the approver. Absent or 0 → DO NOT
   * cache (historical behaviour). When > 0, `cache_sealed_deks_b64u` MUST be
   * present. Server validates against a whitelist. INVARIANT (M1): the Worker
   * can only create a cache entry when the PHONE sends cache material — which
   * the PWA produces solely when the human picks TTL > 0. A compromised CLI or
   * Worker cannot manufacture a cache entry for a TTL=0 ceremony. */
  cache_ttl_s?: number;
  /**
   * One entry per salt, in the same order as the challenge's salts_b64u: each is
   * crypto_box_seal(DEK_i, CACHE_PUBKEY) produced by the PWA. Only sent when
   * cache_ttl_s > 0. */
  cache_sealed_deks_b64u?: string[];
  /** Names the approver typed on the page, one per unnamed salt at most: stored
   *  after the assertion verifies, source='client' when equal to the client's
   *  claim, else 'manual'. */
  adopt_names?: { index: number; name: string }[];
}

// ── Inbound from PWA via POST /api/reject ─────────────────────────────────

export interface RejectRequest {
  approve_token: string;
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
}

// ── WebSocket message sent to waiting client ──────────────────────────────

export type WsMessage =
  | { status: 'waiting' }
  | { status: 'approved'; sealed_deks_b64u: string; pwa_pk_b64u: string; binding_tag_b64u: string;
      /** Enrollment ceremonies only: the freshly minted `vt1.…` host token. */
      host_token?: string }
  | { status: 'rejected' }
  | { status: 'expired' };

// ── Page data embedded in approve.html ────────────────────────────────────

export interface ApprovePageData {
  approve_token: string;
  approve_challenge_b64u: string;
  reject_challenge_b64u: string;
  daemon_pubkey_b64u: string;
  salts_b64u: string[];
  rp_id: string;
  allow_credentials: Array<{ id_b64u: string; h_b64u: string; k_b64u: string }>;
  /** The ceremony's effective UV level — what approve.js passes to
   *  `navigator.credentials.get`. Server-decided; the page never chooses it. */
  user_verification: UvLevel;
  metadata: ChallengeMeta;
  /** One per salt: the owned name (truth line) and the client's claim. */
  records: RecordName[];
  /** TTL options (seconds) the PWA renders as cache-duration radios. Always
   *  includes 0 ("不缓存", the default); only [0] when there is nothing to cache. */
  cache_options_s: number[];
  /** base64url 32-byte X25519 public key the PWA seals cached DEKs to. Empty
   *  string when the ceremony has no DEKs (PWA hides the UI). */
  cache_pubkey_b64u: string;
  /** Enrollment ceremonies only: the pairing code the approver compares with
   *  the requesting terminal before approving. */
  enroll_pair_code?: string;
  /** True when `metadata.host` / `user` came from a host-token record rather
   *  than the request body. */
  host_verified: boolean;
}

// ── DEK cache (opt-in, token+project-scoped) ───────────────────────────────

/** Inbound from daemon via POST /api/dek-cache — the fast path tried before a
 *  ceremony. Host-token HMAC-gated like /api/challenge. */
export interface DekCacheRequest {
  daemon_pubkey_b64u: string;
  /** salts to look up; empty array is rejected (returns miss). */
  salts_b64u: string[];
  timestamp_ms: number;
  /** Display meta (same shape as the challenge request). `meta.project` is the
   *  client-reported, advisory half of the cache key; the host token that
   *  authenticated the request is the hard half. The rest is stored on the hit
   *  audit row so a cache hit carries the same context as a ceremony decrypt. */
  meta?: Partial<ChallengeMeta>;
}

/** Outbound from /api/dek-cache. The `source:'cache'` discriminant is asserted
 *  by the Rust client BEFORE it skips verify_binding, so a normal ceremony
 *  response can never be mistaken for a cache response (and vice-versa). */
export type DekCacheResponse =
  | { source: 'cache'; sealed_deks_b64u: string }
  | { miss: true };

/** A single cached DEK in DO storage, keyed `dek:{token_id}:{project_h}:{salt_b64u}`
 *  where project_h = b64u(SHA-256("vt-dek-ctx-v5" || project)[0..16]); see
 *  docs/dek-cache.md. */
export interface CacheEntry {
  /** crypto_box_seal(DEK_raw, cache public key) — the Worker opens it with the root-key scalar. */
  sealed_to_cache_b64u: string;
  expires_ms: number;
  /** audit: which approval (audit token_id) wrote this entry. */
  origin_token_id: string;
  /** Worker-derived source IP at approval; audit/forensics only, not bound. */
  ip: string;
  /** Legacy (pre-trim entries only); no longer written. */
  ppid?: number;
  ppid_cmd: string;
  /** Client-reported project (for the listing) and name claim at approval;
   *  absent on entries written before they were stored. */
  project?: string;
  name?: string;
  /** The token record's host/user at approval and the TTL chosen; absent on
   *  entries written before they were stored. */
  host?: string;
  user?: string;
  ttl_s?: number;
  /** When the phone approval created this entry (epoch ms). Forensic only — an
   *  extension is measured from the approval and moves expires_ms alone, so
   *  nothing in the policy reads this. ABSENT on pre-migration entries, which are
   *  extendable like any other. Immutable: never rewrite it. */
  created_ms?: number;
}

// ── Agent audit push (SSH-agent → Worker) ──────────────────────────────────

/** One agent-side audit record — the `entry` field of an ingest request. The
 *  agent emits one per decision (approve / reject / unavailable / cache_hit /
 *  spawn_failed) across encrypt@vt / decrypt@vt / auth@vt / run@vt / sign.
 *
 *  `meta` carries the full ChallengeMeta display shape so `capChallengeMeta`
 *  has every field it expects. `meta.ip` is ABSENT on the wire by design — the
 *  Worker always overwrites it from CF-Connecting-IP. `meta.op_kind` duplicates
 *  the sibling `op_kind`. */
export interface AgentAuditEntry {
  /** encrypt | decrypt | auth | run | ssh-sign | sign */
  op_kind: string;
  /** approved | rejected | unavailable | cache_hit | spawn_failed */
  outcome: string;
  /** Decrypt batch size; 0 for auth/sign/run. */
  salts: number;
  /** Prompt-shown → decision, ms. 0 for cache hits. */
  latency_ms: number;
  /** Event time (epoch ms) — becomes created_ms AND finalized_ms. */
  ts_ms: number;
  /** `a_<agent_id>_<8 random bytes b64u>` — UNIQUE retry-dedup key. */
  token_id: string;
  meta?: Partial<ChallengeMeta>;
  // Agent-authoritative context (docs/approval-transparency.md §B). Unlike
  // `meta` these are kernel/agent-derived, never client-claimed. All ABSENT
  // from an old agent — the ingest preserves absence as SQL NULL, while a
  // new agent sends ''/0/false for "not applicable".
  /** Kernel-verified peer executable basename; '' unknown. */
  peer_exe?: string;
  /** Sign operations: `SHA256:…` of the signing key; '' otherwise. */
  key_fp?: string;
  /** Verified non-forwarding session-bind destination label; '' otherwise. */
  dest?: string;
  /** connection | destination | workspace | cwd-fallback | parent-app; '' = fresh. */
  scope_family?: string;
  /** The exact label the Touch ID reuse line displayed; '' = fresh. */
  scope_label?: string;
  /** Effective TTL of the reusable scope (seconds); 0 = fresh. */
  grant_ttl_s?: number;
  /** Peer is the `vt ssh connect --forward-real-agent` relay. */
  relayed?: boolean;
}

/** Inbound to POST /api/audit-ingest. Signed with `VT-HMAC` over the raw body.
 *  `agent_id` selects the key the Worker derives to verify: `t:<token_id>` →
 *  that host token's secret (host_token.ts), anything else → the legacy
 *  hostname-salted HKDF of the master (crypto.ts hkdfSha256). `hostname` is
 *  display-only. */
export interface AgentAuditIngestRequest {
  timestamp_ms: number;
  agent_id: string;
  hostname: string;
  entry: AgentAuditEntry;
}

/** Internal DO op for /op/audit-ingest. The Worker has capped `meta` (forcing
 *  `ip` from CF-Connecting-IP) and bounded the scalars; the DO verifies the
 *  agent's host-token HMAC (`auth`) and inserts a row with source='agent'. */
export interface DoAuditIngestOp {
  token_id: string;
  outcome: string;
  salts: number;
  latency_ms: number;
  ts_ms: number;
  meta: ChallengeMeta;
  // Agent-authoritative context. `null` = the (old) agent never sent the
  // field; ''/0/false = a new agent said "not applicable". The DO stores the
  // null as SQL NULL so the two stay distinguishable (see the ingest caps in
  // index.ts, which must NOT coerce absent to ''/0).
  peer_exe: string | null;
  key_fp: string | null;
  dest: string | null;
  scope_family: string | null;
  scope_label: string | null;
  grant_ttl_s: number | null;
  /** SQLite has no bool: 0 | 1 | null. */
  relayed: number | null;
  /** The host token the agent signed with (`agent_id = t:<token_id>`), the
   *  MAC and the bytes it covers; the DO refuses the row when the MAC fails or
   *  the token is revoked/expired. */
  auth: DaemonAuth;
}

// ── Internal DO op bodies ──────────────────────────────────────────────────

/** What the edge forwards for a daemon body it could only check the shape of:
 *  the token id from `VT-Token-Id`, the MAC from `Authorization`, and the exact
 *  bytes it covered. The DO derives the token secret from the root key and
 *  compares before it touches the token or stores anything. */
export interface DaemonAuth {
  token_id: string;
  mac_b64u: string;
  signed_b64u: string;
}

export interface DoCreateOp {
  challenge: Challenge;
  /** The CLI's `--uv` request (raise-only input to the stored level). */
  uv_request: unknown;
  auth: DaemonAuth;
}

export interface DoApproveOp {
  approve_token: string;
  credential_id_b64u: string;
  sealed_deks_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
  pwa_pk_b64u: string;
  binding_tag_b64u: string;
  cache_ttl_s?: number;
  cache_sealed_deks_b64u?: string[];
  adopt_names?: unknown;
}

/** Internal DO op for POST /api/dek-cache. The Worker builds `meta` (capping the
 *  client-supplied fields and overwriting `meta.ip` from CF-Connecting-IP, never
 *  trusting the body's IP). `token_id` + `meta.project` form the cache key. */
export interface DoDekCacheOp {
  daemon_pubkey_b64u: string;
  salts_b64u: string[];
  meta: ChallengeMeta;
  auth: DaemonAuth;
}

/** Internal DO op for POST /api/admin/cache-extend-request. The DO verified the
 *  admin session and reads the connecting IP from the forwarded headers; it
 *  builds the ceremony (tokens, challenge hashes, immutable intent) itself, so
 *  a request and its approval cannot disagree about what is being extended. */
export interface DoCacheExtendCreateOp {
  entries: unknown;
  ttl_s: unknown;
}

/** Response of a successful cache-extend-request: a pending ceremony that does
 *  nothing until a Passkey approves it. */
export interface CacheExtendCreateResponse {
  approve_token: string;
  approve_url: string;
  /** Human-readable summary shown on the approval page and in the audit row. */
  summary: string;
  /** Salts accepted into the ceremony. */
  targets: string[];
  /** Requested salts that were dropped, with the reason. */
  rejected: Array<{ salt_b64u: string; reason: string }>;
}

export interface DoRejectOp {
  approve_token: string;
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
}
