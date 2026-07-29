// Shared types for the vt-passkey v2 Worker.

export interface Env {
  ACCOUNT: DurableObjectNamespace;
  ASSETS: Fetcher;
  VT_AUTH_CF: string;
  CREDENTIALS_JSON: string;
  /**
   * base64url 32-byte X25519 secret key for the opt-in DEK cache. The PWA seals
   * each cached DEK to the matching public key (derived at runtime via
   * crypto_scalarmult_base, so operators configure ONE secret and cannot mismatch
   * the pair); the Worker opens it on a cache hit and re-seals to the requester's
   * ephemeral pubkey. Empty/absent → DEK caching is disabled and every decrypt
   * requires a phone approval (the historical behaviour). NEVER logged. */
  CACHE_SECKEY: string;
  /** JSON: {"app_token":"…","user_key":"…"}. Empty/invalid → Pushover disabled. */
  PUSHOVER_JSON: string;
  /** JSON: {"webhook_url":"https://hooks.slack.com/services/…"}. Empty/invalid → Slack (webhook) disabled. */
  SLACK_JSON: string;
  /** JSON: {"bot_token","channel","mention"?}. Slack self-built-app (bot token)
   *  channel: @-mentions approvers + edits the message in place on the decision
   *  (like Feishu, unlike the one-way SLACK_JSON webhook). Empty/invalid → Slack
   *  App disabled. See slack_app.ts. */
  SLACK_APP_JSON: string;
  /** JSON: {"app_id","app_secret","receive_id","receive_id_type"?,"mention"?,"base"?}.
   *  Feishu/Lark self-built-app bot channel: @-mentions approvers + edits the
   *  card in place on the decision. Empty/invalid → Feishu disabled. See feishu.ts. */
  FEISHU_JSON: string;
  /** "1" | "true" | "on" | "yes" → push the 免审批 cache-hit notices (Pushover /
   *  Slack / Slack App / Feishu). Anything else, including absent, keeps them
   *  off: a cache hit can fire many times a minute and the stream buries the
   *  approval messages that need a human. The audit row is written regardless,
   *  so cache hits remain fully visible on the admin audit page. */
  CACHE_HIT_NOTIFY?: string;
  /** "1" | "true" | "on" | "yes" → the admin cache tab may REQUEST a DEK-cache
   *  extension. A kill switch, NOT an authorization: even when on, extending
   *  requires a fresh phone Passkey ceremony (see docs/dek-cache.md §extend), is
   *  bounded per-hop by EXTEND_TTL_WHITELIST and can never resurrect a lapsed
   *  entry. Total lifetime is unbounded — every hop needs its own approval. Off by
   *  default so a deployment that never wants the capability simply does not
   *  have it (the routes 404 and the UI hides the controls). */
  CACHE_ADMIN_EXTEND?: string;
  WORKER_ORIGIN: string;
  RP_ID: string;
  /** Cloudflare Access team domain, e.g. "myteam.cloudflareaccess.com". Empty → admin surface fails closed. */
  ACCESS_TEAM_DOMAIN: string;
  /** Cloudflare Access Application AUD tag. Empty → admin surface fails closed. */
  ACCESS_AUD: string;
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

/** Push messages sent to the admin audit page over the '/kestrel/api/audit-stream'
 *  WebSocket. A SEPARATE channel from the per-ceremony daemon socket (WsMessage).
 *  'hello' signals (re)connection — the client then runs an `after_seq` catch-up.
 *  'audit' carries one full row (same projection as AuditQueryResponse.rows) so
 *  the client never has to re-fetch on an event. */
export type AdminWsMessage =
  | { kind: 'hello' }
  | { kind: 'audit'; event: 'insert' | 'update'; row: AuditRow }
  // The audit table was wiped (admin "清空审计") — connected tabs should reset
  // their list and reload, rather than keep showing now-deleted rows.
  | { kind: 'clear' };

// DEK-cache events (hit / miss / clear) are NOT a separate table — they are
// rows in `audit` with op_kind='cache' and status ∈ {approved=hit, miss,
// cleared}. One unified audit surface.


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
  /** Feishu card message_id (present once the approval card was sent), so the DO
   *  can PATCH the card to its terminal state on approve/reject/expire. Absent
   *  when the Feishu channel is off or the send failed. */
  feishu_message_id?: string;
  /** Slack App message reference, present once the approval message was sent, so
   *  the DO can chat.update it to its terminal state on approve/reject/expire.
   *  Absent when the Slack App channel is off or the send failed. */
  slackapp?: SlackAppMsgRef;
  /** Present ONLY on a cache-extension ceremony (op_kind='cache-extend'): the
   *  immutable intent this approval authorizes. Written once by
   *  opCacheExtendCreate and never mutated, so the thing the approver's assertion
   *  finalizes is the thing that was proposed. A challenge carrying this has NO
   *  salts and mints no DEKs — approving it only moves expires_ms forward on the
   *  named groups. */
  extend?: CacheExtendIntent;
}

// ── Cache extension (admin-requested, phone-approved) ──────────────────────

/** What one cache-extension ceremony proposes. Stored on the Challenge, so it
 *  cannot be swapped between the request and the approval. */
export interface CacheExtendIntent {
  /** Target group handles (CacheEntry.cache_group_id). Only `g_…` handles are
   *  accepted — see cache_policy.isExtendableGroupId. */
  group_ids: string[];
  /** Requested TTL in seconds; must be an EXTEND_TTL_WHITELIST member. Absolute
   *  from the moment of approval, not additive. */
  ttl_s: number;
  /** Verified Cloudflare Access email of the admin who requested it (audit). */
  requested_by: string;
  /** Snapshot of each target group at request time, so the approval page and the
   *  audit row show what the admin was actually looking at. */
  preview: CacheExtendPreview[];
}

export interface CacheExtendPreview {
  group_id: string;
  /** Entries live at request time. */
  live: number;
  /** Latest expiry across the group at request time (epoch ms). */
  expires_ms: number;
  host: string;
  ip: string;
}

// ── Admin cache listing ────────────────────────────────────────────────────

/** One row of the admin cache tab: all entries written by ONE approval under one
 *  binding ctx. Deliberately carries NO secret material — no sealed blob, no
 *  binding ctx digest, and no salts (the ctx digest plus a known IP would turn
 *  the listing into an offline oracle for the client-reported `pwd`). */
export interface CacheGroupSummary {
  group_id: string;
  /** Audit token_id of the approval that armed this cache. */
  origin_token_id: string;
  entries: number;
  live: number;
  /** Latest expiry across the group (epoch ms) — what liveness and eligibility
   *  are judged on. */
  max_expires_ms: number;
  /** Entry creation time (epoch ms); null for pre-migration entries. Forensic
   *  only — extension is measured from the approval, not from creation. */
  created_ms: number | null;
  /** Worker-derived source IP the entries are bound to. */
  ip: string;
  ppid: number;
  ppid_cmd: string;
  /** Joined from the origin audit row (same fields the audit tab already shows
   *  on the same Access gate). */
  host: string | null;
  user: string | null;
  pwd: string | null;
  command: string | null;
  finalized_ms: number | null;
  cache_ttl_s: number | null;
  /** True when this group may be targeted by an extension request. A group whose
   *  entries disagree on origin/creation/IP is excluded here with
   *  `reason='inconsistent'` — clearable, never extendable, since we refuse to
   *  guess which record the human meant. */
  extendable: boolean;
  /** Why not, when extendable is false. */
  reason: string | null;
}

export interface CacheListResponse {
  groups: CacheGroupSummary[];
  /** Server clock, so the UI counts down against the same time base that
   *  enforces expiry (a skewed browser clock cannot invent liveness). */
  now_ms: number;
  /** Entries scanned to build this listing. */
  scanned: number;
  /** True when the scan hit its cap — some groups are NOT shown. Never silently
   *  truncate: the UI must say so, and 清除全部 still covers everything. */
  truncated: boolean;
  /** Whether extension requests are enabled (CACHE_ADMIN_EXTEND). */
  extend_enabled: boolean;
  /** TTL options (seconds) an extension may request. */
  ttl_options_s: number[];
}

/** Handle to edit a sent Slack App message in place: `channel` is the resolved
 *  channel ID echoed by chat.postMessage (robust even when config `channel` was
 *  a name), `ts` is the message timestamp. Shared by Challenge.slackapp and
 *  slack_app.ts's send return type. */
export interface SlackAppMsgRef {
  channel: string;
  ts: string;
}

export interface ChallengeMeta {
  op_kind: string;
  command: string;
  host: string;
  /** $USER on the daemon machine */
  user: string;
  /** Current working directory of the vt CLI */
  pwd: string;
  /** Controlling TTY (e.g. /dev/pts/3); empty if not a TTY */
  tty: string;
  /** Parent process command line — which shell / script invoked vt */
  ppid_cmd: string;
  /** Numeric parent PID (libc::getppid()) reported by the CLI. Used (with the
   *  worker-derived IP) to scope the DEK cache: a later /api/dek-cache request
   *  must carry the SAME ppid AND originate from the SAME IP, or it misses.
   *  CLIENT-REPORTED, so it is advisory (blast-radius reduction), not a hard
   *  boundary — a fully-compromised local host can spoof it. The IP is the
   *  trustworthy half of the binding. */
  ppid: number;
  /** SSH_CLIENT / SSH_CONNECTION env if the session is remote */
  ssh_client: string;
  ip: string;
  reason: string;
}

// ── Inbound from daemon via POST /api/challenge ────────────────────────────

export interface ChallengeRequest {
  daemon_pubkey_b64u: string;
  timestamp_ms: number;
  /** per-DEK salts; may be empty for auth-only requests */
  salts_b64u: string[];
  meta?: Partial<ChallengeMeta>;
}

// ── Outbound from /api/challenge ───────────────────────────────────────────

export interface ChallengeResponse {
  approve_token: string;
  poll_token: string;
  worker_nonce_b64u: string;
  timestamp_ms: number;
  approve_url: string;
  push_warning?: string;
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
  | { status: 'approved'; sealed_deks_b64u: string; pwa_pk_b64u: string; binding_tag_b64u: string }
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
  metadata: ChallengeMeta;
  /** TTL options (seconds) the PWA renders as cache-duration radios. Always
   *  includes 0 ("不缓存", the default). Empty (only [0]) when caching disabled. */
  cache_options_s: number[];
  /** base64url 32-byte X25519 public key the PWA seals cached DEKs to. Empty
   *  string when CACHE_SECKEY is unset (caching disabled — PWA hides the UI). */
  cache_pubkey_b64u: string;
}

// ── DEK cache (opt-in, IP+pwd-scoped) ──────────────────────────────────────

/** Inbound from daemon via POST /api/dek-cache — the fast path tried before a
 *  ceremony. HMAC(VT_AUTH_CF)-gated like /api/challenge. */
export interface DekCacheRequest {
  daemon_pubkey_b64u: string;
  /** salts to look up; empty array is rejected (returns miss). */
  salts_b64u: string[];
  timestamp_ms: number;
  /** Full display meta (same shape as the challenge request). `meta.pwd` is the
   *  client-reported half of the cache binding ctx (ctx = IP + pwd); IP is the
   *  worker-derived hard boundary. `meta.ppid` is forensic-only. The rest is
   *  stored on the hit audit row so a cache hit carries the same context as a
   *  ceremony decrypt. */
  meta?: Partial<ChallengeMeta>;
}

/** Outbound from /api/dek-cache. The `source:'cache'` discriminant is asserted
 *  by the Rust client BEFORE it skips verify_binding, so a normal ceremony
 *  response can never be mistaken for a cache response (and vice-versa). */
export type DekCacheResponse =
  | { source: 'cache'; sealed_deks_b64u: string }
  | { miss: true };

/** A single cached DEK in DO storage, keyed `dek:{ctx}:{salt_b64u}` where
 *  ctx = b64u(SHA-256("vt-dek-ctx-v3" || len(ip) || ip || pwd)). (v3 binds IP +
 *  pwd; v2 was IP-only; the v1 ppid component was removed — see
 *  docs/dek-cache.md §2.5.) */
export interface CacheEntry {
  /** crypto_box_seal(DEK_raw, CACHE_PUBKEY) — Worker opens with CACHE_SECKEY. */
  sealed_to_cache_b64u: string;
  expires_ms: number;
  /** audit: which approval (audit token_id) wrote this entry. */
  origin_token_id: string;
  /** binding context, stored redundantly for audit/forensics. */
  ip: string;
  ppid: number;
  ppid_cmd: string;
  /** `g_…` handle minted once per writeCache call (one approval, one binding
   *  ctx). This — not the truncated origin_token_id — is what an extension
   *  selects on: a mutation that GRANTS authority needs an unambiguous key of its
   *  own. ABSENT on pre-migration entries, which stay listable/clearable but are
   *  never extendable (see cache_policy.groupIdOf). */
  cache_group_id?: string;
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

/** Inbound to POST /api/audit-ingest. Signed with `VT-HMAC` over the raw body
 *  using the agent's HKDF-derived key (see crypto.ts hkdfSha256). `agent_id`
 *  selects which key the Worker derives to verify; `hostname` is display-only. */
export interface AgentAuditIngestRequest {
  timestamp_ms: number;
  agent_id: string;
  hostname: string;
  entry: AgentAuditEntry;
}

/** Internal DO op for /op/audit-ingest. The Worker has already verified the
 *  HMAC, capped `meta` (forcing `ip` from CF-Connecting-IP), and bounded the
 *  scalars. The DO inserts a row with source='agent'. */
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
}

// ── Internal DO op bodies ──────────────────────────────────────────────────

export interface DoCreateOp {
  challenge: Challenge;
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
}

/** Internal DO op for POST /api/dek-cache. The Worker builds `meta` (capping the
 *  client-supplied fields and overwriting `meta.ip` from CF-Connecting-IP, never
 *  trusting the body's IP). `meta.ip` + `meta.ppid` form the cache binding ctx. */
export interface DoDekCacheOp {
  daemon_pubkey_b64u: string;
  salts_b64u: string[];
  meta: ChallengeMeta;
}

/** Internal DO op for POST /{ADMIN_SEG}/api/cache-extend-request. The Worker has
 *  already passed the Cloudflare Access gate; it forwards the VERIFIED admin
 *  identity and the connecting IP, never anything client-claimed. The DO builds
 *  the ceremony (tokens, challenge hashes, immutable intent) itself, so a request
 *  and its approval cannot disagree about what is being extended. */
export interface DoCacheExtendCreateOp {
  group_ids: unknown;
  ttl_s: unknown;
  /** Verified Cloudflare Access email (access.ts sets it after JWT verify). */
  admin_email: string;
  /** CF-Connecting-IP of the admin browser (display/audit only). */
  admin_ip: string;
}

/** Response of a successful cache-extend-request: a pending ceremony that does
 *  nothing until a Passkey approves it. */
export interface CacheExtendCreateResponse {
  approve_token: string;
  approve_url: string;
  /** Human-readable summary shown on the approval page and in the audit row. */
  summary: string;
  /** Groups accepted into the ceremony. */
  targets: CacheExtendPreview[];
  /** Requested group ids that were dropped, with the reason. */
  rejected: Array<{ group_id: string; reason: string }>;
}

export interface DoRejectOp {
  approve_token: string;
  credential_id_b64u: string;
  client_data_json_b64u: string;
  authenticator_data_b64u: string;
  signature_b64u: string;
}
