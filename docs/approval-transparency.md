# Approval transparency — prompt truth lines, audit fields, worker display

Status: implemented. Owns what the Touch ID prompt, the Worker approval
surfaces, and the agent audit push show and record, and in which order;
verify against the anchors named per section.

## 1. Contract

### A. Agent prompt truth lines (`src/server_macos/ssh_agent.rs`)

Rendering order invariant: **agent-derived truth lines precede every
client-reported line**, so a hostile caller can pad only its own region
off-screen.

- **A1 — raw sign destination.** After the `ssh-sign` header:
  - `BindState::Bound { forwarding: false }` and the scope is *not*
    destination-reusable (Fresh): add `dest: <destination_label>` — the
    same precomputed label the reuse line would have used. (When the
    reuse line exists it already names the destination; no duplicate
    line.)
  - `BindState::Bound { forwarding: true }`: add
    `dest: <destination_label> (forwarding — may serve a relayed request)`.
  - `BindState::Tainted`: add `warning: session-bind verification failed`.
  - `Unbound`: unchanged (an unbound ssh peer has nothing verified to
    show; modern OpenSSH always binds).
- **A2 — caller line.** `append_caller_line` appends
  `caller: <peer_exe basename>` when `self.peer_exe` is known, placed
  with the truth lines (right after the relay line), on decrypt@vt,
  sign@vt, auth@vt, run@vt and raw sign (see §1a for when it is
  suppressed). Although `peer_exe` is kernel-derived, it is a filesystem
  basename an attacker with local code execution controls, so the line
  goes through `sanitize_for_display` like every other prompt field.
- **A3 — run@vt relay marker.** `append_relay_origin` runs on run@vt too.
  Dead path today (the relay filter refuses run@vt) — cheap insurance,
  keeps the four extension prompts uniform.

Not shown, deliberately: the resolved workspace on Fresh prompts (would blur
the "reuse line appears iff a grant can be created" invariant); tty.

### B. Structured audit fields (agent → worker ingest)

**Top-level** fields on `AgentAuditEntry` / `DoAuditIngestOp` — not on
`ChallengeMeta`, which is the client-claimed display struct; these are
agent-authoritative:

| field | type | content |
|---|---|---|
| `peer_exe` | String | kernel-verified peer executable basename ("" unknown) |
| `key_fp` | String | sign ops: `SHA256:…` of the signing key ("" otherwise) |
| `dest` | String | verified non-forwarding session-bind destination label ("" otherwise) |
| `scope_family` | String | `connection` / `destination` / `workspace` / `cwd-fallback` / `parent-app`; "" = fresh |
| `scope_label` | String | the exact label the reuse line displayed ("" = fresh) |
| `grant_ttl_s` | u64 | effective TTL for the reusable scope; 0 = fresh |
| `relayed` | bool | `peer_is_vt_relay` |

- `scope_family`/`scope_label`/`grant_ttl_s` are set on **both**
  `approved` (grant minted) and `cache_hit` rows (digest match implies
  the hit's recomputed label equals the grant's), answering "which prior
  approval class did this silent hit ride" without engine surgery.
- `GrantScope::family()` and `ScopeFamily::as_wire()` in
  `src/core/authorization.rs` produce the tag. Unlike `ContextBasis`,
  `ScopeFamily` has no `from_wire`: this is one-way telemetry, never
  parsed back.
- Handlers pass the fields through `AuditContext<'_>`
  (`src/server_macos/audit.rs`).
- Raw sign keeps `meta = ClientMeta::default()` (honest: nothing
  client-reported exists on that path) — the structured fields carry
  key/peer/destination.

**Deliberately deferred — grant→hit token linkage.** Storing the minting
approval's `token_id` inside each grant and echoing it on `cache_hit`
(mirroring the Worker cache's `origin_token_id`) requires threading an
audit token through `AuthorizationRequest`, the grant store, and
`Decision`. `scope_label` + timestamps give the correlation for
forensics; revisit only if that proves insufficient in practice. Known
ambiguity, accepted: distinct approvals can share an identical
`scope_label` over time (`commit_at`'s TTL-tightening rule re-mints the
same scope), so label+timestamp correlation blurs when approvals cluster
closely — a forensic imprecision, not a security gap.

Worker side (`cf-worker`):

- `DoAuditIngestOp` (`types.ts`) carries the seven fields (all optional).
- The audit columns `peer_exe TEXT`, `key_fp TEXT`, `dest TEXT`,
  `scope_family TEXT`, `scope_label TEXT`, `grant_ttl_s INTEGER`,
  `relayed INTEGER` are additive `ALTER TABLE` migrations
  (`ADDED_COLUMNS` in `account_audit.ts`).
- **NULL vs "" convention:** the agent always sends every field, using
  `""` / `0` / `false` for "not applicable" (fresh, unknown peer, non-sign
  op). Ingest must preserve *absence* as SQL `NULL` — a null-preserving
  cap helper for the strings (NOT the existing `capMeta`, which coerces
  absent to `''`) and a null-preserving numeric/bool parse for
  `grant_ttl_s`/`relayed` (NOT `clampInt`, which coerces to `0`). Thus
  `NULL` = "old agent, field never sent" and `''`/`0` = "new agent,
  explicitly fresh/unknown" stay distinguishable in SQL.
- `auditAgent` INSERT includes them; defensive caps + control-char strip
  at ingest (strings capped at 160).
- `AUDIT_SELECT_COLS` + the admin audit page detail view render them
  (labels: 调用进程 `peer_exe` / 密钥 `key_fp` / 目的主机 `dest` /
  复用范围 `scope_label` / 范围类型 `scope_family` / 授权时长
  `grant_ttl_s` / 经中继 `relayed`; the page skips empty/NULL values, so
  pre-migration rows render unchanged).
- Compatibility: old agent → new worker ⇒ columns NULL; new agent → old
  worker ⇒ unknown JSON fields ignored. The ingest HMAC covers the body
  as-is; no protocol version needed.

### C. Worker approval surfaces (`cf-worker/pwa`, `notify.ts`)

- **C1 — trust labeling on the approve page** (`pwa/approve.js`): the
  `ip` row is labeled `IP（已验证）`; a footnote under the field list
  names which fields are verified per path. The decision line carries
  `记录 N 条` (N from `salts_b64u.length`, worker-derived); the record names
  sit directly beneath it — see C5.
- **C5 — record names** ([dek-cache.md](dek-cache.md)): a name the operator
  owns (adopted or typed on the console, keyed by the record's salt) is a
  **truth line** — the Worker resolved it from its own table, the client
  cannot influence it — and precedes every unnamed record. A record with no
  owned name shows an empty name input (`记录名`) and, when the client sent
  a suggestion, a chip labeled for what it is, `客户端称 GH_TOKEN`, that
  fills the input on one tap: the label is client-claimed until the approver
  keeps it, and the name — kept or typed — rides on the verified assertion
  (`adopt_names: [{index, name}]`, read at the 同意 tap), so a hostile
  client can propose a misleading name but never make the page state it as
  fact. Named records are read-only on the page; rename lives in admin. The
  same rule holds on the audit table, the DEK 缓存 tab and the cache-hit
  push: owned name, else `X（自报）`, else the salt's first 8 characters
  (`account_names.nameLabel`, `vt.recordLabel`). The footnote says
  `记录名由服务端保存`.
- **C6 — fold** (operator feedback, one-handed phone use): above the fold
  are the decision lines only — 类型, 记录, 主机（已验证）@用户, 命令 — then
  the cache scope + duration radios and 同意/拒绝; 目录, 项目, 父进程,
  IP（已验证）（+上次） and 原因 sit in a collapsed `详情`. Enrollment keeps the
  pairing code as the largest element. Truth-before-claim ordering is kept
  inside each block.
- **C2 — cache consent copy**: 「同一主机令牌（已验证）且同一项目（客户端
  自报）」 so the stated boundary matches the implemented one (key = verified
  host `token_id` + advisory `project`, see [`dek-cache.md`](dek-cache.md)).
  Since the project is WIDER than the reported directory (every worktree of one
  repository shares it), the cache section also renders the project line
  (`缓存范围（项目）`, from `metadata.project`) plus the literal `目录` row: the
  approver reads both the reuse scope and where the request actually came from.
- **C3 — batch size in approval notifications**: `metaLines` takes a
  `salts` parameter; when > 0 the head line becomes `user@host · N 条`
  (mirrors the cache-hit head).
- **C4 — notifications show the parent process**: `metaLines` adds
  `via: <ppid_cmd>` after `cmd`. Cache-hit lines stay compact.

## 1a. Signal-per-line rules

Fields that are always the same carry no signal, and long unshortened strings
drown the signal they do carry. All display-only (grants, digests, and audit
fields are unaffected unless noted):

- **`caller:` is exception-display.** `caller: vt` (the CLI itself, the
  overwhelmingly common case) is suppressed; the line appears only for
  other basenames (`ssh -A` traffic, `ssh-keygen`, renamed binaries).
  Suppressing on the name hides nothing a rename could not already hide —
  the basename is attacker-chosen either way. Audit `peer_exe` stays
  unconditional.
- **Workspace reuse labels are unmarked.** `reuse: ~/code/vt · 8h` — bare,
  home-contracted path = whole repository; `directory` / `app` keep their
  prefixes (§6 of authorization-scopes-v2.md). `contract_home` is display
  only. This changes audit `scope_label` too (it mirrors the displayed
  line by definition).
- **`op: inject` line dropped at the source** (`src/client.rs`): the
  `cmd:`/`file:` lines themselves mean inject, and every surface already
  names the operation (prompt header / approval-page 类型). `vt read`
  keeps its explicit `op: read` (sole distinguishing line on that path).
- **Raw-sign prompt reads like sign@vt**: header `ssh-sign`, then
  `key:` / `caller:` / `dest:` / `reuse:` truth lines, so the two sign
  paths read as one UI.
- **`cmd:` shortened at the source**: basename(argv[0]) + args, cap 160.
  Applies to the Touch ID prompt, the approval page, and notifications
  alike; the executable path is client-claimed display data, never a
  verified field.
- **`ppid_cmd` shortened at collection** (`src/caller_meta.rs`
  `parent_cmd`): basename(argv[0]) + args. Affects the `via:` prompt line,
  the approval page 父进程 row, notifications, and audit rows uniformly.

## 1b. Host-token trim

With per-host Worker tokens ([host-token.md](host-token.md)) the Worker learns
`host` / `user` from the token record, so the ceremony wire meta was cut to
what still carries signal:

| field | verdict | why |
|---|---|---|
| `op_kind` `command` `pwd` `project` `ppid_cmd` `reason` | kept | the operation, its main signal, the directory, the cache scope (advisory), "which program asked", the user's own words |
| `ip` | kept | Worker-derived; on the token path `ip_prev` flags a change since the token's last use |
| `host` `user` | removed from the CLI wire | supplied by the token record and labeled 已验证; the agent audit push still sends them (it names the session host) |
| `tty` | removed | never verified, never shown in notifications, nobody decided on it |
| `ppid` | removed | numeric, audit-only, no longer a cache binding |
| `ssh_client` | removed | spoofable; the host is identified by its token and the IP is verified |

Audit columns stay (NULL on new rows); `metaLines` drops the `ssh:` line; the
approve page footnote now states which fields are verified per path. The
agent-side `ClientMeta` (CLI → agent extension wire) is unchanged.
