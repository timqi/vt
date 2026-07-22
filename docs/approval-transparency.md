# Approval transparency — prompt truth lines, audit fields, worker display

Status: implemented (codex-expert review round folded in; verify current
behavior against the anchors named per section). Follow-up to the
activity-scopes V2 review:
a field-level comparison of the Touch ID prompt, the Worker approval
surfaces, and the agent audit push found gaps in what each shows/records.
This document is the decision record for closing them.

## 1. Problems

1. **Raw `SIGN_REQUEST` hides the verified destination by default.** The
   agent verifies the destination host key via `session-bind@openssh.com`,
   but the prompt (`Session::sign`, `src/server_macos/ssh_agent.rs`) only
   surfaces it inside the `reuse:` line — which exists only when
   `--ssh-auth-cache-duration > 0` and the scope is destination-reusable.
   With the default (`0`), the user approves `sign: <key> (ssh)` with no
   destination shown, even though the agent knows it. Forwarding-capable
   and tainted connections show no marker at all, yet these are exactly
   the connections where a signature may serve a request originating
   beyond hop one.
2. **Kernel truth vs client claims are indistinguishable in vt-extension
   prompts.** decrypt@vt / sign@vt / auth@vt / run@vt render the
   client-reported `via:` (`meta.ppid_cmd`) but never the kernel-verified
   peer executable (`self.peer_exe`), which only the raw-sign prompt shows.
3. **The agent audit push is under-specified.** `AgentAuditEntry`
   (`src/server_macos/audit.rs`) records outcome + `ChallengeMeta` only:
   - raw sign rows carry `ClientMeta::default()` — the key, the peer
     process, and the verified destination survive only as unstructured
     prompt text stuffed into `command`;
   - no row records whether the approval minted a reusable grant, its
     scope family/label, or the TTL; `cache_hit` rows do not say which
     scope was hit;
   - the kernel-verified peer executable is not reported anywhere
     (`meta.ppid` does carry the kernel peer pid);
   - relay provenance (`peer_is_vt_relay`) is not reported.
4. **Worker approval surfaces have small field gaps.**
   - The approve page renders ten meta fields with equal visual weight,
     though only `ip` is worker-verified (`CF-Connecting-IP`); the rest
     are client-claimed and unbound (`src/cf.rs:109-114`, accepted).
   - The DEK-cache consent copy claims "同一来源 IP 且同一工作目录" as if
     both halves were verified; `pwd` is client-reported advisory
     (`types.ts` CacheEntry v3 notes).
   - An approval request never shows the decrypt batch size, although the
     cache-hit FYI does (`N 条`) and the Touch ID prompt does
     (`decrypt N secrets`). A 50-record batch is exactly the anomaly an
     approver should see.
   - Notifications (`metaLines`, `cf-worker/src/notify.ts`) omit
     `ppid_cmd`, though users often decide from the notification alone.

## 2. Changes

### A. Agent prompt truth lines (`src/server_macos/ssh_agent.rs`)

Rendering order invariant (already implicit, now stated): **agent-derived
truth lines precede every client-reported line**, so a hostile caller can
pad only its own region off-screen.

- **A1 — raw sign destination.** After the `sign:` header:
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
- **A2 — caller line.** New helper `append_caller_line`: appends
  `caller: <peer_exe basename>` when `self.peer_exe` is known, placed
  with the truth lines (right after the relay line). Applied to
  decrypt@vt, sign@vt, auth@vt, run@vt. Raw sign keeps its inline
  `({proc})` form. Although `peer_exe` is kernel-derived, it is a
  filesystem basename an attacker with local code execution controls, so
  the line goes through `sanitize_for_display` like every other prompt
  field (the raw-sign header gets the same treatment while we are
  there).
- **A3 — run@vt relay marker.** Add the missing `append_relay_origin`
  call for consistency. Dead path today (the relay filter refuses
  run@vt) — cheap insurance, keeps the four extension prompts uniform.

Descoped: showing the resolved workspace on Fresh prompts (would blur the
"reuse line appears iff a grant can be created" invariant); tty in the
prompt; localizing prompt language; enriching the static CLI-local
prompts (`export master secret` …) — separate, lower-value change.

### B. Structured audit fields (agent → worker ingest)

New **top-level** fields on `AgentAuditEntry` / `DoAuditIngestOp` — not
on `ChallengeMeta`, which stays the client-claimed display struct; these
are agent-authoritative:

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
- `GrantScope` gains `pub fn family(&self) -> Option<ScopeFamily>` and
  `ScopeFamily::as_wire(&self) -> &'static str` in
  `src/core/authorization.rs`. Unlike `ContextBasis`, `ScopeFamily`
  needs no `from_wire`: this is one-way telemetry, never parsed back.
- `emit_audit`'s argument list is refactored into a small
  `AuditContext<'_>` struct (it is at 8 arguments already).
- Raw sign keeps `meta = ClientMeta::default()` (honest: nothing
  client-reported exists on that path) — the new structured fields now
  carry key/peer/destination.

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

- `DoAuditIngestOp` (`types.ts`) gains the seven fields (all optional).
- Additive `ALTER TABLE audit ADD COLUMN` migrations: `peer_exe TEXT`,
  `key_fp TEXT`, `dest TEXT`, `scope_family TEXT`, `scope_label TEXT`,
  `grant_ttl_s INTEGER`, `relayed INTEGER` — same pattern as the existing
  `cache_ttl_s`/`ppid` migrations in `do_account.ts` (re-snapshot
  `PRAGMA table_info` per the stale-snapshot note there).
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
  `grant_ttl_s` / 经中继 `relayed`; the page already skips empty/NULL
  values, so pre-migration rows render unchanged).
- Compatibility: old agent → new worker ⇒ columns NULL; new agent → old
  worker ⇒ unknown JSON fields ignored. The ingest HMAC covers the body
  as-is; no protocol version needed.

### C. Worker approval surfaces (`cf-worker/pwa`, `notify.ts`)

- **C1 — trust labeling on the approve page** (`pwa/approve.js`): the
  `ip` row is labeled `IP（已验证）`; a footnote under the field list
  states `除 IP 外均为客户端自报信息，仅供参考`. New row `记录数: N`
  (from `salts_b64u.length`, worker-derived) when N > 0.
- **C2 — cache consent copy**: 「同一来源 IP（已验证）且同一工作目录
  （客户端自报）」 so the stated boundary matches the implemented one
  (ctx = verified IP + advisory pwd).
- **C3 — batch size in approval notifications**: `metaLines` gains a
  `salts` parameter; when > 0 the head line becomes `user@host · N 条`
  (mirrors the cache-hit head). Ripple is wider than one call site:
  `buildApprovalMessage` (notify.ts) plus `buildCard`/`buildMessage` and
  the public `sendApprovalCard`/`editCard` in feishu.ts and slack_app.ts,
  and their do_account.ts callers, all thread `ch.salts_b64u.length`.
  Terminal edit cards (approved/rejected/expired) keep the count too —
  same shared block, no drift.
- **C4 — notifications show the parent process**: `metaLines` adds
  `via: <ppid_cmd>` between `cmd` and `ssh`. Cache-hit lines stay
  compact (unchanged).

### D. Docs

- `docs/authorization-scopes-v2.md` §6: add the truth-line ordering and
  the new `dest:`/`caller:` lines.
- `CLAUDE.md` invariants: extend the prompt invariant with "agent-derived
  truth lines precede client-reported lines".
- This file joins `docs/README.md`.

## 2a. R2 follow-up — signal-per-line simplifications (operator feedback)

A first round of live use found the opposite failure mode: fields that are
always the same carry no signal, and long unshortened strings drown the
signal they do carry. Changes, all display-only (grants, digests, and audit
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
- **Raw-sign prompt unified with sign@vt**: header `ssh-sign`, then
  `key:` / `caller:` / `dest:` / `reuse:` truth lines — replaces the old
  `sign: key (proc)` one-liner, so the two sign paths read as one UI.
- **`cmd:` shortened at the source**: basename(argv[0]) + args, cap 160
  (was full path, cap 1024). Applies to the Touch ID prompt, the approval
  page, and notifications alike; the executable path was client-claimed
  display data, never a verified field.
- **`ppid_cmd` shortened at collection** (`src/cf.rs parent_cmd`):
  basename(argv[0]) + args. Affects the `via:` prompt line, the approval
  page 父进程 row, notifications, and audit rows uniformly.

## 3. Tests

- Rust (`ssh_agent.rs` unit tests): dest line on Fresh bound; no
  duplicate dest when reuse line names it; forwarding/tainted variants;
  caller line presence/absence; run@vt relay line; `AuditContext`
  population for raw sign (key_fp/dest/peer_exe) and cache_hit scope
  fields. `audit.rs`: serde of new fields; ip-absent test unchanged.
- Worker (Vitest): `metaLines` with salts/via; `auditAgent` writes new
  columns; ingest tolerates missing fields (old agent); approve-page
  data path for 记录数.
- Gates: `cargo test`, `just check`, `just check-worker`.

## 4. Risks

- Touch ID dialog height grows by 1–2 lines on sign/decrypt; caps keep
  each line bounded and truth lines are at the top.
- Notification format change (`· N 条`, `via:`) may surprise downstream
  parsers of Pushover/Slack text — none are known; the audit row is the
  stable machine surface.
- Audit schema growth is additive-only; no migration risk beyond the
  established ALTER pattern.
- `scope_label` for workspace/cwd grants contains a local filesystem
  path (`workspace /Users/…`). Accepted: the same class of data already
  leaves the host via `ChallengeMeta.pwd` on every ceremony, and the
  audit push is opt-in (`--audit-url`).
