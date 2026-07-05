# Feishu / Lark notification channel — design spec (for review)

Status: **draft, pre-implementation**. Adds a third notification channel
(飞书/Lark) alongside Pushover + Slack, with two capabilities the existing
one-way webhooks lack: (1) **@-mention** approvers on an approval request, and
(2) **edit the original card in place** when the request reaches a terminal
state (approved / rejected / expired).

## Why this can't reuse the Slack/Pushover pattern

Pushover and Slack are fire-and-forget webhooks: send returns no addressable
message handle, and neither can be edited. Feishu's *custom-bot incoming
webhook* is the same (no `message_id`, not editable). To edit a card we must use
the **self-built app (bot) API**:

```
POST auth/v3/tenant_access_token/internal   {app_id, app_secret} -> tenant_access_token (~2h)
POST im/v1/messages?receive_id_type=…       msg_type=interactive  -> message_id
PATCH im/v1/messages/:message_id            {content: <card json>} -> edit in place
```

So Feishu is a stateful channel: it needs a cached `tenant_access_token` and it
must persist `message_id` on the challenge to edit later.

## Config secret — `FEISHU_JSON`

New Worker secret, same tri-state contract as `PUSHOVER_JSON` / `SLACK_JSON`
(absent → disabled; present-but-malformed → error surfaced as a warning; valid →
enabled).

```jsonc
{
  "app_id": "cli_xxx",
  "app_secret": "xxx",              // bot credential — NEVER logged, NEVER echoed to admin page
  "receive_id": "oc_xxx",           // target chat_id (group) or open_id (DM)
  "receive_id_type": "chat_id",     // chat_id | open_id | user_id | email  (default chat_id)
  "mention": ["ou_aaa", "ou_bbb"],  // open_ids to @ on APPROVAL requests only; [] = no @
  "base": "feishu"                  // feishu -> open.feishu.cn ; larksuite -> open.larksuite.com (default feishu)
}
```

Validation (in `parseFeishuConfig`, mirrors `parseSlackConfig`):
- `app_id`, `app_secret`, `receive_id` required non-empty strings.
- `receive_id_type` ∈ the 4 enum values, default `chat_id`.
- `mention` optional array of strings (open_ids); non-array → error.
- `base` ∈ {`feishu`,`larksuite`}, default `feishu`. **This is the SSRF
  boundary** — the host is derived from `base`, never from user-supplied URLs,
  so a bad secret can't turn the channel into an SSRF primitive (same principle
  as Slack's `hooks.slack.com` pin).

## Where the code lives

New module `cf-worker/src/feishu.ts`. Unlike `pushover.ts`/`slack.ts` (pure,
stateless), Feishu functions need DO storage (token cache) + must be called from
inside the DO (where the challenge lifecycle lives). Signatures take an explicit
storage accessor so the module itself stays testable:

```ts
type Kv = { get<T>(k: string): Promise<T | undefined>; put(k: string, v: unknown): Promise<void> };

parseFeishuConfig(raw?: string): { config: FeishuConfig | null; error: string | null }
tenantToken(cfg, kv, now): Promise<string>            // cached in kv 'feishu:tat:<app_id>' {token, exp_ms}; refresh when <60s left
sendApprovalCard(cfg, kv, now, ch, approveUrl): Promise<string | null>   // returns message_id | null on failure
editCard(cfg, kv, now, ch, state, extra): Promise<string>               // '' ok | warning
sendCacheHitNotice(cfg, kv, now, meta, salts): Promise<string>          // compact, no @, no edit
```

`now` is passed in (the DO has `Date.now()`; keeps feishu.ts deterministic for
tests). All network fetches: 6 s `AbortController` timeout, best-effort, return a
short warning string — **never throw into the ceremony path**.

## Lifecycle — DO owns the editable channel

| Stage | Site (`do_account.ts`) | Feishu action |
|---|---|---|
| create | `opCreate` (before `storage.put`) | `sendApprovalCard` → store `ch.feishu_message_id`; card = `⏳ 待审批`, @mentions, 「去审批」button → `approveUrl` |
| approve | `opApprove` (after `ch.status='approved'`) | `editCard(state='approved', {approverLabel: entry.l, latencyMs})` → `✅ 已批准`, drop @/button |
| reject | `opReject` | `editCard(state='rejected')` → `❌ 已拒绝`, drop @/button |
| expire | `alarm()` pending-sweep | `editCard(state='expired')` → `⌛ 已过期`, drop @/button |
| cache hit | `opDekCache` (next to existing `notifyCacheHit`) | `sendCacheHitNotice` → 1–2 line compact card, no @, no edit |

Notes:
- **Send is awaited in `opCreate`** so `feishu_message_id` is persisted before
  the op returns. DO ops are serialized, so an `approve` that arrives later
  always sees the stored id. Latency is bounded by the 6 s timeout and matches
  the already-awaited `notifyApproval` on the ceremony path today.
- Pushover/Slack approval fan-out (`index.ts` `notifyApproval`) is **unchanged**
  — Feishu is NOT added to that stateless fan-out. Two send sites, by design.
- Every Feishu call is guarded by `if (cfg)` and wrapped so a failure only
  `logErr`s; the approval/ceremony proceeds regardless. Edit is skipped when
  `feishu_message_id` is absent (send had failed).

## Type changes

- `Challenge` (`types.ts`): add `feishu_message_id?: string`.
- `Env`: add `FEISHU_JSON: string` (documented like the others).

## Requirement 2 — trim the cache-hit (免审批) message, all channels

`buildCacheHitMessage` (`notify.ts`) currently emits the full who/pwd/cmd/ssh/
ip/reason block. Trim to a compact 1–2 line summary reused by every channel
(Pushover/Slack via `notify.ts`, Feishu via its compact card), e.g.:

```
✅ 免审批解密 <op_kind> · <user@host> · <n> 条 (缓存命中)
```

No @-mention anywhere on the cache-hit path.

## Requirement 3 — approver identity on the card

`opApprove` already resolves `entry = lookupByCredentialId(...)`; `entry.l` is
the human label. Pass it to `editCard` so the approved card shows
`批准人(Passkey): <label>` + `用时 <latencyMs> ms`.

## Admin 推送渠道 page

Add a third `<section class="card channel">` "飞书 / Lark" to
`buildChannelsPage` (`index.ts`): switch + fields `app_id` / `app_secret` /
`receive_id` / `receive_id_type` (select) / `mention` (add/remove list) / `base`
(select). `channels.js` gains a `generate` path that emits `FEISHU_JSON`. The
`/${ADMIN_SEG}/channels` route passes a `feishuSet` flag; reuse the existing
"已配置留空保持不变" keep-note. Nothing is POSTed back — page only generates the
JSON for `wrangler secret put`.

## Threat model additions

- `app_secret` is a bot credential. Compromise lets an attacker send/edit as the
  bot and read messages in chats the bot is in — scoped by the app's granted
  permissions. Mitigation: minimal scopes (`im:message`, `im:message:send_as_bot`),
  add the bot only to the target chat. Documented in `docs/feishu.md`.
- The approval card links to `/a/<token>` (unguessable) but this is **not** a
  bearer capability: approval still requires an enrolled Passkey + PRF. Chat
  membership = "who can *see/initiate*", not "who can approve". Same trust model
  as Slack/Pushover.
- `mention` open_ids are app-scoped identifiers, not secrets, but live in the
  secret anyway.
- SSRF: host derived only from `base` enum, never from a URL field.
- Token cache in DO storage (`feishu:tat:<app_id>`) holds a short-lived
  `tenant_access_token`; never logged.

## Review revisions (LOCKED — codex-expert approve-with-changes + API verification)

Folded in before coding:

1. **Error convention**: Feishu returns `{code,msg,data}` — `code !== 0` is a
   failure **even at HTTP 200** (and some errors are HTTP 400). Every call
   checks BOTH transport/HTTP status AND `code === 0`; `message_id` comes from
   `data.message_id`. Do not copy Slack's status-only check.
2. **Token refresh on auth failure**: on a `code` indicating invalid/expired
   token, evict `feishu:tat:<app_id>`, refresh once, retry once. (Feishu
   invalidates tokens on `app_secret` reset; TTL-only refresh isn't enough.)
3. **Button = URL open-link ("跳转交互"), NOT a callback action.** No card
   callback → no new inbound Worker endpoint / attack surface. Button carries
   `url: approveUrl` only.
4. **Card format = raw card JSON with `elements`** (not a template `card_id`);
   PATCH `im/v1/messages/:message_id` with new `content` updates it in place.
5. **`config: { update_multi: true }`** on every card — makes the in-place edit
   visible to ALL recipients of a shared/group card (без it, the edit only
   reaches some). Required for the group-chat use case.
6. **`opCreate` does NOT await the send.** Fire-and-forget via
   `ctx.waitUntil(...)` (same pattern as `opDekCache`'s `notifyCacheHit`,
   do_account.ts:914). The send callback then re-gets the challenge and: if
   still `pending` → store `feishu_message_id`; if already terminal (approve
   raced ahead) → edit the card straight to the final state (we now have the
   id). Keeps 3rd-party latency out of the singleton DO's serialized op path;
   worst-case race is cosmetic (card stuck at ⏳), never a ceremony/security
   issue.
7. **Alarm expire sweep**: collect expiring challenges, edit their cards via
   `Promise.allSettled` (not sequential `await` in the loop), each with its own
   try/catch. `feishu.ts` guards `kv.get/put` too, not just `fetch`.
8. **Requirement 2 (cache-hit trim)** lands as a **separate commit** from the
   Feishu addition (independent revert).
9. `approveUrl` is reconstructed in the DO as `${env.WORKER_ORIGIN}/a/${token}`
   via a shared helper (index.ts:311 computes the same; avoid drift).
10. Known gap to document in `docs/feishu.md`: **a failed card edit is never
    retried** (best-effort) — the card may stay at ⏳ while the ceremony itself
    completed correctly. Consistent with how other known gaps are documented.

## Open questions for review (resolved above)

1. Send-site split (Feishu in DO, Pushover/Slack in `index.ts`) vs. moving ALL
   approval notifications into the DO for symmetry — is the split acceptable?
2. `opCreate` awaiting the Feishu send adds one network RTT to the ceremony
   path (bounded 6 s). Acceptable, or send async + write-back `message_id` in a
   follow-up op (adds an approve/send ordering race to reason about)?
3. Card edit on expire runs inside the `alarm()` sweep, which may edit many
   cards in one tick — should it be capped / rate-limited, or is best-effort +
   per-item try/catch enough?
