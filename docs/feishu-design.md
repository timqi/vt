# Feishu / Lark notification channel

Implemented reference for delivery lifecycle and security decisions. Operator
setup and `FEISHU_JSON` fields belong to [feishu.md](feishu.md). Implementation
history is in Git; this file is not a pending implementation plan.

## API and ownership

Editable cards require the self-built app Bot API, not an incoming webhook:

```text
POST auth/v3/tenant_access_token/internal -> tenant_access_token
POST im/v1/messages?receive_id_type=...   -> data.message_id
PATCH im/v1/messages/:message_id          -> edit original card
```

`cf-worker/src/feishu.ts` owns config parsing, token caching, API calls, and
card rendering. `cf-worker/src/account_notifications.ts` (`AccountNotifications`)
owns asynchronous delivery and message-reference persistence; `do_account.ts`
invokes it at ceremony transitions. Slack App shares this editable-channel
lifecycle. Pushover and Slack incoming webhooks use the stateless fan-out.

## Delivery lifecycle

| Event | Action |
|---|---|
| Create approval | Schedule a pending card with mentions and approval URL |
| Send completes | Merge only `feishu_message_id` into the latest challenge |
| Approve / reject / expire | Schedule an edit to the terminal state; remove mentions and button |
| Decision precedes send completion | Edit the delivered card to the stored terminal state |
| Cache hit | Optional compact notice, no mentions or edit lifecycle |
| Cache-extension ceremony | No channel push; approval and audit stay in the admin UI |

All sends and edits run through `ctx.waitUntil`, outside the protected operation.
Feishu and Slack App initial sends run sequentially inside one background task
so their reference writes cannot overwrite each other. `storeReference` re-reads
the challenge and merges only the delivered channel's reference; it never
recreates a swept record or replaces ceremony state from an old snapshot.

A normal approved-card edit includes the Passkey label and latency. If the
decision races ahead of delivery, the repair path has latency but no approver
label. Missing references skip edits. Send, storage, or edit failure does not
change authorization or DEK delivery; audit remains authoritative. Lost send
responses and failed edits can leave a stale pending card, with no durable
retry queue.

Cache-hit notices require `CACHE_HIT_NOTIFY`, which is off by default and does
not disable audit. Agent-cache notices are additionally throttled in memory;
see [dek-cache.md](dek-cache.md) and [agent-audit.md](agent-audit.md).

## API failure handling

- Config absent means disabled; malformed config reports a warning and disables
  only this channel. `parseFeishuConfig` validates required fields, enum values,
  and mention identifiers.
- The token cache is `feishu:tat:<app_id>` with `{token, exp_ms}` in DO storage.
  Tokens with at most 60 seconds remaining are refreshed. An HTTP 401 or known
  invalid-token code forces one refresh and one retry of the message API call.
- Each network request has a 6-second abort timeout, not a 6-second budget for
  the entire send/refresh/retry sequence. Message calls require both HTTP success
  and Feishu `code === 0`; HTTP 200 alone is insufficient.
- Provider bodies and credentials are not logged. Network and storage failures
  are contained; returned warnings do not fail the ceremony.

## Security boundaries

- `app_secret` is a bot credential: store it in Worker secrets, never logs or
  admin responses. Restrict permissions and chat membership as documented in
  [feishu.md](feishu.md#安全模型). Cached tenant tokens are also secret.
- API hosts derive only from the `base` enum (`feishu` or `larksuite`), never
  arbitrary configured URLs.
- The card's approval button is a URL link, not a callback action; it adds no
  inbound Worker endpoint. Seeing `/a/<token>` does not authorize approval:
  an enrolled Passkey plus PRF is still required.
- Caller context renders as `plain_text`, not `lark_md`. Only the mention line
  uses markup, with validated identifiers. Shared `metaLines` formatting keeps
  card and webhook context consistent without treating client claims as truth.
- Cards use raw JSON and `config.update_multi: true` so edits reach all
  recipients of a shared/group card.

## Verification

`cf-worker/test/do_account.notifications.test.ts` covers delivery races,
reference merging, and failure isolation; `cf-worker/test/notify.test.ts`
covers shared notification formatting. Run `just check-worker` for TypeScript
and Vitest. Real Feishu/Lark delivery and permissions require native provider
verification; unit tests do not establish them.
