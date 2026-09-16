# Slack Bot channel

Operator runbook for the optional Slack notification channel: approval requests
post to one channel, @-mention the configured members, and are edited in place
when the ceremony ends. Configuration lives in the DO config blob (Settings tab);
there is no Wrangler secret for it.

## Create the app

1. [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**.
2. **OAuth & Permissions** → **Bot Token Scopes** → add `chat:write`. Add
   `chat:write.public` only if the bot must post without being invited.
3. **Install to Workspace** → copy the **Bot User OAuth Token** (`xoxb-…`). It is
   a credential: never commit it or paste it outside the Settings tab.
4. In the target channel: `/invite @<app name>`.

## Configure

Settings tab → **Slack Bot channel**:

| Field | Value |
|---|---|
| Bot token | `xoxb-…`; empty on a later save keeps the stored token |
| Channel ID | `C…` (channel details → Channel ID), or a `D…`/`U…` id for a DM |
| Mention member IDs | `U…` per line (profile → More → Copy member ID); optional |

Untick the switch and save to disable. The token is stored encrypted with the
rest of the config and is never returned by the API.

## Behavior

| Event | Message |
|---|---|
| Approval or enrollment request | `⏳ … — pending`, orange bar, mentions, **Approve** link button |
| Approved on the phone | edited to `✅ … — approved`, green, latency line |
| Rejected | edited to `❌ … — rejected`, red |
| Expired without a decision | edited to `⌛ … — expired`, grey |
| Cache hit | one blue FYI message, no mention, no button; requires the cache-hit notify switch |

Cache-extension ceremonies are console-only and never posted.

## Contract

- The **Approve** button is a plain link to `/a/<token>`; approval still needs a
  registered Passkey on that page. Channel membership grants nothing.
- Requests go to `slack.com` only; the config cannot redirect them.
- Client-reported context (`pwd`, `cmd`, …) is escaped before rendering; mention
  ids are charset-checked so they cannot escape the `<@…>` tag.
- Sends and edits are `waitUntil` tasks with a 6 s timeout; failures are logged
  (`slack.send_failed`, `slack.edit_failed`, `slack.cachehit_failed`) and never
  reach the CLI. A lost `chat.postMessage` response leaves the message at ⏳;
  the audit tab is the record.
- If the decision lands before the post returns, the message is edited straight
  to its terminal state.
