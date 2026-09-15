# Agent audit delivery

Agent audit makes local approval decisions and silent reuse visible in the
Worker console without adding a dependency to protected operations.

## Guarantees and limits

- Delivery is opt-in and best-effort; an offline or failed push can lose an
  event. There is no local durable queue.
- Push runs after the decision path and cannot block or fail the operation.
  Retries are bounded and deduplicated; permanent rejections are not retried.
- An approved event records a human decision, not successful execution.
  A failed program launch can produce a separate failure event after approval.
- Cache hits are distinguished from human approval; diagnostics and UI-status
  polling are not audited.
- Agent events share the Worker's audit retention. There is no clear-audit
  operation; an incompatible schema rebuild discards existing audit history.

## Trust

Each Mac signs events with its own enrolled host token. The DO verifies the MAC
and token liveness; background push does not renew token expiry. No Worker root
or KEK is distributed to the agent.

An accepted row is attributed to the signing token: its `token_id` must start
with `a_t:<token_id>_` and `host`/`user` are taken from the token record, never
from the pushed body.

A compromised host can forge its own audit rows and use its live cached DEKs.
Audit is therefore an operational record, not independent proof that Touch ID
occurred. Revoking the token blocks further accepted events and cache reads.

Agent-observed and client-claimed context stay distinct as defined in
[approval-transparency.md](approval-transparency.md). Audit metadata may retain
commands, paths, and host labels; never place plaintext secrets in those fields.

## Enable

Enroll the Mac with `vt enroll`, then supply its token when starting the agent:

```bash
vt ssh agent --audit-url https://vt.example.com --audit-key "$VT_PASSKEY_TOKEN"
```

Here `VT_PASSKEY_TOKEN` must already be set in the invoking shell; enrollment
writes the config file and does not export a shell variable. The flag value is
visible in process arguments. Do not use a shared or master credential.

With no audit URL, `--no-audit-push`, or invalid audit configuration, no events
are sent. Inspect the admin audit tab for agent events; absence is not evidence
that no operation occurred.

Wire types and delivery logic live in
[src/server_macos/audit.rs](../src/server_macos/audit.rs); Worker ingestion and
retention in [account_audit.ts](../cf-worker/src/account_audit.ts).
