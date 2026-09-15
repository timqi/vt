# DEK cache

The DEK cache trades repeated phone approval for time-limited access to approved
records. A live entry lets its enrolled host decrypt without another phone tap.

## Security boundary

- The host token is the hard boundary; client-reported project is advisory.
  Another enrolled host cannot reuse the entry, regardless of egress IP.
- A project is the common Git directory when available, otherwise cwd; worktrees
  of one repository share a Worker project. This differs from local agent scopes.
- Possession of the token and matching project is sufficient to obtain live
  cached DEKs. A compromised Worker can also read them; at-rest encryption does
  not protect against a compromised running service.
- Token revocation prevents further authenticated reads; cache clear removes
  entries. Neither can erase DEKs or plaintext already delivered to a caller.
- The default approval duration is zero: no cache write. There is no independent
  cache switch or client-side bypass of the approval policy.

Use a cache duration only when the resulting no-phone-approval window is
acceptable. The 100-year extension is effectively permanent access: do not rely
on expiry for review or revocation of those entries.

## Approval and extension

Approval and extension have distinct duration ladders: initial approval stays
short, while extension is a deliberate review of named live entries. The values
are defined once in [cache_policy.ts](../cf-worker/src/cache_policy.ts).

| Action | Required authority |
|---|---|
| Read the inventory or clear entries | Admin session |
| Create entries | Verified approval of the decrypt ceremony |
| Extend entries | Admin session plus verified Passkey approval |

- Extension approves an immutable intent for one host token and one project;
  a mixed scope must not become one ceremony.
- New expiry is approval time plus duration, not creation time or remaining
  time plus duration. Total lifetime can grow through repeated approvals.
- Expired entries never revive; entries that would not gain time are unchanged.
  Recheck liveness immediately before committing the extension.
- Creation time remains immutable; finite expiries use the same liveness rules
  everywhere, including the far-future duration.
- The Passkey assertion covers the challenge, not a hash of the displayed text.
  The operator trusts the Worker to render the stored intent faithfully.

## Reads and revocation

A cache hit requires every requested record to be live; a partial hit falls
back to a normal phone ceremony. Stored DEKs are re-sealed to the current CLI
request's ephemeral key, never returned in their at-rest form.

A missing, unavailable, or unusable cache result may lead to approval, but a
response identified as a cache hit with a malformed sealed box is a hard error.
Never reinterpret corrupted key delivery as a successful approval or silently
accept a different envelope. HTTP/WebSocket waits must remain bounded.

The cache tab is the inventory; the audit tab is a record of events, not proof
that an entry is still live. Listing shows only live entries, reports truncation,
and exposes no sealed material or derived storage key.

Named clears remove exactly the selected entries. Clear-all must exhaust the
cache rather than stop at a listing limit. Both report actual deletions and
fail loudly if incomplete. Cache revocation belongs on the cache tab only.

## Names and audit

Record names are operator-owned labels. Client suggestions stay visibly
self-reported until adopted during verified approval or renamed through an
admin session. Renaming can update the display of historical events; it does
not change which record was authorized.

- Every cache hit is audited and is distinguished from phone approval.
- Extension records both the authorization and actual effects, including partial
  writes and skipped entries; intended changes are not reported as completed.
- The original approved TTL remains immutable in audit; actual expiry tracks
  extension separately.
- Hit notifications are optional and off by default; delivery never blocks
  key release. Audit is retention-managed, with no clear-audit action.

## Use

Choose a duration on a record's approval page. In the admin cache tab, select
entries from one host/project to request an extension, then approve the Passkey
ceremony. Clear selected entries or the entire cache to require approval again.

Implementation and tests: [account_cache.ts](../cf-worker/src/account_cache.ts)
and [do_account.ts](../cf-worker/src/do_account.ts). Key delivery is specified in
[sealed-box-v1.md](sealed-box-v1.md); host/admin authority in
[worker-slim.md](worker-slim.md).
