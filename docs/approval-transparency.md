# Approval transparency

An approval must let the human identify the operation, its trusted origin,
and the authority that successful execution will leave behind.

## Truth before claims

- Verified facts precede client-reported text so a hostile caller cannot push
  the trusted context out of view by supplying long metadata.
- Agent identity comes from kernel observations and verified session binding;
  Worker host/user labels come from the approved host-token record.
- A host token authenticates a credential, not a physical machine. Client cwd,
  project, command, reason, and application labels remain advisory.
- Sanitize all displayed text, including kernel-observed executable names:
  a caller may control the underlying filename.
- A verified destination, forwarding warning, or failed-bind warning must not
  be hidden by a client claim or represented as an unverified destination.

## What the approval must show

The decision surface identifies the operation, affected key or records, and
trusted host/caller context. Enrollment makes the pairing code prominent enough
to compare with the requesting terminal.

A reusable approval states its scope and duration. A fresh approval must not
suggest that reuse is granted. Worker approval shows both the literal directory
and the broader project scope, with the project labeled as client-reported.

Operator-owned record names precede suggestions. A suggestion is not a trusted
name until adopted by a verified approval; a later rename requires an admin
session. The same trust distinction applies to approval, cache, audit, and push.

## Presentation

- Keep the decision, reuse scope, duration, and approve/reject actions visible
  on a phone; secondary request metadata may be collapsed.
- Omit repetitive display-only labels when they add no decision information;
  do not omit required provenance from audit merely because a prompt is compact.
- Shortening a command or path is presentation only; it cannot change the scope
  that is authorized. Let the operator inspect necessary detail.
- A cache hit is reuse of prior authority, never a new human approval.
- Audit distinguishes agent-authoritative fields from client claims. Missing
  information is not proof of freshness or verified provenance.

Agent audit does not retain a unique approval-to-hit linkage; matching scope
labels and timestamps can be ambiguous. Do not present that correlation as proof
that a particular approval caused a hit.

Visual interaction rules belong to [design/ui-ux.md](design/ui-ux.md).
Prompt rendering is in [ssh_agent/handlers.rs](../src/server_macos/ssh_agent/handlers.rs)
and [approve.js](../cf-worker/pwa/approve.js); audit guarantees belong to
[agent-audit.md](agent-audit.md).
